#!/usr/bin/env python3
# Copyright 2026 Jaspreet Singh
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Map the AI surface of a mobile repo (React Native / Expo, iOS, Android, Flutter).

Prints JSON: detected stack, AI dependencies, and *leads* grouped by check ID
(MG-Rxx store-rejection, MG-Sxx security). Leads are places to read, not
verdicts — the MobileGuard skill verifies each one by tracing the code.

Standard library only; runs on Python 3.8+.

    python3 ai_surface.py <repo> [--max-per-check N]
    python3 ai_surface.py <repo> --snapshot     # stable fact lines for the ledger
    python3 ai_surface.py <repo> --diff-ledger MOBILEGUARD.md   # drift since last release
    python3 ai_surface.py <repo> --diff-ledger MOBILEGUARD.md --fail-on-drift   # CI gate

The snapshot omits line numbers and test code so two snapshots diff cleanly:
a new line between releases is new AI surface to review and declare.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from collections.abc import Iterator
from pathlib import Path

SKIP_DIRS = {
    "node_modules", "Pods", ".git", "build", "dist", "DerivedData", ".build",
    ".gradle", ".expo", ".next", "vendor", "__pycache__", ".venv", "venv",
    "coverage", ".dart_tool", ".idea", ".vscode", "Carthage", ".yarn",
}
TEST_PATH = re.compile(
    r"(^|/)(__tests__|__mocks__|tests?|androidTest|e2e|fixtures?|mocks?|"
    r"[A-Za-z]+Tests|[A-Za-z]+UITests)(/|$)|\.(test|spec)\.[jt]sx?$|Tests?\.(swift|kt)$"
)
SOURCE_EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".swift", ".m", ".mm",
               ".kt", ".kts", ".java", ".dart"}
CONFIG_NAMES = {
    "package.json", "app.json", "app.config.js", "app.config.ts", "eas.json",
    "pubspec.yaml", "Info.plist", "PrivacyInfo.xcprivacy", "AndroidManifest.xml",
    "build.gradle", "build.gradle.kts", "gradle.properties", "local.properties",
    "network_security_config.xml", "Podfile", "strings.xml",
}
SECRET_FILE = re.compile(r"(^|/)\.env(\.[\w.-]+)?$|\.xcconfig$|(^|/)secrets?\.(json|plist|ya?ml)$")
MAX_BYTES = 1_500_000

# ── AI dependency catalogue ──────────────────────────────────────────────────
# (name pattern, provider, kind) — kind: cloud | on-device | framework
NPM_AI = [
    (r"^openai$", "OpenAI", "cloud"), (r"^@anthropic-ai/", "Anthropic", "cloud"),
    (r"^@google/(generative-ai|genai)$", "Google Gemini", "cloud"),
    (r"^ai$|^@ai-sdk/", "Vercel AI SDK", "framework"),
    (r"^@?langchain", "LangChain", "framework"), (r"^llamaindex$", "LlamaIndex", "framework"),
    (r"^@react-native-firebase/(ai|vertexai)$|^firebase$", "Firebase AI Logic (check usage)", "cloud"),
    (r"^groq-sdk$", "Groq", "cloud"), (r"^@mistralai/", "Mistral", "cloud"),
    (r"^cohere-ai$", "Cohere", "cloud"), (r"^together-ai$", "Together", "cloud"),
    (r"^replicate$", "Replicate", "cloud"), (r"^@?elevenlabs", "ElevenLabs", "cloud"),
    (r"^@huggingface/", "Hugging Face", "cloud"), (r"^ollama$", "Ollama", "cloud"),
    (r"^@openrouter/", "OpenRouter", "cloud"), (r"^@xai-org/|^@ai-sdk/xai$", "xAI", "cloud"),
    (r"^llama\.rn$|^@pocketpalai/llama\.rn$", "llama.cpp (llama.rn)", "on-device"),
    (r"^react-native-executorch$", "ExecuTorch", "on-device"),
    (r"^@mlc-ai/", "MLC LLM", "on-device"), (r"^onnxruntime-react-native$", "ONNX Runtime", "on-device"),
    (r"^react-native-fast-tflite$", "TFLite", "on-device"),
    (r"^@react-native-ai/|^react-native-ai$", "react-native-ai", "on-device"),
]
DART_AI = [
    (r"^google_generative_ai$", "Google Gemini", "cloud"), (r"^firebase_(ai|vertexai)$", "Firebase AI Logic", "cloud"),
    (r"^dart_openai$|^openai_dart$|^chat_gpt_sdk$", "OpenAI", "cloud"),
    (r"^anthropic_sdk_dart$", "Anthropic", "cloud"), (r"^langchain", "LangChain.dart", "framework"),
    (r"^flutter_gemma$|^llama_cpp_dart$|^fllama$|^tflite_flutter$", "on-device LLM", "on-device"),
]
NATIVE_AI = [
    (r"^\s*import\s+OpenAI\b", "OpenAI (Swift)", "cloud"),
    (r"^\s*import\s+(GoogleGenerativeAI|FirebaseAI|FirebaseVertexAI)\b", "Gemini/Firebase AI (Swift)", "cloud"),
    (r"^\s*import\s+(SwiftAnthropic|Anthropic)\b", "Anthropic (Swift)", "cloud"),
    (r"^\s*import\s+FoundationModels\b", "Apple Foundation Models (on-device)", "on-device"),
    (r"^\s*import\s+(CoreML|MLX\w*)\b", "CoreML/MLX (on-device)", "on-device"),
    (r"com\.aallam\.openai|com\.openai\.", "OpenAI (Kotlin/Java)", "cloud"),
    (r"com\.google\.ai\.client\.generativeai|com\.google\.firebase\.(vertexai|ai)\b", "Gemini/Firebase AI (Android)", "cloud"),
    (r"com\.anthropic\.", "Anthropic (Kotlin/Java)", "cloud"),
    (r"com\.google\.mediapipe\.tasks\.genai|com\.google\.mlkit\.genai", "MediaPipe/ML Kit GenAI (on-device)", "on-device"),
]
AI_HOSTS = re.compile(
    r"(api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|"
    r"aiplatform\.googleapis\.com|[\w-]+\.openai\.azure\.com|[\w-]+\.cognitiveservices\.azure\.com|"
    r"api\.cohere\.(ai|com)|api\.mistral\.ai|api\.groq\.com|api\.together\.(xyz|ai)|"
    r"api\.perplexity\.ai|openrouter\.ai/api|api\.replicate\.com|api\.deepseek\.com|"
    r"api\.x\.ai|api\.fireworks\.ai|api-inference\.huggingface\.co|router\.huggingface\.co|"
    r"api\.elevenlabs\.io|bedrock-runtime\.[\w-]+\.amazonaws\.com|dashscope\.aliyuncs\.com)",
    re.I,
)

# ── Lead patterns: (check_id, regex, note, extensions or None for all source) ─
JS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
SWIFT = {".swift", ".m", ".mm"}
KT = {".kt", ".kts", ".java"}
DART = {".dart"}

KEY_FORMATS = re.compile(
    r"(sk-ant-(?:api|admin)\d{2}-[\w-]{20,}|sk-(?:proj|svcacct|or-v1)-[\w-]{20,}|"
    r"sk-[A-Za-z0-9]{32,}|AIza[\w-]{35}|gsk_[A-Za-z0-9]{40,}|hf_[A-Za-z0-9]{30,}|"
    r"r8_[A-Za-z0-9]{30,}|xai-[A-Za-z0-9]{40,}|pplx-[A-Za-z0-9]{40,}|"
    r"(?<![\w-])AKIA[0-9A-Z]{16})"
)

LEADS: list[tuple[str, re.Pattern, str, set[str] | None]] = [
    # Secrets that ship in the binary even though they "come from env"
    ("MG-S01", re.compile(r"process\.env\.EXPO_PUBLIC_\w*(KEY|TOKEN|SECRET)\w*", re.I),
     "EXPO_PUBLIC_* is inlined into the JS bundle at build time", JS),
    ("MG-S01", re.compile(r"\bConfig\.\w*(API_?KEY|TOKEN|SECRET)\w*|from ['\"]react-native-config['\"]", re.I),
     "react-native-config values are compiled into the app (BuildConfig / Info.plist)", JS),
    ("MG-S01", re.compile(r"(expoConfig|manifest2?)\??\.extra\??\.\w*(key|token|secret)", re.I),
     "app.config extra is readable from the public update manifest", JS),
    ("MG-S01", re.compile(r"buildConfigField\s*\(?\s*['\"]String['\"]\s*,\s*['\"]\w*(KEY|TOKEN|SECRET)", re.I),
     "BuildConfig fields are compiled into the APK/AAB", KT | {".gradle"}),
    ("MG-S01", re.compile(r"dotenv\.(env|get)\s*\[?\(?['\"]\w*(KEY|TOKEN|SECRET)|String\.fromEnvironment\(\s*['\"]\w*(KEY|TOKEN)", re.I),
     "flutter_dotenv assets / --dart-define values ship inside the app", DART),
    ("MG-S01", re.compile(r"Bundle\.main\.(object\(forInfoDictionaryKey|infoDictionary)[^\n]*(KEY|TOKEN|SECRET)", re.I),
     "Info.plist values ship inside the IPA", SWIFT),
    ("MG-S01", re.compile(r"dangerouslyAllowBrowser\s*:\s*true"),
     "provider SDK running in the client — the client holds the key", JS),
    # Unbounded consumption
    ("MG-S02", re.compile(r"\b(max_tokens|maxTokens|max_output_tokens|maxOutputTokens|max_completion_tokens)\b"),
     "token cap present (absence near AI calls is the lead)", None),
    # Improper output handling / code execution sinks
    ("MG-S04", re.compile(r"\beval\s*\(|new\s+Function\s*\("), "dynamic JS evaluation", JS),
    ("MG-S04", re.compile(r"\.injectJavaScript\s*\(|injectedJavaScript(BeforeContentLoaded)?\s*=", re.I),
     "JS injected into WebView", JS),
    ("MG-S04", re.compile(r"source=\{\{\s*html\s*:|dangerouslySetInnerHTML"), "HTML rendered from a variable", JS),
    ("MG-S04", re.compile(r"\bLinking\.openURL\s*\(|onLinkPress|onOpenLink"), "URL opened from rendered content", JS),
    ("MG-S04", re.compile(r"\.(evaluateJavaScript|callAsyncJavaScript|evaluateScript|loadHTMLString)\s*\("),
     "WKWebView/JSContext dynamic content", SWIFT),
    ("MG-S04", re.compile(r"\.(evaluateJavascript|loadData|loadDataWithBaseURL)\s*\(|Intent\.parseUri\s*\("),
     "WebView dynamic content / intent URI parsing", KT),
    ("MG-S04", re.compile(r"\b(runJavaScript|evaluateJavascript|loadHtmlString|launchUrl)\s*\("),
     "webview_flutter / url_launcher sink", DART),
    ("MG-S04", re.compile(r"\b(rawQuery|execSQL|executeSql|sqlite3_exec)\s*\(", re.I), "raw SQL sink", None),
    # Native bridges exposed to web content (prompt injection → native call)
    ("MG-S05", re.compile(r"\bonMessage\s*=\s*\{"), "react-native-webview postMessage bridge", JS),
    ("MG-S05", re.compile(r"addJavascriptInterface\s*\(|@JavascriptInterface"), "Android JS bridge", KT),
    ("MG-S05", re.compile(r"WKScriptMessageHandler|addScriptMessageHandler"), "WKWebView JS bridge", SWIFT),
    ("MG-S05", re.compile(r"addJavaScriptChannel|JavascriptChannel\("), "webview_flutter JS bridge", DART),
    # Agentic tool calling and ambient-agent entry points
    ("MG-S05", re.compile(r"\btool_calls\b|\btoolCalls\b|\bfunction_call\b|functionDeclarations|\btool_choice\b|\btoolChoice\b|\btools\s*:\s*[\[{]"),
     "LLM tool/function calling", None),
    ("MG-S05", re.compile(r":\s*(AppIntent|AppShortcutsProvider)\b|\bauthenticationPolicy\b|requestConfirmation\("),
     "App Intent exposed to Siri / Apple Intelligence", SWIFT),
    ("MG-S05", re.compile(r"@AppFunction\b|AppFunctionService"), "Android AppFunction exposed to system agents", KT),
    # Sensitive data reaching the model
    ("MG-S06", re.compile(r"expo-contacts|expo-calendar|expo-location|expo-media-library|react-native-health|"
                          r"CNContactStore|HKHealthStore|ContactsContract|HealthConnect|getClipboard|Clipboard\.getString",
                          re.I), "sensitive data source — check whether it reaches a prompt", None),
    # Storage at rest
    ("MG-S07", re.compile(r"AsyncStorage\.setItem|new MMKV\(|createMMKV\(|UserDefaults\.standard\.set|"
                          r"getSharedPreferences|SharedPreferences\.getInstance|Hive\.openBox"),
     "unencrypted key-value storage — check for chat history or user API keys", None),
    # Logs and telemetry
    ("MG-S08", re.compile(r"console\.(log|info|debug)\s*\([^)]*(prompt|response|completion|message|content)", re.I),
     "AI payload logged (survives in release unless stripped)", JS),
    ("MG-S08", re.compile(r"\b(print|NSLog|os_log|Log\.[dvi]|debugPrint)\s*\([^)]*(prompt|response|completion)", re.I),
     "AI payload logged", None),
    ("MG-S08", re.compile(r"Sentry\.(addBreadcrumb|setContext|captureMessage)|crashlytics\(\)\.(log|setAttribute)|"
                          r"posthog\.capture|mixpanel\.track|analytics\(\)\.logEvent|amplitude\.track", re.I),
     "third-party telemetry — check whether prompts/responses are attached", None),
    # Transport
    ("MG-S10", re.compile(r"['\"]http://(?!localhost|127\.0\.0\.1|10\.0\.2\.2|0\.0\.0\.0)[\w.-]+[^'\"]*(v1|api|chat|completions|generate)", re.I),
     "cleartext AI-looking endpoint", None),
    ("MG-S10", re.compile(r"X509TrustManager|HostnameVerifier\s*\{|ALLOW_ALL_HOSTNAME|"
                          r"\.useCredential,\s*URLCredential\(trust|badCertificateCallback"),
     "TLS validation override", None),
    # Supply chain: downloaded models, OTA
    ("MG-S11", re.compile(r"huggingface\.co/[^'\"\s]+/resolve/|\.(gguf|tflite|onnx|pte|mlmodel)['\"]", re.I),
     "model download — check pinned revision + hash verification", None),
    ("MG-R06", re.compile(r"from ['\"]expo-updates['\"]|react-native-code-push|@hot-updater|@revopush|"
                          r"Updates\.(fetchUpdateAsync|reloadAsync)"), "OTA JS updates", JS),
    # Store-review behaviours
    ("MG-R04", re.compile(r"moderations|safetySettings|HarmCategory|HarmBlockThreshold|content_filter|"
                          r"\breport(Message|Content|Response|Abuse)?\b", re.I),
     "moderation / reporting signal (absence near AI output is the lead)", None),
    ("MG-R01", re.compile(r"(consent|agree|allow|permission)[^\n]{0,60}(\bAI\b|OpenAI|Anthropic|Gemini|Claude|ChatGPT|third[- ]party)|"
                          r"(\bAI\b|OpenAI|Anthropic|Gemini|Claude|ChatGPT)[^\n]{0,60}(consent|agree|share|sent to)", re.I),
     "AI consent / disclosure copy", None),
    ("MG-R06", re.compile(r"remoteConfig|RemoteConfig|getFeatureFlag|isFeatureEnabled|useFeatureFlag|"
                          r"statsig|launchdarkly|growthbook|unleash", re.I),
     "remote feature flag — check whether AI features are dark during review (2.3.1)", None),
    ("MG-R07", re.compile(r"@stripe/stripe-react-native|stripe\.|PaymentSheet|react-native-purchases|"
                          r"react-native-iap|expo-iap|BillingClient|StoreKit|Purchases\.", re.I),
     "payment path — check what AI credits/subscriptions use", None),
    ("MG-R10", re.compile(r"deleteAccount|delete_account|accountDeletion|removeAccount", re.I),
     "account deletion — check AI history / provider-side data is included", None),
]

PLIST_KEYS = re.compile(
    r"<key>(NS(Microphone|SpeechRecognition|Camera|PhotoLibrary|PhotoLibraryAdd|Contacts|Calendars|"
    r"LocationWhenInUse|LocationAlways\w*|Health\w*)UsageDescription)</key>\s*<string>([^<]*)</string>"
)
BRAND = re.compile(r"\b(ChatGPT|GPT-?\d?|OpenAI|Gemini|Claude|Copilot|Grok|Midjourney)\b", re.I)


def iter_files(root: Path) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.endswith((".xcassets", ".lproj"))]
        for name in filenames:
            yield Path(dirpath) / name


def read(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def mask(secret: str) -> str:
    return secret[:7] + "…" + secret[-3:] if len(secret) > 12 else "…"


class Surface:
    def __init__(self, root: Path, max_per_check: int) -> None:
        self.root = root
        self.max_per_check = max_per_check
        self.stack: set[str] = set()
        self.ai_deps: list[dict[str, str]] = []
        self.leads: dict[str, list[dict[str, object]]] = defaultdict(list)
        self.overflow: dict[str, int] = defaultdict(int)
        self.config: dict[str, object] = defaultdict(list)
        self.ai_files: set[str] = set()

    def rel(self, path: Path) -> str:
        return path.relative_to(self.root).as_posix()

    def lead(self, check: str, path: str, line: int | None, note: str, evidence: str) -> None:
        bucket = self.leads[check]
        if len(bucket) >= self.max_per_check:
            self.overflow[check] += 1
            return
        bucket.append({
            "file": path, "line": line, "note": note, "evidence": evidence.strip()[:160],
            "test_code": bool(TEST_PATH.search(path)),
        })

    # ── manifests ────────────────────────────────────────────────────────────
    def package_json(self, path: Path, text: str) -> None:
        try:
            data = json.loads(text)
        except ValueError:
            return
        deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        if "react-native" in deps or "expo" in deps:
            self.stack.add("react-native")
        if "expo" in deps:
            self.stack.add("expo")
        for name in deps:
            if re.search(r"stripe|react-native-purchases|react-native-iap|expo-iap|braintree|paypal", name):
                self.config["payment_packages"].append(name)
            for pat, provider, kind in NPM_AI:
                if re.search(pat, name):
                    dev = name in data.get("devDependencies", {})
                    self.ai_deps.append({"package": name, "provider": provider, "kind": kind,
                                         "file": self.rel(path), "dev_only": str(dev).lower()})
                    break

    def pubspec(self, path: Path, text: str) -> None:
        self.stack.add("flutter")
        in_deps = False
        for i, line in enumerate(text.splitlines(), 1):
            if re.match(r"^(dev_)?dependencies:", line):
                in_deps = True
                continue
            if in_deps and re.match(r"^\S", line):
                in_deps = False
            m = re.match(r"^\s{2}([a-z0-9_]+):", line)
            if in_deps and m:
                for pat, provider, kind in DART_AI:
                    if re.search(pat, m.group(1)):
                        self.ai_deps.append({"package": m.group(1), "provider": provider,
                                             "kind": kind, "file": self.rel(path), "dev_only": "false"})
            if re.match(r"^\s+-\s+\.env\b", line):
                self.lead("MG-S01", self.rel(path), i, ".env is bundled as a Flutter asset", line)

    def app_config(self, path: Path, text: str) -> None:
        rel = self.rel(path)
        if '"privacyManifests"' in text or "privacyManifests" in text:
            self.config["privacy_manifest_files"].append(rel + " (expo ios.privacyManifests)")
            self._privacy_manifest_text(rel, text)
        for m in re.finditer(r"\"(name|displayName)\"\s*:\s*\"([^\"]+)\"", text):
            if BRAND.search(m.group(2)):
                self.lead("MG-R08", rel, text[: m.start()].count("\n") + 1,
                          "provider brand in app name (4.1(c) / Play impersonation)", m.group(0))
        if re.search(r"\"codeSigningCertificate\"", text):
            self.config["ota_code_signing"].append(rel)
        for m in re.finditer(r"\"(RECORD_AUDIO|android\.permission\.RECORD_AUDIO|READ_CONTACTS|"
                             r"ACCESS_FINE_LOCATION|READ_MEDIA_IMAGES)\"", text):
            self.config["android_permissions"].append(f"{rel}: {m.group(1)}")

    def info_plist(self, path: Path, text: str) -> None:
        rel = self.rel(path)
        for m in PLIST_KEYS.finditer(text):
            self.config["ios_purpose_strings"].append({"file": rel, "key": m.group(1), "text": m.group(3)})
        if re.search(r"<key>NSAllowsArbitraryLoads</key>\s*<true/>", text):
            self.lead("MG-S10", rel, None, "ATS disabled globally", "NSAllowsArbitraryLoads = true")
        m = re.search(r"<key>CFBundleDisplayName</key>\s*<string>([^<]+)</string>", text)
        if m and BRAND.search(m.group(1)):
            self.lead("MG-R08", rel, None, "provider brand in display name", m.group(1))

    def _privacy_manifest_text(self, rel: str, text: str) -> None:
        tracking = re.search(r"NSPrivacyTrackingDomains(.{0,2000})", text, re.S)
        if tracking and AI_HOSTS.search(tracking.group(1)[:2000]):
            self.lead("MG-R02", rel, None,
                      "AI host listed in NSPrivacyTrackingDomains — iOS blocks these requests until ATT is granted",
                      AI_HOSTS.search(tracking.group(1)).group(0))
        collected = re.findall(r"NSPrivacyCollectedDataType\w+", text)
        self.config["privacy_collected_types"] = sorted(set(collected) - {"NSPrivacyCollectedDataTypes",
                                                                          "NSPrivacyCollectedDataTypeLinked",
                                                                          "NSPrivacyCollectedDataTypeTracking",
                                                                          "NSPrivacyCollectedDataTypePurposes",
                                                                          "NSPrivacyCollectedDataTypePurpose",
                                                                          "NSPrivacyCollectedDataType"})

    def android_manifest(self, path: Path, text: str) -> None:
        self.stack.add("android")
        rel = self.rel(path)
        for attr in ("usesCleartextTraffic=\"true\"", "allowBackup=\"true\""):
            if attr in text:
                check = "MG-S10" if "Cleartext" in attr else "MG-S07"
                self.lead(check, rel, text[: text.index(attr)].count("\n") + 1, f"android:{attr}", attr)
        for m in re.finditer(r"android\.permission\.(RECORD_AUDIO|READ_CONTACTS|READ_SMS|SEND_SMS|"
                             r"ACCESS_FINE_LOCATION|READ_MEDIA_\w+|FOREGROUND_SERVICE_MICROPHONE|"
                             r"BIND_ACCESSIBILITY_SERVICE|QUERY_ALL_PACKAGES)", text):
            self.config["android_permissions"].append(f"{rel}: {m.group(1)}")
        m = re.search(r"android:label=\"([^\"@]+)\"", text)
        if m and BRAND.search(m.group(1)):
            self.lead("MG-R08", rel, None, "provider brand in app label", m.group(1))

    # ── source ───────────────────────────────────────────────────────────────
    def source(self, path: Path, text: str) -> None:
        rel = self.rel(path)
        ext = path.suffix.lower()
        server_side = bool(re.search(r"\+api\.[jt]sx?$|(^|/)(server|backend|functions|supabase/functions|api)/", rel))
        if ext in SWIFT:
            self.stack.add("ios")
        elif ext in KT:
            self.stack.add("android")
        for i, line in enumerate(text.splitlines(), 1):
            if len(line) > 600:
                continue
            host = AI_HOSTS.search(line)
            if host:
                self.ai_files.add(rel)
                self.config["ai_endpoints"].append(f"{host.group(0)} @ {rel}:{i}" + (" [server]" if server_side else ""))
            for pat, provider, _kind in NATIVE_AI:
                if ext in SWIFT | KT | {".gradle"} and re.search(pat, line):
                    self.ai_files.add(rel)
                    self.config["native_ai_imports"].append(f"{provider} @ {rel}:{i}")
            if re.search(r"from ['\"](openai|@anthropic-ai/sdk|@google/(generative-ai|genai)|ai|@ai-sdk/\w+|"
                         r"groq-sdk|llama\.rn|react-native-executorch|@react-native-firebase/(ai|vertexai)|firebase/(ai|vertexai))['\"]", line):
                self.ai_files.add(rel)
            k = KEY_FORMATS.search(line)
            if k:
                self.lead("MG-S01", rel, i, "provider key literal" + (" (server-side file)" if server_side else ""),
                          line.replace(k.group(0), mask(k.group(0))))
            for check, pat, note, exts in LEADS:
                if exts is not None and ext not in exts:
                    continue
                if pat.search(line):
                    self.lead(check, rel, i, note + (" [server-side file]" if server_side else ""), line)

    def secret_file(self, path: Path, text: str) -> None:
        rel = self.rel(path)
        for i, line in enumerate(text.splitlines(), 1):
            k = KEY_FORMATS.search(line)
            if k:
                public = "EXPO_PUBLIC_" in line
                self.lead("MG-S01", rel, i,
                          "provider key in config file" + (" — EXPO_PUBLIC_ is bundled" if public else ""),
                          line.replace(k.group(0), mask(k.group(0))))

    def run(self) -> dict[str, object]:
        for path in iter_files(self.root):
            name = path.name
            rel = self.rel(path)
            ext = path.suffix.lower()
            if name in CONFIG_NAMES or ext in SOURCE_EXTS or ext == ".gradle" or SECRET_FILE.search(rel):
                text = read(path)
                if text is None:
                    continue
            else:
                continue
            if name == "package.json":
                self.package_json(path, text)
            elif name == "pubspec.yaml":
                self.pubspec(path, text)
            elif name in ("app.json", "app.config.js", "app.config.ts"):
                self.app_config(path, text)
                self.secret_file(path, text)
            elif name == "Info.plist":
                self.info_plist(path, text)
                self.secret_file(path, text)
            elif name == "PrivacyInfo.xcprivacy":
                self.config["privacy_manifest_files"].append(rel)
                self._privacy_manifest_text(rel, text)
            elif name == "AndroidManifest.xml":
                self.android_manifest(path, text)
            elif name in ("build.gradle", "build.gradle.kts") or ext == ".gradle":
                self.stack.add("android")
                self.source(path, text)
            elif SECRET_FILE.search(rel) or name in ("gradle.properties", "local.properties", "eas.json"):
                self.secret_file(path, text)
            elif ext in SOURCE_EXTS:
                self.source(path, text)
            if name == "Podfile":
                self.stack.add("ios")

        ai_present = bool(self.ai_deps or self.ai_files or self.config.get("ai_endpoints"))
        return {
            "root": str(self.root),
            "stack": sorted(self.stack),
            "ai_present": ai_present,
            "ai_dependencies": self.ai_deps,
            "ai_files": sorted(self.ai_files),
            "config": dict(self.config.items()),
            "leads": {k: self.leads[k] for k in sorted(self.leads)},
            "leads_truncated": dict(self.overflow),
            "absent": self._absent(ai_present),
        }

    def _absent(self, ai_present: bool) -> list[str]:
        """Things a reviewed AI app is expected to have; absence is itself a lead."""
        if not ai_present:
            return []
        missing = []
        cloud = any(d["kind"] != "on-device" for d in self.ai_deps) or bool(self.config.get("ai_endpoints"))
        if cloud and "MG-R01" not in self.leads:
            missing.append("MG-R01: no AI consent/disclosure copy found")
        if "MG-R04" not in self.leads:
            missing.append("MG-R04: no moderation or in-app report path found")
        client_cap = any("[server-side file]" not in str(lead["note"]) for lead in self.leads.get("MG-S02", []))
        if cloud and not client_cap:
            missing.append("MG-S02: no token cap (max_tokens) in client code — confirm a server proxy enforces one")
        if ("ios" in self.stack or "expo" in self.stack) and not self.config.get("privacy_manifest_files"):
            missing.append("MG-R02: no PrivacyInfo.xcprivacy or expo ios.privacyManifests")
        if self.leads.get("MG-R06") and any("OTA" in str(lead["note"]) for lead in self.leads["MG-R06"]) \
                and not self.config.get("ota_code_signing"):
            missing.append("MG-S11: OTA updates without codeSigningCertificate")
        return missing


SNAPSHOT_CHECKS = {"MG-S01", "MG-S04", "MG-S05", "MG-S06", "MG-S07", "MG-S08", "MG-S10", "MG-S11",
                   "MG-R02", "MG-R06", "MG-R08"}


def snapshot(result: dict[str, object]) -> list[str]:
    """Reduce a run() result to sorted, line-number-free facts for ledger diffing."""
    facts: set[str] = {f"stack: {s}" for s in result["stack"]}  # type: ignore[union-attr]
    for dep in result["ai_dependencies"]:  # type: ignore[union-attr]
        if dep["dev_only"] != "true":
            facts.add(f"provider: {dep['provider']} [{dep['kind']}] ({dep['package']})")
    config = result["config"]
    for entry in config.get("ai_endpoints", []):  # type: ignore[union-attr]
        host, _, where = entry.partition(" @ ")
        if not TEST_PATH.search(where.split(":")[0]):
            facts.add(f"endpoint: {host}" + (" [server]" if where.endswith("[server]") else ""))
    for entry in config.get("native_ai_imports", []):  # type: ignore[union-attr]
        facts.add(f"provider: {entry.partition(' @ ')[0]}")
    for item in config.get("ios_purpose_strings", []):  # type: ignore[union-attr]
        facts.add(f"ios-purpose: {item['key']} = {item['text']}")
    for perm in config.get("android_permissions", []):  # type: ignore[union-attr]
        facts.add(f"android-permission: {perm.partition(': ')[2]}")
    for dtype in config.get("privacy_collected_types", []):  # type: ignore[union-attr]
        facts.add(f"privacy-collected: {dtype}")
    for pkg in config.get("payment_packages", []):  # type: ignore[union-attr]
        facts.add(f"payment: {pkg}")
    if config.get("ota_code_signing"):
        facts.add("ota-code-signing: on")
    for check, leads in result["leads"].items():  # type: ignore[union-attr]
        if check not in SNAPSHOT_CHECKS:
            continue
        for lead in leads:
            if not lead["test_code"]:
                facts.add(f"{check}: {lead['note']} @ {lead['file']}")
    for gap in result["absent"]:  # type: ignore[union-attr]
        facts.add(f"absent: {gap}")
    return sorted(facts)


def ledger_snapshot(ledger_text: str) -> list[str] | None:
    """Return the fact lines in the ledger's '## Snapshot' fenced block, or None if absent."""
    m = re.search(r"^## Snapshot[^\n]*\n+```[^\n]*\n(.*?)^```", ledger_text, re.S | re.M)
    if m is None:
        return None
    return [ln.strip() for ln in m.group(1).splitlines() if ln.strip() and not ln.strip().startswith("<")]


def diff_lines(before: list[str], after: list[str]) -> list[str]:
    """'+ fact' for new surface, '- fact' for removed surface, sorted by fact."""
    old, new = set(before), set(after)
    changes = [("+", f) for f in new - old] + [("-", f) for f in old - new]
    return [f"{sign} {fact}" for sign, fact in sorted(changes, key=lambda c: (c[1], c[0]))]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("repo", type=Path)
    parser.add_argument("--max-per-check", type=int, default=40)
    parser.add_argument("--snapshot", action="store_true", help="print ledger snapshot lines")
    parser.add_argument("--diff-ledger", type=Path, metavar="LEDGER",
                        help="diff the current snapshot against the ledger's Snapshot block")
    parser.add_argument("--fail-on-drift", action="store_true",
                        help="with --diff-ledger: exit 1 when the AI surface changed (for CI)")
    args = parser.parse_args(argv)
    root = args.repo.resolve()
    if not root.is_dir():
        print(f"not a directory: {root}", file=sys.stderr)
        return 2
    full = args.snapshot or args.diff_ledger is not None
    result = Surface(root, 10_000 if full else args.max_per_check).run()
    if args.diff_ledger is not None:
        try:
            recorded = ledger_snapshot(args.diff_ledger.read_text(encoding="utf-8"))
        except OSError as exc:
            print(f"cannot read ledger: {exc}", file=sys.stderr)
            return 2
        if recorded is None:
            print("ledger has no Snapshot block — treat this as a first submission", file=sys.stderr)
            return 3
        changes = diff_lines(recorded, snapshot(result))
        print("\n".join(changes) if changes else "no drift")
        return 1 if changes and args.fail_on_drift else 0
    if args.snapshot:
        print("\n".join(snapshot(result)))
    else:
        json.dump(result, sys.stdout, indent=2)
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
