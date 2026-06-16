# Copyright 2026 Jaspreet Singh
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""AS-007: Guideline 2.5.2 architectural violation detector.

Real rejection evidence:
March 18, 2026 — The Information: Apple blocked Replit ($9B valuation) and
Vibecode from releasing App Store updates for executing AI-generated code in
in-app WKWebView instances.

March 30, 2026 — Apple pulled "Anything" app entirely for the same pattern.
App was rejected again for "minimum functionality" after removing the preview
feature, then briefly reinstated, then removed again within a day.
(9to5Mac, March 30 2026; vativeapps.com, June 2026)

The fix Apple required: "Replit has been told to stop previewing generated
apps inside its own iOS client. Any newly created software must open in an
external browser." (The Information, March 18 2026)

Apple Guideline 2.5.2: "Apps should be self-contained in their bundles, and
may not read or write data outside the designated container area, nor may they
download, install, or execute code which introduces or changes features or
functionality of the app."
"""

from __future__ import annotations

import re
from pathlib import Path

from mobileguard.models import Finding
from mobileguard.rules.app_store import RULES as APP_STORE_RULES

# ── Swift patterns ─────────────────────────────────────────────────────────────

# Pattern A: loadHTMLString with non-literal first arg (variable = AI content)
# Safe:      webView.loadHTMLString("<html>static</html>", baseURL: nil)
# Violation: webView.loadHTMLString(aiResponse, baseURL: nil)
_WK_LOAD_HTML_VAR = re.compile(
    r'\.loadHTMLString\(\s*(?!"[^"]*")[a-zA-Z_][a-zA-Z0-9_]*',
)

# Pattern B: evaluateJavaScript with non-literal first arg
# Violation: webView.evaluateJavaScript(generatedCode, completionHandler: nil)
_EVAL_JS_VAR = re.compile(
    r'\.evaluateJavaScript\(\s*(?!"[^"]*")[a-zA-Z_][a-zA-Z0-9_]*',
)

# Pattern C: JSContext.evaluateScript with non-literal first arg
# Violation: context.evaluateScript(aiOutput)
_EVAL_SCRIPT_VAR = re.compile(
    r'\.evaluateScript\(\s*(?!"[^"]*")[a-zA-Z_][a-zA-Z0-9_]*',
)

# Pattern D: URLRequest built from a non-literal URL variable
# Violation: webView.load(URLRequest(url: URL(string: aiGeneratedURL)!))
_URLREQUEST_DYNAMIC = re.compile(
    r'URLRequest\(url:\s*URL\(string:\s*(?!"https://)[a-zA-Z_]',
)

# ── Kotlin/Android patterns ────────────────────────────────────────────────────

# WebView.loadData with a variable first arg (not a string literal)
_ANDROID_LOAD_DATA = re.compile(
    r'\.loadData\(\s*(?!"[^"]*")[a-zA-Z_][a-zA-Z0-9_]*',
    re.IGNORECASE,
)

# WebView.loadDataWithBaseURL with variable second arg (data content)
_ANDROID_LOAD_DATA_URL = re.compile(
    r'\.loadDataWithBaseURL\([^,]*,\s*(?!"[^"]*")[a-zA-Z_]',
    re.IGNORECASE,
)

# WebView.evaluateJavascript with a variable first arg
_ANDROID_EVAL_JS = re.compile(
    r'\.evaluateJavascript\(\s*(?!"[^"]*")[a-zA-Z_]',
    re.IGNORECASE,
)

_SKIP_DIRS = {
    "Pods", "node_modules", ".build", "DerivedData", "Packages",
    ".git", ".github", ".mobileguard", "build", "dist", ".gradle", "__pycache__",
}


def check_code_execution(root: Path) -> list[Finding]:
    """Detect AS-007: dynamic content execution in WebView (Guideline 2.5.2).

    Scans Swift and Kotlin files for WKWebView/WebView patterns that load
    or evaluate dynamic (non-literal) content — the pattern Apple blocked
    Replit and Vibecode for in March 2026.
    """
    rule = APP_STORE_RULES["AS-007"]
    findings: list[Finding] = []

    for f in root.rglob("*"):
        if not f.is_file():
            continue
        if any(part in _SKIP_DIRS for part in f.parts):
            continue
        suffix = f.suffix.lower()
        if suffix not in {".swift", ".kt", ".kts"}:
            continue
        try:
            content = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        rel = str(f.relative_to(root))
        lines = content.splitlines()

        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            matched = False

            if suffix == ".swift":
                matched = bool(
                    _WK_LOAD_HTML_VAR.search(line)
                    or _EVAL_JS_VAR.search(line)
                    or _EVAL_SCRIPT_VAR.search(line)
                    or _URLREQUEST_DYNAMIC.search(line)
                )
            elif suffix in {".kt", ".kts"}:
                matched = bool(
                    _ANDROID_LOAD_DATA.search(line)
                    or _ANDROID_LOAD_DATA_URL.search(line)
                    or _ANDROID_EVAL_JS.search(line)
                )

            if matched:
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        severity=rule.severity,
                        category=rule.category,
                        description=rule.description,
                        file_path=rel,
                        line_number=i,
                        evidence=stripped[:120],
                        fix=rule.fix,
                        reference=rule.reference,
                        pillar=rule.pillar,
                    )
                )

    return findings
