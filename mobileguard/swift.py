# Copyright 2026 Jaspreet Singh
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Swift/iOS pattern detector for MobileGuard.

Detects governance violations in .swift and .plist files. All detection is
purely static (regex-based) — no LLM calls. Maps to App Store (AS-xxx),
EU AI Act (EU-xxx), and OWASP (OW-xxx) rule categories.
"""

from __future__ import annotations

import re
from pathlib import Path

from mobileguard.models import Finding
from mobileguard.rules import APP_STORE_RULES, EU_AI_ACT_RULES, OWASP_RULES

# ── Compiled patterns ──────────────────────────────────────────────────────────

_AI_DOMAIN = re.compile(
    r"https?://(?:api\.openai\.com|api\.anthropic\.com|"
    r"generativelanguage\.googleapis\.com|[\w\-]+\.openai\.azure\.com|"
    r"api\.cohere\.ai|api\.mistral\.ai|api\.groq\.com|api\.together\.xyz)",
    re.IGNORECASE,
)

_DISCLOSURE = re.compile(
    r"PrivacyDisclosureView|ATTrackingManager|requestTrackingAuthorization",
)

_API_KEY = re.compile(
    r"""["'](sk-ant-[A-Za-z0-9\-_]{10,}|sk-[A-Za-z0-9\-_]{20,}|AIza[A-Za-z0-9\-_]{25,})["']"""
)

_APP_INTENT = re.compile(r":\s*AppIntent\b")
_SENSITIVE_SCOPE = re.compile(
    r"CNContactStore|\.calendars|HKHealthStore|CLLocationManager|PHPhotoLibrary",
)
_AUTH_CALL = re.compile(
    r"requestAuthorization|requestAccess|requestPermission",
)

# Generic boilerplate privacy strings flagged by App Store reviewers
_GENERIC_PRIVACY = re.compile(
    r"(?:This app uses your data to improve your experience|"
    r"We collect data for analytics purposes|"
    r"Used to improve app performance)",
    re.IGNORECASE,
)

_PRIVACY_KEY_USAGE = re.compile(
    r"NS(?:Location|Camera|Microphone|Contacts|Calendar|Photo|Health|Motion)"
    r"(?:WhenInUse|Always)?UsageDescription",
)

# OW-001: user-controlled variables interpolated into strings (Swift string interpolation)
_USER_INPUT_INTERP = re.compile(
    r'\\\((?:user(?:Message|Input|Text|Query|Prompt|Content|Request)|'
    r'message|query|inputText|userText|prompt)\b',
    re.IGNORECASE,
)

_WEBVIEW_LOAD = re.compile(r"loadHTMLString\s*\(|WKWebView\b.*load", re.IGNORECASE)

_PII_VARS = re.compile(
    r'\b(?:email|ssn|creditCard|credit_card|password|phoneNumber|phone_number|'
    r'socialSecurity|passport)\b',
    re.IGNORECASE,
)

_USERDEFAULTS_STORE = re.compile(
    r"UserDefaults\.standard\.set\s*\([^)]*\)",
    re.IGNORECASE,
)

_LOG_CALL = re.compile(
    r"Logger\.|os_log\b|OSLog|print\s*\(|NSLog\b|analytics\.|Analytics\.|"
    r"Crashlytics\.|FirebaseAnalytics\.",
    re.IGNORECASE,
)

_RATE_LIMIT = re.compile(
    r"rateLimit|rate_limit|throttle|Throttle|debounce|maxRequests|requestBudget",
    re.IGNORECASE,
)

_NSPrivacy = re.compile(r"NSPrivacyCollectedDataTypes")

# AS-010: Platform references to non-Apple platforms in user-facing strings
# Common when AI tools port Android apps to iOS (Guideline 2.3.7)
_PLATFORM_REF = re.compile(
    r'(?:["\'`]|Text\s*\(|Label\s*\(|string\s*=\s*")[^"\'`\n]*'
    r'\b(Android|Google Play|Play Store|Google Play Store|'
    r'Windows Phone|Windows App|PC version|desktop app|'
    r'available on Android|download on Android|Android version)\b',
    re.IGNORECASE,
)

# AS-011: Placeholder / incomplete content in user-facing strings (Guideline 2.1)
# Apple 2024 Transparency Report: 40%+ of unresolved rejections cite App Completeness
_PLACEHOLDER_CONTENT = re.compile(
    r'(?:["\'`]|Text\s*\(|Label\s*\(|title\s*=\s*"|message\s*=\s*")[^"\'`\n]*'
    r'\b(Lorem\s+ipsum|Coming\s+Soon|Under\s+Construction|'
    r'Placeholder\s+Text|Sample\s+Text|Test\s+Content|'
    r'TBD\b|TODO\b|FIXME\b|Insert\s+Text\s+Here|'
    r'Your\s+text\s+here|Add\s+content\s+here)\b',
    re.IGNORECASE,
)

# AS-012: Vague permission usage descriptions in Info.plist (Guideline 5.1.1)
# Statista 2024: ~1/3 of rejections cite missing/inconsistent privacy explanations
_VAGUE_PERMISSION = re.compile(
    r'<string>\s*(?:'
    r'(?:This app (?:needs|requires|uses) (?:your |access to )?'
    r'(?:camera|microphone|location|contacts|photos?|health|motion)(?:\s+access)?\.?)'
    r'|(?:(?:Camera|Microphone|Location|Contacts?|Photos?|Health|Motion)'
    r'\s+(?:access\s+)?(?:needed|required|permission|is required)\.?)'
    r'|(?:For (?:camera|microphone|location|contacts?|photos?|health|motion)'
    r'\s+(?:access|functionality)\.?)'
    r'|(?:Required for (?:app|this app|the app)\.?)'
    r'|(?:Used (?:to improve|for) (?:app|this app|the app)\.?)'
    r')\s*</string>',
    re.IGNORECASE,
)

# Lines where an AI domain URL appears in a non-call context: HTML/JSX attribute,
# comment, or JSDoc. These should not trigger disclosure or rate-limit findings.
_NON_CALL_CTX = re.compile(
    r'placeholder\s*=|\bhref\s*=|^\s*[*/]|^\s*#|@param\b|@default\b',
    re.IGNORECASE,
)


def detect(file_path: str, content: str) -> list[Finding]:
    """Detect governance violations in a Swift or plist file."""
    path = Path(file_path)
    suffix = path.suffix.lower()

    if suffix == ".plist":
        return _detect_plist(file_path, content)
    return _detect_swift(file_path, content)


def _detect_swift(file_path: str, content: str) -> list[Finding]:
    """Run all Swift detectors and return combined findings."""
    lines = content.splitlines()
    findings: list[Finding] = []

    has_real_ai_call = any(
        bool(_AI_DOMAIN.search(ln)) and not _NON_CALL_CTX.search(ln)
        for ln in lines
    )
    has_ai_call = has_real_ai_call  # cleared after first AS-001 report (dedup)
    has_disclosure = bool(_DISCLOSURE.search(content))
    has_log = bool(_LOG_CALL.search(content))
    has_rate_limit = bool(_RATE_LIMIT.search(content))

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()

        # AS-001: AI domain call without disclosure
        if (has_ai_call and not has_disclosure
                and _AI_DOMAIN.search(line) and not _NON_CALL_CTX.search(line)):
            rule = APP_STORE_RULES["AS-001"]
            findings.append(
                Finding(
                    rule_id=rule.id,
                    severity=rule.severity,
                    category=rule.category,
                    description=rule.description,
                    file_path=file_path,
                    line_number=i,
                    evidence=stripped,
                    fix=rule.fix,
                    reference=rule.reference,
                    pillar=rule.pillar,
                )
            )
            has_ai_call = False  # report once per file

        # AS-002: hardcoded API key
        m = _API_KEY.search(line)
        if m:
            rule = APP_STORE_RULES["AS-002"]
            key_preview = m.group(1)[:12] + "..."
            findings.append(
                Finding(
                    rule_id=rule.id,
                    severity=rule.severity,
                    category=rule.category,
                    description=rule.description,
                    file_path=file_path,
                    line_number=i,
                    evidence=f'Found: "{key_preview}" in string literal',
                    fix=rule.fix,
                    reference=rule.reference,
                    pillar=rule.pillar,
                )
            )

        # AS-003: AppIntent without authorization for sensitive scope
        if _APP_INTENT.search(line):
            block_content = "\n".join(lines[max(0, i - 1) : min(len(lines), i + 50)])
            if _SENSITIVE_SCOPE.search(block_content) and not _AUTH_CALL.search(block_content):
                rule = APP_STORE_RULES["AS-003"]
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        severity=rule.severity,
                        category=rule.category,
                        description=rule.description,
                        file_path=file_path,
                        line_number=i,
                        evidence=stripped,
                        fix=rule.fix,
                        reference=rule.reference,
                        pillar=rule.pillar,
                    )
                )

        # AS-005: AI call in file, no NSPrivacyCollectedDataTypes in project
        # (file-level check — project-level check is in scanner.py)

        # EU-001: AI API call without disclosure label in same file
        if (_AI_DOMAIN.search(line) and not _NON_CALL_CTX.search(line)
                and not _DISCLOSURE.search(content)):
            rule = EU_AI_ACT_RULES["EU-001"]
            findings.append(
                Finding(
                    rule_id=rule.id,
                    severity=rule.severity,
                    category=rule.category,
                    description=rule.description,
                    file_path=file_path,
                    line_number=i,
                    evidence=stripped,
                    fix=rule.fix,
                    reference=rule.reference,
                    pillar=rule.pillar,
                )
            )

        # EU-003: AI call without any logging in the file
        if _AI_DOMAIN.search(line) and not _NON_CALL_CTX.search(line) and not has_log:
            rule = EU_AI_ACT_RULES["EU-003"]
            findings.append(
                Finding(
                    rule_id=rule.id,
                    severity=rule.severity,
                    category=rule.category,
                    description=rule.description,
                    file_path=file_path,
                    line_number=i,
                    evidence=stripped,
                    fix=rule.fix,
                    reference=rule.reference,
                    pillar=rule.pillar,
                )
            )
            has_log = True  # report once per file

        # OW-001: user input interpolated into prompt string
        if has_real_ai_call and _USER_INPUT_INTERP.search(line):
            rule = OWASP_RULES["OW-001"]
            findings.append(
                Finding(
                    rule_id=rule.id,
                    severity=rule.severity,
                    category=rule.category,
                    description=rule.description,
                    file_path=file_path,
                    line_number=i,
                    evidence=stripped,
                    fix=rule.fix,
                    reference=rule.reference,
                    pillar=rule.pillar,
                )
            )

        # OW-002: AI output loaded into WebView without visible sanitization
        if _WEBVIEW_LOAD.search(line) and has_real_ai_call:
            rule = OWASP_RULES["OW-002"]
            findings.append(
                Finding(
                    rule_id=rule.id,
                    severity=rule.severity,
                    category=rule.category,
                    description=rule.description,
                    file_path=file_path,
                    line_number=i,
                    evidence=stripped,
                    fix=rule.fix,
                    reference=rule.reference,
                    pillar=rule.pillar,
                )
            )

        # OW-003: PII variable passed to AI API in same file
        if has_real_ai_call and _PII_VARS.search(line):
            rule = OWASP_RULES["OW-003"]
            findings.append(
                Finding(
                    rule_id=rule.id,
                    severity=rule.severity,
                    category=rule.category,
                    description=rule.description,
                    file_path=file_path,
                    line_number=i,
                    evidence=stripped,
                    fix=rule.fix,
                    reference=rule.reference,
                    pillar=rule.pillar,
                )
            )

        # OW-004: UserDefaults storing data when AI is used in the file
        if _USERDEFAULTS_STORE.search(line) and has_real_ai_call:
            rule = OWASP_RULES["OW-004"]
            findings.append(
                Finding(
                    rule_id=rule.id,
                    severity=rule.severity,
                    category=rule.category,
                    description=rule.description,
                    file_path=file_path,
                    line_number=i,
                    evidence=stripped,
                    fix=rule.fix,
                    reference=rule.reference,
                    pillar=rule.pillar,
                )
            )

        # OW-005: AI API call with no rate limiting anywhere in the file
        if _AI_DOMAIN.search(line) and not _NON_CALL_CTX.search(line) and not has_rate_limit:
            rule = OWASP_RULES["OW-005"]
            findings.append(
                Finding(
                    rule_id=rule.id,
                    severity=rule.severity,
                    category=rule.category,
                    description=rule.description,
                    file_path=file_path,
                    line_number=i,
                    evidence=stripped,
                    fix=rule.fix,
                    reference=rule.reference,
                    pillar=rule.pillar,
                )
            )
            has_rate_limit = True  # report once per file

        # AS-010: Platform references to non-Apple platforms (Guideline 2.3.7)
        m = _PLATFORM_REF.search(line)
        if m:
            rule = APP_STORE_RULES["AS-010"]
            findings.append(
                Finding(
                    rule_id=rule.id,
                    severity=rule.severity,
                    category=rule.category,
                    description=rule.description,
                    file_path=file_path,
                    line_number=i,
                    evidence=f'Platform reference: "{m.group(1)}" in user-facing string',
                    fix=rule.fix,
                    reference=rule.reference,
                    pillar=rule.pillar,
                )
            )

        # AS-011: Placeholder content in user-facing strings (Guideline 2.1)
        m = _PLACEHOLDER_CONTENT.search(line)
        if m:
            rule = APP_STORE_RULES["AS-011"]
            findings.append(
                Finding(
                    rule_id=rule.id,
                    severity=rule.severity,
                    category=rule.category,
                    description=rule.description,
                    file_path=file_path,
                    line_number=i,
                    evidence=f'Placeholder detected: "{m.group(1)}"',
                    fix=rule.fix,
                    reference=rule.reference,
                    pillar=rule.pillar,
                )
            )

    return findings


def _detect_plist(file_path: str, content: str) -> list[Finding]:
    """Detect AS-004 and AS-005 violations in Info.plist files."""
    lines = content.splitlines()
    findings: list[Finding] = []

    has_privacy_key = bool(_PRIVACY_KEY_USAGE.search(content))
    has_ai_ref = bool(_AI_DOMAIN.search(content))

    for i, line in enumerate(lines, start=1):
        # AS-004: generic privacy description
        if has_privacy_key and _GENERIC_PRIVACY.search(line):
            rule = APP_STORE_RULES["AS-004"]
            findings.append(
                Finding(
                    rule_id=rule.id,
                    severity=rule.severity,
                    category=rule.category,
                    description=rule.description,
                    file_path=file_path,
                    line_number=i,
                    evidence=line.strip(),
                    fix=rule.fix,
                    reference=rule.reference,
                    pillar=rule.pillar,
                )
            )

    # AS-005: AI used but no NSPrivacyCollectedDataTypes
    if has_ai_ref and not _NSPrivacy.search(content):
        rule = APP_STORE_RULES["AS-005"]
        findings.append(
            Finding(
                rule_id=rule.id,
                severity=rule.severity,
                category=rule.category,
                description=rule.description,
                file_path=file_path,
                line_number=None,
                evidence=None,
                fix=rule.fix,
                reference=rule.reference,
                pillar=rule.pillar,
            )
        )

    # AS-012: Vague permission usage descriptions (Guideline 5.1.1)
    # Statista 2024: ~1/3 of rejections cite missing/inconsistent privacy explanations
    for i, line in enumerate(lines, start=1):
        m = _VAGUE_PERMISSION.search(line)
        if m:
            rule = APP_STORE_RULES["AS-012"]
            findings.append(
                Finding(
                    rule_id=rule.id,
                    severity=rule.severity,
                    category=rule.category,
                    description=rule.description,
                    file_path=file_path,
                    line_number=i,
                    evidence=f"Vague permission string: {line.strip()[:100]}",
                    fix=rule.fix,
                    reference=rule.reference,
                    pillar=rule.pillar,
                )
            )

    return findings
