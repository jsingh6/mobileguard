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

    has_ai_call = bool(_AI_DOMAIN.search(content))
    has_disclosure = bool(_DISCLOSURE.search(content))
    has_log = bool(_LOG_CALL.search(content))
    has_rate_limit = bool(_RATE_LIMIT.search(content))

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()

        # AS-001: AI domain call without disclosure
        if has_ai_call and not has_disclosure and _AI_DOMAIN.search(line):
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
        if _AI_DOMAIN.search(line) and not _DISCLOSURE.search(content):
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
        if _AI_DOMAIN.search(line) and not has_log:
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
        if _AI_DOMAIN.search(content) and _USER_INPUT_INTERP.search(line):
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
        if _WEBVIEW_LOAD.search(line) and _AI_DOMAIN.search(content):
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
        if _AI_DOMAIN.search(content) and _PII_VARS.search(line):
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
        if _USERDEFAULTS_STORE.search(line) and _AI_DOMAIN.search(content):
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
        if _AI_DOMAIN.search(line) and not has_rate_limit:
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

    return findings
