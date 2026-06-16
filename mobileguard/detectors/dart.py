# Copyright 2026 Jaspreet Singh
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Flutter/Dart pattern detector for MobileGuard.

Detects governance violations in .dart files. Dart targets both iOS (App Store)
and Android (Google Play), so this detector reports violations from both AS-xxx
and GP-xxx rule sets in addition to EU-xxx and OW-xxx.
"""

from __future__ import annotations

import re

from mobileguard.models import Finding
from mobileguard.rules import APP_STORE_RULES, EU_AI_ACT_RULES, GOOGLE_PLAY_RULES, OWASP_RULES

# ── Compiled patterns ──────────────────────────────────────────────────────────

_AI_DOMAIN = re.compile(
    r"https?://(?:api\.openai\.com|api\.anthropic\.com|"
    r"generativelanguage\.googleapis\.com|[\w\-]+\.openai\.azure\.com|"
    r"api\.cohere\.ai|api\.mistral\.ai|api\.groq\.com)",
    re.IGNORECASE,
)

_HTTP_CALL = re.compile(r"\bhttp\.(?:post|get|put|patch)\b|\bDio\(\)", re.IGNORECASE)

_API_KEY = re.compile(
    r'''["'](sk-ant-[A-Za-z0-9\-_]{10,}|sk-[A-Za-z0-9\-_]{20,}|AIza[A-Za-z0-9\-_]{25,})["']'''
)

_DISCLOSURE = re.compile(
    r"AIDisclosureWidget|aiDisclosure|showAILabel|AIBadge|aiGenerated",
    re.IGNORECASE,
)

_USER_INPUT_INTERP = re.compile(
    r'\$\{?(?:user(?:Message|Input|Text|Query|Prompt)|message|query|userText|inputText)\b',
    re.IGNORECASE,
)

_WEBVIEW = re.compile(r"WebView\b|WebViewController\b|InAppWebView\b", re.IGNORECASE)

_PII_VARS = re.compile(
    r'\b(?:email|ssn|creditCard|credit_card|password|phoneNumber|phone_number|passport)\b',
    re.IGNORECASE,
)

_SHARED_PREFS = re.compile(
    r"SharedPreferences|getSharedPreferences|prefs\.setString", re.IGNORECASE
)

_LOG_CALL = re.compile(r"debugPrint\b|print\b|log\b|Logger\.|analytics\.", re.IGNORECASE)

_RATE_LIMIT = re.compile(r"rateLimit|rate_limit|throttle|debounce|maxRequests", re.IGNORECASE)

_PERMISSION_HANDLER = re.compile(r"permission_handler|Permission\.", re.IGNORECASE)

_ISOLATE_MISUSE = re.compile(r"compute\s*\(|Isolate\.spawn\b")

# Lines where an AI domain URL is in a non-call context (HTML/JSX attribute, comment, JSDoc)
_NON_CALL_CTX = re.compile(
    r'placeholder\s*=|\bhref\s*=|^\s*[*/]|^\s*#|@param\b|@default\b',
    re.IGNORECASE,
)


def detect(file_path: str, content: str) -> list[Finding]:
    """Detect governance violations in a Flutter/Dart file."""
    lines = content.splitlines()
    findings: list[Finding] = []

    has_ai_call = any(
        bool(_AI_DOMAIN.search(ln)) and not _NON_CALL_CTX.search(ln)
        for ln in lines
    )
    has_disclosure = bool(_DISCLOSURE.search(content))
    has_log = bool(_LOG_CALL.search(content))
    has_rate_limit = bool(_RATE_LIMIT.search(content))
    ai_call_line_nums = {
        i for i, ln in enumerate(lines, start=1)
        if _AI_DOMAIN.search(ln) and not _NON_CALL_CTX.search(ln)
    }

    reported: set[str] = set()

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()

        # AS-002 / GP-002: hardcoded API key
        m = _API_KEY.search(line)
        if m:
            key_preview = m.group(1)[:12] + "..."
            for rule in [APP_STORE_RULES["AS-002"], GOOGLE_PLAY_RULES["GP-002"]]:
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

        # AS-001 / GP-001: AI domain call without disclosure
        if _AI_DOMAIN.search(line) and not _NON_CALL_CTX.search(line):
            if "AS-001" not in reported and not has_disclosure:
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
                reported.add("AS-001")

            if "GP-001" not in reported and not has_disclosure:
                rule = GOOGLE_PLAY_RULES["GP-001"]
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
                reported.add("GP-001")

            # EU-001
            if "EU-001" not in reported and not has_disclosure:
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
                reported.add("EU-001")

            # EU-003: no logging
            if "EU-003" not in reported and not has_log:
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
                reported.add("EU-003")

            # OW-005: no rate limiting
            if "OW-005" not in reported and not has_rate_limit:
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
                reported.add("OW-005")

        # OW-001: user input string interpolation in AI context
        if has_ai_call and _USER_INPUT_INTERP.search(line):
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

        # OW-002: WebView in AI context
        if has_ai_call and _WEBVIEW.search(line):
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

        # OW-003: PII variables in AI context
        if _PII_VARS.search(line) and any(
            abs(i - ai_ln) <= 30 for ai_ln in ai_call_line_nums
        ):
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

        # OW-004: unencrypted storage in AI context
        if has_ai_call and _SHARED_PREFS.search(line):
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

    return findings
