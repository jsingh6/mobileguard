# Copyright 2026 Jaspreet Singh
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Kotlin/Android pattern detector for MobileGuard.

Detects governance violations in .kt, .kts, and build.gradle files. All detection
is purely static (regex-based). Maps to Google Play (GP-xxx), EU AI Act (EU-xxx),
and OWASP (OW-xxx) rule categories.
"""

from __future__ import annotations

import re

from mobileguard.models import Finding
from mobileguard.rules import EU_AI_ACT_RULES, GOOGLE_PLAY_RULES, OWASP_RULES

# ── Compiled patterns ──────────────────────────────────────────────────────────

_AI_DOMAIN = re.compile(
    r"https?://(?:api\.openai\.com|api\.anthropic\.com|"
    r"generativelanguage\.googleapis\.com|[\w\-]+\.openai\.azure\.com|"
    r"api\.cohere\.ai|api\.mistral\.ai|api\.groq\.com|api\.together\.xyz)",
    re.IGNORECASE,
)

_HTTP_CLIENT = re.compile(r"\bOkHttpClient\b|\bRetrofit\b|\bvolley\b", re.IGNORECASE)

_DATA_SAFETY = re.compile(
    r"data_safety|dataSafety|DATA_SAFETY|SafetyNet|safetynet",
)

_API_KEY = re.compile(
    r'''["'`](sk-ant-[A-Za-z0-9\-_]{10,}|sk-[A-Za-z0-9\-_]{20,}|AIza[A-Za-z0-9\-_]{25,})["'`]'''
)

_APP_FUNCTION = re.compile(r"@AppFunction\b|AppFunctionService\b")
_MANAGE_APP_FUNCTIONS = re.compile(r"MANAGE_APP_FUNCTIONS")

_BIOMETRIC = re.compile(r"BiometricPrompt|FingerprintManager|USE_BIOMETRIC", re.IGNORECASE)

_QUERIES_MANIFEST = re.compile(r"<queries>")

# OW-001: string template with user-controlled variable
_USER_INPUT_INTERP = re.compile(
    r'\$\{?(?:user(?:Message|Input|Text|Query|Prompt|Content)|message|query|inputText|userText|prompt)\b',
    re.IGNORECASE,
)

_WEBVIEW_LOAD = re.compile(r"\.loadData\s*\(|\.loadDataWithBaseURL\s*\(|WebView\b", re.IGNORECASE)

_PII_VARS = re.compile(
    r'\b(?:email|ssn|creditCard|credit_card|password|phoneNumber|phone_number|'
    r'socialSecurity|passport)\b',
    re.IGNORECASE,
)

_SHARED_PREFS = re.compile(r"SharedPreferences|getSharedPreferences|edit\(\)\.put", re.IGNORECASE)

_LOG_CALL = re.compile(
    r"\bLog\.[dviwe]\b|Timber\.|Firebase\.analytics|Analytics\.|Crashlytics\.",
    re.IGNORECASE,
)

_RATE_LIMIT = re.compile(
    r"rateLimit|rate_limit|throttle|Throttle|debounce|maxRequests|requestBudget",
    re.IGNORECASE,
)

_DISCLOSURE_UI = re.compile(
    r"AIDisclosure|ai_disclosure|showAILabel|aiGeneratedText|showAIBadge",
    re.IGNORECASE,
)


def detect(file_path: str, content: str) -> list[Finding]:
    """Detect governance violations in a Kotlin or Gradle file."""
    lines = content.splitlines()
    findings: list[Finding] = []

    has_ai_call = bool(_AI_DOMAIN.search(content))
    has_http_client = bool(_HTTP_CLIENT.search(content))
    has_data_safety = bool(_DATA_SAFETY.search(content))
    has_disclosure = bool(_DISCLOSURE_UI.search(content))
    has_log = bool(_LOG_CALL.search(content))
    has_rate_limit = bool(_RATE_LIMIT.search(content))

    reported_gp001 = False
    reported_eu001 = False
    reported_eu003 = False
    reported_ow005 = False

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()

        # GP-001: AI data transmission without DATA_SAFETY
        if not reported_gp001 and has_ai_call and has_http_client and not has_data_safety:
            if _AI_DOMAIN.search(line):
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
                reported_gp001 = True

        # GP-002: hardcoded API key
        m = _API_KEY.search(line)
        if m:
            rule = GOOGLE_PLAY_RULES["GP-002"]
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

        # GP-003: AppFunction without MANAGE_APP_FUNCTIONS
        if _APP_FUNCTION.search(line) and not _MANAGE_APP_FUNCTIONS.search(content):
            rule = GOOGLE_PLAY_RULES["GP-003"]
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

        # EU-001: AI call without disclosure UI
        if not reported_eu001 and _AI_DOMAIN.search(line) and not has_disclosure:
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
            reported_eu001 = True

        # EU-003: AI call without logging
        if not reported_eu003 and _AI_DOMAIN.search(line) and not has_log:
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
            reported_eu003 = True

        # OW-001: user input in string template interpolation
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

        # OW-002: AI output in WebView
        if _WEBVIEW_LOAD.search(line) and has_ai_call:
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

        # OW-003: PII variable used in file that calls AI API
        if has_ai_call and _PII_VARS.search(line):
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

        # OW-004: SharedPreferences storage in file with AI calls
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

        # OW-005: AI call without rate limiting
        if not reported_ow005 and _AI_DOMAIN.search(line) and not has_rate_limit:
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
            reported_ow005 = True

    return findings
