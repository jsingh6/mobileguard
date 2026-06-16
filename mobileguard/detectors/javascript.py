# Copyright 2026 Jaspreet Singh
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""React Native / JavaScript / TypeScript pattern detector for MobileGuard.

Detects governance violations in .js, .ts, .jsx, .tsx files. React Native apps
target both iOS and Android, so this detector reports AS-xxx, GP-xxx, EU-xxx,
and OW-xxx violations.
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

_FETCH_OR_AXIOS = re.compile(r"\bfetch\s*\(|\baxios\b", re.IGNORECASE)

_API_KEY = re.compile(
    r'''["'`](sk-ant-[A-Za-z0-9\-_]{10,}|sk-[A-Za-z0-9\-_]{20,}|AIza[A-Za-z0-9\-_]{25,})["'`]'''
)

_DOTENV_KEY = re.compile(
    r"OPENAI_API_KEY\s*=\s*sk-|ANTHROPIC_API_KEY\s*=\s*sk-ant-",
    re.IGNORECASE,
)

_DISCLOSURE = re.compile(
    r"AIDisclosure|AIBadge|aiGenerated|showAILabel|ai-disclosure",
    re.IGNORECASE,
)

# Template literal interpolation with user-controlled variable names
_USER_INPUT_INTERP = re.compile(
    r'\$\{(?:user(?:Message|Input|Text|Query|Prompt)|message|query|inputText|userText|prompt)\b',
    re.IGNORECASE,
)

_WEBVIEW = re.compile(r"WebView\b|<WebView|dangerouslySetInnerHTML", re.IGNORECASE)

_PII_VARS = re.compile(
    r'\b(?:email|ssn|creditCard|credit_card|password|phoneNumber|phone_number|passport)\b',
    re.IGNORECASE,
)

_ASYNC_STORAGE = re.compile(r"AsyncStorage\.", re.IGNORECASE)

_LOG_CALL = re.compile(
    r"console\.\w+\s*\(|analytics\.|Analytics\.|Sentry\.|firebase\.analytics",
    re.IGNORECASE,
)

_RATE_LIMIT = re.compile(r"rateLimit|rate_limit|throttle|debounce|maxRequests", re.IGNORECASE)

_EXPO_TRACKING = re.compile(r"expo-tracking-transparency|requestTrackingPermissionsAsync")

_ERROR_BOUNDARY = re.compile(r"ErrorBoundary\b|componentDidCatch\b")


def detect(file_path: str, content: str) -> list[Finding]:
    """Detect governance violations in a JavaScript or TypeScript file."""
    lines = content.splitlines()
    findings: list[Finding] = []

    has_ai_call = bool(_AI_DOMAIN.search(content))
    has_disclosure = bool(_DISCLOSURE.search(content))
    has_log = bool(_LOG_CALL.search(content))
    has_rate_limit = bool(_RATE_LIMIT.search(content))
    # Line numbers (1-based) where an AI API domain appears — used for proximity checks
    ai_call_line_nums = {
        i for i, ln in enumerate(lines, start=1) if _AI_DOMAIN.search(ln)
    }

    reported: set[str] = set()

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()

        # AS-002 / GP-002: hardcoded API key in source
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

        # Hardcoded key in .env file
        if _DOTENV_KEY.search(line):
            for rule in [APP_STORE_RULES["AS-002"], GOOGLE_PLAY_RULES["GP-002"]]:
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        severity=rule.severity,
                        category=rule.category,
                        description=f"{rule.description} (in .env file committed to repository)",
                        file_path=file_path,
                        line_number=i,
                        evidence=stripped[:80],
                        fix=rule.fix + " Add .env to .gitignore immediately.",
                        reference=rule.reference,
                        pillar=rule.pillar,
                    )
                )

        # AS-001 / GP-001 / EU-001: AI call without disclosure
        if _AI_DOMAIN.search(line):
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

        # OW-001: user input in template literal going to AI
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

        # OW-002: dangerouslySetInnerHTML or WebView with AI content
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

        # OW-003: PII variable within 30 lines of an actual AI API call.
        # Proximity required to avoid false positives in bundled files where
        # the AI SDK and unrelated code (e.g. URL parsers) coexist far apart.
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

        # OW-004: AsyncStorage in file with AI calls
        if has_ai_call and _ASYNC_STORAGE.search(line):
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
