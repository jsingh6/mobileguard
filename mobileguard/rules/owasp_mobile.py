# Copyright 2026 Jaspreet Singh
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""OWASP Mobile AI security rules.

Rule IDs are stable and cited in the MobileGuard research paper (arXiv:XXXX.XXXXX).
Based on OWASP Mobile Top 10 adapted for AI-generated mobile code.
Pillar: PGSG (Platform Gatekeeper Simulation Gates).
"""

from mobileguard.models import RuleCategory, RuleDefinition, Severity

RULES: dict[str, RuleDefinition] = {
    "OW-001": RuleDefinition(
        id="OW-001",
        severity=Severity.CRITICAL,
        category=RuleCategory.OWASP,
        description=(
            "Prompt injection risk — user input interpolated directly into AI system prompt"
        ),
        fix=(
            "Never interpolate user-controlled input directly into a system prompt or AI "
            "instruction string. Sanitize user input by removing control characters and "
            "prompt-delimiter sequences, then pass user content in a dedicated 'user' "
            "message role rather than the 'system' role."
        ),
        reference="https://owasp.org/www-project-mobile-top-10/",
        pillar="PGSG",
    ),
    "OW-002": RuleDefinition(
        id="OW-002",
        severity=Severity.ERROR,
        category=RuleCategory.OWASP,
        description=(
            "AI model output rendered in WebView without HTML sanitization (XSS via AI output)"
        ),
        fix=(
            "Never render raw AI API response text directly in a WKWebView or WebView. "
            "Either sanitize the HTML (strip script tags, inline event handlers, "
            "javascript: URIs) before loading, or render AI text as plain text outside "
            "of a WebView context."
        ),
        reference="https://owasp.org/www-project-mobile-top-10/",
        pillar="PGSG",
    ),
    "OW-003": RuleDefinition(
        id="OW-003",
        severity=Severity.ERROR,
        category=RuleCategory.OWASP,
        description="Sensitive PII passed to external AI API without masking",
        fix=(
            "Mask or redact PII fields (email, phone, SSN, credit card, password) before "
            "including them in AI API request bodies. Use tokenization or placeholder values "
            "like '[EMAIL REDACTED]'. Review your AI provider's data retention policy — "
            "most retain inputs for safety monitoring by default."
        ),
        reference="https://owasp.org/www-project-mobile-top-10/",
        pillar="PGSG",
    ),
    "OW-004": RuleDefinition(
        id="OW-004",
        severity=Severity.WARNING,
        category=RuleCategory.OWASP,
        description="AI response cached to device storage without encryption",
        fix=(
            "Encrypt AI responses before storing on-device. Use iOS Data Protection "
            "(NSFileProtectionComplete) or Android EncryptedSharedPreferences. "
            "AI responses may contain sensitive inferred information about the user "
            "even when the prompt did not include PII."
        ),
        reference="https://owasp.org/www-project-mobile-top-10/",
        pillar="PGSG",
    ),
    "OW-005": RuleDefinition(
        id="OW-005",
        severity=Severity.WARNING,
        category=RuleCategory.OWASP,
        description="No rate limiting or token budget on AI API calls (denial-of-wallet risk)",
        fix=(
            "Add client-side rate limiting before each AI API call — track request count "
            "per time window (e.g., 10 requests/minute) and reject excess calls with a "
            "user-facing message. Also set a max_tokens parameter on every API call to "
            "bound per-request cost."
        ),
        reference="https://owasp.org/www-project-mobile-top-10/",
        pillar="PGSG",
    ),
}
