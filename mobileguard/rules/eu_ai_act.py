# Copyright 2026 Jaspreet Singh
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""EU AI Act governance rules.

Rule IDs are stable and cited in the MobileGuard research paper (arXiv:XXXX.XXXXX).
EU AI Act enforcement began August 2, 2026.
Pillar: PGSG (Platform Gatekeeper Simulation Gates) / PDQC.
"""

from mobileguard.models import RuleCategory, RuleDefinition, Severity

RULES: dict[str, RuleDefinition] = {
    "EU-001": RuleDefinition(
        id="EU-001",
        severity=Severity.CRITICAL,
        category=RuleCategory.EU_AI_ACT,
        description="AI system interacts with users without transparency disclosure (Article 50)",
        fix=(
            "Add a visible 'AI-generated' or 'Powered by AI' label in the UI wherever "
            "AI-generated content is displayed to users. The disclosure must be presented "
            "before the user interacts with the AI output, not buried in settings or privacy "
            "policy. Required under EU AI Act Article 50 (enforcement: Aug 2, 2026)."
        ),
        reference="https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689#art_50",
        pillar="PGSG",
    ),
    "EU-002": RuleDefinition(
        id="EU-002",
        severity=Severity.ERROR,
        category=RuleCategory.EU_AI_ACT,
        description="Automated AI decision modifies user data without human oversight mechanism (Article 14)",
        fix=(
            "Add a confirmation step before AI-generated decisions take effect on financial, "
            "health, or identity data. Users must be able to review and reject automated "
            "decisions. Log all overrides for audit purposes (see also EU-003)."
        ),
        reference="https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689#art_14",
        pillar="PDQC",
    ),
    "EU-003": RuleDefinition(
        id="EU-003",
        severity=Severity.WARNING,
        category=RuleCategory.EU_AI_ACT,
        description="No logging or audit trail for AI decisions (Article 12)",
        fix=(
            "Add a log statement or analytics event after each AI API call recording: "
            "the model used, input token count, output summary (not raw content), timestamp, "
            "and user action taken. Store logs for minimum 6 months for compliance auditing."
        ),
        reference="https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689#art_12",
        pillar="PDQC",
    ),
    "EU-004": RuleDefinition(
        id="EU-004",
        severity=Severity.WARNING,
        category=RuleCategory.EU_AI_ACT,
        description="AI feature has no user opt-out mechanism at runtime (Article 50(2))",
        fix=(
            "Add a runtime user preference (e.g., Settings toggle) that disables AI features. "
            "A build-time flag alone does not satisfy Article 50(2) — users must be able to "
            "opt out without reinstalling or contacting support."
        ),
        reference="https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689#art_50",
        pillar="PGSG",
    ),
}
