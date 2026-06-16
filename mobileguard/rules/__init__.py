# Copyright 2026 Jaspreet Singh
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Governance rule definitions for MobileGuard.

Each sub-module defines a RULES dict mapping stable rule IDs to RuleDefinition
objects. Rule IDs are permanent — they appear in SARIF output, audit logs, and
the research paper. Never renumber or delete a rule ID; set deprecated=True instead.
"""

from mobileguard.rules.app_store import RULES as APP_STORE_RULES
from mobileguard.rules.eu_ai_act import RULES as EU_AI_ACT_RULES
from mobileguard.rules.google_play import RULES as GOOGLE_PLAY_RULES
from mobileguard.rules.owasp_mobile import RULES as OWASP_RULES

ALL_RULES = {
    **APP_STORE_RULES,
    **GOOGLE_PLAY_RULES,
    **EU_AI_ACT_RULES,
    **OWASP_RULES,
}

__all__ = [
    "ALL_RULES",
    "APP_STORE_RULES",
    "GOOGLE_PLAY_RULES",
    "EU_AI_ACT_RULES",
    "OWASP_RULES",
]
