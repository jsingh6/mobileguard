# Copyright 2026 Jaspreet Singh
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""MobileGuard — AI governance for consumer mobile platforms.

Reference implementation of the MobileGuard governance framework described in:
  "MobileGuard: A Stack-Agnostic Governance Framework for Agentic AI
   Across Consumer Mobile Delivery Platforms"
  Jaspreet Singh · arXiv:XXXX.XXXXX · 2026

Four governance pillars:
  PDQC  — Pre-Deployment Quality Contracting   (mobileguard contract)
  TAC-M — Tiered Autonomy Calibration for Mobile (mobileguard tier)
  PGSG  — Platform Gatekeeper Simulation Gates  (mobileguard scan)
  AABE  — Ambient Agent Boundary Enforcement    (mobileguard scan)

MobileGuard does not collect telemetry, send analytics, or phone home.
All analysis is performed locally. The only outbound network calls are to
the Anthropic API when --llm is passed to `scan` or when running `contract`.
"""

__version__ = "1.1.0"
__author__ = "Jaspreet Singh"
__license__ = "Apache-2.0"

from mobileguard.models import (
    AuditReport,
    ContractVerdict,
    Finding,
    Platform,
    RuleCategory,
    ScanResult,
    Severity,
    TierResult,
)

__all__ = [
    "__version__",
    "AuditReport",
    "ContractVerdict",
    "Finding",
    "Platform",
    "RuleCategory",
    "Severity",
    "ScanResult",
    "TierResult",
]
