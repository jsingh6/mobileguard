# Copyright 2026 Jaspreet Singh
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Pydantic v2 data models for MobileGuard governance artifacts."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Violation severity levels, ordered from most to least severe."""

    CRITICAL = "critical"
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"

    @property
    def weight(self) -> int:
        """Numeric weight for severity comparison (higher = more severe)."""
        return {"critical": 4, "error": 3, "warning": 2, "info": 1}[self.value]


class Platform(str, Enum):
    """Supported mobile platforms."""

    IOS = "ios"
    ANDROID = "android"
    FLUTTER = "flutter"
    REACT_NATIVE = "react-native"


class RuleCategory(str, Enum):
    """Governance rule category, corresponding to the applicable policy framework."""

    APP_STORE = "app-store"
    GOOGLE_PLAY = "google-play"
    EU_AI_ACT = "eu-ai-act"
    OWASP = "owasp"


class Finding(BaseModel):
    """A single governance violation detected by MobileGuard."""

    rule_id: str = Field(description="Stable rule identifier, e.g. AS-001")
    severity: Severity
    category: RuleCategory
    description: str = Field(description="Human-readable description of the violation")
    file_path: str = Field(description="Relative path to the file containing the violation")
    line_number: Optional[int] = Field(default=None, description="1-based line number")
    column: Optional[int] = Field(default=None, description="1-based column number")
    evidence: Optional[str] = Field(default=None, description="Code snippet showing the violation")
    fix: str = Field(description="Actionable remediation guidance")
    reference: Optional[str] = Field(default=None, description="URL to the relevant guideline")
    pillar: str = Field(description="Governance pillar: PDQC | TACM | PGSG | AABE")


class ScanResult(BaseModel):
    """Aggregated result of a `mobileguard scan` run."""

    project_path: str
    platform: Platform
    files_scanned: int
    scan_duration_seconds: float
    findings: list[Finding]
    passed: bool
    summary: dict[str, int] = Field(
        description="Finding counts keyed by severity (critical, error, warning, info)"
    )


class ContractVerdict(BaseModel):
    """Result of a `mobileguard contract` evaluation against a quality contract."""

    stage: str = Field(description="Pipeline stage: code-generation | test-generation | code-review")
    agent_id: str = Field(description="Identifier of the AI agent that produced this code")
    platform: Platform
    score: float = Field(ge=0.0, le=1.0, description="Quality score between 0.0 and 1.0")
    outcome: str = Field(description="PASS | FAIL | WARNING")
    findings: list[Finding]
    halt_pipeline: bool = Field(description="Whether the CI pipeline should halt")
    human_override_required: bool = Field(
        description="Whether a human must approve before the pipeline advances"
    )
    recommendation: str
    timestamp: datetime


class AuditReport(BaseModel):
    """Structured compliance report for `mobileguard audit`."""

    app_name: str
    version: str
    platforms: list[Platform]
    generated_at: datetime
    tool_version: str
    compliance_status: dict[str, Any] = Field(
        description="Per-framework compliance status dict"
    )
    ai_features: list[dict[str, Any]] = Field(
        description="Detected AI integrations and on-device models"
    )
    findings: list[Finding]
    attestation: str


class TierResult(BaseModel):
    """TAC-M autonomy tier result for `mobileguard tier`."""

    agent_id: str
    current_tier: str = Field(description="Current tier label: L1 | L2 | L3 | L4 | L5")
    tier_label: str = Field(description="Human-readable tier description")
    max_deployment_reach: float = Field(
        ge=0.0, le=1.0, description="Maximum permitted deployment reach as a fraction"
    )
    consecutive_clean_cycles: int = Field(ge=0)
    demotion_triggered: bool
    demotion_reason: Optional[str] = None
    recommendation: str


class RuleDefinition(BaseModel):
    """Metadata for a single governance rule (used in rule modules)."""

    id: str
    severity: Severity
    category: RuleCategory
    description: str
    fix: str
    reference: str
    pillar: str
    deprecated: bool = False
