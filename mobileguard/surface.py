# Copyright 2026 Jaspreet Singh
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""AABE: Ambient Agent Boundary Enforcement — surface map scanner.

Real enforcement evidence:
Apple Guideline 5.1.2(i) — November 2025:
"If your app shares personal data with third-party AI services, you must
explicitly disclose the AI provider and obtain explicit user consent before
any data transmission."

Apps with AppIntents that access financial, health, contact, or location data
without explicit requestConfirmation() calls are being flagged in 2026 App
Store review for violating user consent requirements under both 5.1.2(i) and
EU AI Act Article 14 (human oversight).

MobileGuard's AABE pillar is the first published tool to map this surface
systematically. Reference paper:
Singh, J. "MobileGuard: A Stack-Agnostic Governance Framework for Agentic AI
Across Consumer Mobile Delivery Platforms." arXiv, 2026.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from mobileguard.models import Platform, RuleCategory, RuleDefinition, Severity

# ── AABE rule metadata ─────────────────────────────────────────────────────────

_AABE_RULES: dict[str, RuleDefinition] = {
    "AABE-001": RuleDefinition(
        id="AABE-001",
        severity=Severity.CRITICAL,
        category=RuleCategory.APP_STORE,
        description=(
            "AppIntent accesses financial or payment data without requestConfirmation() — "
            "ambient agent can initiate payment without explicit user approval"
        ),
        fix=(
            "Add requestConfirmation() before any financial action: "
            "try await requestConfirmation(result: .result(value: preview)). "
            "Apple Guideline 5.1.2(i) requires explicit consent before any AI-triggered "
            "financial action."
        ),
        reference=(
            "https://developer.apple.com/documentation/appintents/requesting-user-confirmation"
        ),
        pillar="AABE",
    ),
    "AABE-002": RuleDefinition(
        id="AABE-002",
        severity=Severity.ERROR,
        category=RuleCategory.APP_STORE,
        description=(
            "AppIntent accesses sensitive user data (contacts, health, location, calendar) "
            "without requestConfirmation() or explicit authorization check"
        ),
        fix=(
            "Add requestConfirmation() or a dedicated authorization check before accessing "
            "contacts, health, location, or calendar data from an AppIntent. "
            "Siri and Apple Intelligence can invoke this intent without the user opening the app."
        ),
        reference=(
            "https://developer.apple.com/documentation/appintents/requesting-user-confirmation"
        ),
        pillar="AABE",
    ),
}

# ── Models ─────────────────────────────────────────────────────────────────────


class SurfaceEntry(BaseModel):
    """A single ambient agent entry point."""

    name: str = Field(description="Intent / function / shortcut name")
    entry_type: str = Field(
        description="AppIntent | SiriKit | AppShortcut | AppFunction | NSUserActivity"
    )
    file_path: str
    line_number: int | None = None
    data_access: list[str] = Field(
        default_factory=list,
        description="Sensitive data categories accessed: Financial, Contacts, Health, etc.",
    )
    has_confirmation: bool = False
    risk_level: str = Field(default="LOW", description="LOW | MEDIUM | HIGH | CRITICAL")
    finding_id: str | None = Field(
        default=None, description="AABE rule ID if a violation was detected"
    )
    fix: str | None = None


class SurfaceScanResult(BaseModel):
    """Result of a `mobileguard surface` scan."""

    project_path: str
    platform: Platform
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    entry_points: list[SurfaceEntry] = Field(default_factory=list)

    @property
    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for e in self.entry_points:
            counts[e.risk_level.lower()] = counts.get(e.risk_level.lower(), 0) + 1
        return counts

    def model_dump_json(self, **kwargs: Any) -> str:
        data = self.model_dump()
        data["scanned_at"] = self.scanned_at.isoformat()
        data["summary"] = self.summary
        import json

        return json.dumps(data, indent=kwargs.get("indent", 2))


# ── Patterns ───────────────────────────────────────────────────────────────────

_APP_INTENT_DECL = re.compile(
    r'(?:struct|class)\s+(\w+)\s*:\s*(?:\w+\s*,\s*)*AppIntent\b'
)
_PERFORM_FN = re.compile(r'\bfunc\s+perform\s*\(')
_REQUEST_CONFIRMATION = re.compile(r'\brequestConfirmation\s*\(')

# Sensitive data categories
_SENSITIVE_FINANCIAL = re.compile(
    r'\b(?:payment|Payment|transfer|Transfer|purchase|Purchase|'
    r'credit|Credit|debit|Debit|wallet|Wallet|transaction|Transaction)\b',
)
_SENSITIVE_CONTACTS = re.compile(
    r'\b(?:contact|Contact|CNContact|recipient|Recipient|address|Address)\b',
)
_SENSITIVE_HEALTH = re.compile(
    r'\b(?:health|Health|HKHealthStore|medical|Medical|diagnosis|biometric)\b',
)
_SENSITIVE_LOCATION = re.compile(
    r'\b(?:location|Location|CLLocation|GPS|coordinate|latitude|longitude)\b',
)
_SENSITIVE_CALENDAR = re.compile(
    r'\b(?:calendar|Calendar|EventKit|event|Event|schedule|Schedule)\b',
)
_SENSITIVE_MESSAGES = re.compile(
    r'\b(?:message|Message|MFMessage|SMS|email|Email|send|Send)\b',
)

_APP_FUNCTION_DECL = re.compile(r'@AppFunction\b')

_SKIP_DIRS = {
    "Pods", "node_modules", ".build", "DerivedData", "Packages",
    ".git", ".github", ".mobileguard", "build", "dist", ".gradle", "__pycache__",
}


# ── Scanner ────────────────────────────────────────────────────────────────────


class SurfaceScanner:
    """Maps all ambient AI agent entry points in a mobile project."""

    def scan(
        self,
        path: str,
        platform: str = "auto",
        include_risk: bool = False,
    ) -> SurfaceScanResult:
        """Scan path and return a surface map of all ambient entry points."""
        root = Path(path).resolve()

        if platform == "auto":
            detected = self._detect_platform(root)
        else:
            try:
                detected = Platform(platform)
            except ValueError:
                detected = Platform.IOS

        entry_points: list[SurfaceEntry] = []

        if detected in (Platform.IOS,):
            entry_points.extend(self._scan_app_intents(root))

        if detected in (Platform.ANDROID,):
            entry_points.extend(self._scan_app_functions(root))

        if platform == "auto" and not entry_points:
            # Try the other platform
            if detected == Platform.IOS:
                entry_points.extend(self._scan_app_functions(root))
            else:
                entry_points.extend(self._scan_app_intents(root))

        return SurfaceScanResult(
            project_path=str(root),
            platform=detected,
            entry_points=entry_points,
        )

    def _detect_platform(self, root: Path) -> Platform:
        swift_count = sum(1 for _ in root.rglob("*.swift") if not any(
            p in _SKIP_DIRS for p in _.parts
        ))
        kotlin_count = sum(1 for _ in root.rglob("*.kt") if not any(
            p in _SKIP_DIRS for p in _.parts
        ))
        return Platform.IOS if swift_count >= kotlin_count else Platform.ANDROID

    def _scan_app_intents(self, root: Path) -> list[SurfaceEntry]:
        """Find AppIntent conformances in Swift source files."""
        entries: list[SurfaceEntry] = []

        for f in root.rglob("*.swift"):
            if any(part in _SKIP_DIRS for part in f.parts):
                continue
            try:
                content = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            lines = content.splitlines()
            rel = str(f.relative_to(root))

            for i, line in enumerate(lines):
                m = _APP_INTENT_DECL.search(line)
                if not m:
                    continue

                intent_name = m.group(1)
                line_num = i + 1

                # Extract the struct body (next 80 lines or until balanced brace)
                body_lines = lines[i: i + 80]
                body = "\n".join(body_lines)

                data_access: list[str] = []
                if _SENSITIVE_FINANCIAL.search(intent_name + body):
                    data_access.append("Financial")
                if _SENSITIVE_CONTACTS.search(body):
                    data_access.append("Contacts")
                if _SENSITIVE_HEALTH.search(body):
                    data_access.append("Health")
                if _SENSITIVE_LOCATION.search(body):
                    data_access.append("Location")
                if _SENSITIVE_CALENDAR.search(body):
                    data_access.append("Calendar")
                if _SENSITIVE_MESSAGES.search(body):
                    data_access.append("Messages")

                # Strip single-line comments before confirmation check so
                # "// no requestConfirmation()" doesn't produce a false negative.
                code_only = "\n".join(
                    ln for ln in body_lines if not ln.lstrip().startswith("//")
                )
                has_confirmation = bool(_REQUEST_CONFIRMATION.search(code_only))

                risk, finding_id, fix = self._assess_risk(
                    intent_name, data_access, has_confirmation
                )

                entries.append(
                    SurfaceEntry(
                        name=intent_name,
                        entry_type="AppIntent",
                        file_path=rel,
                        line_number=line_num,
                        data_access=data_access,
                        has_confirmation=has_confirmation,
                        risk_level=risk,
                        finding_id=finding_id,
                        fix=fix,
                    )
                )

        return entries

    def _scan_app_functions(self, root: Path) -> list[SurfaceEntry]:
        """Find @AppFunction declarations in Kotlin source files."""
        entries: list[SurfaceEntry] = []

        for f in root.rglob("*.kt"):
            if any(part in _SKIP_DIRS for part in f.parts):
                continue
            try:
                content = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            lines = content.splitlines()
            rel = str(f.relative_to(root))

            for i, line in enumerate(lines):
                if not _APP_FUNCTION_DECL.search(line):
                    continue

                # The function declaration is typically on the next line
                fn_line = lines[i + 1] if i + 1 < len(lines) else line
                fn_name_m = re.search(r'fun\s+(\w+)', fn_line)
                fn_name = fn_name_m.group(1) if fn_name_m else f"AppFunction@{i + 1}"

                body = "\n".join(lines[i: i + 40])
                data_access: list[str] = []
                if _SENSITIVE_FINANCIAL.search(fn_name + body):
                    data_access.append("Financial")
                if _SENSITIVE_CONTACTS.search(body):
                    data_access.append("Contacts")

                has_confirmation = bool(re.search(r'confirm|Confirm|dialog|Dialog', body))
                risk, finding_id, fix = self._assess_risk(fn_name, data_access, has_confirmation)

                entries.append(
                    SurfaceEntry(
                        name=fn_name,
                        entry_type="AppFunction",
                        file_path=rel,
                        line_number=i + 1,
                        data_access=data_access,
                        has_confirmation=has_confirmation,
                        risk_level=risk,
                        finding_id=finding_id,
                        fix=fix,
                    )
                )

        return entries

    def _assess_risk(
        self,
        name: str,
        data_access: list[str],
        has_confirmation: bool,
    ) -> tuple[str, str | None, str | None]:
        """Return (risk_level, finding_id | None, fix | None)."""
        if not data_access:
            return "LOW", None, None

        if "Financial" in data_access:
            if has_confirmation:
                return "MEDIUM", None, None
            rule = _AABE_RULES["AABE-001"]
            return "CRITICAL", rule.id, rule.fix

        # Other sensitive data
        if has_confirmation:
            return "MEDIUM", None, None
        rule = _AABE_RULES["AABE-002"]
        return "HIGH", rule.id, rule.fix
