# Copyright 2026 Jaspreet Singh
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""TAC-M — Tiered Autonomy Calibration for Mobile.

Computes the current autonomy tier for a named AI agent from its quality history
in the JSONL audit log. Tiers govern how much autonomous authority an agent has
earned based on consecutive clean deployment cycles.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from mobileguard.models import TierResult

_DEFAULT_AUDIT_DIR = ".mobileguard/audit"

# TAC-M tier definitions (L1 → L5)
# max_deployment_reach is the fraction of users an agent may autonomously affect.
# min_clean_cycles is the number of consecutive passing contract evaluations required.
TIER_DEFINITIONS: dict[str, dict[str, Any]] = {
    "L1": {
        "label": "Autocomplete only",
        "description": "AI provides suggestions only; all changes require manual authoring.",
        "min_clean_cycles": 0,
        "max_deployment_reach": 0.0,
        "requires_human_review": True,
    },
    "L2": {
        "label": "Draft for review",
        "description": "AI generates complete drafts; human reviews and approves all changes.",
        "min_clean_cycles": 1,
        "max_deployment_reach": 1.0,
        "requires_human_review": True,
    },
    "L3": {
        "label": "Conditional autonomous",
        "description": "AI may make limited autonomous changes to low-risk modules.",
        "min_clean_cycles": 5,
        "max_deployment_reach": 0.10,
        "requires_human_review": False,
    },
    "L4": {
        "label": "Supervised deployment",
        "description": "AI may autonomously deploy to staged rollouts with monitoring.",
        "min_clean_cycles": 10,
        "max_deployment_reach": 0.50,
        "requires_human_review": False,
    },
    "L5": {
        "label": "Full autonomous",
        "description": "AI operates with full deployment authority under continuous monitoring.",
        "min_clean_cycles": 20,
        "max_deployment_reach": 1.0,
        "requires_human_review": False,
    },
}

# Demotion triggers
_DEMOTION_CRITICAL_SCORE = 0.50   # score below this → demote to L1
_DEMOTION_LOW_SCORE = 0.65        # score below this → demote one level


def compute_tier(agent_id: str, audit_dir: str = _DEFAULT_AUDIT_DIR) -> TierResult:
    """Compute the current TAC-M autonomy tier for an agent from its audit history.

    Reads all JSONL audit logs in audit_dir, filters entries for agent_id,
    counts consecutive clean cycles from most recent, and maps to a tier.
    """
    history = _load_history(agent_id, audit_dir)

    if not history:
        return TierResult(
            agent_id=agent_id,
            current_tier="L1",
            tier_label=TIER_DEFINITIONS["L1"]["label"],
            max_deployment_reach=TIER_DEFINITIONS["L1"]["max_deployment_reach"],
            consecutive_clean_cycles=0,
            demotion_triggered=False,
            demotion_reason=None,
            recommendation=(
                f"No audit history found for agent '{agent_id}' in {audit_dir}. "
                "Run 'mobileguard contract' evaluations to build a quality history."
            ),
        )

    # Sort by timestamp ascending
    history.sort(key=lambda e: e["timestamp"])

    # Count consecutive clean cycles from the end (most recent first)
    consecutive_clean = 0
    demotion_triggered = False
    demotion_reason: str | None = None

    for entry in reversed(history):
        outcome = entry.get("outcome", "FAIL")
        score = float(entry.get("score", 0.0))

        # Check demotion triggers on most recent entry
        if consecutive_clean == 0:
            criticals = [
                f for f in entry.get("findings", []) if f.get("severity") == "critical"
            ]
            if criticals:
                demotion_triggered = True
                rule = criticals[0].get("rule_id", "unknown")
                demotion_reason = f"Critical finding in most recent cycle: {rule}"
            elif score < _DEMOTION_CRITICAL_SCORE:
                demotion_triggered = True
                demotion_reason = (
                    f"Score {score:.2f} below critical threshold {_DEMOTION_CRITICAL_SCORE}"
                )

        if outcome == "FAIL":
            break
        consecutive_clean += 1

    # Determine tier from consecutive clean cycles
    earned_tier = "L1"
    for tier_id in ["L5", "L4", "L3", "L2", "L1"]:
        if consecutive_clean >= TIER_DEFINITIONS[tier_id]["min_clean_cycles"]:
            earned_tier = tier_id
            break

    # Apply demotion
    if demotion_triggered:
        tier_keys = ["L1", "L2", "L3", "L4", "L5"]
        current_idx = tier_keys.index(earned_tier)
        demoted_idx = max(0, current_idx - 1)
        earned_tier = tier_keys[demoted_idx]

    tier_def = TIER_DEFINITIONS[earned_tier]

    # Build next-tier recommendation
    next_tier = _next_tier(earned_tier, consecutive_clean)

    return TierResult(
        agent_id=agent_id,
        current_tier=earned_tier,
        tier_label=tier_def["label"],
        max_deployment_reach=tier_def["max_deployment_reach"],
        consecutive_clean_cycles=consecutive_clean,
        demotion_triggered=demotion_triggered,
        demotion_reason=demotion_reason,
        recommendation=next_tier,
    )


def _load_history(agent_id: str, audit_dir: str) -> list[dict[str, Any]]:
    """Load all ContractVerdict entries for agent_id from JSONL audit files."""
    audit_path = Path(audit_dir)
    if not audit_path.exists():
        return []

    entries: list[dict[str, Any]] = []
    for log_file in sorted(audit_path.glob("mobileguard-*.jsonl")):
        try:
            for line in log_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if entry.get("agent_id") == agent_id:
                    entries.append(entry)
        except OSError:
            continue

    return entries


def _next_tier(current: str, clean_cycles: int) -> str:
    """Return a human-readable recommendation for reaching the next tier."""
    tier_keys = ["L1", "L2", "L3", "L4", "L5"]
    idx = tier_keys.index(current)

    if idx >= len(tier_keys) - 1:
        return f"Maximum tier {current} reached. Maintain clean cycles to retain it."

    next_id = tier_keys[idx + 1]
    next_def = TIER_DEFINITIONS[next_id]
    needed = next_def["min_clean_cycles"] - clean_cycles
    reach_pct = int(next_def["max_deployment_reach"] * 100)

    if needed <= 0:
        return (
            f"Eligible for {next_id} — run 'mobileguard contract' to record additional "
            f"cycles. {next_id} allows up to {reach_pct}% deployment reach."
        )
    return (
        f"{next_id} ({next_def['label']}) requires {needed} more consecutive clean "
        f"cycle{'s' if needed > 1 else ''} + deployment reach ≤ {reach_pct}%"
    )


def format_history_table(agent_id: str, audit_dir: str, limit: int = 5) -> list[dict[str, str]]:
    """Return the last `limit` audit entries for display in the tier report."""
    history = _load_history(agent_id, audit_dir)
    history.sort(key=lambda e: e["timestamp"], reverse=True)

    rows = []
    for entry in history[:limit]:
        outcome = entry.get("outcome", "FAIL")
        score = float(entry.get("score", 0.0))
        ts = entry.get("timestamp", "")
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            date_str = dt.strftime("%Y-%m-%d")
        except (ValueError, AttributeError):
            date_str = ts[:10]

        icon = "✅" if outcome == "PASS" else "❌"
        rows.append(
            {
                "icon": icon,
                "date": date_str,
                "outcome": outcome,
                "score": f"{score:.2f}",
                "note": (
                    "Contract violation — reset clean cycle count"
                    if outcome == "FAIL"
                    else ""
                ),
            }
        )
    return rows
