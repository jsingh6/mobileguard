# Copyright 2026 Jaspreet Singh
# Apache-2.0

"""Tests for mobileguard.tier — TAC-M autonomy tier computation."""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from mobileguard.tier import (
    TIER_DEFINITIONS,
    compute_tier,
    format_history_table,
    _load_history,
    _next_tier,
)


def _write_audit_log(audit_dir: Path, entries: list[dict]) -> None:
    """Write ContractVerdict-shaped entries to a JSONL audit log."""
    audit_dir.mkdir(parents=True, exist_ok=True)
    log = audit_dir / "mobileguard-2026-06-15.jsonl"
    with log.open("w", encoding="utf-8") as fh:
        for entry in entries:
            fh.write(json.dumps(entry) + "\n")


def _make_entry(
    agent_id: str = "test-agent",
    outcome: str = "PASS",
    score: float = 0.90,
    timestamp: str = "2026-06-15T00:00:00+00:00",
    findings: list | None = None,
) -> dict:
    return {
        "agent_id": agent_id,
        "outcome": outcome,
        "score": score,
        "timestamp": timestamp,
        "findings": findings or [],
        "stage": "code-generation",
        "platform": "ios",
    }


class TestTierDefinitions:
    """Verify tier metadata is internally consistent."""

    def test_all_tiers_present(self) -> None:
        assert set(TIER_DEFINITIONS.keys()) == {"L1", "L2", "L3", "L4", "L5"}

    def test_min_cycles_ascending(self) -> None:
        tiers = ["L1", "L2", "L3", "L4", "L5"]
        cycles = [TIER_DEFINITIONS[t]["min_clean_cycles"] for t in tiers]
        assert cycles == sorted(cycles)

    def test_l1_no_autonomous_reach(self) -> None:
        assert TIER_DEFINITIONS["L1"]["max_deployment_reach"] == 0.0

    def test_l5_full_reach(self) -> None:
        assert TIER_DEFINITIONS["L5"]["max_deployment_reach"] == 1.0

    def test_all_tiers_have_label(self) -> None:
        for tier_id, defn in TIER_DEFINITIONS.items():
            assert defn["label"], f"{tier_id}: empty label"


class TestComputeTierNoHistory:
    """Tier computation with no audit history should return L1."""

    def test_no_history_returns_l1(self, tmp_path: Path) -> None:
        result = compute_tier("nonexistent-agent", str(tmp_path / "audit"))
        assert result.current_tier == "L1"

    def test_no_history_zero_clean_cycles(self, tmp_path: Path) -> None:
        result = compute_tier("nonexistent-agent", str(tmp_path / "audit"))
        assert result.consecutive_clean_cycles == 0

    def test_no_history_no_demotion(self, tmp_path: Path) -> None:
        result = compute_tier("nonexistent-agent", str(tmp_path / "audit"))
        assert not result.demotion_triggered

    def test_no_history_recommendation_mentions_contract(self, tmp_path: Path) -> None:
        result = compute_tier("nonexistent-agent", str(tmp_path / "audit"))
        assert "mobileguard contract" in result.recommendation


class TestComputeTierWithHistory:
    """Tier computation based on audit history entries."""

    def test_one_pass_gives_l2(self, tmp_path: Path) -> None:
        audit_dir = tmp_path / "audit"
        _write_audit_log(audit_dir, [
            _make_entry("agent", "PASS", 0.90, "2026-06-15T00:00:00+00:00"),
        ])
        result = compute_tier("agent", str(audit_dir))
        assert result.current_tier == "L2"

    def test_five_passes_gives_l3(self, tmp_path: Path) -> None:
        audit_dir = tmp_path / "audit"
        entries = [
            _make_entry("agent", "PASS", 0.90, f"2026-06-{10+i:02d}T00:00:00+00:00")
            for i in range(5)
        ]
        _write_audit_log(audit_dir, entries)
        result = compute_tier("agent", str(audit_dir))
        assert result.current_tier == "L3"
        assert result.consecutive_clean_cycles == 5

    def test_fail_resets_consecutive_count(self, tmp_path: Path) -> None:
        audit_dir = tmp_path / "audit"
        _write_audit_log(audit_dir, [
            _make_entry("agent", "PASS", 0.90, "2026-06-10T00:00:00+00:00"),
            _make_entry("agent", "PASS", 0.88, "2026-06-11T00:00:00+00:00"),
            _make_entry("agent", "FAIL", 0.45, "2026-06-12T00:00:00+00:00"),
            _make_entry("agent", "PASS", 0.91, "2026-06-13T00:00:00+00:00"),
            _make_entry("agent", "PASS", 0.87, "2026-06-14T00:00:00+00:00"),
        ])
        result = compute_tier("agent", str(audit_dir))
        assert result.consecutive_clean_cycles == 2
        assert result.current_tier == "L2"

    def test_ten_passes_gives_l4(self, tmp_path: Path) -> None:
        audit_dir = tmp_path / "audit"
        entries = [
            _make_entry("agent", "PASS", 0.90, f"2026-06-{i+1:02d}T00:00:00+00:00")
            for i in range(10)
        ]
        _write_audit_log(audit_dir, entries)
        result = compute_tier("agent", str(audit_dir))
        assert result.current_tier == "L4"

    def test_agent_isolation(self, tmp_path: Path) -> None:
        """Entries for other agents must not affect the target agent's tier."""
        audit_dir = tmp_path / "audit"
        _write_audit_log(audit_dir, [
            _make_entry("other-agent", "PASS", 0.95, "2026-06-10T00:00:00+00:00"),
            _make_entry("other-agent", "PASS", 0.95, "2026-06-11T00:00:00+00:00"),
        ])
        result = compute_tier("target-agent", str(audit_dir))
        assert result.consecutive_clean_cycles == 0
        assert result.current_tier == "L1"

    def test_demotion_on_critical_finding(self, tmp_path: Path) -> None:
        audit_dir = tmp_path / "audit"
        _write_audit_log(audit_dir, [
            _make_entry("agent", "PASS", 0.90, "2026-06-10T00:00:00+00:00"),
            _make_entry("agent", "PASS", 0.91, "2026-06-11T00:00:00+00:00"),
            _make_entry(
                "agent", "PASS", 0.88, "2026-06-15T00:00:00+00:00",
                findings=[{"severity": "critical", "rule_id": "OW-001"}],
            ),
        ])
        result = compute_tier("agent", str(audit_dir))
        assert result.demotion_triggered
        assert result.demotion_reason is not None


class TestNextTier:
    """Unit tests for the _next_tier recommendation helper."""

    def test_l1_to_l2_recommendation(self) -> None:
        msg = _next_tier("L1", 0)
        assert "L2" in msg

    def test_l5_max_tier_message(self) -> None:
        msg = _next_tier("L5", 25)
        assert "Maximum tier" in msg

    def test_recommendation_includes_cycle_count(self) -> None:
        msg = _next_tier("L2", 3)
        assert "2" in msg  # 5 - 3 = 2 more needed


class TestFormatHistoryTable:
    """Tests for the history table formatter."""

    def test_empty_history_returns_empty_list(self, tmp_path: Path) -> None:
        rows = format_history_table("agent", str(tmp_path / "audit"))
        assert rows == []

    def test_history_rows_have_required_keys(self, tmp_path: Path) -> None:
        audit_dir = tmp_path / "audit"
        _write_audit_log(audit_dir, [
            _make_entry("agent", "PASS", 0.90, "2026-06-15T00:00:00+00:00"),
        ])
        rows = format_history_table("agent", str(audit_dir))
        assert len(rows) == 1
        assert "icon" in rows[0]
        assert "date" in rows[0]
        assert "outcome" in rows[0]
        assert "score" in rows[0]

    def test_pass_shows_check_icon(self, tmp_path: Path) -> None:
        audit_dir = tmp_path / "audit"
        _write_audit_log(audit_dir, [
            _make_entry("agent", "PASS", 0.90, "2026-06-15T00:00:00+00:00"),
        ])
        rows = format_history_table("agent", str(audit_dir))
        assert rows[0]["icon"] == "✅"

    def test_fail_shows_cross_icon(self, tmp_path: Path) -> None:
        audit_dir = tmp_path / "audit"
        _write_audit_log(audit_dir, [
            _make_entry("agent", "FAIL", 0.40, "2026-06-15T00:00:00+00:00"),
        ])
        rows = format_history_table("agent", str(audit_dir))
        assert rows[0]["icon"] == "❌"

    def test_limit_respected(self, tmp_path: Path) -> None:
        audit_dir = tmp_path / "audit"
        entries = [
            _make_entry("agent", "PASS", 0.90, f"2026-06-{i+1:02d}T00:00:00+00:00")
            for i in range(10)
        ]
        _write_audit_log(audit_dir, entries)
        rows = format_history_table("agent", str(audit_dir), limit=3)
        assert len(rows) == 3
