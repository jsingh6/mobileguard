# Copyright 2026 Jaspreet Singh
# Apache-2.0

"""Tests for mobileguard.contract — PDQC pillar."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from mobileguard.contract import load_contract


class TestLoadContract:
    """Tests for the contract loader (does not call the API)."""

    def test_missing_contract_raises_file_not_found(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError) as exc_info:
            load_contract(str(tmp_path / "nonexistent.json"))
        assert "mobileguard init" in str(exc_info.value)

    def test_invalid_json_raises_value_error(self, tmp_path: Path) -> None:
        bad = tmp_path / "mobileguard.json"
        bad.write_text("{not valid json}", encoding="utf-8")
        with pytest.raises(ValueError) as exc_info:
            load_contract(str(bad))
        assert "valid JSON" in str(exc_info.value)

    def test_valid_contract_loads(self, tmp_path: Path) -> None:
        contract = {
            "version": "1.0",
            "platform": "ios",
            "app_name": "Test App",
            "thresholds": {"min_score": 0.80},
        }
        path = tmp_path / "mobileguard.json"
        path.write_text(json.dumps(contract), encoding="utf-8")
        loaded = load_contract(str(path))
        assert loaded["platform"] == "ios"
        assert loaded["thresholds"]["min_score"] == 0.80

    def test_helpful_error_message_includes_init_command(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError) as exc_info:
            load_contract(str(tmp_path / "missing.json"))
        msg = str(exc_info.value)
        assert "mobileguard init" in msg
        assert "--platform" in msg
