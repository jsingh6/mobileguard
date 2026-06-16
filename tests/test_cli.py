# Copyright 2026 Jaspreet Singh
# Apache-2.0

"""Tests for mobileguard.cli — CLI command surface via Click test runner."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from mobileguard.cli import cli

FIXTURES = Path(__file__).parent / "fixtures"


class TestCliHelp:
    """Help output and version should always succeed."""

    def test_root_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "scan" in result.output
        assert "contract" in result.output
        assert "audit" in result.output
        assert "tier" in result.output
        assert "init" in result.output

    def test_version(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "1.0.0" in result.output

    def test_scan_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--platform" in result.output
        assert "--rules" in result.output
        assert "--format" in result.output

    def test_contract_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["contract", "--help"])
        assert result.exit_code == 0

    def test_audit_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["audit", "--help"])
        assert result.exit_code == 0

    def test_tier_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["tier", "--help"])
        assert result.exit_code == 0

    def test_init_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["init", "--help"])
        assert result.exit_code == 0


class TestScanCommand:
    """Tests for mobileguard scan."""

    def test_scan_swift_fixture_exits_1(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(FIXTURES / "swift"), "--platform", "ios"])
        assert result.exit_code == 1  # violations found

    def test_scan_kotlin_fixture_exits_1(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(FIXTURES / "kotlin"), "--platform", "android"])
        assert result.exit_code == 1

    def test_scan_json_format(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["scan", str(FIXTURES / "swift"), "--platform", "ios", "--format", "json"],
        )
        assert result.exit_code == 1
        data = json.loads(result.output)
        assert "findings" in data
        assert "files_scanned" in data

    def test_scan_sarif_format(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["scan", str(FIXTURES / "swift"), "--platform", "ios", "--format", "sarif"],
        )
        assert result.exit_code == 1
        data = json.loads(result.output)
        assert data["version"] == "2.1.0"
        assert "runs" in data

    def test_scan_markdown_format(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["scan", str(FIXTURES / "swift"), "--platform", "ios", "--format", "markdown"],
        )
        assert result.exit_code == 1
        assert "MobileGuard Scan Results" in result.output

    def test_scan_output_to_file(self, tmp_path: Path) -> None:
        out = str(tmp_path / "report.json")
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "scan",
                str(FIXTURES / "swift"),
                "--platform", "ios",
                "--format", "json",
                "--output", out,
            ],
        )
        assert Path(out).exists()
        data = json.loads(Path(out).read_text())
        assert "findings" in data

    def test_scan_fail_on_critical(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "scan",
                str(FIXTURES / "swift"),
                "--platform", "ios",
                "--fail-on", "critical",
            ],
        )
        assert result.exit_code == 1

    def test_scan_severity_filter_critical_only(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "scan",
                str(FIXTURES / "swift"),
                "--platform", "ios",
                "--severity", "critical",
                "--format", "json",
            ],
        )
        data = json.loads(result.output)
        for finding in data["findings"]:
            assert finding["severity"] == "critical"

    def test_scan_llm_without_api_key_exits_2(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["scan", str(FIXTURES / "swift"), "--llm"],
            env={"ANTHROPIC_API_KEY": ""},
        )
        assert result.exit_code == 2

    def test_scan_rules_filter(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "scan",
                str(FIXTURES / "swift"),
                "--platform", "ios",
                "--rules", "owasp",
                "--format", "json",
            ],
        )
        data = json.loads(result.output)
        for finding in data["findings"]:
            assert finding["category"] == "owasp"

    def test_scan_table_output_contains_summary(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(FIXTURES / "swift"), "--platform", "ios"])
        assert "Summary" in result.output
        assert "CRITICAL" in result.output or "ERROR" in result.output

    def test_scan_dart_fixtures(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli, ["scan", str(FIXTURES / "dart"), "--platform", "flutter", "--format", "json"]
        )
        data = json.loads(result.output)
        assert data["files_scanned"] >= 1


class TestInitCommand:
    """Tests for mobileguard init."""

    def test_init_creates_contract(self, tmp_path: Path) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(cli, ["init", "--platform", "ios", "--bundle-id", "com.test.app"])
            assert result.exit_code == 0
            assert Path("mobileguard.json").exists()
            data = json.loads(Path("mobileguard.json").read_text())
            assert data["platform"] == "ios"
            assert data["bundle_id"] == "com.test.app"

    def test_init_android_platform(self, tmp_path: Path) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(cli, ["init", "--platform", "android"])
            assert result.exit_code == 0
            data = json.loads(Path("mobileguard.json").read_text())
            assert data["platform"] == "android"

    def test_init_strict_mode_higher_threshold(self, tmp_path: Path) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(cli, ["init", "--platform", "ios", "--strict"])
            assert result.exit_code == 0
            data = json.loads(Path("mobileguard.json").read_text())
            assert data["thresholds"]["min_score"] > 0.80

    def test_init_contract_has_stages(self, tmp_path: Path) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            runner.invoke(cli, ["init", "--platform", "ios"])
            data = json.loads(Path("mobileguard.json").read_text())
            assert "stages" in data
            assert "code-generation" in data["stages"]
            assert "code-review" in data["stages"]

    def test_init_requires_platform(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["init"])
        assert result.exit_code != 0

    def test_init_with_app_name(self, tmp_path: Path) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(cli, ["init", "--platform", "flutter", "--app-name", "My App"])
            assert result.exit_code == 0
            data = json.loads(Path("mobileguard.json").read_text())
            assert data["app_name"] == "My App"


class TestTierCommand:
    """Tests for mobileguard tier."""

    def test_tier_unknown_agent(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli, ["tier", "unknown-agent", "--history", str(tmp_path / "audit")]
        )
        assert result.exit_code == 0
        assert "L1" in result.output

    def test_tier_output_contains_agent_id(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli, ["tier", "my-agent-01", "--history", str(tmp_path / "audit")]
        )
        assert result.exit_code == 0
        assert "my-agent-01" in result.output

    def test_tier_output_contains_deployment(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli, ["tier", "agent", "--history", str(tmp_path / "audit")]
        )
        assert "Max deployment" in result.output

    def test_tier_with_cfsr(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli, ["tier", "agent", "--history", str(tmp_path / "audit"), "--cfsr", "0.997"]
        )
        assert result.exit_code == 0
        assert "Crash-free" in result.output


class TestAuditCommand:
    """Tests for mobileguard audit."""

    def test_audit_swift_markdown(self, tmp_path: Path) -> None:
        out = str(tmp_path / "report.md")
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "audit",
                str(FIXTURES / "swift"),
                "--app-name", "TestApp",
                "--version", "1.0.0",
                "--format", "markdown",
                "--output", out,
            ],
        )
        assert result.exit_code == 0
        assert Path(out).exists()
        content = Path(out).read_text()
        assert "TestApp" in content
        assert "Compliance Status" in content

    def test_audit_json_format(self, tmp_path: Path) -> None:
        out = str(tmp_path / "report.json")
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "audit",
                str(FIXTURES / "swift"),
                "--app-name", "TestApp",
                "--version", "1.0.0",
                "--format", "json",
                "--output", out,
            ],
        )
        assert result.exit_code == 0
        data = json.loads(Path(out).read_text())
        assert data["app_name"] == "TestApp"

    def test_audit_html_format(self, tmp_path: Path) -> None:
        out = str(tmp_path / "report.html")
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "audit",
                str(FIXTURES / "swift"),
                "--app-name", "TestApp",
                "--version", "1.0.0",
                "--format", "html",
                "--output", out,
            ],
        )
        assert result.exit_code == 0
        html = Path(out).read_text()
        assert "<!DOCTYPE html>" in html


class TestContractCommand:
    """Tests for mobileguard contract (no API key = exit 2)."""

    def test_contract_no_api_key_exits_2(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["contract", str(FIXTURES / "swift"), "--stage", "code-generation"],
            env={"ANTHROPIC_API_KEY": ""},
        )
        assert result.exit_code == 2

    def test_contract_missing_contract_file_exits_2(self, tmp_path: Path) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(
                cli,
                [
                    "contract",
                    str(FIXTURES / "swift"),
                    "--contract", "nonexistent.json",
                    "--api-key", "sk-ant-test-key",
                ],
            )
            assert result.exit_code == 2
            assert "mobileguard init" in result.output
