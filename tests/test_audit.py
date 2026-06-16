# Copyright 2026 Jaspreet Singh
# Apache-2.0

"""Tests for mobileguard.audit — report generation."""

from __future__ import annotations

import json
from pathlib import Path

from mobileguard.audit import (
    _build_compliance_status,
    generate_report,
    render_html,
    render_json,
    render_markdown,
)
from mobileguard.models import Finding, Platform, RuleCategory, ScanResult, Severity


def _make_scan_result(findings: list[Finding], path: str = "/tmp/test") -> ScanResult:
    summary = {
        "critical": sum(1 for f in findings if f.severity == Severity.CRITICAL),
        "error": sum(1 for f in findings if f.severity == Severity.ERROR),
        "warning": sum(1 for f in findings if f.severity == Severity.WARNING),
        "info": sum(1 for f in findings if f.severity == Severity.INFO),
    }
    return ScanResult(
        project_path=path,
        platform=Platform.IOS,
        files_scanned=3,
        scan_duration_seconds=0.5,
        findings=findings,
        passed=not findings,
        summary=summary,
    )


def _make_finding(
    rule_id: str = "AS-001",
    severity: Severity = Severity.CRITICAL,
    category: RuleCategory = RuleCategory.APP_STORE,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        category=category,
        description="Test violation",
        file_path="test.swift",
        line_number=10,
        fix="Fix this",
        reference="https://example.com",
        pillar="PGSG",
    )


class TestComplianceStatus:
    """Tests for _build_compliance_status helper."""

    def test_no_findings_returns_compliant(self) -> None:
        status = _build_compliance_status([])
        for info in status.values():
            assert info["status"] == "Compliant"
            assert info["icon"] == "✅"

    def test_critical_finding_returns_non_compliant(self) -> None:
        findings = [_make_finding("AS-001", Severity.CRITICAL, RuleCategory.APP_STORE)]
        status = _build_compliance_status(findings)
        apple_status = status["Apple Guideline 5.1.2(i)"]
        assert apple_status["icon"] == "❌"
        assert apple_status["status"] == "Non-compliant"

    def test_warning_returns_partial(self) -> None:
        findings = [_make_finding("AS-004", Severity.WARNING, RuleCategory.APP_STORE)]
        status = _build_compliance_status(findings)
        apple_status = status["Apple Guideline 5.1.2(i)"]
        assert apple_status["icon"] == "⚠"


class TestGenerateReport:
    """Tests for generate_report."""

    def test_report_fields_populated(self, tmp_path: Path) -> None:
        scan = _make_scan_result([], path=str(tmp_path))
        report = generate_report(
            scan,
            app_name="TestApp",
            version="1.0.0",
            platforms=[Platform.IOS],
        )
        assert report.app_name == "TestApp"
        assert report.version == "1.0.0"
        assert Platform.IOS in report.platforms
        assert report.tool_version  # non-empty

    def test_evidence_stripped_by_default(self, tmp_path: Path) -> None:
        finding = _make_finding()
        finding = finding.model_copy(update={"evidence": "secret code here"})
        scan = _make_scan_result([finding], path=str(tmp_path))
        report = generate_report(
            scan,
            app_name="App",
            version="1.0",
            platforms=[Platform.IOS],
            include_evidence=False,
        )
        for f in report.findings:
            assert f.evidence is None

    def test_evidence_included_when_flag_set(self, tmp_path: Path) -> None:
        finding = _make_finding()
        finding = finding.model_copy(update={"evidence": "secret code here"})
        scan = _make_scan_result([finding], path=str(tmp_path))
        report = generate_report(
            scan,
            app_name="App",
            version="1.0",
            platforms=[Platform.IOS],
            include_evidence=True,
        )
        evidences = [f.evidence for f in report.findings]
        assert any(e is not None for e in evidences)


class TestRenderMarkdown:
    """Tests for Markdown output rendering."""

    def test_markdown_contains_app_name(self, tmp_path: Path) -> None:
        scan = _make_scan_result([], path=str(tmp_path))
        report = generate_report(
            scan, app_name="MyTestApp", version="2.0", platforms=[Platform.IOS]
        )
        md = render_markdown(report)
        assert "MyTestApp" in md

    def test_markdown_contains_compliance_table(self, tmp_path: Path) -> None:
        scan = _make_scan_result([], path=str(tmp_path))
        report = generate_report(scan, app_name="App", version="1.0", platforms=[Platform.IOS])
        md = render_markdown(report)
        assert "Compliance Status" in md
        assert "Apple Guideline" in md

    def test_markdown_contains_attestation(self, tmp_path: Path) -> None:
        scan = _make_scan_result([], path=str(tmp_path))
        report = generate_report(scan, app_name="App", version="1.0", platforms=[Platform.IOS])
        md = render_markdown(report)
        assert "Attestation" in md
        assert "MobileGuard" in md

    def test_markdown_lists_critical_findings(self, tmp_path: Path) -> None:
        finding = _make_finding("AS-001", Severity.CRITICAL, RuleCategory.APP_STORE)
        scan = _make_scan_result([finding], path=str(tmp_path))
        report = generate_report(scan, app_name="App", version="1.0", platforms=[Platform.IOS])
        md = render_markdown(report)
        assert "AS-001" in md
        assert "Critical Issues" in md


class TestRenderJSON:
    """Tests for JSON output rendering."""

    def test_json_is_valid(self, tmp_path: Path) -> None:
        scan = _make_scan_result([], path=str(tmp_path))
        report = generate_report(scan, app_name="App", version="1.0", platforms=[Platform.IOS])
        rendered = render_json(report)
        data = json.loads(rendered)
        assert data["app_name"] == "App"

    def test_json_contains_findings(self, tmp_path: Path) -> None:
        finding = _make_finding()
        scan = _make_scan_result([finding], path=str(tmp_path))
        report = generate_report(scan, app_name="App", version="1.0", platforms=[Platform.IOS])
        data = json.loads(render_json(report))
        assert len(data["findings"]) == 1
        assert data["findings"][0]["rule_id"] == "AS-001"


class TestRenderHTML:
    """Tests for HTML output rendering."""

    def test_html_is_valid_document(self, tmp_path: Path) -> None:
        scan = _make_scan_result([], path=str(tmp_path))
        report = generate_report(scan, app_name="App", version="1.0", platforms=[Platform.IOS])
        html = render_html(report)
        assert "<!DOCTYPE html>" in html
        assert "<title>" in html
        assert "</html>" in html

    def test_html_contains_app_name(self, tmp_path: Path) -> None:
        scan = _make_scan_result([], path=str(tmp_path))
        report = generate_report(
            scan, app_name="MyHTMLApp", version="1.0", platforms=[Platform.IOS]
        )
        html = render_html(report)
        assert "MyHTMLApp" in html
