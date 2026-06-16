# Copyright 2026 Jaspreet Singh
# Apache-2.0

"""Tests for mobileguard.scanner — end-to-end scan of fixture files."""

from __future__ import annotations

from pathlib import Path

from mobileguard.models import Platform, RuleCategory, Severity
from mobileguard.scanner import detect_platform, findings_meet_fail_threshold, run_scan

FIXTURES = Path(__file__).parent / "fixtures"


class TestSwiftFixtures:
    """Scan the Swift violation fixture and verify expected rules fire."""

    def setup_method(self) -> None:
        self.result = run_scan(
            str(FIXTURES / "swift"),
            platform="ios",
            rules="all",
            min_severity=Severity.INFO,
        )

    def test_files_scanned(self) -> None:
        assert self.result.files_scanned >= 1

    def test_platform_detected(self) -> None:
        assert self.result.platform == Platform.IOS

    def test_as001_detected(self) -> None:
        ids = {f.rule_id for f in self.result.findings}
        assert "AS-001" in ids, f"AS-001 not found. Found: {ids}"

    def test_as002_detected(self) -> None:
        ids = {f.rule_id for f in self.result.findings}
        assert "AS-002" in ids, f"AS-002 not found. Found: {ids}"

    def test_ow001_detected(self) -> None:
        ids = {f.rule_id for f in self.result.findings}
        assert "OW-001" in ids, f"OW-001 not found. Found: {ids}"

    def test_as001_is_critical(self) -> None:
        as001 = [f for f in self.result.findings if f.rule_id == "AS-001"]
        assert as001, "AS-001 finding not present"
        assert as001[0].severity == Severity.CRITICAL

    def test_as002_has_evidence(self) -> None:
        as002 = [f for f in self.result.findings if f.rule_id == "AS-002"]
        assert as002, "AS-002 finding not present"
        assert as002[0].evidence is not None
        assert "sk-ant" in as002[0].evidence

    def test_findings_have_line_numbers(self) -> None:
        for f in self.result.findings:
            if f.rule_id in {"AS-001", "AS-002", "OW-001"}:
                assert f.line_number is not None, f"{f.rule_id} missing line number"

    def test_scan_not_passed(self) -> None:
        assert not self.result.passed

    def test_summary_counts(self) -> None:
        assert self.result.summary["critical"] >= 1


class TestKotlinFixtures:
    """Scan the Kotlin violation fixture and verify expected rules fire."""

    def setup_method(self) -> None:
        self.result = run_scan(
            str(FIXTURES / "kotlin"),
            platform="android",
            rules="all",
            min_severity=Severity.INFO,
        )

    def test_files_scanned(self) -> None:
        assert self.result.files_scanned >= 1

    def test_gp001_detected(self) -> None:
        ids = {f.rule_id for f in self.result.findings}
        assert "GP-001" in ids, f"GP-001 not found. Found: {ids}"

    def test_gp002_detected(self) -> None:
        ids = {f.rule_id for f in self.result.findings}
        assert "GP-002" in ids, f"GP-002 not found. Found: {ids}"

    def test_ow003_detected(self) -> None:
        ids = {f.rule_id for f in self.result.findings}
        assert "OW-003" in ids, f"OW-003 not found. Found: {ids}"

    def test_gp001_is_critical(self) -> None:
        gp001 = [f for f in self.result.findings if f.rule_id == "GP-001"]
        assert gp001
        assert gp001[0].severity == Severity.CRITICAL

    def test_gp002_has_evidence(self) -> None:
        gp002 = [f for f in self.result.findings if f.rule_id == "GP-002"]
        assert gp002
        assert "sk-ant" in (gp002[0].evidence or "")


class TestDartFixtures:
    """Scan the Dart/Flutter violation fixture."""

    def setup_method(self) -> None:
        self.result = run_scan(
            str(FIXTURES / "dart"),
            platform="flutter",
            rules="all",
            min_severity=Severity.INFO,
        )

    def test_as001_or_gp001_detected(self) -> None:
        ids = {f.rule_id for f in self.result.findings}
        assert "AS-001" in ids or "GP-001" in ids, f"No AI disclosure rule found. Got: {ids}"

    def test_hardcoded_key_detected(self) -> None:
        ids = {f.rule_id for f in self.result.findings}
        assert "AS-002" in ids or "GP-002" in ids


class TestJavaScriptFixtures:
    """Scan the JavaScript/React Native violation fixture."""

    def setup_method(self) -> None:
        self.result = run_scan(
            str(FIXTURES / "javascript"),
            platform="react-native",
            rules="all",
            min_severity=Severity.INFO,
        )

    def test_as001_detected(self) -> None:
        ids = {f.rule_id for f in self.result.findings}
        assert "AS-001" in ids or "GP-001" in ids

    def test_ow001_detected(self) -> None:
        ids = {f.rule_id for f in self.result.findings}
        assert "OW-001" in ids


class TestScannerUtilities:
    """Unit tests for scanner helper functions."""

    def test_platform_detection_swift(self) -> None:
        platform = detect_platform(FIXTURES / "swift")
        assert platform == Platform.IOS

    def test_platform_detection_kotlin(self) -> None:
        platform = detect_platform(FIXTURES / "kotlin")
        assert platform == Platform.ANDROID

    def test_fail_threshold_critical(self) -> None:
        result = run_scan(
            str(FIXTURES / "swift"),
            platform="ios",
            rules="all",
            min_severity=Severity.INFO,
        )
        assert findings_meet_fail_threshold(result.findings, "critical")

    def test_fail_threshold_warning(self) -> None:
        result = run_scan(
            str(FIXTURES / "swift"),
            platform="ios",
            rules="all",
            min_severity=Severity.INFO,
        )
        assert findings_meet_fail_threshold(result.findings, "warning")

    def test_severity_filter(self) -> None:
        result = run_scan(
            str(FIXTURES / "swift"),
            platform="ios",
            rules="all",
            min_severity=Severity.CRITICAL,
        )
        for f in result.findings:
            assert f.severity == Severity.CRITICAL

    def test_rule_category_filter(self) -> None:
        result = run_scan(
            str(FIXTURES / "swift"),
            platform="ios",
            rules="owasp",
            min_severity=Severity.INFO,
        )
        for f in result.findings:
            assert f.category == RuleCategory.OWASP

    def test_scan_result_schema(self) -> None:
        result = run_scan(
            str(FIXTURES / "swift"),
            platform="ios",
            rules="all",
            min_severity=Severity.INFO,
        )
        assert result.files_scanned >= 0
        assert result.scan_duration_seconds >= 0
        assert isinstance(result.summary, dict)
        assert "critical" in result.summary


class TestAS006PrivacyManifest:
    """AS-006: PrivacyInfo.xcprivacy mismatch tests."""

    def test_as006_missing_manifest(self) -> None:
        """AS-006 fires when AI API call exists but no PrivacyInfo.xcprivacy."""
        result = run_scan(
            str(FIXTURES / "swift" / "violation_as006_no_manifest"),
            platform="ios",
            rules="all",
            min_severity=Severity.INFO,
        )
        ids = {f.rule_id for f in result.findings}
        assert "AS-006" in ids, f"AS-006 not found. Got: {ids}"
        as006 = [f for f in result.findings if f.rule_id == "AS-006"]
        assert as006[0].severity == Severity.CRITICAL

    def test_as006_manifest_mismatch(self) -> None:
        """AS-006 fires only for the undeclared domain (anthropic), not openai."""
        result = run_scan(
            str(FIXTURES / "swift" / "violation_as006_mismatch"),
            platform="ios",
            rules="all",
            min_severity=Severity.INFO,
        )
        as006 = [f for f in result.findings if f.rule_id == "AS-006"]
        assert len(as006) == 1, (
            f"Expected 1 AS-006, got {len(as006)}: {[f.evidence for f in as006]}"
        )
        assert as006[0].evidence is not None
        assert "anthropic" in as006[0].evidence.lower()

    def test_as006_passes_when_manifest_complete(self) -> None:
        """AS-006 does not fire when all AI domains are declared in manifest."""
        result = run_scan(
            str(FIXTURES / "swift" / "pass_as006_complete"),
            platform="ios",
            rules="all",
            min_severity=Severity.INFO,
        )
        ids = {f.rule_id for f in result.findings}
        assert "AS-006" not in ids, f"False positive AS-006: {ids}"

    def test_as006_clean_when_no_ai_calls(self) -> None:
        """AS-006 does not fire when there are no AI API calls in source."""
        result = run_scan(
            str(FIXTURES / "swift" / "violation_as007_webview"),
            platform="ios",
            rules="all",
            min_severity=Severity.INFO,
        )
        ids = {f.rule_id for f in result.findings}
        assert "AS-006" not in ids


class TestAS007CodeExecution:
    """AS-007: WKWebView dynamic content execution tests."""

    def test_as007_webview_html_string(self) -> None:
        """AS-007 fires for loadHTMLString with variable arg."""
        result = run_scan(
            str(FIXTURES / "swift" / "violation_as007_webview"),
            platform="ios",
            rules="all",
            min_severity=Severity.INFO,
        )
        ids = {f.rule_id for f in result.findings}
        assert "AS-007" in ids, f"AS-007 not found. Got: {ids}"

    def test_as007_is_critical(self) -> None:
        result = run_scan(
            str(FIXTURES / "swift" / "violation_as007_webview"),
            platform="ios",
            rules="all",
            min_severity=Severity.INFO,
        )
        as007 = [f for f in result.findings if f.rule_id == "AS-007"]
        assert as007
        assert as007[0].severity == Severity.CRITICAL

    def test_as007_both_patterns_detected(self) -> None:
        """Both loadHTMLString and evaluateJavaScript patterns fire."""
        result = run_scan(
            str(FIXTURES / "swift" / "violation_as007_webview"),
            platform="ios",
            rules="all",
            min_severity=Severity.INFO,
        )
        as007 = [f for f in result.findings if f.rule_id == "AS-007"]
        assert len(as007) >= 2, f"Expected ≥2 AS-007, got {len(as007)}"

    def test_as007_jseval_detected(self) -> None:
        """AS-007 fires for evaluateJavaScript and evaluateScript patterns."""
        result = run_scan(
            str(FIXTURES / "swift" / "violation_as007_jseval"),
            platform="ios",
            rules="all",
            min_severity=Severity.INFO,
        )
        ids = {f.rule_id for f in result.findings}
        assert "AS-007" in ids, f"AS-007 not found. Got: {ids}"

    def test_as007_passes_with_safari_view_controller(self) -> None:
        """AS-007 does not fire when SFSafariViewController is used (safe pattern)."""
        result = run_scan(
            str(FIXTURES / "swift" / "pass_as007_external"),
            platform="ios",
            rules="all",
            min_severity=Severity.INFO,
        )
        ids = {f.rule_id for f in result.findings}
        assert "AS-007" not in ids, f"False positive AS-007: {ids}"
