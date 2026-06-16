# Copyright 2026 Jaspreet Singh
# Apache-2.0

"""Tests for mobileguard.surface — ambient agent surface map scanner."""

from __future__ import annotations

from pathlib import Path

from mobileguard.surface import SurfaceScanner, SurfaceScanResult

FIXTURES = Path(__file__).parent / "fixtures"
SURFACE_FIXTURE = FIXTURES / "swift" / "surface_payment_no_confirm"


class TestSurfaceScanner:
    """Tests for the SurfaceScanner class."""

    def setup_method(self) -> None:
        self.scanner = SurfaceScanner()
        self.result = self.scanner.scan(str(SURFACE_FIXTURE))

    def test_returns_surface_scan_result(self) -> None:
        assert isinstance(self.result, SurfaceScanResult)

    def test_detects_entry_points(self) -> None:
        assert len(self.result.entry_points) >= 2

    def test_payment_intent_is_critical(self) -> None:
        critical = [e for e in self.result.entry_points if e.risk_level == "CRITICAL"]
        assert len(critical) >= 1
        names = {e.name for e in critical}
        assert "SendPaymentIntent" in names

    def test_payment_intent_has_aabe001(self) -> None:
        payment = next(
            (e for e in self.result.entry_points if e.name == "SendPaymentIntent"), None
        )
        assert payment is not None
        assert payment.finding_id == "AABE-001"

    def test_payment_intent_financial_data(self) -> None:
        payment = next(
            (e for e in self.result.entry_points if e.name == "SendPaymentIntent"), None
        )
        assert payment is not None
        assert "Financial" in payment.data_access

    def test_payment_intent_no_confirmation(self) -> None:
        payment = next(
            (e for e in self.result.entry_points if e.name == "SendPaymentIntent"), None
        )
        assert payment is not None
        assert not payment.has_confirmation

    def test_open_tab_intent_is_low_risk(self) -> None:
        tab = next(
            (e for e in self.result.entry_points if e.name == "OpenTabIntent"), None
        )
        assert tab is not None
        assert tab.risk_level == "LOW"
        assert tab.finding_id is None

    def test_open_tab_intent_no_sensitive_data(self) -> None:
        tab = next(
            (e for e in self.result.entry_points if e.name == "OpenTabIntent"), None
        )
        assert tab is not None
        assert tab.data_access == []

    def test_summary_has_critical(self) -> None:
        assert self.result.summary.get("critical", 0) >= 1

    def test_summary_has_low(self) -> None:
        assert self.result.summary.get("low", 0) >= 1


class TestSurfaceScannerEdgeCases:
    """Edge cases for the surface scanner."""

    def test_empty_directory(self, tmp_path: Path) -> None:
        scanner = SurfaceScanner()
        result = scanner.scan(str(tmp_path))
        assert result.entry_points == []

    def test_json_output(self) -> None:
        import json

        scanner = SurfaceScanner()
        result = scanner.scan(str(SURFACE_FIXTURE))
        raw = result.model_dump_json(indent=2)
        data = json.loads(raw)
        assert "entry_points" in data
        assert "summary" in data

    def test_platform_auto_detects_ios(self) -> None:
        scanner = SurfaceScanner()
        result = scanner.scan(str(SURFACE_FIXTURE), platform="auto")
        from mobileguard.models import Platform

        assert result.platform == Platform.IOS


class TestSurfaceSafeIntents:
    """surface_safe_intents: no sensitive data → all LOW, no CRITICAL/HIGH."""

    def setup_method(self) -> None:
        self.scanner = SurfaceScanner()
        self.result = self.scanner.scan(
            str(FIXTURES / "swift" / "surface_safe_intents")
        )

    def test_no_critical_findings(self) -> None:
        critical = [e for e in self.result.entry_points if e.risk_level == "CRITICAL"]
        assert len(critical) == 0, f"Unexpected CRITICAL entries: {critical}"

    def test_no_high_findings(self) -> None:
        high = [e for e in self.result.entry_points if e.risk_level == "HIGH"]
        assert len(high) == 0, f"Unexpected HIGH entries: {high}"

    def test_all_low_risk(self) -> None:
        assert len(self.result.entry_points) >= 1
        for entry in self.result.entry_points:
            assert entry.risk_level == "LOW", (
                f"{entry.name} has risk {entry.risk_level}, expected LOW"
            )

    def test_no_aabe_findings(self) -> None:
        for entry in self.result.entry_points:
            assert entry.finding_id is None, (
                f"{entry.name} has unexpected finding_id {entry.finding_id}"
            )


class TestSurfaceScannerAndroid:
    """Tests for the Android @AppFunction path."""

    def test_app_function_detected(self, tmp_path: Path) -> None:
        kt = tmp_path / "SendPaymentFunction.kt"
        kt.write_text(
            "@AppFunction\nfun sendPayment(amount: Double, recipient: String): Boolean {\n"
            "    return true\n}\n"
        )
        scanner = SurfaceScanner()
        result = scanner.scan(str(tmp_path), platform="android")
        assert len(result.entry_points) >= 1

    def test_app_function_financial_is_critical(self, tmp_path: Path) -> None:
        kt = tmp_path / "PaymentFunction.kt"
        # Use standalone "payment" keyword at word boundary to trigger Financial
        kt.write_text(
            "@AppFunction\nfun processFunds(amount: Double): Boolean {\n"
            "    payment.send(amount)\n    return true\n}\n"
        )
        scanner = SurfaceScanner()
        result = scanner.scan(str(tmp_path), platform="android")
        financial = [e for e in result.entry_points if "Financial" in e.data_access]
        assert len(financial) >= 1
        assert financial[0].risk_level == "CRITICAL"

    def test_app_function_with_confirmation_is_not_critical(self, tmp_path: Path) -> None:
        kt = tmp_path / "ConfirmedPayment.kt"
        # "transfer" and "confirm" are both at word boundaries
        kt.write_text(
            "@AppFunction\nfun execute(amount: Double): Boolean {\n"
            "    showConfirmDialog()\n    transfer.send(amount)\n    return true\n}\n"
        )
        scanner = SurfaceScanner()
        result = scanner.scan(str(tmp_path), platform="android")
        assert all(e.risk_level != "CRITICAL" for e in result.entry_points)
