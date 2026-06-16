# Copyright 2026 Jaspreet Singh
# Apache-2.0

"""Tests for mobileguard rule definitions and detector pattern correctness."""

from __future__ import annotations

import pytest

from mobileguard.models import RuleCategory, Severity
from mobileguard.rules import ALL_RULES, APP_STORE_RULES, EU_AI_ACT_RULES, GOOGLE_PLAY_RULES, OWASP_RULES
from mobileguard.detectors.swift import detect as detect_swift
from mobileguard.detectors.kotlin import detect as detect_kotlin
from mobileguard.detectors.dart import detect as detect_dart
from mobileguard.detectors.javascript import detect as detect_javascript


# ── Rule metadata tests ────────────────────────────────────────────────────────

class TestRuleMetadata:
    """Every rule must have required fields populated."""

    def test_all_rules_have_id(self) -> None:
        for rule_id, rule in ALL_RULES.items():
            assert rule.id == rule_id, f"{rule_id}: rule.id mismatch"

    def test_all_rules_have_description(self) -> None:
        for rule_id, rule in ALL_RULES.items():
            assert rule.description, f"{rule_id}: empty description"

    def test_all_rules_have_fix(self) -> None:
        for rule_id, rule in ALL_RULES.items():
            assert rule.fix, f"{rule_id}: empty fix"

    def test_all_rules_have_reference(self) -> None:
        for rule_id, rule in ALL_RULES.items():
            assert rule.reference, f"{rule_id}: empty reference"

    def test_all_rules_have_pillar(self) -> None:
        valid_pillars = {"PDQC", "TACM", "PGSG", "AABE"}
        for rule_id, rule in ALL_RULES.items():
            assert rule.pillar in valid_pillars, f"{rule_id}: invalid pillar '{rule.pillar}'"

    def test_app_store_rule_count(self) -> None:
        assert len(APP_STORE_RULES) == 5

    def test_google_play_rule_count(self) -> None:
        assert len(GOOGLE_PLAY_RULES) == 5

    def test_eu_ai_act_rule_count(self) -> None:
        assert len(EU_AI_ACT_RULES) == 4

    def test_owasp_rule_count(self) -> None:
        assert len(OWASP_RULES) == 5

    def test_as001_is_critical(self) -> None:
        assert APP_STORE_RULES["AS-001"].severity == Severity.CRITICAL

    def test_gp001_is_critical(self) -> None:
        assert GOOGLE_PLAY_RULES["GP-001"].severity == Severity.CRITICAL

    def test_eu001_is_critical(self) -> None:
        assert EU_AI_ACT_RULES["EU-001"].severity == Severity.CRITICAL

    def test_ow001_is_critical(self) -> None:
        assert OWASP_RULES["OW-001"].severity == Severity.CRITICAL

    def test_rule_categories(self) -> None:
        for rule_id, rule in APP_STORE_RULES.items():
            assert rule.category == RuleCategory.APP_STORE
        for rule_id, rule in GOOGLE_PLAY_RULES.items():
            assert rule.category == RuleCategory.GOOGLE_PLAY
        for rule_id, rule in EU_AI_ACT_RULES.items():
            assert rule.category == RuleCategory.EU_AI_ACT
        for rule_id, rule in OWASP_RULES.items():
            assert rule.category == RuleCategory.OWASP


# ── Swift detector pattern tests ──────────────────────────────────────────────

class TestSwiftDetector:
    """Unit tests for individual Swift detection patterns."""

    def test_as002_detects_anthropic_key(self) -> None:
        content = 'let key = "sk-ant-api03-somekey123456789012345"'
        findings = detect_swift("test.swift", content)
        ids = {f.rule_id for f in findings}
        assert "AS-002" in ids

    def test_as002_detects_openai_key(self) -> None:
        content = 'let key = "sk-abcdefghijklmnopqrstuvwxyz12345678901234567890"'
        findings = detect_swift("test.swift", content)
        ids = {f.rule_id for f in findings}
        assert "AS-002" in ids

    def test_as001_no_disclosure(self) -> None:
        content = 'URLRequest(url: URL(string: "https://api.anthropic.com/v1/messages")!)'
        findings = detect_swift("test.swift", content)
        ids = {f.rule_id for f in findings}
        assert "AS-001" in ids

    def test_as001_suppressed_with_disclosure(self) -> None:
        content = (
            'URLRequest(url: URL(string: "https://api.anthropic.com/v1/messages")!)\n'
            "ATTrackingManager.requestTrackingAuthorization { _ in }"
        )
        findings = detect_swift("test.swift", content)
        ids = {f.rule_id for f in findings}
        assert "AS-001" not in ids

    def test_ow001_detects_interpolation(self) -> None:
        content = (
            'let body = "https://api.anthropic.com"\n'
            'let prompt = "system: \\(userMessage)"'
        )
        findings = detect_swift("test.swift", content)
        ids = {f.rule_id for f in findings}
        assert "OW-001" in ids

    def test_no_false_positive_clean_file(self) -> None:
        content = "import SwiftUI\n\nstruct ContentView: View {\n    var body: some View { Text(\"Hello\") }\n}"
        findings = detect_swift("test.swift", content)
        assert findings == []

    def test_as002_line_number_reported(self) -> None:
        content = "// line 1\n// line 2\nlet key = \"sk-ant-api03-key12345678901234\""
        findings = detect_swift("test.swift", content)
        as002 = [f for f in findings if f.rule_id == "AS-002"]
        assert as002
        assert as002[0].line_number == 3


# ── Kotlin detector pattern tests ─────────────────────────────────────────────

class TestKotlinDetector:
    """Unit tests for individual Kotlin detection patterns."""

    def test_gp002_detects_hardcoded_key(self) -> None:
        content = 'private val apiKey = "sk-ant-api03-hardcoded12345678"'
        findings = detect_kotlin("test.kt", content)
        ids = {f.rule_id for f in findings}
        assert "GP-002" in ids

    def test_gp001_no_data_safety(self) -> None:
        content = (
            "val client = OkHttpClient()\n"
            'val request = Request.Builder().url("https://api.anthropic.com/v1/messages").build()'
        )
        findings = detect_kotlin("test.kt", content)
        ids = {f.rule_id for f in findings}
        assert "GP-001" in ids

    def test_ow003_pii_in_ai_context(self) -> None:
        content = (
            'val url = "https://api.anthropic.com/v1/messages"\n'
            "json.put(\"email\", email)"
        )
        findings = detect_kotlin("test.kt", content)
        ids = {f.rule_id for f in findings}
        assert "OW-003" in ids

    def test_ow001_kotlin_interpolation(self) -> None:
        content = (
            'val url = "https://api.anthropic.com"\n'
            'val prompt = "context: ${userMessage}"'
        )
        findings = detect_kotlin("test.kt", content)
        ids = {f.rule_id for f in findings}
        assert "OW-001" in ids

    def test_no_false_positive_clean_file(self) -> None:
        content = 'class MainActivity : AppCompatActivity() {\n    override fun onCreate() {}\n}'
        findings = detect_kotlin("test.kt", content)
        assert findings == []


# ── Dart detector pattern tests ───────────────────────────────────────────────

class TestDartDetector:
    """Unit tests for Dart/Flutter detection patterns."""

    def test_hardcoded_key_detected(self) -> None:
        content = "final apiKey = 'sk-ant-api03-somekey123456789';"
        findings = detect_dart("test.dart", content)
        ids = {f.rule_id for f in findings}
        assert "AS-002" in ids or "GP-002" in ids

    def test_ai_domain_without_disclosure(self) -> None:
        content = "await http.post(Uri.parse('https://api.anthropic.com/v1/messages'));"
        findings = detect_dart("test.dart", content)
        ids = {f.rule_id for f in findings}
        assert "AS-001" in ids or "GP-001" in ids


# ── JavaScript detector pattern tests ─────────────────────────────────────────

class TestJavaScriptDetector:
    """Unit tests for JavaScript/TypeScript detection patterns."""

    def test_hardcoded_key_detected(self) -> None:
        content = "const key = 'sk-ant-api03-somekey12345678901234';"
        findings = detect_javascript("test.js", content)
        ids = {f.rule_id for f in findings}
        assert "AS-002" in ids or "GP-002" in ids

    def test_fetch_to_ai_domain(self) -> None:
        content = "fetch('https://api.anthropic.com/v1/messages', { method: 'POST' })"
        findings = detect_javascript("test.js", content)
        ids = {f.rule_id for f in findings}
        assert "AS-001" in ids or "GP-001" in ids

    def test_ow001_template_literal(self) -> None:
        content = (
            "fetch('https://api.openai.com/v1/chat/completions')\n"
            "const prompt = `system: ${userMessage}`"
        )
        findings = detect_javascript("test.js", content)
        ids = {f.rule_id for f in findings}
        assert "OW-001" in ids

    def test_no_false_positive_clean_file(self) -> None:
        content = "const greet = (name) => `Hello, ${name}!`;"
        findings = detect_javascript("test.js", content)
        assert findings == []
