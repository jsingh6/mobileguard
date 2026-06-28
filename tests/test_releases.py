# Copyright 2026 Jaspreet Singh
#
# Licensed under the Apache License, Version 2.0 (the "License");

"""Tests for the AS-009 Release Notes AI Disclosure Scanner (mobileguard releases)."""

import pytest
from mobileguard.releases import (
    AppRecord,
    _apply_as009_rules,
    _is_first_party,
    COHORT_TERMS,
)


def _make_app(**kwargs) -> AppRecord:
    defaults = dict(
        app_id="123",
        name="Test App",
        developer="Test Dev",
        bundle_id="com.test.app",
        category="Productivity",
        version="1.0.0",
        release_notes="",
        platform="ios",
        search_term="test",
    )
    defaults.update(kwargs)
    return AppRecord(**defaults)


# ── AS-009-A: Multiple named providers ───────────────────────────────────────

class TestAS009A:
    def test_two_providers_triggers_critical(self):
        app = _make_app(release_notes="Now powered by GPT-4 and Claude for smarter responses.")
        findings = _apply_as009_rules(app)
        rule_ids = [f.rule_id for f in findings]
        assert "AS-009-A" in rule_ids
        a = next(f for f in findings if f.rule_id == "AS-009-A")
        assert a.severity == "critical"
        assert a.pillar == "PGSG"

    def test_single_provider_no_trigger(self):
        app = _make_app(release_notes="Now powered by GPT-4 for smarter responses.")
        findings = _apply_as009_rules(app)
        assert not any(f.rule_id == "AS-009-A" for f in findings)

    def test_four_providers_triggers_once(self):
        app = _make_app(
            release_notes="Switch between GPT-4, Claude, Gemini, and Mistral seamlessly."
        )
        findings = _apply_as009_rules(app)
        a_findings = [f for f in findings if f.rule_id == "AS-009-A"]
        assert len(a_findings) == 1  # dedup — report once per app

    def test_provider_names_in_matched_text(self):
        app = _make_app(release_notes="Powered by Claude and Gemini AI models.")
        findings = _apply_as009_rules(app)
        a = next(f for f in findings if f.rule_id == "AS-009-A")
        assert "claude" in a.matched_text.lower()
        assert "gemini" in a.matched_text.lower()


# ── AS-009-B: AI intro without disclosure ────────────────────────────────────

class TestAS009B:
    def test_ai_intro_without_disclosure_warns(self):
        app = _make_app(release_notes="New AI-powered features added to improve your workflow.")
        findings = _apply_as009_rules(app)
        assert any(f.rule_id == "AS-009-B" for f in findings)

    def test_ai_intro_with_disclosure_no_warn(self):
        app = _make_app(
            release_notes=(
                "New AI-powered features added. All processing is on-device. "
                "No data sent to the cloud."
            )
        )
        findings = _apply_as009_rules(app)
        assert not any(f.rule_id == "AS-009-B" for f in findings)

    def test_moleskine_pattern(self):
        """Reproduce the real Moleskine Srl AS-009-B finding from Study 3."""
        app = _make_app(
            name="Moleskine Notebooks",
            developer="Moleskine Srl",
            release_notes=(
                "powerful new AI features to better transcribe your text "
                "and turn sketches into artwork"
            ),
        )
        findings = _apply_as009_rules(app)
        assert any(f.rule_id == "AS-009-B" for f in findings)

    def test_severity_is_warning(self):
        app = _make_app(release_notes="Added AI assistant features to help you write better.")
        findings = _apply_as009_rules(app)
        b = next((f for f in findings if f.rule_id == "AS-009-B"), None)
        if b:
            assert b.severity == "warning"


# ── AS-009-C: Training data collection ───────────────────────────────────────

class TestAS009C:
    def test_training_language_triggers_info(self):
        app = _make_app(
            release_notes="Your feedback helps us improve our AI model over time."
        )
        findings = _apply_as009_rules(app)
        assert any(f.rule_id == "AS-009-C" for f in findings)
        c = next(f for f in findings if f.rule_id == "AS-009-C")
        assert c.severity == "info"

    def test_no_training_language_no_trigger(self):
        app = _make_app(release_notes="Bug fixes and performance improvements.")
        findings = _apply_as009_rules(app)
        assert not any(f.rule_id == "AS-009-C" for f in findings)

    def test_moleskine_training_pattern(self):
        """Moleskine also triggered AS-009-C in Study 3."""
        app = _make_app(
            release_notes=(
                "New AI features added. Your notes are processed "
                "to improve our AI model."
            )
        )
        findings = _apply_as009_rules(app)
        assert any(f.rule_id == "AS-009-C" for f in findings)


# ── AS-009-D: Biometric/behavioral data ──────────────────────────────────────

class TestAS009D:
    def test_face_recognition_triggers(self):
        app = _make_app(
            release_notes="New AI-powered face recognition added for smart photo organization."
        )
        findings = _apply_as009_rules(app)
        assert any(f.rule_id == "AS-009-D" for f in findings)

    def test_voice_recognition_triggers(self):
        app = _make_app(
            release_notes="Voice recognition now powered by on-device AI."
        )
        findings = _apply_as009_rules(app)
        assert any(f.rule_id == "AS-009-D" for f in findings)

    def test_severity_is_warning(self):
        app = _make_app(
            release_notes="Emotion detection AI added to personalize your feed."
        )
        findings = _apply_as009_rules(app)
        d = next((f for f in findings if f.rule_id == "AS-009-D"), None)
        if d:
            assert d.severity == "warning"
            assert d.pillar == "AABE"


# ── AS-009-F: Autonomous action (TAC-M) ──────────────────────────────────────

class TestAS009F:
    def test_auto_post_triggers_critical(self):
        """Reproduce the Volm Gym Workout Tracker finding from Study 3."""
        app = _make_app(
            name="Volm Gym Workout Tracker",
            release_notes="automatically post finished workouts to Strava",
        )
        findings = _apply_as009_rules(app)
        assert any(f.rule_id == "AS-009-F" for f in findings)
        f = next(f for f in findings if f.rule_id == "AS-009-F")
        assert f.severity == "critical"
        assert f.pillar == "TAC-M"

    def test_auto_send_triggers(self):
        app = _make_app(
            release_notes="Smart replies are now automatically sent when you are busy."
        )
        findings = _apply_as009_rules(app)
        assert any(f.rule_id == "AS-009-F" for f in findings)

    def test_auto_share_triggers(self):
        app = _make_app(
            release_notes="Your achievements are automatically shared to your social feed."
        )
        findings = _apply_as009_rules(app)
        assert any(f.rule_id == "AS-009-F" for f in findings)

    def test_manual_post_no_trigger(self):
        app = _make_app(
            release_notes="Tap the share button to post your workout to Strava."
        )
        findings = _apply_as009_rules(app)
        assert not any(f.rule_id == "AS-009-F" for f in findings)

    def test_dedup_reports_once(self):
        app = _make_app(
            release_notes=(
                "automatically post workouts to Strava. "
                "automatically share achievements. "
                "automatically send summaries."
            )
        )
        findings = _apply_as009_rules(app)
        f_findings = [f for f in findings if f.rule_id == "AS-009-F"]
        assert len(f_findings) == 1


# ── First-party exclusion ─────────────────────────────────────────────────────

class TestFirstPartyExclusion:
    def test_anthropic_bundle_excluded(self):
        app = _make_app(bundle_id="com.anthropic.claude", name="Claude")
        assert _is_first_party(app)

    def test_openai_bundle_excluded(self):
        app = _make_app(bundle_id="com.openai.chatgpt", name="ChatGPT")
        assert _is_first_party(app)

    def test_meta_bundle_excluded(self):
        app = _make_app(bundle_id="com.meta.social", name="Meta AI")
        assert _is_first_party(app)

    def test_claude_name_excluded(self):
        app = _make_app(bundle_id="com.unknown.app", name="Claude by Anthropic")
        assert _is_first_party(app)

    def test_third_party_not_excluded(self):
        app = _make_app(bundle_id="com.moleskine.journal", name="Moleskine Notebooks")
        assert not _is_first_party(app)

    def test_adobe_not_excluded(self):
        app = _make_app(bundle_id="com.adobe.photoshop", name="Adobe Photoshop Express")
        assert not _is_first_party(app)


# ── Clean release notes ───────────────────────────────────────────────────────

class TestCleanReleaseNotes:
    def test_bug_fix_only_no_findings(self):
        app = _make_app(release_notes="Bug fixes and performance improvements.")
        assert _apply_as009_rules(app) == []

    def test_empty_release_notes_no_findings(self):
        app = _make_app(release_notes="")
        assert _apply_as009_rules(app) == []

    def test_version_bump_no_findings(self):
        app = _make_app(release_notes="Minor updates and stability improvements. v2.1.3")
        assert _apply_as009_rules(app) == []


# ── Cohort presets ────────────────────────────────────────────────────────────

class TestCohortPresets:
    def test_ai_native_has_15_terms(self):
        assert len(COHORT_TERMS["ai-native"]) == 15

    def test_traditional_has_15_terms(self):
        assert len(COHORT_TERMS["traditional"]) == 15

    def test_social_has_15_terms(self):
        assert len(COHORT_TERMS["social"]) == 15

    def test_all_cohorts_present(self):
        assert set(COHORT_TERMS.keys()) == {"ai-native", "traditional", "social"}
