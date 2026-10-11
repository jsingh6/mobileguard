# Copyright 2026 Jaspreet Singh
# Apache-2.0

"""Tests for the MobileGuard skill's AI surface mapper (skills/mobileguard/scripts)."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import pytest

_ROOT = Path(__file__).parent.parent
_SCRIPT = _ROOT / "skills" / "mobileguard" / "scripts" / "ai_surface.py"
_RN_APP = Path(__file__).parent / "fixtures" / "react_native_ai_app"

_spec = importlib.util.spec_from_file_location("ai_surface", _SCRIPT)
assert _spec and _spec.loader
ai_surface = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ai_surface)


@pytest.fixture(scope="module")
def surface() -> dict[str, Any]:
    result: dict[str, Any] = ai_surface.Surface(_RN_APP, max_per_check=40).run()
    return result


def _leads(
    surface: dict[str, Any], check: str, *, include_tests: bool = False
) -> list[dict[str, Any]]:
    leads = surface["leads"].get(check, [])
    return [lead for lead in leads if include_tests or not lead["test_code"]]


class TestStackAndDependencies:
    def test_detects_expo_react_native(self, surface: dict[str, Any]) -> None:
        assert {"expo", "react-native"} <= set(surface["stack"])

    def test_detects_ai_sdks_from_package_json(self, surface: dict[str, Any]) -> None:
        packages = {d["package"] for d in surface["ai_dependencies"]}
        assert {"openai", "ai", "@ai-sdk/openai"} <= packages

    def test_js_import_is_not_reported_as_swift_sdk(self, surface: dict[str, Any]) -> None:
        assert "native_ai_imports" not in surface["config"]

    def test_detects_payment_packages(self, surface: dict[str, Any]) -> None:
        assert "@stripe/stripe-react-native" in surface["config"]["payment_packages"]


class TestSecrets:
    def test_expo_public_key_in_env_file(self, surface: dict[str, Any]) -> None:
        hits = [lead for lead in _leads(surface, "MG-S01") if lead["file"] == ".env"]
        assert hits and "EXPO_PUBLIC_" in hits[0]["note"]

    def test_key_value_is_masked(self, surface: dict[str, Any]) -> None:
        for lead in _leads(surface, "MG-S01", include_tests=True):
            assert "a" * 20 not in lead["evidence"]

    def test_client_side_sdk_flagged(self, surface: dict[str, Any]) -> None:
        notes = [lead["note"] for lead in _leads(surface, "MG-S01")]
        assert any("dangerouslyAllowBrowser" in n or "client holds the key" in n for n in notes)

    def test_test_code_is_tagged(self, surface: dict[str, Any]) -> None:
        leads = _leads(surface, "MG-S01", include_tests=True)
        test_hits = [lead for lead in leads if lead["test_code"]]
        assert test_hits and all(h["file"].startswith("__tests__/") for h in test_hits)


class TestStoreLeads:
    def test_ai_host_in_tracking_domains_is_flagged(self, surface: dict[str, Any]) -> None:
        hits = _leads(surface, "MG-R02")
        assert hits and hits[0]["evidence"] == "api.openai.com"

    def test_brand_in_app_name(self, surface: dict[str, Any]) -> None:
        assert any("ChatGPT" in lead["evidence"] for lead in _leads(surface, "MG-R08"))

    def test_absent_gates_reported(self, surface: dict[str, Any]) -> None:
        absent = " ".join(surface["absent"])
        for check in ("MG-R01", "MG-R04", "MG-S02", "MG-S11"):
            assert check in absent


class TestSecurityLeads:
    @pytest.mark.parametrize(
        ("check", "needle"),
        [
            ("MG-S04", "eval("),
            ("MG-S04", "source={{ html"),
            ("MG-S04", "Linking.openURL"),
            ("MG-S05", "onMessage"),
            ("MG-S05", "tools:"),
            ("MG-S06", "expo-contacts"),
            ("MG-S07", "AsyncStorage.setItem"),
            ("MG-S08", "console.log"),
        ],
    )
    def test_lead_found(self, surface: dict[str, Any], check: str, needle: str) -> None:
        assert any(needle in lead["evidence"] for lead in _leads(surface, check))

    def test_server_route_token_cap_is_marked_server_side(self, surface: dict[str, Any]) -> None:
        caps = _leads(surface, "MG-S02")
        assert caps and all("[server-side file]" in lead["note"] for lead in caps)


class TestCli:
    def test_main_rejects_missing_dir(self, tmp_path: Path) -> None:
        assert ai_surface.main([str(tmp_path / "nope")]) == 2

    def test_non_ai_repo_has_no_absent_gates(self, tmp_path: Path) -> None:
        (tmp_path / "App.tsx").write_text("export const x = 1;\n")
        result = ai_surface.Surface(tmp_path, 40).run()
        assert result["ai_present"] is False and result["absent"] == []


class TestLedgerDrift:
    def test_snapshot_is_stable_and_line_free(self, surface: dict[str, Any]) -> None:
        facts = ai_surface.snapshot(surface)
        assert facts == sorted(facts)
        assert not any(":4" in f or "__tests__" in f for f in facts)
        assert "provider: OpenAI [cloud] (openai)" in facts

    def test_diff_against_ledger(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        facts = ai_surface.snapshot(ai_surface.Surface(_RN_APP, 10_000).run())
        recorded = [f for f in facts if "expo-contacts" not in f and "MG-S06" not in f]
        recorded.append("provider: Anthropic [cloud] (@anthropic-ai/sdk)")
        ledger = tmp_path / "MOBILEGUARD.md"
        ledger.write_text(
            "# ledger\n\n## Snapshot (last release)\n```\n" + "\n".join(recorded) + "\n```\n"
        )
        assert ai_surface.main([str(_RN_APP), "--diff-ledger", str(ledger)]) == 0
        out = capsys.readouterr().out.splitlines()
        assert "- provider: Anthropic [cloud] (@anthropic-ai/sdk)" in out
        assert any(line.startswith("+ MG-S06") for line in out)

    def test_fail_on_drift_exit_codes(self, tmp_path: Path) -> None:
        facts = ai_surface.snapshot(ai_surface.Surface(_RN_APP, 10_000).run())
        ledger = tmp_path / "MOBILEGUARD.md"
        block = "## Snapshot\n```\n{}\n```\n"
        ledger.write_text(block.format("\n".join(facts)))
        args = [str(_RN_APP), "--diff-ledger", str(ledger), "--fail-on-drift"]
        assert ai_surface.main(args) == 0
        ledger.write_text(block.format("\n".join(facts[1:])))
        assert ai_surface.main(args) == 1

    def test_ledger_without_snapshot(self, tmp_path: Path) -> None:
        ledger = tmp_path / "MOBILEGUARD.md"
        ledger.write_text("# ledger\n")
        assert ai_surface.main([str(_RN_APP), "--diff-ledger", str(ledger)]) == 3

    def test_template_placeholder_is_ignored(self) -> None:
        text = "## Snapshot (last release)\n```\n<output of ai_surface.py --snapshot>\n```\n"
        assert ai_surface.ledger_snapshot(text) == []


def _run(tmp_path: Path, files: dict[str, str]) -> dict[str, Any]:
    for rel, body in files.items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body)
    result: dict[str, Any] = ai_surface.Surface(tmp_path, 500).run()
    return result


class TestValidationRegressions:
    """Cases found by running the skill on real open-source apps (Oct 2026)."""

    def test_secrets_gradle_plugin_key_is_caught(self, tmp_path: Path) -> None:
        # chatgpt-android: git-ignored secrets.properties -> BuildConfig -> APK
        result = _run(tmp_path, {
            "gradle/libs.versions.toml": 'google-secrets = { id = "com.google.android.libraries.mapsplatform.secrets-gradle-plugin" }\n',
            "net/GPTInterceptor.kt": 'addHeader("Authorization", "Bearer ${BuildConfig.GPT_API_KEY}")\n',
        })
        notes = " ".join(lead["note"] for lead in result["leads"]["MG-S01"])
        assert "BuildConfig secret" in notes and "Secrets Gradle plugin" in notes

    def test_gradle_ai_dependencies_detected(self, tmp_path: Path) -> None:
        result = _run(tmp_path, {
            "app/build.gradle.kts": 'implementation("com.aallam.openai:openai-client:4.0.1")\n',
            "gradle/libs.versions.toml": 'genai = { module = "com.google.ai.client.generativeai:generativeai" }\n',
        })
        providers = {d["provider"] for d in result["ai_dependencies"]}
        assert {"OpenAI (Kotlin)", "Google Gemini (Android)"} <= providers

    @pytest.mark.parametrize(
        ("rel", "line"),
        [
            ("Keys.swift", 'claudeApiKey = UserDefaults.standard.string(forKey: "claude_api_key") ?? ""'),
            ("Settings.swift", '@AppStorage("ollamaBearerToken") private var token: String = ""'),
            ("openai.tsx", 'const [apiKey, setApiKey] = useStoredString("open-ai-api-key");'),
            ("Prefs.kt", 'prefs.edit().putString("openai_token", value).apply()'),
        ],
    )
    def test_credential_in_plain_storage(self, tmp_path: Path, rel: str, line: str) -> None:
        result = _run(tmp_path, {rel: line + "\n"})
        assert any("credential" in lead["note"] for lead in result["leads"].get("MG-S07", []))

    def test_src_api_is_client_code(self, tmp_path: Path) -> None:
        # pocketpal: src/api/ is RN client code, not a server
        result = _run(tmp_path, {"src/api/openai.ts": "const body = { tools: [] };\n"})
        assert all("[server-side file]" not in lead["note"] for lead in result["leads"]["MG-S05"])

    def test_debug_manifest_cleartext_ignored(self, tmp_path: Path) -> None:
        result = _run(tmp_path, {
            "android/app/src/debug/AndroidManifest.xml": '<application android:usesCleartextTraffic="true"/>\n',
        })
        assert "MG-S10" not in result["leads"]

    def test_commented_code_is_not_a_lead(self, tmp_path: Path) -> None:
        result = _run(tmp_path, {"Engine.swift": '//     print("detokenized prompt: \\(prompt)")\n'})
        assert "MG-S08" not in result["leads"]

    def test_static_sql_is_not_a_lead(self, tmp_path: Path) -> None:
        result = _run(tmp_path, {
            "Migrations.kt": 'db.execSQL("ALTER TABLE chats ADD COLUMN title TEXT")\n',
            "Search.kt": 'db.rawQuery("SELECT * FROM chats WHERE title = \'$query\'", null)\n',
        })
        files = {lead["file"] for lead in result["leads"].get("MG-S04", [])}
        assert files == {"Search.kt"}

    def test_jest_setup_is_test_code(self, tmp_path: Path) -> None:
        result = _run(tmp_path, {"jest.env.js": 'process.env.EXPO_PUBLIC_SUPABASE_KEY ||= "x";\n'})
        assert all(lead["test_code"] for lead in result["leads"]["MG-S01"])
