"""Tests for Gemini CLI framework initializer."""

from __future__ import annotations

import json

from clawsentry.cli.initializers import FRAMEWORK_INITIALIZERS, get_initializer
from clawsentry.cli.initializers.gemini_cli import GeminiCLIInitializer


def _read_env(path):
    values = {}
    for line in path.read_text().splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value
    return values


class TestGeminiInitializer:
    def test_registered(self):
        assert "gemini-cli" in FRAMEWORK_INITIALIZERS
        assert get_initializer("gemini-cli").framework_name == "gemini-cli"

    def test_generate_config_creates_env_with_settings_path(self, tmp_path):
        result = GeminiCLIInitializer().generate_config(tmp_path)
        env_path = tmp_path / ".env.clawsentry"
        env = _read_env(env_path)

        assert env_path.exists()
        assert result.env_vars["CS_FRAMEWORK"] == "gemini-cli"
        assert env["CS_GEMINI_HOOKS_ENABLED"] == "true"
        assert env["CS_GEMINI_SETTINGS_PATH"] == str(tmp_path / ".gemini" / "settings.json")
        assert "CS_AUTH_TOKEN" in env

    def test_setup_writes_project_local_settings_and_preserves_user_hooks(self, tmp_path):
        settings_path = tmp_path / ".gemini" / "settings.json"
        settings_path.parent.mkdir()
        settings_path.write_text(
            json.dumps(
                {
                    "theme": "dark",
                    "hooks": {
                        "BeforeTool": [
                            {
                                "hooks": [
                                    {"type": "command", "command": "echo user-hook"}
                                ]
                            }
                        ]
                    },
                }
            ),
            encoding="utf-8",
        )

        result = GeminiCLIInitializer().setup_gemini_hooks(target_dir=tmp_path)
        payload = json.loads(settings_path.read_text(encoding="utf-8"))

        assert payload["theme"] == "dark"
        assert payload["hooksConfig"]["enabled"] is True
        assert payload["hooks"]["enabled"] is True
        assert "echo user-hook" in str(payload)
        assert "clawsentry harness --framework gemini-cli" in str(payload)
        assert "BeforeAgent" in payload["hooks"]
        assert settings_path in result.files_modified

    def test_setup_is_idempotent(self, tmp_path):
        init = GeminiCLIInitializer()
        init.setup_gemini_hooks(target_dir=tmp_path)
        init.setup_gemini_hooks(target_dir=tmp_path)
        payload = json.loads((tmp_path / ".gemini" / "settings.json").read_text())

        for event_name, entries in payload["hooks"].items():
            if event_name == "enabled":
                continue
            managed = [entry for entry in entries if "clawsentry harness --framework gemini-cli" in str(entry)]
            assert len(managed) == 1

    def test_strong_events_sync_and_advisory_events_async(self, tmp_path):
        GeminiCLIInitializer().setup_gemini_hooks(target_dir=tmp_path)
        payload = json.loads((tmp_path / ".gemini" / "settings.json").read_text())

        for event_name in ("BeforeAgent", "AfterAgent", "BeforeModel", "AfterModel", "BeforeTool", "AfterTool"):
            command = payload["hooks"][event_name][0]["hooks"][0]["command"]
            assert "clawsentry harness --framework gemini-cli" in command
            assert "--async" not in command
            assert "|| true" in command
            assert "CS_HARNESS_DIAG_LOG" in command
        for event_name in ("SessionStart", "SessionEnd", "BeforeToolSelection", "PreCompress", "Notification"):
            command = payload["hooks"][event_name][0]["hooks"][0]["command"]
            assert "clawsentry harness --framework gemini-cli --async" in command
            assert "|| true" in command
            assert "CS_HARNESS_DIAG_LOG" in command

    def test_dry_run_writes_nothing(self, tmp_path):
        GeminiCLIInitializer().setup_gemini_hooks(target_dir=tmp_path, dry_run=True)
        assert not (tmp_path / ".gemini" / "settings.json").exists()

    def test_uninstall_removes_only_managed_entries(self, tmp_path):
        init = GeminiCLIInitializer()
        init.setup_gemini_hooks(target_dir=tmp_path)
        settings_path = tmp_path / ".gemini" / "settings.json"
        payload = json.loads(settings_path.read_text())
        payload["hooks"]["BeforeTool"].insert(0, {"hooks": [{"type": "command", "command": "echo user"}]})
        settings_path.write_text(json.dumps(payload), encoding="utf-8")

        result = init.uninstall(target_dir=tmp_path)
        cleaned = json.loads(settings_path.read_text())

        assert "echo user" in str(cleaned)
        assert "clawsentry harness --framework gemini-cli" not in str(cleaned)
        assert "removed" in " ".join(result.next_steps).lower()

    def test_custom_gemini_home_targets_explicit_settings(self, tmp_path):
        gemini_home = tmp_path / "custom-gemini"
        GeminiCLIInitializer().setup_gemini_hooks(target_dir=tmp_path, gemini_home=gemini_home)
        assert (gemini_home / "settings.json").exists()
        assert not (tmp_path / ".gemini" / "settings.json").exists()
