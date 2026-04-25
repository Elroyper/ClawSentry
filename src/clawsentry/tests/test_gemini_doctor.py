"""Tests for Gemini CLI doctor checks."""

from __future__ import annotations

import json

from clawsentry.cli.doctor_command import (
    ALL_CHECKS,
    check_gemini_config,
    check_gemini_native_hooks,
)
from clawsentry.cli.initializers.gemini_cli import GeminiCLIInitializer


class TestGeminiDoctor:
    def test_gemini_config_skips_when_not_enabled(self, monkeypatch):
        monkeypatch.delenv("CS_FRAMEWORK", raising=False)
        monkeypatch.delenv("CS_ENABLED_FRAMEWORKS", raising=False)
        result = check_gemini_config()
        assert result.status == "PASS"
        assert "skipped" in result.message.lower()

    def test_gemini_config_warns_without_token(self, monkeypatch):
        monkeypatch.setenv("CS_FRAMEWORK", "gemini-cli")
        monkeypatch.setenv("CS_GEMINI_HOOKS_ENABLED", "true")
        monkeypatch.delenv("CS_AUTH_TOKEN", raising=False)
        result = check_gemini_config()
        assert result.status == "WARN"
        assert "CS_AUTH_TOKEN" in result.message

    def test_gemini_config_passes_with_token_and_hook_flag(self, monkeypatch):
        monkeypatch.setenv("CS_FRAMEWORK", "gemini-cli")
        monkeypatch.setenv("CS_GEMINI_HOOKS_ENABLED", "true")
        monkeypatch.setenv("CS_AUTH_TOKEN", "strong-token-value")
        result = check_gemini_config()
        assert result.status == "PASS"
        assert "Gemini CLI configured" in result.message

    def test_gemini_native_hooks_skip_when_not_enabled(self, monkeypatch):
        monkeypatch.delenv("CS_FRAMEWORK", raising=False)
        monkeypatch.delenv("CS_ENABLED_FRAMEWORKS", raising=False)
        result = check_gemini_native_hooks()
        assert result.status == "PASS"
        assert "skipped" in result.message.lower()

    def test_gemini_native_hooks_warn_when_missing(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CS_FRAMEWORK", "gemini-cli")
        monkeypatch.setenv("CS_GEMINI_SETTINGS_PATH", str(tmp_path / ".gemini" / "settings.json"))
        result = check_gemini_native_hooks()
        assert result.status == "WARN"
        assert "not installed" in result.message.lower()

    def test_gemini_native_hooks_pass_when_managed_entries_present(self, tmp_path, monkeypatch):
        GeminiCLIInitializer().setup_gemini_hooks(target_dir=tmp_path)
        monkeypatch.setenv("CS_FRAMEWORK", "gemini-cli")
        monkeypatch.setenv("CS_GEMINI_SETTINGS_PATH", str(tmp_path / ".gemini" / "settings.json"))

        result = check_gemini_native_hooks()

        assert result.status == "PASS"
        assert "settings.json" in result.message
        assert "BeforeTool: sync" in result.detail
        assert "BeforeAgent: sync" in result.detail
        assert "SessionStart: async" in result.detail
        assert "real BeforeTool deny for run_shell_command" in result.detail

    def test_gemini_native_hooks_warn_when_beforetool_is_async(self, tmp_path, monkeypatch):
        GeminiCLIInitializer().setup_gemini_hooks(target_dir=tmp_path)
        settings_path = tmp_path / ".gemini" / "settings.json"
        payload = json.loads(settings_path.read_text(encoding="utf-8"))
        payload["hooks"]["BeforeTool"][0]["hooks"][0]["command"] = (
            "sh -c 'clawsentry harness --framework gemini-cli --async "
            "2>>\"${CS_HARNESS_DIAG_LOG:-/dev/null}\" || true'"
        )
        settings_path.write_text(json.dumps(payload), encoding="utf-8")
        monkeypatch.setenv("CS_FRAMEWORK", "gemini-cli")
        monkeypatch.setenv("CS_GEMINI_SETTINGS_PATH", str(settings_path))

        result = check_gemini_native_hooks()
        assert result.status == "WARN"
        assert "BeforeTool" in result.detail
        assert "synchronous" in result.detail

    def test_gemini_checks_registered(self):
        assert check_gemini_config in ALL_CHECKS
        assert check_gemini_native_hooks in ALL_CHECKS
