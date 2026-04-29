"""Tests for Gemini CLI initializer under TOML-first config model."""

from __future__ import annotations

import json

from clawsentry.cli.initializers.gemini_cli import GeminiCLIInitializer
from clawsentry.gateway.project_config import read_project_frameworks


def test_generate_config_creates_toml_with_settings_path_suggestion(tmp_path):
    result = GeminiCLIInitializer().generate_config(tmp_path)

    assert (tmp_path / ".clawsentry.toml").exists()
    assert not (tmp_path / ".env.clawsentry").exists()
    assert result.env_vars["CLAW_SENTRY_FRAMEWORK"] == "gemini-cli"
    assert result.env_vars["CS_GEMINI_SETTINGS_PATH"].endswith(".gemini/settings.json")
    assert read_project_frameworks(tmp_path)[0] == ["gemini-cli"]


def test_setup_gemini_hooks_writes_project_settings(tmp_path):
    init = GeminiCLIInitializer()
    result = init.setup_gemini_hooks(target_dir=tmp_path, dry_run=False)

    settings_path = tmp_path / ".gemini" / "settings.json"
    assert settings_path.exists()
    assert result.files_modified == [settings_path]
    assert "clawsentry harness --framework gemini-cli" in settings_path.read_text()


def test_uninstall_removes_gemini_hooks(tmp_path):
    init = GeminiCLIInitializer()
    init.setup_gemini_hooks(target_dir=tmp_path, dry_run=False)

    result = init.uninstall(target_dir=tmp_path)

    assert result.next_steps
    payload = json.loads((tmp_path / ".gemini" / "settings.json").read_text())
    assert "clawsentry harness --framework gemini-cli" not in str(payload)
