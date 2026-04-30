"""Gemini initializer env-first tests."""

from __future__ import annotations

from clawsentry.cli.initializers.gemini_cli import GeminiCLIInitializer


def test_gemini_generate_config_reports_env_without_project_file(tmp_path):
    result = GeminiCLIInitializer().generate_config(tmp_path)
    assert result.env_vars["CS_FRAMEWORK"] == "gemini-cli"
    assert result.env_vars["CS_ENABLED_FRAMEWORKS"] == "gemini-cli"
    assert result.env_vars["CS_GEMINI_SETTINGS_PATH"].endswith(".gemini/settings.json")
    assert not (tmp_path / (".clawsentry" + ".toml")).exists()


def test_gemini_setup_uses_project_temp_settings(tmp_path):
    result = GeminiCLIInitializer().setup_gemini_hooks(target_dir=tmp_path)
    assert (tmp_path / ".gemini" / "settings.json").exists()
    assert result.files_modified == [tmp_path / ".gemini" / "settings.json"]
