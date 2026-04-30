"""Kimi initializer env-first tests."""

from __future__ import annotations

from clawsentry.cli.initializers.kimi_cli import KimiCLIInitializer


def test_kimi_generate_config_reports_env_without_project_file(tmp_path):
    result = KimiCLIInitializer().generate_config(tmp_path, kimi_home=tmp_path / "kimi-home")
    assert result.env_vars["CS_FRAMEWORK"] == "kimi-cli"
    assert result.env_vars["CS_ENABLED_FRAMEWORKS"] == "kimi-cli"
    assert result.env_vars["CS_KIMI_HOOKS_ENABLED"] == "true"
    assert not (tmp_path / (".clawsentry" + ".toml")).exists()


def test_kimi_setup_uses_temp_home(tmp_path):
    kimi_home = tmp_path / "kimi-home"
    result = KimiCLIInitializer().setup_kimi_hooks(target_dir=tmp_path, kimi_home=kimi_home)
    assert kimi_home.joinpath("config.toml").exists()
    assert result.files_modified == [kimi_home / "config.toml"]
