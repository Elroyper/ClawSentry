"""Tests for init reporting env-first framework activation guidance."""

from __future__ import annotations

import json
import os
from unittest.mock import patch

import pytest

from clawsentry.cli.init_command import run_init, run_uninstall
from clawsentry.cli.initializers.a3s_code import A3SCodeInitializer
from clawsentry.cli.initializers.openclaw import OpenClawInitializer


class TestOpenClawInitializer:
    def test_generate_config_does_not_create_project_toml_or_env_file(self, tmp_path):
        result = OpenClawInitializer().generate_config(tmp_path)
        assert not (tmp_path / (".clawsentry" + ".toml")).exists()
        assert not (tmp_path / ".env.clawsentry").exists()
        assert result.files_created == []
        assert result.env_vars["CS_FRAMEWORK"] == "openclaw"
        assert result.env_vars["CS_ENABLED_FRAMEWORKS"] == "openclaw"
        assert "CS_AUTH_TOKEN" not in result.env_vars

    def test_existing_legacy_env_file_is_not_merged_or_overwritten(self, tmp_path):
        legacy = tmp_path / ".env.clawsentry"
        legacy.write_text("CS_AUTH_TOKEN" + "=keep-token\n", encoding="utf-8")
        OpenClawInitializer().generate_config(tmp_path, force=True)
        assert legacy.read_text(encoding="utf-8") == "CS_AUTH_TOKEN" + "=keep-token\n"
        assert not (tmp_path / (".clawsentry" + ".toml")).exists()


class TestA3SCodeInitializer:
    def test_generate_config_reports_env_vars_only(self, tmp_path):
        result = A3SCodeInitializer().generate_config(tmp_path)
        assert not (tmp_path / (".clawsentry" + ".toml")).exists()
        assert not (tmp_path / ".env.clawsentry").exists()
        assert result.env_vars == {"CS_FRAMEWORK": "a3s-code", "CS_ENABLED_FRAMEWORKS": "a3s-code"}

    def test_generate_config_warns_but_does_not_reuse_legacy_settings_token(self, tmp_path):
        settings_dir = tmp_path / ".a3s-code"
        settings_dir.mkdir(parents=True)
        (settings_dir / "settings.json").write_text(json.dumps({"token": "old-token"}))
        result = A3SCodeInitializer().generate_config(tmp_path)
        assert result.warnings
        assert not (tmp_path / (".clawsentry" + ".toml")).exists()


class TestRunInit:
    def test_run_init_openclaw(self, tmp_path, capsys):
        assert run_init(framework="openclaw", target_dir=tmp_path, force=False) == 0
        assert not (tmp_path / (".clawsentry" + ".toml")).exists()
        assert not (tmp_path / ".env.clawsentry").exists()
        assert "CS_FRAMEWORK=openclaw" in capsys.readouterr().out

    def test_run_init_creates_target_dir_without_project_config(self, tmp_path):
        target = tmp_path / "new" / "dir"
        assert run_init(framework="codex", target_dir=target, force=False) == 0
        assert target.exists()
        assert not (target / (".clawsentry" + ".toml")).exists()

    def test_run_uninstall_prints_env_next_step(self, tmp_path):
        assert run_uninstall(framework="openclaw", target_dir=tmp_path) == 0
        assert not (tmp_path / (".clawsentry" + ".toml")).exists()

    def test_cli_main_uninstall_codex_dispatch_uses_temp_home(self, tmp_path):
        from clawsentry.cli.main import main
        codex_home = tmp_path / "codex-home"
        with patch.dict(os.environ, {"CODEX_HOME": str(codex_home)}, clear=True):
            with pytest.raises(SystemExit) as exc:
                main(["init", "codex", "--dir", str(tmp_path), "--uninstall", "--codex-home", str(codex_home)])
        assert exc.value.code == 0
        assert not (tmp_path / (".clawsentry" + ".toml")).exists()
