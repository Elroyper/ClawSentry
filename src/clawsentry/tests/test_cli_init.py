"""Tests for init writing .clawsentry.toml framework state (no .env generation)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from clawsentry.cli.init_command import run_init, run_uninstall
from clawsentry.cli.initializers.a3s_code import A3SCodeInitializer
from clawsentry.cli.initializers.openclaw import OpenClawInitializer
from clawsentry.gateway.project_config import read_project_frameworks


def _frameworks_text(path: Path) -> str:
    return (path / ".clawsentry.toml").read_text(encoding="utf-8")


class TestOpenClawInitializer:
    def test_generate_config_creates_toml_not_env_file(self, tmp_path):
        result = OpenClawInitializer().generate_config(tmp_path)

        assert (tmp_path / ".clawsentry.toml").exists()
        assert not (tmp_path / ".env.clawsentry").exists()
        assert tmp_path / ".clawsentry.toml" in result.files_created
        assert "CS_AUTH_TOKEN" not in _frameworks_text(tmp_path)
        assert "OPENCLAW_WEBHOOK_TOKEN" not in _frameworks_text(tmp_path)

    def test_generate_config_env_vars_are_runtime_suggestions_only(self, tmp_path):
        result = OpenClawInitializer().generate_config(tmp_path)
        assert result.env_vars["CLAW_SENTRY_FRAMEWORK"] == "openclaw"
        assert "OPENCLAW_WEBHOOK_TOKEN" in result.env_vars
        assert "CS_AUTH_TOKEN" not in result.env_vars
        assert any("--env-file .clawsentry.env.local" in s for s in result.next_steps)

    def test_existing_legacy_env_file_is_not_merged_or_overwritten(self, tmp_path):
        legacy = tmp_path / ".env.clawsentry"
        legacy.write_text("CS_AUTH_TOKEN=keep-token\n", encoding="utf-8")

        OpenClawInitializer().generate_config(tmp_path, force=True)

        assert legacy.read_text(encoding="utf-8") == "CS_AUTH_TOKEN=keep-token\n"
        assert 'default = "openclaw"' in _frameworks_text(tmp_path)


class TestA3SCodeInitializer:
    def test_generate_config_creates_toml_not_env_file(self, tmp_path):
        result = A3SCodeInitializer().generate_config(tmp_path)

        assert (tmp_path / ".clawsentry.toml").exists()
        assert not (tmp_path / ".env.clawsentry").exists()
        assert result.env_vars == {"CLAW_SENTRY_FRAMEWORK": "a3s-code"}
        text = _frameworks_text(tmp_path)
        assert 'enabled = ["a3s-code"]' in text
        assert "CS_AUTH_TOKEN" not in text

    def test_generate_config_warns_but_does_not_reuse_legacy_settings_token(self, tmp_path):
        settings_dir = tmp_path / ".a3s-code"
        settings_dir.mkdir(parents=True)
        (settings_dir / "settings.json").write_text(json.dumps({"token": "old-token"}))

        result = A3SCodeInitializer().generate_config(tmp_path)

        assert result.warnings
        assert "old-token" not in _frameworks_text(tmp_path)


class TestRunInit:
    def test_run_init_openclaw(self, tmp_path, capsys):
        assert run_init(framework="openclaw", target_dir=tmp_path, force=False) == 0
        assert (tmp_path / ".clawsentry.toml").exists()
        assert not (tmp_path / ".env.clawsentry").exists()
        assert "OpenClaw" not in capsys.readouterr().err

    def test_run_init_a3s_code(self, tmp_path):
        assert run_init(framework="a3s-code", target_dir=tmp_path, force=False) == 0
        assert read_project_frameworks(tmp_path)[0] == ["a3s-code"]

    def test_run_init_creates_target_dir(self, tmp_path):
        target = tmp_path / "new" / "dir"
        assert run_init(framework="codex", target_dir=target, force=False) == 0
        assert (target / ".clawsentry.toml").exists()

    def test_run_init_merges_multiple_frameworks_without_env_file(self, tmp_path):
        assert run_init(framework="codex", target_dir=tmp_path, force=False) == 0
        assert run_init(framework="openclaw", target_dir=tmp_path, force=False) == 0

        enabled, default = read_project_frameworks(tmp_path)
        assert enabled == ["codex", "openclaw"]
        assert default == "codex"
        assert not (tmp_path / ".env.clawsentry").exists()

    def test_run_uninstall_removes_only_target_framework(self, tmp_path):
        assert run_init(framework="codex", target_dir=tmp_path, force=False) == 0
        assert run_init(framework="openclaw", target_dir=tmp_path, force=False) == 0

        assert run_uninstall(framework="openclaw", target_dir=tmp_path) == 0

        enabled, default = read_project_frameworks(tmp_path)
        assert enabled == ["codex"]
        assert default == "codex"
        assert "[frameworks.openclaw]" in _frameworks_text(tmp_path)

    def test_cli_main_uninstall_codex_dispatch(self, tmp_path):
        from clawsentry.cli.main import main

        assert run_init(framework="a3s-code", target_dir=tmp_path, force=False) == 0
        assert run_init(framework="codex", target_dir=tmp_path, force=False) == 0

        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(SystemExit) as exc:
                main(["init", "codex", "--dir", str(tmp_path), "--uninstall"])

        assert exc.value.code == 0
        assert read_project_frameworks(tmp_path)[0] == ["a3s-code"]
