"""Tests for Codex initializer under TOML-first config model."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

from clawsentry.cli.initializers.codex import CodexInitializer
from clawsentry.cli.start_command import detect_framework
from clawsentry.gateway.project_config import read_project_frameworks, update_project_framework


class TestCodexInitializer:
    def test_generate_config_creates_project_toml_not_env_file(self, tmp_path):
        result = CodexInitializer().generate_config(tmp_path)

        assert (tmp_path / ".clawsentry.toml").exists()
        assert not (tmp_path / ".env.clawsentry").exists()
        assert result.env_vars == {"CLAW_SENTRY_FRAMEWORK": "codex"}
        text = (tmp_path / ".clawsentry.toml").read_text()
        assert 'enabled = ["codex"]' in text
        assert "CS_AUTH_TOKEN" not in text

    def test_rerun_preserves_framework_toml(self, tmp_path):
        CodexInitializer().generate_config(tmp_path)
        before = (tmp_path / ".clawsentry.toml").read_text()
        CodexInitializer().generate_config(tmp_path)
        after = (tmp_path / ".clawsentry.toml").read_text()
        assert after == before

    def test_force_refreshes_codex_subsection_without_env_file(self, tmp_path):
        CodexInitializer().generate_config(tmp_path)
        CodexInitializer().generate_config(tmp_path, force=True)
        assert not (tmp_path / ".env.clawsentry").exists()
        assert "[frameworks.codex]" in (tmp_path / ".clawsentry.toml").read_text()

    def test_next_steps_use_explicit_env_file_language(self, tmp_path):
        result = CodexInitializer().generate_config(tmp_path)
        assert any("--env-file .clawsentry.env.local" in step for step in result.next_steps)
        assert not any("source" in step and ".env.clawsentry" in step for step in result.next_steps)


class TestCodexDetectFramework:
    def test_detect_codex_from_project_toml(self, tmp_path, monkeypatch):
        update_project_framework(tmp_path, "codex")
        monkeypatch.chdir(tmp_path)

        result = detect_framework(
            openclaw_home=tmp_path / "nope",
            a3s_dir=tmp_path / "nope2",
            claude_home=tmp_path / "nope3",
            codex_home=tmp_path / "nope4",
        )
        assert result == "codex"

    def test_legacy_env_does_not_override_a3s_marker(self, tmp_path, monkeypatch):
        (tmp_path / ".env.clawsentry").write_text("CS_FRAMEWORK=codex\n")
        a3s_dir = tmp_path / ".a3s-code"
        a3s_dir.mkdir()
        (a3s_dir / "settings.json").write_text("{}")
        monkeypatch.chdir(tmp_path)

        result = detect_framework(
            openclaw_home=tmp_path / "nope",
            a3s_dir=a3s_dir,
            claude_home=tmp_path / "nope3",
            codex_home=tmp_path / "nope4",
        )
        assert result == "a3s-code"


class TestCodexInitializerHooks:
    def test_setup_codex_hooks_dry_run_does_not_write(self, tmp_path):
        init = CodexInitializer()
        result = init.setup_codex_hooks(codex_home=tmp_path / ".codex", dry_run=True)
        assert result.dry_run is True
        assert not (tmp_path / ".codex").exists()

    def test_setup_codex_hooks_writes_managed_entries(self, tmp_path):
        codex_home = tmp_path / ".codex"
        init = CodexInitializer()
        result = init.setup_codex_hooks(codex_home=codex_home, dry_run=False)

        assert (codex_home / "config.toml").exists()
        assert (codex_home / "hooks.json").exists()
        assert result.files_modified
        hooks = json.loads((codex_home / "hooks.json").read_text())
        assert "clawsentry harness --framework codex" in str(hooks)

    def test_uninstall_removes_only_clawsentry_hooks(self, tmp_path):
        codex_home = tmp_path / ".codex"
        init = CodexInitializer()
        init.setup_codex_hooks(codex_home=codex_home, dry_run=False)

        result = init.uninstall(codex_home=codex_home)

        assert result.next_steps
        assert "clawsentry harness --framework codex" not in (codex_home / "hooks.json").read_text()
