"""Tests for Codex initializer under env-first config model."""

from __future__ import annotations

import json

from clawsentry.cli.initializers.codex import CodexInitializer
from clawsentry.cli.start_command import detect_framework


class TestCodexInitializer:
    def test_generate_config_reports_env_vars_not_project_file(self, tmp_path):
        result = CodexInitializer().generate_config(tmp_path)
        assert not (tmp_path / (".clawsentry" + ".toml")).exists()
        assert not (tmp_path / ".env.clawsentry").exists()
        assert result.env_vars == {"CS_FRAMEWORK": "codex", "CS_ENABLED_FRAMEWORKS": "codex"}
        assert result.files_created == []

    def test_rerun_remains_side_effect_free(self, tmp_path):
        CodexInitializer().generate_config(tmp_path)
        CodexInitializer().generate_config(tmp_path, force=True)
        assert list(tmp_path.iterdir()) == []

    def test_next_steps_use_explicit_env_file_language(self, tmp_path):
        result = CodexInitializer().generate_config(tmp_path)
        assert any("--env-file .clawsentry.env.local" in step for step in result.next_steps)
        assert not any("source" in step and ".env.clawsentry" in step for step in result.next_steps)


class TestCodexDetectFramework:
    def test_detect_codex_from_process_env(self, monkeypatch):
        monkeypatch.setenv("CS_FRAMEWORK", "codex")
        assert detect_framework() == "codex"

    def test_legacy_env_file_is_not_auto_discovered(self, tmp_path, monkeypatch):
        (tmp_path / ".env.clawsentry").write_text("CS_FRAMEWORK=codex\n")
        monkeypatch.chdir(tmp_path)
        assert detect_framework(a3s_dir=tmp_path / "missing") is None


class TestCodexInitializerHooks:
    def test_setup_codex_hooks_dry_run_does_not_write(self, tmp_path):
        init = CodexInitializer()
        result = init.setup_codex_hooks(codex_home=tmp_path / ".codex", dry_run=True)
        assert result.dry_run is True
        assert not (tmp_path / ".codex").exists()

    def test_setup_codex_hooks_writes_managed_entries_to_temp_home(self, tmp_path):
        codex_home = tmp_path / ".codex"
        init = CodexInitializer()
        result = init.setup_codex_hooks(codex_home=codex_home, dry_run=False)
        assert (codex_home / "config.toml").exists()
        assert (codex_home / "hooks.json").exists()
        assert result.files_modified
        hooks = json.loads((codex_home / "hooks.json").read_text())
        assert "clawsentry harness --framework codex" in str(hooks)

    def test_uninstall_removes_only_clawsentry_hooks_from_temp_home(self, tmp_path):
        codex_home = tmp_path / ".codex"
        init = CodexInitializer()
        init.setup_codex_hooks(codex_home=codex_home, dry_run=False)
        result = init.uninstall(codex_home=codex_home)
        assert result.next_steps
        assert "clawsentry harness --framework codex" not in (codex_home / "hooks.json").read_text()
