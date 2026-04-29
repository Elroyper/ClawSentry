"""Tests for Claude Code initializer under TOML-first config model."""

from __future__ import annotations

import json

from clawsentry.cli.init_command import run_uninstall
from clawsentry.cli.initializers.claude_code import ClaudeCodeInitializer
from clawsentry.gateway.project_config import read_project_frameworks


class TestClaudeCodeInitializer:
    def test_generate_config_creates_toml_and_hooks_not_env_file(self, tmp_path):
        claude_home = tmp_path / ".claude"
        result = ClaudeCodeInitializer().generate_config(tmp_path, claude_home=claude_home)

        assert (tmp_path / ".clawsentry.toml").exists()
        assert not (tmp_path / ".env.clawsentry").exists()
        assert (claude_home / "settings.json").exists()
        assert "clawsentry-harness" in (claude_home / "settings.json").read_text()
        assert result.env_vars == {"CLAW_SENTRY_FRAMEWORK": "claude-code"}
        assert "CS_AUTH_TOKEN" not in (tmp_path / ".clawsentry.toml").read_text()

    def test_no_overwrite_without_force(self, tmp_path):
        claude_home = tmp_path / ".claude"
        init = ClaudeCodeInitializer()
        init.generate_config(tmp_path, claude_home=claude_home)
        first = json.loads((claude_home / "settings.json").read_text())

        init.generate_config(tmp_path, claude_home=claude_home)

        assert json.loads((claude_home / "settings.json").read_text()) == first
        assert read_project_frameworks(tmp_path)[0] == ["claude-code"]

    def test_existing_legacy_env_file_is_left_untouched(self, tmp_path):
        legacy = tmp_path / ".env.clawsentry"
        legacy.write_text("CS_AUTH_TOKEN=keep-token\n")

        ClaudeCodeInitializer().generate_config(tmp_path, claude_home=tmp_path / ".claude", force=True)

        assert legacy.read_text() == "CS_AUTH_TOKEN=keep-token\n"


class TestClaudeCodeUninstall:
    def test_uninstall_removes_hooks_and_toml_enablement(self, tmp_path):
        claude_home = tmp_path / ".claude"
        init = ClaudeCodeInitializer()
        init.generate_config(tmp_path, claude_home=claude_home)

        exit_code = run_uninstall(
            framework="claude-code",
            target_dir=tmp_path,
            claude_home=claude_home,
        )

        assert exit_code == 0
        settings = json.loads((claude_home / "settings.json").read_text())
        assert "clawsentry-harness" not in str(settings)
        enabled, _default = read_project_frameworks(tmp_path)
        assert enabled == []
