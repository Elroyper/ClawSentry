"""Tests for clawsentry init claude-code."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from clawsentry.cli.initializers.claude_code import ClaudeCodeInitializer


class TestClaudeCodeInitializer:
    """Test Claude Code framework initializer."""

    def test_framework_name(self):
        init = ClaudeCodeInitializer()
        assert init.framework_name == "claude-code"

    def test_generate_config_creates_env_file(self, tmp_path):
        init = ClaudeCodeInitializer()
        result = init.generate_config(tmp_path, claude_home=tmp_path / ".claude")
        env_path = tmp_path / ".env.clawsentry"
        assert env_path.exists()
        content = env_path.read_text()
        assert "CS_UDS_PATH" in content
        assert "CS_AUTH_TOKEN" in content

    def test_generate_config_creates_hook_settings(self, tmp_path):
        init = ClaudeCodeInitializer()
        result = init.generate_config(tmp_path, claude_home=tmp_path / ".claude")
        # Hooks now written to settings.json (not settings.local.json)
        settings_path = tmp_path / ".claude" / "settings.json"
        assert settings_path.exists()
        settings = json.loads(settings_path.read_text())
        assert "hooks" in settings
        assert "PreToolUse" in settings["hooks"]
        assert "PostToolUse" in settings["hooks"]

    def test_hook_command_uses_clawsentry_harness(self, tmp_path):
        init = ClaudeCodeInitializer()
        result = init.generate_config(tmp_path, claude_home=tmp_path / ".claude")
        settings_path = tmp_path / ".claude" / "settings.json"
        settings = json.loads(settings_path.read_text())
        hook_cmd = settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        assert "clawsentry-harness" in hook_cmd
        assert "--framework claude-code" in hook_cmd

    def test_merges_existing_settings(self, tmp_path):
        """Should preserve existing settings when merging hooks."""
        claude_home = tmp_path / ".claude"
        claude_home.mkdir()
        existing = {"env": {"MY_KEY": "my_value"}, "model": "opus"}
        (claude_home / "settings.json").write_text(json.dumps(existing))

        init = ClaudeCodeInitializer()
        result = init.generate_config(tmp_path, claude_home=claude_home)

        settings = json.loads((claude_home / "settings.json").read_text())
        # Existing keys preserved
        assert settings.get("env", {}).get("MY_KEY") == "my_value"
        assert settings.get("model") == "opus"
        # Hooks added
        assert "PreToolUse" in settings["hooks"]

    def test_merges_existing_hooks(self, tmp_path):
        """Should preserve existing hooks for other event types."""
        claude_home = tmp_path / ".claude"
        claude_home.mkdir()
        existing = {
            "hooks": {
                "Notification": [{"matcher": "", "hooks": [{"type": "command", "command": "my-notifier"}]}]
            }
        }
        (claude_home / "settings.json").write_text(json.dumps(existing))

        init = ClaudeCodeInitializer()
        result = init.generate_config(tmp_path, claude_home=claude_home)

        settings = json.loads((claude_home / "settings.json").read_text())
        # Existing hook preserved
        assert "Notification" in settings["hooks"]
        assert settings["hooks"]["Notification"][0]["hooks"][0]["command"] == "my-notifier"
        # New hooks added
        assert "PreToolUse" in settings["hooks"]

    def test_no_overwrite_without_force(self, tmp_path):
        init = ClaudeCodeInitializer()
        init.generate_config(tmp_path, claude_home=tmp_path / ".claude")
        with pytest.raises(FileExistsError):
            init.generate_config(tmp_path, claude_home=tmp_path / ".claude")

    def test_overwrite_with_force(self, tmp_path):
        init = ClaudeCodeInitializer()
        init.generate_config(tmp_path, claude_home=tmp_path / ".claude")
        result = init.generate_config(tmp_path, claude_home=tmp_path / ".claude", force=True)
        assert len(result.warnings) > 0  # warned about overwrite

    def test_next_steps_include_gateway(self, tmp_path):
        init = ClaudeCodeInitializer()
        result = init.generate_config(tmp_path, claude_home=tmp_path / ".claude")
        combined = " ".join(result.next_steps)
        assert "gateway" in combined.lower()

    def test_registered_in_framework_initializers(self):
        from clawsentry.cli.initializers import FRAMEWORK_INITIALIZERS
        assert "claude-code" in FRAMEWORK_INITIALIZERS


class TestClaudeCodeUninstall:
    """Test hook removal via --uninstall."""

    def test_uninstall_removes_hooks(self, tmp_path):
        claude_home = tmp_path / ".claude"
        init = ClaudeCodeInitializer()
        # Install first (writes to settings.json)
        init.generate_config(tmp_path, claude_home=claude_home)
        settings = json.loads((claude_home / "settings.json").read_text())
        assert "PreToolUse" in settings["hooks"]

        # Uninstall
        result = init.uninstall(claude_home=claude_home)
        settings = json.loads((claude_home / "settings.json").read_text())
        # ClawSentry hooks removed
        for hook_type in ("PreToolUse", "PostToolUse", "SessionStart", "SessionEnd"):
            if hook_type in settings.get("hooks", {}):
                entries = settings["hooks"][hook_type]
                for entry in entries:
                    assert "clawsentry-harness" not in str(entry)

    def test_uninstall_preserves_other_hooks(self, tmp_path):
        """Uninstall should preserve non-ClawSentry hooks."""
        claude_home = tmp_path / ".claude"
        claude_home.mkdir()
        existing = {
            "hooks": {
                "PreToolUse": [
                    {"matcher": "", "hooks": [{"type": "command", "command": "clawsentry-harness --framework claude-code"}]},
                    {"matcher": "", "hooks": [{"type": "command", "command": "my-other-hook"}]},
                ],
                "Notification": [{"matcher": "", "hooks": [{"type": "command", "command": "my-notifier"}]}],
            }
        }
        # Test with settings.json
        (claude_home / "settings.json").write_text(json.dumps(existing))

        init = ClaudeCodeInitializer()
        init.uninstall(claude_home=claude_home)

        settings = json.loads((claude_home / "settings.json").read_text())
        # Other hook preserved
        assert "Notification" in settings["hooks"]
        # ClawSentry entry removed, but other PreToolUse entry preserved
        pre_entries = settings["hooks"].get("PreToolUse", [])
        assert len(pre_entries) == 1
        assert "my-other-hook" in str(pre_entries[0])

    def test_uninstall_cleans_legacy_settings_local(self, tmp_path):
        """Uninstall should also clean hooks from legacy settings.local.json."""
        claude_home = tmp_path / ".claude"
        claude_home.mkdir()
        # Legacy hooks in settings.local.json
        legacy = {
            "hooks": {
                "PreToolUse": [
                    {"matcher": "", "hooks": [{"type": "command", "command": "clawsentry-harness --framework claude-code"}]},
                ],
            }
        }
        (claude_home / "settings.local.json").write_text(json.dumps(legacy))

        init = ClaudeCodeInitializer()
        result = init.uninstall(claude_home=claude_home)

        settings = json.loads((claude_home / "settings.local.json").read_text())
        assert "hooks" not in settings or not settings.get("hooks")

    def test_uninstall_nonexistent_settings(self, tmp_path):
        """Uninstall on missing settings file should not crash."""
        init = ClaudeCodeInitializer()
        result = init.uninstall(claude_home=tmp_path / ".claude-nonexist")
        assert len(result.warnings) > 0
