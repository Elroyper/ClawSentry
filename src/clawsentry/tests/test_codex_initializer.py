"""Tests for Codex framework initializer."""

from __future__ import annotations

import json

from clawsentry.cli.initializers.codex import CodexInitializer


class TestCodexInitializer:

    def test_framework_name(self):
        init = CodexInitializer()
        assert init.framework_name == "codex"

    def test_generate_config_creates_env_file(self, tmp_path):
        init = CodexInitializer()
        init.generate_config(tmp_path)
        env_path = tmp_path / ".env.clawsentry"
        assert env_path.exists()
        content = env_path.read_text()
        assert "CS_FRAMEWORK=codex" in content
        assert "CS_AUTH_TOKEN" in content
        assert "CS_HTTP_PORT" in content

    def test_next_steps_include_gateway(self, tmp_path):
        init = CodexInitializer()
        result = init.generate_config(tmp_path)
        combined = " ".join(result.next_steps)
        assert "gateway" in combined.lower()

    def test_no_overwrite_without_force(self, tmp_path):
        init = CodexInitializer()
        init.generate_config(tmp_path)
        before = (tmp_path / ".env.clawsentry").read_text()
        before_token = next(
            line.split("=", 1)[1]
            for line in before.splitlines()
            if line.startswith("CS_AUTH_TOKEN=")
        )

        result = init.generate_config(tmp_path)
        after = (tmp_path / ".env.clawsentry").read_text()

        assert f"CS_AUTH_TOKEN={before_token}" in after
        assert "CS_ENABLED_FRAMEWORKS=codex" in after
        assert result.warnings

    def test_overwrite_with_force(self, tmp_path):
        init = CodexInitializer()
        init.generate_config(tmp_path)
        result = init.generate_config(tmp_path, force=True)
        assert len(result.warnings) > 0

    def test_env_file_permissions(self, tmp_path):
        init = CodexInitializer()
        init.generate_config(tmp_path)
        env_path = tmp_path / ".env.clawsentry"
        mode = env_path.stat().st_mode & 0o777
        assert mode == 0o600

    def test_registered_in_framework_initializers(self):
        from clawsentry.cli.initializers import FRAMEWORK_INITIALIZERS
        assert "codex" in FRAMEWORK_INITIALIZERS

    def test_env_vars_in_result(self, tmp_path):
        init = CodexInitializer()
        result = init.generate_config(tmp_path)
        assert "CS_FRAMEWORK" in result.env_vars
        assert result.env_vars["CS_FRAMEWORK"] == "codex"
        assert "CS_AUTH_TOKEN" in result.env_vars


class TestCodexDetectFramework:

    def test_detect_codex_from_env_file(self, tmp_path, monkeypatch):
        from clawsentry.cli.start_command import detect_framework

        # Create .env.clawsentry with CS_FRAMEWORK=codex
        env_file = tmp_path / ".env.clawsentry"
        env_file.write_text("CS_FRAMEWORK=codex\nCS_AUTH_TOKEN=test\n")
        monkeypatch.chdir(tmp_path)
        result = detect_framework(
            openclaw_home=tmp_path / "fake_oc",
            a3s_dir=tmp_path / "fake_a3s",
        )
        assert result == "codex"

    def test_detect_none_when_empty(self, tmp_path, monkeypatch):
        from clawsentry.cli.start_command import detect_framework
        monkeypatch.chdir(tmp_path)
        result = detect_framework(
            openclaw_home=tmp_path / "fake_oc",
            a3s_dir=tmp_path / "fake_a3s",
            codex_home=tmp_path / "fake_codex",
            claude_home=tmp_path / "fake_claude",
        )
        assert result is None

    def test_explicit_codex_in_env_takes_priority_over_a3s_dir(self, tmp_path, monkeypatch):
        from clawsentry.cli.start_command import detect_framework

        # Create both a3s-code dir and codex env
        a3s_dir = tmp_path / ".a3s-code"
        a3s_dir.mkdir()
        (a3s_dir / "settings.json").write_text("{}")
        env_file = tmp_path / ".env.clawsentry"
        env_file.write_text("CS_FRAMEWORK=codex\n")
        monkeypatch.chdir(tmp_path)
        result = detect_framework(
            openclaw_home=tmp_path / "fake_oc",
            a3s_dir=a3s_dir,
        )
        assert result == "codex"


class TestCodexInitializerSessionDir:

    def test_generates_session_dir_env_var(self, tmp_path, monkeypatch):
        """init codex should set CS_CODEX_SESSION_DIR when Codex home detected."""
        codex_home = tmp_path / ".codex"
        sessions_dir = codex_home / "sessions"
        sessions_dir.mkdir(parents=True)
        monkeypatch.setenv("CODEX_HOME", str(codex_home))

        from clawsentry.cli.initializers.codex import CodexInitializer
        result = CodexInitializer().generate_config(tmp_path)
        assert "CS_CODEX_SESSION_DIR" in result.env_vars
        assert result.env_vars["CS_CODEX_SESSION_DIR"] == str(sessions_dir)

    def test_no_session_dir_when_codex_not_installed(self, tmp_path, monkeypatch):
        """When Codex is not installed, CS_CODEX_SESSION_DIR should not be set."""
        monkeypatch.setenv("CODEX_HOME", str(tmp_path / "nonexistent"))

        from clawsentry.cli.initializers.codex import CodexInitializer
        result = CodexInitializer().generate_config(tmp_path)
        assert "CS_CODEX_SESSION_DIR" not in result.env_vars

    def test_enables_session_auto_detect(self, tmp_path, monkeypatch):
        """init codex should opt in to Codex watcher auto-detection."""
        monkeypatch.setenv("CODEX_HOME", str(tmp_path / "nonexistent"))

        from clawsentry.cli.initializers.codex import CodexInitializer
        result = CodexInitializer().generate_config(tmp_path)
        assert result.env_vars["CS_CODEX_WATCH_ENABLED"] == "true"
        assert "CS_CODEX_WATCH_ENABLED=true" in (tmp_path / ".env.clawsentry").read_text()

    def test_next_steps_no_curl(self, tmp_path, monkeypatch):
        """next_steps should not mention curl or POST /ahp/codex."""
        monkeypatch.setenv("CODEX_HOME", str(tmp_path / "nonexistent"))

        from clawsentry.cli.initializers.codex import CodexInitializer
        result = CodexInitializer().generate_config(tmp_path)
        joined = " ".join(result.next_steps)
        assert "curl" not in joined.lower()
        assert "POST" not in joined
        assert "codex" in joined.lower()


class TestCodexNativeHooks:
    def test_setup_codex_hooks_enables_feature_and_preserves_user_hooks(self, tmp_path):
        codex_home = tmp_path / ".codex"
        codex_home.mkdir()
        (codex_home / "config.toml").write_text(
            "[features]\njs_repl = true\n",
            encoding="utf-8",
        )
        (codex_home / "hooks.json").write_text(
            json.dumps(
                {
                    "hooks": {
                        "PreToolUse": [
                            {
                                "matcher": "Bash",
                                "hooks": [
                                    {
                                        "type": "command",
                                        "command": "echo user-pretool",
                                    }
                                ],
                            }
                        ]
                    }
                }
            ),
            encoding="utf-8",
        )

        result = CodexInitializer().setup_codex_hooks(codex_home=codex_home)

        config_text = (codex_home / "config.toml").read_text(encoding="utf-8")
        hooks_payload = json.loads((codex_home / "hooks.json").read_text(encoding="utf-8"))
        pretool_entries = hooks_payload["hooks"]["PreToolUse"]

        assert "codex_hooks = true" in config_text
        assert "js_repl = true" in config_text
        assert any("echo user-pretool" in str(entry) for entry in pretool_entries)
        assert any("clawsentry harness --framework codex" in str(entry) for entry in pretool_entries)
        assert "PermissionRequest" in hooks_payload["hooks"]
        assert "UserPromptSubmit" in hooks_payload["hooks"]
        assert "PostToolUse" in hooks_payload["hooks"]
        assert "Stop" in hooks_payload["hooks"]
        assert codex_home / "config.toml" in result.files_modified
        assert codex_home / "hooks.json" in result.files_modified

    def test_setup_codex_hooks_is_idempotent(self, tmp_path):
        codex_home = tmp_path / ".codex"
        init = CodexInitializer()

        init.setup_codex_hooks(codex_home=codex_home)
        init.setup_codex_hooks(codex_home=codex_home)

        hooks_payload = json.loads((codex_home / "hooks.json").read_text(encoding="utf-8"))
        for entries in hooks_payload["hooks"].values():
            managed = [
                entry for entry in entries
                if "clawsentry harness --framework codex" in str(entry)
            ]
            assert len(managed) == 1

    def test_pretool_bash_hook_is_synchronous_and_other_hooks_are_async(self, tmp_path):
        """Only verified PreToolUse(Bash) should be installed as blocking preflight."""
        codex_home = tmp_path / ".codex"

        CodexInitializer().setup_codex_hooks(codex_home=codex_home)

        hooks_payload = json.loads((codex_home / "hooks.json").read_text(encoding="utf-8"))
        pretool_command = hooks_payload["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        assert pretool_command == "clawsentry harness --framework codex"

        permission_command = hooks_payload["hooks"]["PermissionRequest"][0]["hooks"][0]["command"]
        assert permission_command == "clawsentry harness --framework codex"

        for event_name in ("SessionStart", "UserPromptSubmit", "PostToolUse", "Stop"):
            command = hooks_payload["hooks"][event_name][0]["hooks"][0]["command"]
            assert command == "clawsentry harness --framework codex --async"

    def test_uninstall_codex_hooks_removes_only_clawsentry_entries(self, tmp_path):
        codex_home = tmp_path / ".codex"
        init = CodexInitializer()
        init.setup_codex_hooks(codex_home=codex_home)

        hooks_path = codex_home / "hooks.json"
        hooks_payload = json.loads(hooks_path.read_text(encoding="utf-8"))
        hooks_payload["hooks"]["PreToolUse"].insert(
            0,
            {
                "matcher": "Bash",
                "hooks": [{"type": "command", "command": "echo user-pretool"}],
            },
        )
        hooks_path.write_text(json.dumps(hooks_payload, indent=2) + "\n", encoding="utf-8")

        result = init.uninstall(codex_home=codex_home)

        cleaned_payload = json.loads(hooks_path.read_text(encoding="utf-8"))
        assert "echo user-pretool" in str(cleaned_payload)
        assert "clawsentry harness --framework codex" not in str(cleaned_payload)
        assert "removed" in " ".join(result.next_steps).lower()

    def test_run_init_setup_installs_codex_hooks(self, tmp_path, capsys):
        from clawsentry.cli.init_command import run_init

        codex_home = tmp_path / ".codex"
        exit_code = run_init(
            framework="codex",
            target_dir=tmp_path,
            force=False,
            setup=True,
            codex_home=codex_home,
        )

        captured = capsys.readouterr()
        assert exit_code == 0
        assert (codex_home / "config.toml").exists()
        assert (codex_home / "hooks.json").exists()
        assert "Codex native hooks updated" in captured.out

    def test_run_uninstall_removes_codex_hooks(self, tmp_path):
        from clawsentry.cli.init_command import run_uninstall

        codex_home = tmp_path / ".codex"
        CodexInitializer().setup_codex_hooks(codex_home=codex_home)

        exit_code = run_uninstall(
            framework="codex",
            target_dir=tmp_path,
            codex_home=codex_home,
        )

        assert exit_code == 0
        hooks_payload = json.loads((codex_home / "hooks.json").read_text(encoding="utf-8"))
        assert "clawsentry harness --framework codex" not in str(hooks_payload)
