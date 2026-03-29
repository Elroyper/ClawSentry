"""Tests for Codex framework initializer."""

from __future__ import annotations

from pathlib import Path

import pytest

from clawsentry.cli.initializers.codex import CodexInitializer


class TestCodexInitializer:

    def test_framework_name(self):
        init = CodexInitializer()
        assert init.framework_name == "codex"

    def test_generate_config_creates_env_file(self, tmp_path):
        init = CodexInitializer()
        result = init.generate_config(tmp_path)
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
        with pytest.raises(FileExistsError):
            init.generate_config(tmp_path)

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
            claude_home=tmp_path / "fake_claude",
        )
        assert result is None

    def test_a3s_takes_priority_over_codex(self, tmp_path, monkeypatch):
        from clawsentry.cli.start_command import detect_framework

        # Create both a3s-code dir and codex env
        a3s_dir = tmp_path / ".a3s-code"
        a3s_dir.mkdir()
        env_file = tmp_path / ".env.clawsentry"
        env_file.write_text("CS_FRAMEWORK=codex\n")
        monkeypatch.chdir(tmp_path)
        result = detect_framework(
            openclaw_home=tmp_path / "fake_oc",
            a3s_dir=a3s_dir,
        )
        assert result == "a3s-code"


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

    def test_next_steps_no_curl(self, tmp_path, monkeypatch):
        """next_steps should not mention curl or POST /ahp/codex."""
        monkeypatch.setenv("CODEX_HOME", str(tmp_path / "nonexistent"))

        from clawsentry.cli.initializers.codex import CodexInitializer
        result = CodexInitializer().generate_config(tmp_path)
        joined = " ".join(result.next_steps)
        assert "curl" not in joined.lower()
        assert "POST" not in joined
        assert "codex" in joined.lower()
