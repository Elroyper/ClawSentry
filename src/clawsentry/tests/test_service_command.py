"""Tests for ``clawsentry service`` command."""

from __future__ import annotations

import platform
import textwrap
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from clawsentry.cli.service_command import (
    _which_clawsentry,
    _ensure_env_file,
    _generate_systemd_unit,
    _generate_launchd_plist,
    _parse_env_lines,
    _redact_env_value,
    _validate_service_env,
    run_service_install,
    run_service_uninstall,
    run_service_validate,
)


# ---------------------------------------------------------------------------
# _which_clawsentry
# ---------------------------------------------------------------------------


class TestWhichClawsentry:
    def test_returns_string(self):
        result = _which_clawsentry()
        assert isinstance(result, str)
        assert len(result) > 0


# ---------------------------------------------------------------------------
# _ensure_env_file
# ---------------------------------------------------------------------------


class TestEnsureEnvFile:
    def test_creates_env_file(self, tmp_path, monkeypatch):
        config_dir = tmp_path / ".config" / "clawsentry"
        monkeypatch.setattr(
            "clawsentry.cli.service_command._env_file_path",
            lambda: config_dir / "gateway.env",
        )
        env_file = _ensure_env_file()
        assert env_file.exists()
        content = env_file.read_text()
        assert "CS_AUTH_TOKEN" in content
        assert "CS_L2_TIMEOUT_MS" in content
        assert "CS_LLM_TOKEN_BUDGET_ENABLED" in content
        assert "CS_LLM_DAILY_BUDGET_USD" not in content
        # Check permissions (owner-only)
        if platform.system() != "Windows":
            mode = oct(env_file.stat().st_mode & 0o777)
            assert mode == "0o600"

    def test_does_not_overwrite(self, tmp_path, monkeypatch):
        config_dir = tmp_path / ".config" / "clawsentry"
        config_dir.mkdir(parents=True)
        env_file = config_dir / "gateway.env"
        env_file.write_text("CUSTOM=value\n")
        monkeypatch.setattr(
            "clawsentry.cli.service_command._env_file_path",
            lambda: env_file,
        )
        result = _ensure_env_file()
        assert result.read_text() == "CUSTOM=value\n"


# ---------------------------------------------------------------------------
# validation helpers
# ---------------------------------------------------------------------------


class TestServiceValidationHelpers:
    def test_parse_env_lines_supports_export_and_quotes(self):
        env, invalid = _parse_env_lines([
            "# comment",
            "export CS_AUTH_TOKEN='secret-token-value'",
            "CS_HTTP_PORT=8080",
            "not-a-var",
        ])
        assert env["CS_AUTH_TOKEN"] == "secret-token-value"
        assert env["CS_HTTP_PORT"] == "8080"
        assert invalid == ["line 4: expected KEY=VALUE"]

    def test_redacts_secret_values(self):
        assert _redact_env_value("CS_AUTH_TOKEN", "abcdefghijklmnopqrstuvwxyz") == "abcd…wxyz"
        assert _redact_env_value("CS_AUTH_TOKEN", "changeme") == "<placeholder>"
        assert _redact_env_value("CS_HTTP_HOST", "127.0.0.1") == "127.0.0.1"

    def test_validate_accepts_canonical_deployment_env(self):
        errors, warnings = _validate_service_env({
            "CS_AUTH_TOKEN": "abcdefghijklmnopqrstuvwxyz123456",
            "CS_HTTP_PORT": "8080",
            "CS_LLM_PROVIDER": "anthropic",
            "CS_LLM_API_KEY": "sk-ant-real-looking-key",
            "CS_L2_TIMEOUT_MS": "60000",
            "CS_L3_TIMEOUT_MS": "300000",
            "CS_HARD_TIMEOUT_MS": "600000",
            "CS_LLM_TOKEN_BUDGET_ENABLED": "true",
            "CS_LLM_DAILY_TOKEN_BUDGET": "100000",
            "CS_LLM_TOKEN_BUDGET_SCOPE": "total",
        })
        assert errors == []
        assert warnings == []

    def test_validate_accepts_supported_provider_key_alias(self):
        errors, warnings = _validate_service_env({
            "CS_AUTH_TOKEN": "abcdefghijklmnopqrstuvwxyz123456",
            "CS_LLM_PROVIDER": "anthropic",
            "ANTHROPIC_API_KEY": "sk-ant-real-looking-key",
        })
        assert errors == []
        assert warnings == []

    def test_validate_warns_when_api_key_alias_lacks_provider(self):
        errors, warnings = _validate_service_env({
            "CS_AUTH_TOKEN": "abcdefghijklmnopqrstuvwxyz123456",
            "OPENAI_API_KEY": "sk-real-looking-key",
        })
        assert errors == []
        assert warnings == ["LLM API key is set but CS_LLM_PROVIDER is missing"]

    def test_validate_rejects_placeholder_auth_and_invalid_token_budget(self):
        errors, warnings = _validate_service_env({
            "CS_AUTH_TOKEN": "changeme-replace-with-a-strong-random-token",
            "CS_HTTP_PORT": "99999",
            "CS_LLM_TOKEN_BUDGET_ENABLED": "true",
            "CS_LLM_DAILY_TOKEN_BUDGET": "0",
            "CS_LLM_TOKEN_BUDGET_SCOPE": "usd",
            "CS_L2_BUDGET_MS": "5000",
        })
        assert any("CS_AUTH_TOKEN" in error for error in errors)
        assert any("CS_HTTP_PORT" in error for error in errors)
        assert any("CS_LLM_DAILY_TOKEN_BUDGET" in error for error in errors)
        assert any("CS_LLM_TOKEN_BUDGET_SCOPE" in error for error in errors)
        assert any("CS_L2_BUDGET_MS is deprecated" in warning for warning in warnings)

    def test_run_service_validate_prints_redacted_summary(self, tmp_path, capsys):
        env_file = tmp_path / "gateway.env"
        env_file.write_text(textwrap.dedent("""\
            CS_AUTH_TOKEN=abcdefghijklmnopqrstuvwxyz123456
            CS_HTTP_PORT=8080
            CS_LLM_TOKEN_BUDGET_ENABLED=false
            CS_LLM_DAILY_TOKEN_BUDGET=0
        """))
        code = run_service_validate(env_file=env_file)
        out = capsys.readouterr().out
        assert code == 0
        assert "PASS: service deployment validation succeeded" in out
        assert "abcdefghijklmnopqrstuvwxyz123456" not in out
        assert "abcd…3456" in out

    def test_run_service_validate_fails_missing_auth(self, tmp_path, capsys):
        env_file = tmp_path / "gateway.env"
        env_file.write_text("CS_HTTP_PORT=8080\n")
        code = run_service_validate(env_file=env_file)
        out = capsys.readouterr().out
        assert code == 1
        assert "CS_AUTH_TOKEN is required" in out


# ---------------------------------------------------------------------------
# _generate_systemd_unit
# ---------------------------------------------------------------------------


class TestGenerateSystemdUnit:
    def test_basic_unit(self, tmp_path):
        env_file = tmp_path / "gateway.env"
        env_file.touch()
        unit = _generate_systemd_unit("/usr/bin/clawsentry-gateway", env_file)
        assert "[Unit]" in unit
        assert "[Service]" in unit
        assert "[Install]" in unit
        assert "ExecStart=/usr/bin/clawsentry-gateway" in unit
        assert f"EnvironmentFile={env_file}" in unit
        assert "Restart=on-failure" in unit
        assert "WantedBy=default.target" in unit

    def test_module_invocation(self, tmp_path):
        env_file = tmp_path / "gateway.env"
        env_file.touch()
        unit = _generate_systemd_unit("/usr/bin/python -m clawsentry.gateway.stack", env_file)
        assert "ExecStart=/usr/bin/python -m clawsentry.gateway.stack" in unit


# ---------------------------------------------------------------------------
# _generate_launchd_plist
# ---------------------------------------------------------------------------


class TestGenerateLaunchdPlist:
    def test_basic_plist(self, tmp_path):
        env_file = tmp_path / "gateway.env"
        env_file.write_text("CS_AUTH_TOKEN=test123\n")
        plist = _generate_launchd_plist("/usr/local/bin/clawsentry-gateway", env_file)
        assert "com.clawsentry.gateway" in plist
        assert "<string>/usr/local/bin/clawsentry-gateway</string>" in plist
        assert "<key>RunAtLoad</key>" in plist
        assert "<key>KeepAlive</key>" in plist
        assert "CS_AUTH_TOKEN" in plist

    def test_empty_env_file(self, tmp_path):
        env_file = tmp_path / "gateway.env"
        env_file.write_text("# comments only\n")
        plist = _generate_launchd_plist("/usr/bin/test", env_file)
        assert "com.clawsentry.gateway" in plist

    def test_module_invocation_splits(self, tmp_path):
        env_file = tmp_path / "gateway.env"
        env_file.touch()
        plist = _generate_launchd_plist("/usr/bin/python -m clawsentry.gateway.stack", env_file)
        assert "<string>/usr/bin/python</string>" in plist
        assert "<string>-m</string>" in plist
        assert "<string>clawsentry.gateway.stack</string>" in plist


# ---------------------------------------------------------------------------
# run_service_install / uninstall / status (smoke tests)
# ---------------------------------------------------------------------------


class TestRunServiceInstall:
    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux only")
    @patch("clawsentry.cli.service_command.subprocess.run")
    def test_install_linux(self, mock_run, tmp_path, monkeypatch):
        user_dir = tmp_path / ".config" / "systemd" / "user"
        monkeypatch.setattr(
            "clawsentry.cli.service_command._systemd_user_dir",
            lambda: user_dir,
        )
        monkeypatch.setattr(
            "clawsentry.cli.service_command._env_file_path",
            lambda: tmp_path / "gateway.env",
        )
        mock_run.return_value = MagicMock(returncode=0, stdout="Linger=yes")
        code = run_service_install(no_enable=True)
        assert code == 0
        unit_file = user_dir / "clawsentry-gateway.service"
        assert unit_file.exists()

    @pytest.mark.skipif(platform.system() != "Darwin", reason="macOS only")
    @patch("clawsentry.cli.service_command.subprocess.run")
    def test_install_macos(self, mock_run, tmp_path, monkeypatch):
        agents_dir = tmp_path / "Library" / "LaunchAgents"
        monkeypatch.setattr(
            "clawsentry.cli.service_command._launchd_dir",
            lambda: agents_dir,
        )
        monkeypatch.setattr(
            "clawsentry.cli.service_command._env_file_path",
            lambda: tmp_path / "gateway.env",
        )
        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
        mock_run.return_value = MagicMock(returncode=0)
        code = run_service_install(no_enable=True)
        assert code == 0

    @pytest.mark.skipif(platform.system() == "Windows", reason="Not Windows")
    @patch("clawsentry.cli.service_command.subprocess.run")
    def test_uninstall_no_service(self, mock_run, tmp_path, monkeypatch):
        if platform.system() == "Linux":
            monkeypatch.setattr(
                "clawsentry.cli.service_command._systemd_user_dir",
                lambda: tmp_path,
            )
        elif platform.system() == "Darwin":
            monkeypatch.setattr(
                "clawsentry.cli.service_command._launchd_dir",
                lambda: tmp_path,
            )
        code = run_service_uninstall()
        assert code == 0


class TestSystemdEnvExample:
    def test_uses_canonical_budget_and_timeout_names(self):
        env_example = Path(__file__).resolve().parents[3] / "systemd" / "gateway.env.example"
        content = env_example.read_text(encoding="utf-8")
        assert "CS_L2_TIMEOUT_MS" in content
        assert "CS_LLM_TOKEN_BUDGET_ENABLED" in content
        assert "CS_LLM_DAILY_BUDGET_USD" not in content
        assert "CS_L2_BUDGET_MS" not in content
