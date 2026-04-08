"""Tests for Phase 5.1 — clawsentry init CLI."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

from clawsentry.cli.initializers.base import InitResult, disable_framework_env


class TestInitResult:
    def test_init_result_fields(self):
        result = InitResult(
            files_created=[Path("/tmp/test")],
            env_vars={"KEY": "val"},
            next_steps=["step 1"],
            warnings=[],
        )
        assert result.files_created == [Path("/tmp/test")]
        assert result.env_vars == {"KEY": "val"}
        assert result.next_steps == ["step 1"]
        assert result.warnings == []

    def test_init_result_defaults_empty_warnings(self):
        result = InitResult(
            files_created=[],
            env_vars={},
            next_steps=[],
            warnings=[],
        )
        assert result.warnings == []


def _read_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip("'\"")
    return values


def test_disable_framework_env_removes_only_target_framework_keys(tmp_path):
    env_path = tmp_path / ".env.clawsentry"
    env_path.write_text(
        "\n".join(
            [
                "# ClawSentry test config",
                "CS_FRAMEWORK=a3s-code",
                "CS_ENABLED_FRAMEWORKS=a3s-code,codex,openclaw",
                "CS_AUTH_TOKEN=keep-token",
                "CS_UDS_PATH=/tmp/clawsentry.sock",
                "CS_CODEX_WATCH_ENABLED=true",
                "CS_CODEX_SESSION_DIR=/tmp/codex-sessions",
                "OPENCLAW_WEBHOOK_TOKEN=keep-openclaw-token",
                "",
            ]
        )
    )

    result = disable_framework_env(
        env_path,
        framework="codex",
        framework_keys={"CS_CODEX_WATCH_ENABLED", "CS_CODEX_SESSION_DIR"},
    )

    env = _read_env_file(env_path)
    assert result.changed is True
    assert result.enabled_frameworks == ["a3s-code", "openclaw"]
    assert env["CS_ENABLED_FRAMEWORKS"] == "a3s-code,openclaw"
    assert env["CS_FRAMEWORK"] == "a3s-code"
    assert env["CS_AUTH_TOKEN"] == "keep-token"
    assert env["OPENCLAW_WEBHOOK_TOKEN"] == "keep-openclaw-token"
    assert "CS_CODEX_WATCH_ENABLED" not in env
    assert "CS_CODEX_SESSION_DIR" not in env


import pytest
from clawsentry.cli.initializers.openclaw import OpenClawInitializer


class TestOpenClawInitializer:
    def test_framework_name(self):
        init = OpenClawInitializer()
        assert init.framework_name == "openclaw"

    def test_generate_config_creates_env_file(self, tmp_path):
        init = OpenClawInitializer()
        result = init.generate_config(tmp_path)
        env_file = tmp_path / ".env.clawsentry"
        assert env_file.exists()
        assert env_file in result.files_created

    def test_generate_config_env_vars(self, tmp_path):
        init = OpenClawInitializer()
        result = init.generate_config(tmp_path)
        assert "OPENCLAW_WEBHOOK_TOKEN" in result.env_vars
        assert "CS_AUTH_TOKEN" in result.env_vars
        assert result.env_vars["CS_HTTP_PORT"] == "8080"
        assert result.env_vars["OPENCLAW_WEBHOOK_PORT"] == "8081"

    def test_generate_config_enforcement_env_vars(self, tmp_path):
        init = OpenClawInitializer()
        result = init.generate_config(tmp_path)
        assert result.env_vars["OPENCLAW_ENFORCEMENT_ENABLED"] == "false"
        assert result.env_vars["OPENCLAW_WS_URL"] == "ws://127.0.0.1:18789"
        assert "OPENCLAW_OPERATOR_TOKEN" in result.env_vars

    def test_generate_config_tokens_are_secure(self, tmp_path):
        init = OpenClawInitializer()
        result = init.generate_config(tmp_path)
        webhook_token = result.env_vars["OPENCLAW_WEBHOOK_TOKEN"]
        auth_token = result.env_vars["CS_AUTH_TOKEN"]
        assert len(webhook_token) >= 32
        assert len(auth_token) >= 32
        assert webhook_token != auth_token

    def test_generate_config_next_steps(self, tmp_path):
        init = OpenClawInitializer()
        result = init.generate_config(tmp_path)
        assert len(result.next_steps) >= 2
        assert any("source" in s for s in result.next_steps)
        assert any("stack" in s or "clawsentry stack" in s for s in result.next_steps)

    def test_generate_config_file_exists_no_force(self, tmp_path):
        env_file = tmp_path / ".env.clawsentry"
        env_file.write_text("CS_AUTH_TOKEN=keep-token\n")
        init = OpenClawInitializer()
        result = init.generate_config(tmp_path, force=False)
        env = _read_env_file(env_file)
        assert env["CS_AUTH_TOKEN"] == "keep-token"
        assert env["CS_ENABLED_FRAMEWORKS"] == "openclaw"
        assert result.warnings

    def test_generate_config_file_exists_force(self, tmp_path):
        env_file = tmp_path / ".env.clawsentry"
        env_file.write_text("existing")
        init = OpenClawInitializer()
        result = init.generate_config(tmp_path, force=True)
        assert env_file in result.files_created
        assert len(result.warnings) >= 1

    def test_generate_config_env_file_content(self, tmp_path):
        init = OpenClawInitializer()
        result = init.generate_config(tmp_path)
        content = (tmp_path / ".env.clawsentry").read_text()
        for key, val in result.env_vars.items():
            assert f"{key}={val}" in content


from clawsentry.cli.initializers.a3s_code import A3SCodeInitializer


class TestA3SCodeInitializer:
    def test_framework_name(self):
        init = A3SCodeInitializer()
        assert init.framework_name == "a3s-code"

    def test_generate_config_creates_env_file(self, tmp_path):
        init = A3SCodeInitializer()
        result = init.generate_config(tmp_path)
        env_file = tmp_path / ".env.clawsentry"
        assert env_file.exists()
        assert env_file in result.files_created

    def test_generate_config_env_vars(self, tmp_path):
        init = A3SCodeInitializer()
        result = init.generate_config(tmp_path)
        assert "CS_UDS_PATH" in result.env_vars
        assert "CS_AUTH_TOKEN" in result.env_vars
        assert result.env_vars["CS_FRAMEWORK"] == "a3s-code"
        assert result.env_vars["CS_UDS_PATH"] == "/tmp/clawsentry.sock"
        assert "OPENCLAW_WEBHOOK_TOKEN" not in result.env_vars

    def test_generate_config_token_is_secure(self, tmp_path):
        init = A3SCodeInitializer()
        result = init.generate_config(tmp_path)
        assert len(result.env_vars["CS_AUTH_TOKEN"]) >= 32

    def test_generate_config_next_steps(self, tmp_path):
        init = A3SCodeInitializer()
        result = init.generate_config(tmp_path)
        assert len(result.next_steps) >= 2
        assert any("source" in s for s in result.next_steps)
        assert any("gateway" in s for s in result.next_steps)

    def test_generate_config_next_steps_uses_explicit_sdk_transport_only(self, tmp_path):
        init = A3SCodeInitializer()
        result = init.generate_config(tmp_path)
        all_steps = "\n".join(result.next_steps).lower()
        assert "settings.json" not in all_steps
        assert "ahp_transport" in all_steps
        assert "httptransport" in all_steps

    def test_generate_config_file_exists_no_force(self, tmp_path):
        env_file = tmp_path / ".env.clawsentry"
        env_file.write_text("CS_AUTH_TOKEN=keep-token\n")
        init = A3SCodeInitializer()
        result = init.generate_config(tmp_path, force=False)
        env = _read_env_file(env_file)
        assert env["CS_AUTH_TOKEN"] == "keep-token"
        assert env["CS_ENABLED_FRAMEWORKS"] == "a3s-code"
        assert result.warnings

    def test_generate_config_file_exists_force(self, tmp_path):
        (tmp_path / ".env.clawsentry").write_text("existing")
        init = A3SCodeInitializer()
        result = init.generate_config(tmp_path, force=True)
        assert len(result.warnings) >= 1

    def test_generate_config_does_not_create_unsupported_settings_json(self, tmp_path):
        init = A3SCodeInitializer()
        result = init.generate_config(tmp_path)

        settings_path = tmp_path / ".a3s-code" / "settings.json"
        assert not settings_path.exists()
        assert settings_path not in result.files_created

    def test_generate_config_does_not_reuse_legacy_settings_token(self, tmp_path):
        settings_dir = tmp_path / ".a3s-code"
        settings_dir.mkdir(parents=True)
        old_token = "existing-token-from-settings"
        old_url = f"http://127.0.0.1:8080/ahp/a3s?token={old_token}"
        (settings_dir / "settings.json").write_text(
            json.dumps(
                {
                    "hooks": {
                        "PreToolUse": [{"type": "http", "url": old_url}],
                        "PostToolUse": [{"type": "http", "url": old_url}],
                    }
                }
            )
        )

        init = A3SCodeInitializer()
        result = init.generate_config(tmp_path, force=False)

        assert result.env_vars["CS_AUTH_TOKEN"] != old_token
        env_content = (tmp_path / ".env.clawsentry").read_text()
        assert f"CS_AUTH_TOKEN={old_token}" not in env_content


from clawsentry.cli.initializers import FRAMEWORK_INITIALIZERS, get_initializer


class TestRegistry:
    def test_registry_has_both_frameworks(self):
        assert "openclaw" in FRAMEWORK_INITIALIZERS
        assert "a3s-code" in FRAMEWORK_INITIALIZERS

    def test_get_initializer_openclaw(self):
        init = get_initializer("openclaw")
        assert init.framework_name == "openclaw"

    def test_get_initializer_a3s_code(self):
        init = get_initializer("a3s-code")
        assert init.framework_name == "a3s-code"

    def test_get_initializer_unknown_raises(self):
        with pytest.raises(KeyError, match="unknown-fw"):
            get_initializer("unknown-fw")

    def test_registry_list(self):
        names = sorted(FRAMEWORK_INITIALIZERS.keys())
        assert names == ["a3s-code", "claude-code", "codex", "openclaw"]


from clawsentry.cli.init_command import run_init, run_uninstall


class TestRunInit:
    def test_run_init_openclaw(self, tmp_path, capsys):
        exit_code = run_init(framework="openclaw", target_dir=tmp_path, force=False)
        assert exit_code == 0
        assert (tmp_path / ".env.clawsentry").exists()
        captured = capsys.readouterr()
        assert "openclaw" in captured.out.lower() or "OpenClaw" in captured.out

    def test_run_init_a3s_code(self, tmp_path, capsys):
        exit_code = run_init(framework="a3s-code", target_dir=tmp_path, force=False)
        assert exit_code == 0
        assert (tmp_path / ".env.clawsentry").exists()
        captured = capsys.readouterr()
        assert "a3s-code" in captured.out

    def test_run_init_unknown_framework(self, tmp_path, capsys):
        exit_code = run_init(framework="unknown", target_dir=tmp_path, force=False)
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "unknown" in captured.err.lower() or "Unknown" in captured.err

    def test_run_init_file_exists_returns_error(self, tmp_path, capsys):
        (tmp_path / ".env.clawsentry").write_text("existing")
        exit_code = run_init(framework="openclaw", target_dir=tmp_path, force=False)
        assert exit_code == 0
        env = _read_env_file(tmp_path / ".env.clawsentry")
        assert env["CS_ENABLED_FRAMEWORKS"] == "openclaw"

    def test_run_init_file_exists_force_succeeds(self, tmp_path, capsys):
        (tmp_path / ".env.clawsentry").write_text("existing")
        exit_code = run_init(framework="openclaw", target_dir=tmp_path, force=True)
        assert exit_code == 0

    def test_run_init_creates_target_dir(self, tmp_path, capsys):
        new_dir = tmp_path / "nonexistent" / "subdir"
        exit_code = run_init(framework="openclaw", target_dir=new_dir, force=False)
        assert exit_code == 0
        assert (new_dir / ".env.clawsentry").exists()

    def test_run_init_merges_multiple_frameworks_without_rotating_token(self, tmp_path, capsys):
        first_exit = run_init(framework="a3s-code", target_dir=tmp_path, force=False)
        assert first_exit == 0
        first_env = _read_env_file(tmp_path / ".env.clawsentry")

        second_exit = run_init(framework="codex", target_dir=tmp_path, force=False)
        assert second_exit == 0
        merged = _read_env_file(tmp_path / ".env.clawsentry")

        assert merged["CS_AUTH_TOKEN"] == first_env["CS_AUTH_TOKEN"]
        assert merged["CS_FRAMEWORK"] == "a3s-code"
        assert merged["CS_CODEX_WATCH_ENABLED"] == "true"
        assert merged["CS_ENABLED_FRAMEWORKS"] == "a3s-code,codex"

    def test_run_init_merges_openclaw_without_replacing_existing_framework(self, tmp_path):
        assert run_init(framework="codex", target_dir=tmp_path, force=False) == 0
        before = _read_env_file(tmp_path / ".env.clawsentry")

        assert run_init(framework="openclaw", target_dir=tmp_path, force=False) == 0
        merged = _read_env_file(tmp_path / ".env.clawsentry")

        assert merged["CS_AUTH_TOKEN"] == before["CS_AUTH_TOKEN"]
        assert merged["CS_FRAMEWORK"] == "codex"
        assert merged["OPENCLAW_WEBHOOK_PORT"] == "8081"
        assert merged["CS_ENABLED_FRAMEWORKS"] == "codex,openclaw"

    def test_run_uninstall_removes_codex_without_rotating_shared_token(self, tmp_path):
        assert run_init(framework="a3s-code", target_dir=tmp_path, force=False) == 0
        before = _read_env_file(tmp_path / ".env.clawsentry")
        assert run_init(framework="codex", target_dir=tmp_path, force=False) == 0

        exit_code = run_uninstall(framework="codex", target_dir=tmp_path)

        env = _read_env_file(tmp_path / ".env.clawsentry")
        assert exit_code == 0
        assert env["CS_AUTH_TOKEN"] == before["CS_AUTH_TOKEN"]
        assert env["CS_ENABLED_FRAMEWORKS"] == "a3s-code"
        assert env["CS_FRAMEWORK"] == "a3s-code"
        assert "CS_CODEX_WATCH_ENABLED" not in env

    def test_run_uninstall_removes_openclaw_without_touching_codex(self, tmp_path):
        assert run_init(framework="codex", target_dir=tmp_path, force=False) == 0
        assert run_init(framework="openclaw", target_dir=tmp_path, force=False) == 0

        exit_code = run_uninstall(framework="openclaw", target_dir=tmp_path)

        env = _read_env_file(tmp_path / ".env.clawsentry")
        assert exit_code == 0
        assert env["CS_ENABLED_FRAMEWORKS"] == "codex"
        assert env["CS_FRAMEWORK"] == "codex"
        assert env["CS_CODEX_WATCH_ENABLED"] == "true"
        assert not any(key.startswith("OPENCLAW_") for key in env)

    def test_cli_main_uninstall_codex_dispatch(self, tmp_path):
        from clawsentry.cli.main import main

        assert run_init(framework="a3s-code", target_dir=tmp_path, force=False) == 0
        assert run_init(framework="codex", target_dir=tmp_path, force=False) == 0

        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(SystemExit) as exc:
                main(["init", "codex", "--dir", str(tmp_path), "--uninstall"])

        assert exc.value.code == 0
        env = _read_env_file(tmp_path / ".env.clawsentry")
        assert env["CS_ENABLED_FRAMEWORKS"] == "a3s-code"
        assert "CS_CODEX_WATCH_ENABLED" not in env


class TestInitOutputImprovement:
    """G-4: init output should include actionable guidance."""

    def test_openclaw_init_mentions_enforcement_extra(self, tmp_path):
        from clawsentry.cli.initializers.openclaw import OpenClawInitializer

        init = OpenClawInitializer()
        result = init.generate_config(tmp_path)
        all_steps = "\n".join(result.next_steps)
        assert "enforcement" in all_steps.lower()

    def test_openclaw_init_mentions_openclaw_side_config(self, tmp_path):
        from clawsentry.cli.initializers.openclaw import OpenClawInitializer

        init = OpenClawInitializer()
        result = init.generate_config(tmp_path)
        all_steps = "\n".join(result.next_steps)
        assert "tools" in all_steps and "exec" in all_steps and "host" in all_steps

    def test_openclaw_init_mentions_watch(self, tmp_path):
        from clawsentry.cli.initializers.openclaw import OpenClawInitializer

        init = OpenClawInitializer()
        result = init.generate_config(tmp_path)
        all_steps = "\n".join(result.next_steps)
        assert "watch" in all_steps

    def test_a3s_code_init_mentions_watch(self, tmp_path):
        from clawsentry.cli.initializers.a3s_code import A3SCodeInitializer

        init = A3SCodeInitializer()
        result = init.generate_config(tmp_path)
        all_steps = "\n".join(result.next_steps)
        assert "watch" in all_steps

    def test_a3s_code_init_mentions_http_port(self, tmp_path):
        from clawsentry.cli.initializers.a3s_code import A3SCodeInitializer

        init = A3SCodeInitializer()
        result = init.generate_config(tmp_path)
        all_steps = "\n".join(result.next_steps)
        assert "8080" in all_steps
