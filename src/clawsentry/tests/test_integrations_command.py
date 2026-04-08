"""Tests for ``clawsentry integrations`` status output."""

from __future__ import annotations

import os
import json
from unittest.mock import patch

from clawsentry.cli.integrations_command import run_integrations_status


def test_integrations_status_reports_enabled_frameworks(tmp_path, capsys):
    env_file = tmp_path / ".env.clawsentry"
    env_file.write_text(
        "\n".join(
            [
                "CS_FRAMEWORK=a3s-code",
                "CS_ENABLED_FRAMEWORKS=a3s-code,codex",
                "CS_AUTH_TOKEN=keep-token",
                "CS_CODEX_WATCH_ENABLED=true",
                "",
            ]
        )
    )

    exit_code = run_integrations_status(target_dir=tmp_path)

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "Enabled frameworks: a3s-code, codex" in out
    assert "Legacy default: a3s-code" in out
    assert "Codex watcher: enabled" in out


def test_main_integrations_status_dispatches(tmp_path, monkeypatch):
    import pytest
    from clawsentry.cli.main import main

    (tmp_path / ".env.clawsentry").write_text("CS_ENABLED_FRAMEWORKS=codex\n")
    monkeypatch.chdir(tmp_path)

    with patch.dict(os.environ, {}, clear=True):
        with pytest.raises(SystemExit) as exc:
            main(["integrations", "status", "--dir", str(tmp_path)])

    assert exc.value.code == 0


def test_integrations_status_json_does_not_report_a3s_transport_for_codex_only(
    tmp_path,
    capsys,
):
    env_file = tmp_path / ".env.clawsentry"
    env_file.write_text(
        "\n".join(
            [
                "CS_FRAMEWORK=codex",
                "CS_ENABLED_FRAMEWORKS=codex",
                "CS_HTTP_PORT=8080",
                "CS_CODEX_WATCH_ENABLED=true",
                "",
            ]
        )
    )

    exit_code = run_integrations_status(target_dir=tmp_path, json_mode=True)

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["a3s_transport_env"] is False


def test_integrations_status_json_reports_claude_hooks_only_when_present(
    tmp_path,
    capsys,
):
    env_file = tmp_path / ".env.clawsentry"
    env_file.write_text(
        "\n".join(
            [
                "CS_FRAMEWORK=claude-code",
                "CS_ENABLED_FRAMEWORKS=claude-code",
                "",
            ]
        )
    )

    with patch("pathlib.Path.home", return_value=tmp_path):
        exit_code = run_integrations_status(target_dir=tmp_path, json_mode=True)

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["claude_code_hooks"] is False

    claude_home = tmp_path / ".claude"
    claude_home.mkdir()
    (claude_home / "settings.json").write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": "clawsentry-harness --framework claude-code",
                                }
                            ]
                        }
                    ]
                }
            }
        )
    )

    with patch("pathlib.Path.home", return_value=tmp_path):
        exit_code = run_integrations_status(target_dir=tmp_path, json_mode=True)

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["claude_code_hooks"] is True
    assert payload["claude_code_hook_files"] == [
        str(claude_home / "settings.json")
    ]


def test_integrations_status_json_reports_openclaw_restore_backups(
    tmp_path,
    capsys,
):
    env_file = tmp_path / ".env.clawsentry"
    env_file.write_text(
        "\n".join(
            [
                "CS_FRAMEWORK=openclaw",
                "CS_ENABLED_FRAMEWORKS=openclaw",
                "",
            ]
        )
    )

    openclaw_home = tmp_path / ".openclaw"
    openclaw_home.mkdir()
    (openclaw_home / "openclaw.json.bak").write_text("{}")

    with patch("pathlib.Path.home", return_value=tmp_path):
        exit_code = run_integrations_status(target_dir=tmp_path, json_mode=True)

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["openclaw_restore_available"] is True
    assert payload["openclaw_restore_files"] == [
        str(openclaw_home / "openclaw.json.bak")
    ]


def test_integrations_status_json_reports_codex_session_dir_reachability(
    tmp_path,
    capsys,
):
    env_file = tmp_path / ".env.clawsentry"
    env_file.write_text(
        "\n".join(
            [
                "CS_FRAMEWORK=codex",
                "CS_ENABLED_FRAMEWORKS=codex",
                "CS_CODEX_WATCH_ENABLED=true",
                "",
            ]
        )
    )

    codex_home = tmp_path / ".codex"
    sessions_dir = codex_home / "sessions"
    sessions_dir.mkdir(parents=True)

    with (
        patch("pathlib.Path.home", return_value=tmp_path),
        patch.dict(os.environ, {"CODEX_HOME": str(codex_home)}, clear=False),
    ):
        exit_code = run_integrations_status(target_dir=tmp_path, json_mode=True)

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["codex_session_dir"] == str(sessions_dir)
    assert payload["codex_session_dir_reachable"] is True


def test_integrations_status_text_includes_extended_diagnostics(tmp_path, capsys):
    env_file = tmp_path / ".env.clawsentry"
    env_file.write_text(
        "\n".join(
            [
                "CS_FRAMEWORK=openclaw",
                "CS_ENABLED_FRAMEWORKS=openclaw,codex,claude-code",
                "CS_CODEX_WATCH_ENABLED=true",
                "",
            ]
        )
    )

    openclaw_home = tmp_path / ".openclaw"
    openclaw_home.mkdir()
    (openclaw_home / "exec-approvals.json.bak").write_text("{}")

    claude_home = tmp_path / ".claude"
    claude_home.mkdir()
    (claude_home / "settings.local.json").write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": "clawsentry-harness --framework claude-code",
                                }
                            ]
                        }
                    ]
                }
            }
        )
    )

    sessions_dir = tmp_path / ".codex" / "sessions"
    sessions_dir.mkdir(parents=True)

    with (
        patch("pathlib.Path.home", return_value=tmp_path),
        patch.dict(os.environ, {"CODEX_HOME": str(tmp_path / ".codex")}, clear=False),
    ):
        exit_code = run_integrations_status(target_dir=tmp_path)

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "Claude hooks files:" in out
    assert str(claude_home / "settings.local.json") in out
    assert "OpenClaw restore:" in out
    assert "available" in out
    assert "Codex session dir:" in out
    assert str(sessions_dir) in out
