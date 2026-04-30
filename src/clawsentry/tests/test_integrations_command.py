"""Tests for ``clawsentry integrations`` env-first status output."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

from clawsentry.cli.integrations_command import run_integrations_status


def _write_explicit_env(tmp_path: Path, content: str) -> Path:
    env_file = tmp_path / ".clawsentry.env.local"
    env_file.write_text(content, encoding="utf-8")
    return env_file


def test_integrations_status_reports_enabled_frameworks_from_env_file(tmp_path, capsys):
    env_file = _write_explicit_env(
        tmp_path,
        "\n".join([
            "CS_FRAMEWORK=a3s-code",
            "CS_ENABLED_FRAMEWORKS=a3s-code,codex",
            "CS_AUTH_TOKEN" + "=keep-token",
            "CS_CODEX_WATCH_ENABLED=true",
            "",
        ]),
    )

    exit_code = run_integrations_status(target_dir=tmp_path, env_file=env_file)

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "Enabled frameworks: a3s-code, codex" in out
    assert "Default framework: a3s-code" in out
    assert "Codex watcher: enabled" in out
    assert not (tmp_path / (".clawsentry" + ".toml")).exists()


def test_integrations_status_uses_process_env_for_readiness(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("CS_ENABLED_FRAMEWORKS", "a3s-code")
    monkeypatch.setenv("CS_HTTP_PORT", "8080")

    exit_code = run_integrations_status(target_dir=tmp_path, json_mode=True)

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["env_exists"] is False
    assert payload["enabled_frameworks"] == ["a3s-code"]
    assert payload["framework_readiness"]["a3s-code"]["checks"]["gateway_endpoint_configured"] is True


def test_main_integrations_status_dispatches_with_explicit_env_file(tmp_path, monkeypatch):
    import pytest
    from clawsentry.cli.main import main

    env_file = _write_explicit_env(tmp_path, "CS_ENABLED_FRAMEWORKS=codex\n")
    monkeypatch.chdir(tmp_path)

    with patch.dict(os.environ, {}, clear=True):
        with pytest.raises(SystemExit) as exc:
            main(["integrations", "status", "--dir", str(tmp_path), "--env-file", str(env_file)])

    assert exc.value.code == 0


def test_integrations_status_json_reports_codex_session_dir_reachability(tmp_path, capsys):
    env_file = _write_explicit_env(
        tmp_path,
        "CS_FRAMEWORK=codex\nCS_ENABLED_FRAMEWORKS=codex\nCS_CODEX_WATCH_ENABLED=true\n",
    )
    codex_home = tmp_path / ".codex"
    sessions_dir = codex_home / "sessions"
    sessions_dir.mkdir(parents=True)

    with patch.dict(os.environ, {"CODEX_HOME": str(codex_home)}, clear=False):
        exit_code = run_integrations_status(target_dir=tmp_path, json_mode=True, env_file=env_file)

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["codex_session_dir"] == str(sessions_dir)
    assert payload["codex_session_dir_reachable"] is True


def test_integrations_status_json_reports_claude_hooks_only_when_present(tmp_path, capsys):
    env_file = _write_explicit_env(tmp_path, "CS_FRAMEWORK=claude-code\nCS_ENABLED_FRAMEWORKS=claude-code\n")
    with patch("pathlib.Path.home", return_value=tmp_path):
        exit_code = run_integrations_status(target_dir=tmp_path, json_mode=True, env_file=env_file)
    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["claude_code_hooks"] is False

    claude_home = tmp_path / ".claude"
    claude_home.mkdir()
    (claude_home / "settings.json").write_text(json.dumps({"hooks": {"PreToolUse": [{"hooks": [{"command": "clawsentry-harness"}]}]}}))
    with patch("pathlib.Path.home", return_value=tmp_path):
        exit_code = run_integrations_status(target_dir=tmp_path, json_mode=True, env_file=env_file)
    payload = json.loads(capsys.readouterr().out)
    assert payload["claude_code_hooks"] is True
