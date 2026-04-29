"""Tests for ``clawsentry integrations`` status output."""

from __future__ import annotations

import os
import json
from unittest.mock import patch

from clawsentry.cli.integrations_command import run_integrations_status
from clawsentry.gateway.project_config import update_project_framework


def _write_explicit_env(tmp_path, content: str) -> Path:
    env_file = tmp_path / ".env.clawsentry"
    env_file.write_text(content)
    values = {}
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    frameworks = []
    for item in values.get("CS_ENABLED_FRAMEWORKS", "").split(","):
        item = item.strip()
        if item and item not in frameworks:
            frameworks.append(item)
    legacy = values.get("CS_FRAMEWORK", "").strip()
    if legacy and legacy not in frameworks:
        frameworks.insert(0, legacy)
    for framework in frameworks:
        update_project_framework(tmp_path, framework)
    return env_file


def test_integrations_status_reports_enabled_frameworks(tmp_path, capsys):
    env_file = _write_explicit_env(tmp_path,
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

    exit_code = run_integrations_status(target_dir=tmp_path, env_file=env_file)

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "Enabled frameworks: a3s-code, codex" in out
    assert "Legacy default: a3s-code" in out
    assert "Codex watcher: enabled" in out



def test_integrations_status_uses_process_env_for_readiness(tmp_path, capsys, monkeypatch):
    update_project_framework(tmp_path, "a3s-code")
    monkeypatch.setenv("CS_HTTP_PORT", "8080")

    exit_code = run_integrations_status(target_dir=tmp_path, json_mode=True)

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["env_exists"] is False
    readiness = payload["framework_readiness"]
    assert readiness["a3s-code"]["status"] == "manual_verification_required"
    assert readiness["a3s-code"]["checks"]["gateway_endpoint_configured"] is True

def test_main_integrations_status_dispatches(tmp_path, monkeypatch):
    import pytest
    from clawsentry.cli.main import main

    _write_explicit_env(tmp_path, "CS_ENABLED_FRAMEWORKS=codex\n")
    monkeypatch.chdir(tmp_path)

    with patch.dict(os.environ, {}, clear=True):
        with pytest.raises(SystemExit) as exc:
            main(["integrations", "status", "--dir", str(tmp_path)])

    assert exc.value.code == 0


def test_integrations_status_json_does_not_report_a3s_transport_for_codex_only(
    tmp_path,
    capsys,
):
    env_file = _write_explicit_env(tmp_path,
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

    exit_code = run_integrations_status(target_dir=tmp_path, json_mode=True, env_file=env_file)

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["a3s_transport_env"] is False


def test_integrations_status_json_reports_claude_hooks_only_when_present(
    tmp_path,
    capsys,
):
    env_file = _write_explicit_env(tmp_path,
        "\n".join(
            [
                "CS_FRAMEWORK=claude-code",
                "CS_ENABLED_FRAMEWORKS=claude-code",
                "",
            ]
        )
    )

    with patch("pathlib.Path.home", return_value=tmp_path):
        exit_code = run_integrations_status(target_dir=tmp_path, json_mode=True, env_file=env_file)

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
        exit_code = run_integrations_status(target_dir=tmp_path, json_mode=True, env_file=env_file)

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
    env_file = _write_explicit_env(tmp_path,
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
        exit_code = run_integrations_status(target_dir=tmp_path, json_mode=True, env_file=env_file)

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
    env_file = _write_explicit_env(tmp_path,
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
        exit_code = run_integrations_status(target_dir=tmp_path, json_mode=True, env_file=env_file)

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["codex_session_dir"] == str(sessions_dir)
    assert payload["codex_session_dir_reachable"] is True


def test_integrations_status_json_includes_framework_capability_matrix(
    tmp_path,
    capsys,
):
    env_file = _write_explicit_env(tmp_path,
        "\n".join(
            [
                "CS_FRAMEWORK=codex",
                "CS_ENABLED_FRAMEWORKS=codex,claude-code",
                "CS_CODEX_WATCH_ENABLED=true",
                "",
            ]
        )
    )

    exit_code = run_integrations_status(target_dir=tmp_path, json_mode=True, env_file=env_file)

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["framework_capabilities"]["a3s-code"]["integration_mode"] == "explicit_sdk_transport"
    assert payload["framework_capabilities"]["codex"]["integration_mode"] == "session_jsonl_watcher_native_hooks"
    assert payload["framework_capabilities"]["codex"]["pre_action_interception"] == "optional_native_hooks"
    assert payload["framework_capabilities"]["claude-code"]["host_config_dependency"].startswith("~/.claude")
    assert payload["enabled_framework_details"]["codex"]["maturity_label"] == "medium-high"
    assert payload["enabled_framework_details"]["claude-code"]["pre_action_label"] == "yes"


def test_integrations_status_json_includes_framework_readiness(tmp_path, capsys):
    env_file = _write_explicit_env(tmp_path,
        "\n".join(
            [
                "CS_FRAMEWORK=a3s-code",
                "CS_ENABLED_FRAMEWORKS=a3s-code,codex,claude-code",
                "CS_CODEX_WATCH_ENABLED=true",
                "CS_UDS_PATH=/tmp/clawsentry.sock",
                "",
            ]
        )
    )

    with patch("pathlib.Path.home", return_value=tmp_path):
        exit_code = run_integrations_status(target_dir=tmp_path, json_mode=True, env_file=env_file)

    payload = json.loads(capsys.readouterr().out)
    readiness = payload["framework_readiness"]
    assert exit_code == 0
    assert readiness["a3s-code"]["status"] == "manual_verification_required"
    assert readiness["a3s-code"]["next_step"].startswith(
        "Verify agent code sets SessionOptions.ahp_transport"
    )
    assert readiness["codex"]["status"] == "needs_attention"
    assert readiness["codex"]["checks"]["watcher_enabled"] is True
    assert readiness["codex"]["checks"]["session_dir_reachable"] is False
    assert readiness["claude-code"]["status"] == "needs_attention"
    assert "clawsentry init claude-code" in readiness["claude-code"]["next_step"]


def test_integrations_status_json_reports_openclaw_host_setup_gaps(
    tmp_path,
    capsys,
):
    env_file = _write_explicit_env(tmp_path,
        "\n".join(
            [
                "CS_FRAMEWORK=openclaw",
                "CS_ENABLED_FRAMEWORKS=openclaw",
                "OPENCLAW_ENFORCEMENT_ENABLED=true",
                "OPENCLAW_OPERATOR_TOKEN=test-token",
                "",
            ]
        )
    )

    openclaw_home = tmp_path / ".openclaw"
    openclaw_home.mkdir()
    (openclaw_home / "openclaw.json").write_text("{}")

    with patch("pathlib.Path.home", return_value=tmp_path):
        exit_code = run_integrations_status(target_dir=tmp_path, json_mode=True, env_file=env_file)

    payload = json.loads(capsys.readouterr().out)
    readiness = payload["framework_readiness"]["openclaw"]
    assert exit_code == 0
    assert readiness["status"] == "needs_attention"
    assert readiness["checks"]["project_env_configured"] is True
    assert readiness["checks"]["openclaw_exec_host_gateway"] is False
    assert readiness["checks"]["exec_approvals_configured"] is False
    assert "clawsentry init openclaw --setup --dry-run" in readiness["next_step"]


def test_integrations_status_text_includes_extended_diagnostics(tmp_path, capsys):
    env_file = _write_explicit_env(tmp_path,
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
        exit_code = run_integrations_status(target_dir=tmp_path, env_file=env_file)

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "Claude hooks files:" in out
    assert str(claude_home / "settings.local.json") in out
    assert "OpenClaw restore:" in out
    assert "available" in out
    assert "Codex session dir:" in out
    assert str(sessions_dir) in out


def test_integrations_status_json_reports_framework_capability_matrix(
    tmp_path,
    capsys,
):
    env_file = _write_explicit_env(tmp_path,
        "\n".join(
            [
                "CS_ENABLED_FRAMEWORKS=a3s-code,claude-code,codex,openclaw",
                "CS_CODEX_WATCH_ENABLED=true",
                "",
            ]
        )
    )

    exit_code = run_integrations_status(target_dir=tmp_path, json_mode=True, env_file=env_file)

    payload = json.loads(capsys.readouterr().out)
    capabilities = payload["framework_capabilities"]
    assert exit_code == 0
    assert capabilities["a3s-code"]["integration_mode"] == "explicit_sdk_transport"
    assert capabilities["a3s-code"]["pre_action_interception"] == "supported"
    assert capabilities["openclaw"]["pre_action_interception"] == "host_config_required"
    assert capabilities["codex"]["pre_action_interception"] == "optional_native_hooks"
    assert capabilities["codex"]["post_action_observation"] == "session_log_watcher_native_hooks"
    assert capabilities["claude-code"]["integration_mode"] == "host_hooks"
    assert capabilities["claude-code"]["maturity"] == "hook_dependent"


def test_integrations_status_text_includes_framework_capability_summary(
    tmp_path,
    capsys,
):
    env_file = _write_explicit_env(tmp_path,
        "\n".join(
            [
                "CS_ENABLED_FRAMEWORKS=a3s-code,codex,openclaw",
                "CS_CODEX_WATCH_ENABLED=true",
                "",
            ]
        )
    )

    exit_code = run_integrations_status(target_dir=tmp_path, env_file=env_file)

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "Framework capabilities:" in out
    assert "a3s-code" in out
    assert "mode=explicit_sdk_transport" in out
    assert "codex" in out
    assert "pre=optional_native_hooks" in out
    assert "openclaw" in out
    assert "maturity=strong_with_host_setup" in out
    assert "Enabled framework details:" in out
    assert "codex: session JSONL watcher + optional native hooks | pre-action: optional Bash preflight + approval gate | post-action: yes | maturity: medium-high" in out
    assert "openclaw: websocket approvals + webhook receiver | pre-action: yes | post-action: yes | maturity: medium-high" in out


def test_integrations_status_json_includes_multi_framework_readiness(
    tmp_path,
    capsys,
):
    env_file = _write_explicit_env(tmp_path,
        "\n".join(
            [
                "CS_FRAMEWORK=a3s-code",
                "CS_ENABLED_FRAMEWORKS=a3s-code,openclaw,codex,claude-code",
                "CS_UDS_PATH=/tmp/clawsentry.sock",
                "CS_CODEX_WATCH_ENABLED=true",
                "OPENCLAW_WS_URL=ws://127.0.0.1:18789",
                "OPENCLAW_OPERATOR_TOKEN=test-token",
                "OPENCLAW_ENFORCEMENT_ENABLED=true",
                "",
            ]
        )
    )

    openclaw_home = tmp_path / ".openclaw"
    openclaw_home.mkdir()
    (openclaw_home / "openclaw.json").write_text(
        json.dumps({"tools": {"exec": {"host": "sandbox"}}})
    )
    (openclaw_home / "exec-approvals.json").write_text(
        json.dumps({"security": "deny", "ask": "manual"})
    )

    with patch("pathlib.Path.home", return_value=tmp_path):
        exit_code = run_integrations_status(target_dir=tmp_path, json_mode=True, env_file=env_file)

    payload = json.loads(capsys.readouterr().out)
    readiness = payload["framework_readiness"]
    assert exit_code == 0
    assert readiness["a3s-code"]["status"] == "manual_verification_required"
    assert "SessionOptions.ahp_transport" in readiness["a3s-code"]["summary"]
    assert readiness["openclaw"]["status"] == "needs_attention"
    assert "tools.exec.host" in " ".join(readiness["openclaw"]["warnings"])
    assert "--setup-openclaw" in readiness["openclaw"]["next_step"]
    assert readiness["codex"]["status"] == "needs_attention"
    assert "session dir" in " ".join(readiness["codex"]["warnings"]).lower()
    assert "CS_CODEX_SESSION_DIR" in readiness["codex"]["next_step"]
    assert readiness["claude-code"]["status"] == "needs_attention"
    assert "hooks" in " ".join(readiness["claude-code"]["warnings"]).lower()


def test_integrations_status_text_includes_framework_readiness_block(
    tmp_path,
    capsys,
):
    env_file = _write_explicit_env(tmp_path,
        "\n".join(
            [
                "CS_FRAMEWORK=a3s-code",
                "CS_ENABLED_FRAMEWORKS=a3s-code,codex,claude-code",
                "CS_UDS_PATH=/tmp/clawsentry.sock",
                "CS_CODEX_WATCH_ENABLED=true",
                "",
            ]
        )
    )

    with patch("pathlib.Path.home", return_value=tmp_path):
        exit_code = run_integrations_status(target_dir=tmp_path, env_file=env_file)

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "Readiness:" in out
    assert "a3s-code: manual verification required" in out
    assert "codex: needs attention" in out
    assert "claude-code: needs attention" in out
    assert "clawsentry init claude-code" in out


def test_integrations_status_text_includes_framework_readiness_section(
    tmp_path,
    capsys,
):
    env_file = _write_explicit_env(tmp_path,
        "\n".join(
            [
                "CS_ENABLED_FRAMEWORKS=a3s-code,codex",
                "CS_CODEX_WATCH_ENABLED=true",
                "CS_UDS_PATH=/tmp/clawsentry.sock",
                "",
            ]
        )
    )

    with patch("pathlib.Path.home", return_value=tmp_path):
        exit_code = run_integrations_status(target_dir=tmp_path, env_file=env_file)

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "Readiness:" in out
    assert "a3s-code: manual verification required" in out
    assert "codex: needs attention" in out
    assert "next step:" in out


def test_integrations_status_json_includes_gemini_readiness(tmp_path, capsys):
    from clawsentry.cli.initializers.gemini_cli import GeminiCLIInitializer

    GeminiCLIInitializer().setup_gemini_hooks(target_dir=tmp_path)
    settings_path = tmp_path / ".gemini" / "settings.json"
    env_file = _write_explicit_env(tmp_path,
        "\n".join(
            [
                "CS_FRAMEWORK=gemini-cli",
                "CS_ENABLED_FRAMEWORKS=gemini-cli",
                "CS_GEMINI_HOOKS_ENABLED=true",
                f"CS_GEMINI_SETTINGS_PATH={settings_path}",
                "",
            ]
        )
    )

    exit_code = run_integrations_status(target_dir=tmp_path, json_mode=True, env_file=env_file)

    payload = json.loads(capsys.readouterr().out)
    readiness = payload["framework_readiness"]["gemini-cli"]
    assert exit_code == 0
    assert payload["gemini_cli_hooks"] is True
    assert readiness["status"] == "ready"
    assert readiness["checks"]["managed_entries_present"] is True
    assert readiness["checks"]["real_beforetool_smoke"] is True
    assert payload["framework_capabilities"]["gemini-cli"]["maturity"] == "real_beforetool_block_supported"


def test_integrations_status_text_includes_gemini_capability(tmp_path, capsys):
    env_file = _write_explicit_env(tmp_path,
        "\n".join(
            [
                "CS_FRAMEWORK=gemini-cli",
                "CS_ENABLED_FRAMEWORKS=gemini-cli",
                "CS_GEMINI_HOOKS_ENABLED=true",
                "",
            ]
        )
    )

    exit_code = run_integrations_status(target_dir=tmp_path, env_file=env_file)

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "gemini-cli: mode=native_command_hooks" in out
    assert "real BeforeTool deny smoke proven" in out
    assert "Gemini settings:" in out


def test_integrations_status_json_reports_kimi_config_readiness(
    tmp_path,
    capsys,
):
    kimi_home = tmp_path / ".kimi"
    kimi_home.mkdir()
    config_path = kimi_home / "config.toml"
    config_path.write_text(
        "[[hooks]]\n"
        'event = "PreToolUse"\n'
        "command = 'clawsentry harness --framework kimi-cli'\n"
    )
    env_file = _write_explicit_env(tmp_path, f"CS_ENABLED_FRAMEWORKS=kimi-cli\nCS_KIMI_CONFIG_PATH={config_path}\n")

    exit_code = run_integrations_status(target_dir=tmp_path, json_mode=True, env_file=env_file)

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["kimi_cli_hooks"] is True
    assert payload["kimi_cli_config_path"] == str(config_path)
    readiness = payload["framework_readiness"]["kimi-cli"]
    assert readiness["status"] == "ready"
    assert readiness["checks"]["native_modify_supported"] is False
    assert readiness["checks"]["native_defer_supported"] is False
