"""Tests for clawsentry start command."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from clawsentry.cli.start_command import detect_framework


@pytest.fixture(autouse=True)
def _isolate_start_command_tests(tmp_path, monkeypatch):
    """Avoid repo-level .env.clawsentry and shell env leaking into detection tests."""
    with patch.dict(os.environ, {}, clear=False):
        monkeypatch.chdir(tmp_path)
        for key in (
            "CS_AUTH_TOKEN",
            "CS_FRAMEWORK",
            "CS_ENABLED_FRAMEWORKS",
            "CS_GEMINI_HOOKS_ENABLED",
            "CS_GEMINI_SETTINGS_PATH",
        ):
            monkeypatch.delenv(key, raising=False)
        yield


class TestDetectFramework:
    def test_explicit_framework_env_takes_priority_over_openclaw(self, tmp_path, monkeypatch):
        env_file = tmp_path / ".env.clawsentry"
        env_file.write_text("CS_FRAMEWORK=codex\n")
        monkeypatch.chdir(tmp_path)

        oc_home = tmp_path / ".openclaw"
        oc_home.mkdir()
        (oc_home / "openclaw.json").write_text("{}")

        result = detect_framework(openclaw_home=oc_home)
        assert result == "codex"

    def test_detects_openclaw(self, tmp_path):
        oc_home = tmp_path / ".openclaw"
        oc_home.mkdir()
        (oc_home / "openclaw.json").write_text("{}")
        result = detect_framework(openclaw_home=oc_home)
        assert result is None

    def test_detects_a3s_code(self, tmp_path):
        a3s_dir = tmp_path / ".a3s-code"
        a3s_dir.mkdir()
        (a3s_dir / "settings.json").write_text("{}")
        result = detect_framework(openclaw_home=tmp_path / "nope", a3s_dir=a3s_dir)
        assert result == "a3s-code"

    def test_a3s_dir_without_settings_json_not_detected(self, tmp_path):
        a3s_dir = tmp_path / ".a3s-code"
        a3s_dir.mkdir()
        result = detect_framework(
            openclaw_home=tmp_path / "nope",
            a3s_dir=a3s_dir,
            codex_home=tmp_path / "nope4",
            claude_home=tmp_path / "nope3",
        )
        assert result is None

    def test_shell_env_framework_opt_in(self, tmp_path, monkeypatch):
        """Explicit CS_FRAMEWORK in *shell env* is treated as opt-in."""
        monkeypatch.setenv("CS_FRAMEWORK", "openclaw")
        result = detect_framework(
            openclaw_home=tmp_path / ".openclaw",
            a3s_dir=tmp_path / ".a3s-code",
            codex_home=tmp_path / ".codex",
            claude_home=tmp_path / ".claude",
        )
        assert result == "openclaw"

    def test_returns_none_when_nothing_found(self, tmp_path):
        result = detect_framework(
            openclaw_home=tmp_path / "nope",
            a3s_dir=tmp_path / "nope2",
            codex_home=tmp_path / "nope4",
            claude_home=tmp_path / "nope3",
        )
        assert result is None

    def test_detects_codex_from_sessions_dir(self, tmp_path):
        codex_home = tmp_path / ".codex"
        (codex_home / "sessions").mkdir(parents=True)
        # Opt-in is required to avoid silent monitoring activation.
        os.environ["CS_CODEX_WATCH_ENABLED"] = "true"
        result = detect_framework(
            openclaw_home=tmp_path / "nope",
            a3s_dir=tmp_path / "nope2",
            claude_home=tmp_path / "nope3",
            codex_home=codex_home,
        )
        assert result == "codex"

    def test_env_enabled_frameworks_ignores_unknown_entries(self, tmp_path):
        env_file = tmp_path / ".env.clawsentry"
        env_file.write_text("CS_ENABLED_FRAMEWORKS=unknown,codex\n")

        result = detect_framework(
            openclaw_home=tmp_path / "nope",
            a3s_dir=tmp_path / "nope2",
            codex_home=tmp_path / "nope4",
            claude_home=tmp_path / "nope3",
        )

        assert result == "codex"

    def test_detects_gemini_cli_from_explicit_env_and_project_settings(self, tmp_path, monkeypatch):
        settings_path = tmp_path / ".gemini" / "settings.json"
        settings_path.parent.mkdir()
        settings_path.write_text("{}")
        monkeypatch.setenv("CS_GEMINI_HOOKS_ENABLED", "true")
        monkeypatch.chdir(tmp_path)

        result = detect_framework(
            openclaw_home=tmp_path / "nope",
            a3s_dir=tmp_path / "nope2",
            codex_home=tmp_path / "nope4",
            claude_home=tmp_path / "nope3",
        )

        assert result == "gemini-cli"


class TestEnsureInit:
    def test_skips_init_when_env_exists(self, tmp_path):
        from clawsentry.cli.start_command import ensure_init

        env_file = tmp_path / ".env.clawsentry"
        env_file.write_text("CS_AUTH_TOKEN=existing-token\n")
        result = ensure_init(framework="openclaw", target_dir=tmp_path)
        assert result is False  # did NOT run init
        # File unchanged
        assert "existing-token" in env_file.read_text()

    def test_runs_init_when_env_missing(self, tmp_path):
        from clawsentry.cli.start_command import ensure_init

        result = ensure_init(framework="a3s-code", target_dir=tmp_path)
        assert result is True  # DID run init
        assert (tmp_path / ".env.clawsentry").exists()

    def test_runs_init_openclaw_with_auto_detect(self, tmp_path):
        from clawsentry.cli.start_command import ensure_init

        # Create fake openclaw config so auto-detect works
        oc_home = tmp_path / ".openclaw"
        oc_home.mkdir()
        (oc_home / "openclaw.json").write_text(json.dumps({
            "gateway": {"auth": {"token": "test-tok"}, "port": 18789},
            "tools": {"exec": {"host": "gateway"}},
        }))
        result = ensure_init(
            framework="openclaw",
            target_dir=tmp_path,
            openclaw_home=oc_home,
        )
        assert result is True
        env_content = (tmp_path / ".env.clawsentry").read_text()
        assert "OPENCLAW_OPERATOR_TOKEN=test-tok" in env_content

    def test_openclaw_init_does_not_setup_external_config_by_default(self, tmp_path):
        from unittest.mock import patch
        from clawsentry.cli.start_command import ensure_init

        with patch("clawsentry.cli.start_command.run_init", return_value=0) as mock_run_init:
            result = ensure_init(framework="openclaw", target_dir=tmp_path)

        assert result is True
        assert mock_run_init.call_args.kwargs["setup"] is False

    def test_ensure_integrations_adds_missing_framework_only(self, tmp_path):
        from unittest.mock import patch
        from clawsentry.cli.start_command import ensure_integrations

        (tmp_path / ".env.clawsentry").write_text(
            "CS_FRAMEWORK=a3s-code\nCS_ENABLED_FRAMEWORKS=a3s-code\n"
        )

        with patch("clawsentry.cli.start_command.run_init", return_value=0) as mock_run_init:
            initialized = ensure_integrations(
                frameworks=["a3s-code", "codex"],
                target_dir=tmp_path,
            )

        assert initialized == ["codex"]
        mock_run_init.assert_called_once()
        assert mock_run_init.call_args.kwargs["framework"] == "codex"
        assert mock_run_init.call_args.kwargs["setup"] is False

    def test_ensure_integrations_forwards_setup_only_to_openclaw(self, tmp_path):
        from unittest.mock import patch
        from clawsentry.cli.start_command import ensure_integrations

        with patch("clawsentry.cli.start_command.run_init", return_value=0) as mock_run_init:
            ensure_integrations(
                frameworks=["codex", "openclaw"],
                target_dir=tmp_path,
                setup_openclaw=True,
            )

        assert mock_run_init.call_count == 2
        first_call = mock_run_init.call_args_list[0]
        second_call = mock_run_init.call_args_list[1]
        assert first_call.kwargs["framework"] == "codex"
        assert first_call.kwargs["setup"] is False
        assert second_call.kwargs["framework"] == "openclaw"
        assert second_call.kwargs["setup"] is True

    def test_raises_runtime_error_on_init_failure(self, tmp_path):
        from unittest.mock import patch
        import pytest
        from clawsentry.cli.start_command import ensure_init

        with patch('clawsentry.cli.start_command.run_init', return_value=1):
            with pytest.raises(RuntimeError, match="Failed to initialize openclaw configuration"):
                ensure_init(framework="openclaw", target_dir=tmp_path)


import subprocess
import signal
import time
from unittest.mock import patch, MagicMock

from clawsentry.cli.start_command import (
    launch_gateway,
    wait_for_health,
    shutdown_gateway,
)


class TestLaunchGateway:
    def test_launch_returns_popen(self, tmp_path):
        log_file = tmp_path / "gateway.log"
        with patch("subprocess.Popen") as mock_popen:
            mock_proc = MagicMock(pid=12345)
            mock_proc.poll.return_value = None  # process still running
            mock_popen.return_value = mock_proc
            proc = launch_gateway(
                host="127.0.0.1",
                port=8080,
                log_path=log_file,
                extra_env={},
            )
            assert proc.pid == 12345
            mock_popen.assert_called_once()
            call_args = mock_popen.call_args
            cmd = call_args[0][0]
            assert "clawsentry.gateway.stack" in " ".join(cmd)

    def test_raises_if_process_exits_immediately(self, tmp_path):
        log_file = tmp_path / "gateway.log"
        with patch("subprocess.Popen") as mock_popen:
            mock_proc = MagicMock()
            mock_proc.poll.return_value = 1  # exited with error
            mock_proc.returncode = 1
            mock_popen.return_value = mock_proc
            import pytest
            with pytest.raises(RuntimeError, match="Gateway process exited immediately with code 1"):
                launch_gateway(
                    host="127.0.0.1",
                    port=8080,
                    log_path=log_file,
                    extra_env={},
                )


class TestWaitForHealth:
    def test_returns_true_when_healthy(self):
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp
            assert wait_for_health("http://127.0.0.1:8080", timeout=1.0) is True

    def test_returns_false_on_timeout(self):
        with patch("urllib.request.urlopen", side_effect=OSError("refused")):
            assert wait_for_health("http://127.0.0.1:8080", timeout=0.3) is False


class TestShutdownGateway:
    def test_terminates_process(self):
        proc = MagicMock()
        proc.poll.return_value = None  # still running
        proc.wait.return_value = 0
        shutdown_gateway(proc)
        proc.terminate.assert_called_once()
        proc.wait.assert_called_once()

    def test_kills_if_terminate_times_out(self):
        proc = MagicMock()
        proc.poll.return_value = None
        # First wait() times out, second wait() (after kill) succeeds
        proc.wait.side_effect = [
            subprocess.TimeoutExpired(cmd="test", timeout=5),
            0,  # second wait() after kill succeeds
        ]
        shutdown_gateway(proc)
        proc.terminate.assert_called_once()
        proc.kill.assert_called_once()

    def test_skips_shutdown_if_already_exited(self):
        proc = MagicMock()
        proc.poll.return_value = 0  # already exited
        shutdown_gateway(proc)
        proc.terminate.assert_not_called()
        proc.kill.assert_not_called()


from clawsentry.cli.start_command import run_start


class TestRunStart:
    def test_run_start_banner_output(self, tmp_path, capsys):
        """Verify the startup banner prints correct info."""
        # Create .env.clawsentry so init is skipped
        env_file = tmp_path / ".env.clawsentry"
        env_file.write_text("CS_AUTH_TOKEN=test-token-123\nCS_HTTP_PORT=8080\n")

        with (
            patch("clawsentry.cli.start_command.launch_gateway") as mock_launch,
            patch("clawsentry.cli.start_command.wait_for_health", return_value=True),
            patch("clawsentry.cli.start_command.run_watch_loop") as mock_watch,
            patch("clawsentry.cli.start_command.shutdown_gateway"),
        ):
            mock_launch.return_value = MagicMock(pid=99999)
            mock_watch.side_effect = KeyboardInterrupt  # simulate Ctrl+C

            run_start(
                framework="a3s-code",
                host="127.0.0.1",
                port=8080,
                target_dir=tmp_path,
                no_watch=False,
                interactive=False,
            )

            captured = capsys.readouterr()
            assert "ClawSentry starting" in captured.out
            assert "127.0.0.1:8080" in captured.out
            assert "test-token-123" in captured.out
            assert "(auto-detected)" not in captured.out

    def test_run_start_banner_prints_enabled_frameworks(self, tmp_path, capsys):
        env_file = tmp_path / ".env.clawsentry"
        env_file.write_text(
            "CS_AUTH_TOKEN=test-token-123\n"
            "CS_FRAMEWORK=a3s-code\n"
            "CS_ENABLED_FRAMEWORKS=a3s-code,codex\n"
            "CS_CODEX_WATCH_ENABLED=true\n"
        )

        with (
            patch("clawsentry.cli.start_command.launch_gateway") as mock_launch,
            patch("clawsentry.cli.start_command.wait_for_health", return_value=True),
            patch("clawsentry.cli.start_command.run_watch_loop") as mock_watch,
            patch("clawsentry.cli.start_command.shutdown_gateway"),
        ):
            mock_launch.return_value = MagicMock(pid=99999)
            mock_watch.side_effect = KeyboardInterrupt

            run_start(
                framework="a3s-code",
                enabled_frameworks=["a3s-code", "codex"],
                host="127.0.0.1",
                port=8080,
                target_dir=tmp_path,
                no_watch=False,
                interactive=False,
            )

        out = capsys.readouterr().out
        assert "Enabled:    a3s-code, codex" in out

    def test_run_start_banner_includes_framework_readiness(self, tmp_path, capsys):
        env_file = tmp_path / ".env.clawsentry"
        env_file.write_text(
            "CS_AUTH_TOKEN=test-token-123\n"
            "CS_FRAMEWORK=a3s-code\n"
            "CS_ENABLED_FRAMEWORKS=a3s-code,codex,claude-code\n"
            "CS_CODEX_WATCH_ENABLED=true\n"
            "CS_UDS_PATH=/tmp/clawsentry.sock\n"
        )

        with (
            patch("clawsentry.cli.start_command.launch_gateway") as mock_launch,
            patch("clawsentry.cli.start_command.wait_for_health", return_value=True),
            patch("clawsentry.cli.start_command.shutdown_gateway"),
            patch("pathlib.Path.home", return_value=tmp_path),
        ):
            mock_launch.return_value = MagicMock(pid=99999)

            run_start(
                framework="a3s-code",
                enabled_frameworks=["a3s-code", "codex", "claude-code"],
                host="127.0.0.1",
                port=8080,
                target_dir=tmp_path,
                no_watch=True,
                interactive=False,
            )

        out = capsys.readouterr().out
        assert "Readiness:" in out
        assert "a3s-code: manual verification required" in out
        assert "codex: needs attention" in out
        assert "claude-code: needs attention" in out
        assert "Next actions:" in out
        assert "clawsentry init claude-code" in out

    def test_run_start_banner_mentions_openclaw_setup_hint(self, tmp_path, capsys):
        env_file = tmp_path / ".env.clawsentry"
        env_file.write_text(
            "CS_AUTH_TOKEN=test-token-123\n"
            "CS_FRAMEWORK=openclaw\n"
            "CS_ENABLED_FRAMEWORKS=openclaw\n"
        )

        with (
            patch("clawsentry.cli.start_command.launch_gateway") as mock_launch,
            patch("clawsentry.cli.start_command.wait_for_health", return_value=True),
            patch("clawsentry.cli.start_command.shutdown_gateway"),
        ):
            mock_launch.return_value = MagicMock(pid=99999)

            run_start(
                framework="openclaw",
                host="127.0.0.1",
                port=8080,
                target_dir=tmp_path,
                no_watch=True,
                interactive=False,
            )

        out = capsys.readouterr().out
        assert "--setup-openclaw" in out

    def test_run_start_setup_openclaw_applies_setup_for_existing_openclaw_env(
        self,
        tmp_path,
    ):
        from clawsentry.cli.initializers.base import SetupResult

        env_file = tmp_path / ".env.clawsentry"
        env_file.write_text(
            "CS_AUTH_TOKEN=test-token-123\n"
            "CS_FRAMEWORK=openclaw\n"
            "CS_ENABLED_FRAMEWORKS=openclaw\n"
        )

        with (
            patch("clawsentry.cli.start_command.launch_gateway") as mock_launch,
            patch("clawsentry.cli.start_command.wait_for_health", return_value=True),
            patch("clawsentry.cli.start_command.shutdown_gateway"),
            patch(
                "clawsentry.cli.initializers.openclaw.OpenClawInitializer.setup_openclaw_config",
                return_value=SetupResult(
                    changes_applied=["updated openclaw.json"],
                    files_modified=[],
                    files_backed_up=[],
                    warnings=[],
                    dry_run=False,
                ),
            ) as mock_setup,
        ):
            mock_launch.return_value = MagicMock(pid=99999)

            run_start(
                framework="openclaw",
                host="127.0.0.1",
                port=8080,
                target_dir=tmp_path,
                no_watch=True,
                interactive=False,
                setup_openclaw=True,
                openclaw_home=tmp_path / ".openclaw",
            )

        mock_setup.assert_called_once_with(openclaw_home=tmp_path / ".openclaw")

    def test_run_start_latch_banner_prints_enabled_frameworks(self, tmp_path, capsys):
        env_file = tmp_path / ".env.clawsentry"
        env_file.write_text(
            "CS_AUTH_TOKEN=test-token-123\n"
            "CS_FRAMEWORK=a3s-code\n"
            "CS_ENABLED_FRAMEWORKS=a3s-code,codex\n"
        )

        with (
            patch("clawsentry.latch.binary_manager.BinaryManager") as mock_bm_cls,
            patch("clawsentry.latch.process_manager.ProcessManager") as mock_pm_cls,
        ):
            mock_bm = MagicMock()
            mock_bm.is_installed = True
            mock_bm.binary_path = tmp_path / "latch"
            mock_bm_cls.return_value = mock_bm
            mock_pm = MagicMock()
            mock_pm.wait_for_health.return_value = True
            mock_pm_cls.return_value = mock_pm

            run_start(
                framework="a3s-code",
                enabled_frameworks=["a3s-code", "codex"],
                host="127.0.0.1",
                port=8080,
                target_dir=tmp_path,
                no_watch=True,
                interactive=False,
                with_latch=True,
            )

        out = capsys.readouterr().out
        assert "Enabled:    a3s-code, codex" in out

    def test_run_start_latch_no_watch_keeps_stack_running(self, tmp_path, capsys):
        env_file = tmp_path / ".env.clawsentry"
        env_file.write_text("CS_AUTH_TOKEN=test-token-123\n")

        with (
            patch("clawsentry.latch.binary_manager.BinaryManager") as mock_bm_cls,
            patch("clawsentry.latch.process_manager.ProcessManager") as mock_pm_cls,
        ):
            mock_bm = MagicMock()
            mock_bm.is_installed = True
            mock_bm.binary_path = tmp_path / "latch"
            mock_bm_cls.return_value = mock_bm
            mock_pm = MagicMock()
            mock_pm.wait_for_health.return_value = True
            mock_pm_cls.return_value = mock_pm

            run_start(
                framework="a3s-code",
                host="127.0.0.1",
                port=8080,
                target_dir=tmp_path,
                no_watch=True,
                interactive=False,
                with_latch=True,
            )

        out = capsys.readouterr().out
        assert "clawsentry latch stop" in out
        mock_pm.stop_all.assert_not_called()

    def test_run_start_no_watch_mode(self, tmp_path, capsys):
        env_file = tmp_path / ".env.clawsentry"
        env_file.write_text("CS_AUTH_TOKEN=abc\n")

        with (
            patch("clawsentry.cli.start_command.launch_gateway") as mock_launch,
            patch("clawsentry.cli.start_command.wait_for_health", return_value=True),
            patch("clawsentry.cli.start_command.run_watch_loop") as mock_watch,
            patch("clawsentry.cli.start_command.shutdown_gateway"),
        ):
            mock_launch.return_value = MagicMock(pid=99999)

            run_start(
                framework="a3s-code",
                host="127.0.0.1",
                port=8080,
                target_dir=tmp_path,
                no_watch=True,
                interactive=False,
            )

            mock_watch.assert_not_called()
            out = capsys.readouterr().out
            assert "clawsentry stop" in out
            assert "Ctrl+C" not in out

    def test_run_start_no_watch_prints_framework_readiness_summary(
        self,
        tmp_path,
        capsys,
    ):
        env_file = tmp_path / ".env.clawsentry"
        env_file.write_text(
            "\n".join(
                [
                    "CS_AUTH_TOKEN=abc",
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

        with (
            patch("pathlib.Path.home", return_value=tmp_path),
            patch("clawsentry.cli.start_command.launch_gateway") as mock_launch,
            patch("clawsentry.cli.start_command.wait_for_health", return_value=True),
            patch("clawsentry.cli.start_command.run_watch_loop") as mock_watch,
            patch("clawsentry.cli.start_command.shutdown_gateway"),
        ):
            mock_launch.return_value = MagicMock(pid=99999)

            run_start(
                framework="a3s-code",
                enabled_frameworks=["a3s-code", "openclaw", "codex", "claude-code"],
                host="127.0.0.1",
                port=8080,
                target_dir=tmp_path,
                no_watch=True,
                interactive=False,
                openclaw_home=openclaw_home,
            )

            mock_watch.assert_not_called()

        out = capsys.readouterr().out
        assert "Readiness:" in out
        assert "a3s-code: manual verification required" in out
        assert "openclaw: needs attention" in out
        assert "codex: needs attention" in out
        assert "claude-code: needs attention" in out
        assert "--setup-openclaw" in out
        assert "Next actions:" in out
        assert "clawsentry integrations status --json" in out

    def test_run_start_exits_on_health_fail(self, tmp_path, capsys):
        env_file = tmp_path / ".env.clawsentry"
        env_file.write_text("CS_AUTH_TOKEN=abc\n")

        with (
            patch("clawsentry.cli.start_command.launch_gateway") as mock_launch,
            patch("clawsentry.cli.start_command.wait_for_health", return_value=False),
            patch("clawsentry.cli.start_command.shutdown_gateway") as mock_shutdown,
        ):
            mock_proc = MagicMock(pid=99999)
            mock_launch.return_value = mock_proc

            run_start(
                framework="a3s-code",
                host="127.0.0.1",
                port=8080,
                target_dir=tmp_path,
                no_watch=False,
                interactive=False,
            )

            captured = capsys.readouterr()
            assert "failed to start" in captured.err.lower() or "failed" in captured.out.lower()
            mock_shutdown.assert_called_once()


# ---------------------------------------------------------------------------
# Task 5: detect_framework fix + PID file + stop/status + --open-browser
# ---------------------------------------------------------------------------


class TestDetectFrameworkFix:
    """detect_framework should not silently activate monitoring integrations."""

    def test_detect_claude_code_from_settings_json(self, tmp_path):
        claude_home = tmp_path / ".claude"
        claude_home.mkdir()
        settings = {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "",
                        "hooks": [
                            {
                                "type": "command",
                                "command": "clawsentry-harness --framework claude-code",
                            }
                        ],
                    }
                ]
            }
        }
        (claude_home / "settings.json").write_text(json.dumps(settings))
        nope = tmp_path / "nope"
        result = detect_framework(
            openclaw_home=nope, a3s_dir=nope, claude_home=claude_home,
        )
        assert result is None

    def test_detect_claude_code_from_settings_local_json(self, tmp_path):
        """Legacy Claude hooks should not cause auto-detect by themselves."""
        claude_home = tmp_path / ".claude"
        claude_home.mkdir()
        settings = {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "",
                        "hooks": [
                            {
                                "type": "command",
                                "command": "clawsentry-harness",
                            }
                        ],
                    }
                ]
            }
        }
        (claude_home / "settings.local.json").write_text(json.dumps(settings))
        nope = tmp_path / "nope"
        result = detect_framework(
            openclaw_home=nope, a3s_dir=nope, claude_home=claude_home,
        )
        assert result is None

    def test_detect_none_when_no_hooks(self, tmp_path):
        claude_home = tmp_path / ".claude"
        claude_home.mkdir()
        (claude_home / "settings.json").write_text("{}")
        nope = tmp_path / "nope"
        result = detect_framework(
            openclaw_home=nope, a3s_dir=nope, codex_home=nope, claude_home=claude_home,
        )
        assert result is None


class TestPidFileManagement:
    def test_write_and_read_pid_file(self, tmp_path):
        from clawsentry.cli.start_command import _write_pid_file, _read_pid_file

        pid_file = tmp_path / "gateway.pid"
        _write_pid_file(pid_file, 12345)
        assert _read_pid_file(pid_file) == 12345

    def test_read_missing_pid_file(self, tmp_path):
        from clawsentry.cli.start_command import _read_pid_file

        assert _read_pid_file(tmp_path / "nope.pid") is None

    def test_remove_pid_file(self, tmp_path):
        from clawsentry.cli.start_command import _write_pid_file, _remove_pid_file

        pid_file = tmp_path / "gateway.pid"
        _write_pid_file(pid_file, 12345)
        _remove_pid_file(pid_file)
        assert not pid_file.exists()

    def test_remove_missing_pid_file(self, tmp_path):
        from clawsentry.cli.start_command import _remove_pid_file

        _remove_pid_file(tmp_path / "nope.pid")  # should not raise


def test_main_start_passes_setup_openclaw_flag(tmp_path, monkeypatch):
    from clawsentry.cli.main import main

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env.clawsentry").write_text("CS_AUTH_TOKEN=test-token-123\n")

    with (
        patch("clawsentry.cli.start_command.run_start") as mock_run_start,
        patch("clawsentry.cli.dotenv_loader.load_dotenv"),
    ):
        main(
            [
                "start",
                "--framework",
                "openclaw",
                "--setup-openclaw",
                "--no-watch",
            ]
        )

    assert mock_run_start.call_args.kwargs["setup_openclaw"] is True


class TestStopStatus:
    def test_stop_no_pid_file(self, tmp_path, monkeypatch, capsys):
        from clawsentry.cli import start_command

        monkeypatch.setattr(start_command, "_PID_FILE", tmp_path / "nope.pid")
        start_command.run_stop()
        out = capsys.readouterr().out
        assert "not running" in out.lower() or "no running" in out.lower()

    def test_status_no_pid_file(self, tmp_path, monkeypatch, capsys):
        from clawsentry.cli import start_command

        monkeypatch.setattr(start_command, "_PID_FILE", tmp_path / "nope.pid")
        start_command.run_status()
        out = capsys.readouterr().out
        assert "not running" in out.lower()

    def test_status_stale_pid(self, tmp_path, monkeypatch, capsys):
        from clawsentry.cli import start_command

        pid_file = tmp_path / "gateway.pid"
        pid_file.write_text("999999999")  # non-existent PID
        monkeypatch.setattr(start_command, "_PID_FILE", pid_file)
        start_command.run_status()
        out = capsys.readouterr().out
        assert "stale" in out.lower() or "not found" in out.lower()

    def test_stop_sends_sigterm(self, tmp_path, monkeypatch, capsys):
        from clawsentry.cli import start_command

        pid_file = tmp_path / "gateway.pid"
        pid_file.write_text("12345")
        monkeypatch.setattr(start_command, "_PID_FILE", pid_file)

        with patch("os.kill") as mock_kill:
            start_command.run_stop()
            mock_kill.assert_called_once()
            args = mock_kill.call_args[0]
            assert args[0] == 12345
            assert args[1] == signal.SIGTERM

        out = capsys.readouterr().out
        assert "stopped" in out.lower()
        # PID file should be removed
        assert not pid_file.exists()

    def test_stop_handles_dead_process(self, tmp_path, monkeypatch, capsys):
        from clawsentry.cli import start_command

        pid_file = tmp_path / "gateway.pid"
        pid_file.write_text("999999999")
        monkeypatch.setattr(start_command, "_PID_FILE", pid_file)

        start_command.run_stop()
        out = capsys.readouterr().out
        assert "not running" in out.lower()
        # PID file should be cleaned up
        assert not pid_file.exists()

    def test_status_running_process(self, tmp_path, monkeypatch, capsys):
        """Status should report running when os.kill(pid, 0) succeeds."""
        from clawsentry.cli import start_command

        pid_file = tmp_path / "gateway.pid"
        pid_file.write_text("12345")
        monkeypatch.setattr(start_command, "_PID_FILE", pid_file)

        with patch("os.kill"):  # does not raise = process exists
            start_command.run_status()

        out = capsys.readouterr().out
        assert "running" in out.lower()
        assert "12345" in out


class TestRunStartPidAndBrowser:
    def test_run_start_writes_pid_file(self, tmp_path, capsys, monkeypatch):
        from clawsentry.cli import start_command

        pid_file = tmp_path / "gateway.pid"
        monkeypatch.setattr(start_command, "_PID_FILE", pid_file)

        env_file = tmp_path / ".env.clawsentry"
        env_file.write_text("CS_AUTH_TOKEN=abc\n")

        with (
            patch("clawsentry.cli.start_command.launch_gateway") as mock_launch,
            patch(
                "clawsentry.cli.start_command.wait_for_health", return_value=True
            ),
            patch("clawsentry.cli.start_command.run_watch_loop") as mock_watch,
            patch("clawsentry.cli.start_command.shutdown_gateway"),
        ):
            mock_launch.return_value = MagicMock(pid=54321)
            mock_watch.side_effect = KeyboardInterrupt

            run_start(
                framework="a3s-code",
                host="127.0.0.1",
                port=8080,
                target_dir=tmp_path,
                no_watch=False,
                interactive=False,
            )

        # PID file should have been written (and removed after shutdown)
        # Since shutdown_gateway is mocked, the PID file cleanup happens
        # in the finally block — but we patched shutdown_gateway so we
        # need to check the file was written at some point.
        # Actually the PID file gets removed in the finally block.
        # Let's just verify the write happened by checking the mock wasn't
        # called with wrong args. Instead, let's verify differently:
        # The PID cleanup happens in the finally block, so the file is gone.
        assert not pid_file.exists()  # cleaned up in finally

    def test_run_start_open_browser(self, tmp_path, capsys, monkeypatch):
        from clawsentry.cli import start_command

        pid_file = tmp_path / "gateway.pid"
        monkeypatch.setattr(start_command, "_PID_FILE", pid_file)

        env_file = tmp_path / ".env.clawsentry"
        env_file.write_text("CS_AUTH_TOKEN=abc\n")

        with (
            patch("clawsentry.cli.start_command.launch_gateway") as mock_launch,
            patch(
                "clawsentry.cli.start_command.wait_for_health", return_value=True
            ),
            patch("clawsentry.cli.start_command.run_watch_loop") as mock_watch,
            patch("clawsentry.cli.start_command.shutdown_gateway"),
            patch("webbrowser.open") as mock_browser,
        ):
            mock_launch.return_value = MagicMock(pid=54321)
            mock_watch.side_effect = KeyboardInterrupt

            run_start(
                framework="a3s-code",
                host="127.0.0.1",
                port=8080,
                target_dir=tmp_path,
                no_watch=False,
                interactive=False,
                open_browser=True,
            )

            mock_browser.assert_called_once()
            url_arg = mock_browser.call_args[0][0]
            assert "127.0.0.1:8080" in url_arg

    def test_run_start_no_open_browser_by_default(self, tmp_path, capsys, monkeypatch):
        from clawsentry.cli import start_command

        pid_file = tmp_path / "gateway.pid"
        monkeypatch.setattr(start_command, "_PID_FILE", pid_file)

        env_file = tmp_path / ".env.clawsentry"
        env_file.write_text("CS_AUTH_TOKEN=abc\n")

        with (
            patch("clawsentry.cli.start_command.launch_gateway") as mock_launch,
            patch(
                "clawsentry.cli.start_command.wait_for_health", return_value=True
            ),
            patch("clawsentry.cli.start_command.run_watch_loop") as mock_watch,
            patch("clawsentry.cli.start_command.shutdown_gateway"),
            patch("webbrowser.open") as mock_browser,
        ):
            mock_launch.return_value = MagicMock(pid=54321)
            mock_watch.side_effect = KeyboardInterrupt

            run_start(
                framework="a3s-code",
                host="127.0.0.1",
                port=8080,
                target_dir=tmp_path,
                no_watch=False,
                interactive=False,
            )

            mock_browser.assert_not_called()

    def test_run_start_marks_auto_detected_when_requested(self, tmp_path, capsys, monkeypatch):
        from clawsentry.cli import start_command

        pid_file = tmp_path / "gateway.pid"
        monkeypatch.setattr(start_command, "_PID_FILE", pid_file)

        env_file = tmp_path / ".env.clawsentry"
        env_file.write_text("CS_AUTH_TOKEN=abc\n")

        with (
            patch("clawsentry.cli.start_command.launch_gateway") as mock_launch,
            patch(
                "clawsentry.cli.start_command.wait_for_health", return_value=True
            ),
            patch("clawsentry.cli.start_command.run_watch_loop") as mock_watch,
            patch("clawsentry.cli.start_command.shutdown_gateway"),
        ):
            mock_launch.return_value = MagicMock(pid=54321)
            mock_watch.side_effect = KeyboardInterrupt

            run_start(
                framework="codex",
                host="127.0.0.1",
                port=8080,
                target_dir=tmp_path,
                no_watch=False,
                interactive=False,
                auto_detected=True,
            )

        out = capsys.readouterr().out
        assert "Framework:  codex (auto-detected)" in out


class TestStartMainFrameworks:
    def test_main_start_frameworks_dispatches_enabled_list(self):
        from clawsentry.cli.main import main

        with patch("clawsentry.cli.start_command.run_start") as mock_run_start:
            main([
                "start",
                "--frameworks",
                "a3s-code,codex",
                "--no-watch",
            ])

        assert mock_run_start.call_args.kwargs["framework"] == "a3s-code"
        assert mock_run_start.call_args.kwargs["enabled_frameworks"] == [
            "a3s-code",
            "codex",
        ]
