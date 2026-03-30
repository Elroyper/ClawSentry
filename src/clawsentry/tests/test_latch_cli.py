"""Tests for latch CLI commands (latch_command.py + main.py dispatch)."""

from __future__ import annotations

import os
from pathlib import Path
from unittest import mock

import pytest

from clawsentry.latch.process_manager import ServiceStatus


# Helper: we need to patch the actual classes in the latch subpackage,
# then the deferred imports inside latch_command.py will pick them up.


def _run_install(**kwargs):
    """Import and call run_latch_install (forces fresh import each time)."""
    from clawsentry.cli.latch_command import run_latch_install
    return run_latch_install(**kwargs)


def _run_start(**kwargs):
    from clawsentry.cli.latch_command import run_latch_start
    return run_latch_start(**kwargs)


def _run_stop():
    from clawsentry.cli.latch_command import run_latch_stop
    return run_latch_stop()


def _run_status():
    from clawsentry.cli.latch_command import run_latch_status
    return run_latch_status()


def _run_uninstall(**kwargs):
    from clawsentry.cli.latch_command import run_latch_uninstall
    return run_latch_uninstall(**kwargs)


# ---------------------------------------------------------------------------
# run_latch_install
# ---------------------------------------------------------------------------


def test_install_already_installed(capsys):
    with mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.is_installed",
        new_callable=mock.PropertyMock,
        return_value=True,
    ), mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.binary_path",
        new_callable=mock.PropertyMock,
        return_value=Path("/fake/latch"),
    ):
        code = _run_install()

    assert code == 0
    assert "already installed" in capsys.readouterr().out


def test_install_success(capsys):
    with mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.is_installed",
        new_callable=mock.PropertyMock,
        return_value=False,
    ), mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.install",
        return_value=Path("/fake/latch"),
    ), mock.patch(
        "clawsentry.latch.desktop.create_desktop_shortcut",
        return_value=Path("/fake/shortcut"),
    ):
        code = _run_install()

    assert code == 0
    assert "installed" in capsys.readouterr().out.lower()


def test_install_unsupported_platform(capsys):
    from clawsentry.latch.binary_manager import UnsupportedPlatformError

    with mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.is_installed",
        new_callable=mock.PropertyMock,
        return_value=False,
    ), mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.install",
        side_effect=UnsupportedPlatformError("unsupported platform"),
    ):
        code = _run_install()

    assert code == 1
    assert "unsupported" in capsys.readouterr().err.lower()


def test_install_checksum_mismatch(capsys):
    from clawsentry.latch.binary_manager import ChecksumMismatchError

    with mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.is_installed",
        new_callable=mock.PropertyMock,
        return_value=False,
    ), mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.install",
        side_effect=ChecksumMismatchError("bad hash"),
    ):
        code = _run_install()

    assert code == 1


def test_install_download_error(capsys):
    with mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.is_installed",
        new_callable=mock.PropertyMock,
        return_value=False,
    ), mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.install",
        side_effect=OSError("network down"),
    ):
        code = _run_install()

    assert code == 1


# ---------------------------------------------------------------------------
# run_latch_install — desktop shortcut integration
# ---------------------------------------------------------------------------


def test_install_creates_shortcut_on_success(capsys):
    """Successful install also creates a desktop shortcut."""
    with mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.is_installed",
        new_callable=mock.PropertyMock,
        return_value=False,
    ), mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.install",
        return_value=Path("/fake/latch"),
    ), mock.patch(
        "clawsentry.latch.desktop.create_desktop_shortcut",
        return_value=Path("/home/user/.local/share/applications/clawsentry.desktop"),
    ) as mock_shortcut:
        code = _run_install()

    assert code == 0
    mock_shortcut.assert_called_once_with(exec_cmd="clawsentry latch start")
    out = capsys.readouterr().out
    assert "desktop shortcut created" in out.lower()


def test_install_shortcut_failure_nonfatal(capsys):
    """Shortcut creation failure is non-fatal — install still succeeds."""
    with mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.is_installed",
        new_callable=mock.PropertyMock,
        return_value=False,
    ), mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.install",
        return_value=Path("/fake/latch"),
    ), mock.patch(
        "clawsentry.latch.desktop.create_desktop_shortcut",
        side_effect=OSError("permission denied"),
    ):
        code = _run_install()

    assert code == 0
    captured = capsys.readouterr()
    assert "installed" in captured.out.lower()
    assert "warning" in captured.err.lower()


def test_install_no_shortcut_flag_skips(capsys):
    """no_shortcut=True skips shortcut creation entirely."""
    with mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.is_installed",
        new_callable=mock.PropertyMock,
        return_value=False,
    ), mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.install",
        return_value=Path("/fake/latch"),
    ), mock.patch(
        "clawsentry.latch.desktop.create_desktop_shortcut",
    ) as mock_shortcut:
        code = _run_install(no_shortcut=True)

    assert code == 0
    mock_shortcut.assert_not_called()
    out = capsys.readouterr().out
    assert "shortcut" not in out.lower()


def test_install_already_installed_no_shortcut_attempted(capsys):
    """Already-installed path returns early — no shortcut creation attempted."""
    with mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.is_installed",
        new_callable=mock.PropertyMock,
        return_value=True,
    ), mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.binary_path",
        new_callable=mock.PropertyMock,
        return_value=Path("/fake/latch"),
    ), mock.patch(
        "clawsentry.latch.desktop.create_desktop_shortcut",
    ) as mock_shortcut:
        code = _run_install()

    assert code == 0
    mock_shortcut.assert_not_called()


def test_main_dispatch_passes_no_shortcut():
    """main.py dispatch passes --no-shortcut to run_latch_install."""
    with mock.patch(
        "clawsentry.cli.latch_command.run_latch_install",
        return_value=0,
    ) as mock_install, mock.patch(
        "clawsentry.cli.dotenv_loader.load_dotenv",
    ):
        from clawsentry.cli.main import main
        try:
            main(["latch", "install", "--no-shortcut"])
        except SystemExit:
            pass

    mock_install.assert_called_once_with(no_shortcut=True)


def test_main_dispatch_no_shortcut_default():
    """main.py dispatch passes no_shortcut=False by default."""
    with mock.patch(
        "clawsentry.cli.latch_command.run_latch_install",
        return_value=0,
    ) as mock_install, mock.patch(
        "clawsentry.cli.dotenv_loader.load_dotenv",
    ):
        from clawsentry.cli.main import main
        try:
            main(["latch", "install"])
        except SystemExit:
            pass

    mock_install.assert_called_once_with(no_shortcut=False)


# ---------------------------------------------------------------------------
# run_latch_start
# ---------------------------------------------------------------------------


def test_start_no_binary(capsys):
    with mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.is_installed",
        new_callable=mock.PropertyMock,
        return_value=False,
    ):
        code = _run_start(no_browser=True)

    assert code == 1
    assert "not found" in capsys.readouterr().err.lower()


def test_start_gateway_already_running(capsys):
    with mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.is_installed",
        new_callable=mock.PropertyMock,
        return_value=True,
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.gateway_status",
        return_value=ServiceStatus.RUNNING,
    ):
        code = _run_start(no_browser=True)

    assert code == 1
    assert "already running" in capsys.readouterr().out.lower()


def test_start_hub_already_running(capsys):
    with mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.is_installed",
        new_callable=mock.PropertyMock,
        return_value=True,
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.gateway_status",
        return_value=ServiceStatus.STOPPED,
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.hub_status",
        return_value=ServiceStatus.RUNNING,
    ):
        code = _run_start(no_browser=True)

    assert code == 1


def test_start_gateway_health_fails(capsys):
    with mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.is_installed",
        new_callable=mock.PropertyMock,
        return_value=True,
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.gateway_status",
        return_value=ServiceStatus.STOPPED,
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.hub_status",
        return_value=ServiceStatus.STOPPED,
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.start_gateway",
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.wait_for_health",
        return_value=False,
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.stop_all",
    ) as mock_stop:
        code = _run_start(no_browser=True)

    assert code == 1
    mock_stop.assert_called()


def test_start_success(capsys):
    with mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.is_installed",
        new_callable=mock.PropertyMock,
        return_value=True,
    ), mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.binary_path",
        new_callable=mock.PropertyMock,
        return_value=Path("/fake/latch"),
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.gateway_status",
        return_value=ServiceStatus.STOPPED,
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.hub_status",
        return_value=ServiceStatus.STOPPED,
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.start_gateway",
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.start_hub",
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.wait_for_health",
        return_value=True,
    ), mock.patch.dict(os.environ, {"CS_AUTH_TOKEN": "test-tok"}):
        code = _run_start(no_browser=True)

    assert code == 0
    out = capsys.readouterr().out
    assert "ready" in out.lower()


def test_start_opens_browser():
    with mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.is_installed",
        new_callable=mock.PropertyMock,
        return_value=True,
    ), mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.binary_path",
        new_callable=mock.PropertyMock,
        return_value=Path("/fake/latch"),
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.gateway_status",
        return_value=ServiceStatus.STOPPED,
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.hub_status",
        return_value=ServiceStatus.STOPPED,
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.start_gateway",
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.start_hub",
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.wait_for_health",
        return_value=True,
    ), mock.patch("clawsentry.cli.latch_command.webbrowser") as mock_wb:
        code = _run_start(no_browser=False)

    assert code == 0
    mock_wb.open.assert_called_once()


def test_start_gateway_start_fails(capsys):
    """Gateway start raises RuntimeError."""
    with mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.is_installed",
        new_callable=mock.PropertyMock,
        return_value=True,
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.gateway_status",
        return_value=ServiceStatus.STOPPED,
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.hub_status",
        return_value=ServiceStatus.STOPPED,
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.start_gateway",
        side_effect=RuntimeError("exited immediately"),
    ):
        code = _run_start(no_browser=True)

    assert code == 1


# ---------------------------------------------------------------------------
# run_latch_stop
# ---------------------------------------------------------------------------


def test_stop(capsys):
    with mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.stop_all",
    ) as mock_stop:
        code = _run_stop()

    assert code == 0
    mock_stop.assert_called_once()
    assert "stopped" in capsys.readouterr().out.lower()


# ---------------------------------------------------------------------------
# run_latch_status
# ---------------------------------------------------------------------------


def test_status_all_stopped(capsys):
    with mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.is_installed",
        new_callable=mock.PropertyMock,
        return_value=False,
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.gateway_status",
        return_value=ServiceStatus.STOPPED,
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.hub_status",
        return_value=ServiceStatus.STOPPED,
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager._read_pid",
        return_value=None,
    ):
        code = _run_status()

    assert code == 0
    out = capsys.readouterr().out
    assert "not installed" in out


def test_status_running(capsys):
    with mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.is_installed",
        new_callable=mock.PropertyMock,
        return_value=True,
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.gateway_status",
        return_value=ServiceStatus.RUNNING,
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.hub_status",
        return_value=ServiceStatus.RUNNING,
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager._read_pid",
        side_effect=[42, 99],
    ):
        code = _run_status()

    assert code == 0
    out = capsys.readouterr().out
    assert "installed" in out
    assert "running" in out


# ---------------------------------------------------------------------------
# run_latch_uninstall
# ---------------------------------------------------------------------------


def test_uninstall_success(capsys, tmp_path):
    """Full uninstall: stop, remove shortcut, uninstall binary, remove data dirs."""
    data_dir = tmp_path / "data"
    run_dir = tmp_path / "run"
    data_dir.mkdir()
    run_dir.mkdir()
    (data_dir / "sessions.db").write_text("fake")

    with mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.stop_all",
    ) as mock_stop, mock.patch(
        "clawsentry.latch.desktop.remove_desktop_shortcut",
        return_value=True,
    ), mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.uninstall",
    ) as mock_uninstall, mock.patch(
        "clawsentry.latch.LATCH_DATA_DIR", data_dir,
    ), mock.patch(
        "clawsentry.latch.LATCH_RUN_DIR", run_dir,
    ):
        code = _run_uninstall()

    assert code == 0
    mock_stop.assert_called_once()
    mock_uninstall.assert_called_once()
    assert not data_dir.exists()
    assert not run_dir.exists()
    out = capsys.readouterr().out
    assert "uninstalled" in out.lower()


def test_uninstall_keep_data(capsys, tmp_path):
    """With keep_data=True, data directories are NOT removed."""
    data_dir = tmp_path / "data"
    run_dir = tmp_path / "run"
    data_dir.mkdir()
    run_dir.mkdir()

    with mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.stop_all",
    ), mock.patch(
        "clawsentry.latch.desktop.remove_desktop_shortcut",
        return_value=False,
    ), mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.uninstall",
    ), mock.patch(
        "clawsentry.latch.LATCH_DATA_DIR", data_dir,
    ), mock.patch(
        "clawsentry.latch.LATCH_RUN_DIR", run_dir,
    ):
        code = _run_uninstall(keep_data=True)

    assert code == 0
    assert data_dir.exists()
    assert run_dir.exists()
    out = capsys.readouterr().out
    assert "kept" in out.lower() or "keep" in out.lower()


def test_uninstall_stop_failure_continues(capsys, tmp_path):
    """Stop failure is non-fatal — uninstall still proceeds."""
    data_dir = tmp_path / "data"
    run_dir = tmp_path / "run"

    with mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.stop_all",
        side_effect=RuntimeError("cannot stop"),
    ), mock.patch(
        "clawsentry.latch.desktop.remove_desktop_shortcut",
        return_value=False,
    ), mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.uninstall",
    ) as mock_uninstall, mock.patch(
        "clawsentry.latch.LATCH_DATA_DIR", data_dir,
    ), mock.patch(
        "clawsentry.latch.LATCH_RUN_DIR", run_dir,
    ):
        code = _run_uninstall()

    assert code == 0
    mock_uninstall.assert_called_once()
    err = capsys.readouterr().err
    assert "warning" in err.lower()


def test_uninstall_shortcut_failure_nonfatal(capsys, tmp_path):
    """Desktop shortcut removal failure is non-fatal."""
    data_dir = tmp_path / "data"
    run_dir = tmp_path / "run"

    with mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.stop_all",
    ), mock.patch(
        "clawsentry.latch.desktop.remove_desktop_shortcut",
        side_effect=OSError("permission denied"),
    ), mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.uninstall",
    ) as mock_uninstall, mock.patch(
        "clawsentry.latch.LATCH_DATA_DIR", data_dir,
    ), mock.patch(
        "clawsentry.latch.LATCH_RUN_DIR", run_dir,
    ):
        code = _run_uninstall()

    assert code == 0
    mock_uninstall.assert_called_once()
    err = capsys.readouterr().err
    assert "warning" in err.lower()


# ---------------------------------------------------------------------------
# start --with-latch integration (run_start with_latch=True)
# ---------------------------------------------------------------------------

_START_COMMON_PATCHES = {
    "ensure_init": "clawsentry.cli.start_command.ensure_init",
    "load_dotenv": "clawsentry.cli.start_command.run_start.__wrapped__"
                   if False else "clawsentry.cli.dotenv_loader.load_dotenv",
    "read_token": "clawsentry.cli.start_command._read_token_from_env",
}


def _run_start_cmd(**kwargs):
    """Call run_start from start_command with sensible defaults."""
    from clawsentry.cli.start_command import run_start
    defaults = dict(
        framework="claude-code",
        host="127.0.0.1",
        port=8080,
        no_watch=True,
        interactive=False,
        open_browser=False,
    )
    defaults.update(kwargs)
    return run_start(**defaults)


def test_start_with_latch_no_binary(capsys):
    """--with-latch with no binary installed prints error and returns."""
    with mock.patch(
        _START_COMMON_PATCHES["ensure_init"], return_value=False,
    ), mock.patch(
        _START_COMMON_PATCHES["load_dotenv"],
    ), mock.patch(
        _START_COMMON_PATCHES["read_token"], return_value="tok",
    ), mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.is_installed",
        new_callable=mock.PropertyMock,
        return_value=False,
    ):
        _run_start_cmd(with_latch=True)

    err = capsys.readouterr().err
    assert "not found" in err.lower()


def test_start_with_latch_success(capsys):
    """--with-latch success: starts gateway + hub via ProcessManager."""
    with mock.patch(
        _START_COMMON_PATCHES["ensure_init"], return_value=False,
    ), mock.patch(
        _START_COMMON_PATCHES["load_dotenv"],
    ), mock.patch(
        _START_COMMON_PATCHES["read_token"], return_value="tok",
    ), mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.is_installed",
        new_callable=mock.PropertyMock,
        return_value=True,
    ), mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.binary_path",
        new_callable=mock.PropertyMock,
        return_value=Path("/fake/latch"),
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.start_gateway",
    ) as mock_gw, mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.start_hub",
    ) as mock_hub, mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.wait_for_health",
        return_value=True,
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.stop_all",
    ) as mock_stop:
        _run_start_cmd(with_latch=True, no_watch=True)

    mock_gw.assert_called_once()
    mock_hub.assert_called_once()
    mock_stop.assert_called()
    out = capsys.readouterr().out
    assert "latch" in out.lower()
    assert "ready" in out.lower()


def test_start_with_latch_gateway_health_fails(capsys):
    """--with-latch gateway health fails → stops all + error."""
    with mock.patch(
        _START_COMMON_PATCHES["ensure_init"], return_value=False,
    ), mock.patch(
        _START_COMMON_PATCHES["load_dotenv"],
    ), mock.patch(
        _START_COMMON_PATCHES["read_token"], return_value="tok",
    ), mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.is_installed",
        new_callable=mock.PropertyMock,
        return_value=True,
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.start_gateway",
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.wait_for_health",
        return_value=False,
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.stop_all",
    ) as mock_stop:
        _run_start_cmd(with_latch=True)

    mock_stop.assert_called()
    err = capsys.readouterr().err
    assert "gateway failed" in err.lower()


def test_start_with_latch_hub_health_fails(capsys):
    """--with-latch hub health fails → stops all + error."""
    health_results = iter([True, False])  # gateway OK, hub FAIL

    with mock.patch(
        _START_COMMON_PATCHES["ensure_init"], return_value=False,
    ), mock.patch(
        _START_COMMON_PATCHES["load_dotenv"],
    ), mock.patch(
        _START_COMMON_PATCHES["read_token"], return_value="tok",
    ), mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.is_installed",
        new_callable=mock.PropertyMock,
        return_value=True,
    ), mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.binary_path",
        new_callable=mock.PropertyMock,
        return_value=Path("/fake/latch"),
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.start_gateway",
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.start_hub",
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.wait_for_health",
        side_effect=lambda *a, **kw: next(health_results),
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.stop_all",
    ) as mock_stop:
        _run_start_cmd(with_latch=True)

    mock_stop.assert_called()
    err = capsys.readouterr().err
    assert "hub failed" in err.lower()


def test_start_with_latch_no_watch(capsys):
    """--with-latch + no_watch → returns without running watch loop."""
    with mock.patch(
        _START_COMMON_PATCHES["ensure_init"], return_value=False,
    ), mock.patch(
        _START_COMMON_PATCHES["load_dotenv"],
    ), mock.patch(
        _START_COMMON_PATCHES["read_token"], return_value="tok",
    ), mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.is_installed",
        new_callable=mock.PropertyMock,
        return_value=True,
    ), mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.binary_path",
        new_callable=mock.PropertyMock,
        return_value=Path("/fake/latch"),
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.start_gateway",
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.start_hub",
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.wait_for_health",
        return_value=True,
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.stop_all",
    ), mock.patch(
        "clawsentry.cli.start_command.run_watch_loop",
    ) as mock_watch:
        _run_start_cmd(with_latch=True, no_watch=True)

    mock_watch.assert_not_called()


def test_start_with_latch_keyboard_interrupt(capsys):
    """--with-latch keyboard interrupt → clean shutdown via stop_all."""
    with mock.patch(
        _START_COMMON_PATCHES["ensure_init"], return_value=False,
    ), mock.patch(
        _START_COMMON_PATCHES["load_dotenv"],
    ), mock.patch(
        _START_COMMON_PATCHES["read_token"], return_value="tok",
    ), mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.is_installed",
        new_callable=mock.PropertyMock,
        return_value=True,
    ), mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.binary_path",
        new_callable=mock.PropertyMock,
        return_value=Path("/fake/latch"),
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.start_gateway",
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.start_hub",
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.wait_for_health",
        return_value=True,
    ), mock.patch(
        "clawsentry.latch.process_manager.ProcessManager.stop_all",
    ) as mock_stop, mock.patch(
        "clawsentry.cli.start_command.run_watch_loop",
        side_effect=KeyboardInterrupt,
    ):
        _run_start_cmd(with_latch=True, no_watch=False)

    mock_stop.assert_called()
    out = capsys.readouterr().out
    assert "shutting down" in out.lower()


def test_start_without_latch_uses_launch_gateway(capsys):
    """Default (no --with-latch) → uses existing launch_gateway() path."""
    fake_proc = mock.MagicMock()
    fake_proc.pid = 12345
    fake_proc.poll.return_value = None

    with mock.patch(
        _START_COMMON_PATCHES["ensure_init"], return_value=False,
    ), mock.patch(
        _START_COMMON_PATCHES["load_dotenv"],
    ), mock.patch(
        _START_COMMON_PATCHES["read_token"], return_value="tok",
    ), mock.patch(
        "clawsentry.cli.start_command.launch_gateway",
        return_value=fake_proc,
    ) as mock_lg, mock.patch(
        "clawsentry.cli.start_command.wait_for_health",
        return_value=True,
    ), mock.patch(
        "clawsentry.cli.start_command.shutdown_gateway",
    ):
        _run_start_cmd(with_latch=False, no_watch=True)

    mock_lg.assert_called_once()
    out = capsys.readouterr().out
    # Should NOT mention "Latch mode"
    assert "latch mode" not in out.lower()


def test_main_dispatch_passes_with_latch_and_hub_port():
    """main.py dispatch passes with_latch + hub_port to run_start."""
    with mock.patch(
        "clawsentry.cli.start_command.run_start",
    ) as mock_run, mock.patch(
        "clawsentry.cli.start_command.detect_framework",
        return_value="claude-code",
    ), mock.patch(
        "clawsentry.cli.dotenv_loader.load_dotenv",
    ):
        from clawsentry.cli.main import main
        main(["start", "--with-latch", "--hub-port", "4000"])

    mock_run.assert_called_once()
    call_kwargs = mock_run.call_args[1]
    assert call_kwargs["with_latch"] is True
    assert call_kwargs["hub_port"] == 4000
