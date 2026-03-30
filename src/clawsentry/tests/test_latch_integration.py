"""Integration tests for Latch package — full-flow + main.py dispatch."""

from __future__ import annotations

import hashlib
import os
import tarfile
from pathlib import Path
from unittest import mock

import pytest

from clawsentry.latch.binary_manager import BinaryManager
from clawsentry.latch.process_manager import ProcessManager, ServiceStatus


# ---------------------------------------------------------------------------
# Full install → status → uninstall flow (mocked HTTP)
# ---------------------------------------------------------------------------


def test_full_install_status_uninstall(tmp_path: Path):
    """Full lifecycle: install → verify is_installed → uninstall → verify gone."""
    install_dir = tmp_path / "bin"
    mgr = BinaryManager(install_dir=install_dir)

    # 1. Not installed yet
    assert mgr.is_installed is False

    # 2. Prepare fake archive
    archive_build = tmp_path / "build"
    archive_build.mkdir()
    fake_binary = archive_build / "latch"
    fake_binary.write_text("#!/bin/sh\necho latch v0.16.1")
    archive_path = tmp_path / "archive.tar.gz"
    with tarfile.open(archive_path, "w:gz") as tf:
        tf.add(fake_binary, arcname="latch")

    archive_bytes = archive_path.read_bytes()
    archive_hash = hashlib.sha256(archive_bytes).hexdigest()
    checksums = f"{archive_hash}  latch-v0.16.1-linux-x64.tar.gz\n"

    def fake_download(url: str, dest: Path) -> None:
        if "checksums.txt" in url:
            dest.write_text(checksums)
        else:
            dest.write_bytes(archive_bytes)

    with mock.patch("platform.system", return_value="Linux"), \
         mock.patch("platform.machine", return_value="x86_64"), \
         mock.patch("clawsentry.latch.binary_manager._download", side_effect=fake_download):
        result = mgr.install()

    # 3. Installed
    assert mgr.is_installed is True
    assert result.is_file()

    # 4. Uninstall
    mgr.uninstall()
    assert mgr.is_installed is False
    assert not install_dir.exists()


# ---------------------------------------------------------------------------
# ProcessManager status lifecycle
# ---------------------------------------------------------------------------


def test_process_manager_lifecycle(tmp_path: Path):
    """Status transitions: stopped → write PID → running → stale → stopped."""
    pm = ProcessManager(run_dir=tmp_path)

    # Initially stopped
    assert pm.gateway_status() == ServiceStatus.STOPPED
    assert pm.hub_status() == ServiceStatus.STOPPED

    # Write our own PID (it's alive)
    pm._write_pid(pm.gateway_pid_file, os.getpid())
    assert pm.gateway_status() == ServiceStatus.RUNNING

    # Write a stale PID
    pm._write_pid(pm.hub_pid_file, 99999999)
    assert pm.hub_status() == ServiceStatus.STALE
    # Stale PID should auto-clean
    assert not pm.hub_pid_file.exists()

    # Clean up gateway PID manually (don't call stop_all with our own PID)
    pm._remove_pid(pm.gateway_pid_file)
    assert pm.gateway_status() == ServiceStatus.STOPPED


# ---------------------------------------------------------------------------
# main.py dispatch
# ---------------------------------------------------------------------------


def test_main_latch_install_dispatch():
    """clawsentry latch install dispatches to run_latch_install."""
    from clawsentry.cli.main import main

    with mock.patch(
        "clawsentry.cli.latch_command.run_latch_install", return_value=0,
    ) as mock_fn, pytest.raises(SystemExit) as exc_info:
        main(["latch", "install"])

    mock_fn.assert_called_once()
    assert exc_info.value.code == 0


def test_main_latch_start_dispatch():
    """clawsentry latch start dispatches to run_latch_start."""
    from clawsentry.cli.main import main

    with mock.patch(
        "clawsentry.cli.latch_command.run_latch_start", return_value=0,
    ) as mock_fn, pytest.raises(SystemExit) as exc_info:
        main(["latch", "start", "--no-browser"])

    mock_fn.assert_called_once_with(
        gateway_port=mock.ANY,
        hub_port=3006,
        no_browser=True,
    )
    assert exc_info.value.code == 0


def test_main_latch_stop_dispatch():
    from clawsentry.cli.main import main

    with mock.patch(
        "clawsentry.cli.latch_command.run_latch_stop", return_value=0,
    ) as mock_fn, pytest.raises(SystemExit) as exc_info:
        main(["latch", "stop"])

    mock_fn.assert_called_once()
    assert exc_info.value.code == 0


def test_main_latch_status_dispatch():
    from clawsentry.cli.main import main

    with mock.patch(
        "clawsentry.cli.latch_command.run_latch_status", return_value=0,
    ) as mock_fn, pytest.raises(SystemExit) as exc_info:
        main(["latch", "status"])

    mock_fn.assert_called_once()
    assert exc_info.value.code == 0


def test_main_latch_uninstall_dispatch():
    """clawsentry latch uninstall dispatches to run_latch_uninstall."""
    from clawsentry.cli.main import main

    with mock.patch(
        "clawsentry.cli.latch_command.run_latch_uninstall", return_value=0,
    ) as mock_fn, pytest.raises(SystemExit) as exc_info:
        main(["latch", "uninstall"])

    mock_fn.assert_called_once_with(keep_data=False)
    assert exc_info.value.code == 0


def test_main_latch_uninstall_keep_data():
    """clawsentry latch uninstall --keep-data passes keep_data=True."""
    from clawsentry.cli.main import main

    with mock.patch(
        "clawsentry.cli.latch_command.run_latch_uninstall", return_value=0,
    ) as mock_fn, pytest.raises(SystemExit) as exc_info:
        main(["latch", "uninstall", "--keep-data"])

    mock_fn.assert_called_once_with(keep_data=True)
    assert exc_info.value.code == 0


def test_main_latch_no_subcommand(capsys):
    """clawsentry latch with no subcommand prints usage."""
    from clawsentry.cli.main import main

    main(["latch"])
    out = capsys.readouterr().out
    assert "usage" in out.lower() or "install" in out.lower()


def test_main_latch_start_custom_ports():
    """clawsentry latch start --gateway-port 9090 --hub-port 4000."""
    from clawsentry.cli.main import main

    with mock.patch(
        "clawsentry.cli.latch_command.run_latch_start", return_value=0,
    ) as mock_fn, pytest.raises(SystemExit):
        main(["latch", "start", "--gateway-port", "9090", "--hub-port", "4000", "--no-browser"])

    mock_fn.assert_called_once_with(
        gateway_port=9090,
        hub_port=4000,
        no_browser=True,
    )


# ---------------------------------------------------------------------------
# Doctor includes Latch checks end-to-end
# ---------------------------------------------------------------------------


def test_doctor_runs_latch_checks():
    """run_all_checks() includes Latch check IDs."""
    from clawsentry.cli.doctor_command import run_all_checks

    with mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.is_installed",
        new_callable=mock.PropertyMock,
        return_value=False,
    ), mock.patch(
        "urllib.request.urlopen",
        side_effect=OSError("not running"),
    ):
        results = run_all_checks()

    ids = {r.check_id for r in results}
    assert "LATCH_BINARY" in ids
    assert "LATCH_HUB_HEALTH" in ids
    assert "LATCH_TOKEN_SYNC" in ids


# ---------------------------------------------------------------------------
# CLI install → status end-to-end (mocked)
# ---------------------------------------------------------------------------


def test_cli_install_then_status(capsys):
    """Install then status shows 'installed'."""
    from clawsentry.cli.latch_command import run_latch_install, run_latch_status

    # Mock install
    with mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.is_installed",
        new_callable=mock.PropertyMock,
        return_value=False,
    ), mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.install",
        return_value=Path("/fake/latch"),
    ):
        code = run_latch_install()
    assert code == 0

    # Mock status
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
        "clawsentry.latch.process_manager.ProcessManager._read_pid",
        return_value=None,
    ):
        code = run_latch_status()
    assert code == 0

    out = capsys.readouterr().out
    assert "installed" in out.lower()


def test_cli_install_then_uninstall(capsys, tmp_path):
    """Full flow: install → uninstall → verify data cleaned."""
    from clawsentry.cli.latch_command import run_latch_install, run_latch_uninstall

    data_dir = tmp_path / "data"
    run_dir = tmp_path / "run"
    data_dir.mkdir()
    run_dir.mkdir()
    (data_dir / "sessions.db").write_text("fake")

    # 1. Install
    with mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.is_installed",
        new_callable=mock.PropertyMock,
        return_value=False,
    ), mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.install",
        return_value=Path("/fake/latch"),
    ):
        code = run_latch_install()
    assert code == 0

    # 2. Uninstall
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
        code = run_latch_uninstall()
    assert code == 0

    # 3. Verify data cleaned
    assert not data_dir.exists()
    assert not run_dir.exists()
    out = capsys.readouterr().out
    assert "uninstalled" in out.lower()
