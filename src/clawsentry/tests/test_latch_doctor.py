"""Tests for Latch-related doctor checks."""

from __future__ import annotations

import os
import urllib.error
from pathlib import Path
from unittest import mock

import pytest

from clawsentry.cli.doctor_command import (
    ALL_CHECKS,
    check_latch_binary,
    check_latch_hub_health,
    check_latch_token_sync,
    run_all_checks,
)


# ---------------------------------------------------------------------------
# check_latch_binary
# ---------------------------------------------------------------------------


def test_latch_binary_not_installed():
    with mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.is_installed",
        new_callable=mock.PropertyMock,
        return_value=False,
    ):
        result = check_latch_binary()

    assert result.check_id == "LATCH_BINARY"
    assert result.status == "WARN"
    assert "not installed" in result.message.lower()


def test_latch_binary_installed_and_executable(tmp_path: Path):
    fake_binary = tmp_path / "latch"
    fake_binary.write_text("#!/bin/sh\necho ok")
    fake_binary.chmod(0o755)

    with mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.is_installed",
        new_callable=mock.PropertyMock,
        return_value=True,
    ), mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.binary_path",
        new_callable=mock.PropertyMock,
        return_value=fake_binary,
    ):
        result = check_latch_binary()

    assert result.status == "PASS"


def test_latch_binary_not_executable(tmp_path: Path):
    fake_binary = tmp_path / "latch"
    fake_binary.write_text("#!/bin/sh\necho ok")
    fake_binary.chmod(0o644)  # not executable

    with mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.is_installed",
        new_callable=mock.PropertyMock,
        return_value=True,
    ), mock.patch(
        "clawsentry.latch.binary_manager.BinaryManager.binary_path",
        new_callable=mock.PropertyMock,
        return_value=fake_binary,
    ):
        result = check_latch_binary()

    assert result.status == "WARN"
    assert "not executable" in result.message.lower()


# ---------------------------------------------------------------------------
# check_latch_hub_health
# ---------------------------------------------------------------------------


def test_hub_health_responding():
    mock_resp = mock.MagicMock()
    mock_resp.status = 200
    mock_resp.__enter__ = mock.MagicMock(return_value=mock_resp)
    mock_resp.__exit__ = mock.MagicMock(return_value=False)

    with mock.patch("urllib.request.urlopen", return_value=mock_resp):
        result = check_latch_hub_health()

    assert result.check_id == "LATCH_HUB_HEALTH"
    assert result.status == "PASS"


def test_hub_health_not_responding():
    with mock.patch(
        "urllib.request.urlopen",
        side_effect=OSError("Connection refused"),
    ):
        result = check_latch_hub_health()

    assert result.status == "WARN"
    assert "not responding" in result.message.lower()


# ---------------------------------------------------------------------------
# check_latch_token_sync
# ---------------------------------------------------------------------------


def test_token_sync_both_unset():
    with mock.patch.dict(os.environ, {}, clear=True):
        result = check_latch_token_sync()
    assert result.check_id == "LATCH_TOKEN_SYNC"
    assert result.status == "PASS"


def test_token_sync_match():
    with mock.patch.dict(os.environ, {
        "CS_AUTH_TOKEN": "abc123",
        "CLI_API_TOKEN": "abc123",
    }):
        result = check_latch_token_sync()
    assert result.status == "PASS"
    assert "match" in result.message.lower()


def test_token_sync_mismatch():
    with mock.patch.dict(os.environ, {
        "CS_AUTH_TOKEN": "token-a",
        "CLI_API_TOKEN": "token-b",
    }):
        result = check_latch_token_sync()
    assert result.status == "WARN"
    assert "differ" in result.message.lower()


def test_token_sync_cli_not_set():
    with mock.patch.dict(os.environ, {
        "CS_AUTH_TOKEN": "abc123",
    }, clear=True):
        os.environ.pop("CLI_API_TOKEN", None)
        result = check_latch_token_sync()
    assert result.status == "PASS"


# ---------------------------------------------------------------------------
# ALL_CHECKS includes Latch checks
# ---------------------------------------------------------------------------


def test_all_checks_count():
    """ALL_CHECKS should contain 20 checks (14 original + Codex native hooks + 3 latch + 2 bridge)."""
    assert len(ALL_CHECKS) == 20


def test_all_checks_includes_latch():
    check_names = [fn.__name__ for fn in ALL_CHECKS]
    assert "check_latch_binary" in check_names
    assert "check_latch_hub_health" in check_names
    assert "check_latch_token_sync" in check_names
