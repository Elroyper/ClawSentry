"""Tests for latch.desktop — desktop shortcut creation."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from unittest import mock

import pytest

from clawsentry.latch.binary_manager import UnsupportedPlatformError
from clawsentry.latch.desktop import (
    _build_linux_desktop_entry,
    _build_macos_app_bundle,
    _build_macos_launcher_script,
    create_desktop_shortcut,
    get_shortcut_path,
    remove_desktop_shortcut,
)


# ---------------------------------------------------------------------------
# get_shortcut_path
# ---------------------------------------------------------------------------


def test_get_shortcut_path_linux():
    with mock.patch("clawsentry.latch.desktop.platform.system", return_value="Linux"):
        path = get_shortcut_path()
    assert path == Path.home() / ".local" / "share" / "applications" / "clawsentry.desktop"


def test_get_shortcut_path_macos():
    with mock.patch("clawsentry.latch.desktop.platform.system", return_value="Darwin"):
        path = get_shortcut_path()
    assert path == Path.home() / "Applications" / "ClawSentry.app"


def test_get_shortcut_path_windows_raises():
    with mock.patch("clawsentry.latch.desktop.platform.system", return_value="Windows"):
        with pytest.raises(UnsupportedPlatformError, match="not supported"):
            get_shortcut_path()


# ---------------------------------------------------------------------------
# _build_linux_desktop_entry
# ---------------------------------------------------------------------------


def test_build_linux_desktop_entry_content():
    entry = _build_linux_desktop_entry("clawsentry stack", "/usr/share/icons/cs.png")
    assert "[Desktop Entry]" in entry
    assert "Name=ClawSentry" in entry
    assert "Exec=clawsentry stack" in entry
    assert "Icon=/usr/share/icons/cs.png" in entry
    assert "Categories=Development;Security;" in entry
    assert "Type=Application" in entry
    assert "Terminal=false" in entry


# ---------------------------------------------------------------------------
# _build_macos_launcher_script
# ---------------------------------------------------------------------------


def test_build_macos_launcher_script():
    script = _build_macos_launcher_script("clawsentry stack --open-browser")
    assert script.startswith("#!/bin/bash\n")
    assert "exec clawsentry stack --open-browser" in script


# ---------------------------------------------------------------------------
# _build_macos_app_bundle
# ---------------------------------------------------------------------------


def test_build_macos_app_bundle_creates_structure(tmp_path: Path):
    """Bundle contains Info.plist, launcher, and copied icon."""
    icon = tmp_path / "custom_icon.png"
    icon.write_bytes(b"\x89PNG fake icon data")
    app_path = tmp_path / "ClawSentry.app"

    _build_macos_app_bundle("clawsentry stack", icon, app_path)

    # Directory structure
    assert (app_path / "Contents" / "Info.plist").is_file()
    assert (app_path / "Contents" / "MacOS" / "launcher").is_file()
    assert (app_path / "Contents" / "Resources" / "icon.png").is_file()

    # Info.plist content
    plist = (app_path / "Contents" / "Info.plist").read_text()
    assert "ClawSentry" in plist
    assert "com.clawsentry.app" in plist
    assert "<string>launcher</string>" in plist

    # Launcher is executable
    launcher = app_path / "Contents" / "MacOS" / "launcher"
    assert launcher.stat().st_mode & stat.S_IXUSR

    # Icon was copied
    copied = (app_path / "Contents" / "Resources" / "icon.png").read_bytes()
    assert copied == b"\x89PNG fake icon data"


def test_build_macos_app_bundle_missing_icon_skips_copy(tmp_path: Path):
    """When icon_path does not exist, Resources/icon.png is not created."""
    app_path = tmp_path / "ClawSentry.app"
    _build_macos_app_bundle("clawsentry stack", "/nonexistent/icon.png", app_path)

    assert (app_path / "Contents" / "Info.plist").is_file()
    assert (app_path / "Contents" / "MacOS" / "launcher").is_file()
    assert not (app_path / "Contents" / "Resources" / "icon.png").exists()


# ---------------------------------------------------------------------------
# create_desktop_shortcut — Linux
# ---------------------------------------------------------------------------


def test_create_shortcut_linux(tmp_path: Path):
    """On Linux, creates a valid .desktop file."""
    desktop_file = tmp_path / "applications" / "clawsentry.desktop"

    with mock.patch("clawsentry.latch.desktop.platform.system", return_value="Linux"), \
         mock.patch("clawsentry.latch.desktop.get_shortcut_path", return_value=desktop_file):
        result = create_desktop_shortcut(
            exec_cmd="clawsentry stack",
            icon_path="/tmp/icon.png",
        )

    assert result == desktop_file
    assert desktop_file.is_file()
    content = desktop_file.read_text()
    assert "Exec=clawsentry stack" in content
    assert "Icon=/tmp/icon.png" in content


def test_create_shortcut_linux_default_icon(tmp_path: Path):
    """When icon_path is None, the built-in icon path is used."""
    desktop_file = tmp_path / "applications" / "clawsentry.desktop"

    with mock.patch("clawsentry.latch.desktop.platform.system", return_value="Linux"), \
         mock.patch("clawsentry.latch.desktop.get_shortcut_path", return_value=desktop_file):
        create_desktop_shortcut(exec_cmd="clawsentry stack")

    content = desktop_file.read_text()
    assert "icon-512.png" in content


# ---------------------------------------------------------------------------
# create_desktop_shortcut — macOS
# ---------------------------------------------------------------------------


def test_create_shortcut_macos(tmp_path: Path):
    """On macOS, creates an .app bundle."""
    app_path = tmp_path / "ClawSentry.app"
    icon = tmp_path / "myicon.png"
    icon.write_bytes(b"png bytes")

    with mock.patch("clawsentry.latch.desktop.platform.system", return_value="Darwin"), \
         mock.patch("clawsentry.latch.desktop.get_shortcut_path", return_value=app_path):
        result = create_desktop_shortcut(exec_cmd="clawsentry stack", icon_path=icon)

    assert result == app_path
    assert (app_path / "Contents" / "Info.plist").is_file()
    assert (app_path / "Contents" / "MacOS" / "launcher").is_file()
    assert (app_path / "Contents" / "Resources" / "icon.png").is_file()


# ---------------------------------------------------------------------------
# create_desktop_shortcut — Windows (unsupported)
# ---------------------------------------------------------------------------


def test_create_shortcut_windows_raises():
    with mock.patch("clawsentry.latch.desktop.platform.system", return_value="Windows"):
        with pytest.raises(UnsupportedPlatformError, match="not supported"):
            create_desktop_shortcut(exec_cmd="clawsentry stack")


# ---------------------------------------------------------------------------
# remove_desktop_shortcut
# ---------------------------------------------------------------------------


def test_remove_shortcut_linux_file(tmp_path: Path):
    """Removing a .desktop file returns True and deletes the file."""
    desktop_file = tmp_path / "clawsentry.desktop"
    desktop_file.write_text("[Desktop Entry]\n")

    with mock.patch("clawsentry.latch.desktop.get_shortcut_path", return_value=desktop_file):
        assert remove_desktop_shortcut() is True
    assert not desktop_file.exists()


def test_remove_shortcut_macos_dir(tmp_path: Path):
    """Removing a .app bundle directory returns True."""
    app_dir = tmp_path / "ClawSentry.app"
    (app_dir / "Contents" / "MacOS").mkdir(parents=True)
    (app_dir / "Contents" / "MacOS" / "launcher").write_text("#!/bin/bash\n")

    with mock.patch("clawsentry.latch.desktop.get_shortcut_path", return_value=app_dir):
        assert remove_desktop_shortcut() is True
    assert not app_dir.exists()


def test_remove_shortcut_nothing_to_remove(tmp_path: Path):
    """Returns False when the shortcut does not exist."""
    desktop_file = tmp_path / "clawsentry.desktop"

    with mock.patch("clawsentry.latch.desktop.get_shortcut_path", return_value=desktop_file):
        assert remove_desktop_shortcut() is False


def test_remove_shortcut_unsupported_platform():
    """Returns False on unsupported platforms (no crash)."""
    with mock.patch(
        "clawsentry.latch.desktop.get_shortcut_path",
        side_effect=UnsupportedPlatformError("nope"),
    ):
        assert remove_desktop_shortcut() is False
