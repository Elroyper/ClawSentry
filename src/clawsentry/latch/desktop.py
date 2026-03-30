"""Desktop shortcut creation for ClawSentry (Linux + macOS)."""

from __future__ import annotations

import os
import platform
import shutil
import textwrap
from pathlib import Path

from .binary_manager import UnsupportedPlatformError

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ASSETS_DIR = Path(__file__).parent / "assets"
_DEFAULT_ICON = _ASSETS_DIR / "icon-512.png"

_APP_NAME = "ClawSentry"


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def get_shortcut_path() -> Path:
    """Return the platform-specific shortcut path.

    * **Linux**: ``~/.local/share/applications/clawsentry.desktop``
    * **macOS**: ``~/Applications/ClawSentry.app``
    * **Windows**: raises :class:`UnsupportedPlatformError`
    """
    system = platform.system()
    if system == "Linux":
        return Path.home() / ".local" / "share" / "applications" / "clawsentry.desktop"
    if system == "Darwin":
        return Path.home() / "Applications" / "ClawSentry.app"
    raise UnsupportedPlatformError(
        f"Desktop shortcuts are not supported on {system}"
    )


def create_desktop_shortcut(
    *,
    exec_cmd: str,
    icon_path: Path | str | None = None,
) -> Path:
    """Create a desktop shortcut and return its path.

    Parameters
    ----------
    exec_cmd:
        The command to execute when the shortcut is launched.
    icon_path:
        Optional path to a custom icon.  Falls back to the built-in
        ``icon-512.png`` shipped with the package.
    """
    icon = Path(icon_path) if icon_path is not None else _DEFAULT_ICON
    shortcut = get_shortcut_path()  # may raise UnsupportedPlatformError

    system = platform.system()
    if system == "Linux":
        shortcut.parent.mkdir(parents=True, exist_ok=True)
        shortcut.write_text(_build_linux_desktop_entry(exec_cmd, icon))
        return shortcut

    if system == "Darwin":
        _build_macos_app_bundle(exec_cmd, icon, shortcut)
        return shortcut

    # get_shortcut_path already raises for unsupported platforms, but
    # guard here as well for safety.
    raise UnsupportedPlatformError(  # pragma: no cover
        f"Desktop shortcuts are not supported on {system}"
    )


def remove_desktop_shortcut() -> bool:
    """Remove the desktop shortcut.  Returns ``True`` if something was removed."""
    try:
        shortcut = get_shortcut_path()
    except UnsupportedPlatformError:
        return False

    if not shortcut.exists():
        return False

    if shortcut.is_dir():
        shutil.rmtree(shortcut)
    else:
        shortcut.unlink()
    return True


# ---------------------------------------------------------------------------
# Linux helpers
# ---------------------------------------------------------------------------


def _build_linux_desktop_entry(exec_cmd: str | Path, icon_path: str | Path) -> str:
    """Return a freedesktop ``.desktop`` file body."""
    return textwrap.dedent(f"""\
        [Desktop Entry]
        Type=Application
        Name={_APP_NAME}
        Comment=AHP security monitor for AI coding agents
        Exec={exec_cmd}
        Icon={icon_path}
        Terminal=false
        Categories=Development;Security;
    """)


# ---------------------------------------------------------------------------
# macOS helpers
# ---------------------------------------------------------------------------


def _build_macos_launcher_script(exec_cmd: str) -> str:
    """Return the shell launcher script placed inside the ``.app`` bundle."""
    return textwrap.dedent(f"""\
        #!/bin/bash
        exec {exec_cmd}
    """)


def _build_macos_app_bundle(
    exec_cmd: str,
    icon_path: str | Path,
    app_path: Path,
) -> None:
    """Create a minimal macOS ``.app`` bundle at *app_path*.

    Structure::

        ClawSentry.app/
            Contents/
                Info.plist
                MacOS/
                    launcher   (executable shell script)
                Resources/
                    icon.png   (copy of icon_path)
    """
    contents = app_path / "Contents"
    macos_dir = contents / "MacOS"
    resources = contents / "Resources"

    macos_dir.mkdir(parents=True, exist_ok=True)
    resources.mkdir(parents=True, exist_ok=True)

    # Info.plist
    info_plist = textwrap.dedent(f"""\
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
          "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>CFBundleName</key>
            <string>{_APP_NAME}</string>
            <key>CFBundleDisplayName</key>
            <string>{_APP_NAME}</string>
            <key>CFBundleIdentifier</key>
            <string>com.clawsentry.app</string>
            <key>CFBundleExecutable</key>
            <string>launcher</string>
            <key>CFBundleIconFile</key>
            <string>icon.png</string>
            <key>CFBundlePackageType</key>
            <string>APPL</string>
        </dict>
        </plist>
    """)
    (contents / "Info.plist").write_text(info_plist)

    # Launcher script
    launcher = macos_dir / "launcher"
    launcher.write_text(_build_macos_launcher_script(exec_cmd))
    launcher.chmod(launcher.stat().st_mode | 0o755)

    # Icon
    icon_src = Path(icon_path)
    if icon_src.is_file():
        shutil.copy2(icon_src, resources / "icon.png")
