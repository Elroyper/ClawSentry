"""Tests for latch package constants and structure."""

from __future__ import annotations

import os
from pathlib import Path
from unittest import mock


def test_default_paths():
    """LATCH_HOME defaults to ~/.clawsentry when CLAWSENTRY_HOME unset."""
    with mock.patch.dict(os.environ, {}, clear=True):
        # Re-import to pick up fresh env
        import importlib
        import clawsentry.latch as latch_mod
        importlib.reload(latch_mod)

        assert latch_mod.LATCH_HOME == Path.home() / ".clawsentry"
        assert latch_mod.LATCH_BIN_DIR == latch_mod.LATCH_HOME / "bin"
        assert latch_mod.LATCH_RUN_DIR == latch_mod.LATCH_HOME / "run"
        assert latch_mod.LATCH_DATA_DIR == latch_mod.LATCH_HOME / "data"


def test_custom_clawsentry_home(tmp_path: Path):
    """CLAWSENTRY_HOME env overrides LATCH_HOME."""
    with mock.patch.dict(os.environ, {"CLAWSENTRY_HOME": str(tmp_path)}):
        import importlib
        import clawsentry.latch as latch_mod
        importlib.reload(latch_mod)

        assert latch_mod.LATCH_HOME == tmp_path
        assert latch_mod.LATCH_BIN_DIR == tmp_path / "bin"


def test_latch_version():
    from clawsentry.latch import LATCH_VERSION
    assert LATCH_VERSION == "0.16.1"


def test_github_release_base():
    from clawsentry.latch import GITHUB_RELEASE_BASE
    assert "github.com" in GITHUB_RELEASE_BASE
    assert "Zhongan-Wang/latch" in GITHUB_RELEASE_BASE


def test_assets_exist():
    """Icon assets are included in the package."""
    assets_dir = Path(__file__).resolve().parent.parent / "latch" / "assets"
    assert (assets_dir / "icon-512.png").is_file()
    assert (assets_dir / "icon.ico").is_file()


def test_latch_assets_dir_constant():
    """LATCH_ASSETS_DIR points to the assets directory."""
    from clawsentry.latch import LATCH_ASSETS_DIR
    assert LATCH_ASSETS_DIR.name == "assets"
    assert LATCH_ASSETS_DIR.is_dir()


def test_latch_assets_dir_contains_icon():
    """LATCH_ASSETS_DIR contains the icon file."""
    from clawsentry.latch import LATCH_ASSETS_DIR
    assert (LATCH_ASSETS_DIR / "icon-512.png").is_file()
