"""Latch integration package — binary management + process lifecycle."""

from __future__ import annotations

import os
from pathlib import Path

LATCH_VERSION = "0.16.1"

LATCH_HOME = Path(os.environ.get("CLAWSENTRY_HOME", Path.home() / ".clawsentry"))
LATCH_BIN_DIR = LATCH_HOME / "bin"
LATCH_RUN_DIR = LATCH_HOME / "run"
LATCH_DATA_DIR = LATCH_HOME / "data"

LATCH_ASSETS_DIR = Path(__file__).parent / "assets"

GITHUB_RELEASE_BASE = (
    "https://github.com/Zhongan-Wang/latch/releases/download"
)
