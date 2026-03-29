"""Project-level .clawsentry.toml configuration loader."""

from __future__ import annotations

import logging
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .detection_config import DetectionConfig, from_preset

logger = logging.getLogger(__name__)

CONFIG_FILENAME = ".clawsentry.toml"


@dataclass(frozen=True)
class ProjectConfig:
    """Parsed project configuration from .clawsentry.toml."""

    enabled: bool = True
    preset: str = "medium"
    overrides: dict[str, Any] = field(default_factory=dict)

    def to_detection_config(self) -> DetectionConfig:
        """Build DetectionConfig from preset + overrides."""
        return from_preset(self.preset, **self.overrides)


def load_project_config(project_dir: Path) -> ProjectConfig:
    """Load .clawsentry.toml from project directory.

    Returns defaults if file is missing or invalid (fail-open).
    """
    config_path = project_dir / CONFIG_FILENAME
    if not config_path.is_file():
        return ProjectConfig()

    try:
        with open(config_path, "rb") as f:
            data = tomllib.load(f)
    except Exception as exc:
        logger.warning("Failed to parse %s: %s — using defaults", config_path, exc)
        return ProjectConfig()

    project = data.get("project", {})
    overrides = data.get("overrides", {})

    return ProjectConfig(
        enabled=bool(project.get("enabled", True)),
        preset=str(project.get("preset", "medium")),
        overrides=dict(overrides),
    )
