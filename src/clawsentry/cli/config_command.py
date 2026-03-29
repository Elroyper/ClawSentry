"""``clawsentry config`` — manage project-level .clawsentry.toml."""

from __future__ import annotations

from pathlib import Path

from clawsentry.gateway.detection_config import PRESETS
from clawsentry.gateway.project_config import CONFIG_FILENAME, load_project_config


def _write_toml(path: Path, *, enabled: bool = True, preset: str = "medium") -> None:
    """Write a .clawsentry.toml file."""
    lines = [
        "# ClawSentry project configuration",
        "# Docs: https://clawsentry.dev/config/project/",
        "",
        "[project]",
        f"enabled = {'true' if enabled else 'false'}",
        f'preset = "{preset}"',
        "",
        "# [overrides]",
        "# threshold_critical = 2.2",
        "# d6_injection_multiplier = 0.5",
        "",
    ]
    path.write_text("\n".join(lines))


def run_config_init(
    *,
    target_dir: Path,
    preset: str = "medium",
    force: bool = False,
) -> None:
    toml_path = target_dir / CONFIG_FILENAME
    if toml_path.exists() and not force:
        raise FileExistsError(f"{toml_path} already exists. Use --force to overwrite.")
    _write_toml(toml_path, preset=preset)
    print(f"Created {toml_path} (preset: {preset})")


def run_config_show(*, target_dir: Path) -> None:
    cfg = load_project_config(target_dir)
    print(f"  enabled: {cfg.enabled}")
    print(f"  preset:  {cfg.preset}")
    if cfg.overrides:
        print(f"  overrides: {cfg.overrides}")
    dc = cfg.to_detection_config()
    print(f"  threshold_critical: {dc.threshold_critical}")
    print(f"  threshold_high:     {dc.threshold_high}")
    print(f"  threshold_medium:   {dc.threshold_medium}")


def run_config_set(*, target_dir: Path, preset: str) -> None:
    if preset not in PRESETS:
        raise ValueError(f"Unknown preset: {preset!r}. Available: {sorted(PRESETS.keys())}")
    cfg = load_project_config(target_dir)
    _write_toml(target_dir / CONFIG_FILENAME, enabled=cfg.enabled, preset=preset)
    print(f"Updated preset to: {preset}")


def run_config_disable(*, target_dir: Path) -> None:
    cfg = load_project_config(target_dir)
    _write_toml(target_dir / CONFIG_FILENAME, enabled=False, preset=cfg.preset)
    print("ClawSentry monitoring disabled for this project.")


def run_config_enable(*, target_dir: Path) -> None:
    cfg = load_project_config(target_dir)
    _write_toml(target_dir / CONFIG_FILENAME, enabled=True, preset=cfg.preset)
    print("ClawSentry monitoring enabled for this project.")
