"""Base protocol and data structures for framework initializers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass
class InitResult:
    """Result of a framework initialization."""

    files_created: list[Path]
    env_vars: dict[str, str]
    next_steps: list[str]
    warnings: list[str]


@dataclass
class SetupResult:
    """Result of an OpenClaw setup operation (--setup)."""

    changes_applied: list[str]
    files_modified: list[Path]
    files_backed_up: list[Path]
    warnings: list[str]
    dry_run: bool


@dataclass
class EnvDisableResult:
    """Result of disabling one framework in a legacy env file."""

    changed: bool
    enabled_frameworks: list[str]
    removed_keys: list[str]
    warnings: list[str]


ENV_FILE_NAME = ".env.clawsentry"
LOCAL_ENV_FILE_EXAMPLE = ".clawsentry.env.local"


def read_env_file(path: Path) -> dict[str, str]:
    """Read a simple KEY=VALUE env file, ignoring comments and malformed lines."""
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if key:
            values[key] = value
    return values


def write_env_file(path: Path, header: str, values: dict[str, str]) -> None:
    """Write values using the legacy KEY=VALUE env-file format."""
    lines = [header]
    for key, val in values.items():
        lines.append(f"{key}={val}")
    lines.append("")
    path.write_text("\n".join(lines))
    path.chmod(0o600)


def merge_env_file(
    path: Path,
    *,
    header: str,
    new_values: dict[str, str],
    framework: str,
    force: bool = False,
) -> dict[str, str]:
    """Create or merge a legacy env file without rotating existing shared secrets.

    Existing values win when *force* is false.  This lets a user add another
    framework without changing the token or the legacy single-framework marker
    that older scripts may still read.  ``CS_ENABLED_FRAMEWORKS`` records the
    additive multi-framework intent.
    """
    merging_existing = path.exists() and not force
    if not merging_existing:
        merged = dict(new_values)
    else:
        merged = read_env_file(path)
        for key, val in new_values.items():
            merged.setdefault(key, val)

    enabled: list[str] = []
    raw_enabled = merged.get("CS_ENABLED_FRAMEWORKS", "")
    for item in raw_enabled.split(","):
        item = item.strip()
        if item and item not in enabled:
            enabled.append(item)
    legacy_framework = merged.get("CS_FRAMEWORK", "").strip()
    if legacy_framework and legacy_framework not in enabled:
        enabled.append(legacy_framework)
    if framework not in enabled:
        enabled.append(framework)
    merged["CS_ENABLED_FRAMEWORKS"] = ",".join(enabled)

    if "CS_FRAMEWORK" not in merged:
        merged["CS_FRAMEWORK"] = framework

    effective_header = (
        "# ClawSentry — multi-framework integration config"
        if merging_existing
        else header
    )
    write_env_file(path, effective_header, merged)
    return merged


def merge_project_framework_config(
    target_dir: Path,
    *,
    framework: str,
    force: bool = False,
) -> tuple[Path, dict[str, str]]:
    """Record framework enablement in ``.clawsentry.toml``.

    Returns a TOML path plus non-secret compatibility values for CLI display.
    Secrets such as ``CS_AUTH_TOKEN`` are intentionally not generated here.
    """
    from clawsentry.gateway.project_config import update_project_framework

    path = update_project_framework(target_dir, framework, force=force)
    return path, {"CLAW_SENTRY_FRAMEWORK": framework}


def _parse_enabled_frameworks(values: dict[str, str]) -> list[str]:
    """Return de-duplicated enabled frameworks from env values."""
    enabled: list[str] = []
    raw_enabled = values.get("CS_ENABLED_FRAMEWORKS", "")
    for item in raw_enabled.split(","):
        item = item.strip()
        if item and item not in enabled:
            enabled.append(item)

    legacy_framework = values.get("CS_FRAMEWORK", "").strip()
    if legacy_framework and legacy_framework not in enabled:
        enabled.append(legacy_framework)

    return enabled


def disable_framework_env(
    path: Path,
    *,
    framework: str,
    framework_keys: set[str],
) -> EnvDisableResult:
    """Disable one framework in a legacy env file without touching shared secrets."""
    if not path.exists():
        return EnvDisableResult(
            changed=False,
            enabled_frameworks=[],
            removed_keys=[],
            warnings=[f"{path} does not exist; no project env was changed."],
        )

    values = read_env_file(path)
    before = dict(values)
    enabled = [
        item for item in _parse_enabled_frameworks(values) if item != framework
    ]

    removed_keys: list[str] = []
    for key in sorted(framework_keys):
        if key in values:
            removed_keys.append(key)
            del values[key]

    if enabled:
        values["CS_ENABLED_FRAMEWORKS"] = ",".join(enabled)
    else:
        values.pop("CS_ENABLED_FRAMEWORKS", None)

    if values.get("CS_FRAMEWORK") == framework:
        if enabled:
            values["CS_FRAMEWORK"] = enabled[0]
        else:
            values.pop("CS_FRAMEWORK", None)

    changed = values != before
    if changed:
        write_env_file(
            path,
            "# ClawSentry — multi-framework integration config",
            values,
        )

    warnings: list[str] = []
    if framework not in _parse_enabled_frameworks(before):
        warnings.append(f"{framework} was not listed in CS_ENABLED_FRAMEWORKS.")

    return EnvDisableResult(
        changed=changed,
        enabled_frameworks=enabled,
        removed_keys=removed_keys,
        warnings=warnings,
    )


class FrameworkInitializer(Protocol):
    """Protocol for framework-specific initializers."""

    framework_name: str

    def generate_config(
        self, target_dir: Path, *, force: bool = False
    ) -> InitResult: ...
