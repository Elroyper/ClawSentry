"""Project-level .clawsentry.toml configuration loader and effective config resolver."""

from __future__ import annotations

import logging
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Mapping, MutableMapping

from clawsentry.cli.dotenv_loader import ParsedEnvFile

from .detection_config import DetectionConfig, from_preset

logger = logging.getLogger(__name__)

CONFIG_FILENAME = ".clawsentry.toml"
_VALID_MODES = {"normal", "strict", "permissive", "benchmark"}
_VALID_TOKEN_SCOPES = {"total", "input", "output"}


class _ConfigSection(Mapping[str, Any]):
    """Read-only dotted-section view that supports both dict and attribute access."""

    def __init__(self, values: Mapping[str, Any] | None = None) -> None:
        self._values = dict(values or {})

    def __getitem__(self, key: str) -> Any:
        return self._values[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def __getattr__(self, name: str) -> Any:
        try:
            return self._values[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    def get(self, key: str, default: Any = None) -> Any:
        return self._values.get(key, default)


def _section(values: Mapping[str, Any] | None) -> _ConfigSection:
    return _ConfigSection(values)


def _as_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _redact_secret(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "***"
    if value.startswith("sk-"):
        return f"{value[:4]}... (redacted)"
    return f"{value[:4]}...{value[-4:]}"


def _toml_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _toml_value(value: Any) -> str:
    if isinstance(value, list):
        return "[" + ", ".join(_toml_scalar(item) for item in value) + "]"
    return _toml_scalar(value)


def _load_project_config_data(project_dir: Path) -> dict[str, Any]:
    config_path = project_dir / CONFIG_FILENAME
    if not config_path.is_file():
        return {}
    try:
        with open(config_path, "rb") as f:
            data = tomllib.load(f)
    except Exception as exc:
        raise ValueError(f"Failed to parse {config_path}: {exc}") from exc
    return data if isinstance(data, dict) else {}


def _write_project_config_data(config_path: Path, data: Mapping[str, Any]) -> None:
    """Write the subset of TOML used by ClawSentry config helpers."""
    lines = [
        "# ClawSentry project configuration",
        "# Docs: https://elroyper.github.io/ClawSentry/configuration/configuration-overview/",
        "",
    ]
    for section in ("project", "frameworks", "llm", "features", "budgets", "defer", "benchmark"):
        values = data.get(section)
        if not isinstance(values, Mapping):
            continue
        scalar_items = {
            key: value
            for key, value in values.items()
            if not isinstance(value, Mapping)
        }
        if scalar_items:
            lines.append(f"[{section}]")
            for key, value in scalar_items.items():
                lines.append(f"{key} = {_toml_value(value)}")
            lines.append("")
        for child_key, child_values in values.items():
            if not isinstance(child_values, Mapping):
                continue
            lines.append(f"[{section}.{child_key}]")
            for key, value in child_values.items():
                if isinstance(value, Mapping):
                    continue
                lines.append(f"{key} = {_toml_value(value)}")
            lines.append("")
    overrides = data.get("overrides")
    if isinstance(overrides, Mapping) and overrides:
        lines.append("[overrides]")
        for key, value in overrides.items():
            lines.append(f"{key} = {_toml_value(value)}")
        lines.append("")
    config_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def default_framework_config(framework: str) -> dict[str, Any]:
    """Return safe-to-commit defaults for a framework subsection."""
    defaults: dict[str, dict[str, Any]] = {
        "codex": {"watch_sessions": True, "managed_hooks": False},
        "openclaw": {
            "setup_managed_config": False,
            "websocket_url_env": "OPENCLAW_WS_URL",
        },
        "a3s-code": {"explicit_transport_required": True},
        "claude-code": {"managed_hooks": True},
        "gemini-cli": {
            "managed_hooks": False,
            "settings_path": ".gemini/settings.json",
        },
    }
    return dict(defaults.get(framework, {}))


def read_project_frameworks(project_dir: Path) -> tuple[list[str], str]:
    """Read enabled/default frameworks from .clawsentry.toml."""
    cfg = load_project_config(project_dir)
    enabled_raw = cfg.frameworks.get("enabled", [])
    enabled = [
        str(item)
        for item in (enabled_raw if isinstance(enabled_raw, list) else [])
        if str(item).strip()
    ]
    default = str(cfg.frameworks.get("default", "") or "")
    return enabled, default


def update_project_framework(
    project_dir: Path,
    framework: str,
    *,
    force: bool = False,
    make_default: bool = False,
) -> Path:
    """Add/update one framework in ``.clawsentry.toml``."""
    project_dir.mkdir(parents=True, exist_ok=True)
    config_path = project_dir / CONFIG_FILENAME
    data = _load_project_config_data(project_dir)
    project = data.setdefault("project", {})
    if isinstance(project, dict):
        project.setdefault("enabled", True)
        project.setdefault("mode", "normal")
        project.setdefault("preset", "medium")
    frameworks = data.setdefault("frameworks", {})
    if not isinstance(frameworks, dict):
        frameworks = {}
        data["frameworks"] = frameworks
    enabled_raw = frameworks.get("enabled", [])
    enabled = [
        str(item)
        for item in (enabled_raw if isinstance(enabled_raw, list) else [])
        if str(item).strip()
    ]
    if framework not in enabled:
        enabled.append(framework)
    frameworks["enabled"] = enabled
    if make_default or not frameworks.get("default"):
        frameworks["default"] = framework
    if force or not isinstance(frameworks.get(framework), dict):
        frameworks[framework] = default_framework_config(framework)
    else:
        defaults = default_framework_config(framework)
        child = frameworks.setdefault(framework, {})
        if isinstance(child, dict):
            for key, value in defaults.items():
                child.setdefault(key, value)
    _write_project_config_data(config_path, data)
    return config_path


def remove_project_framework(project_dir: Path, framework: str, *, prune_config: bool = False) -> Path:
    """Remove one framework from enabled list in ``.clawsentry.toml``."""
    project_dir.mkdir(parents=True, exist_ok=True)
    config_path = project_dir / CONFIG_FILENAME
    data = _load_project_config_data(project_dir)
    frameworks = data.setdefault("frameworks", {})
    if not isinstance(frameworks, dict):
        frameworks = {}
        data["frameworks"] = frameworks
    enabled_raw = frameworks.get("enabled", [])
    enabled = [
        str(item)
        for item in (enabled_raw if isinstance(enabled_raw, list) else [])
        if str(item).strip() and str(item) != framework
    ]
    frameworks["enabled"] = enabled
    if frameworks.get("default") == framework:
        frameworks["default"] = enabled[0] if enabled else ""
    if prune_config:
        frameworks.pop(framework, None)
    elif isinstance(frameworks.get(framework), dict):
        frameworks[framework]["enabled"] = False
    _write_project_config_data(config_path, data)
    return config_path


@dataclass(frozen=True)
class ProjectConfig:
    """Parsed project configuration from .clawsentry.toml."""

    enabled: bool = True
    preset: str = "medium"
    mode: str = "normal"
    overrides: dict[str, Any] = field(default_factory=dict)
    llm: _ConfigSection = field(default_factory=_ConfigSection)
    features: _ConfigSection = field(default_factory=_ConfigSection)
    budgets: _ConfigSection = field(default_factory=_ConfigSection)
    defer: _ConfigSection = field(default_factory=_ConfigSection)
    benchmark: _ConfigSection = field(default_factory=_ConfigSection)
    frameworks: _ConfigSection = field(default_factory=_ConfigSection)

    def to_detection_config(self) -> DetectionConfig:
        """Build DetectionConfig from preset, legacy overrides, and canonical sections."""
        params: dict[str, Any] = dict(self.overrides)
        params["mode"] = self.mode if self.mode in _VALID_MODES else "normal"

        budget_map = {
            "l2_timeout_ms": "l2_budget_ms",
            "l3_timeout_ms": "l3_budget_ms",
            "hard_timeout_ms": "hard_timeout_ms",
            "llm_token_budget_enabled": "llm_token_budget_enabled",
            "llm_daily_token_budget": "llm_daily_token_budget",
            "llm_token_budget_scope": "llm_token_budget_scope",
        }
        for key, field_name in budget_map.items():
            if key in self.budgets:
                params[field_name] = self.budgets[key]

        defer_map = {
            "bridge_enabled": "defer_bridge_enabled",
            "timeout_s": "defer_timeout_s",
            "timeout_action": "defer_timeout_action",
            "max_pending": "defer_max_pending",
        }
        for key, field_name in defer_map.items():
            if key in self.defer:
                params[field_name] = self.defer[key]

        benchmark_map = {
            "auto_resolve_defer": "benchmark_auto_resolve_defer",
            "defer_action": "benchmark_defer_action",
            "persist_scope": "benchmark_persist_scope",
        }
        for key, field_name in benchmark_map.items():
            if key in self.benchmark:
                params[field_name] = self.benchmark[key]

        return from_preset(self.preset, **params)


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

    project = data.get("project", {}) if isinstance(data.get("project", {}), dict) else {}
    mode = str(project.get("mode", "normal"))
    if mode not in _VALID_MODES:
        logger.warning("Invalid project.mode=%r in %s; using normal", mode, config_path)
        mode = "normal"

    return ProjectConfig(
        enabled=_as_bool(project.get("enabled", True), True),
        preset=str(project.get("preset", "medium")),
        mode=mode,
        overrides=dict(data.get("overrides", {}) or {}),
        llm=_section(data.get("llm", {}) or {}),
        features=_section(data.get("features", {}) or {}),
        budgets=_section(data.get("budgets", {}) or {}),
        defer=_section(data.get("defer", {}) or {}),
        benchmark=_section(data.get("benchmark", {}) or {}),
        frameworks=_section(data.get("frameworks", {}) or {}),
    )


@dataclass(frozen=True)
class EffectiveConfig:
    """Resolved operator-facing config values and source metadata."""

    values: dict[str, Any]
    sources: dict[str, str]
    source_details: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def rows(self) -> list[tuple[str, Any, str]]:
        return [
            (key, self.values[key], self.sources.get(key, "default"))
            for key in sorted(self.values)
        ]

    def source_detail_for(self, key: str) -> str | None:
        return self.source_details.get(key)


_DEFAULT_EFFECTIVE: dict[str, Any] = {
    "project.enabled": True,
    "project.mode": "normal",
    "project.preset": "medium",
    "llm.provider": "",
    "llm.api_key_env": "CS_LLM_API_KEY",
    "llm.api_key": "",
    "llm.model": "",
    "llm.base_url": "",
    "features.l2": False,
    "features.l3": False,
    "features.enterprise": False,
    "budgets.llm_token_budget_enabled": False,
    "budgets.llm_daily_token_budget": 0,
    "budgets.llm_token_budget_scope": "total",
    "budgets.l2_timeout_ms": 60_000.0,
    "budgets.l3_timeout_ms": 300_000.0,
    "budgets.hard_timeout_ms": 600_000.0,
    "defer.bridge_enabled": True,
    "defer.timeout_s": 86_400.0,
    "defer.timeout_action": "block",
    "defer.max_pending": 0,
    "benchmark.auto_resolve_defer": True,
    "benchmark.defer_action": "block",
    "benchmark.persist_scope": "project",
    "frameworks.enabled": [],
    "frameworks.default": "",
}

_PROJECT_MAP: dict[str, tuple[str, str]] = {
    "project.enabled": ("project", "enabled"),
    "project.mode": ("project", "mode"),
    "project.preset": ("project", "preset"),
    "llm.provider": ("llm", "provider"),
    "llm.api_key_env": ("llm", "api_key_env"),
    "llm.model": ("llm", "model"),
    "llm.base_url": ("llm", "base_url"),
    "features.l2": ("features", "l2"),
    "features.l3": ("features", "l3"),
    "features.enterprise": ("features", "enterprise"),
    "budgets.llm_token_budget_enabled": ("budgets", "llm_token_budget_enabled"),
    "budgets.llm_daily_token_budget": ("budgets", "llm_daily_token_budget"),
    "budgets.llm_token_budget_scope": ("budgets", "llm_token_budget_scope"),
    "budgets.l2_timeout_ms": ("budgets", "l2_timeout_ms"),
    "budgets.l3_timeout_ms": ("budgets", "l3_timeout_ms"),
    "budgets.hard_timeout_ms": ("budgets", "hard_timeout_ms"),
    "defer.bridge_enabled": ("defer", "bridge_enabled"),
    "defer.timeout_s": ("defer", "timeout_s"),
    "defer.timeout_action": ("defer", "timeout_action"),
    "defer.max_pending": ("defer", "max_pending"),
    "benchmark.auto_resolve_defer": ("benchmark", "auto_resolve_defer"),
    "benchmark.defer_action": ("benchmark", "defer_action"),
    "benchmark.persist_scope": ("benchmark", "persist_scope"),
    "frameworks.enabled": ("frameworks", "enabled"),
    "frameworks.default": ("frameworks", "default"),
}

_ENV_MAP: dict[str, str] = {
    "CS_MODE": "project.mode",
    "CS_LLM_PROVIDER": "llm.provider",
    "CS_LLM_MODEL": "llm.model",
    "CS_LLM_BASE_URL": "llm.base_url",
    "CS_LLM_TOKEN_BUDGET_ENABLED": "budgets.llm_token_budget_enabled",
    "CS_LLM_DAILY_TOKEN_BUDGET": "budgets.llm_daily_token_budget",
    "CS_LLM_TOKEN_BUDGET_SCOPE": "budgets.llm_token_budget_scope",
    "CS_L2_TIMEOUT_MS": "budgets.l2_timeout_ms",
    "CS_L3_TIMEOUT_MS": "budgets.l3_timeout_ms",
    "CS_HARD_TIMEOUT_MS": "budgets.hard_timeout_ms",
    "CS_DEFER_BRIDGE_ENABLED": "defer.bridge_enabled",
    "CS_DEFER_TIMEOUT_S": "defer.timeout_s",
    "CS_DEFER_TIMEOUT_ACTION": "defer.timeout_action",
    "CS_DEFER_MAX_PENDING": "defer.max_pending",
    "CS_BENCHMARK_AUTO_RESOLVE_DEFER": "benchmark.auto_resolve_defer",
    "CS_BENCHMARK_DEFER_ACTION": "benchmark.defer_action",
    "CS_BENCHMARK_PERSIST_SCOPE": "benchmark.persist_scope",
    "CS_L3_ENABLED": "features.l3",
    "CS_ENTERPRISE_ENABLED": "features.enterprise",
}

_EFFECTIVE_TO_ENV_VAR = {key: env_key for env_key, key in _ENV_MAP.items()}

_LEGACY_ENV_MAP: dict[str, tuple[str, str]] = {
    "CS_L2_BUDGET_MS": ("budgets.l2_timeout_ms", "CS_L2_TIMEOUT_MS"),
    "CS_L3_BUDGET_MS": ("budgets.l3_timeout_ms", "CS_L3_TIMEOUT_MS"),
}


def canonical_env_source_for(key: str) -> str | None:
    """Return canonical env var name used to source an effective config key."""
    return _EFFECTIVE_TO_ENV_VAR.get(key)


def _project_sections(cfg: ProjectConfig) -> dict[str, Mapping[str, Any]]:
    return {
        "project": {"enabled": cfg.enabled, "mode": cfg.mode, "preset": cfg.preset},
        "llm": cfg.llm,
        "features": cfg.features,
        "budgets": cfg.budgets,
        "defer": cfg.defer,
        "benchmark": cfg.benchmark,
        "frameworks": cfg.frameworks,
    }


def _coerce_like(default: Any, raw: Any) -> Any:
    if isinstance(default, bool):
        return _as_bool(raw, default)
    if isinstance(default, int) and not isinstance(default, bool):
        return int(raw)
    if isinstance(default, float):
        return float(raw)
    return str(raw)


def _env_file_detail(parsed_env_file: ParsedEnvFile | None, env_key: str) -> str:
    detail = parsed_env_file.source_detail_for(env_key) if parsed_env_file else None
    return detail or env_key


def _set_value(
    *,
    key: str,
    value: Any,
    source: str,
    detail: str | None,
    values: dict[str, Any],
    sources: dict[str, str],
    source_details: dict[str, str],
) -> None:
    values[key] = value
    sources[key] = source
    if detail:
        source_details[key] = detail
    else:
        source_details.pop(key, None)


def resolve_effective_config(
    project_dir: Path,
    *,
    environ: Mapping[str, str] | None = None,
    env_file_values: Mapping[str, str] | None = None,
    env_file_provenance: ParsedEnvFile | None = None,
    cli_overrides: Mapping[str, Any] | None = None,
) -> EffectiveConfig:
    """Resolve canonical config values with source metadata and redaction."""
    env = os.environ if environ is None else environ
    file_env = {} if env_file_values is None else env_file_values
    cli = {} if cli_overrides is None else cli_overrides
    cfg = load_project_config(project_dir)
    values = dict(_DEFAULT_EFFECTIVE)
    sources = {key: "default" for key in values}
    source_details: dict[str, str] = {}
    warnings: list[str] = []

    sections = _project_sections(cfg)
    for key, (section, field_name) in _PROJECT_MAP.items():
        section_values = sections.get(section, {})
        if field_name in section_values:
            _set_value(
                key=key,
                value=section_values[field_name],
                source="project",
                detail=f"{CONFIG_FILENAME}:[{section}].{field_name}",
                values=values,
                sources=sources,
                source_details=source_details,
            )

    for env_key, key in _ENV_MAP.items():
        if env_key in file_env and str(file_env[env_key]).strip() != "":
            try:
                _set_value(
                    key=key,
                    value=_coerce_like(_DEFAULT_EFFECTIVE[key], file_env[env_key]),
                    source="env-file",
                    detail=_env_file_detail(env_file_provenance, env_key),
                    values=values,
                    sources=sources,
                    source_details=source_details,
                )
            except (TypeError, ValueError):
                warnings.append(f"Ignoring invalid env-file {env_key}={file_env[env_key]!r}")

    for env_key, key in _ENV_MAP.items():
        if env_key in env and str(env[env_key]).strip() != "":
            try:
                _set_value(
                    key=key,
                    value=_coerce_like(_DEFAULT_EFFECTIVE[key], env[env_key]),
                    source="process-env",
                    detail=env_key,
                    values=values,
                    sources=sources,
                    source_details=source_details,
                )
            except (TypeError, ValueError):
                warnings.append(f"Ignoring invalid {env_key}={env[env_key]!r}")

    for env_key, (key, canonical_env) in _LEGACY_ENV_MAP.items():
        if env_key not in env or str(env[env_key]).strip() == "":
            continue
        if canonical_env in env or sources.get(key) in {"process-env", "env-file", "project"}:
            warnings.append(f"Ignoring deprecated {env_key}; canonical/project {key} wins")
            continue
        try:
            _set_value(
                key=key,
                value=_coerce_like(_DEFAULT_EFFECTIVE[key], env[env_key]),
                source="legacy-env",
                detail=env_key,
                values=values,
                sources=sources,
                source_details=source_details,
            )
            warnings.append(f"Deprecated {env_key}; use {canonical_env}")
        except (TypeError, ValueError):
            warnings.append(f"Ignoring invalid {env_key}={env[env_key]!r}")

    for key, raw_value in cli.items():
        if key not in values or raw_value is None or str(raw_value).strip() == "":
            continue
        try:
            _set_value(
                key=key,
                value=_coerce_like(_DEFAULT_EFFECTIVE[key], raw_value),
                source="cli",
                detail=key,
                values=values,
                sources=sources,
                source_details=source_details,
            )
        except (TypeError, ValueError):
            warnings.append(f"Ignoring invalid CLI override {key}={raw_value!r}")

    api_key_env = str(values.get("llm.api_key_env") or "CS_LLM_API_KEY")
    api_key = ""
    api_source = "default"
    api_detail: str | None = None
    if api_key_env in file_env and str(file_env[api_key_env]).strip():
        api_key = str(file_env[api_key_env] or "")
        api_source = "env-file"
        api_detail = _env_file_detail(env_file_provenance, api_key_env)
    if api_key_env in env and str(env[api_key_env]).strip():
        api_key = str(env[api_key_env] or "")
        api_source = "process-env"
        api_detail = api_key_env
    provider = str(values.get("llm.provider") or "").lower()
    provider_key = "OPENAI_API_KEY" if provider == "openai" else "ANTHROPIC_API_KEY" if provider == "anthropic" else ""
    if not api_key and provider_key:
        if provider_key in file_env and str(file_env[provider_key]).strip():
            api_key = str(file_env[provider_key] or "")
            api_source = "env-file"
            api_detail = _env_file_detail(env_file_provenance, provider_key)
        if provider_key in env and str(env[provider_key]).strip():
            api_key = str(env[provider_key] or "")
            api_source = "process-env"
            api_detail = provider_key
    _set_value(
        key="llm.api_key",
        value=_redact_secret(api_key),
        source=api_source if api_key else "default",
        detail=api_detail,
        values=values,
        sources=sources,
        source_details=source_details,
    )

    if _as_bool(values.get("budgets.llm_token_budget_enabled")) and int(values.get("budgets.llm_daily_token_budget") or 0) <= 0:
        warnings.append("Token budget enabled with non-positive limit; runtime disables enforcement")
    return EffectiveConfig(values=values, sources=sources, source_details=source_details, warnings=warnings)


def apply_project_config_to_environ(
    project_dir: Path,
    *,
    environ: MutableMapping[str, str] | None = None,
) -> None:
    """Export project config into missing canonical env vars for runtime startup.

    Runtime components historically read canonical ``CS_*`` variables.  This
    bridge makes ``.clawsentry.toml`` effective without overwriting explicit
    environment values, preserving the runtime bridge precedence: existing environment values
    always win over project defaults. Full effective resolution is CLI >
    process env > explicit env-file > project > legacy aliases > defaults.  It intentionally writes only canonical names.
    """
    target = os.environ if environ is None else environ
    cfg = load_project_config(project_dir)
    if not (project_dir / CONFIG_FILENAME).is_file():
        return

    def put(env_key: str, value: Any) -> None:
        if value is None or str(value).strip() == "":
            return
        target.setdefault(env_key, str(value).lower() if isinstance(value, bool) else str(value))

    put("CS_MODE", cfg.mode)
    put("CS_LLM_PROVIDER", cfg.llm.get("provider", ""))
    put("CS_LLM_MODEL", cfg.llm.get("model", ""))
    put("CS_LLM_BASE_URL", cfg.llm.get("base_url", ""))
    api_key_env = str(cfg.llm.get("api_key_env", "CS_LLM_API_KEY") or "CS_LLM_API_KEY")
    if api_key_env != "CS_LLM_API_KEY" and api_key_env in target:
        target.setdefault("CS_LLM_API_KEY", str(target[api_key_env]))

    put("CS_L3_ENABLED", cfg.features.get("l3", None))
    put("CS_ENTERPRISE_ENABLED", cfg.features.get("enterprise", None))

    put("CS_LLM_TOKEN_BUDGET_ENABLED", cfg.budgets.get("llm_token_budget_enabled", None))
    put("CS_LLM_DAILY_TOKEN_BUDGET", cfg.budgets.get("llm_daily_token_budget", None))
    put("CS_LLM_TOKEN_BUDGET_SCOPE", cfg.budgets.get("llm_token_budget_scope", None))
    put("CS_L2_TIMEOUT_MS", cfg.budgets.get("l2_timeout_ms", None))
    put("CS_L3_TIMEOUT_MS", cfg.budgets.get("l3_timeout_ms", None))
    put("CS_HARD_TIMEOUT_MS", cfg.budgets.get("hard_timeout_ms", None))

    put("CS_DEFER_BRIDGE_ENABLED", cfg.defer.get("bridge_enabled", None))
    put("CS_DEFER_TIMEOUT_S", cfg.defer.get("timeout_s", None))
    put("CS_DEFER_TIMEOUT_ACTION", cfg.defer.get("timeout_action", None))
    put("CS_DEFER_MAX_PENDING", cfg.defer.get("max_pending", None))

    put("CS_BENCHMARK_AUTO_RESOLVE_DEFER", cfg.benchmark.get("auto_resolve_defer", None))
    put("CS_BENCHMARK_DEFER_ACTION", cfg.benchmark.get("defer_action", None))
    put("CS_BENCHMARK_PERSIST_SCOPE", cfg.benchmark.get("persist_scope", None))
