"""``clawsentry config`` — manage project-level .clawsentry.toml."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from clawsentry.gateway.detection_config import PRESETS
from clawsentry.gateway.project_config import (
    CONFIG_FILENAME,
    canonical_env_source_for,
    load_project_config,
    resolve_effective_config,
)


def _toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return '"' + str(value).replace('"', '\\"') + '"'


def _as_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _write_toml(
    path: Path,
    *,
    enabled: bool = True,
    preset: str = "medium",
    mode: str = "normal",
    llm_provider: str = "",
    llm_api_key_env: str = "CS_LLM_API_KEY",
    llm_model: str = "",
    llm_base_url: str = "",
    l2: bool = False,
    l3: bool = False,
    enterprise: bool = False,
    token_budget: int = 0,
    token_budget_enabled: bool | None = None,
    token_budget_scope: str = "total",
    l2_timeout_ms: float = 60_000.0,
    l3_timeout_ms: float = 300_000.0,
    hard_timeout_ms: float = 600_000.0,
    defer_bridge_enabled: bool = True,
    defer_timeout_s: float = 86_400.0,
    defer_timeout_action: str = "block",
    defer_max_pending: int = 0,
    benchmark_auto_resolve: bool = True,
    benchmark_defer_action: str = "block",
    benchmark_persist_scope: str = "project",
    framework: str = "",
) -> None:
    """Write a canonical .clawsentry.toml file."""
    if token_budget_enabled is None:
        token_budget_enabled = token_budget > 0
    lines = [
        "# ClawSentry project configuration",
        "# Docs: https://elroyper.github.io/ClawSentry/configuration/configuration-overview/",
        "",
        "[project]",
        f"enabled = {_toml_value(enabled)}",
        f"mode = {_toml_value(mode)}",
        f"preset = {_toml_value(preset)}",
        "",
        "[llm]",
        f"provider = {_toml_value(llm_provider)}",
        f"api_key_env = {_toml_value(llm_api_key_env)}",
        f"model = {_toml_value(llm_model)}",
        f"base_url = {_toml_value(llm_base_url)}",
        "",
        "[features]",
        f"l2 = {_toml_value(l2)}",
        f"l3 = {_toml_value(l3)}",
        f"enterprise = {_toml_value(enterprise)}",
        "",
        "[budgets]",
        f"llm_token_budget_enabled = {_toml_value(token_budget_enabled)}",
        f"llm_daily_token_budget = {int(token_budget)}",
        f"llm_token_budget_scope = {_toml_value(token_budget_scope)}",
        f"l2_timeout_ms = {_toml_value(l2_timeout_ms)}",
        f"l3_timeout_ms = {_toml_value(l3_timeout_ms)}",
        f"hard_timeout_ms = {_toml_value(hard_timeout_ms)}",
        "",
        "[defer]",
        f"bridge_enabled = {_toml_value(defer_bridge_enabled)}",
        f"timeout_s = {_toml_value(defer_timeout_s)}",
        f"timeout_action = {_toml_value(defer_timeout_action)}",
        f"max_pending = {int(defer_max_pending)}",
        "",
        "[benchmark]",
        f"auto_resolve_defer = {_toml_value(benchmark_auto_resolve)}",
        f"defer_action = {_toml_value(benchmark_defer_action)}",
        f"persist_scope = {_toml_value(benchmark_persist_scope)}",
        "",
        "# [overrides]",
        "# threshold_critical = 2.2",
    ]
    if framework:
        lines.extend(["", "# Preferred framework for guided setup", f"# framework = {_toml_value(framework)}"])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


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


def run_config_show(*, target_dir: Path, effective: bool = False) -> None:
    if effective:
        eff = resolve_effective_config(target_dir)
        print("Effective ClawSentry configuration:")
        for key, value, source in eff.rows():
            if source == "env":
                env_name = canonical_env_source_for(key)
                source = f"env:{env_name}" if env_name is not None else "env"
            print(f"  {key}: {value} (source={source})")
        if eff.warnings:
            print("Warnings:")
            for warning in eff.warnings:
                print(f"  - {warning}")
        return

    cfg = load_project_config(target_dir)
    print(f"  enabled: {cfg.enabled}")
    print(f"  mode:    {cfg.mode}")
    print(f"  preset:  {cfg.preset}")
    if cfg.overrides:
        print(f"  overrides: {cfg.overrides}")
    dc = cfg.to_detection_config()
    print(f"  threshold_critical: {dc.threshold_critical}")
    print(f"  threshold_high:     {dc.threshold_high}")
    print(f"  threshold_medium:   {dc.threshold_medium}")
    print(f"  l2_timeout_ms:      {dc.l2_budget_ms}")
    print(f"  token_budget:       {dc.llm_daily_token_budget if dc.llm_token_budget_enabled else 'disabled'}")


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _config_write_kwargs(cfg: Any) -> dict[str, Any]:
    """Return full ``_write_toml`` kwargs so small edits preserve other sections."""
    return {
        "enabled": bool(cfg.enabled),
        "preset": str(cfg.preset),
        "mode": str(cfg.mode),
        "llm_provider": str(cfg.llm.get("provider", "")),
        "llm_api_key_env": str(cfg.llm.get("api_key_env", "CS_LLM_API_KEY")),
        "llm_model": str(cfg.llm.get("model", "")),
        "llm_base_url": str(cfg.llm.get("base_url", "")),
        "l2": _as_bool(cfg.features.get("l2", False)),
        "l3": _as_bool(cfg.features.get("l3", False)),
        "enterprise": _as_bool(cfg.features.get("enterprise", False)),
        "token_budget": _as_int(cfg.budgets.get("llm_daily_token_budget", 0), 0),
        "token_budget_enabled": _as_bool(cfg.budgets.get("llm_token_budget_enabled", False)),
        "token_budget_scope": str(cfg.budgets.get("llm_token_budget_scope", "total")),
        "l2_timeout_ms": _as_float(cfg.budgets.get("l2_timeout_ms", 60_000.0), 60_000.0),
        "l3_timeout_ms": _as_float(cfg.budgets.get("l3_timeout_ms", 300_000.0), 300_000.0),
        "hard_timeout_ms": _as_float(cfg.budgets.get("hard_timeout_ms", 600_000.0), 600_000.0),
        "defer_bridge_enabled": _as_bool(cfg.defer.get("bridge_enabled", True), True),
        "defer_timeout_s": _as_float(cfg.defer.get("timeout_s", 86_400.0), 86_400.0),
        "defer_timeout_action": str(cfg.defer.get("timeout_action", "block")),
        "defer_max_pending": _as_int(cfg.defer.get("max_pending", 0), 0),
        "benchmark_auto_resolve": _as_bool(cfg.benchmark.get("auto_resolve_defer", True), True),
        "benchmark_defer_action": str(cfg.benchmark.get("defer_action", "block")),
        "benchmark_persist_scope": str(cfg.benchmark.get("persist_scope", "project")),
    }


_FIELD_TYPES: dict[str, type] = {
    "project.enabled": bool,
    "project.mode": str,
    "project.preset": str,
    "llm.provider": str,
    "llm.api_key_env": str,
    "llm.model": str,
    "llm.base_url": str,
    "features.l2": bool,
    "features.l3": bool,
    "features.enterprise": bool,
    "budgets.llm_token_budget_enabled": bool,
    "budgets.llm_daily_token_budget": int,
    "budgets.llm_token_budget_scope": str,
    "budgets.l2_timeout_ms": float,
    "budgets.l3_timeout_ms": float,
    "budgets.hard_timeout_ms": float,
    "defer.bridge_enabled": bool,
    "defer.timeout_s": float,
    "defer.timeout_action": str,
    "defer.max_pending": int,
    "benchmark.auto_resolve_defer": bool,
    "benchmark.defer_action": str,
    "benchmark.persist_scope": str,
}

_WRITE_KEY_MAP: dict[str, str] = {
    "project.enabled": "enabled",
    "project.mode": "mode",
    "project.preset": "preset",
    "llm.provider": "llm_provider",
    "llm.api_key_env": "llm_api_key_env",
    "llm.model": "llm_model",
    "llm.base_url": "llm_base_url",
    "features.l2": "l2",
    "features.l3": "l3",
    "features.enterprise": "enterprise",
    "budgets.llm_token_budget_enabled": "token_budget_enabled",
    "budgets.llm_daily_token_budget": "token_budget",
    "budgets.llm_token_budget_scope": "token_budget_scope",
    "budgets.l2_timeout_ms": "l2_timeout_ms",
    "budgets.l3_timeout_ms": "l3_timeout_ms",
    "budgets.hard_timeout_ms": "hard_timeout_ms",
    "defer.bridge_enabled": "defer_bridge_enabled",
    "defer.timeout_s": "defer_timeout_s",
    "defer.timeout_action": "defer_timeout_action",
    "defer.max_pending": "defer_max_pending",
    "benchmark.auto_resolve_defer": "benchmark_auto_resolve",
    "benchmark.defer_action": "benchmark_defer_action",
    "benchmark.persist_scope": "benchmark_persist_scope",
}


def _coerce_config_value(key: str, value: str) -> Any:
    target_type = _FIELD_TYPES.get(key, str)
    if target_type is bool:
        normalized = value.strip().lower()
        if normalized not in {"1", "0", "true", "false", "yes", "no", "on", "off"}:
            raise ValueError(f"{key} must be a boolean")
        return _as_bool(normalized)
    if target_type is int:
        return int(value)
    if target_type is float:
        return float(value)
    return value


def _set_nested(config: dict[str, Any], dotted_key: str, value: str) -> None:
    section, _, name = dotted_key.partition(".")
    if not section or not name:
        raise ValueError("Config key must be section.field, e.g. project.mode")
    if dotted_key not in _FIELD_TYPES:
        raise ValueError(f"Unknown config key: {dotted_key}")
    config.setdefault(section, {})[name] = _coerce_config_value(dotted_key, value)


def run_config_set(
    *,
    target_dir: Path,
    preset: str | None = None,
    key: str | None = None,
    value: str | None = None,
) -> None:
    """Set preset (legacy form) or a canonical section.field key."""
    cfg = load_project_config(target_dir)
    if key is None:
        if preset not in PRESETS:
            raise ValueError(f"Unknown preset: {preset!r}. Available: {sorted(PRESETS.keys())}")
        kwargs = _config_write_kwargs(cfg)
        kwargs["preset"] = str(preset)
        _write_toml(target_dir / CONFIG_FILENAME, **kwargs)
        print(f"Updated preset to: {preset}")
        return

    if value is None:
        raise ValueError("value is required when key is provided")
    if key == "project.mode" and value not in {"normal", "strict", "permissive", "benchmark"}:
        raise ValueError("project.mode must be normal, strict, permissive, or benchmark")
    current = {
        "project": {"enabled": cfg.enabled, "mode": cfg.mode, "preset": cfg.preset},
        "llm": dict(cfg.llm),
        "features": dict(cfg.features),
        "budgets": dict(cfg.budgets),
        "defer": dict(cfg.defer),
        "benchmark": dict(cfg.benchmark),
    }
    _set_nested(current, key, value)
    section_name, _, field_name = key.partition(".")
    kwargs = _config_write_kwargs(cfg)
    kwargs[_WRITE_KEY_MAP[key]] = current[section_name][field_name]
    _write_toml(target_dir / CONFIG_FILENAME, **kwargs)
    print(f"Updated {key} to: {value}")


def run_config_wizard(
    *,
    target_dir: Path,
    non_interactive: bool = False,
    framework: str = "codex",
    mode: str = "normal",
    llm_provider: str = "",
    llm_model: str = "",
    llm_base_url: str = "",
    l2: bool | None = None,
    l3: bool = False,
    token_budget: int = 0,
    force: bool = False,
) -> None:
    """Guided setup. Non-interactive mode is deterministic for CI/wrappers."""
    if not non_interactive:
        print("Interactive wizard is not available in this terminal; using supplied/default values.")
    if mode not in {"normal", "strict", "permissive", "benchmark"}:
        raise ValueError("mode must be normal, strict, permissive, or benchmark")
    if llm_provider == "none":
        llm_provider = ""
    if llm_provider and llm_provider not in {"openai", "anthropic"}:
        raise ValueError("llm_provider must be openai, anthropic, none, or empty")
    l2_enabled = bool(llm_provider) if l2 is None else bool(l2)
    toml_path = target_dir / CONFIG_FILENAME
    if toml_path.exists() and not force:
        raise FileExistsError(f"{toml_path} already exists. Use --force to overwrite.")
    _write_toml(
        toml_path,
        mode=mode,
        llm_provider=llm_provider,
        llm_model=llm_model,
        llm_base_url=llm_base_url,
        l2=l2_enabled,
        l3=l3,
        token_budget=token_budget,
        framework=framework,
    )
    print(f"Configured ClawSentry for {framework} ({mode} mode).")
    if llm_provider:
        print("LLM API key is read from CS_LLM_API_KEY; secrets were not written to config.")


def run_config_disable(*, target_dir: Path) -> None:
    cfg = load_project_config(target_dir)
    kwargs = _config_write_kwargs(cfg)
    kwargs["enabled"] = False
    _write_toml(target_dir / CONFIG_FILENAME, **kwargs)
    print("ClawSentry monitoring disabled for this project.")


def run_config_enable(*, target_dir: Path) -> None:
    cfg = load_project_config(target_dir)
    kwargs = _config_write_kwargs(cfg)
    kwargs["enabled"] = True
    _write_toml(target_dir / CONFIG_FILENAME, **kwargs)
    print("ClawSentry monitoring enabled for this project.")
