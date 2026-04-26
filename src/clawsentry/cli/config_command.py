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


def _write_toml(
    path: Path,
    *,
    enabled: bool = True,
    preset: str = "medium",
    mode: str = "normal",
    llm_provider: str = "",
    llm_model: str = "",
    llm_base_url: str = "",
    l2: bool = False,
    l3: bool = False,
    enterprise: bool = False,
    token_budget: int = 0,
    token_budget_enabled: bool | None = None,
    defer_timeout_s: float = 86_400.0,
    benchmark_auto_resolve: bool = True,
    benchmark_defer_action: str = "block",
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
        'api_key_env = "CS_LLM_API_KEY"',
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
        'llm_token_budget_scope = "total"',
        "l2_timeout_ms = 60000",
        "l3_timeout_ms = 300000",
        "hard_timeout_ms = 600000",
        "",
        "[defer]",
        "bridge_enabled = true",
        f"timeout_s = {_toml_value(defer_timeout_s)}",
        'timeout_action = "block"',
        "max_pending = 0",
        "",
        "[benchmark]",
        f"auto_resolve_defer = {_toml_value(benchmark_auto_resolve)}",
        f"defer_action = {_toml_value(benchmark_defer_action)}",
        'persist_scope = "project"',
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


def _set_nested(config: dict[str, Any], dotted_key: str, value: str) -> None:
    section, _, name = dotted_key.partition(".")
    if not section or not name:
        raise ValueError("Config key must be section.field, e.g. project.mode")
    config.setdefault(section, {})[name] = value


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
        _write_toml(
            target_dir / CONFIG_FILENAME,
            enabled=cfg.enabled,
            preset=str(preset),
            mode=cfg.mode,
            llm_provider=str(cfg.llm.get("provider", "")),
            llm_model=str(cfg.llm.get("model", "")),
            llm_base_url=str(cfg.llm.get("base_url", "")),
            l2=bool(cfg.features.get("l2", False)),
            l3=bool(cfg.features.get("l3", False)),
            enterprise=bool(cfg.features.get("enterprise", False)),
            token_budget=int(cfg.budgets.get("llm_daily_token_budget", 0) or 0),
            token_budget_enabled=bool(cfg.budgets.get("llm_token_budget_enabled", False)),
        )
        print(f"Updated preset to: {preset}")
        return

    if value is None:
        raise ValueError("value is required when key is provided")
    if key == "project.mode" and value not in {"normal", "strict", "permissive", "benchmark"}:
        raise ValueError("project.mode must be normal, strict, permissive, or benchmark")
    current = {
        "project": {"enabled": cfg.enabled, "mode": cfg.mode, "preset": cfg.preset},
        "llm": cfg.llm,
        "features": cfg.features,
        "budgets": cfg.budgets,
        "defer": cfg.defer,
        "benchmark": cfg.benchmark,
    }
    _set_nested(current, key, value)
    _write_toml(
        target_dir / CONFIG_FILENAME,
        enabled=bool(current["project"].get("enabled", True)),
        preset=str(current["project"].get("preset", "medium")),
        mode=str(current["project"].get("mode", "normal")),
        llm_provider=str(current["llm"].get("provider", "")),
        llm_model=str(current["llm"].get("model", "")),
        llm_base_url=str(current["llm"].get("base_url", "")),
        l2=bool(current["features"].get("l2", False)),
        l3=bool(current["features"].get("l3", False)),
        enterprise=bool(current["features"].get("enterprise", False)),
        token_budget=int(current["budgets"].get("llm_daily_token_budget", 0) or 0),
        token_budget_enabled=bool(current["budgets"].get("llm_token_budget_enabled", False)),
    )
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
    if llm_provider and llm_provider not in {"openai", "anthropic"}:
        raise ValueError("llm_provider must be openai, anthropic, or empty")
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
    _write_toml(target_dir / CONFIG_FILENAME, enabled=False, preset=cfg.preset, mode=cfg.mode)
    print("ClawSentry monitoring disabled for this project.")


def run_config_enable(*, target_dir: Path) -> None:
    cfg = load_project_config(target_dir)
    _write_toml(target_dir / CONFIG_FILENAME, enabled=True, preset=cfg.preset, mode=cfg.mode)
    print("ClawSentry monitoring enabled for this project.")
