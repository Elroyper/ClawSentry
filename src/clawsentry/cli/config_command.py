"""``clawsentry config`` — manage project-level .clawsentry.toml."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

from .dotenv_loader import EnvFileError, resolve_explicit_env_file
from .initializers import FRAMEWORK_INITIALIZERS
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
        lines.extend(
            [
                "",
                "[frameworks]",
                f"enabled = [{_toml_value(framework)}]",
                f"default = {_toml_value(framework)}",
                "",
                f"[frameworks.{framework}]",
                "enabled = true",
            ]
        )
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


def run_config_show(
    *,
    target_dir: Path,
    effective: bool = False,
    env_file: Path | None = None,
) -> None:
    if effective:
        try:
            parsed = resolve_explicit_env_file(cli_env_file=env_file, environ=os.environ)
        except EnvFileError as exc:
            print(str(exc), file=sys.stderr)
            raise SystemExit(2) from exc
        eff = resolve_effective_config(
            target_dir,
            environ=os.environ,
            env_file_values=parsed.values,
            env_file_provenance=parsed,
        )
        print("Effective ClawSentry configuration:")
        for key, value, source in eff.rows():
            detail = eff.source_detail_for(key)
            if source == "process-env":
                env_name = canonical_env_source_for(key)
                source = f"process-env:{env_name or detail or ''}".rstrip(":")
            elif source == "env-file":
                source = f"env-file:{detail}" if detail else "env-file"
            elif source == "project":
                source = detail or "project"
            elif source == "legacy-env":
                source = f"legacy-env:{detail}" if detail else "legacy-env"
            print(f"  {key}: {value} (source={source})")
        for warning in parsed.warnings:
            eff.warnings.append(warning)
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


def _print_wizard_header(target_dir: Path) -> None:
    print("+--------------------------------------------+")
    print("| ClawSentry Setup                           |")
    print("| Interactive project configuration guide    |")
    print("+--------------------------------------------+")
    print(f"Target: {target_dir / CONFIG_FILENAME}")
    print()


def _print_wizard_boundary_notes() -> None:
    """Explain which wizard choices are actually written and runtime-effective."""
    print("Configuration boundary:")
    print("  - Writes only runtime-effective .clawsentry.toml fields approved for project config.")
    print("  - API key values are env-only; keep secrets in process env or explicit --env-file.")
    print("  - Runtime precedence: CLI > process env > explicit env-file > TOML > legacy aliases > defaults.")
    print("  - features.l3 requests L3; actual runtime use still requires provider support.")
    print("  - L3 routing/eager profiles, advisory automation, anti-bypass, DEFER, and timeouts")
    print("    stay in env/docs or advanced templates unless a dedicated wizard exposes them.")
    print("  - Verify final sources with `clawsentry config show --effective`.")
    print()


def _prompt_choice(
    *,
    step: str,
    label: str,
    choices: list[str],
    default: str,
) -> str:
    choice_text = ", ".join(f"{index}) {choice}" for index, choice in enumerate(choices, start=1))
    while True:
        raw = input(f"{step} {label} [{choice_text}] (default: {default}): ").strip()
        if raw.isdigit():
            index = int(raw)
            value = choices[index - 1] if 1 <= index <= len(choices) else raw
        else:
            value = raw or default
        if value in choices:
            return value
        print(f"  Choose one of: {choice_text}")


def _prompt_text(*, step: str, label: str, default: str = "") -> str:
    suffix = f" (default: {default})" if default else ""
    raw = input(f"{step} {label}{suffix}: ").strip()
    return raw or default


def _prompt_bool(*, step: str, label: str, default: bool = False) -> bool:
    default_text = "y" if default else "n"
    while True:
        raw = input(f"{step} {label} [y/n] (default: {default_text}): ").strip().lower()
        if not raw:
            return default
        if raw in {"y", "yes", "1", "true", "on"}:
            return True
        if raw in {"n", "no", "0", "false", "off"}:
            return False
        print("  Enter y or n.")


def _prompt_int(*, step: str, label: str, default: int = 0) -> int:
    while True:
        raw = input(f"{step} {label} (default: {default}): ").strip()
        if not raw:
            return default
        try:
            value = int(raw)
        except ValueError:
            print("  Enter a whole number.")
            continue
        if value < 0:
            print("  Enter 0 or a positive number.")
            continue
        return value


def _interactive_wizard_values(
    *,
    target_dir: Path,
    framework: str,
    mode: str,
    llm_provider: str,
    llm_model: str,
    llm_base_url: str,
    l2: bool | None,
    l3: bool,
    token_budget: int,
) -> dict[str, Any]:
    _print_wizard_header(target_dir)
    _print_wizard_boundary_notes()
    print("Step 1/5 - Select the agent framework.")
    framework_choices = sorted(FRAMEWORK_INITIALIZERS.keys())
    provider_default = "" if llm_provider == "none" else llm_provider
    provider_choices = ["none", "openai", "anthropic"]
    if provider_default in {"", "none"}:
        provider_prompt_default = "none"
    else:
        provider_prompt_default = provider_default

    selected_framework = _prompt_choice(
        step="Step 1/5",
        label="Agent framework",
        choices=framework_choices,
        default=framework if framework in framework_choices else "codex",
    )
    print("Step 2/5 - Choose the security mode.")
    selected_mode = _prompt_choice(
        step="Step 2/5",
        label="Security mode",
        choices=["normal", "strict", "permissive", "benchmark"],
        default=mode,
    )
    print("Step 3/5 - Configure optional LLM analysis.")
    selected_provider = _prompt_choice(
        step="Step 3/5",
        label="LLM provider for L2/L3",
        choices=provider_choices,
        default=provider_prompt_default,
    )
    if selected_provider == "none":
        selected_provider = ""
        selected_model = ""
        selected_base_url = ""
        selected_l2 = False
        selected_l3 = False
        print("Step 4/5 - Choose deeper review features.")
        print("  No LLM provider selected; L2 and L3 review are disabled.")
    else:
        selected_model = _prompt_text(
            step="Step 3/5",
            label="LLM model",
            default=llm_model,
        )
        selected_base_url = _prompt_text(
            step="Step 3/5",
            label="OpenAI-compatible base URL",
            default=llm_base_url,
        )
        print("Step 4/5 - Choose deeper review features.")
        print("  L2/L3 can improve semantic detection, but they add model cost and latency.")
        selected_l2 = _prompt_bool(
            step="Step 4/5",
            label="Enable L2 semantic analysis",
            default=True if l2 is None else bool(l2),
        )
        selected_l3 = _prompt_bool(
            step="Step 4/5",
            label="Enable L3 advisory review",
            default=bool(l3),
        )
    print("Step 5/5 - Set budget guardrails.")
    selected_token_budget = _prompt_int(
        step="Step 5/5",
        label="Daily LLM token budget, 0 disables budget enforcement",
        default=int(token_budget),
    )
    print()
    return {
        "framework": selected_framework,
        "mode": selected_mode,
        "llm_provider": selected_provider,
        "llm_model": selected_model,
        "llm_base_url": selected_base_url,
        "l2": selected_l2,
        "l3": selected_l3,
        "token_budget": selected_token_budget,
    }


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
    interactive: bool | None = None,
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
    stdin_is_tty = bool(getattr(sys.stdin, "isatty", lambda: False)())
    use_interactive = False
    if not non_interactive:
        use_interactive = bool(interactive) or (interactive is None and stdin_is_tty)
    if use_interactive and not stdin_is_tty:
        raise RuntimeError(
            "Interactive wizard requires a TTY. Re-run in a terminal, or use "
            "`clawsentry config wizard --non-interactive` with explicit flags."
        )
    elif not non_interactive and not use_interactive:
        if os.environ.get("CI") or os.environ.get("NO_COLOR"):
            print("Non-interactive/CI-safe wizard path: using supplied/default values.")
        else:
            print("Interactive wizard is not available in this terminal; using supplied/default values.")

    if mode not in {"normal", "strict", "permissive", "benchmark"}:
        raise ValueError("mode must be normal, strict, permissive, or benchmark")
    if llm_provider == "none":
        llm_provider = ""
    if llm_provider and llm_provider not in {"openai", "anthropic"}:
        raise ValueError("llm_provider must be openai, anthropic, none, or empty")

    if use_interactive:
        values = _interactive_wizard_values(
            target_dir=target_dir,
            framework=framework,
            mode=mode,
            llm_provider=llm_provider,
            llm_model=llm_model,
            llm_base_url=llm_base_url,
            l2=l2,
            l3=l3,
            token_budget=token_budget,
        )
        framework = values["framework"]
        mode = values["mode"]
        llm_provider = values["llm_provider"]
        llm_model = values["llm_model"]
        llm_base_url = values["llm_base_url"]
        l2 = values["l2"]
        l3 = values["l3"]
        token_budget = values["token_budget"]

    if not llm_provider:
        l2 = False
        l3 = False
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
    print(f"Wrote ClawSentry project config ({mode} mode).")
    if llm_provider:
        print("LLM API key is read from CS_LLM_API_KEY; secrets were not written to config.")
    print("Framework integration is selected for the next command; this wizard does not install hooks.")
    print("Next: run `clawsentry start --open-browser`.")
    print("Next: run `clawsentry config show --effective` to verify resolved values.")


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
