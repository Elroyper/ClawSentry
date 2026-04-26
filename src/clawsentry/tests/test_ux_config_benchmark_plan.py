"""Plan-backed tests for UX/config/token-budget/benchmark rollout."""

from __future__ import annotations

from pathlib import Path

import pytest

from clawsentry.cli.benchmark_command import run_benchmark_env, run_benchmark_enable, run_benchmark_disable
from clawsentry.cli.config_command import run_config_init, run_config_show, run_config_set, run_config_wizard
from clawsentry.cli.service_command import run_service_validate
from clawsentry.gateway.detection_config import DetectionConfig, build_detection_config_from_env
from clawsentry.gateway.metrics import LLMBudgetTracker, MetricsCollector
from clawsentry.gateway.project_config import load_project_config, resolve_effective_config


def test_default_detection_config_uses_bounded_large_timeouts_and_no_token_budget():
    cfg = DetectionConfig()
    assert cfg.mode == "normal"
    assert cfg.l2_budget_ms == 60_000.0
    assert cfg.l3_budget_ms == 300_000.0
    assert cfg.hard_timeout_ms == 600_000.0
    assert cfg.defer_timeout_s == 86_400.0
    assert cfg.defer_max_pending == 0
    assert cfg.llm_token_budget_enabled is False
    assert cfg.llm_daily_token_budget == 0
    assert cfg.llm_token_budget_scope == "total"


def test_canonical_timeout_env_wins_over_legacy_budget_alias(monkeypatch):
    monkeypatch.setenv("CS_L2_BUDGET_MS", "5000")
    monkeypatch.setenv("CS_L2_TIMEOUT_MS", "70000")
    cfg = build_detection_config_from_env()
    assert cfg.l2_budget_ms == 70_000.0


def test_token_budget_env_validation_disables_zero_limit(monkeypatch, caplog):
    monkeypatch.setenv("CS_LLM_TOKEN_BUDGET_ENABLED", "true")
    monkeypatch.setenv("CS_LLM_DAILY_TOKEN_BUDGET", "0")
    cfg = build_detection_config_from_env()
    assert cfg.llm_token_budget_enabled is False
    assert cfg.llm_daily_token_budget == 0
    assert "token budget" in caplog.text.lower()


def test_project_config_canonical_sections_resolve_into_detection_config(tmp_path):
    (tmp_path / ".clawsentry.toml").write_text('''\
[project]
mode = "benchmark"
preset = "high"

[budgets]
llm_token_budget_enabled = true
llm_daily_token_budget = 1234
llm_token_budget_scope = "input"
l2_timeout_ms = 61000

[defer]
timeout_s = 42
max_pending = 0
''')
    cfg = load_project_config(tmp_path)
    dc = cfg.to_detection_config()
    assert cfg.mode == "benchmark"
    assert dc.mode == "benchmark"
    assert dc.llm_token_budget_enabled is True
    assert dc.llm_daily_token_budget == 1234
    assert dc.llm_token_budget_scope == "input"
    assert dc.l2_budget_ms == 61_000.0
    assert dc.defer_timeout_s == 42.0


def test_effective_config_reports_sources_and_redacts_secret(tmp_path, monkeypatch):
    (tmp_path / ".clawsentry.toml").write_text('''\
[project]
preset = "low"

[llm]
provider = "openai"
model = "gpt-test"
api_key_env = "CS_LLM_API_KEY"
''')
    monkeypatch.setenv("CS_LLM_API_KEY", "sk-1234567890secret")
    monkeypatch.setenv("CS_L2_TIMEOUT_MS", "65000")
    eff = resolve_effective_config(tmp_path)
    assert eff.values["llm.provider"] == "openai"
    assert eff.sources["llm.provider"] == "project"
    assert eff.sources["budgets.l2_timeout_ms"] == "env"
    assert eff.values["llm.api_key"] != "sk-1234567890secret"
    assert eff.values["llm.api_key"].startswith("sk-1")


def test_metrics_token_budget_uses_actual_tokens_not_estimated_cost():
    tracker = LLMBudgetTracker(enabled=True, limit_tokens=10, scope="total")
    mc = MetricsCollector(enabled=False, budget_tracker=tracker)
    mc.record_llm_call(provider="expensive", tier="L2", status="ok", input_tokens=4, output_tokens=5)
    assert tracker.can_spend() is True
    mc.record_llm_call(provider="expensive", tier="L2", status="ok", input_tokens=0, output_tokens=1)
    assert tracker.can_spend() is False
    snap = tracker.snapshot()
    assert snap["used_total_tokens"] == 10
    assert snap["exhausted"] is True


def test_metrics_missing_usage_tracks_unknown_without_exhausting():
    tracker = LLMBudgetTracker(enabled=True, limit_tokens=1, scope="total")
    mc = MetricsCollector(enabled=False, budget_tracker=tracker)
    mc.record_llm_call(provider="openai", tier="L2", status="ok", input_tokens=0, output_tokens=0)
    snap = tracker.snapshot()
    assert snap["unknown_usage_calls"] == 1
    assert snap["used_total_tokens"] == 0
    assert snap["exhausted"] is False


def test_config_init_show_set_and_noninteractive_wizard(tmp_path, capsys):
    run_config_init(target_dir=tmp_path, force=True)
    text = (tmp_path / ".clawsentry.toml").read_text()
    assert "[llm]" in text
    assert "llm_token_budget_enabled" in text
    run_config_set(target_dir=tmp_path, key="project.mode", value="benchmark")
    run_config_wizard(
        target_dir=tmp_path,
        non_interactive=True,
        framework="codex",
        mode="benchmark",
        llm_provider="openai",
        llm_model="gpt-4o-mini",
        l3=True,
        token_budget=500,
        force=True,
    )
    run_config_show(target_dir=tmp_path, effective=True)
    out = capsys.readouterr().out
    assert "project.mode" in out
    assert "benchmark" in out
    assert "llm.provider" in out
    assert "CS_LLM_API_KEY" in out


def test_benchmark_env_enable_disable_are_idempotent_and_temp_home_safe(tmp_path):
    active_home = Path.home() / ".codex"
    with pytest.raises(ValueError):
        run_benchmark_enable(target_dir=tmp_path, framework="codex", codex_home=active_home)
    run_benchmark_env(framework="codex", mode="guarded", output_path=tmp_path / ".env.clawsentry.benchmark")
    codex_home = tmp_path / "codex-home"
    run_benchmark_enable(target_dir=tmp_path, framework="codex", codex_home=codex_home)
    first = (codex_home / "hooks.json").read_text()
    run_benchmark_enable(target_dir=tmp_path, framework="codex", codex_home=codex_home)
    assert (codex_home / "hooks.json").read_text() == first
    run_benchmark_disable(target_dir=tmp_path, framework="codex", codex_home=codex_home)
    assert not (codex_home / "hooks.json").exists()


def test_service_validate_reports_canonical_env_and_redacts_secrets(tmp_path, capsys):
    env_file = tmp_path / "gateway.env"
    env_file.write_text("CS_AUTH_TOKEN=super-secret-token-value\nCS_LLM_DAILY_TOKEN_BUDGET=100\n")
    code = run_service_validate(env_file=env_file)
    out = capsys.readouterr().out
    assert code == 0
    assert "CS_LLM_DAILY_TOKEN_BUDGET" in out
    assert "super-secret-token-value" not in out
    assert "supe" in out
