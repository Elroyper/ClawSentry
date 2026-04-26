"""Contract tests for the 2026-04-26 UX/config/docs/benchmark plan.

These tests encode the public acceptance criteria from
``.omx/plans/2026-04-26-clawsentry-ux-config-docs-benchmark-consensus.md``:
effective configuration sources, token-based LLM budgets, guided config UX,
deployment templates, and explicit no-human benchmark mode.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]


def _cli_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = os.environ.copy()
    src_path = str(REPO_ROOT / "src")
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = src_path if not existing else f"{src_path}:{existing}"
    if extra:
        env.update(extra)
    return env


def _run_clawsentry(
    args: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "clawsentry", *args],
        cwd=cwd,
        env=_cli_env(env),
        capture_output=True,
        text=True,
        timeout=15,
    )


def test_default_detection_config_uses_bounded_large_ux_defaults() -> None:
    """Fresh defaults should be non-restrictive but still bounded."""
    from clawsentry.gateway.detection_config import DetectionConfig

    cfg = DetectionConfig()

    assert cfg.mode == "normal"
    assert cfg.l2_timeout_ms == 60_000
    assert cfg.l3_timeout_ms == 300_000
    assert cfg.hard_timeout_ms == 600_000
    assert cfg.defer_timeout_s == 86_400
    assert cfg.defer_max_pending == 0
    assert cfg.llm_token_budget_enabled is False
    assert cfg.llm_daily_token_budget == 0
    assert cfg.llm_token_budget_scope == "total"


def test_canonical_env_names_win_over_legacy_aliases(monkeypatch) -> None:
    """Canonical env vars must override old aliases regardless of load order."""
    from clawsentry.gateway.detection_config import build_detection_config_from_env

    monkeypatch.setenv("CS_L2_BUDGET_MS", "5000")
    monkeypatch.setenv("CS_L2_TIMEOUT_MS", "60000")
    monkeypatch.setenv("CS_L3_BUDGET_MS", "5000")
    monkeypatch.setenv("CS_L3_TIMEOUT_MS", "300000")
    monkeypatch.setenv("CS_LLM_DAILY_BUDGET_USD", "999")
    monkeypatch.setenv("CS_LLM_TOKEN_BUDGET_ENABLED", "true")
    monkeypatch.setenv("CS_LLM_DAILY_TOKEN_BUDGET", "12345")

    cfg = build_detection_config_from_env()

    assert cfg.l2_timeout_ms == 60_000
    assert cfg.l3_timeout_ms == 300_000
    assert cfg.llm_token_budget_enabled is True
    assert cfg.llm_daily_token_budget == 12_345
    assert cfg.llm_daily_budget_usd == 0.0


def test_project_config_loads_canonical_sections_into_detection_config(
    tmp_path: Path,
) -> None:
    """Project TOML should expose canonical sections, not just presets."""
    from clawsentry.gateway.project_config import load_project_config

    (tmp_path / ".clawsentry.toml").write_text(
        "\n".join(
            [
                "[project]",
                'mode = "benchmark"',
                'preset = "medium"',
                "",
                "[llm]",
                'provider = "openai"',
                'api_key_env = "CS_LLM_API_KEY"',
                'model = "gpt-4o-mini"',
                "",
                "[features]",
                "l2 = true",
                "l3 = true",
                "",
                "[budgets]",
                "llm_token_budget_enabled = true",
                "llm_daily_token_budget = 1000",
                'llm_token_budget_scope = "output"',
                "l2_timeout_ms = 61000",
                "l3_timeout_ms = 301000",
                "hard_timeout_ms = 601000",
                "",
                "[benchmark]",
                "auto_resolve_defer = true",
                'defer_action = "block"',
            ]
        )
    )

    project_cfg = load_project_config(tmp_path)
    detection_cfg = project_cfg.to_detection_config()

    assert project_cfg.mode == "benchmark"
    assert project_cfg.llm.provider == "openai"
    assert project_cfg.features.l2 is True
    assert project_cfg.features.l3 is True
    assert detection_cfg.mode == "benchmark"
    assert detection_cfg.llm_token_budget_enabled is True
    assert detection_cfg.llm_daily_token_budget == 1000
    assert detection_cfg.llm_token_budget_scope == "output"
    assert detection_cfg.l2_timeout_ms == 61_000
    assert detection_cfg.l3_timeout_ms == 301_000
    assert detection_cfg.hard_timeout_ms == 601_000


def test_config_cli_exposes_wizard_and_effective_config_help(tmp_path: Path) -> None:
    """The public CLI must include guided setup and effective config output."""
    show_help = _run_clawsentry(["config", "show", "--help"], cwd=tmp_path)
    assert show_help.returncode == 0, show_help.stderr
    assert "--effective" in show_help.stdout

    wizard_help = _run_clawsentry(["config", "wizard", "--help"], cwd=tmp_path)
    assert wizard_help.returncode == 0, wizard_help.stderr
    assert "--non-interactive" in wizard_help.stdout
    assert "--llm-provider" in wizard_help.stdout
    assert "--token-budget" in wizard_help.stdout


def test_config_show_effective_redacts_secrets_and_reports_sources(
    tmp_path: Path,
) -> None:
    """Effective config output should be safe to paste into support tickets."""
    (tmp_path / ".clawsentry.toml").write_text(
        "\n".join(
            [
                "[project]",
                'mode = "normal"',
                "",
                "[llm]",
                'provider = "openai"',
                'api_key_env = "CS_LLM_API_KEY"',
                'model = "gpt-4o-mini"',
            ]
        )
    )

    result = _run_clawsentry(
        ["config", "show", "--effective"],
        cwd=tmp_path,
        env={
            "CS_LLM_API_KEY": "sk-test-secret-value",
            "CS_L2_TIMEOUT_MS": "60000",
        },
    )

    assert result.returncode == 0, result.stderr
    assert "sk-test-secret-value" not in result.stdout
    assert "sk-..." in result.stdout or "redacted" in result.stdout.lower()
    assert "source" in result.stdout.lower()
    assert "CS_L2_TIMEOUT_MS" in result.stdout
    assert "env" in result.stdout.lower()


def test_token_budget_tracker_snapshot_uses_actual_tokens_not_usd() -> None:
    """Budget enforcement must consume provider-reported token counts."""
    from clawsentry.gateway.metrics import LLMBudgetTracker

    tracker = LLMBudgetTracker(
        enabled=True,
        limit_tokens=10,
        scope="total",
        source="env",
    )

    assert tracker.record_usage(input_tokens=4, output_tokens=5) is False
    snapshot = tracker.snapshot()
    assert snapshot == {
        "enabled": True,
        "scope": "total",
        "limit_tokens": 10,
        "used_input_tokens": 4,
        "used_output_tokens": 5,
        "used_total_tokens": 9,
        "remaining_tokens": 1,
        "exhausted": False,
        "unknown_usage_calls": 0,
        "last_reset_utc": snapshot["last_reset_utc"],
        "source": "env",
    }

    assert tracker.record_usage(input_tokens=0, output_tokens=1) is True
    assert tracker.snapshot()["exhausted"] is True


def test_unknown_llm_usage_is_tracked_without_fabricated_exhaustion() -> None:
    """Calls without provider usage should never spend estimated USD tokens."""
    from clawsentry.gateway.metrics import LLMBudgetTracker

    tracker = LLMBudgetTracker(enabled=True, limit_tokens=1, scope="total")
    assert tracker.record_unknown_usage() is False

    snapshot = tracker.snapshot()
    assert snapshot["unknown_usage_calls"] == 1
    assert snapshot["used_total_tokens"] == 0
    assert snapshot["remaining_tokens"] == 1
    assert snapshot["exhausted"] is False


def test_benchmark_cli_requires_temp_codex_home_and_exposes_run_wrapper(
    tmp_path: Path,
) -> None:
    """Benchmark UX should be explicit and safe for Codex hook mutation."""
    help_result = _run_clawsentry(["benchmark", "--help"], cwd=tmp_path)
    assert help_result.returncode == 0, help_result.stderr
    assert "enable" in help_result.stdout
    assert "disable" in help_result.stdout
    assert "run" in help_result.stdout

    unsafe = _run_clawsentry(
        [
            "benchmark",
            "enable",
            "--dir",
            str(tmp_path),
            "--framework",
            "codex",
            "--codex-home",
            str(Path.home() / ".codex"),
        ],
        cwd=tmp_path,
    )
    assert unsafe.returncode != 0
    assert "active ~/.codex" in (unsafe.stderr + unsafe.stdout)
    assert "--force-user-home" in (unsafe.stderr + unsafe.stdout)


def test_deployment_templates_emit_canonical_config_names() -> None:
    """Systemd and Docker samples should stop recommending legacy budget names."""
    sources = [
        REPO_ROOT / "systemd" / "gateway.env.example",
        REPO_ROOT / "docker" / ".env.example",
    ]

    for path in sources:
        text = path.read_text(encoding="utf-8")
        assert "CS_L2_TIMEOUT_MS" in text
        assert "CS_L3_TIMEOUT_MS" in text
        assert "CS_LLM_TOKEN_BUDGET_ENABLED" in text
        assert "CS_LLM_DAILY_TOKEN_BUDGET" in text
        assert "CS_LLM_DAILY_BUDGET_USD" not in text
        assert "CS_L2_BUDGET_MS" not in text


def test_docs_nav_contains_progressive_config_and_benchmark_journeys() -> None:
    """Docs IA should expose quickstart, config templates, deployment, benchmarks."""
    mkdocs = (REPO_ROOT / "mkdocs.yml").read_text(encoding="utf-8")

    expected_pages = [
        "getting-started/quickstart.md",
        "configuration/configuration-overview.md",
        "configuration/templates.md",
        "configuration/llm-config.md",
        "operations/deployment.md",
        "operations/benchmark-mode.md",
    ]
    for page in expected_pages:
        assert page in mkdocs
        assert (REPO_ROOT / "site-docs" / page).is_file()
