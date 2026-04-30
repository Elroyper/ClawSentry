"""Tests for the manual L3 advisory provider smoke helper."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from clawsentry.devtools.l3_advisory_provider_smoke import (
    _smoke_environ,
    render_validation_report,
    run_smoke,
)


def test_l3_advisory_provider_smoke_degrades_without_llm_config() -> None:
    result = run_smoke(environ={})

    assert result.status == "passed"
    assert result.provider == ""
    assert result.model == ""
    assert result.review["review_runner"] == "llm_provider"
    assert result.review["l3_state"] == "degraded"
    assert result.review["l3_reason_code"] == "provider_disabled"
    assert result.evidence["canonical_decision_mutated"] is False


def test_l3_advisory_provider_smoke_runs_guarded_provider_path() -> None:
    result = run_smoke(
        environ={
            "CS_L3_ADVISORY_PROVIDER_ENABLED": "true",
            "CS_L3_ADVISORY_PROVIDER": "openai",
            "CS_L3_ADVISORY_MODEL": "gpt-advisory-smoke",
            "OPENAI_API_KEY": "sk-test-advisory-smoke",
        }
    )

    assert result.status == "passed"
    assert result.provider == "openai"
    assert result.model == "gpt-advisory-smoke"
    assert result.snapshot["advisory_only"] is True
    assert result.job["runner"] == "llm_provider"
    assert result.job["job_state"] == "completed"
    assert result.review["review_runner"] == "llm_provider"
    assert result.review["worker_backend"] == "openai"
    assert result.review["advisory_only"] is True
    assert result.review["l3_state"] == "degraded"
    assert result.review["l3_reason_code"] == "provider_not_implemented"
    assert result.evidence["network_default"] == "no background scheduler; explicit worker call only"


def test_l3_advisory_provider_smoke_can_require_completed_review() -> None:
    result = run_smoke(
        environ={
            "CS_L3_ADVISORY_PROVIDER_ENABLED": "true",
            "CS_L3_ADVISORY_PROVIDER": "openai",
            "CS_L3_ADVISORY_MODEL": "gpt-advisory-smoke",
            "OPENAI_API_KEY": "sk-test-advisory-smoke",
        },
        require_completed=True,
    )

    assert result.status == "failed"
    assert result.review["l3_state"] == "degraded"
    assert "completed" in str(result.failure_reason)


def test_l3_advisory_provider_smoke_report_redacts_api_keys() -> None:
    result = run_smoke(
        environ={
            "CS_L3_ADVISORY_PROVIDER_ENABLED": "true",
            "CS_L3_ADVISORY_PROVIDER": "anthropic",
            "CS_L3_ADVISORY_MODEL": "claude-advisory-smoke",
            "ANTHROPIC_API_KEY": "sk-ant-secret-value",
        }
    )

    report = render_validation_report(result)

    assert "sk-ant-secret-value" not in report
    assert "claude-advisory-smoke" in report
    assert "provider_not_implemented" in report
    assert json.dumps(result.evidence, sort_keys=True) != "{}"


def test_l3_advisory_provider_smoke_strips_proxy_env_by_default() -> None:
    env = _smoke_environ(
        {
            "HTTPS_PROXY": "socks5://127.0.0.1:9999",
            "http_proxy": "socks5://127.0.0.1:9999",
            "CS_LLM_PROVIDER": "openai",
        }
    )

    assert "HTTPS_PROXY" not in env
    assert "http_proxy" not in env
    assert env["CS_LLM_PROVIDER"] == "openai"


def test_l3_advisory_provider_smoke_script_outputs_degraded_json_without_config() -> None:
    repo_root = Path(__file__).parents[3]
    script_path = repo_root / "scripts" / "run_l3_advisory_provider_smoke.py"
    if not script_path.exists():
        pytest.skip("dev checkout smoke script is not synced to the public repository")
    env = os.environ.copy()
    for key in list(env):
        if key.startswith("CS_L3_ADVISORY_") or key.startswith("CS_LLM_") or key in {"OPENAI_API_KEY", "ANTHROPIC_API_KEY"}:
            env.pop(key, None)

    proc = subprocess.run(
        [
            sys.executable,
            str(script_path),
            "--json",
        ],
        cwd=repo_root,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert proc.returncode == 0
    payload = json.loads(proc.stdout)
    assert payload["status"] == "passed"
    assert payload["review"]["l3_state"] == "degraded"
    assert payload["review"]["l3_reason_code"] == "provider_disabled"


def test_l3_advisory_provider_real_network_smoke_is_explicit_opt_in(tmp_path) -> None:
    if os.environ.get("CS_L3_ADVISORY_RUN_REAL_SMOKE", "").strip().lower() not in {
        "1",
        "true",
        "yes",
        "on",
    }:
        pytest.skip("Set CS_L3_ADVISORY_RUN_REAL_SMOKE=true to run real provider smoke")

    required = [
        "CS_LLM_PROVIDER",
        "CS_LLM_MODEL",
    ]
    missing = [key for key in required if not os.environ.get(key, "").strip()]
    provider = os.environ.get("CS_LLM_PROVIDER", "").strip().lower()
    if provider == "openai" and not (os.environ.get("CS_LLM_API_KEY") or os.environ.get("OPENAI_API_KEY")):
        missing.append("OPENAI_API_KEY or CS_LLM_API_KEY")
    if provider == "anthropic" and not (os.environ.get("CS_LLM_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")):
        missing.append("ANTHROPIC_API_KEY or CS_LLM_API_KEY")
    if provider not in {"openai", "anthropic"}:
        missing.append("CS_LLM_PROVIDER=openai|anthropic")
    if missing:
        pytest.skip(f"Missing real provider smoke env: {', '.join(missing)}")

    repo_root = Path(__file__).parents[3]
    report_path = tmp_path / "l3-advisory-real-provider-smoke.md"
    env = os.environ.copy()

    proc = subprocess.run(
        [
            sys.executable,
            str(repo_root / "scripts" / "run_l3_advisory_provider_smoke.py"),
            "--json",
            "--require-completed",
            "--output-report",
            str(report_path),
        ],
        cwd=repo_root,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert proc.returncode == 0, proc.stderr or proc.stdout
    payload = json.loads(proc.stdout)
    assert payload["status"] == "passed"
    assert payload["review"]["l3_state"] == "completed"
    assert payload["review"]["advisory_only"] is True
    assert report_path.exists()
