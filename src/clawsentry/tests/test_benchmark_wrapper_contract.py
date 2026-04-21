"""Contract checks for local benchmark wrapper safety behavior."""

from __future__ import annotations

from pathlib import Path

import pytest


def test_skills_safety_wrapper_strips_proxy_env_from_real_runs() -> None:
    script_path = Path("benchmarks/scripts/skills_safety_bench_codex.sh")
    if not script_path.exists():
        pytest.skip("internal benchmark wrapper is not synced to the public repository")
    script = script_path.read_text(encoding="utf-8")

    assert "SSB_STRIP_PROXY_ENV" in script
    assert "SANITIZED_DOCKER_CONFIG" in script
    assert "sanitize_envrc_without_proxy" in script
    assert "DOCKER_CONFIG" in script
    assert "--envrc" in script
