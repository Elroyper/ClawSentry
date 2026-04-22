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


def test_skills_safety_wrapper_guards_harbor_codex_setup_apt() -> None:
    script_path = Path("benchmarks/scripts/skills_safety_bench_codex.sh")
    guard_path = Path("benchmarks/scripts/harbor_codex_setup_guard.py")
    if not script_path.exists():
        pytest.skip("internal benchmark wrapper is not synced to the public repository")

    script = script_path.read_text(encoding="utf-8")
    assert "SSB_GUARD_HARBOR_CODEX_SETUP" in script
    assert "install_guarded_harbor_shim" in script
    assert "patch_upstream_codex_task_staging" in script
    assert "harbor_codex_setup_guard.py" in script
    assert "SSB_HARBOR_BIN" in script
    assert "SSB_CODEX_FORCE_API_KEY" in script
    assert "SSB_CODEX_AUTH_JSON" in script
    assert "write_codex_auth_json_from_envrc" in script
    assert "CODEX_AUTH_JSON_PATH" in script
    assert "CODEX_FORCE_API_KEY" in script

    assert guard_path.exists()
    guard = guard_path.read_text(encoding="utf-8")
    assert "command -v curl" in guard
    assert "command -v rg" in guard
    assert "apt-get install -y --no-install-recommends curl ripgrep" in guard
    assert "OPENAI_API_KEY" in guard
    assert "json.load" in guard
    assert "HARBOR_INHERIT_ENV" in guard
    assert "DockerEnvironment.exec" in guard
