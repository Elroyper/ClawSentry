"""Tests for benchmark-mode wrapper CLI helpers."""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

import pytest

from clawsentry.cli.benchmark_command import (
    BENCHMARK_ENV_FILE_NAME,
    render_benchmark_env,
    run_benchmark_disable,
    run_benchmark_enable,
    run_benchmark_run,
)
from clawsentry.gateway.config.detection_config import build_detection_config_from_env


def _count_clawsentry_hook_entries(hooks_path: Path) -> int:
    payload = json.loads(hooks_path.read_text(encoding="utf-8"))
    count = 0
    for entries in payload.get("hooks", {}).values():
        for entry in entries:
            if "clawsentry harness --framework codex" in json.dumps(entry):
                count += 1
    return count


def test_benchmark_env_declares_explicit_no_human_mode() -> None:
    text = render_benchmark_env(framework="codex", mode="guarded")

    assert "CS_MODE=benchmark" in text
    assert "CS_BENCHMARK_PROFILE=guarded" in text
    assert "CS_BENCHMARK_AUTO_RESOLVE_DEFER=true" in text
    assert "CS_BENCHMARK_L2_AUTO_ENABLED=false" in text
    assert "CS_BENCHMARK_MEDIUM_L2_AUTO_ENABLED=false" in text
    assert "CS_BENCHMARK_KEY_DOMAIN_L2_AUTO_ENABLED=true" in text
    assert "CS_DEFER_BRIDGE_ENABLED=false" in text
    assert "CS_DEFER_TIMEOUT_ACTION=block" in text
    assert "CS_DEFER_TIMEOUT_S=1" in text
    assert "CS_FRAMEWORK=codex" in text
    assert "CS_CODEX_PRETOOL_SYNC_ALL=true" in text
    env = dict(line.split("=", 1) for line in text.splitlines() if line and not line.startswith("#"))
    with pytest.MonkeyPatch.context() as mp:
        for key, value in env.items():
            mp.setenv(key, value)
        assert build_detection_config_from_env().mode == "benchmark"


def test_benchmark_enable_is_idempotent_for_codex_temp_home(tmp_path: Path) -> None:
    codex_home = tmp_path / "codex-home"

    assert run_benchmark_enable(
        target_dir=tmp_path,
        framework="codex",
        codex_home=codex_home,
    ) == 0
    assert run_benchmark_enable(
        target_dir=tmp_path,
        framework="codex",
        codex_home=codex_home,
    ) == 0

    env_path = tmp_path / BENCHMARK_ENV_FILE_NAME
    assert env_path.exists()
    assert "CS_MODE=benchmark" in env_path.read_text(encoding="utf-8")
    config_text = (codex_home / "config.toml").read_text(encoding="utf-8")
    assert "[features]" in config_text
    assert "hooks = true" in config_text
    assert "codex_hooks = true" not in config_text
    config = tomllib.loads(config_text)
    assert len(config["hooks"]["state"]) == 11
    assert _count_clawsentry_hook_entries(codex_home / "hooks.json") == 11
    hooks = json.loads((codex_home / "hooks.json").read_text(encoding="utf-8"))["hooks"]
    non_bash_pretool = next(
        entry for entry in hooks["PreToolUse"]
        if entry.get("matcher") == "apply_patch|Edit|Write|mcp__.*"
    )
    assert non_bash_pretool["hooks"][0]["command"] == "clawsentry harness --framework codex"


def test_benchmark_enable_rejects_active_user_codex_home(tmp_path: Path) -> None:
    active_user_home = Path.home() / ".codex"

    with pytest.raises(ValueError, match="Refusing to modify active"):
        run_benchmark_enable(
            target_dir=tmp_path,
            framework="codex",
            codex_home=active_user_home,
        )
    assert not (tmp_path / BENCHMARK_ENV_FILE_NAME).exists()


def test_benchmark_disable_removes_benchmark_env_and_codex_hooks(tmp_path: Path) -> None:
    codex_home = tmp_path / "codex-home"
    assert run_benchmark_enable(
        target_dir=tmp_path,
        framework="codex",
        codex_home=codex_home,
    ) == 0

    assert run_benchmark_disable(
        target_dir=tmp_path,
        framework="codex",
        codex_home=codex_home,
    ) == 0

    assert not (tmp_path / BENCHMARK_ENV_FILE_NAME).exists()
    assert not (codex_home / "hooks.json").exists()
    config = tomllib.loads((codex_home / "config.toml").read_text(encoding="utf-8"))
    assert config.get("hooks", {}).get("state", {}) == {}


def test_benchmark_run_uses_temp_codex_home_and_passes_env(tmp_path: Path, monkeypatch) -> None:
    marker = tmp_path / "marker.txt"
    monkeypatch.setenv("CS_BENCHMARK_L2_AUTO_ENABLED", "true")

    assert run_benchmark_run(
        target_dir=tmp_path,
        framework="codex",
        command=[
            "--",
            "python",
            "-c",
            (
                "import os, pathlib; "
                f"pathlib.Path({str(marker)!r}).write_text("
                "os.environ['CS_MODE'] + '|' + "
                "os.environ['CODEX_HOME'] + '|' + "
                "os.environ['CS_BENCHMARK_L2_AUTO_ENABLED'] + '|' + "
                "os.environ['CS_BENCHMARK_MEDIUM_L2_AUTO_ENABLED'] + '|' + "
                "os.environ['CS_BENCHMARK_KEY_DOMAIN_L2_AUTO_ENABLED'])"
            ),
        ],
    ) == 0

    mode, codex_home, legacy_l2, medium_l2, key_domain_l2 = marker.read_text(encoding="utf-8").split("|", 4)
    assert mode == "benchmark"
    assert codex_home != str(Path.home() / ".codex")
    assert legacy_l2 == "false"
    assert medium_l2 == "false"
    assert key_domain_l2 == "true"


def test_benchmark_run_cleans_temp_env_by_default(tmp_path: Path) -> None:
    marker = tmp_path / "ran.txt"

    assert run_benchmark_run(
        target_dir=tmp_path,
        framework="codex",
        command=["--", "python", "-c", f"from pathlib import Path; Path({str(marker)!r}).write_text('ok')"],
    ) == 0

    assert marker.read_text(encoding="utf-8") == "ok"
    assert not (tmp_path / BENCHMARK_ENV_FILE_NAME).exists()


def test_benchmark_run_restores_existing_benchmark_env(tmp_path: Path) -> None:
    env_path = tmp_path / BENCHMARK_ENV_FILE_NAME
    original = "CS_MODE=normal\n"
    env_path.write_text(original, encoding="utf-8")

    assert run_benchmark_run(
        target_dir=tmp_path,
        framework="codex",
        command=["--", "python", "-c", "print('ok')"],
    ) == 0

    assert env_path.read_text(encoding="utf-8") == original
