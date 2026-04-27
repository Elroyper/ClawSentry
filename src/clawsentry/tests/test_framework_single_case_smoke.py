"""Tests for the multi-framework single-case smoke runner."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]


def _load_smoke_script():
    script_path = REPO_ROOT / "benchmarks" / "scripts" / "framework_single_case_smoke.py"
    assert script_path.exists()
    spec = importlib.util.spec_from_file_location("framework_single_case_smoke", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_framework_single_case_smoke_runs_all_framework_paths(tmp_path: Path) -> None:
    module = _load_smoke_script()

    summary = module.run_smoke(
        result_dir=tmp_path,
        case_command="rm -rf /tmp/clawsentry-single-case-target",
    )

    expected_frameworks = {
        "claude-code",
        "codex",
        "gemini-cli",
        "a3s-code",
        "openclaw",
    }
    assert summary["frameworks"] == sorted(expected_frameworks)
    assert summary["passed"] == 5
    assert summary["failed"] == 0
    assert summary["case"]["command"] == "rm -rf /tmp/clawsentry-single-case-target"

    rows = summary["results"]
    assert {row["framework"] for row in rows} == expected_frameworks
    assert all(row["status"] == "passed" for row in rows)
    assert all(row["decision"] in {"block", "defer", "deny"} for row in rows)
    assert all(row["event_count"] >= 1 for row in rows)
    assert {row["source_framework"] for row in rows} == expected_frameworks

    persisted = json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))
    assert persisted == summary
    assert (tmp_path / "summary.md").exists()
