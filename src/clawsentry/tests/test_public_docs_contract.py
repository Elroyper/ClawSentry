"""Contract tests for public docs and release guardrails."""

from __future__ import annotations

import json
from pathlib import Path



REPO_ROOT = Path(__file__).resolve().parents[3]
ENV_VARS_DOC = REPO_ROOT / "site-docs" / "configuration" / "env-vars.md"
RELEASE_CHECKLIST = REPO_ROOT / "docs" / "management" / "RELEASE_CHECKLIST.md"
RULES_CI_EXAMPLE = REPO_ROOT / "examples" / "ci" / "rules-governance.yml"


def test_env_vars_doc_mentions_public_l3_trigger_controls() -> None:
    source = ENV_VARS_DOC.read_text(encoding="utf-8")

    assert "CS_L3_ROUTING_MODE" in source
    assert "CS_L3_TRIGGER_PROFILE" in source
    assert "CS_L3_BUDGET_TUNING_ENABLED" in source


def test_release_checklist_requires_public_surface_verification() -> None:
    if not RELEASE_CHECKLIST.exists():
        assert not (REPO_ROOT / "docs" / "management").exists()
        return

    source = RELEASE_CHECKLIST.read_text(encoding="utf-8")

    assert "pypi.org/project/clawsentry/" in source
    assert "elroyper.github.io/ClawSentry/" in source
    assert "configuration/env-vars/" in source


def test_rules_governance_ci_example_publishes_report_artifact() -> None:
    source = RULES_CI_EXAMPLE.read_text(encoding="utf-8")

    assert "python -m clawsentry rules lint --json" in source
    assert "python -m clawsentry rules dry-run --events examples/sample-events.jsonl --json" in source
    assert (
        "python -m clawsentry rules report --output artifacts/rules-report.json "
        "--events examples/sample-events.jsonl "
        "--summary-markdown artifacts/rules-dashboard.md --json"
    ) in source
    assert "actions/upload-artifact" in source
    assert "artifacts/rules-report.json" in source
    assert "artifacts/rules-dashboard.md" in source
    assert "retention-days: 30" in source


def test_sample_events_cover_representative_rule_governance_cases() -> None:
    sample_events = [
        json.loads(line)
        for line in (REPO_ROOT / "examples" / "sample-events.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]

    assert [event["event_id"] for event in sample_events] == [
        "sample-safe-read",
        "sample-credential-upload",
        "sample-download-execute",
    ]
    assert sample_events[0]["tool_name"] == "list_directory"
    assert sample_events[0]["risk_hints"] == []
    assert "curl -F file=@" in sample_events[1]["payload"]["command"]
    assert "| bash" in sample_events[2]["payload"]["command"]


def test_codex_docs_describe_optional_native_hook_setup() -> None:
    codex_doc = (REPO_ROOT / "site-docs" / "integration" / "codex.md").read_text(
        encoding="utf-8"
    )
    cli_doc = (REPO_ROOT / "site-docs" / "cli" / "index.md").read_text(
        encoding="utf-8"
    )

    assert "clawsentry init codex --setup" in codex_doc
    assert ".codex/hooks.json" in codex_doc
    assert "PreToolUse(Bash)" in codex_doc
    assert "permissionDecision: \"deny\"" in codex_doc
    assert "--codex-home PATH" in cli_doc
