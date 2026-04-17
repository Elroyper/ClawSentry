"""Contract tests for public docs and release guardrails."""

from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
ENV_VARS_DOC = REPO_ROOT / "site-docs" / "configuration" / "env-vars.md"
RELEASE_CHECKLIST = REPO_ROOT / "docs" / "management" / "RELEASE_CHECKLIST.md"


def test_env_vars_doc_mentions_public_l3_trigger_controls() -> None:
    source = ENV_VARS_DOC.read_text(encoding="utf-8")

    assert "CS_L3_ROUTING_MODE" in source
    assert "CS_L3_TRIGGER_PROFILE" in source
    assert "CS_L3_BUDGET_TUNING_ENABLED" in source


def test_release_checklist_requires_public_surface_verification() -> None:
    source = RELEASE_CHECKLIST.read_text(encoding="utf-8")

    assert "pypi.org/project/clawsentry/" in source
    assert "elroyper.github.io/ClawSentry/" in source
    assert "configuration/env-vars/" in source
