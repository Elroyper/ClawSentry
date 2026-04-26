"""Static contract tests for framework/workspace aware UI monitoring views."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1] / "ui" / "src"


def test_dashboard_surfaces_framework_and_workspace_coverage_sections() -> None:
    source = (ROOT / "pages" / "Dashboard.tsx").read_text(encoding="utf-8")
    locales = (ROOT / "lib" / "locales.ts").read_text(encoding="utf-8")

    assert "dashboard.frameworkCoverage" in source
    assert "dashboard.workspaceRiskBoard" in source
    assert "dashboard.prioritySessions" in source
    assert "Framework coverage" in locales
    assert "Workspace risk board" in locales
    assert "Priority sessions" in locales


def test_sessions_page_groups_by_framework_and_workspace() -> None:
    source = (ROOT / "pages" / "Sessions.tsx").read_text(encoding="utf-8")
    locales = (ROOT / "lib" / "locales.ts").read_text(encoding="utf-8")

    assert "sessions.frameworkOverview" in source
    assert "Framework Overview" in locales
    assert "workspace_root" in source
    assert "groupedSessions" in source
