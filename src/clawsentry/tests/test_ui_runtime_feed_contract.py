"""Static contract tests for the dashboard runtime feed.

These tests intentionally verify source-level UI contracts because the repo
does not currently include a browser/component test harness for the React app.
"""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1] / "ui" / "src"


def test_dashboard_uses_runtime_feed_component() -> None:
    source = (ROOT / "pages" / "Dashboard.tsx").read_text()
    assert "RuntimeFeed" in source


def test_runtime_feed_subscribes_to_key_runtime_event_types() -> None:
    source = (ROOT / "components" / "RuntimeFeed.tsx").read_text()
    for event_type in (
        "decision",
        "alert",
        "trajectory_alert",
        "post_action_finding",
        "pattern_candidate",
        "pattern_evolved",
        "defer_pending",
        "defer_resolved",
        "session_enforcement_change",
    ):
        assert f"'{event_type}'" in source


def test_runtime_feed_subscribes_to_budget_exhausted_events() -> None:
    source = (ROOT / "components" / "RuntimeFeed.tsx").read_text()

    assert "'budget_exhausted'" in source
    assert "Budget exhausted" in source
    assert "provider" in source
    assert "cost_usd" in source


def test_runtime_feed_surfaces_l3_evidence_summary() -> None:
    types_source = (ROOT / "api" / "types.ts").read_text()
    feed_source = (ROOT / "components" / "RuntimeFeed.tsx").read_text()

    assert "evidence_summary" in types_source
    assert "retained_sources" in types_source
    assert "tool_calls_count" in types_source
    assert "evidence_summary" in feed_source
    assert "formatL3EvidenceSummary" in feed_source


def test_runtime_feed_exposes_event_type_and_priority_filters() -> None:
    source = (ROOT / "components" / "RuntimeFeed.tsx").read_text()

    assert "eventTypeFilter" in source
    assert "HIGH_PRIORITY_EVENT_TYPES" in source
    assert "High priority only" in source
    assert "All events" in source
    assert "matchesRuntimeFilters" in source


def test_runtime_feed_defines_operator_high_priority_event_set() -> None:
    source = (ROOT / "components" / "RuntimeFeed.tsx").read_text()

    for event_type in (
        "alert",
        "trajectory_alert",
        "post_action_finding",
        "defer_pending",
        "defer_resolved",
        "session_enforcement_change",
    ):
        assert f"'{event_type}'" in source


def test_runtime_feed_surfaces_pause_backlog_and_cap_state() -> None:
    source = (ROOT / "components" / "RuntimeFeed.tsx").read_text()

    assert "Pause feed" in source
    assert "Resume feed" in source
    assert "bufferedCount" in source
    assert "FEED_MAX_EVENTS = 80" in source
    assert "Feed paused" in source
    assert "older events hidden" in source
