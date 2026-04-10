from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
UI_ROOT = REPO_ROOT / "src" / "clawsentry" / "ui" / "src"


def _read_ui_file(relative_path: str) -> str:
    return (UI_ROOT / relative_path).read_text(encoding="utf-8")


def test_dashboard_feed_subscribes_to_runtime_activity_events() -> None:
    source = _read_ui_file("components/RuntimeFeed.tsx")

    assert "Live Activity Feed" in source
    assert "trajectory_alert" in source
    assert "post_action_finding" in source
    assert "pattern_candidate" in source
    assert "pattern_evolved" in source
    assert "defer_pending" in source
    assert "defer_resolved" in source
    assert "session_enforcement_change" in source
    assert "alert" in source


def test_dashboard_highlights_framework_workspace_monitoring() -> None:
    source = _read_ui_file("pages/Dashboard.tsx")

    assert "Framework Coverage" in source
    assert "Workspace Risk Board" in source


def test_defer_panel_uses_explicit_defer_lifecycle_events() -> None:
    source = _read_ui_file("pages/DeferPanel.tsx")

    assert "connectSSE(['defer_pending', 'defer_resolved'])" in source


def test_alerts_page_uses_backend_aligned_severity_taxonomy() -> None:
    source = _read_ui_file("pages/Alerts.tsx")

    assert '<option value="low">Low</option>' in source
    assert '<option value="medium">Medium</option>' in source
    assert '<option value="high">High</option>' in source
    assert '<option value="critical">Critical</option>' in source
    assert '<option value="warning">' not in source
    assert '<option value="info">' not in source
    assert "high: 'var(--color-block)'" in source


def test_alert_types_bind_severity_to_risk_levels() -> None:
    source = _read_ui_file("api/types.ts")

    assert "export type AlertSeverity = RiskLevel" in source
    assert "severity: AlertSeverity" in source


def test_ui_types_expose_l3_as_a_first_class_decision_tier() -> None:
    source = _read_ui_file("api/types.ts")

    assert "export type DecisionTier = 'L1' | 'L2' | 'L3'" in source
    assert "actual_tier: DecisionTier" in source
    assert "trigger_detail?: string" in source


def test_runtime_feed_surfaces_trigger_detail_for_decision_events() -> None:
    source = _read_ui_file("components/RuntimeFeed.tsx")

    assert "event.trigger_detail" in source
    assert "Trigger pattern" in source


def test_session_detail_replay_surfaces_l3_trigger_detail() -> None:
    source = _read_ui_file("pages/SessionDetail.tsx")

    assert "record.l3_trace?.trigger_detail" in source
    assert "Trigger detail" in source


def test_session_risk_timeline_exposes_tier_fields_without_trace_parsing() -> None:
    source = _read_ui_file("api/types.ts")
    timeline_section = source.split("risk_timeline: Array<{", 1)[1].split("}>", 1)[0]

    assert "actual_tier: DecisionTier" in timeline_section
    assert "classified_by: DecisionTier" in timeline_section


def test_alerts_page_gates_sse_insertions_by_active_filters() -> None:
    source = _read_ui_file("pages/Alerts.tsx")

    assert "const matchesAlertFilters" in source
    assert "matchesAlertFilters(newAlert, severity, showAcknowledged)" in source
