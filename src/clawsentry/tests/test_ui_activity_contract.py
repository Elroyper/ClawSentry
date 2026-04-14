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


def test_health_response_exposes_budget_snapshot_for_operator_surfaces() -> None:
    source = _read_ui_file("api/types.ts")

    assert "export interface HealthBudgetSnapshot" in source
    assert "budget: HealthBudgetSnapshot" in source
    assert "daily_budget_usd" in source
    assert "daily_spend_usd" in source
    assert "remaining_usd" in source
    assert "exhausted" in source


def test_status_bar_surfaces_budget_snapshot_copy() -> None:
    source = _read_ui_file("components/StatusBar.tsx")

    assert "Daily budget" in source
    assert "health.budget.daily_budget_usd" in source
    assert "health.budget.daily_spend_usd" in source
    assert "health.budget.remaining_usd" in source
    assert "health.budget.exhausted" in source


def test_dashboard_surfaces_budget_snapshot_in_current_posture() -> None:
    source = _read_ui_file("pages/Dashboard.tsx")

    assert "Daily budget" in source
    assert "Spend" in source
    assert "Remaining" in source
    assert "Exhausted" in source


def test_ui_types_model_llm_usage_snapshot_for_operator_surfaces() -> None:
    source = _read_ui_file("api/types.ts")

    assert "export interface LLMUsageBucket" in source
    assert "export interface LLMUsageSnapshot" in source
    assert "total_calls" in source
    assert "total_input_tokens" in source
    assert "total_output_tokens" in source
    assert "total_cost_usd" in source
    assert "by_provider: Record<string, LLMUsageBucket>" in source
    assert "by_tier: Record<string, LLMUsageBucket>" in source
    assert "by_status: Record<string, LLMUsageBucket>" in source
    assert "llm_usage_snapshot?: LLMUsageSnapshot | null" in source


def test_status_bar_surfaces_llm_usage_snapshot_summary_for_operators() -> None:
    source = _read_ui_file("components/StatusBar.tsx")

    assert "health?.llm_usage_snapshot" in source
    assert "LLM usage" in source
    assert "total_calls" in source
    assert "total_cost_usd" in source


def test_dashboard_surfaces_llm_usage_snapshot_summary_for_operators() -> None:
    source = _read_ui_file("pages/Dashboard.tsx")

    assert "summary?.llm_usage_snapshot" in source
    assert "LLM usage" in source
    assert "total_calls" in source
    assert "total_cost_usd" in source


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


def test_ui_types_expose_l3_reason_code_for_operator_surfaces() -> None:
    source = _read_ui_file("api/types.ts")

    assert "l3_reason_code?: string" in source


def test_ui_types_expose_l3_availability_and_request_state() -> None:
    source = _read_ui_file("api/types.ts")

    assert "l3_available?: boolean" in source
    assert "l3_requested?: boolean" in source


def test_ui_types_expose_l3_state_and_reason_for_operator_surfaces() -> None:
    source = _read_ui_file("api/types.ts")

    assert "l3_state?: string" in source
    assert "l3_reason?: string" in source


def test_ui_types_expose_l3_as_a_first_class_decision_tier() -> None:
    source = _read_ui_file("api/types.ts")

    assert "export type DecisionTier = 'L1' | 'L2' | 'L3'" in source
    assert "actual_tier: DecisionTier" in source
    assert "trigger_detail?: string" in source


def test_runtime_feed_surfaces_trigger_detail_for_decision_events() -> None:
    source = _read_ui_file("components/RuntimeFeed.tsx")

    assert "event.trigger_detail" in source
    assert "Trigger pattern" in source


def test_runtime_feed_surfaces_l3_reason_code_for_decision_events() -> None:
    source = _read_ui_file("components/RuntimeFeed.tsx")

    assert "event.l3_reason_code" in source
    assert "L3 reason code" in source


def test_runtime_feed_surfaces_l3_availability_and_request_state_for_decision_events() -> None:
    source = _read_ui_file("components/RuntimeFeed.tsx")

    assert "event.l3_available" in source
    assert "event.l3_requested" in source
    assert "L3 available" in source
    assert "L3 requested" in source


def test_runtime_feed_surfaces_l3_state_and_reason_for_decision_events() -> None:
    source = _read_ui_file("components/RuntimeFeed.tsx")

    assert "event.l3_state" in source
    assert "event.l3_reason" in source


def test_ui_types_model_budget_exhausted_runtime_events() -> None:
    source = _read_ui_file("api/types.ts")

    assert "export interface SSEBudgetExhaustedEvent" in source
    assert "type: 'budget_exhausted'" in source
    assert "provider: string" in source
    assert "tier: string" in source
    assert "cost_usd: number" in source
    assert "budget: HealthBudgetSnapshot" in source
    assert "budget_exhausted" in source


def test_ui_types_model_budget_exhaustion_event_response_payloads() -> None:
    source = _read_ui_file("api/types.ts")

    assert "budget_exhaustion_event?: SSEBudgetExhaustedEvent | null" in source
    assert "budget_exhaustion_event" in source


def test_runtime_feed_surfaces_budget_exhausted_operator_copy() -> None:
    source = _read_ui_file("components/RuntimeFeed.tsx")

    assert "budget_exhausted" in source
    assert "Budget exhausted" in source
    assert "Provider" in source
    assert "Tier" in source
    assert "Cost" in source


def test_status_bar_emphasizes_budget_exhaustion_for_operators() -> None:
    source = _read_ui_file("components/StatusBar.tsx")

    assert "budget_exhaustion_event" in source
    assert "BUDGET EXHAUSTED" in source
    assert "Operator action required" in source


def test_dashboard_emphasizes_budget_exhaustion_for_operators() -> None:
    source = _read_ui_file("pages/Dashboard.tsx")

    assert "budget_exhaustion_event" in source
    assert "Budget exhaustion event" in source
    assert "Operator attention required" in source


def test_session_detail_replay_surfaces_l3_trigger_detail() -> None:
    source = _read_ui_file("pages/SessionDetail.tsx")

    assert "record.l3_trace?.trigger_detail" in source
    assert "Trigger detail" in source


def test_session_detail_replay_surfaces_l3_reason_code() -> None:
    source = _read_ui_file("pages/SessionDetail.tsx")

    assert "record.meta.l3_reason_code" in source
    assert "L3 reason code" in source


def test_session_detail_replay_surfaces_l3_availability_and_request_state() -> None:
    source = _read_ui_file("pages/SessionDetail.tsx")

    assert "record.meta.l3_available" in source
    assert "record.meta.l3_requested" in source
    assert "L3 available" in source
    assert "L3 requested" in source


def test_session_detail_replay_surfaces_l3_state_and_reason() -> None:
    source = _read_ui_file("pages/SessionDetail.tsx")

    assert "record.meta.l3_state" in source
    assert "record.meta.l3_reason" in source


def test_session_risk_timeline_exposes_tier_fields_without_trace_parsing() -> None:
    source = _read_ui_file("api/types.ts")
    timeline_section = source.split("risk_timeline: Array<{", 1)[1].split("}>", 1)[0]

    assert "actual_tier: DecisionTier" in timeline_section
    assert "classified_by: DecisionTier" in timeline_section


def test_alerts_page_gates_sse_insertions_by_active_filters() -> None:
    source = _read_ui_file("pages/Alerts.tsx")

    assert "const matchesAlertFilters" in source
    assert "matchesAlertFilters(newAlert, severity, showAcknowledged)" in source
