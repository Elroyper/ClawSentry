"""Regression coverage for the P2 browser-validation fixture."""

from __future__ import annotations

import pytest

from clawsentry.gateway.detection_config import DetectionConfig

from clawsentry.devtools.ui_validation_fixture import (
    build_browser_validation_gateway,
    build_runtime_replay_events,
    seed_gateway_for_browser_validation,
)


@pytest.mark.asyncio
async def test_seed_gateway_for_browser_validation_populates_multi_framework_sessions() -> None:
    gateway = build_browser_validation_gateway(trajectory_db_path=":memory:")

    await seed_gateway_for_browser_validation(gateway)

    sessions = gateway.report_sessions(limit=50)["sessions"]
    frameworks = {session["source_framework"] for session in sessions}
    workspace_roots = {session["workspace_root"] for session in sessions}

    assert {"a3s-code", "openclaw", "codex", "claude-code"}.issubset(frameworks)
    assert len([root for root in workspace_roots if root]) >= 3
    assert any(session["workspace_root"].endswith("repo-alpha") for session in sessions)
    assert any(session["workspace_root"].endswith("repo-beta") for session in sessions)


@pytest.mark.asyncio
async def test_seed_gateway_for_browser_validation_populates_all_alert_severities() -> None:
    gateway = build_browser_validation_gateway(trajectory_db_path=":memory:")

    await seed_gateway_for_browser_validation(gateway)

    alerts = gateway.report_alerts(limit=20)["alerts"]
    severities = {alert["severity"] for alert in alerts}

    assert severities == {"low", "medium", "high", "critical"}


@pytest.mark.asyncio
async def test_seed_gateway_for_browser_validation_primes_runtime_feed_replay() -> None:
    gateway = build_browser_validation_gateway(trajectory_db_path=":memory:")

    await seed_gateway_for_browser_validation(gateway)

    subscriber_id, queue = gateway.event_bus.subscribe()
    assert subscriber_id is not None
    assert queue is not None
    try:
        replayed = []
        while not queue.empty():
            replayed.append(queue.get_nowait())
    finally:
        gateway.event_bus.unsubscribe(subscriber_id)

    event_types = {event["type"] for event in replayed}

    assert {
        "alert",
        "trajectory_alert",
        "post_action_finding",
        "defer_pending",
        "defer_resolved",
        "session_enforcement_change",
    }.issubset(event_types)


@pytest.mark.asyncio
async def test_seed_gateway_for_browser_validation_avoids_l2_fallback_warning(caplog) -> None:
    gateway = build_browser_validation_gateway(trajectory_db_path=":memory:")

    with caplog.at_level("WARNING", logger="clawsentry.gateway.policy_engine"):
        await seed_gateway_for_browser_validation(gateway)

    assert "L2 analysis failed; falling back to L1" not in caplog.text


def test_build_runtime_replay_events_matches_runtime_feed_contract() -> None:
    events = build_runtime_replay_events()
    by_type = {event["type"]: event for event in events}

    trajectory = by_type["trajectory_alert"]
    assert trajectory["handling"] in {"broadcast", "defer", "block"}
    assert isinstance(trajectory["matched_event_ids"], list)

    finding = by_type["post_action_finding"]
    assert isinstance(finding["patterns_matched"], list)
    assert isinstance(finding["score"], float)
    assert finding["handling"] in {"broadcast", "defer", "block"}


def test_build_runtime_replay_events_contains_enterprise_defer_popup_seed() -> None:
    events = build_runtime_replay_events()
    defer_pending_events = [event for event in events if event.get("type") == "defer_pending"]

    # Keep at least one classic DEFER sample and one enterprise rollout-style sample.
    assert len(defer_pending_events) >= 2
    assert any(
        event.get("command") == "kubectl apply -f prod-rollout.yaml"
        and event.get("session_id") == "sess-openclaw-beta-001"
        for event in defer_pending_events
    )
    for event in defer_pending_events:
        for required_key in [
            "approval_id",
            "tool_name",
            "command",
            "reason",
            "risk_level",
            "timeout_s",
            "session_id",
            "timestamp",
        ]:
            assert required_key in event


def test_build_browser_validation_gateway_uses_default_rule_based_policy_stack() -> None:
    gateway = build_browser_validation_gateway()

    assert gateway.policy_engine.analyzer.analyzer_id == "rule-based"
    assert gateway.policy_engine._config == DetectionConfig()
