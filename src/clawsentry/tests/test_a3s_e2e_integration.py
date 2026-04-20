"""Integration tests: a3s-code Harness → Adapter → UDS → Gateway → all registries.

Verifies the full in-process pipeline for the a3s-code stdio harness path:
  AHP JSON-RPC message → A3SGatewayHarness.dispatch_async()
    → A3SCodeAdapter.normalize_hook_event()
      → A3SCodeAdapter.request_decision() (UDS transport)
        → SupervisionGateway.handle_jsonrpc()
          → trajectory_store.record()
          → session_registry.record()
          → event_bus.broadcast()
          → alert_registry.add() (for high-risk)

These tests prove the a3s-code path is wired end-to-end through the real
UDS transport and triggers all downstream registries — analogous to
test_ws_gateway_integration.py for the OpenClaw WS path.
"""

from __future__ import annotations

import os

import pytest
import pytest_asyncio

from clawsentry.adapters.a3s_adapter import A3SCodeAdapter
from clawsentry.adapters.a3s_gateway_harness import A3SGatewayHarness
from clawsentry.gateway.server import SupervisionGateway, start_uds_server


TEST_UDS_PATH = "/tmp/ahp-a3s-e2e-test.sock"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _pre_action_msg(
    *,
    req_id: int,
    tool: str = "bash",
    command: str = "echo hello",
    session_id: str = "e2e-sess-1",
    agent_id: str = "e2e-agent-1",
    path: str | None = None,
) -> dict:
    """Build an AHP pre_action JSON-RPC message."""
    arguments: dict = {}
    if command:
        arguments["command"] = command
    if path:
        arguments["path"] = path
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "ahp/event",
        "params": {
            "event_type": "pre_action",
            "session_id": session_id,
            "agent_id": agent_id,
            "payload": {
                "tool": tool,
                "arguments": arguments,
            },
        },
    }


# ---------------------------------------------------------------------------
# Fixture: full pipeline (Harness → Adapter → UDS → Gateway with registries)
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def e2e_harness():
    """Full pipeline: Harness → Adapter → UDS → Gateway (with registries)."""
    if os.path.exists(TEST_UDS_PATH):
        os.unlink(TEST_UDS_PATH)
    gw = SupervisionGateway()
    server = await start_uds_server(gw, TEST_UDS_PATH)
    adapter = A3SCodeAdapter(uds_path=TEST_UDS_PATH, default_deadline_ms=500)
    harness = A3SGatewayHarness(adapter=adapter)
    yield harness, gw
    server.close()
    await server.wait_closed()
    if os.path.exists(TEST_UDS_PATH):
        os.unlink(TEST_UDS_PATH)


# ---------------------------------------------------------------------------
# Test 1: Decision appears in EventBus
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_pre_action_decision_appears_in_eventbus(e2e_harness):
    """A pre_action event should produce a 'decision' broadcast on EventBus."""
    harness, gw = e2e_harness

    sub_id, queue = gw.event_bus.subscribe(event_types={"decision"})
    assert sub_id is not None
    assert queue is not None

    try:
        resp = await harness.dispatch_async(
            _pre_action_msg(
                req_id=10,
                tool="bash",
                command="rm -rf /important-data",
                session_id="e2e-bus-1",
            )
        )
        assert resp is not None
        assert resp["result"]["decision"] == "block"

        # Collect events from the queue
        events = []
        while not queue.empty():
            events.append(queue.get_nowait())

        decision_events = [e for e in events if e["type"] == "decision"]
        assert len(decision_events) >= 1

        evt = decision_events[0]
        assert evt["session_id"] == "e2e-bus-1"
        assert evt["decision"] == "block"
        assert evt["risk_level"] in ("high", "critical")
        assert "timestamp" in evt
    finally:
        gw.event_bus.unsubscribe(sub_id)


# ---------------------------------------------------------------------------
# Test 2: Session created in SessionRegistry
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_pre_action_creates_session_in_registry(e2e_harness):
    """A pre_action event should register the session in SessionRegistry."""
    harness, gw = e2e_harness

    resp = await harness.dispatch_async(
        _pre_action_msg(
            req_id=20,
            tool="bash",
            command="ls -la",
            session_id="e2e-sess-reg-1",
        )
    )
    assert resp is not None

    # Verify session exists
    risk = gw.session_registry.get_current_risk("e2e-sess-reg-1")
    assert risk is not None

    sessions = gw.session_registry.list_sessions()
    session_ids = [s["session_id"] for s in sessions["sessions"]]
    assert "e2e-sess-reg-1" in session_ids


# ---------------------------------------------------------------------------
# Test 3: Dangerous command triggers alert
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_dangerous_command_triggers_alert(e2e_harness):
    """A high-risk pre_action (rm -rf /) should create an alert in AlertRegistry."""
    harness, gw = e2e_harness

    resp = await harness.dispatch_async(
        _pre_action_msg(
            req_id=30,
            tool="bash",
            command="rm -rf /",
            session_id="e2e-alert-1",
        )
    )
    assert resp is not None
    assert resp["result"]["decision"] == "block"

    alerts = gw.alert_registry.list_alerts()
    session_alerts = [
        a for a in alerts["alerts"] if a["session_id"] == "e2e-alert-1"
    ]
    assert len(session_alerts) >= 1
    assert session_alerts[0]["severity"] in ("high", "critical")
    assert session_alerts[0]["metric"] == "session_risk_escalation"
    assert session_alerts[0]["acknowledged"] is False


# ---------------------------------------------------------------------------
# Test 4: Safe read_file command does NOT trigger alert
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_safe_command_no_alert(e2e_harness):
    """A read-only tool with a benign path should NOT create any alert.

    SC-3 short-circuit: D1=0, D2=0, D3=0 → LOW risk → allow, no alert.
    """
    harness, gw = e2e_harness

    resp = await harness.dispatch_async(
        _pre_action_msg(
            req_id=40,
            tool="read_file",
            command="",
            path="/tmp/test.txt",
            session_id="e2e-no-alert-1",
        )
    )
    assert resp is not None
    assert resp["result"]["decision"] == "allow"

    alerts = gw.alert_registry.list_alerts()
    session_alerts = [
        a for a in alerts["alerts"] if a["session_id"] == "e2e-no-alert-1"
    ]
    assert len(session_alerts) == 0


# ---------------------------------------------------------------------------
# Test 5: Sequential events accumulate in session
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sequential_events_accumulate_in_session(e2e_harness):
    """Multiple pre_action events to the same session should accumulate in
    SessionRegistry and their risk timeline should grow."""
    harness, gw = e2e_harness
    sid = "e2e-accum-1"

    commands = ["ls -la", "pwd", "whoami"]
    for i, cmd in enumerate(commands):
        resp = await harness.dispatch_async(
            _pre_action_msg(
                req_id=50 + i,
                tool="bash",
                command=cmd,
                session_id=sid,
            )
        )
        assert resp is not None

    risk = gw.session_registry.get_session_risk(sid)
    assert risk["session_id"] == sid
    assert len(risk["risk_timeline"]) == 3


# ---------------------------------------------------------------------------
# Test 6: session_start broadcast on first event
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_session_start_event_broadcast(e2e_harness):
    """The first event for a new session should broadcast 'session_start'."""
    harness, gw = e2e_harness

    sub_id, queue = gw.event_bus.subscribe(
        event_types={"session_start", "decision"},
    )
    assert sub_id is not None

    try:
        await harness.dispatch_async(
            _pre_action_msg(
                req_id=60,
                tool="bash",
                command="echo hello",
                session_id="e2e-start-1",
            )
        )

        events = []
        while not queue.empty():
            events.append(queue.get_nowait())

        start_events = [e for e in events if e["type"] == "session_start"]
        assert len(start_events) == 1
        assert start_events[0]["session_id"] == "e2e-start-1"
        assert start_events[0]["source_framework"] == "a3s-code"
    finally:
        gw.event_bus.unsubscribe(sub_id)


# ---------------------------------------------------------------------------
# Test 7: richer context/metadata survive to trajectory + replay
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_richer_event_fields_survive_to_trajectory_and_replay(e2e_harness):
    harness, gw = e2e_harness
    session_id = "e2e-rich-trajectory-1"

    resp = await harness.dispatch_async(
        {
            "jsonrpc": "2.0",
            "id": 65,
            "method": "ahp/event",
            "params": {
                "event_type": "pre_action",
                "event_id": "evt-rich-e2e-001",
                "trace_id": "trace-rich-e2e-001",
                "session_id": session_id,
                "agent_id": "e2e-agent-rich-1",
                "context": {
                    "session": {"workspace": "/repo"},
                    "agent": {"role": "implementer"},
                },
                "metadata": {
                    "labels": ["compat", "rich"],
                    "origin": "harness-test",
                },
                "payload": {
                    "tool": "read_file",
                    "arguments": {"path": "/tmp/rich.txt"},
                },
            },
        }
    )

    assert resp is not None
    assert resp["result"]["decision"] == "allow"

    record = gw.trajectory_store.records[-1]
    compat = record["event"]["payload"]["_clawsentry_meta"]["ahp_compat"]
    assert record["event"]["trace_id"] == "trace-rich-e2e-001"
    assert compat["raw_event_type"] == "pre_action"
    assert compat["context_present"] is True
    assert compat["metadata_present"] is True
    assert compat["context"]["session"]["workspace"] == "/repo"
    assert compat["metadata"]["origin"] == "harness-test"
    assert compat["identity"]["event_id"] == "evt-rich-e2e-001"
    assert compat["identity"]["session_id"] == session_id
    assert compat["identity"]["agent_id"] == "e2e-agent-rich-1"

    replay = gw.replay_session(session_id)
    replay_compat = replay["records"][-1]["event"]["payload"]["_clawsentry_meta"]["ahp_compat"]
    assert replay_compat == compat


@pytest.mark.asyncio
@pytest.mark.parametrize("event_type", ["success", "rate_limit"])
async def test_compat_observation_events_reach_stream_and_trajectory_without_blocking(
    e2e_harness,
    event_type,
):
    harness, gw = e2e_harness
    session_id = f"e2e-compat-{event_type}"

    sub_id, queue = gw.event_bus.subscribe(event_types={"decision"})
    try:
        resp = await harness.dispatch_async(
            {
                "jsonrpc": "2.0",
                "id": 66,
                "method": "ahp/event",
                "params": {
                    "event_type": event_type,
                    "session_id": session_id,
                    "agent_id": "e2e-agent-compat",
                    "payload": {
                        "message": f"{event_type} compat event",
                    },
                },
            }
        )

        assert resp is not None
        assert resp["result"]["decision"] == "allow"
        assert resp["result"]["action"] == "continue"

        record = gw.trajectory_store.records[-1]
        assert record["event"]["event_type"] == "session"
        compat = record["event"]["payload"]["_clawsentry_meta"]["ahp_compat"]
        assert compat["raw_event_type"] == event_type

        decision_evt = None
        while not queue.empty():
            evt = queue.get_nowait()
            if evt.get("type") == "decision" and evt.get("compat_event_type") == event_type:
                decision_evt = evt
                break

        assert decision_evt is not None
        assert decision_evt["session_id"] == session_id
        assert decision_evt["decision"] == "allow"
    finally:
        gw.event_bus.unsubscribe(sub_id)


# ---------------------------------------------------------------------------
# Test 7: reason field in harness response
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_reason_field_in_harness_response(e2e_harness):
    """A dangerous pre_action should include a meaningful 'reason' in the
    harness response (not empty)."""
    harness, gw = e2e_harness

    resp = await harness.dispatch_async(
        _pre_action_msg(
            req_id=70,
            tool="bash",
            command="rm -rf /important-data",
            session_id="e2e-reason-1",
        )
    )
    assert resp is not None
    result = resp["result"]
    assert result["decision"] == "block"
    assert result["reason"]  # non-empty
    assert len(result["reason"]) > 5  # meaningful text, not just a symbol


# ---------------------------------------------------------------------------
# Test 8: risk change broadcast on escalation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_risk_change_broadcast_on_escalation(e2e_harness):
    """Sending a safe event then a dangerous event to the same session should
    broadcast a 'session_risk_change' event via EventBus."""
    harness, gw = e2e_harness
    sid = "e2e-risk-change-1"

    # First: a read_file event to establish low-risk baseline
    await harness.dispatch_async(
        _pre_action_msg(
            req_id=80,
            tool="read_file",
            command="",
            path="/tmp/safe.txt",
            session_id=sid,
        )
    )

    # Subscribe AFTER first event so we only see the escalation
    sub_id, queue = gw.event_bus.subscribe(
        event_types={"session_risk_change", "decision"},
    )
    assert sub_id is not None

    try:
        # Second: a dangerous bash command that should escalate risk
        await harness.dispatch_async(
            _pre_action_msg(
                req_id=81,
                tool="bash",
                command="rm -rf /important-data",
                session_id=sid,
            )
        )

        events = []
        while not queue.empty():
            events.append(queue.get_nowait())

        risk_changes = [e for e in events if e["type"] == "session_risk_change"]
        assert len(risk_changes) >= 1
        change = risk_changes[0]
        assert change["session_id"] == sid
        assert change["current_risk"] in ("high", "critical")
    finally:
        gw.event_bus.unsubscribe(sub_id)
