"""E2E tests for LatchHubBridge — full DEFER lifecycle and integration flows."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from clawsentry.latch.hub_bridge import LatchHubBridge


@pytest.fixture
def bridge():
    return LatchHubBridge(
        hub_url="http://localhost:3006",
        token="test-token",
        gateway_url="http://localhost:8080",
        gateway_token="gw-token",
    )


class TestDeferLifecycleE2E:
    """Full DEFER lifecycle: pending → resolve → resolved."""

    def test_defer_pending_message_has_push_fields(self, bridge):
        """Verify defer_pending has all fields needed for push notifications."""
        event = {
            "type": "defer_pending",
            "tool_name": "write_file",
            "approval_id": "cs-defer-lifecycle-1",
            "timeout_s": 300,
            "risk_level": "high",
            "reason": "writes to sensitive path",
            "session_id": "sess-lc-1",
            "expires_at": "2026-03-30T12:00:00Z",
        }
        body = bridge._build_message_body(event)

        # Push notification channel expects these in data
        data = body["content"]["data"]
        assert data["approval_id"] == "cs-defer-lifecycle-1"
        assert data["tool_name"] == "write_file"
        assert data["risk_level"] == "high"
        assert data["reason"] == "writes to sensitive path"
        assert data["timeout_s"] == 300
        assert data["expires_at"] == "2026-03-30T12:00:00Z"

        # metadata.event_type is used by NotificationHub to detect defer_pending
        assert body["metadata"]["event_type"] == "defer_pending"
        assert body["metadata"]["clawsentry"] is True

    def test_defer_resolved_allow(self, bridge):
        event = {
            "type": "defer_resolved",
            "approval_id": "cs-defer-lifecycle-1",
            "resolved_decision": "allow",
            "resolved_by": "operator",
            "session_id": "sess-lc-1",
        }
        body = bridge._build_message_body(event)
        data = body["content"]["data"]
        assert data["type"] == "defer_resolved"
        assert data["resolved_decision"] == "allow"
        assert "DEFER RESOLVED" in body["content"]["text"]
        assert "ALLOW" in body["content"]["text"]

    def test_defer_resolved_deny(self, bridge):
        event = {
            "type": "defer_resolved",
            "approval_id": "cs-defer-lifecycle-2",
            "resolved_decision": "deny",
            "resolved_by": "timeout",
            "session_id": "sess-lc-2",
        }
        body = bridge._build_message_body(event)
        data = body["content"]["data"]
        assert data["resolved_decision"] == "deny"
        assert "DENY" in body["content"]["text"]

    @pytest.mark.asyncio
    async def test_full_lifecycle_forwards_both_events(self, bridge):
        """pending + resolved events both reach Hub in order."""
        bridge._session_map["sess-lc-1"] = "hub-session-lc"
        sent: list[dict] = []

        async def mock_request(method, path, body):
            sent.append({"method": method, "path": path, "body": body})
            return {}

        events = [
            {
                "type": "defer_pending",
                "tool_name": "execute_bash",
                "approval_id": "cs-defer-42",
                "timeout_s": 120,
                "risk_level": "high",
                "session_id": "sess-lc-1",
            },
            {
                "type": "defer_resolved",
                "approval_id": "cs-defer-42",
                "resolved_decision": "allow",
                "session_id": "sess-lc-1",
            },
        ]

        with patch.object(bridge, "_hub_request", side_effect=mock_request):
            for ev in events:
                await bridge._forward_event(ev)

        assert len(sent) == 2
        assert sent[0]["body"]["metadata"]["event_type"] == "defer_pending"
        assert sent[1]["body"]["metadata"]["event_type"] == "defer_resolved"
        # Both go to same Hub session
        assert sent[0]["path"] == sent[1]["path"]


class TestSessionCreationE2E:
    """Hub session creation + message posting integration."""

    @pytest.mark.asyncio
    async def test_new_session_created_then_message_sent(self, bridge):
        """First event for a session creates Hub session, then posts message."""
        calls: list[tuple[str, str, dict]] = []

        async def mock_request(method, path, body):
            calls.append((method, path, body))
            if path == "/cli/sessions":
                return {"id": "hub-new-1"}
            return {}

        with patch.object(bridge, "_hub_request", side_effect=mock_request):
            await bridge._forward_event({
                "type": "decision",
                "decision": "allow",
                "tool_name": "read_file",
                "risk_level": "low",
                "session_id": "new-sess-1",
                "source_framework": "claude-code",
            })

        assert len(calls) == 2
        # First call: session creation
        assert calls[0][1] == "/cli/sessions"
        assert calls[0][2]["title"] == "ClawSentry: new-sess-1"
        assert calls[0][2]["metadata"]["source_framework"] == "claude-code"
        # Second call: message posting
        assert "/messages" in calls[1][1]
        assert calls[1][2]["metadata"]["clawsentry"] is True

    @pytest.mark.asyncio
    async def test_second_event_reuses_session(self, bridge):
        """Second event for same session_id reuses existing Hub session."""
        bridge._session_map["reuse-sess"] = "hub-reuse-1"
        calls: list[tuple[str, str, dict]] = []

        async def mock_request(method, path, body):
            calls.append((method, path, body))
            return {}

        with patch.object(bridge, "_hub_request", side_effect=mock_request):
            await bridge._forward_event({
                "type": "decision",
                "decision": "block",
                "tool_name": "write_file",
                "session_id": "reuse-sess",
            })

        # Only message posting, no session creation
        assert len(calls) == 1
        assert calls[0][1] == "/cli/sessions/hub-reuse-1/messages"

    @pytest.mark.asyncio
    async def test_failed_session_creation_skips_message(self, bridge):
        """If Hub session creation fails, event is dropped gracefully."""
        calls: list[tuple[str, str, dict]] = []

        async def mock_request(method, path, body):
            calls.append((method, path, body))
            if path == "/cli/sessions":
                return None  # failure
            return {}

        with patch.object(bridge, "_hub_request", side_effect=mock_request):
            await bridge._forward_event({
                "type": "decision",
                "decision": "block",
                "tool_name": "rm_rf",
                "session_id": "fail-sess",
            })

        # Only session creation attempted, no message
        assert len(calls) == 1
        assert calls[0][1] == "/cli/sessions"


class TestStartupFlowE2E:
    """Bridge startup: registration + forward loop."""

    @pytest.mark.asyncio
    async def test_start_registers_gateway(self, bridge):
        """start() calls _register_gateway before starting forward loop."""
        registered = []

        async def mock_register():
            registered.append(True)

        with patch.object(bridge, "_register_gateway", side_effect=mock_register):
            bridge._source_queue = asyncio.Queue()
            bridge._task = None
            await bridge.start()
            # Give task a tick to start
            await asyncio.sleep(0.01)
            await bridge.stop()

        assert len(registered) == 1

    @pytest.mark.asyncio
    async def test_disabled_bridge_skips_start(self):
        bridge = LatchHubBridge(
            hub_url="http://localhost:3006",
            token="t",
            enabled=False,
        )
        await bridge.start()
        assert bridge._task is None

    @pytest.mark.asyncio
    async def test_stop_cancels_task(self, bridge):
        bridge._source_queue = asyncio.Queue()

        with patch.object(bridge, "_register_gateway", new_callable=AsyncMock):
            await bridge.start()
            assert bridge._task is not None
            await bridge.stop()
            assert bridge._task is None


class TestMultiEventSequenceE2E:
    """Multiple event types forwarded in sequence."""

    @pytest.mark.asyncio
    async def test_mixed_event_types(self, bridge):
        """Decision, alert, and defer events all forwarded correctly."""
        bridge._session_map["multi-sess"] = "hub-multi"
        sent: list[dict] = []

        async def mock_request(method, path, body):
            sent.append(body)
            return {}

        events = [
            {"type": "session_start", "agent_id": "agent-1", "source_framework": "codex", "session_id": "multi-sess"},
            {"type": "decision", "decision": "allow", "tool_name": "read_file", "risk_level": "low", "session_id": "multi-sess"},
            {"type": "decision", "decision": "block", "tool_name": "rm_rf", "risk_level": "critical", "session_id": "multi-sess"},
            {"type": "alert", "severity": "high", "message": "Secret detected", "session_id": "multi-sess"},
            {"type": "defer_pending", "tool_name": "deploy", "approval_id": "d-1", "timeout_s": 60, "risk_level": "high", "session_id": "multi-sess"},
            {"type": "defer_resolved", "approval_id": "d-1", "resolved_decision": "deny", "session_id": "multi-sess"},
        ]

        with patch.object(bridge, "_hub_request", side_effect=mock_request):
            for ev in events:
                await bridge._forward_event(ev)

        assert len(sent) == 6
        types = [b["metadata"]["event_type"] for b in sent]
        assert types == ["session_start", "decision", "decision", "alert", "defer_pending", "defer_resolved"]
        # All marked as clawsentry
        assert all(b["metadata"]["clawsentry"] is True for b in sent)

    @pytest.mark.asyncio
    async def test_cross_session_events(self, bridge):
        """Events from different sessions go to different Hub sessions."""
        bridge._session_map["s1"] = "hub-1"
        bridge._session_map["s2"] = "hub-2"
        sent: list[tuple[str, str]] = []

        async def mock_request(method, path, body):
            sent.append((path, body["metadata"]["event_type"]))
            return {}

        with patch.object(bridge, "_hub_request", side_effect=mock_request):
            await bridge._forward_event({"type": "decision", "decision": "allow", "session_id": "s1"})
            await bridge._forward_event({"type": "alert", "severity": "high", "session_id": "s2"})

        assert sent[0][0] == "/cli/sessions/hub-1/messages"
        assert sent[1][0] == "/cli/sessions/hub-2/messages"


class TestTextFallbackE2E:
    """Verify text fallback messages are human-readable for all event types."""

    @pytest.mark.parametrize("event,expected_substr", [
        ({"type": "decision", "decision": "allow", "tool_name": "cat", "risk_level": "low"}, "[ALLOW]"),
        ({"type": "decision", "decision": "block", "tool_name": "rm", "risk_level": "critical", "reason": "dangerous"}, "dangerous"),
        ({"type": "alert", "severity": "critical", "message": "Leak found"}, "Leak found"),
        ({"type": "defer_pending", "tool_name": "deploy", "timeout_s": 60}, "deploy"),
        ({"type": "defer_resolved", "resolved_decision": "allow"}, "ALLOW"),
        ({"type": "session_start", "agent_id": "a1", "source_framework": "claude-code"}, "claude-code"),
        ({"type": "session_risk_change", "previous_risk": "low", "current_risk": "high"}, "high"),
        ({"type": "post_action_finding", "finding": "injection"}, "POST_ACTION_FINDING"),
    ])
    def test_text_fallback(self, bridge, event, expected_substr):
        event.setdefault("session_id", "sess-txt")
        body = bridge._build_message_body(event)
        text = body["content"]["text"]
        assert expected_substr in text
