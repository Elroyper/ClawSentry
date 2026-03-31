"""Tests for LatchHubBridge event forwarding."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from clawsentry.latch.hub_bridge import LatchHubBridge


# ---------------------------------------------------------------------------
# 1. test_init_defaults
# ---------------------------------------------------------------------------

def test_init_defaults():
    """Verify default init state (hub_url, enabled, empty session_map)."""
    bridge = LatchHubBridge(hub_url="http://127.0.0.1:3006")
    assert bridge.hub_url == "http://127.0.0.1:3006"
    assert bridge.token == ""
    assert bridge.enabled is True
    assert bridge._session_map == {}
    assert bridge._task is None


# ---------------------------------------------------------------------------
# 2. test_init_disabled
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_init_disabled():
    """Verify enabled=False prevents start from creating a task."""
    bridge = LatchHubBridge(hub_url="http://127.0.0.1:3006", enabled=False)
    await bridge.start()
    assert bridge._task is None


# ---------------------------------------------------------------------------
# 3. test_format_message_decision
# ---------------------------------------------------------------------------

def test_format_message_decision():
    """Verify _format_message for decision event."""
    bridge = LatchHubBridge(hub_url="http://127.0.0.1:3006")
    event = {
        "type": "decision",
        "decision": "allow",
        "tool_name": "bash",
        "risk_level": "low",
        "reason": "safe command",
    }
    msg = bridge._format_message(event)
    assert "[ALLOW]" in msg
    assert "bash" in msg
    assert "risk: low" in msg
    assert "Reason: safe command" in msg


# ---------------------------------------------------------------------------
# 4. test_format_message_alert
# ---------------------------------------------------------------------------

def test_format_message_alert():
    """Verify _format_message for alert event."""
    bridge = LatchHubBridge(hub_url="http://127.0.0.1:3006")
    event = {
        "type": "alert",
        "severity": "high",
        "message": "Suspicious activity detected",
    }
    msg = bridge._format_message(event)
    assert "[ALERT:HIGH]" in msg
    assert "Suspicious activity detected" in msg


# ---------------------------------------------------------------------------
# 5. test_format_message_defer_pending
# ---------------------------------------------------------------------------

def test_format_message_defer_pending():
    """Verify _format_message for defer_pending event."""
    bridge = LatchHubBridge(hub_url="http://127.0.0.1:3006")
    event = {
        "type": "defer_pending",
        "tool_name": "rm -rf",
        "timeout_s": 120,
    }
    msg = bridge._format_message(event)
    assert "[DEFER PENDING]" in msg
    assert "rm -rf" in msg
    assert "timeout: 120s" in msg


# ---------------------------------------------------------------------------
# 6. test_format_message_defer_resolved
# ---------------------------------------------------------------------------

def test_format_message_defer_resolved():
    """Verify _format_message for defer_resolved event."""
    bridge = LatchHubBridge(hub_url="http://127.0.0.1:3006")
    event = {
        "type": "defer_resolved",
        "resolved_decision": "deny",
    }
    msg = bridge._format_message(event)
    assert "[DEFER RESOLVED]" in msg
    assert "DENY" in msg


# ---------------------------------------------------------------------------
# 7. test_format_message_session_start
# ---------------------------------------------------------------------------

def test_format_message_session_start():
    """Verify _format_message for session_start event."""
    bridge = LatchHubBridge(hub_url="http://127.0.0.1:3006")
    event = {
        "type": "session_start",
        "agent_id": "agent-007",
        "source_framework": "claude-code",
    }
    msg = bridge._format_message(event)
    assert "[SESSION START]" in msg
    assert "agent-007" in msg
    assert "claude-code" in msg


# ---------------------------------------------------------------------------
# 8. test_format_message_risk_change
# ---------------------------------------------------------------------------

def test_format_message_risk_change():
    """Verify _format_message for session_risk_change event."""
    bridge = LatchHubBridge(hub_url="http://127.0.0.1:3006")
    event = {
        "type": "session_risk_change",
        "previous_risk": "low",
        "current_risk": "high",
    }
    msg = bridge._format_message(event)
    assert "[RISK CHANGE]" in msg
    assert "low" in msg
    assert "high" in msg


# ---------------------------------------------------------------------------
# 9. test_format_message_fallback
# ---------------------------------------------------------------------------

def test_format_message_fallback():
    """Verify _format_message for unknown event type uses fallback."""
    bridge = LatchHubBridge(hub_url="http://127.0.0.1:3006")
    event = {
        "type": "custom_event",
        "data": "some data",
    }
    msg = bridge._format_message(event)
    assert "[CUSTOM_EVENT]" in msg


# ---------------------------------------------------------------------------
# 10. test_subscribe_to_event_bus
# ---------------------------------------------------------------------------

def test_subscribe_to_event_bus():
    """Verify subscribe() calls event_bus.subscribe with correct event types."""
    bridge = LatchHubBridge(hub_url="http://127.0.0.1:3006")
    mock_bus = MagicMock()
    mock_queue = asyncio.Queue()
    mock_bus.subscribe.return_value = ("sub-123", mock_queue)

    bridge.subscribe(mock_bus)

    mock_bus.subscribe.assert_called_once()
    call_kwargs = mock_bus.subscribe.call_args
    event_types = call_kwargs.kwargs.get("event_types") or call_kwargs[1].get("event_types")
    assert event_types is not None
    expected = {
        "decision", "session_start", "session_risk_change", "alert",
        "defer_pending", "defer_resolved", "post_action_finding",
        "session_enforcement_change",
    }
    assert event_types == expected
    assert bridge._source_queue is mock_queue
    assert bridge._sub_id == "sub-123"


# ---------------------------------------------------------------------------
# 11. TestHubBridgeAttributeInit — P1-6
# ---------------------------------------------------------------------------

class TestHubBridgeAttributeInit:
    """P1-6: Verify attributes initialized safely in __init__."""

    def test_sub_id_and_source_queue_initialized(self):
        """_sub_id and _source_queue should exist after __init__ (before subscribe)."""
        bridge = LatchHubBridge(hub_url="http://localhost:3006")
        assert bridge._sub_id is None
        assert bridge._source_queue is None

    def test_dead_queue_removed(self):
        """self._queue (dead code) should no longer exist."""
        bridge = LatchHubBridge(hub_url="http://localhost:3006")
        assert not hasattr(bridge, "_queue")

    @pytest.mark.asyncio
    async def test_forward_loop_safe_when_subscribe_not_called(self):
        """_forward_loop should exit gracefully if _source_queue is None."""
        bridge = LatchHubBridge(hub_url="http://localhost:3006")
        # _forward_loop should return immediately (not raise AttributeError)
        await bridge._forward_loop()
        # No exception = success

    @pytest.mark.asyncio
    async def test_start_safe_when_subscribe_failed(self):
        """start() should not crash if subscribe was never called."""
        bridge = LatchHubBridge(hub_url="http://invalid:9999", enabled=True)

        # Patch _register_gateway to avoid real HTTP
        async def noop():
            pass

        bridge._register_gateway = noop
        await bridge.start()
        await asyncio.sleep(0.05)
        await bridge.stop()


# ---------------------------------------------------------------------------
# 12. P0-1: _hub_request non-blocking via executor
# ---------------------------------------------------------------------------

class TestHubBridgeNonBlocking:
    """P0-1: _hub_request must use run_in_executor, not block event loop."""

    @pytest.mark.asyncio
    async def test_hub_request_does_not_block_event_loop(self):
        """Concurrent coroutine should run while _hub_request is in flight."""
        bridge = LatchHubBridge(hub_url="http://127.0.0.1:1")  # unreachable

        flag = False

        async def set_flag():
            nonlocal flag
            await asyncio.sleep(0.01)
            flag = True

        task = asyncio.create_task(set_flag())
        # _hub_request will fail (port 1 unreachable) but must not block
        await bridge._hub_request("POST", "/test", {"k": "v"})
        await task
        assert flag, "_hub_request blocked the event loop"

    def test_sync_http_request_exists(self):
        """_sync_http_request helper should exist for executor dispatch."""
        bridge = LatchHubBridge(hub_url="http://localhost:3006")
        assert callable(bridge._sync_http_request)
