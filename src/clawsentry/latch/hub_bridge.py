"""LatchHubBridge — forward Gateway SSE events to Latch Hub.

Subscribes to the Gateway EventBus and forwards events to the Latch Hub
CLI session API, so that mobile/remote operators can monitor activity.

Environment variables:
  CS_LATCH_HUB_URL — Hub base URL (e.g. http://127.0.0.1:3006)
  CS_HUB_BRIDGE_ENABLED — auto/true/false (default: auto)
  CS_LATCH_HUB_PORT — Hub port when URL not set (default: 3006)
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)


class LatchHubBridge:
    """Forward Gateway events to Latch Hub via HTTP API.

    Each unique session_id gets a Hub CLI session. Events are posted
    as messages to the corresponding Hub session.
    """

    def __init__(
        self,
        hub_url: str,
        token: str = "",
        *,
        enabled: bool = True,
    ) -> None:
        self.hub_url = hub_url.rstrip("/")
        self.token = token
        self.enabled = enabled
        self._session_map: dict[str, str] = {}  # cs session_id -> hub session id
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=1000)
        self._task: Optional[asyncio.Task] = None

    def subscribe(self, event_bus) -> None:
        """Subscribe to all relevant event types on the EventBus."""
        event_types = {
            "decision", "session_start", "session_risk_change", "alert",
            "defer_pending", "defer_resolved", "post_action_finding",
            "session_enforcement_change",
        }
        sub_id, queue = event_bus.subscribe(event_types=event_types)
        if sub_id is None or queue is None:
            logger.warning("Failed to subscribe to EventBus for Hub bridge")
            return
        self._sub_id = sub_id
        self._source_queue = queue

    async def start(self) -> None:
        """Start the background forwarding loop."""
        if not self.enabled:
            return
        self._task = asyncio.create_task(self._forward_loop())

    async def stop(self) -> None:
        """Stop the forwarding loop."""
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def _forward_loop(self) -> None:
        """Read events from source queue and forward to Hub."""
        while True:
            try:
                event = await self._source_queue.get()
                await self._forward_event(event)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.debug("Hub bridge forward error", exc_info=True)

    async def _forward_event(self, event: dict[str, Any]) -> None:
        """Forward a single event to Hub."""
        session_id = str(event.get("session_id") or "unknown")
        hub_session_id = await self._ensure_hub_session(session_id, event)
        if hub_session_id is None:
            return
        await self._post_message(hub_session_id, event)

    async def _ensure_hub_session(
        self, session_id: str, event: dict[str, Any],
    ) -> Optional[str]:
        """Create a Hub CLI session if one doesn't exist for this session_id."""
        if session_id in self._session_map:
            return self._session_map[session_id]

        body = {
            "title": f"ClawSentry: {session_id[:20]}",
            "metadata": {
                "clawsentry_session_id": session_id,
                "source_framework": str(event.get("source_framework") or "unknown"),
            },
        }
        resp = await self._hub_request("POST", "/cli/sessions", body)
        if resp is None:
            return None
        hub_id = str(resp.get("id") or resp.get("session_id") or "")
        if hub_id:
            self._session_map[session_id] = hub_id
            return hub_id
        return None

    async def _post_message(
        self, hub_session_id: str, event: dict[str, Any],
    ) -> None:
        """Post an event as a message to a Hub CLI session."""
        body = {
            "role": "system",
            "content": self._format_message(event),
            "metadata": {
                "event_type": str(event.get("type") or "unknown"),
                "clawsentry": True,
            },
        }
        await self._hub_request(
            "POST", f"/cli/sessions/{hub_session_id}/messages", body,
        )

    def _format_message(self, event: dict[str, Any]) -> str:
        """Format an event into a human-readable message for Hub."""
        event_type = str(event.get("type") or "unknown")

        if event_type == "decision":
            decision = str(event.get("decision") or "unknown")
            tool = str(event.get("tool_name") or "")
            risk = str(event.get("risk_level") or "low")
            reason = str(event.get("reason") or "")
            parts = [f"[{decision.upper()}] {tool} (risk: {risk})"]
            if reason:
                parts.append(f"Reason: {reason}")
            return " | ".join(parts)

        if event_type == "alert":
            severity = str(event.get("severity") or "unknown")
            message = str(event.get("message") or "")
            return f"[ALERT:{severity.upper()}] {message}"

        if event_type == "defer_pending":
            tool = str(event.get("tool_name") or "")
            timeout = event.get("timeout_s", 300)
            return f"[DEFER PENDING] {tool} — awaiting operator approval (timeout: {int(timeout)}s)"

        if event_type == "defer_resolved":
            resolved = str(event.get("resolved_decision") or "unknown")
            return f"[DEFER RESOLVED] {resolved.upper()}"

        if event_type == "session_start":
            agent = str(event.get("agent_id") or "unknown")
            framework = str(event.get("source_framework") or "unknown")
            return f"[SESSION START] Agent: {agent} ({framework})"

        if event_type == "session_risk_change":
            prev = str(event.get("previous_risk") or "low")
            curr = str(event.get("current_risk") or "low")
            return f"[RISK CHANGE] {prev} → {curr}"

        # Fallback
        return f"[{event_type.upper()}] {json.dumps(event, default=str)[:200]}"

    async def _hub_request(
        self,
        method: str,
        path: str,
        body: dict[str, Any],
    ) -> Optional[dict[str, Any]]:
        """Make an HTTP request to Hub with retry."""
        import urllib.request
        import urllib.error

        url = f"{self.hub_url}{path}"
        data = json.dumps(body).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        for attempt in range(2):
            try:
                req = urllib.request.Request(
                    url, data=data, headers=headers, method=method,
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    resp_data = resp.read().decode("utf-8")
                    try:
                        return json.loads(resp_data)
                    except json.JSONDecodeError:
                        return {}
            except (OSError, urllib.error.URLError) as exc:
                if attempt == 0:
                    logger.debug("Hub request failed (attempt 1): %s", exc)
                    await asyncio.sleep(0.5)
                else:
                    logger.debug("Hub request failed (attempt 2): %s", exc)
                    return None
        return None
