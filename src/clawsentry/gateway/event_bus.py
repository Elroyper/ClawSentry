"""In-process event bus for SSE stream subscribers."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

import uuid

logger = logging.getLogger("clawsentry")

_RISK_LEVEL_RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _risk_rank(risk_level: Optional[str]) -> int:
    return _RISK_LEVEL_RANK.get(str(risk_level or "low").lower(), 0)


class EventBus:
    """In-process event bus for SSE stream subscribers."""

    MAX_SUBSCRIBERS = 100
    MAX_QUEUE_SIZE = 500
    REPLAY_BUFFER_SIZE = 50

    def __init__(self) -> None:
        from collections import deque
        self._subscribers: dict[str, dict[str, Any]] = {}
        self._replay_buffer: deque = deque(maxlen=self.REPLAY_BUFFER_SIZE)

    def subscribe(
        self,
        *,
        session_id: Optional[str] = None,
        min_risk: Optional[str] = None,
        event_types: Optional[set[str]] = None,
    ) -> tuple[Optional[str], Optional[asyncio.Queue]]:
        if len(self._subscribers) >= self.MAX_SUBSCRIBERS:
            return None, None

        subscriber_id = f"sub-{uuid.uuid4().hex}"
        queue: asyncio.Queue = asyncio.Queue(maxsize=self.MAX_QUEUE_SIZE)
        subscriber = {
            "queue": queue,
            "session_id": session_id,
            "min_risk": min_risk,
            "event_types": event_types or {"decision", "session_risk_change", "session_start", "session_enforcement_change", "post_action_finding", "trajectory_alert", "pattern_evolved", "defer_pending", "defer_resolved"},
        }
        self._subscribers[subscriber_id] = subscriber

        # Replay recent events to new subscriber
        for event in self._replay_buffer:
            if self._matches(subscriber, event):
                try:
                    queue.put_nowait(event)
                except asyncio.QueueFull:
                    break

        return subscriber_id, queue

    def unsubscribe(self, subscriber_id: str) -> None:
        self._subscribers.pop(subscriber_id, None)

    def _matches(self, subscriber: dict[str, Any], event: dict[str, Any]) -> bool:
        event_type = str(event.get("type") or "")
        if event_type not in subscriber["event_types"]:
            return False
        if subscriber.get("session_id") and event.get("session_id") != subscriber["session_id"]:
            return False
        if subscriber.get("min_risk"):
            event_risk = str(event.get("risk_level") or event.get("current_risk") or "low")
            if _risk_rank(event_risk) < _risk_rank(subscriber["min_risk"]):
                return False
        return True

    def broadcast(self, event: dict[str, Any]) -> None:
        self._replay_buffer.append(event)
        for sub_id, subscriber in list(self._subscribers.items()):
            if not self._matches(subscriber, event):
                continue
            queue = subscriber["queue"]
            if queue.full():
                try:
                    queue.get_nowait()
                    subscriber["dropped_count"] = subscriber.get("dropped_count", 0) + 1
                    logger.warning(
                        "EventBus: dropped oldest event for subscriber %s (total dropped: %d)",
                        sub_id,
                        subscriber["dropped_count"],
                    )
                except asyncio.QueueEmpty:
                    pass
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                pass
