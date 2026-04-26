"""Small helpers for the A3S demo L3 terminal event stream."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any


def clip(value: Any, limit: int = 180) -> str:
    """Return a compact one-line value, preserving enough identifier context."""

    text = " ".join(str(value or "").split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def current_time() -> str:
    """Timestamp format used by the concise terminal stream."""

    return datetime.now().strftime("%H:%M:%S")


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _decision_value(payload: Mapping[str, Any], key: str, default: str = "-") -> Any:
    nested_decision = _mapping(payload.get("decision"))
    return nested_decision.get(key) or payload.get(key) or default


def _event_value(payload: Mapping[str, Any], key: str, default: str = "-") -> Any:
    nested_event = _mapping(payload.get("event"))
    return nested_event.get(key) or payload.get(key) or default


def _decision_command(payload: Mapping[str, Any]) -> Any:
    nested_event = _mapping(payload.get("event"))
    event_payload = _mapping(nested_event.get("payload") or payload.get("payload"))
    command = (
        payload.get("command")
        or event_payload.get("command")
        or event_payload.get("prompt")
        or event_payload.get("response_text")
    )
    arguments = _mapping(event_payload.get("arguments"))
    if not command:
        command = arguments.get("command") or arguments.get("path")
    return command


def format_event(
    payload: Mapping[str, Any],
    *,
    now_fn: Callable[[], str] = current_time,
) -> str:
    """Format a report-stream SSE payload for the demo terminal.

    The gateway currently broadcasts flattened report events. Older demo code
    expected nested ``event`` / ``decision`` dictionaries, so this formatter
    accepts both shapes and treats malformed nested fields as absent.
    """

    kind = str(payload.get("type") or "event")
    if kind == "decision":
        decision = str(_decision_value(payload, "decision")).upper()
        return (
            f"[{now_fn()}] DECISION {decision} "
            f"risk={_decision_value(payload, 'risk_level')} "
            f"tier={payload.get('actual_tier') or '-'} "
            f"tool={_event_value(payload, 'tool_name')} "
            f"session={clip(_event_value(payload, 'session_id'), 8)} "
            f"cmd={clip(_decision_command(payload))} "
            f"reason={clip(_decision_value(payload, 'reason', ''))}"
        )
    if kind == "alert":
        return (
            f"[{now_fn()}] ALERT {str(payload.get('severity') or '-').upper()} "
            f"session={clip(payload.get('session_id'), 8)} {clip(payload.get('message'))}"
        )
    if kind.startswith("l3_advisory"):
        state = payload.get("l3_state") or payload.get("job_state")
        if not state and kind == "l3_advisory_snapshot":
            state = "created"
        return (
            f"[{now_fn()}] L3 {kind.replace('l3_advisory_', '').upper()} "
            f"state={state or '-'} "
            f"risk={payload.get('risk_level','-')} "
            f"action={payload.get('recommended_operator_action','-')} "
            f"session={clip(payload.get('session_id'), 8)}"
        )
    return f"[{now_fn()}] {kind.upper()} {clip(json.dumps(dict(payload), ensure_ascii=False), 220)}"
