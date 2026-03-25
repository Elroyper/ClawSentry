"""
OpenClaw event normalizer — OpenClaw events to Canonical Event normalization.

Design basis:
  - 07-openclaw-field-level-mapping.md section 3-4 (event mapping + field contracts)
  - 02-unified-ahp-contract.md section 6.1 (event_id generation)
  - 03-openclaw-adapter-design.md section 2.5 (event mapping matrix)
"""

from __future__ import annotations

import hashlib
import json
import logging

import uuid
from typing import Any, Optional

from ..gateway.models import (
    CanonicalEvent,
    EventType,
    FrameworkMeta,
    NormalizationMeta,
    extract_risk_hints,
    utc_now_iso,
)

logger = logging.getLogger("openclaw-normalizer")

# ---------------------------------------------------------------------------
# OpenClaw → Canonical Event Type Mapping (07 section 3)
# ---------------------------------------------------------------------------

# Maps (openclaw_event_type, optional_state) → (CanonicalEventType, rule_id)
_EVENT_MAPPING: dict[str, tuple[EventType, str]] = {
    "message:received": (EventType.PRE_PROMPT, "oc-message-received"),
    "message:transcribed": (EventType.PRE_PROMPT, "oc-message-transcribed"),
    "message:preprocessed": (EventType.PRE_PROMPT, "oc-message-preprocessed"),
    "message:sent": (EventType.POST_RESPONSE, "oc-message-sent"),
    "exec.approval.requested": (EventType.PRE_ACTION, "oc-exec-approval-requested"),
    "exec.approval.resolved": (EventType.POST_ACTION, "oc-exec-approval-resolved"),
    "session:compact:before": (EventType.SESSION, "oc-session-compact-before"),
    "session:compact:after": (EventType.SESSION, "oc-session-compact-after"),
    "command:new": (EventType.SESSION, "oc-command-new"),
    "command:reset": (EventType.SESSION, "oc-command-reset"),
    "command:stop": (EventType.SESSION, "oc-command-stop"),
    "agent:bootstrap": (EventType.SESSION, "oc-agent-bootstrap"),
    "gateway:startup": (EventType.SESSION, "oc-gateway-startup"),
}

# Chat event state → canonical type (07 section 3 rows 4-7)
_CHAT_STATE_MAPPING: dict[str, tuple[EventType, str]] = {
    "delta": (EventType.POST_RESPONSE, "oc-chat-delta"),
    "final": (EventType.POST_RESPONSE, "oc-chat-final"),
    "aborted": (EventType.ERROR, "oc-chat-aborted"),
    "error": (EventType.ERROR, "oc-chat-error"),
}


# ---------------------------------------------------------------------------
# event_id generation (02 section 6.1)
# ---------------------------------------------------------------------------

def _generate_event_id(
    approval_id: Optional[str],
    run_id: Optional[str],
    source_seq: Optional[int],
    source_framework: str,
    session_id: str,
    event_subtype: str,
    occurred_at: str,
    payload: dict[str, Any],
) -> str:
    """
    Generate stable event_id per 02 section 6.1.

    Priority: approval_id > runId:seq > hash fallback.
    """
    if approval_id:
        raw = f"{source_framework}:{approval_id}:{event_subtype}"
        return hashlib.sha256(raw.encode()).hexdigest()[:24]

    if run_id and source_seq is not None:
        raw = f"{source_framework}:{run_id}:{source_seq}:{event_subtype}"
        return hashlib.sha256(raw.encode()).hexdigest()[:24]

    # Hash fallback (same as a3s_adapter pattern)
    payload_digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str).encode()
    ).hexdigest()[:16]
    raw = f"{source_framework}:{session_id}:{event_subtype}:{occurred_at}:{payload_digest}"
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


# ---------------------------------------------------------------------------
# Core Normalizer
# ---------------------------------------------------------------------------

class OpenClawNormalizer:
    """
    Normalizer for OpenClaw events → CanonicalEvent.

    Responsibilities per 07 section 4:
    - Map event types using the 11-row mapping table.
    - Apply field-level contracts (13 rules).
    - Generate stable event_id (approval_id > runId:seq > hash).
    - Build mapping_profile string.
    - Populate framework_meta.normalization with audit trail.
    - Fill sentinel values for missing fields.
    """

    SOURCE_FRAMEWORK = "openclaw"

    def __init__(
        self,
        source_protocol_version: str,
        git_short_sha: str,
        profile_version: int = 1,
    ) -> None:
        self.source_protocol_version = source_protocol_version
        self.git_short_sha = git_short_sha
        self.profile_version = profile_version
        self._mapping_profile = (
            f"openclaw@{git_short_sha}/protocol.v{source_protocol_version}"
            f"/profile.v{profile_version}"
        )

    def normalize(
        self,
        event_type: str,
        payload: dict[str, Any],
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        run_id: Optional[str] = None,
        source_seq: Optional[int] = None,
        occurred_at: Optional[str] = None,
    ) -> Optional[CanonicalEvent]:
        """
        Normalize an OpenClaw event into a CanonicalEvent.

        Returns None for unmapped event types.
        """
        # Resolve canonical event_type and rule_id
        canonical_type, rule_id = self._resolve_event_type(event_type, payload)
        if canonical_type is None:
            logger.warning("Unmapped OpenClaw event type: %s", event_type)
            return None

        # Per 07 section 4.1: chat events require run_id and source_seq
        if event_type == "chat" and (run_id is None or source_seq is None):
            logger.warning(
                "Chat event missing run_id/source_seq, routing to invalid_event"
            )
            return None

        # Determine event_subtype
        if event_type == "chat":
            state = payload.get("state", "unknown")
            event_subtype = f"chat:{state}"
        else:
            event_subtype = event_type

        # Handle sentinel values
        missing_fields: list[str] = []
        effective_session_id = session_id or CanonicalEvent.sentinel_session_id(self.SOURCE_FRAMEWORK)
        effective_agent_id = agent_id or CanonicalEvent.sentinel_agent_id(self.SOURCE_FRAMEWORK)
        if not session_id:
            missing_fields.append("session_id")
        if not agent_id:
            missing_fields.append("agent_id")

        # Extract approval_id from payload
        approval_id = payload.get("approval_id")

        # Resolve trace_id: run_id > approval_id > provided > uuid
        effective_trace_id = run_id or approval_id or trace_id or str(uuid.uuid4())

        effective_occurred_at = occurred_at or utc_now_iso()

        # Generate stable event_id
        event_id = _generate_event_id(
            approval_id=approval_id,
            run_id=run_id,
            source_seq=source_seq,
            source_framework=self.SOURCE_FRAMEWORK,
            session_id=effective_session_id,
            event_subtype=event_subtype,
            occurred_at=effective_occurred_at,
            payload=payload,
        )

        # Build normalization metadata
        norm_meta = NormalizationMeta(
            rule_id=rule_id,
            inferred=False,
            confidence="high",
            raw_event_type=event_type,
            raw_event_source=self.SOURCE_FRAMEWORK,
            missing_fields=missing_fields,
            fallback_rule="sentinel_value" if missing_fields else None,
        )

        framework_meta = FrameworkMeta(normalization=norm_meta)

        # Extract tool_name
        tool_name = payload.get("tool") or payload.get("tool_name")

        # Extract risk_hints (shared utility in models.py)
        risk_hints = extract_risk_hints(tool_name, str(payload.get("command", "")))

        # Alias OpenClaw output fields to canonical "output" key for post-action analysis
        if canonical_type == EventType.POST_ACTION and "output" not in payload and "result" not in payload:
            for alias in ("toolOutput", "tool_output", "commandOutput", "command_output", "exitOutput", "stdout"):
                if alias in payload and isinstance(payload[alias], str):
                    payload = {**payload, "output": payload[alias]}
                    break

        return CanonicalEvent(
            event_id=event_id,
            trace_id=effective_trace_id,
            event_type=canonical_type,
            session_id=effective_session_id,
            agent_id=effective_agent_id,
            source_framework=self.SOURCE_FRAMEWORK,
            occurred_at=effective_occurred_at,
            payload=payload,
            event_subtype=event_subtype,
            tool_name=tool_name,
            risk_hints=risk_hints,
            framework_meta=framework_meta,
            run_id=run_id,
            approval_id=approval_id,
            source_seq=source_seq,
            source_protocol_version=self.source_protocol_version,
            mapping_profile=self._mapping_profile,
        )

    def _resolve_event_type(
        self, event_type: str, payload: dict[str, Any],
    ) -> tuple[Optional[EventType], Optional[str]]:
        """Resolve OpenClaw event type to canonical type and rule_id."""
        # Chat events need state-based dispatch
        if event_type == "chat":
            state = payload.get("state")
            if state in _CHAT_STATE_MAPPING:
                return _CHAT_STATE_MAPPING[state]
            logger.warning(f"Unknown chat state: {state}")
            return None, None

        # Direct mapping
        if event_type in _EVENT_MAPPING:
            return _EVENT_MAPPING[event_type]

        return None, None


# ---------------------------------------------------------------------------
# Module-level convenience function
# ---------------------------------------------------------------------------

def normalize_openclaw_event(
    normalizer: OpenClawNormalizer,
    event_type: str,
    payload: dict[str, Any],
    **kwargs,
) -> Optional[CanonicalEvent]:
    """Convenience wrapper around OpenClawNormalizer.normalize()."""
    return normalizer.normalize(event_type=event_type, payload=payload, **kwargs)
