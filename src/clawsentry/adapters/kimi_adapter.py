"""Kimi CLI native hook normalization and response translation."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from ..gateway.models import (
    CanonicalEvent,
    EventType,
    FrameworkMeta,
    NormalizationMeta,
    extract_risk_hints,
)
from .a3s_adapter import infer_content_origin
from .event_id import generate_event_id

logger = logging.getLogger(__name__)

_KIMI_HOOK_TYPE_MAP: dict[str, EventType] = {
    "PreToolUse": EventType.PRE_ACTION,
    "PostToolUse": EventType.POST_ACTION,
    "PostToolUseFailure": EventType.POST_ACTION,
    "UserPromptSubmit": EventType.PRE_PROMPT,
    "Stop": EventType.SESSION,
    "StopFailure": EventType.ERROR,
    "SessionStart": EventType.SESSION,
    "SessionEnd": EventType.SESSION,
    "SubagentStart": EventType.SESSION,
    "SubagentStop": EventType.SESSION,
    "PreCompact": EventType.SESSION,
    "PostCompact": EventType.SESSION,
    "Notification": EventType.SESSION,
}

_KIMI_SESSION_SUBTYPES: dict[str, str] = {
    "Stop": "session:stop",
    "StopFailure": "session:stop_failure",
    "SessionStart": "session:start",
    "SessionEnd": "session:end",
    "SubagentStart": "session:subagent_start",
    "SubagentStop": "session:subagent_stop",
    "PreCompact": "session:pre_compact",
    "PostCompact": "session:post_compact",
    "Notification": "session:notification",
}

_KIMI_STRONG_BLOCK_EVENTS = {"PreToolUse", "UserPromptSubmit", "Stop"}
_KIMI_ADVISORY_EVENTS = {
    "PostToolUse",
    "PostToolUseFailure",
    "StopFailure",
    "SessionStart",
    "SessionEnd",
    "SubagentStart",
    "SubagentStop",
    "PreCompact",
    "PostCompact",
    "Notification",
}

# Common Kimi shell tool aliases. Preserve the raw Kimi name in metadata while
# feeding a framework-neutral shell name into ClawSentry policy/risk scoring.
_KIMI_SHELL_TOOL_ALIASES = frozenset({
    "shell",
    "bash",
    "sh",
    "zsh",
    "powershell",
    "terminal",
    "run_shell_command",
    "shell_command",
})


def _canonical_kimi_tool_name(tool_name: str | None) -> str | None:
    if tool_name and tool_name.lower() in _KIMI_SHELL_TOOL_ALIASES:
        return "bash"
    return tool_name


class KimiAdapter:
    """Normalize Kimi CLI hook stdin into :class:`CanonicalEvent`."""

    _DEFAULT_SOURCE_FRAMEWORK = "kimi-cli"

    def __init__(self, source_framework: str | None = None) -> None:
        self.source_framework = source_framework or self._DEFAULT_SOURCE_FRAMEWORK

    def normalize_native_hook_event(
        self,
        message: dict[str, Any],
        *,
        agent_id: str | None = None,
    ) -> CanonicalEvent | None:
        """Normalize Kimi CLI hook JSON from stdin.

        Kimi hook payloads are intentionally close to Claude/Codex native hook
        payloads: top-level ``hook_event_name``, ``tool_name``, ``tool_input``,
        ``session_id`` and ``cwd``.  This adapter keeps Kimi-specific fields in
        payload metadata and maps only the ClawSentry policy-facing names.
        """
        hook_event_name = message.get("hook_event_name")
        if not isinstance(hook_event_name, str):
            logger.debug("Kimi native hook missing hook_event_name")
            return None

        event_type = _KIMI_HOOK_TYPE_MAP.get(hook_event_name)
        if event_type is None:
            logger.debug("Unknown Kimi native hook event: %s", hook_event_name)
            return None

        raw_tool_name = message.get("tool_name")
        kimi_tool_name = raw_tool_name if isinstance(raw_tool_name, str) else None
        tool_name = _canonical_kimi_tool_name(kimi_tool_name)
        tool_input = message.get("tool_input")
        arguments = dict(tool_input) if isinstance(tool_input, dict) else {}

        unified_payload: dict[str, Any] = {
            key: value
            for key, value in message.items()
            if key not in {"hook_event_name", "tool_name", "tool_input"}
        }
        unified_payload["kimi_hook_event_name"] = hook_event_name
        if tool_name:
            unified_payload["tool"] = tool_name
            unified_payload["tool_name"] = tool_name
        if kimi_tool_name:
            unified_payload["kimi_tool_name"] = kimi_tool_name
            if kimi_tool_name != tool_name:
                unified_payload["raw_tool_name"] = kimi_tool_name
        if arguments:
            unified_payload["arguments"] = arguments
            for key in ("command", "file_path", "path", "target"):
                if key in arguments and key not in unified_payload:
                    unified_payload[key] = arguments[key]
        for text_key in (
            "prompt",
            "tool_output",
            "error",
            "error_type",
            "error_message",
            "reason",
            "source",
            "agent_name",
            "response",
            "trigger",
            "token_count",
            "estimated_token_count",
            "sink",
            "notification_type",
            "title",
            "body",
            "severity",
        ):
            if text_key in message and text_key not in unified_payload:
                unified_payload[text_key] = message[text_key]

        command_str = str(arguments.get("command", "")) if arguments else ""
        risk_hints = extract_risk_hints(tool_name, command_str)

        origin = infer_content_origin(tool_name, unified_payload)
        existing_meta = unified_payload.get("_clawsentry_meta")
        meta = dict(existing_meta) if isinstance(existing_meta, dict) else {}
        meta.update(
            {
                "content_origin": origin,
                "kimi_effect_strength": _kimi_effect_strength(hook_event_name),
                "kimi_effect_capability": "native_allow_block_only",
            }
        )
        if kimi_tool_name:
            meta["raw_tool_name"] = kimi_tool_name
        unified_payload["_clawsentry_meta"] = meta

        subtype = _KIMI_SESSION_SUBTYPES.get(hook_event_name, hook_event_name)
        now = datetime.now(timezone.utc)
        session_id = message.get("session_id")
        effective_session = (
            session_id
            if isinstance(session_id, str) and session_id.strip()
            else f"unknown_session:{self.source_framework}"
        )
        effective_agent = agent_id or f"unknown_agent:{self.source_framework}"
        missing: list[str] = []
        if not isinstance(session_id, str) or not session_id.strip():
            missing.append("session_id")
        if agent_id is None:
            missing.append("agent_id")

        trace_id = (
            message.get("tool_call_id")
            or message.get("turn_id")
            or message.get("session_id")
        )
        if not isinstance(trace_id, str) or not trace_id.strip():
            trace_id = None

        event_id = generate_event_id(
            self.source_framework,
            effective_session,
            subtype,
            now.isoformat(),
            unified_payload,
        )

        norm_meta = NormalizationMeta(
            rule_id="kimi-native-hook-direct-map",
            inferred=False,
            confidence="high",
            raw_event_type=hook_event_name,
            raw_event_source=self.source_framework,
            missing_fields=missing,
            fallback_rule="sentinel_value" if missing else None,
        )

        return CanonicalEvent(
            schema_version="ahp.1.0",
            event_id=event_id,
            trace_id=trace_id or event_id,
            event_type=event_type,
            session_id=effective_session,
            agent_id=effective_agent,
            source_framework=self.source_framework,
            occurred_at=now.isoformat(),
            payload=unified_payload,
            tool_name=tool_name,
            risk_hints=risk_hints,
            event_subtype=subtype,
            framework_meta=FrameworkMeta(normalization=norm_meta),
        )


def _kimi_effect_strength(hook_event_name: str) -> str:
    if hook_event_name in _KIMI_STRONG_BLOCK_EVENTS:
        return "strong"
    if hook_event_name in _KIMI_ADVISORY_EVENTS:
        return "advisory"
    return "unknown"


def decision_to_kimi_hook_output(
    result: dict[str, Any],
    hook_event_name: str,
    raw_msg: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Translate an internal ClawSentry result to Kimi hook stdout JSON.

    Kimi server hooks support allow/block only: empty stdout allows execution,
    while JSON stdout containing ``hookSpecificOutput.permissionDecision=deny``
    blocks.  Native modify/defer semantics are not available in phase 1.  A
    ClawSentry ``defer`` is represented as a Kimi deny; ``modify`` fails open
    because there is no Kimi native rewrite contract.
    """
    action = result.get("action", "continue")
    metadata = result.get("metadata", {}) if isinstance(result.get("metadata"), dict) else {}
    policy_id = str(metadata.get("policy_id", ""))
    if policy_id.startswith("fallback-"):
        return None

    if action in {"continue", "allow", "modify"}:
        return None
    if action not in {"block", "defer"}:
        return None
    if hook_event_name in _KIMI_ADVISORY_EVENTS:
        return None
    if hook_event_name == "Stop" and raw_msg and raw_msg.get("stop_hook_active") is True:
        return None

    reason = str(result.get("reason") or "Blocked by ClawSentry security policy")
    risk_level = str(metadata.get("risk_level") or "unknown")
    message = f"[ClawSentry] {reason} (risk: {risk_level})"
    return {
        "hookSpecificOutput": {
            "hookEventName": hook_event_name,
            "permissionDecision": "deny",
            "permissionDecisionReason": message,
        }
    }
