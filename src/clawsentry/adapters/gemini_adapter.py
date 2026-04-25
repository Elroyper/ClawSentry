"""Gemini CLI native hook normalization and response translation."""

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

_GEMINI_HOOK_TYPE_MAP: dict[str, EventType] = {
    "SessionStart": EventType.SESSION,
    "SessionEnd": EventType.SESSION,
    "BeforeAgent": EventType.PRE_PROMPT,
    "AfterAgent": EventType.POST_RESPONSE,
    "BeforeModel": EventType.PRE_PROMPT,
    "AfterModel": EventType.POST_RESPONSE,
    "BeforeToolSelection": EventType.PRE_PROMPT,
    "BeforeTool": EventType.PRE_ACTION,
    "AfterTool": EventType.POST_ACTION,
    "PreCompress": EventType.SESSION,
    "Notification": EventType.SESSION,
}

_GEMINI_SESSION_SUBTYPES: dict[str, str] = {
    "SessionStart": "session:start",
    "SessionEnd": "session:end",
    "PreCompress": "session:pre_compress",
    "Notification": "session:notification",
}

_GEMINI_STRONG_BLOCK_EVENTS = {
    "BeforeAgent",
    "AfterAgent",
    "BeforeModel",
    "AfterModel",
    "BeforeTool",
    "AfterTool",
}

_GEMINI_ADVISORY_EVENTS = {"SessionStart", "SessionEnd", "PreCompress", "Notification"}

# Gemini CLI reports shell execution through a provider-specific tool name.
# ClawSentry policy/risk scoring is intentionally framework-neutral and already
# understands canonical shell tools such as ``bash``. Preserve Gemini's raw tool
# identity in the payload while feeding the canonical name into risk/policy code.
_GEMINI_SHELL_TOOL_ALIASES = frozenset({
    "run_shell_command",
    "shell_command",
    "execute_shell",
    "run_command",
})


def _canonical_gemini_tool_name(tool_name: str | None) -> str | None:
    if tool_name and tool_name.lower() in _GEMINI_SHELL_TOOL_ALIASES:
        return "bash"
    return tool_name


class GeminiAdapter:
    """Normalize Gemini CLI native hook stdin into CanonicalEvent."""

    _DEFAULT_SOURCE_FRAMEWORK = "gemini-cli"

    def __init__(self, source_framework: str | None = None) -> None:
        self.source_framework = source_framework or self._DEFAULT_SOURCE_FRAMEWORK

    def normalize_native_hook_event(
        self,
        message: dict[str, Any],
        *,
        agent_id: str | None = None,
    ) -> CanonicalEvent | None:
        """Normalize Gemini CLI hook JSON from stdin."""
        hook_event_name = message.get("hook_event_name")
        if not isinstance(hook_event_name, str):
            logger.debug("Gemini native hook missing hook_event_name")
            return None

        event_type = _GEMINI_HOOK_TYPE_MAP.get(hook_event_name)
        if event_type is None:
            logger.debug("Unknown Gemini native hook event: %s", hook_event_name)
            return None

        raw_tool_name = message.get("tool_name")
        gemini_tool_name = raw_tool_name if isinstance(raw_tool_name, str) else None
        tool_name = _canonical_gemini_tool_name(gemini_tool_name)
        tool_input = message.get("tool_input")
        arguments = dict(tool_input) if isinstance(tool_input, dict) else {}

        unified_payload: dict[str, Any] = {
            key: value
            for key, value in message.items()
            if key not in {"hook_event_name", "tool_name", "tool_input"}
        }
        unified_payload["gemini_hook_event_name"] = hook_event_name
        if tool_name:
            unified_payload["tool"] = tool_name
            unified_payload["tool_name"] = tool_name
        if gemini_tool_name and gemini_tool_name != tool_name:
            unified_payload["gemini_tool_name"] = gemini_tool_name
        if arguments:
            unified_payload["arguments"] = arguments
            for key in ("command", "file_path", "path", "target"):
                if key in arguments and key not in unified_payload:
                    unified_payload[key] = arguments[key]
        for text_key in ("prompt", "prompt_response", "llm_request", "llm_response", "notification_type", "message", "details"):
            if text_key in message and text_key not in unified_payload:
                unified_payload[text_key] = message[text_key]

        command_str = str(arguments.get("command", "")) if arguments else ""
        risk_hints = extract_risk_hints(tool_name, command_str)

        origin = infer_content_origin(tool_name, unified_payload)
        existing_meta = unified_payload.get("_clawsentry_meta")
        meta = dict(existing_meta) if isinstance(existing_meta, dict) else {}
        meta_update = {
            "content_origin": origin,
            "gemini_effect_strength": _gemini_effect_strength(hook_event_name),
        }
        if gemini_tool_name:
            meta_update["raw_tool_name"] = gemini_tool_name
        meta.update(meta_update)
        unified_payload["_clawsentry_meta"] = meta

        subtype = _GEMINI_SESSION_SUBTYPES.get(hook_event_name, hook_event_name)
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

        trace_id = message.get("tool_use_id") or message.get("turn_id") or message.get("session_id")
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
            rule_id="gemini-native-hook-direct-map",
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


def _gemini_effect_strength(hook_event_name: str) -> str:
    if hook_event_name in _GEMINI_STRONG_BLOCK_EVENTS:
        return "strong"
    if hook_event_name == "BeforeToolSelection":
        return "partial"
    return "advisory" if hook_event_name in _GEMINI_ADVISORY_EVENTS else "unknown"


def decision_to_gemini_hook_output(
    result: dict[str, Any],
    hook_event_name: str,
    raw_msg: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Translate an internal ClawSentry decision result to Gemini hook stdout JSON.

    Returning ``None`` means fail-open/allow with empty stdout. Gemini parses
    JSON-only stdout; callers must route logs to stderr.
    """
    action = result.get("action", "continue")
    metadata = result.get("metadata", {}) if isinstance(result.get("metadata"), dict) else {}
    policy_id = str(metadata.get("policy_id", ""))
    if policy_id.startswith("fallback-"):
        return None

    if action in {"continue", "allow"}:
        return None

    reason = str(result.get("reason") or "Blocked by ClawSentry security policy")
    risk_level = str(metadata.get("risk_level") or "unknown")
    message = f"[ClawSentry] {reason} (risk: {risk_level})"

    if action == "modify":
        return _gemini_modify_output(result, hook_event_name)

    if action not in {"block", "defer"}:
        return None

    if hook_event_name in _GEMINI_ADVISORY_EVENTS:
        return {
            "systemMessage": message,
            "suppressOutput": True,
        }

    if hook_event_name == "BeforeToolSelection":
        return None

    if hook_event_name == "AfterAgent" and raw_msg and raw_msg.get("stop_hook_active") is True:
        return {
            "continue": False,
            "stopReason": message,
            "reason": message,
        }

    return {"decision": "deny", "reason": message}


def _gemini_modify_output(result: dict[str, Any], hook_event_name: str) -> dict[str, Any] | None:
    modified = result.get("modified_payload")
    if not isinstance(modified, dict):
        return None

    hook_specific: dict[str, Any] = {"hookEventName": hook_event_name}
    if hook_event_name == "BeforeTool":
        tool_input = modified.get("tool_input") or modified.get("arguments") or modified
        if isinstance(tool_input, dict):
            hook_specific["tool_input"] = tool_input
    elif hook_event_name == "BeforeAgent":
        additional = modified.get("additionalContext") or modified.get("additional_context")
        if isinstance(additional, str):
            hook_specific["additionalContext"] = additional
    elif hook_event_name == "BeforeModel":
        if isinstance(modified.get("llm_request"), dict):
            hook_specific["llm_request"] = modified["llm_request"]
        if isinstance(modified.get("llm_response"), dict):
            hook_specific["llm_response"] = modified["llm_response"]
    elif hook_event_name == "AfterModel":
        if isinstance(modified.get("llm_response"), dict):
            hook_specific["llm_response"] = modified["llm_response"]
    elif hook_event_name == "BeforeToolSelection":
        tool_config = modified.get("toolConfig") or modified.get("tool_config")
        if isinstance(tool_config, dict):
            hook_specific["toolConfig"] = tool_config
    elif hook_event_name in {"SessionStart", "AfterTool"}:
        additional = modified.get("additionalContext") or modified.get("additional_context")
        if isinstance(additional, str):
            hook_specific["additionalContext"] = additional

    if len(hook_specific) == 1:
        return None
    return {"hookSpecificOutput": hook_specific}
