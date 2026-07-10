"""Approval and rewrite helpers used by the gateway decision flow."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from typing import Any, Optional

from clawsentry.gateway.models import CanonicalEvent, DecisionContext, DecisionEffects, EventType

_APPROVAL_PENDING_REASON_CODE = "approval_pending"
_APPROVAL_ALLOWED_REASON_CODE = "approval_allowed"
_APPROVAL_DENIED_REASON_CODE = "approval_denied"
_APPROVAL_TIMEOUT_REASON_CODE = "approval_timeout"
_APPROVAL_NO_ROUTE_REASON_CODE = "approval_no_route"
_APPROVAL_QUEUE_FULL_REASON_CODE = "approval_queue_full"
_APPROVAL_FIELD_SOURCE_ADAPTER = "adapter_provided"
_APPROVAL_FIELD_SOURCE_GENERATED = "generated"
_APPROVAL_FIELD_SOURCE_UNAVAILABLE = "unavailable"


def _redacted_target_preview(value: Any, *, max_len: int = 96) -> str:
    text = str(value or "").replace("\n", " ").strip()
    if not text:
        return ""
    text = re.sub(r"/workspace/[^\s'\"<>|)]+", "/workspace/<redacted>", text)
    text = re.sub(r"/home/[^\s'\"<>|)]+", "/home/<redacted>", text)
    text = re.sub(r"~/?[^\s'\"<>|)]*", "~/<redacted>", text)
    text = re.sub(r"(?i)(token|password|secret|api_key)=([^\s&]+)", r"\1=<redacted>", text)
    if len(text) > max_len:
        text = text[: max_len - 1] + "\u2026"
    return text


def _is_confirmation_fast_lane(
    event: dict[str, Any],
    compat_event_type: Optional[str],
) -> bool:
    if str(compat_event_type or "").strip().lower() == "confirmation":
        return True
    return str(event.get("event_subtype") or "").strip().lower() == "compat:confirmation"


def _resolve_confirmation_approval_id(event: dict[str, Any]) -> str:
    explicit = str(event.get("approval_id") or "").strip()
    if explicit:
        return explicit

    payload = event.get("payload")
    if isinstance(payload, dict):
        payload_explicit = str(payload.get("approval_id") or "").strip()
        if payload_explicit:
            return payload_explicit
        meta = payload.get("_clawsentry_meta")
        if isinstance(meta, dict):
            compat_meta = meta.get("ahp_compat")
            if isinstance(compat_meta, dict):
                identity = compat_meta.get("identity")
                if isinstance(identity, dict):
                    compat_explicit = str(identity.get("approval_id") or "").strip()
                    if compat_explicit:
                        return compat_explicit

    event_id = str(event.get("event_id") or "").strip()
    if event_id:
        return f"bridge-confirm-{event_id}"
    return f"bridge-confirm-{uuid.uuid4().hex[:12]}"


def _approval_pending_meta(
    *,
    approval_id: str,
    approval_kind: str,
    approval_reason: str,
    approval_timeout_s: float,
) -> dict[str, Any]:
    return {
        "approval_id": approval_id,
        "approval_kind": approval_kind,
        "approval_state": "pending",
        "approval_reason": approval_reason,
        "approval_reason_code": _APPROVAL_PENDING_REASON_CODE,
        "approval_timeout_s": approval_timeout_s,
    }


def _approval_prompt_context(
    *,
    event: dict[str, Any],
    decision: dict[str, Any],
) -> dict[str, Any]:
    payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
    operation_source = _APPROVAL_FIELD_SOURCE_UNAVAILABLE
    operation = _redacted_target_preview(
        event.get("tool_name")
        or payload.get("tool")
        or payload.get("operation")
        or "unknown",
        max_len=80,
    ).strip() or "unknown"
    if operation != "unknown":
        operation_source = _APPROVAL_FIELD_SOURCE_ADAPTER
    affected_target = "unspecified target"
    affected_target_source = _APPROVAL_FIELD_SOURCE_UNAVAILABLE
    for key in (
        "target",
        "path",
        "file_path",
        "workspace_root",
        "workspace",
        "cwd",
        "working_directory",
    ):
        value = payload.get(key)
        if value is None:
            value = event.get(key)
        text = str(value or "").strip()
        if text:
            affected_target = text
            affected_target_source = _APPROVAL_FIELD_SOURCE_ADAPTER
            break
    affected_target = _redacted_target_preview(affected_target) or "unspecified target"
    risk_level = str(decision.get("risk_level") or "unknown")
    policy_id = str(decision.get("policy_id") or "unknown")
    consequence = (
        f"Approving lets {operation} proceed against {affected_target} "
        f"under {risk_level} risk policy {policy_id}."
    )
    command = str(payload.get("command") or "").lower()
    if "rm " in command or "delete" in command or "remove" in command:
        rollback_hint = (
            "Restore from VCS, snapshot, or backup before retrying; verify the "
            "affected path before approval."
        )
    else:
        rollback_hint = (
            "Use adapter or tool rollback support when available; otherwise keep "
            "the action read-only until an operator confirms recovery steps."
        )
    return {
        "affected_target": affected_target,
        "operation": operation,
        "consequence": consequence,
        "dry_run_or_narrower_scope_suggestion": (
            "Prefer a dry-run/read-only preview or narrow the action to the "
            "smallest explicit target before approval."
        ),
        "rollback_hint": rollback_hint,
        "field_sources": {
            "affected_target": affected_target_source,
            "operation": operation_source,
            "consequence": _APPROVAL_FIELD_SOURCE_GENERATED,
            "dry_run_or_narrower_scope_suggestion": _APPROVAL_FIELD_SOURCE_GENERATED,
            "rollback_hint": _APPROVAL_FIELD_SOURCE_GENERATED,
        },
        "redaction_policy_version": "cs.approval_prompt.v1",
    }


def _approval_prompt_event_fields(
    *,
    event: dict[str, Any],
    decision: dict[str, Any],
) -> dict[str, Any]:
    prompt = _approval_prompt_context(event=event, decision=decision)
    return {
        "approval_prompt": prompt,
        "approval_affected_target": prompt["affected_target"],
        "approval_operation": prompt["operation"],
        "approval_consequence": prompt["consequence"],
        "approval_dry_run_or_narrower_scope_suggestion": (
            prompt["dry_run_or_narrower_scope_suggestion"]
        ),
        "approval_rollback_hint": prompt["rollback_hint"],
        "approval_field_sources": prompt["field_sources"],
    }


def _approval_resolution_meta(
    *,
    approval_id: str,
    approval_kind: str,
    approval_state: str,
    approval_reason: str,
    approval_reason_code: str,
    approval_timeout_s: float,
) -> dict[str, Any]:
    return {
        "approval_id": approval_id,
        "approval_kind": approval_kind,
        "approval_state": approval_state,
        "approval_reason": approval_reason,
        "approval_reason_code": approval_reason_code,
        "approval_timeout_s": approval_timeout_s,
    }


def _payload_hash(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _approval_binding_from_snapshot(
    *,
    event: dict[str, Any],
    snapshot: dict[str, Any],
    context: DecisionContext | None,
) -> dict[str, Any] | None:
    effect_summary = snapshot.get("effect_summary")
    if not isinstance(effect_summary, dict):
        return None
    binding: dict[str, Any] = {}
    for source_key, target_key in (
        ("canonical_argv_hash", "canonical_argv_hash"),
        ("raw_payload_hash", "raw_payload_hash"),
    ):
        value = effect_summary.get(source_key)
        if value:
            binding[target_key] = str(value)
    targets = effect_summary.get("targets")
    if isinstance(targets, list) and targets:
        binding["effect_hash"] = _payload_hash({
            "effects": effect_summary.get("effects") or [],
            "targets": [
                {
                    "kind": target.get("kind"),
                    "path_hash": target.get("path_hash"),
                    "path_role": target.get("path_role"),
                }
                for target in targets
                if isinstance(target, dict)
            ],
        })
    session_id = event.get("session_id")
    agent_id = event.get("agent_id")
    if session_id:
        binding["session_id"] = str(session_id)
    if agent_id:
        binding["agent_id"] = str(agent_id)
    if context and context.session_scope_profile:
        profile = context.session_scope_profile
        binding["capability_profile_id"] = profile.profile_id
        binding["profile_fingerprint"] = _payload_hash(profile.model_dump(mode="json"))
    cwd = event.get("cwd") or event.get("working_directory")
    payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
    if cwd is None:
        cwd = payload.get("cwd") or payload.get("working_directory")
    if cwd:
        binding["cwd_hash"] = _payload_hash(str(cwd))
    policy_projection = {
        "schema": "cs.approval_binding_policy.v1",
        "effect_schema": effect_summary.get("schema"),
        "profile_id": binding.get("capability_profile_id"),
    }
    binding["policy_fingerprint"] = _payload_hash(policy_projection)
    binding["env_fingerprint"] = _payload_hash({
        "schema": "cs.policy_env_fingerprint.v1",
        "env": "unavailable",
    })
    return binding or None


def _event_for_effect_resolution(event: CanonicalEvent) -> CanonicalEvent:
    if event.event_type == EventType.PRE_ACTION:
        return event
    return event.model_copy(update={"event_type": EventType.PRE_ACTION})


def _redacted_preview(value: Any, *, max_len: int = 96) -> str:
    if isinstance(value, dict):
        for key in ("command", "input", "tool_input"):
            if key in value:
                value = value[key]
                break
    text = str(value or "").replace("\n", " ").strip()
    for marker in ("token=", "password=", "secret=", "api_key="):
        lower = text.lower()
        idx = lower.find(marker)
        if idx >= 0:
            end = text.find(" ", idx)
            if end < 0:
                end = len(text)
            text = text[: idx + len(marker)] + "\u2026" + text[end:]
    if len(text) > max_len:
        return text[: max_len - 1] + "\u2026"
    return text


def _validate_rewrite_resolution_payload(payload: Any) -> dict[str, Any]:
    """Validate operator rewrite payloads before producing MODIFY decisions."""

    if not isinstance(payload, dict) or not payload:
        raise ValueError("rewrite resolution payload must contain command or tool_input")
    if "prompt" in payload:
        raise ValueError("prompt rewrite is out of scope for decision_effects.v1")

    command = payload.get("command")
    if command is not None:
        command_text = str(command).strip()
        if not command_text:
            raise ValueError("rewrite command must be non-empty")
        return {"command": command_text}

    tool_input = payload.get("tool_input")
    if isinstance(tool_input, dict) and tool_input:
        if "prompt" in tool_input:
            raise ValueError("prompt rewrite is out of scope for decision_effects.v1")
        validated: dict[str, Any] = {"tool_input": dict(tool_input)}
        tool_name = payload.get("tool_name") or payload.get("tool")
        if tool_name is not None:
            validated["tool_name"] = str(tool_name)
        return validated

    raise ValueError("rewrite resolution payload must contain command or tool_input")


def _rewrite_effect_for_resolution(
    *,
    approval_id: str,
    event: dict[str, Any],
    replacement_payload: dict[str, Any],
    resolver_identity: str | None,
    policy_id: str,
) -> DecisionEffects:
    original_payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
    original_command = original_payload.get("command") or original_payload.get("arguments") or original_payload
    validated_payload = _validate_rewrite_resolution_payload(replacement_payload)
    target = "command" if "command" in validated_payload else "tool_input"
    return DecisionEffects(
        effect_id=f"eff-{approval_id}-rewrite",
        action_scope="action",
        rewrite_effect={
            "requested": True,
            "target": target,
            "approval_id": approval_id,
            "original_hash": _payload_hash(original_command),
            "original_preview_redacted": _redacted_preview(original_command),
            "replacement_hash": _payload_hash(validated_payload),
            "replacement_preview_redacted": _redacted_preview(validated_payload),
            "replacement_payload": dict(validated_payload),
            "redaction_policy_version": "cs.redaction.v1",
            "rewrite_source": "operator" if resolver_identity else "system",
            "policy_id": policy_id,
            "post_rewrite_validation_id": f"validation-{approval_id}",
        },
    )
