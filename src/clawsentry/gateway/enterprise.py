"""Enterprise reporting facade and TrinityGuard-derived risk mapping."""

from __future__ import annotations

import asyncio
import logging
import json
import time
import os
from typing import TYPE_CHECKING, Any, Optional

from .llm_settings import resolve_llm_settings
from .models import utc_now_iso
from .llm_provider import AnthropicProvider, LLMProviderConfig, OpenAIProvider
from .risk_signals import (
    build_archive_command_signals,
    build_base_event_signals,
    has_decode_pipe_exec_command,
    has_eval_decode_command,
    has_heredoc_exec_command,
    has_process_sub_remote_command,
    has_remote_pipe_exec_command,
    has_script_encoded_exec_command,
    has_variable_exec_trigger_command,
    has_variable_expansion_command,
)
from .trajectory_store import _parse_iso_timestamp

if TYPE_CHECKING:  # pragma: no cover
    from .server import SupervisionGateway


logger = logging.getLogger("clawsentry.enterprise")

_RISK_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_EXEC_TOOLS = {"bash", "shell", "exec", "sudo"}
_ENTERPRISE_LLM_TIMEOUT_MS = 3000.0
_ENTERPRISE_LLM_MAX_TOKENS = 256

_TRINITYGUARD_TAXONOMY: dict[str, dict[str, str]] = {
    "prompt_injection": {"tier": "RT1", "label": "Prompt Injection"},
    "jailbreak_attack": {"tier": "RT1", "label": "Jailbreak Attack"},
    "sensitive_info_disclosure": {"tier": "RT1", "label": "Sensitive Info Disclosure"},
    "excessive_agency": {"tier": "RT1", "label": "Excessive Agency"},
    "unauthorized_code_execution": {"tier": "RT1", "label": "Unauthorized Code Execution"},
    "hallucination": {"tier": "RT1", "label": "Hallucination"},
    "memory_poisoning": {"tier": "RT1", "label": "Memory Poisoning"},
    "tool_misuse": {"tier": "RT1", "label": "Tool Misuse"},
    "malicious_propagation": {"tier": "RT2", "label": "Malicious Propagation"},
    "misinformation_amplification": {"tier": "RT2", "label": "Misinformation Amplification"},
    "insecure_output_handling": {"tier": "RT2", "label": "Insecure Output Handling"},
    "goal_drift": {"tier": "RT2", "label": "Goal Drift"},
    "message_tampering": {"tier": "RT2", "label": "Message Tampering"},
    "identity_spoofing": {"tier": "RT2", "label": "Identity Spoofing"},
    "cascading_failure": {"tier": "RT3", "label": "Cascading Failure"},
    "sandbox_escape": {"tier": "RT3", "label": "Sandbox Escape"},
    "insufficient_monitoring": {"tier": "RT3", "label": "Insufficient Monitoring"},
    "group_hallucination": {"tier": "RT3", "label": "Group Hallucination"},
    "malicious_emergence": {"tier": "RT3", "label": "Malicious Emergence"},
    "rogue_agent": {"tier": "RT3", "label": "Rogue Agent"},
}

_TIER_LABELS = {
    "RT1": "Atomic Risks",
    "RT2": "Communication Risks",
    "RT3": "System Risks",
}


def _risk_rank(value: Any) -> int:
    return _RISK_RANK.get(str(value or "low").lower(), 0)


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None or not str(raw).strip():
        return default
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def enterprise_mode_enabled() -> bool:
    return (
        _env_bool("CS_ENTERPRISE_ENABLED", False)
        or _env_bool("CS_ENTERPRISE_OS_ENABLED", False)
        or _env_bool("CS_LLM_ENTERPRISE_ENABLED", False)
    )


def _build_enterprise_llm_provider():
    settings = resolve_llm_settings()
    if settings is None:
        return None

    if settings.normalized_provider == "anthropic":
        return AnthropicProvider(
            LLMProviderConfig(api_key=settings.api_key, model=settings.model)
        )
    if settings.normalized_provider == "openai":
        return OpenAIProvider(
            LLMProviderConfig(
                api_key=settings.api_key,
                model=settings.model,
                base_url=settings.base_url,
            )
        )

    logger.warning(
        "Unknown CS_LLM_PROVIDER=%r; enterprise fallback disabled",
        settings.provider,
    )
    return None


def _empty_classification(reason: str = "no enterprise taxonomy rule matched") -> dict[str, Any]:
    return {
        "mapped": False,
        "tier": None,
        "tier_label": None,
        "subtype": "unmapped",
        "label": "Unmapped",
        "confidence": "low",
        "reason": reason,
        "signals": [],
    }


def _classification(
    subtype: str,
    *,
    confidence: str,
    reason: str,
    signals: list[str],
) -> dict[str, Any]:
    entry = _TRINITYGUARD_TAXONOMY[subtype]
    tier = entry["tier"]
    return {
        "mapped": True,
        "tier": tier,
        "tier_label": _TIER_LABELS[tier],
        "subtype": subtype,
        "label": entry["label"],
        "confidence": confidence,
        "reason": reason,
        "signals": signals,
    }


def _confidence_from_score(score: Any) -> str:
    try:
        value = float(score)
    except (TypeError, ValueError):
        return "medium"
    if value >= 0.85:
        return "high"
    if value >= 0.6:
        return "medium"
    return "low"


def _resolve_taxonomy_prompt(observation: dict[str, Any]) -> tuple[str, str]:
    taxonomy_lines = []
    for subtype, entry in _TRINITYGUARD_TAXONOMY.items():
        taxonomy_lines.append(f"- {subtype} [{entry['tier']}]: {entry['label']}")
    system_prompt = (
        "You are a security taxonomy classifier for enterprise supervision. "
        "Choose the single best TrinityGuard subtype for the observation. "
        "If nothing fits, return unmapped."
    )
    user_prompt = "\n".join(
        [
            "TrinityGuard taxonomy:",
            *taxonomy_lines,
            "",
            "Observation:",
            json.dumps(observation, ensure_ascii=False, sort_keys=True),
            "",
            "Return JSON with keys: subtype, confidence, reason, signals.",
            "Subtype must be one of the taxonomy ids or unmapped.",
        ]
    )
    return system_prompt, user_prompt


def _parse_taxonomy_response(raw: str) -> dict[str, Any]:
    try:
        data = json.loads(raw)
    except Exception:
        return _empty_classification("LLM taxonomy response could not be parsed")

    subtype = str(
        data.get("subtype")
        or data.get("risk_subtype")
        or data.get("category")
        or "unmapped"
    ).strip().lower()
    if subtype not in _TRINITYGUARD_TAXONOMY:
        return _empty_classification("LLM taxonomy response did not map to a known subtype")

    entry = _TRINITYGUARD_TAXONOMY[subtype]
    reason = str(data.get("reason") or "LLM semantic match")
    confidence = _confidence_from_score(data.get("confidence", 0.65))
    signals = data.get("signals")
    if isinstance(signals, list):
        parsed_signals = [str(item) for item in signals if str(item).strip()]
    else:
        parsed_signals = []
    if not parsed_signals:
        parsed_signals = ["llm_semantic_fallback"]
    return {
        "mapped": True,
        "tier": entry["tier"],
        "tier_label": _TIER_LABELS[entry["tier"]],
        "subtype": subtype,
        "label": entry["label"],
        "confidence": confidence,
        "reason": f"{reason} (llm fallback)",
        "signals": parsed_signals,
    }


def _payload_text(payload: dict[str, Any]) -> str:
    if not isinstance(payload, dict):
        return ""
    parts: list[str] = []
    for key in (
        "command",
        "path",
        "file_path",
        "output",
        "result",
        "prompt",
        "content",
        "message",
    ):
        value = payload.get(key)
        if value:
            parts.append(str(value))
    return " ".join(parts)


def _normalized_observation(
    *,
    event: dict[str, Any] | None = None,
    decision: dict[str, Any] | None = None,
    snapshot: dict[str, Any] | None = None,
    l3_trace: dict[str, Any] | None = None,
    runtime_event: dict[str, Any] | None = None,
) -> dict[str, Any]:
    event = event or {}
    decision = decision or {}
    snapshot = snapshot or {}
    runtime_event = runtime_event or {}

    payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
    payload_text = _payload_text(payload)
    command_text = str(
        payload.get("command")
        or runtime_event.get("command")
        or payload_text
    )
    tool_name = str(
        event.get("tool_name")
        or runtime_event.get("tool_name")
        or runtime_event.get("tool")
        or ""
    ).lower()
    risk_hints = event.get("risk_hints") if isinstance(event.get("risk_hints"), list) else []
    path_text = str(payload.get("path") or payload.get("file_path") or "")
    dimensions = snapshot.get("dimensions") if isinstance(snapshot.get("dimensions"), dict) else {}
    base_signals = build_base_event_signals(
        tool_name=tool_name,
        path_text=path_text,
        payload_text=payload_text,
        command_text=command_text,
        risk_hints=risk_hints,
    )
    archive_signals = build_archive_command_signals(
        tool_name=tool_name,
        payload_text=payload_text,
        command_text=command_text,
    )
    combined_text = " ".join(
        [
            str(command_text or ""),
            str(payload_text or ""),
            str(runtime_event.get("reason") or ""),
            " ".join(str(v) for v in (runtime_event.get("patterns_matched") or [])),
        ]
    ).lower()
    return {
        "event_type": str(event.get("event_type") or runtime_event.get("type") or "").lower(),
        "runtime_type": str(runtime_event.get("type") or "").lower(),
        "tool_name": tool_name,
        "command_text": command_text,
        "payload_text": payload_text,
        "combined_text": combined_text,
        "risk_level": str(
            decision.get("risk_level")
            or snapshot.get("risk_level")
            or runtime_event.get("risk_level")
            or runtime_event.get("current_risk")
            or "low"
        ).lower(),
        "risk_hints": [str(item).lower() for item in risk_hints],
        "base_signals": base_signals,
        "archive_signals": archive_signals,
        "d6": float(dimensions.get("d6") or 0.0),
        "trigger_reason": str((l3_trace or {}).get("trigger_reason") or runtime_event.get("trigger_reason") or "").lower(),
        "trigger_detail": str((l3_trace or {}).get("trigger_detail") or runtime_event.get("trigger_detail") or "").lower(),
        "patterns_matched": [str(item).lower() for item in (runtime_event.get("patterns_matched") or [])],
        "sequence_id": str(runtime_event.get("sequence_id") or "").lower(),
        "reason": str(runtime_event.get("reason") or ""),
    }


def _classify_observation(observation: dict[str, Any]) -> dict[str, Any]:
    runtime_type = observation["runtime_type"]
    trigger_detail = observation["trigger_detail"]
    command_text = observation["command_text"]
    combined_text = observation["combined_text"]
    base_signals = observation["base_signals"]
    archive_signals = observation["archive_signals"]
    risk_level = observation["risk_level"]
    d6 = observation["d6"]

    if runtime_type == "trajectory_alert":
        return _classification(
            "cascading_failure",
            confidence="high",
            reason="trajectory alert represents a multi-step system-level failure pattern",
            signals=[f"sequence_id:{observation['sequence_id'] or 'unknown'}"],
        )

    if runtime_type == "post_action_finding":
        return _classification(
            "insecure_output_handling",
            confidence="high",
            reason="post-action analyzer found unsafe or toxic tool output",
            signals=[*(f"pattern:{item}" for item in observation["patterns_matched"])],
        )

    if runtime_type == "budget_exhausted":
        return _classification(
            "rogue_agent",
            confidence="medium",
            reason="budget exhaustion indicates uncontrolled agent behavior or runaway activity",
            signals=["event:budget_exhausted"],
        )

    if runtime_type == "decision" and trigger_detail in {
        "secret_harvest_archive",
        "tmp_staging_exfil",
    }:
        return _classification(
            "sandbox_escape",
            confidence="medium",
            reason="decision event matches a high-risk exfiltration or sandbox boundary pattern",
            signals=[f"trigger_detail:{trigger_detail}"],
        )

    injection_phrases = (
        "ignore previous instructions",
        "disregard previous instructions",
        "system prompt",
        "developer message",
    )
    if (
        d6 >= 2.0
        or any(phrase in combined_text for phrase in injection_phrases)
    ):
        return _classification(
            "prompt_injection",
            confidence="high",
            reason="injection signals or strong D6 score indicate prompt injection risk",
            signals=[f"d6:{d6}"] if d6 else ["text:prompt-injection-pattern"],
        )

    if trigger_detail in {"secret_plus_network", "secret_harvest_archive"}:
        return _classification(
            "sensitive_info_disclosure",
            confidence="high",
            reason="secret access combined with network or archive behavior indicates data disclosure",
            signals=[f"trigger_detail:{trigger_detail}"],
        )

    if base_signals["credential_access"] and (
        base_signals["network_activity"] or archive_signals["archive_sensitive_material"]
    ):
        return _classification(
            "sensitive_info_disclosure",
            confidence="high",
            reason="credential access combined with exfiltration-oriented behavior indicates disclosure",
            signals=["signal:credential_access", "signal:network_or_archive"],
        )

    if runtime_type == "alert" and "session_risk_escalation" in combined_text:
        return _classification(
            "tool_misuse",
            confidence="medium",
            reason="alert originated from a high-risk runtime action",
            signals=["metric:session_risk_escalation"],
        )

    if trigger_detail in {"privilege_escalation_chain", "recon_then_sudo"}:
        return _classification(
            "unauthorized_code_execution",
            confidence="high",
            reason="L3 detail indicates privilege escalation or exploit execution flow",
            signals=[f"trigger_detail:{trigger_detail}"],
        )

    if (
        base_signals["exec_action"]
        and (
            base_signals["sudo_action"]
            or has_remote_pipe_exec_command(command_text)
            or has_decode_pipe_exec_command(command_text)
            or has_eval_decode_command(command_text)
            or has_script_encoded_exec_command(command_text)
            or has_process_sub_remote_command(command_text)
            or has_heredoc_exec_command(command_text)
            or has_variable_expansion_command(command_text)
            or has_variable_exec_trigger_command(command_text)
        )
    ):
        return _classification(
            "unauthorized_code_execution",
            confidence="high",
            reason="runtime command shows privileged or decoded shell execution",
            signals=["signal:exec_action", "signal:dangerous_exec_pattern"],
        )

    if trigger_detail == "tmp_staging_exfil":
        return _classification(
            "sandbox_escape",
            confidence="medium",
            reason="temporary staging plus outbound transfer suggests escaping a bounded workspace",
            signals=["trigger_detail:tmp_staging_exfil"],
        )

    if observation["trigger_reason"] == "cumulative_risk":
        return _classification(
            "excessive_agency",
            confidence="medium",
            reason="cumulative risk escalation indicates the agent exceeded safe autonomy bounds",
            signals=["trigger_reason:cumulative_risk"],
        )

    if risk_level in {"high", "critical"} and (
        observation["tool_name"] in _EXEC_TOOLS
        or base_signals["exec_action"]
    ):
        return _classification(
            "tool_misuse",
            confidence="medium",
            reason="high-risk runtime activity centered on powerful tools",
            signals=[f"tool:{observation['tool_name'] or 'unknown'}"],
        )

    return _empty_classification()


def classify_trajectory_record(record: dict[str, Any]) -> dict[str, Any]:
    observation = _normalized_observation(
        event=record.get("event") if isinstance(record.get("event"), dict) else {},
        decision=record.get("decision") if isinstance(record.get("decision"), dict) else {},
        snapshot=record.get("risk_snapshot") if isinstance(record.get("risk_snapshot"), dict) else {},
        l3_trace=record.get("l3_trace") if isinstance(record.get("l3_trace"), dict) else {},
    )
    rule_result = _classify_observation(observation)
    if rule_result["mapped"] or not enterprise_mode_enabled():
        return rule_result
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(classify_trajectory_record_async(record))
    return rule_result


def classify_runtime_event(event: dict[str, Any]) -> dict[str, Any]:
    observation = _normalized_observation(runtime_event=event)
    rule_result = _classify_observation(observation)
    if rule_result["mapped"] or not enterprise_mode_enabled():
        return rule_result
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(classify_runtime_event_async(event))
    return rule_result


async def _classify_with_llm(observation: dict[str, Any]) -> dict[str, Any]:
    provider = _build_enterprise_llm_provider()
    if provider is None:
        return _empty_classification("enterprise LLM fallback unavailable")

    system_prompt, user_prompt = _resolve_taxonomy_prompt(observation)
    try:
        raw = await provider.complete(
            system_prompt,
            user_prompt,
            timeout_ms=_ENTERPRISE_LLM_TIMEOUT_MS,
            max_tokens=_ENTERPRISE_LLM_MAX_TOKENS,
        )
    except Exception:
        logger.warning("Enterprise LLM taxonomy fallback failed", exc_info=True)
        return _empty_classification("enterprise LLM fallback failed")

    return _parse_taxonomy_response(raw)


async def classify_trajectory_record_async(record: dict[str, Any]) -> dict[str, Any]:
    observation = _normalized_observation(
        event=record.get("event") if isinstance(record.get("event"), dict) else {},
        decision=record.get("decision") if isinstance(record.get("decision"), dict) else {},
        snapshot=record.get("risk_snapshot") if isinstance(record.get("risk_snapshot"), dict) else {},
        l3_trace=record.get("l3_trace") if isinstance(record.get("l3_trace"), dict) else {},
    )
    rule_result = _classify_observation(observation)
    if rule_result["mapped"] or not enterprise_mode_enabled():
        return rule_result
    llm_result = await _classify_with_llm(observation)
    if llm_result["mapped"]:
        return llm_result
    return rule_result


async def classify_runtime_event_async(event: dict[str, Any]) -> dict[str, Any]:
    observation = _normalized_observation(runtime_event=event)
    rule_result = _classify_observation(observation)
    if rule_result["mapped"] or not enterprise_mode_enabled():
        return rule_result
    llm_result = await _classify_with_llm(observation)
    if llm_result["mapped"]:
        return llm_result
    return rule_result


def _count_classifications(classifications: list[dict[str, Any]]) -> dict[str, Any]:
    by_tier: dict[str, int] = {}
    by_subtype: dict[str, int] = {}
    mapped = 0
    for item in classifications:
        subtype = str(item.get("subtype") or "unmapped")
        by_subtype[subtype] = by_subtype.get(subtype, 0) + 1
        if item.get("mapped"):
            mapped += 1
            tier = str(item.get("tier") or "")
            by_tier[tier] = by_tier.get(tier, 0) + 1
    return {
        "mapped_records": mapped,
        "unmapped_records": len(classifications) - mapped,
        "by_tier": by_tier,
        "by_subtype": by_subtype,
    }


def _filter_records(
    records: list[dict[str, Any]],
    *,
    since_seconds: Optional[int] = None,
) -> list[dict[str, Any]]:
    if since_seconds is None or since_seconds <= 0:
        return list(records)
    cutoff = time.time() - since_seconds
    filtered: list[dict[str, Any]] = []
    for record in records:
        ts = float(record.get("recorded_at_ts") or 0.0)
        if not ts:
            ts = _parse_iso_timestamp(str(record.get("recorded_at") or ""))
        if ts >= cutoff:
            filtered.append(record)
    return filtered


def _latest_session_record(gateway: SupervisionGateway, session_id: str) -> dict[str, Any] | None:
    replay = gateway.replay_session(session_id, limit=1)
    records = replay.get("records") if isinstance(replay.get("records"), list) else []
    return records[-1] if records else None


def _live_sessions(gateway: SupervisionGateway) -> list[dict[str, Any]]:
    raw_sessions = getattr(gateway.session_registry, "_sessions", {})
    if isinstance(raw_sessions, dict):
        return [dict(value) for value in raw_sessions.values()]
    fallback = gateway.report_sessions(limit=200)
    sessions = fallback.get("sessions")
    return list(sessions) if isinstance(sessions, list) else []


def build_enterprise_live_snapshot(gateway: SupervisionGateway) -> dict[str, Any]:
    if enterprise_mode_enabled():
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(build_enterprise_live_snapshot_async(gateway))
    sessions = _live_sessions(gateway)
    by_risk_level: dict[str, int] = {}
    by_tier: dict[str, int] = {}
    by_subtype: dict[str, int] = {}
    mapped_active_sessions = 0
    high_risk_sessions = 0

    for session in sessions:
        risk_level = str(session.get("current_risk_level") or "low").lower()
        by_risk_level[risk_level] = by_risk_level.get(risk_level, 0) + 1
        if _risk_rank(risk_level) >= _risk_rank("high"):
            high_risk_sessions += 1
        session_id = str(session.get("session_id") or "")
        if not session_id:
            continue
        latest = _latest_session_record(gateway, session_id)
        if latest is None:
            continue
        classification = classify_trajectory_record(latest)
        if classification["mapped"]:
            mapped_active_sessions += 1
            tier = str(classification["tier"])
            subtype = str(classification["subtype"])
            by_tier[tier] = by_tier.get(tier, 0) + 1
            by_subtype[subtype] = by_subtype.get(subtype, 0) + 1

    return {
        "generated_at": utc_now_iso(),
        "active_sessions": len(sessions),
        "high_risk_sessions": high_risk_sessions,
        "mapped_active_sessions": mapped_active_sessions,
        "by_risk_level": by_risk_level,
        "by_trinityguard_tier": by_tier,
        "by_trinityguard_subtype": by_subtype,
    }


async def build_enterprise_live_snapshot_async(gateway: SupervisionGateway) -> dict[str, Any]:
    sessions = _live_sessions(gateway)
    by_risk_level: dict[str, int] = {}
    by_tier: dict[str, int] = {}
    by_subtype: dict[str, int] = {}
    mapped_active_sessions = 0
    high_risk_sessions = 0

    latest_records: list[tuple[str, dict[str, Any]]] = []
    for session in sessions:
        risk_level = str(session.get("current_risk_level") or "low").lower()
        by_risk_level[risk_level] = by_risk_level.get(risk_level, 0) + 1
        if _risk_rank(risk_level) >= _risk_rank("high"):
            high_risk_sessions += 1
        session_id = str(session.get("session_id") or "")
        if not session_id:
            continue
        latest = _latest_session_record(gateway, session_id)
        if latest is not None:
            latest_records.append((session_id, latest))

    classifications = await asyncio.gather(
        *(classify_trajectory_record_async(record) for _, record in latest_records)
    ) if latest_records else []

    for classification in classifications:
        if classification["mapped"]:
            mapped_active_sessions += 1
            tier = str(classification["tier"])
            subtype = str(classification["subtype"])
            by_tier[tier] = by_tier.get(tier, 0) + 1
            by_subtype[subtype] = by_subtype.get(subtype, 0) + 1

    return {
        "generated_at": utc_now_iso(),
        "active_sessions": len(sessions),
        "high_risk_sessions": high_risk_sessions,
        "mapped_active_sessions": mapped_active_sessions,
        "by_risk_level": by_risk_level,
        "by_trinityguard_tier": by_tier,
        "by_trinityguard_subtype": by_subtype,
    }


def build_enterprise_event(event: dict[str, Any], gateway: SupervisionGateway) -> dict[str, Any]:
    if enterprise_mode_enabled():
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(build_enterprise_event_async(event, gateway))
    payload = dict(event)
    payload["trinityguard_classification"] = classify_runtime_event(event)
    payload["live_risk_overview"] = build_enterprise_live_snapshot(gateway)
    return payload


async def build_enterprise_event_async(event: dict[str, Any], gateway: SupervisionGateway) -> dict[str, Any]:
    payload = dict(event)
    payload["trinityguard_classification"] = await classify_runtime_event_async(event)
    payload["live_risk_overview"] = await build_enterprise_live_snapshot_async(gateway)
    return payload


def enrich_health_payload(
    payload: dict[str, Any],
    gateway: SupervisionGateway,
) -> dict[str, Any]:
    if enterprise_mode_enabled():
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(enrich_health_payload_async(payload, gateway))
    enriched = dict(payload)
    enriched["enterprise"] = {
        "live_risk_overview": build_enterprise_live_snapshot(gateway),
    }
    return enriched


def enrich_summary_payload(
    payload: dict[str, Any],
    gateway: SupervisionGateway,
    *,
    window_seconds: Optional[int] = None,
) -> dict[str, Any]:
    if enterprise_mode_enabled():
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(
                enrich_summary_payload_async(payload, gateway, window_seconds=window_seconds)
            )
    enriched = dict(payload)
    records = _filter_records(list(gateway.trajectory_store.records), since_seconds=window_seconds)
    classifications = [classify_trajectory_record(record) for record in records]
    enriched["trinityguard"] = {
        "total_records": len(records),
        **_count_classifications(classifications),
    }
    enriched["enterprise"] = {
        "live_risk_overview": build_enterprise_live_snapshot(gateway),
    }
    return enriched


def enrich_sessions_payload(
    payload: dict[str, Any],
    gateway: SupervisionGateway,
) -> dict[str, Any]:
    if enterprise_mode_enabled():
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(enrich_sessions_payload_async(payload, gateway))
    enriched = dict(payload)
    sessions = []
    for session in payload.get("sessions", []):
        item = dict(session)
        latest = _latest_session_record(gateway, str(item.get("session_id") or ""))
        item["trinityguard_classification"] = (
            classify_trajectory_record(latest) if latest is not None else _empty_classification()
        )
        sessions.append(item)
    enriched["sessions"] = sessions
    enriched["enterprise"] = {
        "live_risk_overview": build_enterprise_live_snapshot(gateway),
    }
    return enriched


def enrich_session_risk_payload(
    payload: dict[str, Any],
    gateway: SupervisionGateway,
) -> dict[str, Any]:
    if enterprise_mode_enabled():
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(enrich_session_risk_payload_async(payload, gateway))
    enriched = dict(payload)
    session_id = str(payload.get("session_id") or "")
    replay = gateway.replay_session(session_id, limit=max(int(payload.get("event_count") or 0), 100))
    records = replay.get("records") if isinstance(replay.get("records"), list) else []
    by_event_id = {
        str(record.get("event", {}).get("event_id") or ""): classify_trajectory_record(record)
        for record in records
    }
    timeline = []
    classifications: list[dict[str, Any]] = []
    for item in payload.get("risk_timeline", []):
        entry = dict(item)
        classification = by_event_id.get(str(entry.get("event_id") or ""), _empty_classification())
        entry["trinityguard_classification"] = classification
        timeline.append(entry)
        classifications.append(classification)
    enriched["risk_timeline"] = timeline
    enriched["trinityguard_summary"] = _count_classifications(classifications)
    return enriched


def enrich_replay_payload(payload: dict[str, Any]) -> dict[str, Any]:
    if enterprise_mode_enabled():
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(enrich_replay_payload_async(payload))
    enriched = dict(payload)
    records = []
    classifications: list[dict[str, Any]] = []
    for item in payload.get("records", []):
        record = dict(item)
        classification = classify_trajectory_record(record)
        record["trinityguard_classification"] = classification
        records.append(record)
        classifications.append(classification)
    enriched["records"] = records
    enriched["trinityguard_summary"] = _count_classifications(classifications)
    return enriched


def enrich_alerts_payload(
    payload: dict[str, Any],
    gateway: SupervisionGateway,
) -> dict[str, Any]:
    if enterprise_mode_enabled():
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(enrich_alerts_payload_async(payload, gateway))
    enriched = dict(payload)
    alerts = []
    for item in payload.get("alerts", []):
        alert = dict(item)
        latest = _latest_session_record(gateway, str(alert.get("session_id") or ""))
        alert["trinityguard_classification"] = (
            classify_trajectory_record(latest)
            if latest is not None
            else classify_runtime_event({"type": "alert", **alert})
        )
        alerts.append(alert)
    enriched["alerts"] = alerts
    return enriched


async def enrich_health_payload_async(
    payload: dict[str, Any],
    gateway: SupervisionGateway,
) -> dict[str, Any]:
    enriched = dict(payload)
    enriched["enterprise"] = {
        "live_risk_overview": await build_enterprise_live_snapshot_async(gateway),
    }
    return enriched


async def enrich_summary_payload_async(
    payload: dict[str, Any],
    gateway: SupervisionGateway,
    *,
    window_seconds: Optional[int] = None,
) -> dict[str, Any]:
    enriched = dict(payload)
    records = _filter_records(list(gateway.trajectory_store.records), since_seconds=window_seconds)
    classifications = await asyncio.gather(
        *(classify_trajectory_record_async(record) for record in records)
    ) if records else []
    enriched["trinityguard"] = {
        "total_records": len(records),
        **_count_classifications(list(classifications)),
    }
    enriched["enterprise"] = {
        "live_risk_overview": await build_enterprise_live_snapshot_async(gateway),
    }
    return enriched


async def enrich_sessions_payload_async(
    payload: dict[str, Any],
    gateway: SupervisionGateway,
) -> dict[str, Any]:
    enriched = dict(payload)
    sessions = []
    latest_records: list[tuple[dict[str, Any], dict[str, Any] | None]] = []
    for session in payload.get("sessions", []):
        item = dict(session)
        latest = _latest_session_record(gateway, str(item.get("session_id") or ""))
        sessions.append(item)
        latest_records.append((item, latest))

    classifications = await asyncio.gather(
        *(classify_trajectory_record_async(latest) for _, latest in latest_records if latest is not None)
    ) if latest_records else []
    classification_iter = iter(classifications)
    for item, latest in latest_records:
        if latest is not None:
            item["trinityguard_classification"] = next(classification_iter)
        else:
            item["trinityguard_classification"] = _empty_classification()

    enriched["sessions"] = sessions
    enriched["enterprise"] = {
        "live_risk_overview": await build_enterprise_live_snapshot_async(gateway),
    }
    return enriched


async def enrich_session_risk_payload_async(
    payload: dict[str, Any],
    gateway: SupervisionGateway,
) -> dict[str, Any]:
    enriched = dict(payload)
    session_id = str(payload.get("session_id") or "")
    replay = gateway.replay_session(session_id, limit=max(int(payload.get("event_count") or 0), 100))
    records = replay.get("records") if isinstance(replay.get("records"), list) else []
    by_event_id = {
        str(record.get("event", {}).get("event_id") or ""): record
        for record in records
    }
    timeline = []
    classifications: list[dict[str, Any]] = []
    for item in payload.get("risk_timeline", []):
        entry = dict(item)
        record = by_event_id.get(str(entry.get("event_id") or ""))
        classification = (
            await classify_trajectory_record_async(record)
            if record is not None
            else _empty_classification()
        )
        entry["trinityguard_classification"] = classification
        timeline.append(entry)
        classifications.append(classification)
    enriched["risk_timeline"] = timeline
    enriched["trinityguard_summary"] = _count_classifications(classifications)
    return enriched


async def enrich_replay_payload_async(payload: dict[str, Any]) -> dict[str, Any]:
    enriched = dict(payload)
    records = []
    classifications: list[dict[str, Any]] = []
    for item in payload.get("records", []):
        record = dict(item)
        classification = await classify_trajectory_record_async(record)
        record["trinityguard_classification"] = classification
        records.append(record)
        classifications.append(classification)
    enriched["records"] = records
    enriched["trinityguard_summary"] = _count_classifications(classifications)
    return enriched


async def enrich_alerts_payload_async(
    payload: dict[str, Any],
    gateway: SupervisionGateway,
) -> dict[str, Any]:
    enriched = dict(payload)
    alerts = []
    for item in payload.get("alerts", []):
        alert = dict(item)
        latest = _latest_session_record(gateway, str(alert.get("session_id") or ""))
        classification = (
            await classify_trajectory_record_async(latest)
            if latest is not None
            else await classify_runtime_event_async({"type": "alert", **alert})
        )
        alert["trinityguard_classification"] = classification
        alerts.append(alert)
    enriched["alerts"] = alerts
    return enriched
