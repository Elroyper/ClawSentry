"""SyncDecision v1 orchestration for the core supervision gateway."""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from pydantic import ValidationError

from clawsentry.gateway.analysis.anti_bypass_guard import AntiBypassMatch
from clawsentry.gateway.analysis.anti_bypass_llm_recognizer import recognize_anti_bypass_candidate
from clawsentry.gateway.analysis.content_evidence import collect_for_event, strip_content_bodies
from clawsentry.gateway.config.detection_config import DetectionConfig, build_detection_config_with_preset
from ..l3.advisory_service import (
    _analyzer_supports_l3,
    _effective_requested_tier_for_l3_config,
)
from clawsentry.gateway.l3.runtime import build_l3_runtime_info
from clawsentry.gateway.models import (
    CanonicalDecision,
    CanonicalEvent,
    DecisionContext,
    DecisionEffects,
    DecisionSource,
    DecisionTier,
    DecisionVerdict,
    EventType,
    FailureClass,
    RPCErrorCode,
    RPC_VERSION,
    RiskLevel,
    SessionEffectRequest,
    SyncDecisionErrorResponse,
    SyncDecisionRequest,
    SyncDecisionResponse,
    decision_effect_summary,
    utc_now_iso,
)
from clawsentry.gateway.policy.session_enforcement import EnforcementAction
from clawsentry.gateway.storage.session_registry import build_compatibility_evidence_summary
from clawsentry.gateway.policy.tool_permissions import parse_tool_permission_group_overrides
from clawsentry.gateway.storage.trajectory_store import _parse_iso_timestamp
from ..trust.request import (
    _blocked_skill_lineage_match_from_session,
    _context_with_blocked_skill_lineage_match,
    _context_with_mcp_raw,
    _context_with_prior_fspr_hard_block,
    _lineage_events_from_summary,
    _lineage_summary_from_event,
    _redact_mcp_raw_from_event,
    _redact_skill_trust_raw_from_event,
)
from .agent_feedback import (
    _agent_advisory_feedback,
    _agent_safety_feedback,
    _agent_safety_feedback_delivery,
    _risk_rank,
)
from .approval_bridge import (
    _APPROVAL_ALLOWED_REASON_CODE,
    _APPROVAL_DENIED_REASON_CODE,
    _APPROVAL_NO_ROUTE_REASON_CODE,
    _APPROVAL_QUEUE_FULL_REASON_CODE,
    _approval_binding_from_snapshot,
    _approval_pending_meta,
    _approval_prompt_event_fields,
    _approval_resolution_meta,
    _event_for_effect_resolution,
    _is_confirmation_fast_lane,
    _resolve_confirmation_approval_id,
    _rewrite_effect_for_resolution,
    _validate_rewrite_resolution_payload,
)
from .capability_narrowing import (
    _capability_narrowing_policy_summary,
    _capability_narrowing_profile,
)
from .config_resolution import (
    _extract_compat_event_fields,
    _extract_project_config,
    _infer_source_framework,
    _risk_level_from_string,
)
from .content_evidence import (
    _content_evidence_approved_roots,
    _content_evidence_metric_flags,
    _snapshot_has_content_evidence_rule,
)
from ..reporting.service import _compact_l3_evidence_summary

logger = logging.getLogger("clawsentry")


@dataclass
class SyncDecisionFlowState:
    rpc_id: Any
    params: dict[str, Any]
    request_id: str
    deadline_at: float | None
    event: CanonicalEvent | None = None
    context: DecisionContext | None = None
    decision: CanonicalDecision | None = None
    snapshot: dict[str, Any] = field(default_factory=dict)
    meta: dict[str, Any] = field(default_factory=dict)
    l3_trace: dict[str, Any] | None = None


async def handle_sync_decision(
    gateway: Any,
    rpc_id: Any,
    params: dict[str, Any],
) -> dict[str, Any]:
    """Process a SyncDecision v1 request for a SupervisionGateway-like object."""
    state = SyncDecisionFlowState(
        rpc_id=rpc_id,
        params=params,
        request_id=str(params.get("request_id") or ""),
        deadline_at=None,
    )
    return await _run_sync_decision_flow(gateway, state)


def _engine_unavailable_response(
    gateway: Any,
    state: SyncDecisionFlowState,
) -> dict[str, Any]:
    error_resp = SyncDecisionErrorResponse(
        request_id=state.request_id or "unknown",
        rpc_error_code=RPCErrorCode.ENGINE_UNAVAILABLE,
        rpc_error_message="Gateway is starting up",
        retry_eligible=True,
        retry_after_ms=500,
    )
    return gateway._jsonrpc_error_with_data(state.rpc_id, -32603, error_resp)


def _cached_success_response(
    gateway: Any,
    state: SyncDecisionFlowState,
) -> dict[str, Any] | None:
    cached = gateway.idempotency_cache.get(state.request_id)
    if cached is None:
        return None
    return gateway._jsonrpc_success(state.rpc_id, cached)


def _invalid_request_response(
    gateway: Any,
    state: SyncDecisionFlowState,
    exc: ValidationError,
) -> dict[str, Any]:
    error_resp = SyncDecisionErrorResponse(
        request_id=state.request_id or "unknown",
        rpc_error_code=RPCErrorCode.INVALID_REQUEST,
        rpc_error_message=f"Request validation failed: {exc.error_count()} error(s)",
        retry_eligible=False,
    )
    return gateway._jsonrpc_error_with_data(state.rpc_id, -32602, error_resp)


def _unsupported_version_response(
    gateway: Any,
    state: SyncDecisionFlowState,
    request: SyncDecisionRequest,
) -> dict[str, Any]:
    error_resp = SyncDecisionErrorResponse(
        request_id=request.request_id,
        rpc_error_code=RPCErrorCode.VERSION_NOT_SUPPORTED,
        rpc_error_message=f"Unsupported rpc_version: '{request.rpc_version}'",
        retry_eligible=False,
    )
    return gateway._jsonrpc_error_with_data(state.rpc_id, -32602, error_resp)


def _cache_successful_response(
    gateway: Any,
    state: SyncDecisionFlowState,
    request: SyncDecisionRequest,
    response: dict[str, Any],
) -> None:
    state.request_id = request.request_id
    gateway.idempotency_cache.put(request.request_id, response, request.deadline_ms)


async def _run_sync_decision_flow(
    gateway: Any,
    state: SyncDecisionFlowState,
) -> dict[str, Any]:
    """Run sync-decision orchestration while preserving legacy ordering."""
    rpc_id = state.rpc_id
    params = state.params

    # ENGINE_UNAVAILABLE when gateway is not ready
    if not gateway._ready:
        return _engine_unavailable_response(gateway, state)

    # Check idempotency cache
    cached_response = _cached_success_response(gateway, state)
    if cached_response is not None:
        return cached_response

    # Validate request
    try:
        req = SyncDecisionRequest(**params)
    except ValidationError as e:
        return _invalid_request_response(gateway, state, e)

    # Check rpc_version
    if req.rpc_version != RPC_VERSION:
        return _unsupported_version_response(gateway, state, req)

    # Check deadline
    start = time.monotonic()
    deadline_at = start + req.deadline_ms / 1000.0
    state.deadline_at = deadline_at

    req = req.model_copy(
        update={"context": gateway._context_with_default_session_scope(req.context)}
    )
    req = req.model_copy(
        update={
            "context": gateway._context_with_skill_trust_raw(
                req.context,
                req.event,
                gateway.skill_registry_records,
                deadline_at=deadline_at,
                detection_config=gateway._detection_config,
            )
        }
    )
    req = req.model_copy(
        update={"context": _context_with_mcp_raw(req.context, req.event)}
    )
    if req.context is not None and req.context.content_evidence is not None:
        req = req.model_copy(
            update={
                "context": req.context.model_copy(update={"content_evidence": None})
            }
        )
    state.event = req.event
    state.context = req.context

    # --- Optional event-scoped preset config from harness metadata ---
    _preset_name, _preset_overrides = _extract_project_config(req.event.payload)
    project_config: Optional[DetectionConfig] = None
    if _preset_name:
        project_config = build_detection_config_with_preset(
            _preset_name,
            _preset_overrides,
        )

    if req.event.event_type == EventType.PRE_ACTION:
        try:
            effective_content_config = project_config or gateway._detection_config
            content_evidence = collect_for_event(
                req.event,
                approved_roots=_content_evidence_approved_roots(
                    req.context,
                    allow_confirmed_profile_roots=(
                        str(effective_content_config.mode or "normal").strip().lower()
                        == "benchmark"
                    ),
                ),
            )
        except Exception:
            logger.exception(
                "content evidence collection failed for event %s",
                req.event.event_id,
            )
            content_evidence = None
        if content_evidence is not None:
            gateway.metrics.record_content_evidence(
                **_content_evidence_metric_flags(content_evidence)
            )
            if (
                not effective_content_config.content_evidence_enabled
                or not effective_content_config.content_evidence_analyzer_body_enabled
            ):
                content_evidence = strip_content_bodies(content_evidence)
            context = req.context or DecisionContext()
            req = req.model_copy(
                update={
                    "context": context.model_copy(
                        update={"content_evidence": content_evidence}
                    )
                }
            )
            state.context = req.context

    # --- E-8: Record tool call for D4 frequency analysis ---
    if req.event.tool_name:
        gateway.policy_engine.session_tracker.record_tool_call(
            str(req.event.session_id or ""),
            req.event.tool_name,
            config=project_config,
        )

    # --- Phase 2A: compromised-session quarantine check (PRE_ACTION only) ---
    quarantine = gateway.session_registry.get_quarantine(
        str(req.event.session_id or "")
    )
    quarantine_applied = False
    if quarantine is not None and req.event.event_type == EventType.PRE_ACTION:
        decision = CanonicalDecision(
            decision=DecisionVerdict.BLOCK,
            reason="Session quarantined / mark-blocked; subsequent PRE_ACTION blocked",
            policy_id="session-quarantine",
            risk_level=RiskLevel.HIGH,
            decision_source=DecisionSource.SYSTEM,
            decision_effects=DecisionEffects(
                effect_id=str(
                    quarantine.get("effect_id")
                    or f"eff-{req.event.session_id}-{req.event.event_id}-session-quarantine"
                ),
                action_scope="session",
                session_effect=SessionEffectRequest(
                    requested=True,
                    mode="mark_blocked",
                    reason_code=str(
                        quarantine.get("reason_code") or "session_quarantined"
                    ),
                    capability_required="clawsentry.session_control.mark_blocked.v1",
                    fallback_on_unsupported="mark_blocked",
                ),
            ),
            final=True,
        )
        try:
            remaining_ms = max(0, (deadline_at - time.monotonic()) * 1000)
            _, snapshot, _ = gateway.policy_engine.evaluate(
                req.event,
                req.context,
                DecisionTier.L1,
                deadline_budget_ms=remaining_ms,
                config=project_config,
            )
        except Exception:
            logger.exception("Policy engine error during quarantine snapshot")
            from clawsentry.gateway.policy.engine import RiskSnapshot

            snapshot = RiskSnapshot()
        actual_tier = DecisionTier.L1
        quarantine_applied = True

    # --- A-7: Session enforcement check (before policy_engine) ---
    enforcement = gateway.session_enforcement.check(str(req.event.session_id or ""))
    enforcement_applied = False
    capability_narrowing_applied = False
    capability_narrowing_profile_id: str | None = None
    budget_exhausted = not gateway.budget_tracker.can_spend()
    effective_requested_tier = req.decision_tier
    l3_runtime_reason_override: str | None = None
    l3_runtime_reason_code_override: str | None = None
    effective_config = project_config or gateway._detection_config
    anti_bypass_match: AntiBypassMatch | None = None
    anti_bypass_probe: dict[str, object] | None = None
    previous_session_risk = gateway.session_registry.get_current_risk(
        str(req.event.session_id or "")
    )
    previous_session_stats = gateway.session_registry.get_session_stats(
        str(req.event.session_id or "")
    )
    lineage_probe = _lineage_summary_from_event(req.event.model_dump(mode="json"))
    blocked_lineage_match = _blocked_skill_lineage_match_from_session(
        lineage_probe,
        previous_session_stats,
    )
    if blocked_lineage_match is not None:
        req = req.model_copy(
            update={
                "context": _context_with_blocked_skill_lineage_match(
                    req.context,
                    blocked_lineage_match,
                )
            }
        )
    prior_fspr_context = _context_with_prior_fspr_hard_block(
        req.context,
        previous_session_stats,
    )
    if prior_fspr_context is not req.context:
        req = req.model_copy(update={"context": prior_fspr_context})
    capability_narrowing_enabled = bool(
        effective_config.capability_narrowing_enabled
    )
    capability_trigger_rank = _risk_rank(
        effective_config.capability_narrowing_trigger_risk
    )
    if capability_trigger_rank <= 0:
        capability_trigger_rank = _risk_rank("high")
    elevated_session_risk = _risk_rank(
        previous_session_risk
    ) >= capability_trigger_rank or (
        capability_trigger_rank <= _risk_rank("high")
        and int(previous_session_stats.get("high_risk_event_count") or 0) > 0
    )
    capability_narrowing_reason = "disabled"
    capability_narrowing_reason_code = "disabled"
    if capability_narrowing_enabled:
        if req.event.event_type != EventType.PRE_ACTION:
            capability_narrowing_reason = "not_pre_action"
            capability_narrowing_reason_code = "not_pre_action"
        elif enforcement is not None:
            capability_narrowing_reason = "explicit_enforcement"
            capability_narrowing_reason_code = "explicit_enforcement"
        elif (
            req.context is not None
            and req.context.session_scope_profile is not None
        ):
            capability_narrowing_reason = "explicit_scope_profile"
            capability_narrowing_reason_code = "explicit_scope_profile"
        elif elevated_session_risk:
            capability_narrowing_reason = "elevated_session_risk"
            capability_narrowing_reason_code = "eligible"
        else:
            capability_narrowing_reason = "session_risk_below_threshold"
            capability_narrowing_reason_code = "session_risk_below_threshold"
    if capability_narrowing_reason == "elevated_session_risk":
        reason_code = "elevated_session_risk"
        narrowed_profile = _capability_narrowing_profile(
            reason_code, effective_config
        )
        capability_narrowing_profile_id = narrowed_profile.profile_id
        tool_permission_overrides = parse_tool_permission_group_overrides(
            effective_config.tool_permission_group_overrides
        ).overrides
        if req.context is None:
            narrowed_context = DecisionContext(
                session_scope_profile_id=narrowed_profile.profile_id,
                session_scope_profile=narrowed_profile,
                tool_permission_group_overrides={
                    tool: list(groups)
                    for tool, groups in tool_permission_overrides.items()
                },
            )
        else:
            narrowed_context = req.context.model_copy(
                update={
                    "session_scope_profile_id": narrowed_profile.profile_id,
                    "session_scope_profile": narrowed_profile,
                    "tool_permission_group_overrides": {
                        **req.context.tool_permission_group_overrides,
                        **{
                            tool: list(groups)
                            for tool, groups in tool_permission_overrides.items()
                        },
                    },
                }
            )
        req = req.model_copy(update={"context": narrowed_context})
        capability_narrowing_applied = True
        capability_narrowing_reason_code = "applied"
    if quarantine_applied:
        pass
    elif (
        enforcement is not None
        and req.event.event_type == EventType.PRE_ACTION
        and not capability_narrowing_applied
    ):
        if enforcement.action == EnforcementAction.L3_REQUIRE:
            effective_requested_tier = DecisionTier.L3
            if budget_exhausted:
                decision = gateway._make_enforcement_decision(enforcement, req.event)
                l3_runtime_reason_override = (
                    "LLM budget exhausted; operator review required"
                )
                l3_runtime_reason_code_override = "budget_exhausted"
                try:
                    remaining_ms = max(0, (deadline_at - time.monotonic()) * 1000)
                    _, snapshot, _ = gateway.policy_engine.evaluate(
                        req.event,
                        req.context,
                        DecisionTier.L1,
                        deadline_budget_ms=remaining_ms,
                        config=project_config,
                    )
                except Exception:
                    logger.exception(
                        "Policy engine error during enforcement snapshot"
                    )
                    from clawsentry.gateway.policy.engine import RiskSnapshot

                    snapshot = RiskSnapshot()
                actual_tier = DecisionTier.L1
                enforcement_applied = True
            else:
                session_summary = {}
                if req.context is not None and isinstance(
                    req.context.session_risk_summary, dict
                ):
                    session_summary.update(req.context.session_risk_summary)
                session_summary.update(
                    {
                        "force_l3": True,
                        "l3_require_enforced": True,
                        "l3_request_reason": "session_l3_require",
                        "l3_trigger_source_metadata": {
                            "enforcement_action": "L3_REQUIRE",
                        },
                    }
                )
                effective_context = (
                    req.context.model_copy(
                        update={"session_risk_summary": session_summary}
                    )
                    if req.context is not None
                    else DecisionContext(session_risk_summary=session_summary)
                )
                try:
                    remaining_ms = max(0, (deadline_at - time.monotonic()) * 1000)
                    decision, snapshot, actual_tier = gateway.policy_engine.evaluate(
                        req.event,
                        effective_context,
                        DecisionTier.L3,
                        deadline_budget_ms=remaining_ms,
                        config=project_config,
                    )
                except Exception:
                    logger.exception("Policy engine error")
                    error_resp = SyncDecisionErrorResponse(
                        request_id=req.request_id,
                        rpc_error_code=RPCErrorCode.ENGINE_INTERNAL_ERROR,
                        rpc_error_message="Internal engine error. Check server logs for details.",
                        retry_eligible=True,
                        retry_after_ms=50,
                    )
                    return gateway._jsonrpc_error_with_data(rpc_id, -32603, error_resp)

                if actual_tier != DecisionTier.L3:
                    decision = gateway._make_enforcement_decision(
                        enforcement, req.event
                    )
                    l3_runtime_reason_override = (
                        "Local L3 review did not complete; operator review required"
                    )
                    l3_runtime_reason_code_override = "local_l3_not_completed"
                    enforcement_applied = True
        else:
            decision = gateway._make_enforcement_decision(enforcement, req.event)
            # Still need a snapshot for recording — run L1 but override decision
            try:
                remaining_ms = max(0, (deadline_at - time.monotonic()) * 1000)
                _, snapshot, _ = gateway.policy_engine.evaluate(
                    req.event,
                    req.context,
                    req.decision_tier,
                    deadline_budget_ms=remaining_ms,
                    config=project_config,
                )
            except Exception:
                logger.exception("Policy engine error during enforcement snapshot")
                from clawsentry.gateway.policy.engine import RiskSnapshot

                snapshot = RiskSnapshot()
            actual_tier = DecisionTier.L1
            enforcement_applied = True
    else:
        anti_bypass_match = gateway.anti_bypass_guard.match_pre_action(
            req.event,
            req.context,
            effective_config,
        )
        if (
            anti_bypass_match is None
            and effective_config.anti_bypass_llm_recognition_enabled
            and req.event.event_type == EventType.PRE_ACTION
        ):
            if budget_exhausted:
                anti_bypass_probe = {
                    "candidate_count": 0,
                    "llm_state": "skipped",
                    "reason": "budget_exhausted",
                    "budget_skipped": True,
                }
            else:
                candidates = gateway.anti_bypass_guard.llm_candidates(
                    req.event,
                    req.context,
                    effective_config,
                )
                if gateway.anti_bypass_llm_provider is None:
                    anti_bypass_probe = {
                        "candidate_count": len(candidates),
                        "llm_state": "disabled",
                        "reason": "provider_unavailable",
                        "budget_skipped": False,
                    }
                elif not candidates:
                    anti_bypass_probe = {
                        "candidate_count": 0,
                        "llm_state": "not_matched",
                        "reason": "no_candidate",
                        "budget_skipped": False,
                    }
                else:
                    recognition = await recognize_anti_bypass_candidate(
                        provider=gateway.anti_bypass_llm_provider,
                        candidates=candidates,
                        config=effective_config,
                    )
                    if recognition.match is not None:
                        anti_bypass_match = recognition.match
                    else:
                        anti_bypass_probe = {
                            "candidate_count": len(candidates),
                            "llm_state": recognition.state,
                            "reason": recognition.reason or recognition.state,
                            "budget_skipped": False,
                        }
        # --- P3: LLM budget check — force L1 if exhausted ---
        requested_tier = req.decision_tier
        if budget_exhausted:
            requested_tier = DecisionTier.L1
            if req.decision_tier != DecisionTier.L1:
                l3_runtime_reason_override = "LLM budget exhausted; L3 skipped"
                l3_runtime_reason_code_override = "budget_exhausted"
        if anti_bypass_match is not None:
            if anti_bypass_match.action == "force_l2":
                requested_tier = DecisionTier.L2
            elif anti_bypass_match.action == "force_l3":
                requested_tier = (
                    DecisionTier.L3 if not budget_exhausted else DecisionTier.L1
                )
                if budget_exhausted:
                    l3_runtime_reason_override = (
                        "LLM budget exhausted; anti-bypass L3 skipped"
                    )
                    l3_runtime_reason_code_override = "budget_exhausted"
        if not budget_exhausted:
            requested_tier = _effective_requested_tier_for_l3_config(
                requested_tier,
                effective_config,
                gateway.policy_engine.analyzer,
            )
        effective_requested_tier = requested_tier

        if anti_bypass_match is not None and anti_bypass_match.action in (
            "block",
            "defer",
        ):
            verdict = (
                DecisionVerdict.BLOCK
                if anti_bypass_match.action == "block"
                else DecisionVerdict.DEFER
            )
            policy_id = {
                "exact_raw_repeat": "anti-bypass-exact-repeat",
                "normalized_destructive_repeat": "anti-bypass-normalized-repeat",
                "cross_tool_script_similarity": "anti-bypass-cross-tool-review",
                "denied_effect_repeat": "anti-bypass-denied-effect-repeat",
                "pending_effect_equivalent": "anti-bypass-pending-effect-review",
            }.get(anti_bypass_match.match_type, "anti-bypass-follow-up-guard")
            decision = CanonicalDecision(
                decision=verdict,
                reason=(
                    "Anti-bypass follow-up guard matched "
                    f"{anti_bypass_match.match_type} after prior "
                    f"{anti_bypass_match.prior_risk_level} "
                    f"{anti_bypass_match.prior_policy_id}"
                ),
                policy_id=policy_id,
                risk_level=_risk_level_from_string(
                    anti_bypass_match.prior_risk_level
                ),
                decision_source=DecisionSource.POLICY,
                failure_class=FailureClass.NONE,
                final=True,
            )
            try:
                remaining_ms = max(0, (deadline_at - time.monotonic()) * 1000)
                _, snapshot, _ = gateway.policy_engine.evaluate(
                    req.event,
                    req.context,
                    DecisionTier.L1,
                    deadline_budget_ms=remaining_ms,
                    config=project_config,
                )
                if anti_bypass_match.match_type in {
                    "denied_effect_repeat",
                    "pending_effect_equivalent",
                }:
                    rule_hits = list(snapshot.rule_hits or [])
                    match_rule = (
                        "denied_effect_repeat"
                        if anti_bypass_match.match_type == "denied_effect_repeat"
                        else "pending_effect_equivalent"
                    )
                    for rule_id in (match_rule, *anti_bypass_match.reason_codes):
                        if rule_id and rule_id not in rule_hits:
                            rule_hits.append(rule_id)
                    update = {"rule_hits": rule_hits}
                    if anti_bypass_match.match_type == "denied_effect_repeat":
                        update["short_circuit_rule"] = "SC-5"
                    snapshot = snapshot.model_copy(update=update)
            except Exception:
                logger.exception("Policy engine error during anti-bypass snapshot")
                from clawsentry.gateway.policy.engine import RiskSnapshot

                snapshot = RiskSnapshot()
            actual_tier = DecisionTier.L1
        else:
            # Evaluate normally
            try:
                remaining_ms = max(0, (deadline_at - time.monotonic()) * 1000)
                policy_context = req.context
                if (
                    anti_bypass_match is not None
                    and anti_bypass_match.action in {"force_l2", "force_l3"}
                    and (
                        anti_bypass_match.action == "force_l2"
                        or not budget_exhausted
                    )
                ):
                    session_summary = {}
                    if policy_context is not None and isinstance(
                        policy_context.session_risk_summary, dict
                    ):
                        session_summary.update(policy_context.session_risk_summary)
                    metadata = anti_bypass_match.to_metadata()
                    if anti_bypass_match.action == "force_l2":
                        session_summary.update(
                            {
                                "force_l2": True,
                                "l2_request_reason": "anti_bypass_followup",
                                "l2_trigger_source_metadata": metadata,
                            }
                        )
                    else:
                        session_summary.update(
                            {
                                "force_l3": True,
                                "l3_request_reason": "anti_bypass_followup",
                                "l3_trigger_source_metadata": metadata,
                            }
                        )
                    session_summary.update(
                        {
                            "anti_bypass_followup": {
                                "action": anti_bypass_match.action,
                                "match_type": anti_bypass_match.match_type,
                                "reason_codes": list(
                                    anti_bypass_match.reason_codes
                                ),
                            },
                        }
                    )
                    policy_context = (
                        policy_context.model_copy(
                            update={"session_risk_summary": session_summary}
                        )
                        if policy_context is not None
                        else DecisionContext(session_risk_summary=session_summary)
                    )
                decision, snapshot, actual_tier = gateway.policy_engine.evaluate(
                    req.event,
                    policy_context,
                    requested_tier,
                    deadline_budget_ms=remaining_ms,
                    config=project_config,
                )
            except Exception:
                logger.exception("Policy engine error")
                error_resp = SyncDecisionErrorResponse(
                    request_id=req.request_id,
                    rpc_error_code=RPCErrorCode.ENGINE_INTERNAL_ERROR,
                    rpc_error_message="Internal engine error. Check server logs for details.",
                    retry_eligible=True,
                    retry_after_ms=50,
                )
                return gateway._jsonrpc_error_with_data(rpc_id, -32603, error_resp)

        # Annotate decision when budget forced L1-only downgrade
        if budget_exhausted and req.decision_tier != DecisionTier.L1:
            decision = decision.model_copy(
                update={
                    "reason": decision.reason + " [LLM budget exhausted, L1-only]"
                }
            )

    # --- CS-012: Record decision BEFORE deadline check ---
    # Recording must happen unconditionally so that even deadline-exceeded
    # decisions are persisted to trajectory_store and session_registry.
    event_dict = req.event.model_dump(mode="json")
    decision_dict = decision.model_dump(mode="json")
    snapshot_dict = snapshot.model_dump(mode="json")
    compat_event_type, compat_observation = _extract_compat_event_fields(event_dict)
    l3_trace = snapshot.l3_trace
    state.event = req.event
    state.context = req.context
    state.decision = decision
    state.snapshot = snapshot_dict
    state.l3_trace = l3_trace
    l3_available = _analyzer_supports_l3(gateway.policy_engine.analyzer)
    if actual_tier == DecisionTier.L3 or l3_trace is not None:
        l3_available = True
    l3_info = build_l3_runtime_info(
        requested_tier=req.decision_tier,
        effective_tier=effective_requested_tier,
        actual_tier=actual_tier,
        l3_available=l3_available,
        l3_trace=l3_trace,
        l3_reason=l3_runtime_reason_override,
        l3_reason_code=l3_runtime_reason_code_override,
    )
    meta_dict = {
        "request_id": req.request_id,
        "actual_tier": actual_tier.value,
        "deadline_ms": req.deadline_ms,
        "record_type": "decision",
        **l3_info,
        "caller_adapter": (
            req.context.caller_adapter
            if req.context and req.context.caller_adapter
            else "unknown"
        ),
    }
    state.meta = meta_dict
    capability_narrowing_meta = {
        "enabled": capability_narrowing_enabled,
        "applied": capability_narrowing_applied,
        "reason": capability_narrowing_reason,
        "reason_code": capability_narrowing_reason_code,
        "reason_codes": [capability_narrowing_reason_code],
    }
    if capability_narrowing_applied:
        capability_narrowing_meta["profile_id"] = (
            capability_narrowing_profile_id
            or (
                req.context.session_scope_profile.profile_id
                if req.context and req.context.session_scope_profile
                else None
            )
        )
    if effective_config.capability_narrowing_audit_verbosity == "verbose":
        capability_narrowing_meta.update(
            {
                "audit_verbosity": "verbose",
                "trigger_risk": effective_config.capability_narrowing_trigger_risk,
                "policy_summary": _capability_narrowing_policy_summary(
                    effective_config
                ),
            }
        )
    meta_dict["capability_narrowing"] = capability_narrowing_meta
    if anti_bypass_match is not None:
        meta_dict["anti_bypass"] = anti_bypass_match.to_metadata()
        meta_dict["anti_bypass_memory_evictions"] = (
            gateway.anti_bypass_guard.memory_evictions
        )
    if anti_bypass_probe is not None:
        meta_dict["anti_bypass_probe"] = anti_bypass_probe
    if snapshot_dict.get("effect_summary") is not None:
        meta_dict["action_effect_summary"] = snapshot_dict["effect_summary"]
    compat_evidence_summary = build_compatibility_evidence_summary(event_dict)
    if compat_evidence_summary is not None:
        # Operator-facing replay/session summaries only; not a canonical
        # decision source and intentionally compact.
        meta_dict["evidence_summary"] = compat_evidence_summary
    l3_trace_summary = _compact_l3_evidence_summary(l3_trace)
    if l3_trace_summary is not None:
        meta_dict["l3_trace_summary"] = l3_trace_summary
    if isinstance(l3_trace, dict):
        analysis_accounting = l3_trace.get("analysis_accounting")
        if analysis_accounting:
            meta_dict["analysis_accounting"] = analysis_accounting
        trace_source = l3_trace.get("trace_source")
        if trace_source:
            meta_dict["trace_source"] = trace_source
    skill_lineage = _lineage_summary_from_event(event_dict)
    if skill_lineage is not None:
        meta_dict["skill_lineage"] = skill_lineage
    if skill_lineage is not None or (
        req.context is not None and req.context.skill_trust_refs
    ):
        lineage_events = _lineage_events_from_summary(
            event=event_dict,
            decision=decision_dict,
            context=req.context,
            summary=skill_lineage or {},
        )
        if lineage_events:
            meta_dict["lineage_event"] = lineage_events[0]
            meta_dict["skill_use_ledger"] = {
                "schema": "clawsentry.skill_use_ledger.v1",
                "entries": lineage_events,
            }
    skill_trust_raw = _redact_skill_trust_raw_from_event(event_dict)
    if skill_trust_raw is not None:
        meta_dict["skill_trust_raw"] = skill_trust_raw
    mcp_raw = _redact_mcp_raw_from_event(event_dict)
    if mcp_raw is not None:
        meta_dict["mcp_raw"] = mcp_raw
    # CS-024: Keep stream/session framework consistent for HTTP adapters.
    event_dict["source_framework"] = _infer_source_framework(
        event_dict.get("source_framework"),
        meta_dict.get("caller_adapter"),
    )
    approval_bridge_kind: str | None = None
    approval_bridge_id: str | None = None
    approval_bridge_timeout_s: float | None = None
    approval_bridge_enabled = False
    if _is_confirmation_fast_lane(event_dict, compat_event_type):
        approval_bridge_kind = "confirmation"
        approval_bridge_id = _resolve_confirmation_approval_id(event_dict)
        approval_bridge_timeout_s = float(
            (project_config or gateway._detection_config).defer_timeout_s
        )
        approval_bridge_enabled = bool(
            gateway._detection_config.defer_bridge_enabled
            and (project_config is None or project_config.defer_bridge_enabled)
        )
        event_dict["approval_id"] = approval_bridge_id
        decision = CanonicalDecision(
            decision=DecisionVerdict.DEFER,
            reason="confirmation observed",
            policy_id="confirmation-bridge",
            risk_level=decision.risk_level,
            decision_source=DecisionSource.POLICY,
            final=False,
        )
        decision_dict = decision.model_dump(mode="json")
        state.decision = decision
        meta_dict.update(
            _approval_pending_meta(
                approval_id=approval_bridge_id,
                approval_kind=approval_bridge_kind,
                approval_reason=str(
                    decision_dict.get("reason") or "confirmation observed"
                ),
                approval_timeout_s=approval_bridge_timeout_s,
            )
        )
    _sid = str(event_dict.get("session_id") or "")
    previous_risk_level = gateway.session_registry.get_current_risk(_sid)
    pending_trajectory_alerts: list[dict[str, Any]] = []

    # --- E-4 Phase 2: Trajectory analysis ---
    # Run before persistence so configured DEFER/BLOCK handling is recorded
    # with the decision returned to the caller.
    try:
        traj_event = {
            "session_id": _sid,
            "event_id": req.event.event_id,
            "tool_name": req.event.tool_name or "",
            "occurred_at_ts": _parse_iso_timestamp(
                str(event_dict.get("occurred_at") or "")
            ),
            "payload": req.event.payload or {},
        }
        handling = (
            project_config or gateway._detection_config
        ).trajectory_alert_action
        traj_matches = gateway.trajectory_analyzer.record(traj_event)
        for tm in traj_matches:
            pending_trajectory_alerts.append(
                {
                    "type": "trajectory_alert",
                    "session_id": _sid,
                    "sequence_id": tm.sequence_id,
                    "risk_level": tm.risk_level,
                    "matched_event_ids": tm.matched_event_ids,
                    "reason": tm.reason,
                    "handling": handling,
                    "timestamp": str(
                        event_dict.get("occurred_at") or utc_now_iso()
                    ),
                }
            )
            if (
                handling in ("defer", "block")
                and req.event.event_type == EventType.PRE_ACTION
                and not enforcement_applied
                and _risk_rank(tm.risk_level) >= _risk_rank("high")
            ):
                verdict = (
                    DecisionVerdict.BLOCK
                    if handling == "block"
                    else DecisionVerdict.DEFER
                )
                if (
                    decision.decision == DecisionVerdict.BLOCK
                    and verdict != DecisionVerdict.BLOCK
                ):
                    continue
                decision = CanonicalDecision(
                    decision=verdict,
                    reason=f"Trajectory alert {tm.sequence_id}: {tm.reason}",
                    policy_id="trajectory-alert",
                    risk_level=_risk_level_from_string(tm.risk_level),
                    decision_source=DecisionSource.POLICY,
                    final=True,
                )
                decision_dict = decision.model_dump(mode="json")
                meta_dict["trajectory_alert_decision_override"] = {
                    "sequence_id": tm.sequence_id,
                    "risk_level": tm.risk_level,
                    "handling": handling,
                }
    except Exception:
        logger.exception(
            "trajectory analysis failed for event %s", req.event.event_id
        )

    decision = gateway._apply_missing_session_scope_evaluation(
        decision,
        req.event,
        req.context,
    )
    decision_dict = decision.model_dump(mode="json")
    state.decision = decision

    # --- Benchmark mode: no human DEFER waits ---
    # Apply before persistence/SSE so audit records and live events carry
    # the deterministic auto-resolution metadata promised by benchmark mode.
    effective_config = project_config or gateway._detection_config
    effective_mode = effective_config.mode
    if (
        effective_mode == "benchmark"
        and effective_config.benchmark_auto_resolve_defer
        and decision.decision == DecisionVerdict.DEFER
        and req.event.event_type == EventType.PRE_ACTION
    ):
        benchmark_action = effective_config.benchmark_defer_action
        resolved_verdict = DecisionVerdict.BLOCK
        if benchmark_action == "allow":
            resolved_verdict = DecisionVerdict.ALLOW
        elif benchmark_action == "allow_low_block_high":
            original_risk = getattr(
                decision.risk_level, "value", str(decision.risk_level)
            )
            resolved_verdict = (
                DecisionVerdict.ALLOW
                if _risk_rank(original_risk) <= _risk_rank("low")
                else DecisionVerdict.BLOCK
            )
        original_reason = decision.reason
        decision = CanonicalDecision(
            decision=resolved_verdict,
            reason=(
                "Benchmark mode auto-resolved DEFER to "
                f"{resolved_verdict.value}: {original_reason}"
            ),
            policy_id=decision.policy_id or "benchmark-auto-resolve",
            risk_level=decision.risk_level,
            decision_source=DecisionSource.POLICY,
            final=True,
        )
        decision_dict = decision.model_dump(mode="json")
        state.decision = decision
        meta_dict.update(
            {
                "auto_resolved": True,
                "auto_resolve_mode": "benchmark",
                "original_verdict": "defer",
                "benchmark_defer_action": benchmark_action,
            }
        )

    agent_safety_feedback_for_response: dict[str, Any] | None = None
    agent_advisory_feedback_for_response: dict[str, Any] | None = None
    if (
        effective_config.agent_safety_feedback_enabled
        and req.event.event_type == EventType.PRE_ACTION
    ):
        feedback_delivery = _agent_safety_feedback_delivery(req.context, req.event)
        feedback = _agent_safety_feedback(
            decision=decision,
            event=req.event,
            snapshot=snapshot_dict,
            delivery=feedback_delivery,
        )
        if feedback is not None:
            meta_dict["agent_safety_feedback"] = feedback
            feedback_surface = str(feedback.get("blocked_surface") or "unknown")
            feedback_delivery_key = (
                str(req.event.session_id or req.event.trace_id or "unknown"),
                feedback_delivery,
                feedback_surface,
            )
            if feedback_delivery == "response":
                if (
                    feedback_delivery_key
                    in gateway._agent_safety_feedback_delivered_surfaces
                ):
                    meta_dict["agent_safety_feedback_delivery_suppressed"] = {
                        "reason": "already_delivered_for_surface",
                        "surface": feedback_surface,
                    }
                else:
                    gateway._agent_safety_feedback_delivered_surfaces.add(
                        feedback_delivery_key
                    )
                    agent_safety_feedback_for_response = feedback
        advisory_feedback = _agent_advisory_feedback(
            decision=decision,
            event=req.event,
            delivery=feedback_delivery,
        )
        if advisory_feedback is not None:
            meta_dict["agent_advisory_feedback"] = advisory_feedback
            if feedback_delivery == "response":
                agent_advisory_feedback_for_response = advisory_feedback

    record_id = gateway._record_decision_path(
        event=event_dict,
        decision=decision_dict,
        snapshot=snapshot_dict,
        meta=meta_dict,
        l3_trace=l3_trace,
    )
    gateway.anti_bypass_guard.record_final_decision(
        event=req.event,
        decision=decision,
        snapshot=snapshot,
        meta=meta_dict,
        record_id=record_id,
        config=effective_config,
        context=req.context,
    )

    current_risk_level = str(
        snapshot_dict.get("risk_level") or decision_dict.get("risk_level") or "low"
    )
    occurred_at = str(event_dict.get("occurred_at") or utc_now_iso())
    gateway._maybe_create_l3_advisory_snapshot(
        config=project_config or gateway._detection_config,
        session_id=_sid,
        event_id=str(event_dict.get("event_id") or "unknown"),
        record_id=record_id,
        current_risk_level=current_risk_level,
        pending_trajectory_alerts=pending_trajectory_alerts,
        compat_event_type=compat_event_type,
    )

    for alert in pending_trajectory_alerts:
        gateway.event_bus.broadcast(alert)

    # --- A-7: Check if threshold is newly breached ---
    session_id = str(event_dict.get("session_id") or "")
    if session_id and gateway.session_enforcement.enabled:
        stats = gateway.session_registry.get_session_stats(session_id)
        new_enf = gateway.session_enforcement.evaluate_threshold(
            session_id, stats.get("high_risk_event_count", 0)
        )
        if new_enf:
            gateway.event_bus.broadcast(
                {
                    "type": "session_enforcement_change",
                    "session_id": session_id,
                    "state": "enforced",
                    "action": new_enf.action.value,
                    "high_risk_count": new_enf.high_risk_count,
                    "timestamp": str(
                        event_dict.get("occurred_at") or utc_now_iso()
                    ),
                }
            )

    # --- CS-013/CS-016: SSE broadcasts BEFORE deadline check ---
    # Event broadcasts must happen unconditionally so that watch CLI and
    # /report/stream subscribers always receive events, even when the
    # request exceeds its deadline.
    if previous_risk_level is None and session_id:
        gateway.event_bus.broadcast(
            {
                "type": "session_start",
                "session_id": session_id,
                "agent_id": str(event_dict.get("agent_id") or "unknown"),
                "source_framework": str(
                    event_dict.get("source_framework") or "unknown"
                ),
                "timestamp": occurred_at,
            }
        )
        gateway.metrics.session_started()

    # --- P3: Record metrics ---
    _latency_s = time.monotonic() - start
    _source_fw = str(event_dict.get("source_framework") or "unknown")
    _risk_score_val = float(snapshot_dict.get("composite_score") or 0.0)
    gateway.metrics.record_decision(
        verdict=str(decision_dict.get("decision") or "unknown"),
        risk_level=current_risk_level,
        risk_score=_risk_score_val,
        tier=actual_tier.value,
        source_framework=_source_fw,
        latency_s=_latency_s,
    )
    if (
        _snapshot_has_content_evidence_rule(snapshot_dict)
        and str(decision_dict.get("decision") or "").lower() != "allow"
    ):
        gateway.metrics.record_content_evidence(policy_not_allow=True)

    decision_event = {
        "type": "decision",
        "session_id": session_id,
        "request_id": req.request_id,
        "event_id": str(event_dict.get("event_id") or "unknown"),
        "risk_level": current_risk_level,
        "decision": str(decision_dict.get("decision") or "unknown"),
        "tool_name": event_dict.get("tool_name"),
        "actual_tier": actual_tier.value,
        "l3_available": l3_info["l3_available"],
        "l3_requested": l3_info["l3_requested"],
        "l3_state": l3_info["l3_state"],
        "l3_reason": l3_info["l3_reason"],
        "l3_reason_code": l3_info["l3_reason_code"],
        "timestamp": occurred_at,
        "reason": str(decision_dict.get("reason") or ""),
        "command": str(
            event_dict.get("tool_name", "")
            if meta_dict.get("anti_bypass") is not None
            else (
                event_dict.get("payload", {}).get("command", "")
                or event_dict.get("tool_name", "")
            )
        ),
        "trigger_detail": (l3_trace or {}).get("trigger_detail"),
        "approval_id": event_dict.get("approval_id"),
        "expires_at": event_dict.get("payload", {}).get("expiresAtMs"),
    }
    if compat_event_type:
        decision_event["compat_event_type"] = compat_event_type
    if compat_observation is not None:
        decision_event["compat_observation"] = compat_observation
    if meta_dict.get("anti_bypass") is not None:
        decision_event["anti_bypass"] = meta_dict["anti_bypass"]
        decision_event["anti_bypass_memory_evictions"] = (
            gateway.anti_bypass_guard.memory_evictions
        )
    if meta_dict.get("anti_bypass_probe") is not None:
        decision_event["anti_bypass_probe"] = meta_dict["anti_bypass_probe"]
    if meta_dict.get("capability_narrowing") is not None:
        decision_event["capability_narrowing"] = meta_dict["capability_narrowing"]
    effect_summary = decision_effect_summary(decision_dict.get("decision_effects"))
    if effect_summary is not None:
        decision_event["effect_summary"] = effect_summary
        decision_event["decision_effect_summary"] = effect_summary
    if meta_dict.get("action_effect_summary") is not None:
        decision_event["action_effect_summary"] = meta_dict["action_effect_summary"]
    if decision_dict.get("scope_evaluation") is not None:
        decision_event["scope_evaluation"] = decision_dict["scope_evaluation"]
    for key in (
        "approval_kind",
        "approval_state",
        "approval_reason",
        "approval_reason_code",
        "approval_timeout_s",
        "auto_resolved",
        "auto_resolve_mode",
        "original_verdict",
        "benchmark_defer_action",
    ):
        if meta_dict.get(key) is not None:
            decision_event[key] = meta_dict.get(key)
    decision_event.update(gateway._reporting_state())
    evidence_summary = _compact_l3_evidence_summary(l3_trace)
    if evidence_summary is not None:
        decision_event["evidence_summary"] = evidence_summary
    gateway.event_bus.broadcast(decision_event)

    if previous_risk_level is not None and _risk_rank(
        current_risk_level
    ) > _risk_rank(previous_risk_level):
        gateway.event_bus.broadcast(
            {
                "type": "session_risk_change",
                "session_id": session_id,
                "previous_risk": previous_risk_level,
                "current_risk": current_risk_level,
                "trigger_event": str(event_dict.get("event_id") or "unknown"),
                "timestamp": occurred_at,
            }
        )

    if session_id and _risk_rank(current_risk_level) >= _risk_rank("high"):
        import uuid as _uuid

        alert_id = f"alert-{_uuid.uuid4().hex[:12]}"
        triggered_at_ts = time.time()
        severity = current_risk_level  # "high" or "critical"
        session_data = gateway.session_registry.get_session_stats(session_id)
        high_risk_count = session_data.get("high_risk_event_count", 1)
        message = (
            f"Session risk escalated to {current_risk_level.upper()}: "
            f"{high_risk_count} high-risk event(s) detected"
        )
        alert = {
            "alert_id": alert_id,
            "severity": severity,
            "metric": "session_risk_escalation",
            "session_id": session_id,
            "message": message,
            "details": {
                "previous_risk": previous_risk_level,
                "current_risk": current_risk_level,
                "high_risk_count": high_risk_count,
                "cumulative_score": session_data.get("cumulative_score", 0),
                "trigger_event_id": str(event_dict.get("event_id") or "unknown"),
                "tool_name": event_dict.get("tool_name"),
            },
            "triggered_at": occurred_at,
            "triggered_at_ts": triggered_at_ts,
            "acknowledged": False,
            "acknowledged_by": None,
            "acknowledged_at": None,
        }
        gateway.alert_registry.add(alert)
        gateway.event_bus.broadcast(
            {
                "type": "alert",
                "alert_id": alert_id,
                "severity": severity,
                "metric": "session_risk_escalation",
                "session_id": session_id,
                "current_risk": current_risk_level,
                "message": message,
                "timestamp": occurred_at,
            }
        )

    # --- E-4: Post-action security analysis (fire-and-forget) ---
    if req.event.event_type == EventType.POST_ACTION:
        from clawsentry.gateway.analysis.risk_snapshot import _flatten_tool_output_text

        output_text = ""
        for _pa_key in ("output", "result", "tool_response", "tool_output"):
            output_text = _flatten_tool_output_text(req.event.payload.get(_pa_key))
            if output_text:
                break
        if output_text:
            _pa_meta = (req.event.payload or {}).get("_clawsentry_meta") or {}
            _pa_origin = (
                _pa_meta.get("content_origin")
                if isinstance(_pa_meta, dict)
                else None
            )
            _pa_file_path = None
            if isinstance(_pa_meta, dict):
                _pa_file_path = _pa_meta.get("file_path")
            if not _pa_file_path:
                _pa_file_path = (
                    req.event.payload.get("file_path")
                    or req.event.payload.get("path")
                    or req.event.payload.get("target_path")
                )
            asyncio.create_task(
                gateway._run_post_action_async(
                    output_text=output_text,
                    tool_name=req.event.tool_name or "unknown",
                    event_id=req.event.event_id,
                    session_id=session_id,
                    source_framework=str(
                        event_dict.get("source_framework") or "unknown"
                    ),
                    content_origin=_pa_origin,
                    external_multiplier=(
                        project_config or gateway._detection_config
                    ).external_content_post_action_multiplier,
                    finding_action=(
                        project_config or gateway._detection_config
                    ).post_action_finding_action,
                    occurred_at=occurred_at,
                    file_path=str(_pa_file_path) if _pa_file_path else None,
                )
            )

    # --- E-5: Extract candidate pattern from confirmed high-risk events ---
    if (
        gateway.evolution_manager.enabled
        and req.event.event_type == EventType.PRE_ACTION
        and decision.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    ):
        try:
            candidate_id = gateway.evolution_manager.extract_candidate(
                event_id=req.event.event_id,
                session_id=str(req.event.session_id or ""),
                tool_name=req.event.tool_name or "",
                command=str(req.event.payload.get("command", ""))
                if req.event.payload
                else "",
                risk_level=decision.risk_level,
                source_framework=str(
                    event_dict.get("source_framework") or "unknown"
                ),
                reasons=decision.reason.split("; ") if decision.reason else [],
            )
            if candidate_id:
                gateway.event_bus.broadcast(
                    {
                        "type": "pattern_candidate",
                        "pattern_id": candidate_id,
                        "session_id": session_id,
                        "source_framework": str(
                            event_dict.get("source_framework") or "unknown"
                        ),
                        "status": "candidate",
                        "timestamp": occurred_at,
                    }
                )
        except Exception:
            logger.warning("evolved pattern extraction failed", exc_info=True)

    if approval_bridge_kind == "confirmation":
        approval_id = approval_bridge_id or _resolve_confirmation_approval_id(
            event_dict
        )
        approval_timeout_s = float(
            approval_bridge_timeout_s
            or (project_config or gateway._detection_config).defer_timeout_s
        )
        resolution_recorded_at = utc_now_iso()
        resolution_event = dict(event_dict)
        resolution_event["occurred_at"] = resolution_recorded_at
        resolution_event["approval_id"] = approval_id
        resolution_meta = {
            **meta_dict,
            "approval_id": approval_id,
        }

        if not approval_bridge_enabled:
            decision = CanonicalDecision(
                decision=DecisionVerdict.BLOCK,
                reason="Confirmation approval has no route; blocking",
                policy_id="confirmation-bridge",
                risk_level=decision.risk_level,
                decision_source=DecisionSource.SYSTEM,
                failure_class=FailureClass.APPROVAL_NO_ROUTE,
                final=True,
            )
            decision_dict = decision.model_dump(mode="json")
            state.decision = decision
            resolution_approval = _approval_resolution_meta(
                approval_id=approval_id,
                approval_kind=approval_bridge_kind,
                approval_state="no_route",
                approval_reason="Confirmation approval has no route; blocking",
                approval_reason_code=_APPROVAL_NO_ROUTE_REASON_CODE,
                approval_timeout_s=approval_timeout_s,
            )
            resolution_record_id = gateway._record_decision_path(
                event=resolution_event,
                decision=decision_dict,
                snapshot=snapshot_dict,
                meta={
                    **resolution_meta,
                    **resolution_approval,
                    "record_type": "decision_resolution",
                },
                l3_trace=l3_trace,
            )
            gateway.anti_bypass_guard.resolve_pending_effect_hold(
                event=_event_for_effect_resolution(req.event),
                context=req.context,
                decision=decision,
                record_id=resolution_record_id,
                config=effective_config,
            )
            gateway.event_bus.broadcast(
                {
                    "type": "defer_resolved",
                    "session_id": session_id,
                    **resolution_approval,
                    "resolved_decision": decision_dict["decision"],
                    "resolved_reason": decision_dict["reason"],
                    "timestamp": resolution_recorded_at,
                }
            )
        elif not gateway.defer_manager.register_approval(
            approval_id,
            approval_kind=approval_bridge_kind,
            session_id=session_id,
            tool_name=req.event.tool_name or "",
            summary=str(
                req.event.payload.get("command", "") if req.event.payload else ""
            )
            or None,
            approval_binding=_approval_binding_from_snapshot(
                event=event_dict,
                snapshot=snapshot_dict,
                context=req.context,
            ),
        ):
            decision = CanonicalDecision(
                decision=DecisionVerdict.BLOCK,
                reason=f"Confirmation approval queue full ({gateway.defer_manager.max_pending}), blocking",
                policy_id="confirmation-bridge",
                risk_level=decision.risk_level,
                decision_source=DecisionSource.SYSTEM,
                failure_class=FailureClass.APPROVAL_QUEUE_FULL,
                final=True,
            )
            decision_dict = decision.model_dump(mode="json")
            state.decision = decision
            resolution_approval = _approval_resolution_meta(
                approval_id=approval_id,
                approval_kind=approval_bridge_kind,
                approval_state="queue_full",
                approval_reason=f"Confirmation approval queue full ({gateway.defer_manager.max_pending}), blocking",
                approval_reason_code=_APPROVAL_QUEUE_FULL_REASON_CODE,
                approval_timeout_s=approval_timeout_s,
            )
            resolution_record_id = gateway._record_decision_path(
                event=resolution_event,
                decision=decision_dict,
                snapshot=snapshot_dict,
                meta={
                    **resolution_meta,
                    **resolution_approval,
                    "record_type": "decision_resolution",
                },
                l3_trace=l3_trace,
            )
            gateway.anti_bypass_guard.resolve_pending_effect_hold(
                event=_event_for_effect_resolution(req.event),
                context=req.context,
                decision=decision,
                record_id=resolution_record_id,
                config=effective_config,
            )
            gateway.event_bus.broadcast(
                {
                    "type": "defer_resolved",
                    "session_id": session_id,
                    **resolution_approval,
                    "resolved_decision": decision_dict["decision"],
                    "resolved_reason": decision_dict["reason"],
                    "timestamp": resolution_recorded_at,
                }
            )
        else:
            gateway.metrics.defer_registered()
            pending_approval = _approval_pending_meta(
                approval_id=approval_id,
                approval_kind=approval_bridge_kind,
                approval_reason=str(
                    meta_dict.get("approval_reason")
                    or decision_dict.get("reason")
                    or "confirmation observed"
                ),
                approval_timeout_s=approval_timeout_s,
            )
            gateway.event_bus.broadcast(
                {
                    "type": "defer_pending",
                    "session_id": session_id,
                    **pending_approval,
                    **_approval_prompt_event_fields(
                        event=event_dict,
                        decision=decision_dict,
                    ),
                    "tool_name": req.event.tool_name or "",
                    "command": str(
                        req.event.tool_name or ""
                        if meta_dict.get("anti_bypass") is not None
                        else (
                            req.event.payload.get("command", "")
                            if req.event.payload
                            else ""
                        )
                    ),
                    "reason": str(decision_dict.get("reason") or ""),
                    "timeout_s": approval_timeout_s,
                    "timestamp": occurred_at,
                }
            )

            (
                _resolved_decision,
                _resolved_reason,
            ) = await gateway.defer_manager.wait_for_resolution(approval_id)
            approval_record = gateway.defer_manager.get_approval(approval_id)
            approval_state = approval_record.approval_state or "resolved"
            approval_reason = approval_record.reason or _resolved_reason
            approval_reason_code = approval_record.reason_code or (
                _APPROVAL_ALLOWED_REASON_CODE
                if _resolved_decision in ("allow", "allow-once", "allow-always")
                else _APPROVAL_DENIED_REASON_CODE
            )

            if _resolved_decision in ("allow", "allow-once", "allow-always"):
                decision_source = (
                    DecisionSource.OPERATOR
                    if approval_state == "resolved"
                    else DecisionSource.SYSTEM
                )
                approval_payload = approval_record.resolution_payload
                if isinstance(approval_payload, dict) and approval_payload:
                    try:
                        validated_payload = _validate_rewrite_resolution_payload(
                            approval_payload
                        )
                        rewrite_effects = _rewrite_effect_for_resolution(
                            approval_id=approval_id,
                            event=event_dict,
                            replacement_payload=validated_payload,
                            resolver_identity=approval_record.resolver_identity,
                            policy_id="confirmation-bridge",
                        )
                    except ValueError as exc:
                        decision = CanonicalDecision(
                            decision=DecisionVerdict.BLOCK,
                            reason=f"Rewrite validation failed: {exc}",
                            policy_id="confirmation-bridge",
                            risk_level=decision.risk_level,
                            decision_source=DecisionSource.SYSTEM,
                            failure_class=FailureClass.INPUT_INVALID,
                            final=True,
                        )
                    else:
                        decision = CanonicalDecision(
                            decision=DecisionVerdict.MODIFY,
                            reason=(
                                f"Operator approved rewrite: {approval_reason}"
                                if approval_state == "resolved" and approval_reason
                                else "Operator approved rewrite"
                            ),
                            policy_id="confirmation-bridge",
                            risk_level=decision.risk_level,
                            decision_source=decision_source,
                            modified_payload=validated_payload,
                            decision_effects=rewrite_effects,
                            failure_class=FailureClass.NONE,
                            final=True,
                        )
                else:
                    decision = CanonicalDecision(
                        decision=DecisionVerdict.ALLOW,
                        reason=(
                            f"Operator approved: {approval_reason}"
                            if approval_state == "resolved" and approval_reason
                            else "Operator approved"
                            if approval_state == "resolved"
                            else approval_reason or "Approval timeout auto-allow"
                        ),
                        policy_id="confirmation-bridge",
                        risk_level=decision.risk_level,
                        decision_source=decision_source,
                        failure_class=(
                            FailureClass.APPROVAL_TIMEOUT
                            if approval_state == "timeout"
                            else FailureClass.NONE
                        ),
                        final=True,
                    )
            else:
                decision_source = (
                    DecisionSource.OPERATOR
                    if approval_state == "resolved"
                    else DecisionSource.SYSTEM
                )
                decision = CanonicalDecision(
                    decision=DecisionVerdict.BLOCK,
                    reason=(
                        f"Operator denied: {approval_reason}"
                        if approval_state == "resolved" and approval_reason
                        else "Operator denied"
                        if approval_state == "resolved"
                        else approval_reason or "Approval denied"
                    ),
                    policy_id="confirmation-bridge",
                    risk_level=decision.risk_level,
                    decision_source=decision_source,
                    failure_class=(
                        FailureClass.APPROVAL_TIMEOUT
                        if approval_state == "timeout"
                        else FailureClass.NONE
                    ),
                    final=True,
                )

            decision_dict = decision.model_dump(mode="json")
            state.decision = decision
            resolution_recorded_at = utc_now_iso()
            resolution_event = dict(event_dict)
            resolution_event["occurred_at"] = resolution_recorded_at
            resolution_event["approval_id"] = approval_id
            resolution_approval = _approval_resolution_meta(
                approval_id=approval_id,
                approval_kind=approval_bridge_kind,
                approval_state=approval_state,
                approval_reason=approval_reason,
                approval_reason_code=approval_reason_code,
                approval_timeout_s=float(
                    approval_record.timeout_s or approval_timeout_s
                ),
            )
            resolution_record_id = gateway._record_decision_path(
                event=resolution_event,
                decision=decision_dict,
                snapshot=snapshot_dict,
                meta={
                    **resolution_meta,
                    **resolution_approval,
                    "record_type": "decision_resolution",
                },
                l3_trace=l3_trace,
            )
            gateway.anti_bypass_guard.resolve_pending_effect_hold(
                event=_event_for_effect_resolution(req.event),
                context=req.context,
                decision=decision,
                record_id=resolution_record_id,
                config=effective_config,
            )
            gateway.metrics.defer_resolved()
            gateway.event_bus.broadcast(
                {
                    "type": "defer_resolved",
                    "session_id": session_id,
                    **resolution_approval,
                    "resolved_decision": decision_dict["decision"],
                    "resolved_reason": decision_dict["reason"],
                    "timestamp": resolution_recorded_at,
                }
            )

    # --- P1: DEFER bridge — wait for operator approval ---
    if (
        gateway._detection_config.defer_bridge_enabled
        and (project_config is None or project_config.defer_bridge_enabled)
        and decision.decision == DecisionVerdict.DEFER
        and req.event.event_type == EventType.PRE_ACTION
        and not enforcement_applied
    ):
        defer_id = f"cs-defer-{uuid.uuid4().hex[:12]}"
        if not gateway.defer_manager.register_defer(
            defer_id,
            approval_binding=_approval_binding_from_snapshot(
                event=event_dict,
                snapshot=snapshot_dict,
                context=req.context,
            ),
        ):
            # Queue full — fall back to block
            decision = CanonicalDecision(
                decision=DecisionVerdict.BLOCK,
                reason=f"DEFER queue full ({gateway.defer_manager.max_pending}), blocking",
                policy_id="defer-bridge",
                risk_level=decision.risk_level,
                decision_source=DecisionSource.POLICY,
                failure_class=FailureClass.APPROVAL_QUEUE_FULL,
                final=True,
            )
            decision_dict = decision.model_dump(mode="json")
            resolution_recorded_at = utc_now_iso()
            resolution_event = dict(event_dict)
            resolution_event["occurred_at"] = resolution_recorded_at
            resolution_event["approval_id"] = defer_id
            resolution_approval = _approval_resolution_meta(
                approval_id=defer_id,
                approval_kind="defer",
                approval_state="queue_full",
                approval_reason=f"DEFER queue full ({gateway.defer_manager.max_pending}), blocking",
                approval_reason_code=_APPROVAL_QUEUE_FULL_REASON_CODE,
                approval_timeout_s=float(
                    (project_config or gateway._detection_config).defer_timeout_s
                ),
            )
            resolution_meta = {
                **meta_dict,
                **resolution_approval,
            }
            resolution_record_id = gateway._record_decision_path(
                event=resolution_event,
                decision=decision_dict,
                snapshot=snapshot_dict,
                meta={
                    **resolution_meta,
                    "record_type": "decision_resolution",
                },
                l3_trace=l3_trace,
            )
            gateway.anti_bypass_guard.resolve_pending_effect_hold(
                event=_event_for_effect_resolution(req.event),
                context=req.context,
                decision=decision,
                record_id=resolution_record_id,
                config=effective_config,
            )
            gateway.event_bus.broadcast(
                {
                    "type": "defer_resolved",
                    "session_id": session_id,
                    **resolution_approval,
                    "resolved_decision": decision_dict["decision"],
                    "resolved_reason": decision_dict["reason"],
                    "timestamp": resolution_recorded_at,
                }
            )
        else:
            gateway.metrics.defer_registered()

            # Broadcast defer_pending event
            _defer_timeout = (
                project_config or gateway._detection_config
            ).defer_timeout_s
            pending_approval = _approval_pending_meta(
                approval_id=defer_id,
                approval_kind="defer",
                approval_reason=str(decision_dict.get("reason") or ""),
                approval_timeout_s=float(_defer_timeout),
            )
            gateway.event_bus.broadcast(
                {
                    "type": "defer_pending",
                    "session_id": session_id,
                    **pending_approval,
                    **_approval_prompt_event_fields(
                        event=event_dict,
                        decision=decision_dict,
                    ),
                    "tool_name": req.event.tool_name or "",
                    "command": str(
                        req.event.tool_name or ""
                        if meta_dict.get("anti_bypass") is not None
                        else (
                            req.event.payload.get("command", "")
                            if req.event.payload
                            else ""
                        )
                    ),
                    "reason": str(decision_dict.get("reason") or ""),
                    "timeout_s": _defer_timeout,
                    "timestamp": occurred_at,
                }
            )

            # Wait for operator resolution
            (
                _resolved_decision,
                _resolved_reason,
            ) = await gateway.defer_manager.wait_for_resolution(defer_id)
            approval_record = gateway.defer_manager.get_approval(defer_id)

            # Convert to final CanonicalDecision
            if _resolved_decision in ("allow", "allow-once"):
                decision_source = (
                    DecisionSource.OPERATOR
                    if (approval_record.approval_state or "resolved") == "resolved"
                    else DecisionSource.SYSTEM
                )
                approval_payload = approval_record.resolution_payload
                if isinstance(approval_payload, dict) and approval_payload:
                    try:
                        validated_payload = _validate_rewrite_resolution_payload(
                            approval_payload
                        )
                        rewrite_effects = _rewrite_effect_for_resolution(
                            approval_id=defer_id,
                            event=event_dict,
                            replacement_payload=validated_payload,
                            resolver_identity=approval_record.resolver_identity,
                            policy_id="defer-bridge",
                        )
                    except ValueError as exc:
                        decision = CanonicalDecision(
                            decision=DecisionVerdict.BLOCK,
                            reason=f"Rewrite validation failed: {exc}",
                            policy_id="defer-bridge",
                            risk_level=decision.risk_level,
                            decision_source=DecisionSource.SYSTEM,
                            failure_class=FailureClass.INPUT_INVALID,
                            final=True,
                        )
                    else:
                        decision = CanonicalDecision(
                            decision=DecisionVerdict.MODIFY,
                            reason=(
                                f"Operator approved rewrite: {_resolved_reason}"
                                if (approval_record.approval_state or "resolved")
                                == "resolved"
                                and _resolved_reason
                                else "Operator approved rewrite"
                            ),
                            policy_id="defer-bridge",
                            risk_level=decision.risk_level,
                            decision_source=decision_source,
                            modified_payload=validated_payload,
                            decision_effects=rewrite_effects,
                            failure_class=FailureClass.NONE,
                            final=True,
                        )
                else:
                    decision = CanonicalDecision(
                        decision=DecisionVerdict.ALLOW,
                        reason=(
                            f"Operator approved: {_resolved_reason}"
                            if (approval_record.approval_state or "resolved")
                            == "resolved"
                            and _resolved_reason
                            else "Operator approved"
                            if (approval_record.approval_state or "resolved")
                            == "resolved"
                            else _resolved_reason or "Approval timeout auto-allow"
                        ),
                        policy_id="defer-bridge",
                        risk_level=decision.risk_level,
                        decision_source=decision_source,
                        failure_class=(
                            FailureClass.APPROVAL_TIMEOUT
                            if (approval_record.approval_state or "resolved")
                            == "timeout"
                            else FailureClass.NONE
                        ),
                        final=True,
                    )
            else:
                decision = CanonicalDecision(
                    decision=DecisionVerdict.BLOCK,
                    reason=(
                        f"Operator denied: {_resolved_reason}"
                        if (approval_record.approval_state or "resolved")
                        == "resolved"
                        and _resolved_reason
                        else "Operator denied"
                        if (approval_record.approval_state or "resolved")
                        == "resolved"
                        else _resolved_reason or "Approval timeout auto-block"
                    ),
                    policy_id="defer-bridge",
                    risk_level=decision.risk_level,
                    decision_source=(
                        DecisionSource.OPERATOR
                        if (approval_record.approval_state or "resolved")
                        == "resolved"
                        else DecisionSource.SYSTEM
                    ),
                    failure_class=(
                        FailureClass.APPROVAL_TIMEOUT
                        if (approval_record.approval_state or "resolved")
                        == "timeout"
                        else FailureClass.NONE
                    ),
                    final=True,
                )

            # Update dict for response
            decision_dict = decision.model_dump(mode="json")
            state.decision = decision

            resolution_recorded_at = utc_now_iso()
            resolution_event = dict(event_dict)
            resolution_event["occurred_at"] = resolution_recorded_at
            resolution_event["approval_id"] = defer_id
            resolution_approval = _approval_resolution_meta(
                approval_id=defer_id,
                approval_kind="defer",
                approval_state=approval_record.approval_state or "resolved",
                approval_reason=approval_record.reason or _resolved_reason,
                approval_reason_code=approval_record.reason_code
                or (
                    _APPROVAL_ALLOWED_REASON_CODE
                    if _resolved_decision in ("allow", "allow-once", "allow-always")
                    else _APPROVAL_DENIED_REASON_CODE
                ),
                approval_timeout_s=float(
                    approval_record.timeout_s or _defer_timeout
                ),
            )
            resolution_meta = {
                **meta_dict,
                **resolution_approval,
            }
            resolution_record_id = gateway._record_decision_path(
                event=resolution_event,
                decision=decision_dict,
                snapshot=snapshot_dict,
                meta={
                    **resolution_meta,
                    "record_type": "decision_resolution",
                },
                l3_trace=l3_trace,
            )
            gateway.anti_bypass_guard.resolve_pending_effect_hold(
                event=_event_for_effect_resolution(req.event),
                context=req.context,
                decision=decision,
                record_id=resolution_record_id,
                config=effective_config,
            )

            gateway.metrics.defer_resolved()

            # Broadcast defer_resolved event
            gateway.event_bus.broadcast(
                {
                    "type": "defer_resolved",
                    "session_id": session_id,
                    **resolution_approval,
                    "resolved_decision": decision_dict["decision"],
                    "resolved_reason": decision_dict["reason"],
                    "timestamp": resolution_recorded_at,
                }
            )

    # Check if we exceeded deadline (after recording + broadcasts, so
    # audit trail and SSE events are intact)
    if time.monotonic() > deadline_at:
        error_resp = SyncDecisionErrorResponse(
            request_id=req.request_id,
            rpc_error_code=RPCErrorCode.DEADLINE_EXCEEDED,
            rpc_error_message=f"Decision took longer than deadline_ms={req.deadline_ms}",
            retry_eligible=True,
            retry_after_ms=50,
            fallback_decision=decision,
        )
        return gateway._jsonrpc_error_with_data(rpc_id, -32604, error_resp)

    # Build success response
    resp = SyncDecisionResponse(
        request_id=req.request_id,
        decision=decision,
        actual_tier=actual_tier,
        l3_available=l3_info["l3_available"],
        l3_requested=l3_info["l3_requested"],
        l3_state=l3_info["l3_state"],
        l3_reason=l3_info["l3_reason"],
        l3_reason_code=l3_info["l3_reason_code"],
        agent_safety_feedback=agent_safety_feedback_for_response,
        agent_advisory_feedback=agent_advisory_feedback_for_response,
        served_at=utc_now_iso(),
    )
    resp_dict = resp.model_dump(mode="json")
    if resp_dict.get("agent_safety_feedback") is None:
        resp_dict.pop("agent_safety_feedback", None)
    if resp_dict.get("agent_advisory_feedback") is None:
        resp_dict.pop("agent_advisory_feedback", None)

    _cache_successful_response(gateway, state, req, resp_dict)

    return gateway._jsonrpc_success(rpc_id, resp_dict)
