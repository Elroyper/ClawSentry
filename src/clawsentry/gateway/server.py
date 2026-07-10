"""
AHP Supervision Gateway — UDS + HTTP dual-transport server.

Design basis:
  - 01-scope-and-architecture.md section 6 (Sidecar + UDS + HTTP)
  - 04-policy-decision-and-fallback.md section 8-11 (SyncDecision v1 / JSON-RPC 2.0)

Transports:
  - Primary: Unix Domain Socket at /tmp/clawsentry.sock
  - Backup: HTTP at localhost:8080
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import argparse
import logging
import os
import re
import sys
import threading
import time
from typing import Any, Literal, Optional

from pathlib import Path
import uuid
import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse
from starlette.responses import FileResponse, HTMLResponse
from pydantic import ValidationError

from clawsentry.gateway.storage.alert_registry import AlertRegistry
from clawsentry.gateway.analysis.anti_bypass_guard import AntiBypassGuard, AntiBypassMatch
from clawsentry.gateway.analysis.anti_bypass_llm_recognizer import (
    AntiBypassLLMProvider,
    recognize_anti_bypass_candidate,
)
from clawsentry.gateway.analysis.content_evidence import collect_for_event, strip_content_bodies
from .core.agent_feedback import (
    _agent_advisory_feedback,
    _agent_safety_feedback,
    _agent_safety_feedback_delivery,
    _risk_points,
    _risk_rank,
)
from .core.capability_narrowing import (
    _capability_narrowing_policy_summary,
    _capability_narrowing_profile,
)
from .core.config_resolution import (
    _enforcement_action_from_config,
    _extract_compat_event_fields,
    _extract_project_config,
    _infer_source_framework,
    _load_default_session_scope_profile,
    _risk_level_from_string,
)
from .core.content_evidence import (
    _content_evidence_approved_roots,
    _content_evidence_metric_flags,
    _content_evidence_rule_ids_from_envelope,
    _l3_trace_has_content_evidence_signal,
    _snapshot_has_content_evidence_rule,
)
from .core.jsonrpc import JSONRPC_METHOD, JSONRPC_VERSION
from .core.approval_bridge import (
    _APPROVAL_ALLOWED_REASON_CODE,
    _APPROVAL_DENIED_REASON_CODE,
    _APPROVAL_NO_ROUTE_REASON_CODE,
    _APPROVAL_PENDING_REASON_CODE,
    _APPROVAL_QUEUE_FULL_REASON_CODE,
    _APPROVAL_TIMEOUT_REASON_CODE,
    _approval_binding_from_snapshot,
    _approval_pending_meta,
    _approval_prompt_context,
    _approval_prompt_event_fields,
    _approval_resolution_meta,
    _event_for_effect_resolution,
    _is_confirmation_fast_lane,
    _payload_hash,
    _redacted_preview,
    _resolve_confirmation_approval_id,
    _rewrite_effect_for_resolution,
    _validate_rewrite_resolution_payload,
)
from .core.supervision_gateway import (
    SupervisionGateway,
    configure_gateway_core_dependencies as _configure_gateway_core_dependencies,
)
from .http.app import (
    GatewayHttpHooks,
    _RateLimiter,
    _find_and_reload_pattern_matcher,
    _make_auth_dependency,
    _read_auth_token,
    create_http_app as _create_http_app,
)
from clawsentry.gateway.telemetry.event_bus import EventBus
from .first_use_skill_review import (
    FSPR_EVIDENCE_CAPSULE_SCHEMA_VERSION,
    FSPRLLMRoleProvider,
    run_agentic_readonly_fspr_review,
    run_first_use_skill_package_review,
)
from clawsentry.gateway.storage.idempotency import IdempotencyCache, periodic_cleanup
from clawsentry.gateway.llm.provider import InstrumentedProvider
from clawsentry.gateway.storage.session_registry import (
    DISPLAY_SCORE_RANGE,
    DISPLAY_SCORE_SEMANTICS,
    POST_ACTION_SCORE_SEMANTICS,
    SessionRegistry,
    build_compatibility_evidence_summary,
)
from clawsentry.gateway.storage.trajectory_store import (
    TrajectoryStore,
    _parse_iso_timestamp,
    DEFAULT_TRAJECTORY_DB_PATH,
    DEFAULT_TRAJECTORY_RETENTION_SECONDS,
    HIGH_RISK_LEVELS,
    MAX_WINDOW_SECONDS,
)
from .transport.uds import DEFAULT_UDS_PATH, _uds_client_handler, start_uds_server
from .transport.runner import _build_gateway_parser, _gateway_args_from_env, main, run_gateway
from .trust import fspr_bridge as _trust_fspr_bridge
from .trust import request as _trust_request
from .trust.registry_api import (
    _consume_expired_skill_trust_lifecycle_windows,
    _find_transition_event_by_idempotency_key,
    _read_skill_trust_registry_payload,
    _read_skill_trust_transition_sidecar,
    _registry_record_evidence_hashes,
    _skill_trust_registry_lock,
    _skill_trust_registry_snapshot_id,
    _skill_trust_transition_sidecar_path,
    _transition_event_id,
    _transition_idempotency_matches,
    _transition_request_evidence_refs,
    _transition_request_optional_str,
    _write_skill_trust_registry_payload,
    _write_skill_trust_transition_sidecar,
)
from clawsentry.gateway.models import (
    AgentAdvisoryFeedback,
    AgentSafetyFeedback,
    AdapterEffectResult,
    CanonicalDecision,
    CanonicalEvent,
    ContentEvidenceEnvelope,
    DecisionContext,
    DecisionEffects,
    DecisionSource,
    DecisionTier,
    DecisionVerdict,
    EventType,
    FailureClass,
    RiskLevel,
    RPCErrorCode,
    RPC_VERSION,
    SyncDecisionErrorResponse,
    SyncDecisionRequest,
    SyncDecisionResponse,
    SessionScopeBaseRules,
    SessionEffectRequest,
    SessionScopeProfile,
    SessionScopeTaskRules,
    adapter_effect_result_summary,
    decision_effect_summary,
    decision_effects_for_trajectory,
    utc_now_iso,
)

from clawsentry.gateway.policy.defer_manager import DeferManager
from clawsentry.gateway.config.detection_config import (
    DetectionConfig,
    build_detection_config_from_env,
    build_detection_config_with_preset,
)
from clawsentry.gateway.llm.factory import build_analyzer_from_env, build_provider_from_env
from .l3 import advisory_service as _l3_advisory_service
from .l3.advisory_service import (
    DEFAULT_L3_ADVISORY_RUNNER,
    PUBLIC_L3_ADVISORY_RUNNERS,
    _analyzer_supports_l3,
    _effective_requested_tier_for_l3_config,
    _validate_public_l3_advisory_runner,
)
from clawsentry.gateway.l3.runtime import build_l3_runtime_info
from clawsentry.gateway.rules.pattern_evolution import PatternEvolutionManager
from clawsentry.gateway.policy.engine import L1PolicyEngine
from clawsentry.gateway.analysis.post_action_analyzer import PostActionAnalyzer
from clawsentry.gateway.policy.session_scope import evaluate_session_scope, scope_protection_statement
from clawsentry.gateway.policy.tool_permissions import parse_tool_permission_group_overrides, resolve_tool_permission
from clawsentry.gateway.telemetry.metrics import LLMBudgetTracker, MetricsCollector
from clawsentry.gateway.analysis.trajectory_analyzer import TrajectoryAnalyzer
from clawsentry.gateway.policy.session_enforcement import (
    EnforcementAction,
    SessionEnforcementPolicy,
)
from clawsentry.gateway.trust.skill_trust import (
    AdmissionScanner,
    bind_runtime_skill_refs,
    derive_skill_trust_grade,
    load_skill_registry_records,
    load_skill_trust_runtime_metadata_bundle,
    record_with_skill_trust_grade,
    resolve_skill_trust,
)
from clawsentry.gateway.trust.lifecycle import apply_expired_lifecycle_windows, apply_lifecycle_transition
from clawsentry.gateway.models import LineageEvent, McpContext, RuntimeSkillRef, SkillRegistryRecord, SkillTrustContext
from .reporting.service import (
    _build_decision_path_io_pressure,
    _build_system_security_posture,
    _build_window_risk_summary,
    _compact_l3_evidence_summary,
    _copy_budget_event,
    _copy_l3_narrative_fields,
    _float_or_zero,
    _l3_trace_for_persistence,
    _new_io_metric_bucket,
    _observe_io_metric,
    _risk_velocity_from_scores,
    _snapshot_io_metric,
)
from clawsentry.gateway.enterprise import (
    build_enterprise_event_async,
    build_enterprise_live_snapshot_cached_async,
    enterprise_mode_enabled,
    enrich_alerts_payload_async,
    enrich_health_payload_async,
    enrich_replay_payload_async,
    enrich_session_risk_payload_async,
    enrich_sessions_payload_async,
    enrich_summary_payload_async,
)

logger = logging.getLogger("clawsentry")

_FSPR_REVIEW_CACHE: dict[str, Any] = _trust_fspr_bridge._FSPR_REVIEW_CACHE


_DEFAULT_UI_DIR = Path(__file__).parent.parent / "ui" / "dist"
DEFAULT_HTTP_HOST = "127.0.0.1"
DEFAULT_HTTP_PORT = 8080



def _trim_fspr_review_cache() -> None:
    _trust_fspr_bridge._trim_fspr_review_cache(_FSPR_REVIEW_CACHE)


_lineage_summary_from_event = _trust_request._lineage_summary_from_event
_lineage_event_from_summary = _trust_request._lineage_event_from_summary
_lineage_skill_trust_from_summary = _trust_request._lineage_skill_trust_from_summary
_lineage_decision_value = _trust_request._lineage_decision_value
_lineage_events_from_summary = _trust_request._lineage_events_from_summary
_blocked_skill_lineage_match_from_session = (
    _trust_request._blocked_skill_lineage_match_from_session
)
_context_with_blocked_skill_lineage_match = (
    _trust_request._context_with_blocked_skill_lineage_match
)
_context_with_prior_fspr_hard_block = _trust_request._context_with_prior_fspr_hard_block
_safe_lineage_value = _trust_request._safe_lineage_value
_is_sha256_digest = _trust_request._is_sha256_digest
_is_pathlike_label = _trust_request._is_pathlike_label
_safe_identity_label = _trust_request._safe_identity_label
_safe_skill_trust_raw_value = _trust_request._safe_skill_trust_raw_value
_redact_skill_trust_raw_from_event = _trust_request._redact_skill_trust_raw_from_event
_redacted_target_preview = _trust_request._redacted_target_preview
_safe_mcp_raw_value = _trust_request._safe_mcp_raw_value
_redact_mcp_raw_from_event = _trust_request._redact_mcp_raw_from_event
_context_with_mcp_raw = _trust_request._context_with_mcp_raw
_mcp_identity_from_event_tool = _trust_request._mcp_identity_from_event_tool
_downgrade_request_skill_trust = _trust_request._downgrade_request_skill_trust
_sanitize_request_skill_trust_raw = _trust_request._sanitize_request_skill_trust_raw


def _gateway_owned_skill_trust_bundle():
    return _trust_fspr_bridge._gateway_owned_skill_trust_bundle()


def _trusted_gateway_observed(
    meta: dict[str, Any],
    context: DecisionContext | None,
) -> dict[str, Any] | None:
    return _trust_fspr_bridge._trusted_gateway_observed(meta, context)


def _gateway_current_runner_contract_id(
    meta: dict[str, Any],
    context: DecisionContext | None,
) -> str | None:
    return _trust_fspr_bridge._gateway_current_runner_contract_id(meta, context)


def _gateway_observed_runtime_skill_refs(
    meta: dict[str, Any],
    context: DecisionContext | None,
    event: CanonicalEvent,
) -> list[RuntimeSkillRef]:
    return _trust_fspr_bridge._gateway_observed_runtime_skill_refs(meta, context, event)


def _gateway_owned_skill_trust_metadata(presented_name: Any) -> dict[str, Any]:
    return _trust_fspr_bridge._gateway_owned_skill_trust_metadata(presented_name)


def _apply_gateway_owned_first_use_scan(
    raw_metadata: dict[str, Any],
    *,
    deadline_at: float | None = None,
) -> None:
    _trust_fspr_bridge._apply_gateway_owned_first_use_scan(
        raw_metadata,
        deadline_at=deadline_at,
    )


def _fspr_timing_mode_for_event(
    event: CanonicalEvent,
    detection_config: DetectionConfig | None,
) -> str | None:
    return _trust_fspr_bridge._fspr_timing_mode_for_event(event, detection_config)


def _fspr_provider_sync_enabled(detection_config: DetectionConfig | None) -> bool:
    return _trust_fspr_bridge._fspr_provider_sync_enabled(detection_config)


_UnavailableFSPRProvider = _trust_fspr_bridge._UnavailableFSPRProvider


def _fspr_review_mode_for_config(
    detection_config: DetectionConfig | None,
) -> str:
    return _trust_fspr_bridge._fspr_review_mode_for_config(detection_config)


def _fspr_review_summary(
    *,
    detection_config: DetectionConfig | None,
    review_state: str,
    timing_mode: str | None = None,
    provider_used: bool = False,
    verdict: str | None = None,
    severity: str | None = None,
    confidence: float | None = None,
    degraded: bool | None = None,
    degradation_reason: str | None = None,
    failure_reason: str | None = None,
    reason: str | None = None,
) -> dict[str, object]:
    return _trust_fspr_bridge._fspr_review_summary(
        detection_config=detection_config,
        review_state=review_state,
        timing_mode=timing_mode,
        provider_used=provider_used,
        verdict=verdict,
        severity=severity,
        confidence=confidence,
        degraded=degraded,
        degradation_reason=degradation_reason,
        failure_reason=failure_reason,
        reason=reason,
    )


def _apply_gateway_owned_first_use_package_review(
    raw_metadata: dict[str, Any],
    *,
    event: CanonicalEvent,
    detection_config: DetectionConfig | None,
    deadline_at: float | None = None,
) -> None:
    _trust_fspr_bridge._apply_gateway_owned_first_use_package_review(
        raw_metadata,
        event=event,
        detection_config=detection_config,
        deadline_at=deadline_at,
        run_first_use_skill_package_review_fn=run_first_use_skill_package_review,
        run_agentic_readonly_fspr_review_fn=run_agentic_readonly_fspr_review,
        build_provider_from_env_fn=build_provider_from_env,
        fspr_llm_role_provider_cls=FSPRLLMRoleProvider,
        evidence_capsule_schema_version=FSPR_EVIDENCE_CAPSULE_SCHEMA_VERSION,
        review_cache=_FSPR_REVIEW_CACHE,
    )


def _context_with_skill_trust_raw(
    context: DecisionContext | None,
    event: CanonicalEvent,
    trusted_records: list[SkillRegistryRecord] | None = None,
    deadline_at: float | None = None,
    detection_config: DetectionConfig | None = None,
) -> DecisionContext | None:
    return _trust_request._context_with_skill_trust_raw(
        context,
        event,
        trusted_records,
        deadline_at,
        detection_config,
        gateway_owned_skill_trust_bundle_fn=_gateway_owned_skill_trust_bundle,
        gateway_observed_runtime_skill_refs_fn=_gateway_observed_runtime_skill_refs,
        gateway_current_runner_contract_id_fn=_gateway_current_runner_contract_id,
        gateway_owned_skill_trust_metadata_fn=_gateway_owned_skill_trust_metadata,
        apply_gateway_owned_first_use_scan_fn=_apply_gateway_owned_first_use_scan,
        apply_gateway_owned_first_use_package_review_fn=(
            _apply_gateway_owned_first_use_package_review
        ),
    )


_configure_gateway_core_dependencies(
    build_provider_from_env_fn=lambda: build_provider_from_env(),
    apply_gateway_owned_first_use_package_review_fn=(
        lambda *args, **kwargs: _apply_gateway_owned_first_use_package_review(
            *args,
            **kwargs,
        )
    ),
)


def create_http_app(gateway, *args, **kwargs):
    hooks = kwargs.pop(
        "hooks",
        GatewayHttpHooks(
            apply_lifecycle_transition=(
                lambda *a, **kw: apply_lifecycle_transition(*a, **kw)
            ),
        ),
    )
    return _create_http_app(gateway, *args, hooks=hooks, **kwargs)


def _request_skill_trust_metadata(skill_trust: SkillTrustContext) -> dict[str, Any]:
    """Extract runtime-observation fields from request context trust data."""

    payload: dict[str, Any] = {}
    if skill_trust.presented_name:
        payload["presented_name"] = skill_trust.presented_name
    elif skill_trust.canonical_skill_id:
        payload["presented_name"] = skill_trust.canonical_skill_id
    if skill_trust.provenance_claim:
        payload["provenance_claim"] = skill_trust.provenance_claim
    return payload




# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------





# TrajectoryStore, SessionRegistry, EventBus, AlertRegistry are in separate modules.
# Imported above from .trajectory_store, .session_registry, .event_bus, .alert_registry

# ---------------------------------------------------------------------------
# Gateway Core
# ---------------------------------------------------------------------------



# ---------------------------------------------------------------------------
# HTTP Transport (FastAPI)
# ---------------------------------------------------------------------------







# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------









if __name__ == "__main__":
    main()
