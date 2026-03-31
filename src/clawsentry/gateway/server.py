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
from datetime import datetime, timezone
import hmac
import json
import argparse
import logging
import os
import struct
import time
from typing import Any, Callable, Optional

from pathlib import Path
import uuid
import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse
from starlette.responses import FileResponse, HTMLResponse
from pydantic import ValidationError

from .alert_registry import AlertRegistry
from .event_bus import EventBus
from .idempotency import IdempotencyCache, periodic_cleanup
from .session_registry import SessionRegistry
from .trajectory_store import (
    TrajectoryStore,
    _parse_iso_timestamp,
    DEFAULT_TRAJECTORY_DB_PATH,
    DEFAULT_TRAJECTORY_RETENTION_SECONDS,
    HIGH_RISK_LEVELS,
    MAX_WINDOW_SECONDS,
)
from .models import (
    CanonicalDecision,
    CanonicalEvent,
    DecisionContext,
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
    utc_now_iso,
)
from .defer_manager import DeferManager
from .detection_config import (
    DetectionConfig,
    build_detection_config_from_env,
    build_detection_config_with_preset,
)
from .llm_factory import build_analyzer_from_env
from .pattern_evolution import PatternEvolutionManager
from .policy_engine import L1PolicyEngine
from .post_action_analyzer import PostActionAnalyzer
from .metrics import LLMBudgetTracker, MetricsCollector
from .trajectory_analyzer import TrajectoryAnalyzer
from .session_enforcement import (
    EnforcementAction,
    SessionEnforcementPolicy,
)

logger = logging.getLogger("clawsentry")

_DEFAULT_UI_DIR = Path(__file__).parent.parent / "ui" / "dist"

# ---------------------------------------------------------------------------
# Shared risk-level helpers
# ---------------------------------------------------------------------------

_RISK_LEVEL_RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}

def _risk_rank(risk_level: Optional[str]) -> int:
    return _RISK_LEVEL_RANK.get(str(risk_level or "low").lower(), 0)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_UDS_PATH = "/tmp/clawsentry.sock"
DEFAULT_HTTP_HOST = "127.0.0.1"
DEFAULT_HTTP_PORT = 8080

JSONRPC_METHOD = "ahp/sync_decision"
JSONRPC_VERSION = "2.0"


def _extract_project_config(
    payload: Optional[dict[str, Any]],
) -> tuple[Optional[str], dict[str, Any]]:
    """Extract project preset/overrides from event payload metadata.

    Returns ``(preset_name, overrides)`` where *preset_name* is ``None``
    when no project preset is specified.
    """
    if not payload or not isinstance(payload, dict):
        return None, {}
    meta = payload.get("_clawsentry_meta")
    if not isinstance(meta, dict):
        return None, {}
    preset = meta.get("project_preset")
    overrides = meta.get("project_overrides", {})
    if not isinstance(overrides, dict):
        overrides = {}
    return preset, overrides

# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

def _read_auth_token() -> str:
    """Read auth token from environment. Empty string means auth disabled."""
    return os.getenv("CS_AUTH_TOKEN", "")


def _make_auth_dependency(auth_token: str):
    """Create a FastAPI dependency that enforces Bearer token auth.

    When auth_token is empty, returns a no-op dependency (auth disabled).
    """
    if not auth_token:
        async def _no_auth(request: Request):  # noqa: ARG001
            pass
        return _no_auth

    async def _require_bearer(request: Request):
        # 1. Try Authorization: Bearer header first
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]  # len("Bearer ") == 7
            if hmac.compare_digest(token, auth_token):
                return None  # Authorized via header

        # 2. Fallback: try ?token= query param (for browser EventSource)
        query_token = request.query_params.get("token", "")
        if query_token and hmac.compare_digest(query_token, auth_token):
            return None  # Authorized via query param

        # 3. Both methods failed — reject
        return Response(
            content=json.dumps({"error": "Unauthorized"}),
            status_code=401,
            media_type="application/json",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return _require_bearer


# TrajectoryStore, SessionRegistry, EventBus, AlertRegistry are in separate modules.
# Imported above from .trajectory_store, .session_registry, .event_bus, .alert_registry

# ---------------------------------------------------------------------------
# Gateway Core
# ---------------------------------------------------------------------------

class SupervisionGateway:
    """
    Core gateway logic shared between UDS and HTTP transports.

    Handles JSON-RPC 2.0 dispatch, SyncDecision v1 processing,
    idempotency, and trajectory recording.
    """

    def __init__(
        self,
        trajectory_db_path: Optional[str] = None,
        trajectory_retention_seconds: int = DEFAULT_TRAJECTORY_RETENTION_SECONDS,
        analyzer=None,
        session_enforcement: Optional[SessionEnforcementPolicy] = None,
        detection_config: Optional[DetectionConfig] = None,
    ) -> None:
        self._detection_config = detection_config if detection_config is not None else DetectionConfig()
        self.policy_engine = L1PolicyEngine(analyzer=analyzer, config=self._detection_config)
        self.idempotency_cache = IdempotencyCache()
        effective_db_path = trajectory_db_path
        if effective_db_path is None:
            effective_db_path = os.getenv("CS_TRAJECTORY_DB_PATH", ":memory:")
        self.trajectory_store = TrajectoryStore(
            db_path=effective_db_path,
            retention_seconds=trajectory_retention_seconds,
        )
        self.session_registry = SessionRegistry()
        self.event_bus = EventBus()
        self.alert_registry = AlertRegistry()
        self.session_enforcement = session_enforcement or SessionEnforcementPolicy()
        self.post_action_analyzer = PostActionAnalyzer(
            whitelist_patterns=self._detection_config.post_action_whitelist,
            tier_emergency=self._detection_config.post_action_emergency,
            tier_escalate=self._detection_config.post_action_escalate,
            tier_monitor=self._detection_config.post_action_monitor,
        )
        self.trajectory_analyzer = TrajectoryAnalyzer(
            max_events_per_session=self._detection_config.trajectory_max_events,
            max_sessions=self._detection_config.trajectory_max_sessions,
        )
        # E-9: DEFER timeout manager
        self.defer_manager = DeferManager(
            timeout_action=self._detection_config.defer_timeout_action,
            timeout_s=self._detection_config.defer_timeout_s,
            max_pending=self._detection_config.defer_max_pending,
        )
        # E-5: Self-evolving pattern repository
        self.evolution_manager = PatternEvolutionManager(
            store_path=self._detection_config.evolved_patterns_path or "",
            enabled=self._detection_config.evolving_enabled,
        )
        # P3: Prometheus metrics collector
        _metrics_enabled = os.getenv("CS_METRICS_ENABLED", "true").lower() not in ("0", "false", "no")
        self.metrics = MetricsCollector(enabled=_metrics_enabled)
        # P3: LLM daily budget tracker
        self.budget_tracker = LLMBudgetTracker(
            daily_budget_usd=self._detection_config.llm_daily_budget_usd,
        )
        self._start_time = time.monotonic()
        self._ready = True

    async def handle_jsonrpc(self, raw_body: bytes) -> dict[str, Any]:
        """
        Process a JSON-RPC 2.0 request and return a JSON-RPC response dict.
        """
        try:
            body = json.loads(raw_body)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            return self._jsonrpc_error(None, -32700, f"Parse error: {e}")

        # Validate JSON-RPC envelope
        if not isinstance(body, dict):
            return self._jsonrpc_error(None, -32600, "Invalid request: not an object")

        jsonrpc_version = body.get("jsonrpc")
        if jsonrpc_version != JSONRPC_VERSION:
            return self._jsonrpc_error(
                body.get("id"), -32600,
                f"Invalid jsonrpc version: expected '{JSONRPC_VERSION}', got '{jsonrpc_version}'",
            )

        method = body.get("method")
        rpc_id = body.get("id")
        params = body.get("params", {})

        if method != JSONRPC_METHOD:
            return self._jsonrpc_error(
                rpc_id, -32601,
                f"Method not found: '{method}'. Expected '{JSONRPC_METHOD}'",
            )

        return await self._handle_sync_decision(rpc_id, params)

    async def _run_post_action_async(
        self,
        output_text: str,
        tool_name: str,
        event_id: str,
        session_id: str,
        source_framework: str | None,
        content_origin: str | None,
        external_multiplier: float,
        occurred_at: str,
    ) -> None:
        """Run post-action analysis in background, broadcast finding if needed."""
        try:
            loop = asyncio.get_running_loop()
            finding = await loop.run_in_executor(
                None,
                lambda: self.post_action_analyzer.analyze(
                    tool_output=output_text,
                    tool_name=tool_name,
                    event_id=event_id,
                    content_origin=content_origin,
                    external_multiplier=external_multiplier,
                ),
            )
            if finding.tier.value != "log_only":
                self.event_bus.broadcast({
                    "type": "post_action_finding",
                    "event_id": event_id,
                    "session_id": session_id,
                    "source_framework": source_framework,
                    "tier": finding.tier.value,
                    "patterns_matched": finding.patterns_matched,
                    "score": finding.score,
                    "timestamp": occurred_at,
                })
        except Exception:
            logger.exception("post-action analysis failed for event %s", event_id)

    async def _handle_sync_decision(
        self, rpc_id: Any, params: dict[str, Any]
    ) -> dict[str, Any]:
        """Process a SyncDecision v1 request."""
        request_id = params.get("request_id", "")

        # ENGINE_UNAVAILABLE when gateway is not ready
        if not self._ready:
            error_resp = SyncDecisionErrorResponse(
                request_id=request_id or "unknown",
                rpc_error_code=RPCErrorCode.ENGINE_UNAVAILABLE,
                rpc_error_message="Gateway is starting up",
                retry_eligible=True,
                retry_after_ms=500,
            )
            return self._jsonrpc_error_with_data(rpc_id, -32603, error_resp)

        # Check idempotency cache
        cached = self.idempotency_cache.get(request_id)
        if cached is not None:
            return self._jsonrpc_success(rpc_id, cached)

        # Validate request
        try:
            req = SyncDecisionRequest(**params)
        except ValidationError as e:
            error_resp = SyncDecisionErrorResponse(
                request_id=request_id or "unknown",
                rpc_error_code=RPCErrorCode.INVALID_REQUEST,
                rpc_error_message=f"Request validation failed: {e.error_count()} error(s)",
                retry_eligible=False,
            )
            return self._jsonrpc_error_with_data(rpc_id, -32602, error_resp)

        # Check rpc_version
        if req.rpc_version != RPC_VERSION:
            error_resp = SyncDecisionErrorResponse(
                request_id=req.request_id,
                rpc_error_code=RPCErrorCode.VERSION_NOT_SUPPORTED,
                rpc_error_message=f"Unsupported rpc_version: '{req.rpc_version}'",
                retry_eligible=False,
            )
            return self._jsonrpc_error_with_data(rpc_id, -32602, error_resp)

        # Check deadline
        start = time.monotonic()
        deadline_at = start + req.deadline_ms / 1000.0

        # --- Project preset config (from .clawsentry.toml via harness) ---
        _preset_name, _preset_overrides = _extract_project_config(
            req.event.payload
        )
        project_config: Optional[DetectionConfig] = None
        if _preset_name:
            project_config = build_detection_config_with_preset(
                _preset_name, _preset_overrides,
            )

        # --- E-8: Record tool call for D4 frequency analysis ---
        if req.event.tool_name:
            self.policy_engine.session_tracker.record_tool_call(
                str(req.event.session_id or ""), req.event.tool_name
            )

        # --- A-7: Session enforcement check (before policy_engine) ---
        enforcement = self.session_enforcement.check(
            str(req.event.session_id or "")
        )
        enforcement_applied = False
        if (
            enforcement is not None
            and req.event.event_type == EventType.PRE_ACTION
        ):
            decision = self._make_enforcement_decision(enforcement, req.event)
            # Still need a snapshot for recording — run L1 but override decision
            try:
                remaining_ms = max(0, (deadline_at - time.monotonic()) * 1000)
                _, snapshot, _ = self.policy_engine.evaluate(
                    req.event, req.context, req.decision_tier,
                    deadline_budget_ms=remaining_ms,
                    config=project_config,
                )
            except Exception:
                logger.exception("Policy engine error during enforcement snapshot")
                from .policy_engine import RiskSnapshot
                snapshot = RiskSnapshot()
            actual_tier = DecisionTier.L1
            enforcement_applied = True
        else:
            # --- P3: LLM budget check — force L1 if exhausted ---
            requested_tier = req.decision_tier
            budget_exhausted = not self.budget_tracker.can_spend()
            if budget_exhausted:
                requested_tier = DecisionTier.L1

            # Evaluate normally
            try:
                remaining_ms = max(0, (deadline_at - time.monotonic()) * 1000)
                decision, snapshot, actual_tier = self.policy_engine.evaluate(
                    req.event, req.context, requested_tier,
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
                return self._jsonrpc_error_with_data(rpc_id, -32603, error_resp)

            # Annotate decision when budget forced L1-only downgrade
            if budget_exhausted and req.decision_tier != DecisionTier.L1:
                decision = decision.model_copy(update={
                    "reason": decision.reason + " [LLM budget exhausted, L1-only]"
                })

        # --- CS-012: Record decision BEFORE deadline check ---
        # Recording must happen unconditionally so that even deadline-exceeded
        # decisions are persisted to trajectory_store and session_registry.
        event_dict = req.event.model_dump(mode="json")
        decision_dict = decision.model_dump(mode="json")
        snapshot_dict = snapshot.model_dump(mode="json")
        meta_dict = {
            "request_id": req.request_id,
            "actual_tier": actual_tier.value,
            "deadline_ms": req.deadline_ms,
            "caller_adapter": (
                req.context.caller_adapter
                if req.context and req.context.caller_adapter
                else "unknown"
            ),
        }
        _sid = str(event_dict.get("session_id") or "")
        previous_risk_level = self.session_registry.get_current_risk(_sid)
        l3_trace = snapshot.l3_trace
        self.trajectory_store.record(
            event=event_dict,
            decision=decision_dict,
            snapshot=snapshot_dict,
            meta=meta_dict,
            l3_trace=l3_trace,
        )
        self.session_registry.record(
            event=event_dict,
            decision=decision_dict,
            snapshot=snapshot_dict,
            meta=meta_dict,
        )

        # --- E-4 Phase 2: Trajectory analysis ---
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
            traj_matches = self.trajectory_analyzer.record(traj_event)
            for tm in traj_matches:
                self.event_bus.broadcast({
                    "type": "trajectory_alert",
                    "session_id": _sid,
                    "sequence_id": tm.sequence_id,
                    "risk_level": tm.risk_level,
                    "matched_event_ids": tm.matched_event_ids,
                    "reason": tm.reason,
                    "timestamp": str(event_dict.get("occurred_at") or utc_now_iso()),
                })
        except Exception:
            logger.exception("trajectory analysis failed for event %s", req.event.event_id)

        # --- A-7: Check if threshold is newly breached ---
        session_id = str(event_dict.get("session_id") or "")
        if session_id and self.session_enforcement.enabled:
            stats = self.session_registry.get_session_stats(session_id)
            new_enf = self.session_enforcement.evaluate_threshold(
                session_id, stats.get("high_risk_event_count", 0)
            )
            if new_enf:
                self.event_bus.broadcast(
                    {
                        "type": "session_enforcement_change",
                        "session_id": session_id,
                        "state": "enforced",
                        "action": new_enf.action.value,
                        "high_risk_count": new_enf.high_risk_count,
                        "timestamp": str(event_dict.get("occurred_at") or utc_now_iso()),
                    }
                )

        # --- CS-013/CS-016: SSE broadcasts BEFORE deadline check ---
        # Event broadcasts must happen unconditionally so that watch CLI and
        # /report/stream subscribers always receive events, even when the
        # request exceeds its deadline.
        current_risk_level = str(snapshot_dict.get("risk_level") or decision_dict.get("risk_level") or "low")
        occurred_at = str(event_dict.get("occurred_at") or utc_now_iso())

        if previous_risk_level is None and session_id:
            self.event_bus.broadcast(
                {
                    "type": "session_start",
                    "session_id": session_id,
                    "agent_id": str(event_dict.get("agent_id") or "unknown"),
                    "source_framework": str(event_dict.get("source_framework") or "unknown"),
                    "timestamp": occurred_at,
                }
            )
            self.metrics.session_started()

        # --- P3: Record metrics ---
        _latency_s = time.monotonic() - start
        _source_fw = str(event_dict.get("source_framework") or "unknown")
        _risk_score_val = float(snapshot_dict.get("composite_score") or 0.0)
        self.metrics.record_decision(
            verdict=str(decision_dict.get("decision") or "unknown"),
            risk_level=current_risk_level,
            risk_score=_risk_score_val,
            tier=actual_tier.value,
            source_framework=_source_fw,
            latency_s=_latency_s,
        )

        self.event_bus.broadcast(
            {
                "type": "decision",
                "session_id": session_id,
                "event_id": str(event_dict.get("event_id") or "unknown"),
                "risk_level": current_risk_level,
                "decision": str(decision_dict.get("decision") or "unknown"),
                "tool_name": event_dict.get("tool_name"),
                "actual_tier": actual_tier.value,
                "timestamp": occurred_at,
                "reason": str(decision_dict.get("reason") or ""),
                "command": str(
                    event_dict.get("payload", {}).get("command", "")
                    or event_dict.get("tool_name", "")
                ),
                "approval_id": event_dict.get("approval_id"),
                "expires_at": event_dict.get("payload", {}).get("expiresAtMs"),
            }
        )

        if (
            previous_risk_level is not None
            and _risk_rank(current_risk_level) > _risk_rank(previous_risk_level)
        ):
            self.event_bus.broadcast(
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
            session_data = self.session_registry.get_session_stats(session_id)
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
            self.alert_registry.add(alert)
            self.event_bus.broadcast(
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
            output_text = str(
                req.event.payload.get("output", "")
                or req.event.payload.get("result", "")
                or ""
            )
            if output_text:
                _pa_meta = (req.event.payload or {}).get("_clawsentry_meta") or {}
                _pa_origin = _pa_meta.get("content_origin") if isinstance(_pa_meta, dict) else None
                asyncio.create_task(self._run_post_action_async(
                    output_text=output_text,
                    tool_name=req.event.tool_name or "unknown",
                    event_id=req.event.event_id,
                    session_id=session_id,
                    source_framework=req.event.source_framework,
                    content_origin=_pa_origin,
                    external_multiplier=(project_config or self._detection_config).external_content_post_action_multiplier,
                    occurred_at=occurred_at,
                ))

        # --- E-5: Extract candidate pattern from confirmed high-risk events ---
        if (
            self.evolution_manager.enabled
            and req.event.event_type == EventType.PRE_ACTION
            and decision.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        ):
            try:
                self.evolution_manager.extract_candidate(
                    event_id=req.event.event_id,
                    session_id=str(req.event.session_id or ""),
                    tool_name=req.event.tool_name or "",
                    command=str(req.event.payload.get("command", "")) if req.event.payload else "",
                    risk_level=decision.risk_level,
                    source_framework=req.event.source_framework or "",
                    reasons=decision.reason.split("; ") if decision.reason else [],
                )
            except Exception:
                logger.warning("evolved pattern extraction failed", exc_info=True)

        # --- P1: DEFER bridge — wait for operator approval ---
        if (
            self._detection_config.defer_bridge_enabled
            and (project_config is None or project_config.defer_bridge_enabled)
            and decision.decision == DecisionVerdict.DEFER
            and req.event.event_type == EventType.PRE_ACTION
            and not enforcement_applied
        ):
            defer_id = f"cs-defer-{uuid.uuid4().hex[:12]}"
            if not self.defer_manager.register_defer(defer_id):
                # Queue full — fall back to block
                decision = CanonicalDecision(
                    decision=DecisionVerdict.BLOCK,
                    reason=f"DEFER queue full ({self.defer_manager.max_pending}), blocking",
                    policy_id="defer-bridge",
                    risk_level=decision.risk_level,
                    decision_source=DecisionSource.POLICY,
                    final=True,
                )
                decision_dict = decision.model_dump(mode="json")
            else:
                self.metrics.defer_registered()

                # Broadcast defer_pending event
                _defer_timeout = (project_config or self._detection_config).defer_timeout_s
                self.event_bus.broadcast({
                    "type": "defer_pending",
                    "session_id": session_id,
                    "approval_id": defer_id,
                    "tool_name": req.event.tool_name or "",
                    "command": str(req.event.payload.get("command", "") if req.event.payload else ""),
                    "reason": str(decision_dict.get("reason") or ""),
                    "timeout_s": _defer_timeout,
                    "timestamp": occurred_at,
                })

                # Wait for operator resolution
                _resolved_decision, _resolved_reason = await self.defer_manager.wait_for_resolution(defer_id)

                # Convert to final CanonicalDecision
                if _resolved_decision in ("allow", "allow-once"):
                    decision = CanonicalDecision(
                        decision=DecisionVerdict.ALLOW,
                        reason=f"Operator approved: {_resolved_reason}" if _resolved_reason else "Operator approved",
                        policy_id="defer-bridge",
                        risk_level=decision.risk_level,
                        decision_source=DecisionSource.OPERATOR,
                        final=True,
                    )
                else:
                    decision = CanonicalDecision(
                        decision=DecisionVerdict.BLOCK,
                        reason=f"Operator denied: {_resolved_reason}" if _resolved_reason else "Operator denied",
                        policy_id="defer-bridge",
                        risk_level=decision.risk_level,
                        decision_source=DecisionSource.OPERATOR,
                        final=True,
                    )

                # Update dict for response
                decision_dict = decision.model_dump(mode="json")

                self.metrics.defer_resolved()

                # Broadcast defer_resolved event
                self.event_bus.broadcast({
                    "type": "defer_resolved",
                    "session_id": session_id,
                    "approval_id": defer_id,
                    "resolved_decision": decision_dict["decision"],
                    "resolved_reason": decision_dict["reason"],
                    "timestamp": utc_now_iso(),
                })

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
            return self._jsonrpc_error_with_data(rpc_id, -32604, error_resp)

        # Build success response
        resp = SyncDecisionResponse(
            request_id=req.request_id,
            decision=decision,
            actual_tier=actual_tier,
            served_at=utc_now_iso(),
        )
        resp_dict = resp.model_dump(mode="json")

        # Cache response
        self.idempotency_cache.put(req.request_id, resp_dict, req.deadline_ms)

        return self._jsonrpc_success(rpc_id, resp_dict)

    def _make_enforcement_decision(
        self, enforcement, event: CanonicalEvent,
    ) -> CanonicalDecision:
        """Build a decision that overrides normal evaluation due to A-7 enforcement."""
        if enforcement.action == EnforcementAction.BLOCK:
            verdict = DecisionVerdict.BLOCK
            policy_id = "session-enforcement-A7"
            reason = (
                f"Session enforcement: BLOCK after {enforcement.high_risk_count} "
                f"high-risk events (threshold reached)"
            )
        elif enforcement.action == EnforcementAction.L3_REQUIRE:
            verdict = DecisionVerdict.DEFER
            policy_id = "session-enforcement-A7-L3"
            reason = (
                f"Session enforcement: L3 review required after "
                f"{enforcement.high_risk_count} high-risk events"
            )
        else:
            # DEFER (default)
            verdict = DecisionVerdict.DEFER
            policy_id = "session-enforcement-A7"
            reason = (
                f"Session enforcement: DEFER after {enforcement.high_risk_count} "
                f"high-risk events (threshold reached)"
            )
        return CanonicalDecision(
            decision=verdict,
            reason=reason,
            policy_id=policy_id,
            risk_level=RiskLevel.HIGH,
            decision_source=DecisionSource.POLICY,
            policy_version="A7",
            failure_class=FailureClass.NONE,
            final=True,
        )

    def health(self) -> dict[str, Any]:
        """Return gateway health status."""
        uptime = time.monotonic() - self._start_time
        return {
            "status": "healthy",
            "uptime_seconds": round(uptime, 1),
            "cache_size": self.idempotency_cache.size(),
            "trajectory_count": self.trajectory_store.count(),
            "trajectory_backend": "sqlite",
            "policy_engine": "L1+L2",
            "rpc_version": RPC_VERSION,
            "auth_enabled": bool(os.getenv("CS_AUTH_TOKEN")),
        }

    def report_summary(self, window_seconds: Optional[int] = None) -> dict[str, Any]:
        """Return cross-framework summary metrics from trajectory records."""
        since_seconds = window_seconds if window_seconds and window_seconds > 0 else None
        summary = self.trajectory_store.summary(since_seconds=since_seconds)
        summary["generated_at"] = utc_now_iso()
        summary["window_seconds"] = since_seconds
        return summary

    def replay_session(
        self,
        session_id: str,
        limit: int = 100,
        window_seconds: Optional[int] = None,
    ) -> dict[str, Any]:
        """Return timeline records for a session (most recent first by append order)."""
        since_seconds = window_seconds if window_seconds and window_seconds > 0 else None
        records = self.trajectory_store.replay_session(
            session_id=session_id,
            limit=limit,
            since_seconds=since_seconds,
        )
        return {
            "session_id": session_id,
            "record_count": len(records),
            "records": records,
            "generated_at": utc_now_iso(),
            "window_seconds": since_seconds,
        }

    def report_sessions(
        self,
        *,
        status: str = "active",
        sort: str = "risk_level",
        limit: int = 50,
        min_risk: Optional[str] = None,
        window_seconds: Optional[int] = None,
    ) -> dict[str, Any]:
        since_seconds = window_seconds if window_seconds and window_seconds > 0 else None
        effective_limit = min(max(limit, 1), 200)
        result = self.session_registry.list_sessions(
            status=status,
            sort=sort,
            min_risk=min_risk,
            limit=effective_limit,
            since_seconds=since_seconds,
        )
        result["generated_at"] = utc_now_iso()
        result["window_seconds"] = since_seconds
        return result

    def report_session_risk(
        self,
        session_id: str,
        *,
        limit: int = 100,
        window_seconds: Optional[int] = None,
    ) -> dict[str, Any]:
        since_seconds = window_seconds if window_seconds and window_seconds > 0 else None
        effective_limit = min(max(limit, 1), 1000)
        result = self.session_registry.get_session_risk(
            session_id,
            limit=effective_limit,
            since_seconds=since_seconds,
        )
        result["generated_at"] = utc_now_iso()
        result["window_seconds"] = since_seconds
        return result

    def report_alerts(
        self,
        *,
        severity: Optional[str] = None,
        acknowledged: Optional[bool] = None,
        window_seconds: Optional[int] = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        since_seconds = window_seconds if window_seconds and window_seconds > 0 else None
        effective_limit = min(max(limit, 1), 1000)
        result = self.alert_registry.list_alerts(
            severity=severity,
            acknowledged=acknowledged,
            since_seconds=since_seconds,
            limit=effective_limit,
        )
        result["generated_at"] = utc_now_iso()
        result["window_seconds"] = since_seconds
        return result

    def acknowledge_alert(
        self,
        alert_id: str,
        acknowledged_by: str,
    ) -> Optional[dict[str, Any]]:
        return self.alert_registry.acknowledge(alert_id, acknowledged_by)

    # --- JSON-RPC helpers ---

    @staticmethod
    def _jsonrpc_success(rpc_id: Any, result: Any) -> dict[str, Any]:
        return {"jsonrpc": JSONRPC_VERSION, "id": rpc_id, "result": result}

    @staticmethod
    def _jsonrpc_error(
        rpc_id: Any, code: int, message: str, data: Any = None,
    ) -> dict[str, Any]:
        error: dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            error["data"] = data
        return {"jsonrpc": JSONRPC_VERSION, "id": rpc_id, "error": error}

    @staticmethod
    def _jsonrpc_error_with_data(
        rpc_id: Any, code: int, error_resp: SyncDecisionErrorResponse,
    ) -> dict[str, Any]:
        return SupervisionGateway._jsonrpc_error(
            rpc_id, code,
            error_resp.rpc_error_message,
            error_resp.model_dump(mode="json"),
        )


# ---------------------------------------------------------------------------
# HTTP Transport (FastAPI)
# ---------------------------------------------------------------------------

class _RateLimiter:
    """Simple sliding-window rate limiter per client identifier."""

    _MAX_CLIENTS = 10_000  # Prevent unbounded memory growth

    def __init__(self, max_requests: int, window_seconds: float):
        self._max = max_requests
        self._window = window_seconds
        self._buckets: dict[str, list[float]] = {}

    def check(self, client_id: str) -> bool:
        """Return True if allowed, False if rate limited."""
        now = time.monotonic()
        bucket = self._buckets.setdefault(client_id, [])
        bucket[:] = [t for t in bucket if now - t < self._window]
        if len(bucket) >= self._max:
            return False
        bucket.append(now)
        # Evict stale clients to prevent unbounded growth
        if len(self._buckets) > self._MAX_CLIENTS:
            oldest_key = next(iter(self._buckets))
            del self._buckets[oldest_key]
        return True


def _find_and_reload_pattern_matcher(analyzer) -> bool:
    """Traverse analyzer hierarchy to find and reload PatternMatcher.

    Works with both RuleBasedAnalyzer (direct _pattern_matcher) and
    CompositeAnalyzer (nested _analyzers list).
    """
    if hasattr(analyzer, '_pattern_matcher'):
        analyzer._pattern_matcher.reload()
        return True
    if hasattr(analyzer, '_analyzers'):
        for a in analyzer._analyzers:
            if hasattr(a, '_pattern_matcher'):
                a._pattern_matcher.reload()
                return True
    return False


def create_http_app(
    gateway: SupervisionGateway,
    *,
    ui_dir: Path | None = None,
) -> FastAPI:
    """Create FastAPI application for the HTTP transport."""
    app = FastAPI(title="AHP Supervision Gateway", version="1.0")

    auth_token = _read_auth_token()
    if not auth_token:
        logger.warning(
            "CS_AUTH_TOKEN not set — HTTP endpoints are UNAUTHENTICATED. "
            "Set CS_AUTH_TOKEN for production deployments."
        )
    elif len(auth_token) < 32:
        logger.warning(
            "CS_AUTH_TOKEN is shorter than 32 chars — "
            "consider using a stronger token for production."
        )

    verify_auth = _make_auth_dependency(auth_token)

    # Rate limiter (0 = disabled)
    rate_limit_per_min = int(os.getenv("CS_RATE_LIMIT_PER_MINUTE", "300"))
    rate_limiter: _RateLimiter | None = None
    if rate_limit_per_min > 0:
        rate_limiter = _RateLimiter(max_requests=rate_limit_per_min, window_seconds=60.0)

    def _check_rate_limit(request: Request) -> Response | None:
        if rate_limiter is None:
            return None
        client_ip = request.client.host if request.client else "unknown"
        if not rate_limiter.check(client_ip):
            error_resp = SyncDecisionErrorResponse(
                request_id="rate-limited",
                rpc_error_code=RPCErrorCode.RATE_LIMITED,
                rpc_error_message="Rate limit exceeded",
                retry_eligible=True,
                retry_after_ms=1000,
            )
            return Response(
                content=json.dumps(error_resp.model_dump()),
                status_code=429,
                media_type="application/json",
            )
        return None

    @app.post("/ahp")
    async def ahp_endpoint(request: Request):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        rl_result = _check_rate_limit(request)
        if rl_result is not None:
            return rl_result
        body = await request.body()
        if len(body) > 10 * 1024 * 1024:
            return Response(
                content=json.dumps({"error": "Payload too large"}),
                status_code=413,
                media_type="application/json",
            )
        result = await gateway.handle_jsonrpc(body)
        return Response(
            content=json.dumps(result),
            media_type="application/json",
        )

    # --- a3s-code HTTP transport (B-1) ---
    from ..adapters.a3s_adapter import InProcessA3SAdapter
    from ..adapters.a3s_gateway_harness import A3SGatewayHarness

    _a3s_adapter = InProcessA3SAdapter(gateway)
    _a3s_harness = A3SGatewayHarness(_a3s_adapter)

    @app.post("/ahp/a3s")
    async def ahp_a3s_endpoint(request: Request):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        rl_result = _check_rate_limit(request)
        if rl_result is not None:
            return rl_result
        try:
            body = await request.json()
        except Exception:
            return Response(
                content=json.dumps({"error": "invalid JSON body"}),
                status_code=400,
                media_type="application/json",
            )
        response = await _a3s_harness.dispatch_async(body)
        if response is None:
            return Response(status_code=204)
        return response

    # --- Codex HTTP transport (E-9 Phase 2) ---
    from ..adapters.codex_adapter import CodexAdapter
    _codex_adapter = CodexAdapter()
    _codex_in_process = InProcessA3SAdapter(gateway)

    @app.post("/ahp/codex")
    async def ahp_codex_endpoint(request: Request):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        rl_result = _check_rate_limit(request)
        if rl_result is not None:
            return rl_result
        try:
            body = await request.json()
        except Exception:
            return Response(
                content=json.dumps({"error": "invalid JSON body"}),
                status_code=400,
                media_type="application/json",
            )

        event = _codex_adapter.normalize_hook_event(
            hook_type=body.get("event_type", ""),
            payload=body.get("payload", {}),
            session_id=body.get("session_id"),
            agent_id=body.get("agent_id"),
        )
        if event is None:
            return {"result": {"action": "continue", "reason": "unrecognized event type"}}

        # Route through in-process Gateway evaluation
        try:
            decision = await _codex_in_process.request_decision(event)
            return {"result": {
                "action": decision.decision.value,
                "reason": decision.reason,
                "risk_level": decision.risk_level.value,
            }}
        except Exception:
            logger.exception("Codex endpoint evaluation failed")
            # Fail-closed: block on evaluation error to prevent unsafe operations
            return {"result": {"action": "block", "reason": "evaluation error (fail-closed)"}}

    @app.get("/health")
    async def health_endpoint():
        return gateway.health()

    # --- P3: Prometheus /metrics endpoint ---
    _metrics_auth_enabled = os.getenv("CS_METRICS_AUTH", "").lower() in ("1", "true", "yes")

    @app.get("/metrics")
    async def metrics_endpoint(request: Request):
        if _metrics_auth_enabled:
            auth_result = await verify_auth(request)
            if isinstance(auth_result, Response):
                return auth_result
        data = gateway.metrics.generate_metrics_text()
        return Response(
            content=data,
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    @app.get("/report/summary")
    async def report_summary_endpoint(request: Request, window_seconds: Optional[int] = None):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if window_seconds is not None and (window_seconds < 1 or window_seconds > MAX_WINDOW_SECONDS):
            return Response(
                content=json.dumps({"error": f"window_seconds must be between 1 and {MAX_WINDOW_SECONDS}"}),
                status_code=400,
                media_type="application/json",
            )
        return gateway.report_summary(window_seconds=window_seconds)

    @app.get("/report/stream")
    async def report_stream_endpoint(
        request: Request,
        session_id: Optional[str] = None,
        min_risk: Optional[str] = None,
        types: Optional[str] = None,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if min_risk is not None and min_risk not in {"low", "medium", "high", "critical"}:
            return Response(
                content=json.dumps({"error": "min_risk must be one of: low, medium, high, critical"}),
                status_code=400,
                media_type="application/json",
            )

        event_types = {"decision", "session_risk_change", "session_start", "alert", "session_enforcement_change", "post_action_finding", "trajectory_alert", "pattern_evolved", "defer_pending", "defer_resolved"}
        if types:
            requested_types = {item.strip() for item in types.split(",") if item.strip()}
            if not requested_types or not requested_types.issubset(event_types):
                return Response(
                    content=json.dumps({"error": "types must be a comma-separated subset of: decision, session_risk_change, session_start, alert, session_enforcement_change, post_action_finding, trajectory_alert, pattern_evolved, defer_pending, defer_resolved"}),
                    status_code=400,
                    media_type="application/json",
                )
            event_types = requested_types

        subscriber_id, queue = gateway.event_bus.subscribe(
            session_id=session_id,
            min_risk=min_risk,
            event_types=event_types,
        )
        if subscriber_id is None or queue is None:
            return Response(
                content=json.dumps({"error": "Too many SSE subscribers"}),
                status_code=503,
                media_type="application/json",
            )

        async def event_generator():
            yield ": connected\n\n"  # Immediately flush headers to client
            try:
                while True:
                    try:
                        event = await asyncio.wait_for(queue.get(), timeout=15.0)
                        event_type = str(event.get("type") or "message")
                        # Keep "type" in data payload so clients that only parse data: lines
                        # (e.g. urllib-based watch CLI) can still dispatch on event type.
                        payload = {**event, "type": event_type}
                        yield f"event: {event_type}\ndata: {json.dumps(payload)}\n\n"
                    except asyncio.TimeoutError:
                        yield ": keepalive\n\n"
            finally:
                gateway.event_bus.unsubscribe(subscriber_id)

        return StreamingResponse(event_generator(), media_type="text/event-stream")

    @app.get("/report/sessions")
    async def report_sessions_endpoint(
        request: Request,
        status: str = "active",
        sort: str = "risk_level",
        limit: int = 50,
        min_risk: Optional[str] = None,
        window_seconds: Optional[int] = None,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if window_seconds is not None and (window_seconds < 1 or window_seconds > MAX_WINDOW_SECONDS):
            return Response(
                content=json.dumps({"error": f"window_seconds must be between 1 and {MAX_WINDOW_SECONDS}"}),
                status_code=400,
                media_type="application/json",
            )
        if status not in {"active", "all"}:
            return Response(
                content=json.dumps({"error": "status must be one of: active, all"}),
                status_code=400,
                media_type="application/json",
            )
        if sort not in {"risk_level", "last_event"}:
            return Response(
                content=json.dumps({"error": "sort must be one of: risk_level, last_event"}),
                status_code=400,
                media_type="application/json",
            )
        if min_risk is not None and min_risk not in {"low", "medium", "high", "critical"}:
            return Response(
                content=json.dumps({"error": "min_risk must be one of: low, medium, high, critical"}),
                status_code=400,
                media_type="application/json",
            )
        effective_limit = min(max(limit, 1), 200)
        return gateway.report_sessions(
            status=status,
            sort=sort,
            limit=effective_limit,
            min_risk=min_risk,
            window_seconds=window_seconds,
        )

    @app.get("/report/session/{session_id}/risk")
    async def report_session_risk_endpoint(
        request: Request,
        session_id: str,
        limit: int = 100,
        window_seconds: Optional[int] = None,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if window_seconds is not None and (window_seconds < 1 or window_seconds > MAX_WINDOW_SECONDS):
            return Response(
                content=json.dumps({"error": f"window_seconds must be between 1 and {MAX_WINDOW_SECONDS}"}),
                status_code=400,
                media_type="application/json",
            )
        effective_limit = min(max(limit, 1), 1000)
        return gateway.report_session_risk(
            session_id=session_id,
            limit=effective_limit,
            window_seconds=window_seconds,
        )

    @app.get("/report/session/{session_id}")
    async def report_session_endpoint(
        request: Request,
        session_id: str,
        limit: int = 100,
        window_seconds: Optional[int] = None,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if window_seconds is not None and (window_seconds < 1 or window_seconds > MAX_WINDOW_SECONDS):
            return Response(
                content=json.dumps({"error": f"window_seconds must be between 1 and {MAX_WINDOW_SECONDS}"}),
                status_code=400,
                media_type="application/json",
            )
        effective_limit = min(max(limit, 1), 1000)
        return gateway.replay_session(
            session_id=session_id,
            limit=effective_limit,
            window_seconds=window_seconds,
        )

    @app.get("/report/alerts")
    async def report_alerts_endpoint(
        request: Request,
        severity: Optional[str] = None,
        acknowledged: Optional[str] = None,
        window_seconds: Optional[int] = None,
        limit: int = 100,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if severity is not None and severity not in {"low", "medium", "high", "critical"}:
            return Response(
                content=json.dumps({"error": "severity must be one of: low, medium, high, critical"}),
                status_code=400,
                media_type="application/json",
            )
        if acknowledged is not None and acknowledged not in {"true", "false"}:
            return Response(
                content=json.dumps({"error": "acknowledged must be 'true' or 'false'"}),
                status_code=400,
                media_type="application/json",
            )
        if window_seconds is not None and (window_seconds < 1 or window_seconds > MAX_WINDOW_SECONDS):
            return Response(
                content=json.dumps({"error": f"window_seconds must be between 1 and {MAX_WINDOW_SECONDS}"}),
                status_code=400,
                media_type="application/json",
            )
        ack_filter: Optional[bool] = None
        if acknowledged is not None:
            ack_filter = acknowledged == "true"
        effective_limit = min(max(limit, 1), 1000)
        return gateway.report_alerts(
            severity=severity,
            acknowledged=ack_filter,
            window_seconds=window_seconds,
            limit=effective_limit,
        )

    @app.post("/report/alerts/{alert_id}/acknowledge")
    async def acknowledge_alert_endpoint(
        request: Request,
        alert_id: str,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        try:
            body = await request.json()
        except Exception:
            body = {}
        acknowledged_by = str(body.get("acknowledged_by") or "unknown")
        result = gateway.acknowledge_alert(alert_id, acknowledged_by)
        if result is None:
            return Response(
                content=json.dumps({"error": f"Alert '{alert_id}' not found"}),
                status_code=404,
                media_type="application/json",
            )
        return result

    # --- Session enforcement management (A-7) ---

    @app.get("/report/session/{session_id}/enforcement")
    async def get_enforcement_endpoint(request: Request, session_id: str):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        return gateway.session_enforcement.get_status(session_id)

    @app.post("/report/session/{session_id}/enforcement")
    async def post_enforcement_endpoint(request: Request, session_id: str):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        try:
            body = await request.json()
        except Exception:
            return Response(
                content=json.dumps({"error": "invalid JSON body"}),
                status_code=400,
                media_type="application/json",
            )
        action = str(body.get("action", "")).lower()
        if action != "release":
            return Response(
                content=json.dumps({"error": "action must be 'release'"}),
                status_code=400,
                media_type="application/json",
            )
        released = gateway.session_enforcement.release(session_id)
        if released:
            gateway.event_bus.broadcast(
                {
                    "type": "session_enforcement_change",
                    "session_id": session_id,
                    "state": "released",
                    "action": None,
                    "high_risk_count": None,
                    "timestamp": utc_now_iso(),
                }
            )
        return {
            "session_id": session_id,
            "released": released,
        }

    # --- E-5: Self-evolving pattern endpoints ---

    @app.get("/ahp/patterns")
    async def list_patterns_endpoint(request: Request):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        return Response(
            content=json.dumps({"patterns": gateway.evolution_manager.list_patterns()}),
            media_type="application/json",
        )

    @app.post("/ahp/patterns/confirm")
    async def confirm_pattern_endpoint(request: Request):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if not gateway.evolution_manager._enabled:
            return Response(
                content=json.dumps({"error": "pattern evolution is disabled (CS_EVOLVING_ENABLED=0)"}),
                status_code=403,
                media_type="application/json",
            )
        try:
            body = await request.json()
        except Exception:
            return Response(
                content=json.dumps({"error": "invalid JSON"}),
                status_code=400,
                media_type="application/json",
            )
        pattern_id = body.get("pattern_id")
        confirmed = body.get("confirmed")
        if not pattern_id or confirmed is None:
            return Response(
                content=json.dumps({"error": "pattern_id and confirmed (bool) are required"}),
                status_code=400,
                media_type="application/json",
            )
        result = gateway.evolution_manager.confirm(pattern_id, confirmed=bool(confirmed))
        if result == "not_found":
            return Response(
                content=json.dumps({"error": "pattern not found"}),
                status_code=404,
                media_type="application/json",
            )
        # Broadcast SSE event
        gateway.event_bus.broadcast({
            "type": "pattern_evolved",
            "pattern_id": pattern_id,
            "action": result,
        })
        # Trigger hot-reload so new experimental/stable patterns take effect
        if result in ("promoted_to_experimental", "promoted_to_stable"):
            if not _find_and_reload_pattern_matcher(gateway.policy_engine._analyzer):
                logger.warning("could not hot-reload PatternMatcher: no RuleBasedAnalyzer found")
        return Response(
            content=json.dumps({"result": result, "pattern_id": pattern_id}),
            media_type="application/json",
        )

    # --- Web Dashboard UI (static SPA) ---
    _ui_dir = ui_dir if ui_dir is not None else _DEFAULT_UI_DIR
    if _ui_dir.exists() and (_ui_dir / "index.html").exists():
        _index_html = (_ui_dir / "index.html").read_text()

        @app.get("/ui/{path:path}")
        async def ui_spa_fallback(path: str):
            """SPA fallback: serve index.html for unmatched /ui/* paths."""
            # Check if requested path is a real file
            file_path = _ui_dir / path
            if file_path.is_file() and file_path.resolve().is_relative_to(
                _ui_dir.resolve()
            ):
                return FileResponse(str(file_path))
            return HTMLResponse(_index_html)

        @app.get("/ui")
        async def ui_root():
            return HTMLResponse(_index_html)

    return app


# ---------------------------------------------------------------------------
# UDS Transport (asyncio)
# ---------------------------------------------------------------------------

async def _uds_client_handler(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    gateway: SupervisionGateway,
) -> None:
    """Handle a single UDS client connection using length-prefixed framing."""
    try:
        while True:
            # Read 4-byte length prefix (big-endian uint32)
            length_bytes = await reader.readexactly(4)
            msg_length = struct.unpack("!I", length_bytes)[0]

            if msg_length == 0 or msg_length > 10 * 1024 * 1024:  # 10MB limit
                logger.warning("UDS: rejected frame with length %d", msg_length)
                break

            data = await reader.readexactly(msg_length)
            result = await gateway.handle_jsonrpc(data)
            response_bytes = json.dumps(result).encode("utf-8")

            # Write length-prefixed response
            writer.write(struct.pack("!I", len(response_bytes)))
            writer.write(response_bytes)
            await writer.drain()

    except (asyncio.IncompleteReadError, ConnectionResetError):
        pass
    except Exception:
        logger.exception("UDS client handler error")
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def start_uds_server(
    gateway: SupervisionGateway,
    path: str = DEFAULT_UDS_PATH,
) -> asyncio.AbstractServer:
    """Start the Unix Domain Socket server."""
    # Remove stale socket file
    if os.path.exists(path):
        os.unlink(path)

    async def handler(reader, writer):
        await _uds_client_handler(reader, writer, gateway)

    server = await asyncio.start_unix_server(handler, path=path)
    os.chmod(path, 0o600)  # Only owner can access
    logger.info(f"UDS server listening on {path} (mode=0600)")
    return server


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def run_gateway(
    uds_path: str = DEFAULT_UDS_PATH,
    http_host: str = DEFAULT_HTTP_HOST,
    http_port: int = DEFAULT_HTTP_PORT,
    trajectory_db_path: str = DEFAULT_TRAJECTORY_DB_PATH,
    trajectory_retention_seconds: int = DEFAULT_TRAJECTORY_RETENTION_SECONDS,
    ssl_certfile: str | None = None,
    ssl_keyfile: str | None = None,
) -> None:
    """Run the Supervision Gateway with both UDS and HTTP transports."""
    # Build detection config from CS_ environment variables
    detection_config = build_detection_config_from_env()
    logger.info("DetectionConfig: %s", detection_config)

    gateway = SupervisionGateway(
        trajectory_db_path=trajectory_db_path,
        trajectory_retention_seconds=trajectory_retention_seconds,
        detection_config=detection_config,
    )

    # Wire LLM analyzer (same pattern as stack.py)
    analyzer = build_analyzer_from_env(
        trajectory_store=gateway.trajectory_store,
        patterns_path=detection_config.attack_patterns_path,
        evolved_patterns_path=detection_config.evolved_patterns_path if detection_config.evolving_enabled else None,
        l3_budget_ms=detection_config.l3_budget_ms,
    )
    if analyzer is not None:
        gateway.policy_engine = L1PolicyEngine(analyzer=analyzer, config=detection_config)

    app = create_http_app(gateway)

    # Start UDS server
    uds_server = await start_uds_server(gateway, uds_path)

    # Start periodic cleanup
    cleanup_task = asyncio.create_task(
        periodic_cleanup(gateway.idempotency_cache, interval_seconds=10.0)
    )

    # Start HTTP server
    uvicorn_kwargs: dict[str, Any] = {
        "app": app,
        "host": http_host,
        "port": http_port,
        "log_level": "info",
        "access_log": False,
    }
    if ssl_certfile and ssl_keyfile:
        uvicorn_kwargs["ssl_certfile"] = ssl_certfile
        uvicorn_kwargs["ssl_keyfile"] = ssl_keyfile
        logger.info("HTTPS enabled (cert=%s, key=%s)", ssl_certfile, ssl_keyfile)
    config = uvicorn.Config(**uvicorn_kwargs)
    server = uvicorn.Server(config)

    logger.info(
        "Gateway starting: UDS=%s, HTTP=%s:%s, TrajectoryDB=%s",
        uds_path,
        http_host,
        http_port,
        trajectory_db_path,
    )

    try:
        await server.serve()
    finally:
        cleanup_task.cancel()
        uds_server.close()
        await uds_server.wait_closed()
        if os.path.exists(uds_path):
            os.unlink(uds_path)


def _gateway_args_from_env() -> dict:
    """Read gateway configuration from environment variables."""
    args: dict[str, Any] = {
        "uds_path": os.environ.get("CS_UDS_PATH", DEFAULT_UDS_PATH),
        "http_host": os.environ.get("CS_HTTP_HOST", DEFAULT_HTTP_HOST),
        "http_port": int(os.environ.get("CS_HTTP_PORT", str(DEFAULT_HTTP_PORT))),
        "trajectory_db_path": os.environ.get(
            "CS_TRAJECTORY_DB_PATH", DEFAULT_TRAJECTORY_DB_PATH
        ),
        "trajectory_retention_seconds": int(os.environ.get(
            "AHP_TRAJECTORY_RETENTION_SECONDS",
            str(DEFAULT_TRAJECTORY_RETENTION_SECONDS),
        )),
    }
    ssl_cert = os.environ.get("AHP_SSL_CERTFILE", "").strip() or None
    ssl_key = os.environ.get("AHP_SSL_KEYFILE", "").strip() or None
    if ssl_cert and ssl_key:
        args["ssl_certfile"] = ssl_cert
        args["ssl_keyfile"] = ssl_key
    return args


def _build_gateway_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="clawsentry-gateway",
        description=(
            "Run the ClawSentry Supervision Gateway.\n\n"
            "All options can also be set via environment variables (shown in brackets).\n"
            "CLI flags take precedence over environment variables."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--uds-path",
        default=None,
        metavar="PATH",
        help=f"Unix domain socket path [CS_UDS_PATH] (default: {DEFAULT_UDS_PATH})",
    )
    parser.add_argument(
        "--host",
        default=None,
        metavar="HOST",
        help=f"HTTP bind host [CS_HTTP_HOST] (default: {DEFAULT_HTTP_HOST})",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        metavar="PORT",
        help=f"HTTP bind port [CS_HTTP_PORT] (default: {DEFAULT_HTTP_PORT})",
    )
    parser.add_argument(
        "--trajectory-db-path",
        default=None,
        metavar="PATH",
        help=f"SQLite trajectory DB path [CS_TRAJECTORY_DB_PATH] (default: {DEFAULT_TRAJECTORY_DB_PATH})",
    )
    parser.add_argument(
        "--trajectory-retention-seconds",
        type=int,
        default=None,
        metavar="SECONDS",
        help=f"Trajectory retention window [AHP_TRAJECTORY_RETENTION_SECONDS] (default: {DEFAULT_TRAJECTORY_RETENTION_SECONDS})",
    )
    parser.add_argument(
        "--ssl-certfile",
        default=None,
        metavar="PATH",
        help="TLS certificate file [AHP_SSL_CERTFILE] (enables HTTPS when combined with --ssl-keyfile)",
    )
    parser.add_argument(
        "--ssl-keyfile",
        default=None,
        metavar="PATH",
        help="TLS private key file [AHP_SSL_KEYFILE]",
    )
    return parser


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")
    from ..cli.dotenv_loader import load_dotenv
    load_dotenv()

    parser = _build_gateway_parser()
    args = parser.parse_args()

    # Build kwargs: env-derived defaults, then override with explicit CLI flags
    kwargs = _gateway_args_from_env()
    if args.uds_path is not None:
        kwargs["uds_path"] = args.uds_path
    if args.host is not None:
        kwargs["http_host"] = args.host
    if args.port is not None:
        kwargs["http_port"] = args.port
    if args.trajectory_db_path is not None:
        kwargs["trajectory_db_path"] = args.trajectory_db_path
    if args.trajectory_retention_seconds is not None:
        kwargs["trajectory_retention_seconds"] = args.trajectory_retention_seconds
    if args.ssl_certfile is not None:
        kwargs["ssl_certfile"] = args.ssl_certfile
    if args.ssl_keyfile is not None:
        kwargs["ssl_keyfile"] = args.ssl_keyfile

    try:
        asyncio.run(run_gateway(**kwargs))
    except KeyboardInterrupt:
        logger.info("Gateway stopped by user.")


if __name__ == "__main__":
    main()
