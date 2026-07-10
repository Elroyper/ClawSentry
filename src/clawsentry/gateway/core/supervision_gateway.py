"""Core supervision gateway implementation."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Any, Optional


from clawsentry.gateway.storage.alert_registry import AlertRegistry
from clawsentry.gateway.analysis.anti_bypass_guard import AntiBypassGuard
from clawsentry.gateway.analysis.anti_bypass_llm_recognizer import (
    AntiBypassLLMProvider,
)
from clawsentry.gateway.policy.defer_manager import DeferManager
from clawsentry.gateway.config.detection_config import DetectionConfig
from clawsentry.gateway.telemetry.event_bus import EventBus
from clawsentry.gateway.storage.idempotency import IdempotencyCache
from ..l3 import advisory_service as _l3_advisory_service
from ..l3.advisory_service import (
    DEFAULT_L3_ADVISORY_RUNNER,
)
from clawsentry.gateway.llm.factory import build_provider_from_env
from clawsentry.gateway.llm.provider import InstrumentedProvider
from clawsentry.gateway.telemetry.metrics import LLMBudgetTracker, MetricsCollector
from clawsentry.gateway.models import (
    AdapterEffectResult,
    CanonicalDecision,
    CanonicalEvent,
    DecisionContext,
    DecisionEffects,
    DecisionSource,
    DecisionVerdict,
    FailureClass,
    RPC_VERSION,
    RiskLevel,
    SessionEffectRequest,
    SkillRegistryRecord,
    SyncDecisionErrorResponse,
    adapter_effect_result_summary,
    decision_effects_for_trajectory,
    utc_now_iso,
)
from clawsentry.gateway.rules.pattern_evolution import PatternEvolutionManager
from clawsentry.gateway.policy.engine import L1PolicyEngine
from clawsentry.gateway.policy.scope_task_artifacts import hash_session_scope_profile
from clawsentry.gateway.analysis.post_action_analyzer import PostActionAnalyzer
from ..reporting.service import (
    _build_decision_path_io_pressure,
    _build_system_security_posture,
    _build_window_risk_summary,
    _copy_budget_event,
    _float_or_zero,
    _l3_trace_for_persistence,
    _new_io_metric_bucket,
    _observe_io_metric,
    _snapshot_io_metric,
)
from clawsentry.gateway.policy.session_enforcement import EnforcementAction, SessionEnforcementPolicy
from clawsentry.gateway.storage.session_registry import (
    DISPLAY_SCORE_RANGE,
    DISPLAY_SCORE_SEMANTICS,
    POST_ACTION_SCORE_SEMANTICS,
    SessionRegistry,
)
from clawsentry.gateway.trust.skill_trust import load_skill_registry_records
from clawsentry.gateway.analysis.trajectory_analyzer import TrajectoryAnalyzer
from clawsentry.gateway.storage.trajectory_store import (
    DEFAULT_TRAJECTORY_RETENTION_SECONDS,
    TrajectoryStore,
)
from ..trust.fspr_bridge import (
    _apply_gateway_owned_first_use_package_review,
    _apply_gateway_owned_first_use_scan,
    _gateway_current_runner_contract_id,
    _gateway_observed_runtime_skill_refs,
    _gateway_owned_skill_trust_bundle,
    _gateway_owned_skill_trust_metadata,
)
from ..trust.request import (
    _context_with_skill_trust_raw as _context_with_skill_trust_raw_base,
)
from .config_resolution import (
    _enforcement_action_from_config,
    _load_default_session_scope_profile,
)
from .content_evidence import (
    _l3_trace_has_content_evidence_signal,
    _snapshot_has_content_evidence_rule,
)
from .jsonrpc import JSONRPC_METHOD, JSONRPC_VERSION
from .sync_decision_flow import handle_sync_decision

logger = logging.getLogger("clawsentry")

_build_provider_from_env_hook = build_provider_from_env


def _apply_default_gateway_owned_first_use_package_review(
    raw_metadata: dict[str, Any],
    *,
    event: CanonicalEvent,
    detection_config: DetectionConfig | None,
    deadline_at: float | None = None,
) -> None:
    """Run gateway-owned FSPR with the default runtime dependencies wired in."""

    from clawsentry.gateway.first_use_skill_review import (
        FSPR_EVIDENCE_CAPSULE_SCHEMA_VERSION,
        FSPRLLMRoleProvider,
        run_agentic_readonly_fspr_review,
        run_first_use_skill_package_review,
    )

    _apply_gateway_owned_first_use_package_review(
        raw_metadata,
        event=event,
        detection_config=detection_config,
        deadline_at=deadline_at,
        run_first_use_skill_package_review_fn=run_first_use_skill_package_review,
        run_agentic_readonly_fspr_review_fn=run_agentic_readonly_fspr_review,
        build_provider_from_env_fn=_build_provider_from_env_hook,
        fspr_llm_role_provider_cls=FSPRLLMRoleProvider,
        evidence_capsule_schema_version=FSPR_EVIDENCE_CAPSULE_SCHEMA_VERSION,
    )


_apply_gateway_owned_first_use_package_review_hook = (
    _apply_default_gateway_owned_first_use_package_review
)


def configure_gateway_core_dependencies(
    *,
    build_provider_from_env_fn: Any | None = None,
    apply_gateway_owned_first_use_package_review_fn: Any | None = None,
) -> None:
    """Install facade-sensitive hooks without importing legacy facade modules."""

    global _build_provider_from_env_hook
    global _apply_gateway_owned_first_use_package_review_hook
    if build_provider_from_env_fn is not None:
        _build_provider_from_env_hook = build_provider_from_env_fn
    if apply_gateway_owned_first_use_package_review_fn is not None:
        _apply_gateway_owned_first_use_package_review_hook = (
            apply_gateway_owned_first_use_package_review_fn
        )


def _context_with_skill_trust_raw(
    context: DecisionContext | None,
    event: CanonicalEvent,
    trusted_records: list[SkillRegistryRecord] | None = None,
    deadline_at: float | None = None,
    detection_config: DetectionConfig | None = None,
) -> DecisionContext | None:
    return _context_with_skill_trust_raw_base(
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
            _apply_gateway_owned_first_use_package_review_hook
        ),
    )


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
        trajectory_store: Optional[TrajectoryStore] = None,
        analyzer=None,
        session_enforcement: Optional[SessionEnforcementPolicy] = None,
        detection_config: Optional[DetectionConfig] = None,
        anti_bypass_llm_provider: Optional[AntiBypassLLMProvider] = None,
        skill_registry_records: Optional[list[SkillRegistryRecord]] = None,
    ) -> None:
        self._detection_config = (
            detection_config if detection_config is not None else DetectionConfig()
        )
        self.policy_engine = L1PolicyEngine(
            analyzer=analyzer, config=self._detection_config
        )
        self.idempotency_cache = IdempotencyCache()
        effective_db_path = trajectory_db_path
        if effective_db_path is None:
            effective_db_path = os.getenv("CS_TRAJECTORY_DB_PATH", ":memory:")
        self.trajectory_store = trajectory_store or TrajectoryStore(
            db_path=effective_db_path,
            retention_seconds=trajectory_retention_seconds,
        )
        self.session_registry = SessionRegistry()
        self.event_bus = EventBus()
        self.alert_registry = AlertRegistry()
        self.session_enforcement = session_enforcement or SessionEnforcementPolicy()
        self.anti_bypass_guard = AntiBypassGuard()
        self.anti_bypass_llm_provider = anti_bypass_llm_provider
        self.skill_registry_records = (
            list(skill_registry_records)
            if skill_registry_records is not None
            else load_skill_registry_records(
                self._detection_config.skill_trust_registry_path
            )
        )
        self._agent_safety_feedback_delivered_surfaces: set[tuple[str, str, str]] = (
            set()
        )
        self.default_session_scope_profile = _load_default_session_scope_profile()
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
        # P3: LLM daily budget tracker
        self.budget_tracker = LLMBudgetTracker(
            daily_budget_usd=self._detection_config.llm_daily_budget_usd,
            enabled=self._detection_config.llm_token_budget_enabled,
            limit_tokens=self._detection_config.llm_daily_token_budget,
            scope=self._detection_config.llm_token_budget_scope,
            source="config",
        )
        self._budget_exhaustion_event: dict[str, Any] | None = None
        # P3: Prometheus metrics collector
        _metrics_enabled = os.getenv("CS_METRICS_ENABLED", "true").lower() not in (
            "0",
            "false",
            "no",
        )
        self.metrics = MetricsCollector(
            enabled=_metrics_enabled,
            budget_tracker=self.budget_tracker,
            budget_exhausted_callback=self._handle_budget_exhausted,
        )
        if (
            self.anti_bypass_llm_provider is None
            and self._detection_config.anti_bypass_llm_recognition_enabled
        ):
            raw_anti_bypass_provider = _build_provider_from_env_hook()
            if raw_anti_bypass_provider is not None:
                self.anti_bypass_llm_provider = InstrumentedProvider(
                    raw_anti_bypass_provider,
                    self.metrics,
                    tier="anti_bypass",
                )
        self._io_metrics = {
            "record_path": {
                "calls": 0,
                "total_seconds": 0.0,
                "last_seconds": 0.0,
                "max_seconds": 0.0,
                "trajectory_store": _new_io_metric_bucket(),
                "session_registry": _new_io_metric_bucket(),
            },
            "reporting": {
                "health": _new_io_metric_bucket(),
                "report_summary": _new_io_metric_bucket(),
                "report_policy_drift": _new_io_metric_bucket(),
                "report_sessions": _new_io_metric_bucket(),
                "report_session_risk": _new_io_metric_bucket(),
                "report_session_post_action": _new_io_metric_bucket(),
                "replay_session": _new_io_metric_bucket(),
                "replay_session_page": _new_io_metric_bucket(),
                "report_alerts": _new_io_metric_bucket(),
            },
        }
        self._start_time = time.monotonic()
        self._ready = True

    def _handle_budget_exhausted(self, event: dict[str, Any]) -> None:
        """Store and broadcast the first budget exhaustion transition for the day."""
        normalized_event = dict(event)
        budget = normalized_event.get("budget")
        if isinstance(budget, dict):
            normalized_event["budget"] = dict(budget)
        self._budget_exhaustion_event = normalized_event
        self.event_bus.broadcast(normalized_event)

    def _budget_state(self) -> dict[str, Any]:
        """Return the current budget-governance state for reporting surfaces."""
        budget = self.budget_tracker.snapshot()
        if not budget.get("exhausted", False):
            self._budget_exhaustion_event = None
        return {
            "budget": budget,
            "budget_exhaustion_event": _copy_budget_event(
                self._budget_exhaustion_event
            ),
        }

    def _reporting_state(self) -> dict[str, Any]:
        """Shared reporting envelope for gateway-owned surfaces."""
        payload = self._budget_state()
        payload["llm_usage_snapshot"] = self.metrics.llm_usage_snapshot()
        return payload

    def _reporting_io_state(self) -> dict[str, Any]:
        """Shared I/O envelope; call after observing the current endpoint."""
        return {"decision_path_io": self._decision_path_io_snapshot()}

    def _observe_record_path_io(
        self,
        *,
        elapsed_seconds: float,
        trajectory_store_seconds: float,
        session_registry_seconds: float,
    ) -> None:
        record_bucket = self._io_metrics["record_path"]
        _observe_io_metric(record_bucket, elapsed_seconds)
        _observe_io_metric(record_bucket["trajectory_store"], trajectory_store_seconds)
        _observe_io_metric(record_bucket["session_registry"], session_registry_seconds)

    def _observe_reporting_io(self, report_name: str, elapsed_seconds: float) -> None:
        _observe_io_metric(self._io_metrics["reporting"][report_name], elapsed_seconds)

    def _decision_path_io_snapshot(self) -> dict[str, Any]:
        record_bucket = self._io_metrics["record_path"]
        reporting_bucket = self._io_metrics["reporting"]
        trajectory_store_io = self.trajectory_store.io_metrics_snapshot()
        session_registry_io = self.session_registry.io_metrics_snapshot()
        alert_registry_io = self.alert_registry.io_metrics_snapshot()
        return {
            "record_path": {
                **_snapshot_io_metric(record_bucket),
                "trajectory_store": _snapshot_io_metric(
                    record_bucket["trajectory_store"]
                ),
                "session_registry": _snapshot_io_metric(
                    record_bucket["session_registry"]
                ),
            },
            "reporting": {
                "health": {
                    **_snapshot_io_metric(reporting_bucket["health"]),
                    "trajectory_count": trajectory_store_io["count"],
                },
                "report_summary": {
                    **_snapshot_io_metric(reporting_bucket["report_summary"]),
                    "trajectory_store": trajectory_store_io["summary"],
                },
                "report_policy_drift": {
                    **_snapshot_io_metric(reporting_bucket["report_policy_drift"]),
                    "trajectory_store": trajectory_store_io["policy_drift"],
                },
                "report_sessions": {
                    **_snapshot_io_metric(reporting_bucket["report_sessions"]),
                    "session_registry": session_registry_io["list_sessions"],
                },
                "report_session_risk": {
                    **_snapshot_io_metric(reporting_bucket["report_session_risk"]),
                    "session_registry": session_registry_io["get_session_risk"],
                },
                "report_session_post_action": {
                    **_snapshot_io_metric(
                        reporting_bucket["report_session_post_action"]
                    ),
                    "session_registry": session_registry_io["get_session_risk"],
                },
                "replay_session": {
                    **_snapshot_io_metric(reporting_bucket["replay_session"]),
                    "trajectory_query": trajectory_store_io["replay_session"],
                },
                "replay_session_page": {
                    **_snapshot_io_metric(reporting_bucket["replay_session_page"]),
                    "trajectory_query": trajectory_store_io["replay_session_page"],
                },
                "report_alerts": {
                    **_snapshot_io_metric(reporting_bucket["report_alerts"]),
                    "alert_registry": alert_registry_io["list_alerts"],
                },
            },
        }

    def _record_decision_path(
        self,
        *,
        event: dict[str, Any],
        decision: dict[str, Any],
        snapshot: dict[str, Any],
        meta: dict[str, Any],
        l3_trace: dict[str, Any] | None,
    ) -> int:
        is_resolution = str(meta.get("record_type") or "") == "decision_resolution"
        stored_l3_trace = _l3_trace_for_persistence(
            l3_trace,
            redact_raw_bodies=not self._detection_config.content_evidence_debug_persist_body,
            redact_final_findings=(
                _snapshot_has_content_evidence_rule(snapshot)
                or _l3_trace_has_content_evidence_signal(l3_trace)
            ),
        )
        total_start = time.perf_counter()
        trajectory_store_seconds = 0.0
        session_registry_seconds = 0.0
        record_id = 0
        try:
            trajectory_start = time.perf_counter()
            stored_decision = dict(decision)
            if stored_decision.get("decision_effects") is not None:
                stored_decision["decision_effects"] = decision_effects_for_trajectory(
                    stored_decision.get("decision_effects")
                )
            if is_resolution:
                record_id = self.trajectory_store.record_resolution(
                    event=event,
                    decision=stored_decision,
                    snapshot=snapshot,
                    meta=meta,
                    l3_trace=stored_l3_trace,
                )
            else:
                record_id = self.trajectory_store.record(
                    event=event,
                    decision=stored_decision,
                    snapshot=snapshot,
                    meta=meta,
                    l3_trace=stored_l3_trace,
                )
            trajectory_store_seconds = time.perf_counter() - trajectory_start

            session_start = time.perf_counter()
            self.session_registry.record(
                event=event,
                decision=stored_decision,
                snapshot=snapshot,
                meta=meta,
            )
            session_registry_seconds = time.perf_counter() - session_start
        finally:
            self._observe_record_path_io(
                elapsed_seconds=time.perf_counter() - total_start,
                trajectory_store_seconds=trajectory_store_seconds,
                session_registry_seconds=session_registry_seconds,
            )
        return record_id

    def record_adapter_effect_result(
        self,
        result: AdapterEffectResult | dict[str, Any],
    ) -> dict[str, Any]:
        """Record an adapter-observed effect outcome without mutating decisions."""

        model = (
            result
            if isinstance(result, AdapterEffectResult)
            else AdapterEffectResult(**result)
        )
        payload = model.model_dump(mode="json")
        write_result = self.trajectory_store.record_adapter_effect_result(payload)
        self.session_registry.record_adapter_effect_result(write_result["result"])
        summary = adapter_effect_result_summary(write_result["result"])
        self.event_bus.broadcast(
            {
                "type": "adapter_effect_result",
                "session_id": payload.get("session_id"),
                "event_id": payload.get("event_id"),
                "effect_id": payload.get("effect_id"),
                "adapter_effect_result_summary": summary,
                "created": write_result["created"],
                "timestamp": utc_now_iso(),
            }
        )
        return write_result

    def _skill_use_ledger_entries_for_session(
        self, session_id: str
    ) -> list[dict[str, Any]]:
        """Return replay-safe skill-use ledger entries recorded for a session."""

        entries: list[dict[str, Any]] = []
        try:
            records = self.replay_session(session_id).get("records") or []
        except Exception:
            return entries
        for record in records:
            if not isinstance(record, dict):
                continue
            meta = record.get("meta")
            if not isinstance(meta, dict):
                continue
            ledger = meta.get("skill_use_ledger")
            if isinstance(ledger, dict) and isinstance(ledger.get("entries"), list):
                entries.extend(
                    dict(entry)
                    for entry in ledger["entries"]
                    if isinstance(entry, dict)
                )
        return entries

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
                body.get("id"),
                -32600,
                f"Invalid jsonrpc version: expected '{JSONRPC_VERSION}', got '{jsonrpc_version}'",
            )

        method = body.get("method")
        rpc_id = body.get("id")
        params = body.get("params", {})

        if method != JSONRPC_METHOD:
            return self._jsonrpc_error(
                rpc_id,
                -32601,
                f"Method not found: '{method}'. Expected '{JSONRPC_METHOD}'",
            )

        return await self._handle_sync_decision(rpc_id, params)

    def _context_with_skill_trust_raw(
        self,
        context: DecisionContext | None,
        event: CanonicalEvent,
        trusted_records: list[SkillRegistryRecord] | None = None,
        deadline_at: float | None = None,
        detection_config: DetectionConfig | None = None,
    ) -> DecisionContext | None:
        return _context_with_skill_trust_raw(
            context,
            event,
            trusted_records,
            deadline_at,
            detection_config,
        )

    def _context_with_default_session_scope(
        self,
        context: DecisionContext | None,
    ) -> DecisionContext | None:
        """Attach the configured default scope profile when request context lacks one."""

        def _without_caller_root_marker(
            ctx: DecisionContext | None,
        ) -> DecisionContext | None:
            if ctx is None or not isinstance(ctx.session_risk_summary, dict):
                return ctx
            if "content_evidence_roots_source" not in ctx.session_risk_summary:
                return ctx
            summary = dict(ctx.session_risk_summary)
            summary.pop("content_evidence_roots_source", None)
            return ctx.model_copy(update={"session_risk_summary": summary})

        context = _without_caller_root_marker(context)
        profile = self.default_session_scope_profile
        if profile is None:
            return context
        marker = {"content_evidence_roots_source": "gateway_default_session_scope"}
        if context is None:
            return DecisionContext(
                session_scope_profile_id=profile.profile_id,
                session_scope_profile=profile,
                session_risk_summary=marker,
            )
        if context.session_scope_profile is not None:
            try:
                context_profile_hash = hash_session_scope_profile(context.session_scope_profile)
                default_profile_hash = hash_session_scope_profile(profile)
            except Exception:
                context_profile_hash = ""
                default_profile_hash = ""
            if context_profile_hash and context_profile_hash == default_profile_hash:
                summary = dict(context.session_risk_summary or {})
                summary.update(marker)
                return context.model_copy(update={"session_risk_summary": summary})
            return context
        summary = dict(context.session_risk_summary or {})
        summary.update(marker)
        return context.model_copy(
            update={
                "session_scope_profile_id": profile.profile_id,
                "session_scope_profile": profile,
                "session_risk_summary": summary,
            }
        )

    def _apply_missing_session_scope_evaluation(
        self,
        decision: CanonicalDecision,
        event: CanonicalEvent,
        context: DecisionContext | None,
    ) -> CanonicalDecision:
        """Tighten override decisions with session scope if they lost scope metadata."""

        if decision.scope_evaluation is not None:
            return decision
        return self.policy_engine.apply_scope_evaluation(decision, event, context)

    async def _run_post_action_async(
        self,
        output_text: str,
        tool_name: str,
        event_id: str,
        session_id: str,
        source_framework: str | None,
        content_origin: str | None,
        external_multiplier: float,
        finding_action: str,
        occurred_at: str,
        file_path: str | None = None,
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
                    file_path=file_path,
                    content_origin=content_origin,
                    external_multiplier=external_multiplier,
                ),
            )
            self.session_registry.record_post_action_score(
                session_id=session_id,
                event_id=event_id,
                occurred_at=occurred_at,
                score=finding.score,
                tier=finding.tier.value,
                patterns_matched=finding.patterns_matched,
                tool_name=tool_name,
                source_framework=source_framework,
                handling=finding_action,
            )

            # Record contamination for high-risk findings
            if finding.tier.value in ("escalate", "emergency"):
                # Extract severity and finding_type
                severity = "high" if finding.tier.value == "escalate" else "critical"
                finding_type = finding.patterns_matched[0] if finding.patterns_matched else "unknown"

                # Record to SessionRiskTracker via policy_engine
                self.policy_engine.session_tracker.record_post_action_contamination(
                    session_id=session_id,
                    finding_severity=severity,
                    finding_type=finding_type,
                    event_id=event_id,
                    tool_name=tool_name,
                )

                # Send contamination alert
                contamination_alert = {
                    "alert_id": f"post_action_contamination_{event_id}",
                    "severity": severity,
                    "type": "indirect_prompt_injection_detected",
                    "session_id": session_id,
                    "tool_name": tool_name,
                    "finding_type": finding_type,
                    "patterns_matched": finding.patterns_matched,
                    "score": finding.score,
                    "recommended_action": "review_or_escalate",
                    "timestamp": occurred_at,
                }

                # Add to alert_registry if exists
                if hasattr(self, 'alert_registry'):
                    self.alert_registry.add(contamination_alert)

                # Broadcast contamination event
                self.event_bus.broadcast({
                    "type": "post_action_contamination",
                    **contamination_alert,
                })

            if finding.tier.value != "log_only":
                handling = finding_action
                if session_id and handling in ("defer", "block"):
                    enf = self.session_enforcement.force(
                        session_id,
                        action=_enforcement_action_from_config(handling),
                        high_risk_count=1,
                    )
                    self.event_bus.broadcast(
                        {
                            "type": "session_enforcement_change",
                            "session_id": session_id,
                            "state": "enforced",
                            "action": enf.action.value,
                            "high_risk_count": enf.high_risk_count,
                            "reason": f"post-action finding {finding.tier.value}",
                            "timestamp": occurred_at,
                        }
                    )
                finding_event = {
                    "type": "post_action_finding",
                    "event_id": event_id,
                    "session_id": session_id,
                    "source_framework": source_framework,
                    "tier": finding.tier.value,
                    "patterns_matched": finding.patterns_matched,
                    "score": finding.score,
                    "handling": handling,
                    "timestamp": occurred_at,
                }
                if isinstance(finding.details, dict) and finding.details.get(
                    "sanitize_advisory"
                ):
                    finding_event["sanitize_advisory"] = finding.details[
                        "sanitize_advisory"
                    ]
                self.event_bus.broadcast(finding_event)
        except Exception:
            logger.exception("post-action analysis failed for event %s", event_id)

    async def _handle_sync_decision(
        self, rpc_id: Any, params: dict[str, Any]
    ) -> dict[str, Any]:
        """Process a SyncDecision v1 request."""
        return await handle_sync_decision(self, rpc_id, params)

    def _make_enforcement_decision(
        self,
        enforcement,
        event: CanonicalEvent,
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
        decision_effects = None
        if verdict == DecisionVerdict.BLOCK:
            decision_effects = DecisionEffects(
                effect_id=f"eff-{event.session_id}-{event.event_id}-session-quarantine",
                action_scope="session",
                session_effect=SessionEffectRequest(
                    requested=True,
                    mode="mark_blocked",
                    reason_code="session_enforcement_threshold",
                    capability_required="clawsentry.session_control.mark_blocked.v1",
                    fallback_on_unsupported="mark_blocked",
                ),
            )
        return CanonicalDecision(
            decision=verdict,
            reason=reason,
            policy_id=policy_id,
            risk_level=RiskLevel.HIGH,
            decision_source=DecisionSource.POLICY,
            policy_version="A7",
            decision_effects=decision_effects,
            failure_class=FailureClass.NONE,
            final=True,
        )

    def health(self) -> dict[str, Any]:
        """Return gateway health status."""
        start = time.perf_counter()
        uptime = time.monotonic() - self._start_time
        payload = {
            "status": "healthy",
            "uptime_seconds": round(uptime, 1),
            "cache_size": self.idempotency_cache.size(),
            "trajectory_count": self.trajectory_store.count(),
            "trajectory_backend": "sqlite",
            "policy_engine": "L1+L2",
            "rpc_version": RPC_VERSION,
            "auth_enabled": bool(os.getenv("CS_AUTH_TOKEN")),
        }
        payload.update(self._reporting_state())
        self._observe_reporting_io("health", time.perf_counter() - start)
        payload.update(self._reporting_io_state())
        return payload

    def report_summary(self, window_seconds: Optional[int] = None) -> dict[str, Any]:
        """Return cross-framework summary metrics from trajectory records."""
        start = time.perf_counter()
        since_seconds = (
            window_seconds if window_seconds and window_seconds > 0 else None
        )
        summary = self.trajectory_store.summary(since_seconds=since_seconds)
        generated_at = utc_now_iso()
        summary["generated_at"] = generated_at
        summary["window_seconds"] = since_seconds
        summary["system_security_posture"] = _build_system_security_posture(
            summary,
            window_seconds=since_seconds,
            generated_at=generated_at,
        )
        summary.update(self._reporting_state())
        self._observe_reporting_io("report_summary", time.perf_counter() - start)
        io_state = self._reporting_io_state()
        summary.update(io_state)
        summary["decision_path_io_pressure"] = _build_decision_path_io_pressure(
            io_state["decision_path_io"]
        )
        return summary

    def report_policy_drift(
        self,
        *,
        window_seconds: Optional[int] = None,
        max_cells: int = 200,
    ) -> dict[str, Any]:
        """Return policy drift grouped for operator traceability."""
        start = time.perf_counter()
        since_seconds = (
            window_seconds if window_seconds and window_seconds > 0 else None
        )
        report = self.trajectory_store.policy_drift_report(
            window_seconds=since_seconds,
            max_cells=max_cells,
        )
        report.update(self._reporting_state())
        self._observe_reporting_io("report_policy_drift", time.perf_counter() - start)
        report.update(self._reporting_io_state())
        return report

    def replay_session(
        self,
        session_id: str,
        limit: int = 100,
        window_seconds: Optional[int] = None,
    ) -> dict[str, Any]:
        """Return timeline records for a session (most recent first by append order)."""
        start = time.perf_counter()
        since_seconds = (
            window_seconds if window_seconds and window_seconds > 0 else None
        )
        records = self.trajectory_store.replay_session(
            session_id=session_id,
            limit=limit,
            since_seconds=since_seconds,
        )
        payload = {
            "session_id": session_id,
            "record_count": len(records),
            "records": records,
            "generated_at": utc_now_iso(),
            "window_seconds": since_seconds,
        }
        payload["l3_advisory"] = self._l3_advisory_payload(session_id)
        payload.update(self._reporting_state())
        self._observe_reporting_io("replay_session", time.perf_counter() - start)
        payload.update(self._reporting_io_state())
        return payload

    def replay_session_page(
        self,
        session_id: str,
        *,
        limit: int = 100,
        cursor: Optional[int] = None,
        window_seconds: Optional[int] = None,
    ) -> dict[str, Any]:
        """Return a paged replay payload for a session."""
        start = time.perf_counter()
        since_seconds = (
            window_seconds if window_seconds and window_seconds > 0 else None
        )
        page = self.trajectory_store.replay_session_page(
            session_id=session_id,
            limit=limit,
            cursor=cursor,
            since_seconds=since_seconds,
        )
        payload = {
            "session_id": session_id,
            "record_count": len(page["records"]),
            "records": page["records"],
            "next_cursor": page["next_cursor"],
            "generated_at": utc_now_iso(),
            "window_seconds": since_seconds,
        }
        payload["l3_advisory"] = self._l3_advisory_payload(session_id)
        payload.update(self._reporting_state())
        self._observe_reporting_io("replay_session_page", time.perf_counter() - start)
        payload.update(self._reporting_io_state())
        return payload

    def report_sessions(
        self,
        *,
        status: str = "active",
        sort: str = "risk_level",
        limit: int = 50,
        min_risk: Optional[str] = None,
        window_seconds: Optional[int] = None,
        max_limit: int = 200,
    ) -> dict[str, Any]:
        start = time.perf_counter()
        since_seconds = (
            window_seconds if window_seconds and window_seconds > 0 else None
        )
        effective_limit = min(max(limit, 1), max(max_limit, 1))
        generated_at = utc_now_iso()
        result = self.session_registry.list_sessions(
            status=status,
            sort=sort,
            min_risk=min_risk,
            limit=effective_limit,
            max_limit=max_limit,
            since_seconds=since_seconds,
        )
        generated_at = utc_now_iso()
        for session in result.get("sessions", []):
            if not isinstance(session, dict):
                continue
            session_id = str(session.get("session_id") or "")
            if since_seconds is None:
                window_summary = {
                    "window_seconds": since_seconds,
                    "generated_at": generated_at,
                    "event_count": int(session.get("event_count") or 0),
                    "latest_composite_score": _float_or_zero(
                        session.get("latest_composite_score")
                    ),
                    "session_risk_sum": round(
                        _float_or_zero(session.get("session_risk_sum")), 4
                    ),
                    "session_risk_ewma": round(
                        _float_or_zero(session.get("session_risk_ewma")), 4
                    ),
                    "risk_points_sum": int(session.get("risk_points_sum") or 0),
                    "risk_velocity": str(session.get("risk_velocity") or "unknown"),
                    "high_or_critical_count": int(
                        session.get("high_risk_event_count") or 0
                    ),
                    "score_range": list(DISPLAY_SCORE_RANGE),
                    "score_semantics": dict(DISPLAY_SCORE_SEMANTICS),
                    "decision_affecting": False,
                }
                session["window_risk_summary"] = window_summary
            else:
                timeline = self.session_registry.get_session_risk(
                    session_id,
                    limit=1000,
                    since_seconds=since_seconds,
                ).get("risk_timeline", [])
                if not isinstance(timeline, list):
                    timeline = []
                window_summary = _build_window_risk_summary(
                    timeline,
                    window_seconds=since_seconds,
                    generated_at=generated_at,
                )
                session["latest_composite_score"] = window_summary[
                    "latest_composite_score"
                ]
                session["session_risk_sum"] = window_summary["session_risk_sum"]
                session["session_risk_ewma"] = window_summary["session_risk_ewma"]
                session["risk_points_sum"] = window_summary["risk_points_sum"]
                session["risk_velocity"] = window_summary["risk_velocity"]
                session["window_risk_summary"] = window_summary
            session["score_range"] = list(DISPLAY_SCORE_RANGE)
            session["score_semantics"] = dict(DISPLAY_SCORE_SEMANTICS)
            latest_review = self.trajectory_store.latest_l3_advisory_review(
                session_id=session_id
            )
            if latest_review is not None:
                session["l3_advisory_latest"] = latest_review
                latest_action = self._l3_advisory_action_for_review(latest_review)
                if latest_action is not None:
                    session["l3_advisory_latest_action"] = latest_action
        result["generated_at"] = generated_at
        result["window_seconds"] = since_seconds
        result.update(self._reporting_state())
        self._observe_reporting_io("report_sessions", time.perf_counter() - start)
        result.update(self._reporting_io_state())
        return result

    def _l3_advisory_payload(self, session_id: str) -> dict[str, Any]:
        return _l3_advisory_service._l3_advisory_payload(self, session_id)

    def _l3_advisory_action_for_review(
        self,
        review: dict[str, Any] | None,
        *,
        job: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        return _l3_advisory_service._l3_advisory_action_for_review(
            self, review, job=job
        )

    def _broadcast_l3_advisory_action(
        self,
        review: dict[str, Any] | None,
        *,
        job: dict[str, Any] | None = None,
    ) -> None:
        return _l3_advisory_service._broadcast_l3_advisory_action(self, review, job=job)

    def report_session_risk(
        self,
        session_id: str,
        *,
        limit: int = 100,
        window_seconds: Optional[int] = None,
    ) -> dict[str, Any]:
        start = time.perf_counter()
        since_seconds = (
            window_seconds if window_seconds and window_seconds > 0 else None
        )
        effective_limit = min(max(limit, 1), 1000)
        result = self.session_registry.get_session_risk(
            session_id,
            limit=effective_limit,
            since_seconds=since_seconds,
        )
        timeline = (
            result.get("risk_timeline")
            if isinstance(result.get("risk_timeline"), list)
            else []
        )
        window_summary = _build_window_risk_summary(
            timeline,
            window_seconds=since_seconds,
        )
        result["latest_composite_score"] = window_summary["latest_composite_score"]
        result["session_risk_sum"] = window_summary["session_risk_sum"]
        result["session_risk_ewma"] = window_summary["session_risk_ewma"]
        result["risk_points_sum"] = window_summary["risk_points_sum"]
        result["risk_velocity"] = window_summary["risk_velocity"]
        result["window_risk_summary"] = window_summary
        result["score_range"] = list(DISPLAY_SCORE_RANGE)
        result["score_semantics"] = dict(DISPLAY_SCORE_SEMANTICS)
        result["l3_advisory"] = self._l3_advisory_payload(session_id)
        result["generated_at"] = utc_now_iso()
        result["window_seconds"] = since_seconds
        result.update(self._reporting_state())
        self._observe_reporting_io("report_session_risk", time.perf_counter() - start)
        result.update(self._reporting_io_state())
        return result

    def report_session_post_action_scores(
        self,
        session_id: str,
        *,
        limit: int = 100,
        window_seconds: Optional[int] = None,
    ) -> dict[str, Any]:
        """Return post-action guard scores and session-level EWMA for a session."""
        start = time.perf_counter()
        since_seconds = (
            window_seconds if window_seconds and window_seconds > 0 else None
        )
        effective_limit = min(max(limit, 1), 1000)
        risk_payload = self.session_registry.get_session_risk(
            session_id,
            limit=effective_limit,
            since_seconds=since_seconds,
        )
        payload = {
            "session_id": session_id,
            "latest_post_action_score": risk_payload.get(
                "latest_post_action_score", 0.0
            ),
            "post_action_score_sum": risk_payload.get("post_action_score_sum", 0.0),
            "post_action_score_avg": risk_payload.get("post_action_score_avg", 0.0),
            "post_action_score_ewma": risk_payload.get("post_action_score_ewma", 0.0),
            "post_action_event_count": risk_payload.get("post_action_event_count", 0),
            "post_action_score_summary": risk_payload.get(
                "post_action_score_summary", {}
            ),
            "post_action_scores": risk_payload.get("post_action_scores", []),
            "score_range": [0.0, 3.0],
            "score_semantics": dict(POST_ACTION_SCORE_SEMANTICS),
            "generated_at": utc_now_iso(),
            "window_seconds": since_seconds,
            "decision_affecting": False,
        }
        self._observe_reporting_io(
            "report_session_post_action", time.perf_counter() - start
        )
        payload.update(self._reporting_state())
        payload.update(self._reporting_io_state())
        return payload

    def create_l3_evidence_snapshot(
        self,
        *,
        session_id: str,
        trigger_event_id: str,
        trigger_reason: str,
        trigger_detail: str | None = None,
        to_record_id: int | None = None,
        from_record_id: int | None = None,
        max_records: int = 50,
        max_tool_calls: int = 4,
    ) -> dict[str, Any]:
        return _l3_advisory_service.create_l3_evidence_snapshot(
            self,
            session_id=session_id,
            trigger_event_id=trigger_event_id,
            trigger_reason=trigger_reason,
            trigger_detail=trigger_detail,
            to_record_id=to_record_id,
            from_record_id=from_record_id,
            max_records=max_records,
            max_tool_calls=max_tool_calls,
        )

    def record_l3_advisory_review(
        self,
        *,
        snapshot_id: str,
        risk_level: str,
        findings: list[str] | None = None,
        confidence: float | None = None,
        recommended_operator_action: str = "inspect",
        advisory_only: bool = True,
        l3_state: str = "completed",
        l3_reason_code: str | None = None,
        extra_fields: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return _l3_advisory_service.record_l3_advisory_review(
            self,
            snapshot_id=snapshot_id,
            risk_level=risk_level,
            findings=findings,
            confidence=confidence,
            recommended_operator_action=recommended_operator_action,
            advisory_only=advisory_only,
            l3_state=l3_state,
            l3_reason_code=l3_reason_code,
            extra_fields=extra_fields,
        )

    def update_l3_advisory_review(
        self,
        review_id: str,
        *,
        risk_level: str | None = None,
        findings: list[str] | None = None,
        confidence: float | None = None,
        recommended_operator_action: str | None = None,
        l3_state: str | None = None,
        l3_reason_code: str | None = None,
        extra_fields: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return _l3_advisory_service.update_l3_advisory_review(
            self,
            review_id,
            risk_level=risk_level,
            findings=findings,
            confidence=confidence,
            recommended_operator_action=recommended_operator_action,
            l3_state=l3_state,
            l3_reason_code=l3_reason_code,
            extra_fields=extra_fields,
        )

    def run_local_l3_advisory_review(self, *, snapshot_id: str) -> dict[str, Any]:
        return _l3_advisory_service.run_local_l3_advisory_review(
            self, snapshot_id=snapshot_id
        )

    def enqueue_l3_advisory_job(
        self,
        *,
        snapshot_id: str,
        runner: str = DEFAULT_L3_ADVISORY_RUNNER,
    ) -> dict[str, Any]:
        return _l3_advisory_service.enqueue_l3_advisory_job(
            self,
            snapshot_id=snapshot_id,
            runner=runner,
        )

    def run_l3_advisory_job_local(self, *, job_id: str) -> dict[str, Any]:
        return _l3_advisory_service.run_l3_advisory_job_local(self, job_id=job_id)

    def run_l3_advisory_worker(
        self,
        *,
        job_id: str,
        worker_name: str,
    ) -> dict[str, Any]:
        return _l3_advisory_service.run_l3_advisory_worker(
            self,
            job_id=job_id,
            worker_name=worker_name,
        )

    def list_l3_advisory_jobs(
        self,
        *,
        session_id: str | None = None,
        state: str | None = None,
        runner: str | None = None,
    ) -> dict[str, Any]:
        return _l3_advisory_service.list_l3_advisory_jobs(
            self,
            session_id=session_id,
            state=state,
            runner=runner,
        )

    def run_next_l3_advisory_job(
        self,
        *,
        runner: str = DEFAULT_L3_ADVISORY_RUNNER,
        session_id: str | None = None,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        return _l3_advisory_service.run_next_l3_advisory_job(
            self,
            runner=runner,
            session_id=session_id,
            dry_run=dry_run,
        )

    def drain_l3_advisory_jobs(
        self,
        *,
        runner: str = DEFAULT_L3_ADVISORY_RUNNER,
        session_id: str | None = None,
        max_jobs: int = 1,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        return _l3_advisory_service.drain_l3_advisory_jobs(
            self,
            runner=runner,
            session_id=session_id,
            max_jobs=max_jobs,
            dry_run=dry_run,
        )

    def run_operator_l3_full_review(
        self,
        *,
        session_id: str,
        trigger_event_id: str,
        trigger_detail: str | None = None,
        from_record_id: int | None = None,
        to_record_id: int | None = None,
        max_records: int = 100,
        max_tool_calls: int = 0,
        runner: str = DEFAULT_L3_ADVISORY_RUNNER,
        run: bool = True,
    ) -> dict[str, Any]:
        return _l3_advisory_service.run_operator_l3_full_review(
            self,
            session_id=session_id,
            trigger_event_id=trigger_event_id,
            trigger_detail=trigger_detail,
            from_record_id=from_record_id,
            to_record_id=to_record_id,
            max_records=max_records,
            max_tool_calls=max_tool_calls,
            runner=runner,
            run=run,
        )

    @staticmethod
    def _is_l3_heartbeat_compatible_event(compat_event_type: str | None) -> str | None:
        return _l3_advisory_service._is_l3_heartbeat_compatible_event(compat_event_type)

    def _heartbeat_backlog_exists(
        self,
        *,
        session_id: str,
        runner: str,
    ) -> bool:
        return _l3_advisory_service._heartbeat_backlog_exists(
            self,
            session_id=session_id,
            runner=runner,
        )

    def _latest_terminal_heartbeat_review_to_record(self, *, session_id: str) -> int:
        return _l3_advisory_service._latest_terminal_heartbeat_review_to_record(
            self,
            session_id=session_id,
        )

    def _has_high_risk_evidence_delta(
        self,
        *,
        session_id: str,
        from_record_id: int,
        to_record_id: int,
    ) -> bool:
        return _l3_advisory_service._has_high_risk_evidence_delta(
            self,
            session_id=session_id,
            from_record_id=from_record_id,
            to_record_id=to_record_id,
        )

    def maybe_create_l3_heartbeat_advisory_snapshot(
        self,
        *,
        config: DetectionConfig,
        session_id: str,
        event_id: str,
        record_id: int,
        compat_event_type: str | None,
        runner: str = "deterministic_local",
    ) -> dict[str, Any] | None:
        return _l3_advisory_service.maybe_create_l3_heartbeat_advisory_snapshot(
            self,
            config=config,
            session_id=session_id,
            event_id=event_id,
            record_id=record_id,
            compat_event_type=compat_event_type,
            runner=runner,
        )

    def _maybe_create_l3_advisory_snapshot(
        self,
        *,
        config: DetectionConfig,
        session_id: str,
        event_id: str,
        record_id: int,
        current_risk_level: str,
        pending_trajectory_alerts: list[dict[str, Any]],
        compat_event_type: str | None = None,
    ) -> dict[str, Any] | None:
        return _l3_advisory_service._maybe_create_l3_advisory_snapshot(
            self,
            config=config,
            session_id=session_id,
            event_id=event_id,
            record_id=record_id,
            current_risk_level=current_risk_level,
            pending_trajectory_alerts=pending_trajectory_alerts,
            compat_event_type=compat_event_type,
        )

    def report_alerts(
        self,
        *,
        severity: Optional[str] = None,
        acknowledged: Optional[bool] = None,
        window_seconds: Optional[int] = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        start = time.perf_counter()
        since_seconds = (
            window_seconds if window_seconds and window_seconds > 0 else None
        )
        effective_limit = min(max(limit, 1), 1000)
        result = self.alert_registry.list_alerts(
            severity=severity,
            acknowledged=acknowledged,
            since_seconds=since_seconds,
            limit=effective_limit,
        )
        result["generated_at"] = utc_now_iso()
        result["window_seconds"] = since_seconds
        result.update(self._reporting_state())
        self._observe_reporting_io("report_alerts", time.perf_counter() - start)
        result.update(self._reporting_io_state())
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
        rpc_id: Any,
        code: int,
        message: str,
        data: Any = None,
    ) -> dict[str, Any]:
        error: dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            error["data"] = data
        return {"jsonrpc": JSONRPC_VERSION, "id": rpc_id, "error": error}

    @staticmethod
    def _jsonrpc_error_with_data(
        rpc_id: Any,
        code: int,
        error_resp: SyncDecisionErrorResponse,
    ) -> dict[str, Any]:
        return SupervisionGateway._jsonrpc_error(
            rpc_id,
            code,
            error_resp.rpc_error_message,
            error_resp.model_dump(mode="json"),
        )
