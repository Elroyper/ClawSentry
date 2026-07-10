"""FastAPI HTTP application for the supervision gateway."""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import ValidationError

from ..core.approval_bridge import _validate_rewrite_resolution_payload
from ..l3 import advisory_service as _l3_advisory_service
from clawsentry.gateway.models import (
    CanonicalEvent,
    DecisionContext,
    RPCErrorCode,
    SessionScopeProfile,
    SkillRegistryRecord,
    TaskArtifactManifest,
    SyncDecisionErrorResponse,
    utc_now_iso,
)
from clawsentry.gateway.policy.scope_task_artifacts import task_artifact_manifest_to_profile
from clawsentry.gateway.policy.session_scope import evaluate_session_scope, scope_protection_statement
from clawsentry.gateway.trust.skill_trust import record_with_skill_trust_grade
from clawsentry.gateway.trust.lifecycle import (
    apply_lifecycle_transition as _apply_lifecycle_transition,
)
from clawsentry.gateway.storage.trajectory_store import MAX_WINDOW_SECONDS
from ..trust.registry_api import (
    _consume_expired_skill_trust_lifecycle_windows,
    _find_transition_event_by_idempotency_key,
    _read_skill_trust_registry_payload,
    _registry_record_evidence_hashes,
    _transition_idempotency_matches,
    _transition_request_evidence_refs,
    _write_skill_trust_registry_payload,
)
from ..enterprise import (
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
from .ui_routes import register_ui_routes

logger = logging.getLogger("clawsentry")

_DEFAULT_UI_DIR = Path(__file__).parent.parent.parent / "ui" / "dist"


@dataclass(frozen=True)
class GatewayHttpHooks:
    apply_lifecycle_transition: Callable[..., Any] = _apply_lifecycle_transition


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
    if hasattr(analyzer, "_pattern_matcher"):
        analyzer._pattern_matcher.reload()
        return True
    if hasattr(analyzer, "_analyzers"):
        for a in analyzer._analyzers:
            if hasattr(a, "_pattern_matcher"):
                a._pattern_matcher.reload()
                return True
    return False


def create_http_app(
    gateway: Any,
    *,
    ui_dir: Path | None = None,
    hooks: GatewayHttpHooks | None = None,
) -> FastAPI:
    """Create FastAPI application for the HTTP transport."""
    hooks = hooks or GatewayHttpHooks()
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
    report_event_types = {
        "decision",
        "session_risk_change",
        "session_start",
        "alert",
        "session_enforcement_change",
        "post_action_finding",
        "trajectory_alert",
        "pattern_candidate",
        "pattern_evolved",
        "defer_pending",
        "defer_resolved",
        "budget_exhausted",
        "l3_advisory_snapshot",
        "l3_advisory_review",
        "l3_advisory_job",
        "l3_advisory_action",
        "adapter_effect_result",
    }
    enterprise_enabled = enterprise_mode_enabled()

    def _enterprise_get(path: str, **kwargs):
        def decorator(func):
            if enterprise_enabled:
                app.get(path, **kwargs)(func)
            return func

        return decorator

    # Rate limiter (0 = disabled)
    rate_limit_per_min = int(os.getenv("CS_RATE_LIMIT_PER_MINUTE", "300"))
    rate_limiter: _RateLimiter | None = None
    if rate_limit_per_min > 0:
        rate_limiter = _RateLimiter(
            max_requests=rate_limit_per_min, window_seconds=60.0
        )

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

    @app.post("/ahp/adapter-effect-result")
    async def adapter_effect_result_endpoint(request: Request):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        rl_result = _check_rate_limit(request)
        if rl_result is not None:
            return rl_result
        try:
            body = await request.json()
            result = gateway.record_adapter_effect_result(body)
        except ValidationError as exc:
            return Response(
                content=json.dumps(
                    {
                        "error": f"adapter effect result validation failed: {exc.error_count()} error(s)"
                    }
                ),
                status_code=400,
                media_type="application/json",
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("adapter effect result writeback failed")
            return Response(
                content=json.dumps(
                    {"error": f"adapter effect result writeback failed: {exc}"}
                ),
                status_code=500,
                media_type="application/json",
            )
        return Response(
            content=json.dumps(result),
            media_type="application/json",
        )

    @app.post("/ahp/scope/preview")
    async def scope_preview_endpoint(request: Request):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        rl_result = _check_rate_limit(request)
        if rl_result is not None:
            return rl_result
        try:
            body = await request.json()
            manifest_summary = None
            if body.get("manifest") is not None and body.get("profile") is not None:
                raise ValueError("use either profile or manifest, not both")
            if body.get("manifest") is not None:
                manifest = TaskArtifactManifest.model_validate(body.get("manifest"))
                conversion = task_artifact_manifest_to_profile(
                    manifest,
                    input_channel="api",
                )
                profile = conversion.profile
                manifest_summary = conversion.summary()
            else:
                profile = SessionScopeProfile.model_validate(body.get("profile"))
            if body.get("confirm") is True:
                profile = profile.model_copy(
                    update={"confirmed": True, "dry_run": False}
                )
            event = CanonicalEvent.model_validate(body.get("event"))
            evaluation = evaluate_session_scope(
                event,
                DecisionContext(session_scope_profile=profile),
            )
        except ValidationError as exc:
            return Response(
                content=json.dumps(
                    {
                        "error": f"scope preview validation failed: {exc.error_count()} error(s)"
                    }
                ),
                status_code=400,
                media_type="application/json",
            )
        except Exception as exc:  # noqa: BLE001
            return Response(
                content=json.dumps({"error": f"scope preview failed: {exc}"}),
                status_code=400,
                media_type="application/json",
            )

        summary = evaluation.summary().model_dump(mode="json") if evaluation else None
        enforced = bool(summary and summary.get("enforced"))
        return {
            "valid": True,
            "mode": "enforced" if enforced else "dry_run_only",
            "profile_id": profile.profile_id,
            "manifest": manifest_summary,
            "scope_evaluation": summary,
            "protection_statement": scope_protection_statement(enforced=enforced),
        }

    # --- a3s-code HTTP transport (B-1) ---
    from ...adapters.a3s_adapter import InProcessA3SAdapter
    from ...adapters.a3s_gateway_harness import A3SGatewayHarness

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

        body_bytes = await request.body()
        if len(body_bytes) > 10 * 1024 * 1024:
            return Response(
                content=json.dumps({"error": "Payload too large"}),
                status_code=413,
                media_type="application/json",
            )
        try:
            body = json.loads(body_bytes.decode("utf-8"))
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
    from ...adapters.codex_adapter import CodexAdapter

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
            return {
                "result": {"action": "continue", "reason": "unrecognized event type"}
            }

        # Route through in-process Gateway evaluation
        try:
            decision = await _codex_in_process.request_decision(event)
            return {
                "result": {
                    "action": decision.decision.value,
                    "reason": decision.reason,
                    "risk_level": decision.risk_level.value,
                }
            }
        except Exception:
            logger.exception("Codex endpoint evaluation failed")
            # Fail-closed: block on evaluation error to prevent unsafe operations
            return {
                "result": {
                    "action": "block",
                    "reason": "evaluation error (fail-closed)",
                }
            }

    @app.get("/health")
    async def health_endpoint():
        return gateway.health()

    @app.get("/skill-trust/registry")
    async def skill_trust_registry_endpoint(request: Request):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        registry_path = getattr(
            gateway._detection_config, "skill_trust_registry_path", None
        )
        if not registry_path:
            return Response(
                content=json.dumps({"error": "skill trust registry is not configured"}),
                status_code=404,
                media_type="application/json",
            )
        try:
            path = Path(str(registry_path)).expanduser()
            payload = _read_skill_trust_registry_payload(path)
            payload = _consume_expired_skill_trust_lifecycle_windows(path, payload)
        except FileNotFoundError:
            return Response(
                content=json.dumps({"error": "skill trust registry is unavailable"}),
                status_code=404,
                media_type="application/json",
            )
        except Exception as exc:  # noqa: BLE001
            return Response(
                content=json.dumps(
                    {"error": f"skill trust registry read failed: {exc}"}
                ),
                status_code=500,
                media_type="application/json",
            )
        return {
            "records": payload.get("records", []),
            "transition_events": payload.get("transition_events", []),
            "registry_snapshot_id": payload["registry_snapshot_id"],
            "next_cursor": None,
        }

    @app.get("/skill-trust/transition/recommendations")
    async def skill_trust_transition_recommendations_endpoint(request: Request):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        registry_path = getattr(
            gateway._detection_config, "skill_trust_registry_path", None
        )
        if not registry_path:
            return Response(
                content=json.dumps({"error": "skill trust registry is not configured"}),
                status_code=404,
                media_type="application/json",
            )
        try:
            path = Path(str(registry_path)).expanduser()
            payload = _read_skill_trust_registry_payload(path)
            payload = _consume_expired_skill_trust_lifecycle_windows(path, payload)
        except FileNotFoundError:
            return Response(
                content=json.dumps({"error": "skill trust registry is unavailable"}),
                status_code=404,
                media_type="application/json",
            )
        except Exception as exc:  # noqa: BLE001
            return Response(
                content=json.dumps(
                    {"error": f"skill trust registry read failed: {exc}"}
                ),
                status_code=500,
                media_type="application/json",
            )
        params = request.query_params
        try:
            limit = min(max(int(params.get("limit", "100")), 1), 1000)
            offset = max(int(params.get("cursor", "0")), 0)
        except ValueError:
            return Response(
                content=json.dumps({"error": "limit and cursor must be integers"}),
                status_code=400,
                media_type="application/json",
            )
        filters = {
            key: params.get(key)
            for key in (
                "canonical_skill_id",
                "metadata_record_id",
                "session_id",
                "severity",
            )
            if params.get(key)
        }
        recommendations = [
            item
            for item in payload.get("transition_recommendations", [])
            if isinstance(item, dict)
            and all(
                str(item.get(key) or "") == str(value) for key, value in filters.items()
            )
        ]
        page = recommendations[offset : offset + limit]
        next_offset = offset + limit
        return {
            "recommendations": page,
            "next_cursor": str(next_offset)
            if next_offset < len(recommendations)
            else None,
            "registry_snapshot_id": payload["registry_snapshot_id"],
        }

    @app.post("/skill-trust/transition")
    async def skill_trust_transition_endpoint(request: Request):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        registry_path = getattr(
            gateway._detection_config, "skill_trust_registry_path", None
        )
        if not registry_path:
            return Response(
                content=json.dumps({"error": "skill trust registry is not configured"}),
                status_code=404,
                media_type="application/json",
            )
        body = await request.json()
        missing = [
            key
            for key in (
                "canonical_skill_id",
                "target_state",
                "reason_code",
                "expected_registry_snapshot_id",
                "idempotency_key",
            )
            if not body.get(key)
        ]
        if missing:
            return Response(
                content=json.dumps(
                    {"error": f"missing required fields: {', '.join(missing)}"}
                ),
                status_code=400,
                media_type="application/json",
            )
        path = Path(str(registry_path)).expanduser()
        try:
            payload = _read_skill_trust_registry_payload(path)
            payload = _consume_expired_skill_trust_lifecycle_windows(path, payload)
        except FileNotFoundError:
            return Response(
                content=json.dumps({"error": "skill trust registry is unavailable"}),
                status_code=404,
                media_type="application/json",
            )
        except Exception as exc:  # noqa: BLE001
            return Response(
                content=json.dumps(
                    {"error": f"skill trust registry read failed: {exc}"}
                ),
                status_code=500,
                media_type="application/json",
            )
        current_snapshot = payload["registry_snapshot_id"]
        records = [row for row in payload.get("records", []) if isinstance(row, dict)]
        record_row = next(
            (
                row
                for row in records
                if str(row.get("canonical_skill_id") or "")
                == str(body["canonical_skill_id"])
            ),
            None,
        )
        replay_event = _find_transition_event_by_idempotency_key(
            payload,
            str(body["idempotency_key"]),
        )
        if replay_event is not None:
            if not _transition_idempotency_matches(replay_event, body):
                return Response(
                    content=json.dumps(
                        {
                            "error": "idempotency key conflict",
                            "registry_snapshot_id": current_snapshot,
                        }
                    ),
                    status_code=409,
                    media_type="application/json",
                )
            if record_row is None:
                return Response(
                    content=json.dumps({"error": "skill not found"}),
                    status_code=404,
                    media_type="application/json",
                )
            return {
                "record": record_row,
                "transition_event": replay_event,
                "registry_snapshot_id": current_snapshot,
                "idempotent_replay": True,
            }
        if str(body["expected_registry_snapshot_id"]) != current_snapshot:
            return Response(
                content=json.dumps(
                    {
                        "error": "registry snapshot conflict",
                        "registry_snapshot_id": current_snapshot,
                    }
                ),
                status_code=409,
                media_type="application/json",
            )
        if record_row is None:
            return Response(
                content=json.dumps({"error": "skill not found"}),
                status_code=404,
                media_type="application/json",
            )
        try:
            record = SkillRegistryRecord.model_validate(record_row)
            updated, event = hooks.apply_lifecycle_transition(
                record,
                target_state=str(body["target_state"]),
                reason_code=str(body["reason_code"]),
                actor_type="operator",
                operator_id_hash=(
                    str(body["operator_id_hash"])
                    if body.get("operator_id_hash")
                    else None
                ),
                override_id=str(body["override_id"])
                if body.get("override_id")
                else None,
                override_indefinite_reason=(
                    str(body["override_indefinite_reason"])
                    if body.get("override_indefinite_reason")
                    else None
                ),
                evidence_hashes=_registry_record_evidence_hashes(record),
                evidence_refs=_transition_request_evidence_refs(body),
                expected_registry_snapshot_id=current_snapshot,
                idempotency_key=str(body["idempotency_key"]),
                policy_fingerprint=record.policy_fingerprint
                or "sha256:skill-trust-lifecycle-v1",
                expires_at=str(body["expires_at"]) if body.get("expires_at") else None,
                disabled_until=str(body["disabled_until"])
                if body.get("disabled_until")
                else None,
                restore_target_state=(
                    str(body["restore_target_state"])
                    if body.get("restore_target_state")
                    else None
                ),
            )
        except ValueError as exc:
            return Response(
                content=json.dumps({"error": str(exc)}),
                status_code=422,
                media_type="application/json",
            )
        except ValidationError as exc:
            return Response(
                content=json.dumps(
                    {
                        "error": f"transition validation failed: {exc.error_count()} error(s)"
                    }
                ),
                status_code=400,
                media_type="application/json",
            )
        updated_rows = [
            row
            for row in records
            if str(row.get("canonical_skill_id") or "") != updated.canonical_skill_id
        ]
        updated_rows.append(updated.model_dump(mode="json"))
        payload["records"] = sorted(
            updated_rows, key=lambda row: str(row.get("canonical_name") or "")
        )
        payload["transition_events"] = [
            *payload.get("transition_events", []),
            event.model_dump(mode="json"),
        ]
        try:
            payload = _write_skill_trust_registry_payload(
                path,
                payload,
                expected_registry_snapshot_id=current_snapshot,
            )
        except ValueError as exc:
            if str(exc) == "registry snapshot conflict":
                latest_payload = _read_skill_trust_registry_payload(path)
                return Response(
                    content=json.dumps(
                        {
                            "error": "registry snapshot conflict",
                            "registry_snapshot_id": latest_payload[
                                "registry_snapshot_id"
                            ],
                        }
                    ),
                    status_code=409,
                    media_type="application/json",
                )
            raise
        return {
            "record": record_with_skill_trust_grade(updated),
            "transition_event": event.model_dump(mode="json"),
            "registry_snapshot_id": payload["registry_snapshot_id"],
            "idempotent_replay": False,
        }

    @_enterprise_get("/enterprise/health")
    async def enterprise_health_endpoint(request: Request):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        return await enrich_health_payload_async(gateway.health(), gateway)

    # --- P3: Prometheus /metrics endpoint ---
    _metrics_auth_enabled = os.getenv("CS_METRICS_AUTH", "").lower() in (
        "1",
        "true",
        "yes",
    )

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
    async def report_summary_endpoint(
        request: Request, window_seconds: Optional[int] = None
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if window_seconds is not None and (
            window_seconds < 1 or window_seconds > MAX_WINDOW_SECONDS
        ):
            return Response(
                content=json.dumps(
                    {
                        "error": f"window_seconds must be between 1 and {MAX_WINDOW_SECONDS}"
                    }
                ),
                status_code=400,
                media_type="application/json",
            )
        return gateway.report_summary(window_seconds=window_seconds)

    @app.get("/report/policy-drift")
    async def report_policy_drift_endpoint(
        request: Request,
        window_seconds: Optional[int] = 3600,
        max_cells: int = 200,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if window_seconds is not None and (
            window_seconds < 1 or window_seconds > MAX_WINDOW_SECONDS
        ):
            return Response(
                content=json.dumps(
                    {
                        "error": f"window_seconds must be between 1 and {MAX_WINDOW_SECONDS}"
                    }
                ),
                status_code=400,
                media_type="application/json",
            )
        return gateway.report_policy_drift(
            window_seconds=window_seconds,
            max_cells=min(max(max_cells, 1), 1000),
        )

    @_enterprise_get("/enterprise/report/summary")
    async def enterprise_report_summary_endpoint(
        request: Request,
        window_seconds: Optional[int] = None,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if window_seconds is not None and (
            window_seconds < 1 or window_seconds > MAX_WINDOW_SECONDS
        ):
            return Response(
                content=json.dumps(
                    {
                        "error": f"window_seconds must be between 1 and {MAX_WINDOW_SECONDS}"
                    }
                ),
                status_code=400,
                media_type="application/json",
            )
        return await enrich_summary_payload_async(
            gateway.report_summary(window_seconds=window_seconds),
            gateway,
            window_seconds=window_seconds,
        )

    @_enterprise_get("/enterprise/report/policy-drift")
    async def enterprise_report_policy_drift_endpoint(
        request: Request,
        window_seconds: Optional[int] = 3600,
        max_cells: int = 1000,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if window_seconds is not None and (
            window_seconds < 1 or window_seconds > MAX_WINDOW_SECONDS
        ):
            return Response(
                content=json.dumps(
                    {
                        "error": f"window_seconds must be between 1 and {MAX_WINDOW_SECONDS}"
                    }
                ),
                status_code=400,
                media_type="application/json",
            )
        return gateway.report_policy_drift(
            window_seconds=window_seconds,
            max_cells=min(max(max_cells, 1), 5000),
        )

    @_enterprise_get("/enterprise/report/live")
    async def enterprise_report_live_endpoint(request: Request, cached: bool = False):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if cached:
            return await build_enterprise_live_snapshot_cached_async(gateway)
        return await build_enterprise_live_snapshot_cached_async(
            gateway, force_refresh=True
        )

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
        if min_risk is not None and min_risk not in {
            "low",
            "medium",
            "high",
            "critical",
        }:
            return Response(
                content=json.dumps(
                    {"error": "min_risk must be one of: low, medium, high, critical"}
                ),
                status_code=400,
                media_type="application/json",
            )

        event_types = set(report_event_types)
        if types:
            requested_types = {
                item.strip() for item in types.split(",") if item.strip()
            }
            if not requested_types or not requested_types.issubset(event_types):
                return Response(
                    content=json.dumps(
                        {
                            "error": "types must be a comma-separated subset of: decision, session_risk_change, session_start, alert, session_enforcement_change, post_action_finding, trajectory_alert, pattern_candidate, pattern_evolved, defer_pending, defer_resolved, adapter_effect_result, budget_exhausted, l3_advisory_snapshot, l3_advisory_review, l3_advisory_job, l3_advisory_action"
                        }
                    ),
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

    @_enterprise_get("/enterprise/report/stream")
    async def enterprise_report_stream_endpoint(
        request: Request,
        session_id: Optional[str] = None,
        min_risk: Optional[str] = None,
        types: Optional[str] = None,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if min_risk is not None and min_risk not in {
            "low",
            "medium",
            "high",
            "critical",
        }:
            return Response(
                content=json.dumps(
                    {"error": "min_risk must be one of: low, medium, high, critical"}
                ),
                status_code=400,
                media_type="application/json",
            )

        event_types = set(report_event_types)
        if types:
            requested_types = {
                item.strip() for item in types.split(",") if item.strip()
            }
            if not requested_types or not requested_types.issubset(event_types):
                return Response(
                    content=json.dumps(
                        {
                            "error": "types must be a comma-separated subset of: decision, session_risk_change, session_start, alert, session_enforcement_change, post_action_finding, trajectory_alert, pattern_candidate, pattern_evolved, defer_pending, defer_resolved, adapter_effect_result, budget_exhausted, l3_advisory_snapshot, l3_advisory_review, l3_advisory_job, l3_advisory_action"
                        }
                    ),
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
            yield ": connected\n\n"
            try:
                while True:
                    try:
                        event = await asyncio.wait_for(queue.get(), timeout=15.0)
                        event_type = str(event.get("type") or "message")
                        payload = await build_enterprise_event_async(
                            {**event, "type": event_type}, gateway
                        )
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
        if window_seconds is not None and (
            window_seconds < 1 or window_seconds > MAX_WINDOW_SECONDS
        ):
            return Response(
                content=json.dumps(
                    {
                        "error": f"window_seconds must be between 1 and {MAX_WINDOW_SECONDS}"
                    }
                ),
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
                content=json.dumps(
                    {"error": "sort must be one of: risk_level, last_event"}
                ),
                status_code=400,
                media_type="application/json",
            )
        if min_risk is not None and min_risk not in {
            "low",
            "medium",
            "high",
            "critical",
        }:
            return Response(
                content=json.dumps(
                    {"error": "min_risk must be one of: low, medium, high, critical"}
                ),
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

    @_enterprise_get("/enterprise/report/sessions")
    async def enterprise_report_sessions_endpoint(
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
        if window_seconds is not None and (
            window_seconds < 1 or window_seconds > MAX_WINDOW_SECONDS
        ):
            return Response(
                content=json.dumps(
                    {
                        "error": f"window_seconds must be between 1 and {MAX_WINDOW_SECONDS}"
                    }
                ),
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
                content=json.dumps(
                    {"error": "sort must be one of: risk_level, last_event"}
                ),
                status_code=400,
                media_type="application/json",
            )
        if min_risk is not None and min_risk not in {
            "low",
            "medium",
            "high",
            "critical",
        }:
            return Response(
                content=json.dumps(
                    {"error": "min_risk must be one of: low, medium, high, critical"}
                ),
                status_code=400,
                media_type="application/json",
            )
        effective_limit = min(max(limit, 1), 5000)
        return await enrich_sessions_payload_async(
            gateway.report_sessions(
                status=status,
                sort=sort,
                limit=effective_limit,
                min_risk=min_risk,
                window_seconds=window_seconds,
                max_limit=5000,
            ),
            gateway,
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
        if window_seconds is not None and (
            window_seconds < 1 or window_seconds > MAX_WINDOW_SECONDS
        ):
            return Response(
                content=json.dumps(
                    {
                        "error": f"window_seconds must be between 1 and {MAX_WINDOW_SECONDS}"
                    }
                ),
                status_code=400,
                media_type="application/json",
            )
        effective_limit = min(max(limit, 1), 1000)
        return gateway.report_session_risk(
            session_id=session_id,
            limit=effective_limit,
            window_seconds=window_seconds,
        )

    @app.get("/report/session/{session_id}/post-action")
    async def report_session_post_action_scores_endpoint(
        request: Request,
        session_id: str,
        limit: int = 100,
        window_seconds: Optional[int] = None,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if window_seconds is not None and (
            window_seconds < 1 or window_seconds > MAX_WINDOW_SECONDS
        ):
            return Response(
                content=json.dumps(
                    {
                        "error": f"window_seconds must be between 1 and {MAX_WINDOW_SECONDS}"
                    }
                ),
                status_code=400,
                media_type="application/json",
            )
        effective_limit = min(max(limit, 1), 1000)
        return gateway.report_session_post_action_scores(
            session_id=session_id,
            limit=effective_limit,
            window_seconds=window_seconds,
        )

    _l3_advisory_service.register_l3_advisory_routes(
        app, gateway, verify_auth, _check_rate_limit
    )

    @_enterprise_get("/enterprise/report/session/{session_id}/risk")
    async def enterprise_report_session_risk_endpoint(
        request: Request,
        session_id: str,
        limit: int = 100,
        window_seconds: Optional[int] = None,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if window_seconds is not None and (
            window_seconds < 1 or window_seconds > MAX_WINDOW_SECONDS
        ):
            return Response(
                content=json.dumps(
                    {
                        "error": f"window_seconds must be between 1 and {MAX_WINDOW_SECONDS}"
                    }
                ),
                status_code=400,
                media_type="application/json",
            )
        effective_limit = min(max(limit, 1), 1000)
        return await enrich_session_risk_payload_async(
            gateway.report_session_risk(
                session_id=session_id,
                limit=effective_limit,
                window_seconds=window_seconds,
            ),
            gateway,
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
        if window_seconds is not None and (
            window_seconds < 1 or window_seconds > MAX_WINDOW_SECONDS
        ):
            return Response(
                content=json.dumps(
                    {
                        "error": f"window_seconds must be between 1 and {MAX_WINDOW_SECONDS}"
                    }
                ),
                status_code=400,
                media_type="application/json",
            )
        effective_limit = min(max(limit, 1), 1000)
        return gateway.replay_session(
            session_id=session_id,
            limit=effective_limit,
            window_seconds=window_seconds,
        )

    @_enterprise_get("/enterprise/report/session/{session_id}")
    async def enterprise_report_session_endpoint(
        request: Request,
        session_id: str,
        limit: int = 100,
        window_seconds: Optional[int] = None,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if window_seconds is not None and (
            window_seconds < 1 or window_seconds > MAX_WINDOW_SECONDS
        ):
            return Response(
                content=json.dumps(
                    {
                        "error": f"window_seconds must be between 1 and {MAX_WINDOW_SECONDS}"
                    }
                ),
                status_code=400,
                media_type="application/json",
            )
        effective_limit = min(max(limit, 1), 1000)
        return await enrich_replay_payload_async(
            gateway.replay_session(
                session_id=session_id,
                limit=effective_limit,
                window_seconds=window_seconds,
            )
        )

    @app.get("/report/session/{session_id}/page")
    async def report_session_page_endpoint(
        request: Request,
        session_id: str,
        limit: int = 100,
        cursor: Optional[int] = None,
        window_seconds: Optional[int] = None,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if window_seconds is not None and (
            window_seconds < 1 or window_seconds > MAX_WINDOW_SECONDS
        ):
            return Response(
                content=json.dumps(
                    {
                        "error": f"window_seconds must be between 1 and {MAX_WINDOW_SECONDS}"
                    }
                ),
                status_code=400,
                media_type="application/json",
            )
        if cursor is not None and cursor < 1:
            return Response(
                content=json.dumps({"error": "cursor must be >= 1"}),
                status_code=400,
                media_type="application/json",
            )
        effective_limit = min(max(limit, 1), 500)
        return gateway.replay_session_page(
            session_id=session_id,
            limit=effective_limit,
            cursor=cursor,
            window_seconds=window_seconds,
        )

    @_enterprise_get("/enterprise/report/session/{session_id}/page")
    async def enterprise_report_session_page_endpoint(
        request: Request,
        session_id: str,
        limit: int = 100,
        cursor: Optional[int] = None,
        window_seconds: Optional[int] = None,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if window_seconds is not None and (
            window_seconds < 1 or window_seconds > MAX_WINDOW_SECONDS
        ):
            return Response(
                content=json.dumps(
                    {
                        "error": f"window_seconds must be between 1 and {MAX_WINDOW_SECONDS}"
                    }
                ),
                status_code=400,
                media_type="application/json",
            )
        if cursor is not None and cursor < 1:
            return Response(
                content=json.dumps({"error": "cursor must be >= 1"}),
                status_code=400,
                media_type="application/json",
            )
        effective_limit = min(max(limit, 1), 500)
        return await enrich_replay_payload_async(
            gateway.replay_session_page(
                session_id=session_id,
                limit=effective_limit,
                cursor=cursor,
                window_seconds=window_seconds,
            )
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
        if severity is not None and severity not in {
            "low",
            "medium",
            "high",
            "critical",
        }:
            return Response(
                content=json.dumps(
                    {"error": "severity must be one of: low, medium, high, critical"}
                ),
                status_code=400,
                media_type="application/json",
            )
        if acknowledged is not None and acknowledged not in {"true", "false"}:
            return Response(
                content=json.dumps({"error": "acknowledged must be 'true' or 'false'"}),
                status_code=400,
                media_type="application/json",
            )
        if window_seconds is not None and (
            window_seconds < 1 or window_seconds > MAX_WINDOW_SECONDS
        ):
            return Response(
                content=json.dumps(
                    {
                        "error": f"window_seconds must be between 1 and {MAX_WINDOW_SECONDS}"
                    }
                ),
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

    @_enterprise_get("/enterprise/report/alerts")
    async def enterprise_report_alerts_endpoint(
        request: Request,
        severity: Optional[str] = None,
        acknowledged: Optional[str] = None,
        window_seconds: Optional[int] = None,
        limit: int = 100,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if severity is not None and severity not in {
            "low",
            "medium",
            "high",
            "critical",
        }:
            return Response(
                content=json.dumps(
                    {"error": "severity must be one of: low, medium, high, critical"}
                ),
                status_code=400,
                media_type="application/json",
            )
        if acknowledged is not None and acknowledged not in {"true", "false"}:
            return Response(
                content=json.dumps({"error": "acknowledged must be 'true' or 'false'"}),
                status_code=400,
                media_type="application/json",
            )
        if window_seconds is not None and (
            window_seconds < 1 or window_seconds > MAX_WINDOW_SECONDS
        ):
            return Response(
                content=json.dumps(
                    {
                        "error": f"window_seconds must be between 1 and {MAX_WINDOW_SECONDS}"
                    }
                ),
                status_code=400,
                media_type="application/json",
            )
        ack_filter: Optional[bool] = None
        if acknowledged is not None:
            ack_filter = acknowledged == "true"
        effective_limit = min(max(limit, 1), 1000)
        return await enrich_alerts_payload_async(
            gateway.report_alerts(
                severity=severity,
                acknowledged=ack_filter,
                window_seconds=window_seconds,
                limit=effective_limit,
            ),
            gateway,
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

    @app.get("/report/session/{session_id}/quarantine")
    async def get_quarantine_endpoint(request: Request, session_id: str):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        return {
            "session_id": session_id,
            "quarantine": gateway.session_registry.get_quarantine(session_id),
        }

    @app.post("/report/session/{session_id}/quarantine")
    async def post_quarantine_endpoint(request: Request, session_id: str):
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
        released = gateway.session_registry.release_quarantine(
            session_id,
            released_by=str(body.get("released_by") or "operator"),
            reason=(
                str(body.get("reason")) if body.get("reason") is not None else None
            ),
        )
        gateway.event_bus.broadcast(
            {
                "type": "session_enforcement_change",
                "session_id": session_id,
                "state": "quarantine_released" if released else "quarantine_not_found",
                "action": None,
                "high_risk_count": None,
                "timestamp": utc_now_iso(),
            }
        )
        return {
            "session_id": session_id,
            "released": released,
            "quarantine": gateway.session_registry.get_quarantine(session_id),
        }

    # --- E-5: Self-evolving pattern endpoints ---

    @app.get("/ahp/patterns")
    async def list_patterns_endpoint(request: Request):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        status = gateway.evolution_manager.status()
        return Response(
            content=json.dumps(
                {
                    **status,
                    "patterns": gateway.evolution_manager.list_patterns(),
                }
            ),
            media_type="application/json",
        )

    @app.post("/ahp/patterns/confirm")
    async def confirm_pattern_endpoint(request: Request):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if not gateway.evolution_manager._enabled:
            return Response(
                content=json.dumps(
                    {"error": "pattern evolution is disabled (CS_EVOLVING_ENABLED=0)"}
                ),
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
        if not pattern_id or not isinstance(confirmed, bool):
            return Response(
                content=json.dumps(
                    {"error": "pattern_id and confirmed (bool) are required"}
                ),
                status_code=400,
                media_type="application/json",
            )
        result = gateway.evolution_manager.confirm(pattern_id, confirmed=confirmed)
        if result == "not_found":
            return Response(
                content=json.dumps({"error": "pattern not found"}),
                status_code=404,
                media_type="application/json",
            )
        # Broadcast SSE event
        gateway.event_bus.broadcast(
            {
                "type": "pattern_evolved",
                "pattern_id": pattern_id,
                "action": result,
                "result": result,
                "timestamp": utc_now_iso(),
            }
        )
        # Trigger hot-reload so new experimental/stable patterns take effect
        if result in ("promoted_to_experimental", "promoted_to_stable"):
            if not _find_and_reload_pattern_matcher(gateway.policy_engine._analyzer):
                logger.warning(
                    "could not hot-reload PatternMatcher: no RuleBasedAnalyzer found"
                )
        return Response(
            content=json.dumps({"result": result, "pattern_id": pattern_id}),
            media_type="application/json",
        )

    # --- Web Dashboard UI (static SPA) ---
    register_ui_routes(app, ui_dir if ui_dir is not None else _DEFAULT_UI_DIR)

    return app
