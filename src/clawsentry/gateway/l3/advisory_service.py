"""L3 advisory service helpers for gateway snapshots, jobs, reviews, and routes."""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

from fastapi import Request, Response

from clawsentry.gateway.config.detection_config import DetectionConfig
from clawsentry.gateway.models import DecisionTier, utc_now_iso
from ..reporting.service import _copy_l3_narrative_fields
from clawsentry.gateway.storage.trajectory_store import HIGH_RISK_LEVELS

logger = logging.getLogger("clawsentry")

DEFAULT_L3_ADVISORY_RUNNER = "llm_provider"
PUBLIC_L3_ADVISORY_RUNNERS = {"deterministic_local", DEFAULT_L3_ADVISORY_RUNNER}
_RISK_LEVEL_RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _risk_rank(risk_level: Optional[str]) -> int:
    return _RISK_LEVEL_RANK.get(str(risk_level or "low").lower(), 0)


def _validate_public_l3_advisory_runner(runner: str) -> None:
    if runner not in PUBLIC_L3_ADVISORY_RUNNERS:
        raise ValueError(
            "runner must be one of: "
            f"{', '.join(sorted(PUBLIC_L3_ADVISORY_RUNNERS))}; "
            "fake_llm is reserved for internal tests"
        )


def _analyzer_supports_l3(analyzer: Any) -> bool:
    """Return True when analyzer tree includes an L3-capable analyzer."""
    if analyzer is None:
        return False
    analyzer_id = str(getattr(analyzer, "analyzer_id", "") or "")
    if analyzer_id == "agent-reviewer":
        return True
    for child in getattr(analyzer, "_analyzers", []) or []:
        if _analyzer_supports_l3(child):
            return True
    return False


def _effective_requested_tier_for_l3_config(
    requested_tier: DecisionTier,
    config: DetectionConfig,
    analyzer: Any,
) -> DecisionTier:
    if (
        requested_tier == DecisionTier.L2
        and config.l3_routing_mode == "replace_l2"
        and _analyzer_supports_l3(analyzer)
    ):
        return DecisionTier.L3
    return requested_tier


def _l3_advisory_payload(gateway, session_id: str) -> dict[str, Any]:
    snapshots = gateway.trajectory_store.list_l3_evidence_snapshots(session_id=session_id)
    reviews = gateway.trajectory_store.list_l3_advisory_reviews(session_id=session_id)
    jobs = gateway.trajectory_store.list_l3_advisory_jobs(session_id=session_id)
    latest_review = reviews[-1] if reviews else None
    latest_job = jobs[-1] if jobs else None
    latest_snapshot = None
    if latest_review is not None:
        latest_snapshot = gateway.trajectory_store.get_l3_evidence_snapshot(
            str(latest_review.get("snapshot_id") or "")
        )
        matching_jobs = [
            job for job in jobs
            if job.get("review_id") == latest_review.get("review_id")
            or job.get("snapshot_id") == latest_review.get("snapshot_id")
        ]
        if matching_jobs:
            latest_job = matching_jobs[-1]
    latest_action = gateway.trajectory_store.build_l3_advisory_action_summary(
        review=latest_review,
        job=latest_job,
        snapshot=latest_snapshot,
    )
    return {
        "snapshots": snapshots,
        "reviews": reviews,
        "jobs": jobs,
        "latest_review": latest_review,
        "latest_job": latest_job,
        "latest_action": latest_action,
    }

def _l3_advisory_action_for_review(
    gateway,
    review: dict[str, Any] | None,
    *,
    job: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    if review is None:
        return None
    snapshot = gateway.trajectory_store.get_l3_evidence_snapshot(
        str(review.get("snapshot_id") or "")
    )
    if job is None:
        candidates = gateway.trajectory_store.list_l3_advisory_jobs(
            session_id=str(review.get("session_id") or ""),
            snapshot_id=str(review.get("snapshot_id") or ""),
        )
        for candidate in reversed(candidates):
            if candidate.get("review_id") == review.get("review_id"):
                job = candidate
                break
        if job is None and candidates:
            job = candidates[-1]
    return gateway.trajectory_store.build_l3_advisory_action_summary(
        review=review,
        job=job,
        snapshot=snapshot,
    )

def _broadcast_l3_advisory_action(
    gateway,
    review: dict[str, Any] | None,
    *,
    job: dict[str, Any] | None = None,
) -> None:
    action = gateway._l3_advisory_action_for_review(review, job=job)
    if action is None:
        return
    event = dict(action)
    event["timestamp"] = action.get("created_at") or utc_now_iso()
    gateway.event_bus.broadcast(event)

def create_l3_evidence_snapshot(
    gateway,
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
    snapshot = gateway.trajectory_store.create_l3_evidence_snapshot(
        session_id=session_id,
        trigger_event_id=trigger_event_id,
        trigger_reason=trigger_reason,
        trigger_detail=trigger_detail,
        to_record_id=to_record_id,
        from_record_id=from_record_id,
        max_records=max_records,
        max_tool_calls=max_tool_calls,
    )
    gateway.event_bus.broadcast({
        "type": "l3_advisory_snapshot",
        "session_id": session_id,
        "snapshot_id": snapshot["snapshot_id"],
        "trigger_event_id": trigger_event_id,
        "trigger_reason": trigger_reason,
        "trigger_detail": trigger_detail,
        "event_range": snapshot["event_range"],
        "advisory_only": True,
        "canonical_decision_mutated": False,
        "timestamp": snapshot["created_at"],
    })
    return snapshot

def record_l3_advisory_review(
    gateway,
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
    review = gateway.trajectory_store.record_l3_advisory_review(
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
    gateway.event_bus.broadcast({
        "type": "l3_advisory_review",
        "session_id": review["session_id"],
        "snapshot_id": snapshot_id,
        "review_id": review["review_id"],
        "risk_level": review["risk_level"],
        "recommended_operator_action": review["recommended_operator_action"],
        "l3_state": review["l3_state"],
        "l3_reason_code": review.get("l3_reason_code"),
        "advisory_only": True,
        "canonical_decision_mutated": False,
        "timestamp": review["created_at"],
        **_copy_l3_narrative_fields(review),
    })
    gateway._broadcast_l3_advisory_action(review)
    return review

def update_l3_advisory_review(
    gateway,
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
    review = gateway.trajectory_store.update_l3_advisory_review(
        review_id,
        risk_level=risk_level,
        findings=findings,
        confidence=confidence,
        recommended_operator_action=recommended_operator_action,
        l3_state=l3_state,
        l3_reason_code=l3_reason_code,
        extra_fields=extra_fields,
    )
    gateway.event_bus.broadcast({
        "type": "l3_advisory_review",
        "session_id": review["session_id"],
        "snapshot_id": review["snapshot_id"],
        "review_id": review["review_id"],
        "risk_level": review["risk_level"],
        "recommended_operator_action": review["recommended_operator_action"],
        "l3_state": review["l3_state"],
        "l3_reason_code": review.get("l3_reason_code"),
        "advisory_only": True,
        "canonical_decision_mutated": False,
        "timestamp": review.get("completed_at") or review["created_at"],
        **_copy_l3_narrative_fields(review),
    })
    gateway._broadcast_l3_advisory_action(review)
    return review

def run_local_l3_advisory_review(gateway, *, snapshot_id: str) -> dict[str, Any]:
    review = gateway.trajectory_store.run_local_l3_advisory_review(snapshot_id)
    gateway.event_bus.broadcast({
        "type": "l3_advisory_review",
        "session_id": review["session_id"],
        "snapshot_id": review["snapshot_id"],
        "review_id": review["review_id"],
        "risk_level": review["risk_level"],
        "recommended_operator_action": review["recommended_operator_action"],
        "l3_state": review["l3_state"],
        "l3_reason_code": review.get("l3_reason_code"),
        "advisory_only": True,
        "canonical_decision_mutated": False,
        "timestamp": review.get("completed_at") or review["created_at"],
        **_copy_l3_narrative_fields(review),
    })
    gateway._broadcast_l3_advisory_action(review)
    return review

def enqueue_l3_advisory_job(
    gateway,
    *,
    snapshot_id: str,
    runner: str = DEFAULT_L3_ADVISORY_RUNNER,
) -> dict[str, Any]:
    _validate_public_l3_advisory_runner(runner)
    job = gateway.trajectory_store.enqueue_l3_advisory_job(
        snapshot_id,
        runner=runner,
    )
    gateway.event_bus.broadcast({
        "type": "l3_advisory_job",
        "session_id": job["session_id"],
        "snapshot_id": job["snapshot_id"],
        "job_id": job["job_id"],
        "job_state": job["job_state"],
        "runner": job["runner"],
        "advisory_only": True,
        "canonical_decision_mutated": False,
        "timestamp": job["updated_at"],
    })
    return job

def run_l3_advisory_job_local(gateway, *, job_id: str) -> dict[str, Any]:
    result = gateway.trajectory_store.run_l3_advisory_job_local(job_id)
    job = result["job"]
    review = result["review"]
    gateway.event_bus.broadcast({
        "type": "l3_advisory_job",
        "session_id": job["session_id"],
        "snapshot_id": job["snapshot_id"],
        "job_id": job["job_id"],
        "job_state": job["job_state"],
        "runner": job["runner"],
        "review_id": job.get("review_id"),
        "advisory_only": True,
        "canonical_decision_mutated": False,
        "timestamp": job["updated_at"],
    })
    gateway.event_bus.broadcast({
        "type": "l3_advisory_review",
        "session_id": review["session_id"],
        "snapshot_id": review["snapshot_id"],
        "review_id": review["review_id"],
        "risk_level": review["risk_level"],
        "recommended_operator_action": review["recommended_operator_action"],
        "l3_state": review["l3_state"],
        "advisory_only": True,
        "canonical_decision_mutated": False,
        "timestamp": review.get("completed_at") or review["created_at"],
        **_copy_l3_narrative_fields(review),
    })
    action = gateway._l3_advisory_action_for_review(review, job=job)
    gateway._broadcast_l3_advisory_action(review, job=job)
    return {**result, "action": action, "advisory_only": True, "canonical_decision_mutated": False}

def run_l3_advisory_worker(
    gateway,
    *,
    job_id: str,
    worker_name: str,
) -> dict[str, Any]:
    from clawsentry.gateway.l3.advisory_worker import (
        FakeLLMAdvisoryWorker,
        LLMProviderAdvisoryWorker,
        run_l3_advisory_worker_job,
    )

    workers = {
        FakeLLMAdvisoryWorker.runner_name: FakeLLMAdvisoryWorker(),
        LLMProviderAdvisoryWorker.runner_name: LLMProviderAdvisoryWorker(),
    }
    worker = workers.get(worker_name)
    if worker is None:
        raise ValueError(f"unsupported advisory worker {worker_name!r}")
    job = gateway.trajectory_store.get_l3_advisory_job(job_id)
    if job is None:
        raise ValueError(f"job {job_id!r} was not found")
    if job.get("runner") != worker.runner_name:
        raise ValueError(
            f"job runner {job.get('runner')!r} does not match worker {worker.runner_name!r}"
        )

    result = run_l3_advisory_worker_job(
        store=gateway.trajectory_store,
        job_id=job_id,
        worker=worker,
    )
    job = result["job"]
    review = result["review"]
    gateway.event_bus.broadcast({
        "type": "l3_advisory_job",
        "session_id": job["session_id"],
        "snapshot_id": job["snapshot_id"],
        "job_id": job["job_id"],
        "job_state": job["job_state"],
        "runner": job["runner"],
        "review_id": job.get("review_id"),
        "advisory_only": True,
        "canonical_decision_mutated": False,
        "timestamp": job["updated_at"],
    })
    gateway.event_bus.broadcast({
        "type": "l3_advisory_review",
        "session_id": review["session_id"],
        "snapshot_id": review["snapshot_id"],
        "review_id": review["review_id"],
        "risk_level": review["risk_level"],
        "recommended_operator_action": review["recommended_operator_action"],
        "l3_state": review["l3_state"],
        "advisory_only": True,
        "canonical_decision_mutated": False,
        "timestamp": review.get("completed_at") or review["created_at"],
        **_copy_l3_narrative_fields(review),
    })
    action = gateway._l3_advisory_action_for_review(review, job=job)
    gateway._broadcast_l3_advisory_action(review, job=job)
    return {**result, "action": action, "advisory_only": True, "canonical_decision_mutated": False}

def list_l3_advisory_jobs(
    gateway,
    *,
    session_id: str | None = None,
    state: str | None = None,
    runner: str | None = None,
) -> dict[str, Any]:
    jobs = gateway.trajectory_store.list_l3_advisory_jobs(
        session_id=session_id,
        job_state=state,
        runner=runner,
    )
    return {
        "jobs": jobs,
        "count": len(jobs),
        "advisory_only": True,
        "canonical_decision_mutated": False,
    }

def run_next_l3_advisory_job(
    gateway,
    *,
    runner: str = DEFAULT_L3_ADVISORY_RUNNER,
    session_id: str | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    _validate_public_l3_advisory_runner(runner)
    queued = gateway.trajectory_store.list_l3_advisory_jobs(
        session_id=session_id,
        job_state="queued",
        runner=runner,
    )
    selected = queued[0] if queued else None
    if dry_run:
        return {
            "selected_jobs": [selected] if selected else [],
            "result": None,
            "ran_count": 0,
            "dry_run": True,
            "advisory_only": True,
            "canonical_decision_mutated": False,
        }
    if selected is None:
        return {
            "selected_jobs": [],
            "result": None,
            "ran_count": 0,
            "dry_run": False,
            "advisory_only": True,
            "canonical_decision_mutated": False,
        }
    if runner == "deterministic_local":
        result = gateway.run_l3_advisory_job_local(job_id=selected["job_id"])
    else:
        result = gateway.run_l3_advisory_worker(
            job_id=selected["job_id"],
            worker_name=runner,
        )
    return {
        "selected_jobs": [selected],
        "result": result,
        "ran_count": 1,
        "dry_run": False,
        "advisory_only": True,
        "canonical_decision_mutated": False,
    }

def drain_l3_advisory_jobs(
    gateway,
    *,
    runner: str = DEFAULT_L3_ADVISORY_RUNNER,
    session_id: str | None = None,
    max_jobs: int = 1,
    dry_run: bool = False,
) -> dict[str, Any]:
    _validate_public_l3_advisory_runner(runner)
    if max_jobs < 1 or max_jobs > 10:
        raise ValueError("max_jobs must be between 1 and 10")
    queued = gateway.trajectory_store.list_l3_advisory_jobs(
        session_id=session_id,
        job_state="queued",
        runner=runner,
    )
    selected = queued[:max_jobs]
    if dry_run:
        return {
            "selected_jobs": selected,
            "results": [],
            "ran_count": 0,
            "max_jobs": max_jobs,
            "dry_run": True,
            "advisory_only": True,
            "canonical_decision_mutated": False,
        }

    results: list[dict[str, Any]] = []
    for _ in range(max_jobs):
        next_result = gateway.run_next_l3_advisory_job(
            runner=runner,
            session_id=session_id,
            dry_run=False,
        )
        if next_result.get("ran_count") != 1 or next_result.get("result") is None:
            break
        results.append(next_result["result"])
    return {
        "selected_jobs": selected,
        "results": results,
        "ran_count": len(results),
        "max_jobs": max_jobs,
        "dry_run": False,
        "advisory_only": True,
        "canonical_decision_mutated": False,
    }

def run_operator_l3_full_review(
    gateway,
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
    _validate_public_l3_advisory_runner(runner)
    snapshot = gateway.create_l3_evidence_snapshot(
        session_id=session_id,
        trigger_event_id=trigger_event_id,
        trigger_reason="operator_full_review",
        trigger_detail=trigger_detail or "operator_requested_full_review",
        from_record_id=from_record_id,
        to_record_id=to_record_id,
        max_records=max_records,
        max_tool_calls=max_tool_calls,
    )
    job = gateway.enqueue_l3_advisory_job(
        snapshot_id=snapshot["snapshot_id"],
        runner=runner,
    )
    review = None
    completed_job = job
    if run:
        if runner == "deterministic_local":
            result = gateway.run_l3_advisory_job_local(job_id=job["job_id"])
        else:
            result = gateway.run_l3_advisory_worker(
                job_id=job["job_id"],
                worker_name=runner,
            )
        completed_job = result["job"]
        review = result["review"]
    return {
        "snapshot": snapshot,
        "job": completed_job,
        "review": review,
        "action": gateway._l3_advisory_action_for_review(review, job=completed_job),
        "advisory_only": True,
        "canonical_decision_mutated": False,
    }

def _is_l3_heartbeat_compatible_event(compat_event_type: str | None) -> str | None:
    compat = str(compat_event_type or "").strip().lower()
    if compat in {"heartbeat", "idle", "success", "rate_limit"}:
        return compat
    return None

def _heartbeat_backlog_exists(
    gateway,
    *,
    session_id: str,
    runner: str,
) -> bool:
    for job in gateway.trajectory_store.list_l3_advisory_jobs(
        session_id=session_id,
        runner=runner,
    ):
        if job.get("job_state") not in {"queued", "running"}:
            continue
        snapshot = gateway.trajectory_store.get_l3_evidence_snapshot(
            str(job.get("snapshot_id") or "")
        )
        if snapshot and snapshot.get("trigger_reason") == "heartbeat_aggregate":
            return True
    return False

def _latest_terminal_heartbeat_review_to_record(gateway, *, session_id: str) -> int:
    latest_to_record = 0
    for review in gateway.trajectory_store.list_l3_advisory_reviews(session_id=session_id):
        if str(review.get("l3_state") or "") not in {"completed", "failed", "degraded"}:
            continue
        snapshot = gateway.trajectory_store.get_l3_evidence_snapshot(
            str(review.get("snapshot_id") or "")
        )
        if not snapshot or snapshot.get("trigger_reason") != "heartbeat_aggregate":
            continue
        event_range = snapshot.get("event_range") or {}
        latest_to_record = max(latest_to_record, int(event_range.get("to_record_id") or 0))
    return latest_to_record

def _has_high_risk_evidence_delta(
    gateway,
    *,
    session_id: str,
    from_record_id: int,
    to_record_id: int,
) -> bool:
    records = gateway.trajectory_store._query_records_by_id_range(
        session_id=session_id,
        from_record_id=max(from_record_id, 1),
        to_record_id=to_record_id,
    )
    for record in records:
        risk_level = str(
            record.get("decision", {}).get("risk_level")
            or record.get("risk_snapshot", {}).get("risk_level")
            or "low"
        ).lower()
        if risk_level in HIGH_RISK_LEVELS:
            return True
    return False

def maybe_create_l3_heartbeat_advisory_snapshot(
    gateway,
    *,
    config: DetectionConfig,
    session_id: str,
    event_id: str,
    record_id: int,
    compat_event_type: str | None,
    runner: str = "deterministic_local",
) -> dict[str, Any] | None:
    """Queue one heartbeat aggregate advisory job when flags and evidence allow it."""

    compat = gateway._is_l3_heartbeat_compatible_event(compat_event_type)
    if compat is None:
        return None
    if not config.l3_advisory_async_enabled or not config.l3_heartbeat_review_enabled:
        return None
    if not session_id or record_id <= 0:
        return None
    if gateway._heartbeat_backlog_exists(session_id=session_id, runner=runner):
        return None

    last_terminal_to = gateway._latest_terminal_heartbeat_review_to_record(session_id=session_id)
    from_record_id = last_terminal_to + 1 if last_terminal_to > 0 else 1
    if record_id < from_record_id:
        return None
    if not gateway._has_high_risk_evidence_delta(
        session_id=session_id,
        from_record_id=from_record_id,
        to_record_id=record_id,
    ):
        return None

    try:
        snapshot = gateway.create_l3_evidence_snapshot(
            session_id=session_id,
            trigger_event_id=event_id,
            trigger_reason="heartbeat_aggregate",
            trigger_detail=f"{compat}_delta",
            from_record_id=from_record_id,
            to_record_id=record_id,
        )
        gateway.enqueue_l3_advisory_job(
            snapshot_id=snapshot["snapshot_id"],
            runner=runner,
        )
        return snapshot
    except Exception:
        logger.exception(
            "failed to create L3 heartbeat advisory snapshot for session %s event %s",
            session_id,
            event_id,
        )
        return None

def _maybe_create_l3_advisory_snapshot(
    gateway,
    *,
    config: DetectionConfig,
    session_id: str,
    event_id: str,
    record_id: int,
    current_risk_level: str,
    pending_trajectory_alerts: list[dict[str, Any]],
    compat_event_type: str | None = None,
) -> dict[str, Any] | None:
    if not config.l3_advisory_async_enabled:
        return None
    if not session_id or record_id <= 0:
        return None

    heartbeat_snapshot = gateway.maybe_create_l3_heartbeat_advisory_snapshot(
        config=config,
        session_id=session_id,
        event_id=event_id,
        record_id=record_id,
        compat_event_type=compat_event_type,
    )
    if heartbeat_snapshot is not None:
        return heartbeat_snapshot
    if config.l3_heartbeat_review_enabled and gateway._is_l3_heartbeat_compatible_event(compat_event_type) is None:
        # When heartbeat aggregation is explicitly enabled, non-compat
        # high-risk records become evidence deltas for the next heartbeat;
        # they do not start a hidden scheduler-like queue by themselves.
        return None

    trigger_reason: str | None = None
    trigger_detail: str | None = None
    for alert in pending_trajectory_alerts:
        if _risk_rank(str(alert.get("risk_level") or "low")) >= _risk_rank("high"):
            trigger_reason = "trajectory_alert"
            trigger_detail = str(alert.get("sequence_id") or alert.get("reason") or "").strip() or None
            break

    if trigger_reason is None and _risk_rank(current_risk_level) >= _risk_rank("high"):
        trigger_reason = "threshold"

    if trigger_reason is None:
        return None

    try:
        snapshot = gateway.create_l3_evidence_snapshot(
            session_id=session_id,
            trigger_event_id=event_id,
            trigger_reason=trigger_reason,
            trigger_detail=trigger_detail,
            to_record_id=record_id,
        )
        gateway.enqueue_l3_advisory_job(snapshot_id=snapshot["snapshot_id"])
        return snapshot
    except Exception:
        logger.exception(
            "failed to create L3 advisory evidence snapshot for session %s event %s",
            session_id,
            event_id,
        )
        return None


def register_l3_advisory_routes(app, gateway, verify_auth, check_rate_limit) -> None:
    """Register L3 advisory HTTP routes without importing server.py."""
    @app.post("/report/session/{session_id}/l3-advisory/snapshots")
    async def create_l3_advisory_snapshot_endpoint(
        request: Request,
        session_id: str,
        body: dict[str, Any],
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        try:
            snapshot = gateway.create_l3_evidence_snapshot(
                session_id=session_id,
                trigger_event_id=str(body.get("trigger_event_id") or ""),
                trigger_reason=str(body.get("trigger_reason") or "operator"),
                trigger_detail=(
                    str(body.get("trigger_detail"))
                    if body.get("trigger_detail") is not None
                    else None
                ),
                to_record_id=(
                    int(body["to_record_id"])
                    if body.get("to_record_id") is not None
                    else None
                ),
                from_record_id=(
                    int(body["from_record_id"])
                    if body.get("from_record_id") is not None
                    else None
                ),
                max_records=int(body.get("max_records") or 50),
                max_tool_calls=int(body.get("max_tool_calls") or 4),
            )
        except (TypeError, ValueError) as exc:
            return Response(
                content=json.dumps({"error": str(exc)}),
                status_code=400,
                media_type="application/json",
            )
        return {"snapshot": snapshot}

    @app.get("/report/session/{session_id}/l3-advisory/snapshots")
    async def list_l3_advisory_snapshots_endpoint(
        request: Request,
        session_id: str,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        return {
            "session_id": session_id,
            "snapshots": gateway.trajectory_store.list_l3_evidence_snapshots(session_id=session_id),
        }

    @app.get("/report/l3-advisory/snapshot/{snapshot_id}")
    async def get_l3_advisory_snapshot_endpoint(
        request: Request,
        snapshot_id: str,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        snapshot = gateway.trajectory_store.get_l3_evidence_snapshot(snapshot_id)
        if snapshot is None:
            return Response(
                content=json.dumps({"error": "snapshot not found"}),
                status_code=404,
                media_type="application/json",
            )
        return {
            "snapshot": snapshot,
            "records": gateway.trajectory_store.replay_l3_evidence_snapshot(snapshot_id),
        }

    @app.get("/report/l3-advisory/jobs")
    async def list_l3_advisory_jobs_endpoint(
        request: Request,
        session_id: Optional[str] = None,
        state: Optional[str] = None,
        runner: Optional[str] = None,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        try:
            return gateway.list_l3_advisory_jobs(
                session_id=session_id,
                state=state,
                runner=runner,
            )
        except ValueError as exc:
            return Response(
                content=json.dumps({"error": str(exc)}),
                status_code=400,
                media_type="application/json",
            )

    @app.post("/report/l3-advisory/jobs/run-next")
    async def run_next_l3_advisory_job_endpoint(
        request: Request,
        body: dict[str, Any] | None = None,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        body = body or {}
        try:
            return gateway.run_next_l3_advisory_job(
                runner=str(body.get("runner") or DEFAULT_L3_ADVISORY_RUNNER),
                session_id=(
                    str(body.get("session_id"))
                    if body.get("session_id") is not None
                    else None
                ),
                dry_run=bool(body.get("dry_run", False)),
            )
        except ValueError as exc:
            status_code = 404 if "was not found" in str(exc) else 400
            return Response(
                content=json.dumps({"error": str(exc)}),
                status_code=status_code,
                media_type="application/json",
            )

    @app.post("/report/l3-advisory/jobs/drain")
    async def drain_l3_advisory_jobs_endpoint(
        request: Request,
        body: dict[str, Any] | None = None,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        body = body or {}
        try:
            return gateway.drain_l3_advisory_jobs(
                runner=str(body.get("runner") or DEFAULT_L3_ADVISORY_RUNNER),
                session_id=(
                    str(body.get("session_id"))
                    if body.get("session_id") is not None
                    else None
                ),
                max_jobs=int(body.get("max_jobs") or 1),
                dry_run=bool(body.get("dry_run", False)),
            )
        except (TypeError, ValueError) as exc:
            status_code = 404 if "was not found" in str(exc) else 400
            return Response(
                content=json.dumps({"error": str(exc)}),
                status_code=status_code,
                media_type="application/json",
            )

    @app.post("/report/l3-advisory/snapshot/{snapshot_id}/jobs")
    async def enqueue_l3_advisory_job_endpoint(
        request: Request,
        snapshot_id: str,
        body: dict[str, Any] | None = None,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        try:
            job = gateway.enqueue_l3_advisory_job(
                snapshot_id=snapshot_id,
                runner=str((body or {}).get("runner") or DEFAULT_L3_ADVISORY_RUNNER),
            )
        except ValueError as exc:
            status_code = 404 if "was not found" in str(exc) else 400
            return Response(
                content=json.dumps({"error": str(exc)}),
                status_code=status_code,
                media_type="application/json",
            )
        return {"job": job}

    @app.post("/report/l3-advisory/reviews")
    async def create_l3_advisory_review_endpoint(
        request: Request,
        body: dict[str, Any],
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        try:
            review = gateway.record_l3_advisory_review(
                snapshot_id=str(body.get("snapshot_id") or ""),
                risk_level=str(body.get("risk_level") or "medium"),
                findings=[
                    str(item)
                    for item in (
                        body.get("findings")
                        if isinstance(body.get("findings"), list)
                        else []
                    )
                ],
                confidence=(
                    float(body["confidence"])
                    if body.get("confidence") is not None
                    else None
                ),
                recommended_operator_action=str(
                    body.get("recommended_operator_action") or "inspect"
                ),
                advisory_only=bool(body.get("advisory_only", True)),
                l3_state=str(body.get("l3_state") or "completed"),
                l3_reason_code=(
                    str(body.get("l3_reason_code"))
                    if body.get("l3_reason_code") is not None
                    else None
                ),
                extra_fields={
                    key: body[key]
                    for key in ("analysis_summary", "analysis_points", "operator_next_steps")
                    if key in body
                },
            )
        except (TypeError, ValueError) as exc:
            return Response(
                content=json.dumps({"error": str(exc)}),
                status_code=400,
                media_type="application/json",
            )
        return {"review": review}

    @app.patch("/report/l3-advisory/review/{review_id}")
    async def update_l3_advisory_review_endpoint(
        request: Request,
        review_id: str,
        body: dict[str, Any],
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        try:
            review = gateway.update_l3_advisory_review(
                review_id,
                risk_level=(
                    str(body.get("risk_level"))
                    if body.get("risk_level") is not None
                    else None
                ),
                findings=(
                    [str(item) for item in body.get("findings")]
                    if isinstance(body.get("findings"), list)
                    else None
                ),
                confidence=(
                    float(body["confidence"])
                    if body.get("confidence") is not None
                    else None
                ),
                recommended_operator_action=(
                    str(body.get("recommended_operator_action"))
                    if body.get("recommended_operator_action") is not None
                    else None
                ),
                l3_state=(
                    str(body.get("l3_state"))
                    if body.get("l3_state") is not None
                    else None
                ),
                l3_reason_code=(
                    str(body.get("l3_reason_code"))
                    if body.get("l3_reason_code") is not None
                    else None
                ),
                extra_fields={
                    key: body[key]
                    for key in ("analysis_summary", "analysis_points", "operator_next_steps")
                    if key in body
                },
            )
        except (TypeError, ValueError) as exc:
            status_code = 404 if "was not found" in str(exc) else 400
            return Response(
                content=json.dumps({"error": str(exc)}),
                status_code=status_code,
                media_type="application/json",
            )
        return {"review": review}

    @app.post("/report/l3-advisory/snapshot/{snapshot_id}/run-local-review")
    async def run_l3_advisory_local_review_endpoint(
        request: Request,
        snapshot_id: str,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        try:
            review = gateway.run_local_l3_advisory_review(snapshot_id=snapshot_id)
        except ValueError as exc:
            status_code = 404 if "was not found" in str(exc) else 400
            return Response(
                content=json.dumps({"error": str(exc)}),
                status_code=status_code,
                media_type="application/json",
            )
        return {"review": review}

    @app.post("/report/l3-advisory/job/{job_id}/run-local")
    async def run_l3_advisory_job_local_endpoint(
        request: Request,
        job_id: str,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        try:
            result = gateway.run_l3_advisory_job_local(job_id=job_id)
        except ValueError as exc:
            status_code = 404 if "was not found" in str(exc) else 400
            return Response(
                content=json.dumps({"error": str(exc)}),
                status_code=status_code,
                media_type="application/json",
            )
        return result

    @app.post("/report/l3-advisory/job/{job_id}/run-worker")
    async def run_l3_advisory_worker_endpoint(
        request: Request,
        job_id: str,
        body: dict[str, Any] | None = None,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        try:
            worker_name = str((body or {}).get("worker") or DEFAULT_L3_ADVISORY_RUNNER)
            _validate_public_l3_advisory_runner(worker_name)
            result = gateway.run_l3_advisory_worker(
                job_id=job_id,
                worker_name=worker_name,
            )
        except ValueError as exc:
            status_code = 404 if "was not found" in str(exc) else 400
            return Response(
                content=json.dumps({"error": str(exc)}),
                status_code=status_code,
                media_type="application/json",
            )
        return result

    @app.post("/report/session/{session_id}/l3-advisory/full-review")
    async def run_l3_advisory_operator_full_review_endpoint(
        request: Request,
        session_id: str,
        body: dict[str, Any] | None = None,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        body = body or {}
        try:
            result = gateway.run_operator_l3_full_review(
                session_id=session_id,
                trigger_event_id=str(body.get("trigger_event_id") or "operator_full_review"),
                trigger_detail=(
                    str(body.get("trigger_detail"))
                    if body.get("trigger_detail") is not None
                    else None
                ),
                from_record_id=(
                    int(body["from_record_id"])
                    if body.get("from_record_id") is not None
                    else None
                ),
                to_record_id=(
                    int(body["to_record_id"])
                    if body.get("to_record_id") is not None
                    else None
                ),
                max_records=int(body.get("max_records") or 100),
                max_tool_calls=int(body.get("max_tool_calls") or 0),
                runner=str(body.get("runner") or DEFAULT_L3_ADVISORY_RUNNER),
                run=bool(body.get("run", True)),
            )
        except (TypeError, ValueError) as exc:
            status_code = 404 if "was not found" in str(exc) else 400
            return Response(
                content=json.dumps({"error": str(exc)}),
                status_code=status_code,
                media_type="application/json",
            )
        return result
