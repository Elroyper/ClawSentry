"""Contracts for L3 advisory frozen evidence snapshots."""

from __future__ import annotations

import pytest

from clawsentry.gateway.trajectory_store import TrajectoryStore


def _record(
    store: TrajectoryStore,
    *,
    session_id: str = "sess-l3adv",
    event_id: str,
    decision: str = "allow",
    risk_level: str = "low",
    recorded_at_ts: float,
) -> int:
    store.record(
        event={
            "event_id": event_id,
            "trace_id": f"trace-{event_id}",
            "event_type": "pre_action",
            "session_id": session_id,
            "agent_id": "agent-l3adv",
            "source_framework": "test",
            "occurred_at": "2026-04-21T00:00:00+00:00",
            "tool_name": "bash",
            "payload": {"command": f"echo {event_id}"},
        },
        decision={
            "decision": decision,
            "risk_level": risk_level,
            "reason": f"{event_id} reason",
        },
        snapshot={
            "risk_level": risk_level,
            "composite_score": 1.5 if risk_level in {"high", "critical"} else 0.1,
        },
        meta={"request_id": f"req-{event_id}", "actual_tier": "L1"},
        recorded_at_ts=recorded_at_ts,
    )
    return store.records[-1]["record_id"]


def test_l3_evidence_snapshot_freezes_record_range_and_risk_summary() -> None:
    store = TrajectoryStore(retention_seconds=0)
    first_record_id = _record(
        store,
        event_id="evt-1",
        decision="allow",
        risk_level="low",
        recorded_at_ts=1.0,
    )
    second_record_id = _record(
        store,
        event_id="evt-2",
        decision="block",
        risk_level="high",
        recorded_at_ts=2.0,
    )

    snapshot = store.create_l3_evidence_snapshot(
        session_id="sess-l3adv",
        trigger_event_id="evt-2",
        trigger_reason="trajectory_alert",
        trigger_detail="secret_plus_network",
        to_record_id=second_record_id,
        max_records=50,
        max_tool_calls=4,
    )

    _record(
        store,
        event_id="evt-3",
        decision="allow",
        risk_level="low",
        recorded_at_ts=3.0,
    )

    assert snapshot["snapshot_id"].startswith("l3snap-")
    assert snapshot["advisory_only"] is True
    assert snapshot["event_range"] == {
        "from_record_id": first_record_id,
        "to_record_id": second_record_id,
    }
    assert snapshot["record_count"] == 2
    assert snapshot["risk_summary"] == {
        "current_risk_level": "high",
        "high_risk_event_count": 1,
        "decision_distribution": {"allow": 1, "block": 1},
    }
    assert snapshot["evidence_budget"] == {
        "max_records": 50,
        "max_tool_calls": 4,
    }

    frozen_records = store.replay_l3_evidence_snapshot(snapshot["snapshot_id"])
    assert [record["event"]["event_id"] for record in frozen_records] == ["evt-1", "evt-2"]


def test_l3_evidence_snapshot_creation_is_idempotent_for_same_boundary() -> None:
    store = TrajectoryStore(retention_seconds=0)
    to_record_id = _record(
        store,
        event_id="evt-idem",
        decision="block",
        risk_level="high",
        recorded_at_ts=1.0,
    )

    first = store.create_l3_evidence_snapshot(
        session_id="sess-l3adv",
        trigger_event_id="evt-idem",
        trigger_reason="threshold",
        to_record_id=to_record_id,
    )
    second = store.create_l3_evidence_snapshot(
        session_id="sess-l3adv",
        trigger_event_id="evt-idem",
        trigger_reason="threshold",
        to_record_id=to_record_id,
    )

    assert second["snapshot_id"] == first["snapshot_id"]
    assert store.list_l3_evidence_snapshots(session_id="sess-l3adv") == [first]


def test_l3_advisory_review_must_remain_advisory_only() -> None:
    store = TrajectoryStore(retention_seconds=0)
    record_id = _record(
        store,
        event_id="evt-review",
        decision="block",
        risk_level="high",
        recorded_at_ts=1.0,
    )
    snapshot = store.create_l3_evidence_snapshot(
        session_id="sess-l3adv",
        trigger_event_id="evt-review",
        trigger_reason="operator",
        to_record_id=record_id,
    )

    with pytest.raises(ValueError, match="advisory_only"):
        store.record_l3_advisory_review(
            snapshot_id=snapshot["snapshot_id"],
            risk_level="critical",
            findings=["would have blocked"],
            advisory_only=False,
        )

    review = store.record_l3_advisory_review(
        snapshot_id=snapshot["snapshot_id"],
        risk_level="critical",
        findings=["credential exfiltration likely"],
        confidence=0.84,
        recommended_operator_action="inspect",
    )

    assert review["review_id"].startswith("l3adv-")
    assert review["snapshot_id"] == snapshot["snapshot_id"]
    assert review["session_id"] == "sess-l3adv"
    assert review["advisory_only"] is True
    assert review["recommended_operator_action"] == "inspect"
    assert store.get_l3_advisory_review(review["review_id"]) == review
    assert store.list_l3_advisory_reviews(session_id="sess-l3adv") == [review]


def test_l3_advisory_review_lifecycle_updates_existing_review() -> None:
    store = TrajectoryStore(retention_seconds=0)
    record_id = _record(
        store,
        event_id="evt-lifecycle",
        decision="block",
        risk_level="high",
        recorded_at_ts=1.0,
    )
    snapshot = store.create_l3_evidence_snapshot(
        session_id="sess-l3adv",
        trigger_event_id="evt-lifecycle",
        trigger_reason="threshold",
        to_record_id=record_id,
    )
    review = store.record_l3_advisory_review(
        snapshot_id=snapshot["snapshot_id"],
        risk_level="high",
        findings=[],
        l3_state="pending",
        recommended_operator_action="inspect",
    )

    running = store.update_l3_advisory_review(
        review["review_id"],
        l3_state="running",
        findings=["review started"],
    )
    completed = store.update_l3_advisory_review(
        review["review_id"],
        l3_state="completed",
        risk_level="critical",
        findings=["credential exfiltration likely"],
        confidence=0.91,
        recommended_operator_action="escalate",
        l3_reason_code=None,
    )

    assert running["review_id"] == review["review_id"]
    assert running["l3_state"] == "running"
    assert completed["review_id"] == review["review_id"]
    assert completed["l3_state"] == "completed"
    assert completed["risk_level"] == "critical"
    assert completed["findings"] == ["credential exfiltration likely"]
    assert completed["confidence"] == 0.91
    assert completed["recommended_operator_action"] == "escalate"
    assert completed["completed_at"] is not None
    assert store.get_l3_advisory_review(review["review_id"]) == completed
    assert store.latest_l3_advisory_review(session_id="sess-l3adv") == completed


def test_l3_advisory_review_rejects_unknown_lifecycle_state() -> None:
    store = TrajectoryStore(retention_seconds=0)
    record_id = _record(
        store,
        event_id="evt-lifecycle-bad",
        decision="block",
        risk_level="high",
        recorded_at_ts=1.0,
    )
    snapshot = store.create_l3_evidence_snapshot(
        session_id="sess-l3adv",
        trigger_event_id="evt-lifecycle-bad",
        trigger_reason="threshold",
        to_record_id=record_id,
    )
    review = store.record_l3_advisory_review(
        snapshot_id=snapshot["snapshot_id"],
        risk_level="high",
        l3_state="pending",
    )

    with pytest.raises(ValueError, match="l3_state"):
        store.update_l3_advisory_review(review["review_id"], l3_state="enforcing")


def test_l3_advisory_local_review_runner_uses_only_frozen_records() -> None:
    store = TrajectoryStore(retention_seconds=0)
    first_record_id = _record(
        store,
        session_id="sess-l3adv-runner",
        event_id="evt-frozen-1",
        decision="allow",
        risk_level="low",
        recorded_at_ts=1.0,
    )
    second_record_id = _record(
        store,
        session_id="sess-l3adv-runner",
        event_id="evt-frozen-2",
        decision="block",
        risk_level="high",
        recorded_at_ts=2.0,
    )
    snapshot = store.create_l3_evidence_snapshot(
        session_id="sess-l3adv-runner",
        trigger_event_id="evt-frozen-2",
        trigger_reason="threshold",
        to_record_id=second_record_id,
    )
    _record(
        store,
        session_id="sess-l3adv-runner",
        event_id="evt-live-after-snapshot",
        decision="block",
        risk_level="critical",
        recorded_at_ts=3.0,
    )

    review = store.run_local_l3_advisory_review(snapshot["snapshot_id"])

    assert review["l3_state"] == "completed"
    assert review["risk_level"] == "high"
    assert review["recommended_operator_action"] == "inspect"
    assert review["evidence_record_count"] == 2
    assert review["evidence_event_ids"] == ["evt-frozen-1", "evt-frozen-2"]
    assert "evt-live-after-snapshot" not in review["evidence_event_ids"]
    assert review["source_record_range"] == {
        "from_record_id": first_record_id,
        "to_record_id": second_record_id,
    }
    assert any("2 frozen record" in finding for finding in review["findings"])
    assert store.latest_l3_advisory_review(session_id="sess-l3adv-runner") == review


def test_l3_advisory_job_queue_runs_local_review_explicitly() -> None:
    store = TrajectoryStore(retention_seconds=0)
    record_id = _record(
        store,
        session_id="sess-l3adv-job",
        event_id="evt-job",
        decision="block",
        risk_level="high",
        recorded_at_ts=1.0,
    )
    snapshot = store.create_l3_evidence_snapshot(
        session_id="sess-l3adv-job",
        trigger_event_id="evt-job",
        trigger_reason="threshold",
        to_record_id=record_id,
    )

    job = store.enqueue_l3_advisory_job(snapshot["snapshot_id"])
    duplicate = store.enqueue_l3_advisory_job(snapshot["snapshot_id"])

    assert duplicate["job_id"] == job["job_id"]
    assert job["job_id"].startswith("l3job-")
    assert job["job_state"] == "queued"
    assert job["snapshot_id"] == snapshot["snapshot_id"]
    assert job["review_id"] is None
    assert store.list_l3_advisory_jobs(session_id="sess-l3adv-job") == [job]

    result = store.run_l3_advisory_job_local(job["job_id"])

    assert result["job"]["job_id"] == job["job_id"]
    assert result["job"]["job_state"] == "completed"
    assert result["job"]["review_id"] == result["review"]["review_id"]
    assert result["job"]["completed_at"] is not None
    assert result["review"]["l3_state"] == "completed"
    assert result["review"]["review_runner"] == "deterministic_local"
    assert store.get_l3_advisory_job(job["job_id"]) == result["job"]


def test_l3_advisory_job_claim_is_queued_only() -> None:
    store = TrajectoryStore(retention_seconds=0)
    record_id = _record(
        store,
        session_id="sess-l3adv-claim",
        event_id="evt-claim",
        decision="block",
        risk_level="high",
        recorded_at_ts=1.0,
    )
    snapshot = store.create_l3_evidence_snapshot(
        session_id="sess-l3adv-claim",
        trigger_event_id="evt-claim",
        trigger_reason="threshold",
        to_record_id=record_id,
    )
    job = store.enqueue_l3_advisory_job(snapshot["snapshot_id"])

    claimed = store.claim_l3_advisory_job(job["job_id"], expected_runner="deterministic_local")
    assert claimed is not None
    assert claimed["job_state"] == "running"
    assert store.claim_l3_advisory_job(job["job_id"], expected_runner="deterministic_local") is None

    store.update_l3_advisory_job(job["job_id"], job_state="completed")
    assert store.claim_next_l3_advisory_job(runner="deterministic_local", session_id="sess-l3adv-claim") is None


def test_l3_advisory_action_summary_is_advisory_only_and_compact() -> None:
    store = TrajectoryStore(retention_seconds=0)
    record_id = _record(
        store,
        session_id="sess-l3adv-action",
        event_id="evt-action",
        decision="block",
        risk_level="critical",
        recorded_at_ts=1.0,
    )
    snapshot = store.create_l3_evidence_snapshot(
        session_id="sess-l3adv-action",
        trigger_event_id="evt-action",
        trigger_reason="heartbeat_aggregate",
        trigger_detail="heartbeat_delta",
        to_record_id=record_id,
    )
    job = store.enqueue_l3_advisory_job(snapshot["snapshot_id"])
    review = store.record_l3_advisory_review(
        snapshot_id=snapshot["snapshot_id"],
        risk_level="critical",
        findings=["compact finding"],
        recommended_operator_action="escalate",
    )
    job = store.update_l3_advisory_job(job["job_id"], job_state="completed", review_id=review["review_id"])

    action = store.build_l3_advisory_action_summary(review=review, job=job, snapshot=snapshot)

    assert action is not None
    assert action["snapshot_id"] == snapshot["snapshot_id"]
    assert action["job_id"] == job["job_id"]
    assert action["review_id"] == review["review_id"]
    assert action["recommended_operator_action"] == "escalate"
    assert action["advisory_only"] is True
    assert action["canonical_decision_mutated"] is False
    assert "findings" not in action


def test_l3_advisory_action_summary_skips_low_none_review() -> None:
    store = TrajectoryStore(retention_seconds=0)
    record_id = _record(
        store,
        session_id="sess-l3adv-action-low",
        event_id="evt-action-low",
        decision="allow",
        risk_level="low",
        recorded_at_ts=1.0,
    )
    snapshot = store.create_l3_evidence_snapshot(
        session_id="sess-l3adv-action-low",
        trigger_event_id="evt-action-low",
        trigger_reason="operator",
        to_record_id=record_id,
    )
    review = store.record_l3_advisory_review(
        snapshot_id=snapshot["snapshot_id"],
        risk_level="low",
        findings=[],
        recommended_operator_action="none",
    )

    assert store.build_l3_advisory_action_summary(review=review, snapshot=snapshot) is None
