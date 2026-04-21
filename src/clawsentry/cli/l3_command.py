"""``clawsentry l3`` — operator-triggered L3 advisory actions."""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from typing import Any


def build_full_review_payload(
    *,
    trigger_event_id: str | None,
    trigger_detail: str | None,
    from_record_id: int | None,
    to_record_id: int | None,
    max_records: int,
    max_tool_calls: int,
    runner: str,
    queue_only: bool,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "trigger_event_id": trigger_event_id or "operator_full_review",
        "trigger_detail": trigger_detail or "operator_requested_full_review",
        "max_records": max_records,
        "max_tool_calls": max_tool_calls,
        "runner": runner,
        "run": not queue_only,
    }
    if from_record_id is not None:
        payload["from_record_id"] = from_record_id
    if to_record_id is not None:
        payload["to_record_id"] = to_record_id
    return payload


def run_l3_full_review(
    *,
    gateway_url: str,
    token: str | None,
    session_id: str,
    trigger_event_id: str | None,
    trigger_detail: str | None,
    from_record_id: int | None,
    to_record_id: int | None,
    max_records: int,
    max_tool_calls: int,
    runner: str,
    queue_only: bool,
    json_mode: bool,
    timeout: float,
) -> int:
    payload = build_full_review_payload(
        trigger_event_id=trigger_event_id,
        trigger_detail=trigger_detail,
        from_record_id=from_record_id,
        to_record_id=to_record_id,
        max_records=max_records,
        max_tool_calls=max_tool_calls,
        runner=runner,
        queue_only=queue_only,
    )
    base = gateway_url.rstrip("/")
    url = f"{base}/report/session/{session_id}/l3-advisory/full-review"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            result = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        print(f"clawsentry l3 full-review: HTTP {exc.code}: {detail}", file=sys.stderr)
        return 1
    except (OSError, json.JSONDecodeError) as exc:
        print(f"clawsentry l3 full-review: {exc}", file=sys.stderr)
        return 1

    if json_mode:
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(_render_full_review_summary(result))
    return 0


def _render_full_review_summary(result: dict[str, Any]) -> str:
    snapshot = result.get("snapshot") if isinstance(result.get("snapshot"), dict) else {}
    job = result.get("job") if isinstance(result.get("job"), dict) else {}
    review = result.get("review") if isinstance(result.get("review"), dict) else None
    lines = [
        "L3 advisory full review requested",
        f"snapshot: {snapshot.get('snapshot_id', '-')}",
        f"job:      {job.get('job_id', '-')} ({job.get('job_state', '-')})",
    ]
    if review:
        lines.append(
            f"review:   {review.get('review_id', '-')} "
            f"({review.get('l3_state', '-')}, risk={review.get('risk_level', '-')})"
        )
    else:
        lines.append("review:   queued only")
    lines.append(f"advisory_only: {bool(result.get('advisory_only'))}")
    lines.append(f"canonical_decision_mutated: {bool(result.get('canonical_decision_mutated'))}")
    return "\n".join(lines)
