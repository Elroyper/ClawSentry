"""``clawsentry l3`` — operator-triggered L3 advisory actions."""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from typing import Any

from clawsentry.cli.http_utils import urlopen_gateway


def build_full_review_payload(
    *,
    trigger_event_id: str | None,
    trigger_detail: str | None,
    from_record_id: int | None,
    to_record_id: int | None,
    max_records: int,
    max_tool_calls: int,
    runner: str | None,
    queue_only: bool,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "trigger_event_id": trigger_event_id or "operator_full_review",
        "trigger_detail": trigger_detail or "operator_requested_full_review",
        "max_records": max_records,
        "max_tool_calls": max_tool_calls,
        "run": not queue_only,
    }
    if runner:
        payload["runner"] = runner
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
    runner: str | None,
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
        with urlopen_gateway(request, timeout=timeout) as response:
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


def _request_json(
    *,
    method: str,
    url: str,
    token: str | None,
    payload: dict[str, Any] | None = None,
    timeout: float,
    command_name: str,
) -> tuple[int, dict[str, Any] | None]:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(payload or {}).encode("utf-8") if method != "GET" else None
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urlopen_gateway(request, timeout=timeout) as response:
            return 0, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        print(f"clawsentry l3 {command_name}: HTTP {exc.code}: {detail}", file=sys.stderr)
        return 1, None
    except (OSError, json.JSONDecodeError) as exc:
        print(f"clawsentry l3 {command_name}: {exc}", file=sys.stderr)
        return 1, None


def run_l3_jobs_list(
    *,
    gateway_url: str,
    token: str | None,
    session_id: str | None,
    state: str | None,
    runner: str | None,
    json_mode: bool,
    timeout: float,
) -> int:
    from urllib.parse import urlencode

    params = {
        key: value
        for key, value in {
            "session_id": session_id,
            "state": state,
            "runner": runner,
        }.items()
        if value
    }
    url = f"{gateway_url.rstrip('/')}/report/l3-advisory/jobs"
    if params:
        url = f"{url}?{urlencode(params)}"
    code, result = _request_json(
        method="GET",
        url=url,
        token=token,
        timeout=timeout,
        command_name="jobs list",
    )
    if code != 0 or result is None:
        return code
    if json_mode:
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(_render_jobs_list_summary(result))
    return 0


def run_l3_jobs_run_next(
    *,
    gateway_url: str,
    token: str | None,
    runner: str,
    session_id: str | None,
    dry_run: bool,
    json_mode: bool,
    timeout: float,
) -> int:
    url = f"{gateway_url.rstrip('/')}/report/l3-advisory/jobs/run-next"
    code, result = _request_json(
        method="POST",
        url=url,
        token=token,
        payload={"runner": runner, "session_id": session_id, "dry_run": dry_run},
        timeout=timeout,
        command_name="jobs run-next",
    )
    if code != 0 or result is None:
        return code
    if json_mode:
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(_render_jobs_run_summary("run-next", result))
    return 0


def run_l3_jobs_drain(
    *,
    gateway_url: str,
    token: str | None,
    runner: str,
    session_id: str | None,
    max_jobs: int,
    dry_run: bool,
    json_mode: bool,
    timeout: float,
) -> int:
    url = f"{gateway_url.rstrip('/')}/report/l3-advisory/jobs/drain"
    code, result = _request_json(
        method="POST",
        url=url,
        token=token,
        payload={
            "runner": runner,
            "session_id": session_id,
            "max_jobs": max_jobs,
            "dry_run": dry_run,
        },
        timeout=timeout,
        command_name="jobs drain",
    )
    if code != 0 or result is None:
        return code
    if json_mode:
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(_render_jobs_run_summary("drain", result))
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


def _render_jobs_list_summary(result: dict[str, Any]) -> str:
    jobs = result.get("jobs") if isinstance(result.get("jobs"), list) else []
    lines = [f"L3 advisory jobs: {len(jobs)}"]
    for job in jobs:
        if not isinstance(job, dict):
            continue
        lines.append(
            f"- {job.get('job_id', '-')} "
            f"state={job.get('job_state', '-')} "
            f"runner={job.get('runner', '-')} "
            f"snapshot={job.get('snapshot_id', '-')}"
        )
    lines.append(f"advisory_only: {bool(result.get('advisory_only'))}")
    lines.append(f"canonical_decision_mutated: {bool(result.get('canonical_decision_mutated'))}")
    return "\n".join(lines)


def _render_jobs_run_summary(label: str, result: dict[str, Any]) -> str:
    lines = [
        f"L3 advisory jobs {label}",
        f"ran_count: {int(result.get('ran_count') or 0)}",
        f"dry_run: {bool(result.get('dry_run'))}",
    ]
    selected = result.get("selected_jobs") if isinstance(result.get("selected_jobs"), list) else []
    if selected:
        lines.append("selected:")
        for job in selected:
            if isinstance(job, dict):
                lines.append(f"- {job.get('job_id', '-')} ({job.get('job_state', '-')})")
    run_result = result.get("result") if isinstance(result.get("result"), dict) else None
    if run_result:
        review = run_result.get("review") if isinstance(run_result.get("review"), dict) else {}
        job = run_result.get("job") if isinstance(run_result.get("job"), dict) else {}
        lines.append(f"job: {job.get('job_id', '-')} ({job.get('job_state', '-')})")
        lines.append(f"review: {review.get('review_id', '-')} ({review.get('l3_state', '-')})")
    results = result.get("results") if isinstance(result.get("results"), list) else []
    for item in results:
        if not isinstance(item, dict):
            continue
        review = item.get("review") if isinstance(item.get("review"), dict) else {}
        job = item.get("job") if isinstance(item.get("job"), dict) else {}
        lines.append(f"- ran {job.get('job_id', '-')} review={review.get('review_id', '-')}")
    lines.append(f"advisory_only: {bool(result.get('advisory_only'))}")
    lines.append(f"canonical_decision_mutated: {bool(result.get('canonical_decision_mutated'))}")
    return "\n".join(lines)
