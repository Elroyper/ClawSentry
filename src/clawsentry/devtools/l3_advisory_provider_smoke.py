"""Manual L3 advisory provider smoke helper.

This helper is intentionally explicit and operator-triggered. It constructs a
small frozen evidence snapshot, queues a single ``llm_provider`` advisory job,
and runs that job once. It does not start a scheduler, mutate canonical
decisions, or enable real provider execution by default.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from ..gateway.l3_advisory_worker import (
    LLMProviderAdvisoryWorker,
    resolve_l3_advisory_provider_config,
    run_l3_advisory_worker_job,
)
from ..gateway.trajectory_store import TrajectoryStore


@dataclass(frozen=True)
class AdvisoryProviderSmokeResult:
    """Captured smoke output and evidence summary."""

    status: str
    provider: str
    model: str
    snapshot: dict[str, Any] = field(default_factory=dict)
    job: dict[str, Any] = field(default_factory=dict)
    review: dict[str, Any] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)
    failure_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def run_smoke(
    *,
    environ: Mapping[str, str] | None = None,
    require_completed: bool = False,
    output_report: Path | None = None,
) -> AdvisoryProviderSmokeResult:
    """Run the manual L3 advisory provider smoke.

    The smoke is skipped unless ``CS_L3_ADVISORY_PROVIDER_ENABLED`` is truthy.
    Current provider shells still degrade with ``provider_not_implemented`` once
    config validation succeeds; that is accepted unless ``require_completed`` is
    set for a future real-provider smoke.
    """

    effective_environ = _smoke_environ(environ)
    config = resolve_l3_advisory_provider_config(environ=effective_environ)
    if not config.enabled:
        result = AdvisoryProviderSmokeResult(
            status="skipped",
            provider=config.provider,
            model=config.model,
            evidence={
                "opt_in_required": "CS_L3_ADVISORY_PROVIDER_ENABLED=true",
                "network_default": "not attempted",
            },
            failure_reason="CS_L3_ADVISORY_PROVIDER_ENABLED is not true",
        )
        _maybe_write_report(result, output_report)
        return result

    store = TrajectoryStore(retention_seconds=0)
    record_id = _record_sample_event(store)
    snapshot = store.create_l3_evidence_snapshot(
        session_id="manual-l3-advisory-provider-smoke",
        trigger_event_id="manual-l3-advisory-provider-smoke-event",
        trigger_reason="operator",
        trigger_detail="manual_provider_smoke",
        to_record_id=record_id,
        max_records=10,
        max_tool_calls=0,
    )
    job = store.enqueue_l3_advisory_job(
        snapshot["snapshot_id"],
        runner=LLMProviderAdvisoryWorker.runner_name,
    )
    with _temporary_environ(effective_environ):
        result_payload = run_l3_advisory_worker_job(
            store=store,
            job_id=job["job_id"],
            worker=LLMProviderAdvisoryWorker(config),
        )
    completed_job = result_payload["job"]
    review = result_payload["review"]
    evidence = {
        "snapshot_id": snapshot["snapshot_id"],
        "job_id": completed_job["job_id"],
        "review_id": review["review_id"],
        "advisory_only": review.get("advisory_only") is True,
        "review_state": review.get("l3_state"),
        "reason_code": review.get("l3_reason_code"),
        "source_record_range": review.get("source_record_range") or snapshot.get("event_range"),
        "network_default": "no background scheduler; explicit worker call only",
        "canonical_decision_mutated": False,
    }
    status = "passed"
    failure_reason = None
    if require_completed and review.get("l3_state") != "completed":
        status = "failed"
        failure_reason = (
            "real-provider smoke required completed review, "
            f"got {review.get('l3_state')}"
        )
    result = AdvisoryProviderSmokeResult(
        status=status,
        provider=config.provider,
        model=config.model,
        snapshot=snapshot,
        job=completed_job,
        review=review,
        evidence=evidence,
        failure_reason=failure_reason,
    )
    _maybe_write_report(result, output_report)
    return result


def render_validation_report(result: AdvisoryProviderSmokeResult) -> str:
    """Render a markdown validation report safe to keep as an artifact."""

    generated_at_utc = datetime.now(timezone.utc).isoformat()
    result_dict = result.to_dict()
    lines = [
        "# L3 Advisory Provider Smoke Validation",
        "",
        f"- Status: **{result.status.upper()}**",
        f"- Generated at (UTC): {generated_at_utc}",
        f"- Provider: `{result.provider or '-'}`",
        f"- Model: `{result.model or '-'}`",
        "",
        "## Evidence summary",
        "",
        "```json",
        json.dumps(result.evidence, ensure_ascii=False, indent=2, sort_keys=True),
        "```",
        "",
        "## Review excerpt",
        "",
        "```json",
        json.dumps(_review_excerpt(result.review), ensure_ascii=False, indent=2, sort_keys=True),
        "```",
    ]
    if result.failure_reason:
        lines.extend(["", "## Failure reason", "", result.failure_reason])
    lines.extend(
        [
            "",
            "## Full redacted result",
            "",
            "```json",
            json.dumps(_redact_sensitive(result_dict), ensure_ascii=False, indent=2, sort_keys=True),
            "```",
        ]
    )
    return "\n".join(lines) + "\n"


def _record_sample_event(store: TrajectoryStore) -> int:
    return store.record(
        event={
            "event_id": "manual-l3-advisory-provider-smoke-event",
            "trace_id": "manual-l3-advisory-provider-smoke-trace",
            "event_type": "pre_action",
            "session_id": "manual-l3-advisory-provider-smoke",
            "agent_id": "manual-smoke-agent",
            "source_framework": "manual-smoke",
            "occurred_at": "2026-04-21T00:00:00+00:00",
            "tool_name": "bash",
            "payload": {"command": "echo CLENTRY_SYNTHETIC_HIGH_RISK_SMOKE"},
        },
        decision={
            "decision": "block",
            "risk_level": "high",
            "reason": "manual smoke high-risk sample",
        },
        snapshot={
            "risk_level": "high",
            "composite_score": 2.2,
        },
        meta={"request_id": "manual-smoke-request", "actual_tier": "L1"},
        recorded_at_ts=1.0,
    )


def _review_excerpt(review: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "review_id",
        "snapshot_id",
        "session_id",
        "risk_level",
        "advisory_only",
        "recommended_operator_action",
        "l3_state",
        "l3_reason_code",
        "review_runner",
        "worker_backend",
        "provider_enabled",
    )
    return {key: review.get(key) for key in keys if key in review}


def _redact_sensitive(value: Any) -> Any:
    if isinstance(value, str):
        if value.startswith(("sk-", "sk-ant-")):
            return value[:6] + "..." if len(value) > 6 else "***"
        return value
    if isinstance(value, list):
        return [_redact_sensitive(item) for item in value]
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            if "key" in str(key).lower() or "token" in str(key).lower():
                redacted[key] = "***" if item else item
            else:
                redacted[key] = _redact_sensitive(item)
        return redacted
    return value


def _smoke_environ(environ: Mapping[str, str] | None) -> dict[str, str]:
    source = dict(environ if environ is not None else os.environ)
    strip_proxy = str(
        source.get("CS_L3_ADVISORY_SMOKE_STRIP_PROXY_ENV", "true")
    ).strip().lower() not in {"0", "false", "no", "off"}
    if strip_proxy:
        source = {
            key: value
            for key, value in source.items()
            if "proxy" not in key.lower()
        }
    return source


@contextlib.contextmanager
def _temporary_environ(environ: Mapping[str, str]):
    old = os.environ.copy()
    try:
        os.environ.clear()
        os.environ.update({str(key): str(value) for key, value in environ.items()})
        yield
    finally:
        os.environ.clear()
        os.environ.update(old)


def _maybe_write_report(
    result: AdvisoryProviderSmokeResult,
    output_report: Path | None,
) -> None:
    if output_report is None:
        return
    output_report.parent.mkdir(parents=True, exist_ok=True)
    output_report.write_text(render_validation_report(result), encoding="utf-8")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="run_l3_advisory_provider_smoke",
        description="Run a manual ClawSentry L3 advisory provider smoke.",
    )
    parser.add_argument("--json", action="store_true", default=False, help="Output JSON.")
    parser.add_argument(
        "--output-report",
        type=Path,
        default=None,
        help="Optional markdown report path.",
    )
    parser.add_argument(
        "--require-completed",
        action="store_true",
        default=False,
        help="Fail unless the advisory provider returns a completed review.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    result = run_smoke(
        environ=os.environ,
        require_completed=args.require_completed,
        output_report=args.output_report,
    )
    if args.json:
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(render_validation_report(result))
    if result.status == "failed":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
