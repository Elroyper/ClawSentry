"""Read-only reporting helpers for gateway API and persistence payloads."""

from __future__ import annotations

import json
from typing import Any, Optional

from clawsentry.gateway.models import utc_now_iso
from clawsentry.gateway.storage.session_registry import DISPLAY_SCORE_RANGE, DISPLAY_SCORE_SEMANTICS

_RISK_LEVEL_RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _risk_rank(risk_level: Optional[str]) -> int:
    return _RISK_LEVEL_RANK.get(str(risk_level or "low").lower(), 0)


def _risk_points(risk_level: Any) -> int:
    return _risk_rank(str(risk_level or "low")) + 1


def _float_or_zero(value: Any) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _risk_velocity_from_scores(scores: list[float]) -> str:
    """Return a compact trend label for a session risk score series."""
    if len(scores) < 2:
        return "unknown"
    delta = scores[-1] - scores[0]
    if delta > 0.25:
        return "up"
    if delta < -0.25:
        return "down"
    return "flat"


def _build_window_risk_summary(
    timeline: list[dict[str, Any]],
    *,
    window_seconds: Optional[int],
    generated_at: Optional[str] = None,
) -> dict[str, Any]:
    """Build API display metrics from a session timeline.

    This reporting helper is intentionally read-only.  It never feeds the
    policy engine, and it treats legacy ``cumulative_score`` separately from
    window-aware fields.
    """
    scores = [_float_or_zero(item.get("composite_score")) for item in timeline]
    risk_points = [_risk_points(item.get("risk_level")) for item in timeline]
    high_or_critical = sum(
        1
        for item in timeline
        if _risk_rank(item.get("risk_level")) >= _risk_rank("high")
    )
    latest_score = scores[-1] if scores else 0.0

    if scores:
        alpha = 0.3
        ewma = scores[0]
        for score in scores[1:]:
            ewma = (alpha * score) + ((1.0 - alpha) * ewma)
    else:
        ewma = 0.0

    return {
        "window_seconds": window_seconds,
        "generated_at": generated_at or utc_now_iso(),
        "event_count": len(timeline),
        "latest_composite_score": latest_score,
        "session_risk_sum": round(sum(scores), 4),
        "session_risk_ewma": round(ewma, 4),
        "risk_points_sum": int(sum(risk_points)),
        "risk_velocity": _risk_velocity_from_scores(scores),
        "high_or_critical_count": high_or_critical,
        "score_range": list(DISPLAY_SCORE_RANGE),
        "score_semantics": dict(DISPLAY_SCORE_SEMANTICS),
        "decision_affecting": False,
    }


def _build_system_security_posture(
    summary: dict[str, Any],
    *,
    window_seconds: Optional[int],
    generated_at: str,
) -> dict[str, Any]:
    """Build a display-only 0-100 system posture from reporting summary data."""
    by_risk = summary.get("by_risk_level") if isinstance(summary.get("by_risk_level"), dict) else {}
    critical_sessions = int(by_risk.get("critical") or 0)
    high_sessions = int(by_risk.get("high") or 0)
    high_trend = summary.get("high_risk_trend") if isinstance(summary.get("high_risk_trend"), dict) else {}
    trend_windows = high_trend.get("windows") if isinstance(high_trend.get("windows"), dict) else {}
    trend_15m = trend_windows.get("15m") if isinstance(trend_windows.get("15m"), dict) else {}
    high_ratio_15m = _float_or_zero(trend_15m.get("ratio"))
    invalid_event = summary.get("invalid_event") if isinstance(summary.get("invalid_event"), dict) else {}
    invalid_rate_15m = _float_or_zero(invalid_event.get("rate_15m"))

    risk_exposure = min(
        100.0,
        (20.0 * critical_sessions)
        + (10.0 * high_sessions)
        + (25.0 * high_ratio_15m)
        + (15.0 * invalid_rate_15m),
    )
    score = max(0.0, 100.0 - risk_exposure)
    if score < 50:
        level = "critical"
    elif score < 75:
        level = "elevated"
    elif score < 90:
        level = "watch"
    else:
        level = "healthy"

    driver_candidates = [
        {
            "key": "critical_sessions",
            "label": "Critical sessions",
            "value": critical_sessions,
            "impact": 20.0 * critical_sessions,
        },
        {
            "key": "high_sessions",
            "label": "High-risk sessions",
            "value": high_sessions,
            "impact": 10.0 * high_sessions,
        },
        {
            "key": "high_risk_ratio_15m",
            "label": "15m high-risk ratio",
            "value": round(high_ratio_15m, 4),
            "impact": 25.0 * high_ratio_15m,
        },
        {
            "key": "invalid_event_rate_15m",
            "label": "15m invalid-event rate",
            "value": round(invalid_rate_15m, 4),
            "impact": 15.0 * invalid_rate_15m,
        },
    ]
    drivers = [
        {k: v for k, v in item.items() if k != "impact"}
        for item in sorted(driver_candidates, key=lambda item: item["impact"], reverse=True)
        if item["impact"] > 0
    ][:3]

    return {
        "score_0_100": round(score, 1),
        "level": level,
        "drivers": drivers,
        "window_seconds": window_seconds or 3600,
        "generated_at": generated_at,
        "decision_affecting": False,
    }


def _build_decision_path_io_pressure(io_snapshot: dict[str, Any]) -> dict[str, Any]:
    reporting = io_snapshot.get("reporting") if isinstance(io_snapshot.get("reporting"), dict) else {}
    record_path = io_snapshot.get("record_path") if isinstance(io_snapshot.get("record_path"), dict) else {}
    max_reporting_seconds = 0.0
    for item in reporting.values():
        if isinstance(item, dict):
            max_reporting_seconds = max(
                max_reporting_seconds,
                _float_or_zero(item.get("max_seconds")),
            )
    max_record_seconds = _float_or_zero(record_path.get("max_seconds"))
    max_seconds = max(max_reporting_seconds, max_record_seconds)
    if max_seconds >= 1.0:
        level = "critical"
    elif max_seconds >= 0.25:
        level = "elevated"
    elif max_seconds >= 0.05:
        level = "watch"
    else:
        level = "healthy"
    return {
        "level": level,
        "max_seconds": round(max_seconds, 6),
        "max_reporting_seconds": round(max_reporting_seconds, 6),
        "max_record_path_seconds": round(max_record_seconds, 6),
        "decision_affecting": False,
    }


def _compact_l3_evidence_summary(l3_trace: dict[str, Any] | None) -> dict[str, Any] | None:
    """Return a compact operator-facing evidence summary from an L3 trace."""
    if not isinstance(l3_trace, dict):
        return None

    evidence_summary = l3_trace.get("evidence_summary")
    if not isinstance(evidence_summary, dict):
        return None

    summary: dict[str, Any] = {}

    retained_sources = evidence_summary.get("retained_sources")
    if isinstance(retained_sources, list):
        compact_sources = [
            str(source).strip()
            for source in retained_sources
            if str(source).strip()
        ]
        if compact_sources:
            summary["retained_sources"] = compact_sources

    tool_calls = evidence_summary.get("tool_calls")
    if isinstance(tool_calls, list):
        summary["tool_calls_count"] = len(tool_calls)
    else:
        tool_calls_count = evidence_summary.get("tool_calls_count")
        if isinstance(tool_calls_count, int):
            summary["tool_calls_count"] = tool_calls_count

    toolkit_budget_mode = str(evidence_summary.get("toolkit_budget_mode") or "").strip()
    if toolkit_budget_mode:
        summary["toolkit_budget_mode"] = toolkit_budget_mode

    toolkit_budget_cap = evidence_summary.get("toolkit_budget_cap")
    if isinstance(toolkit_budget_cap, int):
        summary["toolkit_budget_cap"] = toolkit_budget_cap

    toolkit_calls_remaining = evidence_summary.get("toolkit_calls_remaining")
    if isinstance(toolkit_calls_remaining, int):
        summary["toolkit_calls_remaining"] = toolkit_calls_remaining
    toolkit_budget_exhausted = evidence_summary.get("toolkit_budget_exhausted")
    if isinstance(toolkit_budget_exhausted, bool):
        summary["toolkit_budget_exhausted"] = toolkit_budget_exhausted
    elif (
        isinstance(toolkit_budget_cap, int)
        and toolkit_budget_cap > 0
        and isinstance(toolkit_calls_remaining, int)
    ):
        summary["toolkit_budget_exhausted"] = toolkit_calls_remaining <= 0

    return summary or None


def _l3_trace_for_persistence(
    l3_trace: dict[str, Any] | None,
    *,
    redact_raw_bodies: bool = True,
    redact_final_findings: bool = False,
) -> dict[str, Any] | None:
    """Remove raw model/tool body echoes from durable L3 trace storage."""

    if not isinstance(l3_trace, dict):
        return l3_trace
    sanitized = json.loads(json.dumps(l3_trace, default=str))
    turns = sanitized.get("turns")
    if isinstance(turns, list):
        for turn in turns:
            if not isinstance(turn, dict):
                continue
            if redact_raw_bodies and "response_raw" in turn:
                turn["response_raw"] = "[REDACTED_L3_RESPONSE_RAW]"
            tool_result = turn.get("tool_result")
            if redact_raw_bodies and isinstance(tool_result, dict) and "content" in tool_result:
                tool_result["content"] = "[REDACTED_TOOL_CONTENT]"
    final_verdict = sanitized.get("final_verdict")
    if (
        redact_final_findings
        and isinstance(final_verdict, dict)
        and isinstance(final_verdict.get("findings"), list)
    ):
        final_verdict["findings"] = [
            f"l3_finding_{index + 1}_redacted_for_persistence"
            for index, _finding in enumerate(final_verdict["findings"])
        ]
    return sanitized


def _copy_budget_event(budget_event: dict[str, Any] | None) -> dict[str, Any] | None:
    """Return a copy of a budget exhaustion event payload."""
    if not isinstance(budget_event, dict):
        return None
    copied = dict(budget_event)
    budget = copied.get("budget")
    if isinstance(budget, dict):
        copied["budget"] = dict(budget)
    return copied or None


def _copy_l3_narrative_fields(review: dict[str, Any]) -> dict[str, Any]:
    copied: dict[str, Any] = {}
    for key in ("analysis_summary", "analysis_points", "operator_next_steps"):
        if key in review:
            copied[key] = review[key]
    return copied


def _new_io_metric_bucket() -> dict[str, float | int]:
    return {
        "calls": 0,
        "total_seconds": 0.0,
        "last_seconds": 0.0,
        "max_seconds": 0.0,
    }


def _observe_io_metric(bucket: dict[str, float | int], elapsed_seconds: float) -> None:
    elapsed = max(0.0, float(elapsed_seconds))
    bucket["calls"] = int(bucket["calls"]) + 1
    bucket["total_seconds"] = float(bucket["total_seconds"]) + elapsed
    bucket["last_seconds"] = elapsed
    bucket["max_seconds"] = max(float(bucket["max_seconds"]), elapsed)


def _snapshot_io_metric(bucket: dict[str, float | int]) -> dict[str, float | int]:
    return {
        "calls": int(bucket["calls"]),
        "total_seconds": round(float(bucket["total_seconds"]), 6),
        "last_seconds": round(float(bucket["last_seconds"]), 6),
        "max_seconds": round(float(bucket["max_seconds"]), 6),
    }
