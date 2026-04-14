"""In-memory live session view for current-process metrics endpoints."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Any, Optional

from .models import utc_now_iso
from .trajectory_store import _parse_iso_timestamp

_RISK_LEVEL_RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _risk_rank(risk_level: Optional[str]) -> int:
    return _RISK_LEVEL_RANK.get(str(risk_level or "low").lower(), 0)


class SessionRegistry:
    """In-memory live session view for current-process metrics endpoints."""

    DEFAULT_MAX_SESSIONS = 10_000
    DEFAULT_MAX_TIMELINE_PER_SESSION = 1000

    def __init__(
        self,
        max_sessions: int = DEFAULT_MAX_SESSIONS,
        max_timeline_per_session: int = DEFAULT_MAX_TIMELINE_PER_SESSION,
    ) -> None:
        self.max_sessions = max(max_sessions, 1)
        self.max_timeline_per_session = max(max_timeline_per_session, 1)
        self._sessions: dict[str, dict[str, Any]] = {}

    def _evict_if_needed(self) -> None:
        while len(self._sessions) > self.max_sessions:
            oldest_session_id = next(iter(self._sessions))
            del self._sessions[oldest_session_id]

    def get_current_risk(self, session_id: str) -> Optional[str]:
        """Return current risk level for session_id, or None if not tracked yet."""
        session = self._sessions.get(session_id)
        return str(session["current_risk_level"]) if session is not None else None

    def get_session_stats(self, session_id: str) -> dict[str, Any]:
        """Return a copy of session stats for alert generation."""
        return dict(self._sessions.get(session_id, {}))

    @staticmethod
    def _decrement_counter(counter: defaultdict[int] | defaultdict[str, int], key: str) -> None:
        if key not in counter:
            return
        counter[key] -= 1
        if counter[key] <= 0:
            del counter[key]

    @staticmethod
    def _compact_evidence_summary(summary: Any) -> Optional[dict[str, Any]]:
        if not isinstance(summary, dict):
            return None

        compact: dict[str, Any] = {}

        retained_sources = summary.get("retained_sources")
        if isinstance(retained_sources, list):
            compact_sources = [
                str(source).strip()
                for source in retained_sources
                if str(source).strip()
            ]
            if compact_sources:
                compact["retained_sources"] = compact_sources

        tool_calls = summary.get("tool_calls")
        if isinstance(tool_calls, list):
            compact["tool_calls_count"] = len(tool_calls)
        else:
            tool_calls_count = summary.get("tool_calls_count")
            if isinstance(tool_calls_count, int):
                compact["tool_calls_count"] = tool_calls_count

        return compact or None

    @staticmethod
    def _latest_session_annotations(session: dict[str, Any]) -> dict[str, Any]:
        annotations: dict[str, Any] = {}

        evidence_summary = session.get("latest_evidence_summary")
        if evidence_summary is None:
            timeline = session.get("risk_timeline")
            if timeline:
                latest_item = timeline[-1]
                if isinstance(latest_item, dict):
                    evidence_summary = latest_item.get("evidence_summary")
        if evidence_summary is not None:
            annotations["evidence_summary"] = dict(evidence_summary)

        l3_fields = (
            ("l3_state", session.get("latest_l3_state")),
            ("l3_reason", session.get("latest_l3_reason")),
            ("l3_reason_code", session.get("latest_l3_reason_code")),
        )
        if not any(value is not None for _, value in l3_fields):
            timeline = session.get("risk_timeline")
            if timeline:
                latest_item = timeline[-1]
                if isinstance(latest_item, dict):
                    l3_fields = (
                        ("l3_state", latest_item.get("l3_state")),
                        ("l3_reason", latest_item.get("l3_reason")),
                        ("l3_reason_code", latest_item.get("l3_reason_code")),
                    )

        for key, value in l3_fields:
            if value is not None:
                annotations[key] = str(value)

        return annotations

    def record(
        self,
        *,
        event: dict[str, Any],
        decision: dict[str, Any],
        snapshot: dict[str, Any],
        meta: dict[str, Any],
    ) -> None:
        session_id = str(event.get("session_id") or "")
        if not session_id:
            return

        occurred_at = str(event.get("occurred_at") or utc_now_iso())
        occurred_at_ts = _parse_iso_timestamp(occurred_at)
        risk_level = str(snapshot.get("risk_level") or decision.get("risk_level") or "low")
        dimensions = snapshot.get("dimensions") or {}
        tool_name = event.get("tool_name")
        decision_verdict = str(decision.get("decision") or "unknown")
        actual_tier = str(meta.get("actual_tier") or "unknown")
        classified_by = str(snapshot.get("classified_by") or actual_tier or "unknown")
        l3_state = meta.get("l3_state")
        l3_reason = meta.get("l3_reason")
        l3_reason_code = meta.get("l3_reason_code")
        evidence_summary = None
        for source in (meta, event, decision, snapshot):
            evidence_summary = self._compact_evidence_summary(
                source.get("evidence_summary")
            )
            if evidence_summary is not None:
                break
        record_type = str(meta.get("record_type") or "decision")
        payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
        workspace_root = str(
            payload.get("cwd")
            or payload.get("working_directory")
            or payload.get("workspace_root")
            or ""
        )
        transcript_path = str(payload.get("transcript_path") or "")

        session = self._sessions.pop(session_id, None)
        if session is None:
            session = {
                "session_id": session_id,
                "agent_id": str(event.get("agent_id") or "unknown"),
                "source_framework": str(event.get("source_framework") or "unknown"),
                "caller_adapter": str(meta.get("caller_adapter") or "unknown"),
                "current_risk_level": "low",
                "cumulative_score": 0,
                "event_count": 0,
                "high_risk_event_count": 0,
                "decision_distribution": defaultdict(int),
                "actual_tier_distribution": defaultdict(int),
                "first_event_at": occurred_at,
                "last_event_at": occurred_at,
                "last_event_ts": occurred_at_ts,
                "d4_accumulation": 0,
                "dimensions_latest": {"d1": 0, "d2": 0, "d3": 0, "d4": 0, "d5": 0},
                "risk_hints_seen": set(),
                "tools_used": set(),
                "latest_evidence_summary": None,
                "latest_l3_state": None,
                "latest_l3_reason": None,
                "latest_l3_reason_code": None,
                "risk_timeline": deque(maxlen=self.max_timeline_per_session),
                "workspace_root": "",
                "transcript_path": "",
            }

        session["agent_id"] = str(event.get("agent_id") or session["agent_id"])
        session["source_framework"] = str(event.get("source_framework") or session["source_framework"])
        session["caller_adapter"] = str(meta.get("caller_adapter") or session["caller_adapter"])
        if workspace_root:
            session["workspace_root"] = workspace_root
        if transcript_path:
            session["transcript_path"] = transcript_path
        timeline = session["risk_timeline"]
        timeline_entry = {
            "event_id": str(event.get("event_id") or "unknown"),
            "occurred_at": occurred_at,
            "occurred_at_ts": occurred_at_ts,
            "risk_level": risk_level,
            "composite_score": int(snapshot.get("composite_score") or 0),
            "tool_name": tool_name,
            "decision": decision_verdict,
            "actual_tier": actual_tier,
            "classified_by": classified_by,
            "l3_state": str(l3_state) if l3_state is not None else None,
            "l3_reason": str(l3_reason) if l3_reason is not None else None,
            "l3_reason_code": str(l3_reason_code) if l3_reason_code is not None else None,
        }
        if evidence_summary is not None:
            timeline_entry["evidence_summary"] = evidence_summary

        if record_type == "decision_resolution":
            matched = None
            for item in reversed(timeline):
                if item.get("event_id") == timeline_entry["event_id"]:
                    matched = item
                    break
            if matched is not None:
                previous_decision = str(matched.get("decision") or "unknown")
                previous_tier = str(matched.get("actual_tier") or "unknown")
                previous_high = _risk_rank(str(matched.get("risk_level") or "low")) >= _risk_rank("high")
                self._decrement_counter(session["decision_distribution"], previous_decision)
                self._decrement_counter(session["actual_tier_distribution"], previous_tier)
                if previous_high and session["high_risk_event_count"] > 0:
                    session["high_risk_event_count"] -= 1
            timeline.append(timeline_entry)
            session["decision_distribution"][decision_verdict] += 1
            session["actual_tier_distribution"][actual_tier] += 1
            if _risk_rank(risk_level) >= _risk_rank("high"):
                session["high_risk_event_count"] += 1
        else:
            session["event_count"] += 1
            session["decision_distribution"][decision_verdict] += 1
            session["actual_tier_distribution"][actual_tier] += 1
            session["d4_accumulation"] = session["d4_accumulation"] + int(dimensions.get("d4") or 0)
            if _risk_rank(risk_level) >= _risk_rank("high"):
                session["high_risk_event_count"] += 1
            if tool_name:
                session["tools_used"].add(str(tool_name))
            for hint in event.get("risk_hints", []) or []:
                session["risk_hints_seen"].add(str(hint))
            timeline.append(timeline_entry)

        if evidence_summary is not None:
            session["latest_evidence_summary"] = evidence_summary
        if l3_state is not None:
            session["latest_l3_state"] = str(l3_state)
        if l3_reason is not None:
            session["latest_l3_reason"] = str(l3_reason)
        if l3_reason_code is not None:
            session["latest_l3_reason_code"] = str(l3_reason_code)
        session["current_risk_level"] = risk_level
        if dimensions:
            session["cumulative_score"] = int(snapshot.get("composite_score") or 0)
            session["dimensions_latest"] = {
                "d1": int(dimensions.get("d1") or 0),
                "d2": int(dimensions.get("d2") or 0),
                "d3": int(dimensions.get("d3") or 0),
                "d4": int(dimensions.get("d4") or 0),
                "d5": int(dimensions.get("d5") or 0),
            }
        if occurred_at_ts and occurred_at_ts < _parse_iso_timestamp(session["first_event_at"]):
            session["first_event_at"] = occurred_at
        if occurred_at_ts >= float(session.get("last_event_ts", 0.0)):
            session["last_event_at"] = occurred_at
            session["last_event_ts"] = occurred_at_ts
        self._sessions[session_id] = session
        self._evict_if_needed()

    def list_sessions(
        self,
        *,
        status: str = "active",
        sort: str = "risk_level",
        min_risk: Optional[str] = None,
        limit: int = 50,
        since_seconds: Optional[int] = None,
    ) -> dict[str, Any]:
        _ = status
        sessions = list(self._sessions.values())
        if since_seconds is not None and since_seconds > 0:
            cutoff = time.time() - since_seconds
            sessions = [s for s in sessions if float(s.get("last_event_ts", 0.0)) >= cutoff]
        if min_risk:
            min_rank = _risk_rank(min_risk)
            sessions = [
                s for s in sessions
                if _risk_rank(s.get("current_risk_level")) >= min_rank
            ]

        if sort == "last_event":
            sessions.sort(
                key=lambda s: (float(s.get("last_event_ts", 0.0)), _risk_rank(s.get("current_risk_level"))),
                reverse=True,
            )
        else:
            sessions.sort(
                key=lambda s: (_risk_rank(s.get("current_risk_level")), float(s.get("last_event_ts", 0.0))),
                reverse=True,
            )

        effective_limit = min(max(limit, 1), 200)
        serialized_sessions: list[dict[str, Any]] = []
        for session in sessions[:effective_limit]:
            serialized_session = {
                "session_id": session["session_id"],
                "agent_id": session["agent_id"],
                "source_framework": session["source_framework"],
                "caller_adapter": session["caller_adapter"],
                "workspace_root": session["workspace_root"],
                "transcript_path": session["transcript_path"],
                "current_risk_level": session["current_risk_level"],
                "cumulative_score": session["cumulative_score"],
                "event_count": session["event_count"],
                "high_risk_event_count": session["high_risk_event_count"],
                "decision_distribution": dict(session["decision_distribution"]),
                "first_event_at": session["first_event_at"],
                "last_event_at": session["last_event_at"],
                "d4_accumulation": session["d4_accumulation"],
            }
            serialized_session.update(self._latest_session_annotations(session))
            serialized_sessions.append(serialized_session)

        return {
            "sessions": serialized_sessions,
            "total_active": len(sessions),
        }

    def get_session_risk(
        self,
        session_id: str,
        *,
        limit: int = 100,
        since_seconds: Optional[int] = None,
    ) -> dict[str, Any]:
        session = self._sessions.get(session_id)
        if session is None:
            return {
                "session_id": session_id,
                "current_risk_level": "low",
                "cumulative_score": 0,
                "dimensions_latest": {"d1": 0, "d2": 0, "d3": 0, "d4": 0, "d5": 0},
                "risk_timeline": [],
                "evidence_summary": None,
                "risk_hints_seen": [],
                "tools_used": [],
                "actual_tier_distribution": {},
            }

        timeline = list(session["risk_timeline"])
        if since_seconds is not None and since_seconds > 0:
            cutoff = time.time() - since_seconds
            timeline = [item for item in timeline if float(item.get("occurred_at_ts", 0.0)) >= cutoff]
        effective_limit = min(max(limit, 1), 1000)
        timeline = timeline[-effective_limit:]

        return {
            "session_id": session_id,
            "agent_id": session["agent_id"],
            "source_framework": session["source_framework"],
            "caller_adapter": session["caller_adapter"],
            "workspace_root": session["workspace_root"],
            "transcript_path": session["transcript_path"],
            "current_risk_level": session["current_risk_level"],
            "cumulative_score": session["cumulative_score"],
            "dimensions_latest": dict(session["dimensions_latest"]),
            "event_count": session["event_count"],
            "high_risk_event_count": session["high_risk_event_count"],
            "first_event_at": session["first_event_at"],
            "last_event_at": session["last_event_at"],
            "risk_timeline": [
                {
                    "event_id": item["event_id"],
                    "occurred_at": item["occurred_at"],
                    "risk_level": item["risk_level"],
                    "composite_score": item["composite_score"],
                    "tool_name": item["tool_name"],
                    "decision": item["decision"],
                    "actual_tier": item["actual_tier"],
                    "classified_by": item["classified_by"],
                    "l3_state": item.get("l3_state"),
                    "l3_reason": item.get("l3_reason"),
                    "l3_reason_code": item.get("l3_reason_code"),
                    **(
                        {"evidence_summary": item["evidence_summary"]}
                        if item.get("evidence_summary") is not None
                        else {}
                    ),
                }
                for item in timeline
            ],
            "evidence_summary": (
                dict(session["latest_evidence_summary"])
                if session.get("latest_evidence_summary") is not None
                else None
            ),
            "risk_hints_seen": sorted(session["risk_hints_seen"]),
            "tools_used": sorted(session["tools_used"]),
            "actual_tier_distribution": dict(session["actual_tier_distribution"]),
            **self._latest_session_annotations(session),
        }
