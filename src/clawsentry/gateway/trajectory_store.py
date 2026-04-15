"""SQLite-backed trajectory store with retention + query window support."""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Callable, Optional

logger = logging.getLogger("clawsentry")

DEFAULT_TRAJECTORY_DB_PATH = "/tmp/clawsentry-trajectory.db"
DEFAULT_TRAJECTORY_RETENTION_SECONDS = 30 * 24 * 3600
HIGH_RISK_LEVELS = {"high", "critical"}

INVALID_EVENT_COUNT_THRESHOLD_1M = 20
INVALID_EVENT_RATE_CRITICAL_5M = 0.01
INVALID_EVENT_RATE_WARNING_15M_MIN = 0.001
INVALID_EVENT_RATE_WARNING_15M_MAX = 0.01

MAX_WINDOW_SECONDS = 604800  # 1 week


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


class TrajectoryStore:
    """SQLite-backed trajectory store with retention + query window support."""

    def __init__(
        self,
        db_path: str = ":memory:",
        retention_seconds: int = DEFAULT_TRAJECTORY_RETENTION_SECONDS,
    ) -> None:
        self.db_path = db_path
        self.retention_seconds = retention_seconds
        if db_path != ":memory:":
            db_dir = os.path.dirname(db_path)
            if db_dir:
                os.makedirs(db_dir, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._io_metrics = {
            "count": _new_io_metric_bucket(),
            "summary": _new_io_metric_bucket(),
            "replay_session": _new_io_metric_bucket(),
            "replay_session_page": _new_io_metric_bucket(),
        }
        self._init_schema()
        self._prune_expired()

    def io_metrics_snapshot(self) -> dict[str, dict[str, float | int]]:
        return {
            name: _snapshot_io_metric(bucket)
            for name, bucket in self._io_metrics.items()
        }

    def _init_schema(self) -> None:
        cur = self._conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS trajectory_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recorded_at_ts REAL NOT NULL,
                recorded_at TEXT NOT NULL,
                session_id TEXT,
                source_framework TEXT,
                event_type TEXT,
                decision TEXT,
                risk_level TEXT,
                event_json TEXT NOT NULL,
                decision_json TEXT NOT NULL,
                snapshot_json TEXT NOT NULL,
                meta_json TEXT NOT NULL
            )
            """
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_traj_recorded_at ON trajectory_records(recorded_at_ts)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_traj_session_id ON trajectory_records(session_id)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_traj_source_framework ON trajectory_records(source_framework)"
        )
        # Migrate: add l3_trace_json column if missing
        try:
            cur.execute("ALTER TABLE trajectory_records ADD COLUMN l3_trace_json TEXT")
        except sqlite3.OperationalError:
            pass  # Column already exists
        self._conn.commit()

    @staticmethod
    def _iso_from_ts(ts: float) -> str:
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

    def _prune_expired(self, now_ts: Optional[float] = None) -> None:
        if self.retention_seconds <= 0:
            return
        cutoff = (now_ts or time.time()) - self.retention_seconds
        cur = self._conn.cursor()
        cur.execute("DELETE FROM trajectory_records WHERE recorded_at_ts < ?", (cutoff,))
        self._conn.commit()

    def record(
        self,
        event: dict,
        decision: dict,
        snapshot: dict,
        meta: dict,
        recorded_at_ts: Optional[float] = None,
        l3_trace: Optional[dict] = None,
    ) -> None:
        ts = recorded_at_ts if recorded_at_ts is not None else time.time()
        recorded_at = self._iso_from_ts(ts)
        cur = self._conn.cursor()
        cur.execute(
            """
            INSERT INTO trajectory_records (
                recorded_at_ts,
                recorded_at,
                session_id,
                source_framework,
                event_type,
                decision,
                risk_level,
                event_json,
                decision_json,
                snapshot_json,
                meta_json,
                l3_trace_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ts,
                recorded_at,
                event.get("session_id"),
                event.get("source_framework"),
                event.get("event_type"),
                decision.get("decision"),
                decision.get("risk_level"),
                json.dumps(event),
                json.dumps(decision),
                json.dumps(snapshot),
                json.dumps(meta),
                json.dumps(l3_trace) if l3_trace else None,
            ),
        )
        self._conn.commit()
        self._prune_expired(now_ts=ts)

    def record_resolution(
        self,
        *,
        event: dict,
        decision: dict,
        snapshot: dict,
        meta: dict,
        recorded_at_ts: Optional[float] = None,
        l3_trace: Optional[dict] = None,
    ) -> None:
        resolution_meta = dict(meta)
        resolution_meta["record_type"] = "decision_resolution"
        self.record(
            event=event,
            decision=decision,
            snapshot=snapshot,
            meta=resolution_meta,
            recorded_at_ts=recorded_at_ts,
            l3_trace=l3_trace,
        )

    def _query_records(
        self,
        *,
        session_id: Optional[str] = None,
        since_seconds: Optional[int] = None,
        limit: Optional[int] = None,
        before_id: Optional[int] = None,
    ) -> list[dict[str, Any]]:
        self._prune_expired()
        clauses: list[str] = []
        params: list[Any] = []
        if session_id is not None:
            clauses.append("session_id = ?")
            params.append(session_id)
        if since_seconds is not None and since_seconds > 0:
            clauses.append("recorded_at_ts >= ?")
            params.append(time.time() - since_seconds)
        if before_id is not None and before_id > 0:
            clauses.append("id < ?")
            params.append(before_id)

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        if limit is not None and limit > 0:
            sql = (
                "SELECT id, recorded_at_ts, recorded_at, event_json, decision_json, snapshot_json, meta_json, l3_trace_json "
                "FROM trajectory_records "
                f"{where_sql} "
                "ORDER BY id DESC LIMIT ?"
            )
            rows = self._conn.execute(sql, (*params, limit)).fetchall()
            rows = list(reversed(rows))
        else:
            sql = (
                "SELECT id, recorded_at_ts, recorded_at, event_json, decision_json, snapshot_json, meta_json, l3_trace_json "
                "FROM trajectory_records "
                f"{where_sql} "
                "ORDER BY id ASC"
            )
            rows = self._conn.execute(sql, params).fetchall()

        records: list[dict[str, Any]] = []
        for row in rows:
            l3_raw = row["l3_trace_json"]
            records.append(
                {
                    "event": json.loads(row["event_json"]),
                    "decision": json.loads(row["decision_json"]),
                    "risk_snapshot": json.loads(row["snapshot_json"]),
                    "meta": json.loads(row["meta_json"]),
                    "record_id": int(row["id"]),
                    "recorded_at": row["recorded_at"],
                    "recorded_at_ts": float(row["recorded_at_ts"]),
                    "l3_trace": json.loads(l3_raw) if l3_raw else None,
                }
            )
        return records

    @property
    def records(self) -> list[dict[str, Any]]:
        return self._query_records()

    def count(self, since_seconds: Optional[int] = None) -> int:
        start = time.perf_counter()
        try:
            self._prune_expired()
            clauses: list[str] = []
            params: list[Any] = []
            if since_seconds is not None and since_seconds > 0:
                clauses.append("recorded_at_ts >= ?")
                params.append(time.time() - since_seconds)
            where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
            sql = f"SELECT COUNT(*) AS c FROM trajectory_records {where_sql}"
            row = self._conn.execute(sql, params).fetchone()
            return int(row["c"]) if row else 0
        finally:
            _observe_io_metric(self._io_metrics["count"], time.perf_counter() - start)

    def summary(self, since_seconds: Optional[int] = None) -> dict[str, Any]:
        start = time.perf_counter()
        try:
            records = self._query_records(since_seconds=since_seconds)
            by_source_framework: dict[str, int] = defaultdict(int)
            by_event_type: dict[str, int] = defaultdict(int)
            by_decision: dict[str, int] = defaultdict(int)
            by_risk_level: dict[str, int] = defaultdict(int)
            by_actual_tier: dict[str, int] = defaultdict(int)
            by_caller_adapter: dict[str, int] = defaultdict(int)
            now_ts = time.time()

            for rec in records:
                event = rec.get("event", {})
                decision = rec.get("decision", {})
                meta = rec.get("meta", {})
                source_framework = str(event.get("source_framework", "unknown"))
                event_type = str(event.get("event_type", "unknown"))
                decision_verdict = str(decision.get("decision", "unknown"))
                risk_level = str(decision.get("risk_level", "unknown"))
                actual_tier = str(meta.get("actual_tier", "L1"))
                caller_adapter = str(meta.get("caller_adapter", "unknown"))

                by_source_framework[source_framework] += 1
                by_event_type[event_type] += 1
                by_decision[decision_verdict] += 1
                by_risk_level[risk_level] += 1
                by_actual_tier[actual_tier] += 1
                by_caller_adapter[caller_adapter] += 1

            return {
                "total_records": len(records),
                "by_source_framework": dict(by_source_framework),
                "by_event_type": dict(by_event_type),
                "by_decision": dict(by_decision),
                "by_risk_level": dict(by_risk_level),
                "by_actual_tier": dict(by_actual_tier),
                "by_caller_adapter": dict(by_caller_adapter),
                "invalid_event": self._build_invalid_event_metrics(records, now_ts),
                "high_risk_trend": self._build_high_risk_trend(records, now_ts),
            }
        finally:
            _observe_io_metric(self._io_metrics["summary"], time.perf_counter() - start)

    @staticmethod
    def _is_invalid_event_record(record: dict[str, Any]) -> bool:
        event = record.get("event", {})
        decision = record.get("decision", {})
        event_type = str(event.get("event_type", "")).lower()
        event_subtype = str(event.get("event_subtype", "")).lower()
        failure_class = str(decision.get("failure_class", "")).lower()
        return (
            event_type == "invalid_event"
            or event_subtype == "invalid_event"
            or failure_class == "input_invalid"
        )

    @staticmethod
    def _is_high_risk_record(record: dict[str, Any]) -> bool:
        decision = record.get("decision", {})
        risk_level = str(decision.get("risk_level", "")).lower()
        return risk_level in HIGH_RISK_LEVELS

    @staticmethod
    def _count_in_window(
        records: list[dict[str, Any]],
        *,
        now_ts: float,
        window_seconds: int,
        predicate: Optional[Callable[[dict[str, Any]], bool]] = None,
    ) -> int:
        cutoff = now_ts - window_seconds
        count = 0
        for rec in records:
            recorded_at_ts = float(rec.get("recorded_at_ts", 0.0))
            if recorded_at_ts < cutoff:
                continue
            if predicate is not None and not predicate(rec):
                continue
            count += 1
        return count

    @staticmethod
    def _count_in_range(
        records: list[dict[str, Any]],
        *,
        start_ts: float,
        end_ts: float,
        predicate: Optional[Callable[[dict[str, Any]], bool]] = None,
    ) -> int:
        count = 0
        for rec in records:
            recorded_at_ts = float(rec.get("recorded_at_ts", 0.0))
            if recorded_at_ts < start_ts or recorded_at_ts >= end_ts:
                continue
            if predicate is not None and not predicate(rec):
                continue
            count += 1
        return count

    def _build_invalid_event_metrics(
        self,
        records: list[dict[str, Any]],
        now_ts: float,
    ) -> dict[str, Any]:
        total_5m = self._count_in_window(records, now_ts=now_ts, window_seconds=300)
        total_15m = self._count_in_window(records, now_ts=now_ts, window_seconds=900)
        invalid_1m = self._count_in_window(
            records, now_ts=now_ts, window_seconds=60, predicate=self._is_invalid_event_record,
        )
        invalid_5m = self._count_in_window(
            records, now_ts=now_ts, window_seconds=300, predicate=self._is_invalid_event_record,
        )
        invalid_15m = self._count_in_window(
            records, now_ts=now_ts, window_seconds=900, predicate=self._is_invalid_event_record,
        )

        rate_5m = (invalid_5m / total_5m) if total_5m > 0 else 0.0
        rate_15m = (invalid_15m / total_15m) if total_15m > 0 else 0.0

        alerts: list[dict[str, Any]] = []
        if invalid_1m > INVALID_EVENT_COUNT_THRESHOLD_1M:
            alerts.append({
                "metric": "invalid_event_count_1m", "severity": "critical",
                "value": invalid_1m, "threshold": ">20/min",
            })
        if rate_5m > INVALID_EVENT_RATE_CRITICAL_5M:
            alerts.append({
                "metric": "invalid_event_rate_5m", "severity": "critical",
                "value": rate_5m, "threshold": ">1%/5m",
            })
        if total_15m > 0 and INVALID_EVENT_RATE_WARNING_15M_MIN <= rate_15m <= INVALID_EVENT_RATE_WARNING_15M_MAX:
            alerts.append({
                "metric": "invalid_event_rate_15m", "severity": "medium",
                "value": rate_15m, "threshold": "0.1%-1%/15m",
            })

        return {
            "count_1m": invalid_1m, "count_5m": invalid_5m, "count_15m": invalid_15m,
            "rate_5m": rate_5m, "rate_15m": rate_15m, "alerts": alerts,
        }

    def _build_high_risk_trend(
        self,
        records: list[dict[str, Any]],
        now_ts: float,
    ) -> dict[str, Any]:
        def ratio(high_count: int, total_count: int) -> float:
            return (high_count / total_count) if total_count > 0 else 0.0

        total_5m = self._count_in_window(records, now_ts=now_ts, window_seconds=300)
        total_15m = self._count_in_window(records, now_ts=now_ts, window_seconds=900)
        total_60m = self._count_in_window(records, now_ts=now_ts, window_seconds=3600)
        high_5m = self._count_in_window(records, now_ts=now_ts, window_seconds=300, predicate=self._is_high_risk_record)
        high_15m = self._count_in_window(records, now_ts=now_ts, window_seconds=900, predicate=self._is_high_risk_record)
        high_60m = self._count_in_window(records, now_ts=now_ts, window_seconds=3600, predicate=self._is_high_risk_record)

        prev_5m_high = self._count_in_range(
            records, start_ts=now_ts - 600, end_ts=now_ts - 300, predicate=self._is_high_risk_record,
        )
        if high_5m > prev_5m_high:
            direction_5m = "up"
        elif high_5m < prev_5m_high:
            direction_5m = "down"
        else:
            direction_5m = "flat"

        series_5m: list[dict[str, Any]] = []
        for idx in range(12):
            bucket_start_ts = now_ts - (12 - idx) * 300
            bucket_end_ts = bucket_start_ts + 300
            total_bucket = self._count_in_range(records, start_ts=bucket_start_ts, end_ts=bucket_end_ts)
            high_bucket = self._count_in_range(records, start_ts=bucket_start_ts, end_ts=bucket_end_ts, predicate=self._is_high_risk_record)
            series_5m.append({
                "bucket_start": self._iso_from_ts(bucket_start_ts),
                "bucket_end": self._iso_from_ts(bucket_end_ts),
                "total_count": total_bucket,
                "high_or_critical_count": high_bucket,
                "ratio": ratio(high_bucket, total_bucket),
            })

        return {
            "windows": {
                "5m": {"count": high_5m, "total": total_5m, "ratio": ratio(high_5m, total_5m)},
                "15m": {"count": high_15m, "total": total_15m, "ratio": ratio(high_15m, total_15m)},
                "60m": {"count": high_60m, "total": total_60m, "ratio": ratio(high_60m, total_60m)},
            },
            "direction_5m": direction_5m,
            "series_5m": series_5m,
        }

    def replay_session(
        self,
        session_id: str,
        limit: int = 100,
        since_seconds: Optional[int] = None,
    ) -> list[dict[str, Any]]:
        start = time.perf_counter()
        try:
            return self._query_records(session_id=session_id, limit=limit, since_seconds=since_seconds)
        finally:
            _observe_io_metric(self._io_metrics["replay_session"], time.perf_counter() - start)

    def replay_session_page(
        self,
        session_id: str,
        *,
        limit: int = 100,
        cursor: Optional[int] = None,
        since_seconds: Optional[int] = None,
    ) -> dict[str, Any]:
        start = time.perf_counter()
        try:
            effective_limit = min(max(limit, 1), 500)
            records = self._query_records(
                session_id=session_id,
                limit=effective_limit + 1,
                since_seconds=since_seconds,
                before_id=cursor,
            )
            has_more = len(records) > effective_limit
            page_records = records[-effective_limit:] if has_more else records
            next_cursor = page_records[0]["record_id"] if has_more and page_records else None
            return {
                "records": page_records,
                "next_cursor": next_cursor,
            }
        finally:
            _observe_io_metric(self._io_metrics["replay_session_page"], time.perf_counter() - start)

    def clear(self) -> None:
        self._conn.execute("DELETE FROM trajectory_records")
        self._conn.commit()


def _parse_iso_timestamp(value: Optional[str]) -> float:
    """Parse an ISO-8601 timestamp string to a Unix timestamp float."""
    if not value:
        return 0.0
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError):
        return 0.0
