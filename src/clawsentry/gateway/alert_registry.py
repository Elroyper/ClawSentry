"""In-memory store for triggered alerts with acknowledgement support."""

from __future__ import annotations

import time
from typing import Any, Optional

from .models import utc_now_iso


class AlertRegistry:
    """In-memory store for triggered alerts with acknowledgement support."""

    MAX_ALERTS = 5_000
    VALID_SEVERITIES = {"low", "medium", "high", "critical"}

    def __init__(self) -> None:
        self._alerts: dict[str, dict[str, Any]] = {}  # alert_id -> alert record

    def add(self, alert: dict[str, Any]) -> None:
        """Insert a new alert, evicting the oldest entry when the cap is reached."""
        if len(self._alerts) >= self.MAX_ALERTS:
            oldest = next(iter(self._alerts))
            del self._alerts[oldest]
        alert_id = str(alert.get("alert_id") or "")
        if alert_id:
            self._alerts[alert_id] = alert

    def list_alerts(
        self,
        *,
        severity: Optional[str] = None,
        acknowledged: Optional[bool] = None,
        since_seconds: Optional[int] = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        alerts = list(self._alerts.values())
        if since_seconds is not None and since_seconds > 0:
            cutoff = time.time() - since_seconds
            alerts = [a for a in alerts if float(a.get("triggered_at_ts", 0.0)) >= cutoff]
        if severity is not None:
            alerts = [a for a in alerts if a.get("severity") == severity]
        if acknowledged is not None:
            alerts = [a for a in alerts if a.get("acknowledged", False) == acknowledged]
        alerts.sort(key=lambda a: float(a.get("triggered_at_ts", 0.0)), reverse=True)
        effective_limit = min(max(limit, 1), 1000)
        serialized = [
            {
                "alert_id": a["alert_id"],
                "severity": a["severity"],
                "metric": a["metric"],
                "session_id": a.get("session_id"),
                "message": a["message"],
                "details": a.get("details", {}),
                "triggered_at": a["triggered_at"],
                "acknowledged": a.get("acknowledged", False),
                "acknowledged_by": a.get("acknowledged_by"),
                "acknowledged_at": a.get("acknowledged_at"),
            }
            for a in alerts[:effective_limit]
        ]
        total_unacknowledged = sum(
            1 for a in self._alerts.values() if not a.get("acknowledged", False)
        )
        return {
            "alerts": serialized,
            "total_unacknowledged": total_unacknowledged,
        }

    def acknowledge(self, alert_id: str, acknowledged_by: str) -> Optional[dict[str, Any]]:
        """Mark an alert as acknowledged. Returns updated alert or None if not found."""
        alert = self._alerts.get(alert_id)
        if alert is None:
            return None
        alert["acknowledged"] = True
        alert["acknowledged_by"] = acknowledged_by
        alert["acknowledged_at"] = utc_now_iso()
        return {
            "alert_id": alert["alert_id"],
            "acknowledged": True,
            "acknowledged_by": alert["acknowledged_by"],
            "acknowledged_at": alert["acknowledged_at"],
        }
