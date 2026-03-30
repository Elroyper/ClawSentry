"""
Prometheus metrics collector for ClawSentry Gateway.

Provides a ``MetricsCollector`` class that records decision counters, latency
histograms, LLM token/cost tracking, and session/defer gauges.  When
``prometheus_client`` is not installed the collector degrades gracefully to a
no-op implementation so the gateway runs without the optional dependency.

Usage::

    from clawsentry.gateway.metrics import MetricsCollector

    mc = MetricsCollector(enabled=True)
    mc.record_decision(verdict="allow", risk_level="low", risk_score=0.12,
                       tier="L1", source_framework="test", latency_s=0.002)
    print(mc.generate_metrics_text())
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("clawsentry.metrics")

# ---------------------------------------------------------------------------
# Optional prometheus_client import
# ---------------------------------------------------------------------------

try:
    from prometheus_client import (
        CollectorRegistry,
        Counter,
        Gauge,
        Histogram,
        generate_latest,
    )
    _PROMETHEUS_AVAILABLE = True
except ImportError:  # pragma: no cover
    _PROMETHEUS_AVAILABLE = False

# ---------------------------------------------------------------------------
# Cost estimation helper
# ---------------------------------------------------------------------------

# Hardcoded per-token pricing (USD per 1M tokens).
# These are rough estimates — Task 2 will add per-provider config.
_PRICING: dict[str, tuple[float, float]] = {
    # provider: (input_price_per_M, output_price_per_M)
    "anthropic": (3.0, 15.0),
    "openai": (2.5, 10.0),
}
_DEFAULT_PRICING = (5.0, 15.0)  # fallback for unknown providers


def _estimate_cost(
    provider: str,
    input_tokens: int,
    output_tokens: int,
) -> float:
    """Estimate USD cost for an LLM call based on hardcoded pricing.

    Returns 0.0 when both token counts are zero.
    """
    if input_tokens == 0 and output_tokens == 0:
        return 0.0
    input_price, output_price = _PRICING.get(
        provider.lower(), _DEFAULT_PRICING,
    )
    return (input_tokens * input_price + output_tokens * output_price) / 1_000_000


# ---------------------------------------------------------------------------
# MetricsCollector
# ---------------------------------------------------------------------------


class MetricsCollector:
    """Prometheus metrics collector with graceful no-op degradation.

    Each instance creates a **dedicated** ``CollectorRegistry`` so that
    multiple test instances do not pollute each other's state (the global
    default registry is never used).

    Parameters
    ----------
    enabled:
        If ``False`` — or if ``prometheus_client`` is not installed — all
        recording methods become silent no-ops and
        :meth:`generate_metrics_text` returns ``b""``.
    """

    def __init__(self, enabled: bool = True) -> None:
        if not _PROMETHEUS_AVAILABLE:
            self.enabled = False
        else:
            self.enabled = enabled

        if not self.enabled:
            return

        # Private registry — never touches the global default.
        self._registry = CollectorRegistry()

        # --- Counters ---
        self._decisions_total = Counter(
            "clawsentry_decisions_total",
            "Total supervision decisions",
            ["verdict", "risk_level", "tier", "source_framework"],
            registry=self._registry,
        )

        self._llm_calls_total = Counter(
            "clawsentry_llm_calls_total",
            "Total LLM API calls",
            ["provider", "tier", "status"],
            registry=self._registry,
        )

        self._llm_tokens_total = Counter(
            "clawsentry_llm_tokens_total",
            "Total LLM tokens consumed",
            ["provider", "direction"],
            registry=self._registry,
        )

        self._llm_cost_total = Counter(
            "clawsentry_llm_cost_usd_total",
            "Estimated cumulative LLM cost in USD",
            ["provider"],
            registry=self._registry,
        )

        # --- Histograms ---
        self._decision_latency = Histogram(
            "clawsentry_decision_latency_seconds",
            "Decision latency in seconds",
            ["tier", "source_framework"],
            registry=self._registry,
        )

        self._risk_score = Histogram(
            "clawsentry_risk_score",
            "Observed risk scores",
            ["source_framework"],
            registry=self._registry,
        )

        # --- Gauges ---
        self._active_sessions = Gauge(
            "clawsentry_active_sessions",
            "Number of currently active sessions",
            registry=self._registry,
        )

        self._defers_pending = Gauge(
            "clawsentry_defers_pending",
            "Number of DEFER decisions awaiting operator resolution",
            registry=self._registry,
        )

    # ------------------------------------------------------------------
    # Recording methods
    # ------------------------------------------------------------------

    def record_decision(
        self,
        *,
        verdict: str,
        risk_level: str,
        risk_score: float,
        tier: str,
        source_framework: str,
        latency_s: float,
    ) -> None:
        """Record a supervision decision."""
        if not self.enabled:
            return
        self._decisions_total.labels(
            verdict=verdict,
            risk_level=risk_level,
            tier=tier,
            source_framework=source_framework,
        ).inc()
        self._decision_latency.labels(
            tier=tier,
            source_framework=source_framework,
        ).observe(latency_s)
        self._risk_score.labels(
            source_framework=source_framework,
        ).observe(risk_score)

    def record_llm_call(
        self,
        *,
        provider: str,
        tier: str,
        status: str,
        input_tokens: int = 0,
        output_tokens: int = 0,
    ) -> None:
        """Record an LLM API call with token counts."""
        if not self.enabled:
            return
        self._llm_calls_total.labels(
            provider=provider,
            tier=tier,
            status=status,
        ).inc()
        if input_tokens:
            self._llm_tokens_total.labels(
                provider=provider,
                direction="input",
            ).inc(input_tokens)
        if output_tokens:
            self._llm_tokens_total.labels(
                provider=provider,
                direction="output",
            ).inc(output_tokens)
        cost = _estimate_cost(provider, input_tokens, output_tokens)
        if cost > 0:
            self._llm_cost_total.labels(provider=provider).inc(cost)

    def session_started(self) -> None:
        """Increment the active-sessions gauge."""
        if not self.enabled:
            return
        self._active_sessions.inc()

    def session_ended(self) -> None:
        """Decrement the active-sessions gauge."""
        if not self.enabled:
            return
        self._active_sessions.dec()

    def defer_registered(self) -> None:
        """Increment the pending-defers gauge."""
        if not self.enabled:
            return
        self._defers_pending.inc()

    def defer_resolved(self) -> None:
        """Decrement the pending-defers gauge."""
        if not self.enabled:
            return
        self._defers_pending.dec()

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------

    def generate_metrics_text(self) -> bytes:
        """Render all metrics in Prometheus exposition format.

        Returns ``b""`` when the collector is disabled.
        """
        if not self.enabled:
            return b""
        return generate_latest(self._registry)


# ---------------------------------------------------------------------------
# LLMBudgetTracker
# ---------------------------------------------------------------------------


class LLMBudgetTracker:
    """Thread-safe daily LLM budget tracker (UTC).

    Tracks cumulative LLM spend per UTC day and reports when the daily budget
    is exhausted.  A budget of ``0`` (the default) means *unlimited* — all
    checks return ``True`` and :meth:`record_spend` is a no-op.

    Parameters
    ----------
    daily_budget_usd:
        Maximum spend (USD) per UTC day.  ``0`` disables budgeting.
    """

    def __init__(self, daily_budget_usd: float = 0.0) -> None:
        self._budget = daily_budget_usd  # 0 = unlimited
        self._lock = threading.Lock()
        self._daily_spend = 0.0
        self._day_start = datetime.now(timezone.utc).date()
        self._exhausted_notified = False

    def _maybe_reset(self) -> None:
        """Reset if UTC day has changed.  Must be called under lock."""
        today = datetime.now(timezone.utc).date()
        if today != self._day_start:
            self._daily_spend = 0.0
            self._day_start = today
            self._exhausted_notified = False

    def can_spend(self) -> bool:
        """Return ``True`` if the budget allows further LLM calls."""
        if self._budget <= 0:
            return True  # unlimited
        with self._lock:
            self._maybe_reset()
            return self._daily_spend < self._budget

    def record_spend(self, cost_usd: float) -> bool:
        """Record spend.  Returns ``True`` if budget NEWLY exhausted (first time only)."""
        if self._budget <= 0:
            return False
        with self._lock:
            self._maybe_reset()
            was_ok = self._daily_spend < self._budget
            self._daily_spend += cost_usd
            is_exhausted = self._daily_spend >= self._budget
            if was_ok and is_exhausted and not self._exhausted_notified:
                self._exhausted_notified = True
                return True
            return False
