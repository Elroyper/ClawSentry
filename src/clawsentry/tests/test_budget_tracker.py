"""
Tests for LLMBudgetTracker + DetectionConfig budget field + Gateway integration (P3).

Covers:
  - Unlimited budget always allows spending
  - Budget tracking and exhaustion detection
  - Notified-once semantics (record_spend returns True only on first exhaustion)
  - Daily reset on UTC day boundary (mocked datetime)
  - Thread safety under concurrent record_spend calls
  - DetectionConfig default budget 0.0, env var override, negative rejected
  - Gateway has budget_tracker reflecting config value
"""

from __future__ import annotations

import os
import threading
from datetime import date
from unittest.mock import patch

import pytest

from clawsentry.gateway.metrics import LLMBudgetTracker
from clawsentry.gateway.detection_config import (
    DetectionConfig,
    build_detection_config_from_env,
)
from clawsentry.gateway.server import SupervisionGateway


# ---------------------------------------------------------------------------
# LLMBudgetTracker — unlimited mode
# ---------------------------------------------------------------------------


class TestBudgetTrackerUnlimited:
    """Budget = 0 means unlimited; all operations are no-ops."""

    def test_can_spend_always_true(self):
        bt = LLMBudgetTracker(daily_budget_usd=0.0)
        assert bt.can_spend() is True

    def test_record_spend_returns_false(self):
        bt = LLMBudgetTracker(daily_budget_usd=0.0)
        assert bt.record_spend(100.0) is False
        assert bt.can_spend() is True

    def test_negative_budget_treated_as_unlimited(self):
        bt = LLMBudgetTracker(daily_budget_usd=-5.0)
        assert bt.can_spend() is True
        assert bt.record_spend(999.0) is False


# ---------------------------------------------------------------------------
# LLMBudgetTracker — limited mode
# ---------------------------------------------------------------------------


class TestBudgetTrackerLimited:
    """Budget > 0 enables spend tracking and exhaustion detection."""

    def test_tracks_spending(self):
        bt = LLMBudgetTracker(daily_budget_usd=1.0)
        assert bt.can_spend() is True
        assert bt.record_spend(0.3) is False  # not exhausted yet
        assert bt.can_spend() is True
        assert bt.record_spend(0.3) is False
        assert bt.can_spend() is True

    def test_exhaustion_detected(self):
        bt = LLMBudgetTracker(daily_budget_usd=1.0)
        assert bt.record_spend(0.5) is False
        assert bt.record_spend(0.5) is True  # newly exhausted
        assert bt.can_spend() is False

    def test_notified_once_only(self):
        bt = LLMBudgetTracker(daily_budget_usd=1.0)
        assert bt.record_spend(1.0) is True  # first exhaustion
        assert bt.record_spend(0.5) is False  # already notified
        assert bt.record_spend(0.5) is False

    def test_exact_budget_exhaustion(self):
        bt = LLMBudgetTracker(daily_budget_usd=0.50)
        assert bt.record_spend(0.50) is True  # exactly at limit
        assert bt.can_spend() is False

    def test_over_budget_still_reported_once(self):
        bt = LLMBudgetTracker(daily_budget_usd=1.0)
        assert bt.record_spend(2.0) is True  # way over
        assert bt.record_spend(1.0) is False  # already notified
        assert bt.can_spend() is False


# ---------------------------------------------------------------------------
# LLMBudgetTracker — daily reset
# ---------------------------------------------------------------------------


class TestBudgetTrackerDailyReset:
    """Budget resets at UTC day boundary."""

    def test_reset_on_new_day(self):
        bt = LLMBudgetTracker(daily_budget_usd=1.0)
        bt.record_spend(0.8)
        assert bt.can_spend() is True

        # Simulate previous day by backdating _day_start
        bt._day_start = date(2000, 1, 1)
        # _maybe_reset sees today != _day_start → resets counters
        assert bt.can_spend() is True
        # Spend should have been reset to 0
        assert bt._daily_spend == 0.0

    def test_reset_allows_new_exhaustion_notification(self):
        bt = LLMBudgetTracker(daily_budget_usd=1.0)
        assert bt.record_spend(1.0) is True  # exhausted day 1
        assert bt.can_spend() is False

        # Simulate next day by backdating _day_start
        bt._day_start = date(2000, 1, 1)
        # After reset, budget is available again
        assert bt.can_spend() is True
        assert bt.record_spend(1.0) is True  # exhausted day 2

    def test_reset_clears_exhausted_flag(self):
        bt = LLMBudgetTracker(daily_budget_usd=0.5)
        bt.record_spend(0.5)
        assert bt._exhausted_notified is True

        # Simulate day change
        bt._day_start = date(2000, 1, 1)
        bt.can_spend()  # triggers reset
        assert bt._exhausted_notified is False
        assert bt._daily_spend == 0.0


# ---------------------------------------------------------------------------
# LLMBudgetTracker — thread safety
# ---------------------------------------------------------------------------


class TestBudgetTrackerThreadSafety:
    """Concurrent record_spend calls produce exactly one exhaustion notification."""

    def test_concurrent_spend(self):
        bt = LLMBudgetTracker(daily_budget_usd=1.0)
        results: list[bool] = []
        lock = threading.Lock()

        def spend():
            r = bt.record_spend(0.1)
            with lock:
                results.append(r)

        threads = [threading.Thread(target=spend) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Exactly one thread should have received True (newly exhausted)
        assert results.count(True) == 1
        assert bt.can_spend() is False


# ---------------------------------------------------------------------------
# DetectionConfig — llm_daily_budget_usd
# ---------------------------------------------------------------------------


class TestDetectionConfigBudget:
    """DetectionConfig field for LLM daily budget."""

    def test_default_budget_is_zero(self):
        cfg = DetectionConfig()
        assert cfg.llm_daily_budget_usd == 0.0

    def test_custom_budget(self):
        cfg = DetectionConfig(llm_daily_budget_usd=5.0)
        assert cfg.llm_daily_budget_usd == 5.0

    def test_negative_budget_rejected(self):
        with pytest.raises(ValueError, match="llm_daily_budget_usd must be >= 0"):
            DetectionConfig(llm_daily_budget_usd=-1.0)

    def test_budget_from_env(self):
        with patch.dict(os.environ, {"CS_LLM_DAILY_BUDGET_USD": "2.5"}):
            cfg = build_detection_config_from_env()
            assert cfg.llm_daily_budget_usd == 2.5

    def test_budget_zero_from_env(self):
        with patch.dict(os.environ, {"CS_LLM_DAILY_BUDGET_USD": "0"}):
            cfg = build_detection_config_from_env()
            assert cfg.llm_daily_budget_usd == 0.0

    def test_invalid_budget_env_ignored(self):
        with patch.dict(os.environ, {"CS_LLM_DAILY_BUDGET_USD": "not-a-number"}):
            cfg = build_detection_config_from_env()
            assert cfg.llm_daily_budget_usd == 0.0  # fallback to default


# ---------------------------------------------------------------------------
# Gateway integration — budget_tracker
# ---------------------------------------------------------------------------


class TestGatewayBudgetTracker:
    """SupervisionGateway creates budget_tracker from detection config."""

    def test_gateway_has_budget_tracker(self):
        gw = SupervisionGateway()
        assert hasattr(gw, "budget_tracker")
        assert isinstance(gw.budget_tracker, LLMBudgetTracker)

    def test_gateway_budget_reflects_config(self):
        cfg = DetectionConfig(llm_daily_budget_usd=10.0)
        gw = SupervisionGateway(detection_config=cfg)
        assert gw.budget_tracker._budget == 10.0

    def test_gateway_default_budget_unlimited(self):
        gw = SupervisionGateway()
        assert gw.budget_tracker._budget == 0.0
        assert gw.budget_tracker.can_spend() is True
