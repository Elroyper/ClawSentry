"""Tests for ``clawsentry test-llm`` command."""

from __future__ import annotations

import asyncio
import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from clawsentry.cli.test_llm_command import (
    _build_provider,
    _test_l2,
    _test_l3,
    _test_reachability,
    run_test_llm,
)
from clawsentry.gateway.models import RiskLevel
from clawsentry.gateway.semantic_analyzer import L2Result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_LLM_ENV_KEYS = [
    "CS_LLM_PROVIDER",
    "CS_LLM_API_KEY",
    "CS_LLM_MODEL",
    "CS_LLM_BASE_URL",
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "CS_L3_ENABLED",
]


@pytest.fixture(autouse=True)
def _clean_llm_env(monkeypatch):
    for k in _LLM_ENV_KEYS:
        monkeypatch.delenv(k, raising=False)


# ---------------------------------------------------------------------------
# _build_provider
# ---------------------------------------------------------------------------


class TestBuildProvider:
    def test_no_provider_no_key(self):
        provider, info = _build_provider()
        assert provider is None
        assert "No LLM provider" in info

    def test_auto_detect_anthropic(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key-1234567890abcdef")
        provider, info = _build_provider()
        assert provider is not None
        assert info["provider"] == "anthropic"

    def test_auto_detect_openai(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key-1234567890abcdef")
        provider, info = _build_provider()
        assert provider is not None
        assert info["provider"] == "openai"

    def test_explicit_anthropic(self, monkeypatch):
        monkeypatch.setenv("CS_LLM_PROVIDER", "anthropic")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key-1234567890abcdef")
        provider, info = _build_provider()
        assert provider is not None
        assert info["provider"] == "anthropic"
        assert "sk-ant" in info["key_preview"]

    def test_explicit_openai(self, monkeypatch):
        monkeypatch.setenv("CS_LLM_PROVIDER", "openai")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key-1234567890abcdef")
        provider, info = _build_provider()
        assert provider is not None
        assert info["provider"] == "openai"

    def test_missing_api_key_anthropic(self, monkeypatch):
        monkeypatch.setenv("CS_LLM_PROVIDER", "anthropic")
        provider, info = _build_provider()
        assert provider is None
        assert "no API key" in info

    def test_missing_api_key_openai(self, monkeypatch):
        monkeypatch.setenv("CS_LLM_PROVIDER", "openai")
        provider, info = _build_provider()
        assert provider is None
        assert "no API key" in info

    def test_unknown_provider(self, monkeypatch):
        monkeypatch.setenv("CS_LLM_PROVIDER", "llamacpp")
        provider, info = _build_provider()
        assert provider is None
        assert "Unknown" in info

    def test_custom_model(self, monkeypatch):
        monkeypatch.setenv("CS_LLM_PROVIDER", "openai")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key-1234567890abcdef")
        monkeypatch.setenv("CS_LLM_MODEL", "gpt-4o")
        provider, info = _build_provider()
        assert info["model"] == "gpt-4o"

    def test_cs_llm_api_key_fallback(self, monkeypatch):
        monkeypatch.setenv("CS_LLM_PROVIDER", "anthropic")
        monkeypatch.setenv("CS_LLM_API_KEY", "sk-ant-test-key-1234567890abcdef")
        provider, info = _build_provider()
        assert provider is not None

    def test_key_preview_masking(self, monkeypatch):
        monkeypatch.setenv("CS_LLM_PROVIDER", "anthropic")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-api-1234567890abcdef-long-key")
        provider, info = _build_provider()
        assert "..." in info["key_preview"]
        # Should not expose full key
        assert "1234567890" not in info["key_preview"]


# ---------------------------------------------------------------------------
# _test_reachability
# ---------------------------------------------------------------------------


class TestReachability:
    def test_success(self):
        provider = MagicMock()
        provider.complete = AsyncMock(return_value="PONG")
        ok, latency, detail = asyncio.run(_test_reachability(provider))
        assert ok is True
        assert latency > 0
        assert "PONG" in detail

    def test_timeout(self):
        async def slow_complete(*args, **kwargs):
            raise asyncio.TimeoutError()

        provider = MagicMock()
        provider.complete = slow_complete
        ok, latency, detail = asyncio.run(_test_reachability(provider, timeout_ms=100))
        assert ok is False
        assert "Timeout" in detail

    def test_api_error(self):
        async def error_complete(*args, **kwargs):
            raise ConnectionError("Connection refused")

        provider = MagicMock()
        provider.complete = error_complete
        ok, latency, detail = asyncio.run(_test_reachability(provider))
        assert ok is False
        assert "Connection refused" in detail


class TestL2Probe:
    def test_success_formats_current_l2_result_shape(self, monkeypatch):
        async def fake_analyze(self, event, context, l1_snapshot, budget_ms):
            return L2Result(
                target_level=RiskLevel.HIGH,
                reasons=["credential access detected"],
                confidence=0.95,
            )

        monkeypatch.setattr(
            "clawsentry.gateway.semantic_analyzer.LLMAnalyzer.analyze",
            fake_analyze,
        )

        provider = MagicMock()
        ok, latency, detail = asyncio.run(_test_l2(provider))

        assert ok is True
        assert latency > 0
        assert "risk=high" in detail
        assert "confidence=0.95" in detail
        assert "credential access detected" in detail


class TestL3Probe:
    def test_fails_when_l3_trigger_not_matched(self, monkeypatch):
        async def fake_analyze(self, event, context, l1_snapshot, budget_ms):
            return L2Result(
                target_level=RiskLevel.HIGH,
                reasons=["L3 trigger not matched"],
                confidence=0.0,
                trace={
                    "degraded": True,
                    "trigger_reason": "trigger_not_matched",
                    "degradation_reason": "L3 trigger not matched",
                },
            )

        monkeypatch.setattr(
            "clawsentry.gateway.agent_analyzer.AgentAnalyzer.analyze",
            fake_analyze,
        )

        provider = MagicMock()
        ok, latency, detail = asyncio.run(_test_l3(provider))

        assert ok is False
        assert latency > 0
        assert "trigger not matched" in detail.lower()


# ---------------------------------------------------------------------------
# run_test_llm (integration-level, no real API calls)
# ---------------------------------------------------------------------------


class TestRunTestLlm:
    def test_no_provider_configured(self):
        code = run_test_llm(color=False)
        assert code == 1

    def test_no_provider_configured_json(self, capsys):
        code = run_test_llm(color=False, json_mode=True)
        assert code == 1
        output = capsys.readouterr().out
        data = json.loads(output)
        assert "error" in data

    @patch("clawsentry.cli.test_llm_command._build_provider")
    @patch("clawsentry.cli.test_llm_command._test_reachability")
    @patch("clawsentry.cli.test_llm_command._test_l2")
    def test_all_pass_skip_l3(self, mock_l2, mock_reach, mock_build):
        mock_provider = MagicMock()
        mock_build.return_value = (mock_provider, {
            "provider": "anthropic",
            "model": "claude-haiku-4-5-20251001",
            "base_url": "(default)",
            "key_preview": "sk-ant...cdef",
        })
        mock_reach.return_value = (True, 150.0, "PONG")
        mock_l2.return_value = (True, 800.0, "risk=high, confidence=0.95, reason=test")

        code = run_test_llm(color=False, skip_l3=True)
        assert code == 0

    @patch("clawsentry.cli.test_llm_command._build_provider")
    @patch("clawsentry.cli.test_llm_command._test_reachability")
    def test_api_unreachable_skips_rest(self, mock_reach, mock_build):
        mock_build.return_value = (MagicMock(), {
            "provider": "anthropic",
            "model": "test",
            "base_url": "(default)",
            "key_preview": "sk-...test",
        })
        mock_reach.return_value = (False, 5000.0, "Timeout after 5000ms")

        code = run_test_llm(color=False, skip_l3=True)
        assert code == 1

    @patch("clawsentry.cli.test_llm_command._build_provider")
    @patch("clawsentry.cli.test_llm_command._test_reachability")
    @patch("clawsentry.cli.test_llm_command._test_l2")
    def test_json_output(self, mock_l2, mock_reach, mock_build, capsys):
        mock_build.return_value = (MagicMock(), {
            "provider": "openai",
            "model": "gpt-4o-mini",
            "base_url": "(default)",
            "key_preview": "sk-...test",
        })
        mock_reach.return_value = (True, 200.0, "PONG")
        mock_l2.return_value = (True, 600.0, "risk=medium")

        code = run_test_llm(color=False, skip_l3=True, json_mode=True)
        assert code == 0
        output = capsys.readouterr().out
        data = json.loads(output)
        assert data["all_pass"] is True
        assert len(data["results"]) >= 3
