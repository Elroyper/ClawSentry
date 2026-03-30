"""
Tests for LLMUsage, _last_usage tracking, and InstrumentedProvider (P3 Task 2).

Covers:
  - LLMUsage defaults and frozen semantics
  - _last_usage attribute on AnthropicProvider and OpenAIProvider
  - InstrumentedProvider delegation (complete + provider_id)
  - InstrumentedProvider metrics reporting (ok / timeout / error)
  - InstrumentedProvider Protocol compliance
  - build_analyzer_from_env metrics parameter acceptance
"""

from __future__ import annotations

import asyncio
import inspect
from dataclasses import FrozenInstanceError
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from clawsentry.gateway.llm_provider import (
    AnthropicProvider,
    InstrumentedProvider,
    LLMProvider,
    LLMProviderConfig,
    LLMUsage,
    OpenAIProvider,
)


# ===========================================================================
# LLMUsage dataclass
# ===========================================================================


class TestLLMUsage:
    """LLMUsage frozen dataclass."""

    def test_defaults(self):
        u = LLMUsage()
        assert u.input_tokens == 0
        assert u.output_tokens == 0
        assert u.provider == ""
        assert u.model == ""

    def test_custom_values(self):
        u = LLMUsage(input_tokens=100, output_tokens=50, provider="anthropic", model="claude-haiku-4-5-20251001")
        assert u.input_tokens == 100
        assert u.output_tokens == 50
        assert u.provider == "anthropic"
        assert u.model == "claude-haiku-4-5-20251001"

    def test_frozen_immutable(self):
        u = LLMUsage(input_tokens=10)
        with pytest.raises(FrozenInstanceError):
            u.input_tokens = 20  # type: ignore[misc]

    def test_equality(self):
        a = LLMUsage(input_tokens=10, output_tokens=5, provider="openai", model="gpt-4o")
        b = LLMUsage(input_tokens=10, output_tokens=5, provider="openai", model="gpt-4o")
        assert a == b

    def test_inequality(self):
        a = LLMUsage(input_tokens=10)
        b = LLMUsage(input_tokens=20)
        assert a != b


# ===========================================================================
# _last_usage on concrete providers
# ===========================================================================


class TestAnthropicProviderLastUsage:
    """AnthropicProvider._last_usage tracking."""

    def _make_provider(self) -> AnthropicProvider:
        return AnthropicProvider(LLMProviderConfig(api_key="test"))

    def test_initial_last_usage_is_default(self):
        p = self._make_provider()
        assert p._last_usage == LLMUsage()

    def test_last_usage_updated_after_complete(self):
        p = self._make_provider()
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="hello")]
        mock_response.usage = MagicMock(input_tokens=42, output_tokens=17)

        mock_client = MagicMock()
        mock_client.messages.create = AsyncMock(return_value=mock_response)
        p._client = mock_client

        result = asyncio.run(p.complete("system", "user msg", timeout_ms=3000))
        assert result == "hello"
        assert p._last_usage.input_tokens == 42
        assert p._last_usage.output_tokens == 17
        assert p._last_usage.provider == "anthropic"
        assert p._last_usage.model == AnthropicProvider.DEFAULT_MODEL

    def test_last_usage_handles_missing_usage_attr(self):
        """When response has no .usage attribute, fallback to 0."""
        p = self._make_provider()
        mock_response = MagicMock(spec=[])  # no attributes at all
        mock_response.content = [MagicMock(text="ok")]
        # Create a response that has .content but no .usage
        del mock_response.usage  # ensure usage is missing (spec=[] means no attrs)

        mock_client = MagicMock()
        mock_client.messages.create = AsyncMock(return_value=mock_response)
        p._client = mock_client

        result = asyncio.run(p.complete("system", "user", timeout_ms=3000))
        assert result == "ok"
        assert p._last_usage.input_tokens == 0
        assert p._last_usage.output_tokens == 0


class TestOpenAIProviderLastUsage:
    """OpenAIProvider._last_usage tracking."""

    def _make_provider(self) -> OpenAIProvider:
        return OpenAIProvider(LLMProviderConfig(api_key="test"))

    def test_initial_last_usage_is_default(self):
        p = self._make_provider()
        assert p._last_usage == LLMUsage()

    def test_last_usage_updated_after_complete(self):
        p = self._make_provider()
        mock_choice = MagicMock()
        mock_choice.message.content = "world"
        mock_response = MagicMock()
        mock_response.choices = [mock_choice]
        mock_response.usage = MagicMock(prompt_tokens=99, completion_tokens=33)

        mock_client = MagicMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
        p._client = mock_client

        result = asyncio.run(p.complete("system", "user msg", timeout_ms=3000))
        assert result == "world"
        assert p._last_usage.input_tokens == 99
        assert p._last_usage.output_tokens == 33
        assert p._last_usage.provider == "openai"
        assert p._last_usage.model == OpenAIProvider.DEFAULT_MODEL

    def test_last_usage_handles_missing_usage_attr(self):
        """When response has no .usage attribute, fallback to 0."""
        p = self._make_provider()
        mock_choice = MagicMock()
        mock_choice.message.content = "ok"
        mock_response = MagicMock(spec=[])
        mock_response.choices = [mock_choice]

        mock_client = MagicMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
        p._client = mock_client

        result = asyncio.run(p.complete("system", "user", timeout_ms=3000))
        assert result == "ok"
        assert p._last_usage.input_tokens == 0
        assert p._last_usage.output_tokens == 0


# ===========================================================================
# InstrumentedProvider
# ===========================================================================


class TestInstrumentedProvider:
    """InstrumentedProvider wrapping and metrics delegation."""

    def _make_inner(self, response: str = "ok", provider_id: str = "test") -> MagicMock:
        """Create a mock inner provider."""
        inner = MagicMock()
        inner.provider_id = provider_id
        inner.complete = AsyncMock(return_value=response)
        inner._last_usage = LLMUsage(
            input_tokens=10, output_tokens=5, provider="test", model="test-model",
        )
        return inner

    def _make_metrics(self) -> MagicMock:
        """Create a mock MetricsCollector."""
        return MagicMock()

    # --- Protocol compliance ---

    def test_satisfies_protocol(self):
        inner = self._make_inner()
        metrics = self._make_metrics()
        ip = InstrumentedProvider(inner, metrics, tier="L2")
        assert isinstance(ip, LLMProvider)

    # --- Delegation ---

    def test_provider_id_delegates(self):
        inner = self._make_inner(provider_id="anthropic")
        metrics = self._make_metrics()
        ip = InstrumentedProvider(inner, metrics, tier="L2")
        assert ip.provider_id == "anthropic"

    def test_complete_delegates_and_returns_result(self):
        inner = self._make_inner(response="test result")
        metrics = self._make_metrics()
        ip = InstrumentedProvider(inner, metrics, tier="L2")

        result = asyncio.run(ip.complete("sys", "user", timeout_ms=3000))
        assert result == "test result"
        inner.complete.assert_awaited_once_with("sys", "user", 3000, 256)

    def test_complete_passes_max_tokens(self):
        inner = self._make_inner()
        metrics = self._make_metrics()
        ip = InstrumentedProvider(inner, metrics, tier="L2")

        asyncio.run(ip.complete("sys", "user", timeout_ms=3000, max_tokens=1024))
        inner.complete.assert_awaited_once_with("sys", "user", 3000, 1024)

    # --- Metrics recording on success ---

    def test_metrics_recorded_on_success(self):
        inner = self._make_inner()
        inner._last_usage = LLMUsage(
            input_tokens=100, output_tokens=50, provider="anthropic", model="haiku",
        )
        metrics = self._make_metrics()
        ip = InstrumentedProvider(inner, metrics, tier="L2")

        asyncio.run(ip.complete("sys", "user", timeout_ms=3000))

        metrics.record_llm_call.assert_called_once_with(
            provider="anthropic",
            tier="L2",
            status="ok",
            input_tokens=100,
            output_tokens=50,
        )

    def test_metrics_uses_tier_from_constructor(self):
        inner = self._make_inner()
        metrics = self._make_metrics()
        ip = InstrumentedProvider(inner, metrics, tier="L3")

        asyncio.run(ip.complete("sys", "user", timeout_ms=3000))

        call_kwargs = metrics.record_llm_call.call_args
        assert call_kwargs[1]["tier"] == "L3"

    # --- Error handling ---

    def test_metrics_recorded_on_timeout(self):
        inner = MagicMock()
        inner.provider_id = "test"
        inner.complete = AsyncMock(side_effect=asyncio.TimeoutError)
        inner._last_usage = LLMUsage()
        metrics = self._make_metrics()
        ip = InstrumentedProvider(inner, metrics, tier="L2")

        with pytest.raises(asyncio.TimeoutError):
            asyncio.run(ip.complete("sys", "user", timeout_ms=100))

        metrics.record_llm_call.assert_called_once()
        call_kwargs = metrics.record_llm_call.call_args[1]
        assert call_kwargs["status"] == "timeout"
        assert call_kwargs["input_tokens"] == 0
        assert call_kwargs["output_tokens"] == 0

    def test_metrics_recorded_on_error(self):
        inner = MagicMock()
        inner.provider_id = "test"
        inner.complete = AsyncMock(side_effect=RuntimeError("API error"))
        inner._last_usage = LLMUsage()
        metrics = self._make_metrics()
        ip = InstrumentedProvider(inner, metrics, tier="L2")

        with pytest.raises(RuntimeError, match="API error"):
            asyncio.run(ip.complete("sys", "user", timeout_ms=3000))

        metrics.record_llm_call.assert_called_once()
        call_kwargs = metrics.record_llm_call.call_args[1]
        assert call_kwargs["status"] == "error"

    def test_exception_reraises_after_recording(self):
        """InstrumentedProvider must re-raise exceptions after recording."""
        inner = MagicMock()
        inner.provider_id = "test"
        inner.complete = AsyncMock(side_effect=ValueError("bad"))
        inner._last_usage = LLMUsage()
        metrics = self._make_metrics()
        ip = InstrumentedProvider(inner, metrics, tier="L2")

        with pytest.raises(ValueError, match="bad"):
            asyncio.run(ip.complete("sys", "user", timeout_ms=3000))

        # metrics was still called
        assert metrics.record_llm_call.call_count == 1

    # --- Fallback when _last_usage is missing ---

    def test_fallback_when_no_last_usage(self):
        """If inner provider has no _last_usage, fall back to LLMUsage()."""
        inner = MagicMock()
        inner.provider_id = "test"
        inner.complete = AsyncMock(return_value="ok")
        # Explicitly remove _last_usage
        if hasattr(inner, "_last_usage"):
            del inner._last_usage
        metrics = self._make_metrics()
        ip = InstrumentedProvider(inner, metrics, tier="L2")

        asyncio.run(ip.complete("sys", "user", timeout_ms=3000))

        call_kwargs = metrics.record_llm_call.call_args[1]
        assert call_kwargs["input_tokens"] == 0
        assert call_kwargs["output_tokens"] == 0
        # Provider falls back to inner.provider_id
        assert call_kwargs["provider"] == "test"

    # --- _last_usage pass-through ---

    def test_last_usage_exposed_from_inner(self):
        """InstrumentedProvider exposes inner._last_usage."""
        inner = self._make_inner()
        inner._last_usage = LLMUsage(input_tokens=77, output_tokens=33, provider="x", model="y")
        metrics = self._make_metrics()
        ip = InstrumentedProvider(inner, metrics, tier="L2")

        assert ip._last_usage.input_tokens == 77
        assert ip._last_usage.output_tokens == 33


# ===========================================================================
# build_analyzer_from_env: metrics parameter
# ===========================================================================


class TestBuildAnalyzerMetricsParam:
    """build_analyzer_from_env() accepts optional metrics parameter."""

    def test_signature_accepts_metrics(self):
        from clawsentry.gateway.llm_factory import build_analyzer_from_env
        sig = inspect.signature(build_analyzer_from_env)
        assert "metrics" in sig.parameters
        param = sig.parameters["metrics"]
        assert param.default is None

    def test_factory_wraps_with_instrumented_provider_when_metrics_given(self):
        """When metrics is provided, L2 provider is wrapped with InstrumentedProvider."""
        import os
        from unittest.mock import patch as _patch
        from clawsentry.gateway.llm_factory import build_analyzer_from_env
        from clawsentry.gateway.semantic_analyzer import CompositeAnalyzer, LLMAnalyzer

        env = {
            "CS_LLM_PROVIDER": "openai",
            "OPENAI_API_KEY": "sk-test-key-123",
            "CS_LLM_MODEL": "",
            "CS_LLM_BASE_URL": "",
            "CS_L3_ENABLED": "",
            "ANTHROPIC_API_KEY": "",
        }
        mock_metrics = MagicMock()
        with _patch.dict(os.environ, env, clear=False):
            result = build_analyzer_from_env(metrics=mock_metrics)

        assert isinstance(result, CompositeAnalyzer)
        llm_analyzer = result._analyzers[1]
        assert isinstance(llm_analyzer, LLMAnalyzer)
        # The provider inside LLMAnalyzer should be InstrumentedProvider
        assert isinstance(llm_analyzer._provider, InstrumentedProvider)

    def test_factory_no_wrapping_when_metrics_is_none(self):
        """When metrics is None (default), provider is NOT wrapped."""
        import os
        from unittest.mock import patch as _patch
        from clawsentry.gateway.llm_factory import build_analyzer_from_env

        env = {
            "CS_LLM_PROVIDER": "openai",
            "OPENAI_API_KEY": "sk-test-key-123",
            "CS_LLM_MODEL": "",
            "CS_LLM_BASE_URL": "",
            "CS_L3_ENABLED": "",
            "ANTHROPIC_API_KEY": "",
        }
        with _patch.dict(os.environ, env, clear=False):
            result = build_analyzer_from_env()

        # Provider should NOT be InstrumentedProvider
        llm_analyzer = result._analyzers[1]
        assert not isinstance(llm_analyzer._provider, InstrumentedProvider)

    def test_factory_l3_gets_separate_instrumented_provider(self):
        """When L3 is enabled and metrics given, L3 gets a separate InstrumentedProvider with tier=L3."""
        import os
        from pathlib import Path
        from unittest.mock import patch as _patch
        from clawsentry.gateway.llm_factory import build_analyzer_from_env
        from clawsentry.gateway.server import TrajectoryStore
        from clawsentry.gateway.agent_analyzer import AgentAnalyzer

        env = {
            "CS_LLM_PROVIDER": "openai",
            "OPENAI_API_KEY": "sk-test-key-123",
            "CS_LLM_MODEL": "",
            "CS_LLM_BASE_URL": "",
            "CS_L3_ENABLED": "true",
            "ANTHROPIC_API_KEY": "",
        }
        mock_metrics = MagicMock()
        store = TrajectoryStore(db_path=":memory:")
        with _patch.dict(os.environ, env, clear=False):
            result = build_analyzer_from_env(
                metrics=mock_metrics,
                trajectory_store=store,
                workspace_root=Path("/tmp"),
            )

        assert len(result._analyzers) == 3
        # L2 provider
        l2_provider = result._analyzers[1]._provider
        assert isinstance(l2_provider, InstrumentedProvider)
        assert l2_provider._tier == "L2"

        # L3 provider
        l3_agent = result._analyzers[2]
        assert isinstance(l3_agent, AgentAnalyzer)
        assert isinstance(l3_agent._provider, InstrumentedProvider)
        assert l3_agent._provider._tier == "L3"

        # They must be different instances
        assert l2_provider is not l3_agent._provider
