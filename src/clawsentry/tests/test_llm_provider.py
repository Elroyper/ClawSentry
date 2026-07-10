"""Tests for LLM Provider — AnthropicProvider and OpenAIProvider."""

import asyncio
import sys
import pytest
from unittest.mock import ANY, AsyncMock, MagicMock, patch

from clawsentry.gateway.llm.provider import (
    LLMProvider,
    LLMProviderConfig,
    AnthropicProvider,
    OpenAIProvider,
)


# ===========================================================================
# LLMProviderConfig Tests
# ===========================================================================

class TestLLMProviderConfig:
    def test_defaults(self):
        cfg = LLMProviderConfig(api_key="test-key")
        assert cfg.max_tokens == 256
        assert cfg.temperature == 0.0
        assert cfg.model == ""
        assert cfg.base_url is None

    def test_custom_values(self):
        cfg = LLMProviderConfig(
            api_key="k",
            model="claude-sonnet-4-6",
            max_tokens=512,
            temperature=0.1,
        )
        assert cfg.model == "claude-sonnet-4-6"
        assert cfg.max_tokens == 512


# ===========================================================================
# AnthropicProvider Tests (mocked HTTP — lazy client never touches network)
# ===========================================================================

class TestAnthropicProvider:
    def _make_provider(self) -> AnthropicProvider:
        """Create provider with lazy client (no network)."""
        return AnthropicProvider(LLMProviderConfig(api_key="test"))

    def test_provider_id(self):
        p = self._make_provider()
        assert p.provider_id == "anthropic"

    def test_default_model(self):
        p = self._make_provider()
        assert p._model == AnthropicProvider.DEFAULT_MODEL

    def test_custom_model(self):
        p = AnthropicProvider(LLMProviderConfig(api_key="test", model="claude-sonnet-4-6"))
        assert p._model == "claude-sonnet-4-6"

    def test_custom_base_url_is_passed_to_lazy_client(self):
        cfg = LLMProviderConfig(api_key="test", base_url="http://example.test")
        p = AnthropicProvider(cfg)
        fake_anthropic = MagicMock()

        with patch.dict(sys.modules, {"anthropic": fake_anthropic}):
            p._get_client()

        fake_anthropic.AsyncAnthropic.assert_called_once_with(
            api_key="test",
            base_url="http://example.test",
            http_client=ANY,
        )

    def test_custom_base_url_strips_v1_for_anthropic_sdk(self):
        cfg = LLMProviderConfig(api_key="test", base_url="http://example.test/v1/")
        p = AnthropicProvider(cfg)
        fake_anthropic = MagicMock()

        with patch.dict(sys.modules, {"anthropic": fake_anthropic}):
            p._get_client()

        fake_anthropic.AsyncAnthropic.assert_called_once_with(
            api_key="test",
            base_url="http://example.test",
            http_client=ANY,
        )

    def test_client_init_ignores_unsupported_all_proxy_env(self, monkeypatch):
        monkeypatch.setenv("ALL_PROXY", "socks://host.docker.internal:40567/")
        cfg = LLMProviderConfig(api_key="test", base_url="http://example.test/v1/")
        p = AnthropicProvider(cfg)
        fake_anthropic = MagicMock()

        with patch.dict(sys.modules, {"anthropic": fake_anthropic}):
            p._get_client()

        call_kwargs = fake_anthropic.AsyncAnthropic.call_args.kwargs
        assert call_kwargs["base_url"] == "http://example.test"
        assert getattr(call_kwargs["http_client"], "_trust_env", None) is False
        asyncio.run(call_kwargs["http_client"].aclose())

    def test_satisfies_protocol(self):
        p = self._make_provider()
        assert isinstance(p, LLMProvider)

    def test_complete_success(self):
        p = self._make_provider()
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text='{"risk_assessment":"high","reasons":["test"],"confidence":0.9}')]

        # Inject mock client before _get_client() is ever called
        mock_client = MagicMock()
        mock_client.messages.create = AsyncMock(return_value=mock_response)
        p._client = mock_client

        result = asyncio.run(
            p.complete("system", "user msg", timeout_ms=3000)
        )
        assert "risk_assessment" in result
        mock_client.messages.create.assert_awaited_once()

    def test_complete_uses_first_text_block_after_thinking_block(self):
        p = self._make_provider()
        mock_response = MagicMock()
        thinking_block = MagicMock()
        del thinking_block.text
        thinking_block.type = "thinking"
        text_block = MagicMock()
        text_block.type = "text"
        text_block.text = '{"risk_assessment":"high","reasons":["test"],"confidence":0.9}'
        mock_response.content = [thinking_block, text_block]

        mock_client = MagicMock()
        mock_client.messages.create = AsyncMock(return_value=mock_response)
        p._client = mock_client

        result = asyncio.run(
            p.complete("system", "user msg", timeout_ms=3000)
        )

        assert "risk_assessment" in result
        mock_client.messages.create.assert_awaited_once()

    def test_complete_timeout(self):
        p = self._make_provider()

        async def slow_call(*args, **kwargs):
            await asyncio.sleep(10)

        mock_client = MagicMock()
        mock_client.messages.create = slow_call
        p._client = mock_client

        with pytest.raises(asyncio.TimeoutError):
            asyncio.run(
                p.complete("system", "user msg", timeout_ms=50)
            )

    def test_effective_max_tokens_fallback(self):
        """When max_tokens=0 is passed, falls back to config.max_tokens."""
        cfg = LLMProviderConfig(api_key="test", max_tokens=512)
        p = AnthropicProvider(cfg)

        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="ok")]
        mock_client = MagicMock()
        mock_client.messages.create = AsyncMock(return_value=mock_response)
        p._client = mock_client

        asyncio.run(p.complete("sys", "msg", timeout_ms=3000, max_tokens=0))
        call_kwargs = mock_client.messages.create.call_args[1]
        assert call_kwargs["max_tokens"] == 512

    def test_complete_uses_minimax_instant_mode_extra_body(self):
        p = AnthropicProvider(LLMProviderConfig(api_key="test", model="MiniMax-2.7-w8a8"))
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text='{"risk_assessment":"low","reasons":[],"confidence":0.8}')]

        mock_client = MagicMock()
        mock_client.messages.create = AsyncMock(return_value=mock_response)
        p._client = mock_client

        asyncio.run(p.complete("system", "user msg", timeout_ms=3000))
        call_kwargs = mock_client.messages.create.call_args[1]
        assert call_kwargs["extra_body"] == {
            "thinking": {"type": "disabled"},
            "chat_template_kwargs": {"thinking": False},
        }


# ===========================================================================
# OpenAIProvider Tests (mocked HTTP — lazy client never touches network)
# ===========================================================================

class TestOpenAIProvider:
    def _make_provider(self, **kwargs) -> OpenAIProvider:
        """Create provider with lazy client (no network)."""
        return OpenAIProvider(LLMProviderConfig(api_key="test", **kwargs))

    def test_provider_id(self):
        p = self._make_provider()
        assert p.provider_id == "openai"

    def test_default_model(self):
        p = self._make_provider()
        assert p._model == OpenAIProvider.DEFAULT_MODEL

    def test_custom_model(self):
        p = self._make_provider(model="gpt-4o")
        assert p._model == "gpt-4o"

    def test_satisfies_protocol(self):
        p = self._make_provider()
        assert isinstance(p, LLMProvider)

    def test_complete_success(self):
        p = self._make_provider(model="gpt-4o-mini")
        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = '{"risk_assessment":"medium","reasons":[],"confidence":0.7}'
        mock_response.choices = [mock_choice]

        mock_client = MagicMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
        p._client = mock_client

        result = asyncio.run(
            p.complete("system", "user msg", timeout_ms=3000)
        )
        assert "risk_assessment" in result
        mock_client.chat.completions.create.assert_awaited_once()
        call_kwargs = mock_client.chat.completions.create.call_args[1]
        assert call_kwargs["extra_body"] is None

    def test_complete_uses_kimi_instant_mode_extra_body(self):
        p = self._make_provider(model="kimi-k2.5")
        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = '{"risk_assessment":"low","reasons":[],"confidence":0.8}'
        mock_response.choices = [mock_choice]

        mock_client = MagicMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
        p._client = mock_client

        asyncio.run(p.complete("system", "user msg", timeout_ms=3000))
        call_kwargs = mock_client.chat.completions.create.call_args[1]
        assert call_kwargs["extra_body"] == {
            "thinking": {"type": "disabled"},
            "chat_template_kwargs": {"thinking": False},
        }

    def test_complete_uses_deepseek_reasoning_payload(self):
        p = self._make_provider(model="deepseek-v4-pro")
        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = '{"risk_assessment":"low","reasons":[],"confidence":0.8}'
        mock_response.choices = [mock_choice]

        mock_client = MagicMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
        p._client = mock_client

        asyncio.run(p.complete("system", "user msg", timeout_ms=3000))
        call_kwargs = mock_client.chat.completions.create.call_args[1]
        assert call_kwargs["reasoning_effort"] == "high"
        assert call_kwargs["extra_body"] == {"thinking": {"type": "enabled"}}

    def test_complete_falls_back_to_kimi_reasoning_content(self):
        p = self._make_provider(model="kimi-k2.5")
        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = None
        mock_choice.message.reasoning = '{"risk_assessment":"low","reasons":[],"confidence":0.8}'
        mock_response.choices = [mock_choice]

        mock_client = MagicMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
        p._client = mock_client

        result = asyncio.run(p.complete("system", "user msg", timeout_ms=3000))
        assert "risk_assessment" in result

    def test_custom_base_url(self):
        """OpenAIProvider stores custom base_url for Ollama/local models."""
        cfg = LLMProviderConfig(api_key="test", base_url="http://localhost:11434/v1")
        p = OpenAIProvider(cfg)
        assert p.provider_id == "openai"
        assert p._config.base_url == "http://localhost:11434/v1"

    def test_client_init_ignores_unsupported_all_proxy_env(self, monkeypatch):
        monkeypatch.setenv("ALL_PROXY", "socks://host.docker.internal:40567/")
        cfg = LLMProviderConfig(api_key="test", base_url="http://localhost:11434/v1")
        p = OpenAIProvider(cfg)
        fake_openai = MagicMock()

        with patch.dict(sys.modules, {"openai": fake_openai}):
            p._get_client()

        call_kwargs = fake_openai.AsyncOpenAI.call_args.kwargs
        assert call_kwargs["base_url"] == "http://localhost:11434/v1"
        assert getattr(call_kwargs["http_client"], "_trust_env", None) is False
        asyncio.run(call_kwargs["http_client"].aclose())

    def test_complete_timeout(self):
        p = self._make_provider()

        async def slow_call(*args, **kwargs):
            await asyncio.sleep(10)

        mock_client = MagicMock()
        mock_client.chat.completions.create = slow_call
        p._client = mock_client

        with pytest.raises(asyncio.TimeoutError):
            asyncio.run(
                p.complete("system", "user msg", timeout_ms=50)
            )

    def test_effective_max_tokens_fallback(self):
        """When max_tokens=0 is passed, falls back to config.max_tokens."""
        cfg = LLMProviderConfig(api_key="test", max_tokens=512)
        p = OpenAIProvider(cfg)

        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = "ok"
        mock_response.choices = [mock_choice]

        mock_client = MagicMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
        p._client = mock_client

        asyncio.run(p.complete("sys", "msg", timeout_ms=3000, max_tokens=0))
        call_kwargs = mock_client.chat.completions.create.call_args[1]
        assert call_kwargs["max_tokens"] == 512

    def test_complete_forwards_response_format(self):
        """FSPR strict-final calls can request OpenAI JSON object mode."""
        p = self._make_provider(model="gpt-4o-mini")
        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = "{}"
        mock_response.choices = [mock_choice]

        mock_client = MagicMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
        p._client = mock_client

        response_format = {"type": "json_object"}
        asyncio.run(
            p.complete("system", "user msg", timeout_ms=3000, response_format=response_format)
        )
        call_kwargs = mock_client.chat.completions.create.call_args[1]
        assert call_kwargs["response_format"] == response_format

    def test_complete_retries_transient_502_within_budget(self):
        class ProviderHTTPError(Exception):
            status_code = 502

        p = self._make_provider(
            model="gpt-4o-mini",
            retry_max_attempts=2,
            retry_statuses=(502,),
            retry_backoff_ms=0,
            retry_jitter_ms=0,
            retry_min_remaining_ms=1,
        )
        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = "ok"
        mock_response.choices = [mock_choice]

        mock_client = MagicMock()
        mock_client.chat.completions.create = AsyncMock(
            side_effect=[ProviderHTTPError("Bad Gateway"), mock_response]
        )
        p._client = mock_client

        result = asyncio.run(p.complete("system", "user msg", timeout_ms=3000))

        assert result == "ok"
        assert mock_client.chat.completions.create.await_count == 2

    def test_complete_does_not_retry_non_transient_error(self):
        p = self._make_provider(
            model="gpt-4o-mini",
            retry_max_attempts=3,
            retry_statuses=(502,),
            retry_backoff_ms=0,
            retry_jitter_ms=0,
            retry_min_remaining_ms=1,
        )
        mock_client = MagicMock()
        mock_client.chat.completions.create = AsyncMock(
            side_effect=ValueError("invalid request")
        )
        p._client = mock_client

        with pytest.raises(ValueError):
            asyncio.run(p.complete("system", "user msg", timeout_ms=3000))

        assert mock_client.chat.completions.create.await_count == 1

    def test_complete_does_not_retry_when_remaining_budget_too_small(self):
        class ProviderHTTPError(Exception):
            status_code = 502

        p = self._make_provider(
            model="gpt-4o-mini",
            retry_max_attempts=2,
            retry_statuses=(502,),
            retry_backoff_ms=0,
            retry_jitter_ms=0,
            retry_min_remaining_ms=10_000,
        )
        mock_client = MagicMock()
        mock_client.chat.completions.create = AsyncMock(
            side_effect=ProviderHTTPError("Bad Gateway")
        )
        p._client = mock_client

        with pytest.raises(ProviderHTTPError):
            asyncio.run(p.complete("system", "user msg", timeout_ms=50))

        assert mock_client.chat.completions.create.await_count == 1

    def test_complete_does_not_retry_error_without_http_status(self):
        p = self._make_provider(
            model="gpt-4o-mini",
            retry_max_attempts=3,
            retry_statuses=(502, 503, 504),
            retry_backoff_ms=0,
            retry_jitter_ms=0,
            retry_min_remaining_ms=1,
        )
        mock_client = MagicMock()
        mock_client.chat.completions.create = AsyncMock(
            side_effect=ConnectionError("Bad Gateway")
        )
        p._client = mock_client

        with pytest.raises(ConnectionError):
            asyncio.run(p.complete("system", "user msg", timeout_ms=3000))

        assert mock_client.chat.completions.create.await_count == 1

    def test_complete_does_not_sleep_past_timeout_budget(self):
        class ProviderHTTPError(Exception):
            status_code = 502

        p = self._make_provider(
            model="gpt-4o-mini",
            retry_max_attempts=2,
            retry_statuses=(502,),
            retry_backoff_ms=15_000,
            retry_jitter_ms=0,
            retry_min_remaining_ms=0,
        )
        mock_client = MagicMock()
        mock_client.chat.completions.create = AsyncMock(
            side_effect=ProviderHTTPError("Bad Gateway")
        )
        p._client = mock_client

        with pytest.raises(ProviderHTTPError):
            asyncio.run(p.complete("system", "user msg", timeout_ms=50))

        assert mock_client.chat.completions.create.await_count == 1
