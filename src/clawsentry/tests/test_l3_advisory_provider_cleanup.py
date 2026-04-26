"""Regression tests for async L3 advisory provider cleanup."""

from __future__ import annotations

import asyncio
import json

from clawsentry.gateway.l3_advisory_worker import (
    LLMAdvisoryProviderConfig,
    LLMProviderBridgeAdvisoryProvider,
)
from clawsentry.gateway.llm_provider import LLMProviderConfig, OpenAIProvider


def _worker_request() -> dict[str, object]:
    return {
        "schema_version": "cs.l3_advisory.worker_request.v1",
        "provider": "openai",
        "model": "gpt-test",
        "snapshot_id": "snap-1",
        "session_id": "sess-1",
        "trigger_reason": "threshold",
        "event_range": {"from_record_id": 1, "to_record_id": 1},
        "risk_summary": {},
        "deadline_ms": 1000,
        "budget": {"max_tokens": 512},
        "events": [],
    }


def test_bridge_closes_async_provider_on_worker_loop() -> None:
    class ClosingProvider:
        provider_id = "openai"

        def __init__(self) -> None:
            self.complete_loop_id: int | None = None
            self.close_loop_id: int | None = None
            self.closed = False

        async def complete(self, system_prompt, user_message, timeout_ms, max_tokens=256):
            self.complete_loop_id = id(asyncio.get_running_loop())
            return json.dumps(
                {
                    "schema_version": "cs.l3_advisory.worker_response.v1",
                    "risk_level": "high",
                    "findings": ["cleanup regression"],
                    "confidence": 0.9,
                    "recommended_operator_action": "inspect",
                    "l3_state": "completed",
                    "l3_reason_code": None,
                }
            )

        async def aclose(self) -> None:
            self.close_loop_id = id(asyncio.get_running_loop())
            self.closed = True

    async_provider = ClosingProvider()
    provider = LLMProviderBridgeAdvisoryProvider(
        config=LLMAdvisoryProviderConfig(
            enabled=True,
            provider="openai",
            model="gpt-test",
            api_key="sk-test",
            dry_run=False,
        ),
        provider=async_provider,
    )

    response = provider.complete(_worker_request())

    assert response["l3_state"] == "completed"
    assert async_provider.closed is True
    assert async_provider.close_loop_id == async_provider.complete_loop_id


def test_openai_provider_aclose_closes_client_and_drops_loop_bound_state() -> None:
    provider = OpenAIProvider(LLMProviderConfig(api_key="sk-test"))

    class Client:
        def __init__(self) -> None:
            self.closed = False

        async def close(self) -> None:
            self.closed = True

    client = Client()
    provider._client = client

    asyncio.run(provider.aclose())

    assert client.closed is True
    assert provider._client is None
