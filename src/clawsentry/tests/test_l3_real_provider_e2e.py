"""Explicit opt-in L3 runtime E2E against a real LLM provider.

This test is intentionally skipped by default because it performs a network
call and consumes provider quota.  Enable it only when a real provider key is
available:

    CS_L3_RUN_REAL_E2E=true python -m pytest \
      src/clawsentry/tests/test_l3_real_provider_e2e.py -q
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from clawsentry.gateway.agent_analyzer import AgentAnalyzer, AgentAnalyzerConfig
from clawsentry.gateway.detection_config import DetectionConfig
from clawsentry.gateway.llm_provider import AnthropicProvider, LLMProviderConfig, OpenAIProvider
from clawsentry.gateway.models import RPC_VERSION
from clawsentry.gateway.review_skills import SkillRegistry
from clawsentry.gateway.review_toolkit import ReadOnlyToolkit
from clawsentry.gateway.semantic_analyzer import CompositeAnalyzer, RuleBasedAnalyzer
from clawsentry.gateway.server import SupervisionGateway
from clawsentry.gateway.trajectory_store import TrajectoryStore


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _jsonrpc_request(method: str, params: dict, rpc_id: int = 1) -> bytes:
    return json.dumps({
        "jsonrpc": "2.0",
        "id": rpc_id,
        "method": method,
        "params": params,
    }).encode()


def _sync_decision_params(**overrides) -> dict:
    base = {
        "rpc_version": RPC_VERSION,
        "request_id": "req-real-l3-e2e",
        "deadline_ms": 45_000,
        "decision_tier": "L2",
        "event": {
            "event_id": "evt-real-l3-e2e",
            "trace_id": "trace-real-l3-e2e",
            "event_type": "pre_action",
            "session_id": "sess-real-l3-e2e",
            "agent_id": "agent-real-l3-e2e",
            "source_framework": "pytest-real-provider",
            "occurred_at": "2026-04-29T00:00:00+00:00",
            "payload": {"command": "cat prod-token.txt"},
            "tool_name": "bash",
            "risk_hints": ["credential_exfiltration"],
        },
    }
    base.update(overrides)
    return base


def _real_provider_from_env():
    provider = os.environ.get("CS_L3_REAL_E2E_PROVIDER", "openai").strip().lower()
    if provider == "openai":
        api_key = os.environ.get("CS_LLM_API_KEY") or os.environ.get("OPENAI_API_KEY")
        if not api_key:
            pytest.skip("CS_L3_RUN_REAL_E2E=true requires CS_LLM_API_KEY or OPENAI_API_KEY")
        return OpenAIProvider(
            LLMProviderConfig(
                api_key=api_key,
                model=os.environ.get("CS_L3_REAL_E2E_MODEL")
                or os.environ.get("CS_LLM_MODEL")
                or "gpt-4o-mini",
                base_url=os.environ.get("CS_L3_REAL_E2E_BASE_URL")
                or os.environ.get("CS_LLM_BASE_URL")
                or None,
            )
        )
    if provider == "anthropic":
        api_key = os.environ.get("CS_LLM_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            pytest.skip("CS_L3_RUN_REAL_E2E=true requires CS_LLM_API_KEY or ANTHROPIC_API_KEY")
        return AnthropicProvider(
            LLMProviderConfig(
                api_key=api_key,
                model=os.environ.get("CS_L3_REAL_E2E_MODEL")
                or os.environ.get("CS_LLM_MODEL")
                or AnthropicProvider.DEFAULT_MODEL,
                base_url=os.environ.get("CS_L3_REAL_E2E_BASE_URL")
                or os.environ.get("CS_LLM_BASE_URL")
                or None,
            )
        )
    pytest.skip("CS_L3_REAL_E2E_PROVIDER must be openai or anthropic")


def _write_real_e2e_skill(skills_dir: Path) -> None:
    skills_dir.mkdir()
    (skills_dir / "credential-audit.yaml").write_text(
        """
name: credential-audit
description: Real-provider L3 E2E credential audit fixture
triggers:
  risk_hints:
    - credential_exfiltration
  tool_names:
    - bash
  payload_patterns:
    - token
system_prompt: |
  You are a deterministic ClawSentry L3 E2E verifier.
  Return exactly one JSON object and no markdown.
  The JSON object MUST be:
  {"risk_level":"critical","findings":["real L3 provider executed"],"confidence":0.99}
evaluation_criteria:
  - name: credential_access
    severity: high
    description: Credential-like material is being read by a shell command.
""".strip(),
        encoding="utf-8",
    )
    (skills_dir / "general-review.yaml").write_text(
        """
name: general-review
description: Real-provider L3 E2E fallback review fixture
triggers:
  risk_hints: []
  tool_names: []
  payload_patterns: []
system_prompt: |
  You are a deterministic ClawSentry L3 E2E verifier.
  Return exactly one JSON object and no markdown.
evaluation_criteria:
  - name: general_risk
    severity: medium
    description: General security risk.
""".strip(),
        encoding="utf-8",
    )


@pytest.mark.asyncio
async def test_real_provider_l3_replace_l2_eager_executes_and_persists_trace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    if not _truthy(os.environ.get("CS_L3_RUN_REAL_E2E")):
        pytest.skip("Set CS_L3_RUN_REAL_E2E=true to run real L3 provider E2E")
    if not _truthy(os.environ.get("CS_L3_REAL_E2E_ALLOW_PROXY")):
        for key in (
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ):
            monkeypatch.delenv(key, raising=False)

    provider = _real_provider_from_env()
    skills_dir = tmp_path / "skills"
    _write_real_e2e_skill(skills_dir)
    trajectory_store = TrajectoryStore(db_path=":memory:")
    trajectory_store.record(
        event={
            "event_id": "evt-real-l3-history",
            "event_type": "pre_action",
            "session_id": "sess-real-l3-e2e",
            "source_framework": "pytest-real-provider",
            "tool_name": "read_file",
        },
        decision={"decision": "allow", "risk_level": "low"},
        snapshot={"risk_level": "low"},
        meta={"actual_tier": "L1", "record_type": "decision"},
    )
    agent = AgentAnalyzer(
        provider=provider,
        toolkit=ReadOnlyToolkit(tmp_path, trajectory_store),
        skill_registry=SkillRegistry(skills_dir),
        config=AgentAnalyzerConfig(
            enable_multi_turn=False,
            initial_trajectory_limit=5,
            provider_timeout_ms=30_000,
            hard_cap_ms=35_000,
        ),
        trajectory_store=trajectory_store,
    )
    gateway = SupervisionGateway(
        trajectory_store=trajectory_store,
        analyzer=CompositeAnalyzer([RuleBasedAnalyzer(), agent]),
        detection_config=DetectionConfig(
            l3_routing_mode="replace_l2",
            l3_trigger_profile="eager",
            l2_budget_ms=35_000,
            l3_budget_ms=35_000,
            hard_timeout_ms=45_000,
        ),
    )

    try:
        result = await gateway.handle_jsonrpc(
            _jsonrpc_request("ahp/sync_decision", _sync_decision_params())
        )
    finally:
        close = getattr(provider, "aclose", None)
        if callable(close):
            try:
                await close()
            except RuntimeError:
                # OpenAI/HTTPX clients may be lazily created inside the
                # policy engine's worker thread event loop.  The runtime
                # behavior under test has already completed; do not fail the
                # E2E on cross-loop cleanup quirks.
                pass

    payload = result["result"]
    assert payload["actual_tier"] == "L3"
    assert payload["l3_requested"] is True
    assert payload["l3_state"] == "completed"

    record = gateway.trajectory_store.records[-1]
    assert record["meta"]["actual_tier"] == "L3"
    assert record["meta"]["l3_state"] == "completed"
    assert record["l3_trace"]["trigger_reason"] == "eager"
    assert record["l3_trace"]["skill_selected"] == "credential-audit"
    assert record["l3_trace"]["turns"][0]["type"] == "llm_call"
    assert record["l3_trace"]["final_verdict"]["findings"] == ["real L3 provider executed"]

    risk = gateway.report_session_risk("sess-real-l3-e2e")
    assert risk["risk_timeline"][-1]["actual_tier"] == "L3"
    assert risk["risk_timeline"][-1]["l3_state"] == "completed"
    assert risk["risk_timeline"][-1]["l3_trace_summary"]["retained_sources"]
