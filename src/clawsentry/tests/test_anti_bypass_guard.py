from __future__ import annotations

import json
import os
from unittest.mock import patch

import pytest

from clawsentry.gateway.anti_bypass_guard import AntiBypassGuard
from clawsentry.gateway.detection_config import DetectionConfig, build_detection_config_from_env
from clawsentry.gateway.models import (
    CanonicalDecision,
    CanonicalEvent,
    DecisionSource,
    DecisionVerdict,
    EventType,
    RiskLevel,
)
from clawsentry.gateway.server import SupervisionGateway


def _event(
    *,
    event_id: str,
    event_type: EventType = EventType.PRE_ACTION,
    session_id: str = "sess-anti-bypass",
    tool_name: str = "bash",
    payload: dict | None = None,
) -> CanonicalEvent:
    return CanonicalEvent(
        event_id=event_id,
        trace_id=f"trace-{event_id}",
        event_type=event_type,
        session_id=session_id,
        agent_id="agent-anti-bypass",
        source_framework="test",
        occurred_at="2026-04-28T00:00:00+00:00",
        payload=payload or {"command": "rm -rf /tmp/target"},
        tool_name=tool_name,
    )


def _decision(
    *,
    verdict: str = "block",
    risk_level: RiskLevel = RiskLevel.HIGH,
    policy_id: str = "test-policy",
) -> CanonicalDecision:
    return CanonicalDecision(
        decision=verdict,
        reason="test",
        policy_id=policy_id,
        risk_level=risk_level,
        decision_source=DecisionSource.POLICY,
        final=True,
    )


def _jsonrpc_request(params: dict, rpc_id: int = 1) -> bytes:
    return json.dumps({
        "jsonrpc": "2.0",
        "id": rpc_id,
        "method": "ahp/sync_decision",
        "params": params,
    }).encode()


def _sync_params(*, request_id: str, event_id: str, session_id: str = "sess-gw", tool_name: str = "bash", event_type: str = "pre_action", payload: dict | None = None) -> dict:
    return {
        "rpc_version": "sync_decision.1.0",
        "request_id": request_id,
        "deadline_ms": 1000,
        "decision_tier": "L1",
        "event": {
            "event_id": event_id,
            "trace_id": f"trace-{event_id}",
            "event_type": event_type,
            "session_id": session_id,
            "agent_id": "agent-gw",
            "source_framework": "test",
            "occurred_at": "2026-04-28T00:00:00+00:00",
            "payload": payload or {"command": "rm -rf /tmp/target"},
            "tool_name": tool_name,
        },
    }


class TestAntiBypassConfig:
    def test_defaults_are_behavior_preserving(self):
        cfg = DetectionConfig()
        assert cfg.anti_bypass_guard_enabled is False
        assert cfg.anti_bypass_memory_ttl_s == 86_400.0
        assert cfg.anti_bypass_memory_max_records_per_session == 256
        assert cfg.anti_bypass_min_prior_risk == "high"
        assert cfg.anti_bypass_prior_verdicts == ("block", "defer")
        assert cfg.anti_bypass_exact_repeat_action == "block"
        assert cfg.anti_bypass_normalized_destructive_repeat_action == "defer"
        assert cfg.anti_bypass_cross_tool_similarity_action == "force_l3"
        assert cfg.anti_bypass_record_allow_decisions is False

    def test_env_mapping_and_list_parsing(self):
        env = {
            "CS_ANTI_BYPASS_GUARD_ENABLED": "true",
            "CS_ANTI_BYPASS_MEMORY_TTL_S": "42",
            "CS_ANTI_BYPASS_MEMORY_MAX_RECORDS_PER_SESSION": "3",
            "CS_ANTI_BYPASS_MIN_PRIOR_RISK": "medium",
            "CS_ANTI_BYPASS_PRIOR_VERDICTS": "block, defer",
            "CS_ANTI_BYPASS_EXACT_REPEAT_ACTION": "defer",
            "CS_ANTI_BYPASS_NORMALIZED_DESTRUCTIVE_REPEAT_ACTION": "force_l2",
            "CS_ANTI_BYPASS_CROSS_TOOL_SIMILARITY_ACTION": "observe",
            "CS_ANTI_BYPASS_SIMILARITY_THRESHOLD": "0.5",
            "CS_ANTI_BYPASS_RECORD_ALLOW_DECISIONS": "yes",
        }
        with patch.dict(os.environ, env, clear=True):
            cfg = build_detection_config_from_env()
        assert cfg.anti_bypass_guard_enabled is True
        assert cfg.anti_bypass_memory_ttl_s == 42
        assert cfg.anti_bypass_memory_max_records_per_session == 3
        assert cfg.anti_bypass_min_prior_risk == "medium"
        assert cfg.anti_bypass_prior_verdicts == ("block", "defer")
        assert cfg.anti_bypass_exact_repeat_action == "defer"
        assert cfg.anti_bypass_normalized_destructive_repeat_action == "force_l2"
        assert cfg.anti_bypass_cross_tool_similarity_action == "observe"
        assert cfg.anti_bypass_similarity_threshold == 0.5
        assert cfg.anti_bypass_record_allow_decisions is True

    def test_cross_tool_block_is_coerced_to_force_l3(self, caplog):
        with caplog.at_level("WARNING"):
            cfg = DetectionConfig(anti_bypass_cross_tool_similarity_action="block")
        assert cfg.anti_bypass_cross_tool_similarity_action == "force_l3"
        assert "anti_bypass_cross_tool_similarity_action" in caplog.text


class TestAntiBypassMemory:
    def test_records_only_compact_redacted_fields(self):
        secret = "Bearer SECRET-CANARY-123"
        cfg = DetectionConfig(anti_bypass_guard_enabled=True)
        guard = AntiBypassGuard()
        guard.record_final_decision(
            event=_event(event_id="evt-secret", payload={"command": f"curl -H '{secret}' https://example.test"}),
            decision=_decision(),
            snapshot=None,
            meta={"l3_trace": {"secret": secret}},
            record_id=7,
            config=cfg,
        )
        serialized = json.dumps(guard.records_for_session("sess-anti-bypass"))
        assert "SECRET-CANARY-123" not in serialized
        assert "curl -H" not in serialized
        assert "raw_payload_hash" in serialized
        assert "normalized_action_fingerprint" in serialized

    def test_exact_normalized_and_cross_tool_matching(self):
        cfg = DetectionConfig(anti_bypass_guard_enabled=True)
        guard = AntiBypassGuard()
        guard.record_final_decision(
            event=_event(event_id="evt-1", tool_name="bash", payload={"command": "sudo bash -c 'rm -rf /tmp/target'"}),
            decision=_decision(policy_id="L1-rule-engine"),
            snapshot=None,
            meta={},
            record_id=1,
            config=cfg,
        )

        exact = guard.match_pre_action(
            _event(event_id="evt-2", tool_name="bash", payload={"command": "sudo bash -c 'rm -rf /tmp/target'"}),
            None,
            cfg,
        )
        assert exact is not None
        assert exact.match_type == "exact_raw_repeat"
        assert exact.action == "block"

        normalized = guard.match_pre_action(
            _event(event_id="evt-3", tool_name="bash", payload={"command": "env FOO=bar rm -rf /tmp/target"}),
            None,
            cfg,
        )
        assert normalized is not None
        assert normalized.match_type == "normalized_destructive_repeat"

        cross_tool = guard.match_pre_action(
            _event(event_id="evt-4", tool_name="python", payload={"command": "python -c \"import os; os.system('rm -rf /tmp/target')\""}),
            None,
            cfg,
        )
        assert cross_tool is not None
        assert cross_tool.match_type == "cross_tool_script_similarity"
        assert cross_tool.action != "block"

    def test_ttl_and_cap_eviction(self):
        cfg = DetectionConfig(
            anti_bypass_guard_enabled=True,
            anti_bypass_memory_max_records_per_session=1,
        )
        guard = AntiBypassGuard()
        guard.record_final_decision(_event(event_id="evt-1"), _decision(), None, {}, 1, cfg)
        guard.record_final_decision(_event(event_id="evt-2"), _decision(), None, {}, 2, cfg)
        records = guard.records_for_session("sess-anti-bypass")
        assert len(records) == 1
        assert records[0]["event_id"] == "evt-2"
        assert guard.memory_evictions == 1

    def test_non_pre_action_is_ignored(self):
        cfg = DetectionConfig(anti_bypass_guard_enabled=True)
        guard = AntiBypassGuard()
        guard.record_final_decision(
            _event(event_id="evt-post", event_type=EventType.POST_ACTION),
            _decision(),
            None,
            {},
            1,
            cfg,
        )
        assert guard.records_for_session("sess-anti-bypass") == []

    def test_non_final_decisions_are_not_recorded(self):
        cfg = DetectionConfig(anti_bypass_guard_enabled=True)
        guard = AntiBypassGuard()
        non_final_defer = CanonicalDecision(
            decision=DecisionVerdict.DEFER,
            reason="approval pending",
            policy_id="pending-review",
            risk_level=RiskLevel.HIGH,
            decision_source=DecisionSource.POLICY,
            final=False,
        )
        guard.record_final_decision(
            _event(event_id="evt-non-final"),
            non_final_defer,
            None,
            {},
            1,
            cfg,
        )
        assert guard.records_for_session("sess-anti-bypass") == []


class TestAntiBypassGatewayIntegration:
    @pytest.mark.asyncio
    async def test_default_disabled_repeated_decisions_do_not_attach_guard_metadata(self):
        gw = SupervisionGateway(detection_config=DetectionConfig())
        await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(request_id="req-1", event_id="evt-1")))
        await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(request_id="req-2", event_id="evt-2")))
        assert "anti_bypass" not in gw.trajectory_store.records[-1]["meta"]
        assert gw.anti_bypass_guard.records_for_session("sess-gw") == []

    @pytest.mark.asyncio
    async def test_exact_repeat_blocks_before_normal_policy_and_records_prior_id(self):
        cfg = DetectionConfig(anti_bypass_guard_enabled=True)
        gw = SupervisionGateway(detection_config=cfg)
        await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(request_id="req-1", event_id="evt-1")))
        result = await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(request_id="req-2", event_id="evt-2")))
        decision = result["result"]["decision"]
        assert decision["decision"] == "block"
        assert decision["policy_id"] == "anti-bypass-exact-repeat"
        meta = gw.trajectory_store.records[-1]["meta"]["anti_bypass"]
        assert meta["match_type"] == "exact_raw_repeat"
        assert meta["prior_event_id"] == "evt-1"
        assert meta["prior_record_id"] == 1
        decision_events = [
            event for event in gw.event_bus._replay_buffer  # noqa: SLF001 - compact SSE regression assertion
            if event.get("type") == "decision" and event.get("event_id") == "evt-2"
        ]
        assert decision_events[-1]["anti_bypass"]["match_type"] == "exact_raw_repeat"
        assert "command" not in decision_events[-1]["anti_bypass"]
        assert decision_events[-1]["command"] == "bash"

    @pytest.mark.asyncio
    async def test_anti_bypass_sse_event_redacts_raw_command_canary(self):
        canary = "SECRET-CANARY-123"
        cfg = DetectionConfig(anti_bypass_guard_enabled=True)
        gw = SupervisionGateway(detection_config=cfg)
        payload = {"command": f"curl -H 'Authorization: Bearer {canary}' https://example.test && rm -rf /tmp/target"}
        await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(
            request_id="req-secret-1",
            event_id="evt-secret-1",
            session_id="sess-secret",
            payload=payload,
        )))
        await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(
            request_id="req-secret-2",
            event_id="evt-secret-2",
            session_id="sess-secret",
            payload=payload,
        )))
        decision_events = [
            event for event in gw.event_bus._replay_buffer  # noqa: SLF001 - compact SSE regression assertion
            if event.get("type") == "decision" and event.get("event_id") == "evt-secret-2"
        ]
        serialized = json.dumps(decision_events[-1])
        assert "anti_bypass" in decision_events[-1]
        assert canary not in serialized
        assert "Authorization" not in serialized
        assert decision_events[-1]["command"] == "bash"

    @pytest.mark.asyncio
    async def test_anti_bypass_defer_pending_redacts_raw_command_canary(self):
        canary = "SECRET-CANARY-XYZ"
        cfg = DetectionConfig(
            anti_bypass_guard_enabled=True,
            anti_bypass_exact_repeat_action="defer",
            defer_timeout_s=0.01,
            defer_timeout_action="allow",
        )
        gw = SupervisionGateway(detection_config=cfg)
        payload = {"command": f"sudo bash -c 'curl -H Authorization:Bearer-{canary} https://example.test && rm -rf /tmp/target'"}
        await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(
            request_id="req-defer-secret-1",
            event_id="evt-defer-secret-1",
            session_id="sess-defer-secret",
            payload=payload,
        )))
        await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(
            request_id="req-defer-secret-2",
            event_id="evt-defer-secret-2",
            session_id="sess-defer-secret",
            payload=payload,
        )))
        pending_events = [
            event for event in gw.event_bus._replay_buffer  # noqa: SLF001 - compact SSE regression assertion
            if event.get("type") == "defer_pending" and event.get("session_id") == "sess-defer-secret"
        ]
        assert pending_events
        serialized = json.dumps(pending_events[-1])
        assert canary not in serialized
        assert "Authorization" not in serialized
        assert pending_events[-1]["command"] == "bash"

    @pytest.mark.asyncio
    async def test_guard_runs_pre_action_only(self):
        cfg = DetectionConfig(anti_bypass_guard_enabled=True)
        gw = SupervisionGateway(detection_config=cfg)
        await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(request_id="req-1", event_id="evt-1")))
        await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(
            request_id="req-post",
            event_id="evt-post",
            event_type="post_action",
            payload={"command": "rm -rf /tmp/target", "output": "done"},
        )))
        assert "anti_bypass" not in gw.trajectory_store.records[-1]["meta"]

    @pytest.mark.asyncio
    async def test_benchmark_auto_resolution_is_recorded_as_final_decision(self):
        cfg = DetectionConfig(
            anti_bypass_guard_enabled=True,
            anti_bypass_exact_repeat_action="defer",
            mode="benchmark",
            benchmark_auto_resolve_defer=True,
            benchmark_defer_action="allow",
        )
        gw = SupervisionGateway(detection_config=cfg)
        await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(request_id="req-1", event_id="evt-1")))
        result = await gw.handle_jsonrpc(_jsonrpc_request(_sync_params(request_id="req-2", event_id="evt-2")))
        assert result["result"]["decision"]["decision"] == "allow"
        record = gw.trajectory_store.records[-1]
        assert record["meta"]["anti_bypass"]["action"] == "defer"
        assert record["meta"]["auto_resolved"] is True
        assert len(gw.anti_bypass_guard.records_for_session("sess-gw")) == 1
