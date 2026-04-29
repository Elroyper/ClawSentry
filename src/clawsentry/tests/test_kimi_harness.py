"""Tests for Kimi CLI native hook dispatch through the harness."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from clawsentry.adapters.a3s_adapter import A3SCodeAdapter
from clawsentry.adapters.a3s_gateway_harness import A3SGatewayHarness
from clawsentry.gateway.models import (
    ActionScope,
    CanonicalDecision,
    DecisionEffects,
    DecisionSource,
    DecisionVerdict,
    EventType,
    RiskLevel,
    SessionEffectRequest,
)


class _GatewayRecorder:
    def __init__(self) -> None:
        self.effects = []

    def record_adapter_effect_result(self, payload):
        self.effects.append(payload)


class TestKimiNativeHookDispatch:
    @staticmethod
    def _decision(
        decision: DecisionVerdict,
        *,
        policy_id: str = "test-policy",
        reason: str = "test decision",
        risk_level: RiskLevel = RiskLevel.HIGH,
        decision_effects: DecisionEffects | None = None,
    ) -> CanonicalDecision:
        return CanonicalDecision(
            decision=decision,
            reason=reason,
            policy_id=policy_id,
            risk_level=risk_level,
            decision_source=DecisionSource.POLICY,
            final=True,
            decision_effects=decision_effects,
        )

    @pytest.mark.asyncio
    async def test_pretool_uses_kimi_adapter_then_gateway_transport(self):
        adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent.sock", source_framework="kimi-cli")
        adapter.request_decision = AsyncMock(
            return_value=self._decision(
                DecisionVerdict.ALLOW,
                reason="allowed",
                risk_level=RiskLevel.LOW,
            )
        )
        harness = A3SGatewayHarness(adapter)

        response = await harness.dispatch_async(
            {
                "session_id": "sess-native-kimi",
                "hook_event_name": "PreToolUse",
                "tool_name": "Shell",
                "tool_input": {"command": "echo ok"},
                "cwd": "/workspace/project",
            }
        )

        assert response is None
        event = adapter.request_decision.await_args.args[0]
        assert event.source_framework == "kimi-cli"
        assert event.event_type == EventType.PRE_ACTION
        assert event.tool_name == "bash"
        assert event.payload["arguments"]["command"] == "echo ok"

    @pytest.mark.asyncio
    async def test_pretool_block_returns_kimi_deny_shape(self):
        adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent.sock", source_framework="kimi-cli")
        adapter.request_decision = AsyncMock(
            return_value=self._decision(
                DecisionVerdict.BLOCK,
                reason="dangerous command",
                risk_level=RiskLevel.CRITICAL,
            )
        )
        harness = A3SGatewayHarness(adapter)

        response = await harness.dispatch_async(
            {
                "session_id": "sess-block-kimi",
                "hook_event_name": "PreToolUse",
                "tool_name": "Shell",
                "tool_input": {"command": "rm -rf /"},
            }
        )

        assert response == {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "[ClawSentry] dangerous command (risk: critical)",
            }
        }

    @pytest.mark.asyncio
    async def test_fallback_policy_fails_open(self):
        adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent.sock", source_framework="kimi-cli")
        adapter.request_decision = AsyncMock(
            return_value=self._decision(
                DecisionVerdict.BLOCK,
                policy_id="fallback-fail-closed",
                reason="gateway down",
            )
        )
        harness = A3SGatewayHarness(adapter)

        response = await harness.dispatch_async(
            {
                "session_id": "sess-fallback-kimi",
                "hook_event_name": "PreToolUse",
                "tool_name": "Shell",
                "tool_input": {"command": "rm -rf /tmp/x"},
            }
        )

        assert response is None

    @pytest.mark.asyncio
    async def test_defer_outputs_deny_and_records_degraded_effect(self):
        adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent.sock", source_framework="kimi-cli")
        recorder = _GatewayRecorder()
        adapter._gateway = recorder
        effects = DecisionEffects(
            effect_id="effect-1",
            action_scope=ActionScope.SESSION,
            session_effect=SessionEffectRequest(requested=True),
        )
        adapter.request_decision = AsyncMock(
            return_value=self._decision(
                DecisionVerdict.DEFER,
                reason="approval needed",
                risk_level=RiskLevel.HIGH,
                decision_effects=effects,
            )
        )
        harness = A3SGatewayHarness(adapter)

        response = await harness.dispatch_async(
            {
                "session_id": "sess-defer-kimi",
                "hook_event_name": "PreToolUse",
                "tool_name": "Shell",
                "tool_input": {"command": "sudo rm -rf /tmp/x"},
            }
        )

        assert response is not None
        assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert recorder.effects
        effect = recorder.effects[0]
        assert effect.framework == "kimi-cli"
        assert effect.degraded
        assert effect.degrade_reason == "kimi_native_hooks_do_not_support_modify_or_defer_effects"
