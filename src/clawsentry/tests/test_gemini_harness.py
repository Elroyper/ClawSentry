"""Tests for Gemini CLI native hook dispatch through the harness."""

from __future__ import annotations

import io
import json
import sys
from unittest.mock import AsyncMock

import pytest

from clawsentry.adapters.a3s_adapter import A3SCodeAdapter
from clawsentry.adapters.a3s_gateway_harness import A3SGatewayHarness
from clawsentry.gateway.models import (
    CanonicalDecision,
    DecisionSource,
    DecisionVerdict,
    EventType,
    RiskLevel,
)


class TestGeminiNativeHookDispatch:
    @staticmethod
    def _decision(
        decision: DecisionVerdict,
        *,
        policy_id: str = "test-policy",
        reason: str = "test decision",
        risk_level: RiskLevel = RiskLevel.HIGH,
    ) -> CanonicalDecision:
        return CanonicalDecision(
            decision=decision,
            reason=reason,
            policy_id=policy_id,
            risk_level=risk_level,
            decision_source=DecisionSource.POLICY,
            final=True,
        )

    @pytest.mark.asyncio
    async def test_beforetool_uses_gemini_adapter_then_gateway_transport(self):
        adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent.sock", source_framework="gemini-cli")
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
                "session_id": "sess-native-gemini",
                "turn_id": "turn-native-gemini",
                "hook_event_name": "BeforeTool",
                "tool_name": "ShellTool",
                "tool_input": {"command": "echo ok"},
                "cwd": "/workspace/project",
            }
        )

        assert response is None
        event = adapter.request_decision.await_args.args[0]
        assert event.source_framework == "gemini-cli"
        assert event.event_type == EventType.PRE_ACTION
        assert event.event_subtype == "BeforeTool"
        assert event.tool_name == "ShellTool"
        assert event.payload["arguments"]["command"] == "echo ok"

    @pytest.mark.asyncio
    async def test_real_run_shell_command_is_canonicalized_before_policy_request(self):
        adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent.sock", source_framework="gemini-cli")
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
                "session_id": "sess-real-shell-gemini",
                "hook_event_name": "BeforeTool",
                "tool_name": "run_shell_command",
                "tool_input": {"command": "rm -rf --no-preserve-root /tmp/unsafe"},
            }
        )

        assert response == {
            "decision": "deny",
            "reason": "[ClawSentry] dangerous command (risk: critical)",
        }
        event = adapter.request_decision.await_args.args[0]
        assert event.tool_name == "bash"
        assert event.payload["gemini_tool_name"] == "run_shell_command"
        assert "shell_execution" in event.risk_hints
        assert "destructive_pattern" in event.risk_hints

    @pytest.mark.asyncio
    async def test_beforetool_block_returns_gemini_deny_shape(self):
        adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent.sock", source_framework="gemini-cli")
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
                "session_id": "sess-block-gemini",
                "hook_event_name": "BeforeTool",
                "tool_name": "ShellTool",
                "tool_input": {"command": "rm -rf /"},
            }
        )

        assert response == {
            "decision": "deny",
            "reason": "[ClawSentry] dangerous command (risk: critical)",
        }

    @pytest.mark.asyncio
    async def test_sessionstart_block_is_advisory_not_hard_block(self):
        adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent.sock", source_framework="gemini-cli")
        adapter.request_decision = AsyncMock(
            return_value=self._decision(
                DecisionVerdict.BLOCK,
                reason="session advisory",
                risk_level=RiskLevel.HIGH,
            )
        )
        harness = A3SGatewayHarness(adapter)

        response = await harness.dispatch_async(
            {
                "session_id": "sess-start-gemini",
                "hook_event_name": "SessionStart",
                "source": "startup",
            }
        )

        assert response == {
            "systemMessage": "[ClawSentry] session advisory (risk: high)",
            "suppressOutput": True,
        }

    @pytest.mark.asyncio
    async def test_fallback_policy_fails_open(self):
        adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent.sock", source_framework="gemini-cli")
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
                "session_id": "sess-fallback-gemini",
                "hook_event_name": "BeforeTool",
                "tool_name": "ShellTool",
                "tool_input": {"command": "rm -rf /tmp/x"},
            }
        )

        assert response is None

    def test_stdio_allow_path_emits_no_stdout_or_stderr_for_gemini(self, monkeypatch):
        adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent.sock", source_framework="gemini-cli")
        adapter.request_decision = AsyncMock(
            return_value=self._decision(
                DecisionVerdict.ALLOW,
                reason="allowed",
                risk_level=RiskLevel.LOW,
            )
        )
        harness = A3SGatewayHarness(adapter)
        msg = {
            "session_id": "sess-stdio-gemini",
            "hook_event_name": "BeforeAgent",
            "prompt": "say hello",
        }
        stdout = io.StringIO()
        stderr = io.StringIO()
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(msg) + "\n"))
        monkeypatch.setattr(sys, "stdout", stdout)
        monkeypatch.setattr(sys, "stderr", stderr)

        harness.run_stdio()

        assert stdout.getvalue() == ""
        assert stderr.getvalue() == ""
