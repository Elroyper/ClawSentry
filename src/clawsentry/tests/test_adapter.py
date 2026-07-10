"""
Tests for a3s-code Adapter — Gate 5 verification.

Covers: Hook -> Canonical Event normalization, PostResponse re-mapping,
framework_meta normalization, event_id stability, fallback decisions.
"""

import pytest

from clawsentry.adapters.a3s_adapter import (
    A3SCodeAdapter,
    _generate_event_id,
    _reclassify_post_action,
)
from clawsentry.gateway.models import (
    DecisionContext,
    DecisionVerdict,
    DecisionSource,
    DecisionTier,
    EventType,
)
from clawsentry.gateway.policy.engine import make_fallback_decision


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def adapter():
    return A3SCodeAdapter()


# ===========================================================================
# Hook Mapping Tests
# ===========================================================================

class TestHookMapping:
    def test_pre_tool_use(self, adapter):
        evt = adapter.normalize_hook_event(
            "PreToolUse",
            {"tool": "bash", "command": "ls"},
            session_id="s1", agent_id="a1",
        )
        assert evt is not None
        assert evt.event_type == EventType.PRE_ACTION
        assert evt.source_framework == "a3s-code"
        assert evt.event_subtype == "PreToolUse"

    def test_post_tool_use(self, adapter):
        evt = adapter.normalize_hook_event(
            "PostToolUse",
            {"tool": "bash", "result": "ok"},
            session_id="s1", agent_id="a1",
        )
        assert evt is not None
        assert evt.event_type == EventType.POST_ACTION

    def test_pre_prompt(self, adapter):
        evt = adapter.normalize_hook_event(
            "PrePrompt",
            {"prompt": "hello"},
            session_id="s1", agent_id="a1",
        )
        assert evt is not None
        assert evt.event_type == EventType.PRE_PROMPT

    def test_generate_start(self, adapter):
        evt = adapter.normalize_hook_event(
            "GenerateStart",
            {"model": "test"},
            session_id="s1", agent_id="a1",
        )
        assert evt is not None
        assert evt.event_type == EventType.PRE_PROMPT

    def test_post_response(self, adapter):
        evt = adapter.normalize_hook_event(
            "PostResponse",
            {"response_text": "hello", "usage": {}},
            session_id="s1", agent_id="a1",
        )
        assert evt is not None
        assert evt.event_type == EventType.POST_RESPONSE

    def test_session_start(self, adapter):
        evt = adapter.normalize_hook_event(
            "SessionStart",
            {},
            session_id="s1", agent_id="a1",
        )
        assert evt is not None
        assert evt.event_type == EventType.SESSION
        assert evt.event_subtype == "session:start"

    def test_session_end(self, adapter):
        evt = adapter.normalize_hook_event(
            "SessionEnd",
            {},
            session_id="s1", agent_id="a1",
        )
        assert evt.event_type == EventType.SESSION
        assert evt.event_subtype == "session:end"

    def test_on_error(self, adapter):
        evt = adapter.normalize_hook_event(
            "OnError",
            {"error": "timeout"},
            session_id="s1", agent_id="a1",
        )
        assert evt.event_type == EventType.ERROR

    def test_unmapped_hooks_return_none(self, adapter):
        for hook in ("GenerateEnd", "SkillLoad", "SkillUnload"):
            assert adapter.normalize_hook_event(hook, {}) is None

    def test_unknown_hook_returns_none(self, adapter):
        assert adapter.normalize_hook_event("CompletelyUnknown", {}) is None


# ===========================================================================
# PostResponse Re-mapping Tests (02 section 4.1.2)
# ===========================================================================

class TestPostResponseRemapping:
    def test_payload_with_response_text_reclassified(self):
        """PostAction with response_text should be reclassified to post_response."""
        event_type, norm = _reclassify_post_action(
            "PostAction",
            {"response_text": "hello", "tool_calls_count": 2, "usage": {}},
        )
        assert event_type == EventType.POST_RESPONSE
        assert norm is not None
        assert norm.rule_id == "a3s-post-response-reclassify"
        assert norm.inferred is True
        assert norm.confidence == "high"
        assert norm.raw_event_type == "PostAction"

    def test_payload_with_tool_result_stays_post_action(self):
        """PostAction with tool+result stays as post_action."""
        event_type, norm = _reclassify_post_action(
            "PostAction",
            {"tool": "bash", "result": "ok"},
        )
        assert event_type == EventType.POST_ACTION
        assert norm is None

    def test_non_post_action_passthrough(self):
        """Non-PostAction types are not affected."""
        event_type, norm = _reclassify_post_action(
            "PreAction",
            {"response_text": "this should not matter"},
        )
        assert event_type == EventType.PRE_ACTION
        assert norm is None

    def test_post_tool_use_with_response_text_reclassified(self, adapter):
        """PostToolUse whose payload has response_text should reclassify."""
        evt = adapter.normalize_hook_event(
            "PostToolUse",
            {"response_text": "model output", "usage": {"tokens": 100}},
            session_id="s1", agent_id="a1",
        )
        assert evt.event_type == EventType.POST_RESPONSE
        assert evt.framework_meta.normalization.rule_id == "a3s-post-response-reclassify"


# ===========================================================================
# Normalization Metadata Tests
# ===========================================================================

class TestNormalizationMeta:
    def test_framework_meta_populated(self, adapter):
        evt = adapter.normalize_hook_event(
            "PreToolUse",
            {"tool": "read_file"},
            session_id="s1", agent_id="a1",
        )
        assert evt.framework_meta is not None
        assert evt.framework_meta.normalization is not None
        norm = evt.framework_meta.normalization
        assert norm.raw_event_source == "a3s-code"
        assert norm.raw_event_type == "PreToolUse"

    def test_sentinel_values_when_missing(self, adapter):
        evt = adapter.normalize_hook_event(
            "PreToolUse",
            {"tool": "bash"},
        )
        assert evt.session_id == "unknown_session:a3s-code"
        assert evt.agent_id == "unknown_agent:a3s-code"
        assert "session_id" in evt.framework_meta.normalization.missing_fields
        assert "agent_id" in evt.framework_meta.normalization.missing_fields
        assert evt.framework_meta.normalization.fallback_rule == "sentinel_value"


# ===========================================================================
# event_id Stability Tests
# ===========================================================================

class TestEventId:
    def test_stable_event_id(self):
        """Same inputs produce same event_id."""
        id1 = _generate_event_id("a3s-code", "s1", "PreToolUse", "2026-03-19T12:00:00Z", {"tool": "bash"})
        id2 = _generate_event_id("a3s-code", "s1", "PreToolUse", "2026-03-19T12:00:00Z", {"tool": "bash"})
        assert id1 == id2

    def test_different_payloads_different_ids(self):
        id1 = _generate_event_id("a3s-code", "s1", "PreToolUse", "2026-03-19T12:00:00Z", {"tool": "bash"})
        id2 = _generate_event_id("a3s-code", "s1", "PreToolUse", "2026-03-19T12:00:00Z", {"tool": "read_file"})
        assert id1 != id2

    def test_event_id_length(self):
        eid = _generate_event_id("a3s-code", "s1", "test", "now", {})
        assert len(eid) == 24  # Truncated sha256 hex


# ===========================================================================
# Blocking / Non-blocking Tests
# ===========================================================================

class TestBlocking:
    def test_pre_action_is_blocking(self, adapter):
        assert adapter.is_blocking("PreToolUse") is True
        assert adapter.is_blocking("PrePrompt") is True
        assert adapter.is_blocking("GenerateStart") is True

    def test_post_action_is_not_blocking(self, adapter):
        assert adapter.is_blocking("PostToolUse") is False
        assert adapter.is_blocking("PostResponse") is False
        assert adapter.is_blocking("OnError") is False
        assert adapter.is_blocking("SessionStart") is False


# ===========================================================================
# Risk Hints Tests
# ===========================================================================

class TestRiskHints:
    def test_bash_tool_gets_shell_hint(self, adapter):
        evt = adapter.normalize_hook_event(
            "PreToolUse",
            {"tool": "bash", "command": "ls"},
            session_id="s1", agent_id="a1",
        )
        assert "shell_execution" in evt.risk_hints

    def test_destructive_command_gets_hint(self, adapter):
        evt = adapter.normalize_hook_event(
            "PreToolUse",
            {"tool": "bash", "command": "sudo rm -rf /tmp"},
            session_id="s1", agent_id="a1",
        )
        assert "destructive_pattern" in evt.risk_hints

    def test_safe_tool_no_hints(self, adapter):
        evt = adapter.normalize_hook_event(
            "PreToolUse",
            {"tool": "read_file", "path": "/tmp/x"},
            session_id="s1", agent_id="a1",
        )
        assert evt.risk_hints == []


# ===========================================================================
# Local Fallback Tests (04 section 11.3)
# ===========================================================================

class TestAdapterFallback:
    @pytest.mark.asyncio
    async def test_fallback_when_gateway_unreachable(self, adapter):
        """When UDS is not available, adapter falls back to local decision."""
        adapter.uds_path = "/tmp/nonexistent-gateway.sock"
        evt = adapter.normalize_hook_event(
            "PreToolUse",
            {"tool": "bash", "command": "rm -rf /"},
            session_id="s1", agent_id="a1",
        )
        decision = await adapter.request_decision(evt)
        # bash is a dangerous tool -> fallback should block
        assert decision.decision == DecisionVerdict.BLOCK
        assert decision.decision_source == DecisionSource.SYSTEM

    @pytest.mark.asyncio
    async def test_fallback_safe_tool_defers(self, adapter):
        """Safe tool should defer when gateway unreachable."""
        adapter.uds_path = "/tmp/nonexistent-gateway.sock"
        evt = adapter.normalize_hook_event(
            "PreToolUse",
            {"tool": "read_file", "path": "/tmp/readme"},
            session_id="s1", agent_id="a1",
        )
        decision = await adapter.request_decision(evt)
        assert decision.decision == DecisionVerdict.DEFER


class TestAdapterDecisionTier:
    @pytest.mark.asyncio
    async def test_request_decision_defaults_to_l1_tier(self, adapter):
        captured = {}

        async def fake_send(req):
            captured["tier"] = req.decision_tier.value
            return {
                "result": {
                    "rpc_status": "ok",
                    "decision": {
                        "decision": "allow",
                        "reason": "ok",
                        "policy_id": "test-policy",
                        "risk_level": "low",
                        "decision_source": "policy",
                        "policy_version": "1.0",
                        "failure_class": "none",
                        "final": True,
                    },
                }
            }

        adapter._send_uds_request = fake_send
        evt = adapter.normalize_hook_event(
            "PreToolUse",
            {"tool": "read_file", "path": "/tmp/x"},
            session_id="s-tier-1",
            agent_id="a-tier-1",
        )
        decision = await adapter.request_decision(evt)
        assert captured["tier"] == "L1"
        assert decision.decision == DecisionVerdict.ALLOW

    @pytest.mark.asyncio
    async def test_request_decision_supports_explicit_l2_tier(self, adapter):
        captured = {}

        async def fake_send(req):
            captured["tier"] = req.decision_tier.value
            return {
                "result": {
                    "rpc_status": "ok",
                    "decision": {
                        "decision": "allow",
                        "reason": "ok",
                        "policy_id": "test-policy",
                        "risk_level": "low",
                        "decision_source": "policy",
                        "policy_version": "1.0",
                        "failure_class": "none",
                        "final": True,
                    },
                }
            }

        adapter._send_uds_request = fake_send
        evt = adapter.normalize_hook_event(
            "PreToolUse",
            {"tool": "read_file", "path": "/tmp/y"},
            session_id="s-tier-2",
            agent_id="a-tier-2",
        )
        decision = await adapter.request_decision(evt, decision_tier=DecisionTier.L2)
        assert captured["tier"] == "L2"
        assert decision.decision == DecisionVerdict.ALLOW

    @pytest.mark.asyncio
    async def test_request_decision_sets_default_caller_adapter(self, adapter):
        captured = {}

        async def fake_send(req):
            captured["caller_adapter"] = (
                req.context.caller_adapter if req.context else None
            )
            return {
                "result": {
                    "rpc_status": "ok",
                    "decision": {
                        "decision": "allow",
                        "reason": "ok",
                        "policy_id": "test-policy",
                        "risk_level": "low",
                        "decision_source": "policy",
                        "policy_version": "1.0",
                        "failure_class": "none",
                        "final": True,
                    },
                }
            }

        adapter._send_uds_request = fake_send
        evt = adapter.normalize_hook_event(
            "PreToolUse",
            {"tool": "read_file", "path": "/tmp/caller-default"},
            session_id="s-caller-1",
            agent_id="a-caller-1",
        )
        decision = await adapter.request_decision(evt)
        assert captured["caller_adapter"] == "a3s-adapter.v1"
        assert decision.decision == DecisionVerdict.ALLOW

    @pytest.mark.asyncio
    async def test_request_decision_keeps_explicit_caller_adapter(self, adapter):
        captured = {}

        async def fake_send(req):
            captured["caller_adapter"] = (
                req.context.caller_adapter if req.context else None
            )
            return {
                "result": {
                    "rpc_status": "ok",
                    "decision": {
                        "decision": "allow",
                        "reason": "ok",
                        "policy_id": "test-policy",
                        "risk_level": "low",
                        "decision_source": "policy",
                        "policy_version": "1.0",
                        "failure_class": "none",
                        "final": True,
                    },
                }
            }

        adapter._send_uds_request = fake_send
        evt = adapter.normalize_hook_event(
            "PreToolUse",
            {"tool": "read_file", "path": "/tmp/caller-explicit"},
            session_id="s-caller-2",
            agent_id="a-caller-2",
        )
        context = DecisionContext(caller_adapter="custom-adapter.v9")
        decision = await adapter.request_decision(evt, context=context)
        assert captured["caller_adapter"] == "custom-adapter.v9"
        assert decision.decision == DecisionVerdict.ALLOW


# ===========================================================================
# Source Framework Override Tests (E-9)
# ===========================================================================

class TestSourceFrameworkOverride:
    """A3SCodeAdapter should support configurable source_framework."""

    def test_default_source_framework(self):
        adapter = A3SCodeAdapter()
        assert adapter.source_framework == "a3s-code"

    def test_custom_source_framework(self):
        adapter = A3SCodeAdapter(source_framework="claude-code")
        assert adapter.source_framework == "claude-code"

    def test_custom_framework_in_normalized_event(self):
        adapter = A3SCodeAdapter(source_framework="claude-code")
        evt = adapter.normalize_hook_event(
            "PreToolUse",
            {"tool": "Bash", "command": "ls"},
            session_id="sess-1",
            agent_id="agent-1",
        )
        assert evt is not None
        assert evt.source_framework == "claude-code"
        assert evt.framework_meta.normalization.raw_event_source == "claude-code"

    def test_custom_framework_in_event_id(self):
        """Different frameworks should produce different event_ids for same payload."""
        payload = {"tool": "Bash", "command": "echo hi"}
        a3s = A3SCodeAdapter(source_framework="a3s-code")
        cc = A3SCodeAdapter(source_framework="claude-code")
        evt_a3s = a3s.normalize_hook_event("PreToolUse", payload, session_id="s1")
        evt_cc = cc.normalize_hook_event("PreToolUse", payload, session_id="s1")
        assert evt_a3s is not None and evt_cc is not None
        # event_ids differ because source_framework is part of the hash
        assert evt_a3s.event_id != evt_cc.event_id
