"""
Tests for OpenClaw Normalizer — Gate 1 verification.

Covers: OpenClaw event → CanonicalEvent normalization, field-level contracts,
event_id stability, mapping_profile format, sentinel fallbacks.
"""

import pytest

from clawsentry.adapters.openclaw_normalizer import OpenClawNormalizer, normalize_openclaw_event
from clawsentry.gateway.models import EventType, CanonicalEvent


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def normalizer():
    return OpenClawNormalizer(
        source_protocol_version="1.0",
        git_short_sha="abc1234",
        profile_version=1,
    )


# ===========================================================================
# Event Type Mapping (07 section 3, 11 rows)
# ===========================================================================

class TestEventTypeMapping:
    """Verify OpenClaw event → Canonical event_type mapping per 07 section 3."""

    def test_message_received_maps_to_pre_prompt(self, normalizer):
        evt = normalizer.normalize(
            event_type="message:received",
            payload={"text": "hello"},
            session_id="s1", agent_id="a1",
        )
        assert evt.event_type == EventType.PRE_PROMPT
        assert evt.event_subtype == "message:received"

    def test_message_transcribed_maps_to_pre_prompt(self, normalizer):
        evt = normalizer.normalize(
            event_type="message:transcribed",
            payload={"text": "hello"},
            session_id="s1", agent_id="a1",
        )
        assert evt.event_type == EventType.PRE_PROMPT
        assert evt.event_subtype == "message:transcribed"

    def test_message_preprocessed_maps_to_pre_prompt(self, normalizer):
        evt = normalizer.normalize(
            event_type="message:preprocessed",
            payload={"text": "hello"},
            session_id="s1", agent_id="a1",
        )
        assert evt.event_type == EventType.PRE_PROMPT
        assert evt.event_subtype == "message:preprocessed"

    def test_chat_delta_maps_to_post_response(self, normalizer):
        evt = normalizer.normalize(
            event_type="chat",
            payload={"state": "delta", "content": "partial"},
            session_id="s1", agent_id="a1",
            run_id="run-1", source_seq=1,
        )
        assert evt.event_type == EventType.POST_RESPONSE

    def test_chat_final_maps_to_post_response(self, normalizer):
        evt = normalizer.normalize(
            event_type="chat",
            payload={"state": "final", "content": "done"},
            session_id="s1", agent_id="a1",
            run_id="run-1", source_seq=2,
        )
        assert evt.event_type == EventType.POST_RESPONSE

    def test_chat_aborted_maps_to_error(self, normalizer):
        evt = normalizer.normalize(
            event_type="chat",
            payload={"state": "aborted"},
            session_id="s1", agent_id="a1",
            run_id="run-1", source_seq=3,
        )
        assert evt.event_type == EventType.ERROR

    def test_chat_error_maps_to_error(self, normalizer):
        evt = normalizer.normalize(
            event_type="chat",
            payload={"state": "error", "message": "fail"},
            session_id="s1", agent_id="a1",
            run_id="run-1", source_seq=4,
        )
        assert evt.event_type == EventType.ERROR

    def test_chat_missing_run_id_returns_none(self, normalizer):
        """Per 07 section 4.1: chat events require run_id and source_seq."""
        evt = normalizer.normalize(
            event_type="chat",
            payload={"state": "delta", "content": "partial"},
            session_id="s1", agent_id="a1",
        )
        assert evt is None

    def test_chat_missing_source_seq_returns_none(self, normalizer):
        """Per 07 section 4.1: chat events require run_id and source_seq."""
        evt = normalizer.normalize(
            event_type="chat",
            payload={"state": "delta", "content": "partial"},
            session_id="s1", agent_id="a1",
            run_id="run-1",
        )
        assert evt is None

    def test_exec_approval_requested_maps_to_pre_action(self, normalizer):
        evt = normalizer.normalize(
            event_type="exec.approval.requested",
            payload={"approval_id": "ap-1", "command": "rm -rf /"},
            session_id="s1", agent_id="a1",
        )
        assert evt.event_type == EventType.PRE_ACTION

    def test_exec_approval_resolved_maps_to_post_action(self, normalizer):
        evt = normalizer.normalize(
            event_type="exec.approval.resolved",
            payload={"approval_id": "ap-1", "decision": "allow-once"},
            session_id="s1", agent_id="a1",
        )
        assert evt.event_type == EventType.POST_ACTION

    def test_session_compact_before_maps_to_session(self, normalizer):
        evt = normalizer.normalize(
            event_type="session:compact:before",
            payload={},
            session_id="s1", agent_id="a1",
        )
        assert evt.event_type == EventType.SESSION

    def test_session_compact_after_maps_to_session(self, normalizer):
        evt = normalizer.normalize(
            event_type="session:compact:after",
            payload={},
            session_id="s1", agent_id="a1",
        )
        assert evt.event_type == EventType.SESSION

    def test_command_new_maps_to_session(self, normalizer):
        evt = normalizer.normalize(
            event_type="command:new",
            payload={"command": "test"},
            session_id="s1", agent_id="a1",
        )
        assert evt.event_type == EventType.SESSION

    def test_agent_bootstrap_maps_to_session(self, normalizer):
        evt = normalizer.normalize(
            event_type="agent:bootstrap",
            payload={},
            session_id="s1", agent_id="a1",
        )
        assert evt.event_type == EventType.SESSION

    def test_gateway_startup_maps_to_session(self, normalizer):
        evt = normalizer.normalize(
            event_type="gateway:startup",
            payload={},
            session_id="s1", agent_id="a1",
        )
        assert evt.event_type == EventType.SESSION

    def test_message_sent_maps_to_post_response(self, normalizer):
        evt = normalizer.normalize(
            event_type="message:sent",
            payload={"to": "user", "success": True},
            session_id="s1", agent_id="a1",
        )
        assert evt.event_type == EventType.POST_RESPONSE

    def test_command_reset_maps_to_session(self, normalizer):
        evt = normalizer.normalize(
            event_type="command:reset",
            payload={},
            session_id="s1", agent_id="a1",
        )
        assert evt.event_type == EventType.SESSION

    def test_command_stop_maps_to_session(self, normalizer):
        evt = normalizer.normalize(
            event_type="command:stop",
            payload={},
            session_id="s1", agent_id="a1",
        )
        assert evt.event_type == EventType.SESSION

    def test_unknown_event_returns_none(self, normalizer):
        result = normalizer.normalize(
            event_type="completely:unknown",
            payload={},
            session_id="s1", agent_id="a1",
        )
        assert result is None


# ===========================================================================
# Field-Level Contracts (07 section 4.1, 13 rules)
# ===========================================================================

class TestFieldContracts:
    """Verify field normalization rules per 07 section 4.1."""

    def test_schema_version_is_ahp_1_0(self, normalizer):
        evt = normalizer.normalize(
            event_type="message:received",
            payload={"text": "hi"},
            session_id="s1", agent_id="a1",
        )
        assert evt.schema_version == "ahp.1.0"

    def test_source_framework_is_openclaw(self, normalizer):
        evt = normalizer.normalize(
            event_type="message:received",
            payload={"text": "hi"},
            session_id="s1", agent_id="a1",
        )
        assert evt.source_framework == "openclaw"

    def test_source_protocol_version_set(self, normalizer):
        evt = normalizer.normalize(
            event_type="message:received",
            payload={"text": "hi"},
            session_id="s1", agent_id="a1",
        )
        assert evt.source_protocol_version == "1.0"

    def test_mapping_profile_format(self, normalizer):
        evt = normalizer.normalize(
            event_type="message:received",
            payload={"text": "hi"},
            session_id="s1", agent_id="a1",
        )
        assert evt.mapping_profile == "openclaw@abc1234/protocol.v1.0/profile.v1"

    def test_event_id_from_approval_id(self, normalizer):
        """When approval_id is present, event_id should derive from it."""
        evt = normalizer.normalize(
            event_type="exec.approval.requested",
            payload={"approval_id": "ap-123", "command": "ls"},
            session_id="s1", agent_id="a1",
        )
        assert evt.event_id is not None
        assert len(evt.event_id) > 0

    def test_event_id_from_run_id_seq(self, normalizer):
        """When run_id and source_seq available, event_id derives from them."""
        evt = normalizer.normalize(
            event_type="chat",
            payload={"state": "delta", "content": "x"},
            session_id="s1", agent_id="a1",
            run_id="run-456", source_seq=3,
        )
        assert evt.run_id == "run-456"
        assert evt.source_seq == 3

    def test_event_id_stability(self, normalizer):
        """Same inputs must produce same event_id."""
        kwargs = dict(
            event_type="message:received",
            payload={"text": "hi"},
            session_id="s1", agent_id="a1",
            occurred_at="2026-03-19T12:00:00+00:00",
        )
        evt1 = normalizer.normalize(**kwargs)
        evt2 = normalizer.normalize(**kwargs)
        assert evt1.event_id == evt2.event_id

    def test_trace_id_from_run_id(self, normalizer):
        """trace_id should use run_id when available."""
        evt = normalizer.normalize(
            event_type="chat",
            payload={"state": "final", "content": "done"},
            session_id="s1", agent_id="a1",
            run_id="run-789", source_seq=1,
        )
        assert evt.trace_id == "run-789"

    def test_trace_id_from_approval_id_fallback(self, normalizer):
        """trace_id falls back to approval_id when no run_id."""
        evt = normalizer.normalize(
            event_type="exec.approval.requested",
            payload={"approval_id": "ap-999"},
            session_id="s1", agent_id="a1",
        )
        assert evt.trace_id == "ap-999"

    def test_framework_meta_normalization(self, normalizer):
        """framework_meta.normalization should be populated."""
        evt = normalizer.normalize(
            event_type="message:received",
            payload={"text": "hi"},
            session_id="s1", agent_id="a1",
        )
        assert evt.framework_meta is not None
        norm = evt.framework_meta.normalization
        assert norm is not None
        assert norm.raw_event_type == "message:received"
        assert norm.raw_event_source == "openclaw"
        assert norm.confidence in ("high", "medium", "low")

    def test_approval_id_extracted_from_payload(self, normalizer):
        evt = normalizer.normalize(
            event_type="exec.approval.requested",
            payload={"approval_id": "ap-100"},
            session_id="s1", agent_id="a1",
        )
        assert evt.approval_id == "ap-100"

    def test_tool_name_extracted_from_exec_approval(self, normalizer):
        evt = normalizer.normalize(
            event_type="exec.approval.requested",
            payload={"approval_id": "ap-1", "tool": "bash", "command": "ls"},
            session_id="s1", agent_id="a1",
        )
        assert evt.tool_name == "bash"


# ===========================================================================
# Sentinel Fallbacks
# ===========================================================================

class TestSentinelFallbacks:
    """Verify sentinel values fill missing fields."""

    def test_missing_session_id(self, normalizer):
        evt = normalizer.normalize(
            event_type="message:received",
            payload={"text": "hi"},
            agent_id="a1",
        )
        assert evt.session_id == "unknown_session:openclaw"
        assert "session_id" in evt.framework_meta.normalization.missing_fields

    def test_missing_agent_id(self, normalizer):
        evt = normalizer.normalize(
            event_type="message:received",
            payload={"text": "hi"},
            session_id="s1",
        )
        assert evt.agent_id == "unknown_agent:openclaw"
        assert "agent_id" in evt.framework_meta.normalization.missing_fields


# ===========================================================================
# Risk Hints
# ===========================================================================

class TestRiskHints:
    """Verify risk hints extraction for OpenClaw events."""

    def test_shell_tool_gets_hint(self, normalizer):
        evt = normalizer.normalize(
            event_type="exec.approval.requested",
            payload={"approval_id": "ap-1", "tool": "bash", "command": "ls"},
            session_id="s1", agent_id="a1",
        )
        assert "shell_execution" in evt.risk_hints

    def test_destructive_command_gets_hint(self, normalizer):
        evt = normalizer.normalize(
            event_type="exec.approval.requested",
            payload={"approval_id": "ap-1", "tool": "bash", "command": "sudo rm -rf /"},
            session_id="s1", agent_id="a1",
        )
        assert "destructive_pattern" in evt.risk_hints

    def test_safe_tool_no_hints(self, normalizer):
        evt = normalizer.normalize(
            event_type="exec.approval.requested",
            payload={"approval_id": "ap-1", "tool": "read_file", "path": "/tmp/x"},
            session_id="s1", agent_id="a1",
        )
        assert evt.risk_hints == []


# ===========================================================================
# Post-Action Field Mapping (H-1)
# ===========================================================================

class TestPostActionFieldMapping:
    """H-1: exec.approval.resolved must map output fields for post-action."""

    def test_resolved_event_maps_tool_output(self, normalizer):
        result = normalizer.normalize(
            event_type="exec.approval.resolved",
            payload={"approval_id": "ap-1", "tool": "bash", "toolOutput": "some output"},
            session_id="s1",
        )
        assert result is not None
        assert result.payload.get("output") == "some output"

    def test_resolved_event_maps_command_output(self, normalizer):
        result = normalizer.normalize(
            event_type="exec.approval.resolved",
            payload={"approval_id": "ap-1", "tool": "bash", "commandOutput": "cmd out"},
            session_id="s1",
        )
        assert result is not None
        assert result.payload.get("output") == "cmd out"

    def test_resolved_event_preserves_existing_output(self, normalizer):
        result = normalizer.normalize(
            event_type="exec.approval.resolved",
            payload={"approval_id": "ap-1", "output": "already present"},
            session_id="s1",
        )
        assert result is not None
        assert result.payload.get("output") == "already present"

    def test_resolved_event_preserves_existing_result(self, normalizer):
        result = normalizer.normalize(
            event_type="exec.approval.resolved",
            payload={"approval_id": "ap-1", "result": "result present"},
            session_id="s1",
        )
        assert result is not None
        assert result.payload.get("result") == "result present"
        assert "output" not in result.payload  # should NOT alias when result exists

    def test_non_post_action_no_aliasing(self, normalizer):
        result = normalizer.normalize(
            event_type="exec.approval.requested",
            payload={"tool": "bash", "command": "ls", "toolOutput": "ignore"},
            session_id="s1",
        )
        assert result is not None
        assert "output" not in result.payload  # PRE_ACTION should not alias
