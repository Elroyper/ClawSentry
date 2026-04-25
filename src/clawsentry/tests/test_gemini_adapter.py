"""Tests for Gemini CLI native hook adapter."""

from __future__ import annotations

from clawsentry.adapters.gemini_adapter import (
    GeminiAdapter,
    decision_to_gemini_hook_output,
)


class TestGeminiAdapter:
    def test_source_framework_is_gemini_cli(self):
        assert GeminiAdapter().source_framework == "gemini-cli"

    def test_normalize_before_tool_lifts_arguments_and_risk_hints(self):
        event = GeminiAdapter().normalize_native_hook_event(
            {
                "session_id": "sess-gemini",
                "turn_id": "turn-1",
                "hook_event_name": "BeforeTool",
                "tool_name": "ShellTool",
                "tool_input": {"command": "rm -rf /tmp/unsafe"},
                "cwd": "/workspace/project",
            }
        )

        assert event is not None
        assert event.source_framework == "gemini-cli"
        assert event.event_type.value == "pre_action"
        assert event.event_subtype == "BeforeTool"
        assert event.tool_name == "ShellTool"
        assert event.session_id == "sess-gemini"
        assert event.trace_id == "turn-1"
        assert event.payload["arguments"]["command"] == "rm -rf /tmp/unsafe"
        assert event.payload["command"] == "rm -rf /tmp/unsafe"
        assert event.payload["_clawsentry_meta"]["gemini_effect_strength"] == "strong"
        assert "destructive_pattern" in event.risk_hints

    def test_normalize_real_run_shell_command_as_canonical_bash(self):
        event = GeminiAdapter().normalize_native_hook_event(
            {
                "session_id": "sess-real-gemini",
                "turn_id": "turn-real-gemini",
                "hook_event_name": "BeforeTool",
                "tool_name": "run_shell_command",
                "tool_input": {"command": "rm -rf --no-preserve-root /tmp/unsafe"},
            }
        )

        assert event is not None
        assert event.tool_name == "bash"
        assert event.payload["tool_name"] == "bash"
        assert event.payload["gemini_tool_name"] == "run_shell_command"
        assert event.payload["_clawsentry_meta"]["raw_tool_name"] == "run_shell_command"
        assert event.payload["arguments"]["command"] == "rm -rf --no-preserve-root /tmp/unsafe"
        assert "shell_execution" in event.risk_hints
        assert "destructive_pattern" in event.risk_hints

    def test_normalize_before_agent_is_prompt_event(self):
        event = GeminiAdapter().normalize_native_hook_event(
            {
                "session_id": "sess-gemini",
                "hook_event_name": "BeforeAgent",
                "prompt": "say hello",
            },
            agent_id="agent-1",
        )

        assert event is not None
        assert event.event_type.value == "pre_prompt"
        assert event.event_subtype == "BeforeAgent"
        assert event.agent_id == "agent-1"
        assert event.payload["prompt"] == "say hello"

    def test_unknown_event_returns_none(self):
        assert GeminiAdapter().normalize_native_hook_event(
            {"hook_event_name": "UnknownEvent"}
        ) is None


class TestGeminiHookOutput:
    def test_allow_returns_empty_stdout_semantics(self):
        assert decision_to_gemini_hook_output(
            {"action": "continue", "metadata": {"risk_level": "low"}},
            "BeforeTool",
        ) is None

    def test_before_tool_block_returns_deny_shape(self):
        output = decision_to_gemini_hook_output(
            {
                "action": "block",
                "reason": "dangerous command",
                "metadata": {"risk_level": "critical", "policy_id": "p1"},
            },
            "BeforeTool",
        )
        assert output == {
            "decision": "deny",
            "reason": "[ClawSentry] dangerous command (risk: critical)",
        }

    def test_session_start_block_is_advisory_system_message(self):
        output = decision_to_gemini_hook_output(
            {
                "action": "block",
                "reason": "session needs review",
                "metadata": {"risk_level": "high", "policy_id": "p1"},
            },
            "SessionStart",
        )
        assert output == {
            "systemMessage": "[ClawSentry] session needs review (risk: high)",
            "suppressOutput": True,
        }

    def test_fallback_policy_fails_open(self):
        assert decision_to_gemini_hook_output(
            {
                "action": "block",
                "reason": "gateway down",
                "metadata": {"risk_level": "high", "policy_id": "fallback-fail-closed"},
            },
            "BeforeTool",
        ) is None

    def test_modify_before_tool_wraps_tool_input(self):
        output = decision_to_gemini_hook_output(
            {
                "action": "modify",
                "modified_payload": {"tool_input": {"command": "echo safe"}},
            },
            "BeforeTool",
        )
        assert output == {
            "hookSpecificOutput": {
                "hookEventName": "BeforeTool",
                "tool_input": {"command": "echo safe"},
            }
        }
