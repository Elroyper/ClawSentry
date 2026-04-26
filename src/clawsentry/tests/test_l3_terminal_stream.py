"""Tests for the demo L3 terminal event stream formatter."""

from __future__ import annotations

from clawsentry.devtools.l3_terminal_stream import format_event


def _now() -> str:
    return "12:34:56"


def test_format_event_accepts_current_flat_decision_payload() -> None:
    line = format_event(
        {
            "type": "decision",
            "session_id": "sess-123456789",
            "event_id": "evt-1",
            "risk_level": "high",
            "decision": "block",
            "tool_name": "Bash",
            "actual_tier": "L3",
            "command": "rm -rf workspace/important_data",
            "reason": "dangerous deletion",
        },
        now_fn=_now,
    )

    assert line.startswith("[12:34:56] DECISION BLOCK")
    assert "risk=high" in line
    assert "tier=L3" in line
    assert "tool=Bash" in line
    assert "session=sess-12…" in line
    assert "cmd=rm -rf workspace/important_data" in line


def test_format_event_tolerates_legacy_or_malformed_decision_payload() -> None:
    line = format_event(
        {
            "type": "decision",
            "event": "evt-as-string",
            "decision": "allow",
            "session_id": "sess-flat-fallback",
            "risk_level": "low",
            "tool_name": "Read",
            "command": "cat README.md",
        },
        now_fn=_now,
    )

    assert "DECISION ALLOW" in line
    assert "risk=low" in line
    assert "tool=Read" in line
    assert "cmd=cat README.md" in line


def test_format_event_shows_snapshot_created_state_without_dash_noise() -> None:
    line = format_event(
        {
            "type": "l3_advisory_snapshot",
            "session_id": "sess-l3",
            "snapshot_id": "snap-1",
            "trigger_reason": "threshold",
        },
        now_fn=_now,
    )

    assert line == "[12:34:56] L3 SNAPSHOT state=created risk=- action=- session=sess-l3"
