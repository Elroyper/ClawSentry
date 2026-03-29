"""Tests for Codex session JSONL line parser and session watcher."""

from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from clawsentry.gateway.codex_watcher import (
    CodexSessionWatcher,
    parse_codex_jsonl_line,
)


class TestParseCodexJsonlLine:

    def test_function_call_event(self):
        """response_item + function_call -> ("function_call", payload, None)."""
        line = json.dumps({
            "type": "response_item",
            "payload": {
                "type": "function_call",
                "name": "bash",
                "call_id": "call-1",
                "arguments": '{"command":"ls -la"}',
            },
        })
        result = parse_codex_jsonl_line(line)
        assert result is not None
        hook_type, payload, session_id = result
        assert hook_type == "function_call"
        assert payload["name"] == "bash"
        assert payload["call_id"] == "call-1"
        assert payload["arguments"] == {"command": "ls -la"}
        assert session_id is None

    def test_function_call_output_event(self):
        """response_item + function_call_output -> ("function_call_output", payload, None)."""
        line = json.dumps({
            "type": "response_item",
            "payload": {
                "type": "function_call_output",
                "call_id": "call-1",
                "output": "total 42...",
            },
        })
        result = parse_codex_jsonl_line(line)
        assert result is not None
        hook_type, payload, session_id = result
        assert hook_type == "function_call_output"
        assert payload["call_id"] == "call-1"
        assert payload["output"] == "total 42..."
        assert session_id is None

    def test_session_meta_event(self):
        """session_meta -> ("session_meta", payload, "sess-abc123")."""
        line = json.dumps({
            "type": "session_meta",
            "payload": {"id": "sess-abc123"},
        })
        result = parse_codex_jsonl_line(line)
        assert result is not None
        hook_type, payload, session_id = result
        assert hook_type == "session_meta"
        assert payload["id"] == "sess-abc123"
        assert session_id == "sess-abc123"

    def test_agent_message_skipped(self):
        """event_msg + agent_message -> None."""
        line = json.dumps({
            "type": "event_msg",
            "payload": {"type": "agent_message", "content": "Found it"},
        })
        result = parse_codex_jsonl_line(line)
        assert result is None

    def test_user_message_skipped(self):
        """event_msg + user_message -> None."""
        line = json.dumps({
            "type": "event_msg",
            "payload": {"type": "user_message", "message": "fix bug"},
        })
        result = parse_codex_jsonl_line(line)
        assert result is None

    def test_malformed_json_returns_none(self):
        """Invalid JSON -> None."""
        result = parse_codex_jsonl_line("{not valid json!!!")
        assert result is None

    def test_empty_line_returns_none(self):
        """Empty line -> None."""
        assert parse_codex_jsonl_line("") is None
        assert parse_codex_jsonl_line("   ") is None
        assert parse_codex_jsonl_line("\n") is None

    def test_missing_type_field_returns_none(self):
        """Missing type field -> None."""
        line = json.dumps({"payload": {"name": "bash"}})
        result = parse_codex_jsonl_line(line)
        assert result is None

    def test_function_call_with_dict_arguments(self):
        """arguments already a dict (not JSON string) -> parsed correctly."""
        line = json.dumps({
            "type": "response_item",
            "payload": {
                "type": "function_call",
                "name": "write_file",
                "call_id": "call-2",
                "arguments": {"path": "/tmp/x.txt", "content": "hello"},
            },
        })
        result = parse_codex_jsonl_line(line)
        assert result is not None
        hook_type, payload, session_id = result
        assert hook_type == "function_call"
        assert payload["arguments"] == {"path": "/tmp/x.txt", "content": "hello"}
        assert session_id is None


class TestCodexSessionWatcher:
    """Tests for CodexSessionWatcher file tailing and event loop."""

    def _make_function_call_line(
        self, name: str = "bash", command: str = "ls", call_id: str = "call-1"
    ) -> str:
        return json.dumps({
            "type": "response_item",
            "payload": {
                "type": "function_call",
                "name": name,
                "call_id": call_id,
                "arguments": json.dumps({"command": command}),
            },
        })

    def _make_session_meta_line(self, session_id: str = "sess-abc") -> str:
        return json.dumps({
            "type": "session_meta",
            "payload": {"id": session_id},
        })

    @pytest.mark.asyncio
    async def test_discovers_new_jsonl_file(self, tmp_path: Path):
        """Writing a JSONL file triggers evaluate_fn call."""
        logfile = tmp_path / "2026" / "03" / "30" / "session.jsonl"
        logfile.parent.mkdir(parents=True)
        logfile.write_text(self._make_function_call_line() + "\n")

        evaluate_fn = AsyncMock()
        watcher = CodexSessionWatcher(
            session_dir=tmp_path,
            evaluate_fn=evaluate_fn,
        )
        await watcher._scan_and_read()

        assert evaluate_fn.await_count == 1
        event = evaluate_fn.call_args[0][0]
        assert event.tool_name == "bash"

    @pytest.mark.asyncio
    async def test_tracks_file_offset(self, tmp_path: Path):
        """Second scan with no new data triggers no call; appending a new line triggers one."""
        logfile = tmp_path / "session.jsonl"
        logfile.write_text(self._make_function_call_line(call_id="c1") + "\n")

        evaluate_fn = AsyncMock()
        watcher = CodexSessionWatcher(
            session_dir=tmp_path,
            evaluate_fn=evaluate_fn,
        )

        # First scan: 1 call
        await watcher._scan_and_read()
        assert evaluate_fn.await_count == 1

        # Second scan: no new data -> no new call
        await watcher._scan_and_read()
        assert evaluate_fn.await_count == 1

        # Append a new line
        with logfile.open("a") as f:
            f.write(self._make_function_call_line(call_id="c2") + "\n")

        await watcher._scan_and_read()
        assert evaluate_fn.await_count == 2

    @pytest.mark.asyncio
    async def test_skips_old_files(self, tmp_path: Path):
        """Files older than max_file_age_seconds are not processed."""
        logfile = tmp_path / "old-session.jsonl"
        logfile.write_text(self._make_function_call_line() + "\n")

        evaluate_fn = AsyncMock()
        # max_file_age_seconds=0 means all files are "too old"
        watcher = CodexSessionWatcher(
            session_dir=tmp_path,
            evaluate_fn=evaluate_fn,
            max_file_age_seconds=0,
        )
        await watcher._scan_and_read()

        evaluate_fn.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_nonexistent_dir_no_crash(self, tmp_path: Path):
        """Watcher does not crash when session_dir does not exist."""
        missing = tmp_path / "does_not_exist"

        evaluate_fn = AsyncMock()
        watcher = CodexSessionWatcher(
            session_dir=missing,
            evaluate_fn=evaluate_fn,
        )
        # Should not raise
        await watcher._scan_and_read()
        evaluate_fn.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_session_id_propagated(self, tmp_path: Path):
        """session_meta sets session_id for subsequent function_call events."""
        logfile = tmp_path / "session.jsonl"
        lines = [
            self._make_session_meta_line(session_id="sess-xyz"),
            self._make_function_call_line(name="write_file", call_id="c1"),
        ]
        logfile.write_text("\n".join(lines) + "\n")

        evaluate_fn = AsyncMock()
        watcher = CodexSessionWatcher(
            session_dir=tmp_path,
            evaluate_fn=evaluate_fn,
        )
        await watcher._scan_and_read()

        # session_meta itself is normalized (session event), and function_call also
        assert evaluate_fn.await_count == 2

        # The function_call event should carry the session_id from session_meta
        func_call_event = evaluate_fn.call_args_list[1][0][0]
        assert func_call_event.session_id == "sess-xyz"


class TestCodexWatcherIntegration:
    """Integration test: watcher -> adapter -> gateway evaluation."""

    @pytest.mark.asyncio
    async def test_watcher_full_pipeline(self, tmp_path):
        """Write JSONL -> watcher detects -> gateway evaluates -> trajectory recorded."""
        from clawsentry.gateway.server import SupervisionGateway
        from clawsentry.adapters.a3s_adapter import InProcessA3SAdapter

        gateway = SupervisionGateway()
        evaluator = InProcessA3SAdapter(gateway)

        today = datetime.now(timezone.utc)
        day_dir = tmp_path / today.strftime("%Y/%m/%d")
        day_dir.mkdir(parents=True)

        watcher = CodexSessionWatcher(
            session_dir=tmp_path,
            evaluate_fn=evaluator.request_decision,
            poll_interval=0.1,
        )

        # Write a dangerous command
        session_file = day_dir / "session-integ.jsonl"
        session_file.write_text(
            json.dumps({"type": "session_meta", "payload": {"id": "integ-1"}}) + "\n"
            + json.dumps({
                "type": "response_item",
                "payload": {
                    "type": "function_call",
                    "name": "bash",
                    "call_id": "c-danger",
                    "arguments": {"command": "rm -rf /"},
                },
            }) + "\n"
        )

        await watcher._scan_and_read()
        # Verify trajectory was recorded
        rows = gateway.trajectory_store.replay_session(session_id="integ-1")
        assert len(rows) >= 1


class TestDetectCodexSessionDir:
    def test_explicit_env_var(self, tmp_path, monkeypatch):
        sessions = tmp_path / "sessions"
        sessions.mkdir()
        monkeypatch.setenv("CS_CODEX_SESSION_DIR", str(sessions))
        from clawsentry.gateway.stack import _detect_codex_session_dir
        assert _detect_codex_session_dir() == sessions

    def test_disabled_by_env(self, monkeypatch):
        monkeypatch.setenv("CS_CODEX_WATCH_ENABLED", "false")
        monkeypatch.delenv("CS_CODEX_SESSION_DIR", raising=False)
        from clawsentry.gateway.stack import _detect_codex_session_dir
        assert _detect_codex_session_dir() is None

    def test_auto_detect_from_codex_home(self, tmp_path, monkeypatch):
        sessions = tmp_path / ".codex" / "sessions"
        sessions.mkdir(parents=True)
        monkeypatch.setenv("CODEX_HOME", str(tmp_path / ".codex"))
        monkeypatch.delenv("CS_CODEX_SESSION_DIR", raising=False)
        monkeypatch.delenv("CS_CODEX_WATCH_ENABLED", raising=False)
        from clawsentry.gateway.stack import _detect_codex_session_dir
        assert _detect_codex_session_dir() == sessions

    def test_returns_none_when_no_sessions_dir(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CODEX_HOME", str(tmp_path / "nonexistent"))
        monkeypatch.delenv("CS_CODEX_SESSION_DIR", raising=False)
        monkeypatch.delenv("CS_CODEX_WATCH_ENABLED", raising=False)
        from clawsentry.gateway.stack import _detect_codex_session_dir
        assert _detect_codex_session_dir() is None
