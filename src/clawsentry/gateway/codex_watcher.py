"""Codex session JSONL line parser and file watcher.

Codex CLI writes events to JSONL files (one JSON object per line).
This module parses individual lines, extracting tool-call events
(function_call, function_call_output) and session events (session_meta),
and skipping everything else (user messages, agent messages, etc.).

``CodexSessionWatcher`` monitors a Codex session log directory, tailing
JSONL files and feeding parsed events through a Gateway evaluate function.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Any, Awaitable, Callable

from ..adapters.codex_adapter import CodexAdapter
from .models import CanonicalDecision, CanonicalEvent

logger = logging.getLogger(__name__)


def parse_codex_jsonl_line(
    line: str,
) -> tuple[str, dict[str, Any], str | None] | None:
    """Parse a single JSONL line from a Codex session log.

    Returns ``(hook_type, payload, session_id)`` or ``None`` if the line
    should be skipped.  *hook_type* maps directly to
    :pymethod:`CodexAdapter.normalize_hook_event` parameter names.

    Mapping rules:
    * ``response_item`` with ``payload.type == "function_call"``
      -> ``("function_call", payload, None)``
    * ``response_item`` with ``payload.type == "function_call_output"``
      -> ``("function_call_output", payload, None)``
    * ``session_meta``
      -> ``("session_meta", payload, payload["id"])``
    * Everything else (``event_msg``, unknown types, malformed lines)
      -> ``None``
    """
    stripped = line.strip()
    if not stripped:
        return None

    try:
        obj = json.loads(stripped)
    except (json.JSONDecodeError, ValueError):
        logger.debug("Skipping malformed JSONL line: %.120s", stripped)
        return None

    if not isinstance(obj, dict):
        return None

    line_type: str | None = obj.get("type")
    if not line_type:
        return None

    payload: dict[str, Any] = obj.get("payload", {})

    # --- session_meta ---------------------------------------------------
    if line_type == "session_meta":
        session_id = payload.get("id")
        return ("session_meta", payload, session_id)

    # --- response_item (tool calls) -------------------------------------
    if line_type == "response_item":
        payload_type = payload.get("type")
        if payload_type not in ("function_call", "function_call_output"):
            return None

        # Normalise arguments: may arrive as a JSON string or a dict.
        if payload_type == "function_call":
            args = payload.get("arguments")
            if isinstance(args, str):
                try:
                    payload["arguments"] = json.loads(args)
                except (json.JSONDecodeError, ValueError):
                    pass  # leave as-is if not valid JSON

        return (payload_type, payload, None)

    # --- everything else → skip -----------------------------------------
    return None


# ---------------------------------------------------------------------------
# CodexSessionWatcher — file-tailing event loop
# ---------------------------------------------------------------------------

class CodexSessionWatcher:
    """Watch a Codex session log directory and feed events to Gateway evaluation.

    The watcher periodically scans *session_dir* for ``*.jsonl`` files,
    reads new lines from each file (tracking byte offsets), parses them
    via :func:`parse_codex_jsonl_line`, normalizes through a
    :class:`CodexAdapter`, and calls *evaluate_fn* with the resulting
    :class:`CanonicalEvent`.

    Parameters
    ----------
    session_dir:
        Root directory where Codex writes session JSONL logs.
    evaluate_fn:
        Async callable that receives a :class:`CanonicalEvent` and returns
        a :class:`CanonicalDecision`.
    adapter:
        Optional pre-configured :class:`CodexAdapter`.  A default one is
        created when ``None``.
    poll_interval:
        Seconds between scans (used by :meth:`start`).
    max_file_age_seconds:
        Ignore files whose *mtime* is older than this many seconds.
    """

    def __init__(
        self,
        session_dir: Path,
        evaluate_fn: Callable[[CanonicalEvent], Awaitable[CanonicalDecision]],
        *,
        adapter: CodexAdapter | None = None,
        poll_interval: float = 0.5,
        max_file_age_seconds: float = 300.0,
    ) -> None:
        self._session_dir = Path(session_dir)
        self._evaluate_fn = evaluate_fn
        self._adapter = adapter or CodexAdapter()
        self._poll_interval = poll_interval
        self._max_file_age_seconds = max_file_age_seconds

        # file path -> (byte_offset, current_session_id)
        self._watched: dict[Path, tuple[int, str | None]] = {}
        self._running = False

    async def start(self) -> None:
        """Run the scan-and-read loop until :meth:`stop` is called."""
        self._running = True
        while self._running:
            await self._scan_and_read()
            await asyncio.sleep(self._poll_interval)

    async def stop(self) -> None:
        """Signal the event loop to stop."""
        self._running = False

    async def _scan_and_read(self) -> None:
        """Perform a single scan of the session directory.

        Discovers new ``*.jsonl`` files, reads new lines from tracked
        files, and dispatches parsed events to *evaluate_fn*.
        """
        if not self._session_dir.is_dir():
            return

        now = time.time()

        for path in sorted(self._session_dir.glob("**/*.jsonl")):
            # Skip files older than max_file_age_seconds
            try:
                mtime = path.stat().st_mtime
            except OSError:
                continue
            if now - mtime > self._max_file_age_seconds:
                continue

            # Get or initialize tracking state for this file
            offset, session_id = self._watched.get(path, (0, None))

            try:
                with path.open("r", encoding="utf-8") as fh:
                    fh.seek(offset)
                    new_data = fh.read()
                    new_offset = fh.tell()
            except OSError:
                logger.debug("Failed to read %s, skipping", path)
                continue

            if new_offset == offset:
                # No new data
                continue

            for line in new_data.splitlines():
                parsed = parse_codex_jsonl_line(line)
                if parsed is None:
                    continue

                hook_type, payload, line_session_id = parsed

                # session_meta events update the session_id for this file
                if hook_type == "session_meta" and line_session_id:
                    session_id = line_session_id

                event = self._adapter.normalize_hook_event(
                    hook_type=hook_type,
                    payload=payload,
                    session_id=session_id,
                )
                if event is not None:
                    try:
                        decision = await self._evaluate_fn(event)
                        logger.debug(
                            "codex-watcher: %s %s → %s",
                            event.tool_name, hook_type, decision.decision.value,
                        )
                    except Exception:
                        logger.exception(
                            "evaluate_fn raised for event %s", event.event_id
                        )

            # Update tracked state
            self._watched[path] = (new_offset, session_id)
