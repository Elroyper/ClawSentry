"""
Shared helpers for ClawSentry quick-start examples.

Provides:
- In-process Gateway creation (no external service needed)
- JSON-RPC request builders
- Formatted output utilities
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from clawsentry.gateway.models import (
    CURRENT_SCHEMA_VERSION,
    RPC_VERSION,
)
from clawsentry.gateway.server import SupervisionGateway


# ---------------------------------------------------------------------------
# Gateway factory
# ---------------------------------------------------------------------------

def create_gateway(
    *,
    trajectory_db_path: str = ":memory:",
    analyzer=None,
) -> SupervisionGateway:
    """Create an in-process SupervisionGateway (no UDS/HTTP server needed)."""
    return SupervisionGateway(
        trajectory_db_path=trajectory_db_path,
        analyzer=analyzer,
    )


# ---------------------------------------------------------------------------
# Event / JSON-RPC builders
# ---------------------------------------------------------------------------

def build_jsonrpc_request(
    tool: str,
    *,
    command: Optional[str] = None,
    path: Optional[str] = None,
    session_id: str = "demo-session",
    agent_id: str = "demo-agent",
    event_type: str = "pre_action",
    decision_tier: str = "L1",
    risk_hints: Optional[list[str]] = None,
    extra_payload: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Build a complete JSON-RPC 2.0 request for ahp/sync_decision."""
    request_id = f"req-{uuid.uuid4().hex[:8]}"
    event_id = f"evt-{uuid.uuid4().hex[:8]}"
    now = datetime.now(timezone.utc).isoformat()

    payload: dict[str, Any] = {"tool": tool}
    arguments: dict[str, Any] = {}
    if command is not None:
        payload["command"] = command
        arguments["command"] = command
    if path is not None:
        payload["file_path"] = path
        arguments["file_path"] = path
    payload["arguments"] = arguments
    if extra_payload:
        payload.update(extra_payload)

    event: dict[str, Any] = {
        "schema_version": CURRENT_SCHEMA_VERSION,
        "event_id": event_id,
        "trace_id": f"trace-{event_id}",
        "event_type": event_type,
        "session_id": session_id,
        "agent_id": agent_id,
        "source_framework": "a3s-code",
        "occurred_at": now,
        "payload": payload,
        "event_subtype": "tool:execute",
        "tool_name": tool,
    }
    if risk_hints:
        event["risk_hints"] = risk_hints

    return {
        "jsonrpc": "2.0",
        "method": "ahp/sync_decision",
        "id": request_id,
        "params": {
            "rpc_version": RPC_VERSION,
            "request_id": request_id,
            "deadline_ms": 5000,
            "decision_tier": decision_tier,
            "event": event,
        },
    }


async def send_event(
    gateway: SupervisionGateway,
    tool: str,
    **kwargs,
) -> dict[str, Any]:
    """Build a JSON-RPC request, send to gateway, and return the response."""
    request = build_jsonrpc_request(tool, **kwargs)
    raw = json.dumps(request).encode("utf-8")
    return await gateway.handle_jsonrpc(raw)


def run(coro):
    """Run an async function (convenience for scripts)."""
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def print_section(title: str) -> None:
    """Print a section header."""
    width = 64
    print(f"\n{'=' * width}")
    print(f"  {title}")
    print(f"{'=' * width}\n")


def print_decision(result: dict[str, Any], label: str = "") -> None:
    """Pretty-print a JSON-RPC decision response."""
    prefix = f"[{label}] " if label else ""

    if "error" in result:
        error = result["error"]
        print(f"  {prefix}ERROR: {error.get('message', 'unknown')}")
        return

    resp = result.get("result", {})
    decision = resp.get("decision", {})
    verdict = decision.get("decision", "?")
    risk = decision.get("risk_level", "?")
    reason = decision.get("reason", "")

    # Color-code the verdict
    icon = {"allow": "+", "block": "X", "modify": "~", "defer": "?"}
    marker = icon.get(verdict, " ")

    print(f"  {prefix}[{marker}] verdict={verdict}  risk={risk}")
    if reason:
        print(f"      reason: {reason}")


def print_risk_snapshot(result: dict[str, Any], label: str = "") -> None:
    """Pretty-print the risk dimensions from a decision response."""
    prefix = f"[{label}] " if label else ""
    resp = result.get("result", {})
    decision = resp.get("decision", {})
    reason = decision.get("reason", "")

    # Extract D1-D5 from reason string
    import re
    dims_match = re.search(r"D1=(\d) D2=(\d) D3=(\d) D4=(\d) D5=(\d)", reason)
    if dims_match:
        d1, d2, d3, d4, d5 = dims_match.groups()
        score_match = re.search(r"score=(\d+)", reason)
        score = score_match.group(1) if score_match else "?"
        sc_match = re.search(r"short_circuit=(SC-\d+)", reason)
        sc = sc_match.group(1) if sc_match else "-"
        print(
            f"  {prefix}D1={d1} D2={d2} D3={d3} D4={d4} D5={d5}  "
            f"score={score}  short_circuit={sc}"
        )
    else:
        print(f"  {prefix}{reason[:80]}")


def print_json(data: Any, indent: int = 2) -> None:
    """Pretty-print JSON data."""
    print(json.dumps(data, indent=indent, ensure_ascii=False))
