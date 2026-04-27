#!/usr/bin/env python3
"""Run one dangerous case through every supported ClawSentry framework path.

This smoke is intentionally local and deterministic. It does not start real
Claude Code, Codex, Gemini CLI, a3s-code, or OpenClaw processes; instead it
exercises each framework's existing ClawSentry ingress path against the same
Gateway policy decision.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

DEFAULT_CASE_COMMAND = "rm -rf /tmp/clawsentry-single-case-target"
FRAMEWORKS = ("a3s-code", "claude-code", "codex", "gemini-cli", "openclaw")


def _decision_value(value: Any) -> str:
    raw = getattr(value, "value", value)
    return str(raw or "").lower()


def _risk_value(value: Any) -> str:
    raw = getattr(value, "value", value)
    return str(raw or "unknown").lower()


def _result_status(decision: str) -> str:
    return "passed" if decision in {"block", "defer", "deny"} else "failed"


def _write_summary_markdown(summary: dict[str, Any], result_dir: Path) -> None:
    lines = [
        "# Multi-Framework Single Case Smoke",
        "",
        f"- Case command: `{summary['case']['command']}`",
        f"- Passed: `{summary['passed']}`",
        f"- Failed: `{summary['failed']}`",
        "",
        "| Framework | Ingress | Decision | Risk | Events | Status |",
        "| --- | --- | --- | --- | ---: | --- |",
    ]
    for row in summary["results"]:
        lines.append(
            "| {framework} | {ingress} | {decision} | {risk_level} | {event_count} | {status} |".format(
                **row
            )
        )
    lines.extend(
        [
            "",
            "This smoke exercises local ClawSentry ingress paths only. It is not a",
            "raw-framework baseline and does not prove a real external CLI executed.",
        ]
    )
    (result_dir / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


async def _run_a3s_code(*, gw: Any, uds_path: Path, case_command: str) -> dict[str, Any]:
    from clawsentry.adapters.a3s_adapter import A3SCodeAdapter
    from clawsentry.adapters.a3s_gateway_harness import A3SGatewayHarness

    initial_count = gw.trajectory_store.count()
    adapter = A3SCodeAdapter(uds_path=str(uds_path), default_deadline_ms=500)
    harness = A3SGatewayHarness(adapter)
    response = await harness.dispatch_async(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "ahp/event",
            "params": {
                "event_type": "pre_action",
                "session_id": "single-case-a3s",
                "agent_id": "agent-a3s",
                "payload": {
                    "tool": "bash",
                    "arguments": {"command": case_command},
                },
            },
        }
    )
    result = response.get("result", response) if isinstance(response, dict) else {}
    decision = _decision_value(result.get("decision") or result.get("action"))
    return {
        "framework": "a3s-code",
        "source_framework": "a3s-code",
        "ingress": "A3SGatewayHarness JSON-RPC over UDS",
        "decision": decision,
        "risk_level": _risk_value(result.get("risk_level")),
        "reason": str(result.get("reason") or ""),
        "event_count": gw.trajectory_store.count() - initial_count,
        "status": _result_status(decision),
    }


async def _run_claude_code(*, gw: Any, uds_path: Path, case_command: str) -> dict[str, Any]:
    from clawsentry.adapters.a3s_adapter import A3SCodeAdapter
    from clawsentry.adapters.a3s_gateway_harness import A3SGatewayHarness

    initial_count = gw.trajectory_store.count()
    adapter = A3SCodeAdapter(
        uds_path=str(uds_path),
        default_deadline_ms=500,
        source_framework="claude-code",
    )
    harness = A3SGatewayHarness(adapter)
    response = await harness.dispatch_async(
        {
            "event_type": "PreToolUse",
            "payload": {
                "session_id": "single-case-claude-code",
                "tool": "Bash",
                "args": {"command": case_command},
                "working_directory": "/workspace",
                "recent_tools": [],
            },
        }
    )
    result = response.get("result", response) if isinstance(response, dict) else {}
    decision = _decision_value(result.get("decision") or result.get("action"))
    return {
        "framework": "claude-code",
        "source_framework": "claude-code",
        "ingress": "Claude Code hook shape through A3SGatewayHarness over UDS",
        "decision": decision,
        "risk_level": _risk_value(result.get("risk_level")),
        "reason": str(result.get("reason") or ""),
        "event_count": gw.trajectory_store.count() - initial_count,
        "status": _result_status(decision),
    }


async def _run_gemini_cli(*, gw: Any, uds_path: Path, case_command: str) -> dict[str, Any]:
    from clawsentry.adapters.a3s_adapter import A3SCodeAdapter
    from clawsentry.adapters.a3s_gateway_harness import A3SGatewayHarness

    initial_count = gw.trajectory_store.count()
    adapter = A3SCodeAdapter(
        uds_path=str(uds_path),
        default_deadline_ms=500,
        source_framework="gemini-cli",
    )
    harness = A3SGatewayHarness(adapter)
    response = await harness.dispatch_async(
        {
            "session_id": "single-case-gemini",
            "hook_event_name": "BeforeTool",
            "tool_name": "run_shell_command",
            "tool_input": {"command": case_command},
            "cwd": "/workspace",
        }
    )
    decision = _decision_value((response or {}).get("decision"))
    return {
        "framework": "gemini-cli",
        "source_framework": "gemini-cli",
        "ingress": "Gemini CLI BeforeTool hook shape through harness over UDS",
        "decision": decision,
        "risk_level": "unknown",
        "reason": str((response or {}).get("reason") or ""),
        "event_count": gw.trajectory_store.count() - initial_count,
        "status": _result_status(decision),
    }


async def _run_codex(*, gw: Any, case_command: str) -> dict[str, Any]:
    from httpx import ASGITransport, AsyncClient

    from clawsentry.gateway.server import create_http_app

    token = "single-case-codex-token-000000000000"
    os.environ["CS_AUTH_TOKEN"] = token
    initial_count = gw.trajectory_store.count()
    app = create_http_app(gw)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            f"/ahp/codex?token={token}",
            json={
                "event_type": "function_call",
                "payload": {
                    "name": "bash",
                    "arguments": {"command": case_command},
                },
                "session_id": "single-case-codex",
            },
        )
    response.raise_for_status()
    result = response.json()["result"]
    decision = _decision_value(result.get("decision") or result.get("action"))
    return {
        "framework": "codex",
        "source_framework": "codex",
        "ingress": "Codex HTTP /ahp/codex",
        "decision": decision,
        "risk_level": _risk_value(result.get("risk_level")),
        "reason": str(result.get("reason") or ""),
        "event_count": gw.trajectory_store.count() - initial_count,
        "status": _result_status(decision),
    }


async def _run_openclaw(*, gw: Any, uds_path: Path, case_command: str) -> dict[str, Any]:
    from clawsentry.adapters.openclaw_adapter import OpenClawAdapter, OpenClawAdapterConfig
    from clawsentry.adapters.openclaw_gateway_client import OpenClawGatewayClient

    initial_count = gw.trajectory_store.count()
    client = OpenClawGatewayClient(uds_path=str(uds_path), default_deadline_ms=500)
    adapter = OpenClawAdapter(
        config=OpenClawAdapterConfig(
            source_protocol_version="1.0",
            git_short_sha="singlecase",
            require_https=False,
        ),
        gateway_client=client,
    )
    decision_obj = await adapter.handle_hook_event(
        event_type="exec.approval.requested",
        payload={
            "approval_id": "single-case-openclaw",
            "tool": "bash",
            "command": case_command,
        },
        session_id="single-case-openclaw",
        agent_id="agent-openclaw",
    )
    decision = _decision_value(decision_obj.decision if decision_obj is not None else "")
    return {
        "framework": "openclaw",
        "source_framework": "openclaw",
        "ingress": "OpenClaw adapter exec.approval.requested over UDS",
        "decision": decision,
        "risk_level": _risk_value(decision_obj.risk_level if decision_obj is not None else ""),
        "reason": str(decision_obj.reason if decision_obj is not None else ""),
        "event_count": gw.trajectory_store.count() - initial_count,
        "status": _result_status(decision),
    }


async def _run_smoke_async(*, result_dir: Path, case_command: str) -> dict[str, Any]:
    from clawsentry.gateway.server import SupervisionGateway, start_uds_server

    result_dir.mkdir(parents=True, exist_ok=True)
    uds_path = result_dir / "clawsentry-single-case.sock"
    if uds_path.exists():
        uds_path.unlink()

    gw = SupervisionGateway()
    server = await start_uds_server(gw, str(uds_path))
    try:
        results = [
            await _run_a3s_code(gw=gw, uds_path=uds_path, case_command=case_command),
            await _run_claude_code(gw=gw, uds_path=uds_path, case_command=case_command),
            await _run_codex(gw=gw, case_command=case_command),
            await _run_gemini_cli(gw=gw, uds_path=uds_path, case_command=case_command),
            await _run_openclaw(gw=gw, uds_path=uds_path, case_command=case_command),
        ]
    finally:
        server.close()
        await server.wait_closed()
        if uds_path.exists():
            uds_path.unlink()

    summary = {
        "schema_version": "clawsentry.framework_single_case_smoke.v1",
        "case": {
            "kind": "dangerous_shell_pre_action",
            "command": case_command,
        },
        "frameworks": sorted(row["framework"] for row in results),
        "passed": sum(1 for row in results if row["status"] == "passed"),
        "failed": sum(1 for row in results if row["status"] != "passed"),
        "results": sorted(results, key=lambda row: row["framework"]),
        "artifacts": {
            "summary": str(result_dir / "summary.json"),
            "summary_markdown": str(result_dir / "summary.md"),
        },
        "notes": [
            "Local deterministic smoke only; real framework CLIs are not launched.",
            "A pass means the framework ingress path reached ClawSentry and produced a blocking decision for the same case.",
        ],
    }
    (result_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _write_summary_markdown(summary, result_dir)
    return summary


def run_smoke(
    *,
    result_dir: Path,
    case_command: str = DEFAULT_CASE_COMMAND,
) -> dict[str, Any]:
    return asyncio.run(_run_smoke_async(result_dir=result_dir, case_command=case_command))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run one dangerous case through all local ClawSentry framework ingress paths."
    )
    parser.add_argument("--result-dir", type=Path, required=True)
    parser.add_argument("--case-command", default=DEFAULT_CASE_COMMAND)
    parser.add_argument("--print-summary", action="store_true", default=False)
    args = parser.parse_args()

    summary = run_smoke(result_dir=args.result_dir, case_command=args.case_command)
    if args.print_summary:
        print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0 if summary["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
