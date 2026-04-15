#!/usr/bin/env python3
"""
End-to-end enforcement test for OpenClaw integration.

This script validates the full enforcement loop:
  1. Start a mock OpenClaw Gateway (WebSocket server)
  2. Boot ClawSentry with enforcement enabled
  3. Gateway broadcasts exec.approval.requested events via WS
  4. Monitor automatically receives, analyzes, and resolves via WS

Modes:
  mock  — Local mock gateway, deterministic policy (default)
  ws    — WS listener mode: mock gateway broadcasts events, Monitor auto-resolves
  real  — Connect to a deployed OpenClaw Gateway

Usage:
    python examples/e2e_openclaw_enforcement.py            # mock mode
    python examples/e2e_openclaw_enforcement.py --ws       # WS listener mode
    python examples/e2e_openclaw_enforcement.py --real      # real gateway

Environment variables (real mode):
    OPENCLAW_WS_URL          WebSocket URL of OpenClaw Gateway
    OPENCLAW_OPERATOR_TOKEN  Operator token for authentication
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("e2e-enforcement")


async def run_mock_mode() -> bool:
    """Run E2E test with a local mock OpenClaw Gateway (outbound resolve)."""
    from clawsentry.tests.helpers.mock_openclaw_gateway import (
        MockOpenClawGateway,
    )
    from clawsentry.adapters.openclaw_bootstrap import (
        OpenClawBootstrapConfig,
        build_openclaw_runtime,
    )
    from clawsentry.gateway.models import (
        CanonicalDecision,
        DecisionVerdict,
        DecisionSource,
        RiskLevel,
    )

    logger.info("=== E2E Enforcement Test (Mock Mode) ===")

    # Step 1: Start mock gateway
    logger.info("[Step 1] Starting mock OpenClaw Gateway...")
    gateway = MockOpenClawGateway(require_token="e2e-test-token")
    await gateway.start()
    logger.info("  Mock gateway started on %s", gateway.ws_url)

    try:
        # Step 2: Build runtime with enforcement enabled
        logger.info("[Step 2] Building ClawSentry runtime with enforcement...")
        cfg = OpenClawBootstrapConfig(
            webhook_token="e2e-webhook-token",
            webhook_require_https=False,
            enforcement_enabled=True,
            openclaw_ws_url=gateway.ws_url,
            openclaw_operator_token="e2e-test-token",
        )
        runtime = build_openclaw_runtime(cfg)

        # Override gateway_client to return deterministic decisions
        class MockPolicyGateway:
            """Simulates policy engine decisions for E2E demo."""
            async def request_decision(self, event):
                tool = event.tool_name or ""
                command = event.payload.get("command", "")
                if any(d in command for d in ["rm -rf", "sudo", "chmod 777"]):
                    return CanonicalDecision(
                        decision=DecisionVerdict.BLOCK,
                        reason=f"Dangerous command blocked: {command}",
                        policy_id="e2e-demo-policy",
                        risk_level=RiskLevel.HIGH,
                        decision_source=DecisionSource.POLICY,
                        final=True,
                    )
                return CanonicalDecision(
                    decision=DecisionVerdict.ALLOW,
                    reason=f"Safe tool allowed: {tool}",
                    policy_id="e2e-demo-policy",
                    risk_level=RiskLevel.LOW,
                    decision_source=DecisionSource.POLICY,
                    final=True,
                )

        runtime.adapter._gateway_client = MockPolicyGateway()

        # Step 3: Connect approval client
        logger.info("[Step 3] Connecting approval client to mock gateway...")
        await runtime.approval_client.connect()
        if not runtime.approval_client.connected:
            logger.error("  FAIL: Could not connect to mock gateway")
            return False
        logger.info("  Connected successfully")

        # Step 4: Simulate a dangerous approval event
        logger.info("[Step 4] Simulating dangerous tool approval event...")
        decision = await runtime.adapter.handle_hook_event(
            event_type="exec.approval.requested",
            payload={
                "approval_id": "ap-e2e-001",
                "tool": "bash",
                "command": "rm -rf /important-data",
            },
            session_id="e2e-session-1",
            agent_id="e2e-agent-1",
        )
        logger.info("  Monitor decision: %s (reason: %s)", decision.decision, decision.reason)

        # Step 5: Verify enforcement callback reached the gateway
        logger.info("[Step 5] Checking enforcement callback reached gateway...")
        if len(gateway.resolved_approvals) == 0:
            logger.error("  FAIL: No approval resolutions received by gateway")
            return False

        resolved = gateway.resolved_approvals[0]
        logger.info("  Gateway received: id=%s, decision=%s",
                     resolved["id"], resolved["decision"])

        if resolved["id"] != "ap-e2e-001" or resolved["decision"] != "deny":
            logger.error("  FAIL: Expected deny for ap-e2e-001")
            return False

        # Step 6: Test safe command (should allow)
        logger.info("[Step 6] Simulating safe tool approval event...")
        decision2 = await runtime.adapter.handle_hook_event(
            event_type="exec.approval.requested",
            payload={
                "approval_id": "ap-e2e-002",
                "tool": "Read",
                "path": "/tmp/safe-file.txt",
            },
            session_id="e2e-session-1",
            agent_id="e2e-agent-1",
        )
        logger.info("  Monitor decision: %s", decision2.decision)

        if len(gateway.resolved_approvals) != 2:
            logger.error("  FAIL: Expected 2 resolutions, got %d",
                         len(gateway.resolved_approvals))
            return False

        resolved2 = gateway.resolved_approvals[1]
        if resolved2["decision"] != "allow-once":
            logger.error("  FAIL: Expected allow-once, got %s", resolved2["decision"])
            return False

        # Step 7: Close
        logger.info("[Step 7] Closing connections...")
        await runtime.approval_client.close()

        logger.info("")
        logger.info("=== ALL CHECKS PASSED (Mock Mode) ===")
        return True

    finally:
        await gateway.stop()


async def run_ws_listener_mode() -> bool:
    """Run E2E test with WS event listener: gateway broadcasts events, Monitor auto-resolves."""
    from clawsentry.tests.helpers.mock_openclaw_gateway import (
        MockOpenClawGateway,
    )
    from clawsentry.adapters.openclaw_bootstrap import (
        OpenClawBootstrapConfig,
        build_openclaw_runtime,
    )
    from clawsentry.gateway.models import (
        CanonicalDecision,
        DecisionVerdict,
        DecisionSource,
        RiskLevel,
    )

    logger.info("=== E2E Enforcement Test (WS Listener Mode) ===")

    # Step 1: Start mock gateway
    logger.info("[Step 1] Starting mock OpenClaw Gateway...")
    gateway = MockOpenClawGateway(require_token="e2e-ws-token")
    await gateway.start()
    logger.info("  Mock gateway started on %s", gateway.ws_url)

    try:
        # Step 2: Build runtime
        logger.info("[Step 2] Building ClawSentry runtime with enforcement...")
        cfg = OpenClawBootstrapConfig(
            webhook_token="e2e-webhook-token",
            webhook_require_https=False,
            enforcement_enabled=True,
            openclaw_ws_url=gateway.ws_url,
            openclaw_operator_token="e2e-ws-token",
        )
        runtime = build_openclaw_runtime(cfg)

        # Deterministic policy
        class MockPolicyGateway:
            async def request_decision(self, event):
                command = event.payload.get("command", "")
                if any(d in command for d in ["rm -rf", "sudo", "chmod 777"]):
                    return CanonicalDecision(
                        decision=DecisionVerdict.BLOCK,
                        reason=f"Blocked: {command}",
                        policy_id="e2e-demo-policy",
                        risk_level=RiskLevel.HIGH,
                        decision_source=DecisionSource.POLICY,
                        final=True,
                    )
                return CanonicalDecision(
                    decision=DecisionVerdict.ALLOW,
                    reason=f"Allowed: {event.tool_name}",
                    policy_id="e2e-demo-policy",
                    risk_level=RiskLevel.LOW,
                    decision_source=DecisionSource.POLICY,
                    final=True,
                )

        runtime.adapter._gateway_client = MockPolicyGateway()

        # Step 3: Connect + start WS listener
        logger.info("[Step 3] Connecting and starting WS event listener...")
        await runtime.approval_client.connect()
        if not runtime.approval_client.connected:
            logger.error("  FAIL: Could not connect")
            return False

        await runtime.approval_client.start_listening(
            runtime.adapter.handle_ws_approval_event,
        )
        if not runtime.approval_client.listening:
            logger.error("  FAIL: Listener did not start")
            return False
        logger.info("  WS listener active")

        await asyncio.sleep(0.05)  # let listener settle

        # Step 4: Gateway broadcasts dangerous command
        logger.info("[Step 4] Gateway broadcasting: exec.approval.requested (dangerous)...")
        await gateway.broadcast_approval_request(
            approval_id="ap-ws-e2e-001",
            tool="bash",
            command="rm -rf /important-data",
        )

        # Wait for auto-resolve
        for _ in range(40):
            if gateway.resolved_approvals:
                break
            await asyncio.sleep(0.05)

        if not gateway.resolved_approvals:
            logger.error("  FAIL: No approval resolution received (timeout)")
            return False

        resolved = gateway.resolved_approvals[0]
        logger.info("  Auto-resolved: id=%s decision=%s", resolved["id"], resolved["decision"])

        if resolved["id"] != "ap-ws-e2e-001" or resolved["decision"] != "deny":
            logger.error("  FAIL: Expected deny for ap-ws-e2e-001")
            return False

        # Step 5: Gateway broadcasts safe command
        logger.info("[Step 5] Gateway broadcasting: exec.approval.requested (safe)...")
        await gateway.broadcast_approval_request(
            approval_id="ap-ws-e2e-002",
            tool="Read",
            command="cat /tmp/readme.txt",
        )

        for _ in range(40):
            if len(gateway.resolved_approvals) >= 2:
                break
            await asyncio.sleep(0.05)

        if len(gateway.resolved_approvals) < 2:
            logger.error("  FAIL: Second resolution not received")
            return False

        resolved2 = gateway.resolved_approvals[1]
        logger.info("  Auto-resolved: id=%s decision=%s", resolved2["id"], resolved2["decision"])

        if resolved2["decision"] != "allow-once":
            logger.error("  FAIL: Expected allow-once, got %s", resolved2["decision"])
            return False

        # Step 6: Close
        logger.info("[Step 6] Closing...")
        await runtime.approval_client.close()

        logger.info("")
        logger.info("=== ALL CHECKS PASSED (WS Listener Mode) ===")
        logger.info("  Gateway broadcast → Monitor auto-receive → analyze → auto-resolve")
        logger.info("  Dangerous command → BLOCK → deny")
        logger.info("  Safe command → ALLOW → allow-once")
        return True

    finally:
        await gateway.stop()


async def run_real_mode() -> bool:
    """Run E2E test against a real OpenClaw Gateway deployment."""
    import os
    from clawsentry.adapters.openclaw_ws_client import (
        OpenClawApprovalClient,
        OpenClawApprovalClientConfig,
    )

    ws_url = os.getenv("OPENCLAW_WS_URL", "ws://127.0.0.1:18789")
    token = os.getenv("OPENCLAW_OPERATOR_TOKEN", "")

    if not token:
        logger.error("OPENCLAW_OPERATOR_TOKEN not set. Cannot connect to real gateway.")
        return False

    logger.info("=== E2E Enforcement Test (Real Mode) ===")
    logger.info("  Target: %s", ws_url)

    # Step 1: Connect to real gateway
    logger.info("[Step 1] Connecting to OpenClaw Gateway...")
    cfg = OpenClawApprovalClientConfig(
        ws_url=ws_url,
        operator_token=token,
        enabled=True,
    )
    client = OpenClawApprovalClient(cfg)
    await client.connect()

    if not client.connected:
        logger.error("  FAIL: Could not connect to gateway at %s", ws_url)
        return False
    logger.info("  Connected successfully")

    # Step 2: Start listener to verify we can receive events
    logger.info("[Step 2] Starting WS event listener...")
    received_events: list[dict] = []

    async def on_event(payload):
        logger.info("  Received event: %s", payload.get("id", "?"))
        received_events.append(payload)

    await client.start_listening(on_event)
    logger.info("  Listener active (waiting 3s for any events)...")
    await asyncio.sleep(3.0)
    logger.info("  Received %d events during wait", len(received_events))

    # Step 3: Send a test resolve
    logger.info("[Step 3] Sending test resolve (deny) for dummy approval...")
    result = await client.resolve("ap-e2e-test-dummy", "deny")
    logger.info("  Result: %s (False is expected if approval ID doesn't exist)", result)

    # Step 4: Close
    logger.info("[Step 4] Closing connection...")
    await client.close()

    logger.info("")
    logger.info("=== REAL MODE COMPLETE ===")
    logger.info("  WebSocket connection: OK")
    logger.info("  Authentication: OK")
    logger.info("  WS listener: OK (%d events received)", len(received_events))
    logger.info("  RPC round-trip: OK")
    return True


def main():
    parser = argparse.ArgumentParser(
        description="E2E enforcement test for OpenClaw integration"
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--ws",
        action="store_true",
        help="WS listener mode: gateway broadcasts events, Monitor auto-resolves",
    )
    group.add_argument(
        "--real",
        action="store_true",
        help="Connect to a real OpenClaw Gateway instead of using mock",
    )
    args = parser.parse_args()

    if args.real:
        success = asyncio.run(run_real_mode())
    elif args.ws:
        success = asyncio.run(run_ws_listener_mode())
    else:
        success = asyncio.run(run_mock_mode())

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
