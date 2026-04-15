#!/usr/bin/env python3
"""
Real OpenClaw E2E Monitor — connects to live gateway, intercepts agent commands.

Usage:
    OPENCLAW_OPERATOR_TOKEN=<token> python examples/e2e_openclaw_real_monitor.py

The script will:
  1. Connect to OpenClaw Gateway via WebSocket
  2. Start the WS event listener
  3. Wait for exec.approval.requested events
  4. Analyze each event through L1 policy engine
  5. Auto-resolve (deny dangerous, allow safe)
  6. Log every decision as evidence

Press Ctrl+C to stop.
"""
from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
import time

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("real-monitor")


async def main() -> int:
    from clawsentry.adapters.openclaw_bootstrap import (
        OpenClawBootstrapConfig,
        build_openclaw_runtime,
    )

    ws_url = os.getenv("OPENCLAW_WS_URL", "ws://127.0.0.1:18789")
    token = os.getenv(
        "OPENCLAW_OPERATOR_TOKEN",
        "afbf637a0d9c4f6a960d781b484d454f690683b77793b1605c5ebb9039407330",
    )

    if not token:
        logger.error("OPENCLAW_OPERATOR_TOKEN not set")
        return 1

    logger.info("=" * 60)
    logger.info("ClawSentry — Real OpenClaw E2E Enforcement")
    logger.info("=" * 60)
    logger.info("Target: %s", ws_url)

    # Build full runtime with enforcement
    cfg = OpenClawBootstrapConfig(
        webhook_token="unused-for-ws-mode",
        webhook_require_https=False,
        enforcement_enabled=True,
        openclaw_ws_url=ws_url,
        openclaw_operator_token=token,
    )
    runtime = build_openclaw_runtime(cfg)

    # Connect to real gateway
    logger.info("[1/3] Connecting to OpenClaw Gateway...")
    await runtime.approval_client.connect()
    if not runtime.approval_client.connected:
        logger.error("FAIL: Could not connect to gateway at %s", ws_url)
        return 1
    logger.info("  Connected successfully")

    # Track events for summary
    events_log: list[dict] = []

    # Wrap the event handler to track events
    original_handler = runtime.adapter.handle_ws_approval_event

    async def tracking_handler(payload: dict) -> None:
        t0 = time.monotonic()
        await original_handler(payload)
        elapsed_ms = (time.monotonic() - t0) * 1000
        # Real OpenClaw nests fields under payload.request
        request = payload.get("request", {})
        events_log.append({
            "id": payload.get("id", "?"),
            "tool": request.get("tool") or payload.get("tool", "?"),
            "command": request.get("command") or payload.get("command", "?"),
            "elapsed_ms": round(elapsed_ms, 1),
            "timestamp": time.strftime("%H:%M:%S"),
        })

    # Start WS listener
    logger.info("[2/3] Starting WS event listener...")
    await runtime.approval_client.start_listening(tracking_handler)
    if not runtime.approval_client.listening:
        logger.error("FAIL: Listener did not start")
        return 1
    logger.info("  Listener active — waiting for events...")
    logger.info("")
    logger.info(">>> Now trigger an agent task in OpenClaw:")
    logger.info('    docker exec openclaw-gateway node dist/index.js agent \\')
    logger.info('      --session-id test-001 --message "Run: echo hello world"')
    logger.info("")
    logger.info("  NOTE: openclaw.json must have tools.exec.host='gateway'")
    logger.info("  and exec-approvals.json must have security='allowlist'")
    logger.info("")

    # Wait for Ctrl+C or connection close
    shutdown = asyncio.Event()

    def on_signal(*_):
        shutdown.set()

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, on_signal)

    # Poll until shutdown or disconnected
    try:
        while not shutdown.is_set():
            if not runtime.approval_client.listening:
                logger.warning("WS listener stopped (connection lost?)")
                break
            await asyncio.sleep(1.0)
    except asyncio.CancelledError:
        pass

    # Summary
    logger.info("")
    logger.info("[3/3] Shutting down...")
    await runtime.approval_client.close()

    logger.info("")
    logger.info("=" * 60)
    logger.info("SESSION SUMMARY")
    logger.info("=" * 60)
    logger.info("Total events intercepted: %d", len(events_log))
    for ev in events_log:
        logger.info(
            "  [%s] %s | tool=%s | command=%s | %sms",
            ev["timestamp"], ev["id"], ev["tool"], ev["command"], ev["elapsed_ms"],
        )
    if not events_log:
        logger.info("  (no events received)")

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
