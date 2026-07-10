"""Gateway process runner and CLI entry point."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
from pathlib import Path
from typing import Any

import uvicorn

from ..core.supervision_gateway import SupervisionGateway
from clawsentry.gateway.config.detection_config import build_detection_config_from_env
from ..http.app import create_http_app
from clawsentry.gateway.storage.idempotency import periodic_cleanup
from clawsentry.gateway.llm.factory import build_analyzer_from_env
from clawsentry.gateway.policy.engine import L1PolicyEngine
from clawsentry.gateway.storage.trajectory_store import (
    DEFAULT_TRAJECTORY_DB_PATH,
    DEFAULT_TRAJECTORY_RETENTION_SECONDS,
)
from .uds import DEFAULT_UDS_PATH, start_uds_server

logger = logging.getLogger("clawsentry")

DEFAULT_HTTP_HOST = "127.0.0.1"
DEFAULT_HTTP_PORT = 8080


async def run_gateway(
    uds_path: str = DEFAULT_UDS_PATH,
    http_host: str = DEFAULT_HTTP_HOST,
    http_port: int = DEFAULT_HTTP_PORT,
    trajectory_db_path: str = DEFAULT_TRAJECTORY_DB_PATH,
    trajectory_retention_seconds: int = DEFAULT_TRAJECTORY_RETENTION_SECONDS,
    ssl_certfile: str | None = None,
    ssl_keyfile: str | None = None,
) -> None:
    """Run the Supervision Gateway with both UDS and HTTP transports."""
    # Build detection config from canonical CS_ environment variables.
    detection_config = build_detection_config_from_env()
    logger.info("DetectionConfig: %s", detection_config)

    gateway = SupervisionGateway(
        trajectory_db_path=trajectory_db_path,
        trajectory_retention_seconds=trajectory_retention_seconds,
        detection_config=detection_config,
    )

    # Wire LLM analyzer (same pattern as stack.py)
    analyzer = build_analyzer_from_env(
        trajectory_store=gateway.trajectory_store,
        session_registry=gateway.session_registry,
        patterns_path=detection_config.attack_patterns_path,
        evolved_patterns_path=detection_config.evolved_patterns_path
        if detection_config.evolving_enabled
        else None,
        l3_budget_ms=detection_config.l3_budget_ms,
        metrics=gateway.metrics,
    )
    if analyzer is not None:
        gateway.policy_engine = L1PolicyEngine(
            analyzer=analyzer, config=detection_config
        )

    app = create_http_app(gateway)

    # Start UDS server
    uds_server = await start_uds_server(gateway, uds_path)

    # Start periodic cleanup
    cleanup_task = asyncio.create_task(
        periodic_cleanup(gateway.idempotency_cache, interval_seconds=10.0)
    )

    # Start HTTP server
    uvicorn_kwargs: dict[str, Any] = {
        "app": app,
        "host": http_host,
        "port": http_port,
        "log_level": "info",
        "access_log": False,
    }
    if ssl_certfile and ssl_keyfile:
        uvicorn_kwargs["ssl_certfile"] = ssl_certfile
        uvicorn_kwargs["ssl_keyfile"] = ssl_keyfile
        logger.info("HTTPS enabled (cert=%s, key=%s)", ssl_certfile, ssl_keyfile)
    config = uvicorn.Config(**uvicorn_kwargs)
    server = uvicorn.Server(config)

    logger.info(
        "Gateway starting: UDS=%s, HTTP=%s:%s, TrajectoryDB=%s",
        uds_path,
        http_host,
        http_port,
        trajectory_db_path,
    )

    try:
        await server.serve()
    finally:
        cleanup_task.cancel()
        uds_server.close()
        await uds_server.wait_closed()
        if os.path.exists(uds_path):
            os.unlink(uds_path)


def _gateway_args_from_env() -> dict:
    """Read gateway configuration from environment variables."""
    args: dict[str, Any] = {
        "uds_path": os.environ.get("CS_UDS_PATH", DEFAULT_UDS_PATH),
        "http_host": os.environ.get("CS_HTTP_HOST", DEFAULT_HTTP_HOST),
        "http_port": int(os.environ.get("CS_HTTP_PORT", str(DEFAULT_HTTP_PORT))),
        "trajectory_db_path": os.environ.get(
            "CS_TRAJECTORY_DB_PATH", DEFAULT_TRAJECTORY_DB_PATH
        ),
        "trajectory_retention_seconds": int(
            os.environ.get(
                "AHP_TRAJECTORY_RETENTION_SECONDS",
                str(DEFAULT_TRAJECTORY_RETENTION_SECONDS),
            )
        ),
    }
    ssl_cert = os.environ.get("AHP_SSL_CERTFILE", "").strip() or None
    ssl_key = os.environ.get("AHP_SSL_KEYFILE", "").strip() or None
    if ssl_cert and ssl_key:
        args["ssl_certfile"] = ssl_cert
        args["ssl_keyfile"] = ssl_key
    return args


def _build_gateway_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="clawsentry-gateway",
        description=(
            "Run the ClawSentry Supervision Gateway.\n\n"
            "All options can also be set via environment variables (shown in brackets).\n"
            "CLI flags take precedence over environment variables."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--uds-path",
        default=None,
        metavar="PATH",
        help=f"Unix domain socket path [CS_UDS_PATH] (default: {DEFAULT_UDS_PATH})",
    )
    parser.add_argument(
        "--host",
        default=None,
        metavar="HOST",
        help=f"HTTP bind host [CS_HTTP_HOST] (default: {DEFAULT_HTTP_HOST})",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        metavar="PORT",
        help=f"HTTP bind port [CS_HTTP_PORT] (default: {DEFAULT_HTTP_PORT})",
    )
    parser.add_argument(
        "--trajectory-db-path",
        default=None,
        metavar="PATH",
        help=f"SQLite trajectory DB path [CS_TRAJECTORY_DB_PATH] (default: {DEFAULT_TRAJECTORY_DB_PATH})",
    )
    parser.add_argument(
        "--trajectory-retention-seconds",
        type=int,
        default=None,
        metavar="SECONDS",
        help=f"Trajectory retention window [AHP_TRAJECTORY_RETENTION_SECONDS] (default: {DEFAULT_TRAJECTORY_RETENTION_SECONDS})",
    )
    parser.add_argument(
        "--env-file",
        default=None,
        help="Explicit local env file for secrets/runtime values.",
    )
    parser.add_argument(
        "--ssl-certfile",
        default=None,
        metavar="PATH",
        help="TLS certificate file [AHP_SSL_CERTFILE] (enables HTTPS when combined with --ssl-keyfile)",
    )
    parser.add_argument(
        "--ssl-keyfile",
        default=None,
        metavar="PATH",
        help="TLS private key file [AHP_SSL_KEYFILE]",
    )
    return parser


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")
    from ...cli.dotenv_loader import (
        EnvFileError,
        apply_env_file_to_legacy_environ,
        resolve_explicit_env_file,
    )

    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--env-file", default=None)
    pre_args, _ = pre.parse_known_args()
    try:
        parsed_env = resolve_explicit_env_file(
            cli_env_file=Path(pre_args.env_file) if pre_args.env_file else None,
            environ=os.environ,
        )
    except EnvFileError as exc:
        raise SystemExit(str(exc)) from exc
    apply_env_file_to_legacy_environ(parsed_env, environ=os.environ)

    parser = _build_gateway_parser()
    args = parser.parse_args()

    # Build kwargs: env-derived defaults, then override with explicit CLI flags
    kwargs = _gateway_args_from_env()
    if args.uds_path is not None:
        kwargs["uds_path"] = args.uds_path
    if args.host is not None:
        kwargs["http_host"] = args.host
    if args.port is not None:
        kwargs["http_port"] = args.port
    if args.trajectory_db_path is not None:
        kwargs["trajectory_db_path"] = args.trajectory_db_path
    if args.trajectory_retention_seconds is not None:
        kwargs["trajectory_retention_seconds"] = args.trajectory_retention_seconds
    if args.ssl_certfile is not None:
        kwargs["ssl_certfile"] = args.ssl_certfile
    if args.ssl_keyfile is not None:
        kwargs["ssl_keyfile"] = args.ssl_keyfile

    try:
        asyncio.run(run_gateway(**kwargs))
    except KeyboardInterrupt:
        logger.info("Gateway stopped by user.")
