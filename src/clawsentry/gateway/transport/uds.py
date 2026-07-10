"""Unix domain socket transport for the supervision gateway."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import struct
import sys
from typing import Any, Optional, Protocol

logger = logging.getLogger("clawsentry")

DEFAULT_UDS_PATH = "/tmp/clawsentry.sock"


class JsonRpcGateway(Protocol):
    async def handle_jsonrpc(self, raw_body: bytes) -> dict[str, Any]:
        """Handle a raw JSON-RPC request body."""


async def _uds_client_handler(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    gateway: JsonRpcGateway,
) -> None:
    """Handle a single UDS client connection using length-prefixed framing."""
    try:
        while True:
            length_bytes = await reader.readexactly(4)
            msg_length = struct.unpack("!I", length_bytes)[0]

            if msg_length == 0 or msg_length > 10 * 1024 * 1024:
                logger.warning("UDS: rejected frame with length %d", msg_length)
                break

            data = await reader.readexactly(msg_length)
            result = await gateway.handle_jsonrpc(data)
            response_bytes = json.dumps(result).encode("utf-8")

            writer.write(struct.pack("!I", len(response_bytes)))
            writer.write(response_bytes)
            await writer.drain()

    except (asyncio.IncompleteReadError, ConnectionResetError):
        pass
    except Exception:
        logger.exception("UDS client handler error")
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def start_uds_server(
    gateway: JsonRpcGateway,
    path: str = DEFAULT_UDS_PATH,
) -> Optional[asyncio.AbstractServer]:
    """Start the Unix Domain Socket server (Unix/Linux/macOS only)."""
    if sys.platform == "win32":
        logger.warning("UDS not supported on Windows, using HTTP transport only")
        return None

    if os.path.exists(path):
        os.unlink(path)

    async def handler(reader, writer):
        await _uds_client_handler(reader, writer, gateway)

    server = await asyncio.start_unix_server(handler, path=path)
    os.chmod(path, 0o600)
    logger.info("UDS server listening on %s (mode=0600)", path)
    return server
