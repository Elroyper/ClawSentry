"""
Webhook Security Layer — token, signature, timestamp, and request validation.

Design basis:
  - 08-openclaw-webhook-security-hardening.md section 2-4
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import json
import logging
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

from ..gateway.models import FailureClass

logger = logging.getLogger("webhook-security")


@dataclass
class WebhookSecurityConfig:
    """Configuration per 08 section 4.2."""
    primary_token: str
    secondary_token: Optional[str] = None
    webhook_secret: Optional[str] = None
    signature_mode: str = "strict"  # "strict" or "permissive"
    timestamp_tolerance_seconds: int = 300  # 5 minutes
    require_https: bool = True
    max_body_bytes: int = 1_048_576  # 1MB
    ip_whitelist: Optional[list[str]] = None  # None = disabled, [] = deny all
    token_issued_at: Optional[float] = None  # Unix timestamp
    token_ttl_seconds: int = 86400  # 24h default, 0 = no expiry


@dataclass
class SecurityCheckResult:
    """Result of webhook security verification."""
    ok: bool
    failure_class: FailureClass = FailureClass.NONE
    http_status: int = 200
    message: str = ""
    parsed_body: Optional[dict] = None


class WebhookTokenManager:
    """Dual-token verification per 08 section 2.3."""

    def __init__(self, config: WebhookSecurityConfig) -> None:
        self._tokens: set[str] = set()
        if config.primary_token:
            self._tokens.add(config.primary_token)
        if config.secondary_token:
            self._tokens.add(config.secondary_token)

    def verify_token(self, token: str) -> bool:
        if not token:
            return False
        return any(hmac_mod.compare_digest(token, t) for t in self._tokens)


def verify_webhook_request(
    config: WebhookSecurityConfig,
    token: str,
    signature: Optional[str],
    timestamp: Optional[str],
    content_type: str,
    body: bytes,
    source_url: str,
    source_ip: str = "",
) -> SecurityCheckResult:
    """
    Full webhook request verification pipeline per 08 section 4.1.

    Order: TLS → Token → Timestamp → Size → Content-Type → JSON → Signature → Required fields.
    """
    # 1. TLS enforcement
    if config.require_https:
        parsed = urlparse(source_url)
        scheme = parsed.scheme.lower()
        host = parsed.hostname or ""
        if scheme != "https" and host not in ("localhost", "127.0.0.1", "::1"):
            return SecurityCheckResult(
                ok=False,
                failure_class=FailureClass.INPUT_INVALID,
                http_status=403,
                message="HTTPS required for non-localhost",
            )

    # 1.5. IP whitelist
    if config.ip_whitelist is not None:
        if source_ip not in config.ip_whitelist:
            return SecurityCheckResult(
                ok=False,
                failure_class=FailureClass.AUTH_INVALID_TOKEN,
                http_status=403,
                message=f"Source IP {source_ip} not in whitelist",
            )

    # 2. Token verification
    mgr = WebhookTokenManager(config)
    if not mgr.verify_token(token):
        return SecurityCheckResult(
            ok=False,
            failure_class=FailureClass.AUTH_INVALID_TOKEN,
            http_status=401,
            message="Invalid or missing token",
        )

    # 2.5. Token TTL check
    if config.token_ttl_seconds > 0 and config.token_issued_at is not None:
        if time.time() - config.token_issued_at > config.token_ttl_seconds:
            return SecurityCheckResult(
                ok=False,
                failure_class=FailureClass.AUTH_INVALID_TOKEN,
                http_status=401,
                message="Token expired (TTL exceeded)",
            )

    # 3. Timestamp check
    if config.webhook_secret:
        if not timestamp:
            return SecurityCheckResult(
                ok=False,
                failure_class=FailureClass.AUTH_TIMESTAMP_EXPIRED,
                http_status=401,
                message="Missing timestamp",
            )
        try:
            ts_int = int(timestamp)
        except ValueError:
            return SecurityCheckResult(
                ok=False,
                failure_class=FailureClass.AUTH_TIMESTAMP_EXPIRED,
                http_status=401,
                message="Invalid timestamp format",
            )
        if abs(time.time() - ts_int) > config.timestamp_tolerance_seconds:
            return SecurityCheckResult(
                ok=False,
                failure_class=FailureClass.AUTH_TIMESTAMP_EXPIRED,
                http_status=401,
                message="Timestamp outside tolerance window",
            )

    # 4. Body size check
    if len(body) > config.max_body_bytes:
        return SecurityCheckResult(
            ok=False,
            failure_class=FailureClass.INPUT_INVALID,
            http_status=413,
            message=f"Body exceeds {config.max_body_bytes} bytes",
        )

    # 5. Content-Type check
    if not content_type or not content_type.startswith("application/json"):
        return SecurityCheckResult(
            ok=False,
            failure_class=FailureClass.INPUT_INVALID,
            http_status=415,
            message="Content-Type must be application/json",
        )

    # 6. JSON parse
    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return SecurityCheckResult(
            ok=False,
            failure_class=FailureClass.INPUT_INVALID,
            http_status=400,
            message="Invalid JSON body",
        )

    # 7. HMAC Signature verification
    if config.webhook_secret:
        if signature is None:
            if config.signature_mode == "strict":
                return SecurityCheckResult(
                    ok=False,
                    failure_class=FailureClass.AUTH_INVALID_SIGNATURE,
                    http_status=401,
                    message="Missing signature (strict mode)",
                )
            else:
                logger.warning("Missing webhook signature (permissive mode)")
        elif signature is not None:
            expected_msg = f"{timestamp}.".encode() + body
            expected_sig = hmac_mod.new(
                config.webhook_secret.encode(), expected_msg, hashlib.sha256
            ).hexdigest()
            expected = f"v1={expected_sig}"
            if not hmac_mod.compare_digest(signature, expected):
                return SecurityCheckResult(
                    ok=False,
                    failure_class=FailureClass.AUTH_INVALID_SIGNATURE,
                    http_status=401,
                    message="Invalid HMAC signature",
                )

    # 8. Required fields
    if not isinstance(parsed, dict):
        return SecurityCheckResult(
            ok=False,
            failure_class=FailureClass.INPUT_INVALID,
            http_status=400,
            message="Body must be a JSON object",
        )
    if not parsed.get("type") or not (parsed.get("sessionKey") or parsed.get("sessionId")):
        return SecurityCheckResult(
            ok=False,
            failure_class=FailureClass.INPUT_INVALID,
            http_status=400,
            message="Missing required fields: type, sessionKey",
        )

    return SecurityCheckResult(ok=True, parsed_body=parsed)
