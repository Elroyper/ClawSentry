"""
Tests for OpenClaw Webhook Receiver — Gate 4 verification.

Covers: POST /webhook/openclaw endpoint, security pipeline, normalization,
idempotency dedup, health check.
"""

import hmac
import hashlib
import json
import time
import pytest
from unittest.mock import AsyncMock, MagicMock

from fastapi.testclient import TestClient
from clawsentry.adapters.openclaw_webhook_receiver import create_webhook_app
from clawsentry.adapters.webhook_security import WebhookSecurityConfig
from clawsentry.adapters.openclaw_normalizer import OpenClawNormalizer
from clawsentry.gateway.models import (
    CanonicalDecision,
    DecisionVerdict,
    DecisionSource,
    FailureClass,
    RiskLevel,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_config(**overrides) -> WebhookSecurityConfig:
    defaults = dict(
        primary_token="tok-test",
        webhook_secret="test-secret",
        require_https=False,
    )
    defaults.update(overrides)
    return WebhookSecurityConfig(**defaults)


def _make_normalizer() -> OpenClawNormalizer:
    return OpenClawNormalizer(
        source_protocol_version="1.0",
        git_short_sha="abc1234",
    )


def _sign(secret: str, ts: int, body: bytes) -> str:
    msg = f"{ts}.".encode() + body
    sig = hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()
    return f"v1={sig}"


@pytest.fixture
def mock_gateway_client():
    client = AsyncMock()
    client.request_decision.return_value = CanonicalDecision(
        decision=DecisionVerdict.ALLOW,
        reason="test allow",
        policy_id="test",
        risk_level=RiskLevel.LOW,
        decision_source=DecisionSource.POLICY,
        final=True,
    )
    return client


@pytest.fixture
def app(mock_gateway_client):
    config = _make_config()
    normalizer = _make_normalizer()
    return create_webhook_app(config, normalizer, mock_gateway_client)


@pytest.fixture
def test_client(app):
    return TestClient(app)


def _webhook_headers(token: str, secret: str, body: bytes) -> dict:
    ts = int(time.time())
    sig = _sign(secret, ts, body)
    return {
        "Authorization": f"Bearer {token}",
        "X-AHP-Signature": sig,
        "X-AHP-Timestamp": str(ts),
        "Content-Type": "application/json",
    }


# ===========================================================================
# Health Check
# ===========================================================================

class TestHealthCheck:
    def test_health_returns_ok(self, test_client):
        resp = test_client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"


# ===========================================================================
# Webhook Endpoint — Happy Path
# ===========================================================================

class TestWebhookHappyPath:
    def test_valid_request_returns_decision(self, test_client):
        body = json.dumps({
            "type": "exec.approval.requested",
            "sessionKey": "s1",
            "agentId": "a1",
            "payload": {"approval_id": "ap-1", "tool": "read_file", "path": "/tmp/x"},
        }).encode()
        headers = _webhook_headers("tok-test", "test-secret", body)
        resp = test_client.post("/webhook/openclaw", content=body, headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "allow"

    def test_message_event_returns_decision(self, test_client):
        body = json.dumps({
            "type": "message:received",
            "sessionKey": "s1",
            "agentId": "a1",
            "payload": {"text": "hello"},
        }).encode()
        headers = _webhook_headers("tok-test", "test-secret", body)
        resp = test_client.post("/webhook/openclaw", content=body, headers=headers)
        assert resp.status_code == 200

    def test_chat_event_with_run_metadata_returns_decision(self, test_client, mock_gateway_client):
        body = json.dumps({
            "type": "chat",
            "sessionKey": "s1",
            "agentId": "a1",
            "runId": "run-1",
            "sourceSeq": 1,
            "payload": {"state": "final", "text": "done"},
        }).encode()
        headers = _webhook_headers("tok-test", "test-secret", body)
        resp = test_client.post("/webhook/openclaw", content=body, headers=headers)
        assert resp.status_code == 200
        assert resp.json()["decision"] == "allow"
        assert mock_gateway_client.request_decision.call_count == 1


# ===========================================================================
# Webhook Endpoint — Security Failures
# ===========================================================================

class TestWebhookSecurityFailures:
    def test_invalid_token_401(self, test_client):
        body = json.dumps({
            "type": "message:received",
            "sessionKey": "s1",
        }).encode()
        headers = _webhook_headers("wrong-token", "test-secret", body)
        resp = test_client.post("/webhook/openclaw", content=body, headers=headers)
        assert resp.status_code == 401

    def test_invalid_signature_401(self, test_client):
        body = json.dumps({
            "type": "message:received",
            "sessionKey": "s1",
        }).encode()
        ts = int(time.time())
        headers = {
            "Authorization": "Bearer tok-test",
            "X-AHP-Signature": "v1=invalidsig",
            "X-AHP-Timestamp": str(ts),
            "Content-Type": "application/json",
        }
        resp = test_client.post("/webhook/openclaw", content=body, headers=headers)
        assert resp.status_code == 401

    def test_missing_required_fields_400(self, test_client):
        body = json.dumps({"data": "missing type and sessionKey"}).encode()
        headers = _webhook_headers("tok-test", "test-secret", body)
        resp = test_client.post("/webhook/openclaw", content=body, headers=headers)
        assert resp.status_code == 400


# ===========================================================================
# Idempotency
# ===========================================================================

class TestIdempotency:
    def test_duplicate_idempotency_key(self, test_client, mock_gateway_client):
        body = json.dumps({
            "type": "exec.approval.requested",
            "sessionKey": "s1",
            "idempotencyKey": "idem-1",
            "payload": {"approval_id": "ap-1", "tool": "read_file"},
        }).encode()
        headers = _webhook_headers("tok-test", "test-secret", body)
        resp1 = test_client.post("/webhook/openclaw", content=body, headers=headers)
        # Second request with same body (same idempotency key)
        headers2 = _webhook_headers("tok-test", "test-secret", body)
        resp2 = test_client.post("/webhook/openclaw", content=body, headers=headers2)
        assert resp1.status_code == 200
        assert resp2.status_code == 200
        # Gateway should only be called once (second is cached)
        assert mock_gateway_client.request_decision.call_count == 1

    def test_same_idempotency_key_with_different_body_returns_conflict(self, test_client, mock_gateway_client):
        body1 = json.dumps({
            "type": "exec.approval.requested",
            "sessionKey": "s1",
            "idempotencyKey": "idem-2",
            "payload": {"approval_id": "ap-1", "tool": "read_file", "path": "/tmp/a"},
        }).encode()
        body2 = json.dumps({
            "type": "exec.approval.requested",
            "sessionKey": "s1",
            "idempotencyKey": "idem-2",
            "payload": {"approval_id": "ap-1", "tool": "read_file", "path": "/tmp/b"},
        }).encode()

        resp1 = test_client.post(
            "/webhook/openclaw",
            content=body1,
            headers=_webhook_headers("tok-test", "test-secret", body1),
        )
        resp2 = test_client.post(
            "/webhook/openclaw",
            content=body2,
            headers=_webhook_headers("tok-test", "test-secret", body2),
        )

        assert resp1.status_code == 200
        assert resp2.status_code == 409
        assert "idempotency" in resp2.json()["error"].lower()
        # Second request must not reuse cached decision for a different body.
        assert mock_gateway_client.request_decision.call_count == 1

    def test_idempotency_cache_eviction_at_capacity(self, mock_gateway_client):
        app = create_webhook_app(
            _make_config(),
            _make_normalizer(),
            mock_gateway_client,
            idem_max_size=1,
            idem_ttl_seconds=300,
        )
        test_client = TestClient(app)

        body1 = json.dumps({
            "type": "exec.approval.requested",
            "sessionKey": "s-cap",
            "idempotencyKey": "idem-cap-1",
            "payload": {"approval_id": "ap-cap-1", "tool": "read_file", "path": "/tmp/a"},
        }).encode()
        body2 = json.dumps({
            "type": "exec.approval.requested",
            "sessionKey": "s-cap",
            "idempotencyKey": "idem-cap-2",
            "payload": {"approval_id": "ap-cap-2", "tool": "read_file", "path": "/tmp/b"},
        }).encode()

        resp1 = test_client.post(
            "/webhook/openclaw",
            content=body1,
            headers=_webhook_headers("tok-test", "test-secret", body1),
        )
        resp2 = test_client.post(
            "/webhook/openclaw",
            content=body2,
            headers=_webhook_headers("tok-test", "test-secret", body2),
        )

        assert resp1.status_code == 200
        assert resp2.status_code == 200
        # With max size = 1, second unique key must trigger eviction path.
        assert mock_gateway_client.request_decision.call_count == 2


# ===========================================================================
# Session ID Extraction — H-4
# ===========================================================================

class TestSessionIdExtraction:
    """H-4: Webhook must try both sessionKey and sessionId."""

    def test_webhook_falls_back_to_session_id(self, test_client, mock_gateway_client):
        """Webhook should use sessionId when sessionKey is absent."""
        body = json.dumps({
            "type": "exec.approval.requested",
            "sessionId": "sess-from-id-field",
            "agentId": "a1",
            "payload": {"approval_id": "ap-1", "tool": "read_file", "path": "/tmp/x"},
        }).encode()
        headers = _webhook_headers("tok-test", "test-secret", body)
        resp = test_client.post("/webhook/openclaw", content=body, headers=headers)
        assert resp.status_code == 200
        # Verify the normalizer received the sessionId value
        call_args = mock_gateway_client.request_decision.call_args
        event = call_args[0][0]  # first positional arg = CanonicalEvent
        assert event.session_id == "sess-from-id-field"

    def test_webhook_prefers_session_key_over_session_id(self, test_client, mock_gateway_client):
        """When both sessionKey and sessionId are present, sessionKey wins."""
        body = json.dumps({
            "type": "exec.approval.requested",
            "sessionKey": "from-key",
            "sessionId": "from-id",
            "agentId": "a1",
            "payload": {"approval_id": "ap-2", "tool": "read_file", "path": "/tmp/y"},
        }).encode()
        headers = _webhook_headers("tok-test", "test-secret", body)
        resp = test_client.post("/webhook/openclaw", content=body, headers=headers)
        assert resp.status_code == 200
        call_args = mock_gateway_client.request_decision.call_args
        event = call_args[0][0]
        assert event.session_id == "from-key"
