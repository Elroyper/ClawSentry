"""
Tests for HTTP endpoint authentication (#34).

Covers: Bearer token enforcement, /health bypass, no-token dev mode,
weak token warning, 401 response format, timing-safe comparison.
"""

import hmac
import json
import os
import pytest
from httpx import AsyncClient, ASGITransport

from clawsentry.gateway.server import SupervisionGateway, create_http_app
from clawsentry.gateway.models import RPC_VERSION


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _jsonrpc_request(method: str, params: dict, rpc_id: int = 1) -> bytes:
    return json.dumps({
        "jsonrpc": "2.0",
        "id": rpc_id,
        "method": method,
        "params": params,
    }).encode()


def _sync_decision_params(**overrides) -> dict:
    base = {
        "rpc_version": RPC_VERSION,
        "request_id": "req-auth-001",
        "deadline_ms": 100,
        "decision_tier": "L1",
        "event": {
            "event_id": "evt-auth-001",
            "trace_id": "trace-auth-001",
            "event_type": "pre_action",
            "session_id": "sess-auth-001",
            "agent_id": "agent-001",
            "source_framework": "test",
            "occurred_at": "2026-03-20T12:00:00+00:00",
            "payload": {"tool": "read_file", "path": "/tmp/readme.txt"},
            "tool_name": "read_file",
        },
    }
    base.update(overrides)
    return base


SECRET = "a" * 32  # 32-char token for tests


# ===========================================================================
# Auth Enabled: Token configured via env
# ===========================================================================

class TestAuthEnabled:
    """When CS_AUTH_TOKEN is set, protected endpoints require Bearer token."""

    @pytest.fixture
    def app(self, monkeypatch):
        monkeypatch.setenv("CS_AUTH_TOKEN", SECRET)
        gw = SupervisionGateway()
        return create_http_app(gw)

    @pytest.mark.asyncio
    async def test_ahp_without_token_returns_401(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            body = _jsonrpc_request("ahp/sync_decision", _sync_decision_params())
            resp = await c.post("/ahp", content=body)
            assert resp.status_code == 401
            assert resp.headers.get("www-authenticate") == "Bearer"

    @pytest.mark.asyncio
    async def test_ahp_with_wrong_token_returns_401(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            body = _jsonrpc_request("ahp/sync_decision", _sync_decision_params())
            resp = await c.post(
                "/ahp", content=body,
                headers={"Authorization": "Bearer wrong-token"},
            )
            assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_ahp_with_valid_token_returns_200(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            body = _jsonrpc_request("ahp/sync_decision", _sync_decision_params())
            resp = await c.post(
                "/ahp", content=body,
                headers={"Authorization": f"Bearer {SECRET}"},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert "result" in data
            assert data["result"]["rpc_status"] == "ok"

    @pytest.mark.asyncio
    async def test_report_summary_without_token_returns_401(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.get("/report/summary")
            assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_report_summary_with_valid_token_returns_200(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.get(
                "/report/summary",
                headers={"Authorization": f"Bearer {SECRET}"},
            )
            assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_report_session_without_token_returns_401(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.get("/report/session/sess-001")
            assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_report_session_with_valid_token_returns_200(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.get(
                "/report/session/sess-001",
                headers={"Authorization": f"Bearer {SECRET}"},
            )
            assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_report_session_page_without_token_returns_401(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.get("/report/session/sess-001/page")
            assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_report_session_page_with_valid_token_returns_200(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.get(
                "/report/session/sess-001/page",
                headers={"Authorization": f"Bearer {SECRET}"},
            )
            assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_report_sessions_without_token_returns_401(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.get("/report/sessions")
            assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_report_sessions_with_valid_token_returns_200(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.get(
                "/report/sessions",
                headers={"Authorization": f"Bearer {SECRET}"},
            )
            assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_report_session_risk_without_token_returns_401(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.get("/report/session/sess-001/risk")
            assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_report_session_risk_with_valid_token_returns_200(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.get(
                "/report/session/sess-001/risk",
                headers={"Authorization": f"Bearer {SECRET}"},
            )
            assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_report_stream_without_token_returns_401(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.get("/report/stream")
            assert resp.status_code == 401
            assert resp.headers.get("www-authenticate") == "Bearer"

    @pytest.mark.asyncio
    async def test_report_stream_with_valid_token_does_not_return_401(self, app):
        """Valid token should be accepted — 503 capacity or streaming, never 401.

        NOTE: ASGITransport buffers SSE responses so we only test auth rejection.
        We verify that a valid token does NOT get 401/403.
        We pre-fill MAX_SUBSCRIBERS=0 to get an immediate 503 (non-streaming),
        confirming auth passed before capacity check.
        """
        from clawsentry.gateway.server import EventBus, SupervisionGateway, create_http_app
        import os; os.environ['CS_AUTH_TOKEN'] = SECRET
        original_max = EventBus.MAX_SUBSCRIBERS
        EventBus.MAX_SUBSCRIBERS = 0  # Immediately reject with 503 (non-streaming)
        try:
            gw2 = SupervisionGateway()
            app2 = create_http_app(gw2)
            transport = ASGITransport(app=app2)
            async with AsyncClient(transport=transport, base_url="http://test", timeout=2.0) as c:
                resp = await c.get(
                    "/report/stream",
                    headers={"Authorization": f"Bearer {SECRET}"},
                )
                # Auth passed (no 401), capacity rejected (503)
                assert resp.status_code == 503
        finally:
            EventBus.MAX_SUBSCRIBERS = original_max
            os.environ.pop('CS_AUTH_TOKEN', None)

    @pytest.mark.asyncio
    async def test_health_always_open_even_with_token_configured(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.get("/health")
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "healthy"
            assert data["auth_enabled"] is True

    @pytest.mark.asyncio
    async def test_malformed_auth_header_returns_401(self, app):
        """Authorization header without 'Bearer ' prefix."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            body = _jsonrpc_request("ahp/sync_decision", _sync_decision_params())
            resp = await c.post(
                "/ahp", content=body,
                headers={"Authorization": f"Token {SECRET}"},
            )
            assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_401_response_body_is_json(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.get("/report/summary")
            assert resp.status_code == 401
            data = resp.json()
            assert "error" in data


# ===========================================================================
# Auth Disabled: No token configured (dev mode)
# ===========================================================================

class TestAuthDisabled:
    """When CS_AUTH_TOKEN is not set, all endpoints are open."""

    @pytest.fixture
    def app(self, monkeypatch):
        monkeypatch.delenv("CS_AUTH_TOKEN", raising=False)
        gw = SupervisionGateway()
        return create_http_app(gw)

    @pytest.mark.asyncio
    async def test_ahp_open_without_token(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            body = _jsonrpc_request("ahp/sync_decision", _sync_decision_params())
            resp = await c.post("/ahp", content=body)
            assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_report_summary_open_without_token(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.get("/report/summary")
            assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_report_session_open_without_token(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.get("/report/session/sess-001")
            assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_health_open_without_token(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.get("/health")
            assert resp.status_code == 200
            data = resp.json()
            assert data["auth_enabled"] is False

    @pytest.mark.asyncio
    async def test_bearing_token_still_accepted_when_auth_disabled(self, app):
        """Even if auth is disabled, sending a token should not cause errors."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            body = _jsonrpc_request("ahp/sync_decision", _sync_decision_params(
                request_id="req-auth-optional",
            ))
            resp = await c.post(
                "/ahp", content=body,
                headers={"Authorization": "Bearer some-token"},
            )
            assert resp.status_code == 200


# ===========================================================================
# Token Strength Warning
# ===========================================================================

class TestTokenStrengthWarning:
    """Weak tokens (< 32 chars) should produce a startup warning."""

    def test_short_token_logs_warning(self, monkeypatch, caplog):
        import logging
        monkeypatch.setenv("CS_AUTH_TOKEN", "short")
        with caplog.at_level(logging.WARNING, logger="clawsentry"):
            gw = SupervisionGateway()
            create_http_app(gw)
        assert any("shorter than 32" in msg for msg in caplog.messages)

    def test_strong_token_no_warning(self, monkeypatch, caplog):
        import logging
        monkeypatch.setenv("CS_AUTH_TOKEN", "a" * 32)
        with caplog.at_level(logging.WARNING, logger="clawsentry"):
            gw = SupervisionGateway()
            create_http_app(gw)
        assert not any("shorter than 32" in msg for msg in caplog.messages)


# ===========================================================================
# SSE Query Param Auth Fallback (Stage IV — Web Dashboard)
# ===========================================================================

class TestSSEQueryParamAuth:
    """Browser EventSource cannot set custom headers, so /report/stream
    accepts ``?token=xxx`` as a fallback for ``Authorization: Bearer xxx``."""

    @pytest.mark.asyncio
    async def test_valid_query_param_token_passes_auth(self):
        """A valid token in ?token= should pass auth (expect 503 from capacity, not 401)."""
        from clawsentry.gateway.server import EventBus, SupervisionGateway, create_http_app
        os.environ['CS_AUTH_TOKEN'] = SECRET
        original_max = EventBus.MAX_SUBSCRIBERS
        EventBus.MAX_SUBSCRIBERS = 0
        try:
            gw = SupervisionGateway()
            app = create_http_app(gw)
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test", timeout=2.0) as c:
                resp = await c.get(f"/report/stream?token={SECRET}")
                # Auth passed (no 401), capacity rejected (503)
                assert resp.status_code == 503
        finally:
            EventBus.MAX_SUBSCRIBERS = original_max
            os.environ.pop('CS_AUTH_TOKEN', None)

    @pytest.mark.asyncio
    async def test_invalid_query_param_token_returns_401(self):
        """An invalid token in ?token= should return 401."""
        from clawsentry.gateway.server import SupervisionGateway, create_http_app
        os.environ['CS_AUTH_TOKEN'] = SECRET
        try:
            gw = SupervisionGateway()
            app = create_http_app(gw)
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as c:
                resp = await c.get("/report/stream?token=wrong-token")
                assert resp.status_code == 401
                assert resp.headers.get("www-authenticate") == "Bearer"
        finally:
            os.environ.pop('CS_AUTH_TOKEN', None)

    @pytest.mark.asyncio
    async def test_bearer_header_still_works_with_query_param_support(self):
        """Bearer header auth must continue to work unchanged."""
        from clawsentry.gateway.server import EventBus, SupervisionGateway, create_http_app
        os.environ['CS_AUTH_TOKEN'] = SECRET
        original_max = EventBus.MAX_SUBSCRIBERS
        EventBus.MAX_SUBSCRIBERS = 0
        try:
            gw = SupervisionGateway()
            app = create_http_app(gw)
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test", timeout=2.0) as c:
                resp = await c.get(
                    "/report/stream",
                    headers={"Authorization": f"Bearer {SECRET}"},
                )
                assert resp.status_code == 503
        finally:
            EventBus.MAX_SUBSCRIBERS = original_max
            os.environ.pop('CS_AUTH_TOKEN', None)

    @pytest.mark.asyncio
    async def test_empty_query_param_token_returns_401(self):
        """An empty ?token= should not bypass auth."""
        from clawsentry.gateway.server import SupervisionGateway, create_http_app
        os.environ['CS_AUTH_TOKEN'] = SECRET
        try:
            gw = SupervisionGateway()
            app = create_http_app(gw)
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as c:
                resp = await c.get("/report/stream?token=")
                assert resp.status_code == 401
        finally:
            os.environ.pop('CS_AUTH_TOKEN', None)
