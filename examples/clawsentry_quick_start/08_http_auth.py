#!/usr/bin/env python3
"""
08 - HTTP Bearer Token Authentication

展示 HTTP 端点的 Bearer Token 认证机制：

  - /health 始终开放（K8s 探针兼容）
  - /ahp 和 /report/* 受 Bearer Token 保护
  - 未配置 token 时认证禁用（开发友好）
  - 使用 hmac.compare_digest 防时序攻击

运行方式:
    python examples/clawsentry_quick_start/08_http_auth.py
"""

import asyncio
import os
import json
from _helpers import create_gateway, print_section

# 必须在导入 server 模块之前设置环境变量
# （因为 create_http_app 会读取 CS_AUTH_TOKEN）
SECRET_TOKEN = "my-super-secret-token-for-demo-at-least-32-chars"
os.environ["CS_AUTH_TOKEN"] = SECRET_TOKEN

from clawsentry.gateway.server import create_http_app
from clawsentry.gateway.models import RPC_VERSION, CURRENT_SCHEMA_VERSION

# 需要 httpx 来测试 HTTP 端点
try:
    import httpx
except ImportError:
    print("此示例需要 httpx 库，请运行: pip install httpx")
    raise SystemExit(1)

gateway = create_gateway()
app = create_http_app(gateway)


async def main():
    print_section("08 - HTTP Bearer Token 认证")

    # 使用 httpx 的 ASGITransport 进行本地测试（无需真正启动 HTTP 服务器）
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:

        # ── 测试 1: /health 始终开放 ─────────────────────────────
        print("--- 测试 1: /health 始终开放（无需认证）---\n")

        resp = await client.get("/health")
        print(f"  GET /health → {resp.status_code}")
        print(f"  响应: {json.loads(resp.text)['status']}")

        # ── 测试 2: /report/summary 无 token → 401 ──────────────
        print("\n--- 测试 2: /report/summary 无 token → 401 Unauthorized ---\n")

        resp = await client.get("/report/summary")
        print(f"  GET /report/summary (无 token) → {resp.status_code}")
        print(f"  WWW-Authenticate: {resp.headers.get('www-authenticate', 'N/A')}")
        print(f"  响应: {resp.text}")

        # ── 测试 3: /report/summary 错误 token → 401 ────────────
        print("\n--- 测试 3: /report/summary 错误 token → 401 ---\n")

        resp = await client.get(
            "/report/summary",
            headers={"Authorization": "Bearer wrong-token"},
        )
        print(f"  GET /report/summary (错误 token) → {resp.status_code}")

        # ── 测试 4: /report/summary 正确 token → 200 ────────────
        print("\n--- 测试 4: /report/summary 正确 token → 200 OK ---\n")

        resp = await client.get(
            "/report/summary",
            headers={"Authorization": f"Bearer {SECRET_TOKEN}"},
        )
        print(f"  GET /report/summary (正确 token) → {resp.status_code}")
        data = json.loads(resp.text)
        print(f"  total_records: {data.get('total_records', 0)}")

        # ── 测试 5: /ahp 受保护 ─────────────────────────────────
        print("\n--- 测试 5: POST /ahp 需要认证 ---\n")

        jsonrpc_body = json.dumps({
            "jsonrpc": "2.0",
            "method": "ahp/sync_decision",
            "id": "auth-test",
            "params": {
                "rpc_version": RPC_VERSION,
                "request_id": "auth-test",
                "deadline_ms": 5000,
                "decision_tier": "L1",
                "event": {
                    "schema_version": CURRENT_SCHEMA_VERSION,
                    "event_id": "evt-auth-test",
                    "trace_id": "trace-auth-test",
                    "event_type": "pre_action",
                    "session_id": "auth-demo",
                    "agent_id": "agent-auth",
                    "source_framework": "a3s-code",
                    "occurred_at": "2026-03-20T00:00:00+00:00",
                    "payload": {"tool": "read_file", "file_path": "/tmp/test.txt"},
                    "event_subtype": "tool:execute",
                    "tool_name": "read_file",
                },
            },
        })

        # 无 token
        resp_no_auth = await client.post("/ahp", content=jsonrpc_body)
        print(f"  POST /ahp (无 token) → {resp_no_auth.status_code}")

        # 有 token
        resp_auth = await client.post(
            "/ahp",
            content=jsonrpc_body,
            headers={"Authorization": f"Bearer {SECRET_TOKEN}"},
        )
        print(f"  POST /ahp (有 token) → {resp_auth.status_code}")
        result = json.loads(resp_auth.text)
        decision = result.get("result", {}).get("decision", {})
        print(f"  决策: {decision.get('decision', '?')} ({decision.get('risk_level', '?')})")

    print("""
认证配置说明:
  - 设置环境变量 CS_AUTH_TOKEN 启用认证
  - Token 长度建议 >= 32 字符（短于 32 会收到 warning）
  - 未设置 CS_AUTH_TOKEN 时认证完全禁用（开发模式）
  - /health 始终开放，适配 K8s liveness/readiness 探针
  - 使用 hmac.compare_digest 进行时序安全比较

生产环境配置:
  export CS_AUTH_TOKEN="$(openssl rand -hex 32)"
  clawsentry-gateway

客户端请求:
  curl -H "Authorization: Bearer $CS_AUTH_TOKEN" \\
    http://127.0.0.1:8080/report/summary
""")

    # 清理环境变量
    del os.environ["CS_AUTH_TOKEN"]


asyncio.run(main())
