---
title: API 有效性报告
description: ClawSentry API 文档、源码 route、OpenAPI 与示例的可溯源核验结果
---

# API 有效性报告

生成时间：`2026-04-25T11:14:47+00:00`<br>
核验状态：**通过**

本报告从同一份 docs-owned inventory 生成，核对源码 route decorator/registration、Markdown anchor、OpenAPI operation 和端点提及规则。它不修改后端 API 行为，也不会对写入型 API 做盲目 live 调用。

## 摘要

| 指标 | 数值 |
| --- | ---: |
| Coverage entries | 47 |
| OpenAPI operations | 44 |
| Docs endpoint mentions matched | 119 |
| Docs endpoint mentions unmatched | 0 |

## 状态分布

| 状态 | 数量 |
| --- | ---: |
| `enterprise` | 9 |
| `excluded` | 3 |
| `public` | 35 |

## 反向验证规则

- Exact METHOD /path mentions map directly to coverage.
- GET /report/* is treated as a group alias for concrete report routes, not a runtime route.
- Parameter aliases such as {id} are normalized by route-template shape when the method/path is unambiguous.
- GET /ui and GET /ui/{path:path} map to excluded dashboard static routes.
- Duplicate GET /health is service-disambiguated: API pages default to gateway; webhooks.md maps webhook health.

## 端点核验矩阵

| Service | Method | Path | Status | Source line | Markdown | OpenAPI | Runtime check |
| --- | --- | --- | --- | --- | --- | --- | --- |
| gateway | `POST` | `/ahp` | `public` | `src/clawsentry/gateway/server.py:2981` | yes | yes | `contract-verified` |
| gateway | `POST` | `/ahp/a3s` | `public` | `src/clawsentry/gateway/server.py:3038` | yes | yes | `contract-verified` |
| gateway | `POST` | `/ahp/codex` | `public` | `src/clawsentry/gateway/server.py:3072` | yes | yes | `contract-verified` |
| gateway | `POST` | `/ahp/adapter-effect-result` | `public` | `src/clawsentry/gateway/server.py:3002` | yes | yes | `contract-verified` |
| stack | `POST` | `/ahp/resolve` | `public` | `src/clawsentry/gateway/stack.py:207` | yes | yes | `contract-verified` |
| gateway | `GET` | `/health` | `public` | `src/clawsentry/gateway/server.py:3111` | yes | yes | `contract-verified` |
| gateway | `GET` | `/metrics` | `public` | `src/clawsentry/gateway/server.py:3125` | yes | yes | `contract-verified` |
| gateway | `GET` | `/report/summary` | `public` | `src/clawsentry/gateway/server.py:3137` | yes | yes | `contract-verified` |
| gateway | `GET` | `/report/stream` | `public` | `src/clawsentry/gateway/server.py:3177` | yes | yes | `contract-verified` |
| gateway | `GET` | `/report/sessions` | `public` | `src/clawsentry/gateway/server.py:3291` | yes | yes | `contract-verified` |
| gateway | `GET` | `/report/session/{session_id}/risk` | `public` | `src/clawsentry/gateway/server.py:3384` | yes | yes | `contract-verified` |
| gateway | `GET` | `/report/session/{session_id}` | `public` | `src/clawsentry/gateway/server.py:3807` | yes | yes | `contract-verified` |
| gateway | `GET` | `/report/session/{session_id}/page` | `public` | `src/clawsentry/gateway/server.py:3855` | yes | yes | `contract-verified` |
| gateway | `GET` | `/report/alerts` | `public` | `src/clawsentry/gateway/server.py:3919` | yes | yes | `contract-verified` |
| gateway | `POST` | `/report/alerts/{alert_id}/acknowledge` | `public` | `src/clawsentry/gateway/server.py:4002` | yes | yes | `contract-verified` |
| gateway | `GET` | `/report/session/{session_id}/enforcement` | `public` | `src/clawsentry/gateway/server.py:4026` | yes | yes | `contract-verified` |
| gateway | `POST` | `/report/session/{session_id}/enforcement` | `public` | `src/clawsentry/gateway/server.py:4033` | yes | yes | `contract-verified` |
| gateway | `GET` | `/report/session/{session_id}/quarantine` | `public` | `src/clawsentry/gateway/server.py:4070` | yes | yes | `contract-verified` |
| gateway | `POST` | `/report/session/{session_id}/quarantine` | `public` | `src/clawsentry/gateway/server.py:4080` | yes | yes | `contract-verified` |
| gateway | `GET` | `/ahp/patterns` | `public` | `src/clawsentry/gateway/server.py:4125` | yes | yes | `contract-verified` |
| gateway | `POST` | `/ahp/patterns/confirm` | `public` | `src/clawsentry/gateway/server.py:4139` | yes | yes | `contract-verified` |
| openclaw-webhook | `POST` | `/webhook/openclaw` | `public` | `src/clawsentry/adapters/openclaw_webhook_receiver.py:45` | yes | yes | `contract-verified` |
| gateway | `POST` | `/report/session/{session_id}/l3-advisory/snapshots` | `public` | `src/clawsentry/gateway/server.py:3407` | yes | yes | `contract-verified` |
| gateway | `GET` | `/report/session/{session_id}/l3-advisory/snapshots` | `public` | `src/clawsentry/gateway/server.py:3447` | yes | yes | `contract-verified` |
| gateway | `GET` | `/report/l3-advisory/snapshot/{snapshot_id}` | `public` | `src/clawsentry/gateway/server.py:3460` | yes | yes | `contract-verified` |
| gateway | `GET` | `/report/l3-advisory/jobs` | `public` | `src/clawsentry/gateway/server.py:3480` | yes | yes | `contract-verified` |
| gateway | `POST` | `/report/l3-advisory/jobs/run-next` | `public` | `src/clawsentry/gateway/server.py:3503` | yes | yes | `contract-verified` |
| gateway | `POST` | `/report/l3-advisory/jobs/drain` | `public` | `src/clawsentry/gateway/server.py:3530` | yes | yes | `contract-verified` |
| gateway | `POST` | `/report/l3-advisory/snapshot/{snapshot_id}/jobs` | `public` | `src/clawsentry/gateway/server.py:3558` | yes | yes | `contract-verified` |
| gateway | `POST` | `/report/l3-advisory/reviews` | `public` | `src/clawsentry/gateway/server.py:3581` | yes | yes | `contract-verified` |
| gateway | `PATCH` | `/report/l3-advisory/review/{review_id}` | `public` | `src/clawsentry/gateway/server.py:3625` | yes | yes | `contract-verified` |
| gateway | `POST` | `/report/l3-advisory/snapshot/{snapshot_id}/run-local-review` | `public` | `src/clawsentry/gateway/server.py:3677` | yes | yes | `contract-verified` |
| gateway | `POST` | `/report/l3-advisory/job/{job_id}/run-local` | `public` | `src/clawsentry/gateway/server.py:3696` | yes | yes | `contract-verified` |
| gateway | `POST` | `/report/l3-advisory/job/{job_id}/run-worker` | `public` | `src/clawsentry/gateway/server.py:3715` | yes | yes | `contract-verified` |
| gateway | `POST` | `/report/session/{session_id}/l3-advisory/full-review` | `public` | `src/clawsentry/gateway/server.py:3738` | yes | yes | `contract-verified` |
| gateway-enterprise | `GET` | `/enterprise/health` | `enterprise` | `src/clawsentry/gateway/server.py:3115` | yes | yes | `contract-verified` |
| gateway-enterprise | `GET` | `/enterprise/report/summary` | `enterprise` | `src/clawsentry/gateway/server.py:3150` | yes | yes | `contract-verified` |
| gateway-enterprise | `GET` | `/enterprise/report/live` | `enterprise` | `src/clawsentry/gateway/server.py:3170` | yes | yes | `contract-verified` |
| gateway-enterprise | `GET` | `/enterprise/report/stream` | `enterprise` | `src/clawsentry/gateway/server.py:3235` | yes | yes | `contract-verified` |
| gateway-enterprise | `GET` | `/enterprise/report/sessions` | `enterprise` | `src/clawsentry/gateway/server.py:3336` | yes | yes | `contract-verified` |
| gateway-enterprise | `GET` | `/enterprise/report/session/{session_id}/risk` | `enterprise` | `src/clawsentry/gateway/server.py:3781` | yes | yes | `contract-verified` |
| gateway-enterprise | `GET` | `/enterprise/report/session/{session_id}` | `enterprise` | `src/clawsentry/gateway/server.py:3830` | yes | yes | `contract-verified` |
| gateway-enterprise | `GET` | `/enterprise/report/session/{session_id}/page` | `enterprise` | `src/clawsentry/gateway/server.py:3886` | yes | yes | `contract-verified` |
| gateway-enterprise | `GET` | `/enterprise/report/alerts` | `enterprise` | `src/clawsentry/gateway/server.py:3959` | yes | yes | `contract-verified` |
| gateway-ui | `GET` | `/ui` | `excluded` | `src/clawsentry/gateway/server.py:4206` | yes | yes | `excluded-from-reference` |
| gateway-ui | `GET` | `/ui/{path:path}` | `excluded` | `src/clawsentry/gateway/server.py:4195` | yes | yes | `excluded-from-reference` |
| openclaw-webhook | `GET` | `/health` | `excluded` | `src/clawsentry/adapters/openclaw_webhook_receiver.py:41` | yes | yes | `excluded-from-reference` |

## 复跑命令

```bash
python scripts/docs_api_inventory.py validate
python scripts/docs_api_inventory.py report --output-dir .omx/reports --docs-output site-docs/api
```

机器可读副本：[`api-validity.json`](api-validity.json)。
