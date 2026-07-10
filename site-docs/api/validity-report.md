---
title: API 有效性报告
description: ClawSentry API 文档、源码 route、OpenAPI 与示例的可溯源核验结果
---

# API 有效性报告

生成时间：`2026-06-08T11:06:48+00:00`
核验状态：**通过**

本报告从同一份 docs-owned inventory 生成，核对源码 route decorator/registration、Markdown anchor、OpenAPI operation 和端点提及规则。它不修改后端 API 行为，也不会对写入型 API 做盲目 live 调用。

## 摘要

| 指标 | 数值 |
| --- | ---: |
| Coverage entries | 54 |
| OpenAPI operations | 51 |
| Docs endpoint mentions matched | 149 |
| Docs endpoint mentions unmatched | 0 |

## 状态分布

| 状态 | 数量 |
| --- | ---: |
| `enterprise` | 10 |
| `excluded` | 3 |
| `public` | 41 |

## 反向验证规则

- Exact METHOD /path mentions map directly to coverage.
- GET /report/* is treated as a group alias for concrete report routes, not a runtime route.
- Parameter aliases such as {id} are normalized by route-template shape when the method/path is unambiguous.
- GET /ui and GET /ui/{path:path} map to excluded dashboard static routes.
- Duplicate GET /health is service-disambiguated: API pages default to gateway; webhooks.md maps webhook health.

## 端点核验矩阵

| Service | Method | Path | Status | Source line | Markdown | OpenAPI | Runtime check |
| --- | --- | --- | --- | --- | --- | --- | --- |
| gateway | `POST` | `/ahp` | `public` | `src/clawsentry/gateway/http/app.py:230` | yes | yes | `contract-verified` |
| gateway | `POST` | `/ahp/a3s` | `public` | `src/clawsentry/gateway/http/app.py:340` | yes | yes | `contract-verified` |
| gateway | `POST` | `/ahp/codex` | `public` | `src/clawsentry/gateway/http/app.py:375` | yes | yes | `contract-verified` |
| gateway | `POST` | `/ahp/adapter-effect-result` | `public` | `src/clawsentry/gateway/http/app.py:251` | yes | yes | `contract-verified` |
| gateway | `POST` | `/ahp/scope/preview` | `public` | `src/clawsentry/gateway/http/app.py:286` | yes | yes | `contract-verified` |
| stack | `POST` | `/ahp/resolve` | `public` | `src/clawsentry/gateway/runtime/stack.py:206` | yes | yes | `contract-verified` |
| gateway | `GET` | `/health` | `public` | `src/clawsentry/gateway/http/app.py:423` | yes | yes | `contract-verified` |
| gateway | `GET` | `/skill-trust/registry` | `public` | `src/clawsentry/gateway/http/app.py:427` | yes | yes | `contract-verified` |
| gateway | `GET` | `/skill-trust/transition/recommendations` | `public` | `src/clawsentry/gateway/http/app.py:466` | yes | yes | `contract-verified` |
| gateway | `POST` | `/skill-trust/transition` | `public` | `src/clawsentry/gateway/http/app.py:536` | yes | yes | `contract-verified` |
| gateway | `GET` | `/metrics` | `public` | `src/clawsentry/gateway/http/app.py:752` | yes | yes | `contract-verified` |
| gateway | `GET` | `/report/summary` | `public` | `src/clawsentry/gateway/http/app.py:764` | yes | yes | `contract-verified` |
| gateway | `GET` | `/report/policy-drift` | `public` | `src/clawsentry/gateway/http/app.py:785` | yes | yes | `contract-verified` |
| gateway | `GET` | `/report/stream` | `public` | `src/clawsentry/gateway/http/app.py:874` | yes | yes | `contract-verified` |
| gateway | `GET` | `/report/sessions` | `public` | `src/clawsentry/gateway/http/app.py:1016` | yes | yes | `contract-verified` |
| gateway | `GET` | `/report/session/{session_id}/risk` | `public` | `src/clawsentry/gateway/http/app.py:1140` | yes | yes | `contract-verified` |
| gateway | `GET` | `/report/session/{session_id}/post-action` | `public` | `src/clawsentry/gateway/http/app.py:1169` | yes | yes | `contract-verified` |
| gateway | `GET` | `/report/session/{session_id}` | `public` | `src/clawsentry/gateway/http/app.py:1234` | yes | yes | `contract-verified` |
| gateway | `GET` | `/report/session/{session_id}/page` | `public` | `src/clawsentry/gateway/http/app.py:1294` | yes | yes | `contract-verified` |
| gateway | `GET` | `/report/alerts` | `public` | `src/clawsentry/gateway/http/app.py:1370` | yes | yes | `contract-verified` |
| gateway | `POST` | `/report/alerts/{alert_id}/acknowledge` | `public` | `src/clawsentry/gateway/http/app.py:1479` | yes | yes | `contract-verified` |
| gateway | `GET` | `/report/session/{session_id}/enforcement` | `public` | `src/clawsentry/gateway/http/app.py:1503` | yes | yes | `contract-verified` |
| gateway | `POST` | `/report/session/{session_id}/enforcement` | `public` | `src/clawsentry/gateway/http/app.py:1510` | yes | yes | `contract-verified` |
| gateway | `GET` | `/report/session/{session_id}/quarantine` | `public` | `src/clawsentry/gateway/http/app.py:1547` | yes | yes | `contract-verified` |
| gateway | `POST` | `/report/session/{session_id}/quarantine` | `public` | `src/clawsentry/gateway/http/app.py:1557` | yes | yes | `contract-verified` |
| gateway | `GET` | `/ahp/patterns` | `public` | `src/clawsentry/gateway/http/app.py:1602` | yes | yes | `contract-verified` |
| gateway | `POST` | `/ahp/patterns/confirm` | `public` | `src/clawsentry/gateway/http/app.py:1618` | yes | yes | `contract-verified` |
| openclaw-webhook | `POST` | `/webhook/openclaw` | `public` | `src/clawsentry/adapters/openclaw_webhook_receiver.py:45` | yes | yes | `contract-verified` |
| gateway | `POST` | `/report/session/{session_id}/l3-advisory/snapshots` | `public` | `src/clawsentry/gateway/l3/advisory_service.py:737` | yes | yes | `contract-verified` |
| gateway | `GET` | `/report/session/{session_id}/l3-advisory/snapshots` | `public` | `src/clawsentry/gateway/l3/advisory_service.py:777` | yes | yes | `contract-verified` |
| gateway | `GET` | `/report/l3-advisory/snapshot/{snapshot_id}` | `public` | `src/clawsentry/gateway/l3/advisory_service.py:790` | yes | yes | `contract-verified` |
| gateway | `GET` | `/report/l3-advisory/jobs` | `public` | `src/clawsentry/gateway/l3/advisory_service.py:810` | yes | yes | `contract-verified` |
| gateway | `POST` | `/report/l3-advisory/jobs/run-next` | `public` | `src/clawsentry/gateway/l3/advisory_service.py:833` | yes | yes | `contract-verified` |
| gateway | `POST` | `/report/l3-advisory/jobs/drain` | `public` | `src/clawsentry/gateway/l3/advisory_service.py:860` | yes | yes | `contract-verified` |
| gateway | `POST` | `/report/l3-advisory/snapshot/{snapshot_id}/jobs` | `public` | `src/clawsentry/gateway/l3/advisory_service.py:888` | yes | yes | `contract-verified` |
| gateway | `POST` | `/report/l3-advisory/reviews` | `public` | `src/clawsentry/gateway/l3/advisory_service.py:911` | yes | yes | `contract-verified` |
| gateway | `PATCH` | `/report/l3-advisory/review/{review_id}` | `public` | `src/clawsentry/gateway/l3/advisory_service.py:960` | yes | yes | `contract-verified` |
| gateway | `POST` | `/report/l3-advisory/snapshot/{snapshot_id}/run-local-review` | `public` | `src/clawsentry/gateway/l3/advisory_service.py:1017` | yes | yes | `contract-verified` |
| gateway | `POST` | `/report/l3-advisory/job/{job_id}/run-local` | `public` | `src/clawsentry/gateway/l3/advisory_service.py:1036` | yes | yes | `contract-verified` |
| gateway | `POST` | `/report/l3-advisory/job/{job_id}/run-worker` | `public` | `src/clawsentry/gateway/l3/advisory_service.py:1055` | yes | yes | `contract-verified` |
| gateway | `POST` | `/report/session/{session_id}/l3-advisory/full-review` | `public` | `src/clawsentry/gateway/l3/advisory_service.py:1080` | yes | yes | `contract-verified` |
| gateway-enterprise | `GET` | `/enterprise/health` | `enterprise` | `src/clawsentry/gateway/http/app.py:738` | yes | yes | `contract-verified` |
| gateway-enterprise | `GET` | `/enterprise/report/summary` | `enterprise` | `src/clawsentry/gateway/http/app.py:811` | yes | yes | `contract-verified` |
| gateway-enterprise | `GET` | `/enterprise/report/policy-drift` | `enterprise` | `src/clawsentry/gateway/http/app.py:837` | yes | yes | `contract-verified` |
| gateway-enterprise | `GET` | `/enterprise/report/live` | `enterprise` | `src/clawsentry/gateway/http/app.py:863` | yes | yes | `contract-verified` |
| gateway-enterprise | `GET` | `/enterprise/report/stream` | `enterprise` | `src/clawsentry/gateway/http/app.py:945` | yes | yes | `contract-verified` |
| gateway-enterprise | `GET` | `/enterprise/report/sessions` | `enterprise` | `src/clawsentry/gateway/http/app.py:1076` | yes | yes | `contract-verified` |
| gateway-enterprise | `GET` | `/enterprise/report/session/{session_id}/risk` | `enterprise` | `src/clawsentry/gateway/http/app.py:1202` | yes | yes | `contract-verified` |
| gateway-enterprise | `GET` | `/enterprise/report/session/{session_id}` | `enterprise` | `src/clawsentry/gateway/http/app.py:1263` | yes | yes | `contract-verified` |
| gateway-enterprise | `GET` | `/enterprise/report/session/{session_id}/page` | `enterprise` | `src/clawsentry/gateway/http/app.py:1331` | yes | yes | `contract-verified` |
| gateway-enterprise | `GET` | `/enterprise/report/alerts` | `enterprise` | `src/clawsentry/gateway/http/app.py:1423` | yes | yes | `contract-verified` |
| gateway-ui | `GET` | `/ui` | `excluded` | `src/clawsentry/gateway/http/ui_routes.py:27` | yes | yes | `excluded-from-reference` |
| gateway-ui | `GET` | `/ui/{path:path}` | `excluded` | `src/clawsentry/gateway/http/ui_routes.py:16` | yes | yes | `excluded-from-reference` |
| openclaw-webhook | `GET` | `/health` | `excluded` | `src/clawsentry/adapters/openclaw_webhook_receiver.py:41` | yes | yes | `excluded-from-reference` |

## API 维护说明

后端路由拆分后，维护 API 文档时应从 `scripts/docs_api_inventory.py` 的源码扫描结果生成 coverage、OpenAPI 和有效性报告，避免手写源码行号漂移。

## 复跑命令

```bash
python scripts/docs_api_inventory.py validate
python scripts/docs_api_inventory.py report --output-dir .omx/reports --docs-output site-docs/api
```

机器可读副本：[`api-validity.json`](api-validity.json)。
