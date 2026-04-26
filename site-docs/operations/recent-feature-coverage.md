---
title: 最近功能文档覆盖矩阵
description: 将近期 ClawSentry 功能映射到源码证据、UI/API/CLI 入口和说明页，避免 changelog archaeology
---

# 最近功能文档覆盖矩阵

本页用于回答一个运维读者最常见的问题：**changelog 里提到的新能力，我应该去哪里理解、配置、验证？**

!!! note "覆盖口径"
    本矩阵只记录已在当前实现中存在的功能与文档入口。可选的 `clawsentry setup` / richer interactive questionnaire 不在本轮 docs-only 范围内；当前配置入口仍以 `clawsentry start`、`clawsentry config wizard`、`config show --effective` 和场景模板为准。

## 覆盖矩阵 {#matrix}

| 功能 / 能力 | 源码或验证证据 | Web UI / API / CLI 入口 | 主要文档 | 状态 |
|-------------|----------------|--------------------------|----------|------|
| L3 advisory full-review / snapshot / job / review | `src/clawsentry/gateway/server.py` 的 `/report/*/l3-advisory/*` 路由；`docs/validation/v0.5.10-webui-l3-ux-release-2026-04-26.md` | Session Detail 的 **Request L3 full review**；`clawsentry l3 full-review`；`POST /report/session/{session_id}/l3-advisory/full-review` | [L3 咨询审查](../decision-layers/l3-advisory.md)、[Reporting API](../api/reporting.md#l3-advisory-endpoints) | covered |
| Bounded L3 job drain | `GET /report/l3-advisory/jobs`、`POST /report/l3-advisory/jobs/run-next`、`POST /report/l3-advisory/jobs/drain`；`docs/validation/l3-advisory-phase3-heartbeat-drain-2026-04-23.md` | `clawsentry l3 jobs list/run-next/drain`；API jobs endpoints | [L3 咨询审查：Phase 3 queued jobs](../decision-layers/l3-advisory.md#phase-3queued-jobs)、[API validity report](../api/validity-report.md) | covered |
| Heartbeat / idle aggregate queueing | `trigger_reason=heartbeat_aggregate` 验证；`docs/validation/l3-advisory-phase3-heartbeat-drain-2026-04-23.md` | Feature gates `CS_L3_ADVISORY_ASYNC_ENABLED=true` + `CS_L3_HEARTBEAT_REVIEW_ENABLED=true`；只冻结/排队，不自动运行 | [L3 咨询审查：heartbeat / idle aggregate queueing](../decision-layers/l3-advisory.md#phase-3heartbeat-idle-aggregate-queueing) | covered |
| L3 advisory natural-language action payload | `docs/validation/v0.5.10-webui-l3-ux-release-2026-04-26.md`；review/action payload 字段 `analysis_summary`、`analysis_points`、`operator_next_steps` | Session Detail 的 Analysis summary / points / next steps；SSE/watch/report action payload | [L3 咨询审查：Web UI](../decision-layers/l3-advisory.md#web-ui) | covered |
| 同步 L3 Agent 触发与可观测字段 | `src/clawsentry/gateway/l3_trigger.py`；`l3_state`、`trigger_reason`、`trigger_detail`、`budget_exhaustion_event` report fields | `clawsentry watch`、Runtime Feed、Session Detail、`/report/session/{id}/risk` | [L3 审查 Agent](../decision-layers/l3-agent.md)、[L2 语义分析](../decision-layers/l2-semantic.md#operator-map) | refreshed |
| Gemini CLI native hooks | `src/clawsentry/adapters/gemini_adapter.py`；`docs/validation/gemini-cli-real-hook-feasibility-2026-04-25.md` | `clawsentry init gemini-cli --setup`；`clawsentry harness --framework gemini-cli`；project `.gemini/settings.json` | [Gemini CLI 集成](../integration/gemini-cli.md)、[首页 Gemini path](../index.md#gemini-cli) | covered |
| Benchmark mode | `clawsentry benchmark env|enable|disable|run`；`docs/validation/v0.5.9-docs-runtime-webui-release-2026-04-26.md` | `CS_MODE=benchmark`；Codex benchmark uses temp `CODEX_HOME` | [Benchmark 模式](benchmark-mode.md)、[配置模板：CI / benchmark](../configuration/templates.md#ci-benchmark-operator) | covered |
| Metric / window fields | `src/clawsentry/gateway/session_registry.py`；`site-docs/api/api-coverage.json`；Dashboard Sessions / Session Detail fields | `/report/sessions`、`/report/session/{id}/risk`、SSE、Dashboard cards | [指标字典](../api/metric-dictionary.md)、[Dashboard](../dashboard/index.md)、[API 概览](../api/overview.md) | lane-2-owned |
| Web UI L3 surfaces | `src/clawsentry/ui/src/pages/SessionDetail.tsx`；`docs/validation/v0.5.10-webui-l3-ux-release-2026-04-26.md` | Runtime Feed、Sessions、Session Detail L3 advisory card/action | [Dashboard](../dashboard/index.md)、[L3 咨询审查](../decision-layers/l3-advisory.md#web-ui) | covered |
| Token budget / LLM usage | `InstrumentedProvider` usage fields；`CS_LLM_TOKEN_BUDGET_*`; v0.5.10 token-first UI notes | LLM drilldown/status, budget SSE event, `config show --effective` | [LLM 配置](../configuration/llm-config.md#sync-vs-advisory-provider)、[环境变量](../configuration/env-vars.md) | refreshed |
| Multi-framework startup | `clawsentry start --framework/--frameworks` readiness summaries; v0.4.x/v0.5.x changelog | `clawsentry integrations status`、`clawsentry start --framework codex` | [快速开始](../getting-started/quickstart.md)、[CLI 命令](../cli/index.md)、各集成页 | lane-1-owned |
| Latch integration | `clawsentry start --with-latch`、`clawsentry latch status/start/install` | Hub UI / Gateway start banner / troubleshooting | [Latch 集成](../integration/latch.md)、[故障排查：Latch](troubleshooting.md) | covered |
| OpenClaw managed setup boundary | `clawsentry init openclaw` 默认项目 `.env.clawsentry`；`--setup` / `--setup-openclaw` explicit opt-in | OpenClaw integration status and webhook/WS paths | [OpenClaw 集成](../integration/openclaw.md)、[CLI 命令](../cli/index.md) | covered |
| Codex managed setup boundary | Managed native hooks and `CODEX_NATIVE_HOOKS doctor` details; smoke evidence under `docs/validation/codex-gateway-daemon-e2e-smoke-2026-04-24.md` | `clawsentry init codex --setup`、`clawsentry doctor`、temporary `CODEX_HOME` for real hook tests | [Codex CLI 集成](../integration/codex.md)、[故障排查：Codex Session Watcher](troubleshooting.md#codex-session-watcher) | covered |

## Docs audit checklist {#audit-checklist}

- [x] L2/L3 pages explicitly distinguish L1 deterministic rules, L2 semantic analysis, synchronous L3 Agent, and L3 advisory full-review.
- [x] L3 advisory docs state latency/budget/runner boundaries, queued-only drain semantics, heartbeat/idle aggregate gates, and `advisory_only=true` / `canonical_decision_mutated=false`.
- [x] LLM config docs separate synchronous L2/L3 provider settings from independent `CS_L3_ADVISORY_PROVIDER_*` gates.
- [x] Recent Gemini CLI, benchmark, Latch, OpenClaw and Codex setup boundaries have primary pages and validation evidence links.
- [x] Metric/window field deep rewrite is intentionally delegated to the metric dictionary lane; this matrix links to that primary reference instead of duplicating field semantics.

## Follow-up watchlist {#follow-up-watchlist}

| Follow-up | Reason | Owner lane |
|-----------|--------|------------|
| Metric dictionary canonical aliases | Needs field-by-field canonical/alias/deprecated reconciliation and API/UI mapping | Metric dictionary lane |
| Quickstart/template path naming | Needs final wording from new-user journey lane after templates are reorganized | Content architecture lane |
| Optional `clawsentry setup` UX | Product behavior does not exist as a rich questionnaire in this docs-only scope | Separate optional CLI lane |
