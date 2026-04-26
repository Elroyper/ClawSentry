---
title: Docs coverage audit
description: Source-backed coverage matrix for recent ClawSentry online documentation features
---

# Docs coverage audit（2026-04-27）

本页是在线文档优化的 source-backed audit log。它不是产品功能说明页，而是用来回答：**最近实现的能力是否已经在公开文档里有入口、术语是否一致、哪些页面只是验证未改、哪些仍需后续处理**。

<div class="cs-pill-row" markdown>
<span class="cs-pill">docs-only</span>
<span class="cs-pill">source-backed</span>
<span class="cs-pill">no CLI setup UX change</span>
<span class="cs-pill">mkdocs strict required</span>
</div>

## 审计结论 {#audit-summary}

- Quickstart 和 templates 现在明确区分 **观察优先 / L1-only** 与 **L2/L3-ready operator path**，避免把 no-LLM 路径描述成所有用户的默认终点。
- Metric Dictionary 增加 canonical / alias / legacy 对照，覆盖 `session_risk_sum`、`composite_score_sum`、`high_or_critical_count`、`high_risk_event_count`、`risk_velocity` 和 D1-D6。
- L2/L3 页面补充 operator 合同和同步判决 vs advisory-only full-review 的边界。
- L3 Advisory 页面移除页面内样式岛，改用共享 `.cs-*` 组件。
- 本次不实现 `clawsentry setup` 或交互式 CLI onboarding；文档只说明现有 `clawsentry config wizard` 的确定性边界。

## Recent-feature coverage matrix {#recent-feature-coverage-matrix}

| Feature / capability | Source evidence | Public docs surface | Web UI / API / CLI surface | Status | Planned action |
|---|---|---|---|---|---|
| L3 advisory jobs / full-review | `src/clawsentry/gateway/server.py` full-review route; `src/clawsentry/cli/l3_command.py`; `src/clawsentry/tests/test_l3_command.py` | [L3 咨询审查](../decision-layers/l3-advisory.md), [Reporting API](../api/reporting.md), [CLI](../cli/index.md) | Session Detail full-review controls; `POST /report/session/{id}/l3-advisory/full-review`; `clawsentry l3 full-review` | Covered | Keep advisory-only wording and `canonical_decision_mutated=false` examples in sync with API contract tests. |
| Heartbeat / idle aggregate queueing | `src/clawsentry/gateway/server.py` `heartbeat_aggregate`; `src/clawsentry/tests/test_gateway.py` heartbeat aggregate cases | [L3 咨询审查](../decision-layers/l3-advisory.md), [Reporting API](../api/reporting.md) | SSE advisory snapshot/job events; `clawsentry l3 jobs list/run-next/drain` | Covered | Continue to emphasize no scheduler/daemon and bounded one-shot drain behavior. |
| Gemini CLI hooks | `src/clawsentry/adapters/gemini_adapter.py`; integration tests and CLI init paths | [Gemini CLI 集成](../integration/gemini-cli.md), [Quickstart](../getting-started/quickstart.md) | Framework startup / hook adapter | Covered | Verify hook boundary language during each release. |
| Benchmark mode | `src/clawsentry/cli/benchmark_command.py`; benchmark docs/tests | [Benchmark 模式](benchmark-mode.md), [Quickstart](../getting-started/quickstart.md), [Templates](../configuration/templates.md) | `clawsentry benchmark env/enable/run/disable` | Covered | Keep temporary `CODEX_HOME` warning visible for Codex benchmark examples. |
| Metric/window fields | `src/clawsentry/gateway/session_registry.py` metrics; `src/clawsentry/gateway/server.py` reporting aliases; `src/clawsentry/ui/src/api/types.ts` | [Metric Dictionary](../api/metric-dictionary.md), [Dashboard](../dashboard/index.md), [Reporting API](../api/reporting.md) | `/report/sessions`, `/report/session/{id}/risk`, Sessions row, Session Detail cards | Covered in this pass | Prefer `window_risk_summary` + canonical names; document aliases for legacy payloads. |
| Web UI L3 surfaces | `src/clawsentry/ui/src/pages/SessionDetail.tsx`; `src/clawsentry/ui/src/components/RuntimeFeed.tsx` | [L3 咨询审查](../decision-layers/l3-advisory.md), [Dashboard](../dashboard/index.md) | Session Detail full-review button, L3 advisory review card, Runtime Feed | Covered | Future screenshots can be added when visual smoke tooling is available. |
| Token budget / LLM usage | `src/clawsentry/cli/test_llm_command.py`; config/env docs; metrics token counters | [LLM 配置](../configuration/llm-config.md), [Templates](../configuration/templates.md), [Reporting API](../api/reporting.md) | `clawsentry test-llm --json`, Prometheus `clawsentry_llm_tokens_total` | Covered | Keep examples provider-neutral and budget-first. |
| Multi-framework startup | `src/clawsentry/cli/start_command.py`; adapter packages | [Quickstart](../getting-started/quickstart.md), integration pages | `clawsentry start --framework ...` | Covered | Framework table should stay honest about Codex monitoring vs optional managed hooks. |
| Latch integration | `src/clawsentry/latch/*`; docs integration page | [Latch 集成](../integration/latch.md), homepage Latch callout | Latch daemon / bridge surfaces | Covered | No changes needed in this pass beyond nav verification. |
| OpenClaw / Codex managed setup boundaries | `src/clawsentry/adapters/openclaw_*`; `src/clawsentry/adapters/codex_adapter.py`; Codex init tests | [OpenClaw 集成](../integration/openclaw.md), [Codex CLI 集成](../integration/codex.md), [Quickstart](../getting-started/quickstart.md) | `clawsentry init codex --setup`, OpenClaw webhook/WebSocket | Covered | Keep Codex text clear: default monitoring + optional Bash preflight/native hook enhancement. |
| Deterministic config wizard | `src/clawsentry/cli/config_command.py` fallback message and config write path; CLI parser flags | [Quickstart](../getting-started/quickstart.md), [Templates](../configuration/templates.md), [CLI](../cli/index.md) | `clawsentry config wizard --non-interactive ...` | Covered in this pass | Do not advertise `clawsentry setup` until a separate CLI lane lands with tests. |

## Pages touched / verified {#pages-touched-verified}

| Page | Action | Source evidence used | Notes |
|------|--------|----------------------|-------|
| `getting-started/quickstart.md` | Refresh | CLI `config wizard`, framework startup and Codex managed-hook boundaries | Added two-path journey and deterministic wizard note. |
| `configuration/templates.md` | Refresh | Config schema expectations, L2/L3 budget/timeout fields | Added template chooser by latency/budget/strictness. |
| `api/metric-dictionary.md` | Rewrite section | `session_registry.py`, `server.py`, UI `types.ts`, Session Detail/Sessions fields | Added canonical/alias table, field explainers, D1-D6 table, UI/API read path. |
| `decision-layers/l2-semantic.md` | Refresh | `SemanticAnalyzer` behavior and L3 advisory boundary | Added operator path clarifying L2 vs L3. |
| `decision-layers/l3-agent.md` | Refresh | L3 trigger/runtime telemetry and advisory docs | Added operator contract and L1/L2/L3/Advisory contrast. |
| `decision-layers/l3-advisory.md` | Style conversion | Existing content + shared CSS contract | Removed local CSS; reused `.cs-doc-hero`, `.cs-card-grid`, `.cs-pill`, `.cs-flow-strip`. |
| `stylesheets/clawsentry-docs.css` | Style contract | Existing docs components and Material theme constraints | Added component contract plus shared operator/flow/pill/API classes. |
| `mkdocs.yml` | Nav refresh | Existing operations nav | Added this audit page so matrix is not orphaned. |

## Verified unchanged / linked surfaces {#verified-unchanged}

| Surface | Why unchanged | Verification target |
|---------|---------------|---------------------|
| `api/reporting.md` | Already documents full-review, jobs, SSE and `analysis_summary` fields. | `mkdocs build --strict`; public docs contract tests. |
| `dashboard/index.md` | Already explains Dashboard / Sessions / Session Detail hierarchy and metric fallback ordering. | Link from Metric Dictionary and Quickstart. |
| `integration/codex.md` | Already distinguishes monitoring from optional managed native hooks. | Public docs contract checks `clawsentry init codex --setup`, `PreToolUse(Bash)`. |
| `integration/gemini-cli.md` | Recent-feature entry exists in nav and integration section. | Nav path exists and build includes page. |
| `operations/benchmark-mode.md` | Dedicated benchmark path exists and is linked from Quickstart/Templates. | Build and link sanity. |

## Follow-up candidates {#follow-up-candidates}

These are intentionally not part of this docs-only pass:

1. **Optional CLI setup UX:** add a real `clawsentry setup` / interactive guide only after a separate PRD/test spec. Current docs must continue calling `config wizard` deterministic.
2. **Rendered visual screenshots:** capture light/dark screenshots for Quickstart, Templates, Metric Dictionary and L3 pages when browser tooling is available in CI or release validation.
3. **Generated API excerpt sync:** if OpenAPI generation changes response schemas, rerun `python scripts/docs_api_inventory.py validate` and refresh `api/reference.md` / `api/validity-report.md`.
4. **Bilingual polish pass:** this site uses Chinese navigation with English field names. Future copyediting can normalize operator terminology without changing API names.
