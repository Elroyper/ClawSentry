---
title: L3 咨询审查
description: L3 advisory snapshots、jobs、reviews、operator full review、CLI/API/UI 使用方式与边界
---

# L3 咨询审查

L3 咨询审查（L3 advisory review）用于在不改写历史判决的前提下，对一个高风险 session 做一次可追溯的安全复盘。它把证据先冻结，再让 operator 明确选择是否排队、是否运行、用哪个 runner 运行。

!!! success "一句话理解"
    L3 咨询审查回答的是：“基于已经记录下来的 bounded evidence，这个 session 还需要 operator 做什么？”它不会把过去的 `allow` / `block` / `defer` 改成别的判决。

---

## 适用场景

使用 L3 咨询审查，当你需要：

- 对一个已经变成 high / critical 的 session 做完整复盘；
- 把某段 trajectory records 固定下来，避免后续事件改变审查输入；
- 让 Web UI / `clawsentry watch` 显示 review、job、snapshot ID 与状态；
- 在真实 provider 调用前，先用 deterministic / fake runner 验证流程；
- 保留审计证据，同时明确 `canonical decision unchanged`。

不适合把它当作：

- 后台自动调度器；
- 新的实时阻断层；
- 对历史判决的重写工具；
- 默认联网的 LLM worker。

---

## 核心对象

| 对象 | 作用 | 关键字段 |
|------|------|----------|
| `l3_evidence_snapshot` | 冻结一个 session 的 bounded trajectory record range | `snapshot_id`, `from_record_id`, `to_record_id`, `trigger_reason`, `risk_summary` |
| `l3_advisory_job` | 记录一次待运行或已运行的咨询审查任务 | `job_id`, `snapshot_id`, `runner`, `job_state` |
| `l3_advisory_review` | 保存咨询审查结果 | `review_id`, `snapshot_id`, `l3_state`, `risk_level`, `recommended_operator_action`, `advisory_only` |

状态集合：

- Job：`queued` / `running` / `completed` / `failed`
- Review：`pending` / `running` / `completed` / `failed` / `degraded`

---

## Operator full review

最常用入口是 operator-triggered full review：

```http
POST /report/session/{session_id}/l3-advisory/full-review
```

请求示例：

```json
{
  "trigger_event_id": "operator-action-id",
  "trigger_detail": "operator_requested_full_review",
  "from_record_id": 1,
  "to_record_id": 42,
  "max_records": 100,
  "max_tool_calls": 0,
  "runner": "deterministic_local",
  "run": true
}
```

响应示例：

```json
{
  "snapshot": {"snapshot_id": "l3snap-..."},
  "job": {"job_id": "l3job-...", "job_state": "completed"},
  "review": {"review_id": "l3adv-...", "l3_state": "completed", "advisory_only": true},
  "advisory_only": true,
  "canonical_decision_mutated": false
}
```

`run=false` 时只冻结证据并排队 job，`review` 为 `null`。

---

## CLI 使用

```bash
# 冻结当前 session 证据，并执行一次 deterministic local review
clawsentry l3 full-review --session sess-001 --token "$CS_AUTH_TOKEN"

# 只排队，不运行 worker
clawsentry l3 full-review --session sess-001 --queue-only --json

# 固定 record 范围
clawsentry l3 full-review \
  --session sess-001 \
  --from-record-id 4 \
  --to-record-id 8 \
  --runner deterministic_local
```

常用参数：

| 参数 | 说明 |
|------|------|
| `--session` | 要审查的 session ID |
| `--from-record-id` / `--to-record-id` | 冻结的 trajectory record 范围 |
| `--max-records` | 最多纳入多少条 record |
| `--runner` | `deterministic_local` / `fake_llm` / `llm_provider` |
| `--queue-only` | 只排队，不执行 worker |
| `--json` | 输出完整 JSON |

---

## Runner 选择

| Runner | 是否联网 | 用途 |
|--------|----------|------|
| `deterministic_local` | 否 | 默认选择；用本地确定性逻辑给出可重复的咨询结果 |
| `fake_llm` | 否 | 验证 worker contract 和 job lifecycle |
| `llm_provider` | 默认否；显式打开后可联网 | 调用 OpenAI / Anthropic provider 的咨询审查路径 |

`llm_provider` 不继承同步 L2/L3 的 `CS_LLM_*` 配置，必须单独设置 `CS_L3_ADVISORY_PROVIDER_*`。默认 `CS_L3_ADVISORY_PROVIDER_DRY_RUN=true`，因此不会误发网络请求。

真实 provider 调用需要显式满足：

```bash
CS_L3_ADVISORY_PROVIDER_ENABLED=true
CS_L3_ADVISORY_PROVIDER=openai        # 或 anthropic
CS_L3_ADVISORY_MODEL=<model>
CS_L3_ADVISORY_PROVIDER_DRY_RUN=false
# 以及 OPENAI_API_KEY / ANTHROPIC_API_KEY 或 CS_L3_ADVISORY_API_KEY
```

---

## Web UI 与 watch 中怎么看

Session Detail 页的 **Request L3 full review** 按钮会触发 full-review，并显示：

- latest `review_id` / `snapshot_id` / `job_id`
- frozen record boundary，例如 `Records 4–8`
- `l3_state`、`job_state`、`runner` 的人类可读标签
- `advisory_only=true`
- `canonical decision unchanged`

`clawsentry watch` 会显示三类 SSE 事件：

```text
L3 ADVISORY SNAPSHOT  l3snap-...  Range=4->8
L3 ADVISORY JOB       l3job-...   State=Completed Runner=Deterministic local
L3 ADVISORY REVIEW    l3adv-...   State=Completed Action=Inspect
```

---

## API 与事件

主要 API：

- `POST /report/session/{id}/l3-advisory/snapshots`
- `POST /report/l3-advisory/reviews`
- `PATCH /report/l3-advisory/review/{review_id}`
- `POST /report/l3-advisory/snapshot/{snapshot_id}/jobs`
- `POST /report/l3-advisory/job/{job_id}/run-local`
- `POST /report/l3-advisory/job/{job_id}/run-worker`
- `POST /report/session/{id}/l3-advisory/full-review`

SSE 事件：

- `l3_advisory_snapshot`
- `l3_advisory_job`
- `l3_advisory_review`

完整字段见 [报表与监控端点](../api/reporting.md#l3-advisory-endpoints)。

---

## 安全边界

- 咨询审查只读 frozen trajectory records；不会直接读取不断变化的 live session state。
- full review 默认不调用真实 LLM provider。
- provider 调用必须显式打开独立 `CS_L3_ADVISORY_PROVIDER_*` 闸门。
- 所有结果都标记为 `advisory_only=true`。
- full-review 响应明确返回 `canonical_decision_mutated=false`。
- 如 provider 配置缺失、未启用、dry-run 未关闭或 provider 不支持，结果会降级为 `l3_state=degraded`，而不是静默联网或伪装成功。
