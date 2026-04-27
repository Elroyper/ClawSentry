---
title: 指标字典
description: ClawSentry 报表、Dashboard、SSE 与 Enterprise OS 风险指标的 canonical 合同
---

# Metric Dictionary（报表 / Dashboard / Enterprise OS）

本文是 ClawSentry 风险展示指标的唯一公开字典。它回答三个问题：字段是什么意思、公式是什么、能不能影响 `allow / block / defer`。

!!! note "默认决策语义不变"
    本页字段属于 report / API / SSE / Dashboard / Enterprise OS 展示合同。除非未来配置显式打开策略消费，这些字段不直接改变 L1/L2/L3 判决。

## 命名原则

- **只对新消费者推荐 canonical 字段**：新 UI、文档和集成代码只读取本文列出的 canonical 字段。
- **窗口指标必须带边界**：窗口聚合必须与 `window_seconds`、`event_count` 和 `generated_at` 一起解释。
- **展示指标不是策略阈值**：`session_risk_sum`、`session_risk_ewma`、`risk_points_sum`、`risk_velocity` 默认只解释趋势和暴露压力。
- **D1-D6 是解释维度**：维度分解释单次风险快照，不是窗口聚合，也不单独代表最终 verdict。

## Canonical 字段速查 {#canonical-fields}

| 字段 | 类型 / 单位 | 公式或来源 | 空值语义 | 决策影响 | 主要位置 |
|---|---|---|---|---|---|
| `latest_composite_score` | float，`>=0` | 窗口内最新 `RiskSnapshot.composite_score`；无窗口时为 session 最新事件分 | 无事件时为 `0.0` 或缺失，consumer 可显示为空状态 | 否 | `/report/sessions`、`/report/session/{id}/risk`、SSE、Dashboard 当前风险 |
| `session_risk_sum` | float，`>=0` | `sum(risk_timeline[*].composite_score)`，四舍五入到 4 位 | 无窗口事件为 `0.0` | 否 | session 风险详情、窗口摘要、Enterprise summary |
| `session_risk_ewma` | float，`>=0` | EWMA，`alpha=0.3`：首个分数作为种子，之后 `0.3 * score + 0.7 * previous` | 无窗口事件为 `0.0` | 否 | Sessions 主展示分、Dashboard 态势、Enterprise session score |
| `risk_points_sum` | int，`>=0` | 风险等级点数求和：`low=0`、`medium=1`、`high=2`、`critical=3` | 无窗口事件为 `0` | 否 | L3 解释、Session Detail 辅助指标、Enterprise audit payload |
| `risk_velocity` | enum | 比较窗口内首尾 composite：差值 `>0.25` 为 `up`，`<-0.25` 为 `down`，否则 `flat`；样本不足为 `unknown` | 少于 2 个样本为 `unknown` | 否 | Sessions row、Session Detail、Dashboard trend labels |
| `high_or_critical_count` | int，`>=0` | 窗口内 `risk_level` 为 `high` 或 `critical` 的事件数 | 无窗口事件为 `0` | 否 | `window_risk_summary`、Dashboard high-risk count |
| `window_risk_summary` | object | 同一窗口内的权威聚合容器，包含本表窗口字段 | 正常返回对象；无事件时计数为 0 | 否 | `/report/session/{id}/risk`、`/report/sessions`、Dashboard cards |
| `system_security_posture` | object | Enterprise/Dashboard 对多个 session 的窗口聚合态势 | 数据源不可用时返回 degraded 对象 | 否 | Enterprise overview、Dashboard 顶层态势、SSE overview refresh |

## 核心字段解释 {#core-fields}

| 字段 | 普通含义 | 计算公式 | 读取建议 |
|---|---|---|---|
| `latest_composite_score` | 最近一次事件的连续风险分，适合解释“刚才发生的这一步有多危险”。 | `risk_timeline[-1].composite_score`。 | 没有 EWMA 时可作为当前风险展示分。不要把它当窗口总量。 |
| `session_risk_sum` | 当前窗口内的风险暴露总量，适合解释“这一段时间累计压力有多大”。 | `round(sum(composite_score), 4)`。 | 用于趋势/容量/审计解释，不直接替代判决阈值。 |
| `session_risk_ewma` | 平滑后的当前 session 态势，减少单个尖峰对 UI 的影响。 | `ewma_0 = score_0`，`ewma_n = 0.3 * score_n + 0.7 * ewma_(n-1)`。 | 新 UI 的首选 session score；缺失时回退 `latest_composite_score`。 |
| `risk_points_sum` | 离散风险等级累计点数，便于解释 high/critical 的压力。 | `sum({"low":0,"medium":1,"high":2,"critical":3}[risk_level])`。 | 适合 L3 evidence summary 和 operator 排查，不是新 verdict。 |
| `risk_velocity` | 风险走势方向。 | `last_score - first_score` 映射为 `up/down/flat/unknown`。 | 只说明方向，不说明绝对风险高低。 |
| `window_risk_summary` | 同一时间窗口的风险事实容器。 | 由窗口内 timeline 聚合出 score、点数、速度和高危计数。 | API consumer 应优先读该对象，再读顶层同名展示字段。 |
| `system_security_posture` | 系统级安全态势快照。 | 由多 session 的 high/critical 分布、风险总量、缓存状态和数据可用性聚合。 | 顶层态势必须显示 degraded/stale，不要把缺数据当 healthy。 |

## `window_risk_summary` 最低字段集 {#window-risk-summary}

| 字段 | 状态 | 说明 |
|---|---|---|
| `window_seconds` | required | 本次聚合窗口；`null` 表示未按时间窗口限制。 |
| `generated_at` | required for report API | 服务端生成该摘要的 UTC 时间。 |
| `event_count` | required | 窗口内事件数。 |
| `high_or_critical_count` | required | 窗口内 high 或 critical 事件数。 |
| `latest_composite_score` | required | 窗口内最新 composite score；无事件为 `0.0`。 |
| `session_risk_sum` | required | 窗口内 composite score 总和。 |
| `session_risk_ewma` | required | 窗口内 EWMA 当前态势值。 |
| `risk_points_sum` | required | 同窗口离散风险点数累计。 |
| `risk_velocity` | required | `up/down/flat/unknown`。 |
| `decision_affecting` | required | 当前为 `false`，提醒 consumer 这些字段默认不改判决。 |

## D1-D6 风险维度 {#d1-d6}

D1-D6 来自最新 `RiskSnapshot.dimensions`，解释单个事件为什么被评为某个风险等级。它们不会像 EWMA 一样跨窗口平滑，也不应被单独当作最终 verdict。

| 维度 | 代码键 | 范围 | 含义 | 高分常见信号 |
|---|---|---:|---|---|
| D1 | `d1` | `0..3` | 工具类别危险度。 | shell、sudo、权限修改、进程控制、网络外联工具。 |
| D2 | `d2` | `0..3` | 目标路径或资源敏感度。 | `.env`、SSH key、token、系统路径、凭证目录。 |
| D3 | `d3` | `0..3` | 命令模式危险度。 | `rm -rf`、远程脚本管道执行、force push、日志清理、反连模式。 |
| D4 | `d4` | `0..2` | 会话上下文累积风险。 | 同一 session 多次中高风险、secret 读取后网络动作、可疑序列。 |
| D5 | `d5` | `0..2` | agent / workspace 信任等级。 | 未知 adapter、低信任 agent、缺少可信身份。 |
| D6 | `d6` | `0.0..3.0` | 注入、越权指令或恶意语义风险。 | jailbreak、ignore-policy 指令、凭证请求、隐藏恶意文本。 |

## API / UI 读取示例 {#examples}

### Session 风险

```bash
curl -H "Authorization: Bearer $CS_AUTH_TOKEN" \
  "http://127.0.0.1:8080/report/session/sess-001/risk?window_seconds=3600"
```

```json
{
  "session_id": "sess-001",
  "current_risk_level": "high",
  "latest_composite_score": 2.4,
  "session_risk_sum": 6.7,
  "session_risk_ewma": 1.9,
  "risk_points_sum": 5,
  "risk_velocity": "up",
  "window_risk_summary": {
    "window_seconds": 3600,
    "generated_at": "2026-03-23T10:31:00+00:00",
    "event_count": 9,
    "high_or_critical_count": 2,
    "latest_composite_score": 2.4,
    "session_risk_sum": 6.7,
    "session_risk_ewma": 1.9,
    "risk_points_sum": 5,
    "risk_velocity": "up",
    "decision_affecting": false
  }
}
```

Recommended UI precedence:

```text
primary_session_score = session_risk_ewma
  ?? latest_composite_score
```

### 系统态势

```json
{
  "system_security_posture": {
    "level": "elevated",
    "score_0_100": 72.5,
    "window_seconds": 3600,
    "generated_at": "2026-04-25T12:00:05Z",
    "decision_affecting": false,
    "drivers": [
      {"key": "high_sessions", "label": "High-risk sessions", "value": 3}
    ]
  }
}
```

## Consumer 迁移建议 {#migration}

| Consumer | 推荐读取 | 备注 |
|---|---|---|
| Sessions list | `session_risk_ewma`、`latest_composite_score`、`risk_velocity`、`high_or_critical_count` | 列表用于扫描和排序；必须显示窗口边界。 |
| Session detail | `window_risk_summary`、`dimensions_latest.d1..d6`、L3 evidence summary | 窗口解释和单事件维度分开展示。 |
| Alerts details | `latest_composite_score`、`risk_points_sum`、触发 reason | 告警文案应解释来源，不把展示分写成策略原因。 |
| Enterprise OS | `system_security_posture` | 必须处理 degraded/stale 状态。 |
| L3 解释 | `risk_points_sum` + D1-D6 + evidence summary | 用于解释，不默认替代 trigger policy。 |

## 默认行为不变清单 {#no-behavior-change}

- 新字段默认只出现在 report/API/SSE/dashboard/enterprise payload，不改变 allow/block/defer。
- `risk_points_sum` 的外显值不自动替换 L3 trigger 内部阈值。
- `risk_velocity` 只描述趋势方向，不是风险等级或策略阈值。
- D4/D6 任何重标定都必须先作为 shadow/default-off 语义说明。
