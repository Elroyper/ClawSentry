# Metric Dictionary（报表 / Dashboard / Enterprise OS）

本文冻结 ClawSentry 报表、SSE、Web UI 与企业 OS 交接中使用的风险指标名称。目标是让新增健康分字段可以并行发布，同时保持默认决策语义不变：`cumulative_score` 继续作为 legacy 兼容字段存在，新字段默认用于展示、观测与灰度校验，不直接改变 L1/L2/L3 判决。

## 命名原则

- **不复用 legacy 字段表达新语义**：`cumulative_score` 不是窗口累计分，不应被当作系统健康分输入的唯一来源。
- **窗口字段显式带 window 语义**：窗口聚合字段必须声明 `window_seconds`、窗口内事件数与窗口边界。
- **默认不影响决策**：除非配置明确开启，新字段仅进入 report/API/SSE/dashboard/enterprise payload，不改变 allow/block/defer/L3 触发结果。
- **D4 标准化保持 shadow/default-off**：D4 归一化或重标定只能作为旁路观测值发布，默认不得替换当前维度分或阈值。

## 核心指标表

| 字段 | 单位 / 类型 | 范围 | 数据来源 | 窗口语义 | 可空性 | Legacy | 默认影响决策 | Consumer surfaces | 示例 |
|------|-------------|------|----------|----------|--------|--------|--------------|-------------------|------|
| `cumulative_score` | number（当前实现为 `int`） | `>=0`；当前常见值为最近一次 `int(composite_score)` | `session_registry` 会话摘要；由最新 risk snapshot 覆盖 | **无窗口重算**；即使请求带 `window_seconds`，该字段仍是会话存量兼容值 | 非空；无会话时为 `0` | 是 | 否；仅兼容展示 / alert details | `/report/sessions`、`/report/session/{id}/risk`、alerts details、旧 Web UI | `"cumulative_score": 2` |
| `latest_composite_score` | number（float） | `>=0`；默认权重下通常 `0..3`，自定义权重可能更高 | 最新 risk snapshot 的原始 `composite_score` | 最新事件点值；不代表窗口累计 | 有事件后非空；无事件或降级时可为 `null` | 否 | 否 | reporting API、SSE risk/session events、Dashboard 当前风险读数、Enterprise OS snapshot | `"latest_composite_score": 1.73` |
| `session_risk_sum` | number（float） | `>=0` | 窗口内 `composite_score` / `latest_composite_score` 明细求和 | 按请求或默认窗口计算；必须与 `window_seconds` 同步返回 | 非空；无窗口事件为 `0.0` | 否 | 否（触发策略若未来使用需显式配置） | session risk API、Dashboard 趋势、Enterprise OS health handoff | `"session_risk_sum": 6.42` |
| `session_risk_ewma` | number（float） | `>=0`；通常落在近期 composite score 区间附近 | 窗口内 composite score 的 EWMA；推荐默认 `alpha=0.3` | 窗口内按时间顺序计算；窗口外历史不应隐式混入，除非 payload 声明 seed | 无事件时可为 `null`；Dashboard 展示应回退到 `latest_composite_score` | 否 | 否 | Dashboard 主展示风险分、Enterprise OS preferred session score、reporting API | `"session_risk_ewma": 1.28` |
| `risk_points_sum` | number（int） | `>=0` | 风险等级映射求和：`low=0`、`medium=1`、`high=2`、`critical=3` | 窗口内累计；用于解释“风险点数”而不是 composite score | 非空；无窗口事件为 `0` | 否 | 暴露字段否；现有 L3 内部阈值仍按独立逻辑工作 | L3 解释、Dashboard 辅助指标、Enterprise OS audit payload | `"risk_points_sum": 7` |
| `window_risk_summary` | object | 对象字段各自 `>=0` 或枚举 | 同一窗口内的 session timeline / registry 聚合 | 该对象是窗口聚合的权威容器，必须包含 `window_seconds` 与事件计数 | 非空；无事件时返回空计数对象 | 否 | 否 | `/report/session/{id}/risk`、`/report/sessions` 可选摘要、Dashboard cards、Enterprise OS cache | `{ "window_seconds": 3600, "event_count": 12, "high_risk_event_count": 3 }` |
| `system_security_posture` | object | posture 枚举：`healthy` / `watch` / `elevated` / `critical` / `degraded` | Enterprise overview/cache 聚合多个 session 的窗口摘要 | 系统级窗口快照；必须声明生成时间、窗口、缓存状态 | 正常非空；数据源不可用时返回 `posture: "degraded"` 与 `reason` | 否 | 否；企业 OS 默认展示/告警摘要，不改 gateway 判决 | Enterprise OS overview、Dashboard top-level posture、SSE overview refresh | `{ "posture": "elevated", "stale": false, "window_seconds": 3600 }` |

## 推荐 payload 结构

### Session risk / Dashboard 片段

```json
{
  "session_id": "session-001",
  "current_risk_level": "high",
  "cumulative_score": 2,
  "latest_composite_score": 2.4,
  "session_risk_sum": 6.7,
  "session_risk_ewma": 1.9,
  "risk_points_sum": 5,
  "window_risk_summary": {
    "window_seconds": 3600,
    "event_count": 9,
    "high_risk_event_count": 2,
    "critical_event_count": 1,
    "decision_distribution": {
      "allow": 6,
      "defer": 1,
      "block": 2
    },
    "latest_event_at": "2026-04-25T12:00:00Z"
  }
}
```

### Enterprise OS overview 片段

```json
{
  "system_security_posture": {
    "posture": "elevated",
    "score": 72.5,
    "window_seconds": 3600,
    "generated_at": "2026-04-25T12:00:05Z",
    "source": "clawsentry.enterprise.overview",
    "cache": {
      "state": "fresh",
      "ttl_seconds": 10,
      "age_seconds": 2.1,
      "stale": false,
      "degraded": false
    },
    "summary": {
      "tracked_sessions": 18,
      "high_risk_sessions": 3,
      "critical_sessions": 1,
      "session_risk_sum": 24.8,
      "risk_points_sum": 17
    }
  }
}
```

## 字段边界说明

### `cumulative_score` 与新累计字段

`cumulative_score` 是兼容字段，历史消费者可能仍读取它。因此它必须继续返回数字，但文档、UI 与企业 OS 不应再把它称为“窗口累计分”。新文档与新 UI 应优先使用：

1. `latest_composite_score` 表示当前/最近事件分。
2. `session_risk_sum` 表示窗口内 composite 暴露总量。
3. `session_risk_ewma` 表示更稳定的当前态势。
4. `risk_points_sum` 表示 risk level 离散点数累计，用于解释 L3 风险压力。

### `window_risk_summary` 的最低字段集

`window_risk_summary` 至少应包含：

| 字段 | 说明 |
|------|------|
| `window_seconds` | 本次聚合窗口；`null` 表示未按时间窗口限制 |
| `event_count` | 窗口内事件数 |
| `high_risk_event_count` | 窗口内 `high` 或 `critical` 事件数 |
| `critical_event_count` | 窗口内 `critical` 事件数 |
| `decision_distribution` | 窗口内 allow/block/defer 等判决分布 |
| `latest_event_at` | 窗口内最新事件时间；无事件时可为 `null` |
| `session_risk_sum` | 同窗口 composite 累计值 |
| `session_risk_ewma` | 同窗口 EWMA 当前态势值 |
| `risk_points_sum` | 同窗口离散风险点数累计 |

### `system_security_posture` 的降级语义

企业 OS 读取 overview 时应优先使用 `system_security_posture`。当底层 session registry、缓存或上游数据不可用时，仍返回对象而不是缺字段：

```json
{
  "system_security_posture": {
    "posture": "degraded",
    "score": null,
    "window_seconds": 3600,
    "generated_at": "2026-04-25T12:00:05Z",
    "reason": "session_registry_unavailable",
    "cache": {
      "state": "degraded",
      "stale": true,
      "degraded": true
    }
  }
}
```

## Consumer 迁移建议

| Consumer | 当前兼容读取 | 新推荐读取 | 备注 |
|----------|--------------|------------|------|
| 旧 Dashboard session row | `cumulative_score` | `session_risk_ewma`，回退 `latest_composite_score`，最后回退 `cumulative_score` | 避免把 legacy int 当 0-1 进度条 |
| Session detail | `cumulative_score` + `risk_timeline[].composite_score` | `window_risk_summary` + `latest_composite_score` | 窗口视图以 summary 为准 |
| Alerts details | `details.cumulative_score` | `details.latest_composite_score` / `details.risk_points_sum` | 兼容字段可保留，但新告警解释应带新字段 |
| Enterprise OS | 无统一字段 | `system_security_posture` | 必须处理 `stale/degraded` |
| L3 解释 | 内部 risk point threshold | `risk_points_sum` | 暴露值用于解释，不默认替代触发逻辑 |

## 默认行为不变清单

- `cumulative_score` 不改名、不删除、不改变旧消费者的默认读取路径。
- 新字段默认只出现在 report/API/SSE/dashboard/enterprise payload，不改变 allow/block/defer 结果。
- `risk_points_sum` 的外显值不自动替换 L3 trigger 内部阈值计算。
- D4 normalization / D4 shadow metrics 默认不参与 `dimensions_latest.d4` 或判决阈值。
