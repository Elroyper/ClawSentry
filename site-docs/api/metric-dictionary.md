---
title: 指标字典
description: ClawSentry 报表、Dashboard、SSE 与 Enterprise OS 风险指标的 canonical / alias / legacy 说明
---

# Metric Dictionary（报表 / Dashboard / Enterprise OS）

本文冻结 ClawSentry 报表、SSE、Web UI 与企业 OS 交接中使用的风险指标名称。目标是让 operator、API consumer 和 Dashboard reader 不需要读源码也能判断：字段是什么意思、从哪里计算、在哪里展示、能不能影响 `allow / block / defer`。

!!! note "默认决策语义不变"
    本页字段属于 report / API / SSE / Dashboard / Enterprise OS 展示合同。除非未来配置明确打开策略消费，这些指标**不直接改变** L1/L2/L3 的 allow/block/defer 判决；`cumulative_score` 继续作为 legacy 兼容字段存在。

## 命名原则

- **Canonical 优先**：新文档、新 UI 和 Enterprise OS 集成优先读取 canonical 字段；alias 只用于兼容已有 payload。
- **窗口字段必须带窗口边界**：窗口聚合必须和 `window_seconds`、事件计数、生成时间或窗口来源一起解释。
- **Legacy 不承载新语义**：`cumulative_score` 不是窗口累计分，也不是系统健康分；它只是旧消费者仍可读取的会话兼容值。
- **展示字段不等于策略阈值**：`session_risk_sum`、`session_risk_ewma`、`risk_points_sum`、`risk_velocity` 默认只解释趋势和暴露压力。
- **D1-D6 保持源模型边界**：D1-D5 是整数维度，D6 是注入检测浮点维度；D4/D6 的任何重标定都必须作为 shadow/default-off 语义说明。

## Canonical / alias / legacy 对照 {#canonical-alias-legacy}

先读这一张表，再读下面的字段说明。它解释同一个概念在源码、API、Web UI 与 legacy payload 中的名字如何对应。

| 概念 | Canonical / 推荐读取 | 兼容 alias / legacy | 来源与当前边界 | Web UI / API 位置 | 迁移建议 |
|------|----------------------|---------------------|----------------|-------------------|----------|
| 最近一次 composite 分 | `latest_composite_score` | `cumulative_score` 可作为最后 fallback | `session_registry._session_metrics()` 使用最新 timeline score；`cumulative_score` 是旧整数展示字段 | Sessions 风险读数、Session Detail current score、`/report/sessions`、`/report/session/{id}/risk` | 新 UI 优先 `latest_composite_score`，仅无新字段时回退 legacy |
| 窗口 composite 累计 | `session_risk_sum` | `composite_score_sum` | registry 内部窗口摘要会产出 `composite_score_sum`；reporting API 对外规范使用 `session_risk_sum` | Window summary、Enterprise handoff、Session Detail 趋势块 | 新消费者读取 `session_risk_sum`，遇到历史 payload 再读 `composite_score_sum` |
| 窗口平滑态势 | `session_risk_ewma` | 无 | 按窗口内 score 顺序计算 EWMA；无事件可为 `null` | Sessions row、Dashboard posture、`window_risk_summary` | 适合作为“当前会话态势”主展示，不是累计值 |
| 离散风险点 | `risk_points_sum` | 无 | `low=0`、`medium=1`、`high=2`、`critical=3` 的窗口求和 | L3 解释、Session Detail 辅助指标、Enterprise OS | 用于解释风险压力；不要直接替代 L3 触发阈值 |
| 风险速度 | `risk_velocity` | 无 | 由窗口内 score 变化映射为 `up` / `down` / `flat` / `unknown` | Sessions row、Session Detail metric card、Dashboard summaries | 与 EWMA 一起解释趋势，不能单独代表绝对风险 |
| 高危事件数 | `high_or_critical_count` | `high_risk_event_count` | registry/API/UI 同时兼容；UI 常用 `high_or_critical_count ?? high_risk_event_count` | Dashboard high-risk cards、Session Detail high-risk count | 新窗口对象优先 `high_or_critical_count`；旧会话摘要仍保留 `high_risk_event_count` |
| 窗口容器 | `window_risk_summary` | flat session fields | 包含窗口秒数、事件数、score 汇总与分布；flat 字段用于旧消费者 | `/report/session/{id}/risk`、`/report/sessions` | 新消费者优先读取对象，flat 字段仅作兼容 |
| 维度分 | `dimensions_latest.d1`…`d6` | `D1`…`D6` 文档标签 | `RiskDimensions` 模型中的六个 explainable dimensions | Session Detail risk dimensions、report payload | 面向 operator 显示可用 D1-D6 标签，API 里保持小写键 |

## Canonical / alias / deprecated 对照表

| 字段 | 单位 / 类型 | 范围 | 数据来源 | 窗口语义 | 可空性 | Legacy | 默认影响决策 | Consumer surfaces | 示例 |
|------|-------------|------|----------|----------|--------|--------|--------------|-------------------|------|
| `cumulative_score` | number（当前实现为 `int`） | `>=0`；当前常见值为最近一次 `int(composite_score)` | `session_registry` 会话摘要；由最新 risk snapshot 覆盖 | **无窗口重算**；即使请求带 `window_seconds`，该字段仍是会话存量兼容值 | 非空；无会话时为 `0` | 是 | 否；仅兼容展示 / alert details | `/report/sessions`、`/report/session/{id}/risk`、alerts details、旧 Web UI | `"cumulative_score": 2` |
| `latest_composite_score` | number（float） | `>=0`；默认权重下通常 `0..3`，自定义权重可能更高 | 最新 risk snapshot 的原始 `composite_score` | 最新事件点值；不代表窗口累计 | 有事件后非空；无事件或降级时可为 `null` | 否 | 否 | reporting API、SSE risk/session events、Dashboard 当前风险读数、Enterprise OS snapshot | `"latest_composite_score": 1.73` |
| `session_risk_sum` | number（float） | `>=0` | 窗口内 `composite_score` / `latest_composite_score` 明细求和 | 按请求或默认窗口计算；必须与 `window_seconds` 同步返回 | 非空；无窗口事件为 `0.0` | 否 | 否（触发策略若未来使用需显式配置） | session risk API、Dashboard 趋势、Enterprise OS health handoff | `"session_risk_sum": 6.42` |
| `session_risk_ewma` | number（float） | `>=0`；通常落在近期 composite score 区间附近 | 窗口内 composite score 的 EWMA；推荐默认 `alpha=0.3` | 窗口内按时间顺序计算；窗口外历史不应隐式混入，除非 payload 声明 seed | 无事件时可为 `null`；Dashboard 展示应回退到 `latest_composite_score` | 否 | 否 | Dashboard 主展示风险分、Enterprise OS preferred session score、reporting API | `"session_risk_ewma": 1.28` |
| `risk_velocity` | enum/string | `up` / `down` / `flat` / `unknown` | 窗口内 score 序列的方向判断 | 与同一 `window_seconds` 同步解释 | 无足够样本时为 `unknown` | 否 | 否 | Sessions row、Session Detail、Dashboard trend labels | `"risk_velocity": "up"` |
| `risk_points_sum` | number（int） | `>=0` | 风险等级映射求和：`low=0`、`medium=1`、`high=2`、`critical=3` | 窗口内累计；用于解释“风险点数”而不是 composite score | 非空；无窗口事件为 `0` | 否 | 暴露字段否；现有 L3 内部阈值仍按独立逻辑工作 | L3 解释、Dashboard 辅助指标、Enterprise OS audit payload | `"risk_points_sum": 7` |
| `window_risk_summary` | object | 对象字段各自 `>=0` 或枚举 | 同一窗口内的 session timeline / registry 聚合 | 该对象是窗口聚合的权威容器，必须包含 `window_seconds` 与事件计数 | 非空；无事件时返回空计数对象 | 否 | 否 | `/report/session/{id}/risk`、`/report/sessions` 可选摘要、Dashboard cards、Enterprise OS cache | `{ "window_seconds": 3600, "event_count": 12, "high_risk_event_count": 3 }` |
| `system_security_posture` | object | posture 枚举：`healthy` / `watch` / `elevated` / `critical` / `degraded` | Enterprise overview/cache 聚合多个 session 的窗口摘要 | 系统级窗口快照；必须声明生成时间、窗口、缓存状态 | 正常非空；数据源不可用时返回 `posture: "degraded"` 与 `reason` | 否 | 否；企业 OS 默认展示/告警摘要，不改 gateway 判决 | Enterprise OS overview、Dashboard top-level posture、SSE overview refresh | `{ "posture": "elevated", "stale": false, "window_seconds": 3600 }` |

## 核心字段解释

| 字段 | 普通含义 | 计算来源 | 范围 / 单位 | 可空性 | 决策影响 | Dashboard / Web UI 位置 | API 读取 | 迁移说明 |
|---|---|---|---|---|---|---|---|---|
| `cumulative_score` | Legacy 会话分，用于旧 consumer 的“当前/累计风险”展示。 | `session_registry` 会话摘要；当前常由最新 risk snapshot 的 `int(composite_score)` 覆盖。 | number/int，`>=0`。 | 非空；无会话时为 `0`。 | 否。 | Session Detail 仍显示“Cumulative score”；Sessions 列表只在 `latest_composite_score` 缺失时兜底。 | `/report/sessions`、`/report/session/{id}/risk`、alert details。 | 不要再把它解释为窗口总量；新集成用 `session_risk_sum` / `session_risk_ewma`。 |
| `latest_composite_score` | 最新事件的连续风险分。 | 最新 `RiskSnapshot.composite_score`；窗口摘要取时间线最后一个 score。 | number/float，`>=0`；默认权重下常见 `0..3`，自定义权重可更高。 | 实现中空窗口通常返回 `0.0`；旧 payload 可能缺字段。 | 否。 | Dashboard 当前风险读数、Session Detail “Latest composite”、Sessions “Latest score”。 | `/report/sessions`、`/report/session/{id}/risk`、SSE risk/session events。 | 替代把 `cumulative_score` 当当前风险分的旧读法。 |
| `session_risk_sum` | 当前窗口内 composite 暴露总量。 | 窗口内 `risk_timeline[].composite_score` 求和；server helper 四舍五入到 4 位。 | number/float，`>=0`。 | 非空；无窗口事件为 `0.0`。 | 否。 | Dashboard 趋势/健康摘要、Enterprise OS session summary。 | `/report/session/{id}/risk` 顶层；`/report/sessions` session row；Enterprise overview summary。 | 与 `composite_score_sum` 同义时以 `session_risk_sum` 为 preferred name。 |
| `composite_score_sum` | `session_risk_sum` 的窗口容器 alias。 | `session_registry._window_risk_summary()` 把 `session_risk_sum` 写入该 alias。 | number/float，`>=0`。 | 可缺；如果缺失，读 `session_risk_sum`。 | 否。 | 只作为窗口摘要兼容字段，不建议直接显示标签。 | `window_risk_summary.composite_score_sum`。 | 新 API 文档和 UI 标签统一写 `session_risk_sum`。 |
| `session_risk_ewma` | 平滑后的当前风险态势分。 | 窗口内 composite score 按时间顺序 EWMA；当前 `alpha=0.3`。 | number/float，`>=0`。 | 空窗口实现通常返回 `0.0`；UI 可展示 `—` 或回退 latest score。 | 否。 | Session Detail “Session risk EWMA”、Sessions row “EWMA”、Dashboard 主风险态势。 | `/report/session/{id}/risk`、`/report/sessions`、`window_risk_summary`。 | 推荐作为 UI/Enterprise OS 的 preferred session score。 |
| `risk_points_sum` | 离散风险等级点数累计。 | 每个 timeline event 映射 `low=0`、`medium=1`、`high=2`、`critical=3` 后求和。 | integer，`>=0`。 | 非空；无事件为 `0`。 | 否；L3 内部阈值仍按独立 trigger 逻辑。 | L3 解释、Dashboard 辅助指标、Enterprise OS audit payload。 | `/report/session/{id}/risk`、`/report/sessions`、`window_risk_summary`。 | 用来解释“压力”，不要替代 `current_risk_level`。 |
| `risk_velocity` | 最近风险分变化方向。 | 比较窗口内最后两个 composite score：升为 `up`、降为 `down`、相等为 `flat`。 | enum/string：`up/down/flat/unknown`。 | 事件少于 2 个为 `unknown`。 | 否。 | Session Detail “Risk velocity”、Sessions “Velocity”。 | `/report/session/{id}/risk`、`/report/sessions`、`window_risk_summary`。 | 只解释趋势方向；不要排序为高低风险等级。 |
| `window_risk_summary` | 同一窗口内的权威聚合对象。 | `session_registry` 或 report server 按 session timeline 聚合。 | object；字段各自 `>=0` 或枚举。 | 非空路径应返回对象；无事件时计数为 0。 | 否。 | Session Detail “Window risk summary”、Sessions density/velocity、Dashboard cards。 | `/report/session/{id}/risk`；`/report/sessions` 可带摘要。 | 新 consumer 先读容器，再读顶层兼容字段。 |
| `high_or_critical_count` | 窗口内 high/critical 事件数。 | 对 timeline risk level 排名 `>= high` 的事件计数。 | integer，`>=0`。 | 缺失时 UI 可回退 `high_risk_event_count`。 | 否。 | Dashboard/Session high-risk count；Sessions filter/display。 | `window_risk_summary.high_or_critical_count`，Enterprise group counts。 | Preferred 窗口字段；不要和只在 session 顶层存在的累计 `high_risk_event_count` 混淆。 |
| `high_risk_event_count` | 会话累计 high/critical 事件数或旧窗口 alias。 | session registry 累计计数；部分 legacy payload 也放在 window summary。 | integer，`>=0`。 | 非空会话顶层；窗口内可缺。 | 否。 | Session Detail “High-risk events”、Dashboard session cards。 | `/report/sessions`、`/report/session/{id}/risk` 顶层；旧 `window_risk_summary`。 | 顶层保留；窗口内新读法用 `high_or_critical_count`。 |
| `system_security_posture` | 多 session 聚合后的系统态势。 | Enterprise overview/cache 聚合窗口 session summary、high/critical session、risk sums。 | object；`posture=healthy/watch/elevated/critical/degraded` 等。 | 正常非空；数据源不可用时返回 degraded object。 | 否。 | Dashboard top-level posture、Enterprise OS overview。 | Enterprise overview/report payload、SSE overview refresh。 | Consumer 必须处理 `stale/degraded`，不要把缺缓存当 healthy。 |

## D1-D6 风险维度

D1-D6 来自最新 `RiskSnapshot.dimensions`，用于解释单个事件为什么被判为低/中/高/严重风险。它们不是窗口聚合字段，也不会像 EWMA 一样平滑。

| 维度 | 代码范围 | 运维含义 | 常见触发信号 | Dashboard / API 读取 |
|---|---:|---|---|---|
| D1 — tool type danger | `0..3` | 工具类别危险度；越高表示工具本身越可能造成破坏或外传。 | shell、network、file-write、approval-sensitive tool。 | `dimensions_latest.d1`、risk timeline snapshot。 |
| D2 — target path sensitivity | `0..3` | 目标资源敏感度。 | `.env`、SSH key、生产配置、系统路径、credential store。 | `dimensions_latest.d2`。 |
| D3 — command pattern danger | `0..3` | 命令/参数模式危险度。 | `rm -rf`、recursive delete、archive + upload、curl/scp exfiltration pattern。 | `dimensions_latest.d3`。 |
| D4 — context risk accumulation | `0..2` | 当前 session 上下文累积风险。 | 多次中高风险事件、secret 读取后 network 动作、bounded suspicious sequence。 | `dimensions_latest.d4`；D4 normalization 只能 shadow/default-off。 |
| D5 — agent trust level | `0..2` | 调用方/Agent 信任等级。 | 未知 adapter、低信任 workspace、缺少可信身份。 | `dimensions_latest.d5`。 |
| D6 — injection detection | `0.0..3.0` | Prompt injection / malicious instruction / hidden override 风险。 | jailbreak、ignore policy、credential request、可疑网页/文件指令。 | `dimensions_latest.d6`；高级向量后端见 D6 文档。 |

### D1-D6 如何影响 operator 判断？

- **D1/D3 高**：优先看工具和命令本身，通常对应前置阻断或人工 DEFER。
- **D2/D6 高**：优先确认是否触碰 secret、生产资源或注入载荷。
- **D4 高**：不要只看单条事件；打开 Session Detail 查看 timeline、L3 evidence summary 或 advisory review。
- **D5 高**：检查 adapter、workspace、session owner 是否可信。

## 核心字段解释

| 字段 | 普通含义 | 计算来源 | 范围 / 单位 | 可空性 | 决策影响 | Dashboard / Web UI 位置 | API 读取 | 迁移说明 |
|---|---|---|---|---|---|---|---|---|
| `cumulative_score` | Legacy 会话分，用于旧 consumer 的“当前/累计风险”展示。 | `session_registry` 会话摘要；当前常由最新 risk snapshot 的 `int(composite_score)` 覆盖。 | number/int，`>=0`。 | 非空；无会话时为 `0`。 | 否。 | Session Detail 仍显示“Cumulative score”；Sessions 列表只在 `latest_composite_score` 缺失时兜底。 | `/report/sessions`、`/report/session/{id}/risk`、alert details。 | 不要再把它解释为窗口总量；新集成用 `session_risk_sum` / `session_risk_ewma`。 |
| `latest_composite_score` | 最新事件的连续风险分。 | 最新 `RiskSnapshot.composite_score`；窗口摘要取时间线最后一个 score。 | number/float，`>=0`；默认权重下常见 `0..3`，自定义权重可更高。 | 实现中空窗口通常返回 `0.0`；旧 payload 可能缺字段。 | 否。 | Dashboard 当前风险读数、Session Detail “Latest composite”、Sessions “Latest score”。 | `/report/sessions`、`/report/session/{id}/risk`、SSE risk/session events。 | 替代把 `cumulative_score` 当当前风险分的旧读法。 |
| `session_risk_sum` | 当前窗口内 composite 暴露总量。 | 窗口内 `risk_timeline[].composite_score` 求和；server helper 四舍五入到 4 位。 | number/float，`>=0`。 | 非空；无窗口事件为 `0.0`。 | 否。 | Dashboard 趋势/健康摘要、Enterprise OS session summary。 | `/report/session/{id}/risk` 顶层；`/report/sessions` session row；Enterprise overview summary。 | 与 `composite_score_sum` 同义时以 `session_risk_sum` 为 preferred name。 |
| `composite_score_sum` | `session_risk_sum` 的窗口容器 alias。 | `session_registry._window_risk_summary()` 把 `session_risk_sum` 写入该 alias。 | number/float，`>=0`。 | 可缺；如果缺失，读 `session_risk_sum`。 | 否。 | 只作为窗口摘要兼容字段，不建议直接显示标签。 | `window_risk_summary.composite_score_sum`。 | 新 API 文档和 UI 标签统一写 `session_risk_sum`。 |
| `session_risk_ewma` | 平滑后的当前风险态势分。 | 窗口内 composite score 按时间顺序 EWMA；当前 `alpha=0.3`。 | number/float，`>=0`。 | 空窗口实现通常返回 `0.0`；UI 可展示 `—` 或回退 latest score。 | 否。 | Session Detail “Session risk EWMA”、Sessions row “EWMA”、Dashboard 主风险态势。 | `/report/session/{id}/risk`、`/report/sessions`、`window_risk_summary`。 | 推荐作为 UI/Enterprise OS 的 preferred session score。 |
| `risk_points_sum` | 离散风险等级点数累计。 | 每个 timeline event 映射 `low=0`、`medium=1`、`high=2`、`critical=3` 后求和。 | integer，`>=0`。 | 非空；无事件为 `0`。 | 否；L3 内部阈值仍按独立 trigger 逻辑。 | L3 解释、Dashboard 辅助指标、Enterprise OS audit payload。 | `/report/session/{id}/risk`、`/report/sessions`、`window_risk_summary`。 | 用来解释“压力”，不要替代 `current_risk_level`。 |
| `risk_velocity` | 最近风险分变化方向。 | 比较窗口内最后两个 composite score：升为 `up`、降为 `down`、相等为 `flat`。 | enum/string：`up/down/flat/unknown`。 | 事件少于 2 个为 `unknown`。 | 否。 | Session Detail “Risk velocity”、Sessions “Velocity”。 | `/report/session/{id}/risk`、`/report/sessions`、`window_risk_summary`。 | 只解释趋势方向；不要排序为高低风险等级。 |
| `window_risk_summary` | 同一窗口内的权威聚合对象。 | `session_registry` 或 report server 按 session timeline 聚合。 | object；字段各自 `>=0` 或枚举。 | 非空路径应返回对象；无事件时计数为 0。 | 否。 | Session Detail “Window risk summary”、Sessions density/velocity、Dashboard cards。 | `/report/session/{id}/risk`；`/report/sessions` 可带摘要。 | 新 consumer 先读容器，再读顶层兼容字段。 |
| `high_or_critical_count` | 窗口内 high/critical 事件数。 | 对 timeline risk level 排名 `>= high` 的事件计数。 | integer，`>=0`。 | 缺失时 UI 可回退 `high_risk_event_count`。 | 否。 | Dashboard/Session high-risk count；Sessions filter/display。 | `window_risk_summary.high_or_critical_count`，Enterprise group counts。 | Preferred 窗口字段；不要和只在 session 顶层存在的累计 `high_risk_event_count` 混淆。 |
| `high_risk_event_count` | 会话累计 high/critical 事件数或旧窗口 alias。 | session registry 累计计数；部分 legacy payload 也放在 window summary。 | integer，`>=0`。 | 非空会话顶层；窗口内可缺。 | 否。 | Session Detail “High-risk events”、Dashboard session cards。 | `/report/sessions`、`/report/session/{id}/risk` 顶层；旧 `window_risk_summary`。 | 顶层保留；窗口内新读法用 `high_or_critical_count`。 |
| `system_security_posture` | 多 session 聚合后的系统态势。 | Enterprise overview/cache 聚合窗口 session summary、high/critical session、risk sums。 | object；`posture=healthy/watch/elevated/critical/degraded` 等。 | 正常非空；数据源不可用时返回 degraded object。 | 否。 | Dashboard top-level posture、Enterprise OS overview。 | Enterprise overview/report payload、SSE overview refresh。 | Consumer 必须处理 `stale/degraded`，不要把缺缓存当 healthy。 |

## D1-D6 风险维度

D1-D6 来自最新 `RiskSnapshot.dimensions`，用于解释单个事件为什么被判为低/中/高/严重风险。它们不是窗口聚合字段，也不会像 EWMA 一样平滑。

| 维度 | 代码范围 | 运维含义 | 常见触发信号 | Dashboard / API 读取 |
|---|---:|---|---|---|
| D1 — tool type danger | `0..3` | 工具类别危险度；越高表示工具本身越可能造成破坏或外传。 | shell、network、file-write、approval-sensitive tool。 | `dimensions_latest.d1`、risk timeline snapshot。 |
| D2 — target path sensitivity | `0..3` | 目标资源敏感度。 | `.env`、SSH key、生产配置、系统路径、credential store。 | `dimensions_latest.d2`。 |
| D3 — command pattern danger | `0..3` | 命令/参数模式危险度。 | `rm -rf`、recursive delete、archive + upload、curl/scp exfiltration pattern。 | `dimensions_latest.d3`。 |
| D4 — context risk accumulation | `0..2` | 当前 session 上下文累积风险。 | 多次中高风险事件、secret 读取后 network 动作、bounded suspicious sequence。 | `dimensions_latest.d4`；D4 normalization 只能 shadow/default-off。 |
| D5 — agent trust level | `0..2` | 调用方/Agent 信任等级。 | 未知 adapter、低信任 workspace、缺少可信身份。 | `dimensions_latest.d5`。 |
| D6 — injection detection | `0.0..3.0` | Prompt injection / malicious instruction / hidden override 风险。 | jailbreak、ignore policy、credential request、可疑网页/文件指令。 | `dimensions_latest.d6`；高级向量后端见 D6 文档。 |

### D1-D6 如何影响 operator 判断？

- **D1/D3 高**：优先看工具和命令本身，通常对应前置阻断或人工 DEFER。
- **D2/D6 高**：优先确认是否触碰 secret、生产资源或注入载荷。
- **D4 高**：不要只看单条事件；打开 Session Detail 查看 timeline、L3 evidence summary 或 advisory review。
- **D5 高**：检查 adapter、workspace、session owner 是否可信。

## 核心字段解释

| 字段 | 普通含义 | 计算来源 | 范围 / 单位 | 可空性 | 决策影响 | Dashboard / Web UI 位置 | API 读取 | 迁移说明 |
|---|---|---|---|---|---|---|---|---|
| `cumulative_score` | Legacy 会话分，用于旧 consumer 的“当前/累计风险”展示。 | `session_registry` 会话摘要；当前常由最新 risk snapshot 的 `int(composite_score)` 覆盖。 | number/int，`>=0`。 | 非空；无会话时为 `0`。 | 否。 | Session Detail 仍显示“Cumulative score”；Sessions 列表只在 `latest_composite_score` 缺失时兜底。 | `/report/sessions`、`/report/session/{id}/risk`、alert details。 | 不要再把它解释为窗口总量；新集成用 `session_risk_sum` / `session_risk_ewma`。 |
| `latest_composite_score` | 最新事件的连续风险分。 | 最新 `RiskSnapshot.composite_score`；窗口摘要取时间线最后一个 score。 | number/float，`>=0`；默认权重下常见 `0..3`，自定义权重可更高。 | 实现中空窗口通常返回 `0.0`；旧 payload 可能缺字段。 | 否。 | Dashboard 当前风险读数、Session Detail “Latest composite”、Sessions “Latest score”。 | `/report/sessions`、`/report/session/{id}/risk`、SSE risk/session events。 | 替代把 `cumulative_score` 当当前风险分的旧读法。 |
| `session_risk_sum` | 当前窗口内 composite 暴露总量。 | 窗口内 `risk_timeline[].composite_score` 求和；server helper 四舍五入到 4 位。 | number/float，`>=0`。 | 非空；无窗口事件为 `0.0`。 | 否。 | Dashboard 趋势/健康摘要、Enterprise OS session summary。 | `/report/session/{id}/risk` 顶层；`/report/sessions` session row；Enterprise overview summary。 | 与 `composite_score_sum` 同义时以 `session_risk_sum` 为 preferred name。 |
| `composite_score_sum` | `session_risk_sum` 的窗口容器 alias。 | `session_registry._window_risk_summary()` 把 `session_risk_sum` 写入该 alias。 | number/float，`>=0`。 | 可缺；如果缺失，读 `session_risk_sum`。 | 否。 | 只作为窗口摘要兼容字段，不建议直接显示标签。 | `window_risk_summary.composite_score_sum`。 | 新 API 文档和 UI 标签统一写 `session_risk_sum`。 |
| `session_risk_ewma` | 平滑后的当前风险态势分。 | 窗口内 composite score 按时间顺序 EWMA；当前 `alpha=0.3`。 | number/float，`>=0`。 | 空窗口实现通常返回 `0.0`；UI 可展示 `—` 或回退 latest score。 | 否。 | Session Detail “Session risk EWMA”、Sessions row “EWMA”、Dashboard 主风险态势。 | `/report/session/{id}/risk`、`/report/sessions`、`window_risk_summary`。 | 推荐作为 UI/Enterprise OS 的 preferred session score。 |
| `risk_points_sum` | 离散风险等级点数累计。 | 每个 timeline event 映射 `low=0`、`medium=1`、`high=2`、`critical=3` 后求和。 | integer，`>=0`。 | 非空；无事件为 `0`。 | 否；L3 内部阈值仍按独立 trigger 逻辑。 | L3 解释、Dashboard 辅助指标、Enterprise OS audit payload。 | `/report/session/{id}/risk`、`/report/sessions`、`window_risk_summary`。 | 用来解释“压力”，不要替代 `current_risk_level`。 |
| `risk_velocity` | 最近风险分变化方向。 | 比较窗口内最后两个 composite score：升为 `up`、降为 `down`、相等为 `flat`。 | enum/string：`up/down/flat/unknown`。 | 事件少于 2 个为 `unknown`。 | 否。 | Session Detail “Risk velocity”、Sessions “Velocity”。 | `/report/session/{id}/risk`、`/report/sessions`、`window_risk_summary`。 | 只解释趋势方向；不要排序为高低风险等级。 |
| `window_risk_summary` | 同一窗口内的权威聚合对象。 | `session_registry` 或 report server 按 session timeline 聚合。 | object；字段各自 `>=0` 或枚举。 | 非空路径应返回对象；无事件时计数为 0。 | 否。 | Session Detail “Window risk summary”、Sessions density/velocity、Dashboard cards。 | `/report/session/{id}/risk`；`/report/sessions` 可带摘要。 | 新 consumer 先读容器，再读顶层兼容字段。 |
| `high_or_critical_count` | 窗口内 high/critical 事件数。 | 对 timeline risk level 排名 `>= high` 的事件计数。 | integer，`>=0`。 | 缺失时 UI 可回退 `high_risk_event_count`。 | 否。 | Dashboard/Session high-risk count；Sessions filter/display。 | `window_risk_summary.high_or_critical_count`，Enterprise group counts。 | Preferred 窗口字段；不要和只在 session 顶层存在的累计 `high_risk_event_count` 混淆。 |
| `high_risk_event_count` | 会话累计 high/critical 事件数或旧窗口 alias。 | session registry 累计计数；部分 legacy payload 也放在 window summary。 | integer，`>=0`。 | 非空会话顶层；窗口内可缺。 | 否。 | Session Detail “High-risk events”、Dashboard session cards。 | `/report/sessions`、`/report/session/{id}/risk` 顶层；旧 `window_risk_summary`。 | 顶层保留；窗口内新读法用 `high_or_critical_count`。 |
| `system_security_posture` | 多 session 聚合后的系统态势。 | Enterprise overview/cache 聚合窗口 session summary、high/critical session、risk sums。 | object；`posture=healthy/watch/elevated/critical/degraded` 等。 | 正常非空；数据源不可用时返回 degraded object。 | 否。 | Dashboard top-level posture、Enterprise OS overview。 | Enterprise overview/report payload、SSE overview refresh。 | Consumer 必须处理 `stale/degraded`，不要把缺缓存当 healthy。 |

## D1-D6 风险维度

D1-D6 来自最新 `RiskSnapshot.dimensions`，用于解释单个事件为什么被判为低/中/高/严重风险。它们不是窗口聚合字段，也不会像 EWMA 一样平滑。

| 维度 | 代码范围 | 运维含义 | 常见触发信号 | Dashboard / API 读取 |
|---|---:|---|---|---|
| D1 — tool type danger | `0..3` | 工具类别危险度；越高表示工具本身越可能造成破坏或外传。 | shell、network、file-write、approval-sensitive tool。 | `dimensions_latest.d1`、risk timeline snapshot。 |
| D2 — target path sensitivity | `0..3` | 目标资源敏感度。 | `.env`、SSH key、生产配置、系统路径、credential store。 | `dimensions_latest.d2`。 |
| D3 — command pattern danger | `0..3` | 命令/参数模式危险度。 | `rm -rf`、recursive delete、archive + upload、curl/scp exfiltration pattern。 | `dimensions_latest.d3`。 |
| D4 — context risk accumulation | `0..2` | 当前 session 上下文累积风险。 | 多次中高风险事件、secret 读取后 network 动作、bounded suspicious sequence。 | `dimensions_latest.d4`；D4 normalization 只能 shadow/default-off。 |
| D5 — agent trust level | `0..2` | 调用方/Agent 信任等级。 | 未知 adapter、低信任 workspace、缺少可信身份。 | `dimensions_latest.d5`。 |
| D6 — injection detection | `0.0..3.0` | Prompt injection / malicious instruction / hidden override 风险。 | jailbreak、ignore policy、credential request、可疑网页/文件指令。 | `dimensions_latest.d6`；高级向量后端见 D6 文档。 |

### D1-D6 如何影响 operator 判断？

- **D1/D3 高**：优先看工具和命令本身，通常对应前置阻断或人工 DEFER。
- **D2/D6 高**：优先确认是否触碰 secret、生产资源或注入载荷。
- **D4 高**：不要只看单条事件；打开 Session Detail 查看 timeline、L3 evidence summary 或 advisory review。
- **D5 高**：检查 adapter、workspace、session owner 是否可信。

## 核心指标解释 {#core-fields}

| 字段 | Plain-language meaning | 计算来源 / 单位 | 可空性 | 决策影响 | Web UI 位置 | API 位置 | 迁移说明 |
|---|---|---|---|---|---|---|---|
| `cumulative_score` | 旧版“累计/当前风险”兼容读数 | `session_registry` 会话摘要；常见为最近 composite 的整数化；`>=0` | 非空；无会话时通常为 `0` | 默认不影响新判决 | 仅作为旧 UI fallback | `/report/sessions`、`/report/session/{id}/risk`、alert details | 新 UI 不应把它当 0-1 进度条或窗口总分。 |
| `latest_composite_score` | 最近一次风险快照的综合分 | 最新 `RiskSnapshot.composite_score`；float，默认权重下通常 `0..3` | 无事件或降级时可为 `null` | 默认不改变判决，只解释最新风险 | Session Detail “Latest composite” / Sessions fallback | `/report/sessions`、`/report/session/{id}`、`/report/session/{id}/risk`、SSE | 替代旧“当前风险分”文案；无 EWMA 时可作为主分。 |
| `session_risk_sum` | 当前窗口内 composite 暴露总量 | 窗口内 `composite_score` 求和；float `>=0` | 无窗口事件为 `0.0` | 默认不改变判决 | Session Detail 窗口摘要/趋势解释 | `/report/session/{id}/risk`，有时以 `window_risk_summary.composite_score_sum` 出现 | API consumer 遇到 `composite_score_sum` 应映射到此语义。 |
| `session_risk_ewma` | 平滑后的 session 当前风险态势 | 窗口内 composite score EWMA；当前实现默认 alpha 约 `0.3`；float `>=0` | 无事件时可为 `null` 或 `0.0`（取决于端点） | 默认不改变判决 | Sessions 行主分、Session Detail “EWMA” | `/report/sessions`、`/report/session/{id}/risk` | 新 UI 首选主展示分；回退 latest，再回退 legacy。 |
| `risk_points_sum` | 按风险等级累计的离散风险点 | `low=0`、`medium=1`、`high=2`、`critical=3` 求和；int `>=0` | 无事件为 `0` | 外显字段不替换 L3 内部阈值 | Session Detail 辅助解释、L3 evidence summary | `/report/session/{id}/risk`、`window_risk_summary` | 适合解释“为什么 L3 被触发/为什么 session 压力高”。 |
| `risk_velocity` | 风险趋势方向 | 窗口内分数序列比较；`up/down/flat/unknown` | 样本不足时 `unknown` | 默认不改变判决 | Sessions 行、Session Detail “Velocity”、Dashboard posture | `/report/sessions`、`/report/session/{id}/risk`、`system_security_posture` | 不要把它当速率数值；它是方向枚举。 |
| `window_risk_summary` | 一个窗口内风险事实的权威容器 | object，必须包含 `window_seconds` 与计数字段 | 正常非空；无事件时计数为 0 | 默认不改变判决 | Session Detail 窗口摘要、Dashboard cards | `/report/session/{id}/risk`、`/report/sessions` 可选摘要 | 新字段优先放进该对象，避免顶层字段无限扩张。 |
| `system_security_posture` | 系统级安全态势快照 | Enterprise/Dashboard 聚合多个 session；posture 枚举 + score/cache | 数据不可用时返回 `posture="degraded"` | 默认不改变 gateway 判决 | Dashboard 顶层态势卡 | Enterprise overview / Dashboard summary / SSE overview refresh | consumer 必须处理 `cache.stale` 和 `cache.degraded`。 |

## `window_risk_summary` 最低字段集 {#window-risk-summary}

| 字段 | 状态 | 说明 |
|---|---|---|
| `window_seconds` | required | 本次聚合窗口；`null` 表示未按时间窗口限制。 |
| `event_count` | required | 窗口内事件数。 |
| `high_or_critical_count` | canonical | 窗口内 `high` 或 `critical` 事件数。 |
| `high_risk_event_count` | alias | 兼容旧 UI/API 名；语义等同 high-or-critical。 |
| `critical_event_count` | optional | 窗口内 `critical` 事件数。 |
| `latest_composite_score` | required when available | 窗口内最新 composite score。 |
| `composite_score_sum` | alias | 窗口内 composite score 总和；consumer 映射为 `session_risk_sum`。 |
| `session_risk_ewma` | required when available | 窗口内 EWMA 当前态势值。 |
| `risk_points_sum` | required | 同窗口离散风险点数累计。 |
| `risk_velocity` | required | `up/down/flat/unknown`。 |
| `latest_event_at` | optional | 窗口内最新事件时间；无事件时可为 `null`。 |

## D1-D6 风险维度 {#d1-d6}

D1-D6 是 composite score 的解释维度，来自 Gateway risk snapshot。它们帮助 operator 理解“为什么分数高”，但不要单独把某个维度当最终 verdict。

| 维度 | 含义 | 典型范围/单位 | 高分通常表示 | Dashboard / API 用法 |
|---|---|---|---|---|
| D1 `tool_danger` | 工具/命令本身危险度 | `0..3` | 删除、权限修改、网络外传、凭证读取等危险工具形态 | Session Detail risk dimensions、`dimensions_latest.d1` |
| D2 `data_sensitivity` | 目标数据敏感度 | `0..3` | `.env`、SSH key、token、生产配置、客户数据等 | 解释敏感文件/路径触发原因 |
| D3 `intent_risk` | 行为意图风险 | `0..3` | 混淆、规避审计、打包后外传、可疑链式操作 | L2/L3 reasons 与 risk timeline |
| D4 `context_exposure` | 上下文/工作区暴露面 | `0..3` | 高权限仓库、生产目录、危险上下文组合 | 只按当前实现展示；D4 标准化仍应 default-off/shadow |
| D5 `execution_impact` | 执行影响/破坏面 | `0..3` | 会修改系统、删除数据、改变权限或影响部署 | 用于解释 block/defer 的破坏性 |
| D6 `semantic_similarity` | 向量/语义相似度风险 | `0..1` 或归一化分 | 与已知攻击模式、外传路径或危险 intent 高相似 | 需配置 embedding backend 时才更有价值 |

!!! note "D4 和 D6 的迁移边界"
    D4 normalization / D4 shadow metrics 默认不替换当前 `dimensions_latest.d4` 或判决阈值。D6 依赖向量相似度后端时，应在配置和 payload 中说明数据源；没有后端时不要伪造高置信分。

## API / UI 读取示例 {#examples}

### 从 Web UI 读风险

1. 打开 `clawsentry start` 打印的 `http://127.0.0.1:8080/ui?token=...`。
2. 在 **Sessions** 行上优先读 `EWMA` 和 `Velocity`：它们对应 `session_risk_ewma` 与 `risk_velocity`。
3. 点进 **Session Detail**：
   - “Latest composite” 对应 `latest_composite_score`。
   - “Cumulative/Window” 辅助读数对应 `session_risk_sum` / `window_risk_summary.composite_score_sum`。
   - “High risk events” 优先读 `high_or_critical_count`，兼容 `high_risk_event_count`。
   - L3 advisory 区块只解释复盘报告，不改历史 allow/block/defer。

### 从 API 读 session 风险

```bash
curl -H "Authorization: Bearer $CS_AUTH_TOKEN" \
  "http://127.0.0.1:8080/report/session/sess-001/risk?window_seconds=3600"
```

```json
{
  "session_id": "sess-001",
  "current_risk_level": "high",
  "cumulative_score": 2,
  "latest_composite_score": 2.4,
  "session_risk_sum": 6.7,
  "session_risk_ewma": 1.9,
  "risk_points_sum": 5,
  "risk_velocity": "up",
  "window_risk_summary": {
    "window_seconds": 3600,
    "event_count": 9,
    "high_or_critical_count": 2,
    "latest_composite_score": 2.4,
    "composite_score_sum": 6.7,
    "session_risk_ewma": 1.9,
    "risk_points_sum": 5,
    "risk_velocity": "up"
  }
}
```

Consumer 推荐逻辑：

```text
primary_session_score = session_risk_ewma
  ?? latest_composite_score
  ?? cumulative_score  # legacy fallback only

high_risk_events = window_risk_summary.high_or_critical_count
  ?? window_risk_summary.high_risk_event_count
  ?? 0
```

### 从 API 读系统态势

```json
{
  "system_security_posture": {
    "posture": "elevated",
    "score": 72.5,
    "risk_velocity": "up",
    "window_seconds": 3600,
    "generated_at": "2026-04-25T12:00:05Z",
    "cache": {
      "state": "fresh",
      "ttl_seconds": 10,
      "age_seconds": 2.1,
      "stale": false,
      "degraded": false
    },
    "summary": {
      "tracked_sessions": 18,
      "high_or_critical_count": 3,
      "critical_sessions": 1,
      "session_risk_sum": 24.8,
      "risk_points_sum": 17
    }
  }
}
```

## 读取场景

### 场景 A：从 Web UI 判断一个 session 是否正在升温

1. 打开 **Sessions**，先看 `Latest score`、`EWMA`、`Velocity` 和 `Density`。
2. 进入 **Session Detail**，看：
   - `Current risk`：当前离散风险等级；
   - `Latest composite`：最新连续分；
   - `Session risk EWMA`：平滑后的当前态势；
   - `Window risk summary`：窗口事件数、高危数、累计暴露；
   - `High-risk events`：会话累计 high/critical 数。
3. 如果 `risk_velocity=up` 且 D2/D6 或 D4 高，优先查看 L3 evidence summary / L3 advisory review。

### 场景 B：从 API 查询窗口风险

```bash
curl -s \
  -H "Authorization: Bearer $CS_AUTH_TOKEN" \
  "http://127.0.0.1:8080/report/session/session-001/risk?window_seconds=3600" \
  | jq '{session_id,current_risk_level,latest_composite_score,session_risk_ewma,risk_velocity,window_risk_summary}'
```

读取规则：

1. 当前风险：`current_risk_level` + `latest_composite_score`。
2. 趋势：`session_risk_ewma` + `risk_velocity`。
3. 窗口暴露：`window_risk_summary.composite_score_sum` 或顶层 `session_risk_sum`。
4. 高危计数：优先 `window_risk_summary.high_or_critical_count`，缺失时回退 `high_risk_event_count`。

## `window_risk_summary` 最低字段集

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
| `risk_velocity` | 同窗口分数趋势；无足够样本时为 `unknown` |

## `system_security_posture` 的降级语义

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

## Consumer 迁移建议 {#migration}

| Consumer | 当前兼容读取 | 新推荐读取 | 备注 |
|---|---|---|---|
| 旧 Dashboard session row | `cumulative_score` | `session_risk_ewma`，回退 `latest_composite_score`，最后回退 `cumulative_score` | 避免把 legacy int 当 0-1 进度条。 |
| Sessions list | `latest_composite_score ?? cumulative_score` | `latest_composite_score` + `session_risk_ewma` + `risk_velocity` + window density | 列表用于排序/筛选时要声明 fallback。 |
| Session detail | `cumulative_score` + `risk_timeline[].composite_score` | `window_risk_summary` + `latest_composite_score` + `dimensions_latest` | 窗口视图以 summary 为准；维度解释以 latest snapshot 为准。 |
| Alerts details | `details.cumulative_score` | `details.latest_composite_score` / `details.risk_points_sum` | 兼容字段可保留，但新告警解释应带新字段。 |
| Enterprise OS | 无统一字段 | `system_security_posture` | 必须处理 `stale/degraded`。 |
| L3 解释 | 内部 risk point threshold | `risk_points_sum` + D1-D6 + evidence summary | 暴露值用于解释，不默认替代触发逻辑。 |

## 核心字段怎么读 {#field-explainers}

<div class="cs-card-grid" markdown>

<div class="cs-card" markdown>
### `latest_composite_score`
**含义：** 最近一次事件的综合风险分。**单位/范围：** float，默认权重下常见 `0..3`。**决策影响：** 默认只展示；同步判决仍来自 RiskSnapshot / policy engine。**在哪里看：** Sessions row、Session Detail 顶部风险读数、`/report/sessions`。
</div>

<div class="cs-card" markdown>
### `session_risk_sum`
**含义：** 同一窗口内 composite score 的总暴露量。**计算：** timeline/window summary 中每个事件分数求和。**在哪里看：** Session Detail 窗口汇总、Enterprise OS summary、`/report/session/{id}/risk?window_seconds=...`。
</div>

<div class="cs-card" markdown>
### `session_risk_ewma`
**含义：** 更稳定的当前态势，避免单个尖峰完全主导展示。**空值：** 无事件可为 `null`。**UI fallback：** `session_risk_ewma` → `latest_composite_score` → `cumulative_score`。
</div>

<div class="cs-card" markdown>
### `risk_points_sum`
**含义：** 把风险等级离散成点数后累计，便于解释“为什么 L3/值守压力变高”。**边界：** 外显字段不自动替代内部 L3 trigger policy；若要用它触发策略必须显式配置。
</div>

<div class="cs-card" markdown>
### `risk_velocity`
**含义：** 窗口内风险走势。`up` 表示近期风险升高，`down` 表示缓解，`flat` 表示变化不明显，`unknown` 表示样本不足。**用途：** 值守排序与态势解释，不等于风险等级。
</div>

<div class="cs-card" markdown>
### `window_risk_summary`
**含义：** 窗口聚合的权威容器。**读取方式：** API consumer 应先读对象内字段，再回退 flat session fields。**决策影响：** 默认不改 allow/block/defer；用于 Dashboard、reporting 和 Enterprise OS handoff。
</div>

</div>

## D1-D6 维度解释 {#d1-d6-dimensions}

源码模型使用 `d1`…`d6` 保存维度分，文档和 UI 可显示为 D1-D6。每个维度都是 explainability signal，不应被单独理解成最终判决。

| 维度 | 操作含义 | 常见高分信号 | Operator 读法 |
|------|----------|--------------|---------------|
| D1 Tool danger | 工具/命令本身的危险性 | shell、sudo、删除、网络上传、权限修改 | 高 D1 先检查命令是否能造成不可逆影响 |
| D2 Data exposure | 数据外泄或敏感读取风险 | `.env`、token、SSH key、credential 文件、外发 payload | 高 D2 先看读取对象和后续网络/归档行为 |
| D3 Context mismatch | 当前上下文与行为是否不匹配 | 非部署 session 做部署级操作、非审计路径读取 secrets | 高 D3 需要结合 workspace/session 意图判断 |
| D4 Trajectory pressure | 最近轨迹中风险是否累积 | 多个 medium/high 事件、连续可疑步骤 | D4 更适合解释“为什么现在升级”，不是单条命令分 |
| D5 Policy sensitivity | 策略/模式库命中强度 | 规则治理命中、strict preset、高敏目录 | 高 D5 表示本组织规则明确不鼓励该路径 |
| D6 Similarity / semantic signal | 向量或语义近似风险 | 与已知攻击模式相似、语义分析高置信 | D6 常与 L2/自定义 analyzer 一起解释 |

## API 与 Web UI 读取示例 {#read-examples}

<div class="cs-operator-path" markdown>

**Web UI：** 进入 **Sessions** 先看 `latest_composite_score`、`session_risk_ewma`、`risk_velocity` 和 high-risk count；进入 **Session Detail** 后再看 `window_risk_summary`、D1-D6 bars、L3 advisory review。

**API：**

```bash
curl -H "Authorization: Bearer $CS_AUTH_TOKEN" \
  "http://127.0.0.1:8080/report/session/sess-001/risk?window_seconds=3600"
```

优先读取：

```text
window_risk_summary.session_risk_ewma
window_risk_summary.high_or_critical_count
latest_composite_score
risk_velocity
dimensions_latest.d1..d6
```

</div>

## 默认行为不变清单 {#no-behavior-change}

- `cumulative_score` 不改名、不删除、不改变旧消费者的默认读取路径。
- 新字段默认只出现在 report/API/SSE/dashboard/enterprise payload，不改变 allow/block/defer 结果。
- `risk_points_sum` 的外显值不自动替换 L3 trigger 内部阈值计算。
- `risk_velocity` 只描述趋势方向，不是风险等级或策略阈值。
- D4 normalization / D4 shadow metrics 默认不参与 `dimensions_latest.d4` 或判决阈值。
