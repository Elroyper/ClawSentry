---
title: Web 安全仪表板
description: ClawSentry Web UI 的使用模型、页面职责、实时数据来源与典型操作路径
---

# Web 安全仪表板

从 `0.3.8` 开始，ClawSentry 的 Web UI 不再只是“展示几张图表”，而是一个更接近安全监控台的 **Security Console**。到 `0.4.6`，这条线进一步收口为一个更稳定的、浅色优先的 **operator console**：它更强调扫描路径、阅读舒适度，以及首页第一屏就能回答“现在最值得看什么”。

如果你刚打开它却觉得“不知道该看哪里”，先记住一句话：

> **先看 framework，再看 workspace，再看 session。**

这三个层级就是理解整个 Web UI 的钥匙。

## 30 秒先看懂

如果你只想知道“我现在该点哪里”，先按这个顺序：

| 你的场景 | 先看哪里 | 你要回答的问题 |
|------|------|------|
| 只用一种框架，但开了很多 workspace / session | `Dashboard` → `Workspace Risk Board` | 先找出哪个 workspace 最危险 |
| 同时用了多种框架 | `Dashboard` → `Framework Coverage` | 先找出哪个 framework 当前最值得关注 |
| 已经知道要查某个 session | `Session Detail` | 这个 session 属于哪个 workspace，它为什么危险 |

然后再记住这条固定路径：

```text
Dashboard -> Sessions -> Session Detail
```

- `Dashboard` 用来决定先看哪一块
- `Sessions` 用来区分 framework / workspace / session
- `Session Detail` 用来解释这个 session 具体发生了什么

---

## 先理解三个层级

### 1. Framework

Framework 表示事件来自哪个 Agent 运行时，例如：

- `claude-code`
- `a3s-code`
- `openclaw`
- `codex`

如果你的团队同时用了多种框架，Web UI 会先把它们区分开。

### 2. Workspace

Workspace 表示某个具体的项目目录或工作区，例如：

- `/workspace/repo-alpha`
- `/workspace/repo-beta`
- `/home/user/project-x`

同一个 framework 下可能会同时跑很多 workspace。Web UI 会把这些 workspace 聚合出来，这样你能回答：

- 哪个项目现在最危险？
- 哪个仓库有最多高风险 session？
- 哪个工作区最近最活跃？

### 3. Session

Session 表示某个 workspace 中的一次具体 Agent 会话。

同一个 workspace 下可能同时存在多个 session，例如：

- 一个 session 在读代码
- 一个 session 在跑 shell
- 一个 session 在尝试高危操作

Web UI 的作用不是只告诉你“系统有风险”，而是告诉你：

- **哪个 framework**
- **哪个 workspace**
- **哪个 session**
- **为什么危险**

---

## 访问方式

启动 Gateway 后，Web UI 会挂载在 `/ui`：

```bash
clawsentry gateway
```

浏览器访问：

```text
http://127.0.0.1:8080/ui
```

如果你使用的是推荐的一键启动路径：

```bash
clawsentry start --framework claude-code
```

启动输出中通常会直接给出可登录地址：

```text
http://127.0.0.1:8080/ui?token=...
```

这条带 `?token=` 的链接是最省事的打开方式。页面会先把 URL 中的 token 写入浏览器会话，再开始请求 `summary` 和 SSE 流，避免出现先 401 再重连的认证竞态。

---

## 认证机制

Web UI 与 Gateway API 共享同一个 Bearer Token。

### REST API

REST 请求通过 Header 发送：

```text
Authorization: Bearer <token>
```

### SSE 实时流

浏览器原生 `EventSource` 不支持自定义 Header，因此 SSE 改用 query 参数：

```text
/report/stream?token=<token>&types=decision,alert
```

!!! warning "生产环境建议"
    生产环境中请启用 HTTPS。因为浏览器对 SSE 使用 query 参数携带 token，未加密链路会增加令牌泄露风险。

---

## 每个页面回答什么问题？

如果你把每个页面都当成“看数据”，就会容易迷路。更有效的方式是把它们当成回答不同问题的工具。

### Dashboard

Dashboard 回答：

- **现在哪类 framework 最值得关注？**
- **哪个 workspace 风险最高？**
- **哪些 session 应该优先点进去？**
- **实时流里刚刚发生了什么？**

它是值班视角的“入口页”，适合先扫一眼全局态势。

### Sessions

Sessions 页回答：

- **当前有哪些 framework 正在活跃？**
- **每个 framework 下面有哪些 workspace？**
- **同一个 workspace 里有哪些 session？**
- **哪个 session 是 critical / high / low？**

这是最适合“区分开很多 session”的页面，也是多工作空间、多框架场景下最关键的页面。

### Session Detail

Session Detail 回答：

- **这个 session 到底属于哪个 workspace？**
- **它的 transcript 在哪里？**
- **风险是由哪些维度抬高的？**
- **风险变化时间线是什么样的？**
- **具体都做了哪些决策？**

当你已经确定“要查某个 session”时，再进入这一页。

### Alerts

Alerts 页回答：

- **有哪些告警还没处理？**
- **哪些告警已经 ACK？**
- **它们关联的是哪个 session？**

### DEFER Panel

DEFER Panel 回答：

- **现在有哪些操作在等人工审批？**
- **我应该 Allow 还是 Deny？**

它不是总览页，而是交互审批页。

---

## 推荐使用顺序

### 场景 A：同一种框架，很多 workspace，很多 session

例如你只用了 `codex`，但同时在很多仓库开了很多 session。

推荐路径：

1. 先看 **Dashboard**
2. 从 **Workspace Risk Board** 找到最危险的 workspace
3. 进入 **Sessions** 页，查看该 framework 下该 workspace 的 session 列表
4. 点击具体 session 进入 **Session Detail**

你真正想回答的问题通常不是“系统有多少事件”，而是：

- 哪个 repo 最危险？
- 这个 repo 里是哪一个 session 出问题？

### 场景 B：多种框架并行使用

例如你同时跑了 `claude-code`、`a3s-code`、`codex`。

推荐路径：

1. 先看 **Dashboard → Framework Coverage**
2. 判断哪一个 framework 当前风险更高
3. 再进入 **Sessions**，按 framework 分块查看 workspace 和 session

这时 Web UI 的重点不是“一个 session 的细节”，而是**跨框架的统一监控视角**。

---

## 现在的页面结构

左侧导航保持 4 个主要入口：

| 页面 | 路径 | 适合什么时候看 |
|------|------|----------------|
| `Dashboard` | `/ui/` | 刚打开 UI，先看全局 |
| `Sessions` | `/ui/sessions` | 需要区分 framework / workspace / session |
| `Alerts` | `/ui/alerts` | 需要处理或确认告警 |
| `DEFER Panel` | `/ui/defer` | 需要人工审批延迟决策 |

---

## Dashboard 现在看什么？

### 1. 顶部总览

顶部会告诉你当前整体态势，例如：

- 追踪中的 session 数量
- 高风险 session 数量
- Block rate
- Gateway uptime / live events
- Operator brief 中的 coverage / posture / runtime pulse / budget pulse

### 2. Framework Coverage

这块告诉你：

- 当前有哪些 framework 在活跃
- 每个 framework 下有多少 workspace
- 每个 framework 下有多少高风险 session

这是“多框架视角”的入口。

### 3. Workspace Risk Board

这块告诉你：

- 哪些 workspace 最值得优先排查
- 每个 workspace 下有多少 session
- 哪些 workspace 最近刚刚出现了 critical/high 风险

这是“项目/仓库视角”的入口。

### 4. Priority Sessions

这块告诉你：

- 当前最该点进去看的 session 是哪些

如果你只想快速找到问题 session，这一块最直接。

### 5. Live Activity Feed

这块显示实时事件流，适合看“刚刚发生了什么”。

从 `0.3.8` 开始，feed 会继续保留以下事件可见性：

- `decision`
- `alert`
- `trajectory_alert`
- `post_action_finding`
- `pattern_candidate`
- `pattern_evolved`
- `defer_pending`
- `defer_resolved`
- `session_enforcement_change`

---

## Sessions 页现在怎么读？

Sessions 页不再只是一个平铺表格，而是按下面的结构组织：

```text
Framework
  └─ Workspace
       └─ Session
```

也就是说：

- 先看到 framework 概览卡
- 再看到每个 framework 下的 workspace 分组
- 最后在 workspace 内看到具体 session

这正是“很多工作空间、很多 session”场景下最重要的改动。

### 你会在这里看到什么？

- framework 概览
- workspace 根目录
- workspace 内 session 数量
- 每个 session 的风险等级、事件数、判决分布、最后活动时间

### 适合哪些场景？

- 你需要区分“同名 agent 在不同 repo 里的 session”
- 你需要判断“是某个 workspace 整体变危险，还是单个 session 出问题”
- 你需要同时盯多个 framework

---

## Session Detail 页现在怎么读？

Session Detail 页现在首先回答“这个 session 是谁”：

- 它属于哪个 workspace
- transcript 在哪里
- source framework 是什么
- caller adapter 是什么

然后才回答“它为什么危险”：

- D1-D5 风险构成
- 风险时间线
- replay / decision timeline
- tools used / risk hints / tier distribution

如果这个 session 触发过 L3，这一页现在还会继续给出一组更适合 operator 读取的运行态字段：

- `l3_state`
- `l3_reason_code`
- `trigger_detail`
- compact `evidence_summary`
- `budget_exhaustion_event`
- `decision_path_io`

如果你之前只看到一个 `session_id` 不知道上下文，那么这次改动就是为了解决这个问题。

---

## Web UI 背后的 API 变化

为了支撑 `framework -> workspace -> session` 视图，`0.3.8` 起以下 API 多暴露了会话身份信息：

- `GET /report/sessions`
- `GET /report/session/{id}/risk`

关键字段包括：

- `source_framework`
- `workspace_root`
- `transcript_path`
- `agent_id`
- `caller_adapter`

如果你在做二次开发，建议直接用这些字段做分组，而不是只靠 `session_id`。

---

## 实时数据来源

Web UI 使用两类数据源：

- **REST**：拉 summary / sessions / alerts / session detail
- **SSE**：接收实时事件

典型 SSE 连接形式：

```text
GET /report/stream?token=<token>&types=decision,alert
```

支持参数：

| 参数 | 说明 |
|------|------|
| `token` | 认证令牌 |
| `types` | 订阅的事件类型列表 |
| `session_id` | 只接收某个 session 的事件 |
| `min_risk` | 风险等级过滤 |

---

## 如果你只记住一条

打开 Web UI 后，不要先问“这些图表是什么意思”，而要先问：

1. **哪个 framework 有问题？**
2. **哪个 workspace 最危险？**
3. **哪个 session 需要我点进去看？**

这就是当前 Web UI 的设计主线。

---

## 前端开发入口

如果你需要继续修改前端，主要入口仍在：

```text
src/clawsentry/ui/
├── src/api/
├── src/components/
├── src/pages/
├── src/lib/sessionGroups.ts
├── src/App.tsx
└── src/styles.css
```

其中与本轮使用模型最相关的是：

- `src/pages/Dashboard.tsx`
- `src/pages/Sessions.tsx`
- `src/pages/SessionDetail.tsx`
- `src/lib/sessionGroups.ts`

本地构建：

```bash
cd src/clawsentry/ui
npm run build
```
