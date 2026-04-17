---
title: 核心概念
description: 理解 AHP 协议、三层决策模型和 ClawSentry 的关键设计
---

# 核心概念

本页介绍 ClawSentry 的核心概念和设计原理。理解这些概念将帮助你更高效地配置和使用 ClawSentry 监督网关。

---

## 1. AHP 协议 {#ahp-protocol}

**AHP (Agent Harness Protocol)** 是一套面向 AI Agent 运行时的通用安全监督协议。它定义了统一的事件格式和决策模型，使得不同 Agent 框架可以使用相同的监督基础设施。

ClawSentry 是 AHP 协议的 Python 参考实现。

```mermaid
graph LR
    subgraph "AHP 协议层"
        E[CanonicalEvent] --> D[CanonicalDecision]
    end

    subgraph "Agent 框架"
        A1[a3s-code] -->|Adapter| E
        A2[OpenClaw] -->|Adapter| E
        A3[自定义框架] -->|Adapter| E
    end

    subgraph "ClawSentry 实现"
        D --> L1[L1 规则引擎]
        D --> L2[L2 语义分析]
        D --> L3[L3 审查 Agent]
    end
```

**协议核心要素：**

| 要素 | 说明 |
|------|------|
| 协议版本 | `ahp.1.0`（schema_version 字段） |
| 事件模型 | `CanonicalEvent` — 归一化的 Agent 事件 |
| 决策模型 | `CanonicalDecision` — 监督引擎的裁决 |
| 传输通道 | UDS (Unix Domain Socket) 为主，HTTP 为备 |
| RPC 协议 | `sync_decision.1.0` — 同步决策请求/响应 |

!!! abstract "协议先行，策略后置"
    AHP 协议只定义事件格式和决策接口，不绑定具体的策略逻辑。任何实现都可以自由定义自己的风险评估规则和决策策略。

---

## 2. CanonicalEvent — 归一化事件 {#canonical-event}

`CanonicalEvent` 是 AHP 协议的核心数据模型，将来自不同 Agent 框架的原始事件归一化为统一格式。无论事件来自 a3s-code 还是 OpenClaw，在进入决策引擎时都是同一结构。

### 字段说明

```python
class CanonicalEvent(BaseModel):
    # --- 必填字段 ---
    schema_version: str    # 协议版本，如 "ahp.1.0"
    event_id: str          # 事件唯一标识
    trace_id: str          # 跨组件追踪 ID
    event_type: EventType  # 事件类型（见下方）
    session_id: str        # 会话标识
    agent_id: str          # Agent 标识
    source_framework: str  # 来源框架（"a3s-code" / "openclaw"）
    occurred_at: str       # UTC ISO8601 时间戳
    payload: dict          # 事件载荷（命令、参数等）

    # --- 可选字段 ---
    tool_name: str         # 工具名称（如 "bash", "exec"）
    risk_hints: list[str]  # 来源端提供的风险提示
    approval_id: str       # 审批 ID（用于 DEFER 回调）
    event_subtype: str     # 事件子类型
    framework_meta: dict   # 框架特定元数据
```

### 事件类型

| 类型 | 说明 | 处理方式 |
|------|------|---------|
| `pre_action` | 工具调用前 | **同步阻塞** — 必须等待决策返回 |
| `post_action` | 工具调用后 | 异步审计 — 不阻塞 Agent |
| `pre_prompt` | 提示词发送前 | 可选拦截 |
| `post_response` | LLM 响应后 | 可选审计 |
| `error` | 错误事件 | 日志记录 |
| `session` | 会话生命周期 | 会话追踪 |

### 示例

一个 a3s-code Agent 尝试执行 `rm -rf /tmp/test` 时生成的事件：

```json
{
  "schema_version": "ahp.1.0",
  "event_id": "evt-a1b2c3d4",
  "trace_id": "tr-e5f6g7h8",
  "event_type": "pre_action",
  "session_id": "session-001",
  "agent_id": "agent-main",
  "source_framework": "a3s-code",
  "occurred_at": "2026-03-23T10:30:00Z",
  "tool_name": "bash",
  "event_subtype": "tool_call",
  "payload": {
    "command": "rm -rf /tmp/test",
    "type": "bash"
  }
}
```

---

## 3. CanonicalDecision — 统一判决 {#canonical-decision}

`CanonicalDecision` 是监督引擎对事件的裁决结果。判决由策略引擎产生，永远不会由 Adapter 产生。

### 字段说明

```python
class CanonicalDecision(BaseModel):
    decision: DecisionVerdict      # 判决：allow / block / modify / defer
    reason: str                    # 判决理由（人类可读）
    policy_id: str                 # 产生判决的策略 ID
    risk_level: RiskLevel          # 风险等级：low / medium / high / critical
    decision_source: DecisionSource  # 来源：policy / manual / system
    policy_version: str            # 策略版本
    decision_latency_ms: float     # 决策耗时（毫秒）
    modified_payload: dict         # 修改后的载荷（仅 modify 判决）
    failure_class: FailureClass    # 失败分类（正常为 "none"）
    final: bool                    # 是否为最终判决
```

### 示例

```json
{
  "decision": "block",
  "reason": "Destructive file deletion targeting system path (SC-1 short-circuit)",
  "policy_id": "L1-rule-engine",
  "risk_level": "high",
  "decision_source": "policy",
  "policy_version": "1.0",
  "decision_latency_ms": 0.42,
  "failure_class": "none",
  "final": true
}
```

---

## 4. 三层决策模型 {#three-tier-model}

ClawSentry 实现了渐进式三层决策架构。低层级快速处理简单场景，只有当风险无法在当前层级确定时才向上升级。

```mermaid
graph TD
    E[CanonicalEvent] --> L1

    subgraph L1 ["L1 规则引擎 (< 1ms)"]
        L1_EVAL[D1-D6 六维评分]
        L1_SC[短路规则 SC-1/2/3]
    end

    L1 -->|"低风险 → ALLOW"| OUT_A[ALLOW]
    L1 -->|"短路命中 → BLOCK"| OUT_B[BLOCK]
    L1 -->|"中等风险 → 升级"| L2

    subgraph L2 ["L2 语义分析 (< 3s)"]
        L2_LLM[LLM 语义理解]
        L2_CTX[上下文关联分析]
    end

    L2 -->|"确认安全 → 降级"| OUT_A
    L2 -->|"确认危险 → 升级"| OUT_B2[BLOCK]
    L2 -->|"仍不确定 → 升级"| L3

    subgraph L3 ["L3 审查 Agent (< 30s)"]
        L3_AGENT[多轮工具调用]
        L3_SKILL[专项审计 Skills]
    end

    L3 -->|"最终判决"| OUT_F[ALLOW / BLOCK / DEFER]
```

### 层级对比

| 层级 | 延迟 | 技术 | 适用场景 | 是否需要 LLM |
|------|------|------|---------|-------------|
| **L1** | < 1ms | 规则引擎 + 模式匹配 | 明确的白名单/黑名单命令 | 否 |
| **L2** | < 3s | LLM 语义分析 | 需要理解命令意图的模糊场景 | 是 |
| **L3** | < 30s | 多轮 Agent + 工具调用 | 复杂场景需要主动调查（读文件、查历史） | 是 |

!!! info "L1 覆盖大多数场景"
    在实际使用中，L1 规则引擎可以处理约 80% 的事件。只有真正需要语义理解的模糊场景才会触发 L2/L3。不配置 LLM 也能获得完整的 L1 防护能力。

### L1 短路规则

L1 引擎内置三条短路规则，命中时立即产生判决，不进行完整的六维评分：

| 规则 | 条件 | 判决 |
|------|------|------|
| **SC-1** | D1=3（高危工具）且 D2 ≥ 2（敏感路径） | 立即 CRITICAL |
| **SC-2** | D3=3（高危命令模式，如 `rm -rf /`、`:(){ :\|:& };:`） | 立即 CRITICAL |
| **SC-3** | D1=0 且 D2=0 且 D3=0（纯只读操作） | 立即 LOW |

### L3 审查 Agent

L3 是最强大的分析层级。它运行一个独立的审查 Agent，可以使用只读工具（ReadOnlyToolkit）进行多轮调查：

- 读取相关文件以理解命令上下文
- 查询会话历史以发现行为模式
- 调用专项审计 Skill（shell 审计、凭证检查、代码审查等）
- 综合所有信息生成最终判决

当前版本额外提供两个**显式 opt-in** 的 L3 触发增强语义：

- `l3_routing_mode=replace_l2`：当事件命中 organic L2 入口时，直接跳过 L2 并无条件进入本地 L3。
- `l3_trigger_profile=eager`：仍走正常模式，但比默认档位更容易把事件从 L2 提升到 L3。

这两个开关默认都关闭，因此默认行为不变。若运行时没有本地 L3 能力，系统会继续走真实可执行的 L1/L2 路径，并通过 `l3_available=false` / `l3_reason_code=local_l3_unavailable` 诚实暴露“想跑 L3 但本机没有 L3”。

!!! warning "L3 永不降级"
    如果 L3 执行过程中出现任何错误（LLM 调用失败、工具执行异常等），系统不会回退到低层级。而是返回 `confidence=0.0`，由 Gateway 根据 fail-safe 原则做出保守决策。

---

## 5. D1-D6 六维风险评分 {#risk-dimensions}

ClawSentry 通过六个维度对每个事件进行定量风险评估，生成不可变的 `RiskSnapshot`。

| 维度 | 名称 | 范围 | 评估内容 |
|------|------|------|---------|
| **D1** | 命令危险度 | 0-3 | 工具类型的固有危险性 |
| **D2** | 参数敏感度 | 0-3 | 目标路径或参数是否涉及敏感区域 |
| **D3** | 命令模式危险度 | 0-3 | 命令字符串中的危险模式 |
| **D4** | 历史行为累积 | 0-2 | 当前会话的风险累积程度 |
| **D5** | 作用域权限 | 0-2 | Agent 的信任等级 |
| **D6** | 注入检测 | 0.0-3.0（连续值） | 提示词注入/命令注入/凭证泄露检测（三层：正则 + Canary + 向量相似度） |

**综合评分公式：**

\[
\text{base\_score} = 0.4 \times \max(D1, D2, D3) + 0.25 \times D4 + 0.15 \times D5
\]

\[
\text{composite\_score} = \text{base\_score} \times \left(1.0 + 0.5 \times \frac{D6}{3.0}\right)
\]

**风险等级映射：**

| 合成分范围 | 风险等级 | 默认判决 |
|-----------|---------|---------|
| < 0.8 | `low` | ALLOW |
| 0.8 – 1.5 | `medium` | DEFER（或升级到 L2） |
| 1.5 – 2.2 | `high` | BLOCK |
| >= 2.2 | `critical` | BLOCK |

### D1 评分示例

| 工具类型 | D1 评分 | 示例 |
|---------|--------|------|
| 只读工具 | 0 | `read_file`, `grep`, `list_dir` |
| 有限写入 | 1 | `write_file`, `edit_file` |
| 系统交互 | 2 | `http_request`, `install_package` |
| 高危工具 | 3 | `exec`, `sudo`, `chmod`, `kill` |

### D2 评分示例

| 目标路径 | D2 评分 | 说明 |
|---------|--------|------|
| 项目工作区 | 0 | `./src/app.py` |
| 配置/dotenv 文件 | 1 | `~/.bashrc`, `.env.local`, `Makefile` |
| 凭证/密钥文件 | 2 | `~/.ssh/id_rsa`, `server.pem` |
| 系统关键路径 | 3 | `/etc/hosts`, `/etc/shadow`, `/boot/` |

### D6 — 注入检测 (Injection Detection) {#d6}

**取值范围：0.0-3.0（连续浮点值）**

D6 是 ClawSentry E-4 新增的第六个风险维度，专门检测提示词注入（Prompt Injection）和命令注入（Command Injection）企图。与 D1-D5 的整数评分不同，D6 采用连续浮点值，精度更高。

**三层检测架构：**

| 层级 | 名称 | 机制 | 分值贡献 |
|:----:|------|------|---------|
| **Layer 1** | 启发式正则 | 弱模式 22 条（+0.3/条，上限 1.5）+ 强模式 17 条（+0.8/条，上限 2.4）+ 工具特定模式 | 0.0–3.0 |
| **Layer 2** | Canary Token | 在载荷中嵌入随机 token，检测是否被外泄 | +1.5（若命中） |
| **Layer 3** | 向量相似度 | 可插拔 `EmbeddingBackend` Protocol，与已知攻击语料比较相似度 | 0.0–2.0 |

最终 D6 = min(Layer1 + Layer2 + Layer3, 3.0)。

**弱模式示例（ignore previous instructions、forget everything、忽略之前的指令、从现在开始 等）：** 偏误导性话术（含 12 条中文注入模式），每条 +0.3 分，22 条上限 1.5

**强模式示例（`<script`、`eval(`、Unicode 零宽字符、`data:text/html;base64,`、关闭安全检查、系统提示标记 等）：** 明确的注入技术特征（含 8 条中文注入模式），每条 +0.8 分，17 条上限 2.4

**NFKC 穿透：** 所有检测函数在匹配前先对输入执行 NFKC Unicode 归一化 + 393 个不可见码点剥离（排除 U+FE0F emoji 变体选择符），防止全角字符/不可见字符绕过。

**D6 全局放大效应：**

D6 通过乘数公式放大基础评分，而不是简单累加。例如 D6=3.0 时，基础评分放大 1.5 倍（1.0 + 0.5×1.0 = 1.5）。这使得注入尝试能够将原本中等风险的操作提升到高危区间。

**D6 最低保证：** 当 D6 >= 2.0 且当前风险等级为 LOW 时，强制升级为 MEDIUM，防止高置信度注入被低评分掩盖。

!!! example "D6 放大效应示例"
    假设一个有历史高危记录会话中的 `pip install` 命令（D4=1，base_score = 1.20，MEDIUM 区间）：

    | 场景 | D6 分值 | 乘数 | composite_score | 最终判决 |
    |------|:-------:|:----:|:---------------:|:-------:|
    | 无注入特征 | 0.0 | 1.00 | 1.20 | MEDIUM → L2 分析 |
    | 含 2 条弱注入模式（+0.6） | 0.6 | 1.10 | 1.32 | MEDIUM → L2 分析 |
    | 强注入 + Canary 泄露（+2.3） | 2.3 | 1.38 | 1.66 | HIGH → BLOCK |
    | Layer 3 向量命中 + 强模式（3.0） | 3.0 | 1.50 | 1.80 | HIGH → BLOCK |

    D6 达到强注入强度（≥ 1.5）后，将原本处于 MEDIUM 区间的操作直接提升为 HIGH 拦截。

---

## 6. 四种判决 {#verdicts}

每个 `CanonicalDecision` 包含以下四种判决之一：

```mermaid
graph LR
    subgraph "判决类型"
        A["ALLOW<br/>放行"]
        B["BLOCK<br/>拦截"]
        M["MODIFY<br/>修改"]
        D["DEFER<br/>延迟"]
    end

    A -->|"final=true"| R1["Agent 继续执行"]
    B -->|"final=true"| R2["Agent 操作被拒绝"]
    M -->|"final=true"| R3["Agent 使用修改后的参数执行"]
    D -->|"final=false"| R4["等待人工审批后<br/>返回最终判决"]
```

| 判决 | 语义 | `final` | 适用场景 |
|------|------|---------|---------|
| **ALLOW** | 放行，允许 Agent 执行该操作 | `true` | 低风险的安全操作 |
| **BLOCK** | 拦截，拒绝 Agent 执行该操作 | `true` | 高危或违规操作 |
| **MODIFY** | 修改参数后放行 | `true` | 需要自动脱敏或参数校正的操作 |
| **DEFER** | 延迟等待人工审批 | `false` | 中等风险，需运维人员确认 |

!!! note "MODIFY 判决"
    当判决为 `MODIFY` 时，`CanonicalDecision` 必须包含 `modified_payload` 字段，Agent 应使用修改后的参数执行操作。例如，自动将明文密码替换为环境变量引用。

!!! warning "DEFER 有时间限制"
    DEFER 判决带有 `expires_at` 时间戳。如果运维人员在超时前未做出选择，系统将根据 fail-safe 原则自动拒绝（fail-closed）。

---

## 7. 双通道处理 {#dual-channel}

AHP 协议区分两种处理模式，分别对应不同的时效要求：

```mermaid
sequenceDiagram
    participant Agent
    participant Gateway as ClawSentry Gateway

    rect rgb(200, 230, 200)
        Note over Agent,Gateway: pre_action (同步阻塞通道)
        Agent->>+Gateway: pre_action 事件
        Gateway->>Gateway: 风险评估 + 决策
        Gateway-->>-Agent: CanonicalDecision
        Note right of Agent: Agent 必须等待判决后<br/>才能继续执行
    end

    rect rgb(200, 210, 240)
        Note over Agent,Gateway: post_action (异步审计通道)
        Agent->>Gateway: post_action 事件
        Note right of Gateway: 异步记录，不返回判决
        Note right of Agent: Agent 无需等待，<br/>继续执行下一步
    end
```

| 通道 | 事件类型 | 行为 | SLA |
|------|---------|------|-----|
| **同步阻塞** | `pre_action` | Agent 发送事件后必须等待判决返回 | L1 < 1ms, L2 < 3s, L3 < 30s |
| **异步审计** | `post_action` | Agent 发送事件后立即继续，Gateway 异步处理 | 无硬性限制 |

!!! tip "为什么需要双通道？"
    `pre_action` 通道是安全防线 — 它在操作执行前进行拦截决策。`post_action` 通道用于事后审计和行为分析，不影响 Agent 的执行速度，但提供完整的操作轨迹用于安全审查和 D4 历史行为累积评分。

---

## 8. Sidecar 架构 {#sidecar}

ClawSentry 采用 Sidecar 模式部署，作为 Agent 的伴随进程运行，通过本地通信通道进行交互。

```mermaid
graph TB
    subgraph "主机 / 容器"
        subgraph "Agent 进程"
            A[AI Agent]
            AH[AHP Hook / Adapter]
        end

        subgraph "ClawSentry Sidecar"
            GW[Supervision Gateway]
            PE[Policy Engine]
            DB[(SQLite)]
        end

        AH -->|"UDS (主通道)"| GW
        AH -.->|"HTTP (备用通道)"| GW
        GW --> PE
        PE --> DB
    end

    subgraph "外部（可选）"
        LLM[LLM API]
        WEB[Web 仪表板]
        OC[OpenClaw Gateway]
    end

    PE -.->|"L2/L3"| LLM
    GW -->|SSE| WEB
    GW <-->|WebSocket| OC
```

### 双传输通道

| 通道 | 协议 | 优先级 | 特点 |
|------|------|--------|------|
| **UDS** | Unix Domain Socket | 主通道 | 低延迟、无网络开销、文件权限隔离 |
| **HTTP** | REST API | 备用通道 | 支持跨网络访问、便于调试 |

!!! info "UDS 安全加固"
    ClawSentry 在创建 UDS 文件后会设置 `chmod 600` 权限，确保只有同一用户的进程可以访问。结合 Bearer Token 认证，提供双重安全保障。

---

## 9. 会话累积与强制策略 {#session-enforcement}

ClawSentry 通过 `SessionRegistry` 追踪每个会话的风险累积，通过 `SessionEnforcementPolicy` 在阈值触发时强制执行安全策略。

### 会话风险追踪

每次事件评估后，会话的风险统计会更新：

- 累计高危事件数
- 最近 N 次事件的风险等级分布
- 会话持续时间和活跃度

### 强制策略（Session Enforcement）

当一个会话累积了 N 次高危事件后（默认阈值为 3），强制策略会被触发：

```mermaid
stateDiagram-v2
    [*] --> NORMAL: 会话开始
    NORMAL --> NORMAL: 低/中风险事件
    NORMAL --> ENFORCED: 累积 >= threshold 次高危事件
    ENFORCED --> ENFORCED: 所有后续 pre_action 强制为 DEFER/BLOCK
    ENFORCED --> NORMAL: 冷却超时（默认 600s）
    ENFORCED --> NORMAL: 运维人员手动释放
```

| 配置项 | 环境变量 | 默认值 | 说明 |
|--------|---------|--------|------|
| 启用开关 | `AHP_SESSION_ENFORCEMENT_ENABLED` | `false` | 是否启用会话强制策略 |
| 触发阈值 | `AHP_SESSION_ENFORCEMENT_THRESHOLD` | `3` | 累积多少次高危事件后触发 |
| 强制动作 | `AHP_SESSION_ENFORCEMENT_ACTION` | `defer` | 触发后的动作：`defer` / `block` / `l3_require` |
| 冷却时间 | `AHP_SESSION_ENFORCEMENT_COOLDOWN_SECONDS` | `600` | 自动释放的等待时间（秒） |

---

## 10. Post-action 围栏 {#post-action-fence}

**Post-action 围栏** 是 ClawSentry 的异步后置检测层。与 `pre_action` 同步拦截不同，它在工具调用**执行后**对输出和副作用进行扫描，不阻塞 Agent，但会生成告警事件供运维人员审查。

### 工作时机

```mermaid
sequenceDiagram
    participant Agent
    participant Gateway
    participant PostAction as PostActionAnalyzer（异步）

    Agent->>Gateway: post_action 事件（含工具输出）
    Gateway-->>Agent: 立即返回 ALLOW（不阻塞）
    Gateway->>PostAction: 异步扫描
    PostAction->>Gateway: 输出告警（若检测到威胁）
```

### 检测分层

`PostActionAnalyzer` 分三档响应：

| 告警级别 | 默认阈值 | 行为 |
|---------|---------|------|
| **Monitor** | ≥ 0.3 | 记录日志，SSE 广播告警 |
| **Escalate** | ≥ 0.6 | 升级告警，通知 watch / Web UI |
| **Emergency** | ≥ 0.9 | 最高级告警，触发 Latch 推送通知 |

### 检测类别

| 类别 | 描述 |
|------|------|
| **提示词注入回显** | 检测 LLM 输出中是否含有注入指令被执行后的痕迹 |
| **数据外泄** | 含外部 URL 的 curl/wget/ftp/nc 命令、异常网络请求 |
| **凭证泄露** | API Key、密码、证书在输出中明文出现 |
| **混淆内容** | base64 解码后执行、eval(hex)、复杂字符串拼接执行链 |
| **外部内容放大** | 来自网络或用户输入的内容：D6 额外 +0.3，post-action 分数 ×1.3 |

### 配置

| 环境变量 | 默认值 | 说明 |
|---------|--------|------|
| `CS_POST_ACTION_EMERGENCY` | `0.9` | Emergency 告警阈值 |
| `CS_POST_ACTION_ESCALATE` | `0.6` | Escalate 告警阈值 |
| `CS_POST_ACTION_MONITOR` | `0.3` | Monitor 告警阈值 |
| `CS_POST_ACTION_WHITELIST` | 无 | 逗号分隔的白名单域名，排除误报 |
| `CS_EXTERNAL_CONTENT_D6_BOOST` | `0.3` | 外部内容来源时 D6 额外加分 |
| `CS_EXTERNAL_CONTENT_POST_ACTION_MULTIPLIER` | `1.3` | 外部内容来源时 post-action 分数乘数 |

!!! info "不阻塞但持续审计"
    Post-action 围栏永远不会阻止 Agent 已完成的操作，但其告警会在 Web 仪表板和 `clawsentry watch` 中实时显示，并通过 Latch 推送到手机。

---

## 11. TrajectoryAnalyzer — 多阶段攻击检测 {#trajectory-analyzer}

**TrajectoryAnalyzer** 分析跨多个工具调用步骤的行为序列，检测单个事件无法识别的**多阶段攻击模式**（如 APT 侦察→外泄链路）。

### 工作原理

每个会话保留最近 N 步工具调用记录（默认 50 步）。TrajectoryAnalyzer 在每次 `post_action` 事件后异步扫描该会话的事件轨迹，对以下模式评分：

| 模式 ID | 名称 | 典型特征序列 |
|--------|------|------------|
| **RECON_THEN_EXFIL** | 侦察后外泄 | `ls/find/cat` 读取文件 → 随后 `curl/nc` 外发 |
| **PRIVILEGE_ESCALATION** | 权限提升 | `id/whoami` 探测权限 → `sudo/chmod` 提升权限 |
| **LATERAL_MOVEMENT** | 横向移动 | 读取 SSH 密钥/凭证 → 建立外部连接 |
| **PERSISTENCE** | 持久化 | 修改 `.bashrc`/crontab/systemd → 写入后门 |
| **DATA_STAGING** | 数据预备外泄 | 大量文件聚合压缩 → 准备传输 |

每种模式都有阶段权重，当模式分 ≥ threshold 时触发告警。

### 与 Post-action 的关系

```mermaid
graph TD
    PA["PostActionAnalyzer<br/>单事件扫描"] --> ALERT1[单次告警]
    TA["TrajectoryAnalyzer<br/>跨事件序列分析"] --> ALERT2[模式告警]
    ALERT1 --> EB[EventBus]
    ALERT2 --> EB
    EB --> W[watch CLI]
    EB --> UI[Web UI]
    EB --> L[Latch]
```

两者均为**异步、非阻塞**，互为补充：Post-action 针对单次事件的输出内容扫描，TrajectoryAnalyzer 在时间序列维度检测多步攻击链。

### 配置

| 环境变量 | 默认值 | 说明 |
|---------|--------|------|
| `CS_TRAJECTORY_MAX_EVENTS` | `50` | 每个会话保留的最大事件步数 |
| `CS_TRAJECTORY_MAX_SESSIONS` | `10000` | 内存中保留的最大会话数 |

---

## 12. EventBus 与 SSE 实时推送 {#eventbus-sse}

ClawSentry 内部使用 **EventBus** 作为事件总线，将决策、告警、会话、DEFER 等事件广播给所有订阅者。外部消费者通过 **SSE（Server-Sent Events）** 接收实时事件流。

### 推送架构

```mermaid
graph LR
    subgraph "Gateway 内部"
        LE["L1/L2/L3 决策引擎"] -->|决策事件| EB[EventBus]
        PA[PostActionAnalyzer] -->|告警事件| EB
        DM[DeferManager] -->|defer_pending / defer_resolved| EB
        SR[SessionRegistry] -->|会话事件| EB
    end

    subgraph "外部消费者"
        EB -->|"SSE  GET /events"| W[clawsentry watch]
        EB -->|"SSE  GET /events"| UI[Web UI]
        EB -->|HTTP 转发| LH[Latch Hub]
    end
```

### SSE 事件类型

| 事件类型 | 触发时机 | 主要字段 |
|---------|---------|---------|
| `decision` | 每次产生 allow/block/defer 判决 | `session_id`, `verdict`, `risk_level`, `tool_name`, `reason` |
| `alert` | PostActionAnalyzer / TrajectoryAnalyzer 检测到威胁 | `session_id`, `alert_type`, `severity`, `detail` |
| `defer_pending` | 产生 DEFER 判决，等待人工审批 | `session_id`, `approval_id`, `expires_at`, `command` |
| `defer_resolved` | DEFER 被 Allow/Deny 或超时 | `approval_id`, `resolved_by`, `resolution` |
| `session` | 会话生命周期（start/end） | `session_id`, `agent_id`, `framework` |

### 接入方式

```bash
# clawsentry watch 自动订阅（推荐）
clawsentry watch

# 手动 curl 调试
curl -H "Authorization: Bearer $CS_AUTH_TOKEN" \
     http://127.0.0.1:8080/events
```

!!! tip "DEFER 交互式审批依赖 SSE"
    `clawsentry watch --interactive` 监听 `defer_pending` 事件，在终端提示 `[A]llow / [D]eny / [S]kip`。SSE 连接中断时 Web UI 和 Latch 仍可审批。

---

## 13. 安全预设与项目级配置 {#security-presets}

ClawSentry 提供四个内置安全预设，通过 `.clawsentry.toml` 文件按项目独立配置——不同项目可以有不同的安全强度，互不干扰。

### 四个预设级别

| 预设 | 适用场景 | medium 阈值 | high 阈值 | critical 阈值 | DEFER 超时行为 | D6 放大系数 |
|------|---------|:-----------:|:---------:|:-------------:|:-------------:|:-----------:|
| `low` | 个人项目、本地探索 | 1.2 | 2.0 | 2.8 | **超时放行** | 0.3 |
| `medium` **(默认)** | 日常开发 | 0.8 | 1.5 | 2.2 | 超时拒绝 | 0.5 |
| `high` | 团队项目、敏感代码库 | 0.5 | 1.2 | 1.8 | 超时拒绝 | 0.7 |
| `strict` | CI/CD、安全审计 | 0.3 | 0.9 | 1.3 | 超时拒绝 | 1.0 |

预设值越高，检测敏感度越强（阈值越低 → 更多操作被视为高风险），D6 注入放大系数越大。

### .clawsentry.toml — 项目级配置

在项目根目录创建 `.clawsentry.toml`，Harness 在每次 hook 调用时自动读取（60s TTL 缓存，热更新无需重启）：

```toml
[project]
enabled = true
preset = "high"         # low / medium / high / strict

[overrides]
# 可选：在预设基础上精细覆盖单个参数
# threshold_critical = 2.0
# defer_timeout_action = "allow"
# post_action_emergency = 0.85
```

### 配置优先级链

```
CS_ 环境变量  >  .clawsentry.toml [overrides]  >  预设值  >  DetectionConfig 默认值
```

### 常用命令

```bash
clawsentry config init --preset high   # 在当前目录生成 .clawsentry.toml
clawsentry config set strict           # 切换预设
clawsentry config show                 # 查看当前生效配置和来源
clawsentry config disable              # 临时禁用项目配置
```

!!! info "不同项目，不同预设"
    `.clawsentry.toml` 只影响从该目录（或其子目录）启动的会话。项目 A（preset=high）和项目 B（preset=low）各自独立，互不干扰。

---

## 14. 自进化模式库 {#pattern-evolution}

**自进化模式库**（PatternEvolution）是 ClawSentry 的可选增强功能。它从实际观察到的攻击尝试中自动提炼新的检测模式，经信心评分和状态机晋升后成为 L1 规则库的补充。

!!! warning "默认关闭"
    自进化模式库默认未启用（`CS_EVOLVING_ENABLED=false`）。需明确设置 `CS_EVOLVING_ENABLED=true` 并配置持久化路径后才生效。

### 模式生命周期

```mermaid
stateDiagram-v2
    [*] --> candidate: 从高可信 D6 事件提炼
    candidate --> testing: 累积足够样本
    testing --> active: 信心分 >= 0.8
    active --> retired: 误报率上升 / 长期未命中
    testing --> retired: 样本不足 / 信心过低
```

| 状态 | 说明 |
|------|------|
| **candidate** | 初始提炼阶段，尚未进入规则引擎 |
| **testing** | 影子模式运行，收集命中/误报数据 |
| **active** | 已激活，参与 L1 评分（作为额外 D3 模式） |
| **retired** | 已退休，不再使用 |

### 信心评分（0.0–1.0）

信心分由以下因素加权计算：命中频率、精确率（L2/L3 确认为真实威胁的比例）、新鲜度（近期观察权重更高）、覆盖度（跨会话命中更可信）。

### 启用方法

```bash
# .env.clawsentry 或环境变量
CS_EVOLVING_ENABLED=true
CS_EVOLVED_PATTERNS_PATH=/path/to/evolved_patterns.yaml
```

### REST API

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/evolution/patterns` | 列出所有进化模式（含状态和信心分） |
| `POST` | `/evolution/patterns/{id}/retire` | 手动将某个模式退休 |
| `POST` | `/evolution/patterns/{id}/activate` | 手动激活候选模式 |

!!! tip "何时开启？"
    建议系统运行至少 2 周、积累充足事件后再启用，以保证提炼质量。

---

## 15. Fail-safe 原则 {#fail-safe}

ClawSentry 遵循分级别的 fail-safe 策略，确保在系统异常时仍能维持安全基线：

| 风险等级 | 异常时行为 | 原则名称 |
|---------|----------|---------|
| `high` / `critical` | **阻断** — 拒绝执行 | Fail-closed |
| `low` | **放行** — 允许执行 | Fail-open |
| `medium` | **延迟** — 等待人工确认 | Fail-defer |

!!! danger "高危操作永远不会因系统故障而被放行"
    这是 ClawSentry 最核心的安全承诺。即使策略引擎崩溃、LLM 调用超时、数据库不可用，高危操作也会被拦截。

**具体场景：**

| 故障场景 | 低风险事件 | 高风险事件 |
|---------|----------|----------|
| L2 LLM 调用超时 | 使用 L1 结果（ALLOW） | 使用 L1 结果（BLOCK） |
| L3 Agent 执行失败 | 回退到 L2 结果 | 返回 `confidence=0.0`，保守拦截 |
| 策略引擎不可达 | ALLOW（fail-open） | BLOCK（fail-closed） |
| 数据库写入失败 | 正常决策，日志告警 | 正常决策，日志告警 |

---

## 概念关系总览

```mermaid
graph TB
    subgraph "AHP 协议规范"
        CE[CanonicalEvent]
        CD[CanonicalDecision]
        RS[RiskSnapshot]
    end

    subgraph "ClawSentry 实现"
        A1[a3s-code Adapter]
        A2[OpenClaw Adapter]
        L1[L1 PolicyEngine]
        L2[L2 SemanticAnalyzer]
        L3[L3 AgentAnalyzer]
        SE[SessionEnforcementPolicy]
        SR[SessionRegistry]
        SSE[SSE EventBus]
        PA[PostActionAnalyzer]
        TA[TrajectoryAnalyzer]
    end

    subgraph "外部接口"
        W[clawsentry watch]
        UI[Web 仪表板]
        API[REST API]
        LH[Latch Hub]
    end

    A1 -->|归一化| CE
    A2 -->|归一化| CE
    CE --> L1
    L1 -->|计算| RS
    L1 -->|生成| CD
    L1 -->|升级| L2
    L2 -->|升级| L3
    L1 --> SR
    SR --> SE
    CD --> SSE
    CD --> PA
    PA --> SSE
    TA --> SSE
    SSE --> W
    SSE --> UI
    SSE --> LH
    CD --> API
```

---

## 下一步

- [常见问题](faq.md) — 常见疑问解答
- [检测管线配置](../configuration/detection-config.md) — 调整 D1-D6 阈值和安全预设参数
- [策略调优](../configuration/policy-tuning.md) — 精细控制各层判决行为
- [a3s-code 集成指南](../integration/a3s-code.md) — 完整的集成细节
- [L1 规则引擎](../decision-layers/l1-rules.md) — 深入理解三层决策策略配置
- [自定义 L2 分析器](../advanced/custom-analyzer.md) — 扩展语义分析能力
- [自进化模式库](../advanced/pattern-evolution.md) — 自动提炼项目特定检测规则
