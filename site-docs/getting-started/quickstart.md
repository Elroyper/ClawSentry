---
title: 快速开始
description: 5 分钟内启动 ClawSentry 并对接 AI Agent 框架
---

# 快速开始

选择你使用的 AI 框架，跟随步骤在 5 分钟内完成接入。

## 框架能力对比

| 能力 | Claude Code | a3s-code | OpenClaw | Codex |
|------|:-----------:|:--------:|:--------:|:-----:|
| 实时风险评估 | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| **自动拦截高危操作** | :white_check_mark: | :white_check_mark: | :white_check_mark: | 默认 :x:；可选 `PreToolUse(Bash)` |
| 审计记录 | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| clawsentry watch 监控 | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Web UI 仪表板 | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| DEFER 交互审批 | :white_check_mark: | :white_check_mark: | :white_check_mark: | 默认 :x:；native hook 可返回 host deny |
| 集成方式 | Hook 注入 | 显式 AHP Transport | WebSocket | Session 日志监控 + 可选 managed native hooks |

!!! info "为什么 Codex 默认仍按监控模式使用？"
    ClawSentry 默认通过监控 Codex session 日志实现实时评估和推荐。当前版本可用 `clawsentry init codex --setup` 非破坏式安装 managed native hooks，并已验证 `PreToolUse(Bash)` 可经 Gateway 返回 host deny；其他 native events 仍是异步观察，生产上建议继续配合 `--approval-policy untrusted` 使用。

## 第一次打开 Web UI，先看什么？

如果你刚打开 `http://127.0.0.1:8080/ui?token=...`，先不要把它当成“图表页”，而要把它当成**安全监控台**：

- **Dashboard**：先回答“现在哪一类框架、哪一个工作空间最值得看”
- **Sessions**：再回答“同一框架下哪些 workspace 和 session 正在运行，哪些已经变危险”
- **Session Detail**：最后回答“这个 session 为什么危险，它具体发生了什么”

理解这三个层级最重要：

- **Framework**：Claude Code / a3s-code / OpenClaw / Codex 这类运行时来源
- **Workspace**：某个具体项目目录或工作区，例如 `/workspace/repo-alpha`
- **Session**：该工作区中的某一次具体 Agent 会话

:material-lightbulb-outline: 最简单的使用顺序可以记成：

```text
Dashboard -> Sessions -> Session Detail
```

- 如果你只盯一个框架，先找最危险的 workspace
- 如果你同时盯多个框架，先找当前风险最高的 framework

:material-arrow-right: 如果你想先把这个使用模型看懂，再看页面细节，直接读：[Web 安全仪表板说明](../dashboard/index.md)

---

## 接入步骤

=== "Claude Code"

    Claude Code 通过原生 Hook 系统接入，**自动拦截**高危操作。

    **前置条件**

    ```bash
    pip install clawsentry
    claude --version      # 确认 Claude Code 已安装
    ```

    ### 一键启动（推荐）

    ```bash
    clawsentry start --framework claude-code
    ```

    自动完成：初始化配置 → 注入 hooks → 启动 Gateway → 显示实时监控。

    ??? example "终端输出示例"
        ```
        ClawSentry starting...
          Framework:  claude-code
          Gateway:    http://127.0.0.1:8080 (background)
          Web UI:     http://127.0.0.1:8080/ui?token=xK7m9p2Q...
          Log file:   /tmp/clawsentry-gateway.log

        Gateway ready. Streaming events...

        ──────────────────────────────────────
        [14:23:05] DECISION  session=my-session
          verdict : ALLOW
          risk    : low
          command : cat README.md
        ──────────────────────────────────────
        ```

    !!! tip "可选参数"
        ```bash
        clawsentry start --framework claude-code --interactive   # 启用 DEFER 交互审批
        clawsentry start --framework claude-code --no-watch      # 仅启动 Gateway
        clawsentry start --framework claude-code --open-browser  # 自动打开 Web UI
        ```

    ??? note "分步操作（高级用户）"

        **步骤 1：初始化**

        ```bash
        clawsentry init claude-code
        ```

        生成 `.env.clawsentry`，自动注入 hooks 到 `~/.claude/settings.json`。

        **步骤 2：启动 Gateway**

        ```bash
        source .env.clawsentry
        clawsentry gateway
        ```

        **步骤 3：使用 Claude Code**

        ```bash
        claude   # hooks 自动生效，工具调用经过 ClawSentry 评估
        ```

        **步骤 4：实时监控（另一终端，可选）**

        ```bash
        clawsentry watch
        clawsentry watch --interactive   # 交互式 DEFER 审批
        ```

        **卸载**

        ```bash
        clawsentry init claude-code --uninstall
        ```

    ### 验证

    ```bash
    clawsentry doctor   # 检查配置、连接、hooks 等诊断项
    ```

    :material-arrow-right: 完整配置和高级用法：[Claude Code 集成指南](../integration/claude-code.md)

=== "a3s-code"

    a3s-code 通过显式 AHP Transport（HTTP / stdio）接入，**自动拦截**高危操作。

    **前置条件**

    ```bash
    pip install clawsentry a3s-code
    ```

    ### 一键启动（推荐）

    ```bash
    clawsentry start --framework a3s-code
    ```

    这条命令负责 ClawSentry 侧的运行环境：初始化/合并项目配置、启动 Gateway、显示实时事件流。

    ### 继续配置 a3s-code Agent

    a3s-code 侧仍需要在你的 Agent 代码中显式设置 `SessionOptions().ahp_transport`，然后运行 Agent 脚本。

    ```python
    from a3s_code import Agent, SessionOptions, StdioTransport

    agent = Agent.create("agent.hcl")
    opts = SessionOptions()
    opts.ahp_transport = StdioTransport(program="clawsentry-harness", args=[])
    session = agent.session(".", opts, permissive=True)
    ```

    如需 HTTP 方式，可改用已验证的 `HttpTransport` 直连 Gateway：

    ```python
    import os
    from a3s_code import Agent, HttpTransport, SessionOptions

    agent = Agent.create("agent.hcl")
    opts = SessionOptions()
    token = os.environ["CS_AUTH_TOKEN"]
    opts.ahp_transport = HttpTransport(
        f"http://127.0.0.1:8080/ahp/a3s?token={token}"
    )
    session = agent.session(".", opts, permissive=True)
    ```

    ??? example "终端输出示例"
        ```
        ClawSentry starting...
          Framework:  a3s-code
          Gateway:    http://127.0.0.1:8080 (background)
          Web UI:     http://127.0.0.1:8080/ui?token=xK7m9p2Q...
          Log file:   /tmp/clawsentry-gateway.log

        Gateway ready. Streaming events...
        ```

    ??? note "分步操作（高级用户）"

        如果你不想使用 `clawsentry start`，可以把它拆成下面几步。`init` 只负责写项目配置，`gateway` 只负责启动服务，`watch` 只负责观察事件。

        **步骤 1：初始化**

        ```bash
        clawsentry init a3s-code
        source .env.clawsentry
        ```

        **步骤 2：启动 Gateway**

        ```bash
        clawsentry gateway
        ```

        **步骤 3：在 Agent 代码中显式配置 AHP Transport 并运行 Agent**

        ```python
        from a3s_code import Agent, SessionOptions, StdioTransport

        agent = Agent.create("agent.hcl")
        opts = SessionOptions()
        opts.ahp_transport = StdioTransport(program="clawsentry-harness", args=[])
        session = agent.session(".", opts, permissive=True)
        ```

        如需 HTTP 方式，可改用已验证的 `HttpTransport` 直连 Gateway：

        ```python
        import os
        from a3s_code import Agent, HttpTransport, SessionOptions

        agent = Agent.create("agent.hcl")
        opts = SessionOptions()
        token = os.environ["CS_AUTH_TOKEN"]
        opts.ahp_transport = HttpTransport(
            f"http://127.0.0.1:8080/ahp/a3s?token={token}"
        )
        session = agent.session(".", opts, permissive=True)
        ```

        运行你的 a3s-code Agent 脚本后，如果你还想单独看事件流，可以在另一终端运行 `clawsentry watch`。

    ### 验证

    ```bash
    clawsentry doctor
    ```

    :material-arrow-right: 完整配置和高级用法：[a3s-code 集成指南](../integration/a3s-code.md)

=== "OpenClaw"

    OpenClaw 通过 WebSocket 实时事件流接入，**自动拦截**高危操作。

    **前置条件**

    ```bash
    pip install "clawsentry[enforcement]"
    # OpenClaw Gateway 已启动（默认端口 18789）
    ```

    ### 一键启动（推荐）

    ```bash
    clawsentry start --framework openclaw
    ```

    ??? example "终端输出示例"
        ```
        ClawSentry starting...
          Framework:  openclaw
          Gateway:    http://127.0.0.1:8080 (background)
          Web UI:     http://127.0.0.1:8080/ui?token=xK7m9p2Q...
          Log file:   /tmp/clawsentry-gateway.log

        Gateway ready. Streaming events...

        ──────────────────────────────────────
        [14:30:22] DECISION  session=demo-session
          verdict : DEFER (awaiting operator)
          risk    : medium
          command : pip install requests
          [A]llow  [D]eny  [S]kip >
        ──────────────────────────────────────
        ```

    ??? note "分步操作（高级用户）"

        **步骤 1：初始化（自动检测 OpenClaw 配置）**

        ```bash
        clawsentry init openclaw --auto-detect --setup
        source .env.clawsentry
        ```

        `--auto-detect` 从 `~/.openclaw/openclaw.json` 读取 Token。
        `--setup` 自动配置 `tools.exec.host = "gateway"`。

        **步骤 2：启动 Gateway**

        ```bash
        clawsentry gateway
        ```

        **步骤 3：运行 OpenClaw**

        ```bash
        openclaw agent --session-id demo-session
        ```

        **步骤 4：交互式审批（另一终端）**

        ```bash
        clawsentry watch --interactive
        ```

    ### 验证

    ```bash
    clawsentry doctor
    ```

    :material-arrow-right: 完整配置和高级用法：[OpenClaw 集成指南](../integration/openclaw.md)

=== "Codex"

    !!! warning "默认监控模式"
        ClawSentry 默认通过监控 Codex session 日志实现**实时风险评估和推荐**。可选的 `clawsentry init codex --setup` 会安装 managed native hooks；当前已测试并做过真实 Gateway daemon smoke 的同步防护范围仅限 `PreToolUse(Bash)`，其他 Codex native events 仍为异步观察/建议。建议配合 `--approval-policy untrusted` 使用。

    **前置条件**

    ```bash
    pip install clawsentry
    ```

    ### 一键启动（推荐）

    ```bash
    clawsentry start --framework codex
    ```

    ??? note "分步操作（高级用户）"

        **步骤 1：初始化**

        ```bash
        clawsentry init codex
        # 可选：安装 managed Codex native hooks
        # PreToolUse(Bash) 同步 preflight；其他 native events best-effort 异步观察
        clawsentry init codex --setup
        source .env.clawsentry
        ```

        **步骤 2：启动 Gateway**

        ```bash
        clawsentry gateway
        ```

        Gateway 启动时自动开始监控 Codex session 日志目录。

        **步骤 3：使用 Codex**

        ```bash
        codex --approval-policy untrusted
        ```

        **步骤 4：查看安全建议（另一终端）**

        ```bash
        clawsentry watch
        ```

        `clawsentry watch` 会实时显示风险评估结果；如果启用了 managed native hooks，`PreToolUse(Bash)` 在 Gateway 判为 block/defer 时可让 Codex host deny 该 Bash 调用。其他 native events 只做异步观察/建议。

    ### 验证

    ```bash
    clawsentry doctor
    ```

    :material-arrow-right: 完整配置和高级用法：[Codex 集成指南](../integration/codex.md)

---

## 多框架并存

同一个项目可以逐个初始化多个框架，ClawSentry 会增量合并 `.env.clawsentry`：

```bash
clawsentry init a3s-code
clawsentry init codex
clawsentry init openclaw --auto-detect --setup --dry-run
clawsentry init openclaw --auto-detect --setup
```

也可以在启动时一次声明要启用的框架：

```bash
clawsentry start --frameworks a3s-code,codex,openclaw --no-watch
```

这条命令除了显示 `Enabled: ...`，还会在启动 banner 里打印每个框架的 `Readiness` 摘要与 `Next actions`。例如，`a3s-code` 会提示仍需人工确认 `SessionOptions.ahp_transport` 是否已经在 agent 代码里接好，`openclaw` 会在宿主配置不完整时直接提醒你改用 `--setup-openclaw`。

合并时不会轮换已有 `CS_AUTH_TOKEN`，也不会改写已有 `CS_FRAMEWORK`；新增框架会记录到 `CS_ENABLED_FRAMEWORKS`：

```ini
CS_FRAMEWORK=a3s-code
CS_ENABLED_FRAMEWORKS=a3s-code,codex,openclaw
CS_CODEX_WATCH_ENABLED=true
OPENCLAW_ENFORCEMENT_ENABLED=true
```

!!! tip "OpenClaw 可恢复"
    OpenClaw 外部配置修改是显式 opt-in：`clawsentry init openclaw` 和 `clawsentry start --frameworks ...` 默认不会改 `~/.openclaw/`。`clawsentry init openclaw --setup` 修改 OpenClaw 配置前会创建 `.bak` 备份。需要回退时运行：
    ```bash
    clawsentry init openclaw --restore --dry-run
    clawsentry init openclaw --restore
    ```

如需只禁用其中一个框架，使用同一个 `init` 入口的 `--uninstall`，不会删除整个 `.env.clawsentry` 或影响其他已启用框架：

```bash
clawsentry init codex --uninstall
clawsentry init claude-code --uninstall
clawsentry init openclaw --uninstall
```

查看当前项目集成状态：

```bash
clawsentry integrations status
```

如果你需要脚本化检查或想看更细的排障线索，使用：

```bash
clawsentry integrations status --json
```

其中 `framework_readiness` 会按框架给出 `status / summary / checks / warnings / next_step`，适合 CI、自检脚本和 release 前人工复核。

---

## 项目级安全配置

ClawSentry 提供 4 个内置安全预设，通过一行命令切换，无需手动配置环境变量。

**快速切换预设：**

```bash
clawsentry config init --preset high    # 在当前项目创建 .clawsentry.toml
clawsentry config set strict            # 切换预设
clawsentry config show                  # 查看当前配置及生效参数
clawsentry config disable               # 临时禁用项目配置（恢复全局默认）
```

| 预设 | 适用场景 | 拦截力度 | DEFER 超时行为 |
|------|---------|---------|--------------|
| `low` | 个人项目、学习 | 宽松，仅拦截最危险操作 | 自动放行 |
| `medium` **(默认)** | 日常开发 | 平衡安全与效率 | 超时拒绝 |
| `high` | 团队项目、敏感数据 | 严格，更多操作触发拦截 | 超时拒绝 |
| `strict` | CI/CD、安全审计 | 最严格，D6 注入检测全力放大 | 超时拒绝 |

!!! info "项目配置文件"
    `clawsentry config init` 在项目根目录生成 `.clawsentry.toml`，Harness 在每次 hook 调用时自动读取（60s TTL 缓存）。不同项目可以有不同预设，互不干扰。

    ```toml title=".clawsentry.toml"
    [project]
    enabled = true
    preset = "high"

    [overrides]
    # 可选：在预设基础上精细覆盖单个参数
    # threshold_critical = 2.0
    ```

    :material-arrow-right: 预设参数全表 + 高级调优：[检测管线配置文档](../configuration/detection-config.md#presets)

---

## 下一步

- [核心概念](concepts.md) — 深入理解 AHP 协议和三层决策模型
- [检测管线配置](../configuration/detection-config.md) — 调整 L1 规则和检测阈值
- [启用 LLM 分析](../configuration/llm-config.md) — 开启 L2/L3 语义分析
- [Latch 移动监控](../integration/latch.md) — 手机端实时审批（可选）
- [常见问题](faq.md)
