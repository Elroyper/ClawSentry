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
| **自动拦截高危操作** | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x: |
| 审计记录 | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| clawsentry watch 监控 | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Web UI 仪表板 | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| DEFER 交互审批 | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x: |
| 集成方式 | Hook 注入 | Hook 配置 | WebSocket | Session 日志监控 |

!!! info "为什么 Codex 不能自动拦截？"
    Codex CLI 目前没有提供原生 hook 机制。ClawSentry 通过监控其 session 日志文件实现实时评估和推荐，建议配合 `--approval-policy untrusted` 使用。

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
        [clawsentry] Detected framework: claude-code
        [clawsentry] Starting gateway...
        INFO: ClawSentry Gateway started on 127.0.0.1:8080

        Web UI: http://127.0.0.1:8080/ui?token=xK7m9p2Q...

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
    clawsentry doctor   # 检查配置、连接、hooks 等 17 项
    ```

    :material-arrow-right: 完整配置和高级用法：[Claude Code 集成指南](../integration/claude-code.md)

=== "a3s-code"

    a3s-code 通过 stdio harness 或 HTTP Transport 接入，**自动拦截**高危操作。

    **前置条件**

    ```bash
    pip install clawsentry
    ```

    ### 一键启动（推荐）

    ```bash
    clawsentry start --framework a3s-code
    ```

    ??? example "终端输出示例"
        ```
        [clawsentry] Detected framework: a3s-code
        [clawsentry] Starting gateway...
        INFO: ClawSentry Supervision Gateway ===
        INFO: UDS path  : /tmp/clawsentry.sock
        INFO: HTTP      : 127.0.0.1:8080
        ```

    ??? note "分步操作（高级用户）"

        **步骤 1：初始化**

        ```bash
        clawsentry init a3s-code
        source .env.clawsentry
        ```

        **步骤 2：配置 a3s-code Hook**

        在 a3s-code 配置文件（`agent.hcl` 或 `settings.json`）中：

        ```hcl
        hooks {
          ahp {
            transport = "stdio"
            program   = "clawsentry-harness"
          }
        }
        ```

        **步骤 3：启动 Gateway**

        ```bash
        clawsentry gateway
        ```

        **步骤 4：运行 a3s-code**

        ```bash
        a3s-code agent --session-id my-session
        ```

        **步骤 5：实时监控（另一终端，可选）**

        ```bash
        clawsentry watch
        ```

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
        [clawsentry] Detected framework: openclaw
        [clawsentry] Starting gateway...
        INFO: OpenClaw  : WS ws://127.0.0.1:18789 (enforcement=ON)
        INFO: openclaw-ws: Connected to OpenClaw Gateway

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

    !!! warning "监控模式"
        Codex 没有原生 Hook 系统。ClawSentry 通过监控 session 日志实现**实时风险评估和推荐**，但**无法自动阻止**操作。建议配合 `--approval-policy untrusted` 使用。

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

        `clawsentry watch` 会实时显示风险评估结果，帮助你决定是否批准 Codex 的操作请求。

    ### 验证

    ```bash
    clawsentry doctor
    ```

    :material-arrow-right: 完整配置和高级用法：[Codex 集成指南](../integration/codex.md)

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
