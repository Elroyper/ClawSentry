# Kimi CLI 集成

!!! tip "支持范围"
    Kimi CLI 通过 **native `[[hooks]]`** 接入 ClawSentry。Phase 1 目标是强 pre-tool / prompt 阻断和广泛生命周期观察：`PreToolUse`、`UserPromptSubmit`、`Stop` 同步调用 Gateway；post-tool、session、subagent、compact、notification hooks 使用 async 观察。Kimi 原生 hook 不支持 ClawSentry 的 `modify` / `defer` transport parity，因此文档和诊断都不会把它宣传成 `a3s-code` AHP 等价路径。

## 安装与初始化

Kimi 默认读取 `$KIMI_SHARE_DIR/config.toml`；未设置时读取 `~/.kimi/config.toml`。ClawSentry 只管理包含 `clawsentry harness --framework kimi-cli` marker 的 hook blocks，保留用户自己的 `[[hooks]]` 和其他 TOML 设置。

```bash
clawsentry init kimi-cli
clawsentry init kimi-cli --setup --dry-run
clawsentry init kimi-cli --setup
clawsentry gateway
kimi --help
```

安全预览或隔离测试时，显式传入 Kimi share/config 目录：

```bash
export KIMI_SHARE_DIR=/tmp/kimi-clawsentry-smoke
clawsentry init kimi-cli --setup --dry-run --kimi-home "$KIMI_SHARE_DIR"
clawsentry init kimi-cli --setup --kimi-home "$KIMI_SHARE_DIR"
```

## Hook 覆盖范围

| Kimi hook | ClawSentry 命令 | 支持语义 | 适合用途 |
|---|---|---|---|
| `PreToolUse` | `clawsentry harness --framework kimi-cli` | allow / deny | 工具执行前阻断高危 shell、文件或外部调用 |
| `UserPromptSubmit` | `clawsentry harness --framework kimi-cli` | allow / deny | prompt 注入或敏感请求进入模型前阻断 |
| `Stop` | `clawsentry harness --framework kimi-cli` | allow / deny；无完整 continuation parity | 会话结束前的同步 gate |
| `PostToolUse` / `PostToolUseFailure` | `clawsentry harness --framework kimi-cli --async` | observation only | 工具结果与失败审计；不能撤销副作用 |
| `SessionStart` / `SessionEnd` | `clawsentry harness --framework kimi-cli --async` | observation only | 会话边界审计 |
| `SubagentStart` / `SubagentStop` | `clawsentry harness --framework kimi-cli --async` | observation only | 子代理生命周期审计 |
| `PreCompact` / `PostCompact` | `clawsentry harness --framework kimi-cli --async` | observation only | 压缩前后上下文风险观察 |
| `Notification` | `clawsentry harness --framework kimi-cli --async` | observation only | 通知事件审计 |

Gateway 不可达、fallback policy 生效，或 harness 进程本身启动失败时，Kimi native hooks 默认 fail-open，避免把开发工作流整体卡死。同步 gate 返回 Kimi 支持的 `hookSpecificOutput.permissionDecision = "deny"`；`defer` 会退化为 deny，`modify` 不会改写 Kimi tool input，并会被记录为 degraded adapter effect（如 Gateway 提供 decision effects）。

## Shell tool 规范化

Kimi 的工具名会保留在 payload 中，同时对已知 shell aliases 规范化为 policy-facing `bash`，以复用现有 shell 风险评分与 `rm -rf` / `sudo` 等策略：

- `payload.tool_name`: `bash`
- `payload.kimi_tool_name`: 原始 Kimi 工具名，例如 `Shell`
- `payload._clawsentry_meta.raw_tool_name`: 原始工具名
- `payload._clawsentry_meta.kimi_effect_capability`: `native_allow_block_only`

## 真实 E2E 验证

2026-04-29 的发布验证在隔离 `KIMI_SHARE_DIR` 与临时 Gateway socket 下跑过真实 Kimi CLI / Kimi k2.5 端到端 smoke：

- 普通 prompt allow：模型返回预期响应。
- `UserPromptSubmit` deny：ClawSentry 返回 `permissionDecision=deny`，Kimi 在进入模型前停止。
- 安全 Shell allow：Kimi 触发 `PreToolUse`，命令允许执行，并触发 `PostToolUse` 观察事件。
- 危险 Shell deny：Kimi 尝试执行 `rm -rf ...` 时，ClawSentry 在 `PreToolUse` 返回 deny，命令未执行。
- 卸载 smoke：`clawsentry init kimi-cli --uninstall` 后只移除 ClawSentry marker-managed hooks，保留 Kimi provider/model 与其他配置。

这证明的是 Kimi native hook allow/block 与观察面可用；仍不代表 native `modify` 或 true `defer` parity。

## 诊断

```bash
clawsentry integrations status --json
clawsentry start --framework kimi-cli --no-watch
```

`integrations status` 会报告：

- `kimi_cli_config_path` / `kimi_cli_config_present`：当前诊断到的 Kimi `config.toml`。
- `kimi_cli_hooks`：是否找到 ClawSentry marker-managed hook entries。
- `framework_readiness.kimi-cli.checks.native_modify_supported = false`。
- `framework_readiness.kimi-cli.checks.native_defer_supported = false`。

## 卸载

只移除 ClawSentry managed `[[hooks]]` blocks，保留用户自己的 Kimi hooks 和其他 TOML 设置：

```bash
clawsentry init kimi-cli --uninstall
clawsentry init kimi-cli --uninstall --kimi-home /tmp/kimi-clawsentry-smoke
```

## 边界声明

- 不 patch Kimi internals；Phase 1 只使用公开 config hook surface。
- 不声明 `a3s-code` AHP transport parity；`a3s-code` 仍是 explicit SDK transport reference path。
- Kimi post/session/subagent/compact/notification hooks 是观察面，不提供 side-effect rollback。
- 生产前仍建议在目标环境隔离 `KIMI_SHARE_DIR` 下跑真实 hook smoke，确认本机 Kimi 版本、网络与 provider 配置仍接受 `permissionDecision=deny`。
