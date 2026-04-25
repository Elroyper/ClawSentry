# Gemini CLI 集成

!!! success "当前成熟度：real-cli-hook-supported / real-beforetool-block-supported"
    2026-04-25 的真实 Gemini CLI 0.25.0 smoke 已证明：在临时 `HOME`、临时 `GEMINI_CLI_HOME`、临时 workdir 和临时 `.gemini/settings.json` 中，真实 `gemini` 进程会执行 ClawSentry managed hooks，已观测到 `SessionStart`、`BeforeAgent`、`BeforeModel`、`BeforeTool`、`AfterTool`。

    使用用户授权的 Gemini relay（`GOOGLE_GEMINI_BASE_URL` 指向 server root，模型 `gemini-2.5-flash`）已验证真实 `BeforeTool` deny：Gemini 的 `run_shell_command` 会在适配层保留 raw tool 名，同时规范化为 ClawSentry policy tool `bash`，从而触发 `rm -rf` 阻断。不要把 Kimi / OpenAI-compatible endpoint 直接宣传为 Gemini CLI 可用；如需 Kimi，后续应单独做 Google-GenAI-compatible proxy/adapter spike。

## 安装与初始化

默认 setup 只写项目级 `.gemini/settings.json`，不会修改真实用户 `~/.gemini`：

```bash
clawsentry init gemini-cli
clawsentry init gemini-cli --setup --dry-run
clawsentry init gemini-cli --setup
source .env.clawsentry
clawsentry gateway
gemini --prompt "say hello"
```

如确实需要写某个用户级 Gemini 配置目录，必须显式传入路径：

```bash
clawsentry init gemini-cli --setup --gemini-home /tmp/safe-gemini-home
```

## Hook 覆盖范围

| Gemini hook | ClawSentry 命令 | 支持语义 | 当前证据 |
|---|---|---|---|
| `SessionStart` / `SessionEnd` | `clawsentry harness --framework gemini-cli --async` | 生命周期观察 / advisory | `SessionStart` 真实 CLI smoke 已通过 |
| `BeforeAgent` | `clawsentry harness --framework gemini-cli` | prompt 前置 gate / context 修改 | 真实 CLI smoke 已通过 |
| `BeforeModel` | `clawsentry harness --framework gemini-cli` | model request gate / 修改 | 真实 CLI smoke 已通过 |
| `AfterAgent` / `AfterModel` | `clawsentry harness --framework gemini-cli` | response review / containment | fixture + harness supported |
| `BeforeTool` | `clawsentry harness --framework gemini-cli` | tool preflight deny / rewrite | fixture + harness supported；真实 provider deny smoke 已通过 |
| `AfterTool` | `clawsentry harness --framework gemini-cli` | result review；不能撤销副作用 | 真实 provider tool-path smoke 已观测；fixture + harness supported |
| `BeforeToolSelection` | `clawsentry harness --framework gemini-cli --async` | partial / degraded tool-selection advisory | fixture supported |
| `PreCompress` / `Notification` | `clawsentry harness --framework gemini-cli --async` | advisory observation | fixture supported |

Gateway 不可达、fallback policy 生效，或 `clawsentry harness` 进程本身启动失败时，Gemini native hook 默认 fail-open，避免把开发工作流整体卡死。安装器生成的 managed command 会把 hook 诊断写入 `CS_HARNESS_DIAG_LOG`（未设置时丢弃），避免 Gemini CLI 把普通 stderr 文本误解析成 hook 输出。

## Gemini shell tool 规范化

真实 Gemini CLI 在 shell 执行前会把工具名上报为 `run_shell_command`。ClawSentry 在 Gemini adapter 中将已知 shell aliases 规范化为 policy-facing `bash`，并在 payload 中保留原始字段：

- `payload.tool_name`: `bash`
- `payload.gemini_tool_name`: `run_shell_command`
- `payload._clawsentry_meta.raw_tool_name`: `run_shell_command`

这样既不会丢失 Gemini 原始审计信息，又能复用已有的 shell 风险评分、`rm -rf`/`sudo` 等阻断规则。

## 诊断

```bash
clawsentry integrations status --json
clawsentry doctor
```

`doctor` 会检查：

- `GEMINI_CONFIG`：`CS_AUTH_TOKEN`、`CS_GEMINI_HOOKS_ENABLED` 等项目 env 是否齐全。
- `GEMINI_NATIVE_HOOKS`：`.gemini/settings.json` 是否启用 hooks，并包含 ClawSentry managed sync/async hook 形态。

## 卸载

只移除 ClawSentry managed entries，保留用户自己的 Gemini hooks 和其他设置：

```bash
clawsentry init gemini-cli --uninstall
```
