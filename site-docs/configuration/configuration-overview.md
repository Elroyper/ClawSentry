---
title: 配置概览
description: ClawSentry 配置来源、优先级、有效配置检查与常见路径
---

# 配置概览

ClawSentry 的配置模型现在是**严格分层**：项目策略写在可提交的 `.clawsentry.toml`，密钥和本机运行时值只来自进程/部署环境，或一次性显式传入的 env file。`clawsentry init` / `clawsentry start` 不再自动生成或加载 `.env.clawsentry`。

```bash
clawsentry config wizard --interactive
clawsentry config show --effective
```

没有 TTY 或需要 CI 复现时使用确定性参数：

```bash
clawsentry config wizard --non-interactive --framework codex --mode normal --llm-provider none --write-project-config
clawsentry config show --effective
```

`config show --effective` 是排障时最重要的命令：它会展示最终生效值、来源，并对密钥脱敏。若需要本机 secrets/runtime overrides，可显式指定：

```bash
clawsentry config show --effective --env-file .clawsentry.env.local
clawsentry start --env-file .clawsentry.env.local
```

---

## 你应该先选哪条路径？ {#choose-path}

| 目标 | 推荐入口 | 下一步 |
|---|---|---|
| 本地体验 Gateway / Web UI | `clawsentry start --framework <name>` 或 `config wizard --interactive` | [快速开始](../getting-started/quickstart.md) |
| 团队仓库共享安全策略 | 提交 `.clawsentry.toml`，不提交密钥 | [配置模板](templates.md) |
| 本机密钥 / 临时端口 / provider token | shell `export ...` 或 `--env-file .clawsentry.env.local` | [环境变量参考](env-vars.md) |
| CI / 安全评测 | CI env + `.clawsentry.toml` benchmark mode | [Benchmark 模式](../operations/benchmark-mode.md) |
| systemd / Docker 常驻 | deployment env / `EnvironmentFile=` + `service validate --env-file` | [生产部署](../operations/deployment.md) |

---

## 配置来源与优先级 {#precedence}

ClawSentry 会把多个来源合并成一份有效配置。优先级从高到低：

1. **CLI 参数**：例如 `clawsentry start --mode benchmark --port 9100`
2. **进程/部署环境变量**：当前 shell、CI secret、systemd/Docker 注入的 `CS_*`
3. **显式 env file**：只在传入 `--env-file PATH` 或设置 `CLAWSENTRY_ENV_FILE=PATH` 时读取
4. **项目配置 `.clawsentry.toml`**：唯一自动发现的项目配置文件；只放非密钥策略和默认值
5. **白名单旧别名**：迁移兼容，例如 `CS_L2_BUDGET_MS`；只在新字段缺失时读取
6. **内置默认值**

!!! important "不会自动加载 `.env.clawsentry`"
    `.env.clawsentry` 是旧版本地便利文件名。新版本不会在 `start`、`gateway`、`stack` 或 `init` 正常流程中自动发现、自动生成或自动 source 它。若短期迁移必须复用旧文件，请显式传入 `--env-file .env.clawsentry`；命令会标记其来源并把该名称作为 legacy/migration 用法处理。

显式 env file 的解析是**非突变**的：解析阶段返回隔离的 key/value 与来源路径，不会直接写入 `os.environ`。需要兼容旧 runtime 组件时，启动入口只在受控 adapter 内把解析结果合成到子进程环境中。

规范化名称永远优先于旧别名。例如同时设置：

```bash
CS_L2_BUDGET_MS=5000      # 旧名；只作迁移兼容
CS_L2_TIMEOUT_MS=60000    # 新名，生效
```

最终使用 `60000`。`config show --effective` 会把这类情况以 warning 形式展示，方便迁移。

---

## `.clawsentry.toml` 最小结构 {#toml-shape}

```toml title=".clawsentry.toml"
[project]
enabled = true
mode = "normal"        # normal | strict | permissive | benchmark
preset = "medium"

[frameworks]
enabled = ["codex"]    # framework enablement lives here, not in CS_FRAMEWORK/default envs
default = "codex"

[frameworks.codex]
managed_hooks = true

[llm]
provider = ""          # openai | anthropic | 留空表示不启用外部 LLM
api_key_env = "CS_LLM_API_KEY"  # 只引用环境变量名，不保存真实 key
model = ""
base_url = ""

[features]
l2 = false
l3 = false
enterprise = false

[budgets]
llm_token_budget_enabled = false
llm_daily_token_budget = 0       # 启用预算时必须 > 0
llm_token_budget_scope = "total" # total | input | output
l2_timeout_ms = 60000
l3_timeout_ms = 300000
hard_timeout_ms = 600000

[defer]
bridge_enabled = true
timeout_s = 86400
timeout_action = "block"
max_pending = 0

[benchmark]
auto_resolve_defer = true
defer_action = "block"
persist_scope = "project"
```

`.clawsentry.toml` 可提交到仓库；不要在其中写入 `CS_AUTH_TOKEN`、provider API key、OpenClaw operator token 或任何真实 secret。

---

## 本机 env file：显式、非自动、可替换 {#explicit-env-file}

如果你不想把本机密钥写进 shell profile，可以创建一个未提交的文件，例如 `.clawsentry.env.local`：

```bash title=".clawsentry.env.local"
CS_AUTH_TOKEN=dev-only-token
CS_LLM_PROVIDER=openai
CS_LLM_API_KEY=sk-...
CS_HTTP_PORT=9100
```

然后显式使用：

```bash
clawsentry start --env-file .clawsentry.env.local
clawsentry test-llm --env-file .clawsentry.env.local --json
clawsentry config show --effective --env-file .clawsentry.env.local
```

进程环境变量优先于 env file，因此 CI/CD、Docker secrets、systemd `Environment=` 仍能覆盖本地文件中的值。

---

## Fresh local start 与 auth token {#ephemeral-token}

本地首次运行可以不提供 `CS_AUTH_TOKEN`：

```bash
clawsentry start --framework codex
```

没有 token 时，`start` 会生成**仅本次进程内有效**的临时 `CS_AUTH_TOKEN`，用于启动 banner 中的 Web UI URL 和子进程环境。它不会写入 `.clawsentry.toml`，也不会更新 `.clawsentry.toml`。需要固定 token 时请使用：

```bash
export CS_AUTH_TOKEN='your-dev-token'
# 或
clawsentry start --env-file .clawsentry.env.local
```

---

## Framework enablement {#frameworks}

框架启用状态保存在 `.clawsentry.toml [frameworks]`：

```toml
[frameworks]
enabled = ["a3s-code", "codex", "openclaw"]
default = "codex"
```

`CS_FRAMEWORK` 与 `CS_ENABLED_FRAMEWORKS` 现在仅用于迁移旧脚本或底层 harness 默认值；它们不是 `start`/`init` 的正常 source of truth。运行：

```bash
clawsentry integrations status
```

可查看 `.clawsentry.toml` 中启用的框架和需要人工处理的 framework-side 设置。

---

## Token budget：按真实 token 用量执法 {#token-budget}

预算配置使用 provider 返回的真实 usage，而不是硬编码美元估算。

```bash
CS_LLM_TOKEN_BUDGET_ENABLED=true
CS_LLM_DAILY_TOKEN_BUDGET=200000
CS_LLM_TOKEN_BUDGET_SCOPE=total
```

规则：

- `enabled=false`：不执法，`llm_daily_token_budget=0` 表示未设置上限
- `enabled=true`：`llm_daily_token_budget` 必须大于 `0`
- provider 没有返回 usage 时，不会伪造 token；系统会记录 unknown usage，便于排查
- `CS_LLM_DAILY_BUDGET_USD` 只作为旧配置兼容/估算展示，不再作为推荐执法路径

---

## 常用检查命令 {#checks}

```bash
# 查看最终生效配置、来源、脱敏密钥
clawsentry config show --effective
clawsentry config show --effective --env-file .clawsentry.env.local

# 验证 LLM provider、模型、L2/L3 可用性
clawsentry test-llm --env-file .clawsentry.env.local --json

# 验证 service env/template，不修改宿主服务
clawsentry service validate --env-file /etc/clawsentry/gateway.env
```

如果输出与你预期不一致，优先检查：

1. 是否有 CLI 参数或 shell/部署环境变量覆盖了 env file / `.clawsentry.toml`
2. 是否忘记显式传入 `--env-file` 或 `CLAWSENTRY_ENV_FILE`
3. 是否同时设置了旧名和新名
4. 是否启用了 token budget 但 limit 仍为 `0`
5. Gateway 是否重启以读取新的环境变量或项目配置
