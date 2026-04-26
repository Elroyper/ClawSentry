---
title: 配置概览
description: ClawSentry 配置来源、优先级、有效配置检查与常见路径
---

# 配置概览

ClawSentry 的配置目标是：**先用一条命令跑起来，再按场景逐步加 LLM、预算、DEFER、部署和 benchmark**。如果你是第一次使用，不需要先读完整环境变量表。

```bash
clawsentry config wizard --non-interactive --framework codex --mode normal --llm-provider none
clawsentry config show --effective
```

`config show --effective` 是排障时最重要的命令：它会展示最终生效值、来源，并对密钥脱敏。

---

## 你应该先选哪条路径？ {#choose-path}

| 目标 | 推荐入口 | 下一步 |
|---|---|---|
| 本地体验 Gateway / Web UI | `--llm-provider none` | [快速开始](../getting-started/quickstart.md) |
| 团队仓库启用 L2 | `llm.provider + token budget` | [团队模板](templates.md#team-maintainer-l2-token-budget) |
| 发布前安全审查 | `mode=strict` + L2/L3 | [LLM 配置](llm-config.md) |
| CI / 安全评测 | `mode=benchmark` | [Benchmark 模式](../operations/benchmark-mode.md) |
| systemd / Docker 常驻 | env file + service validate | [生产部署](../operations/deployment.md) |

---

## 配置来源与优先级 {#precedence}

ClawSentry 会把多个来源合并成一份有效配置。优先级从高到低：

1. 单次命令行参数，例如 `clawsentry start --mode benchmark`
2. 规范化环境变量，例如 `CS_L2_TIMEOUT_MS`
3. 项目配置 `.clawsentry.toml`
4. 内置默认值
5. 旧环境变量别名：仅在没有对应规范化环境变量、也没有项目配置字段时兼容读取

规范化名称永远优先于旧别名。例如同时设置：

```bash
CS_L2_BUDGET_MS=5000      # 旧名
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

[llm]
provider = ""          # openai | anthropic | 留空表示不启用外部 LLM
api_key_env = "CS_LLM_API_KEY"
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

完整模板见：[配置模板](templates.md)。

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

# 验证 LLM provider、模型、L2/L3 可用性
clawsentry test-llm --json

# 验证 service env/template，不修改宿主服务
clawsentry service validate --env-file /etc/clawsentry/gateway.env
```

如果输出与你预期不一致，优先检查：

1. 是否有 shell 环境变量覆盖了 `.clawsentry.toml`
2. 是否同时设置了旧名和新名
3. 是否启用了 token budget 但 limit 仍为 `0`
4. Gateway 是否重启以读取新的环境变量
