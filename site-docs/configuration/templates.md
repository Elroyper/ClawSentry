---
title: 配置模板
description: 面向个人、团队、生产与 benchmark 的 ClawSentry 可复制配置模板
---

# 配置模板

本页给出可以直接复制的 `.clawsentry.toml` 和环境变量模板。建议先从最接近你场景的模板开始，再用 `clawsentry config show --effective` 检查最终生效值。

!!! tip "先用 wizard 生成骨架"
    ```bash
    clawsentry config wizard --non-interactive --framework codex --mode normal --llm-provider none
    clawsentry config show --effective
    ```

---

## 个人开发者：先跑起来，不接 LLM {#individual-developer}

适合第一次体验 Gateway、Web UI、审计记录和 L1 规则。这个模板不会调用外部 LLM，也不会设置 token 预算。

```toml title=".clawsentry.toml"
[project]
enabled = true
mode = "normal"
preset = "medium"

[llm]
provider = ""
api_key_env = "CS_LLM_API_KEY"
model = ""
base_url = ""

[features]
l2 = false
l3 = false
enterprise = false

[budgets]
llm_token_budget_enabled = false
llm_daily_token_budget = 0
llm_token_budget_scope = "total"
l2_timeout_ms = 60000
l3_timeout_ms = 300000
hard_timeout_ms = 600000

[defer]
bridge_enabled = true
timeout_s = 86400
timeout_action = "block"
max_pending = 0
```

验证：

```bash
clawsentry config show --effective
clawsentry start --framework codex --open-browser
```

---

## 团队维护者：L2 + token budget {#team-maintainer-l2-token-budget}

适合团队共享仓库：开启 L2 语义分析，但用真实 provider usage 的 token 上限控制每日预算。密钥不写进 `.clawsentry.toml`，只写环境变量。

```toml title=".clawsentry.toml"
[project]
enabled = true
mode = "normal"
preset = "high"

[llm]
provider = "openai"
api_key_env = "CS_LLM_API_KEY"
model = "gpt-4o-mini"
base_url = ""

[features]
l2 = true
l3 = false
enterprise = false

[budgets]
llm_token_budget_enabled = true
llm_daily_token_budget = 200000
llm_token_budget_scope = "total"
l2_timeout_ms = 60000
l3_timeout_ms = 300000
hard_timeout_ms = 600000

[defer]
bridge_enabled = true
timeout_s = 86400
timeout_action = "block"
max_pending = 0
```

```bash title=".env.clawsentry"
CS_LLM_API_KEY=sk-...
```

检查重点：

```bash
clawsentry config show --effective
clawsentry test-llm --json
```

你应该看到 provider、model、token budget 的来源；密钥只显示脱敏值。

---

## 安全审查：严格模式 + L3 {#strict-l3-review}

适合敏感仓库或发布前审查。L3 会带来更高延迟，建议先在小范围仓库试运行。

```toml title=".clawsentry.toml"
[project]
enabled = true
mode = "strict"
preset = "strict"

[llm]
provider = "anthropic"
api_key_env = "CS_LLM_API_KEY"
model = "claude-3-5-sonnet-latest"

[features]
l2 = true
l3 = true
enterprise = false

[budgets]
llm_token_budget_enabled = true
llm_daily_token_budget = 500000
llm_token_budget_scope = "total"
l2_timeout_ms = 60000
l3_timeout_ms = 300000
hard_timeout_ms = 600000

[defer]
bridge_enabled = true
timeout_s = 86400
timeout_action = "block"
max_pending = 0
```

---

## CI / benchmark：无人值守且可审计 {#ci-benchmark-operator}

Benchmark 模式不会等待人工 DEFER。会产生 DEFER 的 pre-action 默认被确定性转换为 `block`，并在元数据中标记 `auto_resolved=true`。

```toml title=".clawsentry.toml"
[project]
enabled = true
mode = "benchmark"
preset = "high"

[benchmark]
auto_resolve_defer = true
defer_action = "block"
persist_scope = "project"

[defer]
bridge_enabled = false
timeout_s = 1
timeout_action = "block"
max_pending = 0
```

Codex benchmark 必须使用临时 `CODEX_HOME`，避免修改正在使用的 `~/.codex`：

```bash
export CS_CODEX_HOME="$(mktemp -d)"
clawsentry benchmark env --framework codex --mode guarded > .env.clawsentry.benchmark
clawsentry benchmark enable --dir . --framework codex --codex-home "$CS_CODEX_HOME"
clawsentry benchmark run --dir . --framework codex --codex-home "$CS_CODEX_HOME" -- \
  bash benchmarks/scripts/skills_safety_bench_codex.sh
clawsentry benchmark disable --dir . --framework codex --codex-home "$CS_CODEX_HOME"
```

---

## 生产部署：环境变量骨架 {#production-env}

生产环境至少设置认证、监听地址、持久化数据库和明确的 LLM/token 策略。

```bash title="/etc/clawsentry/gateway.env"
CS_AUTH_TOKEN=replace-with-long-random-token
CS_HTTP_HOST=127.0.0.1
CS_HTTP_PORT=8080
CS_TRAJECTORY_DB_PATH=/var/lib/clawsentry/trajectory.db

CS_MODE=normal
CS_L2_TIMEOUT_MS=60000
CS_L3_TIMEOUT_MS=300000
CS_HARD_TIMEOUT_MS=600000
CS_DEFER_TIMEOUT_S=86400
CS_DEFER_TIMEOUT_ACTION=block

CS_LLM_PROVIDER=openai
CS_LLM_MODEL=gpt-4o-mini
CS_LLM_API_KEY=sk-...
CS_LLM_TOKEN_BUDGET_ENABLED=true
CS_LLM_DAILY_TOKEN_BUDGET=500000
CS_LLM_TOKEN_BUDGET_SCOPE=total
```

部署前验证：

```bash
clawsentry service validate --env-file /etc/clawsentry/gateway.env
```

更多 systemd、launchd、Docker 细节见：[生产部署](../operations/deployment.md)。
