---
title: 配置模板
description: 按 L3 延迟容忍度、启用方式、部署周期、严格度与预算选择 ClawSentry 配置
---

# 配置模板

本页按 operator 的真实选择顺序组织模板：先决定是否只观察，还是启用 L2/L3；再决定 L3 延迟、部署周期、严格度、provider 与 token budget。标为 `.clawsentry.toml` 的模板可以直接复制；其中 `[frameworks]` 是框架启用来源，可按你的实际框架替换，再用 `clawsentry config show --effective` 验证最终生效值。

!!! note "`config wizard` 支持交互式和确定性两种路径"
    在本地 TTY 中运行 `clawsentry config wizard --interactive` 会进入 5 步终端向导。模板页仍使用 `--non-interactive`，因为复制命令和 CI 需要稳定、可复现的输出。

```bash
clawsentry config wizard --interactive
clawsentry config show --effective
```

```bash
clawsentry config wizard --non-interactive --framework codex --mode normal --llm-provider none --write-project-config
clawsentry config show --effective
```

## 该选哪个模板？ {#choose-template}

| 你的目标 | L3 延迟容忍度 | 启用方式 | 部署周期 | 推荐模板 |
|---|---:|---|---|---|
| 先验证 Gateway / Web UI / session 分组 | 0 秒 | L1 + 规则语义 | 短测 | [观察优先](#template-observe-first) |
| 团队仓库要看语义风险但控制成本 | 低；只接受 L2 provider 延迟 | L2 + token budget | 持久 | [L2 预算模板](#template-l2-budgeted) |
| 安全敏感仓库，愿意为 high/critical 事件等待审查 | 中高；L3 可 10s+ | L2 + 同步 L3 | 持久 / 发布前 | [严格 L3 模板](#template-l3-strict) |
| 只想对高风险 session 做事后复盘 | 与实时判决解耦 | L3 advisory full-review | 短测或值守 | [咨询审查模板](#template-advisory-review) |
| CI、benchmark、安全评测 | 不等待人工 | benchmark deterministic | 短测 | [Benchmark 模板](#template-benchmark) |
| 生产常驻 | 按团队 SLA | 显式 provider / budget / DB | 持久 | [生产环境变量骨架](#template-production-env) |
| a3s-code 录屏 demo | 中；展示实时阻断 + L3 复盘 | L2 + L3 | 短测 | [a3s_demo 脱敏模板](#template-a3s-demo) |

```bash
clawsentry config wizard --non-interactive --framework codex --mode normal --llm-provider none --write-project-config
clawsentry config show --effective
```

## a3s_demo 脱敏模板：录屏/联调专用 {#template-a3s-demo}

`demostation_projects/a3s_demo/.clawsentry.toml.example` 是 allowlisted demo 模板：它只包含 runtime-effective 项目配置字段，密钥只通过 `api_key_env = "CS_LLM_API_KEY"` 引用，不保存真实 API key。复制后用有效配置命令确认来源：

```bash
cd demostation_projects/a3s_demo
cp .clawsentry.toml.example .clawsentry.toml
clawsentry config show --effective
```

边界：CLI / process env / 显式 `--env-file` 仍优先生效；`features.l3 = true` 只是请求同步 L3，实际参与还取决于 provider、模型、预算和 runtime 能力。

```toml title="demostation_projects/a3s_demo/.clawsentry.toml.example"
[project]
enabled = true
mode = "normal"
preset = "high"

[frameworks]
enabled = ["codex"]
default = "codex"

[llm]
provider = "openai"
api_key_env = "CS_LLM_API_KEY"
model = "gpt-4o-mini"
base_url = ""

[features]
l2 = true
l3 = true
enterprise = false

[budgets]
llm_token_budget_enabled = true
llm_daily_token_budget = 200000
llm_token_budget_scope = "total"
l2_timeout_ms = 60000
l3_timeout_ms = 300000
hard_timeout_ms = 600000
```

---

## 观察优先：先跑起来，不接外部 LLM {#template-observe-first}
<span id="individual-developer"></span>

适合第一次体验 Gateway、Web UI、审计记录、Framework/Workspace/Session 分组和 L1 规则。无 provider 成本；L2 仍可通过内置规则语义做有限增强，但不会联网。

```toml title=".clawsentry.toml"
[project]
enabled = true
mode = "normal"
preset = "medium"

[frameworks]
enabled = ["codex"]
default = "codex"

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

```bash title="验证"
clawsentry config show --effective
clawsentry start --framework codex --open-browser
curl -H "Authorization: Bearer $CS_AUTH_TOKEN" http://127.0.0.1:8080/report/summary
```

你应该看到 Web UI token、Runtime Feed、Session 列表和 L1 风险分；不会看到 provider token usage。

---

## 团队语义分析：L2 + token budget {#template-l2-budgeted}
<span id="team-l2-budgeted"></span>
<span id="team-maintainer-l2-token-budget"></span>

适合团队共享仓库：开启 L2 语义分析，但用真实 provider usage 的每日 token 上限控制成本。密钥只放环境变量，不写入 `.clawsentry.toml`。

```toml title=".clawsentry.toml"
[project]
enabled = true
mode = "normal"
preset = "high"

[frameworks]
enabled = ["codex"]
default = "codex"

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

```bash title=".clawsentry.env.local（不要提交）"
CS_LLM_API_KEY=sk-...
```

```bash title="验证"
clawsentry config show --effective --env-file .clawsentry.env.local
clawsentry test-llm --env-file .clawsentry.env.local --json
```

你应该看到 provider、model、token budget 的来源；密钥只显示脱敏值。Dashboard / Session Detail 会优先展示 `session_risk_ewma`、`latest_composite_score` 与 L2/L3 运行态字段（如果存在）。

---

## 严格实时审查：L2 + 同步 L3 {#template-l3-strict}
<span id="strict-l3-review"></span>

适合敏感仓库、发布前窗口或需要在 high/critical 事件上做同步深度审查的团队。L3 会读取有界上下文并使用只读工具，多轮模式可能带来 10s+ 延迟；上线前请先在小仓库试运行。

```toml title=".clawsentry.toml"
[project]
enabled = true
mode = "strict"
preset = "strict"

[frameworks]
enabled = ["claude-code"]
default = "claude-code"

[llm]
provider = "anthropic"
api_key_env = "CS_LLM_API_KEY"
model = "claude-3-5-sonnet-latest"
base_url = ""

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

```bash
export CS_LLM_API_KEY=sk-...
clawsentry test-llm --json
clawsentry start --framework claude-code --interactive --open-browser
```

运营判断：

| 读数 | 说明 |
|---|---|
| `l3_state=completed` | 同步 L3 已实际参与本次高风险事件审查 |
| `l3_reason_code=local_l3_unavailable` | 配置请求 L3，但 runtime 没有可用 L3 能力；实际会回退到可用层级 |
| `budget_exhaustion_event` | token/time budget 用尽，结果需要按降级语义阅读 |

---

## 咨询审查：只读 full-review，不改历史判决 {#template-advisory-review}

适合只想对高风险 session 做 operator-triggered 复盘的团队。它冻结一段证据、排队/运行 advisory job、生成 review；`advisory_only=true`，不会修改已经发生的 allow/block/defer 判决。

```bash
# 同步 L3 可不开；先启动 Gateway / Web UI
clawsentry start --framework codex --open-browser

# 对已记录 session 发起咨询审查
clawsentry l3 full-review --session sess-001 --token "$CS_AUTH_TOKEN"

# 或只排队，交给后续 worker 有界执行
clawsentry l3 full-review --session sess-001 --queue-only --json
clawsentry l3 jobs run-next --runner deterministic_local --json
```

如需 heartbeat / idle aggregate queueing：

```bash
CS_L3_ADVISORY_ASYNC_ENABLED=true
CS_L3_HEARTBEAT_REVIEW_ENABLED=true
```

边界：不启动后台 daemon，不自动联网，不重写 canonical decision。完整说明见 [L3 咨询审查](../decision-layers/l3-advisory.md)。

---

## CI / benchmark：无人值守且可审计 {#template-benchmark}
<span id="ci-benchmark-operator"></span>

适合只想对高风险 session 做 operator-triggered 复盘的团队。它冻结一段证据、排队/运行 advisory job、生成 review；`advisory_only=true`，不会修改已经发生的 allow/block/defer 判决。

```bash
# 同步 L3 可不开；先启动 Gateway / Web UI
clawsentry start --framework codex --open-browser

# 对已记录 session 发起咨询审查
clawsentry l3 full-review --session sess-001 --token "$CS_AUTH_TOKEN"

# 或只排队，交给后续 worker 有界执行
clawsentry l3 full-review --session sess-001 --queue-only --json
clawsentry l3 jobs run-next --runner deterministic_local --json
```

如需 heartbeat / idle aggregate queueing：

```bash
CS_L3_ADVISORY_ASYNC_ENABLED=true
CS_L3_HEARTBEAT_REVIEW_ENABLED=true
```

边界：不启动后台 daemon，不自动联网，不重写 canonical decision。完整说明见 [L3 咨询审查](../decision-layers/l3-advisory.md)。

---

## CI / benchmark：无人值守且可审计 {#template-benchmark}
<span id="ci-benchmark-operator"></span>

适合只想对高风险 session 做 operator-triggered 复盘的团队。它冻结一段证据、排队/运行 advisory job、生成 review；`advisory_only=true`，不会修改已经发生的 allow/block/defer 判决。

```bash
# 同步 L3 可不开；先启动 Gateway / Web UI
clawsentry start --framework codex --open-browser

# 对已记录 session 发起咨询审查
clawsentry l3 full-review --session sess-001 --token "$CS_AUTH_TOKEN"

# 或只排队，交给后续 worker 有界执行
clawsentry l3 full-review --session sess-001 --queue-only --json
clawsentry l3 jobs run-next --runner deterministic_local --json
```

如需 heartbeat / idle aggregate queueing：

```bash
CS_L3_ADVISORY_ASYNC_ENABLED=true
CS_L3_HEARTBEAT_REVIEW_ENABLED=true
```

边界：不启动后台 daemon，不自动联网，不重写 canonical decision。完整说明见 [L3 咨询审查](../decision-layers/l3-advisory.md)。

---

## CI / benchmark：无人值守且可审计 {#template-benchmark}
<span id="ci-benchmark-operator"></span>

**何时使用：** 自动化评测、安全 benchmark、CI smoke test。
**你会看到：** 会产生 DEFER 的 pre-action 被确定性转换为 `block`，并在元数据中标记 `auto_resolved=true`。
**边界：** 不要复用正在工作的 `~/.codex`；Codex benchmark 应使用临时 `CODEX_HOME`。

```toml title=".clawsentry.toml"
[project]
enabled = true
mode = "benchmark"
preset = "high"

[frameworks]
enabled = ["codex"]
default = "codex"

[benchmark]
auto_resolve_defer = true
defer_action = "block"
persist_scope = "project"

[features]
l2 = false
l3 = false
enterprise = false

[defer]
bridge_enabled = false
timeout_s = 1
timeout_action = "block"
max_pending = 0
```

```bash title="Codex benchmark 示例"
export CS_CODEX_HOME="$(mktemp -d)"
clawsentry benchmark env --framework codex --mode guarded > .clawsentry.benchmark.env
clawsentry benchmark enable --dir . --framework codex --codex-home "$CS_CODEX_HOME"
clawsentry benchmark run --dir . --framework codex --codex-home "$CS_CODEX_HOME" -- \
  bash benchmarks/scripts/skills_safety_bench_codex.sh
clawsentry benchmark disable --dir . --framework codex --codex-home "$CS_CODEX_HOME"
```

## E. 生产部署：环境变量骨架 {#production-env}

## 生产部署：环境变量骨架 {#template-production-env}
<span id="production-env"></span>

生产环境至少设置认证、监听地址、持久化数据库和明确的 LLM/token 策略。是否启用 L3 取决于你的延迟 SLA；如果值守团队只需要复盘，优先使用 L3 advisory。

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

# Optional synchronous L3. Enable only after latency/budget tests.
CS_L3_ENABLED=false

# Optional advisory review queueing. Does not mutate canonical decisions.
CS_L3_ADVISORY_ASYNC_ENABLED=true
```

```bash title="部署前验证"
clawsentry service validate --env-file /etc/clawsentry/gateway.env
clawsentry test-llm --json
```

更多 systemd、launchd、Docker 细节见：[生产部署](../operations/deployment.md)。
