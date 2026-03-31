# Changelog

本文件记录 ClawSentry 各版本的重要变更。格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。

## [Unreleased]

---

## [0.3.1] — 2026-03-31

### 修复

#### P0+P1 审查修复（9 commits, +25 tests）

- **Hub Bridge 异步化 (P0-1)**：`LatchHubBridge._hub_request` 从同步 `urllib.request` 改为 `run_in_executor`，不再阻塞 Gateway 事件循环
- **server.py 拆分 (P0-2)**：提取 `TrajectoryStore` / `SessionRegistry` / `EventBus` / `AlertRegistry` 为独立模块，server.py 从 2580→1734 行
- **文档修正 (P0-3)**：修复 `site-docs/` 中 6 项文档-代码不一致 — `AHP_LLM_*` → `CS_LLM_*`、`settings.local.json` → `settings.json`、`watch --port` → `--gateway-url`、`gateway --setup` → `init openclaw --setup`、`.env` → `.env.clawsentry`、FAQ 保留期 7→30 天
- **L2→L3 递进分析 (P1-1)**：`CompositeAnalyzer` 改为顺序执行 — L2 先行，仅当 L2 信心 < 0.8 或风险 < HIGH 时触发 L3，节省不必要的 LLM 调用
- **Post-action 异步 (P1-2)**：后置分析改为 `asyncio.create_task` fire-and-forget，不阻塞请求返回
- **L2 线程池共享 (P1-3)**：`L1PolicyEngine` 共享 `ThreadPoolExecutor(max_workers=2)`，不再每次 L2 分析创建新线程池
- **Regex 转义重写 (P1-4)**：`_sanitize_for_regex` 改用 marker-based 方法，先替换为占位符→ re.escape 全文→恢复 regex 片段，修复原逻辑 regex 损坏问题
- **DEFER 队列上限 (P1-5)**：`DeferManager` 新增 `max_pending` 参数（默认 100），队列满时拒绝新 DEFER 并回退为 BLOCK，防止无限堆积
- **Hub Bridge 初始化修复 (P1-6)**：`LatchHubBridge.__init__` 正确初始化 `_sub_id` / `_source_queue`，移除未使用的 `_queue` 属性

### 测试覆盖

- 测试总量：2144 → 2169（+25 tests, 0 regressions）

---

## [0.3.0] — 2026-03-31

### 新增

#### Prometheus 可观测性

- **`/metrics` 端点**：Prometheus 格式的指标暴露端点，包含 8 个核心指标：决策计数 (`clawsentry_decisions_total`)、决策延迟 (`clawsentry_decision_latency_seconds`)、风险评分分布 (`clawsentry_risk_score`)、活跃会话 (`clawsentry_active_sessions`)、LLM 调用计数 (`clawsentry_llm_calls_total`)、LLM Token 用量 (`clawsentry_llm_tokens_total`)、LLM 成本估算 (`clawsentry_llm_cost_usd_total`)、DEFER 待处理数 (`clawsentry_defers_pending`)
- **No-op 降级**：`prometheus_client` 为可选依赖 (`pip install clawsentry[metrics]`)，未安装时所有指标操作静默退化为 no-op，零强制依赖
- **`CS_METRICS_AUTH`**：可选启用 `/metrics` 端点的 Bearer token 认证（默认无认证，与 `/health` 同级）

#### LLM 成本追踪

- **`InstrumentedProvider` 包装器**：透明包装 `AnthropicProvider` / `OpenAIProvider`，自动提取每次调用的 token 用量并上报 Prometheus 指标，LLMProvider Protocol 签名完全不变
- **`LLMUsage` dataclass**：`input_tokens` / `output_tokens` / `provider` / `model` 四字段，每次 SDK 调用后存入 provider 的 `_last_usage` 属性
- **成本估算**：基于硬编码参考价格（Anthropic $3/$15, OpenAI $2.5/$10 per M tokens）自动估算并累加到 `clawsentry_llm_cost_usd_total`

#### LLM 每日预算控制

- **`CS_LLM_DAILY_BUDGET_USD`**：设置每日 LLM 花费上限（默认 0 = 不限），超出后自动将 L2/L3 请求降级为 L1-only，decision reason 附加 `[LLM budget exhausted, L1-only]`
- **`LLMBudgetTracker`**：线程安全（`threading.Lock`）的日预算追踪器，UTC 日期自动翻转，首次超预算时广播 SSE 事件

#### 生产部署

- **systemd 服务模板**：`systemd/clawsentry-gateway.service`，含安全加固（NoNewPrivileges / ProtectSystem=strict / ProtectHome / PrivateTmp）
- **Docker Compose 可观测性栈**：Gateway + Prometheus + Grafana 三服务编排，Grafana 数据源自动配置，PromQL 查询参考文档
- **Docker 镜像默认含 Prometheus**：Dockerfile 改为安装 `".[metrics]"`

#### 安装途径

- **Homebrew tap 更新**（实验性）：formula 骨架更新至 v0.3.0，添加 `head` 选项
- **uv tool install**：验证并文档化 `uv tool install clawsentry` 安装路径

### 改进

- Docker Compose 格式升级至 Compose V2（移除已废弃的 `version` 键）
- `[metrics]` 可选依赖组加入 `pyproject.toml`，`[all]` 组包含 metrics
- 安装文档新增 Prometheus 可观测性标签页 + 依赖组表更新
- Homebrew 状态从「建设中」改为「实验性」

### 配置

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CS_METRICS_AUTH` | `false` | 启用 `/metrics` 端点认证 |
| `CS_LLM_DAILY_BUDGET_USD` | `0` | 每日 LLM 预算（0=不限） |
| `CS_PROMETHEUS_PORT` | `9090` | Docker Compose Prometheus 端口 |
| `CS_GRAFANA_PORT` | `3000` | Docker Compose Grafana 端口 |
| `CS_GRAFANA_PASSWORD` | `clawsentry` | Grafana admin 密码 |

### 测试覆盖

- 测试总量：2042 → 2144（+102 tests, 0 regressions）
- 新增：test_metrics.py (23) / test_instrumented_provider.py (26) / test_budget_tracker.py (21) + P2 Mobile UI 32 tests (previously unreleased)

---

## [0.2.9] — 2026-03-30

### 新增

#### DEFER → Operator 审批桥接（P1）

- **DEFER Bridge**：Gateway 的 DEFER 决策现在支持等待操作员实时审批，而非立即返回。当 `defer_bridge_enabled=true`（默认）且事件类型为 `PRE_ACTION` 时，Gateway 会注册一个 `cs-defer-*` 审批 ID、广播 `defer_pending` SSE 事件，并阻塞等待操作员通过 `/ahp/resolve` 端点做出 allow/deny 决定
- **`DecisionSource.OPERATOR`**：新增决策来源枚举值，标记由操作员审批产生的决策（区分于 `POLICY`/`MANUAL`/`SYSTEM`）
- **`/ahp/resolve` DeferManager 支持**：resolve 端点现在优先检查 DeferManager 中的待处理请求（`cs-defer-*` ID），若匹配则直接解决；否则 fallback 到 OpenClaw approval_client，保持向后兼容
- **`defer_pending` / `defer_resolved` SSE 事件**：新增两种 SSE 事件类型，EventBus 默认订阅，Watch CLI 和 Hub 均可接收

#### Latch Hub 事件转发

- **`LatchHubBridge`**：新模块 (`latch/hub_bridge.py`)，订阅 Gateway EventBus 并将事件转发到 Latch Hub CLI session API（`POST /cli/sessions` + `POST /cli/sessions/:id/messages`），支持自动创建 Hub session、HTTP 重试、人类可读消息格式化
- **自动启动**：当 `CS_LATCH_HUB_URL` 或 `CS_LATCH_HUB_PORT` 配置时，`run_stack()` 自动启动 Hub bridge 后台任务

#### Watch CLI 增强

- **DEFER 事件格式化**：`clawsentry watch` 现在显示黄色 `DEFER PENDING`（含工具名、命令、超时、审批 ID）和绿色/红色 `DEFER RESOLVED: ALLOW/BLOCK` 事件

#### Doctor 扩展

- **19 项检查**（从 17 项增加）：新增 `DEFER_BRIDGE`（验证 DEFER 桥接配置）和 `HUB_BRIDGE`（验证 Hub 可达性）两项健康检查

### 配置

- **`CS_DEFER_BRIDGE_ENABLED`**（bool, 默认 `true`）：DEFER 桥接开关，`low` 预设默认关闭
- **`CS_LATCH_HUB_URL`**（string, 默认空）：Hub 基础 URL，设置后启用事件转发
- **`CS_HUB_BRIDGE_ENABLED`**（`auto`/`true`/`false`, 默认 `auto`）：Hub 事件桥接模式
- **`CS_LATCH_HUB_PORT`**（int, 默认 `3006`）：Hub 端口（URL 未设时 fallback）

### 测试覆盖

- 测试总量：1970 → 2042（+72 tests, 0 regressions）

---

## [0.2.8] — 2026-03-30

### 新增

#### 项目级安全配置（E-10）

- **`.clawsentry.toml` 项目配置**：在项目根目录放置 `.clawsentry.toml` 即可自定义安全审核强度，harness 自动读取（60s TTL 缓存），支持 `enabled` 开关和 `preset` 预设等级
- **4 个安全预设等级**：`low`（个人项目/学习）、`medium`（默认/日常开发）、`high`（团队/敏感项目）、`strict`（CI/安全审计），每个预设映射到不同的 `DetectionConfig` 阈值组合
- **`clawsentry config` CLI 命令组**：`config init [--preset]` / `config show` / `config set <preset>` / `config disable` / `config enable`，快速管理项目级配置
- **Gateway per-request 预设应用**：harness 通过 `_clawsentry_meta` 将项目预设信息传递到 Gateway，Gateway 的 `L1PolicyEngine.evaluate()` 支持 `config` 覆盖参数，实现每请求独立的检测配置
- **`clawsentry stop` / `clawsentry status`**：PID 文件管理，一键停止/查询 Gateway 状态
- **`clawsentry start --open-browser`**：启动后自动打开 Web UI

#### Codex Session Watcher

- **Codex Session Watcher**：零侵入实时监控 Codex session JSONL 日志，自动发现 `$CODEX_HOME/sessions/` 下活跃 session 文件，tail 新行 → CodexAdapter 归一化 → Gateway 评估 → SSE 广播
- **`CS_CODEX_WATCH_POLL_INTERVAL` / `CS_CODEX_WATCH_ENABLED`**：可调 watcher 行为的环境变量

### 修复

- **`detect_framework` 检测失败**：修复只检查 `settings.local.json` 的 bug，现在同时检查 `settings.json` 和 `settings.local.json`
- **Claude Code hooks 目标文件**：`clawsentry init claude-code` 改为写入 `~/.claude/settings.json`（而非 `settings.local.json`），避免被项目级配置覆盖
- **Gateway 不可达时阻断所有工具**：当 Gateway UDS 不可达时，harness 的 fallback 决策现在 fail-open（允许），而非 fail-closed 阻断所有 Claude Code 工具调用
- **`--uninstall` 清理遗留**：uninstall 现在同时清理 `settings.json` 和 `settings.local.json` 中的 hooks

### 改进

- **`clawsentry init codex` 更新**：自动检测 Codex session 目录并配置 `CS_CODEX_SESSION_DIR`
- **quickstart.md 重构**：四框架集成路径 + 框架能力对比表 + 项目级配置文档 + uv/Homebrew 安装方式
- **installation.md 更新**：新增 `uv tool install` 和 Homebrew tap 安装标签页，更新 CLI 命令一览表
- **Homebrew formula 骨架**：`homebrew/clawsentry.rb` 模板（待创建 tap 仓库后激活）
- **Harness 诊断日志**：`CS_HARNESS_DIAG_LOG` 环境变量支持

### 测试覆盖

- 测试总量：1760 → 1893（+133 tests, 0 regressions）

---

## [0.2.7] — 2026-03-29

### 修复

#### 安全修复（4 P0）

- **ReDoS 正则退化**：`post_action_analyzer` 中 var-expansion 检测正则含嵌套量词，拆分为两个非嵌套简单模式
- **`--async` 模式 event loop 泄漏**：harness 每条消息创建新 event loop，改为持久 loop + finally 清理
- **异常静默吞没**：`server.py` 策略引擎强制执行路径 bare `except` 未记录异常，补充 `logger.exception()`
- **私有属性直接访问**：`PatternEvolutionManager._enabled` 未暴露公共接口，新增 `@property enabled`

#### 重要修复（11 P1）

- **curl 白名单绕过**：不可见 Unicode 字符可绕过 curl-pipe-shell 安全白名单，改为 raw + normalized 双重检查
- **combining diacritics 绕过**：NFD 组合变音符可避开英文注入模式匹配，新增 Mn 类别字符剥离（保留 U+FE0F emoji VS-16）
- **Codex 端点 fail-open**：Codex HTTP 端点异常时 fallback 为 "continue"（放行），改为 fail-closed "block"
- **Claude Code hooks 覆盖**：`_merge_settings` 直接覆盖已有 hooks，改为追加模式 + 防御性 JSON 解析
- **内存无限增长**：`risk_snapshot` 使用 `list.pop(0)` O(n) 操作且无上限，改为 `deque.popleft()` + 驱逐机制 + `_MAX_CLIENTS`
- **OpenClaw 缺少 content_origin**：OpenClaw normalizer 未注入 `_clawsentry_meta.content_origin`，补充 `infer_content_origin` 调用
- **秘密检测误报**：`pwd` 命令匹配 password 模式、`sk-` / `Bearer` token 模式重复计数，清理去重
- **doctor 弱 token 检测**：新增 `check_auth_weak_value`（14 项检查），检测 "changeme" 等已知弱 token
- **正则+import 修复**：`_BASH_EXTERNAL_RE` 错误匹配、`audit_command` 使用 `__import__`、`--stats --format json` 不支持
- **start 命令硬编码**：框架选项列表硬编码，改为动态读取 `FRAMEWORK_INITIALIZERS.keys()`
- **listen_address 判断风格**：多个 `or` 比较改为 `set` 成员检查

### 改进

- **event_id 生成统一**：提取 `adapters/event_id.py` 共享模块，消除 a3s_adapter / codex_adapter / openclaw_normalizer 三处重复
- **测试基础设施**：新增 `conftest.py` 共享 fixtures（`StubTrajectoryStore` / `skills_dir`），`review_toolkit` 测试 3→31 全方法覆盖
- **test_gateway.py**：消除 `__import__('collections')` 反模式

### 测试覆盖
- 测试总量：1760 → 1792（+32 tests, 0 regressions）

---

## [0.2.6] — 2026-03-29

### 新增

#### 高价值功能（E-8，5 Features）

- **`clawsentry doctor` CLI 命令**：离线配置安全审计，12 项检查（AUTH token 强度/Shannon 熵/UDS 权限/阈值排序/权重边界/LLM 配置/OpenClaw secret/监听地址/白名单正则/L2 预算/数据库路径），输出 PASS/WARN/FAIL 报告，支持 `--json` / `--no-color`，exit code 语义化（0=全 PASS, 1=有 FAIL, 2=仅 WARN）
- **`clawsentry audit` CLI 命令**：离线审计日志查询，只读打开 SQLite trajectory 数据库，支持多维过滤（`--session` / `--since` / `--risk` / `--decision` / `--tool`），三种输出格式（`--format table|json|csv`），`--stats` 聚合统计模式（按风险等级/判决/框架/Top Sessions），参数化 SQL 防注入
- **外部内容安全标记**：自动推断工具调用的内容来源（`external` / `user` / `unknown`），外部内容触发 D6 评分加成（默认 +0.3，`CS_EXTERNAL_CONTENT_D6_BOOST`）和 Post-action 乘数（默认 ×1.3，`CS_EXTERNAL_CONTENT_POST_ACTION_MULTIPLIER`），完全向后兼容
- **D4 工具频率异常检测**：三层滑动窗口速率追踪——突发检测（同工具 ≥10 次/5s → D4=2）、重复滥用（同工具 ≥20 次/60s → D4=1）、整体速率（全工具 ≥60 次/min → D4=1），合并逻辑 `d4 = min(max(accum, freq), 2)`，6 个新 `CS_D4_FREQ_*` 环境变量
- **Docker 生产部署**：多阶段 Dockerfile（python:3.12-slim，非 root 用户 `clawsentry`，healthcheck），docker-compose.yml（SQLite volume + env_file + healthcheck），`.env.example` 模板

#### 新增环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CS_EXTERNAL_CONTENT_D6_BOOST` | `0.3` | 外部内容 D6 加成 |
| `CS_EXTERNAL_CONTENT_POST_ACTION_MULTIPLIER` | `1.3` | 外部内容 Post-action 乘数 |
| `CS_D4_FREQ_ENABLED` | `true` | 启用频率异常检测 |
| `CS_D4_FREQ_BURST_COUNT` | `10` | 突发检测阈值 |
| `CS_D4_FREQ_BURST_WINDOW_S` | `5.0` | 突发检测窗口（秒） |
| `CS_D4_FREQ_REPETITIVE_COUNT` | `20` | 重复滥用阈值 |
| `CS_D4_FREQ_REPETITIVE_WINDOW_S` | `60.0` | 重复滥用窗口（秒） |
| `CS_D4_FREQ_RATE_LIMIT_PER_MIN` | `60` | 整体速率限制 |

#### Claude Code 独立接入（E-9 Phase 1）

- **`clawsentry init claude-code`**：一键生成 `.env.clawsentry` + 智能合并 `~/.claude/settings.local.json` hooks（PreToolUse 阻塞 + PostToolUse/SessionStart/SessionEnd 异步）
- **Harness 双格式自动检测**：JSON-RPC 2.0（a3s-code）+ 原生 hook JSON（Claude Code）自动识别分流
- **`--async` 模式**：非阻塞 hook（PostToolUse/SessionStart 等）后台 dispatch，不阻塞 Agent 主流程
- **Adapter `source_framework` 可配置**：`A3SCodeAdapter(source_framework="claude-code")` 在审计日志中区分不同框架
- **DEFER 超时配置**：`CS_DEFER_TIMEOUT_ACTION`（block/allow）+ `CS_DEFER_TIMEOUT_S`（默认 300s）
- **`--uninstall`**：精确移除 ClawSentry hooks，保留用户其他自定义 hooks

#### Codex 独立接入（E-9 Phase 2）

- **`POST /ahp/codex` HTTP 端点**：简化 JSON 请求格式（hook_type + payload），自动归一化为 CanonicalEvent
- **`CodexAdapter`**：支持 4 种事件类型（function_call → pre_action / function_call_output → post_action / session_meta → session / session_end → session）
- **`clawsentry init codex`**：生成 `.env.clawsentry`（含 `CS_HTTP_PORT`、`CS_AUTH_TOKEN`、`CS_FRAMEWORK=codex`）
- **`clawsentry doctor` Codex 检查**：自动检测 Codex 配置完整性（endpoint URL + auth token）
- **Fail-closed 安全默认**：Codex 端点异常时 fallback 为 block（非 continue）

#### 新增环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CS_DEFER_TIMEOUT_ACTION` | `block` | DEFER 超时行为（block / allow） |
| `CS_DEFER_TIMEOUT_S` | `300` | DEFER 超时秒数 |

### 测试覆盖
- 测试总量：1483 → 1760（+277 tests, 0 regressions）
- E-8 新增：test_doctor_command.py (61) / test_audit_command.py (40) / test_content_origin.py (43) / test_d4_frequency.py (25) / test_docker.py (11)
- E-9 新增：test_claude_code_e2e.py (5) / test_claude_code_initializer.py (12) / test_codex_adapter.py (13) / test_codex_http.py (7) / test_codex_e2e.py (8) / test_codex_initializer.py (8) / test_codex_doctor.py (5) / test_defer_manager.py (5) / test_harness_async.py (17) / test_harness_claude_code_format.py (17)

---

## [0.2.5] — 2026-03-29

### 新增

#### 安全检测能力增强（E-7 Hardening）

- **Unicode 归一化层** (`text_utils.py` 新模块)：393 个不可见 Unicode 码点检测 + NFKC 归一化 + 不可见字符计数，排除 U+FE0F 避免 emoji 误报
- **中文注入检测**：D6 `injection_detector.py` 新增 22 条中文注入模式（6 类：忽略/覆盖/新指令/时间锚定/安全绕过/角色扮演/系统标记/混合中英）
- **混淆检测扩充**：`post_action_analyzer.py` 4→13 模式（base64-pipe/hex-pipe/printf-pipe/eval-decode/curl-pipe/process-sub/heredoc/octal/hex-escape/script-exec/var-expansion/reverse-slice/hex-char）+ curl-pipe-shell 安全域名白名单
- **秘密泄露检测扩充**：新增 OpenAI/GitHub/AWS/Slack/Feishu/Bearer/ETH 7 种 secret 模式（含上下文约束避免误报）
- **危险工具扩充**：`risk_snapshot.py` DANGEROUS_TOOLS 9→56（跨平台：shells/execution/privilege/file-ops/process/macOS/Windows/network/persistence），D3 模式 10→25
- **ReDoS 安全正则编译** (`safe_regex.py` 新模块)：嵌套量词检测（含交替分支）+ `compile_safe_regex()` 门控
- **NFKC 穿透**：`injection_detector` + `post_action_analyzer` 全部检测函数先归一化再匹配

### 修复

#### 审查修复（3-agent Sonnet review → 4 P0 + 17 P1）
- **[P0]** `pattern_matcher.py`：移除 `_detection_match` 中 unsafe `re.search` fallback + `_eval_single_trigger` 中 `elif` 原始正则分支
- **[P0]** `injection_detector.py`：`must/should.*now` 换行绕过修复（`.*` → `[^\n]*`）
- **[P0]** `safe_regex.py`：`[]]` 字符类解析修复（首字符 `]` 不再提前终止解析）
- **[P1]** `injection_detector.py`：`[系统...]` 强模式收紧（需 `提示/指令/命令/消息` 关键词），`data:base64` 限界 `{0,2048}`，新增 `无视` 弱模式，混合模式扩展 `忘记/抛弃`
- **[P1]** `post_action_analyzer.py`：`detect_exfiltration` NFKC 归一化，`_is_safe_curl_pipe` 使用归一化文本，`sk-` 模式添加上下文约束，`var-expansion` 收紧需执行指示符，移除 `ghp_` 重复模式
- **[P1]** `risk_snapshot.py`：`DANGEROUS_TOOLS` 同步到 `_score_d1`（扩展工具 D1=3），`dd` 需设备目标（`of=/dev/`），删除过宽 `rm -f /var/log/` 模式，`iptables` 移除 `-Z`（计数器重置非危险）
- **[P1]** `text_utils` 测试精确化：393 精确计数断言 + 空字符串边界测试
- **[P1]** `pattern_matcher.py`：trigger 编译添加 `DOTALL` 与 detection 一致

### 测试覆盖
- 测试总量：1304 → 1483（+179 tests, 0 regressions）
- 14 commits（8 E-7 hardening + 6 review fixes）

---

## [0.2.4] — 2026-03-26

### 修复

#### Issue Batch 2026-03-26-3（CS-013~CS-018, 6 Issues + L3 增强）
- **[CS-013]** `clawsentry watch` 无 decision 事件 — SSE 广播移到 deadline 检查之前
- **[CS-014]** `/ahp/resolve` WS 不可用返回 502 而非 503 — 修正 `stack.py` status_code
- **[CS-015]** L3 trace 未持久化 — 三层修复：CompositeAnalyzer 保留降级 trace / AgentAnalyzer 接入 trajectory_store 累积触发 / inner budget margin 防止外层 timeout 取消 trace
- **[CS-016]** `/report/stream` 无事件 — 同 CS-013 根因，同一修复
- **[CS-017]** 轨迹告警缺失 — EventBus 新增 50 条 replay buffer
- **[CS-018]** `pattern_evolved` 无事件 — 同 CS-017 根因，同一修复

### 新增

#### L3 AgentAnalyzer 健壮性增强
- **健壮 LLM 响应解析**：自动剥离 markdown 代码块包裹 / 递归搜索嵌套 JSON 结构 (`risk_assessment.level`) / 映射非标风险等级别名 (`none`→LOW, `severe`→HIGH 等)
- **格式修正重试**：首次解析失败且剩余 budget ≥ 3s 时，自动发送格式修正 prompt 重试
- **`asyncio.CancelledError` 安全网**：Python 3.9+ 中 CancelledError 为 BaseException，确保任何超时场景下 L3 trace 都能保存
- **`deadline_ms` 上限提升至 120s**：适配 L3 多轮 LLM 调用 + 慢速 provider 场景
- **AgentAnalyzer budget 修正**：`effective_budget` 正确纳入 caller 传入的 `budget_ms`，使 inner margin 机制真正生效

#### 测试新增
- 15 个新测试：EventBus replay / SSE 广播 / L3 trace 持久化 / 累积触发 / markdown 解析 / 嵌套结构 / 别名映射 / 格式重试 / budget 耗尽无重试
- 5 个 budget 测试更新适配 inner margin
- 测试总量：1289 → 1304（+15 tests）

#### 真实环境验证
- 25/25 checks PASS（100%）：L3 非降级 trace 首次通过（Kimi K2.5 via SiliconFlow, confidence=0.95）

---

## [0.2.3] — 2026-03-26

### 修复

#### Issue Batch 2026-03-26-2（2 Critical + 1 High + 1 feat, 12 tests）
- **[CS-012]** `_handle_sync_decision()` deadline exceeded 时 early return 跳过 `trajectory_store.record()` 和 `session_registry.record()`，导致 fallback 决策不落库 — 将 recording 移到 deadline 检查之前
- **[CS-011]** `_send_request()` 收到 OpenClaw 错误响应时返回 `False` 而非抛异常，导致 `resolve()` reason 降级重试永不触发 — 新增 `ResolveError` 异常 + 匹配 "unexpected property" 错误格式
- **[CS-009]** L2 budget cap 无 overhead margin，LLM 调用耗尽 budget 后刚好超过 deadline — 预留 200ms margin

### 新增
- **`CS_L3_BUDGET_MS`** 环境变量：独立配置 L3 最大预算（默认跟随 L2），解决 L3 场景下 deadline 不足问题
- 穿透链：`DetectionConfig` → `policy_engine` → `llm_factory` → `AgentAnalyzerConfig`

#### 测试新增
- 12 个新测试覆盖：deadline 下 recording / ResolveError + retry E2E / overhead margin / L3 budget 配置
- 测试总量：1277 → 1289（+12 tests）

---

## [0.2.2] — 2026-03-26

### 修复

#### Issue Batch 2026-03-26（3 High defects + 6 tests）
- **[CS-008]** `CompositeAnalyzer.analyze()` 返回 `L2Result` 时遗漏 `trace=best.trace`，导致 L3 trace 始终为 NULL 无法落库
- **[CS-009]** `policy_engine.evaluate()` L2 budget 不受请求 `deadline_ms` 约束，高延迟场景触发 `DEADLINE_EXCEEDED` — 新增 `deadline_budget_ms` 参数，以 `min(config, remaining)` 为上限
- **[CS-010]** `_build_openclaw_runtime()` 遗漏 `enforcement_enabled`/`openclaw_ws_url`/`openclaw_operator_token` 三字段，导致 WS 可用时 `/ahp/resolve` 仍返回 502
- **[CS-007]** LLM 超时日志改善：区分 `TimeoutError` 与其他 provider error，便于调参调试（WONTFIX，设计如此）

#### 测试新增
- 6 个新测试覆盖：trace 传递 / deadline budget 限制 / enforcement 参数穿透
- 测试总量：1271 → 1277（+6 tests）

---

## [0.2.1] — 2026-03-25

### 修复

#### OpenClaw 兼容性审查（12 defects + 31 tests，2026-03-25）
- **[C-1/C-2]** `run_gateway()` 未接入 `DetectionConfig` 和 LLM analyzer — 独立启动时 L1/L2 均回退默认值
- **[H-1]** OpenClaw POST_ACTION 事件缺少 `output` 字段映射（`toolOutput`/`command_output` 等别名未转换）
- **[H-2]** CompositeAnalyzer 热重载遍历失败 — `reload_patterns` 未递归查找内层 `_pattern_matcher`
- **[H-4]** Webhook 会话 ID 提取仅识别 `sessionKey`，缺少 `sessionId` 回退
- **[H-5/L-3]** WS Future 注册顺序错误（先 send 后 register 导致竞态）+ `get_event_loop()` 弃用
- **[M-1]** D6 注入检测遗漏 OpenClaw `message`/`transcript`/`userMessage`/`user_message` 字段
- **[M-2/M-4]** `extract_candidate()` 未持久化 + `store_path` 空路径未校验
- **[M-6]** `CS_EVOLVING_ENABLED` 非法值静默忽略，现增加 warning 日志
- **[L-1]** `post_action_finding` SSE 事件缺少 `source_framework` 字段

#### 测试新增
- 31 个 OpenClaw 集成测试：D6 注入检测 / post-action 围栏 / 轨迹序列 / 攻击模式匹配 / Gateway 配置接入
- 测试总量：1239 → 1271（+32 tests）

---

## [0.2.0] — 2026-03-24

### 新增

#### 核心安全增强（E-4 Phase 1-3，2026-03-24）
- **D6 注入检测维度**：`injection_detector.py`，Layer 1（10 弱+8 强 regex, <0.3ms）+ Layer 2（Canary Token 泄露检测）
- **Post-action 安全围栏**：`post_action_analyzer.py`，异步检测间接注入/数据泄露/凭据暴露/混淆，分级响应（LOG/MONITOR/ESCALATE/EMERGENCY）
- **攻击模式库**：`attack_patterns.yaml` v1.1，25 条模式覆盖 OWASP ASI01-04（含供应链/容器逃逸/反弹 shell）
- **EmbeddingBackend Protocol**：可插拔 L3 向量相似度接口（纯 Protocol，无模型依赖）
- **TrajectoryAnalyzer**：5 个多步攻击序列检测（凭据窃取/后门安装/侦察渗透/密钥收割/分阶段渗出）
- **DetectionConfig**：统一 frozen dataclass（20 可调字段）+ `build_detection_config_from_env()` + 19 CS_ 环境变量（含 bool 型 CS_EVOLVING_ENABLED）
- L1 评分重构：加权公式 `0.4*max(D1,D2,D3)+0.25*D4+0.15*D5` + D6 乘数，新阈值 LOW<0.8/MED<1.5/HIGH<2.2/CRIT≥2.2
- SSE 新事件类型：`post_action_finding`、`trajectory_alert`

#### 自进化模式库（E-5，2026-03-24）
- **PatternEvolutionManager**：从高危事件自动提取候选模式，SHA-256 命令去重，模式 ID `EV-{hash8}`
- **EvolvedPattern 生命周期**：CANDIDATE → EXPERIMENTAL → STABLE → DEPRECATED（FP 率 >30% 自动废弃）
- **EvolvedPatternStore**：YAML 原子持久化（tempfile + os.replace），max_patterns=500，LRU 驱逐
- **compute_confidence()**：5 因子信心评分（确认率 30% / 频率 20% / 跨框架 20% / 准确率 20% / 时效 10%）
- **双源加载**：`load_patterns(evolved_path=...)` 合并内置 core + evolved，过滤 inactive 模式
- **REST API**：`GET /ahp/patterns` + `POST /ahp/patterns/confirm`；SSE `pattern_evolved` 事件
- **配置门控**：`CS_EVOLVING_ENABLED`（默认 false）+ `CS_EVOLVED_PATTERNS_PATH`

#### 测试缺口修复（E-6，2026-03-24）
- 4 并行 Sonnet subagent 审查 E-4/E-5 全部测试，发现 6C+14H+10M+3L 缺口
- 10 个测试文件新增 59 个测试：64KB 截断边界、VectorLayer 除零保护、EvolvedPatternStore 驱逐优先级、STABLE 幂等性、compute_confidence 边界、API 400/404 路径、轨迹负面测试、D6/PostAction Gateway 集成等

#### 用户体验改进（E-1~E-3，2026-03-23）
- **`clawsentry start`**：一键启动命令（框架自动检测 → 初始化 → Gateway → watch），Ctrl+C 优雅关闭
- **Web UI 自动登录**：启动时输出带 token 的 URL，点击即可免密登录
- **watch 输出优化**：混合格式（ALLOW 单行/BLOCK-DEFER 树形展开）+ SessionTracker Unicode 分组框 + Emoji 视觉锚点
- **watch 新 CLI 参数**：`--verbose` / `--no-emoji` / `--compact`
- **Web UI 重构**：Linear/Vercel 设计语言，Inter 字体，紫色 accent（#a78bfa），新组件：EmptyState/SkeletonCard/ScoreBar/VerdictBar/AreaChart 渐变/HintTag/LatencyBadge/TierBadge/SVG 环形倒计时

#### 测试覆盖
- 测试总量：775 → 1239（+464 tests，覆盖 D6/Post-action/模式库/DetectionConfig/TrajectoryAnalyzer/E-5 进化模式/E-6 缺口修复）
- 1 skipped = E2E SDK 测试（需 `A3S_SDK_E2E=1` + LLM API key，预期行为）
- E2E 全量测试（含 LLM 调用）：1243 passed（safe/dangerous/alert/eventbus 四项）

### 修复

#### 第二轮代码审查（3 Critical + 16 Important + 16 Minor + 9 Nitpick）
- **[C-1]** PatternMatcher `_detection_match` 全扫描修复（不再 early-return 丢失最高 weight）
- **[C-2]** `copy.copy(pattern)` 防止共享 AttackPattern 对象 mutation
- **[C-3]** TrajectoryAnalyzer `_emitted` set 上限 + LRU 驱逐防止内存泄漏
- SSE `/report/stream` 白名单补充 `post_action_finding` / `trajectory_alert`（I-1）
- `build_detection_config_from_env()` try/except 降级 + `d6_injection_multiplier` 验证（I-2/I-3）
- `score_layer1` + `PostActionAnalyzer` 64KB 输入上限（I-4/I-6）
- ThreadPoolExecutor `asyncio.wait_for` 包装防线程泄漏（I-7）
- `detect_instructional_content` 收窄标记 + 阈值 >0.5（I-8）
- 触发器 command/path_patterns 递归预编译（I-11）
- max_weight ≥ 8 → HIGH 风险升级（I-12）
- RiskSnapshot `frozen=True` 不可变保证（I-10）
- 正则优化 / 防御性拷贝 / bidi 字符检测 / 文档完善（Minor/Nitpick）

#### 第一轮代码审查
- PatternMatcher 正则预编译 + 100KB 输入限制（H9/H10）
- Post-action 复合评分聚合：max + 0.15 per extra signal（H8）
- LLM prompt payload 脱敏（4KB 截断 + REDACTED 标注，H3/H4）
- CDN 白名单扩展 + Shannon 熵阈值 7.0→5.5（M12/M13）
- `event_text()` 64KB 上限防止 regex 性能退化（M5）
- `mount` 加入 DANGEROUS_TOOLS（M3）

---

## [0.1.0] — 2026-03-23

首个公开版本。ClawSentry 是 Agent Harness Protocol (AHP) 的 Python 参考实现——一个面向 AI Agent 运行时的统一安全监督网关，支持 a3s-code 和 OpenClaw 双框架接入。

### 新增

#### 核心架构
- 实现 AHP (Agent Harness Protocol) 统一协议规范，归一化多框架运行时事件
- Sidecar 架构 + UDS（主传输）+ HTTP（备传输）双通道入口
- 同步阻塞 `pre_action` + 异步审计 `post_action` 双通道处理
- 基于 Pydantic v2 的 CanonicalEvent / CanonicalDecision 协议模型
- JSON-RPC 2.0 同步决策接口 (`sync_decision.1.0`)

#### 三层决策模型
- **L1 规则引擎** (<1ms)：D1-D5 五维风险评分（命令危险度/参数敏感度/上下文合理性/历史行为/作用域权限）
- **L2 语义分析** (<3s)：SemanticAnalyzer Protocol + RuleBased / LLM / Composite 三种实现
- **L3 审查 Agent** (<30s)：AgentAnalyzer + ReadOnlyToolkit + SkillRegistry + 多轮工具调用推理
- L3 推理轨迹持久化到 TrajectoryStore (`l3_trace_json` 列)

#### 框架适配器
- **a3s-code Adapter**：stdio harness + HTTP Transport (`POST /ahp/a3s`) 双模式
- **OpenClaw Adapter**：WebSocket 实时事件监听 + Webhook 接收器 + 审批执行器
- LLM 工厂：环境变量驱动的 Anthropic/OpenAI/自定义 provider 构建

#### 安全加固
- Bearer Token HTTP 认证 (`CS_AUTH_TOKEN`)
- Webhook HMAC-SHA256 签名验证 + IP 白名单 + Token TTL
- UDS socket `chmod 0o600` 权限保护
- SSL/TLS 支持 (`AHP_SSL_CERTFILE` / `AHP_SSL_KEYFILE`)
- 速率限制 (`CS_RATE_LIMIT_PER_MINUTE`，默认 300/分钟)
- 幂等性缓存防重复决策
- 按风险等级分层的重试预算（CRITICAL/HIGH=1, MEDIUM=2, LOW=3）

#### 会话管理
- SessionRegistry：会话生命周期追踪 + 风险累积
- 会话级强制策略 (SessionEnforcementPolicy)：累积 N 次高危后自动 DEFER/BLOCK/L3
- 冷却期自动释放 + 手动释放 REST API

#### 实时监控
- EventBus：进程内事件广播
- SSE 实时推送：decision / session_start / session_risk_change / alert / session_enforcement_change
- AlertRegistry：告警聚合 + 过滤 + 确认
- `clawsentry watch` CLI：终端实时展示（彩色输出/JSON 模式/事件过滤）
- `clawsentry watch --interactive`：DEFER 运维确认 (Allow/Deny/Skip + 超时安全余量)

#### Web 安全仪表板
- React 18 + TypeScript + Vite SPA，暗色 SOC 主题
- Dashboard：实时决策 feed + 指标卡 + 饼图/柱状图
- Sessions：会话列表 + D1-D5 雷达图 + 风险曲线 + 决策时间线
- Alerts：告警表格 + 过滤 + 确认 + SSE 自动推送
- DEFER Panel：倒计时 + Allow/Deny 按钮 + 503 降级提示
- Gateway 在 `/ui` 路径提供静态文件 + SPA fallback

#### CLI 工具
- `clawsentry init <framework>`：零配置初始化（支持 `--auto-detect` / `--setup` / `--dry-run`）
- `clawsentry gateway`：智能启动（自动检测 OpenClaw 配置，按需启用 Webhook/WS）
- `clawsentry harness`：a3s-code stdio harness
- `clawsentry watch`：SSE 实时监控
- `.env` 文件自动加载（dotenv_loader）

#### REST API
- `POST /ahp` — OpenClaw Webhook 决策端点
- `POST /ahp/a3s` — a3s-code HTTP Transport
- `POST /ahp/resolve` — DEFER 决策代理 (allow-once/deny)
- `GET /health` — 健康检查
- `GET /report/summary` — 跨框架聚合统计
- `GET /report/stream` — SSE 实时推送（支持 `?token=` query param 认证）
- `GET /report/sessions` — 活跃会话列表 + 风险排序
- `GET /report/session/{id}` — 会话轨迹回放
- `GET /report/session/{id}/risk` — 会话风险详情 + 时间线
- `GET /report/session/{id}/enforcement` — 会话执法状态查询
- `POST /report/session/{id}/enforcement` — 会话执法手动释放
- `GET /report/alerts` — 告警列表 + 过滤
- `POST /report/alerts/{id}/acknowledge` — 确认告警

#### L3 Skills
- 6 个内置审查技能：shell-audit / credential-audit / code-review / file-system-audit / network-audit / general-review
- 自定义 Skills 支持 (`AHP_SKILLS_DIR` 环境变量)
- Skills Schema：enabled / priority 字段 + 双语 system_prompt + 扩展 triggers

#### 测试
- 775 个测试用例，覆盖单元测试 + 集成测试 + E2E 测试
- 测试通过时间 ~6.5s

[0.3.1]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.3.1
[0.3.0]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.3.0
[0.2.9]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.2.9
[0.2.8]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.2.8
[0.2.7]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.2.7
[0.2.6]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.2.6
[0.2.5]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.2.5
[0.2.4]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.2.4
[0.2.3]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.2.3
[0.2.2]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.2.2
[0.2.1]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.2.1
[0.2.0]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.2.0
[0.1.0]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.1.0
