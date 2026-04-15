---
title: CLI 命令参考
description: ClawSentry 全部命令行工具的完整使用手册
---

# CLI 命令参考

ClawSentry 提供统一的命令行入口 `clawsentry`，通过子命令完成框架初始化、网关启动、事件监控等操作。

## 调用方式

安装后，以下三种方式等价：

```bash
# 推荐方式
clawsentry <subcommand> [options]

# Python 模块调用
python -m clawsentry <subcommand> [options]

# 直接调用入口脚本（由 pip install 注册）
clawsentry-gateway   # 等价于 clawsentry gateway
clawsentry-harness   # 等价于 clawsentry harness
clawsentry-stack     # 等价于 clawsentry stack
```

!!! info "`.env.clawsentry` 自动加载"
    `clawsentry gateway`、`clawsentry stack`、`clawsentry start` 和 `clawsentry-gateway`、`clawsentry-stack` 启动时会自动读取当前目录下的 `.env.clawsentry` 文件，并将其中的环境变量注入进程。**已存在的环境变量不会被覆盖。**

    文件格式：
    ```ini
    # 注释行
    CS_AUTH_TOKEN=my-secret-token
    CS_HTTP_PORT=9100
    OPENCLAW_OPERATOR_TOKEN="quoted-value"
    ```

## 命令速查表

| 命令 | 用途 | 典型用法 |
|------|------|---------|
| [`start`](#clawsentry-start) | **一键启动**（推荐） | `clawsentry start --framework claude-code` |
| [`stop`](#clawsentry-stop) | 停止 Gateway | `clawsentry stop` |
| [`status`](#clawsentry-status) | 查看运行状态 | `clawsentry status` |
| [`init`](#clawsentry-init) | 初始化框架配置 | `clawsentry init claude-code` |
| [`gateway`](#clawsentry-gateway) | 直接启动 Gateway（高级） | `clawsentry gateway` |
| [`stack`](#clawsentry-stack) | 直接启动完整栈（高级） | `clawsentry stack` |
| [`harness`](#clawsentry-harness) | stdio hook 处理器 | 由框架自动调用，通常无需手动使用 |
| [`watch`](#clawsentry-watch) | 实时监控事件流 | `clawsentry watch --interactive` |
| [`audit`](#clawsentry-audit) | 离线查询审计日志 | `clawsentry audit --risk high --since 1h` |
| [`doctor`](#clawsentry-doctor) | 诊断配置和连接（19 项检查） | `clawsentry doctor` |
| [`test-llm`](#clawsentry-test-llm) | 验证 L2/L3 连通性、时延与当前运行模式 | `clawsentry test-llm --json` |
| [`service`](#clawsentry-service) | 安装或检查常驻服务（systemd/launchd） | `clawsentry service status` |
| [`config`](#clawsentry-config) | 管理项目安全预设 | `clawsentry config init --preset high` |
| [`rules`](#clawsentry-rules) | 规则治理（lint / dry-run） | `clawsentry rules lint --json` |
| [`latch`](#clawsentry-latch) | 管理 Latch 移动监控 | `clawsentry latch install` |

> **新用户推荐路径：** 先运行 `clawsentry start --framework <你的框架>`。它会自动补齐项目配置、启动 Gateway，并在前台显示 `watch` 事件流；只有需要手动拆分步骤或排障时，再单独使用 `init`、`gateway`、`watch`。

!!! tip "这些命令是什么关系？"
    | 命令 | 你什么时候用 | 与 `start` 的关系 |
    |------|---------------|-------------------|
    | `clawsentry start` | 日常启动和新用户接入 | 推荐入口；内部会按需调用初始化、启动 Gateway、接上事件流 |
    | `clawsentry init` | 只想生成/合并 `.env.clawsentry` 或安装框架 hook | 手动配置步骤；`start` 在缺配置时会自动做 |
    | `clawsentry gateway` | 只启动后台服务、systemd/Docker/调试 transport | `start --no-watch` 的底层服务部分 |
    | `clawsentry watch` | Gateway 已经在跑，只想另开终端看实时事件 | `start` 的前台监控部分 |
    | `clawsentry-harness` | a3s-code stdio transport 自动调用 | 不是普通用户入口，通常只出现在 SDK transport 配置里 |

!!! abstract "本页快速导航"
    [start](#clawsentry-start) · [stop](#clawsentry-stop) · [status](#clawsentry-status) · [init](#clawsentry-init) · [gateway](#clawsentry-gateway) · [stack](#clawsentry-stack) · [harness](#clawsentry-harness) · [watch](#clawsentry-watch) · [audit](#clawsentry-audit) · [doctor](#clawsentry-doctor) · [test-llm](#clawsentry-test-llm) · [service](#clawsentry-service) · [config](#clawsentry-config) · [rules](#clawsentry-rules) · [integrations](#clawsentry-integrations) · [latch](#clawsentry-latch)

---

## clawsentry start

**一键启动 ClawSentry 监督网关**（推荐方式）。自动检测或按参数选择框架，补齐配置，启动 Gateway，并显示实时监控。

### 语法

```bash
clawsentry start [--framework {a3s-code,claude-code,codex,openclaw}]
                 [--frameworks a3s-code,codex,openclaw]
                 [--setup-openclaw | --no-setup-openclaw]
                 [--host HOST] [--port PORT]
                 [--no-watch] [--interactive | -i]
                 [--open-browser] [--with-latch] [--hub-port PORT]
```

### 选项

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `--framework` | 自动检测 | 目标框架：`a3s-code`、`claude-code`、`codex`、`openclaw` |
| `--frameworks` | 空 | 逗号分隔的多框架启用列表，如 `a3s-code,codex,openclaw` |
| `--setup-openclaw` | `false` | 当本次启动涉及 `openclaw` 时，同时显式修改 `~/.openclaw/` 中的审批配置 |
| `--host` | `127.0.0.1` | Gateway HTTP 监听地址 |
| `--port` | `8080` 或 `CS_HTTP_PORT` | Gateway HTTP 监听端口 |
| `--no-watch` | `false` | 仅启动 Gateway，不显示实时监控 |
| `--interactive` / `-i` | `false` | 启用 DEFER 决策交互式审批 |
| `--open-browser` | `false` | 启动后在浏览器中打开 Web UI |
| `--with-latch` | `false` | 同时启动 Latch Hub（需先运行 `clawsentry latch install`） |
| `--hub-port` | `3006` | Latch Hub 端口，配合 `--with-latch` 使用 |

### 工作流程

`clawsentry start` 会自动执行以下步骤：

1. **框架检测**：优先读取 `.env.clawsentry` 中的 `CS_FRAMEWORK`，再扫描 OpenClaw / Claude Code 等已知配置，自动识别框架类型
2. **配置初始化**：如果 `.env.clawsentry` 缺失或 `--frameworks` 中有未启用框架，自动运行 `clawsentry init <framework>` 增量合并
3. **环境加载**：读取 `.env.clawsentry` 并注入环境变量
4. **Gateway 启动**：后台启动 Gateway 进程，等待健康检查通过
5. **实时监控**：前台显示 `clawsentry watch` 输出（除非使用 `--no-watch`）
6. **优雅关闭**：按 `Ctrl+C` 时，先发送 SIGTERM，5 秒后降级为 SIGKILL

### 示例

#### 自动检测并启动

```bash
clawsentry start
```

??? example "终端输出"
    ```
    ClawSentry starting...
      Framework:  openclaw (auto-detected)
      Gateway:    http://127.0.0.1:8080 (background)
      Web UI:     http://127.0.0.1:8080/ui?token=xK7m9p2QaB3...
      Log file:   /tmp/clawsentry-gateway.log

    Gateway ready. Streaming events...

    ──────────────────────────────────────────────────────────────
    [14:23:05] DECISION  session=my-session
      verdict : ALLOW
      risk    : low
      command : cat README.md
    ──────────────────────────────────────────────────────────────
    ```

#### 指定框架和端口

```bash
clawsentry start --framework a3s-code --port 9100
```

#### 多框架一起启用

```bash
clawsentry start --frameworks a3s-code,codex,openclaw --no-watch
```

此命令会按列表增量合并 `.env.clawsentry`，启动 banner 会显示 `Enabled: a3s-code, codex, openclaw`。默认不会修改 `~/.openclaw/`；如需在启动时一并配置 OpenClaw 侧审批文件，显式添加 `--setup-openclaw`。
从这版开始，banner 还会打印 `Readiness` 摘要，把每个框架当前是 `ready`、`needs attention` 还是 `manual verification required` 直接讲明白，并给出 `Next actions`。

#### 启动时同时设置 OpenClaw

```bash
clawsentry start --frameworks codex,openclaw --setup-openclaw --no-watch
```

当启用了 `openclaw` 且显式传入 `--setup-openclaw` 时，`start` 会在项目 `.env.clawsentry` 合并完成后继续尝试更新 `~/.openclaw/openclaw.json` 与 `exec-approvals.json`。如果当前项目已经启用了 OpenClaw，这个参数仍会生效，不需要先删除 `.env.clawsentry` 重新初始化。

#### 仅启动 Gateway（不显示监控）

```bash
clawsentry start --no-watch
```

此模式下，Gateway 在后台运行，命令立即返回。你可以稍后手动运行 `clawsentry watch` 查看事件。
停止后台 Gateway 时运行 `clawsentry stop`。

#### 启用交互式 DEFER 审批

```bash
clawsentry start --interactive
```

当收到 DEFER 决策时，终端会提示你输入 `[A]llow`、`[D]eny` 或 `[S]kip`。

### Web UI 自动登录

启动时，终端会显示带 token 的 Web UI URL：

```
Web UI: http://127.0.0.1:8080/ui?token=xK7m9p2QaB3...
```

点击该 URL 即可自动登录，无需手动输入 token。

### 错误处理

- **框架检测失败**：如果无法自动检测框架，命令会报错并提示使用 `--framework` 参数
- **初始化失败**：如果 `clawsentry init` 失败（如权限问题），命令会抛出 `RuntimeError`
- **Gateway 启动失败**：如果 Gateway 进程在 0.1 秒内退出，命令会报错并显示日志路径
- **健康检查超时**：如果 5 秒内 Gateway 未响应健康检查，命令会报错

### 日志位置

Gateway 的 stdout/stderr 输出会写入临时日志文件：

```
/tmp/clawsentry-gateway.log
```

如果启动失败，命令会提示查看该日志文件。

---

## clawsentry init

初始化框架集成配置。根据目标框架生成 `.env.clawsentry` 配置文件和所需的设置文件。

### 语法

```bash
clawsentry init <framework> [--dir PATH] [--force] [--auto-detect] [--setup] [--dry-run]
                             [--uninstall] [--restore]
```

### 参数

| 参数 | 说明 |
|------|------|
| `framework` | 目标框架，可选值：`a3s-code`、`claude-code`、`codex`、`openclaw` |

### 选项

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `--dir PATH` | `.`（当前目录） | 配置文件写入目录 |
| `--force` | `false` | 覆盖已存在的配置文件；默认会增量合并 `.env.clawsentry` |
| `--auto-detect` | `true` | 自动检测已有的框架配置（如 `~/.openclaw/` 中的 Gateway Token） |
| `--setup` | `false` | 自动配置框架设置以支持 ClawSentry 集成（隐含 `--auto-detect`；目前主要用于 OpenClaw） |
| `--dry-run` | `false` | 预览 `--setup` 将要执行的配置变更，但不实际应用 |
| `--uninstall` | `false` | 从项目 `.env.clawsentry` 中禁用该框架；`claude-code` 会同时移除 hooks |
| `--restore` | `false` | 从 ClawSentry 备份恢复框架设置（目前支持 `openclaw`） |

!!! info "多框架增量合并"
    如果 `.env.clawsentry` 已存在，`clawsentry init <framework>` 默认不会轮换已有 `CS_AUTH_TOKEN`，也不会改写已有 `CS_FRAMEWORK`。命令会追加缺失的框架专属变量，并维护 `CS_ENABLED_FRAMEWORKS`（如 `a3s-code,codex,openclaw`）。

    只有显式使用 `--force` 时才会覆盖 `.env.clawsentry`。

!!! info "按框架安全卸载"
    `clawsentry init <framework> --uninstall` 不会删除整个 `.env.clawsentry`，也不会轮换共享 `CS_AUTH_TOKEN`。命令只会从 `CS_ENABLED_FRAMEWORKS` 移除目标框架，并删除该框架专属变量（如 `CS_CODEX_*` 或 `OPENCLAW_*`）；如果还有其他框架启用，`CS_FRAMEWORK` 会指向剩余框架之一。

!!! warning "OpenClaw setup 是显式 opt-in"
    `clawsentry init openclaw` 默认只生成或合并 `.env.clawsentry`，不会修改 `~/.openclaw/openclaw.json` 或 `exec-approvals.json`。需要自动修改 OpenClaw 侧配置时，显式加上 `--setup`；建议先运行 `--setup --dry-run`。

### 示例

#### 初始化 a3s-code 集成

```bash
clawsentry init a3s-code
```

??? example "终端输出"
    ```
    [clawsentry] a3s-code integration initialized

      Files created:
        .env.clawsentry

      Environment variables:
        CS_FRAMEWORK=a3s-code
        CS_UDS_PATH=/tmp/clawsentry.sock
        CS_AUTH_TOKEN=xK7m9p2QaB3...（自动生成 32 字符令牌）

      Next steps:
        1. source .env.clawsentry
        2. export NO_PROXY=127.0.0.1,localhost
        3. clawsentry gateway    # starts on UDS + HTTP port 8080
        4. Configure a3s-code AHP transport explicitly in your agent script
        5. clawsentry watch --token "$CS_AUTH_TOKEN"
    ```

#### 初始化 OpenClaw 集成（自动检测令牌）

```bash
clawsentry init openclaw --auto-detect
```

此命令会从 `~/.openclaw/openclaw.json` 中读取 `gateway.auth.token`，并自动填入 `.env.clawsentry` 文件。

它不会修改 OpenClaw 侧配置文件；需要自动设置 `tools.exec.host` 和审批策略时使用下一节的 `--setup`。

#### 自动配置 OpenClaw + 预览变更

```bash
clawsentry init openclaw --setup --dry-run
```

??? example "终端输出"
    ```
    [clawsentry] openclaw integration initialized

      Files created:
        .env.clawsentry

      Environment variables:
        OPENCLAW_WS_URL=ws://127.0.0.1:18789
        OPENCLAW_OPERATOR_TOKEN=xxxxxxxxxxxxxxxx...
        CS_AUTH_TOKEN=xK7m9p2QaB3...

      Next steps:
        1. source .env.clawsentry
        2. clawsentry gateway
        3. clawsentry watch

      [DRY RUN] The following changes would be applied:
        - Set tools.exec.host = "gateway" in openclaw.json
        - Set exec-approvals security = "allowlist", ask = "always"
    ```

`--setup` 会自动配置以下 OpenClaw 关键设置：

- `tools.exec.host = "gateway"` —— 启用 Gateway 审批流程（默认 `sandbox` 跳过审批）
- `exec-approvals.json` —— 设置 `security: "allowlist"`, `ask: "always"`

!!! warning "备份机制"
    `--setup`（不带 `--dry-run`）会在修改前自动创建 `.bak` 备份文件。

#### 恢复 OpenClaw 配置

```bash
# 预览恢复操作
clawsentry init openclaw --restore --dry-run

# 从 openclaw.json.bak / exec-approvals.json.bak 恢复
clawsentry init openclaw --restore
```

`--restore` 只读取 ClawSentry `--setup` 创建的 `.bak` 文件；找不到备份时只输出 warning，不会写入新文件。

#### 卸载某个框架

```bash
# 只从当前项目 env 中禁用 Codex watcher；保留其他框架和共享 token
clawsentry init codex --uninstall

# 移除 Claude Code hooks，并从当前项目 env 中移除 claude-code 启用标记
clawsentry init claude-code --uninstall

# 禁用 OpenClaw env 变量；如需恢复 OpenClaw 侧文件，另用 --restore
clawsentry init openclaw --uninstall
```

`--uninstall` 的默认作用域是当前目录的 `.env.clawsentry`。如配置文件位于其他项目目录，使用 `--dir PATH` 指定。

---

## clawsentry gateway

启动 Supervision Gateway（监督网关）。自动检测 OpenClaw 配置，按需启用 Webhook/WebSocket 组件。

### 语法

```bash
clawsentry gateway [--gateway-host HOST] [--gateway-port PORT] [--uds-path PATH]
                    [--trajectory-db-path PATH] [--trajectory-retention-seconds N]
                    [--webhook-host HOST] [--webhook-port PORT]
                    [--webhook-token TOKEN] [--webhook-secret SECRET]
                    [--gateway-transport-preference PREF]
```

此命令委托给 `clawsentry.gateway.stack:main()`，等价于 `clawsentry stack`。

### 选项

#### 网关核心

| 选项 | 环境变量 | 默认值 | 说明 |
|------|----------|--------|------|
| `--gateway-host` | `CS_HTTP_HOST` | `127.0.0.1` | HTTP 服务监听地址 |
| `--gateway-port` | `CS_HTTP_PORT` | `8080` | HTTP 服务监听端口 |
| `--uds-path` | `CS_UDS_PATH` | `/tmp/clawsentry.sock` | Unix Domain Socket 路径 |
| `--trajectory-db-path` | `CS_TRAJECTORY_DB_PATH` | `/tmp/clawsentry-trajectory.db` | 轨迹数据库路径（SQLite） |
| `--trajectory-retention-seconds` | `AHP_TRAJECTORY_RETENTION_SECONDS` | `2592000`（30 天） | 轨迹记录保留时间 |

#### OpenClaw Webhook

| 选项 | 环境变量 | 默认值 | 说明 |
|------|----------|--------|------|
| `--webhook-host` | `OPENCLAW_WEBHOOK_HOST` | `127.0.0.1` | Webhook 接收器监听地址 |
| `--webhook-port` | `OPENCLAW_WEBHOOK_PORT` | `8081` | Webhook 接收器监听端口 |
| `--webhook-token` | `OPENCLAW_WEBHOOK_TOKEN` | （内置默认值） | Webhook 认证令牌 |
| `--webhook-secret` | `OPENCLAW_WEBHOOK_SECRET` | `None` | HMAC 签名密钥 |
| `--webhook-require-https` | — | `false` | 要求 Webhook 使用 HTTPS（localhost 豁免） |
| `--webhook-max-body-bytes` | — | `1048576`（1 MB） | Webhook 请求体大小限制 |

#### 高级选项

| 选项 | 环境变量 | 默认值 | 说明 |
|------|----------|--------|------|
| `--gateway-transport-preference` | — | `uds_first` | OpenClaw Gateway 客户端传输顺序：`uds_first` 或 `http_first` |
| `--source-protocol-version` | — | （自动检测） | OpenClaw 协议版本 |
| `--git-short-sha` | — | （自动检测） | OpenClaw Git 版本标识 |
| `--profile-version` | — | `1` | 映射规则版本号 |

### 运行模式自动检测

Gateway 通过以下条件判断是否启用 OpenClaw 集成：

- `OPENCLAW_WEBHOOK_TOKEN` 不等于内置默认值，**或者**
- `OPENCLAW_ENFORCEMENT_ENABLED=true`

满足任一条件时，自动启动 Webhook 接收器和 WebSocket 事件监听。否则仅启动 Gateway 核心（UDS + HTTP）。

### 示例

#### 仅 Gateway 模式

```bash
clawsentry gateway
```

??? example "启动日志"
    ```
    2026-03-23T10:00:00 [ahp-stack] Gateway-only starting:
      gateway=http://127.0.0.1:8080/ahp
      uds=/tmp/clawsentry.sock
      (no OpenClaw config detected)
    ```

#### 完整模式（含 OpenClaw 集成）

```bash
export OPENCLAW_WEBHOOK_TOKEN=my-webhook-token
export OPENCLAW_ENFORCEMENT_ENABLED=true
export OPENCLAW_OPERATOR_TOKEN=xxxxxxxxxxxxxxxx...
export OPENCLAW_WS_URL=ws://127.0.0.1:18789

clawsentry gateway --gateway-port 9100 --webhook-port 9101
```

??? example "启动日志"
    ```
    2026-03-23T10:00:00 [ahp-stack] Full stack starting:
      gateway=http://127.0.0.1:9100/ahp
      uds=/tmp/clawsentry.sock
      webhook=http://127.0.0.1:9101/webhook/openclaw
    2026-03-23T10:00:00 [ahp-stack] OpenClaw WS enforcement listener active
    ```

#### 指定 SSL 证书启动

```bash
export AHP_SSL_CERTFILE=/etc/ssl/certs/clawsentry.pem
export AHP_SSL_KEYFILE=/etc/ssl/private/clawsentry-key.pem

clawsentry gateway
```

---

## clawsentry stack

`clawsentry gateway` 的别名。语法和选项完全相同。

```bash
clawsentry stack [options]
```

保留此命令是为了向后兼容早期版本。推荐使用 `clawsentry gateway`。

---

## clawsentry harness

启动 a3s-code stdio Harness（AHP 钩子进程）。该进程通过 stdin/stdout 与 a3s-code 通信，将 Hook 事件转发到 ClawSentry Gateway 进行安全评估。

### 语法

```bash
clawsentry harness [--uds-path PATH] [--default-deadline-ms MS]
                    [--max-rpc-retries N] [--retry-backoff-ms MS]
                    [--default-session-id ID] [--default-agent-id ID]
```

### 选项

| 选项 | 环境变量 | 默认值 | 说明 |
|------|----------|--------|------|
| `--uds-path` | `CS_UDS_PATH` | `/tmp/clawsentry.sock` | Gateway UDS 路径 |
| `--default-deadline-ms` | `A3S_GATEWAY_DEFAULT_DEADLINE_MS` | `4500` | RPC 请求超时（毫秒） |
| `--max-rpc-retries` | `A3S_GATEWAY_MAX_RPC_RETRIES` | `1` | RPC 最大重试次数 |
| `--retry-backoff-ms` | `A3S_GATEWAY_RETRY_BACKOFF_MS` | `50` | 重试间隔退避（毫秒） |
| `--default-session-id` | `A3S_GATEWAY_DEFAULT_SESSION_ID` | `ahp-session` | 默认会话 ID |
| `--default-agent-id` | `A3S_GATEWAY_DEFAULT_AGENT_ID` | `ahp-agent` | 默认 Agent ID |

### 工作原理

1. 从 stdin 逐行读取 JSON-RPC 2.0 消息
2. 将 a3s-code Hook 事件归一化为 AHP `CanonicalEvent`
3. 通过 UDS 转发至 Gateway 获取决策
4. 将 `CanonicalDecision` 转换为 a3s-code 可识别的响应格式
5. 将响应写入 stdout

### 支持的 Hook 事件类型

| a3s-code Hook | AHP EventType | 阻塞 | 说明 |
|---------------|---------------|------|------|
| `PreToolUse` | `pre_action` | :material-check: | 工具调用前拦截 |
| `PostToolUse` | `post_action` | :material-close: | 工具调用后审计 |
| `PrePrompt` | `pre_prompt` | :material-check: | Prompt 发送前检查 |
| `GenerateStart` | `pre_prompt` | :material-check: | LLM 生成前检查 |
| `SessionStart` | `session` | :material-close: | 会话启动通知 |
| `SessionEnd` | `session` | :material-close: | 会话结束通知 |
| `OnError` | `error` | :material-close: | 错误事件审计 |

!!! note "未映射事件"
    `GenerateEnd`、`SkillLoad`、`SkillUnload` 事件不会被映射，Harness 会静默忽略。

### 本地降级

当 Gateway 不可达时（UDS 连接失败或超时），Harness 会自动执行本地降级决策：

- 包含 `destructive_pattern` 或 `shell_execution` 风险提示 → **BLOCK**
- 其他 `pre_action` → **DEFER**（等待人工或上游重试）
- `pre_prompt` / `post_action` / `post_response` / `session` / `error` → **ALLOW**（观察型事件 fail-open）

### 示例

```bash
# 直接启动（通常由 a3s-code 自动调用）
clawsentry harness --uds-path /tmp/clawsentry.sock

# 手动测试：发送 handshake
echo '{"jsonrpc":"2.0","id":1,"method":"ahp/handshake","params":{}}' | clawsentry harness
```

??? example "Handshake 响应"
    ```json
    {
      "jsonrpc": "2.0",
      "id": 1,
      "result": {
        "protocol_version": "2.0",
        "harness_info": {
          "name": "a3s-gateway-harness",
          "version": "1.0.0",
          "capabilities": [
            "pre_action",
            "post_action",
            "pre_prompt",
            "session",
            "error"
          ]
        }
      }
    }
    ```

---

## clawsentry watch

实时监控 Gateway 的 SSE（Server-Sent Events）事件流，在终端以彩色格式化输出或原始 JSON 展示。

### 语法

```bash
clawsentry watch [--gateway-url URL] [--token TOKEN] [--filter TYPES]
                 [--json] [--no-color] [--interactive | -i]
                 [--verbose | -v] [--no-emoji] [--compact]
```

### 选项

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `--gateway-url URL` | `http://127.0.0.1:{CS_HTTP_PORT}` | Gateway 基础 URL |
| `--token TOKEN` | `None` | Bearer 认证令牌 |
| `--filter TYPES` | `None`（全部） | 逗号分隔的事件类型过滤器 |
| `--json` | `false` | 输出原始 JSON（适合管道处理） |
| `--no-color` | `false` | 禁用 ANSI 颜色代码 |
| `--interactive` / `-i` | `false` | DEFER 决策交互确认模式 |
| `--verbose` / `-v` | `false` | 显示所有决策详情，包括 ALLOW |
| `--no-emoji` | `false` | 禁用 emoji 输出（适合纯文本/窄终端环境） |
| `--compact` | `false` | 紧凑格式，不使用 Unicode 边框绘制会话分组 |

### 支持的事件类型

用于 `--filter` 的可选值：

| 事件类型 | 说明 |
|----------|------|
| `decision` | 每次决策结果（ALLOW/BLOCK/DEFER/MODIFY） |
| `alert` | 高风险告警 |
| `session_start` | 新会话创建 |
| `session_risk_change` | 会话风险等级变更 |
| `session_enforcement_change` | 会话强制策略状态变更 |

### 终端输出格式

#### 决策事件

```
[10:30:45]  BLOCK     rm -rf /data                             risk=high    D1: destructive pattern
[10:30:46]  ALLOW     cat README.md                            risk=low
[10:30:47]  DEFER     sudo chmod 777 /etc/passwd               risk=high    Requires operator approval
```

颜色编码：:large_red_square: BLOCK（红色）| :large_green_square: ALLOW（绿色）| :large_yellow_square: DEFER（黄色）| :large_blue_square: MODIFY（青色）

#### 告警事件

```
[10:30:45]  ALERT     sess=sess-001  severity=high  Risk escalation detected
```

#### 会话事件

```
[10:30:45]  SESSION   started  sess=sess-001  agent=agent-1  framework=a3s-code
[10:31:00]  RISK      sess=sess-001  low -> high
```

### 交互模式

使用 `--interactive` 或 `-i` 启动交互模式。当收到 DEFER 决策时，运维人员可以实时做出允许或拒绝的决定：

```
  Command: sudo rm -rf /var/log
  Reason:  Destructive operation on system logs
  [A]llow  [D]eny  [S]kip (timeout in 25s) >
```

- 输入 `a` —— 允许执行（resolve 为 `allow-once`）
- 输入 `d` —— 拒绝执行（resolve 为 `deny`，附带原因 `operator denied via watch CLI`）
- 输入 `s` 或直接回车 —— 跳过不处理
- 超时未响应 —— 自动跳过（保留 5 秒安全余量防止竞态）

### 示例

#### 基础监控

```bash
clawsentry watch --token my-secret-token
```

#### 仅监控决策和告警

```bash
clawsentry watch --filter decision,alert --token my-secret-token
```

#### JSON 输出（适合管道）

```bash
clawsentry watch --json --token my-secret-token | jq '.decision'
```

#### 运维交互确认

```bash
clawsentry watch --interactive --token my-secret-token
```

### 连接行为

- 启动时显示 `Connected to <url>`
- 连接断开后自动重连（间隔 3 秒）
- `Ctrl+C` 优雅退出

---

## clawsentry stop

停止正在运行的 Gateway 进程。

### 语法

```bash
clawsentry stop
```

此命令通过读取 PID 文件定位 Gateway 进程，发送 SIGTERM 信号实现优雅关闭。

### 行为

- 读取 `/tmp/clawsentry-gateway.pid` 获取进程 ID
- 发送 SIGTERM 信号
- 如果 PID 文件不存在或进程未运行，输出提示信息并退出

### 示例

```bash
clawsentry stop
```

??? example "终端输出"
    ```
    Gateway (PID 12345) stopped.
    ```

---

## clawsentry status

查看 Gateway 运行状态。

### 语法

```bash
clawsentry status
```

### 输出

显示 Gateway 进程状态（running / not running / stale）和 PID 信息。

### 示例

```bash
clawsentry status
```

??? example "终端输出 — 运行中"
    ```
    Gateway: running (PID 12345)
    ```

??? example "终端输出 — 未运行"
    ```
    Gateway: not running
    ```

??? example "终端输出 — PID 文件过期"
    ```
    Gateway: stale PID file (PID 12345 not found)
    ```

---

## clawsentry audit

离线查询轨迹数据库（Trajectory DB）中的审计记录，支持多维度过滤和聚合统计。

### 语法

```bash
clawsentry audit [--db PATH] [--session ID] [--since DURATION]
                 [--risk LEVEL] [--decision VERDICT] [--tool NAME]
                 [--format {table|json|csv}] [--stats] [--limit N]
                 [--no-color]
```

### 选项

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `--db PATH` | `CS_TRAJECTORY_DB_PATH` 或 `/tmp/clawsentry-trajectory.db` | SQLite 数据库文件路径 |
| `--session ID` | `None` | 按会话 ID 过滤 |
| `--since DURATION` | `None` | 时间窗口过滤，支持格式：`30m`、`1h`、`24h`、`7d` |
| `--risk LEVEL` | `None` | 按风险等级过滤：`low`、`medium`、`high`、`critical` |
| `--decision VERDICT` | `None` | 按决策结果过滤：`allow`、`block`、`defer`、`modify` |
| `--tool NAME` | `None` | 按工具名称过滤 |
| `--format` | `table` | 输出格式：`table`（表格）、`json`、`csv` |
| `--stats` | `false` | 仅显示聚合统计信息 |
| `--limit N` | `100` | 最大返回记录数 |
| `--no-color` | `false` | 禁用 ANSI 颜色代码 |

### 示例

#### 查询最近 1 小时的高风险事件

```bash
clawsentry audit --since 1h --risk high
```

??? example "终端输出"
    ```
    ┌──────────────────────┬────────────┬─────────┬──────────┬────────────────────────────┐
    │ timestamp            │ session    │ risk    │ decision │ command                    │
    ├──────────────────────┼────────────┼─────────┼──────────┼────────────────────────────┤
    │ 2026-03-31T14:23:05  │ sess-001   │ high    │ BLOCK    │ rm -rf /data               │
    │ 2026-03-31T14:25:12  │ sess-001   │ high    │ DEFER    │ sudo chmod 777 /etc/passwd │
    └──────────────────────┴────────────┴─────────┴──────────┴────────────────────────────┘
    2 records found
    ```

#### 查看统计概览

```bash
clawsentry audit --since 24h --stats
```

??? example "终端输出"
    ```
    Audit Statistics (last 24h)
    ───────────────────────────
    Total events:     142
    Sessions:         8

    By decision:
      ALLOW:          128 (90.1%)
      BLOCK:          8   (5.6%)
      DEFER:          4   (2.8%)
      MODIFY:         2   (1.4%)

    By risk:
      low:            115 (81.0%)
      medium:         19  (13.4%)
      high:           7   (4.9%)
      critical:       1   (0.7%)
    ```

#### 导出 JSON 格式

```bash
clawsentry audit --since 7d --format json --limit 500 > audit-report.json
```

#### 按会话和工具过滤

```bash
clawsentry audit --session sess-001 --tool bash
```

---

## clawsentry doctor

离线检查 ClawSentry 配置安全性，共执行 19 项检查，涵盖认证、网络、LLM、Latch 等类别。

### 语法

```bash
clawsentry doctor [--json] [--no-color]
```

### 选项

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `--json` | `false` | 以 JSON 格式输出检查结果 |
| `--no-color` | `false` | 禁用 ANSI 颜色代码 |

### 退出码

| 退出码 | 含义 |
|--------|------|
| `0` | 所有检查均为 PASS |
| `1` | 存在至少一项 FAIL |
| `2` | 存在 WARN 但无 FAIL |

### 检查项一览

| 检查 ID | 类别 | 说明 |
|---------|------|------|
| `AUTH_PRESENCE` | 认证 | `CS_AUTH_TOKEN` 已设置 |
| `AUTH_LENGTH` | 认证 | Token 长度 >= 32（16-31 警告，<16 失败） |
| `AUTH_ENTROPY` | 认证 | Token 熵 >= 3.5 bits/char |
| `AUTH_WEAK_VALUE` | 认证 | Token 非常见弱值/占位符 |
| `UDS_PERMISSIONS` | UDS | Socket 权限为 `0o600`（仅属主可访问） |
| `THRESHOLD_ORDERING` | 配置 | `CS_THRESHOLD_MEDIUM` <= `HIGH` <= `CRITICAL` |
| `WEIGHT_BOUNDS` | 配置 | 所有权重 >= 0 |
| `LLM_CONFIG` | LLM | LLM 提供商与 API 密钥一致性 |
| `OPENCLAW_SECRET` | OpenClaw | 已设置 `CS_OPENCLAW_WEBHOOK_SECRET` |
| `LISTEN_ADDRESS` | 网络 | 监听 localhost（公网地址警告） |
| `WHITELIST_REGEX` | 正则 | Post-action 白名单正则可编译 |
| `L2_BUDGET` | LLM | `CS_L2_BUDGET_MS` 为正数 |
| `TRAJECTORY_DB` | 数据库 | 数据库目录可写 |
| `CODEX_CONFIG` | Codex | `CS_FRAMEWORK=codex` 时 auth token 已设置 |
| `LATCH_BINARY` | Latch | Latch 二进制已安装且可执行 |
| `LATCH_HUB_HEALTH` | Latch | Latch Hub 健康端点响应正常 |
| `LATCH_TOKEN_SYNC` | Latch | `CS_AUTH_TOKEN` 与 `CLI_API_TOKEN` 匹配 |
| `DEFER_BRIDGE` | 桥接 | DEFER 桥接超时配置有效 |
| `HUB_BRIDGE` | 桥接 | Latch Hub 桥接可达（如启用） |

### 示例

```bash
clawsentry doctor
```

??? example "终端输出"
    ```
    ClawSentry Doctor — 19 checks
    ══════════════════════════════

    [PASS] AUTH_PRESENCE      CS_AUTH_TOKEN is set
    [PASS] AUTH_LENGTH        Token length >= 32
    [PASS] AUTH_ENTROPY       Token entropy >= 3.5 bits/char
    [PASS] AUTH_WEAK_VALUE    Token is not a common weak value
    [WARN] UDS_PERMISSIONS    Socket file not found (will be created on start)
    [PASS] THRESHOLD_ORDERING Thresholds are in correct order
    [PASS] WEIGHT_BOUNDS      All weights >= 0
    [PASS] LLM_CONFIG         LLM provider/key consistency OK
    [WARN] OPENCLAW_SECRET    CS_OPENCLAW_WEBHOOK_SECRET not set
    [PASS] LISTEN_ADDRESS     Listening on localhost
    [PASS] WHITELIST_REGEX    All whitelist patterns compile OK
    [PASS] L2_BUDGET          CS_L2_BUDGET_MS is positive
    [PASS] TRAJECTORY_DB      Database directory is writable
    [PASS] CODEX_CONFIG       Codex config OK
    [WARN] LATCH_BINARY       Latch binary not installed
    [WARN] LATCH_HUB_HEALTH   Latch Hub not running
    [WARN] LATCH_TOKEN_SYNC   Latch not configured, skipped
    [PASS] DEFER_BRIDGE       DEFER bridge config OK
    [PASS] HUB_BRIDGE         Hub bridge not enabled, skipped

    ──────────────────────────────
    Result: 14 PASS, 5 WARN, 0 FAIL
    ```

#### JSON 输出

```bash
clawsentry doctor --json
```

??? example "JSON 输出"
    ```json
    {
      "checks": [
        {"id": "AUTH_PRESENCE", "category": "auth", "status": "PASS", "message": "CS_AUTH_TOKEN is set"},
        {"id": "AUTH_LENGTH", "category": "auth", "status": "PASS", "message": "Token length >= 32"}
      ],
      "summary": {"pass": 14, "warn": 5, "fail": 0}
    }
    ```

---

## clawsentry test-llm

`clawsentry test-llm` 用于做一轮实时 LLM 探针，确认当前 provider 配置、基础连通性、L2 语义分析链路，以及可选的 L3 审查链路是否正常。

### 语法

```bash
clawsentry test-llm [--json] [--no-color] [--skip-l3]
```

### 选项

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `--json` | `false` | 输出结构化 JSON 结果 |
| `--no-color` | `false` | 禁用 ANSI 颜色输出 |
| `--skip-l3` | `false` | 跳过 L3 probe，只验证 provider reachability 与 L2 |

### 它会检查什么

1. provider API reachability
2. 单次调用时延
3. L2 semantic analysis 对 sample suspicious event 的响应
4. 当 `CS_L3_ENABLED=true` 且未传 `--skip-l3` 时，额外执行一次 L3 review probe

### 示例

```bash
clawsentry test-llm
clawsentry test-llm --skip-l3
clawsentry test-llm --json
```

---

## clawsentry service

`clawsentry service` 用于把 Gateway 安装成用户级常驻服务，适合长期运行或系统登录后自动拉起。

### 语法

```bash
clawsentry service install [--no-enable]
clawsentry service uninstall
clawsentry service status
```

### 子命令

| 子命令 | 说明 |
|--------|------|
| `install` | 写入平台服务定义，并默认启用/启动 |
| `uninstall` | 停止并移除服务定义 |
| `status` | 查看当前服务状态 |

### 平台行为

- Linux：安装为 `systemd --user` service
- macOS：安装为 `~/Library/LaunchAgents` 下的 `launchd` user agent
- 环境变量文件：`~/.config/clawsentry/gateway.env`

### 选项

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `--no-enable` | `false` | 只写入服务文件，不立即 enable/start |

### 示例

```bash
clawsentry service install
clawsentry service install --no-enable
clawsentry service status
clawsentry service uninstall
```

更多部署细节见：[Deployment](../operations/deployment.md)。

---

## clawsentry config

管理项目级 `.clawsentry.toml` 配置文件。通过预设等级快速配置检测灵敏度。

### 语法

```bash
clawsentry config <subcommand> [options]
```

### 子命令

| 子命令 | 说明 |
|--------|------|
| `init` | 在当前目录创建 `.clawsentry.toml` |
| `show` | 显示当前项目配置 |
| `set <preset>` | 更新预设等级 |
| `disable` | 禁用 ClawSentry（设置 `enabled = false`） |
| `enable` | 启用 ClawSentry（设置 `enabled = true`） |

### `config init` 选项

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `--preset` | `medium` | 预设等级：`low`、`medium`、`high`、`strict` |
| `--force` | `false` | 覆盖已存在的 `.clawsentry.toml` |

### 预设等级

| 预设 | 说明 | 适用场景 |
|------|------|----------|
| `low` | 低灵敏度，仅拦截明确高危操作 | 个人开发、受信环境 |
| `medium` | 平衡灵敏度（推荐） | 日常开发 |
| `high` | 高灵敏度，更严格的阈值 | 团队协作、生产相关代码 |
| `strict` | 最严格模式，几乎所有可疑操作均触发审查 | 安全敏感项目 |

### 示例

#### 初始化配置

```bash
clawsentry config init --preset high
```

??? example "终端输出"
    ```
    Created .clawsentry.toml (preset: high)
    ```

#### 查看当前配置

```bash
clawsentry config show
```

??? example "终端输出"
    ```
      enabled: true
      preset:  high
      threshold_critical: 1.8
      threshold_high:     1.2
      threshold_medium:   0.5
    ```

#### 更改预设等级

```bash
clawsentry config set strict
```

#### 临时禁用 / 启用

```bash
clawsentry config disable
clawsentry config enable
```

### `.clawsentry.toml` 文件格式

```toml
[project]
enabled = true
preset = "high"
```

该文件应放置在项目根目录，Gateway 和 Harness 启动时会自动读取并应用预设配置。

---

## clawsentry rules

`clawsentry rules` 是规则治理入口，用于检查和预演当前 YAML 规则面。它刻意保持为窄范围治理层：管理的是 attack patterns / evolved patterns / review skills 这些规则资产，而不是跨 L1/L2/L3 的统一运行时策略语言。

### 语法

```bash
clawsentry rules lint [--attack-patterns PATH] [--evolved-patterns PATH] [--skills-dir DIR] [--json]
clawsentry rules dry-run --events FILE [--attack-patterns PATH] [--evolved-patterns PATH] [--skills-dir DIR] [--json]
```

### 子命令

| 子命令 | 说明 |
|--------|------|
| `lint` | 加载当前规则资产，输出 schema / duplicate / conflict / source 问题 |
| `dry-run` | 用 sample canonical events 预演 pattern 命中与 skill 选择结果 |

### 输入与输出

- `lint` 默认读取内置 `attack_patterns.yaml` 与 `skills/`，可额外叠加 `--evolved-patterns` 和 `--skills-dir`
- `dry-run --events` 接受三种输入：单个 JSON object、JSON array、JSONL
- `--json` 会返回 machine-readable 报告，包含 `fingerprint`、`source_summaries`、`version_summary`、`findings`

### 退出码

| 退出码 | 含义 |
|--------|------|
| `0` | 无 findings / 输入有效 |
| `1` | 存在规则治理 findings |
| `2` | CLI 调用错误或输入文件错误 |

### 示例

```bash
clawsentry rules lint --json
clawsentry rules dry-run --events examples/sample-events.jsonl --json
clawsentry rules dry-run --events my-events.json --skills-dir /etc/clawsentry/skills
```

!!! tip "和 L3 自定义 Skill 的关系"
    `clawsentry rules` 不会替换 L3 的运行时选择逻辑；它只是帮助你在 rollout 之前确认当前 YAML 规则面是否可加载、是否有冲突，以及 sample events 在当前规则面上会命中什么。

更多 authoring 细节见：[规则治理](../advanced/rule-governance.md)。

---

## clawsentry integrations

查看当前项目中已启用的框架集成状态。

### 语法

```bash
clawsentry integrations status [--dir PATH] [--json]
```

### 选项

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `--dir PATH` | `.`（当前目录） | 包含 `.env.clawsentry` 的项目目录 |
| `--json` | `false` | 输出 JSON，便于脚本或 CI 检查 |

### 示例

```bash
clawsentry integrations status
```

??? example "终端输出"
    ```
    ClawSentry Integrations
    ============================================================
    Env file: .env.clawsentry
    Env exists: yes
    Enabled frameworks: openclaw, codex, claude-code
    Legacy default: openclaw
    Codex watcher: enabled
    OpenClaw env: configured
    OpenClaw restore: available
    OpenClaw restore files: /home/user/.openclaw/openclaw.json.bak
    a3s transport env: not configured
    Claude hooks: not present
    Claude hooks files: (none)
    Codex session dir: /home/user/.codex/sessions (reachable)
    Framework readiness:
    openclaw: ready | project env and host approval files are aligned
      next step: No action required.
    codex: ready | watcher enabled and session directory is reachable
      next step: No action required.
    claude-code: needs attention | host hooks are missing, so Claude Code can bypass ClawSentry
      next step: Run clawsentry init claude-code to reinstall the required Claude hooks.
    ============================================================
    ```

`--json` 输出包含适合脚本消费的诊断字段，例如：

- `framework_readiness.<framework>.status / summary / checks / warnings / next_step`
- `openclaw_restore_available` / `openclaw_restore_files`
- `claude_code_hook_files`
- `codex_session_dir` / `codex_session_dir_reachable`

---

## clawsentry latch

管理 Latch 集成（下载安装、启停、状态查看）。Latch 提供跨设备手机监控、推送审批等增强功能。

### 语法

```bash
clawsentry latch <subcommand> [options]
```

### 子命令

| 子命令 | 说明 |
|--------|------|
| `install` | 下载并安装 Latch 二进制文件 |
| `start` | 启动 Gateway + Latch Hub |
| `stop` | 停止 Gateway + Latch Hub |
| `status` | 查看 Latch 栈运行状态 |
| `uninstall` | 卸载 Latch 二进制和数据 |

### `latch install` 选项

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `--no-shortcut` | `false` | 跳过桌面快捷方式创建 |

安装流程：

1. 从 GitHub Release 下载对应平台的 Latch 二进制压缩包
2. SHA-256 校验文件完整性
3. 解压到 `~/.clawsentry/latch/bin/`（支持 `tar.gz` 和 `zip`）
4. 设置可执行权限
5. 创建桌面快捷方式（可通过 `--no-shortcut` 跳过）

支持平台：Linux (x86_64, aarch64)、macOS (x86_64, arm64)、Windows (x86_64)

### `latch start` 选项

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `--gateway-port` | `8080` 或 `CS_HTTP_PORT` | Gateway HTTP 端口 |
| `--hub-port` | `3006` | Latch Hub 端口 |
| `--no-browser` | `false` | 启动后不自动打开浏览器 |

### `latch stop`

停止 Gateway 和 Latch Hub 进程。

```bash
clawsentry latch stop
```

### `latch status`

查看 Gateway 和 Latch Hub 的运行状态。

```bash
clawsentry latch status
```

### `latch uninstall` 选项

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `--keep-data` | `false` | 仅移除二进制和快捷方式，保留数据目录 |

### 示例

#### 安装 Latch

```bash
clawsentry latch install
```

??? example "终端输出"
    ```
    Downloading Latch v1.0.0 for linux-x86_64...
    Verifying SHA-256 checksum... OK
    Extracting to ~/.clawsentry/latch/bin/
    Latch installed successfully.
    ```

#### 启动完整栈

```bash
clawsentry latch start --hub-port 3006
```

??? example "终端输出"
    ```
    Starting Gateway on 127.0.0.1:8080...
    Starting Latch Hub on 127.0.0.1:3006...
    Gateway + Latch Hub ready.
    ```

#### 查看状态

```bash
clawsentry latch status
```

#### 卸载（保留数据）

```bash
clawsentry latch uninstall --keep-data
```

---

## 独立入口点

以下命令由 `pip install clawsentry` 注册为独立可执行文件，无需使用 `clawsentry` 前缀：

| 命令 | 等价于 | 入口模块 |
|------|--------|----------|
| `clawsentry-gateway` | `clawsentry gateway` | `clawsentry.gateway.server:main` |
| `clawsentry-harness` | `clawsentry harness` | `clawsentry.adapters.a3s_gateway_harness:main` |
| `clawsentry-stack` | `clawsentry stack` | `clawsentry.gateway.stack:main` |

!!! tip "何时使用独立入口"
    在 a3s-code SDK 代码中显式指定 `clawsentry-harness` 作为 `StdioTransport` 程序路径：
    ```python
    from a3s_code import Agent, SessionOptions, StdioTransport

    agent = Agent.create("agent.hcl")
    opts = SessionOptions()
    opts.ahp_transport = StdioTransport(program="clawsentry-harness", args=[])
    session = agent.session(".", opts, permissive=True)
    ```

---

## 环境变量速查

以下环境变量影响 CLI 行为。完整列表参见 [环境变量配置](../configuration/env-vars.md)。

| 变量 | 影响的命令 | 说明 |
|------|-----------|------|
| `CS_AUTH_TOKEN` | gateway, watch | HTTP API 认证令牌 |
| `CS_HTTP_HOST` | gateway | HTTP 监听地址 |
| `CS_HTTP_PORT` | gateway, watch | HTTP 监听端口 |
| `CS_UDS_PATH` | gateway, harness | UDS Socket 路径 |
| `CS_TRAJECTORY_DB_PATH` | gateway | 轨迹数据库路径 |
| `CS_RATE_LIMIT_PER_MINUTE` | gateway | 每 IP 每分钟请求限额 |
| `OPENCLAW_WEBHOOK_TOKEN` | gateway | OpenClaw Webhook 令牌 |
| `OPENCLAW_ENFORCEMENT_ENABLED` | gateway | 启用 OpenClaw WS 强制执行 |
| `OPENCLAW_OPERATOR_TOKEN` | gateway | OpenClaw WS 操作令牌 |
| `OPENCLAW_WS_URL` | gateway | OpenClaw WebSocket URL |
| `AHP_SESSION_ENFORCEMENT_ENABLED` | gateway | 启用会话级强制策略 |
| `AHP_SSL_CERTFILE` | gateway | SSL 证书文件路径 |
| `AHP_SSL_KEYFILE` | gateway | SSL 私钥文件路径 |
| `CS_FRAMEWORK` | start, init | 框架类型标识（`a3s-code`/`claude-code`/`codex`/`openclaw`） |
| `CS_CODEX_SESSION_DIR` | gateway | Codex 会话目录路径（用于 Session Watcher） |
| `CS_DEFER_TIMEOUT_ACTION` | gateway, harness | DEFER 超时后的动作：`block`（默认）或 `allow` |
| `CS_DEFER_TIMEOUT_S` | gateway, harness | DEFER 超时时间（秒），默认 `300` |
| `CS_LLM_DAILY_BUDGET_USD` | gateway | LLM 每日预算（美元），超出后降级为纯规则引擎 |
| `CS_METRICS_ENABLED` | gateway | 启用 Prometheus `/metrics` 端点 |
| `CS_LATCH_HUB_URL` | gateway, doctor | Latch Hub 地址（如 `http://127.0.0.1:3006`） |
| `CS_ENABLED_FRAMEWORKS` | init, docs | 多框架启用列表（如 `a3s-code,codex,openclaw`） |
