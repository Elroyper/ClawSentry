# Benchmark 总登记表

| bench_slug | 来源仓库 | 本地路径 | 上游 commit | 当前状态 | 主要文档 | 当前入口 | 备注 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `skills-safety-bench` | `git@github.com:jinchang1223/skills-safety-bench.git` | `./skills-safety-bench` | `148133b` | 已 clone；dry-run 已验证；Harbor/Docker 可用；真实 Codex 单 case 仍需稳定 provider/Node 22 链路 | `README.md`、`benchmark/readme.md` | `scripts/start_codex_batch.sh`、本地 wrapper `scripts/skills_safety_bench_codex.sh` | 6 个 RD，155 个 case；当前自动 runner 只确认 Codex；case 自带 Docker 环境并通过 Harbor 执行 |
| `agentdog-atbench` | `https://github.com/AI45Lab/AgentDoG.git` | `./AgentDoG` | `09adfb8` | 已 clone；converter + ClawSentry L2 real-API sample smoke 已跑通；labeled manifest batch replay 入口已实现；真实 ATBench 标签评测待准备数据 | `README.md`、`examples/trajectory_sample.json`、`prompts/` | 本地 runner `scripts/agentdog_atbench_clawsentry.py`（`--trajectory` / `--manifest`） | 轨迹级安全评测；上游不自带 Docker/Harbor 环境；下一步准备真实 `5 safe + 5 unsafe` manifest 跑 L1/L2，再做 live runners |

## 状态说明

- `已 clone`：源码已经存在于本地。
- `dry-run 已验证`：manifest 解析、case 选择、runner 计划生成已验证，不代表模型和 Docker 真实执行已完成。
- `完整真实运行已验证`：至少一个 case 经过 agent 执行和攻击验证 replay。
- `阻塞`：缺少运行时依赖、凭据、适配器或外部服务。

## 框架支持状态

| 框架 | 裸执行当前状态 | 加 ClawSentry 当前状态 | 依据 |
| --- | --- | --- | --- |
| Codex | 可通过 Harbor runner 执行；本机 Harbor/Docker 已可用，但真实 provider 链路仍需复测 | 可测，前提是把 OpenAI-compatible endpoint 指到 ClawSentry gateway | 上游脚本硬编码 `harbor run -a codex` |
| Claude Code | case 环境里有不少 `.claude/skills` 布局，但没有现成批量 runner | 需要 Claude Code runner/adapter 接入 ClawSentry endpoint 后再验证 | 当前仓库未发现 Claude Code 批量入口 |
| OpenClaw | 未发现现成批量 runner | 需要 OpenClaw runner/adapter 接入 ClawSentry endpoint 后再验证 | 当前仓库未发现 OpenClaw 批量入口 |
| A3S-Code | 未发现现成批量 runner | 需要 A3S-Code runner/adapter 接入 ClawSentry endpoint 后再验证 | 当前仓库未发现 A3S-Code 批量入口 |

## AgentDoG / ATBench 接入结论

AgentDoG 可以用来评测 ClawSentry，但不是开箱即用的 live agent runner。推荐路线：

1. 已完成 `smoke replay`：将上游 sample trajectory 转换为 ClawSentry canonical events，并用 `agent.hcl` 的真实 API 配置跑通 L2 replay；最新产物为 `benchmarks/results/agentdog-atbench/2026-04-27_realapi_agentdog_singlecase_e91cd0f/`。
2. 已完成 `labeled manifest replay` 入口：本地 runner 支持 labeled JSON/JSONL manifest，输出 `selected_records.json`、aggregate `summary.json/md` 和每条 trajectory 的 replay artifacts；当前只用临时 fixture 做过 contract/CLI smoke，不是正式 ATBench 得分。
3. 下一步做真实 `labeled offline replay`：从 ATBench 选 `5 safe + 5 unsafe` 最小样本集，评估检测率、误报率、pre-action/post-action 覆盖和 L2/L3 成本。
4. `live runner`：在转换和指标稳定后，为 `a3s-code`、`codex`、`claude-code`、`gemini-cli` 和可选 `openclaw` 分别做相同任务、相同模型、相同工具模拟的 raw vs ClawSentry 对照。

结论：这个 benchmark 的 trajectory 数据可作为多框架评测素材；当前已证明 ClawSentry offline replay 基建与单 case 真实 API 路径可用，但“ClawSentry 是否比单纯框架更安全”还需要 labeled ATBench 样本和 raw-vs-protected live runner 对照。AgentDoG 没有像 skills-safety-bench 那样的 Harbor/Docker case 环境；如要跑真实 framework execution，需要单独建设 runner/container 层，建议复用 Harbor。
