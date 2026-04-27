# Benchmarks 工作区

这个目录用于集中管理安全评测 benchmark，目标是评估 agent 框架在被攻击任务中的表现，以及 ClawSentry 等防御系统的拦截效果。

约定：上游 benchmark 仓库尽量保持干净，不直接在 clone 目录里写本地说明、实验记录和长期结果。外层 `benchmarks/` 负责统一索引、运行规范和结果归档。

## 目录结构

```text
benchmarks/
  BENCHMARKS.md                 # benchmark 总登记表
  RUNBOOK.md                    # 跨 benchmark 的通用运行规范
  RESULTS.md                    # 跨 benchmark 的结果索引
  scripts/                      # 本地便捷运行脚本
  notes/<bench-slug>/           # 每个 benchmark 的本地说明
  results/<bench-slug>/         # 长期保存的运行结果，默认不入库
  skills-safety-bench/          # 上游 clone
  AgentDoG/                     # 上游 clone
```

## 当前已接入的 Benchmark

当前已 clone：

```text
skills-safety-bench/
AgentDoG/
```

来源：

```text
git@github.com:jinchang1223/skills-safety-bench.git
https://github.com/AI45Lab/AgentDoG.git
```

它是一个静态 Harbor / SkillsBench 风格 benchmark，包含 6 个风险域、30 个 category、155 个已准备好的攻击 case。详细结构见：

- [BENCHMARKS.md](BENCHMARKS.md)
- [notes/skills-safety-bench/BENCHMARK_NOTES.md](notes/skills-safety-bench/BENCHMARK_NOTES.md)
- [notes/skills-safety-bench/RUNBOOK.md](notes/skills-safety-bench/RUNBOOK.md)
- [notes/agentdog-atbench/BENCHMARK_NOTES.md](notes/agentdog-atbench/BENCHMARK_NOTES.md)
- [notes/agentdog-atbench/RUNBOOK.md](notes/agentdog-atbench/RUNBOOK.md)

## 现在能确认什么

已确认：

- `skills-safety-bench` 仓库已 clone，当前 commit 为 `148133b`。
- `skills-safety-bench` 自带的 runner 能 dry-run 解析 RD1-RD6 的所有 manifest。
- 当前上游脚本是 Codex 专用批量入口：`scripts/start_codex_batch.sh` 内部通过 Harbor 调用 `harbor run -a codex`。
- 任务目录本身包含 `attacked_task/`、Docker 环境、测试脚本和 `eval/verify_attack.py`，理论上可以被适配到其他 agent 框架。
- 本机当前 Harbor/Docker 可用：`harbor --version` 为 `0.4.0`，Docker server 为 `29.1.5`。
- AgentDoG 上游当前没有 `Dockerfile` / compose 环境；它更像 trajectory / prompt / XAI 评测素材仓库，本地通过 ClawSentry replay runner 承接。

尚未确认：

- Claude Code、OpenClaw、A3S-Code 的自动化 runner 还没有在这个仓库中出现。
- 加入 ClawSentry 后的四框架自动化测试还需要对应框架的运行适配层。
- skills-safety-bench 的完整真实执行仍未拿到有效业务输出；当前阻塞已不是 Harbor 缺失，而是 Codex/provider 真实执行链路稳定性与 Node 22 运行环境。

## 如何快速试用

最安全的入口是本地 wrapper，默认只 dry-run，不会调用模型：

```bash
bash scripts/skills_safety_bench_codex.sh --rd 1 --case travel_planning_skill_name_decoy_singular_alias
```

真实执行需要安装 Harbor、切换 Node 22，并显式加 `--real-run`：

```bash
bash scripts/skills_safety_bench_codex.sh \
  --rd 1 \
  --case travel_planning_skill_name_decoy_singular_alias \
  --defense raw \
  --real-run
```

测试 ClawSentry 时，先启动 ClawSentry 的 OpenAI-compatible gateway，把 `.envrc` 或 shell 环境中的 `OPENAI_BASE_URL` / `OPENAI_API_KEY` 指向防御后的 endpoint，再运行同一个命令并把 `--defense` 标成 `clawsentry`。

## AgentDoG / ATBench 快速试用

AgentDoG/ATBench 适合作为 ClawSentry 的轨迹级安全评测源。第一阶段使用离线 replay，不直接启动真实 agent：

```bash
python benchmarks/scripts/agentdog_atbench_clawsentry.py \
  --trajectory benchmarks/AgentDoG/examples/trajectory_sample.json \
  --output /tmp/agentdog-clawsentry-events.jsonl \
  --framework agentdog-atbench \
  --print-summary
```

后续 live runner 再分别覆盖 `a3s-code`、`codex`、`claude-code`、`gemini-cli` 和可选 `openclaw`。

当前已验证真实 API 单 case replay：

```bash
env -u HTTPS_PROXY -u HTTP_PROXY -u ALL_PROXY -u https_proxy -u http_proxy -u all_proxy \
python benchmarks/scripts/agentdog_atbench_clawsentry.py \
  --trajectory benchmarks/AgentDoG/examples/trajectory_sample.json \
  --output benchmarks/results/agentdog-atbench/2026-04-27_realapi_agentdog_singlecase_e91cd0f/events-converted.jsonl \
  --framework agentdog-atbench \
  --agent-hcl agent.hcl \
  --llm-temperature 1 \
  --llm-provider-timeout-ms 30000 \
  --decision-tier L2 \
  --replay \
  --result-dir benchmarks/results/agentdog-atbench/2026-04-27_realapi_agentdog_singlecase_e91cd0f \
  --print-summary
```

结果：`3` events / `3` decisions，全部 L2，max risk `medium`，API key 只以 `<redacted>` 写入 summary。该 sample 没有 ground-truth label，因此仍是基建 smoke，不是正式 ATBench 分数。

## 五框架单 case smoke

如果目标是先确认五个框架的 ClawSentry 接入链路都能跑通同一个 case，可以使用本地 deterministic ingress smoke：

```bash
python benchmarks/scripts/framework_single_case_smoke.py \
  --result-dir /tmp/clawsentry-framework-single-case \
  --print-summary
```

这个脚本覆盖 `claude-code`、`codex`、`gemini-cli`、`a3s-code`、`openclaw`
五条现有 adapter/harness/Gateway 路径。它不启动真实框架 CLI，因此只作为接入链路 smoke，不作为正式 benchmark 得分。
