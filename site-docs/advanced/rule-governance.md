---
title: CS-01 规则治理
description: CS-01 作者期规则治理面：YAML authoring surface、lint、dry-run、fingerprint 与 rollout 前检查
---

# CS-01 规则治理

`CS-01` 的目标不是把 ClawSentry 重写成一个横跨 L1/L2/L3 的全局运行时 DSL，而是把现有 YAML 规则面的**作者期治理**补齐：在 rollout 之前检查规则是否能加载、是否有冲突，以及 sample events 在当前规则面上会命中什么。

!!! abstract "本页快速导航"
    [边界](#scope) · [规则面组成](#rule-surfaces) · [clawsentry rules lint](#rules-lint) · [clawsentry rules dry-run](#rules-dry-run) · [典型工作流](#workflow) · [输出字段](#outputs)

## 作用边界 {#scope}

当前版本的 `CS-01` 只管理以下 authoring surface：

- L2 attack patterns YAML
- 可选 evolved patterns YAML
- L3 review skills YAML

它**不**做这些事：

- 不引入新的运行时 scheduler
- 不替换 `PatternMatcher` / `SkillRegistry` / `L3TriggerPolicy`
- 不构造一个覆盖 L1/L2/L3 控制流的全局 DSL

更准确的理解是：

> `CS-01` 是“规则作者在上线前自检和预演”的治理层，不是“运行时策略解释器”。

## 规则面组成 {#rule-surfaces}

| 规则面 | 主要文件 | 作用 |
|--------|----------|------|
| Core attack patterns | `src/clawsentry/gateway/attack_patterns.yaml` | L2 规则库主干 |
| Evolved patterns | `CS_EVOLVED_PATTERNS_PATH` 指向的 YAML | E-5 提升后的 experimental / stable 模式 |
| Built-in review skills | `src/clawsentry/gateway/skills/*.yaml` | L3 内置审查技能 |
| Custom review skills | `--skills-dir` 指向的目录 | rollout 前追加的自定义 L3 技能 |

默认情况下：

- built-in review skills 总是加载
- `--skills-dir` 会在 built-in 基础上叠加，而不是替换
- `--evolved-patterns` 会把 active evolved patterns 纳入治理报告

## `clawsentry rules lint` {#rules-lint}

```bash
clawsentry rules lint [--attack-patterns PATH] [--evolved-patterns PATH] [--skills-dir DIR] [--json]
```

`lint` 会输出当前规则面的治理报告，重点看：

- source 是否存在、是否可解析
- attack pattern 的 item-level schema 问题
- core/evolved 之间的重复 ID
- review skill 的重复名称与触发签名冲突
- 当前规则集的 deterministic fingerprint

### 示例

```bash
clawsentry rules lint --json
clawsentry rules lint \
  --attack-patterns /opt/clawsentry/patterns.yaml \
  --evolved-patterns /var/lib/clawsentry/evolved_patterns.yaml \
  --skills-dir /etc/clawsentry/skills \
  --json
```

## `clawsentry rules dry-run` {#rules-dry-run}

```bash
clawsentry rules dry-run --events FILE [--attack-patterns PATH] [--evolved-patterns PATH] [--skills-dir DIR] [--json]
```

`dry-run` 不会修改任何运行时状态，只会把 sample canonical events 放到当前规则面上预演：

- 哪些 attack pattern 会命中
- 最终会选中哪个 review skill
- 当前输入是否存在 parse / schema 问题

### 支持的输入格式

- 单个 JSON object
- JSON array
- JSONL

仓库内置了一个最小 sample fixture：

```bash
clawsentry rules dry-run --events examples/sample-events.jsonl --json
```

## 典型工作流 {#workflow}

### 调整 attack patterns 后

```bash
clawsentry rules lint --attack-patterns /opt/clawsentry/patterns.yaml --json
clawsentry rules dry-run --attack-patterns /opt/clawsentry/patterns.yaml \
  --events examples/sample-events.jsonl --json
```

### 调整自定义 L3 skills 后

```bash
clawsentry rules lint --skills-dir /etc/clawsentry/skills --json
clawsentry rules dry-run --skills-dir /etc/clawsentry/skills \
  --events examples/sample-events.jsonl --json
```

### 与 release checklist 一起使用

如果本次版本包含 `CS-01` 相关修改，发布前至少保留两条 smoke：

```bash
PYTHONPATH=src python -m clawsentry rules lint --json
PYTHONPATH=src python -m clawsentry rules dry-run --events examples/sample-events.jsonl --json
```

## 输出字段 {#outputs}

### `fingerprint`

当前完整规则集的 deterministic digest。它会受以下内容影响：

- core attack patterns
- active evolved patterns
- built-in + custom review skills

这个值适合用于 rollout 记录和“当前实际规则面是不是同一版”的快速判断。

### `source_summaries`

按 source 列出当前加载了哪些规则资产，例如：

- `attack_patterns`
- `evolved_patterns`
- `review_skills`
- `custom_review_skills`

### `version_summary`

提供更适合记录的版本摘要，包括：

- attack patterns 版本
- evolved patterns 版本
- review skills 版本摘要
- active pattern / skill 数量
- inactive evolved pattern 数量

### `findings`

结构化治理结果。当前常见的 findings 包括：

- source 缺失
- YAML 解析失败
- item-level schema 问题
- duplicate attack pattern id
- duplicate review skill name
- review skill signature conflict
- invalid dry-run event

## 与其他页面的关系

- [CLI 命令参考](../cli/index.md) — `rules` 命令语法与退出码
- [攻击模式定制](attack-patterns.md) — attack patterns YAML 结构
- [自定义 L3 Skills](custom-skills.md) — review skills YAML 结构
- [自进化模式库](pattern-evolution.md) — evolved patterns 来源
