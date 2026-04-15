---
title: 规则治理
description: YAML 规则与技能的上线前治理：lint、dry-run、fingerprint 与 rollout 前检查
---

# 规则治理

这页是给**规则作者、风控同学和安全运营人员**看的。

如果你只记一句话，可以记这个：

> 规则治理就是“上线前先体检一遍规则”，确认它能不能加载、会不会互相打架、用样例事件跑出来是不是你预期的结果。

它处理的是**上线前检查**，不是新的运行时策略语言。你不需要先理解内部 L1/L2/L3 实现，只要按本页流程走，就能把大多数明显问题挡在上线前。

!!! abstract "本页快速导航"
    [边界](#scope) · [规则面组成](#rule-surfaces) · [clawsentry rules lint](#rules-lint) · [clawsentry rules dry-run](#rules-dry-run) · [典型工作流](#workflow) · [输出字段](#outputs)

## 先区分“编写”和“治理”

这页讲的是**治理**，也就是检查和预演。

如果你想知道：

- 哪些高级能力可以由业务或安全团队编写
- 攻击模式和 L3 Skills 分别应该去哪里看
- 这些内容改完后是如何生效的

建议先看：[自定义能力总览](authoring-overview.md)。

可以把两页的分工理解成：

- [自定义能力总览](authoring-overview.md)：回答“能改什么、去哪改、怎么生效”
- 当前页：回答“改完之后怎么检查能不能上线”

## 什么时候用这页

通常有三种情况：

- 你改了攻击模式，想确认规则文件本身没写坏
- 你新增了自定义 L3 Skill，想确认能被正确加载和选中
- 你准备发版，想先拿样例事件预演一遍

最常用的命令只有两条：

```bash
clawsentry rules lint --json
clawsentry rules dry-run --events examples/sample-events.jsonl --json
```

可以把它们理解成：

- `lint`：查规则文件有没有问题
- `dry-run`：拿样例事件预演结果

## 作用边界 {#scope}

当前版本的规则治理只管理以下规则资产：

- L2 attack patterns YAML
- 可选 evolved patterns YAML
- L3 review skills YAML

它**不**做这些事：

- 不引入新的运行时 scheduler
- 不替换 `PatternMatcher` / `SkillRegistry` / `L3TriggerPolicy`
- 不把 ClawSentry 改造成一个覆盖 L1/L2/L3 的全局 DSL

更准确的理解是：

> 规则治理是“作者期自检和预演”的治理层，不是“运行时解释器”。

## 规则面组成 {#rule-surfaces}

| 规则面 | 主要文件 | 作用 |
|--------|----------|------|
| Core attack patterns | `src/clawsentry/gateway/attack_patterns.yaml` | L2 规则库主干 |
| Evolved patterns | `CS_EVOLVED_PATTERNS_PATH` 指向的 YAML | E-5 提升后的 experimental / stable 模式 |
| Built-in review skills | `src/clawsentry/gateway/skills/*.yaml` | L3 内置审查技能 |
| Custom review skills | `--skills-dir` 指向的目录 | 上线前追加的自定义 L3 技能 |

默认情况下：

- built-in review skills 总是加载
- `--skills-dir` 会在 built-in 基础上叠加，而不是替换
- `--evolved-patterns` 会把 active evolved patterns 纳入治理报告

## 三步完成一次上线前检查

### 第 1 步：先看规则文件能不能用

```bash
clawsentry rules lint --json
```

这一步主要回答：

- 文件在不在
- YAML 能不能解析
- 规则 ID / Skill 名称有没有重复
- 有没有明显冲突

### 第 2 步：再拿样例事件预演

```bash
clawsentry rules dry-run --events examples/sample-events.jsonl --json
```

这一步主要回答：

- 哪些 attack pattern 会命中
- 最终会选中哪个 review skill
- 样例输入本身有没有格式问题

### 第 3 步：结果符合预期再 rollout

只有前两步结果都符合预期时，才建议继续发布、灰度或合并到正式规则面。

## `clawsentry rules lint` {#rules-lint}

```bash
clawsentry rules lint [--attack-patterns PATH] [--evolved-patterns PATH] [--skills-dir DIR] [--json]
```

`lint` 会输出当前规则面的治理报告。最值得优先看的内容是：

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

`dry-run` 不会修改任何运行时状态。你可以把它理解成“先拿样例事件跑一遍”：

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

### 改了 attack patterns 之后

```bash
clawsentry rules lint --attack-patterns /opt/clawsentry/patterns.yaml --json
clawsentry rules dry-run --attack-patterns /opt/clawsentry/patterns.yaml \
  --events examples/sample-events.jsonl --json
```

### 改了自定义 L3 Skills 之后

```bash
clawsentry rules lint --skills-dir /etc/clawsentry/skills --json
clawsentry rules dry-run --skills-dir /etc/clawsentry/skills \
  --events examples/sample-events.jsonl --json
```

### 发版前最小检查

如果本次版本包含规则相关修改，发布前至少保留两条 smoke：

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

按 source 列出当前到底加载了哪些规则资产，例如：

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

结构化检查结果。当前常见的 findings 包括：

- source 缺失
- YAML 解析失败
- item-level schema 问题
- duplicate attack pattern id
- duplicate review skill name
- review skill signature conflict
- invalid dry-run event

## 与其他页面的关系

- [自定义能力总览](authoring-overview.md) — 高级用法里哪些内容可以编写、如何生效
- [CLI 命令参考](../cli/index.md) — `rules` 命令语法与退出码
- [攻击模式定制](attack-patterns.md) — 如何编写 attack patterns 规则
- [自定义 L3 Skills](custom-skills.md) — 如何编写 review skills
- [自进化模式库](pattern-evolution.md) — evolved patterns 来源
