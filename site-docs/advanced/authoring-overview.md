---
title: 自定义能力总览
description: 高级用法中的可定制能力总览：哪些内容可由业务或安全团队编写、去哪里查看详细指南、如何生效以及如何上线前检查
---

# 自定义能力总览

这一页回答的是一个更上层的问题：

> 在 ClawSentry 的高级用法里，哪些内容可以被定制，分别由谁来定制，改完之后如何生效？

如果你是第一次进入“高级用法”，建议先看这一页，再进入具体的编写页面。

!!! abstract "本页快速导航"
    [先建立整体认识](#overview) · [业务和安全团队可编写的部分](#authorable-surfaces) · [需要开发介入的扩展点](#developer-surfaces) · [这些改动如何起作用](#how-it-takes-effect) · [推荐工作流](#workflow)

## 先建立整体认识 {#overview}

ClawSentry 的高级定制能力可以分成两类：

- **规则与技能编写**：主要通过 YAML 调整现有检测与审查能力，适合规则作者、安全运营和风控团队参与
- **系统扩展开发**：通过代码接入新的分析器、Adapter 或基础能力，适合开发人员参与

对大多数非研发使用者来说，真正需要重点关注的是前一类，也就是：

- L2 攻击模式
- L3 审查 Skills
- 上线前的规则治理检查

## 业务和安全团队可编写的部分 {#authorable-surfaces}

下表按“能改什么”来组织，而不是按内部模块名来组织：

| 可定制内容 | 适合谁 | 主要作用 | 详细页面 | 改完如何生效 | 上线前建议 |
|-----------|--------|----------|----------|--------------|------------|
| 攻击模式（Attack Patterns） | 规则作者、安全运营、风控 | 定义哪些工具调用特征会在 L2 被命中 | [攻击模式定制](attack-patterns.md) | 通过 `CS_L2_ATTACK_PATTERNS_PATH` 加载，自定义规则与内置规则合并生效 | 先跑 [规则治理](rule-governance.md) 的 `lint` 和 `dry-run` |
| 自定义 L3 Skills | 安全专家、领域负责人、规则作者 | 定义高风险事件进入 L3 时，模型应该按哪种专家视角审查 | [自定义 L3 Skills](custom-skills.md) | 通过 `AHP_SKILLS_DIR` 加载，在内置 Skills 基础上追加 | 先跑 [规则治理](rule-governance.md) 的 `lint` 和 `dry-run` |
| 自进化模式库（Evolved Patterns） | 安全运营、规则维护者 | 管理从生产数据中沉淀出的实验性或稳定模式 | [自进化模式库](pattern-evolution.md) | 通过 `CS_EVOLVED_PATTERNS_PATH` 纳入当前规则面 | 在 rollout 前用 [规则治理](rule-governance.md) 统一检查 |

### 如何理解这三类内容

可以把它们理解成三种不同层次的“可编写面”：

- **Attack Patterns**：决定“什么行为值得被规则命中”
- **L3 Skills**：决定“命中高风险后，模型应该从什么专业角度继续审查”
- **规则治理**：不负责定义规则本身，而是负责检查这些规则和 Skills 在上线前是否可用、是否冲突、预演结果是否符合预期

因此，`规则治理` 更接近“检查与预演”页，而不是“编写规则”页。

## 需要开发介入的扩展点 {#developer-surfaces}

下面这些页面仍然属于高级用法，但通常不面向业务人员直接编写：

| 扩展点 | 主要作用 | 详细页面 | 典型读者 |
|-------|----------|----------|----------|
| 自定义 L2 Analyzer | 扩展新的 L2 分析逻辑，不局限于现有规则匹配 | [自定义 L2 Analyzer](custom-analyzer.md) | 后端 / 平台开发 |
| 自定义 Adapter | 把新的 Agent 框架或运行时接入 ClawSentry | [自定义 Adapter](custom-adapter.md) | 集成开发、平台开发 |
| 向量相似度接入 (D6) | 为语义相似度或检索相关能力接入向量后端 | [向量相似度接入 (D6)](embedding-backend.md) | 算法 / 平台开发 |

这些页面依然重要，但它们的改动通常意味着代码实现、部署或基础设施调整，而不是单纯的规则编写。

## 这些改动如何起作用 {#how-it-takes-effect}

无论你改的是攻击模式、L3 Skills 还是自进化模式库，实际生效路径都可以概括成同一条链路：

1. 在对应页面按照 YAML 或配置约定完成编写
2. 通过环境变量或指定目录把这些内容纳入当前规则面
3. 用 [规则治理](rule-governance.md) 做 `lint` 和 `dry-run`
4. 重启对应服务或按既有 rollout 流程发布

从运行机制上看：

- L2 攻击模式会影响规则匹配层的命中结果
- L3 Skills 会影响高风险事件进入 L3 后的审查视角和提示词
- Evolved Patterns 会作为当前有效规则面的一部分参与命中与治理报告

## 推荐工作流 {#workflow}

如果你的目标是“让业务或安全团队新增一条可维护的自定义能力”，推荐按下面的顺序阅读和操作：

### 场景 1：我要新增或调整规则命中条件

1. 先看 [攻击模式定制](attack-patterns.md)
2. 写好 YAML 后，进入 [规则治理](rule-governance.md)
3. 运行 `clawsentry rules lint` 与 `clawsentry rules dry-run`
4. 结果符合预期后再发布

### 场景 2：我要让 L3 更懂某个业务领域

1. 先看 [自定义 L3 Skills](custom-skills.md)
2. 按领域编写新的 Skill YAML
3. 再到 [规则治理](rule-governance.md) 做加载检查与样例预演
4. 通过后再纳入正式部署

### 场景 3：我不确定该从哪一页开始

可以先用下面的判断：

- 想定义“哪些行为应被规则命中” → [攻击模式定制](attack-patterns.md)
- 想定义“高风险后模型该怎么审” → [自定义 L3 Skills](custom-skills.md)
- 想确认“当前这套规则能不能上线” → [规则治理](rule-governance.md)
- 想扩展系统本身的分析或接入能力 → 看各类开发向扩展页面

## 相关页面

- [规则治理](rule-governance.md) — 上线前检查、预演和冲突排查
- [攻击模式定制](attack-patterns.md) — 编写 L2 规则
- [自定义 L3 Skills](custom-skills.md) — 编写 L3 审查技能
- [自进化模式库](pattern-evolution.md) — 管理 evolved patterns
- [CLI 命令参考](../cli/index.md) — `clawsentry rules` 命令语法与退出码
