# ClawSentry Quick Start — a3s-code 用户指南

> 面向 a3s-code 开发者的渐进式教程，8 个独立可运行脚本，完整展示 ClawSentry 的核心功能。

## 前置条件

```bash
# 安装 ClawSentry（开发模式）
cd ClawSentry
pip install -e ".[dev]"
```

## 运行方式

每个脚本都是自包含的（内嵌 Gateway，无需启动外部服务），直接运行即可：

```bash
cd examples/clawsentry_quick_start
python 01_hello_gateway.py
```

## 脚本索引

| 脚本 | 主题 | 演示内容 |
|------|------|---------|
| `01_hello_gateway.py` | Hello Gateway | 创建 Gateway，查看健康状态 |
| `02_first_decision.py` | 第一个决策 | 安全操作 → allow，危险操作 → block |
| `03_risk_dimensions.py` | D1-D5 五维评估 | 每个维度如何影响风险分级 + 短路规则 |
| `04_session_accumulation.py` | 会话风险累积 | D4 维度变化 → 中等风险操作被拦截 |
| `05_fallback_degradation.py` | 降级容错 | Gateway 不可达时的 fail-closed/fail-open |
| `06_l2_semantic_analysis.py` | L2 语义分析 | RuleBased / LLM / Composite 三种分析器 |
| `07_trajectory_and_reports.py` | 审计轨迹与报表 | 轨迹存储、摘要统计、会话回放 |
| `08_http_auth.py` | HTTP 认证 | Bearer Token 保护端点，/health 始终开放 |

## 建议阅读顺序

```
01 (基础) → 02 (决策) → 03 (评分) → 04 (累积) → 05 (降级)
                                                      ↓
                            08 (认证) ← 07 (审计) ← 06 (L2)
```

- **01-02**：理解 Gateway 的基本工作模式
- **03-04**：深入 D1-D5 五维评估和会话状态
- **05**：理解安全保障（降级策略）
- **06**：了解 L2 语义分析的扩展能力
- **07**：了解审计轨迹和报表功能
- **08**：了解生产部署的安全配置

## 生产环境使用

示例脚本使用内嵌模式（直接调用 Python API）方便理解。生产环境中通常使用 CLI + 网络模式：

```bash
# 终端 1: 启动 Gateway（UDS + HTTP 双通道）
clawsentry-gateway

# 终端 2（a3s-code 配置）:
# opts.ahp_transport = StdioTransport(program="clawsentry-harness")
```

详见 `src/clawsentry/README.md` 的完整部署指南。

## 文件说明

- `_helpers.py` — 共享工具函数（Gateway 创建、事件构造、格式化输出）
- `01-08_*.py` — 可独立运行的示例脚本
