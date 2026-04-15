#!/usr/bin/env python3
"""
05 - Fallback & Degradation

演示当 Gateway 不可达时，Adapter 的本地降级策略。

降级矩阵（来自设计文档 04 section 11.3）：
  - 高危 pre_action（bash/exec 等危险工具）→ fail-closed: BLOCK
  - 普通 pre_action（非危险工具）          → defer: 延迟 1s 重试
  - pre_prompt / post_action 等            → fail-open:  ALLOW

核心理念：高风险操作宁可误杀不可放过，低风险操作宁可放行不可阻塞。

运行方式:
    python examples/clawsentry_quick_start/05_fallback_degradation.py
"""

from _helpers import print_section, print_json

# 直接使用 make_fallback_decision（无需 Gateway 运行）
from clawsentry.gateway.policy_engine import make_fallback_decision
from clawsentry.gateway.models import CanonicalEvent, EventType

print_section("05 - 降级容错：Gateway 不可达时的本地决策")

print("当 Gateway 宕机或网络不通时，Adapter 不会让 Agent 完全失控，")
print("而是执行本地降级决策。以下演示不同场景的降级行为：\n")


def make_event(tool: str, event_type: EventType, command: str = "") -> CanonicalEvent:
    """创建一个最小化的 CanonicalEvent 用于降级测试。"""
    payload = {"tool": tool}
    if command:
        payload["command"] = command
    return CanonicalEvent(
        event_id="fallback-test",
        trace_id="trace-fallback",
        event_type=event_type,
        session_id="fallback-session",
        agent_id="fallback-agent",
        source_framework="a3s-code",
        occurred_at="2026-03-20T00:00:00+00:00",
        payload=payload,
        event_subtype="tool:execute",
        tool_name=tool,
    )


# ── 场景 1: 高危工具 pre_action → fail-closed ────────────────────
print("--- 场景 1: 高危工具 (bash) + pre_action → fail-closed ---\n")

event1 = make_event("bash", EventType.PRE_ACTION, "rm -rf /tmp")
decision1 = make_fallback_decision(event1)

print(f"  tool=bash  event_type=pre_action")
print(f"  verdict:   {decision1.decision.value}")
print(f"  risk:      {decision1.risk_level.value}")
print(f"  policy_id: {decision1.policy_id}")
print(f"  reason:    {decision1.reason}")

# ── 场景 2: 安全工具 pre_action → defer ──────────────────────────
print("\n--- 场景 2: 安全工具 (write_file) + pre_action → defer ---\n")

event2 = make_event("write_file", EventType.PRE_ACTION)
decision2 = make_fallback_decision(event2)

print(f"  tool=write_file  event_type=pre_action")
print(f"  verdict:        {decision2.decision.value}")
print(f"  risk:           {decision2.risk_level.value}")
print(f"  retry_after_ms: {decision2.retry_after_ms}")
print(f"  reason:         {decision2.reason}")

# ── 场景 3: pre_prompt → fail-open ───────────────────────────────
print("\n--- 场景 3: pre_prompt → fail-open ---\n")

event3 = make_event("prompt", EventType.PRE_PROMPT)
decision3 = make_fallback_decision(event3)

print(f"  event_type=pre_prompt")
print(f"  verdict:   {decision3.decision.value}")
print(f"  risk:      {decision3.risk_level.value}")
print(f"  reason:    {decision3.reason}")

# ── 场景 4: post_action → fail-open ──────────────────────────────
print("\n--- 场景 4: post_action（审计类事件）→ fail-open ---\n")

event4 = make_event("bash", EventType.POST_ACTION, "ls")
decision4 = make_fallback_decision(event4)

print(f"  tool=bash  event_type=post_action")
print(f"  verdict:   {decision4.decision.value}")
print(f"  risk:      {decision4.risk_level.value}")
print(f"  reason:    {decision4.reason}")

print("""
降级策略汇总:
  ┌─────────────────────────┬─────────────┬───────────────────┐
  │ 场景                     │ 降级策略     │ 决策              │
  ├─────────────────────────┼─────────────┼───────────────────┤
  │ 高危工具 + pre_action    │ fail-closed │ BLOCK (宁杀勿放)  │
  │ 普通工具 + pre_action    │ defer       │ 延迟 1s 后重试    │
  │ pre_prompt              │ fail-open   │ ALLOW (不阻塞输入) │
  │ post_action / 审计类     │ fail-open   │ ALLOW (仅观测)    │
  └─────────────────────────┴─────────────┴───────────────────┘
""")
