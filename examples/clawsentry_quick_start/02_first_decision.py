#!/usr/bin/env python3
"""
02 - First Decision

发送两个事件到 Gateway，观察不同操作如何得到不同的决策：
  - 安全操作（Read 工具读文件）→ allow
  - 危险操作（bash rm -rf /）  → block

运行方式:
    python examples/clawsentry_quick_start/02_first_decision.py
"""

from _helpers import create_gateway, send_event, run, print_section, print_decision

gateway = create_gateway()


async def main():
    print_section("02 - First Decision: 安全 vs 危险操作")

    # ── 场景 A: 安全的只读操作 ────────────────────────────────────
    print("场景 A: Agent 想读取一个普通文件")
    print("  tool = read_file,  path = /tmp/notes.txt\n")

    result_a = await send_event(
        gateway,
        "read_file",
        path="/tmp/notes.txt",
    )
    print_decision(result_a, label="read_file")

    # ── 场景 B: 极度危险的操作 ────────────────────────────────────
    print("\n场景 B: Agent 想执行 rm -rf /")
    print("  tool = bash,  command = rm -rf /\n")

    result_b = await send_event(
        gateway,
        "bash",
        command="rm -rf /",
    )
    print_decision(result_b, label="bash rm -rf")

    # ── 场景 C: 中等风险操作 ──────────────────────────────────────
    print("\n场景 C: Agent 想写入一个普通文件")
    print("  tool = write_file,  path = /tmp/output.txt\n")

    result_c = await send_event(
        gateway,
        "write_file",
        path="/tmp/output.txt",
    )
    print_decision(result_c, label="write_file")

    print("""
总结：
  - read_file   → LOW 风险    → allow（只读工具 + 普通路径 → 短路 SC-3）
  - bash rm -rf → CRITICAL 风险 → block（高危命令模式 → 短路 SC-2）
  - write_file  → MEDIUM 风险  → allow（有限写入，审计记录但放行）
""")


run(main())
