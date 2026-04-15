#!/usr/bin/env python3
"""
03 - Risk Dimensions (D1-D5)

展示五维风险评估的每个维度如何影响最终决策。

维度说明：
  D1 - 工具类型危险度（0-3）: read_file=0, write_file=1, bash=2-3, exec=3
  D2 - 目标路径敏感度（0-3）: /tmp=0, .env=1, .ssh/=2, /etc/=3
  D3 - 命令模式危险度（0-3）: ls=0, cp=1, rm=2, rm -rf=3
  D4 - 会话风险累积（0-2）:   <2次高危=0, 2-4次=1, >=5次=2
  D5 - Agent 信任等级（0-2）:  privileged=0, standard=1, untrusted=2

运行方式:
    python examples/clawsentry_quick_start/03_risk_dimensions.py
"""

from _helpers import (
    create_gateway,
    send_event,
    run,
    print_section,
    print_decision,
    print_risk_snapshot,
)

gateway = create_gateway()


async def main():
    print_section("03 - D1-D5 五维风险评估详解")

    # ── 测试用例表 ────────────────────────────────────────────────
    cases = [
        # (label, tool, kwargs)
        (
            "D1 对比：read_file (D1=0) vs bash (D1=2+)",
            [
                ("read_file 读文件", "read_file", {"path": "/tmp/test.txt"}),
                ("write_file 写文件", "write_file", {"path": "/tmp/test.txt"}),
                ("bash ls（安全命令）", "bash", {"command": "ls"}),
                ("bash + 危险命令", "bash", {"command": "rm -rf /tmp/data"}),
            ],
        ),
        (
            "D2 对比：路径敏感度",
            [
                ("普通路径 /tmp/", "bash", {"command": "cat /tmp/test.txt"}),
                ("配置文件 .env", "bash", {"command": "cat .env"}),
                ("凭证目录 .ssh/", "bash", {"command": "cat .ssh/id_rsa"}),
                ("系统路径 /etc/passwd", "bash", {"command": "cat /etc/passwd"}),
            ],
        ),
        (
            "D3 对比：命令模式（仅 bash/exec 工具生效）",
            [
                ("安全: ls", "bash", {"command": "ls -la"}),
                ("写入: cp", "bash", {"command": "cp a.txt b.txt"}),
                ("潜在破坏: rm", "bash", {"command": "rm temp.log"}),
                ("高危: rm -rf", "bash", {"command": "rm -rf /"}),
            ],
        ),
    ]

    for group_label, scenarios in cases:
        print(f"--- {group_label} ---\n")
        for label, tool, kwargs in scenarios:
            result = await send_event(gateway, tool, **kwargs, session_id=f"dim-test-{label}")
            print(f"  [{label}]")
            print_risk_snapshot(result, label="")
            print_decision(result, label="")
            print()

    # ── 短路规则演示 ──────────────────────────────────────────────
    print_section("短路规则（Short-Circuit Rules）")

    print("短路规则在综合评分之前检查，一旦命中直接判定风险等级：\n")
    print("  SC-1: D1=3 且 D2>=2 → CRITICAL（高危工具 + 敏感路径）")
    print("  SC-2: D3=3 → CRITICAL（高危命令模式）")
    print("  SC-3: D1=0 且 D2=0 且 D3=0 → LOW（纯只读安全操作）\n")

    sc_cases = [
        ("SC-3 命中: read_file + 普通路径", "read_file", {"path": "/tmp/test.txt"}),
        ("SC-2 命中: bash rm -rf", "bash", {"command": "rm -rf /home/data"}),
        ("SC-1 命中: exec + 系统路径", "exec", {"command": "cat /etc/shadow"}),
    ]

    for label, tool, kwargs in sc_cases:
        result = await send_event(gateway, tool, **kwargs, session_id=f"sc-test-{label}")
        print(f"  [{label}]")
        print_risk_snapshot(result, label="")
        print_decision(result, label="")
        print()


run(main())
