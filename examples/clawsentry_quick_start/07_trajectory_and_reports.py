#!/usr/bin/env python3
"""
07 - Trajectory & Reports

展示审计轨迹存储和报表查询功能：

  1. 发送一批事件到 Gateway（自动记录审计轨迹）
  2. 查看健康状态（trajectory_count 变化）
  3. 查看统一摘要报表（跨框架聚合统计）
  4. 查看会话回放（按时间线还原事件序列）

所有审计数据存储在 SQLite 中，支持保留期自动淘汰。

运行方式:
    python examples/clawsentry_quick_start/07_trajectory_and_reports.py
"""

from _helpers import (
    create_gateway,
    send_event,
    run,
    print_section,
    print_json,
)

gateway = create_gateway()

SESSION_A = "session-alice"
SESSION_B = "session-bob"


async def main():
    print_section("07 - 审计轨迹与报表")

    # ── 步骤 1: 发送一批模拟事件 ─────────────────────────────────
    print("步骤 1: 发送模拟事件（自动记录到 Trajectory Store）\n")

    events = [
        # Alice 的操作
        ("Alice", SESSION_A, "read_file", {"path": "/home/alice/notes.txt"}),
        ("Alice", SESSION_A, "bash", {"command": "ls -la"}),
        ("Alice", SESSION_A, "bash", {"command": "rm -rf /tmp/cache"}),
        ("Alice", SESSION_A, "write_file", {"path": "/home/alice/output.txt"}),
        # Bob 的操作
        ("Bob", SESSION_B, "bash", {"command": "cat /etc/passwd"}),
        ("Bob", SESSION_B, "bash", {"command": "curl http://example.com"}),
        ("Bob", SESSION_B, "read_file", {"path": "/tmp/data.csv"}),
    ]

    for user, session_id, tool, kwargs in events:
        result = await send_event(gateway, tool, session_id=session_id, **kwargs)
        decision = result.get("result", {}).get("decision", {})
        verdict = decision.get("decision", "?")
        risk = decision.get("risk_level", "?")
        detail = kwargs.get("command", kwargs.get("path", ""))
        print(f"  [{user}] {tool} \"{detail}\" → {verdict} ({risk})")

    # ── 步骤 2: 查看健康状态 ─────────────────────────────────────
    print_section("步骤 2: Gateway 健康状态")
    health = gateway.health()
    print(f"  trajectory_count: {health['trajectory_count']} 条记录")
    print(f"  cache_size:       {health['cache_size']} 条缓存")

    # ── 步骤 3: 统一摘要报表 ─────────────────────────────────────
    print_section("步骤 3: 统一摘要报表 (report/summary)")
    summary = gateway.report_summary()
    # 只显示关键字段
    print(f"  total_records:      {summary['total_records']}")
    print(f"  by_decision:        {summary['by_decision']}")
    print(f"  by_risk_level:      {summary['by_risk_level']}")
    print(f"  by_event_type:      {summary['by_event_type']}")
    print(f"  by_source_framework: {summary['by_source_framework']}")

    # ── 步骤 4: 会话回放 ─────────────────────────────────────────
    print_section("步骤 4: 会话回放 (report/session/{id})")

    for session_id, user in [(SESSION_A, "Alice"), (SESSION_B, "Bob")]:
        replay = gateway.replay_session(session_id)
        print(f"\n  --- {user} 的会话 ({session_id}) ---")
        print(f"  记录数: {replay['record_count']}")
        for i, rec in enumerate(replay["records"], 1):
            event = rec["event"]
            decision = rec["decision"]
            tool = event.get("tool_name", event.get("payload", {}).get("tool", "?"))
            cmd = event.get("payload", {}).get("command", event.get("payload", {}).get("file_path", ""))
            verdict = decision.get("decision", "?")
            risk = decision.get("risk_level", "?")
            print(f"    #{i}: {tool} \"{cmd}\" → {verdict} ({risk})")

    # ── 步骤 5: 带时间窗口的报表 ─────────────────────────────────
    print_section("步骤 5: 带时间窗口的报表")
    print("  report_summary(window_seconds=3600) → 最近 1 小时的统计")
    summary_1h = gateway.report_summary(window_seconds=3600)
    print(f"  total_records: {summary_1h['total_records']}")
    print(f"  window_seconds: {summary_1h['window_seconds']}")

    print("""
生产环境中的等价 HTTP 调用:
  curl http://127.0.0.1:8080/report/summary
  curl http://127.0.0.1:8080/report/summary?window_seconds=3600
  curl http://127.0.0.1:8080/report/session/session-alice
  curl http://127.0.0.1:8080/report/session/session-bob?limit=10
""")


run(main())
