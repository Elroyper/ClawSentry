#!/usr/bin/env python3
"""
01 - Hello Gateway

最简示例：创建一个内存模式的 Supervision Gateway 并查看其健康状态。

运行方式:
    pip install -e ".[dev]"
    python examples/clawsentry_quick_start/01_hello_gateway.py
"""

from _helpers import create_gateway, print_section, print_json

print_section("01 - Hello Gateway")

# ── 创建 Gateway（内存模式，无需启动外部服务） ──────────────────────
gateway = create_gateway()

# ── 查看健康状态 ──────────────────────────────────────────────────
health = gateway.health()

print("Gateway 创建成功！健康状态：\n")
print_json(health)

print("""
说明：
  - status:             Gateway 运行状态（healthy = 正常）
  - uptime_seconds:     运行时长（刚创建所以很短）
  - cache_size:         幂等缓存中的条目数（尚无请求所以为 0）
  - trajectory_count:   审计轨迹记录数（尚无事件所以为 0）
  - trajectory_backend: 轨迹存储后端（sqlite）
  - policy_engine:      策略引擎类型（L1+L2 = 规则 + 语义分析）
  - rpc_version:        支持的 RPC 协议版本
""")
