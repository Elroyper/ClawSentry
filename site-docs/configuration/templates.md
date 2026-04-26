# Configuration templates

## Individual developer

```toml
[project]
mode = "normal"
preset = "medium"

[budgets]
llm_token_budget_enabled = false
l2_timeout_ms = 60000
l3_timeout_ms = 300000
hard_timeout_ms = 600000
```

## CI / benchmark operator

```toml
[project]
mode = "benchmark"

[benchmark]
auto_resolve_defer = true
defer_action = "block"
```

Use a temporary Codex home for benchmark hooks:

```bash
clawsentry benchmark enable --framework codex --codex-home /tmp/cs-codex-home
```
