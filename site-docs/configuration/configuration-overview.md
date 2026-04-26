# Configuration overview

Start with one command:

```bash
clawsentry config wizard --non-interactive --framework codex --mode normal
clawsentry config show --effective
```

ClawSentry resolves configuration in this order: command flags, canonical `CS_*` environment variables, `.clawsentry.toml`, defaults, then legacy aliases only when no canonical value exists. `config show --effective` prints each source and redacts secrets.

Canonical budget names are token based:

```bash
CS_LLM_TOKEN_BUDGET_ENABLED=true
CS_LLM_DAILY_TOKEN_BUDGET=200000
CS_LLM_TOKEN_BUDGET_SCOPE=total
```

`CS_LLM_DAILY_BUDGET_USD` is deprecated and should be treated as estimated telemetry, not the normal enforcement path.
