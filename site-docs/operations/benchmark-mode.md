# Benchmark mode

Benchmark mode is explicit and non-interactive. It never waits for human DEFER resolution; pre-action DEFER outcomes are auto-resolved to deterministic blocks and include metadata such as `auto_resolved=true`, `auto_resolve_mode=benchmark`, and `original_verdict=defer`.

```bash
clawsentry benchmark env --framework codex > .env.clawsentry.benchmark
clawsentry benchmark enable --dir . --framework codex --codex-home /tmp/cs-codex-home
clawsentry benchmark run --dir . --framework codex --codex-home /tmp/cs-codex-home -- bash benchmarks/scripts/skills_safety_bench_codex.sh
clawsentry benchmark disable --dir . --framework codex --codex-home /tmp/cs-codex-home
```

The CLI refuses to modify active `~/.codex` unless `--force-user-home` is supplied for manual use. Automated tests and benchmark runs should always pass a temporary `--codex-home`.
