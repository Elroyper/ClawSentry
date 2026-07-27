[![PyPI](https://img.shields.io/pypi/v/clawsentry)](https://pypi.org/project/clawsentry/) [![Python](https://img.shields.io/pypi/pyversions/clawsentry)](https://pypi.org/project/clawsentry/) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE) [![Docs](https://img.shields.io/badge/docs-online-blue)](https://elroyper.github.io/ClawSentry/)

# ClawSentry

**Runtime safety supervision for tool-using AI agents.**

ClawSentry is the reference implementation of the Agent Harness Protocol
(AHP), a framework-independent interface for mediating AI-agent actions at
runtime. It normalizes events from heterogeneous agent hosts, evaluates them
through a progressive decision pipeline, and returns auditable
`allow` / `block` / `modify` / `defer` decisions before or after tool
execution, according to the enforcement capabilities of each host.

<p align="center">
  <img src="site-docs/assets/architecture-overview.png" alt="ClawSentry Architecture Overview" width="820">
</p>

> **Project status.** ClawSentry is a research artifact and beta-quality
> reference implementation. Its policy decisions complement, but do not
> replace, operating-system isolation, least-privilege credentials, or
> human approval for consequential actions.

## Research Scope

ClawSentry studies runtime mediation for agentic systems in which security
decisions must remain portable across hosts with different hook, approval,
and observation capabilities. The implementation focuses on five properties:

- **Protocol-first supervision** — host-specific events are normalized into a
  common AHP decision contract instead of duplicating policy in every agent
  runtime.
- **Progressive analysis** — deterministic L1 rules handle clear cases first;
  L2 semantic analysis and L3 bounded review are invoked only when additional
  context is required.
- **Action-bound evidence** — decisions retain normalized effects, provenance,
  session context, and policy reasons for audit and replay.
- **Capability-aware enforcement** — each integration states which events can
  be blocked synchronously and which are observation-only.
- **Pre- and post-action coverage** — the gateway combines pre-execution
  mediation with post-action analysis for indirect injection, exfiltration,
  secret exposure, and obfuscation signals.

## Decision Pipeline

| Stage | Role | Operational property |
|---|---|---|
| **L1 Policy Engine** | Deterministic effect normalization, D1–D6 risk scoring, anti-bypass and policy checks | Always on; intended for sub-millisecond decisions |
| **L2 Semantic Analyzer** | Context-sensitive analysis with rule-based or pluggable LLM providers | Invoked for ambiguous or policy-selected events |
| **L3 Review Agent** | Bounded multi-turn review with a read-only toolkit and review-skill dispatch | Optional; reserved for cases requiring additional evidence |
| **Post-action Analyzer** | Non-blocking analysis of tool results and session contamination | Produces findings and influences subsequent decisions |

The gateway also provides Skill Trust controls for local skill packages,
multi-step trajectory analysis, session enforcement, SSE telemetry, a CLI
watcher, and a React/TypeScript operations dashboard.

## Installation

```bash
pip install clawsentry           # core
pip install clawsentry[llm]      # + Anthropic/OpenAI for L2/L3
pip install clawsentry[all]      # everything
```

Requires Python >= 3.11.

## What's New in v0.8.7

This release consolidates the runtime hardening and architectural work merged
after `v0.8.6`:

- **Indirect-injection coverage** — serialized and nested tool outputs are
  flattened into bounded analysis views, with post-action escalation retained
  for contamination-driven follow-up decisions.
- **Context-sensitive escalation** — contamination and uncertain L2 outcomes
  reach their intended review path without being silently demoted by benchmark
  auto-routing controls or parser-only failures.
- **Policy-boundary hardening** — cross-tool write-content equivalence,
  secret-value egress signals, task-artifact scope, and approval-effect binding
  share normalized evidence across enforcement paths.
- **Maintainable public surface** — the gateway has a modular package layout,
  generated API inventory, refreshed documentation, and an updated Web UI
  stylesheet organization.

See [CHANGELOG.md](CHANGELOG.md) for the complete version history.

## Quick Start

### One-Command Launch (Recommended)

```bash
clawsentry start                   # auto-detect framework + init + gateway + watch
# or specify framework:
clawsentry start --framework codex       # installs/refreshes Codex managed hooks by default
clawsentry start --framework openclaw
clawsentry start --framework a3s-code --interactive  # enable DEFER interaction
```

The `start` command will:
1. Auto-detect your framework (a3s-code, Claude Code, Codex, Gemini CLI, Kimi CLI, or OpenClaw)
2. Initialize configuration if needed
3. Start the gateway in the background
4. Display live monitoring in the foreground
5. Show Web UI URL with auto-login token

### Web UI auth quick note

`clawsentry start` prints a Web UI URL such as
`http://127.0.0.1:8080/ui?token=...`. The browser stores that token in
`sessionStorage` and removes `?token=` from the address bar before loading data.
Manual login uses the same `CS_AUTH_TOKEN` from the startup environment, explicit `--env-file`, or the ephemeral token printed by `start`.

- `invalid token` / `401` means the pasted value does not match
  `CS_AUTH_TOKEN`.
- `Gateway unavailable` means the local Gateway cannot be reached; this is not
  an invalid-token error.
- If your shell exports proxy variables, use
  `NO_PROXY=localhost,127.0.0.1,::1` for local Gateway calls.

Press Ctrl+C to gracefully shutdown.

`clawsentry init <framework>` updates `CS_FRAMEWORK / CS_ENABLED_FRAMEWORKS` by
default and does not write secrets. Framework enablement is stored in project
config; local tokens and provider keys belong in process/deployment env or an
explicit `--env-file` such as `.clawsentry.env.local`.

Start multiple integrations together:

```bash
clawsentry start --frameworks a3s-code,codex,openclaw --no-watch
clawsentry integrations status
```

Codex `start` installs only ClawSentry-managed hooks and trust state, preserving user hooks. The startup banner prints the removal command:

```bash
clawsentry init codex --uninstall
```

If you want `start` to also patch OpenClaw-side approval config, opt in explicitly:

```bash
clawsentry start --frameworks codex,openclaw --setup-openclaw --no-watch
clawsentry integrations status --json
```

`integrations status` now reports more than enabled frameworks: it also shows
OpenClaw backup restore availability, Claude hook source files, Codex
session directory reachability, Gemini settings/hook readiness, a per-framework
readiness verdict with next steps, and a machine-readable framework capability matrix. The multi-framework
`start` banner now prints the same readiness summary before it returns or
begins streaming events.

Disable one framework without disturbing the others:

```bash
clawsentry init codex --uninstall
clawsentry init gemini-cli --uninstall  # removes project-local managed Gemini hooks
clawsentry init claude-code --uninstall  # also removes Claude Code hooks
clawsentry init openclaw --uninstall     # env only; use --restore for OpenClaw-side backups
```

### Manual Step-by-Step

#### a3s-code

```bash
clawsentry init a3s-code           # update CS_FRAMEWORK / CS_ENABLED_FRAMEWORKS
clawsentry gateway                 # start gateway (default :8080)
clawsentry watch                   # tail live decisions in your terminal
```

Wire a3s-code through explicit SDK transport in your agent script, for example
`SessionOptions().ahp_transport = StdioTransport(program="clawsentry-harness", args=[])`.
Do not rely on `.a3s-code/settings.json` for AHP; the current upstream runtime
does not auto-load it.

#### OpenClaw

```bash
clawsentry init openclaw           # update CS_FRAMEWORK / CS_ENABLED_FRAMEWORKS only
clawsentry init openclaw --setup   # opt-in: patch OpenClaw settings
clawsentry gateway                 # start gateway (default :8080)
open http://localhost:8080/ui      # open web dashboard
```

OpenClaw setup is explicit opt-in. Plain `init openclaw` and `start --frameworks`
do not modify `~/.openclaw/`. Setup writes `.bak` backups before changing
OpenClaw-side config. To preview or restore those backups:

```bash
clawsentry init openclaw --restore --dry-run
clawsentry init openclaw --restore
```

## Framework Compatibility

| Framework | Integration mode | Pre-action interception | Post-action observation | Main dependency |
|---|---|---|---|---|
| `a3s-code` | Explicit SDK transport + `clawsentry-harness` | Yes | Yes | Agent code must wire `SessionOptions.ahp_transport` |
| `openclaw` | WebSocket approvals + webhook receiver | Yes | Yes | `~/.openclaw/` must be configured for gateway exec + callbacks |
| `codex` | Session JSONL watcher + managed native hooks | Managed `PreToolUse(Bash)` preflight response path + `PermissionRequest(Bash|apply_patch|Edit|Write|mcp__.*)` approval gate when started through `clawsentry start --framework codex` | Yes, including async `PreCompact` / `PostCompact` observation | Session logs and `$CODEX_HOME/hooks.json` managed entries must be reachable |
| `gemini-cli` | Gemini CLI native command hooks | Yes; real `BeforeTool` deny smoke proven for `run_shell_command` | Yes, with post-action side-effect caveat | Project `.gemini/settings.json` managed hooks; global home only with explicit `--gemini-home` |
| `kimi-cli` | Kimi CLI native `[[hooks]]` | Yes; `PreToolUse` and prompt deny via Kimi permission decision | Yes, observation-only for post/session/subagent/compact/notification | `$KIMI_SHARE_DIR/config.toml` or `~/.kimi/config.toml` marker-managed hooks |
| `claude-code` | Host hooks + `clawsentry-harness` | Yes | Yes | `~/.claude/settings.json` hooks must remain installed |

`codex` should be understood as observation plus narrow managed native hooks by default when launched through `clawsentry start --framework codex`: `PreToolUse(Bash)` can deny and `PermissionRequest(Bash|apply_patch|Edit|Write|mcp__.*)` can gate approvals, while non-Bash `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `Stop`, `SessionStart(startup|resume|clear)`, `PreCompact`, and `PostCompact` remain advisory/observational by default. `a3s-code`
should be understood as explicit transport wiring, not `.a3s-code/settings.json`
auto-loading. `claude-code` and `openclaw` remain more host-config-dependent than
`a3s-code`.

`gemini-cli` should be understood as native-hook support: `clawsentry init gemini-cli --setup` installs project-local managed hooks in `.gemini/settings.json`, and shell-tool events are canonicalized to policy-facing `bash` before evaluation. Kimi/OpenAI-compatible endpoints are not directly supported by Gemini CLI. Managed Gemini hook commands redirect diagnostics away from stderr and exit fail-open on harness process failure so Gemini does not treat plain stderr text as hook output.

`kimi-cli` is native-hook support, not AHP transport parity: `clawsentry init kimi-cli --setup` adds marker-managed `[[hooks]]` entries to `$KIMI_SHARE_DIR/config.toml` (or `~/.kimi/config.toml`) and preserves non-ClawSentry user hooks. Kimi `PreToolUse` can block dangerous tool calls, `UserPromptSubmit` can block prompts, and lifecycle hooks provide observation. Native tool-input rewrite and true `defer` are reported as unsupported/degraded rather than presented as equal to `a3s-code`.

For a machine-readable local view of the same boundaries, run
`clawsentry integrations status --json`.

## Architecture

**Decision tiers:**

- **L1 PolicyEngine** — deterministic rule scoring across six risk dimensions (D1–D6), sub-millisecond latency
  - Composite score: `base = 0.4×max(D1,D2,D3) + 0.25×D4 + 0.15×D5; score = base × (1.0 + 0.5×D6/3.0)`
  - Risk thresholds: LOW < 0.8 / MEDIUM 0.8–1.5 / HIGH 1.5–2.2 / CRITICAL ≥ 2.2
- **L2 SemanticAnalyzer** — LLM-backed semantic analysis with configurable provider (Anthropic / OpenAI / rule-based fallback); 25-pattern attack library + trajectory analysis
- **L3 AgentAnalyzer** — multi-turn review agent with read-only toolkit and per-session skill dispatch
- **PostActionAnalyzer** — non-blocking post-execution fence; 4 detectors × 4 response tiers

## Documentation

Full documentation is available at **https://elroyper.github.io/ClawSentry/**

- [Getting Started](https://elroyper.github.io/ClawSentry/getting-started/installation/)
- [Core Concepts](https://elroyper.github.io/ClawSentry/getting-started/concepts/)
- [a3s-code Integration](https://elroyper.github.io/ClawSentry/integration/a3s-code/)
- [OpenClaw Integration](https://elroyper.github.io/ClawSentry/integration/openclaw/)
- [L1 Rules Engine](https://elroyper.github.io/ClawSentry/decision-layers/l1-rules/)
- [L2 Semantic Analysis](https://elroyper.github.io/ClawSentry/decision-layers/l2-semantic/)
- [Configuration Reference](https://elroyper.github.io/ClawSentry/configuration/env-vars/)
- [REST & SSE API](https://elroyper.github.io/ClawSentry/api/decisions/)

## Reproducibility and Validation

The public repository contains the runtime source, public regression tests,
documentation sources, deployment examples, and package metadata used for a
release. A local validation run can be reproduced with:

```bash
python -m pip install -e ".[dev]"
python -m pytest src/clawsentry/tests/ -q --tb=short
python scripts/docs_api_inventory.py
python -m build
```

Provider-backed and host-native integration checks require the corresponding
CLI/runtime and credentials; they are skipped unless explicitly enabled. The
public documentation distinguishes tested enforcement paths from
observation-only or host-dependent paths.

## Citation

Citation metadata for the associated paper will be added after the
double-anonymous review period. During review, please cite the anonymous
artifact URL supplied with the manuscript. For software-specific references,
record the release tag and commit SHA used in the evaluation.

## Security and Responsible Use

ClawSentry is a defense-in-depth component, not a complete sandbox. Deploy it
with least-privilege credentials, host isolation, authenticated gateway
endpoints, and human approval for irreversible or externally consequential
actions. Please report security-sensitive issues privately before public
disclosure.

## Key Environment Variables

| Variable | Default | Description |
|---|---|---|
| `CS_AUTH_TOKEN` | *(required)* | Bearer token for all REST / SSE endpoints |
| `CS_LLM_PROVIDER` | *(empty = rules only)* | LLM backend for L2/L3: `anthropic`, `openai`, or empty for rules-only mode |
| `CS_L3_ENABLED` | `false` | Enable L3 multi-turn review agent |
| `AHP_SESSION_ENFORCEMENT_ENABLED` | `false` | Legacy session-enforcement flag; prefer canonical `CS_*` settings where available |
| `OPENCLAW_WS_URL` | — | WebSocket URL of a running OpenClaw gateway |
| `CS_EVOLVING_ENABLED` | `false` | Enable self-evolving pattern library (E-5) |
| `CS_EVOLVED_PATTERNS_PATH` | — | Path to store evolved patterns YAML |
| `CS_ATTACK_PATTERNS_PATH` | *(built-in)* | Path to custom attack patterns YAML (hot-reload) |
| `CS_THRESHOLD_CRITICAL` | `2.2` | Risk score threshold for CRITICAL level |
| `CS_THRESHOLD_HIGH` | `1.5` | Risk score threshold for HIGH level |
| `CS_THRESHOLD_MEDIUM` | `0.8` | Risk score threshold for MEDIUM level |
| `CS_POST_ACTION_WHITELIST` | — | Comma-separated regex list for post-action path whitelist |

See the [full configuration reference](https://elroyper.github.io/ClawSentry/configuration/env-vars/) for all 20+ tunable parameters.

## License

MIT — see [LICENSE](LICENSE)
