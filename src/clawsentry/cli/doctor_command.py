"""``clawsentry doctor`` — offline configuration security audit.

Loads ``.env.clawsentry``, runs 19 checks, and outputs a PASS/WARN/FAIL report.
"""

from __future__ import annotations

import json
import math
import os
import re
import stat
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from typing import Literal


@dataclass
class DoctorCheck:
    check_id: str
    status: Literal["PASS", "WARN", "FAIL"]
    message: str
    detail: str = ""


def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy in bits per character."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum(
        (c / length) * math.log2(c / length) for c in counts.values() if c > 0
    )


def _env(key: str) -> str:
    """Read an environment variable, returning '' if unset."""
    return os.environ.get(key, "")


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------


def check_auth_presence() -> DoctorCheck:
    token = _env("CS_AUTH_TOKEN")
    if token:
        return DoctorCheck("AUTH_PRESENCE", "PASS", "CS_AUTH_TOKEN is set.")
    return DoctorCheck("AUTH_PRESENCE", "FAIL", "CS_AUTH_TOKEN is not set.",
                       detail="Set CS_AUTH_TOKEN to a strong random value.")


def check_auth_length() -> DoctorCheck:
    token = _env("CS_AUTH_TOKEN")
    if not token:
        return DoctorCheck("AUTH_LENGTH", "FAIL", "CS_AUTH_TOKEN is not set.")
    n = len(token)
    if n >= 32:
        return DoctorCheck("AUTH_LENGTH", "PASS", f"Token length {n} >= 32.")
    if n >= 16:
        return DoctorCheck("AUTH_LENGTH", "WARN",
                           f"Token length {n} is short (16-31).",
                           detail="Recommended: >= 32 characters.")
    return DoctorCheck("AUTH_LENGTH", "FAIL", f"Token length {n} < 16.",
                       detail="Minimum recommended: 16 characters.")


def check_auth_entropy() -> DoctorCheck:
    token = _env("CS_AUTH_TOKEN")
    if not token:
        return DoctorCheck("AUTH_ENTROPY", "WARN",
                           "CS_AUTH_TOKEN not set, cannot measure entropy.")
    ent = _shannon_entropy(token)
    if ent >= 3.5:
        return DoctorCheck("AUTH_ENTROPY", "PASS",
                           f"Token entropy {ent:.2f} bits/char >= 3.5.")
    return DoctorCheck("AUTH_ENTROPY", "WARN",
                       f"Token entropy {ent:.2f} bits/char < 3.5.",
                       detail="Use a mix of uppercase, lowercase, digits, and symbols.")


_KNOWN_WEAK_TOKENS = frozenset({
    "changeme", "secret", "password", "admin", "test", "token",
    "changeme-replace-with-a-strong-random-token",
})


def check_auth_weak_value() -> DoctorCheck:
    token = _env("CS_AUTH_TOKEN")
    if not token:
        return DoctorCheck("AUTH_WEAK_VALUE", "PASS", "No token to check.")
    if token.lower() in _KNOWN_WEAK_TOKENS or token.lower().startswith("changeme"):
        return DoctorCheck(
            "AUTH_WEAK_VALUE", "FAIL",
            "CS_AUTH_TOKEN appears to be a placeholder or weak value.",
            detail="Replace with a cryptographically random value: openssl rand -hex 32",
        )
    return DoctorCheck("AUTH_WEAK_VALUE", "PASS", "Token does not match known weak values.")


def check_uds_permissions() -> DoctorCheck:
    sock_path = _env("CS_UDS_PATH") or "/tmp/clawsentry.sock"
    if not os.path.exists(sock_path):
        return DoctorCheck("UDS_PERMISSIONS", "PASS",
                           f"Socket {sock_path} does not exist (OK).")
    try:
        mode = os.stat(sock_path).st_mode & 0o777
    except OSError as e:
        return DoctorCheck("UDS_PERMISSIONS", "WARN",
                           f"Cannot stat {sock_path}: {e}")
    if mode == 0o600:
        return DoctorCheck("UDS_PERMISSIONS", "PASS",
                           f"Socket permissions {oct(mode)} (owner-only).")
    return DoctorCheck("UDS_PERMISSIONS", "WARN",
                       f"Socket permissions {oct(mode)}, expected 0o600.",
                       detail="Run: chmod 600 " + sock_path)


def check_threshold_ordering() -> DoctorCheck:
    try:
        med = float(_env("CS_THRESHOLD_MEDIUM") or "0.8")
        high = float(_env("CS_THRESHOLD_HIGH") or "1.5")
        crit = float(_env("CS_THRESHOLD_CRITICAL") or "2.2")
    except ValueError as e:
        return DoctorCheck("THRESHOLD_ORDERING", "FAIL",
                           f"Non-numeric threshold value: {e}")
    if med <= high <= crit:
        return DoctorCheck("THRESHOLD_ORDERING", "PASS",
                           f"Thresholds ordered: {med} <= {high} <= {crit}.")
    return DoctorCheck("THRESHOLD_ORDERING", "FAIL",
                       f"Thresholds out of order: med={med}, high={high}, crit={crit}.",
                       detail="Ensure CS_THRESHOLD_MEDIUM <= CS_THRESHOLD_HIGH <= CS_THRESHOLD_CRITICAL.")


def check_weight_bounds() -> DoctorCheck:
    weight_keys = [
        "CS_COMPOSITE_WEIGHT_MAX_D123",
        "CS_COMPOSITE_WEIGHT_D4",
        "CS_COMPOSITE_WEIGHT_D5",
        "CS_D6_INJECTION_MULTIPLIER",
    ]
    negatives: list[str] = []
    for key in weight_keys:
        raw = _env(key)
        if raw:
            try:
                val = float(raw)
                if val < 0:
                    negatives.append(f"{key}={val}")
            except ValueError:
                negatives.append(f"{key}='{raw}' (invalid)")
    if negatives:
        return DoctorCheck("WEIGHT_BOUNDS", "FAIL",
                           f"Negative/invalid weights: {', '.join(negatives)}.")
    return DoctorCheck("WEIGHT_BOUNDS", "PASS", "All weights >= 0.")


def check_llm_config() -> DoctorCheck:
    provider = _env("CS_LLM_PROVIDER")
    api_key = (_env("CS_LLM_API_KEY") or _env("ANTHROPIC_API_KEY")
               or _env("OPENAI_API_KEY"))
    if not provider and not api_key:
        return DoctorCheck("LLM_CONFIG", "PASS",
                           "No LLM provider configured (L2/L3 disabled).")
    if provider and not api_key:
        return DoctorCheck("LLM_CONFIG", "WARN",
                           f"LLM provider '{provider}' set but no API key found.",
                           detail="Set CS_LLM_API_KEY or provider-specific key.")
    return DoctorCheck("LLM_CONFIG", "PASS",
                       "LLM provider and API key configured.")


def check_openclaw_secret() -> DoctorCheck:
    token = _env("CS_OPENCLAW_TOKEN")
    secret = _env("CS_OPENCLAW_WEBHOOK_SECRET")
    if not token:
        return DoctorCheck("OPENCLAW_SECRET", "PASS",
                           "OpenClaw integration not configured.")
    if secret:
        return DoctorCheck("OPENCLAW_SECRET", "PASS",
                           "OpenClaw webhook secret is set.")
    return DoctorCheck("OPENCLAW_SECRET", "WARN",
                       "CS_OPENCLAW_TOKEN set but CS_OPENCLAW_WEBHOOK_SECRET is empty.",
                       detail="Set CS_OPENCLAW_WEBHOOK_SECRET for webhook verification.")


def check_listen_address() -> DoctorCheck:
    host = _env("CS_HTTP_HOST") or "127.0.0.1"
    if host in {"127.0.0.1", "localhost", "::1"}:
        return DoctorCheck("LISTEN_ADDRESS", "PASS",
                           f"Listening on {host} (localhost only).")
    return DoctorCheck("LISTEN_ADDRESS", "WARN",
                       f"Listening on {host} (publicly accessible).",
                       detail="Use 127.0.0.1 for local-only access, "
                              "or ensure firewall rules are in place.")


def check_whitelist_regex() -> DoctorCheck:
    raw = _env("CS_POST_ACTION_WHITELIST")
    if not raw:
        return DoctorCheck("WHITELIST_REGEX", "PASS",
                           "No post-action whitelist configured.")
    patterns = [p.strip() for p in raw.split(",") if p.strip()]
    invalid: list[str] = []
    for p in patterns:
        try:
            re.compile(p)
        except re.error as e:
            invalid.append(f"'{p}': {e}")
    if invalid:
        return DoctorCheck("WHITELIST_REGEX", "FAIL",
                           f"Invalid whitelist regex: {'; '.join(invalid)}.")
    return DoctorCheck("WHITELIST_REGEX", "PASS",
                       f"All {len(patterns)} whitelist patterns compile OK.")


def check_l2_budget() -> DoctorCheck:
    raw = _env("CS_L2_BUDGET_MS")
    if not raw:
        return DoctorCheck("L2_BUDGET", "PASS",
                           "L2 budget using default (5000ms).")
    try:
        val = float(raw)
    except ValueError:
        return DoctorCheck("L2_BUDGET", "FAIL",
                           f"CS_L2_BUDGET_MS='{raw}' is not a number.")
    if val > 0:
        return DoctorCheck("L2_BUDGET", "PASS", f"L2 budget: {val}ms.")
    return DoctorCheck("L2_BUDGET", "FAIL",
                       f"CS_L2_BUDGET_MS={val} <= 0.",
                       detail="L2 budget must be positive.")


def check_trajectory_db() -> DoctorCheck:
    db_path = _env("CS_TRAJECTORY_DB_PATH") or "/tmp/clawsentry-trajectory.db"
    parent = os.path.dirname(db_path) or "."
    if os.path.isdir(parent) and os.access(parent, os.W_OK):
        return DoctorCheck("TRAJECTORY_DB", "PASS",
                           f"Database directory '{parent}' is writable.")
    if not os.path.isdir(parent):
        return DoctorCheck("TRAJECTORY_DB", "WARN",
                           f"Database directory '{parent}' does not exist.",
                           detail="It will be created on first run if possible.")
    return DoctorCheck("TRAJECTORY_DB", "WARN",
                       f"Database directory '{parent}' is not writable.")


def check_codex_config() -> DoctorCheck:
    framework = _env("CS_FRAMEWORK")
    if framework != "codex":
        return DoctorCheck("CODEX_CONFIG", "PASS",
                           "CS_FRAMEWORK is not 'codex' (Codex check skipped).")
    token = _env("CS_AUTH_TOKEN")
    port = _env("CS_HTTP_PORT") or "8080"
    if not token:
        return DoctorCheck("CODEX_CONFIG", "WARN",
                           "CS_FRAMEWORK=codex but CS_AUTH_TOKEN is not set.",
                           detail="Codex endpoint /ahp/codex requires authentication.")
    return DoctorCheck("CODEX_CONFIG", "PASS",
                       f"Codex configured: /ahp/codex on port {port}.")


# ---------------------------------------------------------------------------
# Latch checks
# ---------------------------------------------------------------------------


def check_latch_binary() -> DoctorCheck:
    """Check whether the Latch binary is installed and executable."""
    try:
        from clawsentry.latch.binary_manager import BinaryManager
    except ImportError:
        return DoctorCheck("LATCH_BINARY", "PASS",
                           "Latch package not installed (optional).")

    mgr = BinaryManager()
    if not mgr.is_installed:
        return DoctorCheck("LATCH_BINARY", "WARN",
                           "Latch binary not installed.",
                           detail="Run: clawsentry latch install")
    if not os.access(mgr.binary_path, os.X_OK):
        return DoctorCheck("LATCH_BINARY", "WARN",
                           f"Latch binary at {mgr.binary_path} is not executable.",
                           detail=f"Run: chmod +x {mgr.binary_path}")
    return DoctorCheck("LATCH_BINARY", "PASS",
                       f"Latch binary installed at {mgr.binary_path}.")


def check_latch_hub_health() -> DoctorCheck:
    """Check whether Latch Hub is responding on its health endpoint."""
    import urllib.request

    hub_port = _env("CS_LATCH_HUB_PORT") or "3006"
    url = f"http://127.0.0.1:{hub_port}/health"
    try:
        with urllib.request.urlopen(url, timeout=2) as resp:
            if resp.status == 200:
                return DoctorCheck("LATCH_HUB_HEALTH", "PASS",
                                   f"Latch Hub responding on port {hub_port}.")
    except (OSError, urllib.error.URLError):
        pass
    return DoctorCheck("LATCH_HUB_HEALTH", "WARN",
                       f"Latch Hub not responding on port {hub_port}.",
                       detail="Start with: clawsentry latch start")


def check_latch_token_sync() -> DoctorCheck:
    """Check CS_AUTH_TOKEN and CLI_API_TOKEN are consistent."""
    cs_token = _env("CS_AUTH_TOKEN")
    cli_token = _env("CLI_API_TOKEN")
    if not cs_token and not cli_token:
        return DoctorCheck("LATCH_TOKEN_SYNC", "PASS",
                           "No Latch tokens configured (optional).")
    if not cli_token:
        return DoctorCheck("LATCH_TOKEN_SYNC", "PASS",
                           "CLI_API_TOKEN not set (Latch Hub not configured).")
    if cs_token == cli_token:
        return DoctorCheck("LATCH_TOKEN_SYNC", "PASS",
                           "CS_AUTH_TOKEN and CLI_API_TOKEN match.")
    return DoctorCheck("LATCH_TOKEN_SYNC", "WARN",
                       "CS_AUTH_TOKEN and CLI_API_TOKEN differ.",
                       detail="Ensure both tokens match for Latch ↔ Gateway auth.")


# ---------------------------------------------------------------------------
# Bridge checks
# ---------------------------------------------------------------------------


def check_defer_bridge() -> DoctorCheck:
    """Check DEFER bridge configuration."""
    enabled_raw = (_env("CS_DEFER_BRIDGE_ENABLED") or "true").lower()
    if enabled_raw in ("false", "0", "no"):
        return DoctorCheck("DEFER_BRIDGE", "PASS",
                           "DEFER bridge disabled (immediate DEFER return).")
    timeout_action = _env("CS_DEFER_TIMEOUT_ACTION") or "block"
    timeout_s = _env("CS_DEFER_TIMEOUT_S") or "300"
    try:
        timeout_val = float(timeout_s)
    except ValueError:
        return DoctorCheck("DEFER_BRIDGE", "WARN",
                           f"CS_DEFER_TIMEOUT_S='{timeout_s}' is not a number.",
                           detail="Using default timeout (300s).")
    if timeout_action not in ("block", "allow"):
        return DoctorCheck("DEFER_BRIDGE", "WARN",
                           f"CS_DEFER_TIMEOUT_ACTION='{timeout_action}' invalid.",
                           detail="Must be 'block' or 'allow'.")
    return DoctorCheck("DEFER_BRIDGE", "PASS",
                       f"DEFER bridge enabled (timeout: {int(timeout_val)}s, action: {timeout_action}).")


def check_hub_bridge() -> DoctorCheck:
    """Check Latch Hub bridge configuration and reachability."""
    import urllib.request
    import urllib.error

    hub_enabled = (_env("CS_HUB_BRIDGE_ENABLED") or "auto").lower()
    if hub_enabled == "false":
        return DoctorCheck("HUB_BRIDGE", "PASS",
                           "Hub bridge explicitly disabled.")

    hub_url = _env("CS_LATCH_HUB_URL")
    hub_port = _env("CS_LATCH_HUB_PORT") or "3006"
    if not hub_url:
        hub_url = f"http://127.0.0.1:{hub_port}"

    health_url = f"{hub_url.rstrip('/')}/health"
    try:
        with urllib.request.urlopen(health_url, timeout=2) as resp:
            if resp.status == 200:
                return DoctorCheck("HUB_BRIDGE", "PASS",
                                   f"Hub bridge reachable at {hub_url}.")
    except (OSError, urllib.error.URLError):
        pass

    if hub_enabled == "true":
        return DoctorCheck("HUB_BRIDGE", "WARN",
                           f"Hub bridge enabled but not reachable at {hub_url}.",
                           detail="Start Hub: clawsentry latch start")
    return DoctorCheck("HUB_BRIDGE", "PASS",
                       f"Hub bridge auto-mode, Hub not running at {hub_url} (OK).")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

ALL_CHECKS = [
    check_auth_presence,
    check_auth_length,
    check_auth_entropy,
    check_auth_weak_value,
    check_uds_permissions,
    check_threshold_ordering,
    check_weight_bounds,
    check_llm_config,
    check_openclaw_secret,
    check_listen_address,
    check_whitelist_regex,
    check_l2_budget,
    check_trajectory_db,
    check_codex_config,
    check_latch_binary,
    check_latch_hub_health,
    check_latch_token_sync,
    check_defer_bridge,
    check_hub_bridge,
]


def run_all_checks() -> list[DoctorCheck]:
    """Run all doctor checks and return results."""
    return [fn() for fn in ALL_CHECKS]


def _colorize(status: str, color: bool) -> str:
    if not color:
        return status
    codes = {"PASS": "\033[32m", "WARN": "\033[33m", "FAIL": "\033[31m"}
    reset = "\033[0m"
    return f"{codes.get(status, '')}{status}{reset}"


def format_table(results: list[DoctorCheck], color: bool = True) -> str:
    """Format results as a human-readable table."""
    lines: list[str] = []
    lines.append("ClawSentry Doctor Report")
    lines.append("=" * 60)
    for r in results:
        status = _colorize(r.status, color)
        lines.append(f"  [{status}] {r.check_id}: {r.message}")
        if r.detail:
            lines.append(f"         {r.detail}")
    lines.append("=" * 60)
    counts = Counter(r.status for r in results)
    summary_parts = []
    for s in ("PASS", "WARN", "FAIL"):
        if counts.get(s, 0) > 0:
            label = _colorize(s, color)
            summary_parts.append(f"{label}: {counts[s]}")
    lines.append("  " + "  ".join(summary_parts))
    return "\n".join(lines)


def format_json(results: list[DoctorCheck]) -> str:
    """Format results as JSON."""
    return json.dumps([asdict(r) for r in results], indent=2)


def compute_exit_code(results: list[DoctorCheck]) -> int:
    """0 = all PASS, 1 = any FAIL, 2 = WARN only (no FAIL)."""
    statuses = {r.status for r in results}
    if "FAIL" in statuses:
        return 1
    if "WARN" in statuses:
        return 2
    return 0


def run_doctor(json_mode: bool = False, color: bool = True) -> int:
    """Run doctor command and print output. Returns exit code."""
    results = run_all_checks()
    if json_mode:
        print(format_json(results))
    else:
        print(format_table(results, color=color))
    return compute_exit_code(results)
