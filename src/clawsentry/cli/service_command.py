"""``clawsentry service`` — install/uninstall platform service for auto-start.

Supports:
  - Linux: systemd user service (systemctl --user)
  - macOS: launchd user agent (~//Library/LaunchAgents)
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
import textwrap
import urllib.error
import urllib.request
from pathlib import Path
from typing import Iterable


def _which_clawsentry() -> str:
    """Find the absolute path to the clawsentry-gateway entry point."""
    # Prefer the entry point installed alongside this Python
    candidate = Path(sys.executable).parent / "clawsentry-gateway"
    if candidate.exists():
        return str(candidate)
    found = shutil.which("clawsentry-gateway")
    if found:
        return found
    # Fallback to module invocation
    return f"{sys.executable} -m clawsentry.gateway.stack"


def _env_file_path() -> Path:
    config_dir = Path.home() / ".config" / "clawsentry"
    return config_dir / "gateway.env"


def _ensure_env_file() -> Path:
    """Create a template env file if it doesn't exist."""
    env_file = _env_file_path()
    env_file.parent.mkdir(parents=True, exist_ok=True)
    if not env_file.exists():
        env_file.write_text(textwrap.dedent("""\
            # ClawSentry Gateway environment variables
            # See: https://elroyper.github.io/ClawSentry/operations/deployment/

            # Authentication token (required for production)
            # CS_AUTH_TOKEN=your-strong-random-token

            # LLM provider for L2/L3 (optional)
            # CS_LLM_PROVIDER=anthropic
            # CS_LLM_API_KEY=sk-...
            # CS_LLM_MODEL=claude-haiku-4-5-20251001

            # Token budget enforcement (optional; actual provider-reported tokens)
            # CS_LLM_TOKEN_BUDGET_ENABLED=false
            # CS_LLM_DAILY_TOKEN_BUDGET=0
            # CS_LLM_TOKEN_BUDGET_SCOPE=total

            # Bounded-large timeouts
            # CS_L2_TIMEOUT_MS=60000
            # CS_L3_TIMEOUT_MS=300000
            # CS_HARD_TIMEOUT_MS=600000

            # HTTP listen address
            # CS_HTTP_HOST=127.0.0.1
            # CS_HTTP_PORT=8080

            # DEFER configuration
            # CS_DEFER_TIMEOUT_S=86400
            # CS_DEFER_TIMEOUT_ACTION=block
            # CS_DEFER_BRIDGE_ENABLED=true
        """), encoding="utf-8")
        os.chmod(str(env_file), 0o600)
    return env_file


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

_PLACEHOLDER_VALUES = {
    "",
    "changeme",
    "change-me",
    "replace-me",
    "your-token",
    "your-strong-random-token",
    "changeme-replace-with-a-strong-random-token",
    "sk-ant-...",
    "sk-...",
}

_SECRET_KEY_PARTS = ("TOKEN", "KEY", "SECRET", "PASSWORD")


def _parse_env_lines(lines: Iterable[str]) -> tuple[dict[str, str], list[str]]:
    """Parse simple KEY=VALUE env lines and return invalid line messages."""
    env: dict[str, str] = {}
    invalid: list[str] = []
    for line_no, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        if "=" not in line:
            invalid.append(f"line {line_no}: expected KEY=VALUE")
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip("'\"")
        if not key:
            invalid.append(f"line {line_no}: missing key")
            continue
        env[key] = value
    return env, invalid


def _read_env_file(env_file: Path) -> tuple[dict[str, str], list[str]]:
    if not env_file.exists():
        return {}, [f"env file not found: {env_file}"]
    try:
        return _parse_env_lines(env_file.read_text(encoding="utf-8").splitlines())
    except OSError as exc:
        return {}, [f"failed to read {env_file}: {exc}"]


def _is_placeholder(value: str | None) -> bool:
    if value is None:
        return True
    lowered = value.strip().lower()
    return lowered in _PLACEHOLDER_VALUES or "replace" in lowered or "changeme" in lowered


def _redact_env_value(key: str, value: str) -> str:
    if any(part in key.upper() for part in _SECRET_KEY_PARTS):
        if not value:
            return "<empty>"
        if _is_placeholder(value):
            return "<placeholder>"
        if len(value) <= 8:
            return "<redacted>"
        return f"{value[:4]}…{value[-4:]}"
    return value


def _parse_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    lowered = value.strip().lower()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    return None


def _positive_int(value: str | None) -> bool:
    if value is None:
        return True
    try:
        return int(value) > 0
    except ValueError:
        return False


def _llm_api_key_candidates(provider: str) -> tuple[str, ...]:
    """Return supported API-key env names in effective-precedence order."""
    provider_key = {
        "anthropic": "ANTHROPIC_API_KEY",
        "openai": "OPENAI_API_KEY",
        "openai-compatible": "OPENAI_API_KEY",
    }.get(provider.strip().lower())
    if provider_key:
        return ("CS_LLM_API_KEY", provider_key)
    return ("CS_LLM_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY")


def _has_usable_llm_api_key(env: dict[str, str], provider: str) -> bool:
    return any(not _is_placeholder(env.get(key)) for key in _llm_api_key_candidates(provider))


def _validate_health_url(health_url: str, token: str | None) -> list[str]:
    request = urllib.request.Request(health_url)
    if token and not _is_placeholder(token):
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            status = getattr(response, "status", 200)
    except urllib.error.HTTPError as exc:
        return [f"health check failed: HTTP {exc.code} for {health_url}"]
    except urllib.error.URLError as exc:
        return [f"health check failed: {exc.reason} for {health_url}"]
    except OSError as exc:
        return [f"health check failed: {exc} for {health_url}"]
    if status >= 500:
        return [f"health check failed: HTTP {status} for {health_url}"]
    return []


def _validate_service_env(
    env: dict[str, str],
    *,
    require_auth: bool = True,
) -> tuple[list[str], list[str]]:
    """Return (errors, warnings) for a deployment env mapping."""
    errors: list[str] = []
    warnings: list[str] = []

    auth_token = env.get("CS_AUTH_TOKEN")
    if require_auth and _is_placeholder(auth_token):
        errors.append("CS_AUTH_TOKEN is required and must not be a placeholder")
    elif auth_token and len(auth_token) < 16:
        warnings.append("CS_AUTH_TOKEN is short; use a high-entropy token for deployment")

    port = env.get("CS_HTTP_PORT")
    if port is not None:
        try:
            parsed_port = int(port)
            if parsed_port < 1 or parsed_port > 65535:
                errors.append("CS_HTTP_PORT must be between 1 and 65535")
        except ValueError:
            errors.append("CS_HTTP_PORT must be an integer")

    if env.get("CS_HTTP_HOST") == "":
        errors.append("CS_HTTP_HOST must not be empty when set")

    provider = env.get("CS_LLM_PROVIDER", "").strip()
    if provider and not _has_usable_llm_api_key(env, provider):
        key_names = "/".join(_llm_api_key_candidates(provider))
        warnings.append(f"CS_LLM_PROVIDER is set but {key_names} is missing or placeholder")
    if not provider and any(
        not _is_placeholder(env.get(key))
        for key in ("CS_LLM_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY")
    ):
        warnings.append("LLM API key is set but CS_LLM_PROVIDER is missing")

    deprecated_aliases = {
        "CS_L2_BUDGET_MS": "CS_L2_TIMEOUT_MS",
        "CS_L3_BUDGET_MS": "CS_L3_TIMEOUT_MS",
        "CS_LLM_DAILY_BUDGET_USD": "CS_LLM_TOKEN_BUDGET_ENABLED/CS_LLM_DAILY_TOKEN_BUDGET",
    }
    for legacy, canonical in deprecated_aliases.items():
        if legacy in env:
            warnings.append(f"{legacy} is deprecated; use {canonical}")

    for timeout_key in ("CS_L2_TIMEOUT_MS", "CS_L3_TIMEOUT_MS", "CS_HARD_TIMEOUT_MS"):
        if not _positive_int(env.get(timeout_key)):
            errors.append(f"{timeout_key} must be a positive integer when set")

    token_budget_enabled = _parse_bool(env.get("CS_LLM_TOKEN_BUDGET_ENABLED"))
    if env.get("CS_LLM_TOKEN_BUDGET_ENABLED") is not None and token_budget_enabled is None:
        errors.append("CS_LLM_TOKEN_BUDGET_ENABLED must be true or false")
    token_budget = env.get("CS_LLM_DAILY_TOKEN_BUDGET")
    if token_budget is not None:
        try:
            parsed_budget = int(token_budget)
        except ValueError:
            errors.append("CS_LLM_DAILY_TOKEN_BUDGET must be an integer")
        else:
            if parsed_budget < 0:
                errors.append("CS_LLM_DAILY_TOKEN_BUDGET must be >= 0")
            if token_budget_enabled is True and parsed_budget <= 0:
                errors.append(
                    "CS_LLM_DAILY_TOKEN_BUDGET must be > 0 when token budget enforcement is enabled"
                )

    scope = env.get("CS_LLM_TOKEN_BUDGET_SCOPE")
    if scope is not None and scope not in {"total", "input", "output"}:
        errors.append("CS_LLM_TOKEN_BUDGET_SCOPE must be one of: total, input, output")

    return errors, warnings


# ---------------------------------------------------------------------------
# systemd (Linux)
# ---------------------------------------------------------------------------

_SYSTEMD_UNIT_NAME = "clawsentry-gateway.service"


def _systemd_user_dir() -> Path:
    return Path.home() / ".config" / "systemd" / "user"


def _generate_systemd_unit(exec_start: str, env_file: Path) -> str:
    return textwrap.dedent(f"""\
        [Unit]
        Description=ClawSentry Supervision Gateway
        After=network-online.target
        Wants=network-online.target

        [Service]
        Type=simple
        ExecStart={exec_start}
        EnvironmentFile={env_file}
        Restart=on-failure
        RestartSec=5

        [Install]
        WantedBy=default.target
    """)


def _install_systemd(enable: bool = True) -> int:
    unit_dir = _systemd_user_dir()
    unit_dir.mkdir(parents=True, exist_ok=True)
    unit_path = unit_dir / _SYSTEMD_UNIT_NAME

    exec_start = _which_clawsentry()
    env_file = _ensure_env_file()
    unit_content = _generate_systemd_unit(exec_start, env_file)
    unit_path.write_text(unit_content, encoding="utf-8")
    print(f"  Wrote {unit_path}")
    print(f"  Env file: {env_file}")

    # Reload systemd
    subprocess.run(["systemctl", "--user", "daemon-reload"], check=False)
    print("  Reloaded systemd user daemon")

    if enable:
        subprocess.run(["systemctl", "--user", "enable", _SYSTEMD_UNIT_NAME], check=False)
        subprocess.run(["systemctl", "--user", "start", _SYSTEMD_UNIT_NAME], check=False)
        print(f"  Enabled and started {_SYSTEMD_UNIT_NAME}")
        print()
        print("  Useful commands:")
        print(f"    systemctl --user status {_SYSTEMD_UNIT_NAME}")
        print(f"    systemctl --user stop {_SYSTEMD_UNIT_NAME}")
        print(f"    journalctl --user -u {_SYSTEMD_UNIT_NAME} -f")
    else:
        print()
        print("  To enable and start:")
        print(f"    systemctl --user enable --now {_SYSTEMD_UNIT_NAME}")

    # Ensure lingering is enabled (services survive logout)
    user = os.getenv("USER", "")
    if user:
        result = subprocess.run(
            ["loginctl", "show-user", user, "--property=Linger"],
            capture_output=True, text=True,
        )
        if "Linger=no" in result.stdout:
            print()
            print("  NOTE: Enable lingering so the service runs after logout:")
            print(f"    sudo loginctl enable-linger {user}")

    return 0


def _uninstall_systemd() -> int:
    unit_path = _systemd_user_dir() / _SYSTEMD_UNIT_NAME
    if not unit_path.exists():
        print(f"  Service not installed ({unit_path} not found)")
        return 0

    subprocess.run(["systemctl", "--user", "stop", _SYSTEMD_UNIT_NAME], check=False)
    subprocess.run(["systemctl", "--user", "disable", _SYSTEMD_UNIT_NAME], check=False)
    unit_path.unlink()
    subprocess.run(["systemctl", "--user", "daemon-reload"], check=False)
    print(f"  Removed {unit_path}")
    print(f"  Stopped and disabled {_SYSTEMD_UNIT_NAME}")
    return 0


def _status_systemd() -> int:
    result = subprocess.run(
        ["systemctl", "--user", "status", _SYSTEMD_UNIT_NAME],
        capture_output=False,
    )
    return result.returncode


# ---------------------------------------------------------------------------
# launchd (macOS)
# ---------------------------------------------------------------------------

_LAUNCHD_LABEL = "com.clawsentry.gateway"


def _launchd_dir() -> Path:
    return Path.home() / "Library" / "LaunchAgents"


def _generate_launchd_plist(exec_path: str, env_file: Path) -> str:
    # Parse env file for ProgramArguments and EnvironmentVariables
    env_vars = {}
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, _, v = line.partition("=")
                env_vars[k.strip()] = v.strip()

    env_dict_xml = ""
    if env_vars:
        entries = "\n".join(f"      <key>{k}</key>\n      <string>{v}</string>" for k, v in env_vars.items())
        env_dict_xml = f"    <key>EnvironmentVariables</key>\n    <dict>\n{entries}\n    </dict>"

    log_dir = Path.home() / ".local" / "log" / "clawsentry"

    parts = exec_path.split()
    args_xml = "\n".join(f"      <string>{p}</string>" for p in parts)

    return textwrap.dedent(f"""\
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>{_LAUNCHD_LABEL}</string>
            <key>ProgramArguments</key>
            <array>
        {args_xml}
            </array>
            <key>RunAtLoad</key>
            <true/>
            <key>KeepAlive</key>
            <true/>
        {env_dict_xml}
            <key>StandardOutPath</key>
            <string>{log_dir}/gateway.log</string>
            <key>StandardErrorPath</key>
            <string>{log_dir}/gateway.err</string>
        </dict>
        </plist>
    """)


def _install_launchd(enable: bool = True) -> int:
    plist_dir = _launchd_dir()
    plist_dir.mkdir(parents=True, exist_ok=True)
    plist_path = plist_dir / f"{_LAUNCHD_LABEL}.plist"

    exec_path = _which_clawsentry()
    env_file = _ensure_env_file()
    log_dir = Path.home() / ".local" / "log" / "clawsentry"
    log_dir.mkdir(parents=True, exist_ok=True)

    plist_content = _generate_launchd_plist(exec_path, env_file)
    plist_path.write_text(plist_content, encoding="utf-8")
    print(f"  Wrote {plist_path}")
    print(f"  Env file: {env_file}")
    print(f"  Logs: {log_dir}/")

    if enable:
        subprocess.run(["launchctl", "load", str(plist_path)], check=False)
        print(f"  Loaded {_LAUNCHD_LABEL}")
        print()
        print("  Useful commands:")
        print("    launchctl list | grep clawsentry")
        print(f"    launchctl unload {plist_path}")
        print(f"    tail -f {log_dir}/gateway.log")

    return 0


def _uninstall_launchd() -> int:
    plist_path = _launchd_dir() / f"{_LAUNCHD_LABEL}.plist"
    if not plist_path.exists():
        print(f"  Service not installed ({plist_path} not found)")
        return 0

    subprocess.run(["launchctl", "unload", str(plist_path)], check=False)
    plist_path.unlink()
    print(f"  Removed {plist_path}")
    print(f"  Unloaded {_LAUNCHD_LABEL}")
    return 0


def _status_launchd() -> int:
    result = subprocess.run(
        ["launchctl", "list"],
        capture_output=True, text=True,
    )
    found = [line for line in result.stdout.splitlines() if "clawsentry" in line.lower()]
    if found:
        print("  ClawSentry launchd agent status:")
        for line in found:
            print(f"    {line}")
    else:
        print("  ClawSentry launchd agent not found. Install with: clawsentry service install")
    return 0 if found else 1


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_service_install(no_enable: bool = False) -> int:
    system = platform.system()
    print(f"\n  Installing ClawSentry service ({system})...")
    print()
    if system == "Linux":
        return _install_systemd(enable=not no_enable)
    elif system == "Darwin":
        return _install_launchd(enable=not no_enable)
    else:
        print(f"  Auto-start is not supported on {system}.")
        print("  Use 'clawsentry start --no-watch' to run in background.")
        return 1


def run_service_uninstall() -> int:
    system = platform.system()
    print(f"\n  Uninstalling ClawSentry service ({system})...")
    print()
    if system == "Linux":
        return _uninstall_systemd()
    elif system == "Darwin":
        return _uninstall_launchd()
    else:
        print(f"  No service to uninstall on {system}.")
        return 0


def run_service_status() -> int:
    system = platform.system()
    if system == "Linux":
        return _status_systemd()
    elif system == "Darwin":
        return _status_launchd()
    else:
        print(f"  Service management not supported on {system}.")
        return 1


def _read_env_assignments(env_file: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def run_service_validate(*, env_file: Path | None = None) -> int:
    """Validate deployment env without touching systemd/launchd host state."""
    path = env_file or _env_file_path()
    print(f"  Validating ClawSentry service env: {path}")
    values, parse_errors = _read_env_file(path)
    if parse_errors:
        for error in parse_errors:
            print(f"  FAIL {error}")
        return 1

    errors, warnings = _validate_service_env(values)

    token = values.get("CS_AUTH_TOKEN")
    if token:
        print(f"  PASS CS_AUTH_TOKEN={_redact_env_value('CS_AUTH_TOKEN', token)}")

    for key in (
        "CS_LLM_PROVIDER",
        "CS_LLM_MODEL",
        "CS_LLM_DAILY_TOKEN_BUDGET",
        "CS_LLM_TOKEN_BUDGET_ENABLED",
    ):
        if key in values:
            print(f"  PASS {key}={_redact_env_value(key, values[key])}")

    for key in ("CS_L2_TIMEOUT_MS", "CS_L3_TIMEOUT_MS", "CS_HARD_TIMEOUT_MS"):
        if key in values:
            print(f"  PASS {key}={values[key]}")

    host = values.get("CS_HTTP_HOST", "127.0.0.1")
    print(f"  PASS CS_HTTP_HOST={host}")

    for warning in warnings:
        print(f"  WARN {warning}")
    for error in errors:
        print(f"  FAIL {error}")

    if errors:
        print("  FAIL: service deployment validation found errors")
        return 1
    print("PASS: service deployment validation succeeded")
    return 0
