"""``clawsentry start`` — one-command launch for gateway + watch."""

from __future__ import annotations

import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from .init_command import run_init
from .integrations_command import collect_integration_status
from .initializers.base import ENV_FILE_NAME, read_env_file


_PID_FILE = Path("/tmp/clawsentry-gateway.pid")
_SUPPORTED_FRAMEWORKS = frozenset({
    "openclaw",
    "a3s-code",
    "codex",
    "claude-code",
    "gemini-cli",
})


def _write_pid_file(path: Path, pid: int) -> None:
    path.write_text(str(pid))


def _read_pid_file(path: Path) -> int | None:
    try:
        return int(path.read_text().strip())
    except (OSError, ValueError):
        return None


def _remove_pid_file(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def read_enabled_frameworks_from_env_file(env_file: Path) -> list[str]:
    """Read CS_ENABLED_FRAMEWORKS/CS_FRAMEWORK from .env.clawsentry."""
    values = read_env_file(env_file)
    enabled: list[str] = []
    raw_enabled = values.get("CS_ENABLED_FRAMEWORKS", "")
    for item in raw_enabled.split(","):
        item = item.strip()
        if item and item not in enabled:
            enabled.append(item)
    legacy_framework = values.get("CS_FRAMEWORK", "").strip()
    if legacy_framework and legacy_framework not in enabled:
        enabled.append(legacy_framework)
    return enabled


def _read_framework_from_env_file(env_file: Path) -> str | None:
    """Read the default framework from .env.clawsentry, if present."""
    values = read_env_file(env_file)
    fw = values.get("CS_FRAMEWORK", "").strip()
    if fw in _SUPPORTED_FRAMEWORKS:
        return fw
    enabled = read_enabled_frameworks_from_env_file(env_file)
    for item in enabled:
        if item in _SUPPORTED_FRAMEWORKS:
            return item
    return None


def detect_framework(
    *,
    openclaw_home: Path | None = None,
    a3s_dir: Path | None = None,
    codex_home: Path | None = None,
    claude_home: Path | None = None,
    gemini_home: Path | None = None,
) -> str | None:
    """Auto-detect which framework is configured.

    Returns ``"openclaw"``, ``"a3s-code"``, ``"codex"``, ``"claude-code"``,
    or ``None``.  Explicit ``CS_FRAMEWORK`` in ``.env.clawsentry`` takes
    highest priority.

    Monitoring integrations must be **explicitly enabled**. This function only
    treats project-local config (``.env.clawsentry``) and explicit environment
    variables as opt-in signals. It deliberately avoids silently activating
    monitoring based on home-directory heuristics (e.g. ``~/.codex/sessions``,
    ``~/.claude/settings.json``, ``~/.openclaw/openclaw.json``).
    """
    env_file = Path.cwd() / ".env.clawsentry"
    env_framework = _read_framework_from_env_file(env_file)
    if env_framework:
        return env_framework

    # Explicit shell env can opt-in without writing .env.clawsentry first.
    shell_framework = os.environ.get("CS_FRAMEWORK", "").strip()
    if shell_framework in _SUPPORTED_FRAMEWORKS:
        return shell_framework
    shell_enabled = os.environ.get("CS_ENABLED_FRAMEWORKS", "").strip()
    if shell_enabled:
        enabled = [item.strip() for item in shell_enabled.split(",") if item.strip()]
        for item in enabled:
            if item in _SUPPORTED_FRAMEWORKS:
                return item

    # Legacy ClawSentry releases wrote .a3s-code/settings.json. Keep it as a
    # project marker only; a3s-code AHP still requires explicit SDK transport.
    a3s = a3s_dir or Path.cwd() / ".a3s-code"
    if (a3s / "settings.json").is_file():
        return "a3s-code"

    # Codex: opt-in only when explicitly enabled.
    explicit_codex_session_dir = os.environ.get("CS_CODEX_SESSION_DIR", "").strip()
    if explicit_codex_session_dir:
        candidate = Path(explicit_codex_session_dir)
        if (candidate).is_dir():
            return "codex"

    codex_opt_in = os.environ.get("CS_CODEX_WATCH_ENABLED", "").lower() in ("1", "true", "yes")
    if codex_opt_in:
        effective_codex_home = codex_home or Path(
            os.environ.get("CODEX_HOME", Path.home() / ".codex")
        )
        if (effective_codex_home / "sessions").is_dir():
            return "codex"

    gemini_opt_in = os.environ.get("CS_GEMINI_HOOKS_ENABLED", "").lower() in (
        "1",
        "true",
        "yes",
        "on",
    )
    if gemini_opt_in:
        explicit_settings = os.environ.get("CS_GEMINI_SETTINGS_PATH", "").strip()
        if explicit_settings and Path(explicit_settings).expanduser().is_file():
            return "gemini-cli"
        effective_gemini_home = gemini_home or Path.cwd() / ".gemini"
        if (effective_gemini_home / "settings.json").is_file():
            return "gemini-cli"

    return None


def ensure_init(
    *,
    framework: str,
    target_dir: Path,
    openclaw_home: Path | None = None,
    setup_openclaw: bool = False,
) -> bool:
    """Run init if .env.clawsentry does not exist. Returns True if init was run.

    Raises:
        RuntimeError: If initialization fails.
    """
    env_file = target_dir / ENV_FILE_NAME
    if env_file.exists():
        return False

    exit_code = run_init(
        framework=framework,
        target_dir=target_dir,
        force=False,
        auto_detect=(framework == "openclaw"),
        setup=(framework == "openclaw" and setup_openclaw),
        dry_run=False,
        openclaw_home=openclaw_home,
        quiet=True,
    )
    if exit_code != 0:
        raise RuntimeError(f"Failed to initialize {framework} configuration")
    return True


def ensure_integrations(
    *,
    frameworks: list[str],
    target_dir: Path,
    openclaw_home: Path | None = None,
    setup_openclaw: bool = False,
) -> list[str]:
    """Ensure requested frameworks are present in project env config."""
    env_file = target_dir / ENV_FILE_NAME
    existing = read_enabled_frameworks_from_env_file(env_file)
    initialized: list[str] = []

    for framework in frameworks:
        if framework in existing:
            continue
        exit_code = run_init(
            framework=framework,
            target_dir=target_dir,
            force=False,
            auto_detect=(framework == "openclaw"),
            setup=(framework == "openclaw" and setup_openclaw),
            dry_run=False,
            openclaw_home=openclaw_home,
            quiet=True,
        )
        if exit_code != 0:
            raise RuntimeError(f"Failed to initialize {framework} configuration")
        initialized.append(framework)
        existing = read_enabled_frameworks_from_env_file(env_file)

    return initialized


def ensure_openclaw_setup(
    *,
    openclaw_home: Path | None = None,
):
    """Apply explicit OpenClaw setup when requested at start time."""
    from .initializers.openclaw import OpenClawInitializer

    initializer = OpenClawInitializer()
    return initializer.setup_openclaw_config(openclaw_home=openclaw_home)


def launch_gateway(
    *,
    host: str = "127.0.0.1",
    port: int = 8080,
    log_path: Path,
    extra_env: dict[str, str] | None = None,
) -> subprocess.Popen:
    """Start the gateway as a background subprocess."""
    env = {**os.environ, **(extra_env or {})}
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "w", encoding="utf-8") as log_fh:
        proc = subprocess.Popen(
            [
                sys.executable, "-m", "clawsentry.gateway.stack",
                "--gateway-host", host,
                "--gateway-port", str(port),
            ],
            stdout=log_fh,
            stderr=subprocess.STDOUT,
            env=env,
        )
    time.sleep(0.1)  # brief grace period
    if proc.poll() is not None:
        raise RuntimeError(f"Gateway process exited immediately with code {proc.returncode}")
    return proc


def wait_for_health(
    base_url: str,
    *,
    timeout: float = 5.0,
    interval: float = 0.1,
) -> bool:
    """Poll GET /health until success or timeout."""
    url = f"{base_url.rstrip('/')}/health"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as resp:
                if resp.status == 200:
                    return True
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(interval)
    return False


def shutdown_gateway(proc: subprocess.Popen, timeout: float = 5.0) -> None:
    """Gracefully stop the gateway subprocess."""
    if proc.poll() is not None:
        return  # already exited
    proc.terminate()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=2)


def _read_token_from_env(target_dir: Path) -> str:
    """Read CS_AUTH_TOKEN from environment or .env.clawsentry file."""
    token = os.environ.get("CS_AUTH_TOKEN", "")
    if token:
        return token
    env_file = target_dir / ENV_FILE_NAME
    if env_file.is_file():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line.startswith("CS_AUTH_TOKEN="):
                return line.split("=", 1)[1].strip()
    return ""


def _status_label(status: str) -> str:
    return status.replace("_", " ")


def _print_framework_readiness(
    *,
    active_frameworks: list[str],
    readiness: dict[str, dict[str, object]],
) -> bool:
    """Render concise per-framework readiness hints in start banners."""
    if not readiness:
        return False

    print("  Readiness:")
    next_actions: list[str] = []
    for framework in active_frameworks:
        details = readiness.get(framework)
        if not details:
            continue
        status = _status_label(str(details["status"]))
        summary = str(details["summary"])
        print(f"    {framework}: {status} - {summary}")
        if details["status"] != "ready":
            next_step = str(details.get("next_step", "")).strip()
            if next_step and next_step != "No action required.":
                next_actions.append(f"{framework}: {next_step}")
    if next_actions:
        print("  Next actions:")
        for action in next_actions:
            print(f"    {action}")
        return True
    return False


def run_watch_loop(
    *,
    gateway_url: str,
    token: str,
    interactive: bool = False,
) -> None:
    """Run the watch event loop (blocking). Raises KeyboardInterrupt on Ctrl+C."""
    from .watch_command import run_watch
    run_watch(
        gateway_url=gateway_url,
        token=token,
        filter_types=None,
        json_mode=False,
        color=True,
        interactive=interactive,
    )


def run_stop() -> None:
    """Stop the running gateway process."""
    pid = _read_pid_file(_PID_FILE)
    if pid is None:
        print("No running gateway found.")
        return
    import signal
    try:
        os.kill(pid, signal.SIGTERM)
        print(f"Gateway (PID {pid}) stopped.")
    except ProcessLookupError:
        print(f"Gateway (PID {pid}) not running.")
    _remove_pid_file(_PID_FILE)


def run_status() -> None:
    """Check gateway status."""
    pid = _read_pid_file(_PID_FILE)
    if pid is None:
        print("Gateway: not running")
        return
    try:
        os.kill(pid, 0)  # check if alive
        print(f"Gateway: running (PID {pid})")
    except ProcessLookupError:
        print(f"Gateway: stale PID file (PID {pid} not found)")
        _remove_pid_file(_PID_FILE)


def run_start(
    *,
    framework: str,
    enabled_frameworks: list[str] | None = None,
    host: str = "127.0.0.1",
    port: int = 8080,
    target_dir: Path = Path("."),
    no_watch: bool = False,
    interactive: bool = False,
    openclaw_home: Path | None = None,
    setup_openclaw: bool = False,
    open_browser: bool = False,
    with_latch: bool = False,
    hub_port: int = 3006,
    auto_detected: bool = False,
) -> None:
    """Orchestrate: auto-init → launch gateway → health check → watch."""
    from .dotenv_loader import load_dotenv

    # 1. Auto-init if needed
    requested_frameworks = enabled_frameworks or [framework]
    initialized = ensure_integrations(
        frameworks=requested_frameworks,
        target_dir=target_dir,
        openclaw_home=openclaw_home,
        setup_openclaw=setup_openclaw,
    )
    did_init = bool(initialized)

    # 2. Load env vars (picks up newly created .env.clawsentry)
    load_dotenv(search_dir=target_dir)
    active_frameworks = enabled_frameworks or read_enabled_frameworks_from_env_file(
        target_dir / ENV_FILE_NAME
    ) or [framework]
    openclaw_setup_result = None
    if setup_openclaw and "openclaw" in active_frameworks:
        openclaw_setup_result = ensure_openclaw_setup(openclaw_home=openclaw_home)
    integration_status = collect_integration_status(
        target_dir,
        openclaw_home=openclaw_home,
    )
    framework_readiness = integration_status["framework_readiness"]

    # 3. Read token
    token = _read_token_from_env(target_dir)
    gateway_url = f"http://{host}:{port}"
    log_path = Path("/tmp/clawsentry-gateway.log")
    gateway_ui_url = f"{gateway_url}/ui"
    if token:
        gateway_ui_url += f"?token={token}"

    # -- Latch mode --
    if with_latch:
        latch_ui_url = f"http://127.0.0.1:{hub_port}"
        if token:
            latch_ui_url += f"?token={token}"
        _run_start_with_latch(
            framework=framework,
            active_frameworks=active_frameworks,
            framework_readiness=framework_readiness,
            host=host,
            port=port,
            hub_port=hub_port,
            token=token,
            gateway_url=gateway_url,
            ui_url=latch_ui_url,
            log_path=log_path,
            did_init=did_init,
            no_watch=no_watch,
            interactive=interactive,
            open_browser=open_browser,
            auto_detected=auto_detected,
            setup_openclaw=setup_openclaw,
        )
        return

    # 4. Print banner
    print(f"\nClawSentry starting...")
    print(f"  Framework:  {framework}{' (auto-detected)' if auto_detected else ''}")
    if len(active_frameworks) > 1:
        print(f"  Enabled:    {', '.join(active_frameworks)}")
    if "openclaw" in active_frameworks:
        if setup_openclaw:
            print("  OpenClaw:   setup requested (~/.openclaw/ may be updated)")
        else:
            print(
                "  OpenClaw:   project env only "
                "(use --setup-openclaw to modify ~/.openclaw/)"
            )
    print(f"  Gateway:    {gateway_url} (background)")
    print(f"  Web UI:     {gateway_ui_url}")
    print(f"  Log file:   {log_path}")
    if openclaw_setup_result is not None:
        if openclaw_setup_result.files_modified:
            print(
                "  OpenClaw setup: "
                f"updated {len(openclaw_setup_result.files_modified)} file(s)"
            )
        elif openclaw_setup_result.warnings:
            print("  OpenClaw setup: no files updated")
        else:
            print("  OpenClaw setup: already configured")
        for warning in openclaw_setup_result.warnings:
            print(f"  WARNING:    {warning}")
    has_next_actions = _print_framework_readiness(
        active_frameworks=active_frameworks,
        readiness=framework_readiness,
    )
    if has_next_actions:
        print("  Full diagnostics: clawsentry integrations status --json")
    print()

    # 5. Launch gateway
    proc = launch_gateway(host=host, port=port, log_path=log_path)
    _write_pid_file(_PID_FILE, proc.pid)

    # 6. Health check
    if not wait_for_health(gateway_url):
        print("Gateway failed to start. Check log:", log_path, file=sys.stderr)
        shutdown_gateway(proc)
        _remove_pid_file(_PID_FILE)
        return

    # 6b. Open browser if requested
    if open_browser:
        import webbrowser
        webbrowser.open(gateway_ui_url)

    if no_watch:
        print(f"Gateway running (PID {proc.pid}). Use 'clawsentry stop' to stop it.")
        print(f"  clawsentry watch    # to monitor events")
        return

    # 7. Watch loop (foreground)
    print("Gateway ready. Streaming events...")
    print("─" * 50)
    try:
        run_watch_loop(
            gateway_url=gateway_url,
            token=token,
            interactive=interactive,
        )
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        shutdown_gateway(proc)
        _remove_pid_file(_PID_FILE)
        print(f"Gateway stopped. Log: {log_path}")


def _run_start_with_latch(
    *,
    framework: str,
    active_frameworks: list[str],
    framework_readiness: dict[str, dict[str, object]],
    host: str,
    port: int,
    hub_port: int,
    token: str,
    gateway_url: str,
    ui_url: str,
    log_path: Path,
    did_init: bool,
    no_watch: bool,
    interactive: bool,
    open_browser: bool,
    auto_detected: bool,
    setup_openclaw: bool,
) -> None:
    """Start gateway + Latch Hub via ProcessManager."""
    from ..latch.binary_manager import BinaryManager
    from ..latch.process_manager import ProcessManager

    bm = BinaryManager()
    if not bm.is_installed:
        print(
            "Latch binary not found. Run: clawsentry latch install",
            file=sys.stderr,
        )
        return

    pm = ProcessManager()
    hub_url = f"http://127.0.0.1:{hub_port}"
    keep_running = False

    # Banner
    print(f"\nClawSentry starting (Latch mode)...")
    print(f"  Framework:  {framework}{' (auto-detected)' if auto_detected else ''}")
    if len(active_frameworks) > 1:
        print(f"  Enabled:    {', '.join(active_frameworks)}")
    if "openclaw" in active_frameworks:
        if setup_openclaw:
            print("  OpenClaw:   setup requested (~/.openclaw/ may be updated)")
        else:
            print(
                "  OpenClaw:   project env only "
                "(use --setup-openclaw to modify ~/.openclaw/)"
            )
    print(f"  Gateway:    {gateway_url}")
    print(f"  Latch Hub:  {hub_url}")
    print(f"  Web UI:     {ui_url}")
    print(f"  Log file:   {log_path}")
    has_next_actions = _print_framework_readiness(
        active_frameworks=active_frameworks,
        readiness=framework_readiness,
    )
    if has_next_actions:
        print("  Full diagnostics: clawsentry integrations status --json")
    print()

    try:
        # Start Gateway via ProcessManager
        pm.start_gateway(host=host, port=port, log_path=log_path)

        # Health check Gateway
        if not pm.wait_for_health(gateway_url):
            print("Gateway failed to start. Check log:", log_path, file=sys.stderr)
            pm.stop_all()
            return

        # Start Hub
        pm.start_hub(bm.binary_path, port=hub_port, token=token)

        # Health check Hub
        if not pm.wait_for_health(hub_url):
            print("Latch Hub failed to start.", file=sys.stderr)
            pm.stop_all()
            return

        print("Gateway + Latch Hub ready.")

        if open_browser:
            import webbrowser
            webbrowser.open(ui_url)

        if no_watch:
            print("Use Ctrl+C or 'clawsentry latch stop' to shut down.")
            keep_running = True
            return

        # Watch loop
        print("Streaming events...")
        print("─" * 50)
        run_watch_loop(
            gateway_url=gateway_url,
            token=token,
            interactive=interactive,
        )
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        if keep_running:
            return
        pm.stop_all()
        print("Gateway + Latch Hub stopped.")
