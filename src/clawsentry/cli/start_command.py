"""``clawsentry start`` — one-command launch for gateway + watch."""

from __future__ import annotations

import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from .init_command import run_init
from .initializers.base import ENV_FILE_NAME


_PID_FILE = Path("/tmp/clawsentry-gateway.pid")


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


def detect_framework(
    *,
    openclaw_home: Path | None = None,
    a3s_dir: Path | None = None,
    codex_home: Path | None = None,
    claude_home: Path | None = None,
) -> str | None:
    """Auto-detect which framework is configured.

    Returns ``"openclaw"``, ``"a3s-code"``, ``"codex"``, ``"claude-code"``,
    or ``None``.  OpenClaw takes priority when multiple are present.
    """
    oc = openclaw_home or Path.home() / ".openclaw"
    if (oc / "openclaw.json").is_file():
        return "openclaw"

    a3s = a3s_dir or Path.cwd() / ".a3s-code"
    if a3s.is_dir():
        return "a3s-code"

    # Codex: check .env.clawsentry for CS_FRAMEWORK=codex
    env_file = Path.cwd() / ".env.clawsentry"
    if env_file.is_file():
        try:
            for line in env_file.read_text().splitlines():
                if line.strip() == "CS_FRAMEWORK=codex":
                    return "codex"
        except OSError:
            pass

    # Claude Code: check BOTH settings.json and settings.local.json
    effective_claude_home = claude_home or Path.home() / ".claude"
    for filename in ("settings.json", "settings.local.json"):
        claude_settings = effective_claude_home / filename
        if claude_settings.is_file():
            try:
                import json as _json
                data = _json.loads(claude_settings.read_text())
                hooks = data.get("hooks", {})
                if any("clawsentry" in str(v) for v in hooks.values()):
                    return "claude-code"
            except Exception:
                pass

    return None


def ensure_init(
    *,
    framework: str,
    target_dir: Path,
    openclaw_home: Path | None = None,
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
        setup=(framework == "openclaw"),
        dry_run=False,
        openclaw_home=openclaw_home,
    )
    if exit_code != 0:
        raise RuntimeError(f"Failed to initialize {framework} configuration")
    return True


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
    with open(log_path, "w") as log_fh:
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
    host: str = "127.0.0.1",
    port: int = 8080,
    target_dir: Path = Path("."),
    no_watch: bool = False,
    interactive: bool = False,
    openclaw_home: Path | None = None,
    open_browser: bool = False,
    with_latch: bool = False,
    hub_port: int = 3006,
) -> None:
    """Orchestrate: auto-init → launch gateway → health check → watch."""
    from .dotenv_loader import load_dotenv

    # 1. Auto-init if needed
    did_init = ensure_init(
        framework=framework,
        target_dir=target_dir,
        openclaw_home=openclaw_home,
    )

    # 2. Load env vars (picks up newly created .env.clawsentry)
    load_dotenv(search_dir=target_dir)

    # 3. Read token
    token = _read_token_from_env(target_dir)
    gateway_url = f"http://{host}:{port}"
    log_path = Path("/tmp/clawsentry-gateway.log")
    ui_url = f"{gateway_url}/ui"
    if token:
        ui_url += f"?token={token}"

    # -- Latch mode --
    if with_latch:
        _run_start_with_latch(
            framework=framework,
            host=host,
            port=port,
            hub_port=hub_port,
            token=token,
            gateway_url=gateway_url,
            ui_url=ui_url,
            log_path=log_path,
            did_init=did_init,
            no_watch=no_watch,
            interactive=interactive,
            open_browser=open_browser,
        )
        return

    # 4. Print banner
    print(f"\nClawSentry starting...")
    print(f"  Framework:  {framework}{' (auto-detected)' if not did_init else ''}")
    print(f"  Gateway:    {gateway_url} (background)")
    print(f"  Web UI:     {ui_url}")
    print(f"  Log file:   {log_path}")
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
        webbrowser.open(ui_url)

    if no_watch:
        print(f"Gateway running (PID {proc.pid}). Use Ctrl+C or kill to stop.")
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

    # Banner
    print(f"\nClawSentry starting (Latch mode)...")
    print(f"  Framework:  {framework}{' (auto-detected)' if not did_init else ''}")
    print(f"  Gateway:    {gateway_url}")
    print(f"  Latch Hub:  {hub_url}")
    print(f"  Web UI:     {ui_url}")
    print(f"  Log file:   {log_path}")
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
        pm.stop_all()
        print("Gateway + Latch Hub stopped.")
