"""``clawsentry integrations`` — inspect configured framework integrations."""

from __future__ import annotations

import json
import os
from pathlib import Path

from .initializers.base import ENV_FILE_NAME, read_env_file


def _enabled_frameworks(values: dict[str, str]) -> list[str]:
    enabled: list[str] = []
    for item in values.get("CS_ENABLED_FRAMEWORKS", "").split(","):
        item = item.strip()
        if item and item not in enabled:
            enabled.append(item)
    legacy = values.get("CS_FRAMEWORK", "").strip()
    if legacy and legacy not in enabled:
        enabled.append(legacy)
    return enabled


def _claude_code_hooks_present(claude_home: Path | None = None) -> bool:
    """Return whether Claude Code settings contain ClawSentry hooks."""
    return bool(_claude_code_hook_files(claude_home))


def _claude_code_hook_files(claude_home: Path | None = None) -> list[str]:
    """Return Claude settings files that currently contain ClawSentry hooks."""
    home = claude_home or Path.home() / ".claude"
    found: list[str] = []
    for filename in ("settings.json", "settings.local.json"):
        settings_path = home / filename
        if not settings_path.is_file():
            continue
        try:
            data = json.loads(settings_path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        hooks = data.get("hooks", {})
        if any("clawsentry" in str(value) for value in hooks.values()):
            found.append(str(settings_path))
    return found


def _openclaw_restore_files(openclaw_home: Path | None = None) -> list[str]:
    """Return OpenClaw backup files created by `init openclaw --setup`."""
    home = openclaw_home or Path.home() / ".openclaw"
    backups = [
        home / "openclaw.json.bak",
        home / "exec-approvals.json.bak",
    ]
    return [str(path) for path in backups if path.is_file()]


def _codex_session_dir(values: dict[str, str]) -> Path | None:
    """Resolve the Codex session directory for status reporting."""
    explicit = values.get("CS_CODEX_SESSION_DIR", "").strip()
    if explicit:
        return Path(explicit).expanduser()

    codex_home = Path(
        os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))
    ).expanduser()
    return codex_home / "sessions"


def _status_payload(target_dir: Path) -> dict[str, object]:
    env_path = target_dir / ENV_FILE_NAME
    values = read_env_file(env_path)
    enabled = _enabled_frameworks(values)
    claude_hook_files = (
        _claude_code_hook_files() if "claude-code" in enabled else []
    )
    openclaw_restore_files = (
        _openclaw_restore_files() if "openclaw" in enabled else []
    )
    codex_session_dir = (
        _codex_session_dir(values) if "codex" in enabled else None
    )
    return {
        "env_file": str(env_path),
        "env_exists": env_path.is_file(),
        "legacy_default": values.get("CS_FRAMEWORK", ""),
        "enabled_frameworks": enabled,
        "codex_watcher_enabled": (
            values.get("CS_CODEX_WATCH_ENABLED", "").lower()
            in {"1", "true", "yes", "on"}
        ),
        "openclaw_env_configured": any(key.startswith("OPENCLAW_") for key in values),
        "openclaw_restore_available": bool(openclaw_restore_files),
        "openclaw_restore_files": openclaw_restore_files,
        "claude_code_hooks": (
            "claude-code" in enabled and bool(claude_hook_files)
        ),
        "claude_code_hook_files": claude_hook_files,
        "a3s_transport_env": (
            "a3s-code" in enabled
            and bool(values.get("CS_UDS_PATH") or values.get("CS_HTTP_PORT"))
        ),
        "codex_session_dir": str(codex_session_dir) if codex_session_dir else None,
        "codex_session_dir_reachable": bool(
            codex_session_dir and codex_session_dir.is_dir()
        ),
    }


def run_integrations_status(
    *,
    target_dir: Path = Path("."),
    json_mode: bool = False,
) -> int:
    """Print configured framework integration status."""
    payload = _status_payload(target_dir)
    if json_mode:
        print(json.dumps(payload, indent=2))
        return 0

    enabled = payload["enabled_frameworks"]
    enabled_text = ", ".join(enabled) if enabled else "(none)"
    print("ClawSentry Integrations")
    print("=" * 60)
    print(f"Env file: {payload['env_file']}")
    print(f"Env exists: {'yes' if payload['env_exists'] else 'no'}")
    print(f"Enabled frameworks: {enabled_text}")
    print(f"Legacy default: {payload['legacy_default'] or '(none)'}")
    print(
        "Codex watcher: "
        f"{'enabled' if payload['codex_watcher_enabled'] else 'disabled'}"
    )
    print(
        "OpenClaw env: "
        f"{'configured' if payload['openclaw_env_configured'] else 'not configured'}"
    )
    print(
        "OpenClaw restore: "
        f"{'available' if payload['openclaw_restore_available'] else 'not available'}"
    )
    restore_files = payload["openclaw_restore_files"]
    print(
        "OpenClaw restore files: "
        f"{', '.join(restore_files) if restore_files else '(none)'}"
    )
    print(
        "a3s transport env: "
        f"{'configured' if payload['a3s_transport_env'] else 'not configured'}"
    )
    print(
        "Claude hooks: "
        f"{'present' if payload['claude_code_hooks'] else 'not present'}"
    )
    hook_files = payload["claude_code_hook_files"]
    print(
        "Claude hooks files: "
        f"{', '.join(hook_files) if hook_files else '(none)'}"
    )
    codex_session_dir = payload["codex_session_dir"]
    if codex_session_dir:
        codex_status = (
            "reachable" if payload["codex_session_dir_reachable"] else "missing"
        )
        print(f"Codex session dir: {codex_session_dir} ({codex_status})")
    else:
        print("Codex session dir: (not configured)")
    print("=" * 60)
    return 0
