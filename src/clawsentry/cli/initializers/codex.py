"""Codex framework initializer."""

from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from typing import Any

from .base import ENV_FILE_NAME, InitResult, SetupResult, merge_env_file


_CODEX_HOOK_MARKER = "clawsentry harness --framework codex"
_CODEX_HOOK_COMMAND_SYNC = "clawsentry harness --framework codex"
_CODEX_HOOK_COMMAND_ASYNC = "clawsentry harness --framework codex --async"
_CODEX_HOOK_EVENTS: tuple[tuple[str, str | None, str], ...] = (
    ("SessionStart", "startup|resume", "ClawSentry Codex session monitor"),
    ("UserPromptSubmit", None, "ClawSentry prompt review"),
    ("PreToolUse", "Bash", "ClawSentry Bash preflight"),
    ("PostToolUse", "Bash", "ClawSentry tool review"),
    ("Stop", None, "ClawSentry session finalization"),
)


class CodexInitializer:
    """Generate configuration for Codex integration."""

    framework_name: str = "codex"

    def generate_config(
        self,
        target_dir: Path,
        *,
        force: bool = False,
        **_kwargs: object,
    ) -> InitResult:
        env_path = target_dir / ENV_FILE_NAME
        warnings: list[str] = []
        files_created: list[Path] = []

        # --- .env.clawsentry ---
        if env_path.exists() and force:
            warnings.append(f"Overwriting existing {env_path}")
        elif env_path.exists():
            warnings.append(f"Merging {self.framework_name} settings into existing {env_path}")

        token = secrets.token_urlsafe(32)
        port = "8080"
        env_vars = {
            "CS_HTTP_PORT": port,
            "CS_AUTH_TOKEN": token,
            "CS_FRAMEWORK": "codex",
            "CS_CODEX_WATCH_ENABLED": "true",
        }

        # Auto-detect Codex session directory
        codex_home = Path(os.environ.get("CODEX_HOME", "~/.codex")).expanduser()
        sessions_dir = codex_home / "sessions"
        if sessions_dir.is_dir():
            env_vars["CS_CODEX_SESSION_DIR"] = str(sessions_dir)

        env_vars = merge_env_file(
            env_path,
            header="# ClawSentry — Codex integration config",
            new_values=env_vars,
            framework=self.framework_name,
            force=force,
        )
        files_created.append(env_path)

        next_steps = [
            f"source {ENV_FILE_NAME}",
            "clawsentry gateway    # start Gateway (auto-monitors Codex sessions)",
            "codex                  # use Codex normally",
            "clawsentry watch      # real-time risk evaluation (another terminal)",
        ]

        return InitResult(
            files_created=files_created,
            env_vars=env_vars,
            next_steps=next_steps,
            warnings=warnings,
        )

    def setup_codex_hooks(
        self,
        *,
        codex_home: Path | None = None,
        dry_run: bool = False,
    ) -> SetupResult:
        """Install non-destructive Codex native hook registration.

        The installer owns only entries whose command contains the
        ClawSentry Codex marker.  Existing user/OMX hook entries are
        preserved and ClawSentry entries are idempotently refreshed.
        """
        effective_codex_home = codex_home or Path(os.environ.get("CODEX_HOME", "~/.codex")).expanduser()
        config_path = effective_codex_home / "config.toml"
        hooks_path = effective_codex_home / "hooks.json"

        warnings: list[str] = []
        files_modified = [config_path, hooks_path]
        changes = [
            f"Enable Codex native hooks in {config_path}",
            f"Install ClawSentry managed hook entries in {hooks_path}",
        ]

        if dry_run:
            return SetupResult(
                changes_applied=changes,
                files_modified=files_modified,
                files_backed_up=[],
                warnings=warnings,
                dry_run=True,
            )

        effective_codex_home.mkdir(parents=True, exist_ok=True)
        config_path.write_text(
            _enable_codex_hooks_feature(
                config_path.read_text(encoding="utf-8") if config_path.exists() else ""
            ),
            encoding="utf-8",
        )
        hooks_payload = _load_codex_hooks(hooks_path, warnings)
        merged_hooks = _merge_codex_hooks(hooks_payload)
        hooks_path.write_text(
            json.dumps(merged_hooks, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        return SetupResult(
            changes_applied=changes,
            files_modified=files_modified,
            files_backed_up=[],
            warnings=warnings,
            dry_run=False,
        )

    def uninstall(self, *, codex_home: Path | None = None) -> InitResult:
        """Remove only ClawSentry-managed Codex native hook entries."""
        effective_codex_home = codex_home or Path(os.environ.get("CODEX_HOME", "~/.codex")).expanduser()
        hooks_path = effective_codex_home / "hooks.json"
        warnings: list[str] = []

        if not hooks_path.exists():
            warnings.append(f"{hooks_path} does not exist; no Codex hooks were removed.")
            return InitResult(
                files_created=[],
                env_vars={},
                next_steps=["No ClawSentry Codex hooks were found."],
                warnings=warnings,
            )

        hooks_payload = _load_codex_hooks(hooks_path, warnings)
        cleaned_payload, removed = _remove_clawsentry_codex_hooks(hooks_payload)
        if removed:
            hooks_path.write_text(
                json.dumps(cleaned_payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            next_steps = ["ClawSentry Codex hooks removed. Restart Codex for changes to take effect."]
        else:
            warnings.append("No ClawSentry Codex hooks found in hooks.json")
            next_steps = ["No ClawSentry Codex hooks were found."]

        return InitResult(
            files_created=[],
            env_vars={},
            next_steps=next_steps,
            warnings=warnings,
        )


def _enable_codex_hooks_feature(config_text: str) -> str:
    """Return TOML text with [features].codex_hooks set to true."""
    lines = config_text.splitlines()
    output: list[str] = []
    in_features = False
    saw_features = False
    saw_codex_hooks = False

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            if in_features and not saw_codex_hooks:
                output.append("codex_hooks = true")
                saw_codex_hooks = True
            in_features = stripped == "[features]"
            saw_features = saw_features or in_features
            output.append(line)
            continue
        if in_features and stripped.startswith("codex_hooks"):
            output.append("codex_hooks = true")
            saw_codex_hooks = True
            continue
        output.append(line)

    if in_features and not saw_codex_hooks:
        output.append("codex_hooks = true")
        saw_codex_hooks = True
    if not saw_features:
        if output and output[-1].strip():
            output.append("")
        output.extend(["[features]", "codex_hooks = true"])

    return "\n".join(output).rstrip() + "\n"


def _load_codex_hooks(path: Path, warnings: list[str]) -> dict[str, Any]:
    if not path.exists():
        return {"hooks": {}}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        warnings.append(f"Could not parse {path}, creating fresh hooks.json: {exc}")
        return {"hooks": {}}
    if not isinstance(payload, dict):
        warnings.append(f"{path} must contain a JSON object; creating fresh hooks.json")
        return {"hooks": {}}
    hooks = payload.get("hooks")
    if not isinstance(hooks, dict):
        payload = dict(payload)
        payload["hooks"] = {}
    return payload


def _merge_codex_hooks(existing: dict[str, Any]) -> dict[str, Any]:
    merged = dict(existing)
    hooks = dict(merged.get("hooks") or {})
    for event_name, matcher, status_message in _CODEX_HOOK_EVENTS:
        current = hooks.get(event_name)
        entries = list(current) if isinstance(current, list) else []
        entries = [entry for entry in entries if not _is_clawsentry_codex_hook_entry(entry)]
        entries.append(_build_codex_hook_entry(
            event_name=event_name,
            matcher=matcher,
            status_message=status_message,
        ))
        hooks[event_name] = entries
    merged["hooks"] = hooks
    return merged


def _remove_clawsentry_codex_hooks(existing: dict[str, Any]) -> tuple[dict[str, Any], int]:
    cleaned = dict(existing)
    hooks = dict(cleaned.get("hooks") or {})
    removed = 0
    for event_name in list(hooks.keys()):
        entries = hooks[event_name]
        if not isinstance(entries, list):
            continue
        filtered = []
        for entry in entries:
            if _is_clawsentry_codex_hook_entry(entry):
                removed += 1
            else:
                filtered.append(entry)
        if filtered:
            hooks[event_name] = filtered
        else:
            del hooks[event_name]
    cleaned["hooks"] = hooks
    return cleaned, removed


def _is_clawsentry_codex_hook_entry(entry: Any) -> bool:
    return isinstance(entry, dict) and _CODEX_HOOK_MARKER in str(entry)


def _build_codex_hook_entry(
    *,
    event_name: str,
    matcher: str | None,
    status_message: str,
) -> dict[str, Any]:
    command = (
        _CODEX_HOOK_COMMAND_SYNC
        if event_name == "PreToolUse" and matcher == "Bash"
        else _CODEX_HOOK_COMMAND_ASYNC
    )
    entry: dict[str, Any] = {
        "hooks": [
            {
                "type": "command",
                "command": command,
                "statusMessage": status_message,
            }
        ]
    }
    if matcher is not None:
        entry["matcher"] = matcher
    return entry
