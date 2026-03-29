"""Codex framework initializer."""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from .base import ENV_FILE_NAME, InitResult


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
        if env_path.exists() and not force:
            raise FileExistsError(
                f"{env_path} already exists. Use --force to overwrite."
            )
        if env_path.exists() and force:
            warnings.append(f"Overwriting existing {env_path}")

        token = secrets.token_urlsafe(32)
        port = "8080"
        env_vars = {
            "CS_HTTP_PORT": port,
            "CS_AUTH_TOKEN": token,
            "CS_FRAMEWORK": "codex",
        }

        # Auto-detect Codex session directory
        codex_home = Path(os.environ.get("CODEX_HOME", "~/.codex")).expanduser()
        sessions_dir = codex_home / "sessions"
        if sessions_dir.is_dir():
            env_vars["CS_CODEX_SESSION_DIR"] = str(sessions_dir)

        lines = ["# ClawSentry — Codex integration config"]
        for key, val in env_vars.items():
            lines.append(f"{key}={val}")
        lines.append("")
        env_path.write_text("\n".join(lines))
        env_path.chmod(0o600)
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
