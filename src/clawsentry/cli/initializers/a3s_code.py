"""a3s-code framework initializer."""

from __future__ import annotations

import secrets
from pathlib import Path

from .base import ENV_FILE_NAME, InitResult, merge_env_file


class A3SCodeInitializer:
    """Generate configuration for a3s-code integration."""

    framework_name: str = "a3s-code"

    def generate_config(
        self, target_dir: Path, *, force: bool = False, **_kwargs: object
    ) -> InitResult:
        env_path = target_dir / ENV_FILE_NAME
        legacy_settings_path = target_dir / ".a3s-code" / "settings.json"
        warnings: list[str] = []
        files_created: list[Path] = []

        if env_path.exists() and force:
            warnings.append(f"Overwriting existing {env_path}")
        elif env_path.exists():
            warnings.append(f"Merging {self.framework_name} settings into existing {env_path}")

        if legacy_settings_path.exists():
            warnings.append(
                f"Ignoring legacy {legacy_settings_path}; current upstream "
                "a3s-code does not auto-load it for AHP. Configure "
                "SessionOptions.ahp_transport explicitly."
            )

        env_vars = {
            "CS_FRAMEWORK": self.framework_name,
            "CS_UDS_PATH": "/tmp/clawsentry.sock",
            "CS_AUTH_TOKEN": secrets.token_urlsafe(32),
        }

        env_vars = merge_env_file(
            env_path,
            header="# ClawSentry — a3s-code integration config",
            new_values=env_vars,
            framework=self.framework_name,
            force=force,
        )
        files_created.append(env_path)

        next_steps = [
            f"source {ENV_FILE_NAME}",
            "export NO_PROXY=127.0.0.1,localhost    # avoid routing local Gateway traffic through proxies",
            "clawsentry gateway    # starts on UDS + HTTP port 8080",
            (
                "# Stable path: wire the transport explicitly in your agent script:\n"
                "    #   from a3s_code import Agent, HttpTransport, SessionOptions\n"
                "    #   opts = SessionOptions()\n"
                f'    #   opts.ahp_transport = HttpTransport("http://127.0.0.1:8080/ahp/a3s?token=$CS_AUTH_TOKEN")\n'
                "    #   session = agent.session(\".\", opts, ...)"
            ),
            "clawsentry watch --token \"$CS_AUTH_TOKEN\"    # real-time monitoring",
        ]

        return InitResult(
            files_created=files_created,
            env_vars=env_vars,
            next_steps=next_steps,
            warnings=warnings,
        )
