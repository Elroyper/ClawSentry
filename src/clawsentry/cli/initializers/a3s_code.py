"""a3s-code framework initializer."""

from __future__ import annotations

from pathlib import Path

from .base import LOCAL_ENV_FILE_EXAMPLE, InitResult, merge_project_framework_config


class A3SCodeInitializer:
    """Generate configuration for a3s-code integration."""

    framework_name: str = "a3s-code"

    def generate_config(
        self, target_dir: Path, *, force: bool = False, **_kwargs: object
    ) -> InitResult:
        legacy_settings_path = target_dir / ".a3s-code" / "settings.json"
        warnings: list[str] = []
        files_created: list[Path] = []

        if legacy_settings_path.exists():
            warnings.append(
                f"Ignoring legacy {legacy_settings_path}; current upstream "
                "a3s-code does not auto-load it for AHP. Configure "
                "SessionOptions.ahp_transport explicitly."
            )

        config_path, env_vars = merge_project_framework_config(
            target_dir,
            framework=self.framework_name,
            force=force,
        )
        files_created.append(config_path)

        next_steps = [
            f"Optional local secrets: clawsentry start --env-file {LOCAL_ENV_FILE_EXAMPLE}",
            "export NO_PROXY=127.0.0.1,localhost    # avoid routing local Gateway traffic through proxies",
            "clawsentry gateway    # starts on UDS + HTTP port 8080",
            (
                "# Stable path: wire the transport explicitly in your agent script:\n"
                "    #   from a3s_code import Agent, HttpTransport, SessionOptions\n"
                "    #   opts = SessionOptions()\n"
                '    #   opts.ahp_transport = HttpTransport("http://127.0.0.1:8080/ahp/a3s?token=<startup-token>")\n'
                "    #   session = agent.session(\".\", opts, ...)"
            ),
            "clawsentry watch --token <startup-token>    # real-time monitoring",
        ]

        return InitResult(
            files_created=files_created,
            env_vars=env_vars,
            next_steps=next_steps,
            warnings=warnings,
        )
