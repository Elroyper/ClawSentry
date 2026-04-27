#!/usr/bin/env python3
"""Run Harbor with a guarded Codex setup path for local benchmark smoke runs.

Harbor's installed Codex adapter currently runs ``apt-get update &&
apt-get install -y curl ripgrep`` on every trial setup. On memory-constrained
local machines that package-manager step can be killed even when the task image
already contains the needed binaries. This wrapper keeps Harbor behavior intact
except for the Codex system-package step: if ``curl`` and ``rg`` are already
present in the task container, it skips the package manager.
"""

from __future__ import annotations

import sys
import shlex

from harbor.agents.installed.codex import Codex
from harbor.agents.installed.base import with_prompt_template
from harbor.cli.main import app
from harbor.environments.base import BaseEnvironment
from harbor.environments.docker.docker import DockerEnvironment
from harbor.models.agent.context import AgentContext
from harbor.models.trial.paths import EnvironmentPaths

HARBOR_INHERIT_ENV = "__HARBOR_INHERIT_ENV__"


SYSTEM_DEPS_COMMAND = (
    "if command -v curl >/dev/null 2>&1 && command -v rg >/dev/null 2>&1; then"
    "  echo 'Harbor Codex system deps already present';"
    " elif ldd --version 2>&1 | grep -qi musl || [ -f /etc/alpine-release ]; then"
    "  apk add --no-cache curl bash nodejs npm ripgrep;"
    " elif command -v apt-get &>/dev/null; then"
    "  apt-get update && apt-get install -y --no-install-recommends curl ripgrep && rm -rf /var/lib/apt/lists/*;"
    " elif command -v yum &>/dev/null; then"
    "  yum install -y curl ripgrep;"
    " else"
    '  echo "Warning: No known package manager found, assuming curl is available" >&2;'
    " fi"
)


async def guarded_docker_exec(
    self: DockerEnvironment,
    command: str,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    timeout_sec: int | None = None,
    user: str | int | None = None,
):
    """Support docker compose ``-e KEY`` inheritance for secret env values."""
    user = self._resolve_user(user)
    env = self._merge_env(env)

    exec_command = ["exec"]

    effective_cwd = cwd or self.task_env_config.workdir
    if effective_cwd:
        exec_command.extend(["-w", effective_cwd])

    if env:
        for key, value in env.items():
            if value == HARBOR_INHERIT_ENV:
                exec_command.extend(["-e", key])
            else:
                exec_command.extend(["-e", f"{key}={value}"])

    if user is not None:
        exec_command.extend(["-u", str(user)])

    exec_command.append("main")
    exec_command.extend(["bash", "-c", command])

    return await self._run_docker_compose_command(
        exec_command, check=False, timeout_sec=timeout_sec
    )


async def guarded_install(self: Codex, environment: BaseEnvironment) -> None:
    """Install Codex while skipping redundant apt work when deps are present."""
    await self.exec_as_root(
        environment,
        command=SYSTEM_DEPS_COMMAND,
        env={"DEBIAN_FRONTEND": "noninteractive"},
    )

    version_spec = f"@{self._version}" if self._version else "@latest"
    await self.exec_as_agent(
        environment,
        command=(
            "set -euo pipefail; "
            "if ldd --version 2>&1 | grep -qi musl || [ -f /etc/alpine-release ]; then"
            f"  npm install -g @openai/codex{version_spec};"
            " else"
            "  curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.2/install.sh | bash &&"
            '  export NVM_DIR="$HOME/.nvm" &&'
            '  \\. "$NVM_DIR/nvm.sh" || true &&'
            "  command -v nvm &>/dev/null || { echo 'Error: NVM failed to load' >&2; exit 1; } &&"
            "  nvm install 22 && nvm alias default 22 && npm -v &&"
            f"  npm install -g @openai/codex{version_spec};"
            " fi && "
            "codex --version"
        ),
    )

    await self.exec_as_root(
        environment,
        command=(
            "for bin in node codex; do"
            '  BIN_PATH="$(which "$bin" 2>/dev/null || true)";'
            '  if [ -n "$BIN_PATH" ] && [ "$BIN_PATH" != "/usr/local/bin/$bin" ]; then'
            '    ln -sf "$BIN_PATH" "/usr/local/bin/$bin";'
            "  fi;"
            " done"
        ),
    )


Codex.install = guarded_install


@with_prompt_template
async def guarded_run(
    self: Codex,
    instruction: str,
    environment: BaseEnvironment,
    context: AgentContext,
) -> None:
    """Run Codex while keeping API key material out of docker exec argv."""
    escaped_instruction = shlex.quote(instruction)

    if not self.model_name:
        raise ValueError("Model name is required")

    model = self.model_name.split("/")[-1]
    cli_flags = self.build_cli_flags()
    cli_flags_arg = (cli_flags + " ") if cli_flags else ""
    auth_json_path = self._resolve_auth_json_path()

    env: dict[str, str] = {
        "CODEX_HOME": EnvironmentPaths.agent_dir.as_posix(),
    }

    codex_env_prefix = ""
    if auth_json_path:
        self.logger.debug("Codex auth: using auth.json from %s", auth_json_path)
        auth_target = (EnvironmentPaths.agent_dir / "auth.json").as_posix()
        await environment.upload_file(auth_json_path, auth_target)
        if environment.default_user is not None:
            await self.exec_as_root(
                environment,
                command=f"chown {environment.default_user} {auth_target}",
            )
        codex_env_prefix = (
            "export OPENAI_API_KEY=\"$(python3 - <<'PY'\n"
            "import json, os\n"
            "print(json.load(open(os.environ['CODEX_HOME'] + '/auth.json')).get('OPENAI_API_KEY', ''))\n"
            "PY\n"
            ")\"; "
        )
    else:
        self.logger.debug("Codex auth: using OPENAI_API_KEY")
        env["OPENAI_API_KEY"] = HARBOR_INHERIT_ENV

    if openai_base_url := self._get_env("OPENAI_BASE_URL"):
        env["OPENAI_BASE_URL"] = openai_base_url

    setup_command = ""
    if not auth_json_path:
        setup_command += (
            "mkdir -p /tmp/codex-secrets\n"
            "cat >/tmp/codex-secrets/auth.json <<EOF\n"
            '{\n  "OPENAI_API_KEY": "${OPENAI_API_KEY}"\n}\nEOF\n'
            'ln -sf /tmp/codex-secrets/auth.json "$CODEX_HOME/auth.json"\n'
        )

    skills_command = self._build_register_skills_command()
    if skills_command:
        setup_command += f"\n{skills_command}"

    mcp_command = self._build_register_mcp_servers_command()
    if mcp_command:
        setup_command += f"\n{mcp_command}"

    if setup_command.strip():
        await self.exec_as_agent(environment, command=setup_command, env=env)

    try:
        await self.exec_as_agent(
            environment,
            command=(
                "if [ -s ~/.nvm/nvm.sh ]; then . ~/.nvm/nvm.sh; fi; "
                f"{codex_env_prefix}"
                "codex exec "
                "--dangerously-bypass-approvals-and-sandbox "
                "--skip-git-repo-check "
                f"--model {model} "
                "--json "
                "--enable unified_exec "
                f"{cli_flags_arg}"
                "-- "
                f"{escaped_instruction} "
                f"2>&1 </dev/null | tee {EnvironmentPaths.agent_dir / self._OUTPUT_FILENAME}"
            ),
            env=env,
        )
    finally:
        try:
            await self.exec_as_agent(
                environment,
                command='rm -rf /tmp/codex-secrets "$CODEX_HOME/auth.json" "$CODEX_HOME/tmp"',
                env={"CODEX_HOME": EnvironmentPaths.agent_dir.as_posix()},
            )
        except Exception:
            pass


Codex.run = guarded_run
DockerEnvironment.exec = guarded_docker_exec


if __name__ == "__main__":
    sys.exit(app())
