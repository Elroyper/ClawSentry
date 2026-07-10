"""Session-scope evaluator for minimum task permission.

The evaluator is intentionally deterministic and AHP-native: it reads an
optional ``SessionScopeProfile`` from ``DecisionContext`` and returns a compact
summary. It never lowers an existing risk decision; policy composition decides
whether a non-dry-run, confirmed scope result may tighten ALLOW to DEFER/BLOCK.
"""

from __future__ import annotations

import posixpath
import re
import shlex
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlparse

from clawsentry.gateway.effects.normalizer import normalize_action_effect, shell_command_surface
from clawsentry.gateway.models import (
    ActionEffectEnvelope,
    CanonicalEvent,
    DecisionContext,
    SessionScopeEvaluationSummary,
    SessionScopeProfile,
    SessionScopeVerdict,
)
from clawsentry.gateway.policy.tool_permissions import resolve_tool_permission


_URL_RE = re.compile(r"https?://[^\s'\"<>|)]+", re.IGNORECASE)
_PATH_RE = re.compile(r"(?:~|/|\./|\.\./)[A-Za-z0-9._~:/@%+\-=]+")
_DESTRUCTIVE_COMMAND_RE = re.compile(
    r"\b(?:rm\s+-[^\s]*r|sudo|dd\b.*\bof\s*=\s*/dev/|mkfs|chmod\s+777)\b",
    re.IGNORECASE,
)
_NETWORK_COMMAND_NAMES = frozenset({"curl", "wget", "http", "httpie", "scp", "rsync"})
_NETWORK_WRITE_COMMAND_NAMES = frozenset({"curl", "wget", "http", "httpie"})
_PACKAGE_COMMAND_NAMES = frozenset({"pip", "pip3", "npm", "yarn", "pnpm"})
_PACKAGE_INSTALL_SUBCOMMANDS = frozenset({"install", "add"})
_PACKAGE_OPTION_VALUE_FLAGS = frozenset({
    "--cache-dir",
    "--config",
    "--global-style",
    "--prefix",
    "--python",
    "--registry",
    "--root",
    "--target",
    "--userconfig",
    "--cwd",
})
_SHELL_INLINE_COMMAND_INTERPRETERS = frozenset({"bash", "sh", "zsh"})
_MAX_SHELL_INLINE_DEPTH = 8
_NETWORK_WRITE_FLAGS = frozenset({
    "-d",
    "--data",
    "--data-binary",
    "--post-data",
    "-F",
    "--form",
    "--upload-file",
    "-T",
})
_NETWORK_EFFECT_PREFIXES = (
    "network.",
    "external_sink.",
    "email.",
    "mcp.external_fetch",
    "package.install",
    "remote_execution",
)
_SHELL_AVAILABILITY_PROBE_COMMANDS = frozenset({"command", "which", "type"})
_SHELL_VERSION_PROBE_FLAGS = frozenset({"--help", "--version"})
_MAX_SCOPE_HINT_ROOTS = 3
_SCOPE_TASK_DATA_READONLY_EFFECTS = frozenset({"filesystem.read", "filesystem.enumerate"})
_SCOPE_TASK_OUTPUT_ENV_SETUP_EFFECTS = frozenset({
    "command.exec",
    "filesystem.read",
    "filesystem.enumerate",
    "filesystem.write",
    "environment.probe",
    "package.install",
})
_SCOPE_TASK_OUTPUT_ENV_SETUP_RULES = frozenset({
    "task_output_env_setup",
    "task_output_local_build_execution",
    "task_output_local_python_verify",
    "task_output_local_artifact_execution",
    "task_output_local_test_execution",
    "task_output_local_vcs_inspection",
    "task_output_env_probe",
})
_SCOPE_TASK_OUTPUT_ENV_SETUP_DISQUALIFYING_RULE_FRAGMENTS = frozenset({
    "credential",
    "network",
    "destructive",
    "persistence",
    "encoded_payload",
    "encoded-payload",
    "wrapper",
    "control",
    "oracle",
    "verifier",
    "judge",
    "remote_fetch",
})
_SCOPE_PROCESS_ENV_PROBE_DISQUALIFYING_RULE_FRAGMENTS = frozenset({
    "credential",
    "network",
    "package",
    "destructive",
    "persistence",
    "encoded_payload",
    "encoded-payload",
    "wrapper",
    "control",
    "oracle",
    "verifier",
    "judge",
    "remote_fetch",
    "upload",
    "exfil",
})
_SCOPE_BROAD_ABSOLUTE_ROOTS = frozenset({
    "/",
    "/app",
    "/home",
    "/mnt",
    "/opt",
    "/root",
    "/tmp",
    "/var",
    "/workspace",
})
_SUPERVISION_EVIDENCE_READONLY_PATHS = frozenset({
    "/logs/agent/clawsentry-skill-trust-evidence.jsonl",
})
_SKILL_ROOT_ENUMERATE_EFFECTS = frozenset({"filesystem.enumerate"})
_SKILL_ROOT_ENUMERATE_RULES = frozenset({"shell_enumerate_probe"})
_SKILL_ROOT_ENUMERATE_RELATIONS = frozenset({"inside_workspace", "outside_workspace_or_absolute"})
_SKILL_ROOT_ENUMERATE_EXACT_PATHS = frozenset({
    "/app/skills",
    "/logs/agent/skills",
    "/root/.agents/skills",
    "/root/.claude/skills",
    "/root/.codex/skills",
    "/root/.factory/skills",
    "/root/.gemini/skills",
    "/root/.goose/skills",
    "/root/skills",
    "/skills",
    "/workspace/.codex/skills",
    "/workspace/skills",
})
_SKILL_ROOT_ENUMERATE_NO_EFFECT_COMMANDS = frozenset({"printf", "echo", "sort", "true", "false", ":"})
_STATIC_EXTERNAL_ASSET_SUFFIXES = frozenset({
    ".avif",
    ".cjs",
    ".css",
    ".csv",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".js",
    ".json",
    ".map",
    ".mjs",
    ".otf",
    ".png",
    ".svg",
    ".ttf",
    ".wasm",
    ".webp",
    ".woff",
    ".woff2",
})
_STATIC_EXTERNAL_ASSET_DOWNLOAD_SAFE_CURL_FLAGS = frozenset({"f", "L", "s", "S"})
_STATIC_EXTERNAL_ASSET_DOWNLOAD_SAFE_CURL_OPTIONS = frozenset({
    "--compressed",
    "--fail",
    "--fail-with-body",
    "--location",
    "--show-error",
    "--silent",
})
_STATIC_EXTERNAL_ASSET_DOWNLOAD_SAFE_WGET_OPTIONS = frozenset({
    "--https-only",
    "--quiet",
})
_STATIC_EXTERNAL_ASSET_DOWNLOAD_FORBIDDEN_OPTION_PREFIXES = (
    "--aws-sigv4",
    "--config",
    "--connect-to",
    "--cookie",
    "--cookie-jar",
    "--data",
    "--form",
    "--header",
    "--netrc",
    "--oauth2-bearer",
    "--post-",
    "--proxy",
    "--referer",
    "--request",
    "--resolve",
    "--upload-file",
    "--user",
    "--user-agent",
)
_STATIC_EXTERNAL_ASSET_DOWNLOAD_FORBIDDEN_SHORT_FLAGS = frozenset({
    "A",
    "b",
    "c",
    "d",
    "e",
    "F",
    "H",
    "K",
    "T",
    "u",
    "U",
    "X",
})
_AUXILIARY_OUTPUT_PATH_RE = re.compile(
    r"(?<![a-z0-9])(?:handoff|hand[\W_]*off|sidecar|auxiliary|"
    r"submission[\W_]*(?:bundle|sidecar|handoff|review|reviewer)|"
    r"hidden[\W_]*(?:review|marker|field|sheet|metadata|payload|annotation))"
    r"(?![a-z0-9])",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class SessionScopeEvaluation:
    profile: SessionScopeProfile
    verdict: SessionScopeVerdict
    reason_codes: tuple[str, ...]

    @property
    def enforced(self) -> bool:
        return bool(self.profile.confirmed and not self.profile.dry_run)

    def summary(self) -> SessionScopeEvaluationSummary:
        return SessionScopeEvaluationSummary(
            profile_id=self.profile.profile_id,
            source=self.profile.source,
            confirmed=self.profile.confirmed,
            dry_run=self.profile.dry_run,
            enforced=self.enforced,
            verdict=self.verdict,
            reason_codes=list(self.reason_codes),
        )


@dataclass(frozen=True)
class NetworkScopeDemand:
    demanded: bool
    source: str


def scope_protection_statement(*, enforced: bool) -> str:
    """Return capability-honest user copy for session-scope surfaces."""

    if enforced:
        return (
            "Protected today: confirmed non-dry-run scope profiles can tighten "
            "Gateway decisions to defer or block actions. Not protected today: "
            "ClawSentry does not infer scopes automatically from LLM output."
        )
    return (
        "Protected today: scope preview validates rules and explains the decision "
        "that would apply. Not protected today: dry-run scope profiles do not "
        "block or defer actions until explicitly confirmed."
    )


def evaluate_session_scope(
    event: CanonicalEvent,
    context: DecisionContext | None,
) -> SessionScopeEvaluation | None:
    """Evaluate the optional session scope profile attached to *context*."""

    profile = context.session_scope_profile if context else None
    if profile is None:
        return None

    command = _event_command(event)
    command_surface = shell_command_surface(command)
    tool = (event.tool_name or "").lower()
    tool_permission_group = resolve_tool_permission(
        tool,
        overrides=context.tool_permission_group_overrides if context else None,
    ).group
    effect_envelope = normalize_action_effect(event, context)
    paths = _event_paths(event, command_surface)
    domains = _event_domains(event, command_surface)
    capabilities = tuple(effect_envelope.effects)
    skill_id = _context_skill_id(context)
    skill_trust_state = _context_skill_trust_state(context)
    skill_identity_untrusted = _context_skill_identity_untrusted(context)
    mcp_server = _context_mcp_server(context, tool)
    mcp_tool = _context_mcp_tool(context, tool)
    mcp_status = _context_mcp_status(context)
    mcp_trust_level = _context_mcp_trust_level(context)

    deny_reasons = _base_deny_reasons(
        profile,
        tool,
        command_surface,
        paths,
        domains,
        skill_id,
        skill_trust_state,
        mcp_server,
        mcp_tool,
        mcp_status,
        mcp_trust_level,
        capabilities,
        tool_permission_group,
    )
    if deny_reasons:
        return SessionScopeEvaluation(
            profile=profile,
            verdict=SessionScopeVerdict.DENY,
            reason_codes=tuple(deny_reasons),
        )

    if profile.confirmed and not profile.dry_run:
        if _is_scope_process_environment_probe(effect_envelope, command):
            return SessionScopeEvaluation(
                profile=profile,
                verdict=SessionScopeVerdict.ALLOW,
                reason_codes=("scope_allow:process_environment_probe",),
            )
        if _is_scope_task_data_readonly_probe(effect_envelope):
            return SessionScopeEvaluation(
                profile=profile,
                verdict=SessionScopeVerdict.ALLOW,
                reason_codes=("scope_allow:task_data_readonly",),
            )
        if _is_scope_task_output_readonly_probe(effect_envelope):
            return SessionScopeEvaluation(
                profile=profile,
                verdict=SessionScopeVerdict.ALLOW,
                reason_codes=("scope_allow:task_output_readonly",),
            )
        if _is_scope_task_output_env_setup(effect_envelope):
            return SessionScopeEvaluation(
                profile=profile,
                verdict=SessionScopeVerdict.ALLOW,
                reason_codes=("scope_allow:task_output_env_setup",),
            )
        if _is_scope_task_output_external_asset_download(effect_envelope, command_surface):
            return SessionScopeEvaluation(
                profile=profile,
                verdict=SessionScopeVerdict.ALLOW,
                reason_codes=("scope_allow:task_output_external_asset_download",),
            )
        if _is_scope_supervision_evidence_readonly_probe(
            effect_envelope,
            _event_paths(event, command),
        ):
            return SessionScopeEvaluation(
                profile=profile,
                verdict=SessionScopeVerdict.ALLOW,
                reason_codes=("scope_allow:supervision_evidence_readonly",),
            )
        if _is_scope_skill_root_enumerate_probe(effect_envelope, command_surface):
            return SessionScopeEvaluation(
                profile=profile,
                verdict=SessionScopeVerdict.ALLOW,
                reason_codes=("scope_allow:skill_root_enumerate",),
            )

    allow_reasons = _task_allow_reasons(
        profile,
        tool,
        command_surface,
        paths,
        domains,
        skill_id,
        skill_trust_state,
        skill_identity_untrusted,
        mcp_server,
        mcp_tool,
        mcp_status,
        mcp_trust_level,
        capabilities,
        tool_permission_group,
    )
    defer_reasons = _task_defer_reasons(
        profile,
        event,
        tool,
        command_surface,
        paths,
        domains,
        skill_id,
        skill_trust_state,
        skill_identity_untrusted,
        mcp_server,
        mcp_tool,
        mcp_status,
        mcp_trust_level,
        capabilities,
        tool_permission_group,
    )
    if defer_reasons:
        return SessionScopeEvaluation(
            profile=profile,
            verdict=SessionScopeVerdict.DEFER,
            reason_codes=tuple(defer_reasons),
        )
    if allow_reasons:
        return SessionScopeEvaluation(
            profile=profile,
            verdict=SessionScopeVerdict.ALLOW,
            reason_codes=tuple(allow_reasons),
        )
    return SessionScopeEvaluation(
        profile=profile,
        verdict=SessionScopeVerdict.NEUTRAL,
        reason_codes=(
            "scope_neutral:no_applicable_rule",
            *_scope_task_artifact_hint_reason_codes(profile),
        ),
    )


def _event_command(event: CanonicalEvent) -> str:
    command = event.payload.get("command")
    if command is None:
        command = event.payload.get("cmd")
    if command is None:
        arguments = event.payload.get("arguments")
        if isinstance(arguments, dict):
            command = arguments.get("command")
            if command is None:
                command = arguments.get("cmd")
    return str(command or "")


def _event_paths(event: CanonicalEvent, command: str) -> tuple[str, ...]:
    paths: list[str] = []
    for key in ("path", "file_path", "target_path"):
        value = event.payload.get(key)
        if value:
            paths.append(str(value))
    paths.extend(match.group(0) for match in _PATH_RE.finditer(command))
    return tuple(dict.fromkeys(paths))


def _event_domains(event: CanonicalEvent, command: str) -> tuple[str, ...]:
    urls: list[str] = []
    for key in ("url", "uri", "endpoint"):
        value = event.payload.get(key)
        if value:
            urls.append(str(value))
    urls.extend(match.group(0) for match in _URL_RE.finditer(command))
    domains: list[str] = []
    for url in urls:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split("/", 1)[0]
        domain = domain.split("@")[-1].split(":")[0].lower()
        if domain:
            domains.append(domain)
    return tuple(dict.fromkeys(domains))


def _is_scope_process_environment_probe(envelope: ActionEffectEnvelope, command: str) -> bool:
    effects = {str(effect) for effect in envelope.effects}
    if effects != {"environment.probe"}:
        return False
    evidence_rules = {str(rule) for rule in envelope.evidence_rules}
    if any(
        fragment in rule.lower()
        for rule in evidence_rules
        for fragment in _SCOPE_PROCESS_ENV_PROBE_DISQUALIFYING_RULE_FRAGMENTS
    ):
        return False
    targets = list(envelope.targets)
    if not targets:
        return False
    if not all(
        target.path_role == "capability_probe"
        and target.workspace_relation == "process_environment"
        for target in targets
    ):
        return False
    return (
        _is_scope_command_availability_probe(command)
        or bool({
            "python_module_capability_probe",
            "python_importlib_metadata_version_probe",
            "python_path_capability_probe",
            "python_constant_capability_probe",
        }.intersection(evidence_rules))
    )


def _is_scope_task_data_readonly_probe(envelope: ActionEffectEnvelope) -> bool:
    effects = {str(effect) for effect in envelope.effects}
    if not effects or not effects.issubset(_SCOPE_TASK_DATA_READONLY_EFFECTS):
        return False
    if envelope.analysis_state != "complete":
        return False
    path_targets = [target for target in envelope.targets if target.kind == "path"]
    if not path_targets:
        return False
    return all(_target_is_effective_task_data_readonly(target) for target in path_targets)


def _is_scope_task_output_readonly_probe(envelope: ActionEffectEnvelope) -> bool:
    effects = {str(effect) for effect in envelope.effects}
    if not effects or not effects.issubset(_SCOPE_TASK_DATA_READONLY_EFFECTS):
        return False
    if envelope.analysis_state != "complete":
        return False
    path_targets = [target for target in envelope.targets if target.kind == "path"]
    if not path_targets:
        return False
    return all(_target_is_effective_task_output_readonly(target) for target in path_targets)


def _is_scope_task_output_env_setup(envelope: ActionEffectEnvelope) -> bool:
    effects = {str(effect) for effect in envelope.effects}
    if not effects or not effects.issubset(_SCOPE_TASK_OUTPUT_ENV_SETUP_EFFECTS):
        return False
    if envelope.analysis_state != "complete":
        return False
    if envelope.wrapper_chain:
        return False
    evidence_rules = {str(rule).lower() for rule in envelope.evidence_rules}
    if not evidence_rules.intersection(_SCOPE_TASK_OUTPUT_ENV_SETUP_RULES):
        return False
    if "package.install" in effects and "task_output_env_setup" not in evidence_rules:
        return False
    for rule in evidence_rules:
        if rule == "package_install" and "task_output_env_setup" in evidence_rules:
            continue
        if any(
            fragment in rule
            for fragment in _SCOPE_TASK_OUTPUT_ENV_SETUP_DISQUALIFYING_RULE_FRAGMENTS
        ):
            return False
        if "package" in rule and rule != "package_install":
            return False
    path_targets = [target for target in envelope.targets if target.kind == "path"]
    if not path_targets:
        return False
    has_task_output_target = False
    for target in path_targets:
        if target.path_role == "capability_probe":
            if target.workspace_relation != "process_environment":
                return False
            continue
        if not _target_is_effective_task_output_readonly(target):
            return False
        has_task_output_target = True
    return has_task_output_target


def _static_external_asset_download_details(command: str) -> dict[str, object] | None:
    command_surface = shell_command_surface(str(command or ""))
    if not command_surface.strip():
        return None
    tokens = _static_external_asset_download_tokens(command_surface)
    if tokens is None or len(tokens) < 4:
        return None
    head = _clean_scope_shell_path(tokens[0]).rsplit("/", 1)[-1].lower()
    if head == "curl":
        details = _static_curl_download_details(tokens)
    elif head == "wget":
        details = _static_wget_download_details(tokens)
    else:
        return None
    if details is None:
        return None
    if not _is_static_https_asset_url(str(details.get("url") or "")):
        return None
    if not _is_static_external_asset_output_path(str(details.get("output_path") or "")):
        return None
    return details


def _static_external_asset_download_tokens(command: str) -> list[str] | None:
    command_surface = shell_command_surface(str(command or ""))
    if not command_surface.strip():
        return None
    if re.search(r"(?:&&|\|\||[|;&`]|<\(|\$\(|\$\{)", command_surface):
        return None
    try:
        tokens = shlex.split(command_surface)
    except ValueError:
        return None
    if not tokens:
        return None
    unwrapped = _static_unwrap_shell_download_tokens(tokens)
    return unwrapped if unwrapped is not None else tokens


def _static_external_asset_download_has_safe_shell_wrapper(command: str) -> bool:
    command_surface = shell_command_surface(str(command or ""))
    if not command_surface.strip():
        return False
    if re.search(r"(?:&&|\|\||[|;&`]|<\(|\$\(|\$\{)", command_surface):
        return False
    try:
        tokens = shlex.split(command_surface)
    except ValueError:
        return False
    return _static_unwrap_shell_download_tokens(tokens) is not None


def _static_unwrap_shell_download_tokens(tokens: list[str]) -> list[str] | None:
    if len(tokens) != 3:
        return None
    shell_name = _clean_scope_shell_path(tokens[0]).rsplit("/", 1)[-1].lower()
    if shell_name not in {"bash", "sh", "dash"}:
        return None
    flags = tokens[1]
    if not flags.startswith("-") or "c" not in flags[1:]:
        return None
    if set(flags[1:]) != {"c"}:
        return None
    inner_command = shell_command_surface(tokens[2])
    if not inner_command.strip():
        return None
    if re.search(r"(?:&&|\|\||[|;&`]|<\(|\$\(|\$\{)", inner_command):
        return None
    try:
        inner_tokens = shlex.split(inner_command)
    except ValueError:
        return None
    if not inner_tokens:
        return None
    inner_head = _clean_scope_shell_path(inner_tokens[0]).rsplit("/", 1)[-1].lower()
    if inner_head not in {"curl", "wget"}:
        return None
    return inner_tokens


def _static_curl_download_details(tokens: list[str]) -> dict[str, object] | None:
    url: str | None = None
    output_path: str | None = None
    allows_redirects = False
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if not token or token == "--":
            return None
        if _static_download_token_has_dynamic_shell_surface(token):
            return None
        if token in {"-o", "--output"}:
            index += 1
            if index >= len(tokens):
                return None
            output_path = tokens[index]
        elif token.startswith("--output="):
            output_path = token.split("=", 1)[1]
        elif token.startswith("-o") and len(token) > 2:
            output_path = token[2:]
        elif token == "-L" or token == "--location":
            allows_redirects = True
        elif token.startswith("--"):
            if _static_download_long_option_forbidden(token):
                return None
            if token not in _STATIC_EXTERNAL_ASSET_DOWNLOAD_SAFE_CURL_OPTIONS:
                return None
            if token == "--location":
                allows_redirects = True
        elif token.startswith("-") and len(token) > 1:
            flags = token[1:]
            if any(flag in _STATIC_EXTERNAL_ASSET_DOWNLOAD_FORBIDDEN_SHORT_FLAGS for flag in flags):
                return None
            if not set(flags).issubset(_STATIC_EXTERNAL_ASSET_DOWNLOAD_SAFE_CURL_FLAGS):
                return None
            if "L" in flags:
                allows_redirects = True
        elif token.startswith(("https://", "http://")):
            if url is not None:
                return None
            url = token
        else:
            return None
        index += 1
    if url is None or output_path is None:
        return None
    return {
        "tool": "curl",
        "url": url,
        "output_path": output_path,
        "allows_redirects": allows_redirects,
    }


def _static_wget_download_details(tokens: list[str]) -> dict[str, object] | None:
    url: str | None = None
    output_path: str | None = None
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if not token or token == "--":
            return None
        if _static_download_token_has_dynamic_shell_surface(token):
            return None
        if token in {"-O", "--output-document"}:
            index += 1
            if index >= len(tokens):
                return None
            output_path = tokens[index]
        elif token.startswith("--output-document="):
            output_path = token.split("=", 1)[1]
        elif token.startswith("--"):
            if _static_download_long_option_forbidden(token):
                return None
            if token not in _STATIC_EXTERNAL_ASSET_DOWNLOAD_SAFE_WGET_OPTIONS:
                return None
        elif token.startswith("-"):
            flags = token[1:]
            if "O" in flags or any(flag in _STATIC_EXTERNAL_ASSET_DOWNLOAD_FORBIDDEN_SHORT_FLAGS for flag in flags):
                return None
            if flags not in {"q"}:
                return None
        elif token.startswith(("https://", "http://")):
            if url is not None:
                return None
            url = token
        else:
            return None
        index += 1
    if url is None or output_path is None:
        return None
    return {
        "tool": "wget",
        "url": url,
        "output_path": output_path,
        "allows_redirects": True,
    }


def _static_download_token_has_dynamic_shell_surface(token: str) -> bool:
    return any(fragment in token for fragment in ("$", "`", "$(", "${", "<("))


def _static_download_long_option_forbidden(token: str) -> bool:
    option_name = token.split("=", 1)[0]
    return any(
        option_name == prefix or option_name.startswith(prefix)
        for prefix in _STATIC_EXTERNAL_ASSET_DOWNLOAD_FORBIDDEN_OPTION_PREFIXES
    )


def _is_static_https_asset_url(url: str) -> bool:
    if not re.fullmatch(r"https://[^\s'\"<>]+", str(url or ""), re.IGNORECASE):
        return False
    return not _static_download_token_has_dynamic_shell_surface(url)


def _is_static_external_asset_output_path(path: str) -> bool:
    cleaned = str(path or "").strip().strip("'\"").replace("\\", "/")
    if not cleaned or cleaned == "-":
        return False
    if _static_download_token_has_dynamic_shell_surface(cleaned):
        return False
    normalized = posixpath.normpath(cleaned)
    if any(part == ".." for part in normalized.split("/")):
        return False
    if _AUXILIARY_OUTPUT_PATH_RE.search(cleaned):
        return False
    suffixes = []
    base = cleaned
    while True:
        base, suffix = posixpath.splitext(base)
        if not suffix:
            break
        suffixes.append(suffix.lower())
    return any(suffix in _STATIC_EXTERNAL_ASSET_SUFFIXES for suffix in suffixes)


def _is_scope_task_output_external_asset_download(
    envelope: ActionEffectEnvelope,
    command: str,
) -> bool:
    if _static_external_asset_download_details(command) is None:
        return False
    safe_shell_wrapper = _static_external_asset_download_has_safe_shell_wrapper(command)
    effects = {str(effect) for effect in envelope.effects}
    if not {"network.fetch", "filesystem.write"}.issubset(effects):
        return False
    allowed_effects = {"network.fetch", "filesystem.write", "future_execution.artifact"}
    if safe_shell_wrapper:
        allowed_effects.add("command.exec")
    if not effects.issubset(allowed_effects):
        return False
    if envelope.analysis_state != "complete":
        return False
    if envelope.wrapper_chain and not safe_shell_wrapper:
        return False
    if envelope.sources:
        return False

    evidence_rules = {str(rule).lower() for rule in envelope.evidence_rules}
    required_rules = {"network_equivalent_fetch", "network_download_write"}
    if not required_rules.issubset(evidence_rules):
        return False
    allowed_rules = {
        *required_rules,
        "associated_script_network_indicator",
        "generated_script_future_exec",
    }
    for rule in evidence_rules:
        if rule in allowed_rules:
            continue
        if rule in {"wrapper_chain_unresolved", "shell_unresolved_command_segment"} and safe_shell_wrapper:
            continue
        return False

    if not envelope.targets:
        return False
    has_task_output_target = False
    for target in envelope.targets:
        if getattr(target, "kind", None) == "path" and _target_is_effective_task_output_asset(target):
            has_task_output_target = True
            continue
        if _is_static_external_asset_wrapper_modeling_target(
            target,
            safe_shell_wrapper=safe_shell_wrapper,
        ):
            continue
        if _is_static_external_asset_content_evidence_modeling_target(
            target,
            evidence_rules=evidence_rules,
        ):
            continue
        return False
    return has_task_output_target


def _target_is_effective_task_data_readonly(target: object) -> bool:
    return bool(
        getattr(target, "path_role", None) == "benchmark_task_data_read"
        and getattr(target, "workspace_relation", None) == "benchmark_task_data"
        and getattr(target, "artifact_role", None) == "task_data"
        and getattr(target, "artifact_source_tier", None) == "risk_adjusting"
        and getattr(target, "artifact_confidence", None) == "high"
        and getattr(target, "artifact_trust_confirmed", None) is True
        and getattr(target, "artifact_risk_adjusting", None) is True
    )


def _target_is_effective_task_output_readonly(target: object) -> bool:
    return bool(
        getattr(target, "path_role", None) == "benchmark_task_output"
        and getattr(target, "workspace_relation", None) == "task_output_artifact"
        and getattr(target, "artifact_role", None) == "task_output"
        and getattr(target, "artifact_source_tier", None) == "risk_adjusting"
        and getattr(target, "artifact_confidence", None) == "high"
        and getattr(target, "artifact_trust_confirmed", None) is True
        and getattr(target, "artifact_risk_adjusting", None) is True
    )


def _target_is_effective_task_output_asset(target: object) -> bool:
    return bool(
        getattr(target, "path_role", None) in {"benchmark_task_output", "future_execution.artifact"}
        and getattr(target, "workspace_relation", None) == "task_output_artifact"
        and getattr(target, "artifact_role", None) == "task_output"
        and getattr(target, "artifact_candidate_role", None) == "benchmark_task_output"
        and getattr(target, "artifact_source_tier", None) == "risk_adjusting"
        and getattr(target, "artifact_confidence", None) == "high"
        and getattr(target, "artifact_trust_confirmed", None) is True
        and getattr(target, "artifact_risk_adjusting", None) is True
    )


def _is_static_external_asset_wrapper_modeling_target(
    target: object,
    *,
    safe_shell_wrapper: bool,
) -> bool:
    if not safe_shell_wrapper:
        return False
    return (
        getattr(target, "path_role", None) == "future_execution.artifact"
        and getattr(target, "workspace_relation", None) == "inside_workspace"
        and getattr(target, "artifact_trust_confirmed", None) is False
        and getattr(target, "artifact_deny_reason", None)
        == "deny_override:future_execution.artifact"
    )


def _is_static_external_asset_content_evidence_modeling_target(
    target: object,
    *,
    evidence_rules: set[str],
) -> bool:
    return bool(
        "associated_script_network_indicator" in evidence_rules
        and getattr(target, "kind", None) == "content_evidence"
        and getattr(target, "path_role", None) == "executed_script"
        and getattr(target, "workspace_relation", None) == "gateway_content_evidence"
    )


def _is_scope_supervision_evidence_readonly_probe(
    envelope: ActionEffectEnvelope,
    paths: Iterable[str],
) -> bool:
    effects = {str(effect) for effect in envelope.effects}
    if not effects or not effects.issubset(_SCOPE_TASK_DATA_READONLY_EFFECTS):
        return False
    if envelope.analysis_state != "complete":
        return False
    if not envelope.targets:
        return False
    normalized_paths = tuple(
        path
        for path in (_normalize_supervision_evidence_path(path) for path in paths)
        if path is not None
    )
    return bool(normalized_paths) and all(
        path in _SUPERVISION_EVIDENCE_READONLY_PATHS
        for path in normalized_paths
    )


def _is_scope_skill_root_enumerate_probe(
    envelope: ActionEffectEnvelope,
    command: str,
) -> bool:
    effects = {str(effect) for effect in envelope.effects}
    if effects != _SKILL_ROOT_ENUMERATE_EFFECTS:
        return False
    if envelope.analysis_state != "complete":
        return False
    if envelope.wrapper_chain:
        return False
    evidence_rules = {str(rule) for rule in envelope.evidence_rules}
    if not evidence_rules or not evidence_rules.issubset(_SKILL_ROOT_ENUMERATE_RULES):
        return False
    path_targets = [target for target in envelope.targets if target.kind == "path"]
    if not path_targets:
        return False
    roots_are_skill_roots = all(
        target.path_role == "skill_package_read"
        and target.workspace_relation in _SKILL_ROOT_ENUMERATE_RELATIONS
        for target in path_targets
    )
    return roots_are_skill_roots and (
        _is_exact_nonrecursive_skill_root_ls(command)
        or _is_bounded_skill_manifest_find(command)
    )


def _is_exact_nonrecursive_skill_root_ls(command: str) -> bool:
    saw_skill_root_ls = False
    for segment in _split_scope_shell_segments(command):
        tokens = _scope_shell_tokens_without_redirects(_scope_shell_tokens(segment))
        if not tokens:
            continue
        head = _clean_scope_shell_path(tokens[0]).rsplit("/", 1)[-1].lower()
        if head in _SKILL_ROOT_ENUMERATE_NO_EFFECT_COMMANDS:
            continue
        if head != "ls":
            return False
        paths: list[str] = []
        for token in tokens[1:]:
            if token.startswith("-"):
                if token == "--recursive" or (token.startswith("-") and "R" in token):
                    return False
                continue
            normalized = _normalize_exact_skill_root_path(token)
            if normalized is None:
                return False
            paths.append(normalized)
        if not paths or any(path not in _SKILL_ROOT_ENUMERATE_EXACT_PATHS for path in paths):
            return False
        saw_skill_root_ls = True
    return saw_skill_root_ls


def _normalize_exact_skill_root_path(path: str) -> str | None:
    cleaned = str(path or "").strip().strip("'\"").replace("\\", "/")
    if not cleaned.startswith("/"):
        return None
    parts = [part for part in cleaned.split("/") if part]
    if any(part in {".", ".."} for part in parts):
        return None
    return posixpath.normpath(cleaned).rstrip("/") or "/"


def _is_bounded_skill_manifest_find(command: str) -> bool:
    saw_find = False
    for segment in _split_scope_shell_segments(command):
        tokens = _scope_shell_tokens_without_redirects(_scope_shell_tokens(segment))
        if not tokens:
            continue
        head = _clean_scope_shell_path(tokens[0]).rsplit("/", 1)[-1].lower()
        if head in _SKILL_ROOT_ENUMERATE_NO_EFFECT_COMMANDS:
            continue
        if head != "find":
            return False
        if not _bounded_skill_manifest_find_tokens(tokens):
            return False
        saw_find = True
    return saw_find


def _bounded_skill_manifest_find_tokens(tokens: list[str]) -> bool:
    roots: list[str] = []
    saw_name = False
    saw_maxdepth = False
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if not token:
            return False
        if _scope_shell_token_is_redirect(token):
            index += 1
            continue
        if token == "--":
            return False
        if token in {"-exec", "-execdir", "-delete", "-ok", "-okdir", "-fprint", "-fprintf", "-print0"}:
            return False
        if token == "-maxdepth":
            index += 1
            if index >= len(tokens):
                return False
            try:
                maxdepth = int(str(tokens[index]).strip())
            except ValueError:
                return False
            if maxdepth < 0 or maxdepth > 2:
                return False
            saw_maxdepth = True
        elif token == "-name":
            index += 1
            if index >= len(tokens):
                return False
            if str(tokens[index]).strip().strip("'\"") != "SKILL.md":
                return False
            saw_name = True
        elif token == "-type":
            index += 1
            if index >= len(tokens) or str(tokens[index]).strip() != "f":
                return False
        elif token in {"-print"}:
            pass
        elif token.startswith("-"):
            return False
        else:
            normalized = _normalize_skill_manifest_find_root(token)
            if normalized is None:
                return False
            roots.append(normalized)
        index += 1
    return (
        bool(roots)
        and saw_name
        and saw_maxdepth
        and all(root in _SKILL_ROOT_ENUMERATE_EXACT_PATHS for root in roots)
    )


def _scope_shell_token_is_redirect(token: str) -> bool:
    return bool(re.fullmatch(r"(?:[012])?>{1,2}.*|(?:[012])?<.*", str(token or "")))


def _normalize_skill_manifest_find_root(path: str) -> str | None:
    cleaned = str(path or "").strip().strip("'\"").replace("\\", "/")
    if not cleaned:
        return None
    if cleaned in {"$CODEX_HOME/skills", "${CODEX_HOME}/skills"}:
        return "/logs/agent/skills"
    if re.fullmatch(r"\$\{CODEX_HOME:-[^}]+\}/skills", cleaned):
        return "/logs/agent/skills"
    if cleaned in {"$HOME/.agents/skills", "${HOME}/.agents/skills"}:
        return "/root/.agents/skills"
    return _normalize_exact_skill_root_path(cleaned)


def _normalize_supervision_evidence_path(path: str) -> str | None:
    normalized = _clean_scope_shell_path(str(path or "")).replace("\\", "/").rstrip("/")
    if not normalized.startswith("/"):
        return None
    return normalized or "/"


def _is_scope_command_availability_probe(command: str) -> bool:
    segments = _split_scope_shell_segments(command)
    if not segments:
        return False
    for segment in segments:
        tokens = _scope_shell_tokens(segment)
        if not tokens:
            return False
        if _is_scope_shell_availability_probe_segment(tokens):
            continue
        if _is_scope_shell_version_probe_segment(tokens):
            continue
        if _is_scope_shell_status_noop_segment(tokens):
            continue
        return False
    return True


def _split_scope_shell_segments(command: str) -> list[str]:
    return [
        segment.strip()
        for segment in re.split(r"\s*(?:&&|\|\||;|\n|\|)\s*", command or "")
        if segment.strip()
    ]


def _scope_shell_tokens(segment: str) -> list[str]:
    try:
        return shlex.split(segment)
    except ValueError:
        return segment.split()


def _scope_shell_tokens_without_redirects(tokens: list[str]) -> list[str]:
    stripped: list[str] = []
    skip_next = False
    redirect_ops = {">", ">>", "1>", "1>>", "2>", "2>>", "<", "0<"}
    for token in tokens:
        if skip_next:
            skip_next = False
            continue
        if token in redirect_ops:
            skip_next = True
            continue
        if re.fullmatch(r"\d?>&\d", token) or re.fullmatch(r"\d?>>?.+", token):
            continue
        stripped.append(token)
    return stripped


def _clean_scope_shell_path(value: str) -> str:
    return value.strip().strip("'\"").rstrip(".,)")


def _is_simple_scope_shell_command_name(value: str) -> bool:
    cleaned = _clean_scope_shell_path(value)
    return bool(re.fullmatch(r"[A-Za-z0-9_.+-]+", cleaned))


def _is_simple_scope_tool_probe_name(value: str) -> bool:
    cleaned = _clean_scope_shell_path(value)
    return bool(re.fullmatch(r"[A-Za-z0-9_.+@:-]+", cleaned))


def _is_scope_shell_availability_probe_segment(tokens: list[str]) -> bool:
    cleaned = _scope_shell_tokens_without_redirects(tokens)
    if not cleaned:
        return False
    raw_command = _clean_scope_shell_path(cleaned[0])
    if not _is_simple_scope_shell_command_name(raw_command):
        return False
    command = raw_command.lower()
    if command not in _SHELL_AVAILABILITY_PROBE_COMMANDS:
        return False
    if command == "command":
        if len(cleaned) < 3 or cleaned[1] != "-v":
            return False
        args = cleaned[2:]
    else:
        supported_flags = {"-a", "-p", "-P", "--all"}
        args = [token for token in cleaned[1:] if token not in supported_flags]
    return bool(args) and all(
        not token.startswith("-") and _is_simple_scope_tool_probe_name(token)
        for token in args
    )


def _is_scope_shell_version_probe_segment(tokens: list[str]) -> bool:
    cleaned = _scope_shell_tokens_without_redirects(tokens)
    if len(cleaned) < 2:
        return False
    raw_command = _clean_scope_shell_path(cleaned[0])
    if not _is_simple_scope_shell_command_name(raw_command):
        return False
    args = cleaned[1:]
    return any(token in _SHELL_VERSION_PROBE_FLAGS for token in args) and all(
        token in _SHELL_VERSION_PROBE_FLAGS for token in args
    )


def _is_scope_shell_status_noop_segment(tokens: list[str]) -> bool:
    cleaned = _scope_shell_tokens_without_redirects(tokens)
    return cleaned in (["true"], [":"])


def _scope_task_artifact_hint_reason_codes(profile: SessionScopeProfile) -> tuple[str, ...]:
    if not profile.confirmed or profile.dry_run:
        return ()
    hints: list[str] = []
    data_count = 0
    output_count = 0
    output_has_verifier_confirmed_rule = any(
        rule.artifact_role == "task_output"
        and rule.source_tier == "risk_adjusting"
        and rule.confidence == "high"
        and rule.artifact_trust_confirmed
        and "filesystem.write" in set(rule.allowed_effects)
        and bool((rule.source_metadata or {}).get("path_confirmed_by_verifier"))
        for rule in profile.task_artifacts
    )
    for rule in profile.task_artifacts:
        if rule.artifact_role not in {"task_data", "task_output"}:
            continue
        if rule.source_tier != "risk_adjusting" or rule.confidence != "high":
            continue
        if not rule.artifact_trust_confirmed:
            continue
        if rule.artifact_role == "task_data":
            if data_count >= _MAX_SCOPE_HINT_ROOTS:
                continue
            if not {"filesystem.read", "filesystem.enumerate"}.intersection(rule.allowed_effects):
                continue
            hint_prefix = "scope_hint:task_data_root"
        else:
            if output_count >= _MAX_SCOPE_HINT_ROOTS:
                continue
            if "filesystem.write" not in set(rule.allowed_effects):
                continue
            if (
                output_has_verifier_confirmed_rule
                and not bool((rule.source_metadata or {}).get("path_confirmed_by_verifier"))
            ):
                continue
            hint_prefix = "scope_hint:task_output_root"
        for path in rule.paths:
            hint_path = _normalize_scope_hint_path(str(path))
            if hint_path is None:
                continue
            hints.append(f"{hint_prefix}:{hint_path}")
            if rule.artifact_role == "task_data":
                data_count += 1
                if data_count >= _MAX_SCOPE_HINT_ROOTS:
                    break
            else:
                output_count += 1
                if output_count >= _MAX_SCOPE_HINT_ROOTS:
                    break
    return tuple(dict.fromkeys(hints))


def _normalize_scope_hint_path(path: str) -> str | None:
    normalized = path.strip().replace("\\", "/")
    if not normalized.startswith("/"):
        return None
    if any(char in normalized for char in "*?[]{}"):
        return None
    normalized = normalized.rstrip("/") or "/"
    if normalized in _SCOPE_BROAD_ABSOLUTE_ROOTS:
        return None
    return normalized


def _context_skill_id(context: DecisionContext | None) -> str | None:
    skill_trust = context.skill_trust if context else None
    if skill_trust is None:
        return None
    return skill_trust.canonical_skill_id or skill_trust.presented_name


def _context_skill_trust_state(context: DecisionContext | None) -> str | None:
    skill_trust = context.skill_trust if context else None
    if skill_trust is None:
        return None
    return skill_trust.trust_list_state


def _context_skill_identity_untrusted(context: DecisionContext | None) -> bool:
    skill_trust = context.skill_trust if context else None
    if skill_trust is None:
        return False
    if "runtime_registry_claim_untrusted" in skill_trust.invariant_violations:
        return True
    return skill_trust.registry_status in {"unknown", "unbound", "ambiguous"}


def _mcp_server(tool: str) -> str | None:
    parts = tool.split("__")
    if len(parts) >= 3 and parts[0] == "mcp":
        return parts[1]
    return None


def _context_mcp_server(context: DecisionContext | None, tool: str) -> str | None:
    if context and context.mcp_context and context.mcp_context.server_name:
        return context.mcp_context.server_name
    return _mcp_server(tool)


def _context_mcp_tool(context: DecisionContext | None, tool: str) -> str | None:
    if context and context.mcp_context and context.mcp_context.tool_name:
        server_name = context.mcp_context.server_name
        tool_name = context.mcp_context.tool_name
        if server_name:
            return f"{server_name}.{tool_name}"
        return tool_name
    parts = tool.split("__")
    if len(parts) >= 3 and parts[0] == "mcp":
        return f"{parts[1]}.{ '__'.join(parts[2:]) }"
    return None


def _context_mcp_status(context: DecisionContext | None) -> str | None:
    if context and context.mcp_context and context.mcp_context.status:
        return context.mcp_context.status
    return None


def _context_mcp_trust_level(context: DecisionContext | None) -> str | None:
    if context and context.mcp_context and context.mcp_context.trust_level:
        return context.mcp_context.trust_level
    return None


def _base_deny_reasons(
    profile: SessionScopeProfile,
    tool: str,
    command: str,
    paths: Iterable[str],
    domains: Iterable[str],
    skill_id: str | None,
    skill_trust_state: str | None,
    mcp_server: str | None,
    mcp_tool: str | None,
    mcp_status: str | None,
    mcp_trust_level: str | None,
    capabilities: Iterable[str],
    tool_permission_group: str | None,
) -> list[str]:
    reasons: list[str] = []
    if tool and _contains_ci(profile.base_rules.denied_tools, tool):
        reasons.append(f"scope_deny:tool {tool}")
    for prefix in profile.base_rules.denied_command_prefixes:
        if command.strip().lower().startswith(prefix.lower()):
            reasons.append(f"scope_deny:command_prefix {prefix}")
    for path in paths:
        match = _match_path(profile.base_rules.denied_paths, path)
        if match:
            reasons.append(f"scope_deny:path {match}")
    for domain in domains:
        match = _match_domain(profile.base_rules.denied_domains, domain)
        if match:
            reasons.append(f"scope_deny:domain {match}")
    if skill_id and _contains_ci(profile.base_rules.denied_skill_ids, skill_id):
        reasons.append(f"scope_deny:skill {skill_id}")
    if skill_trust_state and _contains_ci(profile.base_rules.denied_skill_trust_states, skill_trust_state):
        reasons.append(f"scope_deny:skill_trust_state {skill_trust_state}")
    if mcp_server and _contains_ci(profile.base_rules.denied_mcp_servers, mcp_server):
        reasons.append(f"scope_deny:mcp_server {mcp_server}")
    if mcp_tool and _contains_ci(profile.base_rules.denied_mcp_tools, mcp_tool):
        reasons.append(f"scope_deny:mcp_tool {mcp_tool}")
    if mcp_status and _contains_ci(profile.base_rules.denied_mcp_statuses, mcp_status):
        reasons.append(f"scope_deny:mcp_status {mcp_status}")
    if mcp_trust_level and _contains_ci(profile.base_rules.denied_mcp_trust_levels, mcp_trust_level):
        reasons.append(f"scope_deny:mcp_trust_level {mcp_trust_level}")
    for capability in capabilities:
        if _contains_ci(profile.base_rules.denied_capabilities, capability):
            reasons.append(f"scope_deny:capability {capability}")
    if (
        tool_permission_group
        and _contains_ci(profile.base_rules.denied_tool_permission_groups, tool_permission_group)
    ):
        reasons.append(f"scope_deny:tool_permission_group {tool_permission_group}")
    if _DESTRUCTIVE_COMMAND_RE.search(command):
        # User-friendly base invariant even when the profile author forgot the
        # exact command prefix.
        reasons.append("scope_deny:destructive_command")
    return reasons


def _task_allow_reasons(
    profile: SessionScopeProfile,
    tool: str,
    command: str,
    paths: Iterable[str],
    domains: Iterable[str],
    skill_id: str | None,
    skill_trust_state: str | None,
    skill_identity_untrusted: bool,
    mcp_server: str | None,
    mcp_tool: str | None,
    mcp_status: str | None,
    mcp_trust_level: str | None,
    capabilities: Iterable[str],
    tool_permission_group: str | None,
) -> list[str]:
    reasons: list[str] = []
    if tool and _contains_ci(profile.task_rules.allowed_tools, tool):
        reasons.append(f"scope_allow:tool {tool}")
    for prefix in profile.task_rules.allowed_command_prefixes:
        if command.strip().lower().startswith(prefix.lower()):
            reasons.append(f"scope_allow:command_prefix {prefix}")
    for path in paths:
        match = _match_path(profile.task_rules.allowed_path_prefixes, path)
        if match:
            reasons.append(f"scope_allow:path_prefix {match}")
    for domain in domains:
        match = _match_domain(profile.task_rules.allowed_domains, domain)
        if match:
            reasons.append(f"scope_allow:domain {match}")
    if (
        skill_id
        and not skill_identity_untrusted
        and _contains_ci(profile.task_rules.allowed_skill_ids, skill_id)
    ):
        reasons.append(f"scope_allow:skill {skill_id}")
    if (
        skill_trust_state
        and not skill_identity_untrusted
        and _contains_ci(profile.task_rules.allowed_skill_trust_states, skill_trust_state)
    ):
        reasons.append(f"scope_allow:skill_trust_state {skill_trust_state}")
    if mcp_server and _contains_ci(profile.task_rules.allowed_mcp_servers, mcp_server):
        reasons.append(f"scope_allow:mcp_server {mcp_server}")
    if mcp_tool and _contains_ci(profile.task_rules.allowed_mcp_tools, mcp_tool):
        reasons.append(f"scope_allow:mcp_tool {mcp_tool}")
    if mcp_status and _contains_ci(profile.task_rules.allowed_mcp_statuses, mcp_status):
        reasons.append(f"scope_allow:mcp_status {mcp_status}")
    if mcp_trust_level and _contains_ci(profile.task_rules.allowed_mcp_trust_levels, mcp_trust_level):
        reasons.append(f"scope_allow:mcp_trust_level {mcp_trust_level}")
    for capability in capabilities:
        if _contains_ci(profile.task_rules.allowed_capabilities, capability):
            reasons.append(f"scope_allow:capability {capability}")
    if (
        tool_permission_group
        and _contains_ci(profile.task_rules.allowed_tool_permission_groups, tool_permission_group)
    ):
        reasons.append(f"scope_allow:tool_permission_group {tool_permission_group}")
    return reasons


def _task_defer_reasons(
    profile: SessionScopeProfile,
    event: CanonicalEvent,
    tool: str,
    command: str,
    paths: Iterable[str],
    domains: Iterable[str],
    skill_id: str | None,
    skill_trust_state: str | None,
    skill_identity_untrusted: bool,
    mcp_server: str | None,
    mcp_tool: str | None,
    mcp_status: str | None,
    mcp_trust_level: str | None,
    capabilities: Iterable[str],
    tool_permission_group: str | None,
) -> list[str]:
    reasons: list[str] = []
    task = profile.task_rules
    network_demand = _network_scope_demand(
        event=event,
        command=command,
        capabilities=capabilities,
        tool_permission_group=tool_permission_group,
        domains=domains,
    )
    allowed_by_permission_group = bool(
        tool_permission_group
        and _contains_ci(task.allowed_tool_permission_groups, tool_permission_group)
    )
    if (
        task.allowed_tools
        and tool
        and not _contains_ci(task.allowed_tools, tool)
        and not allowed_by_permission_group
    ):
        reasons.append(f"scope_defer:unknown_tool {tool}")
    if task.allowed_domains and network_demand.demanded:
        for domain in domains:
            if not _match_domain(task.allowed_domains, domain):
                reasons.append(f"scope_defer:unknown_domain {domain}")
    if task.allowed_skill_ids and skill_id and skill_identity_untrusted:
        reasons.append(f"scope_defer:untrusted_skill_identity {skill_id}")
    elif task.allowed_skill_ids and skill_id and not _contains_ci(task.allowed_skill_ids, skill_id):
        reasons.append(f"scope_defer:unknown_skill {skill_id}")
    if (
        task.allowed_skill_trust_states
        and skill_trust_state
        and skill_identity_untrusted
    ):
        reasons.append(f"scope_defer:untrusted_skill_trust_state {skill_trust_state}")
    elif (
        task.allowed_skill_trust_states
        and skill_trust_state
        and not _contains_ci(task.allowed_skill_trust_states, skill_trust_state)
    ):
        reasons.append(f"scope_defer:skill_trust_state {skill_trust_state}")
    if task.allowed_mcp_servers and mcp_server and not _contains_ci(task.allowed_mcp_servers, mcp_server):
        reasons.append(f"scope_defer:unknown_mcp_server {mcp_server}")
    if task.allowed_mcp_tools and mcp_tool and not _contains_ci(task.allowed_mcp_tools, mcp_tool):
        reasons.append(f"scope_defer:unknown_mcp_tool {mcp_tool}")
    if task.allowed_mcp_statuses and mcp_status and not _contains_ci(task.allowed_mcp_statuses, mcp_status):
        reasons.append(f"scope_defer:mcp_status {mcp_status}")
    if (
        task.allowed_mcp_trust_levels
        and mcp_trust_level
        and not _contains_ci(task.allowed_mcp_trust_levels, mcp_trust_level)
    ):
        reasons.append(f"scope_defer:mcp_trust_level {mcp_trust_level}")
    if task.allowed_path_prefixes:
        for path in paths:
            if not _match_path(task.allowed_path_prefixes, path):
                reasons.append(f"scope_defer:unknown_path {path}")
    if task.allowed_command_prefixes and command.strip():
        if not any(
            command.strip().lower().startswith(prefix.lower())
            for prefix in task.allowed_command_prefixes
        ):
            reasons.append("scope_defer:unknown_command")
    if _network_write_command_invoked(command):
        reasons.append("scope_defer:network_write")
    if (
        network_demand.demanded
        and not task.allowed_domains
        and "network" not in task.queued_categories
    ):
        reasons.append("scope_defer:network_unscoped")
    if task.queued_capabilities:
        for capability in capabilities:
            if _contains_ci(task.queued_capabilities, capability):
                reasons.append(f"scope_defer:queued_capability {capability}")
    if (
        tool_permission_group
        and _contains_ci(task.queued_tool_permission_groups, tool_permission_group)
    ):
        reasons.append(f"scope_defer:queued_tool_permission_group {tool_permission_group}")
    if (
        task.allowed_tool_permission_groups
        and tool_permission_group
        and not _contains_ci(task.allowed_tool_permission_groups, tool_permission_group)
    ):
        reasons.append(f"scope_defer:unknown_tool_permission_group {tool_permission_group}")
    if task.allowed_capabilities:
        for capability in capabilities:
            if not _contains_ci(task.allowed_capabilities, capability):
                reasons.append(f"scope_defer:unknown_capability {capability}")
    return list(dict.fromkeys(reasons))


def _network_scope_demand(
    *,
    event: CanonicalEvent,
    command: str,
    capabilities: Iterable[str],
    tool_permission_group: str | None,
    domains: Iterable[str],
) -> NetworkScopeDemand:
    effects = {str(capability) for capability in capabilities}
    if any(
        effect == prefix.rstrip(".") or effect.startswith(prefix)
        for effect in effects
        for prefix in _NETWORK_EFFECT_PREFIXES
    ):
        return NetworkScopeDemand(True, "effect")
    if tool_permission_group == "network":
        return NetworkScopeDemand(True, "tool_group")
    tool = str(event.tool_name or "").strip().lower()
    if tool in {"fetch", "http_request", "web_fetch", "browser", "email", "send_email"}:
        return NetworkScopeDemand(True, "tool_group")
    if _network_command_invoked(command):
        return NetworkScopeDemand(True, "command")
    if event.payload.get("url") and (tool_permission_group == "network" or tool in {"fetch", "http_request"}):
        return NetworkScopeDemand(True, "payload_url")
    if event.payload.get("url") or tuple(domains):
        return NetworkScopeDemand(False, "payload_url_content_only")
    return NetworkScopeDemand(False, "none")


def _network_write_command_invoked(command: str, *, depth: int = 0) -> bool:
    if depth > _MAX_SHELL_INLINE_DEPTH:
        return True
    for argv in _shell_command_argvs(command):
        inline_command = _shell_inline_command(argv)
        if inline_command and _network_write_command_invoked(inline_command, depth=depth + 1):
            return True
        effective = _shell_effective_argv(argv)
        head = effective[0].rsplit("/", 1)[-1].lower() if effective else ""
        if head not in _NETWORK_WRITE_COMMAND_NAMES:
            continue
        if any(arg in _NETWORK_WRITE_FLAGS for arg in effective[1:]):
            return True
        if head == "curl" and _curl_request_method_is_write(effective):
            return True
        if head in {"http", "httpie"} and any(arg.upper() in {"POST", "PUT", "PATCH"} for arg in argv[1:3]):
            return True
    return False


def _curl_request_method_is_write(argv: tuple[str, ...]) -> bool:
    index = 1
    while index < len(argv):
        arg = argv[index]
        if arg in {"-X", "--request"} and index + 1 < len(argv):
            if argv[index + 1].upper() in {"POST", "PUT", "PATCH", "DELETE"}:
                return True
            index += 2
            continue
        if arg.startswith("--request="):
            method = arg.split("=", 1)[1].strip().upper()
            if method in {"POST", "PUT", "PATCH", "DELETE"}:
                return True
        index += 1
    return False


def _network_command_invoked(command: str, *, depth: int = 0) -> bool:
    if depth > _MAX_SHELL_INLINE_DEPTH:
        return True
    for argv in _shell_command_argvs(command):
        inline_command = _shell_inline_command(argv)
        if inline_command and _network_command_invoked(inline_command, depth=depth + 1):
            return True
        head = _shell_command_head(argv)
        if head in _NETWORK_COMMAND_NAMES:
            return True
        package_args = _shell_package_command_args(argv)
        if package_args is not None:
            if _package_install_subcommand_present(package_args):
                return True
    return False


def _shell_command_argvs(command: str) -> tuple[tuple[str, ...], ...]:
    argvs: list[tuple[str, ...]] = []
    for segment in re.split(r"(?:&&|\|\||;|\n|\|)", command or ""):
        segment = segment.strip()
        if not segment:
            continue
        try:
            tokens = tuple(shlex.split(segment, posix=True))
        except ValueError:
            continue
        if tokens:
            argvs.append(tokens)
    return tuple(argvs)


def _shell_command_head(argv: tuple[str, ...]) -> str:
    effective = _shell_effective_argv(argv)
    if not effective:
        return ""
    return effective[0].rsplit("/", 1)[-1].lower()


def _shell_effective_argv(argv: tuple[str, ...]) -> tuple[str, ...]:
    index = 0
    wrappers = {"sudo", "command", "nohup", "time"}
    while index < len(argv):
        token = argv[index]
        if not token:
            index += 1
            continue
        head = token.rsplit("/", 1)[-1].lower()
        if head in wrappers or "=" in token and not token.startswith("-") and token.split("=", 1)[0].isidentifier():
            index += 1
            continue
        if head == "env":
            index += 1
            while index < len(argv):
                env_token = argv[index]
                if env_token in {"-i", "-0"}:
                    index += 1
                    continue
                if env_token == "-u":
                    index += 2
                    continue
                if env_token.startswith("-"):
                    index += 1
                    continue
                if "=" in env_token and env_token.split("=", 1)[0].isidentifier():
                    index += 1
                    continue
                break
            continue
        return argv[index:]
    return ()


def _shell_inline_command(argv: tuple[str, ...]) -> str | None:
    effective = _shell_effective_argv(argv)
    if not effective:
        return None
    head = effective[0].rsplit("/", 1)[-1].lower()
    if head not in _SHELL_INLINE_COMMAND_INTERPRETERS:
        return None
    for index, token in enumerate(effective[1:], start=1):
        if token == "--":
            break
        if token == "-c" or (token.startswith("-") and "c" in token):
            if index + 1 < len(effective):
                return effective[index + 1]
            return None
    return None


def _shell_package_command_args(argv: tuple[str, ...]) -> tuple[str, ...] | None:
    effective = _shell_effective_argv(argv)
    if not effective:
        return None
    head = effective[0].rsplit("/", 1)[-1].lower()
    if head in _PACKAGE_COMMAND_NAMES:
        return effective[1:]
    if _python_module_invokes_pip(effective):
        for index, token in enumerate(effective[:-1]):
            if token == "-m" and effective[index + 1].rsplit("/", 1)[-1].lower() in {"pip", "pip3"}:
                return effective[index + 2:]
    return None


def _python_module_invokes_pip(argv: tuple[str, ...]) -> bool:
    if not argv:
        return False
    head = argv[0].rsplit("/", 1)[-1].lower()
    if re.fullmatch(r"python(?:\d+(?:\.\d+)?)?", head) is None:
        return False
    return any(
        token == "-m" and argv[index + 1].rsplit("/", 1)[-1].lower() in {"pip", "pip3"}
        for index, token in enumerate(argv[:-1])
    )


def _package_install_subcommand_present(args: Iterable[str]) -> bool:
    arg_list = list(args)
    index = 0
    while index < len(arg_list):
        token = arg_list[index]
        if not token:
            index += 1
            continue
        if token == "--":
            index += 1
            continue
        if token.startswith("-"):
            if token in _PACKAGE_OPTION_VALUE_FLAGS and index + 1 < len(arg_list):
                index += 2
            else:
                index += 1
            continue
        return token.lower() in _PACKAGE_INSTALL_SUBCOMMANDS
    return False


def _contains_ci(values: Iterable[str], value: str) -> bool:
    needle = value.lower()
    return any(item.lower() == needle for item in values)


def _match_domain(patterns: Iterable[str], domain: str) -> str | None:
    domain = domain.lower()
    for pattern in patterns:
        candidate = pattern.lower().lstrip(".")
        if domain == candidate or domain.endswith("." + candidate):
            return pattern
    return None


def _match_path(patterns: Iterable[str], path: str) -> str | None:
    normalized = path.replace("\\", "/")
    expanded = normalized.replace("~", "/home/user", 1) if normalized.startswith("~") else normalized
    for pattern in patterns:
        pat = pattern.replace("\\", "/")
        pat_expanded = pat.replace("~", "/home/user", 1) if pat.startswith("~") else pat
        if normalized.startswith(pat) or expanded.startswith(pat_expanded) or pat in normalized:
            return pattern
    return None
