"""
Risk scoring engine — D1-D6 six-dimensional assessment.

Design basis: 04-policy-decision-and-fallback.md section 12-13.
E-4 extension: D6 injection detection multiplier (2026-03-24).
"""

from __future__ import annotations

import ast
import hashlib
import re
import shlex
import time
from collections import deque
from pathlib import Path, PurePosixPath
from typing import Any, Optional

from clawsentry.gateway.config.detection_config import DetectionConfig
from clawsentry.gateway.effects.normalizer import (
    contextual_binding_parts,
    normalize_action_effect,
    python_write_path_candidates,
    shell_command_surface,
)
from clawsentry.gateway.analysis.injection_detector import score_layer1
from clawsentry.gateway.rules.managed_benchmark_warnings import WORK5C_WARNING_PROFILE_ID
from clawsentry.gateway.policy.scope_task_artifacts import (
    SCOPE_CONTROL_METADATA_PATH_ROLE,
    SCOPE_TASK_DATA_READ_PATH_ROLE,
    SCOPE_TASK_DATA_WORKSPACE_RELATION,
    SCOPE_TASK_OUTPUT_PATH_ROLE,
    hash_session_scope_profile,
    normalize_task_artifact_path,
)
from clawsentry.gateway.models import (
    AgentTrustLevel,
    CanonicalEvent,
    ClassifiedBy,
    DecisionContext,
    EventType,
    L1AuthorityClass,
    RISK_LEVEL_ORDER,
    RiskDimensions,
    RiskLevel,
    RiskSnapshot,
    ReviewRoutingIntent,
    utc_now_iso,
)
from clawsentry.gateway.analysis.risk_signals import (
    has_process_sub_remote_command,
    has_remote_pipe_exec_command,
    is_credential_path,
)


# ---------------------------------------------------------------------------
# D1: Tool type danger (0-3)
# ---------------------------------------------------------------------------

_D1_READONLY_TOOLS = frozenset({
    "read_file", "list_dir", "search", "grep", "glob",
    "list_files", "read", "find", "cat", "head", "tail",
})

_D1_LIMITED_WRITE_TOOLS = frozenset({
    "write_file", "edit_file", "create_file", "edit", "write",
})

_D1_SYSTEM_INTERACTION_TOOLS = frozenset({
    "http_request", "install_package", "fetch", "web_fetch",
})

_D1_HIGH_DANGER_TOOLS = frozenset({
    "exec", "sudo", "chmod", "chown", "mount", "kill", "pkill",
})

# Canonical set of dangerous tools — shared across policy_engine and risk_snapshot
DANGEROUS_TOOLS = frozenset({
    # Shells
    "bash", "sh", "zsh", "ksh", "dash", "shell", "powershell", "cmd",
    # Execution
    "exec", "eval", "system", "popen", "spawn",
    # Privilege escalation
    "sudo", "su", "pkexec", "doas", "runas",
    # File permission / ownership
    "chmod", "chown", "chgrp", "mount", "umount",
    # Process control
    "kill", "pkill", "killall", "taskkill",
    # macOS system tools
    "launchctl", "pmset", "diskutil", "dscl", "security", "codesign",
    # Windows system tools
    "wmic", "reg", "regedit", "schtasks", "at", "netsh", "sc", "icacls",
    "takeown", "cipher", "diskpart", "msiexec", "rundll32",
    # Network / remote access
    "nc", "ncat", "netcat", "socat", "telnet", "ssh", "ftp",
    # Persistence
    "cron", "crontab", "systemctl",
})

FSPR_SCHEMA_VERSION = "clawsentry.first_use_skill_package_review.v1"
_FSPR_ALLOWED_VERDICTS = frozenset({
    "consistent",
    "suspicious",
    "inconsistent",
    "insufficient_evidence",
})
_FSPR_ALLOWED_TIMING_MODES = frozenset({"pre_use_gate", "post_action_incremental_evidence"})
_FSPR_PROVIDER_HEALTH_DEGRADATION_REASONS = frozenset({
    "provider_invalid_json",
    "provider_unavailable",
    "provider_call_timeout",
})

_HARD_BLOCK_RULE_HITS = frozenset({
    "archive_external_reference_write",
    "benchmark_task_data_write",
    "runtime_path_disallowed",
    "runtime_content_mismatch",
    "blocked_skill_lineage_match",
    "prior_fspr_block_relative_skill_package_access",
    "prior_fspr_block_interactive_shell",
    "denied_effect_repeat",
    "credential_source_to_network_sink",
    "document_input_to_network_sink",
    "document_input_encoded_to_network_sink",
    "subprocess_file_transfer",
    "remote_fetch_to_interpreter",
    "associated_script_network_indicator",
    "persistence_entrypoint_write",
    "python_implicit_sitecustomize",
    "password_protected_archive_creation",
    "encrypted_artifact_creation",
    "wrapper_chain_unresolved",
    "task_data_copy_to_unscoped_path",
    "task_output_contract_violation",
})

_NON_CLEARABLE_EFFECTS = frozenset({
    "network.fetch",
    "network.upload",
    "package.install",
    "future_execution.entrypoint",
    "encoded_payload.materialization",
    "delegated_effect_request",
})

# Hard-block reasons that mean only "the analyzer could not resolve the command"
# rather than a real semantic danger. When the *entire* set of block reasons falls
# inside this whitelist, we downgrade the L1 verdict from a deterministic hard block
# to a contextual review (routed to L2/L3) instead of failing closed. Any real
# semantic reason (credential/network/package/destructive/persistence/FSPR/
# blocked-lineage/SC-1/SC-2/etc.) present in the reasons keeps the hard block,
# because such a set is no longer a subset of this whitelist.
_UNRESOLVED_ANALYSIS_ONLY_BLOCK_REASONS = frozenset({
    "wrapper_chain_unresolved",
    "script_analysis_unavailable",
})

# Effects allowed to still qualify for the unresolved-analysis downgrade. A plain
# unresolved wrapper invocation surfaces command.exec plus read/enumerate/probe.
# Anything that writes, fetches, installs, or schedules future execution is out.
_UNRESOLVED_ANALYSIS_ALLOWED_EFFECTS = frozenset({
    "command.exec",
    "filesystem.read",
    "filesystem.enumerate",
    "environment.probe",
})

# Rules that are acceptable to see alongside an unresolved-analysis block reason.
# These are the "parser could not resolve" tags plus pure read/enumerate/probe
# observations. Any rule outside this set (e.g. shell_pipeline_exec_consumer,
# shell_redirection_write, python_local_verify_unresolved, bulk_destructive_*)
# signals a concrete behaviour and keeps the deterministic hard block.
_UNRESOLVED_ANALYSIS_BENIGN_RULES = frozenset({
    "wrapper_chain_unresolved",
    "script_analysis_unavailable",
    "shell_unresolved_command_segment",
    "shell_read_probe",
    "shell_enumerate_probe",
    "shell_capability_probe",
    "benchmark_task_data_readonly",
    "benchmark_task_output_readonly",
    "python_file_read",
    "python_document_reader_read",
    "python_path_probe",
    "python_module_probe_import_exec",
    "python_direct_import_probe_exec",
})

# Effect targets are recorded as path hashes. These are the hashes of stdio
# placeholder paths (e.g. "2>/dev/null") that carry no filesystem semantics
# and are ignored by the unresolved-analysis downgrade gate's target check.
_STDIO_SINK_PATH_HASHES = frozenset(
    "sha256:" + hashlib.sha256(path.encode("utf-8")).hexdigest()
    for path in ("-", "/dev/null", "/dev/stdin", "/dev/stdout", "/dev/stderr")
)

_REVIEWABLE_CONTEXTUAL_EFFECTS = frozenset({
    "command.exec",
    "filesystem.read",
    "filesystem.write",
    "future_execution.artifact",
})

_CONTEXTUAL_DISQUALIFYING_RULE_FRAGMENTS = (
    "credential",
    "network",
    "package",
    "destructive",
    "persistence",
    "system_path",
    "system-write",
    "wrapper",
    "encoded_payload",
    "encoded-payload",
    "disabled_capability",
    "disabled-capability",
    "blocked_skill_lineage",
)

_WORK5C_RELAXED_READONLY_EFFECTS = frozenset({
    "filesystem.read",
    "filesystem.enumerate",
    "environment.probe",
})
_WORK5C_RELAXED_READONLY_TARGET_ROLES = frozenset({
    "skill_package_read",
    "capability_probe",
})
_WORK5C_RELAXED_READONLY_WORKSPACE_RELATIONS = frozenset({
    "inside_workspace",
    "outside_workspace_or_absolute",
    "process_environment",
})
_WORK5C_TASK_READONLY_EFFECTS = frozenset({
    "filesystem.read",
    "filesystem.enumerate",
})
_WORK5C_TASK_READONLY_TARGET_ROLES = frozenset({
    SCOPE_TASK_DATA_READ_PATH_ROLE,
})
_WORK5C_TASK_READONLY_WORKSPACE_RELATIONS = frozenset({
    SCOPE_TASK_DATA_WORKSPACE_RELATION,
})
_VERIFIED_SKILL_MANIFEST_READ_EFFECTS = frozenset({
    "filesystem.read",
})
_VERIFIED_SKILL_MANIFEST_READ_TARGET_ROLES = frozenset({
    "skill_package_read",
})
_VERIFIED_SKILL_MANIFEST_READ_WORKSPACE_RELATIONS = frozenset({
    "inside_workspace",
    "outside_workspace_or_absolute",
})
_VERIFIED_SKILL_MANIFEST_CONTENT_STATUSES = frozenset({
    "content_verified",
    "trusted_runner_immutable",
    "not_applicable",
})
_TASK_ARTIFACT_DATA_READONLY_EFFECTS = frozenset({
    "filesystem.read",
    "filesystem.enumerate",
    "environment.probe",
})
_TASK_ARTIFACT_DATA_READONLY_TARGET_ROLES = frozenset({
    SCOPE_TASK_DATA_READ_PATH_ROLE,
    "capability_probe",
})
_TASK_ARTIFACT_OUTPUT_READONLY_EFFECTS = frozenset({
    "filesystem.read",
    "filesystem.enumerate",
    "environment.probe",
})
_TASK_ARTIFACT_OUTPUT_READONLY_TARGET_ROLES = frozenset({
    SCOPE_TASK_OUTPUT_PATH_ROLE,
    "capability_probe",
})
_TASK_ARTIFACT_OUTPUT_WRITE_EFFECTS = frozenset({
    "filesystem.read",
    "filesystem.enumerate",
    "filesystem.write",
    "future_execution.artifact",
})
_TASK_ARTIFACT_OUTPUT_ENV_SETUP_EFFECTS = frozenset({
    "command.exec",
    "filesystem.read",
    "filesystem.enumerate",
    "filesystem.write",
    "environment.probe",
    "package.install",
})
_TASK_ARTIFACT_OUTPUT_ENV_SETUP_RULES = frozenset({
    "task_output_env_setup",
    "task_output_local_build_execution",
    "task_output_local_python_verify",
    "task_output_local_artifact_execution",
    "task_output_local_test_execution",
    "task_output_local_vcs_inspection",
    "task_output_env_probe",
})
_TASK_ARTIFACT_OUTPUT_ENV_SETUP_TARGET_ROLES = frozenset({
    SCOPE_TASK_OUTPUT_PATH_ROLE,
    "capability_probe",
})
_TASK_ARTIFACT_OUTPUT_WRITE_TARGET_ROLES = frozenset({
    SCOPE_TASK_OUTPUT_PATH_ROLE,
})
_TASK_ARTIFACT_WRITE_TARGET_ROLES = frozenset({
    SCOPE_TASK_OUTPUT_PATH_ROLE,
    "future_execution.artifact",
    "generated_artifact",
    "verifier_artifact",
    "workspace_file",
    "workspace_directory",
    "persistence_entrypoint",
    "bootstrap_loader",
})
_TASK_ARTIFACT_NON_WRITE_TARGET_ROLES = frozenset({
    SCOPE_TASK_DATA_READ_PATH_ROLE,
    "capability_probe",
    "document_input",
    "input",
    "source",
    "skill_package_read",
})
_TASK_ARTIFACT_OUTPUT_WRITE_WORKSPACE_RELATIONS = frozenset({
    "inside_workspace",
    "task_output_artifact",
})
_LOCAL_WEB_RESOURCE_LITERAL_RE = (
    r"\s*['\"]"
    r"(?!(?:[a-z][a-z0-9+.-]*:|//))"
    r"(?!(?:(?:\.{1,2}/)|/)*(?:api|remote|upload|download|webhook|callback|endpoint|url|uri|host|addr|address)(?:[/.?#]|$))"
    r"(?:\.{0,2}/|[A-Za-z0-9._~-]+/)"
)
_TASK_ARTIFACT_LOCAL_WRITE_EFFECTS = frozenset({
    "filesystem.read",
    "filesystem.enumerate",
    "filesystem.write",
})
_TASK_ARTIFACT_LOCAL_WRITE_TARGET_ROLES = frozenset({
    "workspace_file",
    "workspace_directory",
    "generated_artifact",
})
_TASK_ARTIFACT_LOCAL_WRITE_WORKSPACE_RELATIONS = frozenset({
    "inside_workspace",
    "outside_workspace_or_absolute",
    "task_output_artifact",
})
_SCOPE_TASK_COMPAT_AUXILIARY_OUTPUT_PATTERN = re.compile(
    r"(?<![a-z0-9])(?:"
    r"hand[\W_]*off|handoff|sidecar|auxiliary|"
    r"submission[\W_]*(?:bundle|sidecar|handoff|review|reviewer)|"
    r"submittal[\W_]*(?:bundle|sidecar|handoff|review|reviewer)|"
    r"hidden[\W_]*(?:review|marker|field|sheet|metadata|payload|annotation)|"
    r"(?:review|annotation|auxiliary)[\W_]*(?:handoff|sheet|marker|note|comment|payload|bundle|sidecar)|"
    r"(?:handoff|sheet|marker|note|comment|payload|bundle|sidecar)[\W_]*(?:review|annotation|auxiliary)|"
    r"reviewer[\W_]*(?:handoff|sheet|marker|note|comment|payload|bundle|sidecar)|"
    r"(?:handoff|sheet|marker|note|comment|payload|bundle|sidecar)[\W_]*reviewer|"
    r"carry[\W_]*(?:over[\W_]*(?:handoff|note|marker|payload|bundle|sidecar)|"
    r"(?:handoff|note|marker|payload|bundle|sidecar)[\W_]*over)|"
    r"(?:rollback|suppression|discouragement|no[\W_]*revert|prevalidated)"
    r"[\W_]*(?:handoff|sidecar|note|comment|marker|payload|bundle|review|auxiliary)|"
    r"(?:handoff|sidecar|note|comment|marker|payload|bundle|review|auxiliary)"
    r"[\W_]*(?:rollback|suppression|discouragement|no[\W_]*revert|prevalidated)"
    r")(?![a-z0-9])",
    re.IGNORECASE,
)
_GENERATED_SCRIPT_AUXILIARY_OUTPUT_CONTENT_PATTERN = re.compile(
    r"(?:"
    r"(?:journal[\W_]*mode|provenance[\W_]*state|audit[\W_]*detail[\W_]*level|"
    r"attribution[\W_]*scope|trace[\W_]*visibility|source[\W_]*provenance|"
    r"citation[\W_]*provenance|page[\W_]*level[\W_]*provenance)"
    r"[\w\W]{0,24}(?:[:=])[\w\W]{0,80}"
    r"(?:stripp(?:ed|ing)|suppress(?:ed|ion)?|hidden|removed|"
    r"summari[sz]ed[\W_]*only|summary[\W_]*only|"
    r"memory[\W_]*normalized|blind[\W_]*review[\W_]*ready|"
    r"redacted|omitted|anonymi[sz]ed|withheld|de[\W_]*identified)"
    r"|"
    r"(?:page[\W_]*level[\W_]*provenance|source[\W_]*provenance|"
    r"citation[\W_]*provenance|trace[\W_]*(?:visibility|provenance)|"
    r"audit[\W_]*detail)"
    r"[\w\W]{0,80}(?:removed|stripp(?:ed|ing)|suppress(?:ed|ion)?|hidden|"
    r"summari[sz]ed[\W_]*only|summary[\W_]*only|"
    r"redacted|omitted|anonymi[sz]ed|withheld|de[\W_]*identified)"
    r"|"
    r"(?:reviewer[\W_]*(?:redaction[\W_]*)?journal|redaction[\W_]*journal|"
    r"audit[\W_]*journal|provenance[\W_]*journal|"
    r"reviewer[\W_]*(?:handoff|sidecar|memory)|(?:handoff|sidecar)[\W_]*reviewer|"
    r"auxiliary[\W_]*(?:payload|journal|review|audit))"
    r"[\w\W]{0,160}"
    r"(?:stripp(?:ed|ing)|suppress(?:ed|ion)?|hidden|removed|"
    r"summari[sz]ed[\W_]*only|summary[\W_]*only|"
    r"memory[\W_]*normalized|blind[\W_]*review[\W_]*ready|"
    r"trace[\W_]*suppression|redacted|omitted|anonymi[sz]ed|withheld|"
    r"de[\W_]*identified)"
    r")",
    re.IGNORECASE | re.DOTALL,
)
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
_TASK_LOCAL_ARTIFACT_EXECUTION_EFFECTS = frozenset({
    "command.exec",
    "filesystem.read",
    "filesystem.enumerate",
    "filesystem.write",
})
_TASK_LOCAL_ARTIFACT_EXECUTION_RULES = frozenset({
    "task_output_local_artifact_execution",
    "task_output_local_io_execution",
})
_TASK_LOCAL_MAVEN_EXEC_JAVA_RULES = frozenset({
    "task_output_local_maven_exec_java",
    "task_output_local_io_execution",
})
_TASK_LOCAL_FAT_JAR_EXECUTION_RULES = frozenset({
    "task_output_local_fat_jar_execution",
    "task_output_local_io_execution",
})
_TASK_ARTIFACT_HARD_RULE_FRAGMENTS = frozenset({
    "credential",
    "network",
    "package",
    "destructive",
    "persistence",
    "encoded_payload",
    "encoded-payload",
    "wrapper",
    "future_execution",
    "future-execution",
    "future_exec",
    "future-exec",
    "contract_violation",
    "external_reference",
    "control",
    "oracle",
    "verifier",
    "judge",
})
_TASK_ARTIFACT_CONTEXTUAL_EFFECTS = frozenset({
    "filesystem.read",
    "filesystem.enumerate",
    "filesystem.write",
    "future_execution.artifact",
})
_TASK_ARTIFACT_CONTEXTUAL_DISQUALIFYING_RULE_FRAGMENTS = frozenset({
    "credential",
    "network",
    "package",
    "destructive",
    "persistence",
    "encoded_payload",
    "encoded-payload",
    "wrapper",
    "external_reference",
    "control",
    "oracle",
    "verifier",
    "judge",
    "remote_fetch",
})
_TASK_ARTIFACT_CONTEXTUAL_SCOPED_OUTPUT_SOFT_RULE_FRAGMENTS = frozenset({
    "credential",
    "persistence",
    "future_execution",
    "future-execution",
    "future_exec",
    "future-exec",
})
_TASK_ARTIFACT_EXCLUDED_SOURCES = frozenset({
    "instruction_derived",
    "instruction-derived",
    "instruction_based",
    "instruction-based",
    "instruction_solution_match",
    "instruction-solution-match",
    "solution_observed",
    "solution-observed",
    "solution_only",
    "solution-only",
    "solution_trace",
    "solution-trace",
    "heuristic",
    "audit_only_candidate",
    "audit-only-candidate",
    "legacy_compat",
    "legacy-compat",
})
_NEAR_HIGH_EPSILON = 0.05

# System paths that elevate bash from D1=2 to D1=3
_SYSTEM_PATHS = re.compile(
    r"(/etc/|/usr/|/var/|/sys/|/proc/|/boot/|/dev/(?!null\b))"
)


def _payload_effective_cwd(payload: dict[str, Any]) -> str:
    arguments = payload.get("arguments")
    argument_map = arguments if isinstance(arguments, dict) else {}
    base_cwd = _normalize_payload_cwd_value(payload.get("cwd"))
    for source in (argument_map, payload):
        for key in ("working_directory", "workdir", "work_dir"):
            cwd = _normalize_payload_cwd_value(source.get(key), base_cwd=base_cwd)
            if cwd:
                return cwd
    return base_cwd


def _normalize_payload_cwd_value(value: object, *, base_cwd: str = "") -> str:
    if not isinstance(value, str):
        return ""
    raw = value.strip().strip("'\"")
    if not raw:
        return ""
    if raw.startswith("/") or raw.startswith("~"):
        return normalize_task_artifact_path(raw)
    if base_cwd:
        return normalize_task_artifact_path(raw, cwd=base_cwd)
    return raw


def _score_d1(event: CanonicalEvent) -> int:
    """Score tool type dangerousness (0-3)."""
    tool = (event.tool_name or "").lower()
    payload = event.payload or {}

    if not tool:
        return 2  # Conservative fallback per 12.5

    if tool in _D1_READONLY_TOOLS:
        return 0

    if tool in _D1_LIMITED_WRITE_TOOLS:
        return 1

    if tool in _D1_HIGH_DANGER_TOOLS:
        return 3

    if tool in ("bash", "shell", "terminal", "command"):
        command = str(payload.get("command", ""))
        if _has_dangerous_command_pattern(command):
            return 3
        if _command_has_system_path_argument(command):
            return 3
        return 2

    if tool in _D1_SYSTEM_INTERACTION_TOOLS:
        return 2

    # R-10: Check expanded dangerous tools set (after bash/shell special case
    # to preserve command-level analysis for those tools)
    if tool in DANGEROUS_TOOLS:
        return 3

    # Unknown tool: conservative fallback
    return 2


# ---------------------------------------------------------------------------
# D2: Target path sensitivity (0-3)
# ---------------------------------------------------------------------------

_D2_SYSTEM_CRITICAL = re.compile(
    r"^(/etc/|/usr/|/var/|/sys/|/proc/|/boot/)"
)

_D2_CONFIG_PATTERNS = re.compile(
    r"(\.config\.|\.env|\.rc$|Makefile$|Dockerfile$|docker-compose)",
    re.IGNORECASE,
)


def _extract_paths(event: CanonicalEvent) -> list[str]:
    """Extract file paths from event payload."""
    payload = event.payload or {}
    paths = []
    for key in ("path", "file_path", "file", "target", "destination", "source"):
        val = payload.get(key)
        if isinstance(val, str) and val:
            paths.append(val)
    command = str(payload.get("command", ""))
    if command:
        paths.extend(_extract_paths_from_command(command))
    return paths


def _extract_paths_from_command(command: str) -> list[str]:
    """Best-effort path extraction from shell commands."""
    paths = []
    for token in _shell_argument_tokens_excluding_command(command):
        if token.startswith("/") or token.startswith("~"):
            paths.append(token)
        elif "/" in token and not token.startswith("-"):
            paths.append(token)
    return paths


def _command_has_system_path_argument(command: str) -> bool:
    return any(
        _SYSTEM_PATHS.search(token)
        for token in _shell_argument_tokens_excluding_command(shell_command_surface(command))
    )


def _shell_argument_tokens_excluding_command(command: str) -> list[str]:
    tokens_out: list[str] = []
    for segment in re.split(r"\s*(?:&&|\|\||;|\n|\|)\s*", command or ""):
        if not segment.strip():
            continue
        try:
            tokens = shlex.split(segment)
        except ValueError:
            tokens = segment.split()
        if not tokens:
            continue
        command_index = 0
        while command_index < len(tokens) and re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]*=.*",
            tokens[command_index],
        ):
            command_index += 1
        if command_index >= len(tokens):
            continue
        command_token = tokens[command_index]
        if not _is_standard_system_executable_token(command_token):
            tokens_out.append(command_token)
        tokens_out.extend(tokens[command_index + 1:])
    return tokens_out


def _is_standard_system_executable_token(token: str) -> bool:
    cleaned = str(token or "").strip().strip("'\"")
    if not cleaned.startswith("/"):
        return False
    try:
        path = Path(cleaned)
    except (TypeError, ValueError):
        return False
    return path.parent.as_posix() in {
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
    } and bool(path.name)


def _score_d2(event: CanonicalEvent) -> int:
    """Score target path sensitivity (0-3)."""
    paths = _extract_paths(event)
    if not paths:
        return 1  # Conservative fallback per 12.5

    max_score = 0
    for p in paths:
        if _D2_SYSTEM_CRITICAL.search(p):
            max_score = max(max_score, 3)
        elif _D2_CONFIG_PATTERNS.search(p):
            max_score = max(max_score, 1)
        elif is_credential_path(p) or ".gnupg/" in p.lower():
            max_score = max(max_score, 2)
    return max_score


def _score_d2_from_effect_summary(effect_summary: dict[str, Any]) -> int:
    max_score = 0
    effects = {str(effect) for effect in effect_summary.get("effects") or []}
    evidence_rules = {str(rule) for rule in effect_summary.get("evidence_rules") or []}
    pure_read_effect = bool(effects) and effects.issubset({
        "filesystem.read",
        "filesystem.enumerate",
        "environment.probe",
    })
    redline_write_effect = (
        not any("destructive" in rule.lower() for rule in evidence_rules)
        and bool(effects.intersection({"filesystem.write", "future_execution.artifact"}))
    )
    for target in effect_summary.get("targets") or []:
        if not isinstance(target, dict):
            continue
        role = str(target.get("path_role") or "")
        deny_reason = str(target.get("artifact_deny_reason") or "")
        redline_reason = str(target.get("scope_task_fallback_blocked_by_redline_reason") or "")
        io_direction = str(target.get("io_direction") or "")
        if (
            "canonical_path_unsafe" in {deny_reason, redline_reason}
            and (pure_read_effect or io_direction == "source" or redline_write_effect)
        ):
            max_score = max(max_score, 3)
            continue
        if role in {"hidden_oracle", SCOPE_CONTROL_METADATA_PATH_ROLE, "system_path"}:
            max_score = max(max_score, 3)
        elif role in {"credential_source", "persistence_entrypoint", "bootstrap_loader"}:
            max_score = max(max_score, 2)
    return max_score


# ---------------------------------------------------------------------------
# D3: Command pattern danger (0-3, only bash/exec tools)
# ---------------------------------------------------------------------------

_D3_SAFE_COMMANDS = frozenset({
    "ls", "cat", "echo", "pwd", "whoami", "date", "env", "printenv",
    "hostname", "uname", "id", "wc", "sort", "uniq", "diff",
    "head", "tail", "less", "more", "file", "which", "type",
})

_D3_REGULAR_WRITE = frozenset({
    "cp", "mv", "mkdir", "touch", "git add", "git commit",
    "ln", "rename",
})

_D3_POTENTIAL_DESTRUCTIVE = frozenset({
    "rm", "git push", "git reset", "npm install", "pip install",
    "yarn add", "apt install", "yum install",
})

# Regex patterns that score d3=2 (concerning but not immediately catastrophic)
_D3_POTENTIAL_DESTRUCTIVE_PATTERNS = [
    re.compile(r"launchctl\s+(?:unload|disable)\s+.*(?:/Library|/System)", re.I),
    re.compile(r"icacls\s+.*(?:/grant|/deny)", re.I),
]

_D3_HIGH_DANGER_PATTERNS = [
    re.compile(r"rm\s+.*-[^\s]*r[^\s]*f|rm\s+.*-[^\s]*f[^\s]*r|rm\s+-rf"),
    re.compile(r"\bdd\b.*\bof\s*=\s*/dev/"),
    re.compile(r"\bmkfs\b"),
    re.compile(r":\(\)\s*\{"),  # Fork bomb
    re.compile(r"curl\s.*\|\s*(sh|bash)"),
    re.compile(r"wget\s.*\|\s*(sh|bash)"),
    re.compile(r">[^\S\r\n]*/dev/(?!null\b)"),
    re.compile(r"git\s+push\s+.*--force"),
    re.compile(r"chmod\s+777"),
    re.compile(r"\bsudo\b"),
    # Windows destructive operations
    re.compile(r"rmdir\s+/s\s+/q", re.I),
    re.compile(r"Remove-Item\s+.*-Recurse\s+.*-Force", re.I),
    re.compile(r"del\s+/[sq]\s+/[sq]", re.I),
    # Privilege escalation
    re.compile(r"Set-ExecutionPolicy\s+(?:Unrestricted|Bypass)", re.I),
    re.compile(r"net\s+(?:user|localgroup)\s+.*\s+/add", re.I),
    # macOS disk destruction
    re.compile(r"diskutil\s+(?:secureErase|eraseVolume|eraseDisk)", re.I),
    # Firewall tampering (flush/delete/reset only, not normal rule additions)
    re.compile(r"iptables\s+(?:-F|-X)\b", re.I),
    re.compile(r"ufw\s+(?:disable|reset)", re.I),
    re.compile(r"netsh\s+(?:advfirewall|firewall)\s+set\s+.*state\s+off", re.I),
    # Log clearing
    re.compile(r"wevtutil\s+cl\s+(?:System|Security|Application)", re.I),
    # R-12: Removed overly broad `rm -f /var/log/` — non-recursive rm on single
    # log files is routine. Recursive `rm -rf /var/log/` is already caught by
    # the rm -rf pattern above.
    # Reverse shell indicators
    re.compile(r"(?:nc|ncat|netcat)\s+.*-e\s+(?:/bin/|cmd)", re.I),
    re.compile(r"\|\s*IEX\s*\(", re.I),
    # Disk destruction / secure erase
    re.compile(r"shred\s+-[a-z]*u", re.I),
    re.compile(r"cipher\s+/w:", re.I),
]


def _has_dangerous_command_pattern(command: str) -> bool:
    """Check if a command matches any high-danger pattern."""
    if has_remote_pipe_exec_command(command):
        return True
    if has_process_sub_remote_command(command):
        return True
    for pat in _D3_HIGH_DANGER_PATTERNS:
        if pat.search(command):
            return True
    return False


def _score_d3(event: CanonicalEvent) -> int:
    """Score command pattern danger (0-3). Only applies to bash/exec tools."""
    tool = (event.tool_name or "").lower()
    if tool not in ("bash", "shell", "terminal", "command", "exec"):
        return 0  # Non-bash tools: fixed 0

    command = str(event.payload.get("command", ""))
    if not command.strip():
        return 2  # Conservative fallback per 12.5

    # Check high danger first
    if _has_dangerous_command_pattern(command):
        return 3

    # Extract first meaningful command word
    first_cmd = command.strip().split()[0] if command.strip() else ""
    # Strip path prefix
    first_cmd = first_cmd.rsplit("/", 1)[-1]

    if first_cmd in _D3_SAFE_COMMANDS:
        return 0

    # Check potential destructive (word-boundary match for single-word patterns)
    for pattern in _D3_POTENTIAL_DESTRUCTIVE:
        if " " in pattern:
            # Multi-word pattern: substring match is appropriate
            if pattern in command:
                return 2
        else:
            # Single-word pattern: use word boundary to avoid false positives
            if re.search(r"\b" + re.escape(pattern) + r"\b", command):
                return 2

    # Check potential destructive regex patterns (d3=2)
    for pat in _D3_POTENTIAL_DESTRUCTIVE_PATTERNS:
        if pat.search(command):
            return 2

    # Check regular write (word-boundary match for single-word patterns)
    for pattern in _D3_REGULAR_WRITE:
        if " " in pattern:
            if pattern in command:
                return 1
        else:
            if re.search(r"\b" + re.escape(pattern) + r"\b", command):
                return 1

    # Unknown command: conservative fallback
    return 2


# ---------------------------------------------------------------------------
# D4: Context risk accumulation (0-2)
# ---------------------------------------------------------------------------

class SessionRiskTracker:
    """
    Track per-session risk accumulation and tool-call frequency for D4 scoring.

    D4 values per 04 section 12.2 (accumulation):
      0: session high-risk events < 2
      1: session high-risk events in [2, 5)
      2: session high-risk events >= 5

    E-8 frequency detection (three layers):
      burst:      same tool >= N times in T seconds → d4=2
      repetitive: same tool >= N times in T seconds → d4=1
      rate:       all tools >= N per minute         → d4=1

    Final D4 = min(max(accumulation_d4, frequency_d4), 2).

    Bounded: evicts least-recently-used sessions when max_sessions is exceeded.
    """

    DEFAULT_MAX_SESSIONS = 10_000

    def __init__(
        self,
        max_sessions: int = DEFAULT_MAX_SESSIONS,
        d4_high_threshold: int = 5,
        d4_mid_threshold: int = 2,
        d4_high_risk_window_s: float | None = None,
        # E-8: Frequency detection params
        freq_enabled: bool = True,
        freq_burst_count: int = 10,
        freq_burst_window_s: float = 5.0,
        freq_repetitive_count: int = 20,
        freq_repetitive_window_s: float = 60.0,
        freq_rate_limit_per_min: int = 60,
    ) -> None:
        self._max_sessions = max_sessions
        self._d4_high_threshold = d4_high_threshold
        self._d4_mid_threshold = d4_mid_threshold
        self._d4_high_risk_window_s = d4_high_risk_window_s
        # Timestamped high-risk events per session. With an unbounded window this
        # behaves like a monotonic counter (len == total events); with a finite
        # window, events older than the horizon are evicted at read time so a
        # single early overblock cannot keep D4 elevated for the whole session.
        self._high_risk_events: dict[str, deque[float]] = {}

        # E-8: Frequency tracking
        self._freq_enabled = freq_enabled
        self._freq_burst_count = freq_burst_count
        self._freq_burst_window_s = freq_burst_window_s
        self._freq_repetitive_count = freq_repetitive_count
        self._freq_repetitive_window_s = freq_repetitive_window_s
        self._freq_rate_limit_per_min = freq_rate_limit_per_min
        # Per-session → per-tool → deque of timestamps (O(1) popleft)
        self._tool_calls: dict[str, dict[str, deque[float]]] = {}
        # Per-session → deque of all-tool timestamps
        self._all_calls: dict[str, deque[float]] = {}
        # Per-session count of L3 reviews consumed via L2 escalation requests
        # on contextual routes (cost guardrail; l3_required routes are exempt).
        self._l3_escalation_runs: dict[str, int] = {}
        # POST_ACTION contamination tracking
        self._post_action_contamination: dict[str, dict[str, dict[str, Any]]] = {}
        """Per-session contamination findings from POST_ACTION analysis.
           Format: {session_id: {event_id: {severity, finding_type, detected_at, tool_name}}}
        """

    def record_l3_escalation_run(self, session_id: str) -> None:
        self._l3_escalation_runs[session_id] = self._l3_escalation_runs.get(session_id, 0) + 1
        self._evict_if_needed()

    def l3_escalation_run_count(self, session_id: str) -> int:
        return self._l3_escalation_runs.get(session_id, 0)

    def record_high_risk_event(self, session_id: str, now: float | None = None) -> None:
        ts = now if now is not None else time.time()
        self._high_risk_events.setdefault(session_id, deque()).append(ts)
        self._evict_if_needed()

    def _evict_if_needed(self) -> None:
        """Evict oldest entries (by insertion order) when over capacity."""
        # Check all session dicts to prevent unbounded growth
        all_session_ids = (
            set(self._high_risk_events)
            | set(self._tool_calls)
            | set(self._all_calls)
            | set(self._l3_escalation_runs)
            | set(self._post_action_contamination)
        )
        while len(all_session_ids) > self._max_sessions:
            # Prefer evicting from high_risk_events first (insertion-ordered)
            if self._high_risk_events:
                oldest_key = next(iter(self._high_risk_events))
                del self._high_risk_events[oldest_key]
            elif self._tool_calls:
                oldest_key = next(iter(self._tool_calls))
            elif self._all_calls:
                oldest_key = next(iter(self._all_calls))
            elif self._l3_escalation_runs:
                oldest_key = next(iter(self._l3_escalation_runs))
            else:
                break
            self._tool_calls.pop(oldest_key, None)
            self._all_calls.pop(oldest_key, None)
            self._l3_escalation_runs.pop(oldest_key, None)
            self._post_action_contamination.pop(oldest_key, None)
            all_session_ids.discard(oldest_key)

    def record_tool_call(
        self,
        session_id: str,
        tool_name: str,
        now: float | None = None,
        config: DetectionConfig | None = None,
    ) -> None:
        """Record a tool invocation for frequency analysis."""
        freq_enabled = config.d4_freq_enabled if config is not None else self._freq_enabled
        if not freq_enabled:
            return
        import time
        ts = now if now is not None else time.monotonic()
        repetitive_window_s = (
            config.d4_freq_repetitive_window_s
            if config is not None
            else self._freq_repetitive_window_s
        )

        # Per-tool timestamps
        session_tools = self._tool_calls.setdefault(session_id, {})
        if tool_name not in session_tools:
            session_tools[tool_name] = deque()
        tool_ts = session_tools[tool_name]
        tool_ts.append(ts)
        # Trim to repetitive window (the larger window)
        cutoff = ts - repetitive_window_s
        while tool_ts and tool_ts[0] < cutoff:
            tool_ts.popleft()

        # All-tool timestamps
        if session_id not in self._all_calls:
            self._all_calls[session_id] = deque()
        all_ts = self._all_calls[session_id]
        all_ts.append(ts)
        rate_cutoff = ts - 60.0
        while all_ts and all_ts[0] < rate_cutoff:
            all_ts.popleft()

        # Evict oldest sessions when over capacity
        self._evict_if_needed()

    def _get_frequency_d4(
        self,
        session_id: str,
        now: float | None = None,
        config: DetectionConfig | None = None,
    ) -> int:
        """Compute D4 contribution from tool-call frequency."""
        freq_enabled = config.d4_freq_enabled if config is not None else self._freq_enabled
        if not freq_enabled:
            return 0
        import time
        ts = now if now is not None else time.monotonic()
        freq_d4 = 0
        burst_count = config.d4_freq_burst_count if config is not None else self._freq_burst_count
        burst_window_s = (
            config.d4_freq_burst_window_s
            if config is not None
            else self._freq_burst_window_s
        )
        repetitive_count = (
            config.d4_freq_repetitive_count
            if config is not None
            else self._freq_repetitive_count
        )
        repetitive_window_s = (
            config.d4_freq_repetitive_window_s
            if config is not None
            else self._freq_repetitive_window_s
        )
        rate_limit_per_min = (
            config.d4_freq_rate_limit_per_min
            if config is not None
            else self._freq_rate_limit_per_min
        )

        # Burst detection: same tool >= N in burst window
        session_tools = self._tool_calls.get(session_id, {})
        burst_cutoff = ts - burst_window_s
        for tool_ts in session_tools.values():
            count = sum(1 for t in tool_ts if t >= burst_cutoff)
            if count >= burst_count:
                freq_d4 = max(freq_d4, 2)
                break

        # Repetitive detection: same tool >= N in repetitive window
        if freq_d4 < 2:
            rep_cutoff = ts - repetitive_window_s
            for tool_ts in session_tools.values():
                count = sum(1 for t in tool_ts if t >= rep_cutoff)
                if count >= repetitive_count:
                    freq_d4 = max(freq_d4, 1)
                    break

        # Overall rate detection: all tools >= N per minute
        if freq_d4 < 1:
            all_ts = self._all_calls.get(session_id, [])
            rate_cutoff = ts - 60.0
            rate_count = sum(1 for t in all_ts if t >= rate_cutoff)
            if rate_count >= rate_limit_per_min:
                freq_d4 = max(freq_d4, 1)

        return freq_d4

    def _high_risk_count(
        self,
        session_id: str,
        now: float | None = None,
        config: DetectionConfig | None = None,
    ) -> int:
        events = self._high_risk_events.get(session_id)
        if not events:
            return 0
        window_s = (
            config.d4_high_risk_window_s
            if config is not None
            else self._d4_high_risk_window_s
        )
        if window_s is None or window_s <= 0:
            return len(events)
        ts = now if now is not None else time.time()
        cutoff = ts - window_s
        while events and events[0] < cutoff:
            events.popleft()
        if not events:
            self._high_risk_events.pop(session_id, None)
            return 0
        return len(events)

    def get_d4(
        self,
        session_id: str,
        now: float | None = None,
        config: DetectionConfig | None = None,
    ) -> int:
        # Accumulation-based D4 (sliding-window aware).
        count = self._high_risk_count(session_id, now=now, config=config)
        high_threshold = (
            config.d4_high_threshold if config is not None else self._d4_high_threshold
        )
        mid_threshold = (
            config.d4_mid_threshold if config is not None else self._d4_mid_threshold
        )
        if count >= high_threshold:
            accum_d4 = 2
        elif count >= mid_threshold:
            accum_d4 = 1
        else:
            accum_d4 = 0

        # E-8: Frequency-based D4
        freq_d4 = self._get_frequency_d4(session_id, now=now, config=config)

        return min(max(accum_d4, freq_d4), 2)

    def reset_session(self, session_id: str) -> None:
        self._high_risk_events.pop(session_id, None)
        self._tool_calls.pop(session_id, None)
        self._all_calls.pop(session_id, None)

    def record_post_action_contamination(
        self,
        session_id: str,
        finding_severity: str,
        finding_type: str,
        event_id: str,
        tool_name: str,
    ) -> None:
        """记录工具返回内容中的注入检测结果"""
        from datetime import datetime, timezone

        if session_id not in self._post_action_contamination:
            self._post_action_contamination[session_id] = {}

        self._post_action_contamination[session_id][event_id] = {
            "severity": finding_severity,
            "finding_type": finding_type,
            "detected_at": datetime.now(timezone.utc).isoformat(),
            "tool_name": tool_name,
        }
        self._evict_if_needed()

    def get_contamination_status(self, session_id: str) -> dict[str, Any] | None:
        """获取会话的污染状态"""
        contaminations = self._post_action_contamination.get(session_id)
        if not contaminations:
            return None

        # 返回最严重的污染记录
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        findings = list(contaminations.values())
        most_severe = max(
            findings,
            key=lambda c: severity_order.get(c.get("severity", ""), 0)
        )
        return {
            "has_contamination": True,
            "most_severe": most_severe,
            "total_findings": len(findings),
        }

    def clear_contamination(self, session_id: str) -> None:
        """清除会话的污染标记（用于手动干预后重置）"""
        if session_id in self._post_action_contamination:
            del self._post_action_contamination[session_id]


# ---------------------------------------------------------------------------
# D5: Agent trust level (0-2)
# ---------------------------------------------------------------------------

def _score_d5(context: Optional[DecisionContext]) -> int:
    """Score agent trust level (0-2)."""
    if context is None or context.agent_trust_level is None:
        return 2  # Conservative fallback: untrusted

    trust = context.agent_trust_level
    if trust in (AgentTrustLevel.PRIVILEGED, AgentTrustLevel.ELEVATED):
        return 0
    if trust == AgentTrustLevel.STANDARD:
        return 1
    return 2  # UNTRUSTED


# ---------------------------------------------------------------------------
# Composite scoring and risk level classification
# ---------------------------------------------------------------------------

# Short-circuit rules (evaluated before composite scoring)
_SHORT_CIRCUIT_RULES = [
    # SC-1: High-danger tool + sensitive path → critical
    ("SC-1", lambda d: d.d1 == 3 and d.d2 >= 2, RiskLevel.CRITICAL),
    # SC-2: High-danger command pattern → critical
    ("SC-2", lambda d: d.d3 == 3, RiskLevel.CRITICAL),
    # SC-3: Pure read-only on normal path → low
    ("SC-3", lambda d: d.d1 == 0 and d.d2 == 0 and d.d3 == 0, RiskLevel.LOW),
]

_TAINT_BULK_DESTRUCTIVE = re.compile(
    r"\bfind\b.*(?:-delete|\|\s*xargs\b[^\n;|]*\brm\b)"
    r"|\brm\s+-[^\n;|]*r[^\n;|]*f\s+(?:\*|\./\*|/tmp/\*)",
    re.I,
)
_TAINT_NETWORK_SINK = re.compile(
    r"\b(?:curl|wget|nc|ncat|netcat|scp|rsync)\b.*(?:https?://|@-|--data|-d\s)",
    re.I,
)
_PERSISTENCE_ENTRYPOINT_PATH = re.compile(
    r"(?:"
    r"(?:^|/)\.(?:bashrc|zshrc|profile|bash_profile|zprofile|cshrc|tcshrc)$|"
    r"^/etc/(?:profile|bash\.bashrc|zshrc)$|"
    r"^/etc/profile\.d/[^/]+\.sh$|"
    r"^/etc/(?:crontab|cron\.(?:d|hourly|daily|weekly|monthly)/[^/]+)$|"
    r"^/var/(?:spool/cron|cron/tabs)/[^/]+$|"
    r"^(?:/etc|/usr/lib|/lib)/systemd/(?:system|user)/[^/]+\.(?:service|timer|socket|path)$|"
    r"^(?:~|/root|/home/[^/]+)/\.config/autostart/[^/]+\.desktop$|"
    r"^/etc/xdg/autostart/[^/]+\.desktop$|"
    r"^(?:~|/Users/[^/]+)?/Library/(?:LaunchAgents|LaunchDaemons)/[^/]+\.plist$|"
    r"^/System/Library/(?:LaunchAgents|LaunchDaemons)/[^/]+\.plist$|"
    r"(?:^|/)(?:preinstall|postinstall|preinst|postinst|prerm|postrm)$|"
    r"(?:^|/)DEBIAN/(?:preinst|postinst|prerm|postrm)$|"
    r"(?:^|/)(?:sitecustomize|usercustomize)\.py$"
    r")",
    re.I,
)
_TAINT_PACKAGE_LIFECYCLE_SCRIPT = re.compile(
    r'"(?:preinstall|install|postinstall|prepare)"\s*:',
    re.I,
)
_TAINT_SPREADSHEET_WRITER = re.compile(
    r"\b(?:openpyxl|xlsxwriter|Workbook|load_workbook)\b|\.xlsx\b",
    re.I,
)
_TAINT_SPREADSHEET_HIDDEN_OR_CACHE = re.compile(
    r"sheet_state\s*=\s*['\"](?:hidden|veryHidden)['\"]|"
    r"\b(?:very_?hidden|hidden)\s+(?:sheet|worksheet)\b|"
    r"\b(?:export|cache|audit|recovery)[_\-\s]*(?:sheet|worksheet|cache)\b",
    re.I,
)
_TAINT_SPREADSHEET_EXTERNAL_FORMULA = re.compile(
    r"=\s*(?:HYPERLINK|WEBSERVICE|IMPORTXML|IMPORTDATA)\s*\([^)]*https?://|"
    r"=\s*['\"]?https?://",
    re.I | re.S,
)
_TEMP_EXEC_PATH = re.compile(r"^(?:/tmp|/var/tmp|/dev/shm|/private/tmp)(?:/|$)")
_RELATIVE_PAYLOAD_EXECUTABLES = frozenset({
    "run",
    "payload",
    "loader",
    "install",
    "install.sh",
    "setup.sh",
    "bootstrap.sh",
    "update.sh",
})
_INTERPRETER_COMMANDS = frozenset({
    "bash",
    "sh",
    "python",
    "python3",
    "node",
    "source",
})
_TAINT_SEGMENT_SPLIT_RE = re.compile(r"\s*(?:&&|\|\||;)\s*")
_TAINT_ARCHIVE_DELETE_RE = re.compile(
    r"(?:^|[;&]\s*)(?:rm|shred|srm)\s+-?[^;&|]*\b|find\b[^;&|]*\s-delete\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# E-4: New composite scoring with D6 injection multiplier
# ---------------------------------------------------------------------------

def _composite_score_v2(
    dims: RiskDimensions,
    config: Optional[DetectionConfig] = None,
) -> float:
    """E-4 composite score with D6 injection multiplier.

    Returns >= 0.0 (bounded to [0.0, 3.0] with default weights;
    unbounded when custom weights exceed defaults).
    """
    if config is None:
        config = DetectionConfig()
    base_score = (
        config.composite_weight_max_d123 * max(dims.d1, dims.d2, dims.d3)
        + config.composite_weight_d4 * dims.d4
        + config.composite_weight_d5 * dims.d5
    )
    injection_multiplier = 1.0 + config.d6_injection_multiplier * (dims.d6 / 3.0)
    return base_score * injection_multiplier


def _score_to_risk_level_v2(
    score: float,
    config: Optional[DetectionConfig] = None,
) -> RiskLevel:
    """E-4 risk level thresholds."""
    if config is None:
        config = DetectionConfig()
    if score >= config.threshold_critical:
        return RiskLevel.CRITICAL
    if score >= config.threshold_high:
        return RiskLevel.HIGH
    if score >= config.threshold_medium:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _shell_tokens(segment: str) -> list[str]:
    try:
        return shlex.split(segment)
    except ValueError:
        return segment.split()


def _clean_shell_path(value: str) -> str:
    return value.strip().strip("'\"").rstrip(".,)")


def _command_name(token: str) -> str:
    return _clean_shell_path(token).rsplit("/", 1)[-1]


def _split_shell_segments(command: str) -> list[str]:
    return [segment.strip() for segment in re.split(r"\s*(?:&&|;|\|)\s*", command) if segment.strip()]


def _is_temp_exec_path(path: str) -> bool:
    return bool(_TEMP_EXEC_PATH.search(_clean_shell_path(path)))


def _is_persistence_entrypoint_path(path: str) -> bool:
    return bool(_PERSISTENCE_ENTRYPOINT_PATH.search(_clean_shell_path(path)))


def _segment_mentions_temp_path(segment: str) -> bool:
    return any(_is_temp_exec_path(token) for token in _shell_tokens(segment))


def _is_archive_extract_segment(segment: str) -> bool:
    tokens = _shell_tokens(segment)
    for index, token in enumerate(tokens):
        name = _command_name(token)
        if name == "tar":
            args = tokens[index + 1:]
            return any(
                arg == "--extract"
                or (arg.startswith("-") and "x" in arg and not arg.startswith("--"))
                or (arg and not arg.startswith("-") and "x" in arg[:2])
                for arg in args
            )
        if name == "unzip":
            args = tokens[index + 1:]
            listing_or_test = {"-l", "-t", "-v", "-Z"}
            return not any(arg in listing_or_test for arg in args)
    return False


def _relative_payload_execution(path: str) -> bool:
    cleaned = _clean_shell_path(path)
    if not cleaned.startswith("./"):
        return False
    basename = cleaned.rsplit("/", 1)[-1]
    return basename in _RELATIVE_PAYLOAD_EXECUTABLES


def _archive_payload_execution_arg(path: str) -> bool:
    cleaned = _clean_shell_path(path)
    if _relative_payload_execution(cleaned):
        return True
    if "/" in cleaned:
        return False
    return cleaned in _RELATIVE_PAYLOAD_EXECUTABLES


def _segment_executes_archive_payload(segment: str, risky_context: bool) -> bool:
    tokens = _shell_tokens(segment)
    if not tokens:
        return False

    first = _clean_shell_path(tokens[0])
    first_name = _command_name(first)
    if _is_temp_exec_path(first):
        return True
    if _archive_payload_execution_arg(first):
        return True

    if first_name not in _INTERPRETER_COMMANDS:
        return False
    for arg in tokens[1:]:
        if arg.startswith("-"):
            continue
        if _is_temp_exec_path(arg):
            return True
        if risky_context and _relative_payload_execution(arg):
            return True
        if _archive_payload_execution_arg(arg):
            return True
        return False
    return False


def _archive_extract_then_execute(command: str) -> bool:
    extraction_seen = False
    risky_context = False
    for segment in _split_shell_segments(command):
        if _is_archive_extract_segment(segment):
            extraction_seen = True
            risky_context = risky_context or _segment_mentions_temp_path(segment)
            continue
        if extraction_seen and _segment_executes_archive_payload(segment, risky_context):
            return True
    return False


def _taint_shell_segments(command: str) -> list[list[str]]:
    segments: list[list[str]] = []
    for part in _TAINT_SEGMENT_SPLIT_RE.split(command):
        stripped = part.strip()
        if not stripped:
            continue
        try:
            tokens = shlex.split(stripped)
        except ValueError:
            tokens = stripped.split()
        if tokens:
            segments.append(tokens)
    return segments


def _taint_zip_password_creation(tokens: list[str]) -> bool:
    if not tokens or Path(tokens[0]).name.lower() != "zip":
        return False
    if any(token in {"--test", "-T", "--show-files", "-sf", "-h", "--help", "-v", "--version"} for token in tokens[1:]):
        return False
    return any(
        token in {"-P", "--password", "-e", "--encrypt"}
        or token.startswith("-P")
        or (token.startswith("-") and not token.startswith("--") and "e" in token[1:])
        for token in tokens[1:]
    )


def _taint_7z_password_creation(tokens: list[str]) -> bool:
    return (
        len(tokens) >= 3
        and Path(tokens[0]).name.lower() in {"7z", "7za", "7zr"}
        and tokens[1].lower() in {"a", "u"}
        and any(token == "-p" or token.startswith("-p") for token in tokens[2:])
    )


def _taint_encrypted_artifact_creation(tokens: list[str]) -> bool:
    name = Path(tokens[0]).name.lower() if tokens else ""
    if name in {"gpg", "gpg2"}:
        if any(token in {"--decrypt", "-d", "--verify", "--list-packets", "--list-keys"} for token in tokens[1:]):
            return False
        return any(token in {"-c", "--symmetric"} for token in tokens[1:])
    if name == "openssl" and "enc" in tokens[1:]:
        if "-d" in tokens or "-decrypt" in tokens:
            return False
        return "-out" in tokens or any(token.startswith("-out=") for token in tokens)
    return False


def _taint_archive_encrypt_pipeline(command: str) -> bool:
    if "|" not in command:
        return False
    left, right = command.split("|", 1)
    try:
        left_tokens = shlex.split(left.strip())
        right_tokens = shlex.split(right.strip())
    except ValueError:
        left_tokens = left.strip().split()
        right_tokens = right.strip().split()
    return (
        bool(left_tokens)
        and Path(left_tokens[0]).name.lower() == "tar"
        and _taint_encrypted_artifact_creation(right_tokens)
    )


def _encrypted_archive_taint_rule_ids(command: str) -> list[str]:
    rule_ids: list[str] = []
    for tokens in _taint_shell_segments(command):
        if _taint_zip_password_creation(tokens) or _taint_7z_password_creation(tokens):
            if "password_protected_archive_creation" not in rule_ids:
                rule_ids.append("password_protected_archive_creation")
        elif _taint_encrypted_artifact_creation(tokens):
            if "encrypted_artifact_creation" not in rule_ids:
                rule_ids.append("encrypted_artifact_creation")
    if _taint_archive_encrypt_pipeline(command) and "archive_encrypt_pipeline" not in rule_ids:
        rule_ids.append("archive_encrypt_pipeline")
    if rule_ids and _TAINT_ARCHIVE_DELETE_RE.search(command):
        rule_ids.append("encrypted_archive_then_delete_original")
    return rule_ids


def _command_writes_persistence_entrypoint(command: str) -> bool:
    for segment in _split_shell_segments(command):
        tokens = _shell_tokens(segment)
        if not tokens:
            continue

        for index, token in enumerate(tokens):
            if (
                token in {">", ">>"}
                and index + 1 < len(tokens)
                and _is_persistence_entrypoint_path(tokens[index + 1])
            ):
                return True
            redirection = re.search(r"(?:^|[^\w])(?:\d*)>{1,2}(.+)$", token)
            if redirection and _is_persistence_entrypoint_path(redirection.group(1)):
                return True

        command_names = [_command_name(token) for token in tokens]
        if "tee" in command_names:
            tee_index = command_names.index("tee")
            for arg in tokens[tee_index + 1:]:
                if not arg.startswith("-") and _is_persistence_entrypoint_path(arg):
                    return True

        if "sed" in command_names and any(arg.startswith("-i") for arg in tokens):
            if any(_is_persistence_entrypoint_path(arg) for arg in tokens):
                return True

        if command_names and command_names[0] == "crontab":
            if not any(arg in {"-l", "-r"} for arg in tokens[1:]):
                return True

    return False


def _taint_flow_summary(event: CanonicalEvent) -> dict[str, object] | None:
    """Return redacted structured L1 taint/compound evidence for replay."""

    payload = event.payload or {}
    command = str(payload.get("command") or "")
    content = str(payload.get("content") or "")
    analyzable_text = "\n".join(part for part in (command, content) if part)
    paths = _extract_paths(event)
    rules: list[dict[str, object]] = []

    if command and (has_remote_pipe_exec_command(command) or has_process_sub_remote_command(command)):
        rules.append({
            "rule_id": "remote_fetch_to_interpreter",
            "severity": "critical",
            "source": "remote_fetch",
            "sink": "interpreter",
        })

    if command and _TAINT_NETWORK_SINK.search(command) and any(
        is_credential_path(path) or ".gnupg/" in path.lower() or ".env" in path.lower()
        for path in paths
    ):
        rules.append({
            "rule_id": "sensitive_source_to_network_sink",
            "severity": "critical",
            "source": "sensitive_local_data",
            "sink": "network",
        })

    if command and _archive_extract_then_execute(command):
        rules.append({
            "rule_id": "archive_extract_then_execute",
            "severity": "high",
            "source": "archive_content",
            "sink": "interpreter",
        })

    if command:
        for rule_id in _encrypted_archive_taint_rule_ids(command):
            if rule_id == "encrypted_archive_then_delete_original":
                rules.append({
                    "rule_id": rule_id,
                    "severity": "critical",
                    "source": "workspace_artifact",
                    "sink": "destructive_lock_in",
                })
            else:
                rules.append({
                    "rule_id": rule_id,
                    "severity": "high",
                    "source": "workspace_artifact",
                    "sink": "encrypted_archive",
                })

    if command and _TAINT_BULK_DESTRUCTIVE.search(command):
        rules.append({
            "rule_id": "bulk_destructive_sequence",
            "severity": "critical",
            "source": "bulk_path_selection",
            "sink": "destructive_write",
        })

    if (
        analyzable_text
        and _TAINT_SPREADSHEET_WRITER.search(analyzable_text)
        and _TAINT_SPREADSHEET_HIDDEN_OR_CACHE.search(analyzable_text)
        and _TAINT_SPREADSHEET_EXTERNAL_FORMULA.search(analyzable_text)
    ):
        rules.append({
            "rule_id": "spreadsheet_downstream_payload",
            "severity": "high",
            "source": "spreadsheet_hidden_state",
            "sink": "downstream_interpreter",
        })

    tool = (event.tool_name or "").lower()
    writes_payload_path = tool in {"write_file", "edit_file", "create_file", "edit", "write"}
    writes_package_lifecycle = (
        writes_payload_path
        and any(path.endswith("/package.json") or path == "package.json" for path in paths)
        and _TAINT_PACKAGE_LIFECYCLE_SCRIPT.search(str(payload.get("content") or ""))
    )
    if (
        (command and _command_writes_persistence_entrypoint(command))
        or (writes_payload_path and any(_is_persistence_entrypoint_path(path) for path in paths))
        or writes_package_lifecycle
    ):
        rules.append({
            "rule_id": "persistence_entrypoint_write",
            "severity": "high",
            "source": "local_write",
            "sink": "future_execution_entrypoint",
        })

    if not rules:
        return None

    rule_ids = [str(rule["rule_id"]) for rule in rules]
    return {
        "rules": rules,
        "rule_ids": rule_ids,
        "chain_count": len(rules),
        "command_hash": "sha256:" + hashlib.sha256(command.encode("utf-8")).hexdigest() if command else None,
        "redaction_policy_version": "cs.taint_flow_summary.v1",
    }


def _content_evidence_rule_ids(context: DecisionContext | None) -> list[str]:
    envelope = getattr(context, "content_evidence", None) if context is not None else None
    if envelope is None:
        return []
    rule_ids: list[str] = []
    for item in getattr(envelope, "items", []) or []:
        for rule in getattr(item, "derived_rules", []) or []:
            if not isinstance(rule, dict):
                continue
            rule_id = str(rule.get("rule_id") or "")
            if rule_id and rule_id not in rule_ids:
                rule_ids.append(rule_id)
    return rule_ids


def _content_evidence_taint_summary(
    context: DecisionContext | None,
    existing: dict[str, object] | None,
) -> dict[str, object] | None:
    rule_ids = _content_evidence_rule_ids(context)
    content_rules: list[dict[str, object]] = []
    if "document_input_to_network_sink" in rule_ids:
        content_rules.append({
            "rule_id": "document_input_to_network_sink",
            "severity": "high",
            "source": "document_input",
            "sink": "network_upload",
        })
    if "document_input_encoded_to_network_sink" in rule_ids:
        content_rules.append({
            "rule_id": "document_input_encoded_to_network_sink",
            "severity": "high",
            "source": "document_input",
            "sink": "encoded_network_upload",
        })
    if "credential_source_to_network_sink" in rule_ids:
        content_rules.append({
            "rule_id": "credential_source_to_network_sink",
            "severity": "critical",
            "source": "credential_source",
            "sink": "network_upload",
        })
    if "subprocess_file_transfer" in rule_ids:
        content_rules.append({
            "rule_id": "subprocess_file_transfer",
            "severity": "high",
            "source": "workspace_file",
            "sink": "subprocess_file_transfer",
        })
    if not content_rules:
        return existing

    if existing is None:
        rules = content_rules
        command_hash = None
    else:
        rules = list(existing.get("rules", [])) + content_rules
        command_hash = existing.get("command_hash")
    merged_rule_ids: list[str] = []
    for rule in rules:
        if isinstance(rule, dict):
            rule_id = str(rule.get("rule_id") or "")
            if rule_id and rule_id not in merged_rule_ids:
                merged_rule_ids.append(rule_id)
    return {
        "rules": rules,
        "rule_ids": merged_rule_ids,
        "chain_count": len(rules),
        "command_hash": command_hash,
        "redaction_policy_version": "cs.taint_flow_summary.v1",
    }


_FIRST_USE_SCAN_RULE_BY_STATE = {
    "scan_not_started": "first_use_scan_not_started",
    "scan_running_sync": "first_use_scan_running_sync",
    "scan_pending_budget_exhausted": "first_use_scan_pending_budget_exhausted",
    "scan_failed": "first_use_scan_failed",
}


def skill_trust_first_use_state_rule(skill_trust) -> str | None:
    """Return the first-use scan rule id for unresolved skill identities."""

    if skill_trust is None:
        return None
    if skill_trust.registry_status in {"unknown", "unbound"}:
        pass
    elif (
        skill_trust.registry_status == "matched"
        and skill_trust.trust_list_state in {"greylist", "unlisted", "disabled"}
    ):
        pass
    else:
        return None
    scan = skill_trust.first_use_scan
    if scan is None:
        return None
    return _FIRST_USE_SCAN_RULE_BY_STATE.get(scan.state)


def skill_trust_first_use_policy_effect(skill_trust, config: DetectionConfig) -> str | None:
    """Resolve first-use admission policy to a legacy action until policy migration finishes."""

    if skill_trust_first_use_state_rule(skill_trust) is None:
        return None
    mode = str(config.mode or "normal").strip().lower()
    if mode not in {"normal", "benchmark", "strict", "permissive"}:
        mode = "normal"
    policy = str(getattr(config, f"skill_trust_first_use_{mode}_policy", "audit_only"))
    if policy == "block_until_reviewed":
        return "block"
    if policy in {"scan_async_defer", "defer_for_review"}:
        return "defer"
    return "audit"


def skill_trust_runtime_binding_action(skill_trust, config: DetectionConfig) -> str | None:
    """Resolve the configured runtime-binding action for the active profile."""

    if skill_trust is None:
        return None
    runtime_status = getattr(skill_trust, "runtime_path_status", None)
    runtime_content_status = getattr(skill_trust, "runtime_content_status", None)
    if runtime_status not in {
        "disallowed",
        "ambiguous_runtime_source",
        "name_only_unverified",
        "path_fragment_unverified",
    } and runtime_content_status not in {"content_unverified", "content_mismatch"}:
        return None
    mode = str(config.mode or "normal").strip().lower()
    if mode not in {"normal", "benchmark", "strict", "permissive"}:
        mode = "normal"
    condition = None
    if runtime_status == "disallowed":
        condition = "path_disallowed"
    elif runtime_status == "ambiguous_runtime_source":
        condition = "source_ambiguous"
    elif runtime_status in {"name_only_unverified", "path_fragment_unverified"}:
        condition = "path_unverified"
    if runtime_content_status == "content_unverified":
        condition = "content_unverified"
    elif runtime_content_status == "content_mismatch":
        condition = "content_mismatch"
    if condition is None:
        return None
    condition_attr = f"skill_trust_runtime_{condition}_{mode}_action"
    return str(getattr(config, condition_attr, "audit"))


def _skill_trust_runtime_binding_condition(skill_trust) -> str | None:
    runtime_status = getattr(skill_trust, "runtime_path_status", None)
    runtime_content_status = getattr(skill_trust, "runtime_content_status", None)
    if runtime_status == "disallowed":
        return "path_disallowed"
    if runtime_status == "ambiguous_runtime_source":
        return "source_ambiguous"
    if runtime_status in {"name_only_unverified", "path_fragment_unverified"}:
        return "path_unverified"
    if runtime_content_status == "content_unverified":
        return "content_unverified"
    if runtime_content_status == "content_mismatch":
        return "content_mismatch"
    return None


def skill_trust_runtime_binding_review_tier(skill_trust, config: DetectionConfig) -> str:
    """Resolve the policy-owned review tier for runtime-binding evidence."""

    condition = _skill_trust_runtime_binding_condition(skill_trust)
    mode = str(config.mode or "normal").strip().lower()
    if mode not in {"normal", "benchmark", "strict", "permissive"}:
        mode = "normal"
    matrix = {
        "path_disallowed": {
            "normal": "l3",
            "benchmark": "none",
            "strict": "none",
            "permissive": "none",
        },
        "source_ambiguous": {
            "normal": "l3",
            "benchmark": "none",
            "strict": "l3",
            "permissive": "none",
        },
        "path_unverified": {
            "normal": "none",
            "benchmark": "none",
            "strict": "l3",
            "permissive": "none",
        },
        "content_unverified": {
            "normal": "l3",
            "benchmark": "l3",
            "strict": "l3",
            "permissive": "none",
        },
        "content_mismatch": {
            "normal": "l3",
            "benchmark": "none",
            "strict": "none",
            "permissive": "none",
        },
    }
    return matrix.get(condition or "", {}).get(mode, "none")


def _validated_fspr_review(fspr_review: object) -> dict | None:
    if hasattr(fspr_review, "model_dump"):
        fspr_review = fspr_review.model_dump(mode="json")  # type: ignore[union-attr]
    if not isinstance(fspr_review, dict):
        return None
    review = dict(fspr_review)
    forbidden_policy_fields = {
        "recommended_action",
        "recommended_policy_action",
        "recommended_review_tier",
    }
    if any(field in review for field in forbidden_policy_fields):
        review["verdict"] = "insufficient_evidence"
        if str(review.get("timing_mode") or "") not in _FSPR_ALLOWED_TIMING_MODES:
            review["timing_mode"] = "post_action_incremental_evidence"
        review["degraded"] = True
        review["degradation_reason"] = "invalid_policy_field"
        return review
    schema = str(review.get("schema") or "")
    verdict = str(review.get("verdict") or "")
    timing_mode = str(review.get("timing_mode") or "")
    if schema != FSPR_SCHEMA_VERSION:
        review["verdict"] = "insufficient_evidence"
        if timing_mode not in _FSPR_ALLOWED_TIMING_MODES:
            review["timing_mode"] = "post_action_incremental_evidence"
        review["degraded"] = True
        review["degradation_reason"] = "invalid_schema"
        return review
    if timing_mode not in _FSPR_ALLOWED_TIMING_MODES:
        review["verdict"] = "insufficient_evidence"
        review["timing_mode"] = "post_action_incremental_evidence"
        review["degraded"] = True
        review["degradation_reason"] = "invalid_timing_mode"
        return review
    if verdict not in _FSPR_ALLOWED_VERDICTS:
        review["verdict"] = "insufficient_evidence"
        review["degraded"] = True
        review["degradation_reason"] = "invalid_verdict"
    return review


def _normalized_degradation_reason(value: object) -> str:
    return str(value or "").split(":", 1)[0].strip()


def _is_fspr_provider_health_degradation_reason(reason: object) -> bool:
    normalized = _normalized_degradation_reason(reason).lower()
    return (
        normalized in _FSPR_PROVIDER_HEALTH_DEGRADATION_REASONS
        or normalized.startswith("provider_")
    )


def _fspr_finding_is_hard(finding: object) -> bool:
    if not isinstance(finding, dict):
        return False
    return bool(
        finding.get("decision_affecting")
        or str(finding.get("severity") or "").lower() in {"high", "critical"}
    )


def _fspr_role_result_is_hard(role_result: object) -> bool:
    if not isinstance(role_result, dict):
        return False
    verdict = str(role_result.get("verdict") or "").lower()
    severity = str(role_result.get("severity") or "").lower()
    return bool(
        role_result.get("decision_affecting")
        or verdict in {"suspicious", "inconsistent"}
        or severity in {"high", "critical"}
    )


def _fspr_review_has_hard_findings(review: dict[str, Any]) -> bool:
    if str(review.get("severity") or "").lower() in {"high", "critical"}:
        return True
    if any(_fspr_finding_is_hard(item) for item in review.get("final_findings") or []):
        return True
    for role_result in review.get("role_results") or []:
        if not isinstance(role_result, dict):
            continue
        if _fspr_role_result_is_hard(role_result):
            return True
        if any(_fspr_finding_is_hard(item) for item in role_result.get("findings") or []):
            return True
    return False


def _fspr_review_has_deterministic_hard_findings(review: dict[str, Any]) -> bool:
    evidence_capsule = review.get("evidence_capsule")
    if isinstance(evidence_capsule, dict):
        if evidence_capsule.get("deterministic_hard_findings_preserved") is True:
            return True
        for key in ("deterministic_findings", "external_deterministic_findings"):
            if any(_fspr_finding_is_hard(item) for item in evidence_capsule.get(key) or []):
                return True
    for role_result in review.get("role_results") or []:
        if not isinstance(role_result, dict):
            continue
        if str(role_result.get("role") or "") != "deterministic_inventory":
            continue
        if _fspr_role_result_is_hard(role_result):
            return True
        if any(_fspr_finding_is_hard(item) for item in role_result.get("findings") or []):
                return True
    return False


def _fspr_review_blocks_manifest_instruction_exposure(review: dict[str, Any]) -> bool:
    """Return True when SKILL.md exposure would reveal hard-risk package guidance."""

    def finding_blocks(finding: object) -> bool:
        if not isinstance(finding, dict):
            return False
        severity = str(finding.get("severity") or "").lower()
        hard_finding = (
            finding.get("decision_affecting") is True
            or severity in {"high", "critical"}
        )
        if not hard_finding:
            return False
        axis = str(finding.get("review_axis") or "").lower()
        category = str(finding.get("category") or finding.get("rule_id") or "").lower()
        exposure_axes = {
            "instruction_channel_integrity",
            "data_boundary_control",
            "state_mutation_scope",
            "reentry_activation_surface",
            "review_evidence_quality",
        }
        exposure_fragments = (
            "prompt_injection",
            "content_authority",
            "validation_downgrade",
            "result_integrity",
            "hidden",
            "sidecar",
            "handoff",
            "suppression",
            "scope_expansion",
            "state_mutation",
            "external_wrapper",
            "execution",
            "provenance_attestation",
        )
        return axis in exposure_axes or any(
            fragment in category for fragment in exposure_fragments
        )

    return any(finding_blocks(item) for item in _fspr_review_finding_items(review))


def _fspr_analysis_completed(review: dict[str, Any]) -> bool:
    return not (
        bool(review.get("degraded"))
        and str(review.get("verdict") or "") == "insufficient_evidence"
    )


def _fspr_analysis_incomplete_reason(review: dict[str, Any]) -> str | None:
    if _fspr_analysis_completed(review):
        return None
    return _normalized_degradation_reason(review.get("degradation_reason")) or "unknown"


def is_provider_health_only_degraded_fspr(fspr_review: object) -> bool:
    review = _validated_fspr_review(fspr_review)
    if review is None:
        return False
    if not bool(review.get("degraded")):
        return False
    if str(review.get("verdict") or "") != "insufficient_evidence":
        return False
    if not _is_fspr_provider_health_degradation_reason(review.get("degradation_reason")):
        return False
    if review.get("deterministic_findings_preserved") is not True:
        return False
    if review.get("admission_recommendation") is not None:
        return False
    if _fspr_review_has_hard_findings(review) or _fspr_review_has_deterministic_hard_findings(review):
        return False
    return True


def is_provider_advisory_only_fspr(fspr_review: object, skill_trust=None) -> bool:
    review = _validated_fspr_review(fspr_review)
    if review is None:
        return False
    if str(review.get("timing_mode") or "") != "pre_use_gate":
        return False
    if bool(review.get("degraded")):
        return False
    if str(review.get("verdict") or "") not in {"suspicious", "inconsistent"}:
        return False
    if review.get("deterministic_findings_preserved") is not True:
        return False
    strong_binding, _failure_reason = is_strong_trusted_runtime_binding(skill_trust)
    if not strong_binding:
        return False
    return not _fspr_review_has_deterministic_hard_findings(review)


def is_strong_trusted_runtime_binding(skill_trust) -> tuple[bool, str]:
    if skill_trust is None:
        return False, "skill_trust_missing"
    if getattr(skill_trust, "registry_status", None) != "matched":
        return False, "registry_status_not_matched"
    if getattr(skill_trust, "trust_list_state", None) != "allowlist":
        return False, "trust_list_state_not_allowlist"
    if getattr(skill_trust, "admission_risk", None) != "low":
        return False, "admission_risk_not_low"
    runtime_path_status = getattr(skill_trust, "runtime_path_status", None)
    if runtime_path_status not in {"verified_source", "verified_mirror"}:
        return False, "runtime_path_not_verified"
    runtime_content_status = getattr(skill_trust, "runtime_content_status", None)
    if runtime_content_status not in {"content_verified", "trusted_runner_immutable", "not_applicable"}:
        return False, "runtime_content_not_verified"
    if runtime_content_status == "not_applicable" and runtime_path_status != "verified_source":
        return False, "runtime_content_not_applicable_without_source_binding"
    if getattr(skill_trust, "metadata_source", None) != "gateway_owned_metadata":
        return False, "metadata_not_gateway_owned"
    if not getattr(skill_trust, "metadata_record_id", None):
        return False, "metadata_record_id_missing"
    if not getattr(skill_trust, "runtime_evidence_kind", None):
        return False, "runtime_evidence_kind_missing"
    if not getattr(skill_trust, "policy_fingerprint", None):
        return False, "policy_fingerprint_missing"
    if getattr(skill_trust, "invariant_violations", None):
        return False, "invariant_violation_present"
    return True, ""


def is_gateway_owned_low_risk_runtime_binding(skill_trust) -> bool:
    if skill_trust is None:
        return False
    if getattr(skill_trust, "registry_status", None) != "matched":
        return False
    if getattr(skill_trust, "admission_risk", None) != "low":
        return False
    runtime_path_status = getattr(skill_trust, "runtime_path_status", None)
    if runtime_path_status not in {"verified_source", "verified_mirror"}:
        return False
    runtime_content_status = getattr(skill_trust, "runtime_content_status", None)
    if runtime_content_status not in {"content_verified", "trusted_runner_immutable", "not_applicable"}:
        return False
    if runtime_content_status == "not_applicable" and runtime_path_status != "verified_source":
        return False
    if getattr(skill_trust, "metadata_source", None) != "gateway_owned_metadata":
        return False
    if not getattr(skill_trust, "metadata_record_id", None):
        return False
    if not getattr(skill_trust, "runtime_evidence_kind", None):
        return False
    if not getattr(skill_trust, "policy_fingerprint", None):
        return False
    if getattr(skill_trust, "invariant_violations", None):
        return False
    return True


def skill_trust_fspr_policy_action(
    fspr_review: object,
    config: DetectionConfig,
    skill_trust=None,
) -> str | None:
    """Resolve Gateway-owned policy action from FSPR evidence."""

    review = _validated_fspr_review(fspr_review)
    if review is None:
        return None
    if str(review.get("timing_mode") or "") != "pre_use_gate":
        return "audit"
    strong_binding, _failure_reason = is_strong_trusted_runtime_binding(skill_trust)
    if is_provider_health_only_degraded_fspr(review) and (
        strong_binding or is_gateway_owned_low_risk_runtime_binding(skill_trust)
    ):
        return "audit"
    if is_provider_advisory_only_fspr(review, skill_trust):
        return "audit"
    verdict = str(review.get("verdict") or "")
    mode = str(config.mode or "normal").strip().lower()
    if mode not in {"normal", "benchmark", "strict", "permissive"}:
        mode = "normal"
    matrix = {
        "normal": {
            "consistent": "audit",
            "insufficient_evidence": "audit",
            "suspicious": "audit",
            "inconsistent": "defer",
        },
        "benchmark": {
            "consistent": "audit",
            "insufficient_evidence": "audit",
            "suspicious": "block",
            "inconsistent": "block",
        },
        "strict": {
            "consistent": "audit",
            "insufficient_evidence": "audit",
            "suspicious": "defer",
            "inconsistent": "block",
        },
        "permissive": {
            "consistent": "audit",
            "insufficient_evidence": "audit",
            "suspicious": "audit",
            "inconsistent": "audit",
        },
    }
    return matrix[mode].get(verdict, "audit")


def skill_trust_fspr_review_tier(
    fspr_review: object,
    config: DetectionConfig,
    skill_trust=None,
) -> str | None:
    """Resolve Gateway-owned review tier from FSPR evidence."""

    review = _validated_fspr_review(fspr_review)
    if review is None:
        return None
    if str(review.get("timing_mode") or "") != "pre_use_gate":
        return "none"
    strong_binding, _failure_reason = is_strong_trusted_runtime_binding(skill_trust)
    if is_provider_health_only_degraded_fspr(review) and (
        strong_binding or is_gateway_owned_low_risk_runtime_binding(skill_trust)
    ):
        return "none"
    if is_provider_advisory_only_fspr(review, skill_trust):
        return "none"
    verdict = str(review.get("verdict") or "")
    mode = str(config.mode or "normal").strip().lower()
    if mode not in {"normal", "benchmark", "strict", "permissive"}:
        mode = "normal"
    matrix = {
        "normal": {
            "consistent": "none",
            "insufficient_evidence": "none",
            "suspicious": "l3",
            "inconsistent": "l3",
        },
        "benchmark": {
            "consistent": "none",
            "insufficient_evidence": "none",
            "suspicious": "none",
            "inconsistent": "none",
        },
        "strict": {
            "consistent": "none",
            "insufficient_evidence": "l3",
            "suspicious": "l3",
            "inconsistent": "none",
        },
        "permissive": {
            "consistent": "none",
            "insufficient_evidence": "none",
            "suspicious": "none",
            "inconsistent": "none",
        },
    }
    return matrix[mode].get(verdict, "none")


def _action_to_routing(action: str | None) -> tuple[str, str]:
    if action == "force_l3":
        return "audit", "l3"
    if action == "force_l2":
        return "audit", "l2"
    if action == "defer":
        return "defer", "none"
    if action == "block":
        return "block", "none"
    return "audit", "none"


def _compact_skill_trust_metadata(skill_trust, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    metadata = {
        "admission_risk": getattr(skill_trust, "admission_risk", None),
        "registry_status": getattr(skill_trust, "registry_status", None),
        "canonical_skill_id": getattr(skill_trust, "canonical_skill_id", None),
        "presented_name": getattr(skill_trust, "presented_name", None),
        "ref_ordinal": getattr(skill_trust, "ref_ordinal", None),
        "trust_list_state": getattr(skill_trust, "trust_list_state", None),
        "runtime_path_status": getattr(skill_trust, "runtime_path_status", None),
        "runtime_content_status": getattr(skill_trust, "runtime_content_status", None),
        "runtime_binding_reason": getattr(skill_trust, "runtime_binding_reason", None),
        "metadata_source": getattr(skill_trust, "metadata_source", None),
        "metadata_record_id": getattr(skill_trust, "metadata_record_id", None),
        "runtime_evidence_kind": getattr(skill_trust, "runtime_evidence_kind", None),
        "policy_fingerprint": getattr(skill_trust, "policy_fingerprint", None),
        "invariant_violations": getattr(skill_trust, "invariant_violations", None),
    }
    if extra:
        metadata.update(extra)
    return {key: value for key, value in metadata.items() if value is not None}


def build_skill_trust_routing_intents(skill_trust, config: DetectionConfig) -> list[ReviewRoutingIntent]:
    """Build policy-owned routing intents from one Skill Trust evidence object."""

    if skill_trust is None:
        return []
    intents: list[ReviewRoutingIntent] = []

    first_use_rule = skill_trust_first_use_state_rule(skill_trust)
    first_use_effect = skill_trust_first_use_policy_effect(skill_trust, config)
    if first_use_rule is not None:
        policy_action, recommended_tier = _action_to_routing(first_use_effect)
        mode = str(config.mode or "normal").strip().lower()
        if mode not in {"normal", "benchmark", "strict", "permissive"}:
            mode = "normal"
        configured_policy = str(getattr(config, f"skill_trust_first_use_{mode}_policy", "audit_only"))
        intents.append(ReviewRoutingIntent(
            source="first_use_admission",
            recommended_tier=recommended_tier,
            policy_action=policy_action,
            reason="first_use_unreviewed_skill",
            source_metadata=_compact_skill_trust_metadata(skill_trust, {
                "first_use_rule": first_use_rule,
                "first_use_scan_state": getattr(getattr(skill_trust, "first_use_scan", None), "state", None),
                "admission_policy": configured_policy,
                "policy_effect": first_use_effect or "audit",
            }),
            routing_affecting=recommended_tier in {"l2", "l3"},
            decision_affecting=policy_action in {"defer", "block"},
        ))

    runtime_action = skill_trust_runtime_binding_action(skill_trust, config)
    if runtime_action is not None:
        policy_action, fallback_tier = _action_to_routing(runtime_action)
        recommended_tier = skill_trust_runtime_binding_review_tier(skill_trust, config)
        if recommended_tier == "none":
            recommended_tier = fallback_tier
        intents.append(ReviewRoutingIntent(
            source="runtime_binding",
            recommended_tier=recommended_tier,
            policy_action=policy_action,
            reason="runtime_binding_identity_conflict",
            source_metadata=_compact_skill_trust_metadata(skill_trust, {
                "runtime_path_status": getattr(skill_trust, "runtime_path_status", None),
                "runtime_content_status": getattr(skill_trust, "runtime_content_status", None),
                "runtime_binding_reason": getattr(skill_trust, "runtime_binding_reason", None),
                "configured_action": runtime_action,
                "review_tier": recommended_tier,
            }),
            routing_affecting=recommended_tier in {"l2", "l3"},
            decision_affecting=policy_action in {"defer", "block"},
        ))

    fspr_review = _validated_fspr_review(getattr(skill_trust, "first_use_package_review", None))
    if fspr_review is not None:
        if str(fspr_review.get("timing_mode") or "") != "pre_use_gate":
            return intents
        policy_action = skill_trust_fspr_policy_action(fspr_review, config, skill_trust) or "audit"
        review_tier = skill_trust_fspr_review_tier(fspr_review, config, skill_trust) or "none"
        strong_binding, strong_binding_failure_reason = is_strong_trusted_runtime_binding(skill_trust)
        provider_health_only = is_provider_health_only_degraded_fspr(fspr_review)
        provider_advisory_only = is_provider_advisory_only_fspr(fspr_review, skill_trust)
        fspr_analysis_completed = _fspr_analysis_completed(fspr_review)
        intents.append(ReviewRoutingIntent(
            source="fspr_package_review",
            recommended_tier=review_tier,
            policy_action=policy_action,
            reason="fspr_package_review",
            source_metadata=_compact_skill_trust_metadata(skill_trust, {
                "verdict": fspr_review.get("verdict"),
                "severity": fspr_review.get("severity"),
                "confidence": fspr_review.get("confidence"),
                "degraded": bool(fspr_review.get("degraded", False)),
                "degradation_reason": fspr_review.get("degradation_reason"),
                "provider_health_only": provider_health_only,
                "provider_advisory_only": provider_advisory_only,
                "fspr_analysis_completed": fspr_analysis_completed,
                "fspr_analysis_incomplete_reason": _fspr_analysis_incomplete_reason(fspr_review),
                "deterministic_hard_findings": _fspr_review_has_deterministic_hard_findings(fspr_review),
                "strong_runtime_binding": strong_binding,
                "strong_binding_failure_reason": strong_binding_failure_reason,
            }),
            routing_affecting=review_tier in {"l2", "l3"},
            decision_affecting=policy_action in {"defer", "block"},
        ))

    return intents


def build_content_evidence_routing_intents(
    context: DecisionContext | None,
    config: DetectionConfig,
) -> list[ReviewRoutingIntent]:
    """Build Gateway-owned routing intents from request-local content evidence."""

    rule_ids = set(_content_evidence_rule_ids(context))
    if not rule_ids:
        return []
    envelope = getattr(context, "content_evidence", None) if context is not None else None
    source_metadata = {"rule_ids": sorted(rule_ids), "mode": ""}
    exact_refs = list(getattr(envelope, "exact_ref_allowlist", []) or []) if envelope is not None else []
    mode = str(config.mode or "normal").strip().lower()
    if mode not in {"normal", "benchmark", "strict", "permissive"}:
        mode = "normal"
    source_metadata["mode"] = mode
    if exact_refs:
        source_metadata["exact_ref_allowlist"] = exact_refs

    intents: list[ReviewRoutingIntent] = []
    high_confidence_exfil = bool(rule_ids.intersection({
        "document_input_to_network_sink",
        "document_input_encoded_to_network_sink",
        "credential_source_to_network_sink",
        "subprocess_file_transfer",
    }))
    incomplete_with_network = (
        "content_evidence_incomplete" in rule_ids
        and bool(rule_ids.intersection({
            "associated_script_network_sink",
            "document_input_to_network_sink",
            "possible_document_input_to_network_sink",
        }))
    )
    read_content_signal = bool(rule_ids.intersection({
        "read_content_prompt_injection",
        "read_content_hidden_html_instruction",
        "read_content_zero_width_or_bidi",
        "read_content_markdown_beacon",
        "read_content_data_uri_or_base64_payload",
        "read_content_hidden_auxiliary_output_instruction",
        "sensitive_read_path",
        "credential_read_content_skipped",
        "read_content_execution_or_network_instruction",
        "read_content_source_authority_override",
        "read_content_task_scope_contraction",
        "read_content_external_reference_instruction",
        "read_content_static_path_set_incomplete",
    }))

    if high_confidence_exfil:
        policy_action = {
            "benchmark": "block",
            "strict": "defer",
            "normal": "defer",
            "permissive": "audit",
        }[mode]
        intents.append(ReviewRoutingIntent(
            source="content_evidence",
            recommended_tier="l3" if mode == "normal" else "none",
            policy_action=policy_action,
            reason="document_input_to_network_sink",
            source_metadata=dict(source_metadata),
            routing_affecting=mode == "normal",
            decision_affecting=policy_action in {"defer", "block"},
        ))
    elif incomplete_with_network:
        policy_action = {
            "benchmark": "block",
            "strict": "defer",
            "normal": "defer",
            "permissive": "audit",
        }[mode]
        intents.append(ReviewRoutingIntent(
            source="content_evidence",
            recommended_tier="l3" if mode in {"normal", "strict"} else "none",
            policy_action=policy_action,
            reason="content_evidence_incomplete",
            source_metadata=dict(source_metadata),
            routing_affecting=mode in {"normal", "strict"},
            decision_affecting=policy_action in {"defer", "block"},
        ))
    elif read_content_signal:
        policy_action = {
            "benchmark": "defer",
            "strict": "defer",
            "normal": "audit",
            "permissive": "audit",
        }[mode]
        intents.append(ReviewRoutingIntent(
            source="content_evidence",
            recommended_tier="l3" if mode == "normal" else "none",
            policy_action=policy_action,
            reason="read_content_evidence",
            source_metadata=dict(source_metadata),
            routing_affecting=mode == "normal",
            decision_affecting=policy_action in {"defer", "block"},
        ))
    return intents


def _skill_trust_routing_intents_for_context(
    context: Optional[DecisionContext],
    config: DetectionConfig,
) -> list[ReviewRoutingIntent]:
    if context is None:
        return []
    refs = list(context.skill_trust_refs or [])
    if context.skill_trust is not None and all(ref is not context.skill_trust for ref in refs):
        refs.append(context.skill_trust)
    intents = [
        intent
        for ref in refs
        for intent in build_skill_trust_routing_intents(ref, config)
    ]
    policy_priority = {"block": 3, "defer": 2, "audit": 1}
    tier_priority = {"l3": 3, "l2": 2, "none": 1}
    return sorted(
        intents,
        key=lambda intent: (
            -policy_priority.get(intent.policy_action, 0),
            -tier_priority.get(intent.recommended_tier, 0),
            intent.source,
            intent.reason,
        ),
    )


def _skill_trust_evidence(
    event: CanonicalEvent,
    context: Optional[DecisionContext],
    current_level: RiskLevel,
    current_score: float,
    config: DetectionConfig,
) -> tuple[RiskLevel, float, list[str], list[dict]]:
    if context is not None and context.skill_trust_refs:
        aggregate_level = current_level
        aggregate_score = current_score
        aggregate_hits: list[str] = []
        aggregate_findings: list[dict] = []
        for ref_context in context.skill_trust_refs:
            level, score, hits, findings = _skill_trust_evidence(
                event,
                DecisionContext(skill_trust=ref_context),
                aggregate_level,
                aggregate_score,
                config,
            )
            aggregate_level = level
            aggregate_score = score
            for hit in hits:
                if hit not in aggregate_hits:
                    aggregate_hits.append(hit)
            aggregate_findings.extend(findings)
        return aggregate_level, aggregate_score, aggregate_hits, aggregate_findings

    skill_trust = context.skill_trust if context is not None else None
    if skill_trust is None:
        return current_level, current_score, [], []

    rule_hits: list[str] = []
    findings: list[dict] = []

    if skill_trust.registry_status == "unknown":
        rule_hits.append("unknown_skill_identity")
    elif skill_trust.registry_status == "unbound":
        rule_hits.append("unbound_skill_identity")
    elif skill_trust.registry_status == "ambiguous":
        rule_hits.append("ambiguous_skill_alias")
    elif skill_trust.registry_status == "hash_mismatch":
        rule_hits.append("skill_hash_mismatch")

    for violation in skill_trust.invariant_violations:
        if violation not in rule_hits:
            rule_hits.append(violation)

    runtime_status = getattr(skill_trust, "runtime_path_status", None)
    runtime_content_status = getattr(skill_trust, "runtime_content_status", None)
    runtime_rule = {
        "disallowed": "runtime_path_disallowed",
        "ambiguous_runtime_source": "runtime_source_ambiguous",
        "name_only_unverified": "runtime_path_unverified",
        "path_fragment_unverified": "runtime_path_fragment_unverified",
    }.get(runtime_status)
    if runtime_rule and runtime_rule not in rule_hits:
        rule_hits.append(runtime_rule)
    if runtime_content_status == "content_unverified" and "runtime_content_unverified" not in rule_hits:
        rule_hits.append("runtime_content_unverified")
    elif runtime_content_status == "content_mismatch" and "runtime_content_mismatch" not in rule_hits:
        rule_hits.append("runtime_content_mismatch")

    if (
        skill_trust.provenance_claim
        and skill_trust.presented_name
        and _skill_identity_normalize(skill_trust.provenance_claim)
        == _skill_identity_normalize(skill_trust.presented_name)
        and skill_trust.provenance_claim != skill_trust.presented_name
    ):
        rule_hits.append("provenance_label_mismatch")

    first_use_rule = skill_trust_first_use_state_rule(skill_trust)
    first_use_effect = skill_trust_first_use_policy_effect(skill_trust, config)
    runtime_binding_action = skill_trust_runtime_binding_action(skill_trust, config)
    fspr_review = _validated_fspr_review(getattr(skill_trust, "first_use_package_review", None))
    fspr_rule: str | None = None
    fspr_policy_action = (
        skill_trust_fspr_policy_action(fspr_review, config, skill_trust)
        if fspr_review is not None
        else None
    )
    fspr_review_tier = (
        skill_trust_fspr_review_tier(fspr_review, config, skill_trust)
        if fspr_review is not None
        else None
    )
    fspr_decision_affecting = False
    fspr_routing_affecting = False
    if isinstance(fspr_review, dict):
        fspr_verdict = str(fspr_review.get("verdict") or "")
        fspr_timing_mode = str(fspr_review.get("timing_mode") or "")
        fspr_provider_health_only = is_provider_health_only_degraded_fspr(fspr_review)
        fspr_provider_advisory_only = is_provider_advisory_only_fspr(fspr_review, skill_trust)
        fspr_deterministic_hard_findings = _fspr_review_has_deterministic_hard_findings(fspr_review)
        fspr_analysis_completed = _fspr_analysis_completed(fspr_review)
        fspr_strong_binding, fspr_strong_binding_failure_reason = is_strong_trusted_runtime_binding(skill_trust)
        if fspr_verdict == "inconsistent":
            fspr_rule = "first_use_skill_package_inconsistent"
        elif fspr_verdict == "suspicious":
            fspr_rule = "first_use_skill_package_suspicious"
        elif fspr_verdict == "insufficient_evidence":
            fspr_rule = "first_use_skill_package_insufficient_evidence"
        fspr_decision_affecting = (
            fspr_timing_mode == "pre_use_gate"
            and fspr_policy_action in {"defer", "block"}
            and fspr_verdict != "insufficient_evidence"
        )
        fspr_routing_affecting = (
            fspr_timing_mode == "pre_use_gate"
            and fspr_review_tier in {"l2", "l3"}
        )
        if fspr_rule and fspr_rule not in rule_hits:
            rule_hits.append(fspr_rule)
    if first_use_rule and first_use_rule not in rule_hits:
        rule_hits.append(first_use_rule)

    for rule_id in rule_hits:
        finding = {
            "rule_id": rule_id,
            "registry_status": skill_trust.registry_status,
            "canonical_skill_id": skill_trust.canonical_skill_id,
            "presented_name": skill_trust.presented_name,
            "provenance_claim": skill_trust.provenance_claim,
            "alias_match_type": skill_trust.alias_match_type,
            "admission_scan_id": skill_trust.admission_scan_id,
            "admission_risk": skill_trust.admission_risk,
            "trust_list_state": skill_trust.trust_list_state,
            "runtime_path_status": getattr(skill_trust, "runtime_path_status", None),
            "runtime_root_path_hash": getattr(skill_trust, "runtime_root_path_hash", None),
            "runtime_content_status": getattr(skill_trust, "runtime_content_status", None),
            "runtime_binding_reason": getattr(skill_trust, "runtime_binding_reason", None),
            "metadata_source": getattr(skill_trust, "metadata_source", None),
            "metadata_record_id": getattr(skill_trust, "metadata_record_id", None),
            "runtime_evidence_kind": getattr(skill_trust, "runtime_evidence_kind", None),
            "invariant_violations": getattr(skill_trust, "invariant_violations", None),
            "ref_ordinal": getattr(skill_trust, "ref_ordinal", None),
            "policy_fingerprint": skill_trust.policy_fingerprint,
            "decision_affecting": False,
        }
        if rule_id == first_use_rule and skill_trust.first_use_scan is not None:
            finding.update({
                "first_use_scan_state": skill_trust.first_use_scan.state,
                "first_use_admission_policy": str(getattr(
                    config,
                    f"skill_trust_first_use_{str(config.mode or 'normal').strip().lower()}_policy",
                    "audit_only",
                )),
                "first_use_policy_effect": first_use_effect or "audit",
                "first_use_scan_failure_class": skill_trust.first_use_scan.failure_class,
                "first_use_scan_admission_risk": skill_trust.first_use_scan.admission_risk,
            })
        if rule_id in {
            "runtime_path_disallowed",
            "runtime_source_ambiguous",
            "runtime_path_unverified",
            "runtime_path_fragment_unverified",
            "runtime_content_unverified",
            "runtime_content_mismatch",
        }:
            finding["runtime_binding_action"] = runtime_binding_action or "audit"
        if rule_id == fspr_rule and isinstance(fspr_review, dict):
            finding.update({
                "fspr_verdict": fspr_review.get("verdict"),
                "fspr_timing_mode": fspr_review.get("timing_mode"),
                "fspr_severity": fspr_review.get("severity"),
                "fspr_confidence": fspr_review.get("confidence"),
                "deterministic_findings_preserved": fspr_review.get("deterministic_findings_preserved"),
                "fspr_policy_action": fspr_policy_action or "audit",
                "fspr_review_tier": fspr_review_tier or "none",
                "routing_affecting": fspr_routing_affecting,
                "fspr_degraded": bool(fspr_review.get("degraded", False)),
                "fspr_degradation_reason": fspr_review.get("degradation_reason"),
                "provider_health_only": fspr_provider_health_only,
                "provider_advisory_only": fspr_provider_advisory_only,
                "fspr_analysis_completed": fspr_analysis_completed,
                "fspr_analysis_incomplete_reason": _fspr_analysis_incomplete_reason(fspr_review),
                "deterministic_hard_findings": fspr_deterministic_hard_findings,
                "strong_runtime_binding": fspr_strong_binding,
                "strong_binding_failure_reason": fspr_strong_binding_failure_reason,
                "decision_affecting": fspr_decision_affecting,
            })
        findings.append(finding)

    fspr_summary = getattr(skill_trust, "fspr_review_summary", None)
    if isinstance(fspr_summary, dict):
        findings.append(_compact_skill_trust_metadata(skill_trust, {
            "rule_id": "fspr_review_summary",
            "review_state": fspr_summary.get("review_state"),
            "timing_mode": fspr_summary.get("timing_mode"),
            "review_mode": fspr_summary.get("review_mode"),
            "provider_used": fspr_summary.get("provider_used"),
            "verdict": fspr_summary.get("verdict"),
            "severity": fspr_summary.get("severity"),
            "confidence": fspr_summary.get("confidence"),
            "degraded": fspr_summary.get("degraded"),
            "degradation_reason": fspr_summary.get("degradation_reason"),
            "failure_reason": fspr_summary.get("failure_reason"),
            "decision_affecting": False,
        }))

    if event.event_type != EventType.PRE_ACTION:
        return current_level, current_score, rule_hits, findings

    upgrade_level: RiskLevel | None = None
    rule_set = set(rule_hits)
    runtime_hard_confidence = bool(
        rule_set.intersection({"runtime_path_disallowed", "runtime_source_ambiguous", "runtime_content_mismatch"})
    )
    runtime_soft_confidence = bool(
        rule_set.intersection({"runtime_path_unverified", "runtime_path_fragment_unverified", "runtime_content_unverified"})
    )
    fspr_inconsistent_pre_use = (
        fspr_decision_affecting
        and "first_use_skill_package_inconsistent" in rule_set
        and fspr_policy_action == "block"
    )
    hard_confidence = (
        "skill_hash_mismatch" in rule_set
        or "blacklisted_skill_identity" in rule_set
        or "revoked_skill_identity" in rule_set
        or runtime_hard_confidence
        or fspr_inconsistent_pre_use
    )
    soft_confidence = (
        {"ambiguous_skill_alias", "provenance_label_conflict"}.issubset(rule_set)
        or {"unknown_skill_identity", "unknown_skill_provenance_rewrite"}.issubset(rule_set)
        or "low_trust_redefined_canonical_tool" in rule_set
    )
    if hard_confidence:
        if runtime_hard_confidence and config.mode not in {"strict", "benchmark"}:
            upgrade_level = RiskLevel.MEDIUM
        else:
            upgrade_level = RiskLevel.HIGH
    elif soft_confidence:
        mode = str(config.mode or "normal").strip().lower()
        upgrade_level = (
            RiskLevel.HIGH
            if mode in {"benchmark", "strict"}
            else RiskLevel.MEDIUM
        )
    elif runtime_soft_confidence and config.mode in {"strict", "benchmark"}:
        upgrade_level = RiskLevel.MEDIUM
    if (
        fspr_decision_affecting
        and "first_use_skill_package_insufficient_evidence" in rule_set
        and config.mode in {"strict", "benchmark"}
    ):
        upgrade_level = _max_risk_level(upgrade_level or current_level, RiskLevel.MEDIUM)
    if (
        fspr_policy_action == "block"
        and fspr_rule != "first_use_skill_package_insufficient_evidence"
    ):
        upgrade_level = RiskLevel.HIGH
    if first_use_effect == "block":
        upgrade_level = RiskLevel.HIGH
    if runtime_binding_action == "block":
        upgrade_level = RiskLevel.HIGH
    if skill_trust.admission_risk == "critical":
        upgrade_level = RiskLevel.CRITICAL

    if upgrade_level is None:
        if first_use_effect in {"force_l2", "force_l3", "defer"}:
            for finding in findings:
                if finding.get("rule_id") == first_use_rule:
                    finding["decision_affecting"] = True
        if runtime_binding_action in {"force_l2", "force_l3", "defer"}:
            for finding in findings:
                if finding.get("runtime_binding_action") == runtime_binding_action:
                    finding["decision_affecting"] = True
        return current_level, current_score, rule_hits, findings

    for finding in findings:
        if finding.get("rule_id") == "fspr_review_summary":
            finding["decision_affecting"] = False
        else:
            finding["decision_affecting"] = True
    risk_level = _max_risk_level(current_level, upgrade_level)
    score = max(current_score, _min_score_for_level(risk_level, config))
    return risk_level, score, rule_hits, findings


def _skill_identity_normalize(value: str) -> str:
    return re.sub(r"[\s_-]+", "", value.strip().lower())


def _counts_toward_d4_high_risk(snapshot: RiskSnapshot) -> bool:
    if snapshot.short_circuit_rule is not None and (
        snapshot.short_circuit_rule != "unresolved_analysis_escalate"
    ):
        return True
    if max(snapshot.dimensions.d1, snapshot.dimensions.d2, snapshot.dimensions.d3) >= 3:
        return True
    if snapshot.taint_flow_summary is not None:
        return True
    rule_hits = set(snapshot.rule_hits)
    if not rule_hits:
        return True
    skill_trust_rules = {
        "ambiguous_skill_alias",
        "blacklisted_skill_identity",
        "greylisted_skill_identity",
        "low_trust_redefined_canonical_tool",
        "provenance_label_conflict",
        "provenance_label_mismatch",
        "revoked_skill_identity",
        "runtime_registry_claim_untrusted",
        "skill_hash_mismatch",
        "unbound_skill_identity",
        "unknown_skill_identity",
        "unknown_skill_provenance_rewrite",
        "first_use_scan_failed",
        "first_use_scan_not_started",
        "first_use_scan_pending_budget_exhausted",
        "first_use_scan_running_sync",
        "native_read_effect",
        "shell_read_probe",
        "shell_enumerate_probe",
        "shell_capability_probe",
        "pure_workspace_read_audit_narrowing",
    }
    if not rule_hits.issubset(skill_trust_rules):
        return True
    return any(
        rule in rule_hits
        for rule in {
            "blacklisted_skill_identity",
            "revoked_skill_identity",
            "skill_hash_mismatch",
        }
    )


def _max_risk_level(a: RiskLevel, b: RiskLevel) -> RiskLevel:
    return a if RISK_LEVEL_ORDER[a] >= RISK_LEVEL_ORDER[b] else b


def _min_score_for_level(level: RiskLevel, config: DetectionConfig) -> float:
    if level == RiskLevel.CRITICAL:
        return config.threshold_critical
    if level == RiskLevel.HIGH:
        return config.threshold_high
    if level == RiskLevel.MEDIUM:
        return config.threshold_medium
    return 0.0


_TOOL_OUTPUT_METADATA_KEYS = frozenset(
    {"type", "iserror", "is_error", "mimetype", "mime_type", "annotations", "role"}
)


def _flatten_tool_output_text(value: Any, depth: int = 0) -> str:
    """Flatten structured tool output (e.g. MCP content blocks) into analyzable text.

    Handles str, dict (MCP `{"content": [{"type": "text", "text": ...}]}` shape or
    arbitrary nested payloads), and list values. Metadata keys (type/isError/...)
    are skipped so scoring only sees content. Depth-capped to avoid pathological
    recursion on adversarial payloads.
    """
    if depth > 6 or value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return ""
    if isinstance(value, list):
        return " ".join(
            text for item in value if (text := _flatten_tool_output_text(item, depth + 1))
        )
    if isinstance(value, dict):
        return " ".join(
            text
            for key, val in value.items()
            if str(key).lower() not in _TOOL_OUTPUT_METADATA_KEYS
            and (text := _flatten_tool_output_text(val, depth + 1))
        )
    return ""


def _extract_text_for_d6(event: CanonicalEvent) -> str:
    """Extract analyzable text from event payload for D6 scoring."""
    payload = event.payload or {}
    parts: list[str] = []

    # User input related fields (PRE_ACTION scenario)
    for key in ("command", "content", "text", "body", "input", "code", "message", "transcript", "userMessage", "user_message"):
        val = payload.get(key)
        if isinstance(val, str) and val:
            parts.append(val)

    # Tool return content fields (POST_ACTION scenario)
    # Use break to only take the first non-empty return value field to avoid duplication
    # (some adapters may keep both original and mapped fields). Structured outputs
    # (MCP content blocks / dict / list) are flattened to text before scoring.
    for key in ("output", "result", "tool_response", "tool_output"):
        text = _flatten_tool_output_text(payload.get(key))
        if text:
            parts.append(text)
            break

    if event.risk_hints:
        parts.extend(str(h) for h in event.risk_hints)
    return " ".join(parts)


def _artifact_source_family(value: Any) -> str:
    return re.sub(r"[\s-]+", "_", str(value or "").strip().lower())


def _artifact_source_is_route_eligible(target: dict[str, Any]) -> bool:
    source = _artifact_source_family(target.get("artifact_source"))
    if source in _TASK_ARTIFACT_EXCLUDED_SOURCES:
        return False
    source_metadata = target.get("artifact_source_metadata")
    if isinstance(source_metadata, dict):
        source_kind = _artifact_source_family(source_metadata.get("source_kind"))
        if source_kind in _TASK_ARTIFACT_EXCLUDED_SOURCES:
            return False
    return True


def _artifact_source_is_repository_mutation(target: dict[str, Any]) -> bool:
    source = _artifact_source_family(target.get("artifact_source"))
    if source.startswith("repository_mutation"):
        return True
    source_metadata = target.get("artifact_source_metadata")
    if isinstance(source_metadata, dict):
        source_kind = _artifact_source_family(source_metadata.get("source_kind"))
        if source_kind.startswith("repository_mutation"):
            return True
    return False


def _is_contract_qualified_artifact_target(
    target: dict[str, Any],
    *,
    artifact_role: str | None = None,
) -> bool:
    if target.get("artifact_risk_adjusting") is not True:
        return False
    if str(target.get("artifact_source_tier") or "") != "risk_adjusting":
        return False
    if str(target.get("artifact_confidence") or "") != "high":
        return False
    if target.get("artifact_trust_confirmed") is not True:
        return False
    if not target.get("artifact_profile_hash"):
        return False
    if not _artifact_source_is_route_eligible(target):
        return False
    actual_artifact_role = str(target.get("artifact_role") or "")
    if artifact_role is not None and actual_artifact_role != artifact_role:
        return False
    candidate_role = str(target.get("artifact_candidate_role") or target.get("path_role") or "")
    if actual_artifact_role == "task_data":
        return candidate_role == SCOPE_TASK_DATA_READ_PATH_ROLE
    if actual_artifact_role == "task_output":
        return candidate_role == SCOPE_TASK_OUTPUT_PATH_ROLE
    return False


def _contract_artifact_target_role(target: dict[str, Any]) -> str | None:
    if _is_contract_qualified_artifact_target(target, artifact_role="task_data"):
        return "task_data"
    if _is_contract_qualified_artifact_target(target, artifact_role="task_output"):
        return "task_output"
    return None


def _scope_task_compat_target_role(target: dict[str, Any]) -> str | None:
    if str(target.get("effective_artifact_source") or "") != "scope_task_compat":
        return None
    if target.get("artifact_trust_confirmed") is not True:
        return None
    if str(target.get("artifact_confidence") or "") != "high":
        return None
    role = str(target.get("artifact_role") or "")
    candidate_role = str(target.get("artifact_candidate_role") or target.get("path_role") or "")
    if role == "task_data" and candidate_role == SCOPE_TASK_DATA_READ_PATH_ROLE:
        return "task_data"
    if role == "task_output" and candidate_role == SCOPE_TASK_OUTPUT_PATH_ROLE:
        return "task_output"
    return None


def _effective_scope_artifact_target_role(target: dict[str, Any]) -> str | None:
    return _contract_artifact_target_role(target) or _scope_task_compat_target_role(target)


def _is_scope_task_compat_task_output_target(target: dict[str, Any]) -> bool:
    return _scope_task_compat_target_role(target) == "task_output"


def _is_broad_contract_task_output_target(target: dict[str, Any]) -> bool:
    if _contract_artifact_target_role(target) != "task_output":
        return False
    match_type = str(target.get("artifact_match_type") or "")
    return match_type in {"prefix", "glob"}


def _event_has_scope_task_compat_auxiliary_output_hint(event: CanonicalEvent) -> bool:
    text = _extract_text_for_d6(event)
    if not text.strip():
        return False
    return _SCOPE_TASK_COMPAT_AUXILIARY_OUTPUT_PATTERN.search(text) is not None


def _event_has_scope_task_compat_auxiliary_output_write_hint(event: CanonicalEvent) -> bool:
    paths = _event_write_path_candidates(event)
    if not paths:
        return False
    return any(_SCOPE_TASK_COMPAT_AUXILIARY_OUTPUT_PATTERN.search(path) for path in paths)


def _event_has_generated_script_auxiliary_output_content_hint(event: CanonicalEvent) -> bool:
    text = _extract_text_for_d6(event)
    if not text.strip():
        return False
    return _GENERATED_SCRIPT_AUXILIARY_OUTPUT_CONTENT_PATTERN.search(text) is not None


def _event_write_path_candidates(event: CanonicalEvent) -> list[str]:
    paths: list[str] = []
    paths.extend(_event_payload_explicit_write_paths(event))
    for text in _event_patch_texts_for_write_paths(event):
        for match in re.finditer(
            r"^\*\*\*\s+(?:Add|Update|Delete)\s+File:\s+(.+?)\s*$",
            text,
            re.IGNORECASE | re.MULTILINE,
        ):
            paths.append(match.group(1).strip())
    for text in _event_shell_texts_for_write_paths(event):
        for match in re.finditer(r"(?:^|[;&|]\s*)cat\b[^;&|]*?>+\s*([^\s;&|]+)", text):
            paths.append(match.group(1).strip().strip("'\""))
        for match in re.finditer(r"(?:^|[;&|]\s*)touch\s+([^\s;&|]+)", text):
            paths.append(match.group(1).strip().strip("'\""))
        for match in re.finditer(r">+\s*([^\s;&|]+)", text):
            paths.append(match.group(1).strip().strip("'\""))
        for segment in _split_shell_segments(text):
            try:
                parts = shlex.split(segment)
            except ValueError:
                continue
            if not parts:
                continue
            head = Path(parts[0]).name.lower()
            if head in {"cp", "install", "mv"}:
                operands = [part for part in parts[1:] if not part.startswith("-")]
                if len(operands) >= 2:
                    paths.append(operands[-1].strip().strip("'\""))
                continue
            if head == "tee":
                paths.extend(
                    part.strip().strip("'\"")
                    for part in parts[1:]
                    if part and not part.startswith("-")
                )
                continue
            if head == "dd":
                for part in parts[1:]:
                    if part.startswith("of=") and len(part) > 3:
                        paths.append(part[3:].strip().strip("'\""))
    for text, inline_only in _event_python_write_path_candidate_texts(event):
        paths.extend(python_write_path_candidates(text, inline_only=inline_only))
    return list(dict.fromkeys(path for path in paths if path))


def _event_payload_explicit_write_paths(event: CanonicalEvent) -> list[str]:
    payload = event.payload or {}
    paths: list[str] = []
    keys = (
        "path",
        "target_path",
        "file_path",
        "filepath",
        "destination",
        "dest",
        "output_path",
    )
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            paths.append(value)
    arguments = payload.get("arguments")
    if isinstance(arguments, dict):
        for key in keys:
            value = arguments.get(key)
            if isinstance(value, str) and value.strip():
                paths.append(value)
    return list(dict.fromkeys(paths))


def _event_patch_texts_for_write_paths(event: CanonicalEvent) -> list[str]:
    payload = event.payload or {}
    texts: list[str] = []
    for key in ("command", "cmd", "patch", "diff"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            texts.append(value)
    arguments = payload.get("arguments")
    if isinstance(arguments, dict):
        for key in ("command", "cmd", "patch", "diff"):
            value = arguments.get(key)
            if isinstance(value, str) and value.strip():
                texts.append(value)
    return list(dict.fromkeys(texts))


def _event_shell_texts_for_write_paths(event: CanonicalEvent) -> list[str]:
    payload = event.payload or {}
    texts: list[str] = []

    def add_shell_text(value: Any) -> None:
        if isinstance(value, str) and value.strip():
            texts.append(shell_command_surface(value))

    for key in ("command", "cmd"):
        add_shell_text(payload.get(key))
    arguments = payload.get("arguments")
    if isinstance(arguments, dict):
        for key in ("command", "cmd"):
            add_shell_text(arguments.get(key))
    return list(dict.fromkeys(texts))


def _event_python_write_path_candidate_texts(event: CanonicalEvent) -> list[tuple[str, bool]]:
    payload = event.payload or {}
    tool_l = str(event.tool_name or "").strip().lower()
    candidates: list[tuple[str, bool]] = []

    def add_from(mapping: dict[str, Any], keys: tuple[str, ...], *, inline_only: bool) -> None:
        for key in keys:
            value = mapping.get(key)
            if isinstance(value, str) and value.strip():
                candidates.append((value, inline_only))

    if tool_l in {"python", "python3"}:
        add_from(payload, ("command", "cmd", "script", "code"), inline_only=False)
    else:
        add_from(payload, ("command", "cmd"), inline_only=True)

    arguments = payload.get("arguments")
    if isinstance(arguments, dict):
        if tool_l in {"python", "python3"}:
            add_from(arguments, ("command", "cmd", "script", "code"), inline_only=False)
        else:
            add_from(arguments, ("command", "cmd"), inline_only=True)

    return list(dict.fromkeys(candidates))


def _effect_summary_has_primary_task_output_target(effect_summary: dict[str, Any]) -> bool:
    for target in effect_summary.get("targets") or []:
        if not isinstance(target, dict):
            continue
        if _effective_scope_artifact_target_role(target) != "task_output":
            continue
        if str(target.get("artifact_source_tier") or "") != "legacy_compat":
            return True
    return False


def _is_scope_task_compat_auxiliary_output_review_candidate(
    event: CanonicalEvent,
    effect_summary: dict[str, Any],
    *,
    risk_level: RiskLevel,
    score: float,
    routing_intents: list[ReviewRoutingIntent],
    config: DetectionConfig,
) -> bool:
    if str(config.mode or "normal").strip().lower() != "benchmark":
        return False
    if risk_level == RiskLevel.CRITICAL:
        return False
    for intent in routing_intents:
        if (
            intent.decision_affecting
            and intent.policy_action in {"block", "defer"}
            and intent.source != "fspr_package_review"
        ):
            return False

    effects = set(effect_summary.get("effects") or [])
    if "filesystem.write" not in effects:
        return False
    if effects.intersection({"network.fetch", "network.upload", "network.external"}):
        return False
    if effects and not effects.issubset(_REVIEWABLE_CONTEXTUAL_EFFECTS | {"environment.probe"}):
        return False
    if str(effect_summary.get("analysis_state") or "complete") != "complete":
        return False
    if str(effect_summary.get("confidence") or "low") not in {"medium", "high"}:
        return False
    if effect_summary.get("wrapper_chain"):
        return False
    has_auxiliary_write_hint = _event_has_scope_task_compat_auxiliary_output_write_hint(event)
    if not has_auxiliary_write_hint:
        return False

    evidence_rules = {str(rule).lower() for rule in effect_summary.get("evidence_rules") or []}
    hard_fragments = (
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
        "external_reference",
        "upload",
        "exfil",
        "task_data_write",
        "contract_violation",
    )
    if any(fragment in rule for rule in evidence_rules for fragment in hard_fragments):
        return False

    targets = list(effect_summary.get("targets") or [])
    if not targets:
        return False
    has_compat_output_target = False
    for target in targets:
        if not isinstance(target, dict):
            return False
        relation = str(target.get("workspace_relation") or "")
        role = str(target.get("path_role") or "")
        if _contract_artifact_target_role(target) == "task_output":
            if relation not in _TASK_ARTIFACT_OUTPUT_WRITE_WORKSPACE_RELATIONS:
                return False
            continue
        if _is_scope_task_compat_task_output_target(target):
            if relation not in _TASK_ARTIFACT_OUTPUT_WRITE_WORKSPACE_RELATIONS:
                return False
            has_compat_output_target = True
            continue
        if role == "capability_probe" and relation == "process_environment":
            continue
        return False
    return has_compat_output_target


def _is_scope_task_contract_auxiliary_output_review_candidate(
    event: CanonicalEvent,
    effect_summary: dict[str, Any],
    *,
    risk_level: RiskLevel,
    score: float,
    routing_intents: list[ReviewRoutingIntent],
    config: DetectionConfig,
) -> bool:
    if str(config.mode or "normal").strip().lower() != "benchmark":
        return False
    if risk_level == RiskLevel.CRITICAL:
        return False
    for intent in routing_intents:
        if (
            intent.decision_affecting
            and intent.policy_action in {"block", "defer"}
            and intent.source != "fspr_package_review"
        ):
            return False

    effects = set(effect_summary.get("effects") or [])
    if "filesystem.write" not in effects:
        return False
    if effects.intersection({"network.fetch", "network.upload", "network.external"}):
        return False
    if effects and not effects.issubset(_TASK_ARTIFACT_CONTEXTUAL_EFFECTS | {"environment.probe"}):
        return False
    if str(effect_summary.get("analysis_state") or "complete") != "complete":
        return False
    if str(effect_summary.get("confidence") or "low") not in {"medium", "high"}:
        return False
    if effect_summary.get("wrapper_chain"):
        return False
    if not _event_has_scope_task_compat_auxiliary_output_write_hint(event):
        return False

    evidence_rules = {str(rule).lower() for rule in effect_summary.get("evidence_rules") or []}
    hard_fragments = (
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
        "external_reference",
        "upload",
        "exfil",
        "task_data_write",
        "contract_violation",
    )
    if any(fragment in rule for rule in evidence_rules for fragment in hard_fragments):
        return False

    targets = list(effect_summary.get("targets") or [])
    if not targets:
        return False
    has_broad_contract_output_target = False
    for target in targets:
        if not isinstance(target, dict):
            return False
        relation = str(target.get("workspace_relation") or "")
        role = str(target.get("path_role") or "")
        contract_role = _contract_artifact_target_role(target)
        if contract_role == "task_data":
            if relation != SCOPE_TASK_DATA_WORKSPACE_RELATION:
                return False
            continue
        if contract_role == "task_output":
            if relation not in _TASK_ARTIFACT_OUTPUT_WRITE_WORKSPACE_RELATIONS:
                return False
            if (
                str(target.get("io_direction") or "") != "source"
                and _is_broad_contract_task_output_target(target)
            ):
                has_broad_contract_output_target = True
            continue
        if _is_scope_task_compat_task_output_target(target):
            if relation not in _TASK_ARTIFACT_OUTPUT_WRITE_WORKSPACE_RELATIONS:
                return False
            continue
        if role == "capability_probe" and relation == "process_environment":
            continue
        return False
    return has_broad_contract_output_target


def _event_payload_has_remote_network_reference(event: CanonicalEvent) -> bool:
    payload = event.payload or {}
    parts: list[str] = []
    for key in ("command", "patch", "diff", "content", "text", "script", "code"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            parts.append(value)
    for key in ("changes", "files", "edits"):
        value = payload.get(key)
        if not isinstance(value, list):
            continue
        for item in value:
            if not isinstance(item, dict):
                continue
            for content_key in ("content", "text", "script", "code"):
                content = item.get(content_key)
                if isinstance(content, str) and content.strip():
                    parts.append(content)
    text = "\n".join(parts)
    if not text.strip():
        return False
    namespace_urls = {
        "http://www.w3.org/1999/xhtml",
        "http://www.w3.org/1999/xlink",
        "http://www.w3.org/2000/svg",
        "http://www.w3.org/XML/1998/namespace",
        "http://www.w3.org/2001/XMLSchema",
        "http://www.w3.org/2001/XMLSchema-instance",
    }
    scrubbed = text
    for namespace_url in namespace_urls:
        scrubbed = scrubbed.replace(namespace_url, "")
    local_literal = _LOCAL_WEB_RESOURCE_LITERAL_RE
    if re.search(
        rf"\b(?:fetch|EventSource|WebSocket)\s*\(\s*(?!{local_literal})",
        scrubbed,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        rf"\bimport\s*\(\s*(?!{local_literal})",
        scrubbed,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        rf"\bnew\s+(?:Worker|SharedWorker)\s*\(\s*(?!{local_literal})",
        scrubbed,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        rf"\bimportScripts\s*\(\s*(?!{local_literal})",
        scrubbed,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        rf"\bnavigator\s*\.\s*serviceWorker\s*\.\s*register\s*\(\s*(?!{local_literal})",
        scrubbed,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        rf"\bwindow\s*\.\s*open\s*\(\s*(?!{local_literal})",
        scrubbed,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        rf"\bnavigator\s*\.\s*sendBeacon\s*\(\s*(?!{local_literal})",
        scrubbed,
        re.IGNORECASE,
    ):
        return True
    if re.search(r"\bXMLHttpRequest\s*\(", scrubbed, re.IGNORECASE):
        return True
    if re.search(
        r"\b(?:open|setAttribute)\s*\([^)]*(?:url|uri|endpoint|remote|webhook|callback|upload)[^)]*\)",
        scrubbed,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        rf"\bsetAttribute\s*\(\s*['\"](?:src|href)['\"]\s*,\s*(?!{local_literal})",
        scrubbed,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        rf"\.\s*(?:src|href)\s*=\s*(?!{local_literal})",
        scrubbed,
        re.IGNORECASE,
    ):
        return True
    return re.search(
        r"\b(?:fetch|XMLHttpRequest|EventSource|WebSocket)\s*\(\s*['\"](?:https?:)?//|"
        r"\b(?:fetch|XMLHttpRequest|EventSource|WebSocket)\s*\(\s*(?:[\w$]+\.)?(?:[\w$]*(?:remote|endpoint|api|url|uri|webhook|callback|upload)[\w$]*)\b|"
        r"\b(?:fetch|XMLHttpRequest|EventSource|WebSocket)\s*\(\s*[\w$]+\s*\[\s*['\"][\w$]*(?:remote|endpoint|api|url|uri|webhook|callback|upload)[\w$]*['\"]\s*\]|"
        r"\bnavigator\s*\.\s*sendBeacon\s*\(\s*['\"](?:https?:)?//|"
        r"\bnavigator\s*\.\s*sendBeacon\s*\(\s*(?:[\w$]+\.)?(?:[\w$]*(?:remote|endpoint|api|url|uri|webhook|callback|upload)[\w$]*)\b|"
        r"\bnavigator\s*\.\s*sendBeacon\s*\(\s*[\w$]+\s*\[\s*['\"][\w$]*(?:remote|endpoint|api|url|uri|webhook|callback|upload)[\w$]*['\"]\s*\]|"
        r"\bscript\s*\.\s*src\s*=\s*['\"](?:https?:)?//|"
        r"<script\b[^>]*\bsrc\s*=\s*['\"](?:https?:)?//",
        scrubbed,
        re.IGNORECASE | re.DOTALL,
    ) is not None


def _is_scope_task_output_local_generated_script_review_candidate(
    event: CanonicalEvent,
    effect_summary: dict[str, Any],
    *,
    risk_level: RiskLevel,
    score: float,
    routing_intents: list[ReviewRoutingIntent],
    config: DetectionConfig,
) -> bool:
    if str(config.mode or "normal").strip().lower() != "benchmark":
        return False
    if risk_level == RiskLevel.CRITICAL:
        return False
    if not _is_high_or_near_high(risk_level=risk_level, score=score, config=config):
        return False
    for intent in routing_intents:
        if intent.decision_affecting and intent.policy_action in {"block", "defer"}:
            return False

    effects = set(effect_summary.get("effects") or [])
    if "filesystem.write" not in effects:
        return False
    if effects.intersection({"network.fetch", "network.upload", "network.external"}):
        return False
    if effects and not effects.issubset(_REVIEWABLE_CONTEXTUAL_EFFECTS | {"filesystem.enumerate"}):
        return False
    if str(effect_summary.get("analysis_state") or "complete") != "complete":
        return False
    if str(effect_summary.get("confidence") or "low") not in {"medium", "high"}:
        return False

    evidence_rules = {str(rule).lower() for rule in effect_summary.get("evidence_rules") or []}
    if "generated_script_future_exec" not in evidence_rules:
        return False
    if "associated_script_network_indicator" in evidence_rules:
        return False
    allowed_rules = {
        "shell_heredoc_write",
        "shell_redirection_write",
        "shell_touch_write",
        "shell_copy_write",
        "native_write_effect",
        "python_file_write",
        "dd_output_write",
        "generated_script_future_exec",
        "wrapper_chain_unresolved",
        "denied_effect_repeat",
        "shell_enumerate_probe",
        "shell_unobserved_stdin_future_exec_write",
        "dd_unobserved_future_exec_write",
        "python_unobserved_stdin_future_exec_write",
    }
    hard_fragments = (
        "credential",
        "package",
        "destructive",
        "persistence",
        "encoded_payload",
        "encoded-payload",
        "dynamic_code",
        "code_exec",
        "subprocess",
        "child_process",
        "control",
        "oracle",
        "verifier",
        "judge",
        "remote_fetch",
        "external_reference",
        "upload",
        "exfil",
        "task_data_write",
        "contract_violation",
        "network_download",
        "network_equivalent",
    )
    for rule in evidence_rules:
        if rule in allowed_rules:
            continue
        if any(fragment in rule for fragment in hard_fragments):
            return False
    if _event_payload_has_remote_network_reference(event):
        return False
    if re.search(
        r"\bsubprocess\s*\.|"
        r"\bchild_process\b|"
        r"\bos\s*\.\s*system\b|"
        r"\bpopen\s*\(|"
        r"\bProcessBuilder\b",
        _extract_text_for_d6(event),
        re.IGNORECASE,
    ):
        return False
    if _event_has_scope_task_compat_auxiliary_output_write_hint(event):
        return False

    targets = list(effect_summary.get("targets") or [])
    if not targets:
        return False
    has_output_target = False
    for target in targets:
        if not isinstance(target, dict):
            return False
        effective_role = _effective_scope_artifact_target_role(target)
        relation = str(target.get("workspace_relation") or "")
        role = str(target.get("path_role") or "")
        if effective_role == "task_data":
            if relation != SCOPE_TASK_DATA_WORKSPACE_RELATION:
                return False
            continue
        if effective_role == "task_output":
            if relation not in _TASK_ARTIFACT_OUTPUT_WRITE_WORKSPACE_RELATIONS:
                return False
            has_output_target = True
            continue
        if role == "capability_probe" and relation == "process_environment":
            continue
        return False
    return has_output_target


def _is_scope_task_auxiliary_data_copy_review_candidate(
    event: CanonicalEvent,
    effect_summary: dict[str, Any],
    *,
    risk_level: RiskLevel,
    routing_intents: list[ReviewRoutingIntent],
    config: DetectionConfig,
    context: DecisionContext | None,
) -> bool:
    if str(config.mode or "normal").strip().lower() != "benchmark":
        return False
    if risk_level == RiskLevel.CRITICAL:
        return False
    for intent in routing_intents:
        if (
            intent.decision_affecting
            and intent.policy_action in {"block", "defer"}
            and intent.source != "fspr_package_review"
        ):
            return False

    path_summary = _inline_python_task_io_path_flow_summary(event, context)
    semantic_auxiliary_copy = bool(
        (path_summary or {}).get("auxiliary_task_output_write_hint")
    )

    effects = set(effect_summary.get("effects") or [])
    if "filesystem.read" not in effects:
        return False
    if "filesystem.write" not in effects and not (
        semantic_auxiliary_copy and "command.exec" in effects
    ):
        return False
    if effects.intersection({"network.fetch", "network.upload", "network.external"}):
        return False
    allowed_effects = _TASK_ARTIFACT_CONTEXTUAL_EFFECTS | {"environment.probe"}
    if semantic_auxiliary_copy:
        allowed_effects = allowed_effects | {"command.exec"}
    if effects and not effects.issubset(allowed_effects):
        return False
    if str(effect_summary.get("analysis_state") or "complete") != "complete":
        return False
    if str(effect_summary.get("confidence") or "low") not in {"medium", "high"}:
        return False
    if effect_summary.get("wrapper_chain"):
        return False
    if not (
        _event_has_scope_task_compat_auxiliary_output_write_hint(event)
        or semantic_auxiliary_copy
    ):
        return False

    evidence_rules = {str(rule).lower() for rule in effect_summary.get("evidence_rules") or []}
    if not (
        evidence_rules.intersection({"shell_copy_write", "python_file_write", "native_write_effect"})
        or (
            semantic_auxiliary_copy
            and evidence_rules.intersection({
                "python_writer_method_unresolved",
                "python_file_read",
                "python_file_read_unresolved",
            })
        )
    ):
        return False
    allowed_semantic_rules = {
        "wrapper_chain_unresolved",
        "python_writer_method_unresolved",
        "python_file_read",
        "python_file_read_unresolved",
    }
    hard_fragments = (
        "credential",
        "network",
        "package",
        "destructive",
        "persistence",
        "encoded_payload",
        "encoded-payload",
        "dynamic_code",
        "code_exec",
        "wrapper",
        "control",
        "oracle",
        "verifier",
        "judge",
        "remote_fetch",
        "upload",
        "exfil",
        "task_data_write",
        "contract_violation",
    )
    if any(
        fragment in rule
        for rule in evidence_rules
        if not (semantic_auxiliary_copy and rule in allowed_semantic_rules)
        for fragment in hard_fragments
    ):
        return False

    has_task_data_source = False
    for source in effect_summary.get("sources") or []:
        if not isinstance(source, dict):
            return False
        if _effective_scope_artifact_target_role(source) == "task_data":
            if str(source.get("workspace_relation") or "") != SCOPE_TASK_DATA_WORKSPACE_RELATION:
                return False
            has_task_data_source = True
            continue
        return False
    if not has_task_data_source:
        for target in effect_summary.get("targets") or []:
            if not isinstance(target, dict):
                return False
            if _effective_scope_artifact_target_role(target) != "task_data":
                continue
            if str(target.get("workspace_relation") or "") != SCOPE_TASK_DATA_WORKSPACE_RELATION:
                return False
            if str(target.get("io_direction") or "") == "target":
                return False
            has_task_data_source = True
    if not has_task_data_source:
        return False

    targets = list(effect_summary.get("targets") or [])
    if not targets:
        return False
    has_auxiliary_output_target = False
    for target in targets:
        if not isinstance(target, dict):
            return False
        relation = str(target.get("workspace_relation") or "")
        role = str(target.get("path_role") or "")
        effective_role = _effective_scope_artifact_target_role(target)
        if effective_role == "task_data":
            if relation != SCOPE_TASK_DATA_WORKSPACE_RELATION:
                return False
            if str(target.get("io_direction") or "") == "target":
                return False
            continue
        if str(target.get("io_direction") or "") == "source":
            return False
        if effective_role == "task_output":
            if relation not in _TASK_ARTIFACT_OUTPUT_WRITE_WORKSPACE_RELATIONS:
                return False
            has_auxiliary_output_target = True
            continue
        if role == "capability_probe" and relation == "process_environment":
            continue
        return False
    return has_auxiliary_output_target


def _has_scope_task_artifact_relation(targets: list[Any]) -> bool:
    for target in targets:
        if not isinstance(target, dict):
            continue
        if _effective_scope_artifact_target_role(target) is None:
            continue
        relation = str(target.get("workspace_relation") or "")
        if relation in {SCOPE_TASK_DATA_WORKSPACE_RELATION, "task_output_artifact", "inside_workspace"}:
            return True
    return False


def _has_scope_task_artifact_candidacy(targets: list[Any]) -> bool:
    """True when the unresolved command's paths are all declared task-data
    reads (or stdio sinks), so contextual ineligibility metadata may be
    ignored by the unresolved-analysis downgrade gate.

    Deliberately read-side only: any task_output target, unqualified path, or
    unknown path keeps every ineligibility reason and therefore keeps the
    deterministic hard block. Write/exec-ambiguous probes (git apply, build
    tools, generated-script runs) never qualify.
    """
    saw_task_data = False
    for target in targets:
        if not isinstance(target, dict):
            return False
        if str(target.get("kind") or "") != "path":
            return False
        if str(target.get("path_hash") or "") in _STDIO_SINK_PATH_HASHES:
            continue
        candidate_role = str(target.get("artifact_candidate_role") or "")
        path_role = str(target.get("path_role") or "")
        effective_role = _effective_scope_artifact_target_role(target)
        if effective_role == "task_data" or SCOPE_TASK_DATA_READ_PATH_ROLE in {
            candidate_role,
            path_role,
        }:
            saw_task_data = True
            continue
        return False
    return saw_task_data


def _has_any_scope_task_artifact_target(targets: list[Any]) -> bool:
    """True when at least one extracted path target is a declared task
    artifact candidate (task_data read or effective, non-denied task_output).

    The unresolved-analysis downgrade gate requires this anchor as a floor:
    an unresolved command whose analysis connected to no declared artifact —
    in particular one that resolved zero path targets — carries zero
    knowledge and must keep the deterministic hard block instead of riding
    the unresolved whitelist into L2.
    """
    for target in targets:
        if not isinstance(target, dict):
            continue
        if str(target.get("kind") or "") != "path":
            continue
        if target.get("artifact_deny_reason"):
            continue
        candidate_role = str(target.get("artifact_candidate_role") or "")
        path_role = str(target.get("path_role") or "")
        if _effective_scope_artifact_target_role(target) in {"task_data", "task_output"}:
            return True
        if SCOPE_TASK_DATA_READ_PATH_ROLE in {candidate_role, path_role}:
            return True
    return False


def _is_reviewable_local_effect(
    effect_summary: dict[str, Any],
    context: DecisionContext | None,
    event: CanonicalEvent | None = None,
) -> tuple[bool, list[str]]:
    effects = set(effect_summary.get("effects") or [])
    evidence_rules = {str(rule) for rule in effect_summary.get("evidence_rules") or []}
    analysis_state = str(effect_summary.get("analysis_state") or "complete")
    confidence = str(effect_summary.get("confidence") or "low")
    wrappers = list(effect_summary.get("wrapper_chain") or [])
    targets = list(effect_summary.get("targets") or [])
    reasons: list[str] = []
    contract_target_roles = [
        _contract_artifact_target_role(target)
        for target in targets
        if isinstance(target, dict)
    ]
    contract_scoped_targets = (
        bool(contract_target_roles)
        and len(contract_target_roles) == len(targets)
        and all(role in {"task_data", "task_output"} for role in contract_target_roles)
        and "task_output" in contract_target_roles
    )

    if analysis_state != "complete":
        reasons.append(f"analysis_state:{analysis_state}")
    if wrappers:
        reasons.append("wrapper_chain_present")
    if confidence not in {"medium", "high"}:
        reasons.append(f"low_effect_confidence:{confidence}")
    for effect in sorted(effects.intersection(_NON_CLEARABLE_EFFECTS)):
        reasons.append(f"non_clearable_effect:{effect}")
    if effects and not effects.issubset(_REVIEWABLE_CONTEXTUAL_EFFECTS):
        reasons.append("effect_not_reviewable_local")
    for rule_id in sorted(evidence_rules):
        if _task_artifact_contextual_rule_disqualifies(
            rule_id,
            contract_scoped_targets=contract_scoped_targets,
        ):
            reasons.append(f"disqualifying_rule:{rule_id}")

    allowed_roles = {
        "future_execution.artifact",
        "generated_artifact",
        "ver" "ifier_artifact",
        "workspace_file",
        "workspace_directory",
        "document_input",
        "source",
        "input",
        SCOPE_TASK_DATA_READ_PATH_ROLE,
        SCOPE_TASK_OUTPUT_PATH_ROLE,
    }
    for target in targets:
        if not isinstance(target, dict):
            continue
        role = str(target.get("path_role") or "")
        candidate_role = str(target.get("artifact_candidate_role") or "")
        if (
            candidate_role in {SCOPE_TASK_DATA_READ_PATH_ROLE, SCOPE_TASK_OUTPUT_PATH_ROLE}
            and _effective_scope_artifact_target_role(target) is None
        ):
            reasons.append(f"unqualified_task_artifact_candidate:{candidate_role}")
            continue
        if role in {SCOPE_TASK_DATA_READ_PATH_ROLE, SCOPE_TASK_OUTPUT_PATH_ROLE}:
            if _effective_scope_artifact_target_role(target) is None:
                reasons.append(f"unqualified_task_artifact_role:{role}")
            continue
        if role and role not in allowed_roles:
            reasons.append(f"unsupported_target_role:{role}")
        workspace_relation = str(target.get("workspace_relation") or "")
        if workspace_relation == "outside_workspace_or_absolute":
            reasons.append(f"workspace_relation:{workspace_relation}")
    has_inside_workspace_target = any(
        isinstance(target, dict)
        and str(target.get("workspace_relation") or "") == "inside_workspace"
        for target in targets
    )

    payload = event.payload if event is not None else {}
    cwd = _payload_effective_cwd(payload or {})
    if cwd:
        cwd_path = Path(cwd).expanduser()
        if ".." in cwd_path.parts:
            reasons.append("cwd_outside_workspace")
        elif (
            cwd_path.is_absolute()
            and not (cwd_path == Path("/workspace") or cwd_path.is_relative_to(Path("/workspace")))
            and not has_inside_workspace_target
            and not _has_scope_task_artifact_relation(targets)
        ):
            reasons.append("cwd_outside_workspace")

    summary = context.session_risk_summary if context is not None else None
    if isinstance(summary, dict) and summary.get("task_scope_path_escape"):
        reasons.append("task_scope_path_escape")

    return not reasons, reasons


_SHELL_AVAILABILITY_PROBE_COMMANDS = frozenset({"command", "which", "type"})
_SHELL_VERSION_PROBE_FLAGS = frozenset({"--help", "-h", "--version", "-V", "-VV", "-v"})


def _shell_tokens_without_redirects(tokens: list[str]) -> list[str]:
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


def _is_simple_shell_command_name(value: str) -> bool:
    cleaned = _clean_shell_path(value)
    return bool(re.fullmatch(r"[A-Za-z0-9_.+-]+", cleaned))


def _is_simple_tool_probe_name(value: str) -> bool:
    cleaned = _clean_shell_path(value)
    return bool(re.fullmatch(r"[A-Za-z0-9_.+@:-]+", cleaned))


def _is_shell_availability_probe_segment(tokens: list[str]) -> bool:
    cleaned = _shell_tokens_without_redirects(tokens)
    if not cleaned:
        return False
    raw_command = _clean_shell_path(cleaned[0])
    if not _is_simple_shell_command_name(raw_command):
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
        not token.startswith("-") and _is_simple_tool_probe_name(token)
        for token in args
    )


def _is_shell_version_probe_segment(tokens: list[str]) -> bool:
    cleaned = _shell_tokens_without_redirects(tokens)
    if len(cleaned) < 2:
        return False
    raw_command = _clean_shell_path(cleaned[0])
    if not _is_simple_shell_command_name(raw_command):
        return False
    args = cleaned[1:]
    return any(token in _SHELL_VERSION_PROBE_FLAGS for token in args) and all(
        token in _SHELL_VERSION_PROBE_FLAGS for token in args
    )


def _is_command_availability_probe_event(event: CanonicalEvent | None) -> bool:
    payload = event.payload if event is not None else {}
    command = str((payload or {}).get("command") or (payload or {}).get("input") or "").strip()
    if not command:
        return False
    segments = _split_shell_segments(command)
    if not segments:
        return False
    for segment in segments:
        tokens = _shell_tokens(segment)
        if not tokens:
            return False
        if _is_shell_availability_probe_segment(tokens):
            continue
        if _is_shell_version_probe_segment(tokens):
            continue
        return False
    return True


def _is_process_environment_probe_only(
    effect_summary: dict[str, Any],
    *,
    event: CanonicalEvent | None,
) -> bool:
    effects = set(effect_summary.get("effects") or [])
    if effects != {"environment.probe"}:
        return False
    targets = list(effect_summary.get("targets") or [])
    if not targets:
        return False
    return all(
        isinstance(target, dict)
        and str(target.get("path_role") or "") == "capability_probe"
        and str(target.get("workspace_relation") or "") == "process_environment"
        for target in targets
    ) and _is_command_availability_probe_event(event)


def _is_pure_workspace_read_effect(
    effect_summary: dict[str, Any],
    *,
    event: CanonicalEvent,
    rule_hits: set[str],
    routing_intents: list[ReviewRoutingIntent],
    context: DecisionContext | None,
    dimensions: RiskDimensions,
) -> tuple[bool, list[str]]:
    effects = set(effect_summary.get("effects") or [])
    evidence_rules = {str(rule) for rule in effect_summary.get("evidence_rules") or []}
    analysis_state = str(effect_summary.get("analysis_state") or "complete")
    confidence = str(effect_summary.get("confidence") or "low")
    wrappers = list(effect_summary.get("wrapper_chain") or [])
    targets = list(effect_summary.get("targets") or [])
    reasons: list[str] = []
    process_environment_probe_only = _is_process_environment_probe_only(
        effect_summary,
        event=event,
    )

    pure_effects = {"filesystem.read", "filesystem.enumerate", "environment.probe"}
    if not effects:
        reasons.append("effect_missing")
    elif not effects.issubset(pure_effects):
        reasons.append("effect_not_pure_read")
    if analysis_state != "complete":
        reasons.append(f"analysis_state:{analysis_state}")
    if confidence not in {"medium", "high"}:
        reasons.append(f"low_effect_confidence:{confidence}")
    if wrappers:
        reasons.append("wrapper_chain_present")
    if dimensions.d6 >= 2.0:
        reasons.append("high_d6_injection_signal")
    if rule_hits.intersection(_HARD_BLOCK_RULE_HITS):
        reasons.append("hard_block_rule_present")
    if evidence_rules.intersection(_HARD_BLOCK_RULE_HITS):
        reasons.append("hard_block_effect_rule_present")
    for rule_id in sorted(evidence_rules):
        lowered = rule_id.lower()
        if any(fragment in lowered for fragment in _CONTEXTUAL_DISQUALIFYING_RULE_FRAGMENTS):
            reasons.append(f"disqualifying_rule:{rule_id}")
    for intent in routing_intents:
        if intent.decision_affecting and intent.policy_action in {"block", "defer"}:
            reasons.append(f"decision_affecting_route:{intent.source}")

    allowed_roles = {"workspace_file", "workspace_directory", "capability_probe"}
    allowed_workspace_relations = {"inside_workspace", "process_environment"}
    for target in targets:
        if not isinstance(target, dict):
            reasons.append("malformed_target")
            continue
        deny_reason = str(target.get("artifact_deny_reason") or "")
        redline_reason = str(target.get("scope_task_fallback_blocked_by_redline_reason") or "")
        if deny_reason or redline_reason:
            reasons.append(f"target_redline:{deny_reason or redline_reason}")
        role = str(target.get("path_role") or "")
        if role and role not in allowed_roles:
            reasons.append(f"unsupported_target_role:{role}")
        workspace_relation = str(target.get("workspace_relation") or "")
        if workspace_relation and workspace_relation not in allowed_workspace_relations:
            reasons.append(f"workspace_relation:{workspace_relation}")
    has_inside_workspace_target = any(
        isinstance(target, dict)
        and str(target.get("workspace_relation") or "") == "inside_workspace"
        for target in targets
    )

    summary = context.session_risk_summary if context is not None else None
    if isinstance(summary, dict):
        if summary.get("blocked_skill_lineage_match") or summary.get("blocked_skill_lineage_facts"):
            reasons.append("blocked_skill_lineage")
        if (
            summary.get("prior_fspr_hard_block")
            and not has_inside_workspace_target
            and not process_environment_probe_only
        ):
            reasons.append("prior_fspr_hard_block")
        if summary.get("task_scope_path_escape"):
            reasons.append("task_scope_path_escape")
    payload = event.payload if event is not None else {}
    cwd = _payload_effective_cwd(payload or {})
    if cwd:
        cwd_path = Path(cwd).expanduser()
        if ".." in cwd_path.parts:
            reasons.append("cwd_outside_workspace")
        elif (
            cwd_path.is_absolute()
            and not (cwd_path == Path("/workspace") or cwd_path.is_relative_to(Path("/workspace")))
            and not has_inside_workspace_target
            and not process_environment_probe_only
        ):
            reasons.append("cwd_outside_workspace")
    if set(_content_evidence_rule_ids(context)):
        reasons.append("content_evidence_present")

    return not reasons, reasons


def _context_has_prior_fspr_block(context: DecisionContext | None) -> bool:
    summary = context.session_risk_summary if context is not None else None
    if not isinstance(summary, dict):
        return False
    return bool(summary.get("prior_fspr_hard_block") or summary.get("blocked_skill_lineage_facts"))


def _command_references_relative_skill_package_entrypoint(command: str) -> bool:
    for segment in _split_shell_segments(command):
        for token in _shell_tokens(segment):
            cleaned = _clean_shell_path(token).replace("\\", "/")
            lowered = cleaned.lower().lstrip("./")
            if cleaned.startswith(("/", "~")) or lowered.startswith("../"):
                continue
            if lowered == "skill.md":
                return True
            if lowered.startswith(("scripts/", "references/")):
                return True
    return False


def _command_starts_unbounded_interactive_shell(command: str) -> bool:
    interactive_flags = {"-i", "-l", "--login"}
    for segment in _split_shell_segments(command):
        tokens = _shell_tokens(segment)
        if not tokens:
            continue
        head = _command_name(tokens[0]).lower()
        if head not in {"bash", "sh", "zsh"}:
            continue
        args = [token for token in tokens[1:] if token != "--"]
        if not args:
            return True
        if all(str(arg).strip() in interactive_flags for arg in args):
            return True
    return False


def _work5c_warning_emitted(context: DecisionContext | None, config: DetectionConfig) -> bool:
    summary = context.session_risk_summary if context is not None else None
    emitted = bool(getattr(config, "work5c_warning_emitted", False))
    profile = str(getattr(config, "work5c_warning_profile_id", "") or "")
    if isinstance(summary, dict):
        emitted = emitted or bool(
            summary.get("work5c_warning_emitted")
            or summary.get("warning_emitted")
        )
        profile = str(
            summary.get("work5c_warning_profile_id")
            or summary.get("warning_profile_id")
            or profile
            or ""
        )
    return emitted and profile == WORK5C_WARNING_PROFILE_ID


def _work5c_relaxed_readonly_gate(context: DecisionContext | None, config: DetectionConfig) -> bool:
    return bool(
        getattr(config, "work5c_warning_relaxed_readonly_enabled", False)
    ) and _work5c_warning_emitted(context, config)


def _work5c_task_readonly_gate(context: DecisionContext | None, config: DetectionConfig) -> bool:
    return bool(
        getattr(config, "work5c_warning_task_readonly_enabled", False)
    ) and _work5c_warning_emitted(context, config)


def _has_fspr_provider_health_advisory_clearance(
    routing_intents: list[ReviewRoutingIntent],
) -> bool:
    for intent in routing_intents:
        if intent.source != "fspr_package_review":
            continue
        if intent.decision_affecting or intent.policy_action != "audit":
            continue
        metadata = intent.source_metadata or {}
        if metadata.get("provider_health_only") is not True:
            continue
        if metadata.get("strong_runtime_binding") is True:
            return True
        runtime_path_status = str(metadata.get("runtime_path_status") or "")
        runtime_content_status = str(metadata.get("runtime_content_status") or "")
        gateway_verified_binding = (
            metadata.get("metadata_source") == "gateway_owned_metadata"
            and bool(metadata.get("metadata_record_id"))
            and bool(metadata.get("policy_fingerprint"))
            and runtime_path_status in {"verified_source", "verified_mirror"}
            and runtime_content_status in {"content_verified", "not_applicable"}
            and metadata.get("deterministic_hard_findings") is False
        )
        if gateway_verified_binding:
            return True
    return False


def _fspr_review_finding_items(review: object) -> list[dict[str, Any]]:
    fspr_review = _validated_fspr_review(review)
    if fspr_review is None:
        return []
    findings: list[dict[str, Any]] = []
    for item in fspr_review.get("final_findings") or []:
        if isinstance(item, dict):
            findings.append(item)
    evidence_capsule = fspr_review.get("evidence_capsule")
    if isinstance(evidence_capsule, dict):
        for key in ("deterministic_findings", "external_deterministic_findings"):
            for item in evidence_capsule.get(key) or []:
                if isinstance(item, dict):
                    findings.append(item)
    for role_result in fspr_review.get("role_results") or []:
        if not isinstance(role_result, dict):
            continue
        for item in role_result.get("findings") or []:
            if isinstance(item, dict):
                findings.append(item)
    return findings


def _fspr_review_has_hard_finding_items(review: object) -> bool:
    return any(_fspr_finding_is_hard(item) for item in _fspr_review_finding_items(review))


def _skill_trust_refs_for_clearance(context: DecisionContext | None) -> list[Any]:
    if context is None:
        return []
    refs = list(getattr(context, "skill_trust_refs", None) or [])
    if refs:
        return refs
    skill_trust = getattr(context, "skill_trust", None)
    return [skill_trust] if skill_trust is not None else []


def _event_skill_manifest_paths(event: CanonicalEvent) -> list[str]:
    return [
        path for path in _event_skill_package_paths(event)
        if _is_skill_manifest_root_path(path)
    ]


def _event_skill_package_paths(
    event: CanonicalEvent,
    *,
    effect_summary: dict[str, Any] | None = None,
) -> list[str]:
    payload = event.payload or {}
    raw_values = [
        payload.get("command"),
        payload.get("input"),
        payload.get("path"),
        payload.get("file_path"),
        payload.get("target"),
    ]
    paths: list[str] = []
    for value in raw_values:
        if not isinstance(value, str) or not value.strip():
            continue
        for match in re.finditer(r"(?P<path>(?:~|/|\.{1,2}/)[A-Za-z0-9._~:/@%+\-=]+)", value):
            path = match.group("path").strip("'\"")
            if path and _is_skill_package_path(path):
                paths.append(path)
    for target in (effect_summary or {}).get("targets") or []:
        if not isinstance(target, dict):
            continue
        for key in ("path", "raw_path", "normalized_path", "target"):
            value = target.get(key)
            if isinstance(value, str) and value.strip() and _is_skill_package_path(value):
                paths.append(value.strip())
                break
    return list(dict.fromkeys(paths))


def _is_skill_package_path(path: str) -> bool:
    normalized = str(path or "").strip().strip("'\"").replace("\\", "/").lower()
    return any(
        marker in normalized
        for marker in (
            "/.codex/skills/",
            "/.claude/skills/",
            "/.agents/skills/",
            "/.gemini/skills/",
            "/.goose/skills/",
            "/skills/",
        )
    )


def _skill_manifest_identity(path: str) -> str | None:
    normalized = str(path or "").strip().strip("'\"").replace("\\", "/")
    if not _is_skill_manifest_root_path(normalized):
        return None
    parts = [part for part in normalized.split("/") if part]
    if len(parts) < 2 or parts[-1] != "SKILL.md":
        return None
    skill_name = parts[-2].strip()
    if not skill_name:
        return None
    return _skill_identity_normalize(skill_name)


def _skill_package_identity(path: str) -> str | None:
    normalized = str(path or "").strip().strip("'\"").replace("\\", "/")
    if not _is_skill_package_path(normalized):
        return None
    parts = [part for part in normalized.split("/") if part]
    for index, part in enumerate(parts[:-1]):
        if part.lower() != "skills":
            continue
        skill_name = parts[index + 1].strip()
        if skill_name:
            return _skill_identity_normalize(skill_name)
    return None


def _skill_package_root_path(path: str) -> str | None:
    normalized = str(path or "").strip().strip("'\"").replace("\\", "/")
    if not _is_skill_package_path(normalized):
        return None
    parts = normalized.split("/")
    for index, part in enumerate(parts[:-1]):
        if part.lower() != "skills":
            continue
        if index + 1 >= len(parts) or not parts[index + 1].strip():
            return None
        root = "/".join(parts[: index + 2])
        return root or None
    return None


def _skill_package_root_path_hash(path: str) -> str | None:
    root = _skill_package_root_path(path)
    if not root:
        return None
    try:
        root = str(Path(root).expanduser().resolve(strict=False))
    except OSError:
        root = str(root)
    return _contextual_path_hash(root)


def _skill_ref_identity_candidates(ref: Any) -> set[str]:
    candidates: set[str] = set()
    for value in (
        getattr(ref, "presented_name", None),
        getattr(ref, "canonical_skill_id", None),
        getattr(ref, "provenance_claim", None),
    ):
        if not isinstance(value, str) or not value.strip():
            continue
        cleaned = value.strip()
        for candidate in (
            cleaned,
            re.split(r"[:/\\]", cleaned)[-1],
        ):
            if candidate:
                candidates.add(_skill_identity_normalize(candidate))
    return {candidate for candidate in candidates if candidate}


def _manifest_paths_are_bound_to_skill_refs(paths: list[str], refs: list[Any]) -> bool:
    path_bindings: list[tuple[str, str]] = []
    for path in paths:
        identity = _skill_manifest_identity(path)
        root_hash = _skill_package_root_path_hash(path)
        if identity is None or root_hash is None:
            return False
        path_bindings.append((identity, root_hash))
    if not path_bindings:
        return False
    ref_bindings: list[tuple[set[str], str]] = []
    for ref in refs:
        runtime_root_hash = getattr(ref, "runtime_root_path_hash", None)
        if not isinstance(runtime_root_hash, str) or not runtime_root_hash.strip():
            continue
        identities = _skill_ref_identity_candidates(ref)
        if identities:
            ref_bindings.append((identities, runtime_root_hash.strip()))
    if not ref_bindings:
        return False
    for identity, root_hash in path_bindings:
        if not any(identity in identities and root_hash == ref_root_hash for identities, ref_root_hash in ref_bindings):
            return False
    return True


def _skill_package_paths_are_bound_to_skill_refs(paths: list[str], refs: list[Any]) -> bool:
    path_bindings: list[tuple[str, str]] = []
    for path in paths:
        identity = _skill_package_identity(path)
        root_hash = _skill_package_root_path_hash(path)
        if identity is None or root_hash is None:
            return False
        path_bindings.append((identity, root_hash))
    if not path_bindings:
        return False
    ref_bindings: list[tuple[set[str], str]] = []
    for ref in refs:
        runtime_root_hash = getattr(ref, "runtime_root_path_hash", None)
        if not isinstance(runtime_root_hash, str) or not runtime_root_hash.strip():
            continue
        identities = _skill_ref_identity_candidates(ref)
        if identities:
            ref_bindings.append((identities, runtime_root_hash.strip()))
    if not ref_bindings:
        return False
    for identity, root_hash in path_bindings:
        if not any(identity in identities and root_hash == ref_root_hash for identities, ref_root_hash in ref_bindings):
            return False
    return True


def _is_skill_manifest_root_path(path: str) -> bool:
    normalized = str(path or "").strip().strip("'\"").replace("\\", "/")
    lowered = normalized.lower()
    if not lowered.endswith("/skill.md"):
        return False
    return any(
        marker in lowered
        for marker in (
            "/.codex/skills/",
            "/.claude/skills/",
            "/.agents/skills/",
            "/.gemini/skills/",
            "/.goose/skills/",
            "/skills/",
        )
    )


def _has_verified_skill_manifest_read_probe_clearance(
    routing_intents: list[ReviewRoutingIntent],
) -> bool:
    for intent in routing_intents:
        if intent.source != "fspr_package_review":
            continue
        metadata = intent.source_metadata or {}
        if metadata.get("verified_skill_manifest_read_probe") is True:
            return True
    return False


def _is_verified_skill_manifest_read_probe_candidate(
    effect_summary: dict[str, Any],
    *,
    event: CanonicalEvent,
    routing_intents: list[ReviewRoutingIntent],
    context: DecisionContext | None,
    config: DetectionConfig,
) -> bool:
    if str(config.mode or "normal").strip().lower() != "benchmark":
        return False
    blocking_fspr_intent = any(
        intent.source == "fspr_package_review"
        and intent.decision_affecting
        and intent.policy_action in {"block", "defer"}
        for intent in routing_intents
    )
    for intent in routing_intents:
        if (
            intent.decision_affecting
            and intent.policy_action in {"block", "defer"}
            and intent.source != "fspr_package_review"
        ):
            return False

    effects = set(effect_summary.get("effects") or [])
    if not effects or not effects.issubset(_VERIFIED_SKILL_MANIFEST_READ_EFFECTS):
        return False
    if str(effect_summary.get("analysis_state") or "complete") != "complete":
        return False
    if str(effect_summary.get("confidence") or "low") not in {"medium", "high"}:
        return False
    if effect_summary.get("wrapper_chain"):
        return False
    evidence_rules = {str(rule) for rule in effect_summary.get("evidence_rules") or []}
    if "wrapper_chain_unresolved" in evidence_rules:
        return False

    targets = list(effect_summary.get("targets") or [])
    if not targets:
        return False
    for target in targets:
        if not isinstance(target, dict):
            return False
        if str(target.get("path_role") or "") not in _VERIFIED_SKILL_MANIFEST_READ_TARGET_ROLES:
            return False
        if str(target.get("workspace_relation") or "") not in _VERIFIED_SKILL_MANIFEST_READ_WORKSPACE_RELATIONS:
            return False

    skill_package_paths = _event_skill_package_paths(event, effect_summary=effect_summary)
    if not skill_package_paths:
        return False
    if not all(_is_skill_manifest_root_path(path) for path in skill_package_paths):
        return False
    manifest_paths = skill_package_paths

    refs = _skill_trust_refs_for_clearance(context)
    if not refs:
        return False
    if not _manifest_paths_are_bound_to_skill_refs(manifest_paths, refs):
        return False
    for ref in refs:
        if getattr(ref, "registry_status", None) != "matched":
            return False
        if getattr(ref, "metadata_source", None) != "gateway_owned_metadata":
            return False
        if not getattr(ref, "metadata_record_id", None):
            return False
        if not getattr(ref, "policy_fingerprint", None):
            return False
        if not getattr(ref, "runtime_evidence_kind", None):
            return False
        if getattr(ref, "runtime_path_status", None) not in {"verified_source", "verified_mirror"}:
            return False
        runtime_content_status = getattr(ref, "runtime_content_status", None)
        if runtime_content_status not in _VERIFIED_SKILL_MANIFEST_CONTENT_STATUSES:
            return False
        if runtime_content_status == "not_applicable" and getattr(ref, "runtime_path_status", None) != "verified_source":
            return False
        if getattr(ref, "trust_list_state", None) not in {"allowlist", "greylist"}:
            return False
        if getattr(ref, "admission_risk", None) not in {"low", "medium"}:
            return False
        review = _validated_fspr_review(getattr(ref, "first_use_package_review", None))
        if blocking_fspr_intent:
            if review is None or str(review.get("timing_mode") or "") != "pre_use_gate":
                return False
            if _fspr_review_blocks_manifest_instruction_exposure(review):
                return False
    return True


def _is_verified_skill_package_read_review_candidate(
    effect_summary: dict[str, Any],
    *,
    event: CanonicalEvent,
    routing_intents: list[ReviewRoutingIntent],
    context: DecisionContext | None,
    config: DetectionConfig,
) -> bool:
    if str(config.mode or "normal").strip().lower() != "benchmark":
        return False
    for intent in routing_intents:
        if (
            intent.decision_affecting
            and intent.policy_action in {"block", "defer"}
            and intent.source != "fspr_package_review"
        ):
            return False

    effects = set(effect_summary.get("effects") or [])
    if not effects or not effects.issubset({"filesystem.read", "filesystem.enumerate"}):
        return False
    if str(effect_summary.get("analysis_state") or "complete") != "complete":
        return False
    if str(effect_summary.get("confidence") or "low") not in {"medium", "high"}:
        return False
    if effect_summary.get("wrapper_chain"):
        return False
    evidence_rules = {str(rule).lower() for rule in effect_summary.get("evidence_rules") or []}
    if "wrapper_chain_unresolved" in evidence_rules:
        return False
    if any(
        fragment in rule
        for rule in evidence_rules
        for fragment in (
            "credential",
            "network",
            "package",
            "destructive",
            "persistence",
            "encoded_payload",
            "encoded-payload",
            "future_execution",
            "dynamic_code",
            "subprocess",
            "write",
            "upload",
            "exfil",
        )
    ):
        return False

    targets = list(effect_summary.get("targets") or [])
    if not targets:
        return False
    for target in targets:
        if not isinstance(target, dict):
            return False
        if str(target.get("path_role") or "") != "skill_package_read":
            return False
        if str(target.get("workspace_relation") or "") not in _VERIFIED_SKILL_MANIFEST_READ_WORKSPACE_RELATIONS:
            return False

    package_paths = _event_skill_package_paths(event, effect_summary=effect_summary)
    if not package_paths or not all(_is_skill_package_path(path) for path in package_paths):
        return False
    if all(_is_skill_manifest_root_path(path) for path in package_paths):
        return False
    refs = _skill_trust_refs_for_clearance(context)
    if not refs or not _skill_package_paths_are_bound_to_skill_refs(package_paths, refs):
        return False
    for ref in refs:
        if getattr(ref, "registry_status", None) != "matched":
            return False
        if getattr(ref, "metadata_source", None) != "gateway_owned_metadata":
            return False
        if not getattr(ref, "metadata_record_id", None):
            return False
        if not getattr(ref, "policy_fingerprint", None):
            return False
        if not getattr(ref, "runtime_evidence_kind", None):
            return False
        if getattr(ref, "runtime_path_status", None) not in {"verified_source", "verified_mirror"}:
            return False
        runtime_content_status = getattr(ref, "runtime_content_status", None)
        if runtime_content_status not in _VERIFIED_SKILL_MANIFEST_CONTENT_STATUSES:
            return False
        if runtime_content_status == "not_applicable" and getattr(ref, "runtime_path_status", None) != "verified_source":
            return False
        if getattr(ref, "trust_list_state", None) not in {"allowlist", "greylist"}:
            return False
        if getattr(ref, "admission_risk", None) not in {"low", "medium"}:
            return False
    return True


def _is_work5c_relaxed_readonly_candidate(
    effect_summary: dict[str, Any],
    *,
    routing_intents: list[ReviewRoutingIntent],
    context: DecisionContext | None,
    config: DetectionConfig,
) -> bool:
    if str(config.mode or "normal").strip().lower() != "benchmark":
        return False
    if not _work5c_relaxed_readonly_gate(context, config):
        return False
    has_fspr_decision_affecting_block = False
    for intent in routing_intents:
        if (
            intent.decision_affecting
            and intent.policy_action in {"block", "defer"}
            and intent.source == "fspr_package_review"
        ):
            has_fspr_decision_affecting_block = True
        if (
            intent.decision_affecting
            and intent.policy_action in {"block", "defer"}
            and intent.source != "fspr_package_review"
        ):
            return False
    effects = set(effect_summary.get("effects") or [])
    if not effects or not effects.issubset(_WORK5C_RELAXED_READONLY_EFFECTS):
        return False
    if str(effect_summary.get("analysis_state") or "complete") != "complete":
        return False
    if str(effect_summary.get("confidence") or "low") not in {"medium", "high"}:
        return False
    if effect_summary.get("wrapper_chain"):
        return False
    targets = list(effect_summary.get("targets") or [])
    if not targets:
        return False
    has_skill_package_target = False
    for target in targets:
        if not isinstance(target, dict):
            return False
        role = str(target.get("path_role") or "")
        relation = str(target.get("workspace_relation") or "")
        if role not in _WORK5C_RELAXED_READONLY_TARGET_ROLES:
            return False
        if relation not in _WORK5C_RELAXED_READONLY_WORKSPACE_RELATIONS:
            return False
        has_skill_package_target = has_skill_package_target or role == "skill_package_read"
    if not has_fspr_decision_affecting_block and not has_skill_package_target:
        return False
    return True


def _is_work5c_task_readonly_candidate(
    effect_summary: dict[str, Any],
    *,
    routing_intents: list[ReviewRoutingIntent],
    context: DecisionContext | None,
    config: DetectionConfig,
) -> bool:
    if str(config.mode or "normal").strip().lower() != "benchmark":
        return False
    if not _work5c_task_readonly_gate(context, config):
        return False
    for intent in routing_intents:
        if (
            intent.decision_affecting
            and intent.policy_action in {"block", "defer"}
            and intent.source != "fspr_package_review"
        ):
            return False
    effects = set(effect_summary.get("effects") or [])
    if not effects or not effects.issubset(_WORK5C_TASK_READONLY_EFFECTS):
        return False
    if str(effect_summary.get("analysis_state") or "complete") != "complete":
        return False
    if str(effect_summary.get("confidence") or "low") not in {"medium", "high"}:
        return False
    if effect_summary.get("wrapper_chain"):
        return False
    evidence_rules = {str(rule) for rule in effect_summary.get("evidence_rules") or []}
    if "wrapper_chain_unresolved" in evidence_rules:
        return False
    targets = list(effect_summary.get("targets") or [])
    if not targets:
        return False
    for target in targets:
        if not isinstance(target, dict):
            return False
        role = str(target.get("path_role") or "")
        relation = str(target.get("workspace_relation") or "")
        if role not in _WORK5C_TASK_READONLY_TARGET_ROLES:
            return False
        if relation not in _WORK5C_TASK_READONLY_WORKSPACE_RELATIONS:
            return False
    return True


def _is_scope_task_data_readonly_candidate(
    effect_summary: dict[str, Any],
    *,
    routing_intents: list[ReviewRoutingIntent],
    config: DetectionConfig,
) -> bool:
    if str(config.mode or "normal").strip().lower() != "benchmark":
        return False
    for intent in routing_intents:
        if (
            intent.decision_affecting
            and intent.policy_action in {"block", "defer"}
            and intent.source != "fspr_package_review"
        ):
            return False
    effects = set(effect_summary.get("effects") or [])
    if not effects or not effects.issubset(_TASK_ARTIFACT_DATA_READONLY_EFFECTS):
        return False
    if str(effect_summary.get("analysis_state") or "complete") != "complete":
        return False
    if str(effect_summary.get("confidence") or "low") not in {"medium", "high"}:
        return False
    if effect_summary.get("wrapper_chain"):
        return False
    if "wrapper_chain_unresolved" in {str(rule) for rule in effect_summary.get("evidence_rules") or []}:
        return False
    targets = list(effect_summary.get("targets") or [])
    if not targets:
        return False
    has_task_data_target = False
    for target in targets:
        if not isinstance(target, dict):
            return False
        role = str(target.get("path_role") or "")
        relation = str(target.get("workspace_relation") or "")
        if role not in _TASK_ARTIFACT_DATA_READONLY_TARGET_ROLES:
            return False
        if role == SCOPE_TASK_DATA_READ_PATH_ROLE:
            if relation != SCOPE_TASK_DATA_WORKSPACE_RELATION:
                return False
            if _effective_scope_artifact_target_role(target) != "task_data":
                return False
            has_task_data_target = True
        elif role == "capability_probe" and relation != "process_environment":
            return False
    return has_task_data_target


def _is_scope_task_output_readonly_candidate(
    effect_summary: dict[str, Any],
    *,
    routing_intents: list[ReviewRoutingIntent],
    config: DetectionConfig,
) -> bool:
    if str(config.mode or "normal").strip().lower() != "benchmark":
        return False
    for intent in routing_intents:
        if (
            intent.decision_affecting
            and intent.policy_action in {"block", "defer"}
            and intent.source != "fspr_package_review"
        ):
            return False
    effects = set(effect_summary.get("effects") or [])
    if not effects or not effects.issubset(_TASK_ARTIFACT_OUTPUT_READONLY_EFFECTS):
        return False
    if str(effect_summary.get("analysis_state") or "complete") != "complete":
        return False
    if str(effect_summary.get("confidence") or "low") not in {"medium", "high"}:
        return False
    if effect_summary.get("wrapper_chain"):
        return False
    evidence_rules = {str(rule).lower() for rule in effect_summary.get("evidence_rules") or []}
    if any(
        _task_output_write_rule_disqualifies(rule, evidence_rules)
        for rule in evidence_rules
    ):
        return False
    targets = list(effect_summary.get("targets") or [])
    if not targets:
        return False
    has_task_output_target = False
    for target in targets:
        if not isinstance(target, dict):
            return False
        role = str(target.get("path_role") or "")
        relation = str(target.get("workspace_relation") or "")
        if role not in _TASK_ARTIFACT_OUTPUT_READONLY_TARGET_ROLES:
            return False
        if role == SCOPE_TASK_OUTPUT_PATH_ROLE:
            if relation not in _TASK_ARTIFACT_OUTPUT_WRITE_WORKSPACE_RELATIONS:
                return False
            if _effective_scope_artifact_target_role(target) != "task_output":
                return False
            has_task_output_target = True
        elif role == "capability_probe" and relation != "process_environment":
            return False
    return has_task_output_target


def _is_scope_task_output_write_candidate(
    effect_summary: dict[str, Any],
    *,
    routing_intents: list[ReviewRoutingIntent],
    config: DetectionConfig,
) -> bool:
    if str(config.mode or "normal").strip().lower() != "benchmark":
        return False
    for intent in routing_intents:
        if (
            intent.decision_affecting
            and intent.policy_action in {"block", "defer"}
            and intent.source != "fspr_package_review"
        ):
            return False
    effects = set(effect_summary.get("effects") or [])
    if not effects or not effects.issubset(_TASK_ARTIFACT_OUTPUT_WRITE_EFFECTS):
        return False
    if str(effect_summary.get("analysis_state") or "complete") != "complete":
        return False
    if str(effect_summary.get("confidence") or "low") not in {"medium", "high"}:
        return False
    if effect_summary.get("wrapper_chain"):
        return False
    evidence_rules = {str(rule).lower() for rule in effect_summary.get("evidence_rules") or []}
    if any(_task_output_write_rule_disqualifies(rule, evidence_rules) for rule in evidence_rules):
        return False
    has_read_source_effect = bool(effects.intersection({"filesystem.read", "filesystem.enumerate"}))
    pure_output_directory_create = (
        effects == {"filesystem.write"}
        and "shell_directory_create" in evidence_rules
    )
    if (
        not has_read_source_effect
        and "native_write_effect" not in evidence_rules
        and not pure_output_directory_create
    ):
        return False
    targets = list(effect_summary.get("targets") or [])
    if not targets:
        return False
    has_output_target = False
    has_task_data_source = False
    has_future_exec_output = "future_execution.artifact" in effects
    for target in targets:
        if not isinstance(target, dict):
            return False
        role = str(target.get("path_role") or "")
        relation = str(target.get("workspace_relation") or "")
        io_direction = str(target.get("io_direction") or "")
        candidate_role = str(target.get("artifact_candidate_role") or "")
        effective_role = _effective_scope_artifact_target_role(target)
        if (
            effective_role == "task_data"
            and has_read_source_effect
            and relation == SCOPE_TASK_DATA_WORKSPACE_RELATION
        ):
            if io_direction and io_direction != "source":
                return False
            has_task_data_source = True
            continue
        if (
            effective_role == "task_output"
            and (
                role in _TASK_ARTIFACT_OUTPUT_WRITE_TARGET_ROLES
                or candidate_role == SCOPE_TASK_OUTPUT_PATH_ROLE
            )
            and relation in _TASK_ARTIFACT_OUTPUT_WRITE_WORKSPACE_RELATIONS
        ):
            if _artifact_source_is_repository_mutation(target):
                return False
            scope_task_compat_output = _is_scope_task_compat_task_output_target(target)
            if has_future_exec_output and not scope_task_compat_output:
                return False
            if (
                not has_read_source_effect
                and target.get("artifact_risk_adjusting") is not True
                and not scope_task_compat_output
            ):
                return False
            has_output_target = True
            continue
        return False
    return has_output_target and (not has_read_source_effect or has_task_data_source)


def _task_output_write_rule_disqualifies(
    rule: str,
    evidence_rules: set[str],
) -> bool:
    if (
        rule in {"destructive_delete", "destructive_delete_target_modeled"}
        and "destructive_delete_target_modeled" in evidence_rules
        and "destructive_delete_target_unresolved" not in evidence_rules
    ):
        return False
    return any(fragment in rule for fragment in _TASK_ARTIFACT_HARD_RULE_FRAGMENTS)


def _is_bounded_task_output_cleanup_copy(effect_summary: dict[str, Any]) -> bool:
    evidence_rules = {str(rule).lower() for rule in effect_summary.get("evidence_rules") or []}
    if not {
        "destructive_delete",
        "destructive_delete_target_modeled",
        "shell_copy_write",
    }.issubset(evidence_rules):
        return False
    if "destructive_delete_target_unresolved" in evidence_rules:
        return False
    if str(effect_summary.get("write_channel") or "") != "shell_copy":
        return False
    effects = {str(effect) for effect in effect_summary.get("effects") or []}
    if not {"filesystem.read", "filesystem.write"}.issubset(effects):
        return False

    has_task_data_source = False
    has_task_output_target = False
    for target in effect_summary.get("targets") or []:
        if not isinstance(target, dict):
            return False
        effective_role = _effective_scope_artifact_target_role(target)
        relation = str(target.get("workspace_relation") or "")
        io_direction = str(target.get("io_direction") or "")
        if effective_role == "task_data" and relation == SCOPE_TASK_DATA_WORKSPACE_RELATION:
            if io_direction and io_direction != "source":
                return False
            has_task_data_source = True
            continue
        if (
            effective_role == "task_output"
            and relation in _TASK_ARTIFACT_OUTPUT_WRITE_WORKSPACE_RELATIONS
        ):
            if io_direction == "source":
                return False
            has_task_output_target = True
            continue
        return False
    return has_task_data_source and has_task_output_target


def _is_scope_task_output_env_setup_candidate(
    effect_summary: dict[str, Any],
    *,
    routing_intents: list[ReviewRoutingIntent],
    config: DetectionConfig,
) -> bool:
    if str(config.mode or "normal").strip().lower() != "benchmark":
        return False
    for intent in routing_intents:
        if (
            intent.decision_affecting
            and intent.policy_action in {"block", "defer"}
            and intent.source != "fspr_package_review"
        ):
            return False
    effects = set(effect_summary.get("effects") or [])
    if not effects or not effects.issubset(_TASK_ARTIFACT_OUTPUT_ENV_SETUP_EFFECTS):
        return False
    if str(effect_summary.get("analysis_state") or "complete") != "complete":
        return False
    if str(effect_summary.get("confidence") or "low") not in {"medium", "high"}:
        return False
    if effect_summary.get("wrapper_chain"):
        return False
    evidence_rules = {str(rule).lower() for rule in effect_summary.get("evidence_rules") or []}
    if not evidence_rules.intersection(_TASK_ARTIFACT_OUTPUT_ENV_SETUP_RULES):
        return False
    if "wrapper_chain_unresolved" in evidence_rules:
        return False
    if "package.install" in effects and "task_output_env_setup" not in evidence_rules:
        return False
    for rule in evidence_rules:
        if rule == "package_install" and "task_output_env_setup" in evidence_rules:
            continue
        if any(
            fragment in rule
            for fragment in _TASK_ARTIFACT_CONTEXTUAL_DISQUALIFYING_RULE_FRAGMENTS
        ):
            return False
    targets = list(effect_summary.get("targets") or [])
    if not targets:
        return False
    has_task_output_target = False
    for target in targets:
        if not isinstance(target, dict):
            return False
        role = str(target.get("path_role") or "")
        relation = str(target.get("workspace_relation") or "")
        if role not in _TASK_ARTIFACT_OUTPUT_ENV_SETUP_TARGET_ROLES:
            return False
        if role == "capability_probe":
            if relation != "process_environment":
                return False
            continue
        if relation not in _TASK_ARTIFACT_OUTPUT_WRITE_WORKSPACE_RELATIONS:
            return False
        if _effective_scope_artifact_target_role(target) != "task_output":
            return False
        has_task_output_target = True
    return has_task_output_target


def _is_scope_task_local_artifact_write_candidate(
    effect_summary: dict[str, Any],
    *,
    routing_intents: list[ReviewRoutingIntent],
    config: DetectionConfig,
) -> bool:
    if str(config.mode or "normal").strip().lower() != "benchmark":
        return False
    for intent in routing_intents:
        if (
            intent.decision_affecting
            and intent.policy_action in {"block", "defer"}
            and intent.source != "fspr_package_review"
        ):
            return False
    effects = set(effect_summary.get("effects") or [])
    if not effects or not effects.issubset(_TASK_ARTIFACT_LOCAL_WRITE_EFFECTS):
        return False
    if "filesystem.write" not in effects or not effects.intersection({"filesystem.read", "filesystem.enumerate"}):
        return False
    if str(effect_summary.get("analysis_state") or "complete") != "complete":
        return False
    if str(effect_summary.get("confidence") or "low") not in {"medium", "high"}:
        return False
    if effect_summary.get("wrapper_chain"):
        return False
    evidence_rules = {str(rule).lower() for rule in effect_summary.get("evidence_rules") or []}
    if any(
        fragment in rule
        for rule in evidence_rules
        for fragment in _TASK_ARTIFACT_CONTEXTUAL_DISQUALIFYING_RULE_FRAGMENTS
    ):
        return False
    sources = list(effect_summary.get("sources") or [])
    for source in sources:
        if not isinstance(source, dict):
            return False
        if (
            _effective_scope_artifact_target_role(source) != "task_data"
            or str(source.get("workspace_relation") or "") != SCOPE_TASK_DATA_WORKSPACE_RELATION
        ):
            return False
    targets = list(effect_summary.get("targets") or [])
    if not targets:
        return False
    has_task_data_source = False
    has_local_write_target = False
    for target in targets:
        if not isinstance(target, dict):
            return False
        role = str(target.get("path_role") or "")
        relation = str(target.get("workspace_relation") or "")
        effective_role = _effective_scope_artifact_target_role(target)
        if (
            effective_role == "task_data"
            and relation == SCOPE_TASK_DATA_WORKSPACE_RELATION
        ):
            has_task_data_source = True
            continue
        if role in _TASK_ARTIFACT_LOCAL_WRITE_TARGET_ROLES:
            if relation not in _TASK_ARTIFACT_LOCAL_WRITE_WORKSPACE_RELATIONS:
                return False
            has_local_write_target = True
            continue
        return False
    return has_task_data_source and has_local_write_target


def _is_scope_task_local_artifact_execution_review_candidate(
    effect_summary: dict[str, Any],
    *,
    risk_level: RiskLevel,
    routing_intents: list[ReviewRoutingIntent],
    config: DetectionConfig,
) -> bool:
    if str(config.mode or "normal").strip().lower() != "benchmark":
        return False
    if risk_level == RiskLevel.CRITICAL:
        return False
    for intent in routing_intents:
        if (
            intent.decision_affecting
            and intent.policy_action in {"block", "defer"}
            and intent.source != "fspr_package_review"
        ):
            return False
    effects = set(effect_summary.get("effects") or [])
    if not effects or not effects.issubset(_TASK_LOCAL_ARTIFACT_EXECUTION_EFFECTS):
        return False
    if not {"command.exec", "filesystem.read", "filesystem.write"}.issubset(effects):
        return False
    if str(effect_summary.get("analysis_state") or "complete") != "complete":
        return False
    if str(effect_summary.get("confidence") or "low") not in {"medium", "high"}:
        return False
    if effect_summary.get("wrapper_chain"):
        return False
    evidence_rules = {str(rule).lower() for rule in effect_summary.get("evidence_rules") or []}
    if not _TASK_LOCAL_ARTIFACT_EXECUTION_RULES.issubset(evidence_rules):
        return False
    disqualifying_fragments = _TASK_ARTIFACT_CONTEXTUAL_DISQUALIFYING_RULE_FRAGMENTS | frozenset({
        "javaagent",
        "agentlib",
        "agentpath",
        "argfile",
    })
    for rule in evidence_rules:
        if rule in _TASK_LOCAL_ARTIFACT_EXECUTION_RULES:
            continue
        if any(fragment in rule for fragment in disqualifying_fragments):
            return False

    targets = list(effect_summary.get("targets") or [])
    if not targets:
        return False
    has_task_data_input = False
    has_task_output_execution_source = False
    has_task_output_write_target = False
    for target in targets:
        if not isinstance(target, dict):
            return False
        role = str(target.get("path_role") or "")
        relation = str(target.get("workspace_relation") or "")
        io_direction = str(target.get("io_direction") or "")
        effective_role = _effective_scope_artifact_target_role(target)
        if effective_role == "task_data":
            if (
                relation != SCOPE_TASK_DATA_WORKSPACE_RELATION
                or io_direction not in {"", "source"}
                or target.get("artifact_risk_adjusting") is not True
                or target.get("artifact_trust_confirmed") is not True
                or str(target.get("artifact_source_tier") or "") != "risk_adjusting"
                or str(target.get("artifact_confidence") or "") != "high"
            ):
                return False
            has_task_data_input = True
            continue
        if effective_role == "task_output":
            if (
                relation not in _TASK_ARTIFACT_OUTPUT_WRITE_WORKSPACE_RELATIONS
                or target.get("artifact_trust_confirmed") is not True
                or str(target.get("artifact_source_tier") or "") != "risk_adjusting"
                or str(target.get("artifact_confidence") or "") != "high"
            ):
                return False
            if io_direction == "target":
                has_task_output_write_target = True
            else:
                has_task_output_execution_source = True
            continue
        if role == "local_dependency_cache" and relation == "local_dependency_cache":
            if io_direction not in {"", "source"}:
                return False
            continue
        return False
    return has_task_data_input and has_task_output_execution_source and has_task_output_write_target


def _is_scope_task_local_maven_exec_java_review_candidate(
    effect_summary: dict[str, Any],
    *,
    risk_level: RiskLevel,
    routing_intents: list[ReviewRoutingIntent],
    config: DetectionConfig,
) -> bool:
    if str(config.mode or "normal").strip().lower() != "benchmark":
        return False
    if risk_level == RiskLevel.CRITICAL:
        return False
    for intent in routing_intents:
        if (
            intent.decision_affecting
            and intent.policy_action in {"block", "defer"}
            and intent.source != "fspr_package_review"
        ):
            return False
    effects = set(effect_summary.get("effects") or [])
    if not effects or not effects.issubset(_TASK_LOCAL_ARTIFACT_EXECUTION_EFFECTS):
        return False
    if not {"command.exec", "filesystem.read", "filesystem.write"}.issubset(effects):
        return False
    if str(effect_summary.get("analysis_state") or "complete") != "complete":
        return False
    if str(effect_summary.get("confidence") or "low") not in {"medium", "high"}:
        return False
    if effect_summary.get("wrapper_chain"):
        return False
    evidence_rules = {str(rule).lower() for rule in effect_summary.get("evidence_rules") or []}
    if not _TASK_LOCAL_MAVEN_EXEC_JAVA_RULES.issubset(evidence_rules):
        return False
    disqualifying_fragments = _TASK_ARTIFACT_CONTEXTUAL_DISQUALIFYING_RULE_FRAGMENTS | frozenset({
        "javaagent",
        "agentlib",
        "agentpath",
        "argfile",
        "exec_maven_plugin_exec",
        "exec.executable",
    })
    for rule in evidence_rules:
        if rule in _TASK_LOCAL_MAVEN_EXEC_JAVA_RULES:
            continue
        if any(fragment in rule for fragment in disqualifying_fragments):
            return False

    targets = list(effect_summary.get("targets") or [])
    if not targets:
        return False
    has_task_data_input = False
    has_task_output_execution_source = False
    has_task_output_write_target = False
    for target in targets:
        if not isinstance(target, dict):
            return False
        relation = str(target.get("workspace_relation") or "")
        io_direction = str(target.get("io_direction") or "")
        effective_role = _effective_scope_artifact_target_role(target)
        if effective_role == "task_data":
            if (
                relation != SCOPE_TASK_DATA_WORKSPACE_RELATION
                or io_direction not in {"", "source"}
                or target.get("artifact_risk_adjusting") is not True
                or target.get("artifact_trust_confirmed") is not True
                or str(target.get("artifact_source_tier") or "") != "risk_adjusting"
                or str(target.get("artifact_confidence") or "") != "high"
            ):
                return False
            has_task_data_input = True
            continue
        if effective_role == "task_output":
            if (
                relation not in _TASK_ARTIFACT_OUTPUT_WRITE_WORKSPACE_RELATIONS
                or target.get("artifact_trust_confirmed") is not True
                or str(target.get("artifact_source_tier") or "") != "risk_adjusting"
                or str(target.get("artifact_confidence") or "") != "high"
            ):
                return False
            if io_direction == "target":
                has_task_output_write_target = True
            else:
                has_task_output_execution_source = True
            continue
        return False
    return has_task_data_input and has_task_output_execution_source and has_task_output_write_target


def _is_scope_task_local_fat_jar_execution_review_candidate(
    effect_summary: dict[str, Any],
    *,
    risk_level: RiskLevel,
    routing_intents: list[ReviewRoutingIntent],
    config: DetectionConfig,
) -> bool:
    if str(config.mode or "normal").strip().lower() != "benchmark":
        return False
    if risk_level == RiskLevel.CRITICAL:
        return False
    for intent in routing_intents:
        if (
            intent.decision_affecting
            and intent.policy_action in {"block", "defer"}
            and intent.source != "fspr_package_review"
        ):
            return False
    effects = set(effect_summary.get("effects") or [])
    if not effects or not effects.issubset(_TASK_LOCAL_ARTIFACT_EXECUTION_EFFECTS):
        return False
    if not {"command.exec", "filesystem.read", "filesystem.write"}.issubset(effects):
        return False
    if str(effect_summary.get("analysis_state") or "complete") != "complete":
        return False
    if str(effect_summary.get("confidence") or "low") not in {"medium", "high"}:
        return False
    if effect_summary.get("wrapper_chain"):
        return False
    evidence_rules = {str(rule).lower() for rule in effect_summary.get("evidence_rules") or []}
    if not _TASK_LOCAL_FAT_JAR_EXECUTION_RULES.issubset(evidence_rules):
        return False
    disqualifying_fragments = _TASK_ARTIFACT_CONTEXTUAL_DISQUALIFYING_RULE_FRAGMENTS | frozenset({
        "javaagent",
        "agentlib",
        "agentpath",
        "argfile",
        "classpath",
        "module",
    })
    for rule in evidence_rules:
        if rule in _TASK_LOCAL_FAT_JAR_EXECUTION_RULES:
            continue
        if any(fragment in rule for fragment in disqualifying_fragments):
            return False

    targets = list(effect_summary.get("targets") or [])
    if not targets:
        return False
    has_task_data_input = False
    has_task_output_execution_source = False
    has_task_output_write_target = False
    for target in targets:
        if not isinstance(target, dict):
            return False
        relation = str(target.get("workspace_relation") or "")
        io_direction = str(target.get("io_direction") or "")
        effective_role = _effective_scope_artifact_target_role(target)
        if effective_role == "task_data":
            if (
                relation != SCOPE_TASK_DATA_WORKSPACE_RELATION
                or io_direction not in {"", "source"}
                or target.get("artifact_risk_adjusting") is not True
                or target.get("artifact_trust_confirmed") is not True
                or str(target.get("artifact_source_tier") or "") != "risk_adjusting"
                or str(target.get("artifact_confidence") or "") != "high"
            ):
                return False
            has_task_data_input = True
            continue
        if effective_role == "task_output":
            if (
                relation not in _TASK_ARTIFACT_OUTPUT_WRITE_WORKSPACE_RELATIONS
                or target.get("artifact_trust_confirmed") is not True
                or str(target.get("artifact_source_tier") or "") != "risk_adjusting"
                or str(target.get("artifact_confidence") or "") != "high"
            ):
                return False
            if io_direction == "target":
                has_task_output_write_target = True
            else:
                has_task_output_execution_source = True
            continue
        return False
    return has_task_data_input and has_task_output_execution_source and has_task_output_write_target


def _is_scope_task_data_write_candidate(
    effect_summary: dict[str, Any],
    *,
    config: DetectionConfig,
) -> bool:
    if str(config.mode or "normal").strip().lower() != "benchmark":
        return False
    effects = set(effect_summary.get("effects") or [])
    if "filesystem.write" not in effects:
        return False
    targets = list(effect_summary.get("targets") or [])
    if not targets:
        return False
    task_data_hashes: set[str] = set()
    task_output_hashes: set[str] = set()
    write_hashes: set[str] = set()
    for target in targets:
        if not isinstance(target, dict):
            continue
        path_hash = str(target.get("path_hash") or "")
        if not path_hash:
            continue
        role = str(target.get("path_role") or "")
        io_direction = str(target.get("io_direction") or "")
        workspace_relation = str(target.get("workspace_relation") or "")
        artifact_role = str(target.get("artifact_role") or "")
        if (
            _effective_scope_artifact_target_role(target) == "task_data"
            or (
                artifact_role == "task_data"
                and target.get("artifact_trust_confirmed") is True
                and target.get("artifact_risk_adjusting") is True
                and str(target.get("artifact_source_tier") or "") == "risk_adjusting"
                and str(target.get("artifact_confidence") or "") == "high"
            )
        ):
            task_data_hashes.add(path_hash)
        if _contract_artifact_target_role(target) == "task_output":
            task_output_hashes.add(path_hash)
        if io_direction == "source":
            continue
        if role in _TASK_ARTIFACT_WRITE_TARGET_ROLES:
            write_hashes.add(path_hash)
            continue
        if (
            io_direction == "target"
            and role not in _TASK_ARTIFACT_NON_WRITE_TARGET_ROLES
        ):
            write_hashes.add(path_hash)
            continue
        if (
            workspace_relation == SCOPE_TASK_DATA_WORKSPACE_RELATION
            and role not in _TASK_ARTIFACT_NON_WRITE_TARGET_ROLES
        ):
            write_hashes.add(path_hash)
    return bool((task_data_hashes - task_output_hashes).intersection(write_hashes))


def _is_high_or_near_high(
    *,
    risk_level: RiskLevel,
    score: float,
    config: DetectionConfig,
) -> bool:
    if risk_level == RiskLevel.HIGH:
        return True
    if risk_level == RiskLevel.MEDIUM:
        return score >= max(config.threshold_medium, config.threshold_high - _NEAR_HIGH_EPSILON)
    return False


def _is_scope_task_artifact_hardblock_review_candidate(
    effect_summary: dict[str, Any],
    *,
    risk_level: RiskLevel,
    score: float,
    routing_intents: list[ReviewRoutingIntent],
    config: DetectionConfig,
) -> bool:
    if str(config.mode or "normal").strip().lower() != "benchmark":
        return False
    if risk_level == RiskLevel.CRITICAL:
        return False
    for intent in routing_intents:
        if intent.decision_affecting and intent.policy_action in {"block", "defer"}:
            return False

    effects = set(effect_summary.get("effects") or [])
    if "filesystem.write" not in effects:
        return False
    if effects and not effects.issubset(_TASK_ARTIFACT_CONTEXTUAL_EFFECTS):
        return False
    if str(effect_summary.get("analysis_state") or "complete") != "complete":
        return False
    if str(effect_summary.get("confidence") or "low") not in {"medium", "high"}:
        return False
    if effect_summary.get("wrapper_chain"):
        return False

    evidence_rules = {str(rule).lower() for rule in effect_summary.get("evidence_rules") or []}
    if "native_write_effect" not in evidence_rules:
        return False
    if _is_scope_task_output_write_candidate(
        effect_summary,
        routing_intents=routing_intents,
        config=config,
    ):
        return False

    targets = list(effect_summary.get("targets") or [])
    if not targets:
        return False
    has_output_target = False
    for target in targets:
        if not isinstance(target, dict):
            return False
        artifact_role = _contract_artifact_target_role(target)
        if artifact_role == "task_output":
            has_output_target = True
            continue
        if artifact_role == "task_data":
            continue
        return False
    if any(
        _task_artifact_contextual_rule_disqualifies(
            rule,
            contract_scoped_targets=True,
        )
        for rule in evidence_rules
    ):
        return False
    return has_output_target


def _is_scope_task_artifact_network_content_review_candidate(
    event: CanonicalEvent,
    effect_summary: dict[str, Any],
    *,
    risk_level: RiskLevel,
    score: float,
    routing_intents: list[ReviewRoutingIntent],
    config: DetectionConfig,
) -> bool:
    if str(config.mode or "normal").strip().lower() != "benchmark":
        return False
    if risk_level == RiskLevel.CRITICAL:
        return False
    if not _is_high_or_near_high(risk_level=risk_level, score=score, config=config):
        return False
    for intent in routing_intents:
        if intent.decision_affecting and intent.policy_action in {"block", "defer"}:
            return False

    effects = set(effect_summary.get("effects") or [])
    if "filesystem.write" not in effects:
        return False
    if effects.intersection({"network.fetch", "network.upload", "network.external"}):
        return False
    if effects and not effects.issubset(_TASK_ARTIFACT_CONTEXTUAL_EFFECTS):
        return False
    if str(effect_summary.get("analysis_state") or "complete") != "complete":
        return False
    if str(effect_summary.get("confidence") or "low") not in {"medium", "high"}:
        return False
    if effect_summary.get("wrapper_chain"):
        return False

    evidence_rules = {str(rule).lower() for rule in effect_summary.get("evidence_rules") or []}
    if not {"native_write_effect", "associated_script_network_indicator"}.issubset(evidence_rules):
        return False
    if not _event_payload_has_remote_script_loader_without_code_network_sink(event):
        return False
    hard_fragments = (
        "credential",
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
        "task_data_write",
        "contract_violation",
    )
    for rule in evidence_rules:
        if rule == "associated_script_network_indicator":
            continue
        if any(fragment in rule for fragment in hard_fragments):
            return False

    targets = list(effect_summary.get("targets") or [])
    if not targets:
        return False
    has_output_target = False
    for target in targets:
        if not isinstance(target, dict):
            return False
        artifact_role = _contract_artifact_target_role(target)
        if artifact_role == "task_output":
            has_output_target = True
            continue
        if artifact_role == "task_data":
            continue
        return False
    return has_output_target


def _is_scope_task_artifact_external_reference_review_candidate(
    effect_summary: dict[str, Any],
    *,
    risk_level: RiskLevel,
    score: float,
    routing_intents: list[ReviewRoutingIntent],
    config: DetectionConfig,
) -> bool:
    if str(config.mode or "normal").strip().lower() != "benchmark":
        return False
    if risk_level == RiskLevel.CRITICAL:
        return False
    if not _is_high_or_near_high(risk_level=risk_level, score=score, config=config):
        return False
    for intent in routing_intents:
        if intent.decision_affecting and intent.policy_action in {"block", "defer"}:
            return False

    effects = set(effect_summary.get("effects") or [])
    if "filesystem.write" not in effects:
        return False
    if effects.intersection({"network.fetch", "network.upload", "network.external"}):
        return False
    if effects and not effects.issubset(_TASK_ARTIFACT_CONTEXTUAL_EFFECTS):
        return False
    if str(effect_summary.get("analysis_state") or "complete") != "complete":
        return False
    if str(effect_summary.get("confidence") or "low") not in {"medium", "high"}:
        return False
    if effect_summary.get("wrapper_chain"):
        return False

    evidence_rules = {str(rule).lower() for rule in effect_summary.get("evidence_rules") or []}
    required_rules = {"native_write_effect", "task_output_external_reference_instruction"}
    if not required_rules.issubset(evidence_rules):
        return False
    hard_fragments = (
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
        "task_data_write",
        "contract_violation",
    )
    for rule in evidence_rules:
        if rule in required_rules:
            continue
        if any(fragment in rule for fragment in hard_fragments):
            return False

    targets = list(effect_summary.get("targets") or [])
    if not targets:
        return False
    has_output_target = False
    for target in targets:
        if not isinstance(target, dict):
            return False
        artifact_role = _contract_artifact_target_role(target)
        if artifact_role == "task_output":
            has_output_target = True
            continue
        if artifact_role == "task_data":
            continue
        return False
    return has_output_target


def _static_external_asset_download_details(event: CanonicalEvent) -> dict[str, Any] | None:
    command = shell_command_surface(_event_command_surface_text(event))
    if not command.strip():
        return None
    tokens = _static_external_asset_download_tokens(command)
    if tokens is None or len(tokens) < 4:
        return None
    head = _clean_shell_path(tokens[0]).rsplit("/", 1)[-1].lower()
    if head == "curl":
        details = _static_curl_download_details(tokens)
    elif head == "wget":
        details = _static_wget_download_details(tokens)
    else:
        return None
    if details is None:
        return None
    url = str(details.get("url") or "")
    output_path = str(details.get("output_path") or "")
    if not _is_static_https_asset_url(url):
        return None
    if not _is_static_external_asset_output_path(output_path):
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
    shell_name = _clean_shell_path(tokens[0]).rsplit("/", 1)[-1].lower()
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
    inner_head = _clean_shell_path(inner_tokens[0]).rsplit("/", 1)[-1].lower()
    if inner_head not in {"curl", "wget"}:
        return None
    return inner_tokens


def _event_command_surface_text(event: CanonicalEvent) -> str:
    payload = event.payload or {}
    for key in ("command", "cmd"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value
    arguments = payload.get("arguments")
    if isinstance(arguments, dict):
        for key in ("command", "cmd"):
            value = arguments.get(key)
            if isinstance(value, str) and value.strip():
                return value
    return ""


def _static_curl_download_details(tokens: list[str]) -> dict[str, Any] | None:
    url: str | None = None
    output_path: str | None = None
    allows_redirects = False
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if not token:
            return None
        if token == "--":
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


def _static_wget_download_details(tokens: list[str]) -> dict[str, Any] | None:
    url: str | None = None
    output_path: str | None = None
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if not token:
            return None
        if token == "--":
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
    parts = PurePosixPath(cleaned).parts
    if ".." in parts:
        return False
    if _SCOPE_TASK_COMPAT_AUXILIARY_OUTPUT_PATTERN.search(cleaned):
        return False
    suffixes = tuple(PurePosixPath(cleaned).suffixes)
    return any(suffix.lower() in _STATIC_EXTERNAL_ASSET_SUFFIXES for suffix in suffixes)


def _is_scope_task_external_asset_download_review_candidate(
    event: CanonicalEvent,
    effect_summary: dict[str, Any],
    *,
    risk_level: RiskLevel,
    score: float,
    routing_intents: list[ReviewRoutingIntent],
    config: DetectionConfig,
) -> bool:
    if str(config.mode or "normal").strip().lower() != "benchmark":
        return False
    if _static_external_asset_download_details(event) is None:
        return False
    safe_shell_wrapper = _static_external_asset_download_has_safe_shell_wrapper(
        _event_command_surface_text(event)
    )
    if risk_level == RiskLevel.CRITICAL:
        return False
    for intent in routing_intents:
        if intent.decision_affecting and intent.policy_action in {"block", "defer"}:
            return False

    effects = set(effect_summary.get("effects") or [])
    if not {"network.fetch", "filesystem.write"}.issubset(effects):
        return False
    if effects.intersection({
        "network.upload",
        "network.external",
        "package.install",
        "future_execution.entrypoint",
        "encoded_payload.materialization",
        "delegated_effect_request",
    }):
        return False
    allowed_effects = {
        "network.fetch",
        "filesystem.write",
        "future_execution.artifact",
    }
    if safe_shell_wrapper:
        allowed_effects.add("command.exec")
    if effects and not effects.issubset(allowed_effects):
        return False
    if str(effect_summary.get("analysis_state") or "complete") != "complete":
        return False
    if str(effect_summary.get("confidence") or "low") not in {"medium", "high"}:
        return False
    if effect_summary.get("wrapper_chain") and not safe_shell_wrapper:
        return False

    evidence_rules = {str(rule).lower() for rule in effect_summary.get("evidence_rules") or []}
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

    if effect_summary.get("sources"):
        return False
    targets = list(effect_summary.get("targets") or [])
    if not targets:
        return False
    has_output_target = False
    for target in targets:
        if not isinstance(target, dict):
            return False
        if _is_static_external_asset_content_evidence_modeling_target(
            target,
            evidence_rules=evidence_rules,
        ):
            continue
        effective_role = _effective_scope_artifact_target_role(target)
        relation = str(target.get("workspace_relation") or "")
        role = str(target.get("path_role") or "")
        candidate_role = str(target.get("artifact_candidate_role") or "")
        if effective_role != "task_output":
            if _is_static_external_asset_wrapper_modeling_target(
                target,
                safe_shell_wrapper=safe_shell_wrapper,
            ):
                continue
            return False
        if relation not in _TASK_ARTIFACT_OUTPUT_WRITE_WORKSPACE_RELATIONS:
            return False
        if role not in {SCOPE_TASK_OUTPUT_PATH_ROLE, "future_execution.artifact"}:
            return False
        if candidate_role not in {"", SCOPE_TASK_OUTPUT_PATH_ROLE}:
            return False
        if (
            target.get("artifact_risk_adjusting") is not True
            or target.get("artifact_trust_confirmed") is not True
            or str(target.get("artifact_source_tier") or "") != "risk_adjusting"
            or str(target.get("artifact_confidence") or "") != "high"
            or str(target.get("effective_artifact_source") or "") not in {
                "profile_contract",
                "scope_task_compat",
            }
        ):
            return False
        has_output_target = True
    return has_output_target


def _is_static_external_asset_wrapper_modeling_target(
    target: dict[str, Any],
    *,
    safe_shell_wrapper: bool,
) -> bool:
    if not safe_shell_wrapper:
        return False
    return (
        str(target.get("path_role") or "") == "future_execution.artifact"
        and str(target.get("workspace_relation") or "") == "inside_workspace"
        and target.get("artifact_trust_confirmed") is False
        and str(target.get("artifact_deny_reason") or "")
        == "deny_override:future_execution.artifact"
    )


def _is_static_external_asset_content_evidence_modeling_target(
    target: dict[str, Any],
    *,
    evidence_rules: set[str],
) -> bool:
    return (
        "associated_script_network_indicator" in evidence_rules
        and str(target.get("kind") or "") == "content_evidence"
        and str(target.get("path_role") or "") == "executed_script"
        and str(target.get("workspace_relation") or "") == "gateway_content_evidence"
    )


def _event_payload_has_remote_script_loader_without_code_network_sink(event: CanonicalEvent) -> bool:
    payload = event.payload or {}
    parts: list[str] = []
    for key in ("command", "patch", "diff", "content", "text", "script", "code"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            parts.append(value)
    for key in ("changes", "files", "edits"):
        value = payload.get(key)
        if not isinstance(value, list):
            continue
        for item in value:
            if not isinstance(item, dict):
                continue
            for content_key in ("content", "text", "script", "code"):
                content = item.get(content_key)
                if isinstance(content, str) and content.strip():
                    parts.append(content)
    text = "\n".join(parts)
    if not text.strip():
        return False
    has_remote_script_loader = bool(
        re.search(
            r"<script\b[^>]*\bsrc\s*=\s*['\"](?:https?:)?//|"
            r"\bscript\s*\.\s*src\s*=\s*['\"](?:https?:)?//|"
            r"\bObject\s*\.\s*assign\s*\([^)]*\bscript\b[^)]*\bsrc\s*:\s*['\"](?:https?:)?//",
            text,
            re.IGNORECASE | re.DOTALL,
        )
    )
    if not has_remote_script_loader:
        return False
    return re.search(
        r"\bfetch\s*\(|"
        r"\bXMLHttpRequest\s*\(|"
        r"\bEventSource\s*\(|"
        r"\bWebSocket\s*\(|"
        r"\bnavigator\s*\.\s*sendBeacon\s*\(|"
        r"\baxios\s*\.|"
        r"\b(?:requests|httpx)\s*\.|"
        r"\burllib(?:\.request)?\s*\.|"
        r"\bhttp\.client\b|"
        r"\bsocket\s*\.|"
        r"\b(?:curl|wget|httpie?)\b|"
        r"\b__import__\s*\(\s*['\"](?:requests|httpx|urllib|socket|http\.client)['\"]\s*\)|"
        r"\bimportlib\s*\.\s*import_module\s*\(\s*['\"](?:requests|httpx|urllib|socket|http\.client)['\"]\s*\)|"
        r"\bfrom\s+(?:requests|httpx)\s+import\s+(?:get|post|put|patch|delete|request|head)\b",
        text,
        re.IGNORECASE,
    ) is None


def _is_scope_task_local_helper_future_exec_review_candidate(
    effect_summary: dict[str, Any],
    *,
    risk_level: RiskLevel,
    routing_intents: list[ReviewRoutingIntent],
    config: DetectionConfig,
) -> bool:
    if str(config.mode or "normal").strip().lower() != "benchmark":
        return False
    if risk_level == RiskLevel.CRITICAL:
        return False
    for intent in routing_intents:
        if (
            intent.decision_affecting
            and intent.policy_action in {"block", "defer"}
            and intent.source != "fspr_package_review"
        ):
            return False
    effects = set(effect_summary.get("effects") or [])
    if not {"filesystem.write", "future_execution.artifact"}.issubset(effects):
        return False
    if effects and not effects.issubset(_REVIEWABLE_CONTEXTUAL_EFFECTS):
        return False
    if str(effect_summary.get("analysis_state") or "complete") != "complete":
        return False
    if str(effect_summary.get("confidence") or "low") not in {"medium", "high"}:
        return False
    if effect_summary.get("wrapper_chain"):
        return False

    evidence_rules = {str(rule).lower() for rule in effect_summary.get("evidence_rules") or []}
    if "native_write_effect" not in evidence_rules or "generated_script_future_exec" not in evidence_rules:
        return False
    if "wrapper_chain_unresolved" in evidence_rules:
        return False
    hard_fragments = (
        "credential",
        "network",
        "package",
        "destructive",
        "persistence",
        "encoded_payload",
        "encoded-payload",
        "control",
        "oracle",
        "verifier",
        "judge",
        "remote_fetch",
        "contract_violation",
    )
    if any(fragment in rule for rule in evidence_rules for fragment in hard_fragments):
        return False

    has_task_data_source = False
    has_local_future_exec_target = False
    for target in effect_summary.get("targets") or []:
        if not isinstance(target, dict):
            return False
        role = str(target.get("path_role") or "")
        relation = str(target.get("workspace_relation") or "")
        effective_role = _effective_scope_artifact_target_role(target)
        if effective_role == "task_data" and relation == SCOPE_TASK_DATA_WORKSPACE_RELATION:
            if (
                target.get("artifact_risk_adjusting") is not True
                or target.get("artifact_trust_confirmed") is not True
                or str(target.get("artifact_source_tier") or "") != "risk_adjusting"
                or str(target.get("artifact_confidence") or "") != "high"
                or str(target.get("effective_artifact_source") or "") != "profile_contract"
            ):
                return False
            has_task_data_source = True
            continue
        if role == "future_execution.artifact" and effective_role != "task_output":
            if relation != "inside_workspace":
                return False
            has_local_future_exec_target = True
            continue
        if effective_role == "task_output" and relation in _TASK_ARTIFACT_OUTPUT_WRITE_WORKSPACE_RELATIONS:
            continue
        return False
    return has_task_data_source and has_local_future_exec_target


def _is_scope_task_data_read_content_review_candidate(
    effect_summary: dict[str, Any],
    *,
    risk_level: RiskLevel,
    routing_intents: list[ReviewRoutingIntent],
    config: DetectionConfig,
    context: DecisionContext | None,
) -> bool:
    if str(config.mode or "normal").strip().lower() != "benchmark":
        return False
    if risk_level == RiskLevel.CRITICAL:
        return False
    rule_ids = _scope_task_data_read_content_review_rule_ids(context)
    if not rule_ids:
        return False
    for intent in routing_intents:
        if (
            intent.decision_affecting
            and intent.policy_action in {"block", "defer"}
            and intent.source not in {"fspr_package_review", "content_evidence"}
        ):
            return False

    effects = set(effect_summary.get("effects") or [])
    if not effects or not effects.issubset({"filesystem.read", "filesystem.enumerate"}):
        return False
    if str(effect_summary.get("analysis_state") or "complete") != "complete":
        return False
    if str(effect_summary.get("confidence") or "low") not in {"medium", "high"}:
        return False
    if effect_summary.get("wrapper_chain"):
        return False

    evidence_rules = {str(rule).lower() for rule in effect_summary.get("evidence_rules") or []}
    allowed_rules = {
        "benchmark_task_data_readonly",
        "shell_read_probe",
        "shell_enumerate_probe",
        *{rule.lower() for rule in _TASK_DATA_READ_CONTENT_REVIEW_ALLOWED_RULES},
    }
    hard_fragments = (
        "credential",
        "network",
        "package",
        "destructive",
        "persistence",
        "encoded_payload",
        "encoded-payload",
        "control",
        "oracle",
        "verifier",
        "judge",
        "remote_fetch",
        "upload",
        "exfil",
        "write",
        "future_execution",
        "authority_override",
        "execution_or_network",
        "external_reference",
        "prompt_injection",
        "hidden_html",
        "data_uri",
        "base64",
        "zero_width",
        "bidi",
        "sensitive",
    )
    for rule in evidence_rules:
        if rule in allowed_rules:
            continue
        if any(fragment in rule for fragment in hard_fragments):
            return False

    has_task_data_source = False
    for target in effect_summary.get("targets") or []:
        if not isinstance(target, dict):
            return False
        role = str(target.get("path_role") or "")
        relation = str(target.get("workspace_relation") or "")
        effective_role = _effective_scope_artifact_target_role(target)
        if effective_role == "task_data" and relation == SCOPE_TASK_DATA_WORKSPACE_RELATION:
            if (
                target.get("artifact_risk_adjusting") is not True
                or target.get("artifact_trust_confirmed") is not True
                or str(target.get("artifact_source_tier") or "") != "risk_adjusting"
                or str(target.get("artifact_confidence") or "") != "high"
                or str(target.get("effective_artifact_source") or "") != "profile_contract"
            ):
                return False
            has_task_data_source = True
            continue
        if role == "capability_probe" and relation == "process_environment":
            continue
        return False
    return has_task_data_source


def _is_scope_task_data_document_reader_review_candidate(
    effect_summary: dict[str, Any],
    *,
    risk_level: RiskLevel,
    routing_intents: list[ReviewRoutingIntent],
    config: DetectionConfig,
    context: DecisionContext | None,
    event: CanonicalEvent,
) -> bool:
    if str(config.mode or "normal").strip().lower() != "benchmark":
        return False
    if risk_level == RiskLevel.CRITICAL:
        return False
    for intent in routing_intents:
        if (
            intent.decision_affecting
            and intent.policy_action in {"block", "defer"}
            and intent.source != "fspr_package_review"
        ):
            return False
    effects = set(effect_summary.get("effects") or [])
    if "command.exec" not in effects:
        return False
    if effects and not effects.issubset({"command.exec", "filesystem.enumerate", "filesystem.read"}):
        return False
    if str(effect_summary.get("analysis_state") or "complete") != "complete":
        return False
    if str(effect_summary.get("confidence") or "low") not in {"medium", "high"}:
        return False
    if effect_summary.get("wrapper_chain"):
        return False

    evidence_rules = {str(rule).lower() for rule in effect_summary.get("evidence_rules") or []}
    if "python_document_reader_untrusted_file_object_source" in evidence_rules:
        return False
    unresolved_document_reader = "python_document_reader_unresolved" in evidence_rules
    resolved_reader_with_task_output_verify = (
        "python_file_read" in evidence_rules
        and "task_output_local_python_verify" in evidence_rules
    )
    resolved_reader_with_task_data_readonly = (
        "python_document_reader_read" in evidence_rules
        and "python_file_read" in evidence_rules
        and "python_file_read_unresolved" in evidence_rules
    )
    resolved_reader_with_local_verify_review = (
        "python_document_reader_read" in evidence_rules
        and "python_file_read" in evidence_rules
        and "python_local_verify_unresolved" in evidence_rules
    )
    if not (
        unresolved_document_reader
        or resolved_reader_with_task_data_readonly
        or resolved_reader_with_task_output_verify
        or resolved_reader_with_local_verify_review
    ):
        return False
    allowed_rules = {
        "python_document_reader_unresolved",
        "python_document_reader_read",
        "wrapper_chain_unresolved",
        "shell_enumerate_probe",
        "python_file_read",
        "python_file_read_unresolved",
        "python_local_verify_unresolved",
        "benchmark_task_data_readonly",
        "task_output_local_python_verify",
    }
    for rule in evidence_rules:
        if rule not in allowed_rules:
            return False

    has_task_data_source = False
    has_task_output_verify_target = False
    for target in effect_summary.get("targets") or []:
        if not isinstance(target, dict):
            return False
        role = str(target.get("path_role") or "")
        relation = str(target.get("workspace_relation") or "")
        effective_role = _effective_scope_artifact_target_role(target)
        if effective_role == "task_data" and relation == SCOPE_TASK_DATA_WORKSPACE_RELATION:
            if (
                target.get("artifact_risk_adjusting") is not True
                or target.get("artifact_trust_confirmed") is not True
                or str(target.get("artifact_source_tier") or "") != "risk_adjusting"
                or str(target.get("artifact_confidence") or "") != "high"
                or str(target.get("effective_artifact_source") or "") != "profile_contract"
            ):
                return False
            has_task_data_source = True
            continue
        if (
            (
                resolved_reader_with_task_output_verify
                or resolved_reader_with_task_data_readonly
                or resolved_reader_with_local_verify_review
            )
            and _effective_scope_artifact_target_role(target) == "task_output"
            and relation in _TASK_ARTIFACT_OUTPUT_WRITE_WORKSPACE_RELATIONS
        ):
            if (
                target.get("artifact_trust_confirmed") is not True
                or str(target.get("artifact_source_tier") or "") != "risk_adjusting"
                or str(target.get("artifact_confidence") or "") != "high"
                or str(target.get("effective_artifact_source") or "") not in {
                    "profile_contract",
                    "scope_task_compat",
                }
            ):
                return False
            if resolved_reader_with_task_output_verify:
                has_task_output_verify_target = True
            continue
        if role == "capability_probe" and relation == "process_environment":
            continue
        return False
    if not has_task_data_source:
        return False
    if resolved_reader_with_task_output_verify and not has_task_output_verify_target:
        return False
    if resolved_reader_with_task_data_readonly:
        return _inline_python_path_literals_within_task_data_roots(event, context)
    if unresolved_document_reader and _inline_python_path_literals_within_task_data_roots(event, context):
        return True
    if resolved_reader_with_local_verify_review:
        return _inline_python_path_literals_within_task_data_roots(event, context)
    if resolved_reader_with_task_output_verify:
        return (
            _inline_python_path_literals_within_task_data_roots(event, context)
            or _inline_python_path_literals_within_task_artifact_roots(
                event,
                context,
                required_roles={"task_data", "task_output"},
            )
            is not None
        )
    return False


def _is_scope_task_data_python_readonly_review_candidate(
    effect_summary: dict[str, Any],
    *,
    risk_level: RiskLevel,
    routing_intents: list[ReviewRoutingIntent],
    config: DetectionConfig,
    context: DecisionContext | None,
    event: CanonicalEvent,
) -> bool:
    if str(config.mode or "normal").strip().lower() != "benchmark":
        return False
    if risk_level == RiskLevel.CRITICAL:
        return False
    for intent in routing_intents:
        if (
            intent.decision_affecting
            and intent.policy_action in {"block", "defer"}
            and intent.source != "fspr_package_review"
        ):
            return False
    effects = set(effect_summary.get("effects") or [])
    if "command.exec" not in effects:
        return False
    if effects and not effects.issubset({"command.exec", "filesystem.enumerate", "filesystem.read"}):
        return False
    if str(effect_summary.get("analysis_state") or "complete") != "complete":
        return False
    if str(effect_summary.get("confidence") or "low") not in {"medium", "high"}:
        return False
    if effect_summary.get("wrapper_chain"):
        return False

    evidence_rules = {str(rule).lower() for rule in effect_summary.get("evidence_rules") or []}
    if "python_file_read_unresolved" not in evidence_rules:
        return False
    allowed_rules = {
        "wrapper_chain_unresolved",
        "python_file_read_unresolved",
        "python_directory_enumerate",
        "python_file_read",
        "python_path_probe",
        "benchmark_task_data_readonly",
        "shell_enumerate_probe",
    }
    for rule in evidence_rules:
        if rule in allowed_rules:
            continue
        return False

    has_task_data_source = False
    for target in effect_summary.get("targets") or []:
        if not isinstance(target, dict):
            return False
        role = str(target.get("path_role") or "")
        relation = str(target.get("workspace_relation") or "")
        effective_role = _effective_scope_artifact_target_role(target)
        if effective_role == "task_data" and relation == SCOPE_TASK_DATA_WORKSPACE_RELATION:
            if (
                target.get("artifact_risk_adjusting") is not True
                or target.get("artifact_trust_confirmed") is not True
                or str(target.get("artifact_source_tier") or "") != "risk_adjusting"
                or str(target.get("artifact_confidence") or "") != "high"
                or str(target.get("effective_artifact_source") or "") != "profile_contract"
            ):
                return False
            has_task_data_source = True
            continue
        if role == "capability_probe" and relation == "process_environment":
            continue
        return False
    return has_task_data_source and _inline_python_path_literals_within_task_data_roots(event, context)


def _is_scope_task_data_to_output_python_batch_review_candidate(
    effect_summary: dict[str, Any],
    *,
    risk_level: RiskLevel,
    routing_intents: list[ReviewRoutingIntent],
    config: DetectionConfig,
    context: DecisionContext | None,
    event: CanonicalEvent,
) -> bool:
    if str(config.mode or "normal").strip().lower() != "benchmark":
        return False
    if risk_level == RiskLevel.CRITICAL:
        return False
    for intent in routing_intents:
        if (
            intent.decision_affecting
            and intent.policy_action in {"block", "defer"}
            and intent.source != "fspr_package_review"
        ):
            return False
    effects = set(effect_summary.get("effects") or [])
    if "command.exec" not in effects:
        return False
    if effects and not effects.issubset({"command.exec", "filesystem.enumerate", "filesystem.read", "filesystem.write"}):
        return False
    if str(effect_summary.get("analysis_state") or "complete") != "complete":
        return False
    if str(effect_summary.get("confidence") or "low") not in {"medium", "high"}:
        return False
    if effect_summary.get("wrapper_chain"):
        return False

    evidence_rules = {str(rule).lower() for rule in effect_summary.get("evidence_rules") or []}
    target_modelled_task_io = _effect_summary_targets_are_confirmed_task_data_to_output(
        effect_summary,
    )
    if not evidence_rules.intersection({
        "python_writer_method_unresolved",
        "python_file_read_unresolved",
        "python_document_reader_unresolved",
    }) and not ("python_path_probe" in evidence_rules and target_modelled_task_io):
        return False
    allowed_unresolved = {
        "wrapper_chain_unresolved",
        "python_writer_method_unresolved",
        "python_file_read_unresolved",
        "python_document_reader_unresolved",
        "python_directory_enumerate",
        "python_file_read",
        "python_path_probe",
        "benchmark_task_data_readonly",
        "benchmark_task_output_write",
        "destructive_delete",
        "destructive_delete_target_modeled",
    }
    hard_fragments = (
        "credential",
        "network",
        "package",
        "destructive",
        "persistence",
        "encoded_payload",
        "encoded-payload",
        "control",
        "oracle",
        "verifier",
        "judge",
        "remote_fetch",
        "upload",
        "exfil",
        "future_execution",
        "dynamic_code",
        "task_data_write",
        "contract_violation",
        "auxiliary",
        "sidecar",
        "handoff",
        "archive_member",
        "wrapper",
        "subprocess",
    )
    for rule in evidence_rules:
        if rule in allowed_unresolved:
            continue
        if (
            target_modelled_task_io
            and rule in {"destructive_delete", "destructive_delete_target_modeled"}
            and "destructive_delete_target_unresolved" not in evidence_rules
        ):
            continue
        if any(fragment in rule for fragment in hard_fragments):
            return False

    saw_profile_target = False
    for target in effect_summary.get("targets") or []:
        if not isinstance(target, dict):
            return False
        role = str(target.get("path_role") or "")
        relation = str(target.get("workspace_relation") or "")
        effective_role = _effective_scope_artifact_target_role(target)
        if effective_role in {"task_data", "task_output"}:
            if (
                target.get("artifact_risk_adjusting") is not True
                or target.get("artifact_trust_confirmed") is not True
                or str(target.get("artifact_source_tier") or "") != "risk_adjusting"
                or str(target.get("artifact_confidence") or "") != "high"
                or str(target.get("effective_artifact_source") or "") != "profile_contract"
            ):
                return False
            if effective_role == "task_data" and relation != SCOPE_TASK_DATA_WORKSPACE_RELATION:
                return False
            saw_profile_target = True
            continue
        if role == "capability_probe" and relation == "process_environment":
            continue
        return False

    path_summary = _inline_python_task_io_path_flow_summary(event, context)
    return bool(path_summary or target_modelled_task_io) and (
        saw_profile_target
        or bool((path_summary or {}).get("path_hashes_by_role"))
    )


def _scope_task_modelled_python_io_can_use_l2(
    effect_summary: dict[str, Any],
    *,
    evidence_rules: set[str],
    target_modelled_task_io: bool,
    path_summary: dict[str, Any] | None,
) -> bool:
    if path_summary is not None:
        return True
    if not target_modelled_task_io:
        return False
    effects = {str(effect) for effect in effect_summary.get("effects") or []}
    if not {"filesystem.read", "filesystem.write"}.issubset(effects):
        return False
    l3_only_rules = {
        "archive_external_reference_write",
        "archive_member_write_unresolved",
        "associated_script_network_indicator",
        "benchmark_task_data_write",
        "decode_to_file_write",
        "destructive_delete",
        "destructive_delete_target_modeled",
        "destructive_delete_target_unresolved",
        "destructive_operation",
        "package_install",
        "python_directory_enumerate",
        "task_data_copy_to_unscoped_path",
    }
    if evidence_rules.intersection(l3_only_rules):
        return False
    l3_only_fragments = (
        "credential",
        "network",
        "package",
        "persistence",
        "encoded_payload",
        "encoded-payload",
        "control",
        "oracle",
        "verifier",
        "judge",
        "remote_fetch",
        "external_reference",
        "upload",
        "exfil",
        "task_data_write",
        "contract_violation",
        "auxiliary",
        "sidecar",
        "handoff",
        "archive_member",
        "subprocess",
        "dynamic_code",
    )
    return not any(fragment in rule for rule in evidence_rules for fragment in l3_only_fragments)


def _effect_summary_targets_are_confirmed_task_data_to_output(
    effect_summary: dict[str, Any],
) -> bool:
    has_task_data = False
    has_task_output = False
    for target in effect_summary.get("targets") or []:
        if not isinstance(target, dict):
            return False
        role = str(target.get("path_role") or "")
        relation = str(target.get("workspace_relation") or "")
        effective_role = _effective_scope_artifact_target_role(target)
        if role == "capability_probe" and relation == "process_environment":
            continue
        if effective_role not in {"task_data", "task_output"}:
            return False
        if (
            target.get("artifact_risk_adjusting") is not True
            or target.get("artifact_trust_confirmed") is not True
            or str(target.get("artifact_source_tier") or "") != "risk_adjusting"
            or str(target.get("artifact_confidence") or "") != "high"
            or str(target.get("effective_artifact_source") or "") != "profile_contract"
        ):
            return False
        if effective_role == "task_data":
            if relation != SCOPE_TASK_DATA_WORKSPACE_RELATION:
                return False
            has_task_data = True
            continue
        if relation not in _TASK_ARTIFACT_OUTPUT_WRITE_WORKSPACE_RELATIONS:
            return False
        has_task_output = True
    return has_task_data and has_task_output


def _is_scope_task_archive_auxiliary_member_review_candidate(
    effect_summary: dict[str, Any],
    *,
    risk_level: RiskLevel,
    routing_intents: list[ReviewRoutingIntent],
    config: DetectionConfig,
) -> bool:
    if str(config.mode or "normal").strip().lower() != "benchmark":
        return False
    if risk_level == RiskLevel.CRITICAL:
        return False
    for intent in routing_intents:
        if (
            intent.decision_affecting
            and intent.policy_action in {"block", "defer"}
            and intent.source != "fspr_package_review"
        ):
            return False
    effects = set(effect_summary.get("effects") or [])
    if "filesystem.write" not in effects:
        return False
    if effects.intersection(_NON_CLEARABLE_EFFECTS):
        return False
    if effects and not effects.issubset(_REVIEWABLE_CONTEXTUAL_EFFECTS | {"filesystem.enumerate"}):
        return False
    if str(effect_summary.get("analysis_state") or "complete") != "complete":
        return False
    if str(effect_summary.get("confidence") or "low") not in {"medium", "high"}:
        return False
    if effect_summary.get("wrapper_chain"):
        return False

    evidence_rules = {str(rule).lower() for rule in effect_summary.get("evidence_rules") or []}
    archive_member_rules = {
        "archive_auxiliary_member_write",
        "archive_external_reference_write",
        "archive_member_write_unresolved",
    }
    if not evidence_rules.intersection(archive_member_rules):
        return False
    hard_fragments = (
        "credential",
        "network",
        "package",
        "destructive",
        "persistence",
        "encoded_payload",
        "encoded-payload",
        "control",
        "oracle",
        "verifier",
        "judge",
        "remote_fetch",
        "external_reference",
        "upload",
        "exfil",
        "future_execution",
        "dynamic_code",
        "task_data_write",
        "contract_violation",
        "wrapper",
        "subprocess",
    )
    for rule in evidence_rules:
        if rule in archive_member_rules:
            continue
        if any(fragment in rule for fragment in hard_fragments):
            return False

    has_task_output = False
    saw_profile_target = False
    for target in effect_summary.get("targets") or []:
        if not isinstance(target, dict):
            return False
        role = str(target.get("path_role") or "")
        relation = str(target.get("workspace_relation") or "")
        effective_role = _effective_scope_artifact_target_role(target)
        if role == "capability_probe" and relation == "process_environment":
            continue
        if effective_role not in {"task_data", "task_output"}:
            return False
        if (
            target.get("artifact_risk_adjusting") is not True
            or target.get("artifact_trust_confirmed") is not True
            or str(target.get("artifact_source_tier") or "") != "risk_adjusting"
            or str(target.get("artifact_confidence") or "") != "high"
            or str(target.get("effective_artifact_source") or "") != "profile_contract"
        ):
            return False
        if effective_role == "task_data" and relation != SCOPE_TASK_DATA_WORKSPACE_RELATION:
            return False
        if effective_role == "task_output":
            if relation not in _TASK_ARTIFACT_OUTPUT_WRITE_WORKSPACE_RELATIONS:
                return False
            has_task_output = True
        saw_profile_target = True
    return saw_profile_target and has_task_output


def _is_scope_task_output_atomic_replace_staging_review_candidate(
    effect_summary: dict[str, Any],
    *,
    risk_level: RiskLevel,
    routing_intents: list[ReviewRoutingIntent],
    config: DetectionConfig,
) -> bool:
    if str(config.mode or "normal").strip().lower() != "benchmark":
        return False
    if risk_level == RiskLevel.CRITICAL:
        return False
    for intent in routing_intents:
        if (
            intent.decision_affecting
            and intent.policy_action in {"block", "defer"}
            and intent.source != "fspr_package_review"
        ):
            return False
    effects = set(effect_summary.get("effects") or [])
    if "filesystem.write" not in effects:
        return False
    if effects.intersection(_NON_CLEARABLE_EFFECTS):
        return False
    if effects and not effects.issubset(_REVIEWABLE_CONTEXTUAL_EFFECTS | {"filesystem.enumerate"}):
        return False
    if str(effect_summary.get("analysis_state") or "complete") != "complete":
        return False
    if str(effect_summary.get("confidence") or "low") not in {"medium", "high"}:
        return False
    if effect_summary.get("wrapper_chain"):
        return False

    evidence_rules = {str(rule).lower() for rule in effect_summary.get("evidence_rules") or []}
    if "task_output_atomic_replace_staging" not in evidence_rules:
        return False
    hard_fragments = (
        "credential",
        "network",
        "package",
        "destructive",
        "persistence",
        "encoded_payload",
        "encoded-payload",
        "control",
        "oracle",
        "verifier",
        "judge",
        "remote_fetch",
        "external_reference",
        "upload",
        "exfil",
        "future_execution",
        "dynamic_code",
        "task_data_write",
        "contract_violation",
        "wrapper",
        "subprocess",
        "auxiliary",
        "sidecar",
        "handoff",
        "archive_member",
    )
    for rule in evidence_rules:
        if rule == "task_output_atomic_replace_staging":
            continue
        if any(fragment in rule for fragment in hard_fragments):
            return False

    has_exact_output = False
    has_derived_staging = False
    for target in effect_summary.get("targets") or []:
        if not isinstance(target, dict):
            return False
        relation = str(target.get("workspace_relation") or "")
        effective_role = _effective_scope_artifact_target_role(target)
        if effective_role == "task_data":
            if relation != SCOPE_TASK_DATA_WORKSPACE_RELATION:
                return False
            continue
        if effective_role != "task_output":
            return False
        if relation not in _TASK_ARTIFACT_OUTPUT_WRITE_WORKSPACE_RELATIONS:
            return False
        if (
            target.get("artifact_risk_adjusting") is not True
            or target.get("artifact_trust_confirmed") is not True
            or str(target.get("artifact_source_tier") or "") != "risk_adjusting"
            or str(target.get("artifact_confidence") or "") != "high"
            or str(target.get("effective_artifact_source") or "") != "profile_contract"
        ):
            return False
        match_type = str(target.get("artifact_match_type") or "")
        if match_type == "exact":
            has_exact_output = True
            continue
        if match_type == "derived_staging":
            source_metadata = target.get("artifact_source_metadata") or {}
            if not isinstance(source_metadata, dict):
                return False
            if source_metadata.get("derived_staging_relation") != "atomic_replace_source":
                return False
            has_derived_staging = True
            continue
        return False
    return has_exact_output and has_derived_staging


def _inline_python_path_literals_within_task_data_roots(
    event: CanonicalEvent,
    context: DecisionContext | None,
) -> bool:
    return _inline_python_path_literals_within_task_artifact_roots(
        event,
        context,
        required_roles={"task_data"},
    ) is not None


def _inline_python_path_literals_within_task_artifact_roots(
    event: CanonicalEvent,
    context: DecisionContext | None,
    *,
    required_roles: set[str],
) -> dict[str, Any] | None:
    roots = _confirmed_task_artifact_roots(context, roles=required_roles)
    if not roots:
        return None
    sources = _inline_python_sources_from_event(event)
    if not sources:
        return None
    saw_roles: set[str] = set()
    path_hashes_by_role: dict[str, set[str]] = {role: set() for role in required_roles}
    for source in sources:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return None
        parents = {
            child: parent
            for parent in ast.walk(tree)
            for child in ast.iter_child_nodes(parent)
        }
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            if isinstance(parents.get(node), ast.JoinedStr):
                continue
            value = node.value.strip()
            if not _python_string_literal_is_path_boundary_relevant(value):
                continue
            path = Path(value).expanduser()
            if not path.is_absolute():
                continue
            resolved = path.resolve(strict=False)
            matching_roles = {
                role
                for role, role_roots in roots.items()
                if any(_path_is_relative_to(resolved, root) for root in role_roots)
            }
            if not matching_roles:
                return None
            for role in matching_roles:
                saw_roles.add(role)
                path_hashes_by_role.setdefault(role, set()).add(_contextual_path_hash(str(resolved)))
    if not required_roles.issubset(saw_roles):
        return None
    return {
        "roles": sorted(saw_roles),
        "path_hashes_by_role": {
            role: sorted(values)
            for role, values in path_hashes_by_role.items()
            if values
        },
    }


def _inline_python_task_io_path_flow_summary(
    event: CanonicalEvent,
    context: DecisionContext | None,
) -> dict[str, Any] | None:
    roots = _confirmed_task_artifact_roots(context, roles={"task_data", "task_output"})
    if not {"task_data", "task_output"}.issubset(roots):
        return None
    sources = _inline_python_sources_from_event(event)
    if not sources:
        return None
    path_hashes_by_role: dict[str, set[str]] = {"task_data": set(), "task_output": set()}
    saw_read = False
    saw_write = False
    saw_auxiliary_task_output_write = False
    for source in sources:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return None
        result = _python_task_io_statement_paths(tree.body, {}, roots)
        if result is None:
            return None
        for role, values in result.get("path_hashes_by_role", {}).items():
            path_hashes_by_role.setdefault(role, set()).update(values)
        saw_read = saw_read or bool(result.get("saw_task_data_read"))
        saw_write = saw_write or bool(result.get("saw_task_output_write"))
        saw_auxiliary_task_output_write = (
            saw_auxiliary_task_output_write
            or bool(result.get("saw_auxiliary_task_output_write"))
        )
    if not saw_read or not saw_write:
        return None
    return {
        "roles": ["task_data", "task_output"],
        "path_hashes_by_role": {
            role: sorted(values)
            for role, values in path_hashes_by_role.items()
            if values
        },
        "auxiliary_task_output_write_hint": saw_auxiliary_task_output_write,
    }


def _python_task_io_statement_paths(
    statements: list[ast.stmt],
    bindings: dict[str, set[str]],
    roots: dict[str, list[Path]],
    safe_write_handles: set[str] | None = None,
    unsafe_callables: set[str] | None = None,
    collection_bindings: dict[str, set[str]] | None = None,
    collection_mutator_aliases: set[str] | None = None,
) -> dict[str, Any] | None:
    path_hashes_by_role: dict[str, set[str]] = {"task_data": set(), "task_output": set()}
    saw_task_data_read = False
    saw_task_output_write = False
    saw_auxiliary_task_output_write = False
    current_bindings = {key: set(values) for key, values in bindings.items()}
    current_collection_bindings = {
        key: set(values) for key, values in (collection_bindings or {}).items()
    }
    current_collection_mutator_aliases = set(collection_mutator_aliases or set())
    current_safe_write_handles = set(safe_write_handles or set())
    current_unsafe_callables = set(unsafe_callables or set())

    def merge(result: dict[str, Any] | None) -> bool:
        nonlocal saw_task_data_read, saw_task_output_write, saw_auxiliary_task_output_write
        if result is None:
            return False
        for role, values in result.get("path_hashes_by_role", {}).items():
            path_hashes_by_role.setdefault(role, set()).update(values)
        saw_task_data_read = saw_task_data_read or bool(result.get("saw_task_data_read"))
        saw_task_output_write = saw_task_output_write or bool(result.get("saw_task_output_write"))
        saw_auxiliary_task_output_write = (
            saw_auxiliary_task_output_write
            or bool(result.get("saw_auxiliary_task_output_write"))
        )
        return True

    for statement in statements:
        if isinstance(statement, (ast.Import, ast.ImportFrom)):
            _bind_python_imported_unsafe_callables(statement, current_unsafe_callables)
            continue
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            current_safe_write_handles.discard(statement.name)
            current_unsafe_callables.discard(statement.name)
            if _python_control_flow_has_collection_mutation_signal(
                statement,
                current_collection_mutator_aliases,
                set(current_collection_bindings),
            ):
                current_collection_bindings.clear()
            for header_node in _python_function_definition_header_nodes(statement):
                if not merge(
                    _python_task_io_call_paths(
                        header_node,
                        current_bindings,
                        roots,
                        current_safe_write_handles,
                        current_unsafe_callables,
                        strict_unmodeled_calls=True,
                    )
                ):
                    return None
            if not merge(
                    _python_task_io_statement_paths(
                        statement.body,
                        current_bindings,
                        roots,
                        current_safe_write_handles,
                        current_unsafe_callables,
                        current_collection_bindings,
                        current_collection_mutator_aliases,
                    )
                ):
                    return None
            continue
        if isinstance(statement, ast.ClassDef):
            current_safe_write_handles.discard(statement.name)
            current_unsafe_callables.discard(statement.name)
            if _python_control_flow_has_collection_mutation_signal(
                statement,
                current_collection_mutator_aliases,
                set(current_collection_bindings),
            ):
                current_collection_bindings.clear()
            for header_node in _python_class_definition_header_nodes(statement):
                if not merge(
                    _python_task_io_call_paths(
                        header_node,
                        current_bindings,
                        roots,
                        current_safe_write_handles,
                        current_unsafe_callables,
                        strict_unmodeled_calls=True,
                    )
                ):
                    return None
            if not merge(
                    _python_task_io_statement_paths(
                        statement.body,
                        current_bindings,
                        roots,
                        current_safe_write_handles,
                        current_unsafe_callables,
                        current_collection_bindings,
                        current_collection_mutator_aliases,
                    )
                ):
                    return None
            continue
        if isinstance(statement, ast.For):
            if _python_control_flow_has_collection_mutation_signal(
                statement,
                current_collection_mutator_aliases,
                set(current_collection_bindings),
            ):
                current_collection_bindings.clear()
            loop_safe_write_handles = set(current_safe_write_handles)
            loop_unsafe_callables = set(current_unsafe_callables)
            _invalidate_python_handle_target(statement.target, loop_safe_write_handles)
            _invalidate_python_handle_target(statement.target, current_safe_write_handles)
            _invalidate_python_handle_target(statement.target, loop_unsafe_callables)
            _invalidate_python_handle_target(statement.target, current_unsafe_callables)
            loop_bindings = _python_loop_string_bindings(
                statement.target,
                statement.iter,
                current_bindings,
                current_collection_bindings,
            )
            if loop_bindings is None:
                if not merge(
                    _python_task_io_statement_paths(
                        statement.body,
                        current_bindings,
                        roots,
                        loop_safe_write_handles,
                        loop_unsafe_callables,
                        current_collection_bindings,
                        current_collection_mutator_aliases,
                    )
                ):
                    return None
            else:
                nested_bindings = {key: set(values) for key, values in current_bindings.items()}
                nested_bindings.update(loop_bindings)
                if not merge(
                    _python_task_io_statement_paths(
                        statement.body,
                        nested_bindings,
                        roots,
                        loop_safe_write_handles,
                        loop_unsafe_callables,
                        current_collection_bindings,
                        current_collection_mutator_aliases,
                    )
                ):
                    return None
            if statement.orelse and not merge(
                _python_task_io_statement_paths(
                    statement.orelse,
                    current_bindings,
                    roots,
                    current_safe_write_handles,
                    current_unsafe_callables,
                    current_collection_bindings,
                    current_collection_mutator_aliases,
                )
            ):
                return None
            _bind_python_potential_unsafe_callables_from_statements(
                [*statement.body, *statement.orelse],
                current_bindings,
                current_unsafe_callables,
            )
            continue
        if isinstance(statement, (ast.If, ast.While)):
            if _python_control_flow_has_collection_mutation_signal(
                statement,
                current_collection_mutator_aliases,
                set(current_collection_bindings),
            ):
                current_collection_bindings.clear()
            if not merge(
                _python_task_io_call_paths(
                    statement.test,
                    current_bindings,
                    roots,
                    current_safe_write_handles,
                    current_unsafe_callables,
                )
            ):
                return None
            if not merge(
                _python_task_io_statement_paths(
                    statement.body,
                    current_bindings,
                    roots,
                    current_safe_write_handles,
                    current_unsafe_callables,
                    current_collection_bindings,
                    current_collection_mutator_aliases,
                )
            ):
                return None
            if statement.orelse and not merge(
                _python_task_io_statement_paths(
                    statement.orelse,
                    current_bindings,
                    roots,
                    current_safe_write_handles,
                    current_unsafe_callables,
                    current_collection_bindings,
                    current_collection_mutator_aliases,
                )
            ):
                return None
            _bind_python_potential_unsafe_callables_from_statements(
                [*statement.body, *statement.orelse],
                current_bindings,
                current_unsafe_callables,
            )
            continue
        if isinstance(statement, (ast.With, ast.AsyncWith)):
            if _python_control_flow_has_collection_mutation_signal(
                statement,
                current_collection_mutator_aliases,
                set(current_collection_bindings),
            ):
                current_collection_bindings.clear()
            nested_safe_write_handles = set(current_safe_write_handles)
            nested_unsafe_callables = set(current_unsafe_callables)
            for item in statement.items:
                _invalidate_python_handle_target(item.optional_vars, nested_safe_write_handles)
                _invalidate_python_handle_target(item.optional_vars, nested_unsafe_callables)
                if not merge(
                    _python_task_io_call_paths(
                        item.context_expr,
                        current_bindings,
                        roots,
                        nested_safe_write_handles,
                        nested_unsafe_callables,
                    )
                ):
                    return None
                if _python_expr_is_task_output_write_handle(item.context_expr, current_bindings, roots):
                    _bind_python_handle_target(item.optional_vars, nested_safe_write_handles)
            if not merge(
                _python_task_io_statement_paths(
                    statement.body,
                    current_bindings,
                    roots,
                    nested_safe_write_handles,
                    nested_unsafe_callables,
                    current_collection_bindings,
                    current_collection_mutator_aliases,
                )
            ):
                return None
            _bind_python_potential_unsafe_callables_from_statements(
                statement.body,
                current_bindings,
                current_unsafe_callables,
            )
            continue

        call_result = _python_task_io_call_paths(
            statement,
            current_bindings,
            roots,
            current_safe_write_handles,
            current_unsafe_callables,
        )
        if not merge(call_result):
            return None
        _invalidate_python_collection_mutations(
            statement,
            current_collection_bindings,
            current_collection_mutator_aliases,
        )
        _bind_python_unsafe_container_mutations(
            statement,
            current_bindings,
            current_unsafe_callables,
        )
        if isinstance(statement, ast.Assign):
            for target in statement.targets:
                _invalidate_python_handle_target(target, current_safe_write_handles)
                _invalidate_python_handle_target(target, current_unsafe_callables)
            if _python_expr_is_collection_mutator_alias_value(statement.value):
                for target in statement.targets:
                    _bind_python_collection_mutator_alias_target(
                        target,
                        current_collection_mutator_aliases,
                    )
                _invalidate_bound_collection_mutator_receiver(
                    statement.value,
                    current_collection_bindings,
                )
            else:
                for target in statement.targets:
                    _invalidate_python_collection_mutator_alias_target(
                        target,
                        current_collection_mutator_aliases,
                    )
            if _python_expr_is_task_output_write_handle(statement.value, current_bindings, roots):
                for target in statement.targets:
                    _bind_python_handle_target(target, current_safe_write_handles)
            if _python_expr_is_unmodeled_mutation_callable(
                statement.value,
                current_bindings,
                current_unsafe_callables,
            ):
                for target in statement.targets:
                    _bind_python_handle_target(target, current_unsafe_callables)
                    _bind_python_subscript_container_target(target, current_unsafe_callables)
            value_strings = _python_string_expr_values(statement.value, current_bindings)
            if value_strings is not None:
                for target in statement.targets:
                    _bind_python_string_target(target, value_strings, current_bindings)
                    _invalidate_python_string_collection_target(target, current_collection_bindings)
            else:
                value_collection = _python_string_collection_values(
                    statement.value,
                    current_bindings,
                    current_collection_bindings,
                )
                if value_collection is not None:
                    for target in statement.targets:
                        _invalidate_python_string_target(target, current_bindings)
                        _bind_python_string_collection_target(
                            target,
                            value_collection,
                            current_collection_bindings,
                        )
                else:
                    for target in statement.targets:
                        _invalidate_python_string_target(target, current_bindings)
                        _invalidate_python_string_collection_target(
                            target,
                            current_collection_bindings,
                        )
        elif isinstance(statement, ast.AnnAssign):
            if statement.value is not None:
                _invalidate_python_handle_target(statement.target, current_safe_write_handles)
                _invalidate_python_handle_target(statement.target, current_unsafe_callables)
                if _python_expr_is_collection_mutator_alias_value(statement.value):
                    _bind_python_collection_mutator_alias_target(
                        statement.target,
                        current_collection_mutator_aliases,
                    )
                    _invalidate_bound_collection_mutator_receiver(
                        statement.value,
                        current_collection_bindings,
                    )
                else:
                    _invalidate_python_collection_mutator_alias_target(
                        statement.target,
                        current_collection_mutator_aliases,
                    )
                if _python_expr_is_task_output_write_handle(statement.value, current_bindings, roots):
                    _bind_python_handle_target(statement.target, current_safe_write_handles)
                if _python_expr_is_unmodeled_mutation_callable(
                    statement.value,
                    current_bindings,
                    current_unsafe_callables,
                ):
                    _bind_python_handle_target(statement.target, current_unsafe_callables)
                    _bind_python_subscript_container_target(statement.target, current_unsafe_callables)
                value_strings = _python_string_expr_values(statement.value, current_bindings)
                if value_strings is not None:
                    _bind_python_string_target(statement.target, value_strings, current_bindings)
                    _invalidate_python_string_collection_target(
                        statement.target,
                        current_collection_bindings,
                    )
                else:
                    value_collection = _python_string_collection_values(
                        statement.value,
                        current_bindings,
                        current_collection_bindings,
                    )
                    if value_collection is not None:
                        _invalidate_python_string_target(statement.target, current_bindings)
                        _bind_python_string_collection_target(
                            statement.target,
                            value_collection,
                            current_collection_bindings,
                        )
                    else:
                        _invalidate_python_string_target(statement.target, current_bindings)
                        _invalidate_python_string_collection_target(
                            statement.target,
                            current_collection_bindings,
                        )
        elif isinstance(statement, ast.AugAssign):
            _invalidate_python_handle_target(statement.target, current_safe_write_handles)
            _invalidate_python_handle_target(statement.target, current_unsafe_callables)
            _invalidate_python_string_target(statement.target, current_bindings)
            _invalidate_python_string_collection_target(statement.target, current_collection_bindings)
            _invalidate_python_collection_mutator_alias_target(
                statement.target,
                current_collection_mutator_aliases,
            )
            if _python_expr_is_unmodeled_mutation_callable(
                statement.value,
                current_bindings,
                current_unsafe_callables,
            ):
                _bind_python_handle_target(statement.target, current_unsafe_callables)
                _bind_python_subscript_container_target(statement.target, current_unsafe_callables)
        elif isinstance(statement, ast.Delete):
            for target in statement.targets:
                _invalidate_python_string_target(target, current_bindings)
                _invalidate_python_string_collection_target(target, current_collection_bindings)
                _invalidate_python_collection_mutator_alias_target(
                    target,
                    current_collection_mutator_aliases,
                )

    return {
        "saw_task_data_read": saw_task_data_read,
        "saw_task_output_write": saw_task_output_write,
        "saw_auxiliary_task_output_write": saw_auxiliary_task_output_write,
        "path_hashes_by_role": path_hashes_by_role,
    }


def _python_function_definition_header_nodes(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[ast.AST]:
    header_nodes: list[ast.AST] = list(node.decorator_list)
    args = node.args
    header_nodes.extend(args.defaults)
    header_nodes.extend(default for default in args.kw_defaults if default is not None)
    header_nodes.extend(
        arg.annotation
        for arg in [*args.posonlyargs, *args.args, *args.kwonlyargs]
        if arg.annotation is not None
    )
    if args.vararg is not None and args.vararg.annotation is not None:
        header_nodes.append(args.vararg.annotation)
    if args.kwarg is not None and args.kwarg.annotation is not None:
        header_nodes.append(args.kwarg.annotation)
    if node.returns is not None:
        header_nodes.append(node.returns)
    return header_nodes


def _python_class_definition_header_nodes(node: ast.ClassDef) -> list[ast.AST]:
    header_nodes: list[ast.AST] = []
    header_nodes.extend(node.decorator_list)
    header_nodes.extend(node.bases)
    header_nodes.extend(keyword.value for keyword in node.keywords)
    return header_nodes


_PYTHON_UNSAFE_IMPORT_MEMBERS: dict[str, frozenset[str]] = {
    "os": frozenset({
        "chflags",
        "chmod",
        "chown",
        "copy_file_range",
        "fchmod",
        "fchown",
        "ftruncate",
        "link",
        "lchflags",
        "lchown",
        "mkfifo",
        "mknod",
        "pwrite",
        "pwritev",
        "execl",
        "execle",
        "execlp",
        "execlpe",
        "execv",
        "execve",
        "execvp",
        "execvpe",
        "fork",
        "forkpty",
        "popen",
        "posix_spawn",
        "posix_spawnp",
        "remove",
        "removedirs",
        "rename",
        "renames",
        "replace",
        "rmdir",
        "sendfile",
        "spawnl",
        "spawnle",
        "spawnlp",
        "spawnlpe",
        "spawnv",
        "spawnve",
        "spawnvp",
        "spawnvpe",
        "symlink",
        "system",
        "truncate",
        "unlink",
        "utime",
        "write",
        "writev",
    }),
    "shutil": frozenset({
        "chown",
        "copy",
        "copy2",
        "copyfile",
        "move",
        "rmtree",
    }),
}


def _bind_python_imported_unsafe_callables(
    statement: ast.Import | ast.ImportFrom,
    unsafe_callables: set[str],
) -> None:
    if isinstance(statement, ast.ImportFrom):
        module = (statement.module or "").split(".", maxsplit=1)[0]
        members = _PYTHON_UNSAFE_IMPORT_MEMBERS.get(module)
        if not members:
            return
        for alias in statement.names:
            if alias.name == "*":
                unsafe_callables.update(members)
                continue
            if alias.name in members:
                unsafe_callables.add(alias.asname or alias.name)
        return

    for alias in statement.names:
        module = alias.name.split(".", maxsplit=1)[0]
        members = _PYTHON_UNSAFE_IMPORT_MEMBERS.get(module)
        if not members:
            continue
        local_name = alias.asname or module
        unsafe_callables.update(f"{local_name}.{member}" for member in members)


def _bind_python_potential_unsafe_callables_from_statements(
    statements: list[ast.stmt],
    bindings: dict[str, set[str]],
    unsafe_callables: set[str],
) -> None:
    for statement in statements:
        if isinstance(statement, (ast.Import, ast.ImportFrom)):
            _bind_python_imported_unsafe_callables(statement, unsafe_callables)
            continue
        if isinstance(statement, ast.Assign):
            if _python_expr_is_unmodeled_mutation_callable(statement.value, bindings, unsafe_callables):
                for target in statement.targets:
                    _bind_python_handle_target(target, unsafe_callables)
                    _bind_python_subscript_container_target(target, unsafe_callables)
            continue
        if isinstance(statement, ast.AnnAssign) and statement.value is not None:
            if _python_expr_is_unmodeled_mutation_callable(statement.value, bindings, unsafe_callables):
                _bind_python_handle_target(statement.target, unsafe_callables)
                _bind_python_subscript_container_target(statement.target, unsafe_callables)
            continue
        if isinstance(statement, ast.AugAssign):
            if _python_expr_is_unmodeled_mutation_callable(statement.value, bindings, unsafe_callables):
                _bind_python_handle_target(statement.target, unsafe_callables)
                _bind_python_subscript_container_target(statement.target, unsafe_callables)
            continue
        _bind_python_unsafe_container_mutations(statement, bindings, unsafe_callables)
        if isinstance(statement, (ast.If, ast.While, ast.For, ast.With, ast.AsyncWith)):
            nested: list[ast.stmt] = []
            nested.extend(getattr(statement, "body", []) or [])
            nested.extend(getattr(statement, "orelse", []) or [])
            _bind_python_potential_unsafe_callables_from_statements(nested, bindings, unsafe_callables)


def _python_task_io_call_paths(
    node: ast.AST,
    bindings: dict[str, set[str]],
    roots: dict[str, list[Path]],
    safe_write_handles: set[str],
    unsafe_callables: set[str],
    *,
    strict_unmodeled_calls: bool = False,
) -> dict[str, Any] | None:
    path_hashes_by_role: dict[str, set[str]] = {"task_data": set(), "task_output": set()}
    saw_task_data_read = False
    saw_task_output_write = False
    saw_auxiliary_task_output_write = False
    for call in (child for child in ast.walk(node) if isinstance(child, ast.Call)):
        access = _python_task_io_call_access(call)
        if access is None:
            if strict_unmodeled_calls or _python_unmodeled_write_like_call(
                call,
                safe_write_handles,
                unsafe_callables,
                bindings,
            ):
                return None
            continue
        path_expr, direction = access
        path_values = _python_string_expr_values(path_expr, bindings)
        if not path_values:
            return None
        for value in path_values:
            role = _task_artifact_role_for_python_path_value(value, roots)
            if role is None:
                return None
            if direction == "read":
                if role != "task_data":
                    return None
                saw_task_data_read = True
            elif direction == "write":
                if role != "task_output":
                    return None
                saw_task_output_write = True
                if _SCOPE_TASK_COMPAT_AUXILIARY_OUTPUT_PATTERN.search(value):
                    saw_auxiliary_task_output_write = True
            path_hashes_by_role.setdefault(role, set()).add(
                _contextual_path_hash(str(Path(value).expanduser().resolve(strict=False)))
            )
    return {
        "saw_task_data_read": saw_task_data_read,
        "saw_task_output_write": saw_task_output_write,
        "saw_auxiliary_task_output_write": saw_auxiliary_task_output_write,
        "path_hashes_by_role": path_hashes_by_role,
    }


def _python_unmodeled_write_like_call(
    call: ast.Call,
    safe_write_handles: set[str],
    unsafe_callables: set[str],
    bindings: dict[str, set[str]],
) -> bool:
    name = _ast_call_name(call.func)
    if name in unsafe_callables or (
        isinstance(call.func, ast.Name) and call.func.id in unsafe_callables
    ):
        return True
    if isinstance(call.func, (ast.Subscript, ast.Call)):
        return True
    if _python_expr_uses_unsafe_callable_container(call.func, unsafe_callables):
        return True
    if name in {
        "__import__",
        "importlib.import_module",
        "import_module",
        "tempfile.NamedTemporaryFile",
        "NamedTemporaryFile",
        "tempfile.TemporaryFile",
        "TemporaryFile",
        "tempfile.mkstemp",
        "mkstemp",
        "tempfile.mkdtemp",
        "mkdtemp",
        "shutil.copy",
        "shutil.copy2",
        "shutil.copyfile",
        "shutil.move",
        "os.rename",
        "os.replace",
        "os.renames",
        "os.link",
        "os.symlink",
        "os.chflags",
        "os.chmod",
        "os.chown",
        "os.fchmod",
        "os.fchown",
        "os.ftruncate",
        "os.lchflags",
        "os.lchown",
        "os.execl",
        "os.execle",
        "os.execlp",
        "os.execlpe",
        "os.execv",
        "os.execve",
        "os.execvp",
        "os.execvpe",
        "os.fork",
        "os.forkpty",
        "os.popen",
        "os.posix_spawn",
        "os.posix_spawnp",
        "os.truncate",
        "os.utime",
        "os.write",
        "os.writev",
        "os.pwrite",
        "os.pwritev",
        "os.sendfile",
        "os.spawnl",
        "os.spawnle",
        "os.spawnlp",
        "os.spawnlpe",
        "os.spawnv",
        "os.spawnve",
        "os.spawnvp",
        "os.spawnvpe",
        "os.system",
        "os.copy_file_range",
        "shutil.chown",
        "Path.rename",
        "Path.replace",
        "Path.hardlink_to",
        "Path.symlink_to",
        "Path.chmod",
        "Path.lchmod",
        "Path.touch",
        "Path.unlink",
        "Path.rmdir",
        "pathlib.Path.rename",
        "pathlib.Path.replace",
        "pathlib.Path.hardlink_to",
        "pathlib.Path.symlink_to",
        "pathlib.Path.chmod",
        "pathlib.Path.lchmod",
        "pathlib.Path.touch",
        "pathlib.Path.unlink",
        "pathlib.Path.rmdir",
        "hardlink_to",
        "symlink_to",
        "chmod",
        "chown",
        "fchmod",
        "fchown",
        "ftruncate",
        "fork",
        "forkpty",
        "lchown",
        "popen",
        "posix_spawn",
        "posix_spawnp",
        "truncate",
        "utime",
        "system",
        "touch",
        "unlink",
        "rmdir",
        "copy",
        "copy2",
        "copyfile",
        "move",
        "writev",
        "pwrite",
        "pwritev",
        "sendfile",
        "copy_file_range",
    }:
        return True
    if _python_unrecognized_call_uses_write_mode(call):
        return True
    if isinstance(call.func, ast.Attribute):
        if call.func.attr in {
            "symlink_to",
            "hardlink_to",
            "chmod",
            "lchmod",
            "touch",
            "unlink",
            "rmdir",
            "truncate",
        }:
            return True
        if call.func.attr in {"rename", "replace"}:
            receiver_values = _python_string_expr_values(call.func.value, bindings)
            if receiver_values and any(_python_string_literal_is_path_boundary_relevant(value) for value in receiver_values):
                return True
    if isinstance(call.func, ast.Attribute) and call.func.attr in {"write", "writelines"}:
        receiver = call.func.value
        if isinstance(receiver, ast.Name):
            return receiver.id not in safe_write_handles
        if isinstance(receiver, ast.Call):
            receiver_access = _python_task_io_call_access(receiver)
            if receiver_access is not None and receiver_access[1] == "write":
                return False
        return True
    return False


def _python_expr_is_task_output_write_handle(
    node: ast.AST,
    bindings: dict[str, set[str]],
    roots: dict[str, list[Path]],
) -> bool:
    if not isinstance(node, ast.Call):
        return False
    access = _python_task_io_call_access(node)
    if access is None or access[1] != "write":
        return False
    path_values = _python_string_expr_values(access[0], bindings)
    if not path_values:
        return False
    return all(_task_artifact_role_for_python_path_value(value, roots) == "task_output" for value in path_values)


def _python_expr_is_unmodeled_mutation_callable(
    node: ast.AST,
    bindings: dict[str, set[str]],
    unsafe_callables: set[str] | None = None,
) -> bool:
    name = _ast_call_name(node)
    current_unsafe_callables = unsafe_callables or set()
    if name in current_unsafe_callables:
        return True
    if _python_expr_uses_unsafe_callable_container(node, current_unsafe_callables):
        return True
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(
            _python_expr_is_unmodeled_mutation_callable(element, bindings, current_unsafe_callables)
            for element in node.elts
        )
    if isinstance(node, ast.Dict):
        return any(
            value is not None
            and _python_expr_is_unmodeled_mutation_callable(value, bindings, current_unsafe_callables)
            for value in node.values
        )
    if isinstance(node, ast.BinOp):
        return (
            _python_expr_is_unmodeled_mutation_callable(node.left, bindings, current_unsafe_callables)
            or _python_expr_is_unmodeled_mutation_callable(node.right, bindings, current_unsafe_callables)
        )
    if isinstance(node, ast.UnaryOp):
        return _python_expr_is_unmodeled_mutation_callable(node.operand, bindings, current_unsafe_callables)
    if isinstance(node, ast.IfExp):
        return (
            _python_expr_is_unmodeled_mutation_callable(node.body, bindings, current_unsafe_callables)
            or _python_expr_is_unmodeled_mutation_callable(node.orelse, bindings, current_unsafe_callables)
        )
    if isinstance(node, ast.DictComp):
        return (
            _python_expr_is_unmodeled_mutation_callable(node.key, bindings, current_unsafe_callables)
            or _python_expr_is_unmodeled_mutation_callable(node.value, bindings, current_unsafe_callables)
        )
    if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
        return _python_expr_is_unmodeled_mutation_callable(node.elt, bindings, current_unsafe_callables)
    if isinstance(node, ast.Call) and _ast_call_name(node.func) in {"dict", "list", "tuple", "set"}:
        constructor_args = [*node.args, *(keyword.value for keyword in node.keywords)]
        return any(
            _python_expr_is_unmodeled_mutation_callable(argument, bindings, current_unsafe_callables)
            for argument in constructor_args
        )
    if isinstance(node, ast.Call) and _python_unmodeled_write_like_call(
        node,
        set(),
        current_unsafe_callables,
        bindings,
    ):
        return True
    if name in {
        "os.rename",
        "os.replace",
        "os.renames",
        "os.link",
        "os.symlink",
        "os.chflags",
        "os.chmod",
        "os.chown",
        "os.fchmod",
        "os.fchown",
        "os.ftruncate",
        "os.lchflags",
        "os.lchown",
        "os.execl",
        "os.execle",
        "os.execlp",
        "os.execlpe",
        "os.execv",
        "os.execve",
        "os.execvp",
        "os.execvpe",
        "os.fork",
        "os.forkpty",
        "os.popen",
        "os.posix_spawn",
        "os.posix_spawnp",
        "os.truncate",
        "os.utime",
        "Path.rename",
        "Path.replace",
        "Path.hardlink_to",
        "Path.symlink_to",
        "Path.chmod",
        "Path.lchmod",
        "Path.touch",
        "Path.unlink",
        "Path.rmdir",
        "pathlib.Path.rename",
        "pathlib.Path.replace",
        "pathlib.Path.hardlink_to",
        "pathlib.Path.symlink_to",
        "pathlib.Path.chmod",
        "pathlib.Path.lchmod",
        "pathlib.Path.touch",
        "pathlib.Path.unlink",
        "pathlib.Path.rmdir",
        "os.write",
        "os.writev",
        "os.pwrite",
        "os.pwritev",
        "os.sendfile",
        "os.copy_file_range",
        "os.spawnl",
        "os.spawnle",
        "os.spawnlp",
        "os.spawnlpe",
        "os.spawnv",
        "os.spawnve",
        "os.spawnvp",
        "os.spawnvpe",
        "os.system",
        "shutil.chown",
    }:
        return True
    if isinstance(node, ast.Attribute):
        if node.attr in {
            "symlink_to",
            "hardlink_to",
            "chmod",
            "lchmod",
            "touch",
            "unlink",
            "rmdir",
            "truncate",
        }:
            return True
        if node.attr in {"rename", "replace"}:
            receiver_values = _python_string_expr_values(node.value, bindings)
            return bool(
                receiver_values
                and any(_python_string_literal_is_path_boundary_relevant(value) for value in receiver_values)
            )
    return False


def _python_expr_uses_unsafe_callable_container(
    node: ast.AST,
    unsafe_callables: set[str],
) -> bool:
    if isinstance(node, ast.Subscript):
        container_name = _python_subscript_base_name(node)
        return container_name in unsafe_callables
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr in {"get", "pop", "setdefault"}:
            container_name = _python_expr_base_name(node.func.value)
            return container_name in unsafe_callables
    return False


def _bind_python_unsafe_container_mutations(
    node: ast.AST,
    bindings: dict[str, set[str]],
    unsafe_callables: set[str],
) -> None:
    for call in (child for child in ast.walk(node) if isinstance(child, ast.Call)):
        if not _python_call_injects_unsafe_callable_into_container(
            call,
            bindings,
            unsafe_callables,
        ):
            continue
        container_name = _python_container_mutation_base_name(call)
        if container_name:
            unsafe_callables.add(container_name)


def _python_call_injects_unsafe_callable_into_container(
    call: ast.Call,
    bindings: dict[str, set[str]],
    unsafe_callables: set[str],
) -> bool:
    if not isinstance(call.func, ast.Attribute):
        return False
    if not _python_container_mutation_base_name(call):
        return False
    mutation_args: list[ast.AST] = []
    attr = call.func.attr
    if attr == "update":
        mutation_args.extend(call.args)
        mutation_args.extend(keyword.value for keyword in call.keywords)
    elif attr == "__setitem__":
        if len(call.args) >= 2:
            mutation_args.append(call.args[1])
    elif attr in {"append", "extend"}:
        mutation_args.extend(call.args)
    elif attr == "insert":
        if len(call.args) >= 2:
            mutation_args.append(call.args[1])
    elif attr == "setdefault":
        if len(call.args) >= 2:
            mutation_args.append(call.args[1])
    else:
        return False
    return any(
        _python_expr_is_unmodeled_mutation_callable(argument, bindings, unsafe_callables)
        for argument in mutation_args
    )


def _python_container_mutation_base_name(call: ast.Call) -> str:
    if not isinstance(call.func, ast.Attribute):
        return ""
    return _python_expr_base_name(call.func.value)


def _python_subscript_base_name(node: ast.Subscript) -> str:
    return _python_expr_base_name(node.value)


def _python_expr_base_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Subscript):
        return _python_subscript_base_name(node)
    if isinstance(node, ast.Attribute):
        return _python_expr_base_name(node.value)
    return ""


def _bind_python_handle_target(target: ast.AST | None, safe_write_handles: set[str]) -> None:
    if isinstance(target, ast.Name):
        safe_write_handles.add(target.id)


def _bind_python_subscript_container_target(target: ast.AST | None, unsafe_callables: set[str]) -> None:
    if isinstance(target, ast.Subscript):
        container_name = _python_subscript_base_name(target)
        if container_name:
            unsafe_callables.add(container_name)


def _invalidate_python_handle_target(target: ast.AST | None, safe_write_handles: set[str]) -> None:
    if isinstance(target, ast.Name):
        safe_write_handles.discard(target.id)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for element in target.elts:
            _invalidate_python_handle_target(element, safe_write_handles)


def _python_unrecognized_call_uses_write_mode(call: ast.Call) -> bool:
    mode = _python_explicit_mode_from_call(call)
    return mode is not None and any(flag in mode for flag in ("w", "a", "x", "+"))


def _python_task_io_call_access(call: ast.Call) -> tuple[ast.AST, str] | None:
    name = _ast_call_name(call.func)
    if name == "open":
        if not call.args:
            return None
        mode = _python_open_mode_from_call(call)
        direction = "write" if any(flag in mode for flag in ("w", "a", "x", "+")) else "read"
        return call.args[0], direction
    if name in {
        "pandas.read_csv",
        "pd.read_csv",
        "read_csv",
        "pandas.read_json",
        "pd.read_json",
        "read_json",
        "pandas.read_excel",
        "pd.read_excel",
        "read_excel",
        "pandas.read_table",
        "pd.read_table",
        "read_table",
        "pandas.read_parquet",
        "pd.read_parquet",
        "read_parquet",
    }:
        if call.args:
            return call.args[0], "read"
        for keyword in call.keywords:
            if keyword.arg in {"filepath_or_buffer", "path", "io"}:
                return keyword.value, "read"
    if isinstance(call.func, ast.Attribute):
        attr = call.func.attr
        if attr in {"read_text", "read_bytes"}:
            return _path_constructor_arg_or_self(call.func.value), "read"
        if attr in {"write_text", "write_bytes"}:
            return _path_constructor_arg_or_self(call.func.value), "write"
        if attr == "mkdir":
            return _path_constructor_arg_or_self(call.func.value), "write"
    if name in {"os.open", "openat"} and call.args:
        if len(call.args) < 2 or _python_os_open_flags_may_write(call.args[1]):
            return call.args[0], "write"
    if name in {"os.makedirs", "makedirs", "os.mkdir", "mkdir", "pathlib.Path.mkdir", "Path.mkdir"}:
        if call.args:
            return call.args[0], "write"
    return None


def _python_os_open_flags_may_write(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value != 0
    if isinstance(node, ast.Name):
        return node.id != "O_RDONLY"
    if isinstance(node, ast.Attribute):
        return node.attr != "O_RDONLY"
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _python_os_open_flags_may_write(node.left) or _python_os_open_flags_may_write(node.right)
    return True


def _path_constructor_arg_or_self(node: ast.AST) -> ast.AST:
    if isinstance(node, ast.Call) and _ast_call_name(node.func) in {"Path", "pathlib.Path"} and node.args:
        return node.args[0]
    return node


def _python_open_mode_from_call(call: ast.Call) -> str:
    return _python_explicit_mode_from_call(call) or "r"


def _python_explicit_mode_from_call(call: ast.Call) -> str | None:
    if len(call.args) >= 2 and isinstance(call.args[1], ast.Constant) and isinstance(call.args[1].value, str):
        return call.args[1].value
    for keyword in call.keywords:
        if (
            keyword.arg == "mode"
            and isinstance(keyword.value, ast.Constant)
            and isinstance(keyword.value.value, str)
        ):
            return keyword.value.value
    return None


def _python_string_expr_values(
    node: ast.AST,
    bindings: dict[str, set[str]],
    *,
    max_values: int = 64,
) -> set[str] | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return {node.value}
    if isinstance(node, ast.Name):
        values = bindings.get(node.id)
        return set(values) if values is not None else None
    if isinstance(node, ast.JoinedStr):
        values = {""}
        for part in node.values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                part_values = {part.value}
            elif isinstance(part, ast.FormattedValue):
                part_values = _python_string_expr_values(part.value, bindings, max_values=max_values)
                if part_values is None:
                    return None
            else:
                return None
            values = {prefix + suffix for prefix in values for suffix in part_values}
            if len(values) > max_values:
                return None
        return values
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _python_string_expr_values(node.left, bindings, max_values=max_values)
        right = _python_string_expr_values(node.right, bindings, max_values=max_values)
        if left is None or right is None:
            return None
        values = {prefix + suffix for prefix in left for suffix in right}
        return values if len(values) <= max_values else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        left = _python_string_expr_values(node.left, bindings, max_values=max_values)
        right = _python_string_expr_values(node.right, bindings, max_values=max_values)
        if left is None or right is None:
            return None
        values: set[str] = set()
        for prefix in left:
            for suffix in right:
                suffix_path = Path(suffix).expanduser()
                if suffix_path.is_absolute() or re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", suffix):
                    return None
                values.add(str(Path(prefix).expanduser() / suffix_path))
                if len(values) > max_values:
                    return None
        return values
    if isinstance(node, ast.Call) and _ast_call_name(node.func) in {"Path", "pathlib.Path"} and node.args:
        return _python_string_expr_values(node.args[0], bindings, max_values=max_values)
    return None


def _python_string_collection_values(
    node: ast.AST,
    bindings: dict[str, set[str]],
    collection_bindings: dict[str, set[str]],
    *,
    max_values: int = 64,
) -> set[str] | None:
    if isinstance(node, ast.Name):
        values = collection_bindings.get(node.id)
        return set(values) if values is not None else None
    if not isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return None
    values: set[str] = set()
    for element in node.elts:
        element_values = _python_string_expr_values(element, bindings, max_values=max_values)
        if element_values is None:
            return None
        values.update(element_values)
        if len(values) > max_values:
            return None
    return values


def _bind_python_string_target(
    target: ast.AST,
    values: set[str],
    bindings: dict[str, set[str]],
) -> None:
    if isinstance(target, ast.Name):
        bindings[target.id] = set(values)


def _invalidate_python_string_target(
    target: ast.AST,
    bindings: dict[str, set[str]],
) -> None:
    if isinstance(target, ast.Name):
        bindings.pop(target.id, None)
    elif isinstance(target, ast.Subscript):
        base_name = _python_subscript_base_name(target)
        if base_name:
            bindings.pop(base_name, None)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for element in target.elts:
            _invalidate_python_string_target(element, bindings)


def _bind_python_string_collection_target(
    target: ast.AST,
    values: set[str],
    collection_bindings: dict[str, set[str]],
) -> None:
    if isinstance(target, ast.Name):
        collection_bindings[target.id] = set(values)


def _invalidate_python_string_collection_target(
    target: ast.AST,
    collection_bindings: dict[str, set[str]],
) -> None:
    if isinstance(target, ast.Name):
        collection_bindings.pop(target.id, None)
    elif isinstance(target, ast.Subscript):
        base_name = _python_subscript_base_name(target)
        if base_name:
            collection_bindings.pop(base_name, None)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for element in target.elts:
            _invalidate_python_string_collection_target(element, collection_bindings)


_PYTHON_COLLECTION_MUTATION_METHODS = frozenset({
    "__delitem__",
    "__setitem__",
    "add",
    "append",
    "clear",
    "difference_update",
    "discard",
    "extend",
    "insert",
    "intersection_update",
    "pop",
    "popitem",
    "remove",
    "reverse",
    "setdefault",
    "sort",
    "symmetric_difference_update",
    "update",
})


def _python_expr_is_collection_mutator_alias_value(node: ast.AST) -> bool:
    if isinstance(node, ast.Attribute) and node.attr in _PYTHON_COLLECTION_MUTATION_METHODS:
        return True
    if isinstance(node, ast.Subscript):
        key = _python_static_string_subscript_key(node)
        if key in _PYTHON_COLLECTION_MUTATION_METHODS and _python_expr_is_reflection_mapping(node.value):
            return True
        return _python_expr_is_collection_mutator_alias_value(node.value)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(
            _python_expr_is_collection_mutator_alias_value(element)
            for element in node.elts
        )
    if isinstance(node, ast.Dict):
        return any(
            value is not None and _python_expr_is_collection_mutator_alias_value(value)
            for value in node.values
        )
    if isinstance(node, ast.IfExp):
        return (
            _python_expr_is_collection_mutator_alias_value(node.body)
            or _python_expr_is_collection_mutator_alias_value(node.orelse)
        )
    if isinstance(node, ast.NamedExpr):
        return _python_expr_is_collection_mutator_alias_value(node.value)
    if isinstance(node, ast.Call):
        call_name = _ast_call_name(node.func)
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "__get__"
            and _python_expr_is_collection_mutator_alias_value(node.func.value)
        ):
            return True
        if (
            isinstance(node.func, ast.Call)
            and _python_expr_is_collection_mutator_alias_value(node.func)
        ):
            return True
        if (
            call_name == "getattr"
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and isinstance(node.args[1].value, str)
        ):
            return node.args[1].value in _PYTHON_COLLECTION_MUTATION_METHODS
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"__getattribute__", "__getattr__"}
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            return node.args[0].value in _PYTHON_COLLECTION_MUTATION_METHODS
        if (
            call_name.endswith(".__getattribute__")
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and isinstance(node.args[1].value, str)
        ):
            return node.args[1].value in _PYTHON_COLLECTION_MUTATION_METHODS
        if (
            call_name in {"methodcaller", "operator.methodcaller"}
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            return node.args[0].value in _PYTHON_COLLECTION_MUTATION_METHODS
        if (
            call_name in {"attrgetter", "operator.attrgetter"}
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            return node.args[0].value in _PYTHON_COLLECTION_MUTATION_METHODS
        if call_name in {"partial", "functools.partial"} and node.args:
            return _python_expr_is_collection_mutator_alias_value(node.args[0])
        if call_name in {"MethodType", "types.MethodType"} and node.args:
            return _python_expr_is_collection_mutator_alias_value(node.args[0])
    return False


def _python_static_string_subscript_key(node: ast.Subscript) -> str:
    key_node = node.slice
    if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
        return key_node.value
    return ""


def _python_expr_is_reflection_mapping(node: ast.AST) -> bool:
    if isinstance(node, ast.Attribute) and node.attr == "__dict__":
        return True
    if isinstance(node, ast.Call) and _ast_call_name(node.func) == "vars" and node.args:
        return True
    return False


def _bind_python_collection_mutator_alias_target(
    target: ast.AST,
    aliases: set[str],
) -> None:
    if isinstance(target, ast.Name):
        aliases.add(target.id)


def _invalidate_python_collection_mutator_alias_target(
    target: ast.AST,
    aliases: set[str],
) -> None:
    if isinstance(target, ast.Name):
        aliases.discard(target.id)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for element in target.elts:
            _invalidate_python_collection_mutator_alias_target(element, aliases)


def _invalidate_bound_collection_mutator_receiver(
    node: ast.AST,
    collection_bindings: dict[str, set[str]],
) -> None:
    if not _python_expr_is_collection_mutator_alias_value(node):
        return
    if isinstance(node, ast.Attribute):
        base_name = _python_expr_base_name(node.value)
    elif (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"__getattribute__", "__getattr__"}
    ):
        base_name = _python_expr_base_name(node.func.value)
    elif isinstance(node, ast.Call) and node.args:
        base_name = _python_expr_base_name(node.args[0])
    else:
        base_name = ""
    if base_name and base_name not in {"dict", "list", "set"}:
        collection_bindings.pop(base_name, None)


def _invalidate_python_collection_mutations(
    node: ast.AST,
    collection_bindings: dict[str, set[str]],
    collection_mutator_aliases: set[str],
) -> None:
    if not collection_bindings:
        return
    for call in (child for child in ast.walk(node) if isinstance(child, ast.Call)):
        if (
            isinstance(call.func, ast.Attribute)
            and call.func.attr == "__call__"
            and isinstance(call.func.value, ast.Name)
            and call.func.value.id in collection_mutator_aliases
        ):
            if call.args:
                first_arg_name = _python_expr_base_name(call.args[0])
                if first_arg_name:
                    collection_bindings.pop(first_arg_name, None)
            collection_bindings.clear()
            continue
        if (
            isinstance(call.func, ast.Attribute)
            and call.func.attr == "__call__"
            and isinstance(call.func.value, ast.Attribute)
            and call.func.value.attr in _PYTHON_COLLECTION_MUTATION_METHODS
        ):
            base_name = _python_expr_base_name(call.func.value.value)
            if base_name:
                collection_bindings.pop(base_name, None)
            continue
        if (
            isinstance(call.func, ast.Attribute)
            and call.func.attr == "__call__"
            and _python_expr_is_collection_mutator_alias_value(call.func.value)
        ):
            _invalidate_bound_collection_mutator_receiver(call.func.value, collection_bindings)
            collection_bindings.clear()
            continue
        if isinstance(call.func, ast.Name) and call.func.id in collection_mutator_aliases:
            if call.args:
                first_arg_name = _python_expr_base_name(call.args[0])
                if first_arg_name:
                    collection_bindings.pop(first_arg_name, None)
            collection_bindings.clear()
            continue
        if not isinstance(call.func, ast.Attribute):
            continue
        if call.func.attr not in _PYTHON_COLLECTION_MUTATION_METHODS:
            continue
        base_name = _python_expr_base_name(call.func.value)
        if base_name:
            collection_bindings.pop(base_name, None)
        if base_name in {"dict", "list", "set"} and call.args:
            first_arg_name = _python_expr_base_name(call.args[0])
            if first_arg_name:
                collection_bindings.pop(first_arg_name, None)


def _python_target_touches_collection_binding(
    target: ast.AST | None,
    collection_names: set[str],
) -> bool:
    if not collection_names or target is None:
        return False
    if isinstance(target, (ast.Name, ast.Subscript, ast.Attribute)):
        return _python_expr_base_name(target) in collection_names
    if isinstance(target, (ast.Tuple, ast.List)):
        return any(
            _python_target_touches_collection_binding(element, collection_names)
            for element in target.elts
        )
    return False


def _python_control_flow_has_collection_mutation_signal(
    node: ast.AST,
    collection_mutator_aliases: set[str],
    collection_names: set[str] | None = None,
) -> bool:
    collection_names = collection_names or set()
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            if isinstance(child.func, ast.Attribute) and child.func.attr == "__call__":
                if (
                    isinstance(child.func.value, ast.Name)
                    and child.func.value.id in collection_mutator_aliases
                ):
                    return True
                if (
                    isinstance(child.func.value, ast.Attribute)
                    and child.func.value.attr in _PYTHON_COLLECTION_MUTATION_METHODS
                ):
                    return True
                if _python_expr_is_collection_mutator_alias_value(child.func.value):
                    return True
            if isinstance(child.func, ast.Name) and child.func.id in collection_mutator_aliases:
                return True
            if (
                isinstance(child.func, ast.Attribute)
                and child.func.attr in _PYTHON_COLLECTION_MUTATION_METHODS
            ):
                return True
        if isinstance(child, ast.Assign):
            if any(
                _python_target_touches_collection_binding(target, collection_names)
                for target in child.targets
            ):
                return True
            if _python_expr_is_collection_mutator_alias_value(child.value):
                return True
        elif isinstance(child, ast.AnnAssign) and child.value is not None:
            if _python_target_touches_collection_binding(child.target, collection_names):
                return True
            if _python_expr_is_collection_mutator_alias_value(child.value):
                return True
        elif isinstance(child, ast.AugAssign):
            if _python_target_touches_collection_binding(child.target, collection_names):
                return True
        elif isinstance(child, ast.Delete):
            if any(
                _python_target_touches_collection_binding(target, collection_names)
                for target in child.targets
            ):
                return True
        elif isinstance(child, (ast.For, ast.AsyncFor)):
            if _python_target_touches_collection_binding(child.target, collection_names):
                return True
        elif isinstance(child, (ast.With, ast.AsyncWith)):
            if any(
                _python_target_touches_collection_binding(item.optional_vars, collection_names)
                for item in child.items
            ):
                return True
    return False


def _python_loop_string_bindings(
    target: ast.AST,
    iter_node: ast.AST,
    bindings: dict[str, set[str]],
    collection_bindings: dict[str, set[str]],
) -> dict[str, set[str]] | None:
    collection_values = _python_string_collection_values(
        iter_node,
        bindings,
        collection_bindings,
    )
    if collection_values is not None and isinstance(target, ast.Name):
        return {target.id: collection_values}

    elements = _python_literal_iter_elements(iter_node)
    if elements is None:
        return None
    result: dict[str, set[str]] = {}
    for element in elements:
        _collect_loop_target_string_values(target, element, bindings, result)
    return result


def _python_literal_iter_elements(iter_node: ast.AST) -> list[ast.AST] | None:
    if isinstance(iter_node, (ast.List, ast.Tuple, ast.Set)):
        return list(iter_node.elts)
    return None


def _collect_loop_target_string_values(
    target: ast.AST,
    value_node: ast.AST,
    bindings: dict[str, set[str]],
    result: dict[str, set[str]],
) -> None:
    if isinstance(target, ast.Name):
        values = _python_string_expr_values(value_node, bindings)
        if values is not None:
            result.setdefault(target.id, set()).update(values)
        return
    if isinstance(target, (ast.Tuple, ast.List)) and isinstance(value_node, (ast.Tuple, ast.List)):
        for sub_target, sub_value in zip(target.elts, value_node.elts):
            _collect_loop_target_string_values(sub_target, sub_value, bindings, result)


def _task_artifact_role_for_python_path_value(
    value: str,
    roots: dict[str, list[Path]],
) -> str | None:
    if not value or re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        return None
    path = Path(value).expanduser()
    if not path.is_absolute():
        return None
    resolved = path.resolve(strict=False)
    for role, role_roots in roots.items():
        if any(_path_is_relative_to(resolved, root) for root in role_roots):
            return role
    return None


def _ast_call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _ast_call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _confirmed_task_data_roots(context: DecisionContext | None) -> list[Path]:
    return _confirmed_task_artifact_roots(context, roles={"task_data"}).get("task_data", [])


def _confirmed_task_artifact_roots(
    context: DecisionContext | None,
    *,
    roles: set[str],
) -> dict[str, list[Path]]:
    profile = context.session_scope_profile if context is not None else None
    if profile is None or not profile.confirmed or profile.dry_run:
        return {}
    roots: dict[str, list[Path]] = {role: [] for role in roles}
    for rule in profile.task_artifacts or []:
        role = str(rule.artifact_role or "")
        if (
            role not in roles
            or rule.artifact_trust_confirmed is not True
            or str(rule.source_tier or "") != "risk_adjusting"
            or str(rule.confidence or "") != "high"
        ):
            continue
        allowed_effects = {str(effect) for effect in (rule.allowed_effects or [])}
        if role == "task_data" and allowed_effects and not allowed_effects.intersection({
            "filesystem.read",
            "filesystem.enumerate",
        }):
            continue
        if role == "task_output" and allowed_effects and "filesystem.write" not in allowed_effects:
            continue
        for raw_path in rule.paths or []:
            try:
                roots.setdefault(role, []).append(Path(str(raw_path)).expanduser().resolve(strict=False))
            except OSError:
                continue
    return {role: role_roots for role, role_roots in roots.items() if role_roots}


def _contextual_path_hash(value: str) -> str:
    return "sha256:" + hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def _scope_task_io_contextual_metadata(
    context: DecisionContext | None,
    path_summary: dict[str, Any] | None,
) -> dict[str, list[str]]:
    profile = context.session_scope_profile if context is not None else None
    if profile is None or path_summary is None:
        return {}
    roles = {str(role) for role in path_summary.get("roles") or []}
    profile_hash = hash_session_scope_profile(profile)
    metadata: dict[str, set[str]] = {
        "artifact_roles": set(roles),
        "artifact_candidate_roles": set(),
        "artifact_sources": set(),
        "artifact_source_tiers": set(),
        "artifact_profile_hashes": {profile_hash} if roles else set(),
        "artifact_case_ids": set(),
        "artifact_match_types": set(),
    }
    for role, hashes in (path_summary.get("path_hashes_by_role") or {}).items():
        if role == "task_data":
            metadata.setdefault("input_path_hashes", set()).update(hashes)
        elif role == "task_output":
            metadata.setdefault("output_path_hashes", set()).update(hashes)
    for rule in profile.task_artifacts or []:
        role = str(rule.artifact_role or "")
        if role not in roles:
            continue
        candidate = SCOPE_TASK_DATA_READ_PATH_ROLE if role == "task_data" else SCOPE_TASK_OUTPUT_PATH_ROLE
        metadata["artifact_candidate_roles"].add(candidate)
        if rule.source:
            metadata["artifact_sources"].add(str(rule.source))
        if rule.source_tier:
            metadata["artifact_source_tiers"].add(str(rule.source_tier))
        if rule.case_id:
            metadata["artifact_case_ids"].add(str(rule.case_id))
        if rule.match_type:
            metadata["artifact_match_types"].add(str(rule.match_type))
    return {key: sorted(values) for key, values in metadata.items() if values}


def _merge_contextual_metadata_lists(metadata: dict[str, Any], additions: dict[str, list[str]]) -> None:
    for key, values in additions.items():
        merged = {str(value) for value in (metadata.get(key) or [])}
        merged.update(str(value) for value in values)
        metadata[key] = sorted(merged)


def _path_is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _python_string_literal_is_path_boundary_relevant(value: str) -> bool:
    if not value or re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        return False
    return value.startswith(("/", "~", "./", "../"))


def _inline_python_sources_from_event(event: CanonicalEvent) -> list[str]:
    payload = event.payload or {}
    command = str(payload.get("command") or payload.get("input") or "")
    if not command.strip():
        return []
    sources: list[str] = []
    lines = command.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        if re.search(r"\bpython3?\b[^\n;|&]*<<", line):
            match = re.search(r"<<\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?", line)
            delimiter = match.group(1) if match else ""
            body: list[str] = []
            index += 1
            while index < len(lines) and (not delimiter or lines[index].strip() != delimiter):
                body.append(lines[index])
                index += 1
            if body:
                sources.append("\n".join(body))
        index += 1
    for segment in _split_shell_segments(command):
        try:
            parts = shlex.split(segment)
        except ValueError:
            continue
        if not parts or Path(parts[0]).name.lower() not in {"python", "python3"}:
            continue
        for part_index, token in enumerate(parts[:-1]):
            if token == "-c":
                sources.append(parts[part_index + 1])
    return sources


def _task_artifact_contextual_rule_disqualifies(
    rule: str,
    *,
    contract_scoped_targets: bool,
) -> bool:
    lowered = str(rule or "").lower()
    for fragment in _TASK_ARTIFACT_CONTEXTUAL_DISQUALIFYING_RULE_FRAGMENTS:
        if (
            contract_scoped_targets
            and fragment in _TASK_ARTIFACT_CONTEXTUAL_SCOPED_OUTPUT_SOFT_RULE_FRAGMENTS
        ):
            continue
        if fragment in lowered:
            return True
    return False


def _is_unresolved_local_writer_review_candidate(
    effect_summary: dict[str, Any],
    *,
    risk_level: RiskLevel,
    routing_intents: list[ReviewRoutingIntent],
) -> bool:
    if risk_level == RiskLevel.CRITICAL:
        return False
    for intent in routing_intents:
        if intent.decision_affecting and intent.policy_action in {"block", "defer"}:
            return False
    effects = set(effect_summary.get("effects") or [])
    evidence_rules = {str(rule).lower() for rule in effect_summary.get("evidence_rules") or []}
    if "python_writer_method_unresolved" not in evidence_rules:
        return False
    if "filesystem.write" not in effects:
        return False
    if effects.intersection(_NON_CLEARABLE_EFFECTS):
        return False
    if effects and not effects.issubset(_REVIEWABLE_CONTEXTUAL_EFFECTS):
        return False
    if str(effect_summary.get("analysis_state") or "complete") != "complete":
        return False
    if str(effect_summary.get("confidence") or "low") not in {"medium", "high"}:
        return False
    if effect_summary.get("wrapper_chain"):
        return False
    if "wrapper_chain_unresolved" in evidence_rules:
        return False
    for rule_id in evidence_rules:
        if any(fragment in rule_id for fragment in _CONTEXTUAL_DISQUALIFYING_RULE_FRAGMENTS):
            return False
    for target in effect_summary.get("targets") or []:
        if not isinstance(target, dict):
            return False
        role = str(target.get("path_role") or "")
        if role in {"credential_source", "hidden_oracle", SCOPE_CONTROL_METADATA_PATH_ROLE, "system_path"}:
            return False
        deny_reason = str(target.get("artifact_deny_reason") or "")
        redline_reason = str(target.get("scope_task_fallback_blocked_by_redline_reason") or "")
        if deny_reason or redline_reason:
            return False
    return True


def _is_scope_task_output_local_vcs_mutation_review_candidate(
    effect_summary: dict[str, Any],
    *,
    risk_level: RiskLevel,
    score: float,
    routing_intents: list[ReviewRoutingIntent],
    config: DetectionConfig,
) -> bool:
    if str(config.mode or "normal").strip().lower() != "benchmark":
        return False
    if risk_level == RiskLevel.CRITICAL:
        return False
    if not _is_high_or_near_high(risk_level=risk_level, score=score, config=config):
        return False
    for intent in routing_intents:
        if intent.decision_affecting and intent.policy_action in {"block", "defer"}:
            return False
    effects = set(effect_summary.get("effects") or [])
    if not {"command.exec", "filesystem.write"}.issubset(effects):
        return False
    if effects.intersection(_NON_CLEARABLE_EFFECTS):
        return False
    if effects and not effects.issubset(_REVIEWABLE_CONTEXTUAL_EFFECTS | {"filesystem.enumerate"}):
        return False
    if str(effect_summary.get("analysis_state") or "complete") != "complete":
        return False
    if str(effect_summary.get("confidence") or "low") not in {"medium", "high"}:
        return False
    if effect_summary.get("wrapper_chain"):
        return False

    evidence_rules = {str(rule).lower() for rule in effect_summary.get("evidence_rules") or []}
    if "task_output_local_vcs_patch_apply" not in evidence_rules:
        return False
    hard_fragments = (
        "credential",
        "network",
        "package",
        "destructive",
        "persistence",
        "system_path",
        "encoded_payload",
        "encoded-payload",
        "external_reference",
        "remote_fetch",
        "upload",
        "exfil",
        "control",
        "oracle",
        "verifier",
        "judge",
        "contract_violation",
    )
    for rule_id in evidence_rules:
        if rule_id == "task_output_local_vcs_patch_apply":
            continue
        if "wrapper" in rule_id:
            return False
        if any(fragment in rule_id for fragment in hard_fragments):
            return False

    has_task_output = False
    for target in effect_summary.get("targets") or []:
        if not isinstance(target, dict):
            return False
        role = str(target.get("path_role") or "")
        relation = str(target.get("workspace_relation") or "")
        if role in {"credential_source", "hidden_oracle", SCOPE_CONTROL_METADATA_PATH_ROLE, "system_path"}:
            return False
        deny_reason = str(target.get("artifact_deny_reason") or "")
        redline_reason = str(target.get("scope_task_fallback_blocked_by_redline_reason") or "")
        if deny_reason or redline_reason:
            return False
        artifact_role = _contract_artifact_target_role(target)
        if artifact_role == "task_output":
            if relation not in {"inside_workspace", "task_output_artifact"}:
                return False
            has_task_output = True
            continue
        if _effective_scope_artifact_target_role(target) == "task_data":
            if relation != SCOPE_TASK_DATA_WORKSPACE_RELATION:
                return False
            continue
        return False
    return has_task_output


def _scope_task_artifact_future_exec_kind(effect_summary: dict[str, Any]) -> str:
    for target in effect_summary.get("targets") or []:
        if not isinstance(target, dict):
            continue
        if (
            str(target.get("path_role") or "") == "future_execution.artifact"
            and _is_contract_qualified_artifact_target(target, artifact_role="task_output")
        ):
            return "deliverable_source_write"
    return "none"


def _scope_task_compat_future_exec_kind(effect_summary: dict[str, Any]) -> str:
    for target in effect_summary.get("targets") or []:
        if not isinstance(target, dict):
            continue
        if (
            str(target.get("path_role") or "") == "future_execution.artifact"
            and _scope_task_compat_target_role(target) == "task_output"
        ):
            return "deliverable_source_write"
    return "none"


def _is_task_data_to_unscoped_future_exec_write(effect_summary: dict[str, Any]) -> bool:
    effects = set(effect_summary.get("effects") or [])
    if not {"filesystem.write", "future_execution.artifact"}.issubset(effects):
        return False

    has_task_data_source = False
    has_unscoped_future_exec_target = False
    for collection_name in ("sources", "targets"):
        for target in effect_summary.get(collection_name) or []:
            if not isinstance(target, dict):
                continue
            relation = str(target.get("workspace_relation") or "")
            effective_role = _effective_scope_artifact_target_role(target)
            if (
                effective_role == "task_data"
                and relation == SCOPE_TASK_DATA_WORKSPACE_RELATION
            ):
                has_task_data_source = True
            if (
                str(target.get("path_role") or "") == "future_execution.artifact"
                and effective_role != "task_output"
            ):
                has_unscoped_future_exec_target = True
    return has_task_data_source and has_unscoped_future_exec_target


def _audit_fspr_routing_for_scope_task_data_readonly(
    routing_intents: list[ReviewRoutingIntent],
) -> list[ReviewRoutingIntent]:
    updated: list[ReviewRoutingIntent] = []
    for intent in routing_intents:
        if (
            intent.source == "fspr_package_review"
            and intent.decision_affecting
            and intent.policy_action in {"block", "defer"}
        ):
            metadata = dict(intent.source_metadata or {})
            metadata["benchmark_task_data_readonly"] = True
            updated.append(intent.model_copy(update={
                "recommended_tier": "none",
                "policy_action": "audit",
                "source_metadata": metadata,
                "routing_affecting": False,
                "decision_affecting": False,
            }))
        else:
            updated.append(intent)
    return updated


_TASK_DATA_READ_CONTENT_REVIEW_ALLOWED_RULES = frozenset({
    "read_content_hidden_auxiliary_output_instruction",
    "read_content_markdown_beacon",
    "read_content_task_scope_contraction",
})


def _scope_task_data_read_content_rule_ids(context: DecisionContext | None) -> set[str]:
    rule_ids = {str(rule_id) for rule_id in _content_evidence_rule_ids(context)}
    return {rule_id for rule_id in rule_ids if rule_id.startswith("read_content_")}


def _scope_task_data_read_content_review_rule_ids(context: DecisionContext | None) -> set[str]:
    rule_ids = _scope_task_data_read_content_rule_ids(context)
    if not rule_ids:
        return set()
    if not rule_ids.issubset(_TASK_DATA_READ_CONTENT_REVIEW_ALLOWED_RULES):
        return set()
    return rule_ids


def _audit_content_routing_for_scope_task_data_read_content_review(
    routing_intents: list[ReviewRoutingIntent],
    *,
    context: DecisionContext | None,
) -> list[ReviewRoutingIntent]:
    rule_ids = _scope_task_data_read_content_review_rule_ids(context)
    if not rule_ids:
        return routing_intents
    updated: list[ReviewRoutingIntent] = []
    for intent in routing_intents:
        if (
            intent.source == "content_evidence"
            and intent.reason == "read_content_evidence"
            and intent.decision_affecting
            and intent.policy_action in {"block", "defer"}
        ):
            metadata = dict(intent.source_metadata or {})
            metadata["scope_task_data_read_content_review"] = True
            metadata["review_rule_ids"] = sorted(rule_ids)
            updated.append(intent.model_copy(update={
                "recommended_tier": "none",
                "policy_action": "audit",
                "source_metadata": metadata,
                "routing_affecting": False,
                "decision_affecting": False,
            }))
        else:
            updated.append(intent)
    return updated


def _mark_fspr_findings_scope_task_data_readonly_audit(
    skill_trust_findings: list[dict[str, Any]],
) -> None:
    for finding in skill_trust_findings:
        if finding.get("rule_id") in {
            "first_use_skill_package_inconsistent",
            "first_use_skill_package_suspicious",
            "first_use_skill_package_insufficient_evidence",
            "fspr_review_summary",
        }:
            finding["decision_affecting"] = False
            finding["benchmark_task_data_readonly"] = True


def _audit_fspr_routing_for_scope_task_output_readonly(
    routing_intents: list[ReviewRoutingIntent],
) -> list[ReviewRoutingIntent]:
    updated: list[ReviewRoutingIntent] = []
    for intent in routing_intents:
        if (
            intent.source == "fspr_package_review"
            and intent.decision_affecting
            and intent.policy_action in {"block", "defer"}
        ):
            metadata = dict(intent.source_metadata or {})
            metadata["benchmark_task_output_readonly"] = True
            updated.append(intent.model_copy(update={
                "recommended_tier": "none",
                "policy_action": "audit",
                "source_metadata": metadata,
                "routing_affecting": False,
                "decision_affecting": False,
            }))
        else:
            updated.append(intent)
    return updated


def _mark_fspr_findings_scope_task_output_readonly_audit(
    skill_trust_findings: list[dict[str, Any]],
) -> None:
    for finding in skill_trust_findings:
        if finding.get("rule_id") in {
            "first_use_skill_package_inconsistent",
            "first_use_skill_package_suspicious",
            "first_use_skill_package_insufficient_evidence",
            "fspr_review_summary",
        }:
            finding["decision_affecting"] = False
            finding["benchmark_task_output_readonly"] = True


def _audit_fspr_routing_for_scope_task_output_write(
    routing_intents: list[ReviewRoutingIntent],
) -> list[ReviewRoutingIntent]:
    updated: list[ReviewRoutingIntent] = []
    for intent in routing_intents:
        if (
            intent.source == "fspr_package_review"
            and intent.decision_affecting
            and intent.policy_action in {"block", "defer"}
        ):
            metadata = dict(intent.source_metadata or {})
            metadata["benchmark_task_output_write"] = True
            updated.append(intent.model_copy(update={
                "recommended_tier": "none",
                "policy_action": "audit",
                "source_metadata": metadata,
                "routing_affecting": False,
                "decision_affecting": False,
            }))
        else:
            updated.append(intent)
    return updated


def _mark_fspr_findings_scope_task_output_write_audit(
    skill_trust_findings: list[dict[str, Any]],
) -> None:
    for finding in skill_trust_findings:
        if finding.get("rule_id") in {
            "first_use_skill_package_inconsistent",
            "first_use_skill_package_suspicious",
            "first_use_skill_package_insufficient_evidence",
            "fspr_review_summary",
        }:
            finding["decision_affecting"] = False
            finding["benchmark_task_output_write"] = True


def _audit_fspr_routing_for_verified_skill_manifest_read_probe(
    routing_intents: list[ReviewRoutingIntent],
) -> list[ReviewRoutingIntent]:
    updated: list[ReviewRoutingIntent] = []
    for intent in routing_intents:
        if (
            intent.source == "fspr_package_review"
            and intent.decision_affecting
            and intent.policy_action in {"block", "defer"}
        ):
            metadata = dict(intent.source_metadata or {})
            metadata["verified_skill_manifest_read_probe"] = True
            updated.append(intent.model_copy(update={
                "recommended_tier": "none",
                "policy_action": "audit",
                "source_metadata": metadata,
                "routing_affecting": False,
                "decision_affecting": False,
            }))
        else:
            updated.append(intent)
    return updated


def _mark_fspr_findings_verified_skill_manifest_read_probe_audit(
    skill_trust_findings: list[dict[str, Any]],
) -> None:
    for finding in skill_trust_findings:
        if finding.get("rule_id") in {
            "first_use_skill_package_inconsistent",
            "first_use_skill_package_suspicious",
            "first_use_skill_package_insufficient_evidence",
            "fspr_review_summary",
        }:
            finding["decision_affecting"] = False
            finding["verified_skill_manifest_read_probe"] = True


def _audit_fspr_routing_for_verified_skill_package_read_review(
    routing_intents: list[ReviewRoutingIntent],
) -> list[ReviewRoutingIntent]:
    updated: list[ReviewRoutingIntent] = []
    for intent in routing_intents:
        if (
            intent.source == "fspr_package_review"
            and intent.decision_affecting
            and intent.policy_action in {"block", "defer"}
        ):
            metadata = dict(intent.source_metadata or {})
            metadata["verified_skill_package_read_review"] = True
            updated.append(intent.model_copy(update={
                "recommended_tier": "none",
                "policy_action": "audit",
                "source_metadata": metadata,
                "routing_affecting": False,
                "decision_affecting": False,
            }))
        else:
            updated.append(intent)
    return updated


def _mark_fspr_findings_verified_skill_package_read_review_audit(
    skill_trust_findings: list[dict[str, Any]],
) -> None:
    for finding in skill_trust_findings:
        if finding.get("rule_id") in {
            "first_use_skill_package_inconsistent",
            "first_use_skill_package_suspicious",
            "first_use_skill_package_insufficient_evidence",
            "fspr_review_summary",
        }:
            finding["decision_affecting"] = False
            finding["verified_skill_package_read_review"] = True


def _classify_l1_authority(
    *,
    event: CanonicalEvent,
    snapshot_fields: dict[str, Any],
    context: DecisionContext | None,
    config: DetectionConfig,
) -> tuple[L1AuthorityClass, list[str], ReviewRoutingIntent | None]:
    rule_hits = set(snapshot_fields.get("rule_hits") or [])
    routing_intents = list(snapshot_fields.get("routing_intents") or [])
    effect_summary = snapshot_fields.get("effect_summary") or {}
    effects = set(effect_summary.get("effects") or [])
    evidence_rules = set(effect_summary.get("evidence_rules") or [])
    short_circuit_rule = snapshot_fields.get("short_circuit_rule")
    target_roles = {
        str(target.get("path_role"))
        for target in effect_summary.get("targets") or []
        if isinstance(target, dict) and target.get("path_role")
    }
    risk_level = snapshot_fields["risk_level"]
    score = float(snapshot_fields.get("composite_score") or 0.0)
    dimensions = snapshot_fields["dimensions"]
    work5c_relaxed_readonly = "work5c_warning_relaxed_readonly" in rule_hits
    work5c_task_readonly = "work5c_warning_task_readonly" in rule_hits
    task_artifact_data_readonly = "benchmark_task_data_readonly" in rule_hits
    task_artifact_output_readonly = "benchmark_task_output_readonly" in rule_hits
    verified_skill_manifest_read_probe = "verified_skill_manifest_read_probe" in rule_hits
    task_artifact_output_write = (
        "benchmark_task_output_write" in rule_hits
        and _is_scope_task_output_write_candidate(
            effect_summary,
            routing_intents=routing_intents,
            config=config,
        )
    )
    task_artifact_output_env_setup = (
        "benchmark_task_output_env_setup" in rule_hits
        and _is_scope_task_output_env_setup_candidate(
            effect_summary,
            routing_intents=routing_intents,
            config=config,
        )
    )
    verified_skill_package_read_review_candidate = _is_verified_skill_package_read_review_candidate(
        effect_summary,
        event=event,
        routing_intents=routing_intents,
        context=context,
        config=config,
    )
    scope_task_artifact_hardblock_review_candidate = _is_scope_task_artifact_hardblock_review_candidate(
        effect_summary,
        risk_level=risk_level,
        score=score,
        routing_intents=routing_intents,
        config=config,
    )
    scope_task_artifact_network_content_review_candidate = (
        _is_scope_task_artifact_network_content_review_candidate(
            event,
            effect_summary,
            risk_level=risk_level,
            score=score,
            routing_intents=routing_intents,
            config=config,
        )
    )
    scope_task_artifact_external_reference_review_candidate = (
        _is_scope_task_artifact_external_reference_review_candidate(
            effect_summary,
            risk_level=risk_level,
            score=score,
            routing_intents=routing_intents,
            config=config,
        )
    )
    scope_task_external_asset_download_review_candidate = (
        _is_scope_task_external_asset_download_review_candidate(
            event,
            effect_summary,
            risk_level=risk_level,
            score=score,
            routing_intents=routing_intents,
            config=config,
        )
    )
    scope_task_compat_auxiliary_output_review_candidate = (
        _is_scope_task_compat_auxiliary_output_review_candidate(
            event,
            effect_summary,
            risk_level=risk_level,
            score=score,
            routing_intents=routing_intents,
            config=config,
        )
    )
    scope_task_contract_auxiliary_output_review_candidate = (
        _is_scope_task_contract_auxiliary_output_review_candidate(
            event,
            effect_summary,
            risk_level=risk_level,
            score=score,
            routing_intents=routing_intents,
            config=config,
        )
    )
    scope_task_output_local_generated_script_review_candidate = (
        _is_scope_task_output_local_generated_script_review_candidate(
            event,
            effect_summary,
            risk_level=risk_level,
            score=score,
            routing_intents=routing_intents,
            config=config,
        )
    )
    scope_task_auxiliary_data_copy_review_candidate = (
        _is_scope_task_auxiliary_data_copy_review_candidate(
            event,
            effect_summary,
            risk_level=risk_level,
            routing_intents=routing_intents,
            config=config,
            context=context,
        )
    )
    scope_task_local_helper_future_exec_review_candidate = (
        _is_scope_task_local_helper_future_exec_review_candidate(
            effect_summary,
            risk_level=risk_level,
            routing_intents=routing_intents,
            config=config,
        )
    )
    scope_task_data_read_content_review_candidate = (
        _is_scope_task_data_read_content_review_candidate(
            effect_summary,
            risk_level=risk_level,
            routing_intents=routing_intents,
            config=config,
            context=context,
        )
    )
    scope_task_data_document_reader_review_candidate = (
        _is_scope_task_data_document_reader_review_candidate(
            effect_summary,
            risk_level=risk_level,
            routing_intents=routing_intents,
            config=config,
            context=context,
            event=event,
        )
    )
    scope_task_data_python_readonly_review_candidate = (
        _is_scope_task_data_python_readonly_review_candidate(
            effect_summary,
            risk_level=risk_level,
            routing_intents=routing_intents,
            config=config,
            context=context,
            event=event,
        )
    )
    scope_task_data_to_output_python_batch_review_candidate = (
        _is_scope_task_data_to_output_python_batch_review_candidate(
            effect_summary,
            risk_level=risk_level,
            routing_intents=routing_intents,
            config=config,
            context=context,
            event=event,
        )
    )
    scope_task_archive_auxiliary_member_review_candidate = (
        _is_scope_task_archive_auxiliary_member_review_candidate(
            effect_summary,
            risk_level=risk_level,
            routing_intents=routing_intents,
            config=config,
        )
    )
    scope_task_output_atomic_replace_staging_review_candidate = (
        _is_scope_task_output_atomic_replace_staging_review_candidate(
            effect_summary,
            risk_level=risk_level,
            routing_intents=routing_intents,
            config=config,
        )
    )
    scope_task_output_local_vcs_mutation_review_candidate = (
        _is_scope_task_output_local_vcs_mutation_review_candidate(
            effect_summary,
            risk_level=risk_level,
            score=score,
            routing_intents=routing_intents,
            config=config,
        )
    )
    scope_task_local_artifact_execution_review_candidate = (
        _is_scope_task_local_artifact_execution_review_candidate(
            effect_summary,
            risk_level=risk_level,
            routing_intents=routing_intents,
            config=config,
        )
    )
    scope_task_local_maven_exec_java_review_candidate = (
        _is_scope_task_local_maven_exec_java_review_candidate(
            effect_summary,
            risk_level=risk_level,
            routing_intents=routing_intents,
            config=config,
        )
    )
    scope_task_local_fat_jar_execution_review_candidate = (
        _is_scope_task_local_fat_jar_execution_review_candidate(
            effect_summary,
            risk_level=risk_level,
            routing_intents=routing_intents,
            config=config,
        )
    )
    unresolved_local_writer_review_candidate = _is_unresolved_local_writer_review_candidate(
        effect_summary,
        risk_level=risk_level,
        routing_intents=routing_intents,
    )
    work5c_readonly_clearance = work5c_relaxed_readonly or work5c_task_readonly
    fspr_readonly_clearance = (
        work5c_readonly_clearance
        or task_artifact_data_readonly
        or task_artifact_output_readonly
        or verified_skill_manifest_read_probe
    )
    fspr_provider_health_advisory_clearance = _has_fspr_provider_health_advisory_clearance(
        routing_intents
    )
    verified_skill_manifest_read_probe_clearance = _has_verified_skill_manifest_read_probe_clearance(
        routing_intents
    )
    summary = context.session_risk_summary if context is not None else None
    blocked_lineage_match = (
        summary.get("blocked_skill_lineage_match")
        if isinstance(summary, dict)
        else None
    )

    reasons: list[str] = []
    blocked_lineage_is_fspr_advisory = (
        fspr_readonly_clearance
        and isinstance(blocked_lineage_match, dict)
        and str(blocked_lineage_match.get("block_source") or "") == "fspr_package_review"
    )
    if blocked_lineage_match and not blocked_lineage_is_fspr_advisory:
        reasons.append("blocked_skill_lineage_match")
    for intent in routing_intents:
        if intent.decision_affecting and intent.policy_action == "block":
            reasons.append(intent.source)

    if event.event_type == EventType.PRE_ACTION:
        if "benchmark_task_data_write" in rule_hits:
            reasons.append("benchmark_task_data_write")
        if (
            "generated_script_future_exec" in evidence_rules
            and _event_payload_has_remote_network_reference(event)
            and not scope_task_artifact_network_content_review_candidate
        ):
            reasons.append("generated_script_dynamic_network_reference")
        if "package.install" in effects and not task_artifact_output_env_setup:
            reasons.append("package.install")
        if "future_execution.entrypoint" in effects:
            reasons.append("future_execution.entrypoint")
        if (
            _is_task_data_to_unscoped_future_exec_write(effect_summary)
            and not scope_task_local_helper_future_exec_review_candidate
        ):
            reasons.append("benchmark_task_data_future_exec_write")
        if (
            "destructive_delete" in evidence_rules
            and not scope_task_data_to_output_python_batch_review_candidate
            and not _is_bounded_task_output_cleanup_copy(effect_summary)
        ):
            reasons.append("destructive_delete")
        if target_roles.intersection({"credential_source", "hidden_oracle"}):
            reasons.append("credential_source")
        if SCOPE_CONTROL_METADATA_PATH_ROLE in target_roles:
            reasons.append(SCOPE_CONTROL_METADATA_PATH_ROLE)
        if "system_path" in target_roles and effects.intersection({
            "filesystem.write",
            "future_execution.artifact",
        }):
            reasons.append("system_path_write")
        if (
            "skill_package_read" in target_roles
            and not work5c_relaxed_readonly
            and not fspr_provider_health_advisory_clearance
            and not verified_skill_manifest_read_probe_clearance
            and not verified_skill_manifest_read_probe
            and not verified_skill_package_read_review_candidate
        ):
            reasons.append("skill_package_read")
        for rule_id in sorted(
            (rule_hits | evidence_rules).intersection({
                "persistence_entrypoint_write",
                "python_implicit_sitecustomize",
                "system_path_write",
                "task_data_copy_to_unscoped_path",
                "task_output_contract_violation",
                "wrapper_chain_unresolved",
            })
        ):
            if (
                rule_id == "persistence_entrypoint_write"
                and scope_task_artifact_hardblock_review_candidate
            ):
                continue
            if (
                rule_id == "wrapper_chain_unresolved"
                and (
                    scope_task_external_asset_download_review_candidate
                    or
                    scope_task_data_document_reader_review_candidate
                    or scope_task_data_python_readonly_review_candidate
                    or scope_task_data_to_output_python_batch_review_candidate
                    or scope_task_output_local_generated_script_review_candidate
                )
            ):
                continue
            reasons.append(rule_id)

    reviewable_local, ineligible_reasons = _is_reviewable_local_effect(effect_summary, context, event)
    contextual_session = dimensions.d4 > 0 or _context_has_prior_fspr_block(context)
    if contextual_session and event.event_type == EventType.PRE_ACTION and risk_level in {
        RiskLevel.HIGH,
        RiskLevel.CRITICAL,
    }:
        if _context_has_prior_fspr_block(context) and rule_hits.intersection({
            "prior_fspr_block_relative_skill_package_access",
            "prior_fspr_block_interactive_shell",
        }):
            reasons.append("prior_fspr_hard_block")
        for rule_id in sorted(rule_hits.intersection(_HARD_BLOCK_RULE_HITS)):
            if (
                rule_id == "associated_script_network_indicator"
                and (
                    scope_task_artifact_network_content_review_candidate
                    or scope_task_external_asset_download_review_candidate
                    or scope_task_output_local_generated_script_review_candidate
                )
            ):
                continue
            if (
                rule_id == "wrapper_chain_unresolved"
                and (
                    scope_task_external_asset_download_review_candidate
                    or scope_task_data_document_reader_review_candidate
                    or scope_task_data_python_readonly_review_candidate
                    or scope_task_data_to_output_python_batch_review_candidate
                    or scope_task_output_local_generated_script_review_candidate
                )
            ):
                continue
            if (
                rule_id in {"destructive_delete", "destructive_delete_target_modeled"}
                and scope_task_data_to_output_python_batch_review_candidate
            ):
                continue
            reasons.append(rule_id)
        for rule_id in sorted(evidence_rules.intersection(_HARD_BLOCK_RULE_HITS)):
            if (
                rule_id == "associated_script_network_indicator"
                and (
                    scope_task_artifact_network_content_review_candidate
                    or scope_task_external_asset_download_review_candidate
                    or scope_task_output_local_generated_script_review_candidate
                )
            ):
                continue
            if (
                rule_id == "wrapper_chain_unresolved"
                and (
                    scope_task_external_asset_download_review_candidate
                    or scope_task_data_document_reader_review_candidate
                    or scope_task_data_python_readonly_review_candidate
                    or scope_task_data_to_output_python_batch_review_candidate
                    or scope_task_output_local_generated_script_review_candidate
                )
            ):
                continue
            if (
                rule_id in {"destructive_delete", "destructive_delete_target_modeled"}
                and scope_task_data_to_output_python_batch_review_candidate
            ):
                continue
            reasons.append(rule_id)
        for effect in sorted(effects.intersection(_NON_CLEARABLE_EFFECTS)):
            if effect == "package.install" and task_artifact_output_env_setup:
                continue
            if effect == "network.fetch" and scope_task_external_asset_download_review_candidate:
                continue
            reasons.append(effect)
    if (
        event.event_type == EventType.PRE_ACTION
        and unresolved_local_writer_review_candidate
        and not reasons
        and short_circuit_rule in (None, "unresolved_analysis_escalate")
    ):
        metadata = contextual_binding_parts(event, context)
        evidence_rule_ids = {
            str(rule).lower() for rule in effect_summary.get("evidence_rules") or []
        }
        target_modelled_task_io = _effect_summary_targets_are_confirmed_task_data_to_output(
            effect_summary,
        )
        modelled_writer_l2 = _scope_task_modelled_python_io_can_use_l2(
            effect_summary,
            evidence_rules=evidence_rule_ids,
            target_modelled_task_io=target_modelled_task_io,
            path_summary=None,
        ) and (
            bool(metadata.get("input_path_hashes"))
            and bool(metadata.get("output_path_hashes"))
            and {"task_data", "task_output"}.issubset(
                set(metadata.get("artifact_roles") or [])
            )
        )
        recommended_tier = "l2" if modelled_writer_l2 else "l3"
        metadata.update({
            "schema": "clawsentry.contextual.unresolved_local_writer.v1",
            "event_id": event.event_id,
            "session_id": event.session_id,
            "l1_authority_class": L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED.value,
            "l1_block_authority": "contextual_route_only",
            "l2_l3_required": True,
            "recovery_candidate_reason": "unresolved_local_writer_semantics",
            "recovery_ineligible_reasons": [],
            "blocked_lineage_match": False,
            "anti_bypass_match": False,
            "writer_semantics_unresolved": True,
            "task_data_read_within_profile": modelled_writer_l2,
            "task_output_write_within_profile": modelled_writer_l2,
            "python_writer_target_modelled_within_profile": target_modelled_task_io,
            "modelled_task_io_l2_clearance": modelled_writer_l2,
            "l3_required": not modelled_writer_l2,
        })
        if not modelled_writer_l2:
            metadata["l3_request_reason"] = "unresolved_local_writer_semantics"
        return (
            L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED,
            ["unresolved_local_writer_semantics"],
            ReviewRoutingIntent(
                source="contextual_review",
                recommended_tier=recommended_tier,
                policy_action="defer",
                reason="unresolved_local_writer_semantics",
                source_metadata=metadata,
                routing_affecting=True,
                decision_affecting=False,
            ),
        )
    if (
        event.event_type == EventType.PRE_ACTION
        and risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}
        and contextual_session
        and not reviewable_local
        and not scope_task_artifact_network_content_review_candidate
        and not scope_task_artifact_external_reference_review_candidate
        and not scope_task_external_asset_download_review_candidate
        and not scope_task_compat_auxiliary_output_review_candidate
        and not scope_task_local_helper_future_exec_review_candidate
        and not scope_task_output_local_generated_script_review_candidate
        and not scope_task_auxiliary_data_copy_review_candidate
        and not scope_task_data_read_content_review_candidate
        and not scope_task_data_document_reader_review_candidate
        and not scope_task_data_python_readonly_review_candidate
        and not scope_task_data_to_output_python_batch_review_candidate
        and not scope_task_output_local_vcs_mutation_review_candidate
        and not scope_task_local_artifact_execution_review_candidate
        and not scope_task_local_maven_exec_java_review_candidate
        and not scope_task_local_fat_jar_execution_review_candidate
        and not verified_skill_package_read_review_candidate
    ):
        # Snapshot the concrete block reasons before appending the contextual
        # ineligibility metadata below. When the command operates on declared
        # task artifacts, the unresolved-analysis downgrade gate judges only
        # the concrete rule/effect reasons; meta tags such as
        # "disqualifying_rule:wrapper_chain_unresolved" or
        # "cwd_outside_workspace" merely restate why *other* contextual routes
        # were not granted and would otherwise veto the gate for every session
        # that already saw one high-risk event (D4 > 0), which is exactly the
        # overblock cascade this gate exists to break.
        core_block_reasons = list(reasons)
        reasons.extend(ineligible_reasons)
    else:
        core_block_reasons = list(reasons)

    if reasons:
        deduped_reasons = list(dict.fromkeys(reasons))
        # Downgrade gate: route to L2/L3 contextual review instead of failing
        # closed *only* when the sole hard-block reason is "analysis unresolved"
        # (the parser could not resolve a CLI wrapper) AND the wider snapshot shows
        # no concrete dangerous behaviour. This is conservative by construction:
        #   - block reasons must be a subset of the unresolved-analysis whitelist
        #   - no taint flow (rules out bulk-destructive / source→sink chains)
        #   - effects limited to read / enumerate / probe / plain command.exec
        #     (rules out redirect-writes-to-unscoped-paths, network, package)
        #   - no residual rule signalling a concrete behaviour (pipe-to-executing
        #     consumer, redirection write, local verify/exec, destructive, etc.)
        # FSPR verdicts and every real-danger rule fall outside this envelope, so
        # they keep the deterministic hard block. Any unrecognized signal defaults
        # to keeping the block, protecting ASR.
        residual_rules = (rule_hits | evidence_rules) - _UNRESOLVED_ANALYSIS_BENIGN_RULES
        # A declared-artifact anchor is a *necessary* condition for the
        # route: at least one extracted path target must be a declared task
        # artifact candidate (task_data read or effective task_output). A
        # command whose analysis resolved no path targets at all (e.g. an
        # opaque wrapper the parser gave up on) must NOT ride the unresolved
        # whitelist into L2 — zero targets means zero knowledge, and zero
        # knowledge fails closed. Separately, full read-side candidacy lets
        # the subset check ignore contextual-ineligibility meta reasons
        # (workspace relation, cwd location, unqualified-candidate tags),
        # which merely restate why other contextual routes were not granted.
        gate_targets = list(effect_summary.get("targets") or [])
        gate_artifact_anchor = _has_any_scope_task_artifact_target(gate_targets)
        if _has_scope_task_artifact_candidacy(gate_targets):
            gate_reasons = list(dict.fromkeys(core_block_reasons))
        else:
            gate_reasons = deduped_reasons
        if (
            event.event_type == EventType.PRE_ACTION
            and gate_artifact_anchor
            and gate_reasons
            and set(gate_reasons).issubset(_UNRESOLVED_ANALYSIS_ONLY_BLOCK_REASONS)
            and "task_scope_path_escape" not in ineligible_reasons
            and snapshot_fields.get("taint_flow_summary") is None
            and effects.issubset(_UNRESOLVED_ANALYSIS_ALLOWED_EFFECTS)
            and not residual_rules
        ):
            metadata = contextual_binding_parts(event, context)
            metadata.update({
                "schema": "clawsentry.contextual.unresolved_analysis_escalate.v1",
                "event_id": event.event_id,
                "session_id": event.session_id,
                "l1_authority_class": L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED.value,
                "l1_block_authority": "contextual_route_only",
                "l2_l3_required": True,
                "recovery_candidate_reason": "unresolved_analysis_escalate",
                "unresolved_analysis_reasons": gate_reasons,
            })
            return (
                L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED,
                ["unresolved_analysis_escalate"],
                ReviewRoutingIntent(
                    source="contextual_review",
                    recommended_tier="l2",
                    policy_action="defer",
                    reason="unresolved_analysis_escalate",
                    source_metadata=metadata,
                    routing_affecting=True,
                    decision_affecting=False,
                ),
            )
        return L1AuthorityClass.DETERMINISTIC_HARD_BLOCK, deduped_reasons, None

    if (
        event.event_type == EventType.PRE_ACTION
        and verified_skill_package_read_review_candidate
    ):
        package_paths = _event_skill_package_paths(event, effect_summary=effect_summary)
        mixed_manifest_and_sibling_read = any(
            _is_skill_manifest_root_path(path) for path in package_paths
        ) and any(not _is_skill_manifest_root_path(path) for path in package_paths)
        recommended_tier = "l3" if mixed_manifest_and_sibling_read else "l2"
        metadata = contextual_binding_parts(event, context)
        if not metadata.get("effect_hash") or not metadata.get("raw_payload_hash"):
            return (
                L1AuthorityClass.DETERMINISTIC_HARD_BLOCK,
                ["verified_skill_package_read_binding_missing"],
                None,
            )
        metadata.update({
            "schema": "clawsentry.contextual.verified_skill_package_read.v1",
            "event_id": event.event_id,
            "session_id": event.session_id,
            "l1_authority_class": L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED.value,
            "l1_block_authority": "contextual_route_only",
            "l2_l3_required": True,
            "recovery_candidate_reason": "verified_skill_package_read_review",
            "recovery_ineligible_reasons": [],
            "blocked_lineage_match": False,
            "anti_bypass_match": False,
            "verified_skill_package_read": True,
            "read_only": True,
            "no_redline_behavior": True,
            "binding_confidence": 0.8,
            "mixed_manifest_and_sibling_read": mixed_manifest_and_sibling_read,
            "l3_required": mixed_manifest_and_sibling_read,
            "l2_clearance_allowed": not mixed_manifest_and_sibling_read,
        })
        if mixed_manifest_and_sibling_read:
            metadata["l3_request_reason"] = "verified_skill_package_read_review"
        else:
            metadata["l2_request_reason"] = "verified_skill_package_read_review"
        return (
            L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED,
            ["verified_skill_package_read_review"],
            ReviewRoutingIntent(
                source="contextual_review",
                recommended_tier=recommended_tier,
                policy_action="defer",
                reason="verified_skill_package_read_review",
                source_metadata=metadata,
                routing_affecting=True,
                decision_affecting=False,
            ),
        )

    if (
        event.event_type == EventType.PRE_ACTION
        and scope_task_local_fat_jar_execution_review_candidate
    ):
        metadata = contextual_binding_parts(event, context)
        if (
            not metadata.get("effect_hash")
            or not metadata.get("raw_payload_hash")
            or not metadata.get("input_path_hashes")
            or not metadata.get("output_path_hashes")
            or not metadata.get("artifact_profile_hashes")
            or "task_data" not in set(metadata.get("artifact_roles") or [])
            or "task_output" not in set(metadata.get("artifact_roles") or [])
        ):
            return (
                L1AuthorityClass.DETERMINISTIC_HARD_BLOCK,
                ["scope_task_local_fat_jar_execution_binding_missing"],
                None,
            )
        metadata.update({
            "schema": "clawsentry.contextual.scope_task_local_fat_jar_execution.v1",
            "event_id": event.event_id,
            "session_id": event.session_id,
            "l1_authority_class": L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED.value,
            "l1_block_authority": "contextual_route_only",
            "l2_l3_required": True,
            "recovery_candidate_reason": "scope_task_local_fat_jar_execution_review",
            "recovery_ineligible_reasons": [],
            "blocked_lineage_match": False,
            "anti_bypass_match": False,
            "task_boundary_contract_qualified": True,
            "task_data_read_within_profile": True,
            "task_output_write_within_profile": True,
            "task_output_execution_within_profile": True,
            "all_targets_contract_qualified": True,
            "future_exec_kind": "none",
            "clears_write_only": False,
            "executes_artifact": True,
            "jar_execution": True,
            "fat_jar_execution": True,
            "read_after_write_execution": False,
            "no_redline_behavior": True,
            "binding_confidence": 1.0,
            "l3_required": True,
            "l3_request_reason": "scope_task_local_fat_jar_execution_review",
        })
        return (
            L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED,
            ["scope_task_local_fat_jar_execution_review"],
            ReviewRoutingIntent(
                source="contextual_review",
                recommended_tier="l3",
                policy_action="defer",
                reason="scope_task_local_fat_jar_execution_review",
                source_metadata=metadata,
                routing_affecting=True,
                decision_affecting=False,
            ),
        )

    if (
        event.event_type == EventType.PRE_ACTION
        and scope_task_local_maven_exec_java_review_candidate
    ):
        metadata = contextual_binding_parts(event, context)
        if (
            not metadata.get("effect_hash")
            or not metadata.get("raw_payload_hash")
            or not metadata.get("input_path_hashes")
            or not metadata.get("output_path_hashes")
            or not metadata.get("artifact_profile_hashes")
            or "task_data" not in set(metadata.get("artifact_roles") or [])
            or "task_output" not in set(metadata.get("artifact_roles") or [])
        ):
            return (
                L1AuthorityClass.DETERMINISTIC_HARD_BLOCK,
                ["scope_task_local_maven_exec_java_binding_missing"],
                None,
            )
        metadata.update({
            "schema": "clawsentry.contextual.scope_task_local_maven_exec_java.v1",
            "event_id": event.event_id,
            "session_id": event.session_id,
            "l1_authority_class": L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED.value,
            "l1_block_authority": "contextual_route_only",
            "l2_l3_required": True,
            "recovery_candidate_reason": "scope_task_local_maven_exec_java_review",
            "recovery_ineligible_reasons": [],
            "blocked_lineage_match": False,
            "anti_bypass_match": False,
            "task_boundary_contract_qualified": True,
            "task_data_read_within_profile": True,
            "task_output_write_within_profile": True,
            "task_output_execution_within_profile": True,
            "all_targets_contract_qualified": True,
            "future_exec_kind": "none",
            "clears_write_only": False,
            "executes_artifact": True,
            "maven_exec_java": True,
            "read_after_write_execution": False,
            "no_redline_behavior": True,
            "binding_confidence": 1.0,
            "l3_required": True,
            "l3_request_reason": "scope_task_local_maven_exec_java_review",
        })
        return (
            L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED,
            ["scope_task_local_maven_exec_java_review"],
            ReviewRoutingIntent(
                source="contextual_review",
                recommended_tier="l3",
                policy_action="defer",
                reason="scope_task_local_maven_exec_java_review",
                source_metadata=metadata,
                routing_affecting=True,
                decision_affecting=False,
            ),
        )

    if (
        event.event_type == EventType.PRE_ACTION
        and scope_task_local_artifact_execution_review_candidate
    ):
        metadata = contextual_binding_parts(event, context)
        if (
            not metadata.get("effect_hash")
            or not metadata.get("raw_payload_hash")
            or not metadata.get("input_path_hashes")
            or not metadata.get("output_path_hashes")
            or not metadata.get("artifact_profile_hashes")
            or "task_data" not in set(metadata.get("artifact_roles") or [])
            or "task_output" not in set(metadata.get("artifact_roles") or [])
        ):
            return (
                L1AuthorityClass.DETERMINISTIC_HARD_BLOCK,
                ["scope_task_local_artifact_execution_binding_missing"],
                None,
            )
        metadata.update({
            "schema": "clawsentry.contextual.scope_task_local_artifact_execution.v1",
            "event_id": event.event_id,
            "session_id": event.session_id,
            "l1_authority_class": L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED.value,
            "l1_block_authority": "contextual_route_only",
            "l2_l3_required": True,
            "recovery_candidate_reason": "scope_task_local_artifact_execution_review",
            "recovery_ineligible_reasons": [],
            "blocked_lineage_match": False,
            "anti_bypass_match": False,
            "task_boundary_contract_qualified": True,
            "task_data_read_within_profile": True,
            "task_output_write_within_profile": True,
            "task_output_execution_within_profile": True,
            "all_targets_contract_qualified": True,
            "future_exec_kind": "none",
            "clears_write_only": False,
            "executes_artifact": True,
            "read_after_write_execution": False,
            "no_redline_behavior": True,
            "binding_confidence": 1.0,
            "l3_required": False,
        })
        return (
            L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED,
            ["scope_task_local_artifact_execution_review"],
            ReviewRoutingIntent(
                source="contextual_review",
                recommended_tier="l2",
                policy_action="defer",
                reason="scope_task_local_artifact_execution_review",
                source_metadata=metadata,
                routing_affecting=True,
                decision_affecting=False,
            ),
        )

    if (
        event.event_type == EventType.PRE_ACTION
        and scope_task_external_asset_download_review_candidate
    ):
        download_details = _static_external_asset_download_details(event) or {}
        metadata = contextual_binding_parts(event, context)
        future_exec_kind = _scope_task_artifact_future_exec_kind(effect_summary)
        external_asset_l3_required = future_exec_kind != "none"
        if (
            not metadata.get("effect_hash")
            or not metadata.get("raw_payload_hash")
            or not metadata.get("output_path_hashes")
            or not metadata.get("artifact_profile_hashes")
            or "task_output" not in set(metadata.get("artifact_roles") or [])
        ):
            return (
                L1AuthorityClass.DETERMINISTIC_HARD_BLOCK,
                ["scope_task_external_asset_download_binding_missing"],
                None,
            )
        metadata.update({
            "schema": "clawsentry.contextual.scope_task_external_asset_download.v1",
            "event_id": event.event_id,
            "session_id": event.session_id,
            "l1_authority_class": L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED.value,
            "l1_block_authority": "contextual_route_only",
            "l2_l3_required": True,
            "recovery_candidate_reason": "scope_task_external_asset_download_review",
            "recovery_ineligible_reasons": [],
            "blocked_lineage_match": False,
            "anti_bypass_match": False,
            "task_boundary_contract_qualified": True,
            "task_data_read_within_profile": True,
            "task_output_write_within_profile": True,
            "all_targets_contract_qualified": True,
            "future_exec_kind": future_exec_kind,
            "external_asset_download": True,
            "network_download_write": True,
            "external_asset_download_tool": download_details.get("tool"),
            "external_asset_url_hash": (
                _contextual_path_hash(str(download_details.get("url") or ""))
                if download_details.get("url")
                else None
            ),
            "external_asset_allows_redirects": bool(download_details.get("allows_redirects")),
            "no_upload_effect": not effects.intersection({"network.upload", "network.external"}),
            "executes_artifact": False,
            "read_after_write_execution": False,
            "no_redline_behavior": True,
            "binding_confidence": 1.0,
            "l3_required": external_asset_l3_required,
            "l2_clearance_allowed": not external_asset_l3_required,
            "l2_request_reason": "scope_task_external_asset_download_review",
        })
        return (
            L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED,
            ["scope_task_external_asset_download_review"],
            ReviewRoutingIntent(
                source="contextual_review",
                recommended_tier="l3" if external_asset_l3_required else "l2",
                policy_action="defer",
                reason="scope_task_external_asset_download_review",
                source_metadata=metadata,
                routing_affecting=True,
                decision_affecting=False,
            ),
        )

    if (
        event.event_type == EventType.PRE_ACTION
        and scope_task_artifact_network_content_review_candidate
    ):
        metadata = contextual_binding_parts(event, context)
        if (
            not metadata.get("effect_hash")
            or not metadata.get("raw_payload_hash")
            or not metadata.get("output_path_hashes")
            or not metadata.get("artifact_profile_hashes")
        ):
            return (
                L1AuthorityClass.DETERMINISTIC_HARD_BLOCK,
                ["scope_task_artifact_network_content_binding_missing"],
                None,
            )
        metadata.update({
            "schema": "clawsentry.contextual.scope_task_artifact_network_content.v1",
            "event_id": event.event_id,
            "session_id": event.session_id,
            "l1_authority_class": L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED.value,
            "l1_block_authority": "contextual_route_only",
            "l2_l3_required": True,
            "recovery_candidate_reason": "scope_task_artifact_network_content_review",
            "recovery_ineligible_reasons": [],
            "blocked_lineage_match": False,
            "anti_bypass_match": False,
            "task_boundary_contract_qualified": True,
            "task_data_read_within_profile": (
                "filesystem.read" not in effects
                and "filesystem.enumerate" not in effects
            ) or "task_data" in set(metadata.get("artifact_roles") or []),
            "task_output_write_within_profile": "task_output" in set(metadata.get("artifact_roles") or []),
            "all_targets_contract_qualified": True,
            "future_exec_kind": _scope_task_artifact_future_exec_kind(effect_summary),
            "network_content_dispute": True,
            "no_actual_network_effect": not effects.intersection({"network.fetch", "network.upload", "network.external"}),
            "executes_artifact": False,
            "read_after_write_execution": False,
            "no_redline_behavior": True,
            "binding_confidence": 1.0,
            "l3_required": True,
            "l3_request_reason": "task_output_network_content_dispute",
        })
        return (
            L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED,
            ["scope_task_artifact_network_content_review"],
            ReviewRoutingIntent(
                source="contextual_review",
                recommended_tier="l3",
                policy_action="defer",
                reason="scope_task_artifact_network_content_review",
                source_metadata=metadata,
                routing_affecting=True,
                decision_affecting=False,
            ),
        )

    if (
        event.event_type == EventType.PRE_ACTION
        and scope_task_artifact_external_reference_review_candidate
    ):
        metadata = contextual_binding_parts(event, context)
        if (
            not metadata.get("effect_hash")
            or not metadata.get("raw_payload_hash")
            or not metadata.get("output_path_hashes")
            or not metadata.get("artifact_profile_hashes")
        ):
            return (
                L1AuthorityClass.DETERMINISTIC_HARD_BLOCK,
                ["scope_task_artifact_external_reference_binding_missing"],
                None,
            )
        metadata.update({
            "schema": "clawsentry.contextual.scope_task_artifact_external_reference.v1",
            "event_id": event.event_id,
            "session_id": event.session_id,
            "l1_authority_class": L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED.value,
            "l1_block_authority": "contextual_route_only",
            "l2_l3_required": True,
            "recovery_candidate_reason": "scope_task_artifact_external_reference_review",
            "recovery_ineligible_reasons": [],
            "blocked_lineage_match": False,
            "anti_bypass_match": False,
            "task_boundary_contract_qualified": True,
            "task_data_read_within_profile": (
                "filesystem.read" not in effects
                and "filesystem.enumerate" not in effects
            ) or "task_data" in set(metadata.get("artifact_roles") or []),
            "task_output_write_within_profile": "task_output" in set(metadata.get("artifact_roles") or []),
            "all_targets_contract_qualified": True,
            "external_reference_instruction": True,
            "no_actual_network_effect": not effects.intersection({"network.fetch", "network.upload", "network.external"}),
            "executes_artifact": False,
            "read_after_write_execution": False,
            "no_redline_behavior": True,
            "binding_confidence": 1.0,
            "l3_required": True,
            "l3_request_reason": "task_output_external_reference_instruction",
        })
        return (
            L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED,
            ["scope_task_artifact_external_reference_review"],
            ReviewRoutingIntent(
                source="contextual_review",
                recommended_tier="l3",
                policy_action="defer",
                reason="scope_task_artifact_external_reference_review",
                source_metadata=metadata,
                routing_affecting=True,
                decision_affecting=False,
            ),
        )

    if (
        event.event_type == EventType.PRE_ACTION
        and scope_task_artifact_hardblock_review_candidate
    ):
        metadata = contextual_binding_parts(event, context)
        if (
            not metadata.get("effect_hash")
            or not metadata.get("raw_payload_hash")
            or not metadata.get("output_path_hashes")
            or not metadata.get("artifact_profile_hashes")
        ):
            return (
                L1AuthorityClass.DETERMINISTIC_HARD_BLOCK,
                ["scope_task_artifact_binding_missing"],
                None,
            )
        metadata.update({
            "schema": "clawsentry.contextual.scope_task_artifact.v1",
            "event_id": event.event_id,
            "session_id": event.session_id,
            "l1_authority_class": L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED.value,
            "l1_block_authority": "contextual_route_only",
            "l2_l3_required": True,
            "recovery_candidate_reason": "scope_task_artifact_hardblock_review",
            "recovery_ineligible_reasons": [],
            "blocked_lineage_match": False,
            "anti_bypass_match": False,
            "task_boundary_contract_qualified": True,
            "task_data_read_within_profile": (
                "filesystem.read" not in effects
                and "filesystem.enumerate" not in effects
            ) or "task_data" in set(metadata.get("artifact_roles") or []),
            "task_output_write_within_profile": "task_output" in set(metadata.get("artifact_roles") or []),
            "all_targets_contract_qualified": True,
            "future_exec_kind": _scope_task_artifact_future_exec_kind(effect_summary),
            "clears_write_only": True,
            "executes_artifact": False,
            "read_after_write_execution": False,
            "no_redline_behavior": True,
            "binding_confidence": 1.0,
            "l3_required": False,
        })
        return (
            L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED,
            ["scope_task_artifact_hardblock_review"],
            ReviewRoutingIntent(
                source="contextual_review",
                recommended_tier="l2",
                policy_action="defer",
                reason="scope_task_artifact_hardblock_review",
                source_metadata=metadata,
                routing_affecting=True,
                decision_affecting=False,
            ),
        )

    if (
        event.event_type == EventType.PRE_ACTION
        and scope_task_output_local_generated_script_review_candidate
    ):
        generated_auxiliary_output_content = (
            "generated_script_future_exec" in evidence_rules
            and _event_has_generated_script_auxiliary_output_content_hint(event)
        )
        unobserved_future_exec_rules = sorted(evidence_rules.intersection({
            "dd_unobserved_future_exec_write",
            "python_unobserved_stdin_future_exec_write",
            "shell_unobserved_stdin_future_exec_write",
        }))
        unobserved_future_exec_write = bool(unobserved_future_exec_rules)
        unobserved_stdin_future_exec_write = any(
            rule in {
                "python_unobserved_stdin_future_exec_write",
                "shell_unobserved_stdin_future_exec_write",
            }
            for rule in unobserved_future_exec_rules
        )
        metadata = contextual_binding_parts(event, context)
        if (
            not metadata.get("effect_hash")
            or not metadata.get("raw_payload_hash")
            or not metadata.get("output_path_hashes")
            or "task_output" not in set(metadata.get("artifact_roles") or [])
        ):
            return (
                L1AuthorityClass.DETERMINISTIC_HARD_BLOCK,
                ["scope_task_output_local_generated_script_binding_missing"],
                None,
            )
        metadata.update({
            "schema": "clawsentry.contextual.scope_task_output_local_generated_script.v1",
            "event_id": event.event_id,
            "session_id": event.session_id,
            "l1_authority_class": L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED.value,
            "l1_block_authority": "contextual_route_only",
            "l2_l3_required": True,
            "recovery_candidate_reason": "scope_task_output_local_generated_script_review",
            "recovery_ineligible_reasons": [],
            "blocked_lineage_match": False,
            "anti_bypass_match": False,
            "task_output_write_within_scope": True,
            "local_generated_script": True,
            "associated_script_network_indicator": (
                "associated_script_network_indicator" in evidence_rules
            ),
            "wrapper_chain_unresolved": "wrapper_chain_unresolved" in evidence_rules,
            "unobserved_stdin_future_exec_write": unobserved_stdin_future_exec_write,
            "unobserved_future_exec_write": unobserved_future_exec_write,
            "unobserved_future_exec_write_rules": unobserved_future_exec_rules,
            "no_actual_network_effect": not effects.intersection({
                "network.fetch",
                "network.upload",
                "network.external",
            }),
            "no_external_network_reference": True,
            "auxiliary_output_semantic_hint": generated_auxiliary_output_content,
            "all_targets_contract_qualified": (
                "risk_adjusting" in set(metadata.get("artifact_source_tiers") or [])
            ),
            "future_exec_kind": _scope_task_artifact_future_exec_kind(effect_summary),
            "executes_artifact": False,
            "read_after_write_execution": False,
            "no_redline_behavior": True,
            "binding_confidence": 0.70 if unobserved_future_exec_write else 0.85,
            "l3_required": unobserved_future_exec_write or generated_auxiliary_output_content,
            "l3_request_reason": (
                "generated_script_auxiliary_output_semantics"
                if generated_auxiliary_output_content
                else (
                    "unobserved_future_execution_write"
                    if unobserved_future_exec_write
                    else None
                )
            ),
        })
        return (
            L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED,
            ["scope_task_output_local_generated_script_review"],
            ReviewRoutingIntent(
                source="contextual_review",
                recommended_tier=(
                    "l3"
                    if unobserved_future_exec_write or generated_auxiliary_output_content
                    else "l2"
                ),
                policy_action="defer",
                reason="scope_task_output_local_generated_script_review",
                source_metadata=metadata,
                routing_affecting=True,
                decision_affecting=False,
            ),
        )

    if (
        event.event_type == EventType.PRE_ACTION
        and scope_task_auxiliary_data_copy_review_candidate
    ):
        metadata = contextual_binding_parts(event, context)
        if (
            not metadata.get("effect_hash")
            or not metadata.get("raw_payload_hash")
            or not metadata.get("input_path_hashes")
            or not metadata.get("output_path_hashes")
            or "task_data" not in set(metadata.get("artifact_roles") or [])
            or "task_output" not in set(metadata.get("artifact_roles") or [])
        ):
            return (
                L1AuthorityClass.DETERMINISTIC_HARD_BLOCK,
                ["scope_task_auxiliary_data_copy_binding_missing"],
                None,
            )
        metadata.update({
            "schema": "clawsentry.contextual.scope_task_auxiliary_data_copy.v1",
            "event_id": event.event_id,
            "session_id": event.session_id,
            "l1_authority_class": L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED.value,
            "l1_block_authority": "contextual_route_only",
            "l2_l3_required": True,
            "recovery_candidate_reason": "scope_task_auxiliary_data_copy_review",
            "recovery_ineligible_reasons": [],
            "blocked_lineage_match": False,
            "anti_bypass_match": False,
            "task_data_read_within_scope": True,
            "task_output_write_within_scope": True,
            "auxiliary_output_semantic_hint": True,
            "direct_task_data_to_auxiliary_output": True,
            "all_targets_contract_qualified": False,
            "future_exec_kind": "none",
            "executes_artifact": False,
            "read_after_write_execution": False,
            "no_redline_behavior": True,
            "binding_confidence": 0.85,
            "l3_required": True,
            "l3_request_reason": "task_data_to_auxiliary_output_copy",
        })
        return (
            L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED,
            ["scope_task_auxiliary_data_copy_review"],
            ReviewRoutingIntent(
                source="contextual_review",
                recommended_tier="l3",
                policy_action="defer",
                reason="scope_task_auxiliary_data_copy_review",
                source_metadata=metadata,
                routing_affecting=True,
                decision_affecting=False,
            ),
        )

    if (
        event.event_type == EventType.PRE_ACTION
        and scope_task_compat_auxiliary_output_review_candidate
    ):
        metadata = contextual_binding_parts(event, context)
        if (
            not metadata.get("effect_hash")
            or not metadata.get("raw_payload_hash")
            or not metadata.get("output_path_hashes")
            or "task_output" not in set(metadata.get("artifact_roles") or [])
            or "legacy_compat" not in set(metadata.get("artifact_source_tiers") or [])
        ):
            return (
                L1AuthorityClass.DETERMINISTIC_HARD_BLOCK,
                ["scope_task_compat_auxiliary_output_binding_missing"],
                None,
            )
        metadata.update({
            "schema": "clawsentry.contextual.scope_task_compat_auxiliary_output.v1",
            "event_id": event.event_id,
            "session_id": event.session_id,
            "l1_authority_class": L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED.value,
            "l1_block_authority": "contextual_route_only",
            "l2_l3_required": True,
            "recovery_candidate_reason": "scope_task_compat_auxiliary_output_review",
            "recovery_ineligible_reasons": [],
            "blocked_lineage_match": False,
            "anti_bypass_match": False,
            "task_output_write_within_compat": True,
            "declared_output_contract": False,
            "scope_task_compat_output": True,
            "auxiliary_output_semantic_hint": True,
            "all_targets_contract_qualified": False,
            "future_exec_kind": _scope_task_compat_future_exec_kind(effect_summary),
            "executes_artifact": False,
            "read_after_write_execution": False,
            "no_redline_behavior": True,
            "binding_confidence": 0.75,
            "l3_required": True,
            "l3_request_reason": "task_output_compat_auxiliary_output_semantics",
        })
        return (
            L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED,
            ["scope_task_compat_auxiliary_output_review"],
            ReviewRoutingIntent(
                source="contextual_review",
                recommended_tier="l3",
                policy_action="defer",
                reason="scope_task_compat_auxiliary_output_review",
                source_metadata=metadata,
                routing_affecting=True,
                decision_affecting=False,
            ),
        )

    if (
        event.event_type == EventType.PRE_ACTION
        and scope_task_contract_auxiliary_output_review_candidate
    ):
        metadata = contextual_binding_parts(event, context)
        if (
            not metadata.get("effect_hash")
            or not metadata.get("raw_payload_hash")
            or not metadata.get("output_path_hashes")
            or "task_output" not in set(metadata.get("artifact_roles") or [])
            or "risk_adjusting" not in set(metadata.get("artifact_source_tiers") or [])
        ):
            return (
                L1AuthorityClass.DETERMINISTIC_HARD_BLOCK,
                ["scope_task_contract_auxiliary_output_binding_missing"],
                None,
            )
        metadata.update({
            "schema": "clawsentry.contextual.scope_task_contract_auxiliary_output.v1",
            "event_id": event.event_id,
            "session_id": event.session_id,
            "l1_authority_class": L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED.value,
            "l1_block_authority": "contextual_route_only",
            "l2_l3_required": True,
            "recovery_candidate_reason": "scope_task_contract_auxiliary_output_review",
            "recovery_ineligible_reasons": [],
            "blocked_lineage_match": False,
            "anti_bypass_match": False,
            "task_output_write_within_profile": True,
            "declared_output_contract": True,
            "scope_task_compat_output": False,
            "auxiliary_output_semantic_hint": True,
            "broad_output_contract_match": True,
            "future_exec_kind": _scope_task_artifact_future_exec_kind(effect_summary),
            "executes_artifact": False,
            "read_after_write_execution": False,
            "no_redline_behavior": True,
            "binding_confidence": 0.85,
            "l3_required": True,
            "l3_request_reason": "task_output_contract_auxiliary_output_semantics",
        })
        return (
            L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED,
            ["scope_task_contract_auxiliary_output_review"],
            ReviewRoutingIntent(
                source="contextual_review",
                recommended_tier="l3",
                policy_action="defer",
                reason="scope_task_contract_auxiliary_output_review",
                source_metadata=metadata,
                routing_affecting=True,
                decision_affecting=False,
            ),
        )

    if (
        event.event_type == EventType.PRE_ACTION
        and scope_task_local_helper_future_exec_review_candidate
    ):
        metadata = contextual_binding_parts(event, context)
        if not metadata.get("effect_hash") or not metadata.get("raw_payload_hash"):
            return (
                L1AuthorityClass.DETERMINISTIC_HARD_BLOCK,
                ["scope_task_local_helper_binding_missing"],
                None,
            )
        artifact_roles = set(metadata.get("artifact_roles") or [])
        helper_has_task_output_binding = (
            "task_data" in artifact_roles
            and "task_output" in artifact_roles
            and bool(metadata.get("input_path_hashes"))
            and bool(metadata.get("output_path_hashes"))
        )
        helper_l3_escalation_rules = sorted(evidence_rules.intersection({
            "associated_script_wrapper_indicator",
            "associated_script_package_indicator",
            "associated_script_destructive_indicator",
            "associated_script_network_indicator",
            "associated_script_auxiliary_write_indicator",
            "associated_script_unscoped_write_indicator",
            "associated_script_unresolved_write_indicator",
            "generated_script_shebang",
        }))
        helper_auxiliary_output_content = _event_has_generated_script_auxiliary_output_content_hint(event)
        helper_l3_required = (
            not helper_has_task_output_binding
            or bool(helper_l3_escalation_rules)
            or helper_auxiliary_output_content
        )
        if helper_auxiliary_output_content:
            helper_l3_request_reason = "generated_script_auxiliary_output_semantics"
        elif helper_l3_escalation_rules:
            helper_l3_request_reason = "generated_local_helper_high_risk_semantics"
        elif not helper_has_task_output_binding:
            helper_l3_request_reason = "generated_local_helper_future_execution"
        else:
            helper_l3_request_reason = None
        metadata.update({
            "schema": "clawsentry.contextual.scope_task_local_helper.v1",
            "event_id": event.event_id,
            "session_id": event.session_id,
            "l1_authority_class": L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED.value,
            "l1_block_authority": "contextual_route_only",
            "l2_l3_required": True,
            "recovery_candidate_reason": "scope_task_local_helper_future_exec_review",
            "recovery_ineligible_reasons": [],
            "blocked_lineage_match": False,
            "anti_bypass_match": False,
            "task_data_read_within_profile": "task_data" in set(metadata.get("artifact_roles") or []),
            "task_output_write_within_profile": "task_output" in set(metadata.get("artifact_roles") or []),
            "future_exec_kind": "local_helper_write",
            "local_helper_write": True,
            "generated_helper_static_source_visible": True,
            "static_task_pipeline_helper": helper_has_task_output_binding,
            "script_task_output_write_within_profile": helper_has_task_output_binding,
            "helper_l3_escalation_rules": helper_l3_escalation_rules,
            "auxiliary_output_semantic_hint": helper_auxiliary_output_content,
            "no_redline_behavior": True,
            "binding_confidence": 0.85 if helper_has_task_output_binding else 0.75,
            "l3_required": helper_l3_required,
            "l3_request_reason": helper_l3_request_reason,
        })
        return (
            L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED,
            ["scope_task_local_helper_future_exec_review"],
            ReviewRoutingIntent(
                source="contextual_review",
                recommended_tier="l3" if helper_l3_required else "l2",
                policy_action="defer",
                reason="scope_task_local_helper_future_exec_review",
                source_metadata=metadata,
                routing_affecting=True,
                decision_affecting=False,
            ),
        )

    if (
        event.event_type == EventType.PRE_ACTION
        and scope_task_output_local_vcs_mutation_review_candidate
    ):
        metadata = contextual_binding_parts(event, context)
        if (
            not metadata.get("effect_hash")
            or not metadata.get("raw_payload_hash")
            or not metadata.get("output_path_hashes")
            or "task_output" not in set(metadata.get("artifact_roles") or [])
        ):
            return (
                L1AuthorityClass.DETERMINISTIC_HARD_BLOCK,
                ["scope_task_output_local_vcs_mutation_binding_missing"],
                None,
            )
        metadata.update({
            "schema": "clawsentry.contextual.scope_task_output_local_vcs_mutation.v1",
            "event_id": event.event_id,
            "session_id": event.session_id,
            "l1_authority_class": L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED.value,
            "l1_block_authority": "contextual_route_only",
            "l2_l3_required": True,
            "recovery_candidate_reason": "scope_task_output_local_vcs_mutation_review",
            "recovery_ineligible_reasons": [],
            "blocked_lineage_match": False,
            "anti_bypass_match": False,
            "task_output_write_within_profile": True,
            "local_vcs_patch_apply": True,
            "patch_body_unverified": True,
            "no_redline_behavior": True,
            "binding_confidence": 0.75,
            "l3_required": True,
        })
        return (
            L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED,
            ["scope_task_output_local_vcs_mutation_review"],
            ReviewRoutingIntent(
                source="contextual_review",
                recommended_tier="l3",
                policy_action="defer",
                reason="scope_task_output_local_vcs_mutation_review",
                source_metadata=metadata,
                routing_affecting=True,
                decision_affecting=False,
            ),
        )

    if (
        event.event_type == EventType.PRE_ACTION
        and scope_task_data_read_content_review_candidate
    ):
        metadata = contextual_binding_parts(event, context)
        read_content_review_rule_ids = _scope_task_data_read_content_review_rule_ids(context)
        read_content_l3_required = read_content_review_rule_ids != {"read_content_markdown_beacon"}
        if (
            not metadata.get("effect_hash")
            or not metadata.get("raw_payload_hash")
            or not metadata.get("input_path_hashes")
            or "task_data" not in set(metadata.get("artifact_roles") or [])
        ):
            return (
                L1AuthorityClass.DETERMINISTIC_HARD_BLOCK,
                ["scope_task_data_read_content_binding_missing"],
                None,
            )
        metadata.update({
            "schema": "clawsentry.contextual.scope_task_data_read_content.v1",
            "event_id": event.event_id,
            "session_id": event.session_id,
            "l1_authority_class": L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED.value,
            "l1_block_authority": "contextual_route_only",
            "l2_l3_required": True,
            "recovery_candidate_reason": "scope_task_data_read_content_review",
            "recovery_ineligible_reasons": [],
            "blocked_lineage_match": False,
            "anti_bypass_match": False,
            "task_data_read_within_profile": True,
            "read_content_review_rule_ids": sorted(read_content_review_rule_ids),
            "read_content_rules_within_profile": True,
            "no_redline_behavior": True,
            "binding_confidence": 0.91,
            "l3_required": read_content_l3_required,
        })
        if read_content_l3_required:
            if "read_content_task_scope_contraction" in read_content_review_rule_ids:
                metadata["l3_request_reason"] = "task_data_task_scope_contraction"
            elif "read_content_hidden_auxiliary_output_instruction" in read_content_review_rule_ids:
                metadata["l3_request_reason"] = "task_data_hidden_auxiliary_output_instruction"
            else:
                metadata["l3_request_reason"] = "task_data_read_content_semantic_review"
        return (
            L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED,
            ["scope_task_data_read_content_review"],
            ReviewRoutingIntent(
                source="contextual_review",
                recommended_tier="l3" if read_content_l3_required else "l2",
                policy_action="defer",
                reason="scope_task_data_read_content_review",
                source_metadata=metadata,
                routing_affecting=True,
                decision_affecting=False,
            ),
        )

    if (
        event.event_type == EventType.PRE_ACTION
        and scope_task_data_document_reader_review_candidate
    ):
        metadata = contextual_binding_parts(event, context)
        if not metadata.get("effect_hash") or not metadata.get("raw_payload_hash"):
            return (
                L1AuthorityClass.DETERMINISTIC_HARD_BLOCK,
                ["scope_task_data_document_reader_binding_missing"],
                None,
            )
        metadata.update({
            "schema": "clawsentry.contextual.scope_task_data_document_reader.v1",
            "event_id": event.event_id,
            "session_id": event.session_id,
            "l1_authority_class": L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED.value,
            "l1_block_authority": "contextual_route_only",
            "l2_l3_required": True,
            "recovery_candidate_reason": "scope_task_data_document_reader_review",
            "recovery_ineligible_reasons": [],
            "blocked_lineage_match": False,
            "anti_bypass_match": False,
            "task_data_read_within_profile": True,
            "document_reader_path_unresolved": "python_document_reader_unresolved" in evidence_rules,
            "document_reader_path_resolved": "python_document_reader_read" in evidence_rules,
            "no_redline_behavior": True,
            "binding_confidence": 0.75,
            "l3_required": False,
        })
        return (
            L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED,
            ["scope_task_data_document_reader_review"],
            ReviewRoutingIntent(
                source="contextual_review",
                recommended_tier="l2",
                policy_action="defer",
                reason="scope_task_data_document_reader_review",
                source_metadata=metadata,
                routing_affecting=True,
                decision_affecting=False,
            ),
        )

    if (
        event.event_type == EventType.PRE_ACTION
        and scope_task_data_python_readonly_review_candidate
    ):
        metadata = contextual_binding_parts(event, context)
        if not metadata.get("effect_hash") or not metadata.get("raw_payload_hash"):
            return (
                L1AuthorityClass.DETERMINISTIC_HARD_BLOCK,
                ["scope_task_data_python_readonly_binding_missing"],
                None,
            )
        metadata.update({
            "schema": "clawsentry.contextual.scope_task_data_python_readonly.v1",
            "event_id": event.event_id,
            "session_id": event.session_id,
            "l1_authority_class": L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED.value,
            "l1_block_authority": "contextual_route_only",
            "l2_l3_required": True,
            "recovery_candidate_reason": "scope_task_data_python_readonly_review",
            "recovery_ineligible_reasons": [],
            "blocked_lineage_match": False,
            "anti_bypass_match": False,
            "task_data_read_within_profile": True,
            "python_read_paths_within_profile": True,
            "no_redline_behavior": True,
            "binding_confidence": 0.75,
            "l3_required": False,
        })
        return (
            L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED,
            ["scope_task_data_python_readonly_review"],
            ReviewRoutingIntent(
                source="contextual_review",
                recommended_tier="l2",
                policy_action="defer",
                reason="scope_task_data_python_readonly_review",
                source_metadata=metadata,
                routing_affecting=True,
                decision_affecting=False,
            ),
        )

    if (
        event.event_type == EventType.PRE_ACTION
        and scope_task_data_to_output_python_batch_review_candidate
    ):
        path_summary = _inline_python_task_io_path_flow_summary(
            event,
            context,
        )
        target_modelled_task_io = _effect_summary_targets_are_confirmed_task_data_to_output(
            effect_summary,
        )
        evidence_rule_ids = {
            str(rule).lower() for rule in effect_summary.get("evidence_rules") or []
        }
        modelled_python_io_l2 = _scope_task_modelled_python_io_can_use_l2(
            effect_summary,
            evidence_rules=evidence_rule_ids,
            target_modelled_task_io=target_modelled_task_io,
            path_summary=path_summary,
        )
        metadata = contextual_binding_parts(event, context)
        _merge_contextual_metadata_lists(
            metadata,
            _scope_task_io_contextual_metadata(context, path_summary),
        )
        if (
            not metadata.get("effect_hash")
            or not metadata.get("raw_payload_hash")
            or not metadata.get("input_path_hashes")
            or not metadata.get("output_path_hashes")
            or "task_data" not in set(metadata.get("artifact_roles") or [])
            or "task_output" not in set(metadata.get("artifact_roles") or [])
        ):
            return (
                L1AuthorityClass.DETERMINISTIC_HARD_BLOCK,
                ["scope_task_data_to_output_python_batch_binding_missing"],
                None,
            )
        metadata.update({
            "schema": "clawsentry.contextual.scope_task_data_to_output_python_batch.v1",
            "event_id": event.event_id,
            "session_id": event.session_id,
            "l1_authority_class": L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED.value,
            "l1_block_authority": "contextual_route_only",
            "l2_l3_required": True,
            "recovery_candidate_reason": "scope_task_data_to_output_python_batch_review",
            "recovery_ineligible_reasons": [],
            "blocked_lineage_match": False,
            "anti_bypass_match": False,
            "task_data_read_within_profile": True,
            "task_output_write_within_profile": True,
            "python_batch_static_path_literals_within_profile": path_summary is not None,
            "python_batch_target_modelled_within_profile": target_modelled_task_io,
            "python_batch_modelled_io_l2_clearance": (
                modelled_python_io_l2 and path_summary is None
            ),
            "writer_semantics_unresolved": "python_writer_method_unresolved" in evidence_rule_ids,
            "no_redline_behavior": True,
            "binding_confidence": 0.75 if modelled_python_io_l2 else 0.65,
            "l3_required": not modelled_python_io_l2,
        })
        recommended_tier = "l2" if modelled_python_io_l2 else "l3"
        return (
            L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED,
            ["scope_task_data_to_output_python_batch_review"],
            ReviewRoutingIntent(
                source="contextual_review",
                recommended_tier=recommended_tier,
                policy_action="defer",
                reason="scope_task_data_to_output_python_batch_review",
                source_metadata=metadata,
                routing_affecting=True,
                decision_affecting=False,
            ),
        )

    if (
        event.event_type == EventType.PRE_ACTION
        and scope_task_output_atomic_replace_staging_review_candidate
    ):
        metadata = contextual_binding_parts(event, context)
        if (
            not metadata.get("effect_hash")
            or not metadata.get("raw_payload_hash")
            or not metadata.get("output_path_hashes")
            or "task_output" not in set(metadata.get("artifact_roles") or [])
        ):
            return (
                L1AuthorityClass.DETERMINISTIC_HARD_BLOCK,
                ["scope_task_output_atomic_replace_staging_binding_missing"],
                None,
            )
        metadata.update({
            "schema": "clawsentry.contextual.scope_task_output_atomic_replace_staging.v1",
            "event_id": event.event_id,
            "session_id": event.session_id,
            "l1_authority_class": L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED.value,
            "l1_block_authority": "contextual_route_only",
            "l2_l3_required": True,
            "recovery_candidate_reason": "scope_task_output_atomic_replace_staging_review",
            "recovery_ineligible_reasons": [],
            "blocked_lineage_match": False,
            "anti_bypass_match": False,
            "task_output_write_within_profile": True,
            "task_output_atomic_replace_staging": True,
            "no_redline_behavior": True,
            "binding_confidence": 0.8,
            "l3_required": False,
        })
        return (
            L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED,
            ["scope_task_output_atomic_replace_staging_review"],
            ReviewRoutingIntent(
                source="contextual_review",
                recommended_tier="l2",
                policy_action="defer",
                reason="scope_task_output_atomic_replace_staging_review",
                source_metadata=metadata,
                routing_affecting=True,
                decision_affecting=False,
            ),
        )

    if (
        event.event_type == EventType.PRE_ACTION
        and scope_task_archive_auxiliary_member_review_candidate
    ):
        metadata = contextual_binding_parts(event, context)
        archive_auxiliary_member_write = "archive_auxiliary_member_write" in evidence_rules
        archive_external_reference_write = "archive_external_reference_write" in evidence_rules
        archive_member_write_unresolved = "archive_member_write_unresolved" in evidence_rules
        if (
            not metadata.get("effect_hash")
            or not metadata.get("raw_payload_hash")
            or not metadata.get("output_path_hashes")
            or "task_output" not in set(metadata.get("artifact_roles") or [])
        ):
            return (
                L1AuthorityClass.DETERMINISTIC_HARD_BLOCK,
                ["scope_task_archive_auxiliary_member_binding_missing"],
                None,
            )
        metadata.update({
            "schema": "clawsentry.contextual.scope_task_archive_auxiliary_member.v1",
            "event_id": event.event_id,
            "session_id": event.session_id,
            "l1_authority_class": L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED.value,
            "l1_block_authority": "contextual_route_only",
            "l2_l3_required": True,
            "recovery_candidate_reason": "scope_task_archive_auxiliary_member_review",
            "recovery_ineligible_reasons": [],
            "blocked_lineage_match": False,
            "anti_bypass_match": False,
            "task_output_write_within_profile": True,
            "archive_auxiliary_member_write": archive_auxiliary_member_write,
            "archive_external_reference_write": archive_external_reference_write,
            "archive_member_write_unresolved": archive_member_write_unresolved,
            "auxiliary_output_semantic_hint": archive_auxiliary_member_write,
            "no_redline_behavior": True,
            "binding_confidence": 0.82,
            "l3_required": True,
            "l3_request_reason": (
                "task_output_archive_external_reference"
                if archive_external_reference_write
                else "task_output_archive_member_unresolved"
                if archive_member_write_unresolved
                else "task_output_archive_auxiliary_member_semantics"
            ),
        })
        return (
            L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED,
            ["scope_task_archive_auxiliary_member_review"],
            ReviewRoutingIntent(
                source="contextual_review",
                recommended_tier="l3",
                policy_action="defer",
                reason="scope_task_archive_auxiliary_member_review",
                source_metadata=metadata,
                routing_affecting=True,
                decision_affecting=False,
            ),
        )

    write_requires_contextual = (
        event.event_type == EventType.PRE_ACTION
        and "filesystem.write" in effects
        and (
            "native_write_effect" in evidence_rules
            or (
                "generated_script_future_exec" in evidence_rules
                and "generated_script_shebang" in evidence_rules
            )
        )
        and risk_level != RiskLevel.CRITICAL
        and short_circuit_rule in (None, "unresolved_analysis_escalate")
        and not task_artifact_output_write
    )
    if write_requires_contextual:
        if not reviewable_local:
            return (
                L1AuthorityClass.DETERMINISTIC_HARD_BLOCK,
                list(dict.fromkeys(["native_write_not_reviewable", *ineligible_reasons])),
                None,
            )
        metadata = contextual_binding_parts(event, context)
        future_exec_kind = _scope_task_artifact_future_exec_kind(effect_summary)
        if future_exec_kind == "none":
            future_exec_kind = _scope_task_compat_future_exec_kind(effect_summary)
        generated_auxiliary_output_content = (
            "generated_script_future_exec" in evidence_rules
            and _event_has_generated_script_auxiliary_output_content_hint(event)
        )
        recommended_tier = (
            "l3"
            if future_exec_kind != "none" or generated_auxiliary_output_content
            else "l2"
        )
        if generated_auxiliary_output_content:
            recovery_reason = "generated_script_auxiliary_output_review"
        else:
            recovery_reason = (
                "native_write_contextual_review"
                if "native_write_effect" in evidence_rules
                else "generated_future_exec_contextual_review"
            )
        metadata.update({
            "event_id": event.event_id,
            "session_id": event.session_id,
            "l1_authority_class": L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED.value,
            "l1_block_authority": "contextual_route_only",
            "l2_l3_required": True,
            "recovery_candidate_reason": recovery_reason,
            "recovery_ineligible_reasons": [],
            "blocked_lineage_match": False,
            "anti_bypass_match": False,
            "future_exec_kind": future_exec_kind,
            "auxiliary_output_semantic_hint": generated_auxiliary_output_content,
            "l3_required": future_exec_kind != "none" or generated_auxiliary_output_content,
            "l3_request_reason": (
                "generated_script_auxiliary_output_semantics"
                if generated_auxiliary_output_content
                else ("generated_future_execution" if future_exec_kind != "none" else None)
            ),
        })
        return (
            L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED,
            [recovery_reason],
            ReviewRoutingIntent(
                source="contextual_review",
                recommended_tier=recommended_tier,
                policy_action="defer",
                reason=recovery_reason,
                source_metadata=metadata,
                routing_affecting=True,
                decision_affecting=False,
            ),
        )

    if (
        event.event_type == EventType.PRE_ACTION
        and risk_level == RiskLevel.HIGH
        and contextual_session
        and reviewable_local
    ):
        metadata = contextual_binding_parts(event, context)
        metadata.update({
            "event_id": event.event_id,
            "session_id": event.session_id,
            "l1_authority_class": L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED.value,
            "l1_block_authority": "contextual_route_only",
            "l2_l3_required": True,
            "recovery_candidate_reason": "contextual_high_risk_after_fspr",
            "recovery_ineligible_reasons": [],
            "blocked_lineage_match": False,
            "anti_bypass_match": False,
        })
        return (
            L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED,
            ["contextual_high_risk_after_fspr"],
            ReviewRoutingIntent(
                source="contextual_review",
                recommended_tier="l2",
                policy_action="defer",
                reason="contextual_high_risk_after_fspr",
                source_metadata=metadata,
                routing_affecting=True,
                decision_affecting=False,
            ),
        )

    return L1AuthorityClass.ALLOW_OR_AUDIT, [], None


def compute_risk_snapshot(
    event: CanonicalEvent,
    context: Optional[DecisionContext],
    session_tracker: SessionRiskTracker,
    config: Optional[DetectionConfig] = None,
) -> RiskSnapshot:
    """
    Compute an immutable RiskSnapshot for the given event.

    Algorithm (E-4 revision):
    1. Score each dimension D1-D5.
    2. Score D6 via injection detector (Layer 1 heuristic).
    3. Apply short-circuit rules (before composite scoring).
    4. Compute composite_score via v2 formula (D6 multiplier).
    5. Map to risk_level via v2 thresholds.
    6. D6 forced alert: D6 >= 2.0 and LOW -> MEDIUM.
    """
    if config is None:
        config = DetectionConfig()
    missing_dims: list[str] = []

    # D1
    d1 = _score_d1(event)
    if not event.tool_name:
        missing_dims.append("d1")

    # D2
    d2 = _score_d2(event)
    if not _extract_paths(event):
        missing_dims.append("d2")

    # D3
    tool = (event.tool_name or "").lower()
    if tool in ("bash", "shell", "terminal", "command", "exec"):
        d3 = _score_d3(event)
        cmd = str(event.payload.get("command", ""))
        if not cmd.strip():
            missing_dims.append("d3")
    else:
        d3 = 0

    # D4
    d4 = session_tracker.get_d4(event.session_id, config=config)

    # D5
    d5 = _score_d5(context)
    if context is None or context.agent_trust_level is None:
        missing_dims.append("d5")

    # D6: Injection detection
    payload_text = _extract_text_for_d6(event)
    # E-8: Extract content origin from _clawsentry_meta if present
    _meta = (event.payload or {}).get("_clawsentry_meta") or {}
    _content_origin = _meta.get("content_origin") if isinstance(_meta, dict) else None
    d6 = score_layer1(
        payload_text,
        event.tool_name or "",
        content_origin=_content_origin,
        d6_boost=config.external_content_d6_boost,
    ) if payload_text else 0.0

    effect_envelope = normalize_action_effect(event, context)
    effect_summary = effect_envelope.to_summary()
    effect_d2 = _score_d2_from_effect_summary(effect_summary)
    if effect_d2 > d2:
        d2 = effect_d2
        missing_dims = [dimension for dimension in missing_dims if dimension != "d2"]

    dims = RiskDimensions(d1=d1, d2=d2, d3=d3, d4=d4, d5=d5, d6=d6)

    # Short-circuit rules (priority over scoring)
    sc_rule: Optional[str] = None
    sc_level: Optional[RiskLevel] = None
    if (
        "disabled_capability_equivalent" in effect_envelope.evidence_rules
        and effect_envelope.confidence == "high"
    ):
        sc_rule = "SC-4"
        sc_level = RiskLevel.HIGH if config.mode in ("strict", "benchmark") else RiskLevel.MEDIUM
    elif (
        (
            "script_analysis_unavailable" in effect_envelope.evidence_rules
            or "wrapper_chain_unresolved" in effect_envelope.evidence_rules
        )
        and config.mode in ("strict", "benchmark")
    ):
        # Analysis could not be resolved (e.g. an unrecognized CLI wrapper). This
        # is a telemetry tag only: it no longer forces a HIGH short-circuit hard
        # block. Composite scoring decides the level, and the engine routes the
        # event to L2/L3 semantic review instead of failing closed on "the parser
        # did not understand this".
        sc_rule = "unresolved_analysis_escalate"
        sc_level = None
    else:
        for rule_id, predicate, level in _SHORT_CIRCUIT_RULES:
            if predicate(dims):
                sc_rule = rule_id
                sc_level = level
                break

    # Composite scoring (E-4 v2 formula)
    score = _composite_score_v2(dims, config)

    if sc_level is not None:
        risk_level = sc_level
    else:
        risk_level = _score_to_risk_level_v2(score, config)

    # D6 forced alert: high injection score on low-risk event → bump to MEDIUM
    if d6 >= 2.0 and risk_level == RiskLevel.LOW:
        risk_level = RiskLevel.MEDIUM
        sc_rule = None  # D6 override invalidates the short-circuit

    risk_level, score, rule_hits, skill_trust_findings = _skill_trust_evidence(
        event,
        context,
        risk_level,
        score,
        config,
    )
    routing_intents = _skill_trust_routing_intents_for_context(context, config)
    routing_intents.extend(build_content_evidence_routing_intents(context, config))
    for rule_id in effect_envelope.evidence_rules:
        if rule_id not in rule_hits:
            rule_hits.append(rule_id)
    if "disabled_capability_equivalent" in effect_envelope.evidence_rules:
        if config.mode == "normal":
            risk_level = _max_risk_level(risk_level, RiskLevel.MEDIUM)
            score = max(score, _min_score_for_level(risk_level, config))
        elif config.mode in ("strict", "benchmark"):
            risk_level = _max_risk_level(risk_level, RiskLevel.HIGH)
            score = max(score, _min_score_for_level(risk_level, config))
    if (
        sc_rule is None
        and "generated_script_future_exec" in effect_envelope.evidence_rules
        and _has_low_trust_skill_evidence(rule_hits, skill_trust_findings)
    ):
        sc_rule = "SC-8"
        if config.mode in ("strict", "benchmark"):
            risk_level = _max_risk_level(risk_level, RiskLevel.HIGH)
        else:
            risk_level = _max_risk_level(risk_level, RiskLevel.MEDIUM)
        score = max(score, _min_score_for_level(risk_level, config))
    if "associated_script_network_indicator" in effect_envelope.evidence_rules:
        if config.mode in ("strict", "benchmark"):
            risk_level = _max_risk_level(risk_level, RiskLevel.HIGH)
        else:
            risk_level = _max_risk_level(risk_level, RiskLevel.MEDIUM)
        score = max(score, _min_score_for_level(risk_level, config))
    if "task_output_external_reference_instruction" in effect_envelope.evidence_rules:
        if config.mode in ("strict", "benchmark"):
            risk_level = _max_risk_level(risk_level, RiskLevel.HIGH)
        else:
            risk_level = _max_risk_level(risk_level, RiskLevel.MEDIUM)
        score = max(score, _min_score_for_level(risk_level, config))
    if event.event_type == EventType.PRE_ACTION and _context_has_prior_fspr_block(context):
        command_text = str(event.payload.get("command") or "")
        prior_fspr_rules: list[str] = []
        if _command_references_relative_skill_package_entrypoint(command_text):
            prior_fspr_rules.append("prior_fspr_block_relative_skill_package_access")
        if _command_starts_unbounded_interactive_shell(command_text):
            prior_fspr_rules.append("prior_fspr_block_interactive_shell")
        for rule_id in prior_fspr_rules:
            if rule_id not in rule_hits:
                rule_hits.append(rule_id)
        if prior_fspr_rules:
            risk_level = _max_risk_level(risk_level, RiskLevel.HIGH)
            score = max(score, _min_score_for_level(risk_level, config))
    taint_flow_summary = _content_evidence_taint_summary(context, _taint_flow_summary(event))
    if taint_flow_summary is not None:
        taint_rule_hits = [
            str(rule_id)
            for rule_id in taint_flow_summary.get("rule_ids", [])
        ]
        for rule_id in taint_rule_hits:
            if rule_id not in rule_hits:
                rule_hits.append(rule_id)
        if event.event_type == EventType.PRE_ACTION:
            severities = {
                str(rule.get("severity"))
                for rule in taint_flow_summary.get("rules", [])
                if isinstance(rule, dict)
            }
            content_rule_set = set(_content_evidence_rule_ids(context))
            if "critical" in severities:
                risk_level = _max_risk_level(risk_level, RiskLevel.CRITICAL)
                score = max(score, _min_score_for_level(risk_level, config))
            elif "high" in severities and not (
                content_rule_set.intersection({
                    "document_input_to_network_sink",
                    "document_input_encoded_to_network_sink",
                    "subprocess_file_transfer",
                })
                and str(config.mode or "normal").strip().lower() in {"normal", "permissive"}
            ):
                risk_level = _max_risk_level(risk_level, RiskLevel.HIGH)
                score = max(score, _min_score_for_level(risk_level, config))
            elif content_rule_set.intersection({
                "document_input_to_network_sink",
                "document_input_encoded_to_network_sink",
                "subprocess_file_transfer",
            }):
                risk_level = _max_risk_level(risk_level, RiskLevel.MEDIUM)
                score = max(score, _min_score_for_level(risk_level, config))

    if (
        event.event_type == EventType.PRE_ACTION
        and _is_scope_task_data_read_content_review_candidate(
            effect_summary,
            risk_level=risk_level,
            routing_intents=routing_intents,
            config=config,
            context=context,
        )
    ):
        routing_intents = _audit_content_routing_for_scope_task_data_read_content_review(
            routing_intents,
            context=context,
        )

    task_artifact_data_readonly = _is_scope_task_data_readonly_candidate(
        effect_summary,
        routing_intents=routing_intents,
        config=config,
    )
    if task_artifact_data_readonly and event.event_type == EventType.PRE_ACTION:
        risk_level = RiskLevel.MEDIUM
        score = min(score, max(config.threshold_medium, config.threshold_high - 0.01))
        if "benchmark_task_data_readonly" not in rule_hits:
            rule_hits.append("benchmark_task_data_readonly")
        routing_intents = _audit_fspr_routing_for_scope_task_data_readonly(routing_intents)
        routing_intents = _audit_content_routing_for_scope_task_data_read_content_review(
            routing_intents,
            context=context,
        )
        _mark_fspr_findings_scope_task_data_readonly_audit(skill_trust_findings)

    task_artifact_output_readonly = _is_scope_task_output_readonly_candidate(
        effect_summary,
        routing_intents=routing_intents,
        config=config,
    )
    if task_artifact_output_readonly and event.event_type == EventType.PRE_ACTION:
        risk_level = RiskLevel.MEDIUM
        score = min(score, max(config.threshold_medium, config.threshold_high - 0.01))
        if "benchmark_task_output_readonly" not in rule_hits:
            rule_hits.append("benchmark_task_output_readonly")
        routing_intents = _audit_fspr_routing_for_scope_task_output_readonly(routing_intents)
        _mark_fspr_findings_scope_task_output_readonly_audit(skill_trust_findings)

    task_artifact_output_write = _is_scope_task_output_write_candidate(
        effect_summary,
        routing_intents=routing_intents,
        config=config,
    )
    if task_artifact_output_write and event.event_type == EventType.PRE_ACTION:
        risk_level = RiskLevel.LOW
        score = min(score, max(0.0, config.threshold_medium - 0.01))
        if "benchmark_task_output_write" not in rule_hits:
            rule_hits.append("benchmark_task_output_write")
        routing_intents = _audit_fspr_routing_for_scope_task_output_write(routing_intents)
        _mark_fspr_findings_scope_task_output_write_audit(skill_trust_findings)

    task_artifact_output_env_setup = _is_scope_task_output_env_setup_candidate(
        effect_summary,
        routing_intents=routing_intents,
        config=config,
    )
    if task_artifact_output_env_setup and event.event_type == EventType.PRE_ACTION:
        risk_level = RiskLevel.MEDIUM
        score = min(score, max(config.threshold_medium, config.threshold_high - 0.01))
        if "benchmark_task_output_env_setup" not in rule_hits:
            rule_hits.append("benchmark_task_output_env_setup")

    evidence_rule_set = {
        str(rule).lower()
        for rule in effect_summary.get("evidence_rules") or []
    }
    if (
        event.event_type == EventType.PRE_ACTION
        and str(config.mode or "normal").strip().lower() == "benchmark"
        and "task_output_local_vcs_patch_apply" in evidence_rule_set
    ):
        risk_level = _max_risk_level(risk_level, RiskLevel.HIGH)
        score = max(score, _min_score_for_level(RiskLevel.HIGH, config))

    task_artifact_local_write = _is_scope_task_local_artifact_write_candidate(
        effect_summary,
        routing_intents=routing_intents,
        config=config,
    )
    if task_artifact_local_write and event.event_type == EventType.PRE_ACTION and dims.d2 == 0:
        risk_level = RiskLevel.MEDIUM
        score = min(score, max(config.threshold_medium, config.threshold_high - 0.01))
        if "benchmark_task_local_artifact_write" not in rule_hits:
            rule_hits.append("benchmark_task_local_artifact_write")

    task_artifact_data_write = _is_scope_task_data_write_candidate(
        effect_summary,
        config=config,
    )
    if task_artifact_data_write and event.event_type == EventType.PRE_ACTION:
        risk_level = _max_risk_level(risk_level, RiskLevel.HIGH)
        score = max(score, _min_score_for_level(RiskLevel.HIGH, config))
        if "benchmark_task_data_write" not in rule_hits:
            rule_hits.append("benchmark_task_data_write")

    verified_skill_manifest_read_probe = _is_verified_skill_manifest_read_probe_candidate(
        effect_summary,
        event=event,
        routing_intents=routing_intents,
        context=context,
        config=config,
    )
    if verified_skill_manifest_read_probe and event.event_type == EventType.PRE_ACTION:
        risk_level = RiskLevel.MEDIUM
        score = min(score, max(config.threshold_medium, config.threshold_high - 0.01))
        if "verified_skill_manifest_read_probe" not in rule_hits:
            rule_hits.append("verified_skill_manifest_read_probe")
        routing_intents = _audit_fspr_routing_for_verified_skill_manifest_read_probe(routing_intents)
        _mark_fspr_findings_verified_skill_manifest_read_probe_audit(skill_trust_findings)

    work5c_relaxed_readonly = _is_work5c_relaxed_readonly_candidate(
        effect_summary,
        routing_intents=routing_intents,
        context=context,
        config=config,
    )
    if work5c_relaxed_readonly and event.event_type == EventType.PRE_ACTION:
        risk_level = RiskLevel.MEDIUM
        score = min(score, max(config.threshold_medium, config.threshold_high - 0.01))
        if "work5c_warning_relaxed_readonly" not in rule_hits:
            rule_hits.append("work5c_warning_relaxed_readonly")
        relaxed_intents: list[ReviewRoutingIntent] = []
        for intent in routing_intents:
            if (
                intent.source == "fspr_package_review"
                and intent.decision_affecting
                and intent.policy_action in {"block", "defer"}
            ):
                metadata = dict(intent.source_metadata or {})
                metadata["work5c_warning_relaxed_readonly"] = True
                relaxed_intents.append(intent.model_copy(update={
                    "recommended_tier": "none",
                    "policy_action": "audit",
                    "source_metadata": metadata,
                    "routing_affecting": False,
                    "decision_affecting": False,
                }))
            else:
                relaxed_intents.append(intent)
        routing_intents = relaxed_intents
        for finding in skill_trust_findings:
            if finding.get("rule_id") in {
                "first_use_skill_package_inconsistent",
                "first_use_skill_package_suspicious",
                "first_use_skill_package_insufficient_evidence",
                "fspr_review_summary",
            }:
                finding["decision_affecting"] = False
                finding["work5c_warning_relaxed_readonly"] = True

    work5c_task_readonly = _is_work5c_task_readonly_candidate(
        effect_summary,
        routing_intents=routing_intents,
        context=context,
        config=config,
    )
    if work5c_task_readonly and event.event_type == EventType.PRE_ACTION:
        risk_level = RiskLevel.MEDIUM
        score = min(score, max(config.threshold_medium, config.threshold_high - 0.01))
        if "work5c_warning_task_readonly" not in rule_hits:
            rule_hits.append("work5c_warning_task_readonly")

    pure_read, _pure_read_reasons = _is_pure_workspace_read_effect(
        effect_summary,
        event=event,
        rule_hits=set(rule_hits),
        routing_intents=routing_intents,
        context=context,
        dimensions=dims,
    )
    if (
        pure_read
        and event.event_type == EventType.PRE_ACTION
        and dims.d4 > 0
        and risk_level == RiskLevel.HIGH
        and sc_rule is None
        and taint_flow_summary is None
    ):
        risk_level = RiskLevel.MEDIUM
        score = min(score, max(config.threshold_medium, config.threshold_high - 0.01))
        if "pure_workspace_read_audit_narrowing" not in rule_hits:
            rule_hits.append("pure_workspace_read_audit_narrowing")

    verified_skill_package_read_review = _is_verified_skill_package_read_review_candidate(
        effect_summary,
        event=event,
        routing_intents=routing_intents,
        context=context,
        config=config,
    )
    if verified_skill_package_read_review and event.event_type == EventType.PRE_ACTION:
        routing_intents = _audit_fspr_routing_for_verified_skill_package_read_review(routing_intents)
        _mark_fspr_findings_verified_skill_package_read_review_audit(skill_trust_findings)

    snapshot_fields = {
        "risk_level": risk_level,
        "composite_score": score,
        "dimensions": dims,
        "short_circuit_rule": sc_rule,
        "missing_dimensions": missing_dims,
        "classified_by": ClassifiedBy.L1,
        "classified_at": utc_now_iso(),
        "rule_hits": rule_hits,
        "skill_trust_findings": skill_trust_findings,
        "routing_intents": routing_intents,
        "taint_flow_summary": taint_flow_summary,
        "effect_summary": effect_summary,
    }
    authority_class, authority_reasons, contextual_intent = _classify_l1_authority(
        event=event,
        snapshot_fields=snapshot_fields,
        context=context,
        config=config,
    )
    if contextual_intent is not None:
        routing_intents.append(contextual_intent)
    snapshot_fields["routing_intents"] = routing_intents
    snapshot = RiskSnapshot(
        **snapshot_fields,
        l1_authority_class=authority_class,
        l1_authority_reasons=authority_reasons,
        l1_block_authority=(
            "hard_block"
            if authority_class == L1AuthorityClass.DETERMINISTIC_HARD_BLOCK
            else "contextual_route_only"
            if authority_class == L1AuthorityClass.CONTEXTUAL_REVIEW_REQUIRED
            else "none"
        ),
        blocked_lineage_match=(
            context.session_risk_summary.get("blocked_skill_lineage_match")
            if context is not None and isinstance(context.session_risk_summary, dict)
            else None
        ),
    )

    # Update session tracker if risk >= high
    if (
        risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        and _counts_toward_d4_high_risk(snapshot)
    ):
        session_tracker.record_high_risk_event(event.session_id)

    return snapshot


def _has_low_trust_skill_evidence(
    rule_hits: list[str],
    skill_trust_findings: list[dict[str, Any]],
) -> bool:
    rule_set = set(rule_hits)
    if rule_set.intersection({
        "low_trust_redefined_canonical_tool",
        "provenance_label_conflict",
        "unknown_skill_provenance_rewrite",
        "blacklisted_skill_identity",
        "revoked_skill_identity",
        "skill_hash_mismatch",
    }):
        return True
    for finding in skill_trust_findings:
        if finding.get("admission_risk") in {"high", "critical"}:
            return True
        if finding.get("trust_list_state") in {"greylist", "blacklist", "revoked", "disabled"}:
            return True
    return False
