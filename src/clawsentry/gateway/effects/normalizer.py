"""Deterministic action-effect normalization for Gateway L1 evidence.

The normalizer intentionally stores only hashes, labels, and compact rule ids.
Raw commands, prompts, payloads, paths, and environment values stay out of the
returned envelope and downstream ledgers.
"""

from __future__ import annotations

import ast
import contextvars
import hashlib
import json
import posixpath
import re
import shlex
from pathlib import Path, PurePosixPath
from typing import Any

from clawsentry.gateway.analysis.content_scanners import text_has_external_reference_instruction
from clawsentry.gateway.models import (
    ActionEffectEnvelope,
    ActionEffectTarget,
    CanonicalEvent,
    DecisionContext,
)
from clawsentry.gateway.policy.scope_task_artifacts import (
    ScopeTaskArtifactDecision,
    SCOPE_CONTROL_METADATA_PATH_ROLE,
    SCOPE_CONTROL_METADATA_RELATION,
    SCOPE_TASK_DATA_READ_PATH_ROLE,
    SCOPE_TASK_DATA_WORKSPACE_RELATION,
    SCOPE_TASK_OUTPUT_PATH_ROLE,
    hard_path_role,
    is_skill_package_path,
    normalize_task_artifact_path,
    resolve_scope_task_artifact,
)
_NATIVE_DELETE_TOOLS = {
    "delete",
    "delete_file",
    "remove",
    "remove_file",
}
_NATIVE_READ_TOOLS = {
    "read",
    "read_file",
    "filesystem.read_file",
}
_NATIVE_ENUMERATE_TOOLS = {
    "glob",
    "grep",
    "ls",
    "list",
    "list_dir",
    "list_files",
    "search",
}
_DELEGATION_TOOLS = {"agent", "task"}
_EXECUTABLE_SUFFIXES = (".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ps1", ".bat", ".cmd")
_ASSOCIATED_SCRIPT_SURFACE_SUFFIXES = frozenset({
    *_EXECUTABLE_SUFFIXES,
    ".htm",
    ".html",
    ".svg",
})
_SCRIPT_ASSET_DIRECTORY_NAMES = frozenset({
    "javascript",
    "javascripts",
    "js",
    "script",
    "scripts",
})
_MAX_SCRIPT_BINDING_BYTES = 1_048_576
_MAX_MKDIR_TARGETS = 12
_CREDENTIAL_WORD_RE = re.compile(
    r"(?:^|[._-])(?:credentials?|secrets?|tokens?|passwords?)(?:$|[._-])",
    re.IGNORECASE,
)
_PATH_RE = re.compile(r"(?:[A-Za-z]:)?(?:[./~]?[\w.-]+/)*[\w.-]+\.[A-Za-z0-9_+-]+")
_REMOTE_URI_SCHEME_RE = r"(?:https?|ftp|ftps|rtmp|rtmps|rtsp|rtsps|srt|udp|tcp)"
_URL_RE = re.compile(rf"(?:{_REMOTE_URI_SCHEME_RE}://|//)[^\s'\"<>]+", re.IGNORECASE)
_NETWORK_FETCH_COMMANDS = frozenset({"curl", "wget", "http", "httpie", "scp", "rsync"})
_PACKAGE_COMMANDS = frozenset({"pip", "pip3", "npm", "yarn", "pnpm"})
_PACKAGE_INSTALL_SUBCOMMANDS = frozenset({"install", "add"})
_MAVEN_LOCAL_BUILD_COMMANDS = frozenset({"mvn", "mvnw"})
_GRADLE_LOCAL_BUILD_COMMANDS = frozenset({"gradle", "gradlew"})
_MAVEN_ALLOWED_LOCAL_BUILD_GOALS = frozenset({
    "clean",
    "compile",
    "package",
    "test",
    "validate",
    "verify",
})
_GRADLE_ALLOWED_LOCAL_BUILD_TASKS = frozenset({
    "assemble",
    "build",
    "check",
    "classes",
    "clean",
    "compilejava",
    "compiletestjava",
    "jar",
    "test",
    "testclasses",
})
_SBT_ALLOWED_LOCAL_BUILD_TASKS = frozenset({
    "clean",
    "compile",
    "package",
    "test",
})
_BUILD_DANGEROUS_ENV_NAMES = frozenset({
    "CLASSPATH",
    "CMAKE_TOOLCHAIN_FILE",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "GRADLE_OPTS",
    "HOME",
    "JAVA_TOOL_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "LD_AUDIT",
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "MAKE",
    "MAKEFLAGS",
    "MAVEN_CONFIG",
    "MAVEN_OPTS",
    "MFLAGS",
    "PATH",
    "SBT_OPTS",
    "SHELL",
    "USERPROFILE",
    "_JAVA_OPTIONS",
})
_MAKE_EXECUTION_ASSIGNMENT_NAMES = frozenset({
    "AR",
    "AS",
    "CC",
    "CXX",
    "JAVA",
    "LD",
    "MAKE",
    "MAKEFLAGS",
    "MFLAGS",
    "NODE",
    "PYTHON",
    "RUBY",
    "SHELL",
})
_MAVEN_DANGEROUS_PROPERTY_KEYS = frozenset({
    "exec.args",
    "exec.executable",
    "java.io.tmpdir",
    "maven.repo.local",
    "user.home",
})
_MAVEN_EXEC_JAVA_FORBIDDEN_OPTIONS = frozenset({
    "-f",
    "--file",
    "-s",
    "--settings",
    "-gs",
    "--global-settings",
    "-t",
    "--toolchains",
    "--global-toolchains",
    "-P",
    "--activate-profiles",
    "-pl",
    "--projects",
    "-am",
    "--also-make",
    "-amd",
    "--also-make-dependents",
})
_MAVEN_EXEC_JAVA_ALLOWED_EXEC_PROPERTIES = frozenset({
    "exec.args",
    "exec.mainclass",
})
_MAVEN_EXEC_JAVA_DANGEROUS_PROPERTY_KEYS = frozenset({
    "argline",
    "java.io.tmpdir",
    "maven.config",
    "maven.ext.class.path",
    "maven.repo.local",
    "maven.user.conf",
    "user.home",
})
_GRADLE_DANGEROUS_PROPERTY_KEYS = frozenset({
    "gradle.user.home",
    "init.gradle",
    "org.gradle.java.home",
    "org.gradle.jvmargs",
    "org.gradle.projectcachedir",
})
_SBT_DANGEROUS_PROPERTY_KEYS = frozenset({
    "sbt.boot.directory",
    "sbt.global.base",
    "sbt.ivy.home",
})
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
_MAX_SHELL_INLINE_DEPTH = 8
_COPY_LIKE_OPTION_VALUE_FLAGS = frozenset({
    "-m",
    "--mode",
    "-o",
    "--owner",
    "-g",
    "--group",
    "-S",
    "--suffix",
})
_PIPE_STDIN_EXEC_COMMANDS = frozenset({
    "bash",
    "dash",
    "node",
    "nodejs",
    "perl",
    "php",
    "python",
    "python3",
    "pwsh",
    "powershell",
    "ruby",
    "sh",
    "zsh",
})
_PROTECTED_SYSTEM_WRITE_PATH_PREFIXES = (
    "/etc/",
    "/usr/",
    "/var/",
    "/sys/",
    "/proc/",
    "/boot/",
)
_FIND_OUTPUT_PREDICATES = frozenset({"-fprint", "-fprint0", "-fprintf", "-fls"})
_ASSOCIATED_SCRIPT_AUXILIARY_WRITE_PATH_RE = re.compile(
    r"(?<![a-z0-9])(?:"
    r"hand[\W_]*off|handoff|sidecar|auxiliary|"
    r"submission[\W_]*(?:bundle|sidecar|handoff|review|reviewer)|"
    r"submittal[\W_]*(?:bundle|sidecar|handoff|review|reviewer)|"
    r"(?:review|annotation|auxiliary)[\W_]*(?:handoff|sheet|marker|note|comment|payload|bundle|sidecar)|"
    r"(?:handoff|sheet|marker|note|comment|payload|bundle|sidecar)[\W_]*(?:review|annotation|auxiliary)|"
    r"reviewer[\W_]*(?:handoff|sheet|marker|note|comment|payload|bundle|sidecar)|"
    r"(?:handoff|sheet|marker|note|comment|payload|bundle|sidecar)[\W_]*reviewer"
    r")(?![a-z0-9])",
    re.IGNORECASE,
)
_ARCHIVE_AUXILIARY_MEMBER_WRITE_RE = re.compile(
    r"(?<![a-z0-9])(?:"
    r"hand[\W_]*off|handoff|sidecar|auxiliary|"
    r"submission[\W_]*(?:bundle|sidecar|handoff|review|reviewer)|"
    r"submittal[\W_]*(?:bundle|sidecar|handoff|review|reviewer)|"
    r"(?:review|annotation|auxiliary)[\W_]*(?:handoff|sheet|marker|note|comment|payload|bundle|sidecar)|"
    r"(?:handoff|sheet|marker|note|comment|payload|bundle|sidecar)[\W_]*(?:review|annotation|auxiliary)|"
    r"reviewer[\W_]*(?:handoff|sheet|marker|note|comment|payload|bundle|sidecar)|"
    r"(?:handoff|sheet|marker|note|comment|payload|bundle|sidecar)[\W_]*reviewer|"
    r"provenance|journal|audit"
    r")(?![a-z0-9])",
    re.IGNORECASE,
)
_COMMAND_AVAILABILITY_PROBE_DIRS = frozenset({
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/opt/homebrew/bin",
})
_ARCHIVE_DELETE_RE = re.compile(
    r"(?:^|[;&]\s*)(?:rm|shred|srm)\s+-?[^;&|]*\b|find\b[^;&|]*\s-delete\b",
    re.IGNORECASE,
)
_NORMALIZER_CONTEXT: contextvars.ContextVar[DecisionContext | None] = contextvars.ContextVar(
    "clawsentry_normalizer_context",
    default=None,
)
_NORMALIZER_CWD: contextvars.ContextVar[str] = contextvars.ContextVar(
    "clawsentry_normalizer_cwd",
    default="",
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


def normalize_action_effect(
    event: CanonicalEvent,
    context: DecisionContext | None = None,
) -> ActionEffectEnvelope:
    """Return a redacted effect envelope for a canonical action event."""
    payload = event.payload or {}
    cwd = _payload_effective_cwd(payload)
    context_token = _NORMALIZER_CONTEXT.set(context)
    cwd_token = _NORMALIZER_CWD.set(cwd)
    try:
        return _normalize_action_effect_impl(event, context)
    finally:
        _NORMALIZER_CONTEXT.reset(context_token)
        _NORMALIZER_CWD.reset(cwd_token)


def _normalize_action_effect_impl(
    event: CanonicalEvent,
    context: DecisionContext | None = None,
) -> ActionEffectEnvelope:
    """Implementation for ``normalize_action_effect`` with contextvars bound."""

    tool = str(event.tool_name or "")
    tool_l = tool.lower()
    payload = event.payload or {}
    raw_text = _payload_text(payload)
    cwd = _payload_effective_cwd(payload)
    effects: list[str] = []
    sources: list[ActionEffectTarget] = []
    targets: list[ActionEffectTarget] = []
    interpreters: list[str] = []
    wrappers: list[str] = []
    rules: list[str] = []
    analysis_state = "complete"
    confidence = "low"

    if tool_l in _NATIVE_WRITE_TOOLS:
        _add_effect(effects, "filesystem.write")
        if tool_l in _NATIVE_DELETE_TOOLS:
            _add_rule(rules, "destructive_delete")
        payload_targets = _payload_paths(
            payload,
            include_patch_targets=tool_l == "apply_patch"
            or any(isinstance(payload.get(key), str) for key in ("patch", "diff")),
        )
        if not payload_targets:
            first_target = _first_path(raw_text)
            payload_targets = [first_target] if first_target else []
        native_write_scan_texts = _native_write_payload_scan_texts_for_payload(payload, raw_text)
        native_write_script_targets = _native_write_script_target_paths(
            payload,
            raw_text,
            cwd=cwd,
            scan_texts=native_write_scan_texts,
        )
        native_write_associated_payloads = _native_write_associated_payload_texts(payload, raw_text, cwd=cwd)
        native_write_payload_has_shebang = _native_write_scan_texts_have_executable_script_marker(
            native_write_scan_texts
        )
        native_write_payload_is_script = _native_write_scan_texts_have_future_execution_marker(native_write_scan_texts)
        for target in payload_targets:
            destination_target = _target_for_path(target, cwd=cwd)
            target_payload_is_script = _native_write_target_has_script_payload(
                target,
                script_targets=native_write_script_targets,
                fallback=native_write_payload_is_script,
                cwd=cwd,
            )
            if target_payload_is_script and _native_write_target_is_task_output(destination_target):
                destination_target = destination_target.model_copy(update={"path_role": "future_execution.artifact"})
            targets.append(destination_target)
            if _direct_task_output_contract_violated(target, destination_target):
                _add_rule(rules, "task_output_contract_violation")
        if _native_write_has_associated_script_target(targets):
            read_reference_text = "\n".join(native_write_associated_payloads) if native_write_associated_payloads else raw_text
            for referenced_path in _native_write_content_read_reference_paths(read_reference_text, cwd=cwd):
                role = _path_role_for_read(referenced_path)
                targets.append(_target_for_path(referenced_path, role=role, cwd=cwd))
                if role == "credential_source":
                    _add_rule(rules, "credential_read")
            (
                write_reference_targets,
                has_unscoped_write_reference,
                has_auxiliary_write_reference,
            ) = (
                _native_write_content_write_reference_targets(read_reference_text, cwd=cwd)
            )
            targets.extend(write_reference_targets)
            if has_unscoped_write_reference:
                _add_rule(rules, "associated_script_unscoped_write_indicator")
            if has_auxiliary_write_reference:
                _add_rule(rules, "associated_script_auxiliary_write_indicator")
            if _native_write_content_has_unresolved_write_reference(read_reference_text):
                _add_rule(rules, "associated_script_unresolved_write_indicator")
        if native_write_payload_has_shebang and _native_write_has_associated_script_target(targets):
            _add_rule(rules, "generated_script_shebang")
        _add_rule(rules, "native_write_effect")
        if (
            (
                _native_write_has_associated_script_surface(targets, raw_text)
                or bool(native_write_associated_payloads)
            )
            and _native_write_scan_texts_have_remote_network_indicator(
                native_write_associated_payloads or native_write_scan_texts
            )
        ):
            _add_rule(rules, "associated_script_network_indicator")
        if (
            _native_write_has_task_output_target(targets)
            and any(text_has_external_reference_instruction(text) for text in native_write_scan_texts)
        ):
            _add_rule(rules, "task_output_external_reference_instruction")
        associated_script_scan_texts = (
            native_write_associated_payloads
            if native_write_associated_payloads
            else native_write_scan_texts
            if _native_write_has_associated_script_surface(targets, raw_text)
            else []
        )
        if associated_script_scan_texts:
            if _native_write_scan_texts_have_wrapper_indicator(associated_script_scan_texts):
                _add_rule(rules, "associated_script_wrapper_indicator")
            if _native_write_scan_texts_have_package_indicator(associated_script_scan_texts):
                _add_rule(rules, "associated_script_package_indicator")
            if _native_write_scan_texts_have_destructive_indicator(associated_script_scan_texts):
                _add_rule(rules, "associated_script_destructive_indicator")
        confidence = "high"

    if tool_l in _NATIVE_READ_TOOLS:
        _add_effect(effects, "filesystem.read")
        target = _first_payload_path(payload) or _first_path(raw_text)
        if target:
            targets.append(_target_for_path(target, role=_path_role_for_read(target), cwd=cwd))
        _add_rule(rules, "native_read_effect")
        confidence = _max_confidence(confidence, "high")

    if tool_l in _NATIVE_ENUMERATE_TOOLS:
        _add_effect(effects, "filesystem.enumerate")
        target = _first_payload_path(payload) or _first_path(raw_text)
        if target:
            role = "skill_package_read" if is_skill_package_path(str(target).lower()) else "workspace_directory"
            targets.append(_target_for_path(target, role=role, cwd=cwd))
        _add_rule(rules, "native_enumerate_effect")
        confidence = _max_confidence(confidence, "high")

    shell_like_tool = tool_l in _SHELL_TOOL_NAMES
    if shell_like_tool:
        interpreters.append("bash")
        shell_result = _analyze_shell(raw_text)
        _merge(effects, shell_result["effects"])
        sources.extend(shell_result["sources"])
        targets.extend(shell_result["targets"])
        _merge(rules, shell_result["rules"])
        wrappers.extend(shell_result["wrappers"])
        if shell_result["analysis_state"] != "complete":
            analysis_state = shell_result["analysis_state"]
        confidence = _max_confidence(confidence, shell_result["confidence"])
        if raw_text and analysis_state == "complete":
            confidence = _max_confidence(confidence, "medium")

    language_surface = _language_analysis_surface(tool_l, raw_text)
    python_surface = _python_language_analysis_surface(tool_l, raw_text, language_surface)
    inline_python_present = tool_l in _SHELL_TOOL_NAMES and bool(_inline_python_sources(raw_text))
    if tool_l in {"python", "python3"} or inline_python_present or _looks_like_python(python_surface):
        _add_unique(interpreters, "python")
        py_result = _analyze_python(
            python_surface,
            argv_text=raw_text if inline_python_present else None,
        )
        _merge(effects, py_result["effects"])
        targets.extend(py_result["targets"])
        _merge(rules, py_result["rules"])
        confidence = _max_confidence(confidence, py_result["confidence"])

    node_surface = _node_language_analysis_surface(tool_l, raw_text, language_surface)
    if tool_l in {"node", "nodejs", "javascript"} or _looks_like_node(node_surface):
        _add_unique(interpreters, "node")
        node_result = _analyze_node(node_surface)
        _merge(effects, node_result["effects"])
        targets.extend(node_result["targets"])
        _merge(rules, node_result["rules"])
        confidence = _max_confidence(confidence, node_result["confidence"])

    if tool_l in {"powershell", "pwsh"} or _looks_like_powershell(language_surface):
        _add_unique(interpreters, "powershell")
        ps_result = _analyze_powershell(language_surface)
        _merge(effects, ps_result["effects"])
        targets.extend(ps_result["targets"])
        _merge(rules, ps_result["rules"])
        confidence = _max_confidence(confidence, ps_result["confidence"])

    if tool_l in _DELEGATION_TOOLS:
        delegated = _analyze_delegation(raw_text)
        _merge(effects, delegated["effects"])
        targets.extend(delegated["targets"])
        _merge(rules, delegated["rules"])
        confidence = _max_confidence(confidence, delegated["confidence"])

    content_result = _analyze_content_evidence(context)
    _merge(effects, content_result["effects"])
    targets.extend(content_result["targets"])
    _merge(rules, content_result["rules"])
    confidence = _max_confidence(confidence, content_result["confidence"])
    if content_result["analysis_state"] != "complete":
        analysis_state = content_result["analysis_state"]

    command_surface = shell_command_surface(raw_text)
    if shell_like_tool and _shell_command_invokes_network_fetch(command_surface):
        _add_effect(effects, "network.fetch")
        _add_rule(rules, "network_equivalent_fetch")
        confidence = _max_confidence(confidence, "high")

    if shell_like_tool and _shell_command_invokes_package_install(command_surface):
        _add_effect(effects, "package.install")
        _add_rule(rules, "package_install")
        confidence = _max_confidence(confidence, "high")

    if shell_like_tool and _shell_command_invokes_remote_package_reference(command_surface):
        _add_effect(effects, "network.fetch")
        _add_rule(rules, "package_remote_reference")
        confidence = _max_confidence(confidence, "high")

    if any(target.path_role in {"future_execution.artifact", "bootstrap_loader"} for target in targets):
        _add_effect(effects, "future_execution.artifact")
        _add_rule(rules, "generated_script_future_exec")
    if any(target.path_role == "persistence_entrypoint" for target in targets):
        _add_effect(effects, "future_execution.entrypoint")
        _add_rule(rules, "persistence_entrypoint_write")

    if "<(" in raw_text or re.search(r"\b(?:bash|sh|zsh)\s+<\(", raw_text):
        analysis_state = "unsupported"
        _add_rule(rules, "wrapper_chain_unresolved")
        _add_unique(wrappers, "process_substitution")

    disabled = _disabled_capabilities(context)
    matched_disabled = sorted(set(effects).intersection(disabled))
    if matched_disabled:
        _add_rule(rules, "disabled_capability_equivalent")

    deduped_sources = _dedupe_targets(sources)
    deduped_targets = _dedupe_targets(targets)
    envelope = ActionEffectEnvelope(
        effects=effects,
        tool_name=tool or None,
        canonical_argv_hash=_hash(raw_text) if raw_text else None,
        raw_payload_hash=_hash_json(payload),
        sources=deduped_sources,
        canonical_source_hashes=sorted({
            str(source.path_hash)
            for source in deduped_sources
            if source.path_hash
        }),
        write_channel=_write_channel(rules),
        targets=deduped_targets,
        interpreters=interpreters,
        wrapper_chain=wrappers,
        confidence=confidence,
        evidence_rules=rules,
        analysis_state=analysis_state,
        disabled_capabilities=matched_disabled,
    )
    return envelope


def effect_hash(envelope: ActionEffectEnvelope) -> str:
    projection = {
        "effects": envelope.effects,
        "targets": [
            {
                "kind": target.kind,
                "path_hash": target.path_hash,
                "path_role": target.path_role,
            }
            for target in envelope.targets
        ],
    }
    return _hash_json(projection)


def target_hashes(envelope: ActionEffectEnvelope) -> list[str]:
    return sorted({str(target.path_hash) for target in envelope.targets if target.path_hash})


_WRITE_CONTENT_FP_MIN_LINE_LEN = 12


def write_payload_texts(event: CanonicalEvent) -> list[str]:
    """Texts an action writes to disk, across write channels.

    Covers native-write payload keys (content/text/script/code, and the
    changes/files/edits list forms), apply_patch added lines, and shell
    heredoc write bodies. Guard-side helper: not part of the L1 effect
    surface, so it must not influence envelope construction.
    """
    tool_l = str(event.tool_name or "").lower()
    payload = event.payload or {}
    raw_text = _payload_text(payload)
    texts: list[str] = []
    if tool_l in _NATIVE_WRITE_TOOLS:
        for key in ("content", "text", "script", "code"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                texts.append(value)
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
                        texts.append(content)
        if tool_l == "apply_patch" or any(
            isinstance(payload.get(key), str) for key in ("patch", "diff")
        ):
            added_lines = [
                line[1:]
                for line in raw_text.splitlines()
                if line.startswith("+") and not line.startswith("+++")
            ]
            if added_lines:
                texts.append("\n".join(added_lines))
    elif tool_l in _SHELL_TOOL_NAMES:
        texts.extend(_shell_write_payload_texts(raw_text))
    return [text for text in texts if text.strip()]


def write_content_fingerprint(event: CanonicalEvent) -> tuple[str, ...]:
    """Stable line-level fingerprints of the content an action writes.

    The same payload rewritten through a different write channel
    (apply_patch -> heredoc/tee) yields intersecting fingerprints; blank
    and short lines are skipped to bound false positives.
    """
    lines: set[str] = set()
    for text in write_payload_texts(event):
        for line in text.splitlines():
            normalized = " ".join(line.split())
            if len(normalized) < _WRITE_CONTENT_FP_MIN_LINE_LEN:
                continue
            lines.add(normalized)
    return tuple(sorted(_hash(line) for line in lines))



def _language_analysis_surface(tool_l: str, text: str) -> str:
    if tool_l in _NATIVE_WRITE_TOOLS:
        return ""
    if tool_l in _SHELL_TOOL_NAMES:
        return _strip_nonexecuted_heredoc_bodies(text or "")
    return text or ""


def _node_language_analysis_surface(tool_l: str, raw_text: str, language_surface: str) -> str:
    if tool_l in {"node", "nodejs", "javascript"}:
        return language_surface
    if tool_l not in _SHELL_TOOL_NAMES:
        return language_surface
    node_sources = _inline_node_sources(raw_text)
    if node_sources:
        return "\n".join(node_sources)
    if _inline_python_sources(raw_text):
        return ""
    return language_surface


def python_write_path_candidates(text: str, *, inline_only: bool = False) -> list[str]:
    inline_invocations = _inline_python_invocations(text)
    if not inline_invocations and inline_only:
        return []
    if inline_invocations:
        targets: list[str] = []
        for source_text, argv_values in inline_invocations:
            argv_token = _PYTHON_ARGV_PATH_BINDINGS.set(
                _python_argv_path_bindings_from_values(argv_values)
            )
            try:
                targets.extend(_python_write_targets(source_text))
            finally:
                _PYTHON_ARGV_PATH_BINDINGS.reset(argv_token)
        return _dedupe_strings(targets)
    return _python_write_targets(str(text or ""))


def _package_indicator_scan_texts(scan_texts: list[str]) -> list[str]:
    expanded: list[str] = []
    for scan_text in scan_texts:
        text = str(scan_text or "")
        if _text_looks_like_patch_payload(text):
            patch_texts = [
                candidate
                for candidate in _native_write_payload_scan_texts(text)
                if candidate != text
            ]
            if patch_texts:
                expanded.extend(patch_texts)
                continue
        expanded.append(text)
    return _dedupe_strings(expanded)


def _text_looks_like_patch_payload(text: str) -> bool:
    return bool(
        "*** Begin Patch" in text
        or re.search(r"(?m)^\*\*\*\s+(?:Add|Update|Delete)\s+File:\s+", text)
        or re.search(r"(?m)^@@(?:\s|$)", text)
    )


def _js_fetch_call_has_remote_network_sink(
    stripped_line: str,
    *,
    string_bindings: dict[str, str] | None = None,
) -> bool:
    bindings = string_bindings or {}
    for match in re.finditer(r"\bfetch\s*\(", stripped_line, re.IGNORECASE):
        argument = _first_call_argument(stripped_line, match.end() - 1)
        if argument is None:
            return True
        static_argument = _js_static_string_expression_value(argument, bindings)
        if static_argument is not None:
            if _js_fetch_literal_value_is_local(static_argument):
                continue
            if _js_fetch_literal_value_is_remote(static_argument):
                return True
            continue
        if _js_fetch_argument_is_local(argument):
            continue
        if _js_fetch_argument_is_remote(argument):
            return True
    return False


def _js_static_string_bindings(text: str) -> dict[str, str]:
    raw = str(text or "")
    if not raw:
        return {}
    assignments: list[tuple[str, str]] = []
    assigned_names: set[str] = set()
    duplicate_names: set[str] = set()
    for statement in _js_static_binding_candidate_statements(raw):
        statement = statement.strip()
        if not statement:
            continue
        declaration = re.search(
            r"(?:^|[;\n{(])\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(.+)$",
            statement,
            re.DOTALL,
        )
        if declaration:
            name = declaration.group(1)
            expression = declaration.group(2).strip()
            if name in assigned_names:
                duplicate_names.add(name)
            assigned_names.add(name)
            assignments.append((name, expression))
            continue
        reassignment = re.search(r"(?:^|[;\n{(])\s*([A-Za-z_$][\w$]*)\s*(?:=|\+=)", statement)
        if reassignment:
            name = reassignment.group(1)
            if name in assigned_names:
                duplicate_names.add(name)
            assigned_names.add(name)
    bindings: dict[str, str] = {}
    unresolved = list(assignments)
    for _ in range(max(len(unresolved), 1)):
        if not unresolved:
            break
        next_unresolved: list[tuple[str, str]] = []
        progressed = False
        for name, expression in unresolved:
            if name in duplicate_names:
                continue
            value = _js_static_string_expression_value(expression, bindings)
            if value is None:
                next_unresolved.append((name, expression))
                continue
            bindings[name] = value
            progressed = True
        if not progressed:
            break
        unresolved = next_unresolved
    for name in duplicate_names:
        bindings.pop(name, None)
    return bindings


def _js_static_binding_candidate_statements(text: str) -> list[str]:
    candidates: list[str] = []
    for statement in _split_js_statements(text):
        if "\n" not in statement:
            candidates.append(statement)
            continue
        candidates.extend(line for line in statement.splitlines() if line.strip())
    return candidates


def _split_js_statements(text: str) -> list[str]:
    statements: list[str] = []
    start = 0
    quote = ""
    escaped = False
    template_depth = 0
    depth = 0
    raw = str(text or "")
    for index, char in enumerate(raw):
        if quote:
            if escaped:
                escaped = False
                continue
            if char == "\\":
                escaped = True
                continue
            if quote == "`" and char == "$" and index + 1 < len(raw) and raw[index + 1] == "{":
                template_depth += 1
                continue
            if quote == "`" and template_depth > 0:
                if char == "{":
                    template_depth += 1
                elif char == "}":
                    template_depth -= 1
                continue
            if char == quote:
                quote = ""
            continue
        if char in {"'", '"', "`"}:
            quote = char
            continue
        if char in "([":
            depth += 1
            continue
        if char in ")]":
            depth = max(depth - 1, 0)
            continue
        if char == ";" and depth == 0:
            statements.append(raw[start:index])
            start = index + 1
    tail = raw[start:]
    if tail.strip():
        statements.append(tail)
    return statements


def _js_static_string_expression_value(expression: str, bindings: dict[str, str] | None = None) -> str | None:
    expr = str(expression or "").strip()
    if not expr:
        return None
    bindings = bindings or {}
    unwrapped = _strip_wrapping_parentheses(expr)
    if unwrapped != expr:
        return _js_static_string_expression_value(unwrapped, bindings)
    literal = _js_static_string_literal_value(expr)
    if literal is not None:
        return literal
    if re.fullmatch(r"[A-Za-z_$][\w$]*", expr):
        return bindings.get(expr)
    parts = _split_js_plus_expression(expr)
    if len(parts) <= 1:
        return None
    values: list[str] = []
    for part in parts:
        value = _js_static_string_expression_value(part, bindings)
        if value is None:
            return None
        values.append(value)
    return "".join(values)


def _split_js_plus_expression(expression: str) -> list[str]:
    parts: list[str] = []
    start = 0
    quote = ""
    escaped = False
    template_depth = 0
    depth = 0
    expr = str(expression or "")
    for index, char in enumerate(expr):
        if quote:
            if escaped:
                escaped = False
                continue
            if char == "\\":
                escaped = True
                continue
            if quote == "`" and char == "$" and index + 1 < len(expr) and expr[index + 1] == "{":
                template_depth += 1
                continue
            if quote == "`" and template_depth > 0:
                if char == "{":
                    template_depth += 1
                elif char == "}":
                    template_depth -= 1
                continue
            if char == quote:
                quote = ""
            continue
        if char in {"'", '"', "`"}:
            quote = char
            continue
        if char in "([{":
            depth += 1
            continue
        if char in ")]}":
            depth = max(depth - 1, 0)
            continue
        if char == "+" and depth == 0:
            parts.append(expr[start:index].strip())
            start = index + 1
    parts.append(expr[start:].strip())
    return parts


def _strip_wrapping_parentheses(expression: str) -> str:
    expr = str(expression or "").strip()
    if not (expr.startswith("(") and expr.endswith(")")):
        return expr
    depth = 0
    quote = ""
    escaped = False
    for index, char in enumerate(expr):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {"'", '"', "`"}:
            quote = char
            continue
        if char == "(":
            depth += 1
            continue
        if char == ")":
            depth -= 1
            if depth == 0 and index != len(expr) - 1:
                return expr
    return expr[1:-1].strip() if depth == 0 else expr


def _js_static_string_literal_value(expression: str) -> str | None:
    expr = str(expression or "").strip()
    if len(expr) < 2:
        return None
    quote = expr[0]
    if quote in {"'", '"'} and expr[-1] == quote:
        try:
            value = ast.literal_eval(expr)
        except (SyntaxError, ValueError):
            return None
        return value if isinstance(value, str) else None
    if quote == "`" and expr[-1] == "`":
        body = expr[1:-1]
        if "${" in body:
            return None
        return body.replace("\\`", "`").replace("\\\\", "\\")
    return None


def _first_call_argument(text: str, open_paren_index: int) -> str | None:
    if open_paren_index < 0 or open_paren_index >= len(text) or text[open_paren_index] != "(":
        return None
    depth = 0
    quote = ""
    escaped = False
    start = open_paren_index + 1
    for index in range(open_paren_index + 1, len(text)):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {"'", '"', "`"}:
            quote = char
            continue
        if char in "([{":
            depth += 1
            continue
        if char in ")]}":
            if depth <= 0:
                return text[start:index].split(",", 1)[0].strip()
            depth -= 1
            continue
        if char == "," and depth == 0:
            return text[start:index].strip()
    return None


def _js_fetch_argument_is_local(argument: str) -> bool:
    arg = str(argument or "").strip()
    literal = _js_static_string_literal_value(arg)
    if literal is not None and _js_fetch_literal_value_is_local(literal):
        return True
    if _js_fetch_argument_name_has_remote_network_semantics(arg):
        return False
    if re.fullmatch(r"[A-Za-z_$][\w$]*", arg):
        lowered = arg.lower()
        if lowered in {"path", "pathname", "filepath", "filename", "file", "src", "href"}:
            return True
        if lowered.endswith("path") and not any(token in lowered for token in ("url", "uri", "endpoint", "host")):
            return True
    return False


def _js_fetch_argument_is_remote(argument: str) -> bool:
    arg = str(argument or "").strip()
    literal = _js_static_string_literal_value(arg)
    if literal is not None and _js_fetch_literal_value_is_remote(literal):
        return True
    if re.search(r"['\"](?:(?:https?|ftp|ftps|wss?)://|//)", arg, re.IGNORECASE):
        return True
    if re.search(r"\bnew\s+URL\s*\(", arg):
        return True
    return _js_fetch_argument_name_has_remote_network_semantics(arg)


def _js_fetch_literal_value_is_local(value: str) -> bool:
    return bool(re.match(r"(?:\.{0,2}/|/)", str(value or "").strip()))


def _js_fetch_literal_value_is_remote(value: str) -> bool:
    return bool(re.match(r"(?:(?:https?|ftp|ftps|wss?)://|//)", str(value or "").strip(), re.IGNORECASE))


def _js_fetch_argument_name_has_remote_network_semantics(argument: str) -> bool:
    network_terms = {
        "endpoint",
        "url",
        "uri",
        "host",
        "addr",
        "address",
        "webhook",
        "callback",
        "remote",
        "upload",
        "download",
        "api",
    }
    for identifier in re.findall(r"[A-Za-z_$][\w$]*", str(argument or "")):
        pieces = re.split(r"[_$]+", identifier)
        tokens: list[str] = []
        for piece in pieces:
            tokens.extend(
                token.lower()
                for token in re.findall(
                    r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)|\d+",
                    piece,
                )
            )
        if any(token in network_terms for token in tokens):
            return True
    return False


def _strip_markdown_fenced_blocks(text: str) -> str:
    lines = str(text or "").splitlines()
    output: list[str] = []
    in_fence = False
    fence_marker = ""
    for line in lines:
        stripped = line.strip()
        marker_match = re.match(r"^(```+|~~~+)", stripped)
        if marker_match:
            marker = marker_match.group(1)
            if not in_fence:
                in_fence = True
                fence_marker = marker[:3]
            elif marker.startswith(fence_marker):
                in_fence = False
                fence_marker = ""
            continue
        if not in_fence:
            output.append(line)
    return "\n".join(output)


def _patch_added_file_payloads(text: str) -> list[tuple[str, str]]:
    payloads: list[tuple[str, str]] = []
    current_path: str | None = None
    current_lines: list[str] = []
    for line in str(text or "").splitlines():
        stripped = line.strip()
        match = re.match(r"^\*\*\*\s+(?:Add|Update)\s+File:\s+(.+)$", stripped)
        if match:
            if current_path is not None and current_lines:
                payloads.append((current_path, "\n".join(current_lines)))
            current_path = match.group(1).strip()
            current_lines = []
            continue
        if stripped.startswith("***"):
            if current_path is not None and current_lines:
                payloads.append((current_path, "\n".join(current_lines)))
            current_path = None
            current_lines = []
            continue
        if current_path is None:
            continue
        if line.startswith("+") and not line.startswith("+++"):
            current_lines.append(line[1:])
        elif line.startswith(" ") and not line.startswith(" ***"):
            current_lines.append(line[1:])
    if current_path is not None and current_lines:
        payloads.append((current_path, "\n".join(current_lines)))
    return payloads


def _patch_updated_file_payloads(text: str) -> list[tuple[str, str]]:
    payloads: list[tuple[str, str]] = []
    current_path: str | None = None
    current_lines: list[str] = []
    for line in str(text or "").splitlines():
        stripped = line.strip()
        match = re.match(r"^\*\*\*\s+Update\s+File:\s+(.+)$", stripped)
        if match:
            if current_path is not None and current_lines:
                payloads.append((current_path, "\n".join(current_lines)))
            current_path = match.group(1).strip()
            current_lines = []
            continue
        if stripped.startswith("***"):
            if current_path is not None and current_lines:
                payloads.append((current_path, "\n".join(current_lines)))
            current_path = None
            current_lines = []
            continue
        if current_path is None:
            continue
        if line.startswith("+") and not line.startswith("+++"):
            current_lines.append(line[1:])
        elif line.startswith(" ") and not line.startswith(" ***"):
            current_lines.append(line[1:])
    if current_path is not None and current_lines:
        payloads.append((current_path, "\n".join(current_lines)))
    return payloads


def _apply_patch_file_directive_path(line: str) -> str | None:
    stripped = str(line or "").strip()
    match = re.match(r"^\*\*\*\s+(?:Add|Update|Delete)\s+File:\s+(.+)$", stripped)
    if not match:
        return None
    return match.group(1).strip()


def _path_has_associated_script_surface_suffix(path: str) -> bool:
    suffix = PurePosixPath(str(path or "").strip().strip("'\"")).suffix.lower()
    return suffix in _ASSOCIATED_SCRIPT_SURFACE_SUFFIXES


def _web_text_has_remote_script_loader(text: str) -> bool:
    raw = str(text or "")
    if re.search(
        r"\bscript\s*\.\s*src\s*=\s*['\"]?(?:https?:)?//|"
        r"<script\b[^>]*\bsrc\s*=\s*['\"]?(?:https?:)?//|"
        r"\bimport\s*\(\s*['\"](?:https?:)?//|"
        r"\bfrom\s+['\"](?:https?:)?//",
        raw,
        re.IGNORECASE,
    ):
        return True
    return _web_text_has_dynamic_remote_script_loader(raw)


def _web_text_has_dynamic_remote_script_loader(text: str) -> bool:
    if not re.search(r"\bcreateElement\b", text, re.IGNORECASE):
        return False
    identifier = r"[A-Za-z_$][A-Za-z0-9_$]*"
    document_aliases = _web_js_string_aliases_for_object(text, r"(?:document|window\.document)")
    script_tag_vars = _web_js_string_aliases_for_literal(text, "script")
    script_creator_expr = _web_script_creator_expr(document_aliases, script_tag_vars)
    src_attr_vars = _web_js_string_aliases_for_literal(text, "src")
    src_attr_expr = _web_script_src_attr_expr(src_attr_vars)
    script_vars = set(
        re.findall(
            rf"\b(?:const|let|var)\s+({identifier})\s*=\s*{script_creator_expr}",
            text,
            re.IGNORECASE,
        )
    )
    script_vars.update(
        re.findall(
            rf"(?<![\w$.])({identifier})\s*=\s*{script_creator_expr}",
            text,
            re.IGNORECASE,
        )
    )
    remote_url_vars = _web_remote_url_aliases(text)
    remote_source_expr = _web_remote_script_source_expr(remote_url_vars)
    if _web_text_has_object_assign_remote_script_loader(text, remote_source_expr, script_creator_expr):
        return True
    return any(
        re.search(rf"\b{re.escape(script_var)}\s*\.\s*src\s*=\s*{remote_source_expr}", text, re.IGNORECASE)
        or re.search(
            rf"\b{re.escape(script_var)}\s*\[\s*{src_attr_expr}\s*\]\s*=\s*{remote_source_expr}",
            text,
            re.IGNORECASE,
        )
        or re.search(
            rf"\b{re.escape(script_var)}\s*\.\s*setAttribute\s*\(\s*{src_attr_expr}\s*,\s*"
            rf"{remote_source_expr}",
            text,
            re.IGNORECASE,
        )
        or re.search(
            rf"\bObject\s*\.\s*assign\s*\(\s*{re.escape(script_var)}\s*,\s*\{{[^}}]*"
            rf"{_web_object_src_key_expr(src_attr_vars)}\s*:\s*{remote_source_expr}",
            text,
            re.IGNORECASE | re.DOTALL,
        )
        for script_var in script_vars
    )


def _web_js_string_aliases_for_literal(text: str, literal: str) -> set[str]:
    return set(
        re.findall(
            rf"\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*['\"]{re.escape(literal)}['\"]",
            text,
            re.IGNORECASE,
        )
    )


def _web_js_string_aliases_for_object(text: str, object_expr: str) -> set[str]:
    return set(
        re.findall(
            rf"\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*{object_expr}\b",
            text,
            re.IGNORECASE,
        )
    )


def _web_script_creator_expr(document_aliases: set[str], script_tag_vars: set[str]) -> str:
    document_expr = r"(?:document|window\.document"
    if document_aliases:
        document_expr += "|" + "|".join(re.escape(alias) for alias in sorted(document_aliases))
    document_expr += ")"
    tag_expr = r"(?:['\"]script['\"]"
    if script_tag_vars:
        tag_expr += "|" + "|".join(rf"\b{re.escape(alias)}\b" for alias in sorted(script_tag_vars))
    tag_expr += ")"
    return (
        rf"{document_expr}\s*(?:\.\s*createElement|\[\s*['\"]createElement['\"]\s*\])"
        rf"\s*\(\s*{tag_expr}\s*\)"
    )


def _web_script_src_attr_expr(src_attr_vars: set[str]) -> str:
    attr_expr = r"(?:['\"]src['\"]"
    if src_attr_vars:
        attr_expr += "|" + "|".join(rf"\b{re.escape(alias)}\b" for alias in sorted(src_attr_vars))
    attr_expr += ")"
    return attr_expr


def _web_object_src_key_expr(src_attr_vars: set[str]) -> str:
    key_expr = r"(?:['\"]src['\"]|src"
    if src_attr_vars:
        key_expr += "|" + "|".join(rf"\[\s*\b{re.escape(alias)}\b\s*\]" for alias in sorted(src_attr_vars))
    key_expr += ")"
    return key_expr


def _web_remote_url_aliases(text: str) -> set[str]:
    aliases: set[str] = set()
    for pattern in (
        r"\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*['\"](?:https?:)?//",
        r"\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*new\s+URL\s*\(\s*['\"](?:https?:)?//",
        r"\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*['\"]https?:['\"]\s*\+\s*['\"]//",
    ):
        aliases.update(re.findall(pattern, text, re.IGNORECASE))
    return aliases


def _web_text_has_object_assign_remote_script_loader(
    text: str,
    remote_source_expr: str,
    script_creator_expr: str,
) -> bool:
    object_assign_script = (
        r"\bObject\s*\.\s*assign\s*\(\s*"
        rf"{script_creator_expr}\s*,"
        r"\s*\{[^}]*"
        r"(?:['\"]src['\"]|src)\s*:\s*"
        rf"{remote_source_expr}"
    )
    return re.search(object_assign_script, text, re.IGNORECASE | re.DOTALL) is not None


def _web_remote_script_source_expr(remote_url_vars: set[str]) -> str:
    if not remote_url_vars:
        return r"(?:['\"](?:https?:)?//|['\"]https?:['\"]\s*\+\s*['\"]//)"
    variable_alternatives = "|".join(
        rf"\b{re.escape(name)}\b(?:\s*\.\s*href|\s*\.\s*toString\s*\(\s*\))?"
        for name in sorted(remote_url_vars)
    )
    return rf"(?:['\"](?:https?:)?//|['\"]https?:['\"]\s*\+\s*['\"]//|{variable_alternatives})"


def _web_text_has_persistence_loader_contract(text: str) -> bool:
    raw = str(text or "")
    if not raw.strip():
        return False
    lowered = raw.lower()
    has_web_surface = bool(
        re.search(
            r"<script\b|"
            r"</script>|"
            r"<html\b|"
            r"\bwindow\s*\.|"
            r"\bdocument\s*\.|"
            r"<link\b[^>]*\brel\s*=\s*['\"][^'\"]*manifest",
            raw,
            re.IGNORECASE,
        )
    )
    if not has_web_surface:
        return False
    marker_categories = 0
    if _web_text_has_enabled_autoload_marker(lowered):
        marker_categories += 1
    if re.search(r"\b(?:[a-z0-9]+[_-])?reentry(?:[_-]?(?:expected|hook|loader))?\b", lowered):
        marker_categories += 1
    if re.search(r"\b(?:bootstrap|loader)[_-]?(?:scope|mode|path|manifest|hook)\b", lowered):
        marker_categories += 1
    if re.search(r"\b(?:persistence|persisted|long[_-]?lived)[_-]?(?:loader|hook|entrypoint|bootstrap)\b", lowered):
        marker_categories += 1
    if re.search(r"\bwindow\s*\.\s*__[A-Za-z0-9_$]*(?:loader|bootstrap|autoload|reentry)\b", raw):
        marker_categories += 1
    return marker_categories >= 2


def _web_text_has_enabled_autoload_marker(text: str) -> bool:
    for match in re.finditer(r"\bauto(?:load|run|start)(?:[_-]?on[_-]?(?:open|load|startup))?\b", text):
        after = text[match.end(): match.end() + 48]
        if re.match(r"\s*['\"]?\s*[:=]\s*['\"]?(?:false|0|no|null|none)\b", after):
            continue
        return True
    return False


def _shebang_names_executable_script(line: str) -> bool:
    stripped = str(line or "").rstrip()
    if not stripped.startswith("#!"):
        return False
    body = stripped[2:].strip()
    if not body:
        return False
    try:
        tokens = shlex.split(body)
    except ValueError:
        tokens = body.split()
    if not tokens:
        return False
    command = Path(tokens[0]).name.lower()
    args = tokens[1:]
    if command == "env":
        command = _env_shebang_interpreter(args)
    return bool(
        re.fullmatch(r"python(?:\d+(?:\.\d+)?)?", command)
        or command in {"node", "nodejs", "bash", "sh", "dash", "zsh", "ruby", "perl", "php", "pwsh"}
    )


def _env_shebang_interpreter(tokens: list[str]) -> str:
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if not token:
            index += 1
            continue
        if token in {"-S", "--split-string"}:
            if index + 1 >= len(tokens):
                return ""
            nested = _env_shebang_interpreter(_split_env_shebang_command(tokens[index + 1]))
            if nested:
                return nested
            index += 2
            continue
        if token.startswith("-") and not token.startswith("--"):
            split_index = token.find("S", 1)
            if split_index >= 1:
                split_value = token[split_index + 1:]
                if split_value:
                    nested = _env_shebang_interpreter(_split_env_shebang_command(split_value))
                    if nested:
                        return nested
                    index += 1
                    continue
                if index + 1 >= len(tokens):
                    return ""
                nested = _env_shebang_interpreter(_split_env_shebang_command(tokens[index + 1]))
                if nested:
                    return nested
                index += 2
                continue
        if token.startswith("-S") and len(token) > 2:
            nested = _env_shebang_interpreter(_split_env_shebang_command(token[2:]))
            if nested:
                return nested
            index += 1
            continue
        if token.startswith("--split-string="):
            nested = _env_shebang_interpreter(_split_env_shebang_command(token.partition("=")[2]))
            if nested:
                return nested
            index += 1
            continue
        if token in {"-u", "--unset", "-C", "--chdir"}:
            index += 2
            continue
        if token.startswith("--unset=") or token.startswith("--chdir="):
            index += 1
            continue
        if token.startswith("-") or ("=" in token and not token.startswith("=")):
            index += 1
            continue
        return Path(token).name.lower()
    return ""


def _split_env_shebang_command(token: str) -> list[str]:
    try:
        return shlex.split(token)
    except ValueError:
        return token.split()


def _first_meaningful_payload_line(text: str) -> str | None:
    for line in str(text or "").splitlines():
        raw_line = line.rstrip()
        stripped = raw_line.strip()
        if not stripped:
            continue
        if stripped.startswith(("***", "@@", "---", "+++")):
            continue
        return raw_line
    return None


_INPUT_TARGET_ROLES = frozenset({
    "document_input",
    "source",
    "input",
    SCOPE_TASK_DATA_READ_PATH_ROLE,
})
_OUTPUT_TARGET_ROLES = frozenset({
    "future_execution.artifact",
    "generated_artifact",
    "verifier_artifact",
    "workspace_file",
    "persistence_entrypoint",
    "bootstrap_loader",
    SCOPE_TASK_OUTPUT_PATH_ROLE,
})


def contextual_binding_parts(
    event: CanonicalEvent,
    context: DecisionContext | None = None,
) -> dict[str, Any]:
    envelope = normalize_action_effect(event, context)
    payload = event.payload or {}
    cwd = _payload_effective_cwd(payload)
    input_hashes = sorted(
        target.path_hash for target in envelope.targets
        if target.path_hash and target.path_role in _INPUT_TARGET_ROLES
    )
    output_hashes = sorted(
        target.path_hash for target in envelope.targets
        if target.path_hash and target.path_role in _OUTPUT_TARGET_ROLES
    )
    artifact_targets = [
        target for target in envelope.targets
        if target.artifact_role
    ]
    return {
        "event_id": event.event_id,
        "session_id": event.session_id,
        "effect_hash": effect_hash(envelope),
        "canonical_argv_hash": envelope.canonical_argv_hash,
        "raw_payload_hash": envelope.raw_payload_hash,
        "cwd_hash": _hash(cwd) if cwd else None,
        "interpreter": envelope.interpreters[0] if envelope.interpreters else None,
        "script_or_content_hash": _script_or_content_hash(event, envelope, context),
        "input_path_hashes": input_hashes,
        "output_path_hashes": output_hashes,
        "analysis_state": envelope.analysis_state,
        "confidence": envelope.confidence,
        "effects": list(envelope.effects),
        "evidence_rules": list(envelope.evidence_rules),
        "wrapper_chain": list(envelope.wrapper_chain),
        "target_roles": sorted({target.path_role for target in envelope.targets if target.path_role}),
        "artifact_roles": sorted({target.artifact_role for target in artifact_targets if target.artifact_role}),
        "artifact_candidate_roles": sorted({
            target.artifact_candidate_role for target in artifact_targets
            if target.artifact_candidate_role
        }),
        "artifact_sources": sorted({
            target.artifact_source for target in artifact_targets
            if target.artifact_source
        }),
        "artifact_source_families": sorted({
            _artifact_source_family(target.artifact_source) for target in artifact_targets
            if _artifact_source_family(target.artifact_source)
        }),
        "artifact_source_tiers": sorted({
            target.artifact_source_tier for target in artifact_targets
            if target.artifact_source_tier
        }),
        "artifact_profile_hashes": sorted({
            target.artifact_profile_hash for target in artifact_targets
            if target.artifact_profile_hash
        }),
        "artifact_case_ids": sorted({
            target.artifact_case_id for target in artifact_targets
            if target.artifact_case_id
        }),
        "artifact_match_types": sorted({
            target.artifact_match_type for target in artifact_targets
            if target.artifact_match_type
        }),
    }


def _script_or_content_hash(
    event: CanonicalEvent,
    envelope: ActionEffectEnvelope,
    context: DecisionContext | None,
) -> str | None:
    payload = event.payload or {}
    command = str(payload.get("command") or payload.get("cmd") or "").strip()
    cwd = _payload_effective_cwd(payload)
    script_path = _script_path_from_command(command)
    if script_path and cwd:
        relative = Path(script_path)
        if relative.is_absolute() or ".." in relative.parts:
            return envelope.raw_payload_hash
        cwd_root = _trusted_cwd_root(cwd, context)
        if cwd_root is None:
            return envelope.raw_payload_hash
        try:
            candidate = (cwd_root / relative).resolve(strict=True)
            candidate.relative_to(cwd_root)
            if candidate.is_file() and candidate.stat().st_size <= _MAX_SCRIPT_BINDING_BYTES:
                digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
                return "sha256:" + digest
        except (OSError, RuntimeError, ValueError):
            pass
    return envelope.raw_payload_hash


def _trusted_cwd_root(cwd: str, context: DecisionContext | None) -> Path | None:
    scope = context.session_scope_profile if context is not None else None
    prefixes = (
        list(scope.task_rules.allowed_path_prefixes or [])
        if scope is not None and scope.task_rules is not None
        else []
    )
    if not prefixes:
        return None
    try:
        cwd_root = Path(cwd).resolve(strict=True)
    except OSError:
        return None
    for prefix in prefixes:
        try:
            allowed_root = Path(str(prefix)).resolve(strict=True)
            cwd_root.relative_to(allowed_root)
            return cwd_root
        except (OSError, RuntimeError, ValueError):
            continue
    return None


def _script_path_from_command(command: str) -> str | None:
    if not command:
        return None
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    for index, token in enumerate(tokens[:-1]):
        name = Path(token).name.lower()
        if name in {"python", "python3", "node", "nodejs", "bash", "sh", "zsh"}:
            for candidate in tokens[index + 1:]:
                if candidate.startswith("-"):
                    continue
                if candidate.endswith(_EXECUTABLE_SUFFIXES):
                    return candidate
                return None
    return None


def _strip_safe_shell_path_format_substitutions(text: str) -> str:
    raw = str(text or "")
    pattern = re.compile(
        r"\$\(\s*(?:basename|dirname)\s+(?:--\s+)?[\"']?"
        r"(?:\$\{?[A-Za-z_]\w*\}?|[~/\.A-Za-z0-9_+@%:,=-][~/\.A-Za-z0-9_+@%:,=\[\]*?-]*)"
        r"[\"']?\s*\)"
    )

    def _replace(match: re.Match[str]) -> str:
        suffix = raw[match.end():].lstrip("'\"")
        if suffix.startswith(("/", "\\", ".", "*", "?", "[")):
            return match.group(0)
        return ""

    return pattern.sub(_replace, raw)


def _is_shell_capability_probe(command: str, tokens: list[str], text: str) -> bool:
    if not tokens:
        return False
    if _is_help_or_version_probe(tokens):
        return True
    if command in {"npm", "pnpm", "yarn"} and len(tokens) >= 2:
        subcommand = tokens[1].lower()
        if subcommand in {"root", "prefix", "bin", "config"}:
            return True
        if subcommand == "list" and any(token in {"-g", "--global"} for token in tokens[2:]):
            return True
    if command == "git" and tokens[1:3] == ["rev-parse", "--is-inside-work-tree"]:
        return True
    if command in {"python", "python3"}:
        return _is_python_capability_probe(tokens, text)
    if command in {"node", "nodejs"}:
        return _is_node_capability_probe(tokens, text)
    if command == "perl":
        return _is_perl_constant_probe(tokens)
    if command == "awk":
        return _is_awk_constant_probe(tokens)
    if command in {"echo", "printf"}:
        return _is_stdout_constant_probe(tokens, text)
    return False


def _is_help_or_version_probe(tokens: list[str]) -> bool:
    return any(token in {"--help", "-h", "--version", "-v", "-V", "-VV"} for token in tokens[1:])


def _is_python_capability_probe(tokens: list[str], text: str) -> bool:
    if _is_help_or_version_probe(tokens):
        return True
    if _is_python_constant_probe(tokens):
        return True
    lowered = text.lower()
    risky_markers = (
        "open(",
        ".write(",
        "subprocess",
        "os.system",
        "requests.",
        "socket",
        "shutil",
        "eval(",
        "exec(",
    )
    if any(marker in lowered for marker in risky_markers):
        return False
    if any(marker in lowered for marker in ("sys.version", "importlib.util.find_spec")):
        return True
    if _is_python_module_capability_probe(text):
        return True
    return _is_python_metadata_version_probe(text)


def _is_python_module_capability_probe(text: str) -> bool:
    source = _inline_python_source(text) or text
    lowered = source.lower()
    risky_markers = (
        "open(",
        ".write(",
        "write_text(",
        "write_bytes(",
        "subprocess",
        "os.system",
        "popen",
        "requests.",
        "httpx.",
        "http.client",
        "urllib.",
        "socket",
        "shutil",
        "eval(",
        "exec(",
        "compile(",
        "__import__(",
    )
    if any(marker in lowered for marker in risky_markers):
        return False
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return False

    importlib_aliases = {"importlib"}
    find_spec_aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "importlib":
                    importlib_aliases.add(alias.asname or "importlib")
                elif alias.name == "importlib.util":
                    if alias.asname:
                        find_spec_aliases.add(f"{alias.asname}.find_spec")
                    importlib_aliases.add("importlib")
                else:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module not in {"importlib", "importlib.util"}:
                return False
            for alias in node.names:
                if node.module == "importlib.util" and alias.name == "find_spec":
                    find_spec_aliases.add(alias.asname or alias.name)
                else:
                    return False

    module_bindings = _python_module_probe_literal_bindings(tree)
    loop_bindings = _python_module_probe_loop_bindings(tree, module_bindings)
    saw_probe = False
    saw_print = False
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _python_call_matches_name(node.func, {"print"}):
            saw_print = True
            continue
        if _python_call_is_bool_find_spec_probe(
            node,
            importlib_aliases=importlib_aliases,
            find_spec_aliases=find_spec_aliases,
            module_bindings=module_bindings,
            loop_bindings=loop_bindings,
        ):
            saw_probe = True
            continue
        if _python_call_is_find_spec_probe(
            node,
            importlib_aliases=importlib_aliases,
            find_spec_aliases=find_spec_aliases,
            module_bindings=module_bindings,
            loop_bindings=loop_bindings,
        ):
            saw_probe = True
            continue
        return False
    return saw_probe and saw_print


def _is_python_constant_probe(tokens: list[str]) -> bool:
    script = _inline_script_after_flag(tokens, {"-c", "--command"})
    if script is None:
        return False
    return _is_python_source_constant_probe(script)


def _is_python_source_constant_probe(script: str) -> bool:
    try:
        tree = ast.parse(script)
    except SyntaxError:
        return False
    if len(tree.body) != 1 or not isinstance(tree.body[0], ast.Expr):
        return False
    call = tree.body[0].value
    if not isinstance(call, ast.Call) or not _python_call_matches_name(call.func, {"print"}):
        return False
    return all(_python_constant_probe_arg(arg) for arg in call.args) and not call.keywords


def _is_safe_python_module_probe_name(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z_]\w*", str(value or "")))


def _is_python_metadata_version_probe(text: str) -> bool:
    source = _inline_python_source(text) or text
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return False
    metadata_aliases = {"importlib.metadata"}
    version_aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "importlib.metadata":
                    metadata_aliases.add(alias.asname or "importlib.metadata")
                elif alias.name == "importlib":
                    continue
                else:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module != "importlib.metadata":
                return False
            for alias in node.names:
                if alias.name == "version":
                    version_aliases.add(alias.asname or alias.name)
                else:
                    return False
    saw_version = False
    saw_print = False
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _python_call_matches_name(node.func, {"print"}):
            saw_print = True
            continue
        if _python_call_is_importlib_metadata_version(node, metadata_aliases, version_aliases):
            saw_version = True
            continue
        return False
    return saw_version and saw_print


def _is_node_capability_probe(tokens: list[str], text: str) -> bool:
    if _is_help_or_version_probe(tokens):
        return True
    if _is_node_constant_probe(tokens):
        return True
    lowered = text.lower()
    risky_markers = (
        "writefile",
        "appendfile",
        "unlink",
        "rm(",
        "rmdir",
        "mkdir",
        "child_process",
        "process.env",
        "eval(",
        "function(",
        "fetch(",
        "axios.",
    )
    if any(marker in lowered for marker in risky_markers):
        return False
    modules = re.findall(r"\brequire\(\s*['\"]([^'\"]+)['\"]\s*\)", text)
    if not modules or "console.log" not in lowered:
        return False
    blocked_modules = {"fs", "node:fs", "child_process", "node:child_process", "http", "https", "net", "tls", "dgram"}
    return all(_is_safe_node_probe_module(module, blocked_modules) for module in modules)


def _inline_script_after_flag(tokens: list[str], flags: set[str]) -> str | None:
    for index, token in enumerate(tokens[:-1]):
        if token in flags:
            return tokens[index + 1]
    return None


def _is_node_constant_probe(tokens: list[str]) -> bool:
    script = _inline_script_after_flag(tokens, {"-e", "--eval"})
    if script is None:
        return False
    return re.fullmatch(
        r"\s*console\.log\(\s*['\"][A-Za-z0-9_.: -]{1,80}['\"]\s*\)\s*;?\s*",
        script,
    ) is not None


def _is_perl_constant_probe(tokens: list[str]) -> bool:
    script = _inline_script_after_flag(tokens, {"-e"})
    if script is None:
        return False
    return re.fullmatch(
        r"\s*print\s+['\"][A-Za-z0-9_.: -]{1,80}(?:\\n)?['\"]\s*;?\s*",
        script,
    ) is not None


def _is_awk_constant_probe(tokens: list[str]) -> bool:
    if len(tokens) != 2:
        return False
    return re.fullmatch(
        r"\s*BEGIN\s*\{\s*print\s+['\"][A-Za-z0-9_.: -]{1,80}['\"]\s*;?\s*\}\s*",
        tokens[1],
    ) is not None


def _is_safe_node_probe_module(module: str, blocked_modules: set[str]) -> bool:
    normalized = str(module or "").strip().lower()
    if not normalized or normalized in blocked_modules:
        return False
    if normalized.startswith((".", "/", "\\")) or ".." in normalized:
        return False
    if "/" in normalized and not normalized.startswith("@"):
        return False
    if normalized.startswith("@") and normalized.count("/") != 1:
        return False
    return bool(re.fullmatch(r"@?[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?", normalized))


def _is_stdout_constant_probe(tokens: list[str], text: str) -> bool:
    if len(tokens) < 2:
        return False
    if any(marker in text for marker in ("$", "`", "<", ">", "|")):
        return False
    return not any(_looks_like_path_arg(token) for token in tokens[1:])


def _zip_password_creation(tokens: list[str]) -> bool:
    if not tokens or Path(tokens[0]).name.lower() != "zip":
        return False
    read_modes = {"--test", "-T", "--show-files", "-sf", "-h", "--help", "-v", "--version"}
    if any(token in read_modes for token in tokens[1:]):
        return False
    for index, token in enumerate(tokens[1:], start=1):
        if token in {"-P", "--password"} and index + 1 < len(tokens):
            return True
        if token.startswith("-P") and len(token) > 2:
            return True
        if token in {"-e", "--encrypt"} or (
            "e" in token[1:] and token.startswith("-") and not token.startswith("--")
        ):
            return True
    return False


def _seven_zip_password_creation(tokens: list[str]) -> bool:
    if not tokens or Path(tokens[0]).name.lower() not in {"7z", "7za", "7zr"}:
        return False
    if len(tokens) < 2 or tokens[1].lower() not in {"a", "u"}:
        return False
    return any(token == "-p" or token.startswith("-p") for token in tokens[2:])


def _gpg_symmetric_creation(tokens: list[str]) -> bool:
    if not tokens or Path(tokens[0]).name.lower() not in {"gpg", "gpg2"}:
        return False
    if any(token in {"--decrypt", "-d", "--verify", "--list-packets", "--list-keys"} for token in tokens[1:]):
        return False
    return any(token in {"-c", "--symmetric"} for token in tokens[1:])


def _openssl_enc_creation(tokens: list[str]) -> bool:
    if not tokens or Path(tokens[0]).name.lower() != "openssl":
        return False
    if "enc" not in tokens[1:]:
        return False
    if "-d" in tokens or "-decrypt" in tokens:
        return False
    return "-out" in tokens or any(token.startswith("-out=") for token in tokens)


def _archive_encrypt_pipeline(text: str) -> bool:
    if "|" not in text:
        return False
    left, right = text.split("|", 1)
    try:
        left_tokens = shlex.split(left.strip())
        right_tokens = shlex.split(right.strip())
    except ValueError:
        left_tokens = left.strip().split()
        right_tokens = right.strip().split()
    if not left_tokens or Path(left_tokens[0]).name.lower() != "tar":
        return False
    return _gpg_symmetric_creation(right_tokens) or _openssl_enc_creation(right_tokens)


def _archive_targets(tokens: list[str]) -> list[str]:
    return [
        token
        for token in tokens[1:]
        if not token.startswith("-") and _PATH_RE.search(token)
    ][:3]


def _analyze_encrypted_archive_creation(text: str) -> dict[str, Any]:
    rules: list[str] = []
    targets: list[str] = []
    segments = _shell_segments(text)

    for tokens in segments:
        if _zip_password_creation(tokens) or _seven_zip_password_creation(tokens):
            _add_rule(rules, "password_protected_archive_creation")
            targets.extend(_archive_targets(tokens))
        elif _gpg_symmetric_creation(tokens) or _openssl_enc_creation(tokens):
            _add_rule(rules, "encrypted_artifact_creation")
            targets.extend(_archive_targets(tokens))

    if _archive_encrypt_pipeline(text):
        _add_rule(rules, "archive_encrypt_pipeline")
        targets.extend(_first_path(part) for part in text.split("|") if _first_path(part))

    if rules and _ARCHIVE_DELETE_RE.search(text):
        _add_rule(rules, "encrypted_archive_then_delete_original")

    return {
        "rules": rules,
        "targets": [path for path in targets if path],
        "confidence": "high" if rules else "low",
    }


def _mkdir_targets(text: str) -> list[str]:
    targets: list[str] = []
    for tokens, shell_cwd in _shell_segments_with_cwd(text):
        if not tokens or Path(tokens[0]).name.lower() != "mkdir":
            continue
        for token in tokens[1:]:
            if token.startswith("-"):
                continue
            targets.append(_resolve_shell_target(token, shell_cwd))
    return targets[:_MAX_MKDIR_TARGETS]


def _install_directory_targets(text: str) -> list[str]:
    targets: list[str] = []
    for tokens, shell_cwd in _shell_segments_with_cwd(text):
        if not tokens or Path(tokens[0]).name.lower() != "install":
            continue
        directory_mode = False
        operands: list[str] = []
        index = 1
        while index < len(tokens):
            token = tokens[index]
            if token == "--":
                operands.extend(tokens[index + 1:])
                break
            if token in {"-d", "--directory"}:
                directory_mode = True
                index += 1
                continue
            if _copy_like_option_consumes_value(token) and index + 1 < len(tokens):
                index += 2
                continue
            if token.startswith("-"):
                index += 1
                continue
            operands.append(token)
            index += 1
        if directory_mode:
            targets.extend(_resolve_shell_target(operand, shell_cwd) for operand in operands)
    return targets[:_MAX_MKDIR_TARGETS]


def _directory_create_targets(text: str) -> list[str]:
    return _dedupe_strings([*_mkdir_targets(text), *_install_directory_targets(text)])[
        :_MAX_MKDIR_TARGETS
    ]


def _plain_archive_creation_targets(text: str) -> list[str]:
    targets: list[str] = []
    shell_cwd: str | None = None
    for tokens in _shell_segments(text):
        if not tokens:
            continue
        command = Path(tokens[0]).name.lower()
        if command == "cd":
            shell_cwd = _updated_shell_cwd(shell_cwd, tokens)
            continue
        if command == "zip":
            for token in tokens[1:]:
                if token.startswith("-"):
                    continue
                targets.append(_resolve_shell_target(token, shell_cwd))
                break
        elif command == "tar":
            for index, token in enumerate(tokens[:-1]):
                if token in {"-f", "--file"}:
                    targets.append(_resolve_shell_target(tokens[index + 1], shell_cwd))
                    break
                if token.startswith("--file="):
                    targets.append(_resolve_shell_target(token.split("=", 1)[1], shell_cwd))
                    break
    return [target for target in targets if target][:3]


def _updated_shell_cwd(current: str | None, tokens: list[str]) -> str | None:
    if len(tokens) < 2:
        return current
    target = str(tokens[1] or "").strip()
    if not target or target.startswith("-") or target == "~":
        return None
    if target.startswith("/"):
        return posixpath.normpath(target)
    if current:
        return posixpath.normpath(posixpath.join(current, target))
    return None


def _resolve_shell_target(target: str, shell_cwd: str | None) -> str:
    normalized = str(target or "").strip().strip("'\"")
    if not shell_cwd or not normalized or normalized.startswith(("/", "~")):
        return normalized
    if re.match(r"^[A-Za-z]:", normalized):
        return normalized
    return posixpath.normpath(posixpath.join(shell_cwd, normalized))


def _interpreter_script_target_role(path: str, written_script_paths: set[str]) -> str:
    if _normalize_shell_compare_path(path) in written_script_paths:
        return "future_execution.artifact"
    if _scope_task_output_target_for_path(path) is not None:
        return SCOPE_TASK_OUTPUT_PATH_ROLE
    return _path_role(path)


def _interpreter_script_targets(text: str) -> list[str]:
    targets: list[str] = []
    interpreters = {
        "python",
        "python3",
        "node",
        "nodejs",
        "bash",
        "sh",
        "dash",
        "zsh",
        "ksh",
        "perl",
        "ruby",
        "php",
        "pwsh",
        "powershell",
    }
    inline_flags = {"-c", "-e", "-m", "-"}
    for line in shell_command_surface(text).splitlines():
        for tokens, shell_cwd in _shell_segments_with_cwd(line):
            if not tokens:
                continue
            command_name = Path(tokens[0]).name.lower()
            if command_name not in interpreters:
                continue
            nested_shell = command_name in {"bash", "sh", "dash", "zsh", "ksh"}
            nested_payload = _shell_c_payload(tokens) if nested_shell else None
            if nested_payload:
                targets.extend(_interpreter_script_targets(nested_payload))
                continue
            for token in tokens[1:]:
                if token in {"<", ">", ">>", "<<", "|", ";", "&"}:
                    break
                if token in inline_flags:
                    break
                if token.startswith("-"):
                    continue
                targets.append(_resolve_shell_target(token, shell_cwd))
                break
    return targets[:3]


def _empty_shell_effects() -> dict[str, Any]:
    return {"effects": [], "targets": [], "rules": [], "confidence": "low"}


def _jar_list_archive_arg(args: list[str]) -> str | None:
    saw_list = False
    file_arg: str | None = None
    positional: list[str] = []
    index = 0
    while index < len(args):
        token = str(args[index] or "").strip()
        if not token:
            index += 1
            continue
        if token == "|":
            break
        if token in {";", "&&", "||"}:
            return None
        if token in {">", ">>", "2>", "2>>", "&>", "<"}:
            return None
        if token == "--":
            positional.extend(
                arg for arg in args[index + 1:] if not str(arg or "").startswith("-")
            )
            break
        if token.startswith("@") or _URL_RE.match(token):
            return None
        if token == "--list":
            saw_list = True
            index += 1
            continue
        if token.startswith("--list="):
            return None
        if token == "--file":
            if index + 1 >= len(args):
                return None
            file_arg = str(args[index + 1] or "").strip()
            index += 2
            continue
        if token.startswith("--file="):
            file_arg = token.split("=", 1)[1].strip()
            index += 1
            continue
        flags = _jar_list_short_flags(token, allow_plain=index == 0)
        if flags is not None:
            if any(flag not in {"t", "f", "v"} for flag in flags):
                return None
            if "t" not in flags:
                return None
            saw_list = True
            if "f" in flags:
                if index + 1 >= len(args):
                    return None
                file_arg = str(args[index + 1] or "").strip()
                index += 2
                continue
            index += 1
            continue
        if token.startswith("-"):
            return None
        positional.append(token)
        index += 1
    if not saw_list:
        return None
    if file_arg is None:
        if len(positional) != 1:
            return None
        file_arg = positional[0]
    elif positional:
        return None
    if not _jar_archive_path_is_supported(file_arg):
        return None
    return file_arg


def _jar_list_short_flags(token: str, *, allow_plain: bool) -> str | None:
    text = str(token or "").strip()
    if not text:
        return None
    if text.startswith("--"):
        return None
    if text.startswith("-"):
        flags = text[1:]
    elif allow_plain and re.fullmatch(r"[A-Za-z0-9]+", text):
        flags = text
    else:
        return None
    if not flags or any(char in flags for char in {"c", "u", "x", "i", "m", "e", "C", "J", "M", "0"}):
        return None
    if "t" not in flags:
        return None
    return flags


def _jar_archive_path_is_supported(path: str | None) -> bool:
    text = str(path or "").strip().strip("'\"")
    if not text or text == "-" or text.startswith("@") or _URL_RE.match(text):
        return False
    suffix = PurePosixPath(text.replace("\\", "/")).suffix.lower()
    return suffix in {".jar", ".war", ".ear", ".zip"}


def _jar_raw_tokens_have_disallowed_wrapper(raw_tokens: list[str]) -> bool:
    for token in raw_tokens:
        head = Path(str(token or "")).name.lower()
        if head in {"env", "command"}:
            return True
    return False


_JAVA_CLASSPATH_FLAGS = frozenset({"-cp", "-classpath", "--class-path"})
_JAVA_REJECTED_OPTIONS = frozenset({"-jar", "-m", "--module", "--module-path", "--upgrade-module-path"})
_JAVA_REJECTED_OPTION_PREFIXES = (
    "-javaagent",
    "-agentlib",
    "-agentpath",
    "-Xbootclasspath",
    "--module=",
    "--module-path=",
    "--upgrade-module-path=",
)
_JAVA_ALLOWED_NO_VALUE_OPTIONS = frozenset({
    "-ea",
    "-enableassertions",
    "-da",
    "-disableassertions",
    "-esa",
    "-dsa",
    "--enable-preview",
})
_JAVA_OUTPUT_FLAG_NAMES = frozenset({
    "-o",
    "--out",
    "--output",
    "--output-file",
    "--output_path",
    "--output-path",
    "--dest",
    "--destination",
    "--result",
    "--result-file",
})


def _maven_exec_java_invocation(tokens: list[str]) -> tuple[str, list[str]] | None:
    if not tokens or Path(tokens[0]).name.lower() not in _MAVEN_LOCAL_BUILD_COMMANDS:
        return None
    args = [str(token or "").strip() for token in tokens[1:]]
    if not args:
        return None
    if any(_maven_exec_java_token_is_dynamic_or_shell_control(token) for token in args):
        return None
    if _local_build_has_option(args, set(_MAVEN_EXEC_JAVA_FORBIDDEN_OPTIONS)):
        return None
    goals = _local_build_non_option_tokens(args)
    if len(goals) != 1 or not _maven_exec_java_goal_is_supported(goals[0]):
        return None

    properties = _maven_exec_java_d_property_items(args)
    property_map: dict[str, str] = {}
    for key, value in properties:
        normalized_key = _maven_exec_java_property_key(key)
        if not normalized_key:
            return None
        if normalized_key.startswith("exec.") and normalized_key not in _MAVEN_EXEC_JAVA_ALLOWED_EXEC_PROPERTIES:
            return None
        if normalized_key in _MAVEN_EXEC_JAVA_DANGEROUS_PROPERTY_KEYS:
            return None
        if value is None:
            if normalized_key.startswith("exec."):
                return None
            continue
        if (
            normalized_key not in _MAVEN_EXEC_JAVA_ALLOWED_EXEC_PROPERTIES
            and _maven_exec_java_property_value_is_dangerous(value)
        ):
            return None
        property_map[normalized_key] = value

    main_class = property_map.get("exec.mainclass")
    exec_args = property_map.get("exec.args")
    if not main_class or not exec_args:
        return None
    if not _java_main_class_name_is_supported(main_class):
        return None
    program_args = _maven_exec_java_program_args(exec_args)
    if program_args is None:
        return None
    return main_class, program_args


def _maven_exec_java_goal_is_supported(goal: str) -> bool:
    normalized = str(goal or "").strip().lower()
    if normalized == "exec:java":
        return True
    parts = normalized.split(":")
    if len(parts) == 3:
        group_id, artifact_id, goal_name = parts
        version = ""
    elif len(parts) == 4:
        group_id, artifact_id, version, goal_name = parts
    else:
        return False
    if group_id != "org.codehaus.mojo" or artifact_id != "exec-maven-plugin":
        return False
    if goal_name != "java":
        return False
    if version and re.fullmatch(r"[A-Za-z0-9_.-]+", version) is None:
        return False
    return True


def _maven_exec_java_d_property_items(args: list[str]) -> list[tuple[str, str | None]]:
    items: list[tuple[str, str | None]] = []
    skip_next = False
    for index, raw in enumerate(args):
        token = str(raw or "").strip()
        if not token:
            continue
        if skip_next:
            skip_next = False
            continue
        if token == "-D":
            if index + 1 >= len(args):
                return [("", None)]
            next_token = str(args[index + 1] or "").strip()
            if "=" in next_token:
                key, value = next_token.split("=", 1)
                items.append((key, value))
            else:
                items.append((next_token, None))
            skip_next = True
            continue
        if token.startswith("-D"):
            body = token[2:]
            if "=" in body:
                key, value = body.split("=", 1)
                items.append((key, value))
            else:
                items.append((body, None))
    return items


def _maven_exec_java_property_key(key: str) -> str:
    return str(key or "").strip().lower().replace("-", ".")


def _maven_exec_java_property_value_is_dangerous(value: str) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    if "$" in text or "`" in text or _URL_RE.match(text):
        return True
    lowered = text.lower()
    if any(marker in lowered for marker in ("javaagent", "agentlib", "agentpath")):
        return True
    if _local_build_value_looks_like_path(text):
        return True
    return False


def _maven_exec_java_program_args(value: str) -> list[str] | None:
    text = str(value or "").strip()
    if not text:
        return None
    if any(marker in text for marker in ("\n", "\r", "`", "$(", ";", "&&", "||", "|", "<", ">")):
        return None
    try:
        args = shlex.split(text)
    except ValueError:
        return None
    if not args:
        return None
    for arg in args:
        if _maven_exec_java_token_is_dynamic_or_shell_control(arg):
            return None
        if any(marker in arg for marker in (";", "|", "<", ">")):
            return None
    return args


def _maven_exec_java_token_is_dynamic_or_shell_control(token: str) -> bool:
    text = str(token or "").strip()
    if not text:
        return True
    return (
        "$" in text
        or "`" in text
        or text in {";", "&&", "||", "|"}
        or _shell_token_starts_redirect(text)
        or _URL_RE.match(text) is not None
    )


def _java_local_main_invocation(tokens: list[str]) -> tuple[list[str], str, list[str]] | None:
    if not tokens or Path(tokens[0]).name.lower() != "java":
        return None
    classpath: str | None = None
    index = 1
    while index < len(tokens):
        token = str(tokens[index] or "").strip()
        if not token:
            return None
        if _java_token_is_dynamic_or_remote(token):
            return None
        if token.startswith("@"):
            return None
        if token in {";", "&&", "||", "|"} or _shell_token_starts_redirect(token):
            return None
        if token in _JAVA_REJECTED_OPTIONS or any(
            token.startswith(prefix) for prefix in _JAVA_REJECTED_OPTION_PREFIXES
        ):
            return None
        if token in _JAVA_CLASSPATH_FLAGS:
            if index + 1 >= len(tokens):
                return None
            classpath = str(tokens[index + 1] or "").strip()
            if _java_token_is_dynamic_or_remote(classpath):
                return None
            index += 2
            continue
        if token.startswith("--class-path="):
            classpath = token.split("=", 1)[1].strip()
            if _java_token_is_dynamic_or_remote(classpath):
                return None
            index += 1
            continue
        if token in _JAVA_ALLOWED_NO_VALUE_OPTIONS:
            index += 1
            continue
        if token.startswith("-D") and _java_system_property_is_static(token):
            index += 1
            continue
        if token.startswith("-Xmx") or token.startswith("-Xms") or token.startswith("-Xss"):
            index += 1
            continue
        if token.startswith("-"):
            return None
        main_class = token
        if not _java_main_class_name_is_supported(main_class):
            return None
        if classpath is None:
            return None
        entries = _java_classpath_entries(classpath)
        if not entries:
            return None
        return (entries, main_class, tokens[index + 1:])
    return None


def _java_local_jar_invocation(tokens: list[str]) -> tuple[str, list[str]] | None:
    if not tokens or Path(tokens[0]).name.lower() != "java":
        return None
    index = 1
    while index < len(tokens):
        token = str(tokens[index] or "").strip()
        if not token:
            return None
        if _java_token_is_dynamic_or_remote(token) or token.startswith("@"):
            return None
        if token in {";", "&&", "||", "|"} or _shell_token_starts_redirect(token):
            return None
        if token in _JAVA_CLASSPATH_FLAGS or token.startswith("--class-path="):
            return None
        if token in {"-m", "--module", "--module-path", "--upgrade-module-path"}:
            return None
        if any(token.startswith(prefix) for prefix in _JAVA_REJECTED_OPTION_PREFIXES):
            return None
        if token == "-jar":
            if index + 1 >= len(tokens):
                return None
            jar_path = str(tokens[index + 1] or "").strip()
            if (
                not _java_fat_jar_path_is_supported(jar_path)
                or _java_token_is_dynamic_or_remote(jar_path)
                or jar_path.startswith("@")
            ):
                return None
            program_args = tokens[index + 2:]
            if any(_java_jar_program_arg_is_rejected(arg) for arg in program_args):
                return None
            return jar_path, program_args
        if token in _JAVA_ALLOWED_NO_VALUE_OPTIONS:
            index += 1
            continue
        if token.startswith("-D") and _java_system_property_is_static(token):
            index += 1
            continue
        if token.startswith("-Xmx") or token.startswith("-Xms") or token.startswith("-Xss"):
            index += 1
            continue
        if token.startswith("-"):
            return None
        return None
    return None


def _java_fat_jar_path_is_supported(path: str | None) -> bool:
    text = str(path or "").strip().strip("'\"")
    if not text or text == "-" or text.startswith("@") or _URL_RE.match(text):
        return False
    if any(marker in text for marker in {"*", "$", "`"}):
        return False
    return PurePosixPath(text.replace("\\", "/")).suffix.lower() == ".jar"


def _java_fat_jar_execution_target(
    path: str,
    *,
    cwd: str | None,
) -> ActionEffectTarget | None:
    if not _java_fat_jar_path_is_supported(path):
        return None
    target = _scope_task_output_build_child_target_for_path(
        path,
        cwd=cwd,
        allow_exact_direct=False,
    )
    if target is None:
        return None
    return target.model_copy(update={"io_direction": "source"})


def _java_jar_program_arg_is_rejected(arg: str) -> bool:
    token = str(arg or "").strip()
    if not token:
        return False
    if token in _JAVA_CLASSPATH_FLAGS or token.startswith("--class-path="):
        return True
    if token in _JAVA_REJECTED_OPTIONS:
        return True
    return any(token.startswith(prefix) for prefix in _JAVA_REJECTED_OPTION_PREFIXES)


def _java_classpath_entries(classpath: str) -> list[str]:
    text = str(classpath or "").strip().strip("'\"")
    if not text or any(marker in text for marker in {"*", "$", "`"}):
        return []
    entries = [entry.strip() for entry in text.split(":") if entry.strip()]
    if not entries or any(entry in {".", "-"} for entry in entries):
        return []
    return entries


def _java_classpath_entry_target(
    entry: str,
    *,
    cwd: str | None,
) -> ActionEffectTarget | None:
    if _java_token_is_dynamic_or_remote(entry) or entry.startswith("@"):
        return None
    output_target = _scope_task_output_build_child_target_for_path(entry, cwd=cwd)
    if output_target is not None:
        return output_target.model_copy(update={"io_direction": "source"})
    return _java_local_dependency_cache_target(entry, cwd=cwd)


def _java_local_dependency_cache_target(
    entry: str,
    *,
    cwd: str | None,
) -> ActionEffectTarget | None:
    if not _jar_archive_path_is_supported(entry):
        return None
    normalized = normalize_task_artifact_path(entry, cwd=cwd)
    if not normalized or any(part == ".." for part in normalized.replace("\\", "/").split("/")):
        return None
    normalized_slash = normalized.replace("\\", "/")
    if not _java_path_is_canonical_dependency_cache_entry(normalized_slash):
        return None
    return ActionEffectTarget(
        kind="path",
        path_hash=_hash(normalized_slash),
        path_role="local_dependency_cache",
        io_direction="source",
        workspace_relation="local_dependency_cache",
    )


def _java_path_is_canonical_dependency_cache_entry(path: str) -> bool:
    normalized = str(path or "").replace("\\", "/")
    return bool(
        normalized.startswith("/root/.m2/repository/")
        or normalized.startswith("/root/.gradle/caches/")
        or re.match(r"^/home/[^/]+/\.m2/repository/", normalized)
        or re.match(r"^/home/[^/]+/\.gradle/caches/", normalized)
    )


def _java_program_arg_targets(
    args: list[str],
    *,
    cwd: str | None,
) -> list[ActionEffectTarget] | None:
    targets: list[ActionEffectTarget] = []
    index = 0
    while index < len(args):
        token = str(args[index] or "").strip()
        if not token:
            index += 1
            continue
        if _java_token_is_dynamic_or_remote(token) or token.startswith("@"):
            return None
        if token in {";", "&&", "||", "|"} or _shell_token_starts_redirect(token):
            return None
        option, inline_value = _java_option_and_inline_value(token)
        if option and _java_option_name_is_output_flag(option):
            value: str | None = inline_value
            if value is None:
                if index + 1 >= len(args):
                    return None
                value = str(args[index + 1] or "").strip()
                index += 2
            else:
                index += 1
            target = _scope_task_output_explicit_output_target_for_path(value, cwd=cwd)
            if target is None:
                return None
            targets.append(target.model_copy(update={"io_direction": "target"}))
            continue
        if option:
            if inline_value is not None and _looks_like_path_arg(inline_value):
                target = _java_task_data_input_target(inline_value, cwd=cwd)
                if target is None:
                    return None
                targets.append(target)
            index += 1
            continue
        if _looks_like_path_arg(token):
            target = _java_task_data_input_target(token, cwd=cwd)
            if target is None:
                return None
            targets.append(target)
        index += 1
    return _dedupe_targets(targets)


def _java_option_and_inline_value(token: str) -> tuple[str | None, str | None]:
    text = str(token or "").strip()
    if not text.startswith("-") or text == "-":
        return (None, None)
    if "=" in text:
        option, value = text.split("=", 1)
        return (option, value)
    return (text, None)


def _java_option_name_is_output_flag(option: str) -> bool:
    normalized = str(option or "").strip().lower().replace("_", "-")
    return normalized in _JAVA_OUTPUT_FLAG_NAMES


def _java_token_is_dynamic_or_remote(token: str) -> bool:
    text = str(token or "").strip()
    return (
        not text
        or "$" in text
        or "`" in text
        or _URL_RE.match(text) is not None
    )


def _java_system_property_is_static(token: str) -> bool:
    text = str(token or "")
    if not text.startswith("-D") or "=" not in text:
        return False
    key, value = text[2:].split("=", 1)
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", key or ""):
        return False
    if _looks_like_path_arg(value) or _java_token_is_dynamic_or_remote(value):
        return False
    return True


def _java_main_class_name_is_supported(value: str) -> bool:
    return re.fullmatch(
        r"[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*",
        str(value or ""),
    ) is not None


def _is_python_interpreter_name(command: str) -> bool:
    return re.fullmatch(r"python(?:\d+(?:\.\d+)?)?", str(command or "")) is not None


def _local_build_command_shape_is_supported(command: str, args: list[str]) -> bool:
    if command in _MAVEN_LOCAL_BUILD_COMMANDS:
        if _local_build_has_dangerous_properties(args, _MAVEN_DANGEROUS_PROPERTY_KEYS):
            return False
        goals = _local_build_non_option_tokens(args)
        return all(_maven_local_build_goal_is_supported(goal) for goal in goals)
    if command in _GRADLE_LOCAL_BUILD_COMMANDS:
        if _local_build_has_option(args, {"-I", "--init-script"}):
            return False
        if _local_build_has_dangerous_properties(args, _GRADLE_DANGEROUS_PROPERTY_KEYS):
            return False
        if _gradle_has_unsafe_project_property(args):
            return False
        tasks = _local_build_non_option_tokens(args)
        return all(_gradle_local_build_task_is_supported(task) for task in tasks)
    if command == "sbt":
        if _local_build_has_dangerous_properties(args, _SBT_DANGEROUS_PROPERTY_KEYS):
            return False
        tasks = _local_build_non_option_tokens(args)
        return all(_sbt_local_build_task_is_supported(task) for task in tasks)
    if command in {"make", "gmake"} and _make_has_dangerous_assignment(args):
        return False
    if command == "cmake" and _local_build_has_option(args, {"-P"}):
        return False
    if command == "cmake" and any(str(arg or "").startswith("--install") for arg in args):
        return False
    return True


def _maven_local_build_goal_is_supported(goal: str) -> bool:
    normalized = str(goal or "").strip().lower()
    if not normalized:
        return True
    if ":" in normalized:
        return False
    return normalized in _MAVEN_ALLOWED_LOCAL_BUILD_GOALS


def _gradle_local_build_task_is_supported(task: str) -> bool:
    normalized = str(task or "").strip().lower()
    if not normalized:
        return True
    if normalized.startswith(":"):
        normalized = normalized.rsplit(":", 1)[-1]
    return normalized in _GRADLE_ALLOWED_LOCAL_BUILD_TASKS


def _sbt_local_build_task_is_supported(task: str) -> bool:
    normalized = str(task or "").strip().lower()
    if not normalized:
        return True
    return normalized in _SBT_ALLOWED_LOCAL_BUILD_TASKS


def _local_build_has_option(args: list[str], options: set[str]) -> bool:
    for raw in args:
        token = str(raw or "").strip()
        if not token:
            continue
        option, separator, _value = token.partition("=")
        if token in options or (separator and option in options):
            return True
        if any(
            option.startswith("-")
            and not option.startswith("--")
            and token.startswith(option)
            and token != option
            for option in options
        ):
            return True
    return False


def _local_build_has_dangerous_properties(
    args: list[str],
    dangerous_keys: frozenset[str],
) -> bool:
    for key, value in _local_build_d_property_items(args):
        normalized_key = key.strip().lower().replace("-", ".")
        if normalized_key in dangerous_keys:
            return True
        if normalized_key.startswith("exec."):
            return True
        if "javaagent" in value.lower():
            return True
    return False


def _local_build_d_property_items(args: list[str]) -> list[tuple[str, str]]:
    items: list[tuple[str, str]] = []
    skip_next = False
    for index, raw in enumerate(args):
        token = str(raw or "").strip()
        if not token:
            continue
        if skip_next:
            skip_next = False
            continue
        if token == "-D":
            if index + 1 < len(args):
                next_token = str(args[index + 1] or "").strip()
                if "=" in next_token:
                    key, value = next_token.split("=", 1)
                    items.append((key, value))
                skip_next = True
            continue
        if token.startswith("-D") and "=" in token:
            key, value = token[2:].split("=", 1)
            items.append((key, value))
    return items


def _gradle_has_unsafe_project_property(args: list[str]) -> bool:
    for _key, value in _gradle_project_property_items(args):
        if _URL_RE.match(value):
            return True
        if _local_build_value_looks_like_path(value):
            return True
    return False


def _gradle_project_property_items(args: list[str]) -> list[tuple[str, str]]:
    items: list[tuple[str, str]] = []
    skip_next = False
    for index, raw in enumerate(args):
        token = str(raw or "").strip()
        if not token:
            continue
        if skip_next:
            skip_next = False
            continue
        if token == "-P":
            if index + 1 < len(args):
                next_token = str(args[index + 1] or "").strip()
                if "=" in next_token:
                    key, value = next_token.split("=", 1)
                    items.append((key, value))
                skip_next = True
            continue
        if token.startswith("-P") and "=" in token:
            key, value = token[2:].split("=", 1)
            items.append((key, value))
    return items


def _make_has_dangerous_assignment(args: list[str]) -> bool:
    for raw in args:
        token = str(raw or "").strip()
        if not _shell_env_assignment(token):
            continue
        name, value = token.split("=", 1)
        if name.upper() not in _MAKE_EXECUTION_ASSIGNMENT_NAMES:
            continue
        if _local_build_value_looks_like_path(value):
            return True
        if any(marker in value for marker in (";", "&&", "|", "`", "$(")):
            return True
    return False


def _local_build_non_option_tokens(args: list[str]) -> list[str]:
    tokens: list[str] = []
    skip_next = False
    for index, raw in enumerate(args):
        token = str(raw or "").strip()
        if not token:
            continue
        if skip_next:
            skip_next = False
            continue
        if token == "--":
            tokens.extend(
                str(arg or "").strip()
                for arg in args[index + 1:]
                if str(arg or "").strip()
            )
            break
        option, separator, _value = token.partition("=")
        if separator:
            if option in _TASK_OUTPUT_LOCAL_BUILD_OPAQUE_VALUE_OPTIONS:
                continue
            if option in _TASK_OUTPUT_LOCAL_BUILD_PATH_VALUE_OPTIONS:
                continue
        joined = _local_build_joined_path_option_value(token)
        if joined is not None:
            continue
        if token in _TASK_OUTPUT_LOCAL_BUILD_PATH_VALUE_OPTIONS:
            skip_next = True
            continue
        if token in _TASK_OUTPUT_LOCAL_BUILD_OPAQUE_VALUE_OPTIONS:
            skip_next = True
            continue
        if token.startswith("-"):
            continue
        tokens.append(token)
    return tokens


def _local_build_path_args(args: list[str]) -> list[str]:
    paths: list[str] = []
    skip_next = False
    for index, raw in enumerate(args):
        token = str(raw or "").strip()
        if not token:
            continue
        if skip_next:
            skip_next = False
            continue
        if token == "--":
            paths.extend(
                arg
                for arg in args[index + 1:]
                if _local_build_value_looks_like_path(str(arg or ""))
            )
            break
        assignment_paths = _local_build_assignment_path_values(token)
        if assignment_paths:
            paths.extend(assignment_paths)
            continue
        if token in _TASK_OUTPUT_LOCAL_BUILD_OPAQUE_VALUE_OPTIONS:
            skip_next = True
            continue
        option, separator, value = token.partition("=")
        if separator:
            if option in _TASK_OUTPUT_LOCAL_BUILD_PATH_VALUE_OPTIONS:
                paths.append(value)
                continue
            if option in _TASK_OUTPUT_LOCAL_BUILD_OPAQUE_VALUE_OPTIONS:
                paths.extend(_local_build_path_values_from_assignment_value(value))
                continue
            if option.startswith("-D") and _local_build_value_looks_like_path(value):
                paths.extend(_local_build_path_values_from_assignment_value(value))
                continue
        joined = _local_build_joined_path_option_value(token)
        if joined is not None:
            paths.append(joined)
            continue
        if token in _TASK_OUTPUT_LOCAL_BUILD_PATH_VALUE_OPTIONS:
            if index + 1 < len(args):
                paths.append(str(args[index + 1] or ""))
                skip_next = True
            continue
        if token.startswith("-"):
            continue
        if _local_build_value_looks_like_path(token):
            paths.append(token)
    return paths


def _local_build_assignment_path_values(token: str) -> list[str]:
    if not _shell_env_assignment(token):
        return []
    _name, value = token.split("=", 1)
    return _local_build_path_values_from_assignment_value(value)


def _local_build_path_values_from_assignment_value(value: str) -> list[str]:
    text = str(value or "").strip()
    if not text:
        return []
    paths: list[str] = []
    javaagent_match = re.search(r"(?:^|\s)-javaagent:([^\s:]+(?::[^\s]+)?)", text)
    if javaagent_match is not None:
        paths.append(javaagent_match.group(1))
    if _local_build_value_looks_like_path(text):
        paths.append(text)
    return _dedupe_strings(paths)


def _local_build_joined_path_option_value(token: str) -> str | None:
    if not token or token.startswith("--"):
        return None
    for option in sorted(_TASK_OUTPUT_LOCAL_BUILD_JOINED_PATH_OPTIONS, key=len, reverse=True):
        if token == option:
            return None
        if token.startswith(option):
            return token[len(option):]
    return None


def _local_build_value_looks_like_path(value: str) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    if _URL_RE.match(text):
        return True
    return text.startswith(("/", "./", "../")) or "/" in text or "\\" in text


def _pytest_path_args(args: list[str]) -> list[str]:
    paths: list[str] = []
    skip_next_value = False
    skip_next_path_option: str | None = None
    opaque_value_options = {
        "-k",
        "-m",
    }
    path_value_options = {
        "--ignore",
        "--ignore-glob",
        "--rootdir",
        "--confcutdir",
        "--basetemp",
        "--junitxml",
        "--cov",
        "--cov-report",
    }
    for raw in args:
        token = str(raw or "")
        if not token:
            continue
        if skip_next_value:
            skip_next_value = False
            continue
        if skip_next_path_option is not None:
            paths.extend(_pytest_option_path_values(skip_next_path_option, token))
            skip_next_path_option = None
            continue
        if token in opaque_value_options:
            skip_next_value = True
            continue
        if token in path_value_options:
            skip_next_path_option = token
            continue
        if token.startswith("--") and "=" in token:
            option, value = token.split("=", 1)
            if option in opaque_value_options:
                continue
            if option in path_value_options:
                paths.extend(_pytest_option_path_values(option, value))
                continue
            if _pytest_value_looks_like_path(value):
                paths.append(value.split("::", 1)[0])
            continue
        if token.startswith("-"):
            continue
        path = token.split("::", 1)[0]
        if path:
            paths.append(path)
    return paths


def _pytest_option_path_values(option: str, value: str) -> list[str]:
    text = str(value or "").strip()
    if not text:
        return []
    if option == "--cov-report":
        if ":" not in text:
            return []
        text = text.split(":", 1)[1].strip()
        if not text or text in {"-", "term", "term-missing"}:
            return []
    if option == "--cov" and not _pytest_value_looks_like_path(text):
        return []
    return [text.split("::", 1)[0]]


def _pytest_value_looks_like_path(value: str) -> bool:
    text = str(value or "").strip()
    return text.startswith(("/", "./", "../")) or "/" in text


def _git_effective_worktree_cwd(args: list[str], shell_cwd: str | None) -> str | None:
    cwd = shell_cwd
    index = 0
    while index < len(args):
        token = str(args[index] or "")
        if token == "-C":
            if index + 1 >= len(args):
                return None
            cwd = _resolve_shell_target(str(args[index + 1] or ""), cwd)
            index += 2
            continue
        option, separator, value = token.partition("=")
        if separator and option == "-C":
            cwd = _resolve_shell_target(value, cwd)
            index += 1
            continue
        if token.startswith("-"):
            if token in {"--git-dir", "--work-tree"}:
                index += 2
                continue
            option, separator, _value = token.partition("=")
            if separator and option in {"--git-dir", "--work-tree"}:
                index += 1
                continue
            index += 1
            continue
        break
    return cwd


def _git_apply_has_disallowed_global_option(args: list[str]) -> bool:
    index = 0
    while index < len(args):
        token = str(args[index] or "")
        if not token:
            index += 1
            continue
        if token == "-C":
            if index + 1 >= len(args):
                return True
            index += 2
            continue
        option, separator, _value = token.partition("=")
        if separator and option == "-C":
            index += 1
            continue
        if token.startswith("-"):
            return True
        return False
    return True


def _git_readonly_has_disallowed_option(args: list[str]) -> bool:
    disallowed_exact = {
        "-c",
        "--config-env",
        "--ext-diff",
        "--exec-path",
        "--output",
        "--paginate",
        "--textconv",
    }
    disallowed_prefixes = (
        "-c=",
        "--config-env=",
        "--exec-path=",
        "--output=",
    )
    path_options = {"-C", "--git-dir", "--work-tree"}
    seen_subcommand = False
    index = 0
    while index < len(args):
        token = str(args[index] or "")
        if token == "--":
            return False
        if not seen_subcommand:
            if token in path_options:
                index += 2
                continue
            option, separator, _value = token.partition("=")
            if separator and option in path_options:
                index += 1
                continue
            if token == "-p":
                return True
            if token and not token.startswith("-"):
                seen_subcommand = True
                index += 1
                continue
        if token in disallowed_exact:
            return True
        if any(token.startswith(prefix) for prefix in disallowed_prefixes):
            return True
        index += 1
    return False


def _git_parse_global_options_and_subcommand(args: list[str]) -> tuple[str, list[str]] | None:
    index = 0
    path_options = {"-C", "--git-dir", "--work-tree"}
    opaque_value_options = {"--namespace"}
    while index < len(args):
        token = str(args[index] or "")
        if not token:
            index += 1
            continue
        if token in path_options or token in opaque_value_options:
            index += 2
            continue
        option, separator, _value = token.partition("=")
        if separator and (option in path_options or option in opaque_value_options):
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        return token, args[index + 1:]
    return None


def _git_apply_has_disallowed_option(args: list[str]) -> bool:
    disallowed_exact = {
        "-R",
        "--cached",
        "--index",
        "--unsafe-paths",
        "--directory",
        "--include",
        "--exclude",
        "--build-fake-ancestor",
        "--index-output",
        "--reject",
    }
    disallowed_prefixes = (
        "-R",
        "--directory=",
        "--include=",
        "--exclude=",
        "--build-fake-ancestor=",
        "--index-output=",
    )
    for token in (str(arg or "") for arg in args):
        if token in disallowed_exact:
            return True
        if any(token.startswith(prefix) for prefix in disallowed_prefixes):
            return True
    return False


def _git_apply_patch_path_args(args: list[str]) -> list[str]:
    paths: list[str] = []
    skip_next = False
    options_with_value = {
        "-p",
        "-C",
        "--whitespace",
    }
    for raw in args:
        token = str(raw or "")
        if not token:
            continue
        if skip_next:
            skip_next = False
            continue
        if token == "--":
            continue
        if token in options_with_value:
            skip_next = True
            continue
        if token.startswith("-p") and len(token) > 2 and token[2:].isdigit():
            continue
        if token.startswith("--"):
            continue
        if token.startswith("-"):
            continue
        paths.append(token)
    return paths


def _git_raw_tokens_have_execution_env(raw_tokens: list[str]) -> bool:
    for token in _git_leading_env_assignment_tokens(raw_tokens):
        name = token.split("=", 1)[0].upper()
        if name in {
            "PAGER",
            "GIT_PAGER",
            "GIT_EXTERNAL_DIFF",
            "GIT_DIFF_OPTS",
            "GIT_EXEC_PATH",
            "GIT_SSH",
            "GIT_SSH_COMMAND",
            "GIT_PROXY_COMMAND",
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        }:
            return True
        if name.startswith("GIT_CONFIG"):
            return True
    return False


def _build_raw_tokens_have_execution_env(raw_tokens: list[str]) -> bool:
    for token in _build_leading_env_assignment_tokens(raw_tokens):
        name, value = token.split("=", 1)
        normalized_name = name.upper()
        if normalized_name in _BUILD_DANGEROUS_ENV_NAMES:
            return True
        if _local_build_value_looks_like_path(value) and any(
            fragment in normalized_name
            for fragment in ("CONFIG", "HOME", "OPTS", "PATH", "TOOL", "TOOLCHAIN")
        ):
            return True
        if "javaagent" in value.lower():
            return True
    return False


def _build_raw_tokens_have_privileged_wrapper(raw_tokens: list[str]) -> bool:
    for token in [str(token or "") for token in raw_tokens]:
        head = Path(token).name.lower()
        if head in _TASK_OUTPUT_LOCAL_BUILD_COMMANDS:
            return False
        if head in _TASK_OUTPUT_LOCAL_BUILD_PRIVILEGED_WRAPPERS:
            return True
    return False


def _build_leading_env_assignment_tokens(raw_tokens: list[str]) -> list[str]:
    assignments: list[str] = []
    tokens = [str(token or "") for token in raw_tokens]
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if not token:
            index += 1
            continue
        if Path(token).name.lower() in _TASK_OUTPUT_LOCAL_BUILD_COMMANDS:
            break
        if _shell_env_assignment(token):
            assignments.append(token)
            index += 1
            continue
        if Path(token).name.lower() == "env":
            index += 1
            while index < len(tokens):
                env_token = tokens[index]
                if env_token in {"-i", "-0"}:
                    index += 1
                    continue
                if env_token == "-u":
                    index += 2
                    continue
                if env_token.startswith("-"):
                    index += 1
                    continue
                if _shell_env_assignment(env_token):
                    assignments.append(env_token)
                    index += 1
                    continue
                break
            continue
        index += 1
    return assignments


def _git_leading_env_assignment_tokens(raw_tokens: list[str]) -> list[str]:
    assignments: list[str] = []
    tokens = [str(token or "") for token in raw_tokens]
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if not token:
            index += 1
            continue
        if Path(token).name.lower() == "git":
            break
        if _shell_env_assignment(token):
            assignments.append(token)
            index += 1
            continue
        if Path(token).name.lower() == "env":
            index += 1
            while index < len(tokens):
                env_token = tokens[index]
                if env_token in {"-i", "-0"}:
                    index += 1
                    continue
                if env_token == "-u":
                    index += 2
                    continue
                if env_token.startswith("-"):
                    index += 1
                    continue
                if _shell_env_assignment(env_token):
                    assignments.append(env_token)
                    index += 1
                    continue
                break
            continue
        index += 1
    return assignments


def _git_readonly_parse_args(args: list[str]) -> tuple[str, list[str]] | None:
    scoped_paths: list[str] = []
    index = 0
    path_options = {"-C", "--git-dir", "--work-tree"}
    while index < len(args):
        token = str(args[index] or "")
        if not token:
            index += 1
            continue
        if token in path_options:
            if index + 1 >= len(args):
                return None
            scoped_paths.append(str(args[index + 1] or ""))
            index += 2
            continue
        option, separator, value = token.partition("=")
        if separator and option in path_options:
            scoped_paths.append(value)
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        return token, scoped_paths + _git_readonly_path_args(args[index:], token)
    return None


def _git_readonly_path_args(args: list[str], subcommand: str) -> list[str]:
    paths: list[str] = []
    seen_subcommand = False
    path_mode = False
    for raw in args:
        token = str(raw or "")
        if not token:
            continue
        if not seen_subcommand:
            if token == subcommand:
                seen_subcommand = True
            continue
        if token == "--":
            path_mode = True
            continue
        if token.startswith("-") and not path_mode:
            continue
        if re.fullmatch(r"[A-Fa-f0-9]{7,40}", token) and not path_mode:
            continue
        if ".." in token and not token.startswith((".", "/")):
            continue
        if re.fullmatch(r"(?:HEAD|FETCH_HEAD|ORIG_HEAD|MERGE_HEAD)(?:[~^]\d*)?", token):
            continue
        paths.append(token)
    return paths


def _pip_install_subcommand(args: list[str]) -> tuple[str | None, int]:
    index = 0
    value_flags = {
        "--cache-dir",
        "--cert",
        "--client-cert",
        "--exists-action",
        "--log",
        "--proxy",
        "--python",
        "--retries",
        "--timeout",
        "--trusted-host",
    }
    bool_flags = {
        "--disable-pip-version-check",
        "--help",
        "--isolated",
        "--no-cache-dir",
        "--no-color",
        "--no-input",
        "--require-virtualenv",
        "--verbose",
        "-q",
        "-qq",
        "-qqq",
        "-v",
        "-vv",
        "-vvv",
    }
    while index < len(args):
        token = args[index]
        if token == "--":
            index += 1
            break
        if token in value_flags and index + 1 < len(args):
            index += 2
            continue
        if token.startswith(tuple(f"{flag}=" for flag in value_flags if flag.startswith("--"))):
            index += 1
            continue
        if token in bool_flags:
            index += 1
            continue
        if token.startswith("-"):
            return None, -1
        return token.lower(), index
    if index < len(args):
        return args[index].lower(), index
    return None, -1


def _pip_output_paths(args: list[str]) -> list[str]:
    paths: list[str] = []
    path_flags = {"--prefix", "--root", "--src", "--target", "-t"}
    for index, token in enumerate(args):
        if token in path_flags and index + 1 < len(args):
            paths.append(args[index + 1])
        elif token.startswith(tuple(f"{flag}=" for flag in path_flags if flag.startswith("--"))):
            paths.append(token.split("=", 1)[1])
        elif token.startswith("-t") and len(token) > 2:
            paths.append(token[2:])
    return paths


def _pip_path_reference_targets(args: list[str], shell_cwd: str | None) -> list[ActionEffectTarget]:
    targets: list[ActionEffectTarget] = []
    read_flags = {
        "--constraint",
        "--editable",
        "--find-links",
        "--requirement",
        "-c",
        "-e",
        "-f",
        "-r",
    }
    write_flags = {"--prefix", "--root", "--src", "--target", "-t"}
    path_flags = read_flags | write_flags
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            for arg in args[index + 1:]:
                if _shell_tokens_have_remote_package_reference([arg]):
                    continue
                if _uv_option_value_looks_like_path_or_sensitive(arg):
                    targets.append(_target_for_path(arg, cwd=shell_cwd, io_direction="source"))
            break
        if token in path_flags and index + 1 < len(args):
            direction = "target" if token in write_flags else "source"
            value = args[index + 1]
            if not _shell_tokens_have_remote_package_reference([value]):
                targets.append(_target_for_path(value, cwd=shell_cwd, io_direction=direction))
            index += 2
            continue
        matched_long_flag = next(
            (
                flag
                for flag in path_flags
                if flag.startswith("--") and token.startswith(flag + "=")
            ),
            None,
        )
        if matched_long_flag is not None:
            direction = "target" if matched_long_flag in write_flags else "source"
            value = token.split("=", 1)[1]
            if not _shell_tokens_have_remote_package_reference([value]):
                targets.append(_target_for_path(value, cwd=shell_cwd, io_direction=direction))
            index += 1
            continue
        matched_short_flag = next(
            (
                flag
                for flag in path_flags
                if flag.startswith("-") and not flag.startswith("--") and token.startswith(flag) and len(token) > len(flag)
            ),
            None,
        )
        if matched_short_flag is not None:
            direction = "target" if matched_short_flag in write_flags else "source"
            value = token[len(matched_short_flag):]
            if not _shell_tokens_have_remote_package_reference([value]):
                targets.append(_target_for_path(value, cwd=shell_cwd, io_direction=direction))
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        if _shell_tokens_have_remote_package_reference([token]):
            index += 1
            continue
        if _uv_option_value_looks_like_path_or_sensitive(token):
            targets.append(_target_for_path(token, cwd=shell_cwd, io_direction="source"))
        index += 1
    return _dedupe_targets(targets)


def _uv_subcommand(tokens: list[str]) -> tuple[str | None, int]:
    index = 1
    value_flags = {
        "--cache-dir",
        "--config-file",
        "--directory",
        "--index-url",
        "--keyring-provider",
        "--link-mode",
        "--managed-python",
        "--project",
        "--python",
        "--refresh-package",
        "--resolution",
    }
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            index += 1
            break
        if token in value_flags and index + 1 < len(tokens):
            index += 2
            continue
        if token.startswith(tuple(f"{flag}=" for flag in value_flags)):
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        return token.lower(), index
    if index < len(tokens):
        return tokens[index].lower(), index
    return None, -1


def _uv_option_value_looks_like_path_or_sensitive(value: str) -> bool:
    normalized = str(value or "").strip().strip("'\"")
    if not normalized:
        return False
    return (
        normalized.startswith(("/", "~", "."))
        or "/" in normalized
        or "\\" in normalized
        or _path_has_credential_marker(normalized)
    )


def _uv_pip_subcommand(args: list[str]) -> tuple[str | None, int]:
    index = 0
    value_flags = {"--python", "-p", "--project", "--directory"}
    while index < len(args):
        token = args[index]
        if token == "--":
            index += 1
            break
        if token in value_flags and index + 1 < len(args):
            index += 2
            continue
        if token.startswith(tuple(f"{flag}=" for flag in value_flags if flag.startswith("--"))):
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        return token.lower(), index
    if index < len(args):
        return args[index].lower(), index
    return None, -1


def _uv_run_command_tokens(args: list[str]) -> list[str]:
    index = 0
    value_flags = {
        "--config-file",
        "--directory",
        "--env-file",
        "--from",
        "--index-url",
        "--isolated",
        "--module",
        "--project",
        "--python",
        "--with",
        "--with-editable",
    }
    while index < len(args):
        token = args[index]
        if token == "--":
            return args[index + 1:]
        if token in value_flags and index + 1 < len(args):
            index += 2
            continue
        if token.startswith(tuple(f"{flag}=" for flag in value_flags if flag.startswith("--"))):
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        return args[index:]
    return []


def _uv_option_path(tokens: list[str], option: str) -> str | None:
    for index, token in enumerate(tokens[:-1]):
        if token == option:
            return tokens[index + 1]
        prefix = option + "="
        if token.startswith(prefix):
            return token.split("=", 1)[1]
    if tokens:
        prefix = option + "="
        for token in tokens:
            if token.startswith(prefix):
                return token.split("=", 1)[1]
    return None


def _uv_short_option_path(tokens: list[str], option: str) -> str | None:
    for index, token in enumerate(tokens[:-1]):
        if token == option:
            return tokens[index + 1]
        if token.startswith(option) and len(token) > len(option):
            return token[len(option):]
    return None


def _uv_editable_paths(tokens: list[str]) -> list[str]:
    paths: list[str] = []
    for index, token in enumerate(tokens):
        if token in {"-e", "--editable"} and index + 1 < len(tokens):
            paths.append(tokens[index + 1])
        elif token.startswith("--editable="):
            paths.append(token.split("=", 1)[1])
        elif token.startswith("-e") and len(token) > 2:
            paths.append(token[2:])
    return paths


def _normalized_path_set(paths: list[str]) -> set[str]:
    return {_normalize_shell_compare_path(path) for path in paths if path}


def _normalize_shell_compare_path(path: str) -> str:
    normalized = str(path or "").strip().strip("'\"")
    if not normalized:
        return ""
    return posixpath.normpath(normalized)


def _inline_interpreter_heredoc_sources(
    text: str,
    interpreter_names: set[str],
    *,
    depth: int = 0,
) -> list[str]:
    if "<<" not in str(text or "") or depth > _MAX_SHELL_INLINE_DEPTH:
        return []
    sources: list[str] = []
    for opener, body in _top_level_heredoc_sections(text):
        if _heredoc_prefix_command_head(opener) in interpreter_names and body:
            sources.append("\n".join(body))
    for body in _shell_executable_heredoc_bodies(text):
        sources.extend(
            _inline_interpreter_heredoc_sources(
                body,
                interpreter_names,
                depth=depth + 1,
            )
        )
    return _dedupe_strings([source for source in sources if source])


def _top_level_heredoc_sections(text: str) -> list[tuple[str, list[str]]]:
    lines = str(text or "").splitlines()
    sections: list[tuple[str, list[str]]] = []
    index = 0
    while index < len(lines):
        opener = lines[index]
        delimiter = _heredoc_delimiter_from_line(opener)
        if not delimiter:
            index += 1
            continue
        strip_tabs = _heredoc_strips_leading_tabs(opener)
        body: list[str] = []
        index += 1
        while index < len(lines) and lines[index].strip() != delimiter:
            body.append(lines[index].lstrip("\t") if strip_tabs else lines[index])
            index += 1
        sections.append((opener, body))
        if index < len(lines):
            index += 1
    return sections


def _inline_node_sources(text: str) -> list[str]:
    sources: list[str] = []
    sources.extend(_inline_interpreter_heredoc_sources(text, {"node", "nodejs", "javascript"}))
    for tokens in _shell_segments(shell_command_surface(text)):
        if not tokens or Path(tokens[0]).name.lower() not in {"node", "nodejs", "javascript"}:
            continue
        for index, token in enumerate(tokens[:-1]):
            if token == "-e":
                sources.append(tokens[index + 1])
    return _dedupe_strings([source for source in sources if source])


def _reset_python_sys_argv_aliases(
    tokens: tuple[contextvars.Token[set[str]], contextvars.Token[set[str]]],
) -> None:
    _PYTHON_SYS_MODULE_ALIASES.reset(tokens[0])
    _PYTHON_SYS_ARGV_ALIASES.reset(tokens[1])


def _heredoc_delimiter_from_line(line: str) -> str:
    match = re.search(
        r"<<-?\s*(?:\\?['\"]?|\$['\"])([A-Za-z0-9_][A-Za-z0-9_-]*)['\"]?",
        str(line or ""),
    )
    return match.group(1) if match else ""


def _heredoc_strips_leading_tabs(line: str) -> bool:
    return bool(re.search(r"<<-", str(line or "")))


def _is_static_inline_python_unresolved_writer_review(text: str) -> bool:
    argv_token = _with_inline_python_argv_bindings(text)
    source = _inline_python_source(text)
    alias_tokens: tuple[contextvars.Token[set[str]], contextvars.Token[set[str]]] | None = None
    try:
        if source is None:
            return False
        alias_tokens = _with_python_sys_argv_aliases(source)
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return False
        path_bindings = _python_path_variable_bindings(source)
        path_sequence_bindings = _python_path_sequence_variable_bindings(source)
        return _python_ast_has_unresolved_writer_method_call(
            tree,
            path_bindings,
            path_sequence_bindings,
        )
    finally:
        if alias_tokens is not None:
            _reset_python_sys_argv_aliases(alias_tokens)
        _PYTHON_ARGV_PATH_BINDINGS.reset(argv_token)


def _empty_python_readonly_import_aliases() -> dict[str, set[str]]:
    return {
        "os_module_aliases": {"os"},
        "pathlib_module_aliases": {"pathlib"},
        "path_constructor_aliases": set(_PYTHON_PATH_CONSTRUCTOR_NAMES),
        "os_replace_aliases": set(),
        "itertools_module_aliases": {"itertools"},
        "itertools_chain_aliases": set(),
        "itertools_first_arg_path_iterator_aliases": set(),
        "itertools_second_arg_path_iterator_aliases": set(),
    }


def _add_embedded_path_read_targets(
    text: str,
    effects: list[str],
    targets: list[ActionEffectTarget],
    rules: list[str],
) -> None:
    for path in _embedded_command_paths(text):
        _add_effect(effects, "filesystem.read")
        role = _path_role_for_read(path)
        targets.append(_target_for_path(path, role=role))
        if role == "credential_source" or _path_has_credential_marker(path):
            _add_rule(rules, "credential_read")


def _embedded_command_paths(text: str) -> list[str]:
    candidates = re.findall(
        r"(?:^|[\s'\"(,\[])(/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+)",
        text or "",
    )
    candidates.extend(re.findall(
        r"(?:^|[\s'\"(,\[])(\.{1,2}/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\.?[A-Za-z0-9_.-]*)",
        text or "",
    ))
    return _dedupe_strings(candidates)


def _read_probe_source_args(args: list[str]) -> list[str]:
    sources: list[str] = []
    index = 0
    while index < len(args):
        token = args[index]
        if token in {">", ">>", ">|", "<>", "<<"} or token.startswith("<<"):
            break
        if token == "<":
            if index + 1 < len(args):
                sources.append(args[index + 1])
            break
        if token.startswith(">"):
            break
        sources.append(token)
        index += 1
    return sources


_STDOUT_CONVERTER_OUTPUT_FLAGS = frozenset({
    "-o",
    "--output",
    "--output-file",
    "--outfile",
    "--out",
})
_STDOUT_CONVERTER_VALUE_FLAGS = frozenset({
    "--format",
    "--encoding",
    "--llm-model",
    "--page-range",
})
_PDFTOTEXT_VALUE_FLAGS = frozenset({
    "-f",
    "-l",
    "-r",
    "-x",
    "-y",
    "-W",
    "-H",
    "-opw",
    "-upw",
    "-enc",
    "-eol",
    "-paper",
})
_PANDOC_VALUE_FLAGS = frozenset({
    "-f",
    "-t",
    "--from",
    "--to",
    "--read",
    "--write",
    "--metadata",
    "--resource-path",
    "--extract-media",
    "--reference-doc",
    "--template",
    "--data-dir",
    "--defaults",
    "--lua-filter",
    "--filter",
})
_STRINGS_VALUE_FLAGS = frozenset({"-n", "--bytes", "-t", "--radix", "-e", "--encoding", "-T", "--target"})
_DOCX2TXT_VALUE_FLAGS = frozenset({"--encoding", "-i", "--image-dir", "--images", "--img-dir", "--img_dir"})
_DOCX2TXT_IMAGE_OUTPUT_FLAGS = frozenset({"-i", "--image-dir", "--images", "--img-dir", "--img_dir"})
_SOFFICE_VALUE_FLAGS = frozenset({"--convert-to", "--outdir", "--infilter"})
_SOFFICE_OUTPUT_FLAGS = frozenset({"--outdir"})
_GZIP_VALUE_FLAGS = frozenset({"-S", "--suffix"})
_BSDTAR_VALUE_FLAGS = frozenset({
    "-C",
    "--directory",
    "--exclude",
    "--format",
    "--include",
    "--options",
    "--strip-components",
})


def _unzip_token_is_read_mode(token: str) -> bool:
    if token in {"-p", "-c", "-l", "-v", "-t", "-z", "-Z", "--list", "--test"}:
        return True
    if token.startswith("--"):
        return False
    return token.startswith("-") and any(flag in token[1:] for flag in ("p", "c", "l", "v", "t", "z"))


def _gzip_token_is_read_mode(token: str) -> bool:
    if token in {"-c", "--stdout", "--to-stdout", "-t", "--test", "-l", "--list"}:
        return True
    if token.startswith("--"):
        return False
    return token.startswith("-") and any(flag in token[1:] for flag in ("c", "t", "l"))


def _glob_base_path(value: str) -> str:
    cleaned = str(value or "").strip().strip("'\"")
    if not _path_has_glob(cleaned):
        return cleaned
    parts = cleaned.split("/")
    absolute = cleaned.startswith("/")
    base_parts: list[str] = []
    for part in parts:
        if not part:
            continue
        if any(char in part for char in "*?["):
            break
        base_parts.append(part)
    if absolute:
        return "/" + "/".join(base_parts) if base_parts else "/"
    if base_parts:
        base = "/".join(base_parts)
        if cleaned.startswith("./"):
            return f"./{base}" if not base.startswith(".") else base
        return base
    return "."


def _path_has_glob(value: str) -> bool:
    return any(char in str(value or "") for char in "*?[")


_ARCHIVE_MEMBER_COLLECTION_MUTATING_METHODS = {
    "__delitem__",
    "__setitem__",
    "add",
    "append",
    "clear",
    "discard",
    "extend",
    "insert",
    "pop",
    "popitem",
    "remove",
    "setdefault",
    "update",
}
_ARCHIVE_MEMBER_COLLECTION_MUTATOR_TYPE_NAMES = {"dict", "list", "set"}


def _dedupe_archive_mutation_hints(hints: list[tuple[str, str]]) -> list[tuple[str, str]]:
    seen: set[tuple[str, str]] = set()
    deduped: list[tuple[str, str]] = []
    for hint in hints:
        if hint in seen:
            continue
        seen.add(hint)
        deduped.append(hint)
    return deduped


def _collect_matching_name_node_ids(
    node: ast.AST,
    names: set[str],
    node_ids: set[int],
) -> None:
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in names:
            node_ids.add(id(child))


def _append_python_static_text_payload_candidate(existing: list[str], item: str) -> bool:
    if item in existing:
        return False
    if len(existing) >= _PYTHON_STATIC_TEXT_PAYLOAD_CANDIDATE_LIMIT:
        return True
    existing.append(item)
    return False


def _path_with_suffix(path: str, suffix: str) -> str | None:
    try:
        return str(PurePosixPath(path).with_suffix(suffix))
    except ValueError:
        return None


def _analyze_node(text: str) -> dict[str, Any]:
    effects: list[str] = []
    targets: list[ActionEffectTarget] = []
    rules: list[str] = []
    confidence = "low"
    if _node_has_child_process_execution(text):
        _add_effect(effects, "command.exec")
        _add_rule(rules, "wrapper_chain_unresolved")
        _add_rule(rules, "node_child_process_exec")
        confidence = _max_confidence(confidence, "high")
        _add_embedded_path_read_targets(text, effects, targets, rules)
    if _node_has_raw_network(text):
        _add_effect(effects, "network.fetch")
        _add_rule(rules, "node_network_socket")
        confidence = _max_confidence(confidence, "high")
    if re.search(r"\bprocess\.env\b", text):
        _add_effect(effects, "environment.probe")
        targets.append(_probe_target("environment_credentials"))
        _add_rule(rules, "credential_read")
        confidence = _max_confidence(confidence, "high")
    for path in re.findall(r"\brequire\(\s*['\"]([^'\"]+)['\"]\s*\)", text):
        if not _node_require_path_is_file(path):
            continue
        _add_effect(effects, "filesystem.read")
        targets.append(_target_for_path(path, role=_path_role_for_read(path)))
        _add_rule(rules, "node_file_read")
        if _path_has_credential_marker(path):
            _add_rule(rules, "credential_read")
        confidence = _max_confidence(confidence, "medium")
    for path in re.findall(r"(?:readFile|readFileSync)\(\s*['\"]([^'\"]+)['\"]", text):
        _add_effect(effects, "filesystem.read")
        targets.append(_target_for_path(path, role=_path_role_for_read(path)))
        _add_rule(rules, "node_file_read")
        if _path_has_credential_marker(path):
            _add_rule(rules, "credential_read")
        confidence = _max_confidence(confidence, "medium")
    for path in re.findall(r"(?:writeFile|writeFileSync|appendFile|appendFileSync)\(\s*['\"]([^'\"]+)['\"]", text):
        _add_effect(effects, "filesystem.write")
        targets.append(_target_for_path(path))
        _add_rule(rules, "node_file_write")
        confidence = "high"
    for path in re.findall(
        r"\bwriteFile\s*\(\s*\{[^{}]*\bfileName\s*:\s*['\"]([^'\"]+)['\"]",
        text,
    ):
        _add_effect(effects, "filesystem.write")
        targets.append(_target_for_path(path))
        _add_rule(rules, "node_file_write")
        confidence = "high"
    if re.search(r"\b(?:fetch|axios\.)\s*\(", text):
        _add_effect(effects, "network.fetch")
        _add_rule(rules, "node_network_fetch")
        confidence = _max_confidence(confidence, "high")
    return {"effects": effects, "targets": targets, "rules": rules, "confidence": confidence}


def _node_has_child_process_execution(text: str) -> bool:
    return bool(re.search(
        r"\bchild_process\b|"
        r"\brequire\(\s*['\"]child_process['\"]\s*\)|"
        r"\b(?:exec|execFile|execSync|execFileSync|spawn|spawnSync|fork)\s*\(",
        text,
    ))


def _node_has_raw_network(text: str) -> bool:
    return bool(re.search(
        r"\brequire\(\s*['\"](?:net|tls|dgram|http|https)['\"]\s*\)|"
        r"\b(?:net|tls|dgram|http|https)\.|"
        r"\.(?:connect|request|get)\s*\(",
        text,
    ))


def _node_require_path_is_file(path: str) -> bool:
    normalized = str(path or "").strip()
    if not normalized:
        return False
    if normalized.startswith(("./", "../", "/", "~")):
        return True
    return normalized.endswith((".json", ".js", ".mjs", ".cjs", ".node"))


def _analyze_delegation(text: str) -> dict[str, Any]:
    effects: list[str] = []
    targets: list[ActionEffectTarget] = []
    rules: list[str] = []
    confidence = "low"
    if re.search(r"\b(?:write|create|edit|save|generate)\b", text, re.IGNORECASE):
        paths = _paths(text)
        if paths:
            _add_effect(effects, "delegated_effect_request")
            _add_effect(effects, "filesystem.write")
            targets.extend(_target_for_path(path) for path in paths)
            _add_rule(rules, "delegated_write_request")
            confidence = "medium"
    return {"effects": effects, "targets": targets, "rules": rules, "confidence": confidence}


def _analyze_content_evidence(context: DecisionContext | None) -> dict[str, Any]:
    effects: list[str] = []
    targets: list[ActionEffectTarget] = []
    rules: list[str] = []
    confidence = "low"
    analysis_state = "complete"
    envelope = getattr(context, "content_evidence", None) if context is not None else None
    if envelope is None:
        return {
            "effects": effects,
            "targets": targets,
            "rules": rules,
            "confidence": confidence,
            "analysis_state": analysis_state,
        }
    for item in getattr(envelope, "items", []) or []:
        item_rules = [
            str(rule.get("rule_id"))
            for rule in getattr(item, "derived_rules", []) or []
            if isinstance(rule, dict) and rule.get("rule_id")
        ]
        for rule_id in item_rules:
            _add_rule(rules, rule_id)
        if str(getattr(item, "kind", "")) in {"skill_script", "script"}:
            targets.append(_content_target(getattr(item, "canonical_evidence_id", ""), "executed_script"))
        if "document_input_to_network_sink" in item_rules:
            _add_effect(effects, "network.upload")
            targets.append(_content_target(getattr(item, "canonical_evidence_id", ""), "document_input"))
            confidence = _max_confidence(confidence, "high")
        elif "associated_script_network_sink" in item_rules:
            _add_effect(effects, "network.upload")
            confidence = _max_confidence(confidence, "high")
        elif "associated_script_network_indicator" in item_rules:
            _add_effect(effects, "network.fetch")
            confidence = _max_confidence(confidence, "medium")
        if "content_evidence_incomplete" in item_rules:
            analysis_state = "incomplete"
            confidence = _max_confidence(confidence, "medium")
    return {
        "effects": effects,
        "targets": targets,
        "rules": rules,
        "confidence": confidence,
        "analysis_state": analysis_state,
    }


def _content_target(evidence_id: str, role: str) -> ActionEffectTarget:
    return ActionEffectTarget(
        kind="content_evidence",
        path_hash=_hash(str(evidence_id)),
        path_role=role,
        workspace_relation="gateway_content_evidence",
    )


def _payload_text(payload: dict[str, Any]) -> str:
    parts: list[str] = []
    text_keys = (
        "command",
        "cmd",
        "script",
        "code",
        "input",
        "prompt",
        "instructions",
        "content",
        "path",
        "target_path",
        "destination_path",
        "relative_path",
        "output_path",
        "patch",
        "diff",
    )
    for key in text_keys:
        value = payload.get(key)
        if isinstance(value, str):
            parts.append(value)
    arguments = payload.get("arguments")
    if isinstance(arguments, dict):
        for key in text_keys:
            value = arguments.get(key)
            if isinstance(value, str):
                parts.append(value)
    if not parts:
        try:
            parts.append(json.dumps(payload, sort_keys=True, default=str))
        except TypeError:
            parts.append(str(payload))
    return "\n".join(dict.fromkeys(parts))


def _first_payload_path(payload: dict[str, Any]) -> str | None:
    paths = _payload_paths(payload, include_patch_targets=False)
    return paths[0] if paths else None


def _payload_paths(payload: dict[str, Any], *, include_patch_targets: bool) -> list[str]:
    paths: list[str] = []
    for key in (
        "path",
        "file_path",
        "relative_path",
        "target",
        "target_path",
        "destination",
        "destination_path",
        "output_path",
    ):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            paths.append(value.strip())
    for key in ("changes", "files", "edits"):
        value = payload.get(key)
        if not isinstance(value, list):
            continue
        for item in value:
            if not isinstance(item, dict):
                continue
            for path_key in (
                "path",
                "file_path",
                "relative_path",
                "target",
                "target_path",
                "destination",
                "destination_path",
                "output_path",
            ):
                path = item.get(path_key)
                if isinstance(path, str) and path.strip():
                    paths.append(path.strip())
    if include_patch_targets:
        paths.extend(_patch_target_paths(_payload_text(payload)))
    return _dedupe_strings(paths)


def _patch_target_paths(text: str) -> list[str]:
    paths: list[str] = []
    in_apply_patch_file_block = False
    for line in str(text or "").splitlines():
        stripped = line.strip()
        match = re.match(
            r"^\*\*\*\s+(?:Add|Update|Delete)\s+File:\s+(.+)$",
            stripped,
        )
        if match:
            paths.append(match.group(1).strip())
            in_apply_patch_file_block = True
            continue
        match = re.match(r"^\*\*\*\s+Move\s+to:\s+(.+)$", stripped)
        if match:
            paths.append(match.group(1).strip())
            in_apply_patch_file_block = True
            continue
        if stripped.startswith("***"):
            in_apply_patch_file_block = False
            continue
        if in_apply_patch_file_block:
            continue
        if stripped.startswith(("+++ ", "--- ")):
            candidate = stripped[4:].strip()
            if candidate == "/dev/null":
                continue
            if candidate.startswith(("a/", "b/")):
                candidate = candidate[2:]
            if candidate:
                paths.append(candidate)
    return _dedupe_strings(paths)


def _dedupe_strings(values: list[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        cleaned = str(value or "").strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        deduped.append(cleaned)
    return deduped


def _dedupe_scan_texts(values: list[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "")
        if not text.strip():
            continue
        key = text
        if key in seen:
            continue
        seen.add(key)
        deduped.append(text)
    return deduped


def _redirection_paths(text: str) -> list[str]:
    paths: list[str] = []
    write_redirect_ops = {">", ">>", "&>", ">&", ">|"}
    for tokens, shell_cwd in _shell_segments_with_cwd(shell_command_surface(text)):
        for index, token in enumerate(tokens[:-1]):
            if token not in write_redirect_ops:
                continue
            if token == ">" and tokens[index + 1].startswith("="):
                continue
            path = tokens[index + 1]
            if _is_nonpersistent_redirect_target(path):
                continue
            paths.append(_resolve_shell_target(path, shell_cwd))
    return paths


def _input_redirection_paths(text: str) -> list[str]:
    paths: list[str] = []
    for tokens, shell_cwd in _shell_segments_with_cwd(shell_command_surface(text)):
        for index, token in enumerate(tokens[:-1]):
            if token != "<":
                continue
            path = tokens[index + 1]
            if _is_nonpersistent_redirect_target(path):
                continue
            if path.startswith("("):
                continue
            paths.append(_resolve_shell_target(path, shell_cwd))
    return paths


def _is_python_launcher_name(value: str) -> bool:
    return re.fullmatch(r"python(?:\d+(?:\.\d+)?)?", Path(str(value or "")).name.lower()) is not None


def _is_python_help_or_version_probe(tokens: list[str]) -> bool:
    args = [str(token or "") for token in tokens[1:]]
    if not args:
        return False
    probe_flags = {"-h", "-?", "--help", "-V", "-VV", "--version"}
    return all(arg in probe_flags for arg in args)


def _uv_invokes_package_install(tokens: list[str]) -> bool:
    if not tokens or Path(tokens[0]).name.lower() != "uv":
        return False
    subcommand, subcommand_index = _uv_subcommand(tokens)
    if subcommand in {"add", "sync"}:
        return True
    if subcommand == "pip":
        pip_subcommand, _ = _uv_pip_subcommand(tokens[subcommand_index + 1:])
        return pip_subcommand == "install"
    if subcommand == "run":
        args = tokens[subcommand_index + 1:]
        return any(
            token == "--with"
            or token == "--with-editable"
            or token.startswith("--with=")
            or token.startswith("--with-editable=")
            for token in args
        )
    return False


def _heredoc_line_invokes_shell_interpreter(line: str) -> bool:
    return _heredoc_prefix_command_head(line) in _SHELL_INLINE_COMMAND_INTERPRETERS


def _heredoc_prefix_command_head(line: str) -> str:
    prefix = line.split("<<", 1)[0].strip()
    if not prefix:
        return ""
    for tokens in reversed(_shell_segments(prefix)):
        head = _shell_command_head(tokens)
        if head:
            return head
    return ""


def _package_install_subcommand_present(args: list[str]) -> bool:
    index = 0
    while index < len(args):
        token = args[index]
        if not token:
            index += 1
            continue
        if token == "--":
            index += 1
            continue
        if token.startswith("-"):
            if token in _PACKAGE_OPTION_VALUE_FLAGS and index + 1 < len(args):
                index += 2
            else:
                index += 1
            continue
        return token.lower() in _PACKAGE_INSTALL_SUBCOMMANDS
    return False


def _is_nonpersistent_redirect_target(path: str) -> bool:
    normalized = str(path or "").strip().strip("'\"")
    lowered = normalized.lower()
    return (
        not normalized
        or normalized.startswith("&")
        or normalized.isdigit()
        or lowered in {"/dev/null", "nul", "/dev/stdout", "/dev/stderr"}
        or re.fullmatch(r"/dev/fd/\d+", lowered) is not None
        or re.fullmatch(r"/proc/self/fd/\d+", lowered) is not None
    )


def _tee_paths(text: str) -> list[str]:
    paths: list[str] = []
    for parts, shell_cwd in _shell_segments_with_cwd(text):
        tee_indexes = [
            index for index, part in enumerate(parts)
            if Path(part).name.lower() == "tee"
        ]
        if not tee_indexes:
            continue
        idx = tee_indexes[0] + 1
        while idx < len(parts):
            if parts[idx].startswith("-"):
                idx += 1
                continue
            if parts[idx].startswith("<<"):
                idx += 2
                continue
            break
        if idx < len(parts):
            paths.append(_resolve_shell_target(parts[idx], shell_cwd))
    return paths


def _dd_output_paths(text: str) -> list[str]:
    paths: list[str] = []
    for parts, shell_cwd in _shell_segments_with_cwd(text):
        if not parts or Path(parts[0]).name.lower() != "dd":
            continue
        for token in parts[1:]:
            if not token.startswith("of="):
                continue
            path = token.split("=", 1)[1]
            if path:
                paths.append(_resolve_shell_target(path, shell_cwd))
    return paths


def _copy_like_operations(text: str) -> list[tuple[tuple[str, ...], str]]:
    operations: list[tuple[tuple[str, ...], str]] = []
    for parts, shell_cwd in _shell_segments_with_cwd(text):
        if len(parts) < 3:
            continue
        command = Path(parts[0]).name
        if command not in {"cp", "mv", "install"}:
            continue
        operands: list[str] = []
        index = 1
        while index < len(parts):
            part = parts[index]
            if part == "--":
                operands.extend(parts[index + 1:])
                break
            if part in {"-t", "--target-directory"} and index + 1 < len(parts):
                destination = parts[index + 1]
                sources = tuple(
                    candidate
                    for candidate in parts[index + 2:]
                    if candidate and not candidate.startswith("-")
                )
                if sources:
                    operations.append((
                        tuple(_resolve_shell_target(source, shell_cwd) for source in sources),
                        _resolve_shell_target(destination, shell_cwd),
                    ))
                break
            if part.startswith("--target-directory="):
                destination = part.split("=", 1)[1]
                sources = tuple(
                    candidate
                    for candidate in parts[index + 1:]
                    if candidate and not candidate.startswith("-")
                )
                if sources:
                    operations.append((
                        tuple(_resolve_shell_target(source, shell_cwd) for source in sources),
                        _resolve_shell_target(destination, shell_cwd),
                    ))
                break
            if _copy_like_option_consumes_value(part) and index + 1 < len(parts):
                index += 2
                continue
            if part.startswith("-"):
                index += 1
                continue
            operands.append(part)
            index += 1
        if len(operands) >= 2:
            operations.append((
                tuple(_resolve_shell_target(source, shell_cwd) for source in operands[:-1]),
                _resolve_shell_target(operands[-1], shell_cwd),
            ))
    return operations


def _copy_like_option_consumes_value(option: str) -> bool:
    return option in _COPY_LIKE_OPTION_VALUE_FLAGS


def _path_has_script_asset_directory(path: str) -> bool:
    normalized = normalize_task_artifact_path(path, cwd=_NORMALIZER_CWD.get())
    if not normalized:
        return False
    return any(
        part.lower() in _SCRIPT_ASSET_DIRECTORY_NAMES
        for part in PurePosixPath(normalized).parts
    )


def _target_allowed_output_extensions(target: ActionEffectTarget) -> set[str]:
    if target.path_role != SCOPE_TASK_OUTPUT_PATH_ROLE:
        return set()
    metadata = target.artifact_source_metadata or {}
    raw_extensions = metadata.get("allowed_output_extensions")
    if not isinstance(raw_extensions, list):
        return set()
    extensions: set[str] = set()
    for value in raw_extensions:
        lowered = str(value or "").strip().lower()
        if lowered.startswith(".") and len(lowered) > 1:
            extensions.add(lowered)
    return extensions


def _lexical_absolute_path(path: str) -> str:
    raw = str(path or "").strip().strip("'\"").replace("\\", "/")
    if not raw:
        return ""
    if _path_is_absolute_like(raw):
        return raw
    cwd = _NORMALIZER_CWD.get()
    if cwd:
        return posixpath.join(cwd, raw)
    return raw


def _path_string_is_within_root(path: str, root: str) -> bool:
    normalized_path = str(path or "").rstrip("/")
    normalized_root = str(root or "").rstrip("/")
    return bool(
        normalized_path
        and normalized_root
        and (
            normalized_path == normalized_root
            or normalized_path.startswith(f"{normalized_root}/")
        )
    )


def _network_download_targets(text: str) -> list[str]:
    targets: list[str] = []
    for parts in _shell_segments(text):
        if not parts:
            continue
        inline_command = _shell_inline_command(parts)
        if inline_command:
            targets.extend(_network_download_targets(inline_command))
            continue
        command = _shell_command_head(parts)
        if command in {"curl", "wget"}:
            for index, part in enumerate(parts[:-1]):
                if part in {"-o", "--output"} or (command == "wget" and part == "-O"):
                    targets.append(parts[index + 1])
                elif part.startswith("--output="):
                    targets.append(part.split("=", 1)[1])
                elif part.startswith("--output-document="):
                    targets.append(part.split("=", 1)[1])
            continue
        if command in {"scp", "rsync"} and len(parts) >= 3:
            targets.append(parts[-1])
    return targets


def _rm_delete_targets(text: str) -> list[str]:
    targets: list[str] = []
    for parts, shell_cwd in _shell_segments_with_cwd(text):
        effective = _shell_effective_tokens(parts)
        if len(effective) < 2 or Path(effective[0]).name.lower() != "rm":
            continue
        targets.extend(
            _resolve_shell_target(path, shell_cwd)
            for path in _rm_segment_delete_targets(effective[1:])
        )
    return _dedupe_strings(targets)


def _rm_segment_delete_targets(tokens: list[str]) -> list[str]:
    targets: list[str] = []
    index = 0
    end_of_options = False
    while index < len(tokens):
        token = tokens[index]
        if not token:
            index += 1
            continue
        if not end_of_options and token == "--":
            end_of_options = True
            index += 1
            continue
        if not end_of_options and token.startswith("-"):
            index += 1
            continue
        targets.append(token)
        index += 1
    return targets


def _paths(text: str) -> list[str]:
    return [match.group(0) for match in _PATH_RE.finditer(text or "")]


def _first_path(text: str) -> str | None:
    paths = _paths(text)
    return paths[0] if paths else None


def _path_has_credential_marker(path: str) -> bool:
    for part in str(path or "").replace("\\", "/").split("/"):
        name = part.strip().strip("'\"").lower()
        if not name:
            continue
        if name == ".ssh":
            return True
        if (
            name in {"credentials", "credential"}
            or name == "id_rsa"
            or name.startswith("id_rsa.")
            or name == "id_ed25519"
            or name.startswith("id_ed25519.")
        ):
            return True
        if name == ".env" or name.startswith(".env."):
            return True
        if _CREDENTIAL_WORD_RE.search(name):
            return True
    return False


def _target_for_path(
    path: str,
    *,
    role: str | None = None,
    cwd: str | None = None,
    io_direction: str | None = None,
) -> ActionEffectTarget:
    normalized = str(path or "").strip().strip("'\"")
    effective_cwd = cwd if cwd is not None else _NORMALIZER_CWD.get()
    canonical_path = normalize_task_artifact_path(normalized, cwd=effective_cwd) if normalized else normalized
    target_role = role or _path_role(normalized, cwd=effective_cwd)
    relation_cwd = (
        effective_cwd
        if (
            not _path_is_absolute_like(normalized)
            or (
                target_role == "future_execution.artifact"
                and io_direction != "source"
            )
        )
        else ""
    )
    artifact = _artifact_decision_for_target(normalized, target_role, cwd=effective_cwd)
    metadata = artifact.target_metadata() if artifact is not None else {}
    return ActionEffectTarget(
        kind="path",
        path_hash=_hash(canonical_path or normalized),
        path_role=target_role,
        io_direction=io_direction,
        workspace_relation=_workspace_relation(
            canonical_path or normalized,
            cwd=relation_cwd,
            role=target_role,
            artifact=artifact,
        ),
        **metadata,
    )


def _write_target_for_path(
    path: str,
    *,
    payload_is_script: bool = False,
    cwd: str | None = None,
    io_direction: str | None = None,
) -> ActionEffectTarget:
    target = _target_for_path(path, cwd=cwd, io_direction=io_direction)
    if payload_is_script and _native_write_target_is_task_output(target):
        return target.model_copy(update={"path_role": "future_execution.artifact"})
    return target


def _path_is_absolute_like(path: str) -> bool:
    normalized = str(path or "").strip().strip("'\"")
    return normalized.startswith(("/", "~")) or re.match(r"^[A-Za-z]:", normalized) is not None


def _workspace_relation(
    path: str,
    *,
    cwd: str | None = None,
    role: str | None = None,
    artifact: ScopeTaskArtifactDecision | None = None,
) -> str:
    normalized = str(path or "").strip().strip("'\"")
    normalized_slash = normalized.replace("\\", "/")
    parts = [part for part in normalized_slash.split("/") if part]
    if ".." in parts:
        return "outside_workspace_or_absolute"
    if _artifact_decision_is_effective(artifact) and artifact.workspace_relation:
        return artifact.workspace_relation
    if role == SCOPE_CONTROL_METADATA_PATH_ROLE:
        return SCOPE_CONTROL_METADATA_RELATION
    if normalized in {".", "./"}:
        return "inside_workspace"
    cwd_slash = str(cwd or "").strip().strip("'\"").replace("\\", "/").rstrip("/")
    if cwd_slash and not cwd_slash.startswith("~") and not re.match(r"^[A-Za-z]:", cwd_slash):
        if normalized_slash == cwd_slash or normalized_slash.startswith(cwd_slash + "/"):
            return "inside_workspace"
    artifact = artifact or _artifact_decision_for_target(normalized, role or _path_role(normalized), cwd=cwd)
    if _artifact_decision_is_effective(artifact) and artifact.workspace_relation:
        return artifact.workspace_relation
    if normalized.startswith("/workspace/") or normalized == "/workspace":
        return "inside_workspace"
    if normalized.startswith(("/", "~")) or re.match(r"^[A-Za-z]:", normalized):
        return "outside_workspace_or_absolute"
    return "inside_workspace"


def _write_decision_can_attach_to_target(
    decision: ScopeTaskArtifactDecision | None,
    role: str | None,
) -> bool:
    if not _task_output_decision_is_derived_parent(decision):
        return True
    return role == SCOPE_TASK_OUTPUT_PATH_ROLE


def _probe_target(probe: str) -> ActionEffectTarget:
    return ActionEffectTarget(
        kind="capability_probe",
        path_hash=_hash(probe),
        path_role="capability_probe",
        workspace_relation="process_environment",
    )


def _disabled_capabilities(context: DecisionContext | None) -> set[str]:
    if context is None or context.session_scope_profile is None:
        return set()
    profile = context.session_scope_profile
    return {str(item) for item in getattr(profile.base_rules, "denied_capabilities", [])}


def _dedupe_targets(targets: list[ActionEffectTarget]) -> list[ActionEffectTarget]:
    seen: set[tuple[str | None, str | None, str | None]] = set()
    deduped: list[ActionEffectTarget] = []
    for target in targets:
        key = (target.path_hash, target.path_role, target.io_direction)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(target)
    return deduped


def _write_channel(rules: list[str]) -> str | None:
    if "shell_copy_write" in rules:
        return "shell_copy"
    if "network_download_write" in rules:
        return "network_download"
    if "shell_heredoc_write" in rules:
        return "shell_heredoc"
    if "shell_redirection_write" in rules:
        return "shell_redirection"
    if "shell_tee_write" in rules:
        return "shell_tee"
    if "native_write_effect" in rules:
        return "native_write"
    if "python_file_write" in rules:
        return "python_file_write"
    if "node_file_write" in rules:
        return "node_file_write"
    return None


def _strip_shell_heredoc_bodies(text: str) -> str:
    if "<<" not in text:
        return text
    lines = text.splitlines()
    if not lines:
        return text
    retained: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        delimiter = _heredoc_delimiter_from_line(line)
        if not delimiter:
            retained.append(line)
            index += 1
            continue
        opener = _strip_heredoc_redirect_from_line(line)
        if opener:
            retained.append(opener)
        retain_body = _heredoc_line_invokes_shell_interpreter(line)
        index += 1
        while index < len(lines) and lines[index].strip() != delimiter:
            if retain_body:
                retained.append(lines[index])
            index += 1
        if index < len(lines):
            index += 1
    return "\n".join(retained)


def _strip_heredoc_redirect_from_line(line: str) -> str:
    stripped = re.sub(
        r"\s*<<-?\s*(?:\\?['\"]?|\$['\"])[A-Za-z0-9_][A-Za-z0-9_-]*['\"]?",
        "",
        str(line or ""),
        count=1,
    ).rstrip()
    return stripped


def _strip_nonexecuted_heredoc_bodies(text: str) -> str:
    if "<<" not in text:
        return text
    lines = text.splitlines()
    if not lines:
        return text
    retained: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        delimiter = _heredoc_delimiter_from_line(line)
        if not delimiter:
            retained.append(line)
            index += 1
            continue
        opener = _strip_heredoc_redirect_from_line(line)
        if opener:
            retained.append(opener)
        retain_body = _heredoc_line_invokes_code_interpreter(line)
        if _heredoc_line_invokes_shell_interpreter(line):
            retain_body = True
        index += 1
        while index < len(lines) and lines[index].strip() != delimiter:
            if retain_body:
                retained.append(lines[index])
            index += 1
        if index < len(lines):
            index += 1
    return "\n".join(retained)


def _heredoc_line_invokes_code_interpreter(line: str) -> bool:
    head = _heredoc_prefix_command_head(line)
    return head in {
        *_SHELL_INLINE_COMMAND_INTERPRETERS,
        "python",
        "python3",
        "node",
        "nodejs",
        "javascript",
        "powershell",
        "pwsh",
    }


def _add_effect(effects: list[str], effect: str) -> None:
    _add_unique(effects, effect)


def _add_rule(rules: list[str], rule: str) -> None:
    _add_unique(rules, rule)


def _add_unique(values: list[str], value: str) -> None:
    if value and value not in values:
        values.append(value)


def _merge(values: list[str], additions: list[str]) -> None:
    for addition in additions:
        _add_unique(values, addition)


def _max_confidence(left: str, right: str) -> str:
    order = {"low": 0, "medium": 1, "high": 2}
    return left if order[left] >= order[right] else right


def _hash(value: str) -> str:
    return "sha256:" + hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def _hash_json(value: Any) -> str:
    return _hash(json.dumps(value, sort_keys=True, default=str, separators=(",", ":")))


# --- late-bound cross-module names (mechanical split of normalizer.py) ---
# Placed after all definitions on purpose: modules in this package form
# import cycles that are only safe because every module completes its own
# definitions before this block runs. Do not move these imports to the top.
from clawsentry.gateway.effects.python_ast import (  # noqa: E402
    _PYTHON_ARGV_PATH_BINDINGS,
    _PYTHON_ATOMIC_REPLACE_STAGING_SUFFIXES,
    _PYTHON_DICT_CONTENT_POLLUTING_METHOD_NAMES,
    _PYTHON_DOCUMENT_READER_DYNAMIC_IMPORT_MODULES,
    _PYTHON_DOCUMENT_READER_SOURCE_KEYWORDS,
    _PYTHON_DYNAMIC_CODE_CALLABLE_NAMES,
    _PYTHON_FILESYSTEM_REPLACE_METHOD_NAMES,
    _PYTHON_ITERTOOLS_FIRST_ARG_PATH_ITERATORS,
    _PYTHON_ITERTOOLS_SECOND_ARG_PATH_ITERATORS,
    _PYTHON_LIST_CONTENT_POLLUTING_METHOD_NAMES,
    _PYTHON_MUTATING_METHOD_NAMES,
    _PYTHON_OS_DESTRUCTIVE_DELETE_METHOD_NAMES,
    _PYTHON_PATH_CONSTRUCTOR_NAMES,
    _PYTHON_PATH_WRITER_CONSTRUCTOR_KEYWORDS_BY_NAME,
    _PYTHON_PATH_WRITER_CONSTRUCTOR_NAMES,
    _PYTHON_PATH_WRITER_KEYWORDS_BY_METHOD,
    _PYTHON_PATH_WRITER_METHOD_NAMES,
    _PYTHON_SAFE_READONLY_GETATTR_CONSUMERS,
    _PYTHON_SAVE_METHOD_PATH_KEYWORDS,
    _PYTHON_SHUTIL_COPY_METHOD_NAMES,
    _PYTHON_SHUTIL_DESTRUCTIVE_DELETE_METHOD_NAMES,
    _PYTHON_STATIC_DICT_BINDINGS,
    _PYTHON_STATIC_TEXT_PAYLOAD_BINDING_MAX_PASSES,
    _PYTHON_STATIC_TEXT_PAYLOAD_CANDIDATE_LIMIT,
    _PYTHON_SYS_ARGV_ALIASES,
    _PYTHON_SYS_MODULE_ALIASES,
    _PYTHON_TRUSTED_PATHLIKE_METHOD_NAMES,
    _PYTHON_UNSAFE_READONLY_GETATTR_NAMES,
    _analyze_python,
    _analyze_python_invocations,
    _analyze_python_source,
    _analyze_python_source_with_context,
    _inline_python_argv_path_bindings,
    _inline_python_argv_values,
    _inline_python_invocations,
    _inline_python_source,
    _inline_python_sources,
    _python_archive_auxiliary_member_write_hints,
    _python_archive_bound_collection_mutator_alias,
    _python_archive_comprehension_projects_archive_info_filename,
    _python_archive_comprehension_projects_existing_member_name,
    _python_archive_comprehension_projects_existing_member_numeric_index,
    _python_archive_existing_member_collection_names,
    _python_archive_existing_member_name_node_ids,
    _python_archive_expr_is_existing_member_collection,
    _python_archive_expr_is_existing_member_numeric_index_aggregate,
    _python_archive_expr_is_safe_structural_index,
    _python_archive_external_reference_write_hint,
    _python_archive_has_ooxml_write_target,
    _python_archive_loop_index_has_no_post_loop_reassignment,
    _python_archive_loop_index_has_safe_initializer,
    _python_archive_loop_index_mutations_are_safe,
    _python_archive_loop_index_step_is_safe,
    _python_archive_member_collection_mutation_analysis,
    _python_archive_member_collection_mutator_aliases,
    _python_archive_member_expr_is_ooxml_structural,
    _python_archive_member_iter_is_existing_collection,
    _python_archive_member_name_arg_node,
    _python_archive_member_name_is_auxiliary,
    _python_archive_member_name_is_ooxml_structural,
    _python_archive_member_template_index_names,
    _python_archive_member_template_is_ooxml_structural,
    _python_archive_member_template_value,
    _python_archive_member_write_has_unresolved_member_name,
    _python_archive_member_write_read_targets,
    _python_archive_member_write_semantics,
    _python_archive_mutating_call_member_names,
    _python_archive_mutator_collection_arg_name,
    _python_archive_ooxml_structural_index_binding_names,
    _python_archive_ooxml_structural_loop_index_names,
    _python_archive_ooxml_structural_member_binding_names,
    _python_archive_ooxml_structural_membership_index_names,
    _python_archive_read_handle_names,
    _python_archive_record_collection_assignment_mutation,
    _python_archive_record_mutating_method_call,
    _python_archive_static_member_names_from_expr,
    _python_archive_static_structural_loop_member_names,
    _python_archive_static_structural_member_name_node_ids,
    _python_archive_static_subscript_member_name,
    _python_archive_subscript_member_expr_is_ooxml_structural,
    _python_archive_target_is_ooxml_office_package,
    _python_archive_unbound_collection_mutator_name,
    _python_archive_write_call_targets,
    _python_archive_write_handle_bindings,
    _python_archive_write_receiver_targets,
    _python_archive_write_targets,
    _python_archive_writestr_payload_node,
    _python_argument_names,
    _python_arguments_binding_names,
    _python_argv_path_bindings_from_values,
    _python_assignment_name_value_pairs,
    _python_assignment_name_value_pairs_with_strings,
    _python_assignment_target_names,
    _python_assignment_value_and_targets,
    _python_ast_arg_is_stdin_fd,
    _python_ast_arg_is_url,
    _python_ast_constructs_non_file_writer_sink,
    _python_ast_dotted_name,
    _python_ast_has_disallowed_dynamic_code_reference,
    _python_ast_has_disallowed_dynamic_path_source,
    _python_ast_has_disallowed_readonly_task_data_effect,
    _python_ast_has_document_reader_url_call,
    _python_ast_has_dynamic_code_call,
    _python_ast_has_dynamic_code_callable_reference,
    _python_ast_has_invalidated_mapping_writer_method_call,
    _python_ast_has_network_fetch_call,
    _python_ast_has_only_document_reader_dynamic_import_probe,
    _python_ast_has_unresolved_open_read_call,
    _python_ast_has_unresolved_path_writer_receiver_call,
    _python_ast_has_unresolved_writer_method_call,
    _python_ast_has_untrusted_document_reader_like_call,
    _python_ast_has_untrusted_open_call_for_verify,
    _python_ast_has_wrapper_execution_call,
    _python_ast_imports_blocked_readonly_module,
    _python_ast_is_constant_false,
    _python_ast_is_non_file_writer_sink,
    _python_ast_is_none,
    _python_ast_is_static_string_expr,
    _python_ast_is_task_data_readonly_probe,
    _python_ast_node_end_lineno,
    _python_ast_node_is_inside,
    _python_ast_parent_map,
    _python_ast_uses_trusted_archive_api,
    _python_atomic_replace_path_arg_targets,
    _python_attr_is_os_path,
    _python_attribute_is_disallowed_bound_method,
    _python_attribute_is_safe_type_name_lookup,
    _python_builtin_namespace_aliases,
    _python_builtin_namespace_get_aliases,
    _python_builtin_namespace_getattribute_aliases,
    _python_builtin_namespace_getitem_aliases,
    _python_call_constructs_task_data_path,
    _python_call_dotted_name,
    _python_call_first_arg_is_task_data_path,
    _python_call_func_is_safe_readonly_getattr_consumer,
    _python_call_func_is_unbound_getattribute,
    _python_call_func_is_unbound_mapping_get,
    _python_call_func_is_unbound_mapping_getitem,
    _python_call_has_archive_write_receiver,
    _python_call_has_writer_path_argument,
    _python_call_invokes_getattr_result,
    _python_call_invokes_network_client_method,
    _python_call_invokes_network_methodcaller,
    _python_call_invokes_network_methodcaller_alias,
    _python_call_is_any_dynamic_import,
    _python_call_is_archive_handle_member_write,
    _python_call_is_archive_write_open,
    _python_call_is_bool_find_spec_probe,
    _python_call_is_compressed_open,
    _python_call_is_compressed_reader,
    _python_call_is_destructive_delete_function,
    _python_call_is_document_reader,
    _python_call_is_document_reader_dynamic_import,
    _python_call_is_dynamic_code_builtin,
    _python_call_is_dynamic_path_constructor,
    _python_call_is_filesystem_replace_callable,
    _python_call_is_find_spec_like,
    _python_call_is_find_spec_probe,
    _python_call_is_functools_partial_factory,
    _python_call_is_getattr,
    _python_call_is_getattr_mutating_call,
    _python_call_is_importlib_metadata_version,
    _python_call_is_mutating_method,
    _python_call_is_open_function,
    _python_call_is_operator_setitem,
    _python_call_is_os_listdir,
    _python_call_is_os_path_join,
    _python_call_is_os_walk,
    _python_call_is_path_constructor,
    _python_call_is_path_constructor_with_aliases,
    _python_call_is_safe_readonly_getattr,
    _python_call_is_shutil_copy_function,
    _python_call_is_shutil_copytree_function,
    _python_call_is_static_path_constructor_value,
    _python_call_is_task_data_path_probe,
    _python_call_is_trusted_archive_read_open,
    _python_call_is_trusted_archive_write_open,
    _python_call_is_trusted_pathlib_constructor,
    _python_call_is_unresolved_archive_writestr,
    _python_call_is_unresolved_open_writer_method,
    _python_call_is_xml_etree_non_file_write,
    _python_call_looks_like_document_reader,
    _python_call_matches_name,
    _python_call_mode_writes,
    _python_call_mode_writes_or_unknown,
    _python_call_opens_disallowed_mode,
    _python_call_path_args,
    _python_call_reads_unobserved_stdin,
    _python_call_returns_builtin_namespace_named_attr,
    _python_call_returns_dynamic_code_callable,
    _python_call_uses_disallowed_dynamic_callable,
    _python_compileall_targets,
    _python_configured_operator_method_name,
    _python_constant_or_bound_string,
    _python_constant_probe_arg,
    _python_default_arg_name_value_pairs,
    _python_default_arg_name_value_pairs_with_strings,
    _python_destructive_delete_aliases,
    _python_destructive_delete_arg_targets,
    _python_destructive_delete_targets,
    _python_destructive_path_variable_bindings,
    _python_dict_binding_root_name,
    _python_direct_import_probe_modules,
    _python_document_reader_arg_targets,
    _python_document_reader_attr_in_module_mapping,
    _python_document_reader_attr_on_module,
    _python_document_reader_bindings,
    _python_document_reader_call_arg_targets,
    _python_document_reader_dynamic_import_arg_is_safe,
    _python_document_reader_dynamic_import_modules,
    _python_document_reader_has_unknown_non_url_path_arg,
    _python_document_reader_has_unresolved_path_arg,
    _python_document_reader_has_untrusted_file_object_source,
    _python_document_reader_module_iter_values,
    _python_document_reader_module_literal_bindings,
    _python_document_reader_module_literal_sequence,
    _python_document_reader_module_loop_bindings,
    _python_document_reader_shadowed_names,
    _python_document_reader_source_arg_nodes,
    _python_document_reader_targets,
    _python_dynamic_code_benign_name_shadows,
    _python_dynamic_namespace_aliases,
    _python_dynamic_path_binding_names,
    _python_enumerate_targets,
    _python_executable_venv_root,
    _python_explicit_interpreter_venv_root,
    _python_expr_is_allowed_task_data_probe,
    _python_expr_is_archive_existing_member_projection,
    _python_expr_is_archive_info_filename_projection,
    _python_expr_is_archive_infolist_iter,
    _python_expr_is_archive_namelist_iter,
    _python_expr_is_builtin_namespace,
    _python_expr_is_builtin_namespace_mapping,
    _python_expr_is_builtin_open_lookup,
    _python_expr_is_builtins_or_io_module,
    _python_expr_is_destructive_delete_callable,
    _python_expr_is_direct_dynamic_namespace_call,
    _python_expr_is_dynamic_code_callable,
    _python_expr_is_dynamic_namespace,
    _python_expr_is_dynamic_path_value,
    _python_expr_is_filesystem_path_receiver,
    _python_expr_is_filesystem_replace_callable,
    _python_expr_is_import_version_probe,
    _python_expr_is_itertools_chain_from_iterable_function,
    _python_expr_is_itertools_chain_function,
    _python_expr_is_network_client_class,
    _python_expr_is_network_client_class_mapping,
    _python_expr_is_network_client_getattribute_bound_method,
    _python_expr_is_network_client_getattribute_owner,
    _python_expr_is_network_client_instance,
    _python_expr_is_network_fetch_callable,
    _python_expr_is_network_fetch_mapping_key,
    _python_expr_is_network_module_alias,
    _python_expr_is_network_module_mapping,
    _python_expr_is_numeric_projection_of_names,
    _python_expr_is_obvious_benign_dynamic_name_shadow,
    _python_expr_is_open_function,
    _python_expr_is_operator_attrgetter_callable,
    _python_expr_is_operator_named_callable,
    _python_expr_is_os_module,
    _python_expr_is_pathlib_constructor_class,
    _python_expr_is_pathlib_constructor_module_attribute,
    _python_expr_is_pathlib_pathlike_attribute,
    _python_expr_is_re_compile_callable,
    _python_expr_is_runtime_namespace,
    _python_expr_is_shutil_copy_callable,
    _python_expr_is_shutil_copytree_callable,
    _python_expr_is_stdin_object,
    _python_expr_is_sys_path,
    _python_expr_is_trusted_document_reader_callable,
    _python_expr_is_trusted_document_reader_pathlike,
    _python_expr_is_trusted_pathlib_path_object,
    _python_expr_is_type_call,
    _python_expr_is_untrusted_pathlike_binding,
    _python_expr_is_xml_etree_module,
    _python_expr_is_xml_etree_writer_receiver,
    _python_expr_iterates_path_iterables,
    _python_expr_iterates_path_objects,
    _python_expr_iterates_task_data_iterables,
    _python_expr_iterates_task_data_path_objects,
    _python_expr_iterates_walk_child_names,
    _python_expr_mutates_sys_path,
    _python_expr_returns_path_object,
    _python_expr_uses_any_name,
    _python_expr_uses_unobserved_stdin,
    _python_fileinput_call_reads_stdin,
    _python_fileinput_files_arg_is_stdin,
    _python_filesystem_replace_call_path_nodes,
    _python_filesystem_replace_callable_aliases,
    _python_filesystem_replace_path_pairs,
    _python_first_path_argument_node,
    _python_functools_partial_reader_effective_call,
    _python_getattr_aliases,
    _python_getattr_attr_name_is_safe_readonly,
    _python_getattr_default_is_safe_readonly,
    _python_has_direct_import_version_probe,
    _python_has_dynamic_namespace_mutation,
    _python_has_import_module_call,
    _python_has_socket_or_raw_network,
    _python_has_unsafe_find_spec_probe,
    _python_has_wrapper_execution,
    _python_heredoc_opener_argv_values,
    _python_immediate_lambda_non_file_arg_node_ids,
    _python_implicit_customization_candidate_paths,
    _python_implicit_customization_targets,
    _python_import_smoke_except_stmt_allowed,
    _python_import_smoke_stmt_allowed,
    _python_import_smoke_sys_path_stmt_allowed,
    _python_import_smoke_try_body_stmt_allowed,
    _python_import_smoke_value_allowed,
    _python_importlib_find_spec_aliases,
    _python_importlib_import_module_name,
    _python_inline_code_arg,
    _python_inline_import_smoke_test_is_scope_safe,
    _python_inline_verify_code_is_readonly,
    _python_invocation_argv_values,
    _python_invocation_imports_site,
    _python_io_module_aliases,
    _python_is_safe_relative_path_fragment,
    _python_itertools_path_iterator_arg_index,
    _python_json_tool_input_targets,
    _python_language_analysis_surface,
    _python_leading_env_assignment_tokens,
    _python_lexical_shadow_binding_names,
    _python_literal_dict_candidate_names,
    _python_literal_dict_names_in_ast,
    _python_literal_is_path_like,
    _python_literal_path_arg_targets,
    _python_literal_path_sequence_from_ast,
    _python_literal_path_sequence_item_value,
    _python_literal_relative_fragment_sequence_from_ast,
    _python_literal_sequence_candidate_names,
    _python_literal_sequence_escaped_candidate_names,
    _python_literal_sequence_names_in_ast,
    _python_literal_writer_path_arg_targets,
    _python_local_verify_task_output_targets,
    _python_loop_target_value_nodes_by_name,
    _python_match_pattern_binding_names,
    _python_module_attribute_mutations,
    _python_module_invocation,
    _python_module_invokes_pip,
    _python_module_probe_arg_is_safe,
    _python_module_probe_iter_values,
    _python_module_probe_literal_bindings,
    _python_module_probe_literal_sequence,
    _python_module_probe_loop_bindings,
    _python_mutated_dict_binding_names,
    _python_mutated_sequence_binding_names,
    _python_mutated_static_sequence_names,
    _python_mutating_path_method_targets,
    _python_name_assignment_counts,
    _python_names_shadowed_by_runtime_store,
    _python_non_file_writer_sink_names,
    _python_non_import_binding_names,
    _python_open_binding_names,
    _python_open_call_has_dynamic_path,
    _python_open_call_path_and_mode_position,
    _python_open_call_read_targets,
    _python_open_call_write_or_unknown_targets,
    _python_open_mode_writes,
    _python_open_write_call_targets,
    _python_open_write_handle_bindings,
    _python_operator_attrgetter_aliases,
    _python_operator_callable_aliases,
    _python_option_arity,
    _python_option_flag_present,
    _python_option_tokens,
    _python_os_filesystem_replace_aliases,
    _python_os_listdir_task_data_base,
    _python_os_walk_join_aliases,
    _python_os_walk_task_data_base,
    _python_package_command_text_from_call,
    _python_path_arg_is_dynamic,
    _python_path_constructor_literals,
    _python_path_is_protected_system_write,
    _python_path_like_binding_names,
    _python_path_probe_is_command_availability_probe,
    _python_path_probe_targets,
    _python_path_sequence_variable_bindings,
    _python_path_variable_bindings,
    _python_path_writer_constructor_aliases,
    _python_path_writer_constructor_module_alias_mutations,
    _python_path_writer_constructor_target_arg_nodes,
    _python_path_writer_method_alias_candidate_names,
    _python_path_writer_method_aliases,
    _python_path_writer_target_arg_nodes,
    _python_path_writer_targets,
    _python_pathlib_pathlike_is_monkeypatched,
    _python_paths_are_scope_task_data,
    _python_pip_unscoped_install_effects,
    _python_positional_or_keyword_pair_nodes,
    _python_py_compile_targets,
    _python_raw_tokens_have_execution_env,
    _python_re_compile_aliases,
    _python_read_targets,
    _python_readonly_import_aliases,
    _python_reassigned_names,
    _python_rebound_names_in_statements,
    _python_register_document_reader_dynamic_module_aliases,
    _python_register_document_reader_module_alias,
    _python_runtime_namespace_callable_aliases,
    _python_runtime_namespace_get_aliases,
    _python_runtime_namespace_getitem_aliases,
    _python_runtime_namespace_value_aliases,
    _python_safe_readonly_getattr_call_ids,
    _python_safe_task_data_join_arg_targets,
    _python_safe_task_data_join_or_alias_base,
    _python_save_call_target_arg_nodes,
    _python_save_call_targets,
    _python_scope_task_data_literal_targets,
    _python_script_dir,
    _python_script_path_arg,
    _python_second_path_argument_node,
    _python_sequence_binding_root_name,
    _python_shutil_copy_aliases,
    _python_shutil_copy_lexical_binding_names,
    _python_shutil_copy_path_pairs,
    _python_shutil_copytree_has_unsafe_option,
    _python_single_name_assignment,
    _python_source_has_disallowed_readonly_task_data_effect,
    _python_source_has_disallowed_task_data_output_transform_effect,
    _python_source_has_executable_package_install,
    _python_source_has_explicit_filesystem_path,
    _python_source_has_network_fetch,
    _python_source_paths_are_scope_task_data_only,
    _python_source_paths_are_scope_task_data_or_output_only,
    _python_startup_hook_is_declared_task_data,
    _python_startup_search_roots,
    _python_static_archive_member_name_value,
    _python_static_command_text,
    _python_static_container_element_or_self,
    _python_static_dict_literal_bindings,
    _python_static_loop_iter_elements,
    _python_static_mapping_dict_from_iter,
    _python_static_mapping_key_fragments_from_iter,
    _python_static_mapping_key_paths_from_iter,
    _python_static_mapping_reader_value,
    _python_static_mapping_value_loop_target_name,
    _python_static_mapping_value_payloads_from_iter,
    _python_static_path_arg_value,
    _python_static_path_sequence_value,
    _python_static_relative_fragment_sequence_value,
    _python_static_relative_path_fragment,
    _python_static_safe_dict_literal_bindings,
    _python_static_scalar_path_value,
    _python_static_sequence_element_or_self,
    _python_static_sequence_literal_bindings,
    _python_static_string_expr_value,
    _python_static_string_sequence,
    _python_static_string_value,
    _python_static_subscript_dict_value,
    _python_static_subscript_sequence_element,
    _python_static_subscript_string_key,
    _python_static_text_payload_bindings,
    _python_static_text_payload_candidate_bindings,
    _python_static_text_payload_value,
    _python_static_text_payload_value_candidates,
    _python_static_text_sequence_value,
    _python_static_write_payload_node,
    _python_static_write_payload_sequence,
    _python_static_write_payload_text_candidates,
    _python_stdin_aliases,
    _python_stdin_payload_names,
    _python_string_is_archive_member_path,
    _python_string_is_explicit_filesystem_path,
    _python_string_is_xml_selector_path,
    _python_string_literal_bindings,
    _python_string_paths_from_ast,
    _python_stringio_aliases,
    _python_subscript_root_name,
    _python_sys_argv_aliases,
    _python_sys_argv_assignment_bindings,
    _python_sys_argv_path_value_index,
    _python_sys_argv_subscript_index,
    _python_sys_path_targets_for_values,
    _python_sys_path_task_output_targets,
    _python_target_is_dynamic_namespace_mutation,
    _python_target_name_value_pairs,
    _python_target_name_value_pairs_with_strings,
    _python_targets_are_allowed_task_output_readback,
    _python_task_data_dynamic_join_context,
    _python_task_data_reader_safe_binding_names,
    _python_task_data_walk_dynamic_path_bindings,
    _python_task_output_atomic_replace_staging_targets,
    _python_text_has_ooxml_external_reference,
    _python_trusted_pathlib_open_context,
    _python_unobserved_stdin_write_targets,
    _python_unresolved_writer_redline_literal_targets,
    _python_untrusted_document_reader_alias_names,
    _python_untrusted_pathlike_binding_names,
    _python_value_child_nodes,
    _python_vars_aliases,
    _python_venv_target_paths,
    _python_venv_task_output_targets,
    _python_version_probe_tokens,
    _python_walk_child_collection_unsafe_names,
    _python_walk_collection_alias_root,
    _python_walk_collection_mutator_alias_root,
    _python_walk_collection_target_root,
    _python_walk_join_fragment_is_safe,
    _python_wave_module_aliases,
    _python_wave_open_call_path_and_mode_position,
    _python_write_items,
    _python_write_targets,
    _python_writer_arg_targets,
    _python_writer_path_variable_bindings,
    _python_xml_etree_aliases,
    _python_xml_etree_writer_receiver_names,
    _pythonpath_assignment_roots,
    _with_inline_python_argv_bindings,
    _with_python_sys_argv_aliases,
)
from clawsentry.gateway.effects.shell_model import (  # noqa: E402
    _SHELL_AWK_COMMANDS,
    _SHELL_INLINE_COMMAND_INTERPRETERS,
    _SHELL_JQ_FILE_VALUE_FLAGS,
    _SHELL_JQ_FILTER_FILE_FLAGS,
    _SHELL_JQ_NAMED_FILE_FLAGS,
    _SHELL_JQ_ONE_VALUE_FLAGS,
    _SHELL_JQ_TWO_VALUE_FLAGS,
    _SHELL_LOOP_CONTROL_COMMANDS,
    _SHELL_LOOP_READONLY_COMMANDS,
    _SHELL_LOOP_SEARCH_COMMANDS,
    _SHELL_LOOP_STDIN_FILTER_COMMANDS,
    _SHELL_REDIRECT_TOKENS,
    _SHELL_SEARCH_AUXILIARY_FILE_OPTIONS,
    _SHELL_SEARCH_EXEC_OPTIONS,
    _SHELL_SEARCH_FILE_VALUE_OPTIONS,
    _SHELL_SEARCH_INLINE_VALUE_OPTION_PREFIXES,
    _SHELL_SEARCH_PATTERN_FILE_OPTIONS,
    _SHELL_SEARCH_PATTERN_OPTIONS,
    _SHELL_SEARCH_VALUE_OPTIONS,
    _SHELL_SED_ADDRESS_RE,
    _SHELL_SED_EXEC_RE,
    _SHELL_SED_READ_RE,
    _SHELL_SED_WRITE_RE,
    _SHELL_SEGMENT_SPLIT_RE,
    _SHELL_TOOL_NAMES,
    _SHELL_WRAPPER_COMMANDS,
    _analyze_powershell,
    _analyze_shell,
    _analyze_shell_pipeline_consumers,
    _analyze_shell_read_list_probe,
    _analyze_shell_task_data_for_loops,
    _awk_inline_script_is_stdout_filter,
    _awk_inline_scripts,
    _awk_internal_write_targets,
    _awk_string_bindings,
    _awk_write_expressions,
    _looks_like_node,
    _looks_like_path_arg,
    _looks_like_powershell,
    _looks_like_python,
    _shell_awk_has_execution_wrapper,
    _shell_awk_script_files,
    _shell_awk_side_effects,
    _shell_awk_source_args,
    _shell_awk_uses_stdin_script,
    _shell_bsdtar_has_exec_program_option,
    _shell_bsdtar_has_mode,
    _shell_bsdtar_is_stdout_or_listing,
    _shell_bsdtar_option_value_target,
    _shell_bsdtar_short_option_letters,
    _shell_bsdtar_source_args,
    _shell_bsdtar_write_targets,
    _shell_c_payload,
    _shell_cat_segment_writes_stdin,
    _shell_combined_short_option_value,
    _shell_command_head,
    _shell_command_invokes_network_fetch,
    _shell_command_invokes_package_install,
    _shell_command_invokes_remote_package_reference,
    _shell_converter_write_targets,
    _shell_docx2txt_positionals,
    _shell_docx2txt_source_args,
    _shell_docx2txt_write_targets,
    _shell_effective_tokens,
    _shell_enumerate_candidate_paths,
    _shell_env_assignment,
    _shell_env_assignment_truthy,
    _shell_executable_heredoc_bodies,
    _shell_ffmpeg_file_effects,
    _shell_ffmpeg_io_args,
    _shell_ffprobe_source_args,
    _shell_file_has_indirect_list_option,
    _shell_file_source_args,
    _shell_files0_from_option_effects,
    _shell_find_output_targets,
    _shell_find_source_args,
    _shell_find_write_effects,
    _shell_for_iter_task_artifact_readonly_targets,
    _shell_git_task_output_mutation_effects,
    _shell_git_task_output_readonly_effects,
    _shell_gzip_has_unscoped_write_redirect,
    _shell_gzip_is_stdout_or_listing,
    _shell_gzip_positionals,
    _shell_gzip_stdout_source_args,
    _shell_has_executable_expansion,
    _shell_has_supported_task_data_readonly_for_loop,
    _shell_inline_command,
    _shell_inline_depth_exceeded,
    _shell_input_redirection_executes_stdin,
    _shell_jar_task_output_readonly_effects,
    _shell_java_task_output_command_effects,
    _shell_join_tokens,
    _shell_jq_source_args,
    _shell_jq_tokens_are_readonly,
    _shell_linewise_segments,
    _shell_local_build_task_output_command_effects,
    _shell_loop_body_has_executable_expansion,
    _shell_loop_body_is_supported_task_data_readonly,
    _shell_loop_body_segments_are_supported_readonly,
    _shell_loop_command_tokens_are_readonly,
    _shell_loop_iter_word_is_static_path,
    _shell_loop_representative_iter_word,
    _shell_loop_target_is_task_artifact_readonly,
    _shell_markitdown_source_args,
    _shell_maven_exec_java_task_output_command_effects,
    _shell_media_version_probe,
    _shell_output_flag_targets,
    _shell_package_command_args,
    _shell_pandoc_source_args,
    _shell_pandoc_write_targets,
    _shell_pdftotext_positionals,
    _shell_pdftotext_source_args,
    _shell_pdftotext_write_targets,
    _shell_pipeline_consumer_executes_stdin,
    _shell_pipeline_consumer_segments,
    _shell_positionals_after_options,
    _shell_pytest_task_output_command_effects,
    _shell_python_inline_task_output_verify_effects,
    _shell_python_module_markitdown_source_args,
    _shell_python_module_markitdown_tokens,
    _shell_python_module_zipfile_list_source_args,
    _shell_python_pip_effects,
    _shell_python_task_output_command_effects,
    _shell_python_venv_effects,
    _shell_rg_files_source_args,
    _shell_search_source_args,
    _shell_search_tokens_are_readonly,
    _shell_search_tokens_have_execution_option,
    _shell_sed_file_args,
    _shell_sed_find_unescaped_delimiter,
    _shell_sed_has_in_place_write,
    _shell_sed_script_files,
    _shell_sed_script_has_exec,
    _shell_sed_script_read_targets,
    _shell_sed_script_write_targets,
    _shell_sed_scripts,
    _shell_sed_side_effects,
    _shell_sed_substitution_has_flag,
    _shell_sed_substitution_replacements,
    _shell_sed_substitution_write_targets,
    _shell_sed_tokens_are_readonly,
    _shell_sed_uses_stdin_script,
    _shell_segment_consumes_unobserved_stdin,
    _shell_segment_has_visible_literal_stdout_payload,
    _shell_segment_has_write_redirect,
    _shell_segments,
    _shell_segments_from_punctuation_tokens,
    _shell_segments_with_cwd,
    _shell_skip_command_wrapper,
    _shell_skip_nice_wrapper,
    _shell_skip_stdbuf_wrapper,
    _shell_skip_sudo_wrapper,
    _shell_skip_time_wrapper,
    _shell_skip_timeout_wrapper,
    _shell_soffice_has_convert_to,
    _shell_soffice_source_args,
    _shell_soffice_write_targets,
    _shell_static_for_loops,
    _shell_static_status_normalization_segment,
    _shell_status_assignment_var,
    _shell_status_exit_segment,
    _shell_status_test_segment,
    _shell_stdin_filter_file_effects,
    _shell_stdout_path_enumerate_args,
    _shell_stdout_token_is_labelled_path,
    _shell_strings_source_args,
    _shell_substitute_loop_variable,
    _shell_task_output_local_command_effects,
    _shell_task_output_local_command_was_modeled,
    _shell_tee_segment_has_persistent_target,
    _shell_test_path_probe_targets,
    _shell_token_is_output_flag,
    _shell_token_is_status_code,
    _shell_token_is_status_var,
    _shell_token_starts_redirect,
    _shell_tokens_have_remote_package_reference,
    _shell_tokens_with_punctuation,
    _shell_touch_file_effects,
    _shell_unobserved_stdin_writer_present,
    _shell_unzip_is_stdout_or_listing,
    _shell_unzip_source_args,
    _shell_unzip_write_targets,
    _shell_uv_pip_effects,
    _shell_uv_run_effects,
    _shell_uv_sync_effects,
    _shell_uv_task_output_command_effects,
    _shell_uv_venv_effects,
    _shell_write_paths_include_future_execution_artifact,
    _shell_write_payload_texts,
    _shell_write_redirect_targets_from_tokens,
    shell_command_surface,
)
from clawsentry.gateway.effects.native_write import (  # noqa: E402
    _NATIVE_WRITE_TOOLS,
    _native_write_associated_payload_texts,
    _native_write_code_line_has_network_sink,
    _native_write_content_has_unresolved_write_reference,
    _native_write_content_read_reference_paths,
    _native_write_content_write_reference_targets,
    _native_write_has_associated_script_surface,
    _native_write_has_associated_script_target,
    _native_write_has_task_output_target,
    _native_write_line_is_network_import,
    _native_write_line_starts_with_code_call_tail,
    _native_write_path_is_patch_document_artifact,
    _native_write_payload_has_executable_script_marker,
    _native_write_payload_has_future_execution_marker,
    _native_write_payload_has_remote_network_indicator,
    _native_write_payload_has_web_script_marker,
    _native_write_payload_scan_texts,
    _native_write_payload_scan_texts_for_payload,
    _native_write_scan_text_has_shell_backtick_indicator,
    _native_write_scan_texts_have_code_network_sink,
    _native_write_scan_texts_have_destructive_indicator,
    _native_write_scan_texts_have_executable_script_marker,
    _native_write_scan_texts_have_future_execution_marker,
    _native_write_scan_texts_have_package_indicator,
    _native_write_scan_texts_have_remote_network_indicator,
    _native_write_scan_texts_have_wrapper_indicator,
    _native_write_script_target_paths,
    _native_write_target_has_script_payload,
    _native_write_target_is_task_output,
    _native_write_text_has_code_network_sink,
)
from clawsentry.gateway.effects.artifact_scope import (  # noqa: E402
    _TASK_OUTPUT_LOCAL_BUILD_COMMANDS,
    _TASK_OUTPUT_LOCAL_BUILD_JOINED_PATH_OPTIONS,
    _TASK_OUTPUT_LOCAL_BUILD_OPAQUE_VALUE_OPTIONS,
    _TASK_OUTPUT_LOCAL_BUILD_PATH_VALUE_OPTIONS,
    _TASK_OUTPUT_LOCAL_BUILD_PRIVILEGED_WRAPPERS,
    _append_task_output_env_probe_target,
    _artifact_decision_for_target,
    _artifact_decision_is_effective,
    _artifact_source_family,
    _declared_task_output_root_paths,
    _destination_is_declared_task_output_root,
    _direct_task_output_contract_violated,
    _direct_task_output_extension_contract_violated,
    _inline_interpreter_task_data_targets,
    _is_profile_contract_task_output_decision,
    _is_scope_task_artifact_readonly_path,
    _is_scope_task_compat_task_output_decision,
    _is_scope_task_data_path,
    _is_scope_task_output_path,
    _is_scope_task_output_write_target,
    _is_static_inline_python_task_data_readonly,
    _is_static_inline_python_task_data_to_task_output_transform,
    _is_static_inline_python_task_output_write,
    _java_task_data_input_target,
    _path_is_task_output_atomic_replace_staging_path,
    _path_role,
    _path_role_for_enumerate,
    _path_role_for_read,
    _pip_preinstall_args_are_scope_safe,
    _profile_task_data_decision_for_write_target,
    _scope_task_data_literal_reference_paths,
    _scope_task_output_atomic_replace_staging_target,
    _scope_task_output_build_artifact_target_for_path,
    _scope_task_output_build_child_target_for_path,
    _scope_task_output_explicit_output_target_for_path,
    _scope_task_output_or_data_read_target_for_path,
    _scope_task_output_target_for_path,
    _target_is_effective_scope_task_data_read,
    _target_is_effective_scope_task_output,
    _task_output_decision_is_derived_parent,
    _task_output_extension_contract_violated,
    _task_output_parent_escape_contract_violated,
    _task_output_write_decision_can_support_readonly_fallback,
    _uv_global_options_are_scope_safe,
    _uv_pip_install_args_are_scope_safe,
    _uv_pip_install_path_arg_is_scope_safe,
    _uv_pip_install_positional_arg_is_scope_safe,
    _uv_pip_install_python_arg_is_scope_safe,
    _uv_python_option_value_is_scope_safe,
    _uv_task_output_lane_args_are_scope_safe,
    _uv_unknown_option_value_is_scope_safe,
    artifact_families,
)
