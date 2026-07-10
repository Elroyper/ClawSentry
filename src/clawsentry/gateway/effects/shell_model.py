"""Shell/PowerShell command modeling subsystem for the effect normalizer.

Mechanically split from normalizer.py (single shared late-bound namespace;
see the bottom import block). Behavior-preserving: do not reorder segments.
"""

from __future__ import annotations

import posixpath
import re
import shlex
from pathlib import Path, PurePosixPath
from typing import Any
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
    TASK_DATA_COMPAT_ROOTS,
    hard_path_role,
    is_skill_package_path,
    normalize_task_artifact_path,
    resolve_scope_task_artifact,
)
_SHELL_TOOL_NAMES = {"bash", "shell", "terminal", "command", "exec", "sh", "zsh"}
_SHELL_SEGMENT_SPLIT_RE = re.compile(r"\s*(?:&&|\|\||;)\s*")
_SHELL_WRAPPER_COMMANDS = frozenset({"sudo", "command", "nohup", "time"})
_SHELL_INLINE_COMMAND_INTERPRETERS = frozenset({"bash", "sh", "zsh"})
_SHELL_AWK_COMMANDS = frozenset({"awk", "gawk", "mawk", "nawk"})


def shell_command_surface(text: str) -> str:
    """Return shell text with heredoc bodies removed for side-effect detection."""

    return _strip_shell_heredoc_bodies(text or "")


def _analyze_shell(text: str, *, analyze_for_loops: bool = True) -> dict[str, Any]:
    effects: list[str] = []
    sources: list[ActionEffectTarget] = []
    targets: list[ActionEffectTarget] = []
    rules: list[str] = []
    wrappers: list[str] = []
    confidence = "low"
    analysis_state = "complete"
    command_surface = shell_command_surface(text)
    if _shell_inline_depth_exceeded(command_surface):
        _add_effect(effects, "command.exec")
        _add_rule(rules, "wrapper_chain_unresolved")
        _add_rule(rules, "shell_inline_depth_exceeded")
        confidence = _max_confidence(confidence, "high")
    if _shell_has_executable_expansion(command_surface):
        _add_effect(effects, "command.exec")
        _add_rule(rules, "wrapper_chain_unresolved")
        _add_rule(rules, "shell_executable_expansion")
        confidence = _max_confidence(confidence, "high")

    if re.search(r"\b(?:bash|sh|zsh)\s+-[^;|&]*c\b", text):
        wrappers.append("shell -c")

    heredoc_write = "<<" in text and re.search(r"(?:^|\s)(?:cat|tee)\b[^;&|]*(?:>|tee)\s*", text)
    shell_write_payloads = _shell_write_payload_texts(text)
    shell_write_payload_has_shebang = any(
        _native_write_payload_has_executable_script_marker(payload_text)
        for payload_text in shell_write_payloads
    )
    shell_write_payload_is_script = any(
        _native_write_payload_has_future_execution_marker(payload_text)
        for payload_text in shell_write_payloads
    )
    redirection_paths = _redirection_paths(text)
    if redirection_paths:
        _add_effect(effects, "filesystem.write")
        targets.extend(
            _write_target_for_path(path, payload_is_script=shell_write_payload_is_script)
            for path in redirection_paths
        )
        _add_rule(rules, "shell_heredoc_write" if heredoc_write else "shell_redirection_write")
        confidence = "high"

    tee_paths = _tee_paths(text)
    written_script_paths = _normalized_path_set([*redirection_paths, *tee_paths])
    if (
        not shell_write_payloads
        and _shell_unobserved_stdin_writer_present(command_surface)
        and _shell_write_paths_include_future_execution_artifact([*redirection_paths, *tee_paths])
    ):
        _add_rule(rules, "shell_unobserved_stdin_future_exec_write")

    input_redirection_paths = _input_redirection_paths(text)
    stdin_executes = _shell_input_redirection_executes_stdin(command_surface)
    if input_redirection_paths:
        _add_effect(effects, "filesystem.read")
        targets.extend(
            _target_for_path(
                path,
                role=(
                    "future_execution.artifact"
                    if stdin_executes and _normalize_shell_compare_path(path) in written_script_paths
                    else _path_role_for_read(path)
                ),
            )
            for path in input_redirection_paths
        )
        _add_rule(rules, "shell_input_redirection_read")
        confidence = _max_confidence(confidence, "medium")
        if stdin_executes:
            _add_effect(effects, "command.exec")
            _add_rule(rules, "shell_input_redirection_exec_consumer")
            _add_rule(rules, "wrapper_chain_unresolved")
            confidence = _max_confidence(confidence, "high")
            if any(
                _normalize_shell_compare_path(path) in written_script_paths
                for path in input_redirection_paths
            ):
                _add_rule(rules, "interpreter_script_execution")

    if tee_paths:
        _add_effect(effects, "filesystem.write")
        targets.extend(
            _write_target_for_path(path, payload_is_script=shell_write_payload_is_script)
            for path in tee_paths
        )
        _add_rule(rules, "shell_tee_write")
        confidence = "high"
    if shell_write_payload_has_shebang and _native_write_has_associated_script_target(targets):
        _add_rule(rules, "generated_script_shebang")

    converter_writes = _shell_converter_write_targets(command_surface)
    if converter_writes["targets"] or converter_writes["unknown_write"]:
        _add_effect(effects, "filesystem.write")
        targets.extend(_target_for_path(path) for path in converter_writes["targets"])
        _add_rule(rules, "shell_converter_write")
        confidence = _max_confidence(confidence, "medium")

    dd_paths = _dd_output_paths(text)
    if dd_paths:
        _add_effect(effects, "filesystem.write")
        targets.extend(_target_for_path(path) for path in dd_paths)
        _add_rule(rules, "dd_output_write")
        if _shell_write_paths_include_future_execution_artifact(dd_paths):
            _add_rule(rules, "dd_unobserved_future_exec_write")
        confidence = "high"

    if re.search(r"\b(?:base64|xxd)\b[^;&|]*(?:-d|-r|--decode)", text) and redirection_paths:
        _add_effect(effects, "encoded_payload.materialization")
        _add_rule(rules, "decode_to_file_write")
        confidence = "high"

    copy_operations = _copy_like_operations(command_surface)
    if copy_operations:
        _add_effect(effects, "filesystem.read")
        _add_effect(effects, "filesystem.write")
        for operation_sources, destination in copy_operations:
            source_targets = [
                _target_for_path(
                    path,
                    role=_path_role_for_read(path),
                    io_direction="source",
                )
                for path in operation_sources
            ]
            sources.extend(source_targets)
            targets.extend(source_targets)
            destination_target = _target_for_path(destination, io_direction="target")
            if _path_has_script_asset_directory(destination):
                destination_target = destination_target.model_copy(
                    update={"path_role": "future_execution.artifact"}
                )
                _add_rule(rules, "copy_to_script_asset_tree")
            targets.append(destination_target)
            if _task_output_extension_contract_violated(
                operation_sources,
                destination,
                destination_target,
            ):
                _add_rule(rules, "task_output_contract_violation")
            if any(
                source_target.path_role == SCOPE_TASK_DATA_READ_PATH_ROLE
                for source_target in source_targets
            ) and destination_target.path_role != SCOPE_TASK_OUTPUT_PATH_ROLE:
                _add_rule(rules, "task_data_copy_to_unscoped_path")
        _add_rule(rules, "shell_copy_write")
        confidence = _max_confidence(confidence, "medium")

    archive_result = _analyze_encrypted_archive_creation(text)
    if archive_result["rules"]:
        _add_effect(effects, "filesystem.write")
        targets.extend(_target_for_path(path) for path in archive_result["targets"])
        _merge(rules, archive_result["rules"])
        confidence = _max_confidence(confidence, archive_result["confidence"])

    directory_create_targets = _directory_create_targets(text)
    if directory_create_targets:
        _add_effect(effects, "filesystem.write")
        targets.extend(
            _target_for_path(
                path,
                role=SCOPE_TASK_OUTPUT_PATH_ROLE
                if _is_scope_task_output_path(path)
                else "workspace_directory",
            )
            for path in directory_create_targets
        )
        _add_rule(rules, "shell_directory_create")
        confidence = _max_confidence(confidence, "medium")

    archive_targets = _plain_archive_creation_targets(text)
    if archive_targets:
        _add_effect(effects, "filesystem.write")
        targets.extend(_target_for_path(path) for path in archive_targets)
        _add_rule(rules, "archive_creation_write")
        confidence = _max_confidence(confidence, "medium")

    script_targets = _interpreter_script_targets(text)
    if script_targets:
        _add_effect(effects, "command.exec")
        for path in script_targets:
            role = _interpreter_script_target_role(path, written_script_paths)
            targets.append(_target_for_path(path, role=role))
        _add_rule(rules, "interpreter_script_execution")
        confidence = _max_confidence(confidence, "medium")

    python_startup_targets = _python_implicit_customization_targets(command_surface)
    if python_startup_targets:
        _add_effect(effects, "command.exec")
        _add_effect(effects, "filesystem.read")
        targets.extend(python_startup_targets)
        _add_rule(rules, "python_implicit_sitecustomize")
        confidence = _max_confidence(confidence, "high")

    inline_task_data_targets = _inline_interpreter_task_data_targets(text)
    if inline_task_data_targets:
        if not (
            _is_static_inline_python_task_data_readonly(text)
            or _is_static_inline_python_task_data_to_task_output_transform(text)
            or _is_static_inline_python_task_output_write(text)
            or _is_static_inline_python_unresolved_writer_review(text)
        ):
            _add_effect(effects, "command.exec")
            targets.extend(
                _target_for_path(path, role=_path_role_for_read(path))
                for path in inline_task_data_targets
            )
            _add_rule(rules, "wrapper_chain_unresolved")
            confidence = _max_confidence(confidence, "high")

    read_probe_result = _analyze_shell_read_list_probe(command_surface)
    _merge(effects, read_probe_result["effects"])
    targets.extend(read_probe_result["targets"])
    _merge(rules, read_probe_result["rules"])
    confidence = _max_confidence(confidence, read_probe_result["confidence"])

    pipeline_result = _analyze_shell_pipeline_consumers(command_surface)
    _merge(effects, pipeline_result["effects"])
    targets.extend(pipeline_result["targets"])
    _merge(rules, pipeline_result["rules"])
    confidence = _max_confidence(confidence, pipeline_result["confidence"])

    if analyze_for_loops:
        loop_result = _analyze_shell_task_data_for_loops(command_surface)
        _merge(effects, loop_result["effects"])
        targets.extend(loop_result["targets"])
        _merge(rules, loop_result["rules"])
        confidence = _max_confidence(confidence, loop_result["confidence"])

    awk_write_targets = _awk_internal_write_targets(text)
    if awk_write_targets:
        _add_effect(effects, "filesystem.write")
        targets.extend(_target_for_path(path) for path in awk_write_targets)
        _add_rule(rules, "awk_file_write")
        confidence = _max_confidence(confidence, "medium")

    if _shell_command_invokes_network_fetch(command_surface):
        _add_effect(effects, "network.fetch")
        _add_rule(rules, "network_equivalent_fetch")
        confidence = _max_confidence(confidence, "high")
        download_targets = _network_download_targets(command_surface)
        if download_targets:
            _add_effect(effects, "filesystem.write")
            targets.extend(_target_for_path(path) for path in download_targets)
            _add_rule(rules, "network_download_write")
            confidence = _max_confidence(confidence, "high")

    if re.search(r"\brm\s+-[^\s;|&]*r[^\s;|&]*f|\brm\s+-[^\s;|&]*f[^\s;|&]*r", text):
        _add_effect(effects, "filesystem.write")
        _add_rule(rules, "destructive_delete")
        delete_targets = _rm_delete_targets(text)
        if delete_targets:
            targets.extend(
                _target_for_path(path, io_direction="target")
                for path in delete_targets
            )
            _add_rule(rules, "destructive_delete_target_modeled")
        else:
            _add_rule(rules, "destructive_delete_target_unresolved")
        confidence = _max_confidence(confidence, "high")

    if (
        "filesystem.write" in effects
        and _native_write_has_associated_script_surface(targets, "\n".join(shell_write_payloads))
        and any(
        _native_write_payload_has_remote_network_indicator(payload_text)
        for payload_text in shell_write_payloads
        )
    ):
        _add_rule(rules, "associated_script_network_indicator")

    return {
        "effects": effects,
        "sources": sources,
        "targets": targets,
        "rules": rules,
        "wrappers": wrappers,
        "confidence": confidence,
        "analysis_state": analysis_state,
    }


def _analyze_shell_read_list_probe(text: str) -> dict[str, Any]:
    effects: list[str] = []
    targets: list[ActionEffectTarget] = []
    rules: list[str] = []
    confidence = "low"

    read_commands = {
        "cat",
        "cut",
        "head",
        "tail",
        "less",
        "more",
        "nl",
        "file",
        "strings",
        "wc",
        "pdfinfo",
    }
    enumerate_commands = {"ls", "find"}
    probe_commands = {"which", "type", "pwd", "whoami", "id", "uname", "command"}
    no_effect_stdout_commands = {"basename", "break", "continue", "dirname", "echo", "false", "printf", "tr", "true", ":"}
    modeled_effect_commands = {
        *_NETWORK_FETCH_COMMANDS,
        "base64",
        "cp",
        "dd",
        "gzip",
        "gunzip",
        "install",
        "mkdir",
        "mv",
        "rm",
        "shred",
        "srm",
        "tar",
        "tee",
        "xxd",
        "zcat",
        "zip",
    }
    known_local_exec_commands = {"configure"}
    skip_for_syntax_segments = _shell_has_supported_task_data_readonly_for_loop(text)
    previous_task_output_local_command = False
    status_normalization_vars: set[str] = set()

    for raw_tokens, shell_cwd in _shell_segments_with_cwd(text):
        status_var = _shell_status_assignment_var(raw_tokens)
        if status_var and previous_task_output_local_command:
            status_normalization_vars.add(status_var)
            previous_task_output_local_command = False
            continue
        tokens = _shell_effective_tokens(raw_tokens)
        if _shell_static_status_normalization_segment(tokens, status_normalization_vars):
            if tokens and tokens[0] == "fi":
                status_normalization_vars.clear()
            previous_task_output_local_command = False
            continue
        if status_normalization_vars:
            status_normalization_vars.clear()
        previous_task_output_local_command = False
        if not tokens:
            continue
        command = Path(tokens[0]).name.lower()
        task_output_command = _shell_task_output_local_command_effects(
            tokens,
            shell_cwd,
            raw_tokens=raw_tokens,
            shell_text=text,
        )
        if task_output_command["effects"]:
            _merge(effects, task_output_command["effects"])
            targets.extend(task_output_command["targets"])
            _merge(rules, task_output_command["rules"])
            confidence = _max_confidence(confidence, task_output_command["confidence"])
            previous_task_output_local_command = _shell_task_output_local_command_was_modeled(
                task_output_command
            )
            continue
        if skip_for_syntax_segments and command in {"for", "do", "done"}:
            continue
        if skip_for_syntax_segments and any("$" in token for token in tokens):
            continue
        non_option_args = [token for token in tokens[1:] if token and not token.startswith("-")]
        if command in read_commands:
            if command == "file" and _shell_file_has_indirect_list_option(tokens):
                _add_effect(effects, "command.exec")
                _add_rule(rules, "wrapper_chain_unresolved")
                _add_rule(rules, "shell_file_indirect_list_read")
                confidence = _max_confidence(confidence, "high")
            if command == "wc":
                wc_files0 = _shell_files0_from_option_effects(tokens)
                if wc_files0["stdin"]:
                    _add_effect(effects, "command.exec")
                    _add_rule(rules, "wrapper_chain_unresolved")
                    _add_rule(rules, "shell_wc_files0_from_stdin")
                    confidence = _max_confidence(confidence, "high")
                if wc_files0["read_targets"]:
                    _add_effect(effects, "filesystem.read")
                    for path in wc_files0["read_targets"][:3]:
                        role = _path_role_for_read(path, cwd=shell_cwd)
                        targets.append(_target_for_path(path, role=role, cwd=shell_cwd))
                        if role == "credential_source" or _path_has_credential_marker(path):
                            _add_rule(rules, "credential_read")
                    _add_rule(rules, "shell_read_probe")
                    confidence = _max_confidence(confidence, "medium")
            source_args = (
                _shell_strings_source_args(tokens)
                if command == "strings"
                else _shell_file_source_args(tokens)
                if command == "file"
                else _read_probe_source_args(non_option_args)
            )
            source_paths = [
                path for path in source_args[:3]
                if path not in {"-", "/dev/null"} and _looks_like_path_arg(path)
            ]
            if source_paths:
                _add_effect(effects, "filesystem.read")
                for path in source_paths:
                    role = _path_role_for_read(path, cwd=shell_cwd)
                    targets.append(_target_for_path(path, role=role, cwd=shell_cwd))
                    if role == "credential_source" or _path_has_credential_marker(path):
                        _add_rule(rules, "credential_read")
                _add_rule(rules, "shell_read_probe")
                confidence = _max_confidence(confidence, "medium")
        elif command in {"rg", "ripgrep"} and "--files" in tokens[1:]:
            _add_effect(effects, "filesystem.enumerate")
            candidate_paths = [
                arg for arg in _shell_rg_files_source_args(tokens)
                if _looks_like_path_arg(arg)
            ] or ["."]
            targets.extend(
                _target_for_path(
                    path,
                    role=_path_role_for_enumerate(path, cwd=shell_cwd),
                    cwd=shell_cwd,
                )
                for path in candidate_paths[:3]
            )
            _add_rule(rules, "shell_enumerate_probe")
            confidence = _max_confidence(confidence, "medium")
        elif command in {"grep", "egrep", "fgrep", "rg", "ripgrep", "ag"}:
            candidate_paths = [
                arg for arg in _shell_search_source_args(command, tokens)
                if _looks_like_path_arg(arg)
            ]
            if candidate_paths:
                _add_effect(effects, "filesystem.read")
                for path in candidate_paths[:3]:
                    role = _path_role_for_read(path, cwd=shell_cwd)
                    targets.append(_target_for_path(path, role=role, cwd=shell_cwd))
                    if role == "credential_source" or _path_has_credential_marker(path):
                        _add_rule(rules, "credential_read")
                _add_rule(rules, "shell_read_probe")
                confidence = _max_confidence(confidence, "medium")
            elif _is_shell_capability_probe(command, tokens, text):
                _add_effect(effects, "environment.probe")
                probe = " ".join(tokens[:2]) if len(tokens) > 1 else command
                targets.append(_probe_target(probe))
                _add_rule(rules, "shell_capability_probe")
                _append_task_output_env_probe_target(targets, rules, shell_cwd)
                confidence = _max_confidence(confidence, "medium")
        elif command == "jq":
            candidate_paths = [
                arg for arg in _shell_jq_source_args(tokens)
                if _looks_like_path_arg(arg)
            ]
            if candidate_paths:
                _add_effect(effects, "filesystem.read")
                for path in candidate_paths[:3]:
                    role = _path_role_for_read(path)
                    targets.append(_target_for_path(path, role=role))
                    if role == "credential_source" or _path_has_credential_marker(path):
                        _add_rule(rules, "credential_read")
                _add_rule(rules, "shell_read_probe")
                confidence = _max_confidence(confidence, "medium")
        elif command == "sed":
            sed_side_effects = _shell_sed_side_effects(tokens, shell_cwd=shell_cwd)
            _merge(effects, sed_side_effects["effects"])
            targets.extend(sed_side_effects["targets"])
            _merge(rules, sed_side_effects["rules"])
            confidence = _max_confidence(confidence, sed_side_effects["confidence"])
            candidate_paths = [
                arg for arg in _read_probe_source_args(non_option_args[1:])
                if _looks_like_path_arg(arg)
            ]
            if candidate_paths:
                _add_effect(effects, "filesystem.read")
                targets.extend(
                    _target_for_path(
                        path,
                        role=_path_role_for_read(path, cwd=shell_cwd),
                        cwd=shell_cwd,
                    )
                    for path in candidate_paths[:3]
                )
                _add_rule(rules, "shell_read_probe")
                confidence = _max_confidence(confidence, "medium")
            elif _is_shell_capability_probe(command, tokens, text):
                _add_effect(effects, "environment.probe")
                probe = " ".join(tokens[:2]) if len(tokens) > 1 else command
                targets.append(_probe_target(probe))
                _add_rule(rules, "shell_capability_probe")
                _append_task_output_env_probe_target(targets, rules, shell_cwd)
                confidence = _max_confidence(confidence, "medium")
        elif command in _SHELL_AWK_COMMANDS:
            awk_side_effects = _shell_awk_side_effects(tokens, raw_tokens=raw_tokens)
            _merge(effects, awk_side_effects["effects"])
            targets.extend(awk_side_effects["targets"])
            _merge(rules, awk_side_effects["rules"])
            confidence = _max_confidence(confidence, awk_side_effects["confidence"])
            candidate_paths = [
                arg for arg in _read_probe_source_args(non_option_args[1:])
                if _looks_like_path_arg(arg)
            ]
            if candidate_paths:
                _add_effect(effects, "filesystem.read")
                targets.extend(
                    _target_for_path(path, role=_path_role_for_read(path))
                    for path in candidate_paths[:3]
                )
                _add_rule(rules, "shell_read_probe")
                confidence = _max_confidence(confidence, "medium")
            elif _is_shell_capability_probe(command, tokens, text):
                _add_effect(effects, "environment.probe")
                probe = " ".join(tokens[:2]) if len(tokens) > 1 else command
                targets.append(_probe_target(probe))
                _add_rule(rules, "shell_capability_probe")
                _append_task_output_env_probe_target(targets, rules, shell_cwd)
                confidence = _max_confidence(confidence, "medium")
        elif command == "pdftotext":
            candidate_paths = [
                arg for arg in _shell_pdftotext_source_args(tokens)
                if _looks_like_path_arg(arg)
            ]
            if candidate_paths:
                _add_effect(effects, "filesystem.read")
                targets.extend(
                    _target_for_path(path, role=_path_role_for_read(path))
                    for path in candidate_paths[:3]
                )
                _add_rule(rules, "shell_read_probe")
                confidence = _max_confidence(confidence, "medium")
        elif command == "pandoc":
            candidate_paths = [
                arg for arg in _shell_pandoc_source_args(tokens)
                if _looks_like_path_arg(arg)
            ]
            if candidate_paths:
                _add_effect(effects, "filesystem.read")
                targets.extend(
                    _target_for_path(path, role=_path_role_for_read(path))
                    for path in candidate_paths[:3]
                )
                _add_rule(rules, "shell_read_probe")
                confidence = _max_confidence(confidence, "medium")
        elif command == "markitdown":
            candidate_paths = [
                arg for arg in _shell_markitdown_source_args(tokens)
                if _looks_like_path_arg(arg)
            ]
            if candidate_paths:
                _add_effect(effects, "filesystem.read")
                targets.extend(
                    _target_for_path(path, role=_path_role_for_read(path))
                    for path in candidate_paths[:3]
                )
                _add_rule(rules, "shell_read_probe")
                confidence = _max_confidence(confidence, "medium")
        elif command in {"python", "python3"}:
            candidate_paths = [
                arg for arg in _shell_python_module_markitdown_source_args(tokens)
                if _looks_like_path_arg(arg)
            ]
            zipfile_paths = [
                arg for arg in _shell_python_module_zipfile_list_source_args(tokens)
                if _looks_like_path_arg(arg)
            ]
            if zipfile_paths:
                _add_effect(effects, "filesystem.read")
                targets.extend(
                    _target_for_path(path, role=_path_role_for_read(path))
                    for path in zipfile_paths[:3]
                )
                _add_rule(rules, "shell_read_probe")
                confidence = _max_confidence(confidence, "medium")
            if candidate_paths:
                _add_effect(effects, "filesystem.read")
                targets.extend(
                    _target_for_path(path, role=_path_role_for_read(path))
                    for path in candidate_paths[:3]
                )
                _add_rule(rules, "shell_read_probe")
                confidence = _max_confidence(confidence, "medium")
            if not zipfile_paths and not candidate_paths and _is_shell_capability_probe(command, tokens, text):
                _add_effect(effects, "environment.probe")
                probe = " ".join(tokens[:2]) if len(tokens) > 1 else command
                targets.append(_probe_target(probe))
                _add_rule(rules, "shell_capability_probe")
                _append_task_output_env_probe_target(targets, rules, shell_cwd)
                confidence = _max_confidence(confidence, "medium")
        elif command == "ffprobe":
            source_paths = _shell_ffprobe_source_args(tokens)
            remote_sources = [path for path in source_paths if _URL_RE.match(path)]
            local_sources = [path for path in source_paths if not _URL_RE.match(path)]
            if remote_sources:
                _add_effect(effects, "network.fetch")
                _add_rule(rules, "network_equivalent_fetch")
                confidence = _max_confidence(confidence, "high")
            if local_sources:
                _add_effect(effects, "filesystem.read")
                targets.extend(
                    _target_for_path(path, role=_path_role_for_read(path))
                    for path in local_sources[:3]
                )
                _add_rule(rules, "shell_read_probe")
                confidence = _max_confidence(confidence, "medium")
            elif _shell_media_version_probe(tokens):
                _add_effect(effects, "environment.probe")
                targets.append(_probe_target(command))
                _add_rule(rules, "shell_capability_probe")
                confidence = _max_confidence(confidence, "medium")
        elif command == "ffmpeg":
            media_effects = _shell_ffmpeg_file_effects(tokens)
            _merge(effects, media_effects["effects"])
            targets.extend(media_effects["targets"])
            _merge(rules, media_effects["rules"])
            confidence = _max_confidence(confidence, media_effects["confidence"])
        elif command == "touch":
            touch_effects = _shell_touch_file_effects(tokens)
            _merge(effects, touch_effects["effects"])
            targets.extend(touch_effects["targets"])
            _merge(rules, touch_effects["rules"])
            confidence = _max_confidence(confidence, touch_effects["confidence"])
        elif command == "unzip":
            candidate_paths = [
                arg for arg in _shell_unzip_source_args(tokens)
                if _looks_like_path_arg(arg)
            ]
            if candidate_paths:
                _add_effect(effects, "filesystem.read")
                targets.extend(
                    _target_for_path(path, role=_path_role_for_read(path))
                    for path in candidate_paths[:3]
                )
                _add_rule(rules, "shell_read_probe")
                confidence = _max_confidence(confidence, "medium")
        elif command in {"gzip", "gunzip", "zcat"}:
            candidate_paths = [
                arg for arg in _shell_gzip_stdout_source_args(command, tokens)
                if _looks_like_path_arg(arg)
            ]
            unscoped_redirect = _shell_gzip_has_unscoped_write_redirect(tokens, shell_cwd)
            if candidate_paths:
                _add_effect(effects, "filesystem.read")
                targets.extend(
                    _target_for_path(path, role=_path_role_for_read(path))
                    for path in candidate_paths[:3]
                )
                _add_rule(rules, "shell_read_probe")
                confidence = _max_confidence(confidence, "medium")
                if unscoped_redirect:
                    _add_effect(effects, "command.exec")
                    _add_rule(rules, "wrapper_chain_unresolved")
                    _add_rule(rules, "shell_gzip_redirect_unresolved")
                    confidence = _max_confidence(confidence, "high")
            else:
                write_like_sources = [
                    arg for arg in _shell_gzip_positionals(tokens)
                    if _looks_like_path_arg(arg)
                ]
                if write_like_sources:
                    _add_effect(effects, "command.exec")
                    _add_effect(effects, "filesystem.read")
                    _add_rule(rules, "wrapper_chain_unresolved")
                    _add_rule(rules, "shell_gzip_write_unresolved")
                    targets.extend(
                        _target_for_path(path, role=_path_role_for_read(path))
                        for path in write_like_sources[:3]
                    )
                    confidence = _max_confidence(confidence, "high")
        elif command == "bsdtar":
            if _shell_bsdtar_has_exec_program_option(tokens):
                _add_effect(effects, "command.exec")
                _add_rule(rules, "wrapper_chain_unresolved")
                _add_rule(rules, "shell_bsdtar_exec_program")
                confidence = _max_confidence(confidence, "high")
            reads_archive = _shell_bsdtar_is_stdout_or_listing(tokens) or _shell_bsdtar_has_mode(
                tokens,
                long_names=frozenset({"--extract", "--get"}),
                short_letters="x",
            )
            candidate_paths = [
                arg for arg in _shell_bsdtar_source_args(tokens)
                if reads_archive and _looks_like_path_arg(arg)
            ]
            if candidate_paths:
                _add_effect(effects, "filesystem.read")
                targets.extend(
                    _target_for_path(path, role=_path_role_for_read(path))
                    for path in candidate_paths[:3]
                )
                _add_rule(rules, "shell_read_probe")
                confidence = _max_confidence(confidence, "medium")
        elif command == "docx2txt":
            candidate_paths = [
                arg for arg in _shell_docx2txt_source_args(tokens)
                if _looks_like_path_arg(arg)
            ]
            if candidate_paths:
                _add_effect(effects, "filesystem.read")
                targets.extend(
                    _target_for_path(path, role=_path_role_for_read(path))
                    for path in candidate_paths[:3]
                )
                _add_rule(rules, "shell_read_probe")
                confidence = _max_confidence(confidence, "medium")
        elif command in {"soffice", "libreoffice"}:
            candidate_paths = [
                arg for arg in _shell_soffice_source_args(tokens)
                if _looks_like_path_arg(arg)
            ]
            if candidate_paths:
                _add_effect(effects, "filesystem.read")
                targets.extend(
                    _target_for_path(path, role=_path_role_for_read(path))
                    for path in candidate_paths[:3]
                )
                _add_rule(rules, "shell_read_probe")
                confidence = _max_confidence(confidence, "medium")
            else:
                _add_effect(effects, "command.exec")
                _add_rule(rules, "wrapper_chain_unresolved")
                _add_rule(rules, "shell_unresolved_command_segment")
                segment_paths = [arg for arg in tokens[1:] if _looks_like_path_arg(arg)]
                targets.extend(
                    _target_for_path(path, role=_path_role(path))
                    for path in segment_paths[:3]
                )
                confidence = _max_confidence(confidence, "high")
        elif command in {"test", "[", "[["}:
            candidate_paths = _shell_test_path_probe_targets(tokens)
            if candidate_paths:
                _add_effect(effects, "filesystem.read")
                targets.extend(
                    _target_for_path(path, role=_path_role_for_read(path))
                    for path in candidate_paths[:3]
                )
                _add_rule(rules, "shell_path_metadata_probe")
                confidence = _max_confidence(confidence, "medium")
        elif command in {"sort", "uniq"}:
            filter_effects = _shell_stdin_filter_file_effects(command, tokens)
            if filter_effects["exec_rules"]:
                _add_effect(effects, "command.exec")
                for path in filter_effects["exec_targets"][:3]:
                    targets.append(_target_for_path(path, role=_path_role(path)))
                _add_rule(rules, "wrapper_chain_unresolved")
                _merge(rules, filter_effects["exec_rules"])
                confidence = _max_confidence(confidence, "high")
            if filter_effects["read_targets"]:
                _add_effect(effects, "filesystem.read")
                for path in filter_effects["read_targets"][:3]:
                    role = _path_role_for_read(path)
                    targets.append(_target_for_path(path, role=role))
                    if role == "credential_source":
                        _add_rule(rules, "credential_read")
                _add_rule(rules, "shell_read_probe")
                confidence = _max_confidence(confidence, "medium")
            if filter_effects["write_targets"]:
                _add_effect(effects, "filesystem.write")
                targets.extend(
                    _target_for_path(path)
                    for path in filter_effects["write_targets"][:3]
                )
                _add_rule(rules, "shell_filter_write")
                confidence = _max_confidence(confidence, "medium")
        elif command in enumerate_commands:
            source_args = _shell_find_source_args(tokens) if command == "find" else non_option_args
            if command == "find" and any(
                token in {"-exec", "-execdir", "-ok", "-okdir"}
                or token.startswith(("-exec", "-ok"))
                for token in tokens[1:]
            ):
                _add_effect(effects, "command.exec")
                candidate_paths = _shell_enumerate_candidate_paths(command, source_args)
                targets.extend(
                    _target_for_path(
                        path,
                        role=_path_role_for_enumerate(path, cwd=shell_cwd),
                        cwd=shell_cwd,
                    )
                    for path in candidate_paths[:3]
                )
                _add_rule(rules, "wrapper_chain_unresolved")
                confidence = _max_confidence(confidence, "high")
                continue
            if command == "find":
                find_write = _shell_find_write_effects(tokens, source_args)
                _merge(effects, find_write["effects"])
                targets.extend(find_write["targets"])
                _merge(rules, find_write["rules"])
                confidence = _max_confidence(confidence, find_write["confidence"])
            _add_effect(effects, "filesystem.enumerate")
            candidate_paths = _shell_enumerate_candidate_paths(command, source_args)
            targets.extend(
                _target_for_path(
                    path,
                    role=_path_role_for_enumerate(path, cwd=shell_cwd),
                    cwd=shell_cwd,
                )
                for path in candidate_paths[:3]
            )
            _add_rule(rules, "shell_enumerate_probe")
            confidence = _max_confidence(confidence, "medium")
        elif command in probe_commands:
            _add_effect(effects, "environment.probe")
            probe = " ".join(tokens[:2]) if len(tokens) > 1 else command
            targets.append(_probe_target(probe))
            _add_rule(rules, "shell_capability_probe")
            _append_task_output_env_probe_target(targets, rules, shell_cwd)
            confidence = _max_confidence(confidence, "medium")
        elif command in no_effect_stdout_commands:
            glob_paths = _shell_stdout_path_enumerate_args(command, tokens)
            if glob_paths:
                _add_effect(effects, "filesystem.enumerate")
                targets.extend(
                    _target_for_path(
                        path,
                        role=_path_role_for_enumerate(path, cwd=shell_cwd),
                        cwd=shell_cwd,
                    )
                    for path in glob_paths[:3]
                )
                _add_rule(rules, "shell_enumerate_probe")
                confidence = _max_confidence(confidence, "medium")
            continue
        elif command in known_local_exec_commands:
            _add_effect(effects, "command.exec")
            confidence = _max_confidence(confidence, "medium")
        elif command in modeled_effect_commands:
            continue
        elif _is_shell_capability_probe(command, tokens, text):
            _add_effect(effects, "environment.probe")
            probe = " ".join(tokens[:2]) if len(tokens) > 1 else command
            targets.append(_probe_target(probe))
            _add_rule(rules, "shell_capability_probe")
            _append_task_output_env_probe_target(targets, rules, shell_cwd)
            confidence = _max_confidence(confidence, "medium")
        else:
            _add_effect(effects, "command.exec")
            _add_rule(rules, "wrapper_chain_unresolved")
            _add_rule(rules, "shell_unresolved_command_segment")
            segment_paths = [arg for arg in tokens[1:] if _looks_like_path_arg(arg)]
            targets.extend(
                _target_for_path(path, role=_path_role(path))
                for path in segment_paths[:3]
            )
            confidence = _max_confidence(confidence, "high")

    return {
        "effects": effects,
        "targets": targets,
        "rules": rules,
        "confidence": confidence,
    }


def _shell_has_supported_task_data_readonly_for_loop(text: str) -> bool:
    for variable, iter_words, body in _shell_static_for_loops(text):
        iter_targets = _shell_for_iter_task_artifact_readonly_targets(iter_words)
        if not iter_targets:
            continue
        replacement = _shell_loop_representative_iter_word(iter_words[0])
        substituted_body = _shell_substitute_loop_variable(body, variable, replacement)
        body_result = _analyze_shell(substituted_body, analyze_for_loops=False)
        if _shell_loop_body_is_supported_task_data_readonly(substituted_body, body_result):
            return True
    return False


def _shell_test_path_probe_targets(tokens: list[str]) -> list[str]:
    path_flags = {"-e", "-f", "-d", "-s", "-r", "-w", "-x", "-L", "-h"}
    binary_path_flags = {"-ef", "-nt", "-ot"}
    closers = {"]", "]]"}
    candidates: list[str] = []
    for index, token in enumerate(tokens[1:], start=1):
        if token in path_flags and index + 1 < len(tokens):
            candidate = tokens[index + 1]
            if candidate not in closers and candidate not in {"-a", "-o"} and _looks_like_path_arg(candidate):
                candidates.append(candidate)
            continue
        if token in binary_path_flags and 0 < index < len(tokens) - 1:
            left = tokens[index - 1]
            right = tokens[index + 1]
            for candidate in (left, right):
                if candidate in closers or candidate in {"-a", "-o"}:
                    continue
                if _looks_like_path_arg(candidate):
                    candidates.append(candidate)
    return candidates


def _shell_file_source_args(tokens: list[str]) -> list[str]:
    sources: list[str] = []
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if _shell_token_starts_redirect(token):
            break
        if token == "--":
            sources.extend(_read_probe_source_args(tokens[index + 1:]))
            break
        if token in {"-f", "--files-from", "-m", "--magic-file"}:
            if index + 1 < len(tokens):
                sources.append(tokens[index + 1])
            index += 2
            continue
        if token.startswith("--files-from=") or token.startswith("--magic-file="):
            sources.append(token.split("=", 1)[1])
            index += 1
            continue
        if token.startswith("-f") and len(token) > 2:
            sources.append(token[2:])
            index += 1
            continue
        if token.startswith("-m") and len(token) > 2:
            sources.append(token[2:])
            index += 1
            continue
        if token.startswith("-") and token != "-":
            index += 1
            continue
        sources.append(token)
        index += 1
    return _read_probe_source_args(sources)


def _shell_media_version_probe(tokens: list[str]) -> bool:
    args = [token for token in tokens[1:] if token]
    if not args:
        return False
    return all(token in {"-version", "--version", "-h", "-help", "--help"} for token in args)


def _shell_ffprobe_source_args(tokens: list[str]) -> list[str]:
    option_args = {
        "-f",
        "-i",
        "-loglevel",
        "-of",
        "-print_format",
        "-read_intervals",
        "-select_streams",
        "-show_entries",
        "-sexagesimal",
        "-unit",
        "-v",
    }
    sources: list[str] = []
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            sources.extend(tokens[index + 1:])
            break
        if token in option_args:
            if index + 1 < len(tokens):
                value = tokens[index + 1]
                if token == "-i" or _looks_like_path_arg(value) or _URL_RE.match(value):
                    sources.append(value)
            index += 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        if _looks_like_path_arg(token) or _URL_RE.match(token):
            sources.append(token)
        index += 1
    return _read_probe_source_args(sources)


def _shell_ffmpeg_file_effects(tokens: list[str]) -> dict[str, Any]:
    effects: list[str] = []
    targets: list[ActionEffectTarget] = []
    rules: list[str] = []
    confidence = "low"
    if _shell_media_version_probe(tokens):
        _add_effect(effects, "environment.probe")
        targets.append(_probe_target("ffmpeg"))
        _add_rule(rules, "shell_capability_probe")
        return {"effects": effects, "targets": targets, "rules": rules, "confidence": "medium"}

    inputs, outputs = _shell_ffmpeg_io_args(tokens)
    remote_inputs = [path for path in inputs if _URL_RE.match(path)]
    local_inputs = [path for path in inputs if not _URL_RE.match(path)]
    remote_outputs = [path for path in outputs if _URL_RE.match(path)]
    local_outputs = [path for path in outputs if not _URL_RE.match(path)]
    if remote_inputs:
        _add_effect(effects, "network.fetch")
        _add_rule(rules, "network_equivalent_fetch")
        confidence = _max_confidence(confidence, "high")
    if remote_outputs:
        _add_effect(effects, "network.upload")
        _add_rule(rules, "network_equivalent_upload")
        confidence = _max_confidence(confidence, "high")
    if local_inputs:
        _add_effect(effects, "filesystem.read")
        targets.extend(
            _target_for_path(path, role=_path_role_for_read(path))
            for path in local_inputs[:3]
        )
        _add_rule(rules, "shell_read_probe")
        confidence = _max_confidence(confidence, "medium")
    if local_outputs:
        _add_effect(effects, "filesystem.write")
        targets.extend(_write_target_for_path(path) for path in local_outputs[:3])
        _add_rule(rules, "shell_media_output_write")
        confidence = _max_confidence(confidence, "medium")
    if not effects:
        _add_effect(effects, "command.exec")
        _add_rule(rules, "wrapper_chain_unresolved")
        _add_rule(rules, "shell_unresolved_command_segment")
        confidence = _max_confidence(confidence, "high")
    return {"effects": effects, "targets": targets, "rules": rules, "confidence": confidence}


def _shell_ffmpeg_io_args(tokens: list[str]) -> tuple[list[str], list[str]]:
    value_options = {
        "-ac",
        "-acodec",
        "-ar",
        "-b:a",
        "-b:v",
        "-c",
        "-c:a",
        "-c:v",
        "-codec",
        "-crf",
        "-filter",
        "-filter:a",
        "-filter:v",
        "-filter_complex",
        "-f",
        "-framerate",
        "-loglevel",
        "-map",
        "-metadata",
        "-movflags",
        "-pix_fmt",
        "-preset",
        "-r",
        "-s",
        "-ss",
        "-t",
        "-threads",
        "-to",
        "-v",
        "-vf",
        "-vol",
    }
    inputs: list[str] = []
    outputs: list[str] = []
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            outputs.extend(
                arg for arg in tokens[index + 1:]
                if _looks_like_path_arg(arg) or _URL_RE.match(arg)
            )
            break
        if token == "-i":
            if index + 1 < len(tokens):
                inputs.append(tokens[index + 1])
            index += 2
            continue
        if token in value_options:
            index += 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        if _looks_like_path_arg(token) or _URL_RE.match(token):
            outputs.append(token)
        index += 1
    return (_read_probe_source_args(inputs), _read_probe_source_args(outputs))


def _shell_touch_file_effects(tokens: list[str]) -> dict[str, Any]:
    effects: list[str] = []
    targets: list[ActionEffectTarget] = []
    rules: list[str] = []
    reads: list[str] = []
    writes: list[str] = []
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            writes.extend(arg for arg in tokens[index + 1:] if _looks_like_path_arg(arg))
            break
        if token in {"-r", "--reference"}:
            if index + 1 < len(tokens) and _looks_like_path_arg(tokens[index + 1]):
                reads.append(tokens[index + 1])
            index += 2
            continue
        if token.startswith("--reference="):
            value = token.split("=", 1)[1]
            if _looks_like_path_arg(value):
                reads.append(value)
            index += 1
            continue
        if token in {"-d", "--date", "-t"}:
            index += 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        if _looks_like_path_arg(token):
            writes.append(token)
        index += 1
    if reads:
        _add_effect(effects, "filesystem.read")
        targets.extend(
            _target_for_path(path, role=_path_role_for_read(path))
            for path in reads[:3]
        )
        _add_rule(rules, "shell_read_probe")
    if writes:
        _add_effect(effects, "filesystem.write")
        targets.extend(_write_target_for_path(path) for path in writes[:3])
        _add_rule(rules, "shell_touch_write")
    confidence = "medium" if effects else "low"
    return {"effects": effects, "targets": targets, "rules": rules, "confidence": confidence}


def _shell_file_has_indirect_list_option(tokens: list[str]) -> bool:
    return any(
        token in {"-f", "--files-from"}
        or token.startswith("-f")
        or token.startswith("--files-from=")
        for token in tokens[1:]
    )


def _shell_sed_side_effects(tokens: list[str], *, shell_cwd: str | None = None) -> dict[str, Any]:
    effects: list[str] = []
    targets: list[ActionEffectTarget] = []
    rules: list[str] = []
    confidence = "low"

    if _shell_sed_has_in_place_write(tokens):
        _add_effect(effects, "filesystem.write")
        for path in _shell_sed_file_args(tokens)[:3]:
            targets.append(_target_for_path(path))
        _add_rule(rules, "shell_sed_in_place_write")
        confidence = _max_confidence(confidence, "high")

    script_files = _shell_sed_script_files(tokens)
    if script_files:
        _add_effect(effects, "filesystem.read")
        targets.extend(
            _target_for_path(path, role=_path_role_for_read(path))
            for path in script_files[:3]
        )
        _add_effect(effects, "command.exec")
        _add_rule(rules, "wrapper_chain_unresolved")
        _add_rule(rules, "shell_sed_script_file_unresolved")
        confidence = _max_confidence(confidence, "high")

    if _shell_sed_uses_stdin_script(tokens):
        _add_effect(effects, "command.exec")
        _add_rule(rules, "wrapper_chain_unresolved")
        _add_rule(rules, "shell_sed_stdin_script_unresolved")
        confidence = _max_confidence(confidence, "high")

    for script in _shell_sed_scripts(tokens):
        if _shell_sed_script_has_exec(script):
            _add_effect(effects, "command.exec")
            _add_rule(rules, "wrapper_chain_unresolved")
            _add_rule(rules, "shell_sed_exec")
            confidence = _max_confidence(confidence, "high")
        write_targets = _shell_sed_script_write_targets(script)
        if write_targets:
            _add_effect(effects, "filesystem.write")
            targets.extend(_target_for_path(path, cwd=shell_cwd) for path in write_targets[:3])
            _add_rule(rules, "shell_sed_write")
            confidence = _max_confidence(confidence, "high")
        read_targets = _shell_sed_script_read_targets(script)
        if read_targets:
            _add_effect(effects, "filesystem.read")
            targets.extend(
                _target_for_path(path, role=_path_role_for_read(path, cwd=shell_cwd), cwd=shell_cwd)
                for path in read_targets[:3]
            )
            _add_rule(rules, "shell_sed_extra_read")
            confidence = _max_confidence(confidence, "medium")

    return {"effects": effects, "targets": targets, "rules": rules, "confidence": confidence}


def _shell_sed_tokens_are_readonly(tokens: list[str]) -> bool:
    if _shell_sed_has_in_place_write(tokens):
        return False
    if _shell_sed_script_files(tokens) or _shell_sed_uses_stdin_script(tokens):
        return False
    scripts = _shell_sed_scripts(tokens)
    if not scripts:
        return False
    return all(
        not _shell_sed_script_has_exec(script)
        and not _shell_sed_script_write_targets(script)
        and not _shell_sed_script_read_targets(script)
        for script in scripts
    )


def _shell_sed_has_in_place_write(tokens: list[str]) -> bool:
    return any(
        token == "-i"
        or token.startswith("-i")
        or token == "--in-place"
        or token.startswith("--in-place=")
        for token in tokens[1:]
    )


def _shell_sed_scripts(tokens: list[str]) -> list[str]:
    scripts: list[str] = []
    index = 1
    saw_script = False
    while index < len(tokens):
        token = tokens[index]
        if _shell_token_starts_redirect(token):
            break
        if token == "--":
            break
        if token in {"-e", "--expression"}:
            if index + 1 < len(tokens):
                scripts.append(tokens[index + 1])
            index += 2
            continue
        if token.startswith("--expression="):
            scripts.append(token.split("=", 1)[1])
            index += 1
            continue
        if token in {"-f", "--file"} or token.startswith("--file="):
            return []
        if token == "-n" or token == "--quiet" or token == "--silent":
            index += 1
            continue
        if token.startswith("-") and token != "-":
            index += 1
            continue
        if not saw_script:
            scripts.append(token)
            saw_script = True
            index += 1
            continue
        index += 1
    return scripts


def _shell_sed_script_files(tokens: list[str]) -> list[str]:
    files: list[str] = []
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if _shell_token_starts_redirect(token):
            break
        if token == "--":
            break
        if token in {"-f", "--file"}:
            if index + 1 < len(tokens):
                files.append(tokens[index + 1])
            index += 2
            continue
        if token.startswith("--file="):
            files.append(token.split("=", 1)[1])
            index += 1
            continue
        if token.startswith("-") and not token.startswith("--") and len(token) > 2:
            short_options = token[1:]
            option_at = short_options.find("f")
            if option_at >= 0:
                inline_value = short_options[option_at + 1:]
                if inline_value:
                    files.append(inline_value)
                    index += 1
                    continue
                if index + 1 < len(tokens):
                    files.append(tokens[index + 1])
                    index += 2
                    continue
                index += 1
                continue
        index += 1
    return [file for file in _dedupe_strings(files) if _looks_like_path_arg(file)]


def _shell_sed_uses_stdin_script(tokens: list[str]) -> bool:
    for index, token in enumerate(tokens):
        if token in {"-f", "--file"} and index + 1 < len(tokens) and tokens[index + 1] == "-":
            return True
        if token == "--file=-":
            return True
        if token.startswith("-") and not token.startswith("--") and len(token) > 2:
            if _shell_combined_short_option_value(tokens, index, "f") == "-":
                return True
    return False


def _shell_combined_short_option_value(tokens: list[str], index: int, option: str) -> str | None:
    token = tokens[index]
    if not token.startswith("-") or token.startswith("--") or len(token) <= 2:
        return None
    short_options = token[1:]
    option_at = short_options.find(option)
    if option_at < 0:
        return None
    inline_value = short_options[option_at + 1:]
    if inline_value:
        return inline_value
    if index + 1 < len(tokens):
        return tokens[index + 1]
    return None


def _shell_sed_file_args(tokens: list[str]) -> list[str]:
    files: list[str] = []
    index = 1
    saw_script = False
    while index < len(tokens):
        token = tokens[index]
        if _shell_token_starts_redirect(token):
            break
        if token == "--":
            files.extend(
                arg for arg in tokens[index + 1:]
                if _looks_like_path_arg(arg)
            )
            break
        if token in {"-e", "--expression", "-f", "--file"}:
            index += 2
            continue
        if token.startswith(("--expression=", "--file=")):
            index += 1
            continue
        if token == "-n" or token == "--quiet" or token == "--silent":
            index += 1
            continue
        if token.startswith("-") and token != "-":
            index += 1
            continue
        if not saw_script:
            saw_script = True
            index += 1
            continue
        if _looks_like_path_arg(token):
            files.append(token)
        index += 1
    return _dedupe_strings(files)


def _shell_sed_script_has_exec(script: str) -> bool:
    normalized = str(script or "")
    return bool(_SHELL_SED_EXEC_RE.search(normalized)) or _shell_sed_substitution_has_flag(normalized, "e")


def _shell_sed_script_write_targets(script: str) -> list[str]:
    targets = [
        match.group("target").strip()
        for match in _SHELL_SED_WRITE_RE.finditer(str(script or ""))
        if match.group("target").strip()
    ]
    targets.extend(_shell_sed_substitution_write_targets(str(script or "")))
    return _dedupe_strings(targets)


def _shell_sed_script_read_targets(script: str) -> list[str]:
    return _dedupe_strings(
        match.group("target").strip()
        for match in _SHELL_SED_READ_RE.finditer(str(script or ""))
        if match.group("target").strip()
    )


def _shell_sed_substitution_has_flag(script: str, flag: str) -> bool:
    return any(flag in flags for _replacement, flags in _shell_sed_substitution_replacements(script))


def _shell_sed_substitution_write_targets(script: str) -> list[str]:
    targets: list[str] = []
    for _replacement, flags in _shell_sed_substitution_replacements(script):
        match = re.search(r"\bw\s*(/[^\s;{}\n]+)", flags)
        if match:
            targets.append(match.group(1))
    return targets


def _shell_sed_substitution_replacements(script: str) -> list[tuple[str, str]]:
    substitutions: list[tuple[str, str]] = []
    index = 0
    while index < len(script):
        if script[index] != "s" or index + 1 >= len(script):
            index += 1
            continue
        delimiter = script[index + 1]
        if delimiter.isalnum() or delimiter.isspace() or delimiter == "\\":
            index += 1
            continue
        first = _shell_sed_find_unescaped_delimiter(script, delimiter, index + 2)
        if first < 0:
            index += 1
            continue
        second = _shell_sed_find_unescaped_delimiter(script, delimiter, first + 1)
        if second < 0:
            index = first + 1
            continue
        flags_end = second + 1
        while flags_end < len(script) and script[flags_end] not in ";\n{}":
            flags_end += 1
        substitutions.append((script[first + 1:second], script[second + 1:flags_end].strip()))
        index = flags_end
    return substitutions


def _shell_sed_find_unescaped_delimiter(script: str, delimiter: str, start: int) -> int:
    index = start
    escaped = False
    while index < len(script):
        char = script[index]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == delimiter:
            return index
        index += 1
    return -1


_SHELL_SED_ADDRESS_RE = r"(?:\s*(?:\d+|\$|/[^\n;/]+/)(?:\s*,\s*(?:\d+|\$|/[^\n;/]+/))?\s*)?"
_SHELL_SED_EXEC_RE = re.compile(rf"(?:^|[;{{}}\n]){_SHELL_SED_ADDRESS_RE}e(?:\s|$)")
_SHELL_SED_WRITE_RE = re.compile(
    rf"(?:^|[;{{}}\n]){_SHELL_SED_ADDRESS_RE}[wW]\s*(?P<target>/[^\s;{{}}\n]+)"
)
_SHELL_SED_READ_RE = re.compile(
    rf"(?:^|[;{{}}\n]){_SHELL_SED_ADDRESS_RE}[rR]\s*(?P<target>/[^\s;{{}}\n]+)"
)


def _shell_awk_side_effects(
    tokens: list[str],
    *,
    raw_tokens: list[str] | None = None,
) -> dict[str, Any]:
    effects: list[str] = []
    targets: list[ActionEffectTarget] = []
    rules: list[str] = []
    confidence = "low"

    script_files = _shell_awk_script_files(tokens)
    stdin_script = _shell_awk_uses_stdin_script(tokens)
    inline_scripts = _awk_inline_scripts(tokens)
    unsafe = bool(
        script_files
        or stdin_script
        or not inline_scripts
        or _shell_awk_has_execution_wrapper(tokens, raw_tokens)
    )
    for script in inline_scripts:
        if not _awk_inline_script_is_stdout_filter(script):
            unsafe = True
            break

    if unsafe:
        _add_effect(effects, "command.exec")
        _add_rule(rules, "wrapper_chain_unresolved")
        _add_rule(rules, "shell_awk_unresolved")
        confidence = _max_confidence(confidence, "high")
        if script_files:
            _add_effect(effects, "filesystem.read")
            targets.extend(
                _target_for_path(path, role=_path_role_for_read(path))
                for path in script_files[:3]
            )
            _add_rule(rules, "shell_awk_script_file_unresolved")
        if stdin_script:
            _add_rule(rules, "shell_awk_stdin_script_unresolved")
        if any(re.search(r"\bsystem\s*\(|\|\s*(?:&\s*)?getline\b", script) for script in inline_scripts):
            _add_rule(rules, "shell_awk_exec")
        if any(re.search(r"@include\b", script) for script in inline_scripts):
            for script in inline_scripts:
                for path in re.findall(r"@include\s+['\"]([^'\"]+)['\"]", script):
                    if _looks_like_path_arg(path):
                        _add_effect(effects, "filesystem.read")
                        targets.append(_target_for_path(path, role=_path_role_for_read(path)))
            _add_rule(rules, "shell_awk_include_unresolved")
        return {"effects": effects, "targets": targets, "rules": rules, "confidence": confidence}

    source_paths = [
        path for path in _shell_awk_source_args(tokens)
        if _looks_like_path_arg(path)
    ]
    if source_paths:
        _add_effect(effects, "filesystem.read")
        targets.extend(
            _target_for_path(path, role=_path_role_for_read(path))
            for path in source_paths[:3]
        )
        _add_rule(rules, "shell_read_probe")
        confidence = _max_confidence(confidence, "medium")

    return {"effects": effects, "targets": targets, "rules": rules, "confidence": confidence}


def _shell_awk_has_execution_wrapper(
    tokens: list[str],
    raw_tokens: list[str] | None,
) -> bool:
    if not tokens or not raw_tokens:
        return False
    return Path(str(raw_tokens[0] or "")).name.lower() != Path(str(tokens[0] or "")).name.lower()


def _awk_inline_script_is_stdout_filter(script: str) -> bool:
    text = str(script or "")
    if not text.strip():
        return False
    if re.search(r"\bsystem\s*\(|\bgetline\b|@include\b", text):
        return False
    if any(marker in text for marker in (">", "|", "`", "$(")):
        return False
    return bool(re.search(r"\bprint(?:f)?\b", text))


def _shell_awk_source_args(tokens: list[str]) -> list[str]:
    sources: list[str] = []
    saw_script = False
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if _shell_token_starts_redirect(token):
            break
        if token == "--":
            sources.extend(_read_probe_source_args(tokens[index + 1:]))
            break
        if token in {"-F", "-v", "--assign", "--field-separator"}:
            index += 2
            continue
        if token.startswith("--assign=") or token.startswith("--field-separator="):
            index += 1
            continue
        if token.startswith("-F") and token != "-F":
            index += 1
            continue
        if token.startswith("-v") and token != "-v":
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        if not saw_script:
            saw_script = True
            index += 1
            continue
        sources.append(token)
        index += 1
    return _read_probe_source_args(sources)


def _shell_awk_script_files(tokens: list[str]) -> list[str]:
    files: list[str] = []
    value_flags = {"-f", "-i", "--include", "-l", "--load"}
    inline_prefixes = ("-f", "-i", "-l")
    for index, token in enumerate(tokens[:-1]):
        if token in value_flags:
            files.append(tokens[index + 1])
            continue
        if token.startswith("--include=") or token.startswith("--load="):
            files.append(token.split("=", 1)[1])
            continue
        for prefix in inline_prefixes:
            if token.startswith(prefix) and len(token) > len(prefix):
                files.append(token[len(prefix):])
                break
    return [file for file in _dedupe_strings(files) if file != "-" and _looks_like_path_arg(file)]


def _shell_awk_uses_stdin_script(tokens: list[str]) -> bool:
    return any(
        (token == "-f" and index + 1 < len(tokens) and tokens[index + 1] == "-")
        or token == "-f-"
        for index, token in enumerate(tokens)
    )


def _shell_find_source_args(tokens: list[str]) -> list[str]:
    roots: list[str] = []
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token in {"(", ")", "!", "-not", "-and", "-or", "-a", "-o", ","}:
            break
        if token in {"-H", "-L", "-P"}:
            index += 1
            continue
        if token == "-D":
            index += 2
            continue
        if token.startswith("-D") or token.startswith("-O"):
            index += 1
            continue
        if token.startswith("-"):
            break
        roots.append(token)
        index += 1
    return _read_probe_source_args(roots) or ["."]


def _shell_enumerate_candidate_paths(command: str, source_args: list[str]) -> list[str]:
    if command in {"find", "ls"}:
        return [arg for arg in source_args if arg and not arg.startswith("-")] or ["."]
    return [arg for arg in source_args if _looks_like_path_arg(arg)] or ["."]


def _shell_find_write_effects(tokens: list[str], source_args: list[str]) -> dict[str, Any]:
    effects: list[str] = []
    targets: list[ActionEffectTarget] = []
    rules: list[str] = []
    confidence = "low"
    if "-delete" in tokens[1:]:
        _add_effect(effects, "filesystem.write")
        for path in (source_args or ["."])[:3]:
            targets.append(_target_for_path(path))
        _add_rule(rules, "find_delete_write")
        confidence = _max_confidence(confidence, "high")
    for path in _shell_find_output_targets(tokens):
        _add_effect(effects, "filesystem.write")
        targets.append(_target_for_path(path))
        _add_rule(rules, "find_output_write")
        confidence = _max_confidence(confidence, "medium")
    return {
        "effects": effects,
        "targets": targets,
        "rules": rules,
        "confidence": confidence,
    }


def _shell_find_output_targets(tokens: list[str]) -> list[str]:
    targets: list[str] = []
    index = 1
    while index < len(tokens) - 1:
        token = tokens[index]
        if token in _FIND_OUTPUT_PREDICATES:
            targets.append(tokens[index + 1])
            index += 2
            continue
        index += 1
    return _dedupe_strings(targets)


def _analyze_shell_pipeline_consumers(text: str) -> dict[str, Any]:
    effects: list[str] = []
    targets: list[ActionEffectTarget] = []
    rules: list[str] = []
    confidence = "low"
    for tokens in _shell_pipeline_consumer_segments(text):
        if _shell_pipeline_consumer_executes_stdin(tokens):
            _add_effect(effects, "command.exec")
            _add_rule(rules, "shell_pipeline_exec_consumer")
            _add_rule(rules, "wrapper_chain_unresolved")
            confidence = _max_confidence(confidence, "high")
        effective = _shell_effective_tokens(tokens)
        if not effective:
            continue
        head = Path(effective[0]).name.lower()
        if head in _SHELL_AWK_COMMANDS:
            awk_side_effects = _shell_awk_side_effects(effective)
            _merge(effects, awk_side_effects["effects"])
            targets.extend(awk_side_effects["targets"])
            _merge(rules, awk_side_effects["rules"])
            confidence = _max_confidence(confidence, awk_side_effects["confidence"])
        elif head == "sed":
            sed_side_effects = _shell_sed_side_effects(effective)
            _merge(effects, sed_side_effects["effects"])
            targets.extend(sed_side_effects["targets"])
            _merge(rules, sed_side_effects["rules"])
            confidence = _max_confidence(confidence, sed_side_effects["confidence"])
        elif head in {"rg", "ripgrep", "ag"} and _shell_search_tokens_have_execution_option(head, effective):
            _add_effect(effects, "command.exec")
            _add_rule(rules, "shell_search_exec_option")
            _add_rule(rules, "wrapper_chain_unresolved")
            confidence = _max_confidence(confidence, "high")
    return {"effects": effects, "targets": targets, "rules": rules, "confidence": confidence}


def _shell_pipeline_consumer_segments(text: str) -> list[list[str]]:
    tokens = _shell_tokens_with_punctuation(text)
    if not tokens:
        return []
    segments: list[tuple[str | None, list[str]]] = []
    separator: str | None = None
    current: list[str] = []
    for token in tokens:
        if token and all(char in ";&|" for char in token):
            if current:
                segments.append((separator, current))
                current = []
            separator = token
            continue
        current.append(token)
    if current:
        segments.append((separator, current))
    return [
        segment
        for separator, segment in segments
        if separator and "|" in separator and separator != "||"
    ]


def _shell_pipeline_consumer_executes_stdin(tokens: list[str]) -> bool:
    effective = _shell_effective_tokens(tokens)
    if not effective:
        return False
    head = Path(effective[0]).name.lower()
    if head == "xargs":
        return True
    if head == "while":
        return True
    if head in _PIPE_STDIN_EXEC_COMMANDS:
        return True
    return False


def _shell_stdin_filter_file_effects(command: str, tokens: list[str]) -> dict[str, Any]:
    read_targets: list[str] = []
    write_targets: list[str] = []
    exec_targets: list[str] = []
    exec_rules: list[str] = []
    operands: list[str] = []
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token in {">", ">>", ">|", "<>", "<<"} or token.startswith((">", "<<")):
            break
        if token == "<":
            if index + 1 < len(tokens):
                read_targets.append(tokens[index + 1])
            break
        if command == "sort":
            if token in {"-o", "--output"}:
                if index + 1 < len(tokens):
                    write_targets.append(tokens[index + 1])
                index += 2
                continue
            if token.startswith("--output="):
                write_targets.append(token.split("=", 1)[1])
                index += 1
                continue
            if token.startswith("-o") and len(token) > 2:
                write_targets.append(token[2:])
                index += 1
                continue
            if token in {"-T", "--temporary-directory"}:
                if index + 1 < len(tokens):
                    write_targets.append(tokens[index + 1])
                index += 2
                continue
            if token.startswith("-T") and len(token) > 2 and not token.startswith("--"):
                write_targets.append(token[2:])
                index += 1
                continue
            if token.startswith("--temporary-directory="):
                write_targets.append(token.split("=", 1)[1])
                index += 1
                continue
            if token == "--files0-from":
                if index + 1 < len(tokens):
                    source = tokens[index + 1]
                    if source == "-":
                        exec_rules.append("shell_sort_files0_from_stdin")
                    else:
                        read_targets.append(source)
                index += 2
                continue
            if token == "--random-source":
                if index + 1 < len(tokens):
                    read_targets.append(tokens[index + 1])
                index += 2
                continue
            if token.startswith("--files0-from="):
                source = token.split("=", 1)[1]
                if source == "-":
                    exec_rules.append("shell_sort_files0_from_stdin")
                else:
                    read_targets.append(source)
                index += 1
                continue
            if token.startswith("--random-source="):
                read_targets.append(token.split("=", 1)[1])
                index += 1
                continue
            if token == "--compress-program":
                if index + 1 < len(tokens):
                    exec_targets.append(tokens[index + 1])
                exec_rules.append("shell_sort_exec_program")
                index += 2
                continue
            if token.startswith("--compress-program="):
                exec_targets.append(token.split("=", 1)[1])
                exec_rules.append("shell_sort_exec_program")
                index += 1
                continue
        if token.startswith("-") and token != "-":
            index += 1
            continue
        operands.append(token)
        index += 1

    if command == "sort":
        read_targets.extend(operands)
    elif command == "uniq":
        if operands:
            read_targets.append(operands[0])
        if len(operands) > 1:
            write_targets.append(operands[1])

    return {
        "read_targets": _dedupe_strings([
            path for path in read_targets if _looks_like_path_arg(path)
        ]),
        "write_targets": _dedupe_strings([
            path for path in write_targets if _looks_like_path_arg(path)
        ]),
        "exec_targets": _dedupe_strings([
            path for path in exec_targets if _looks_like_path_arg(path)
        ]),
        "exec_rules": _dedupe_strings(exec_rules),
    }


def _shell_files0_from_option_effects(tokens: list[str]) -> dict[str, Any]:
    read_targets: list[str] = []
    stdin = False
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token == "--files0-from":
            if index + 1 < len(tokens):
                source = tokens[index + 1]
                if source == "-":
                    stdin = True
                else:
                    read_targets.append(source)
            index += 2
            continue
        if token.startswith("--files0-from="):
            source = token.split("=", 1)[1]
            if source == "-":
                stdin = True
            else:
                read_targets.append(source)
            index += 1
            continue
        index += 1
    return {
        "read_targets": _dedupe_strings([
            path for path in read_targets if _looks_like_path_arg(path)
        ]),
        "stdin": stdin,
    }


def _analyze_shell_task_data_for_loops(text: str) -> dict[str, Any]:
    effects: list[str] = []
    targets: list[ActionEffectTarget] = []
    rules: list[str] = []
    confidence = "low"

    for variable, iter_words, body in _shell_static_for_loops(text):
        iter_targets = _shell_for_iter_task_artifact_readonly_targets(iter_words)
        if not iter_targets:
            continue

        replacement = _shell_loop_representative_iter_word(iter_words[0])
        substituted_body = _shell_substitute_loop_variable(body, variable, replacement)
        body_result = _analyze_shell(substituted_body, analyze_for_loops=False)
        targets.extend(body_result["targets"])
        _merge(rules, body_result["rules"])
        _merge(effects, body_result["effects"])
        confidence = _max_confidence(confidence, body_result["confidence"])

        if _shell_loop_body_is_supported_task_data_readonly(substituted_body, body_result):
            _add_effect(effects, "filesystem.enumerate")
            targets.extend(
                _target_for_path(
                    target,
                    role=_path_role_for_enumerate(target),
                )
                for target in iter_targets
            )
            if all(_is_scope_task_data_path(target) for target in iter_targets):
                _add_rule(rules, "shell_for_loop_task_data_readonly")
            else:
                _add_rule(rules, "shell_for_loop_task_artifact_readonly")
            confidence = _max_confidence(confidence, "medium")
            continue

        _add_effect(effects, "command.exec")
        targets.extend(
            _target_for_path(
                target,
                role=_path_role_for_read(target),
            )
            for target in iter_targets
        )
        _add_rule(rules, "wrapper_chain_unresolved")
        _add_rule(rules, "shell_for_loop_unresolved")
        confidence = _max_confidence(confidence, "high")

    return {"effects": effects, "targets": targets, "rules": rules, "confidence": confidence}


def _shell_static_for_loops(text: str) -> list[tuple[str, list[str], str]]:
    tokens = _shell_tokens_with_punctuation(text)
    if not tokens:
        return []
    loops: list[tuple[str, list[str], str]] = []
    index = 0
    while index < len(tokens):
        if tokens[index] != "for" or index + 3 >= len(tokens):
            index += 1
            continue
        variable = tokens[index + 1]
        if not re.fullmatch(r"[A-Za-z_]\w*", variable) or tokens[index + 2] != "in":
            index += 1
            continue

        iter_index = index + 3
        iter_words: list[str] = []
        while iter_index < len(tokens):
            token = tokens[iter_index]
            if token == "do":
                break
            if token == ";":
                iter_index += 1
                break
            if token and all(char in "&|" for char in token):
                iter_words = []
                break
            iter_words.append(token)
            iter_index += 1

        if not iter_words or iter_index >= len(tokens) or tokens[iter_index] != "do":
            index += 1
            continue

        body_start = iter_index + 1
        body_index = body_start
        depth = 1
        body_tokens: list[str] = []
        while body_index < len(tokens):
            token = tokens[body_index]
            if token == "for":
                depth += 1
            elif token == "done":
                depth -= 1
                if depth == 0:
                    break
            body_tokens.append(token)
            body_index += 1
        if depth != 0:
            index += 1
            continue

        loops.append((variable, iter_words, _shell_join_tokens(body_tokens)))
        index = body_index + 1
    return loops


def _shell_join_tokens(tokens: list[str]) -> str:
    return " ".join(
        shlex.quote(token) if re.search(r"\s", token) else token
        for token in tokens
        if token
    )


def _shell_for_iter_task_artifact_readonly_targets(iter_words: list[str]) -> list[str]:
    targets: list[str] = []
    for word in iter_words:
        normalized = str(word or "").strip().strip("'\"")
        if not normalized or not _shell_loop_iter_word_is_static_path(normalized):
            return []
        target = _glob_base_path(normalized)
        if not _is_scope_task_artifact_readonly_path(target):
            return []
        targets.append(target)
    return _dedupe_strings(targets)


def _shell_loop_iter_word_is_static_path(word: str) -> bool:
    if word.startswith("-"):
        return False
    return not any(marker in word for marker in ("$", "`", "<", ">", "|", ";", "&"))


def _shell_loop_representative_iter_word(word: str) -> str:
    normalized = str(word or "").strip().strip("'\"")
    if not any(marker in normalized for marker in ("*", "?", "[")):
        return normalized
    base = _glob_base_path(normalized)
    suffix = PurePosixPath(normalized).suffix
    return posixpath.join(base, f"__task_data_sample__{suffix}")


def _shell_substitute_loop_variable(body: str, variable: str, replacement: str) -> str:
    basename = PurePosixPath(replacement).name or replacement

    def _replace_parameter_expansion(match: re.Match[str]) -> str:
        suffix = match.group(1)
        if suffix in {"#*/", "##*/"}:
            return basename
        return replacement

    substituted = re.sub(
        rf"\$\{{{re.escape(variable)}([^}}]*)\}}",
        _replace_parameter_expansion,
        body,
    )
    return re.sub(rf"\${re.escape(variable)}\b", replacement, substituted)


_SHELL_LOOP_READONLY_COMMANDS = frozenset({
    "bsdtar",
    "break",
    "cat",
    "continue",
    "cut",
    "docx2txt",
    "dirname",
    "echo",
    "basename",
    "egrep",
    "fgrep",
    "find",
    "grep",
    "head",
    "jq",
    "gzip",
    "gunzip",
    "nl",
    "pdfinfo",
    "pdftotext",
    "printf",
    "sed",
    "sort",
    "strings",
    "tail",
    "tr",
    "uniq",
    "unzip",
    "wc",
    "zcat",
})
_SHELL_LOOP_SEARCH_COMMANDS = frozenset({"grep", "egrep", "fgrep"})
_SHELL_LOOP_STDIN_FILTER_COMMANDS = frozenset({"cut", "sort", "tr", "uniq"})
_SHELL_LOOP_CONTROL_COMMANDS = frozenset({"break", "continue"})


def _shell_loop_body_is_supported_task_data_readonly(
    body: str,
    body_result: dict[str, Any],
) -> bool:
    if _shell_loop_body_has_executable_expansion(body):
        return False
    effects = {str(effect) for effect in body_result["effects"]}
    if effects - {"filesystem.read", "filesystem.enumerate"}:
        return False
    if any(not _shell_loop_target_is_task_artifact_readonly(target) for target in body_result["targets"]):
        return False
    if not _shell_loop_body_segments_are_supported_readonly(body):
        return False
    return True


def _shell_loop_target_is_task_artifact_readonly(target: ActionEffectTarget) -> bool:
    task_data = (
        target.kind == "path"
        and target.path_role == SCOPE_TASK_DATA_READ_PATH_ROLE
        and target.workspace_relation == "benchmark_task_data"
        and getattr(target, "artifact_role", None) == "task_data"
    )
    task_output = (
        target.kind == "path"
        and target.path_role == SCOPE_TASK_OUTPUT_PATH_ROLE
        and target.workspace_relation == "task_output_artifact"
        and getattr(target, "artifact_role", None) == "task_output"
    )
    return bool(task_data or task_output)


def _shell_loop_body_segments_are_supported_readonly(body: str) -> bool:
    saw_segment = False
    for tokens in _shell_segments(body):
        if not tokens:
            continue
        saw_segment = True
        command = Path(tokens[0]).name.lower()
        if command in _SHELL_LOOP_READONLY_COMMANDS and _shell_loop_command_tokens_are_readonly(command, tokens):
            continue
        if command in {"python", "python3"} and _shell_python_module_markitdown_source_args(tokens):
            continue
        return False
    return saw_segment


def _shell_loop_command_tokens_are_readonly(command: str, tokens: list[str]) -> bool:
    if command in _SHELL_LOOP_CONTROL_COMMANDS:
        return len(tokens) == 1 or all(re.fullmatch(r"\d+", token) for token in tokens[1:])
    if command in _SHELL_LOOP_SEARCH_COMMANDS:
        return _shell_search_tokens_are_readonly(command, tokens)
    if command == "jq":
        return _shell_jq_tokens_are_readonly(tokens)
    if command in {"gzip", "gunzip", "zcat"}:
        return bool(_shell_gzip_stdout_source_args(command, tokens))
    if command in _SHELL_LOOP_STDIN_FILTER_COMMANDS:
        filter_effects = _shell_stdin_filter_file_effects(command, tokens)
        return (
            not filter_effects["read_targets"]
            and not filter_effects["write_targets"]
            and not filter_effects["exec_rules"]
        )
    if command == "sed":
        return _shell_sed_tokens_are_readonly(tokens)
    if command == "bsdtar":
        return _shell_bsdtar_is_stdout_or_listing(tokens) and not _shell_bsdtar_has_exec_program_option(tokens)
    if command == "docx2txt":
        write_targets, unknown = _shell_docx2txt_write_targets(tokens)
        return not write_targets and not unknown
    if command == "pandoc":
        return not any(
            _shell_token_is_output_flag(token, _STDOUT_CONVERTER_OUTPUT_FLAGS)
            or token == "--extract-media"
            or token.startswith("--extract-media=")
            for token in tokens[1:]
        )
    return True


def _shell_has_executable_expansion(text: str) -> bool:
    raw = _strip_safe_shell_path_format_substitutions(str(text or ""))
    return "$(" in raw or "`" in raw or "<(" in raw or ">(" in raw


def _shell_loop_body_has_executable_expansion(body: str) -> bool:
    raw = _strip_safe_shell_path_format_substitutions(str(body or ""))
    return _shell_has_executable_expansion(raw) or "$ (" in raw or "< (" in raw or "> (" in raw


def _awk_internal_write_targets(text: str) -> list[str]:
    targets: list[str] = []
    for tokens in _shell_segments(text):
        if not tokens or Path(tokens[0]).name.lower() != "awk":
            continue
        for script in _awk_inline_scripts(tokens):
            bindings = _awk_string_bindings(script)
            for raw_target in _awk_write_expressions(script):
                target = raw_target.strip().strip("()").strip()
                if len(target) >= 2 and target[0] in {"'", '"'} and target[-1] == target[0]:
                    path = target[1:-1]
                else:
                    path = bindings.get(target)
                if path and _looks_like_path_arg(path):
                    targets.append(path)
    return targets[:3]


def _awk_inline_scripts(tokens: list[str]) -> list[str]:
    scripts: list[str] = []
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token == "-f":
            index += 2
            continue
        if token == "-v":
            index += 2
            continue
        if token.startswith("-v") or token.startswith("--"):
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        if "{" in token or "BEGIN" in token or "END" in token or ">" in token:
            scripts.append(token)
        index += 1
    return scripts


def _awk_string_bindings(script: str) -> dict[str, str]:
    bindings: dict[str, str] = {}
    for match in re.finditer(r"\b([A-Za-z_]\w*)\s*=\s*(['\"])([^'\"]+)\2", script):
        variable = match.group(1)
        value = match.group(3)
        if _looks_like_path_arg(value):
            bindings[variable] = value
    return bindings


def _awk_write_expressions(script: str) -> list[str]:
    targets: list[str] = []
    pattern = re.compile(
        r"\b(?:print|printf)\b[^;{}\n]{0,512}>\s*"
        r"(?P<target>\(?\s*(?:[A-Za-z_]\w*|['\"][^'\"]+['\"])\s*\)?)"
    )
    for match in pattern.finditer(script):
        targets.append(match.group("target"))
    return targets


def _shell_segments(text: str) -> list[list[str]]:
    line_segments = _shell_linewise_segments(text)
    if line_segments:
        return line_segments

    tokens = _shell_tokens_with_punctuation(text)
    if tokens:
        return _shell_segments_from_punctuation_tokens(tokens)

    segments: list[list[str]] = []
    for part in _SHELL_SEGMENT_SPLIT_RE.split(text):
        stripped = part.strip()
        if not stripped:
            continue
        try:
            part_tokens = shlex.split(stripped)
        except ValueError:
            part_tokens = stripped.split()
        if part_tokens:
            segments.append(part_tokens)
    return segments


def _shell_linewise_segments(text: str) -> list[list[str]]:
    if "\n" not in str(text or ""):
        return []
    if "<<" in text:
        return []
    lines = str(text or "").splitlines()
    if any(line.rstrip().endswith("\\") for line in lines):
        return []
    segments: list[list[str]] = []
    saw_command = False
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        saw_command = True
        tokens = _shell_tokens_with_punctuation(stripped)
        if not tokens:
            return []
        segments.extend(_shell_segments_from_punctuation_tokens(tokens))
    return segments if saw_command else []


def _shell_segments_from_punctuation_tokens(tokens: list[str]) -> list[list[str]]:
    segments: list[list[str]] = []
    current: list[str] = []
    for token in tokens:
        if token and all(char in ";&|" for char in token):
            if current:
                segments.append(current)
                current = []
            continue
        current.append(token)
    if current:
        segments.append(current)
    return segments


def _shell_segments_with_cwd(text: str) -> list[tuple[list[str], str | None]]:
    segments: list[tuple[list[str], str | None]] = []
    shell_cwd: str | None = _NORMALIZER_CWD.get() or None
    for tokens in _shell_segments(text):
        if not tokens:
            continue
        command = Path(tokens[0]).name.lower()
        if command == "cd":
            shell_cwd = _updated_shell_cwd(shell_cwd, tokens)
            continue
        segments.append((tokens, shell_cwd))
    return segments


def _shell_status_assignment_var(tokens: list[str]) -> str | None:
    if len(tokens) != 1:
        return None
    match = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)=\$\?", str(tokens[0] or ""))
    if match is None:
        return None
    return match.group(1)


def _shell_token_is_status_var(token: str, status_vars: set[str]) -> bool:
    text = str(token or "").strip()
    return any(text in {f"${var}", f"${{{var}}}"} for var in status_vars)


def _shell_token_is_status_code(token: str) -> bool:
    text = str(token or "").strip()
    if not re.fullmatch(r"\d{1,3}", text):
        return False
    try:
        return 0 <= int(text) <= 255
    except ValueError:
        return False


def _shell_status_test_segment(tokens: list[str], status_vars: set[str]) -> bool:
    if not tokens or not status_vars:
        return False
    test_tokens = [str(token or "") for token in tokens]
    if test_tokens[0] == "if":
        test_tokens = test_tokens[1:]
    if not test_tokens:
        return False
    head = test_tokens[0]
    closing: str | None = None
    if head in {"[", "[["}:
        closing = "]]" if head == "[[" else "]"
        test_tokens = test_tokens[1:]
    elif head == "test":
        test_tokens = test_tokens[1:]
    else:
        return False
    if closing and test_tokens and test_tokens[-1] == closing:
        test_tokens = test_tokens[:-1]
    if len(test_tokens) != 3:
        return False
    left, operator, right = test_tokens
    if operator != "-eq":
        return False
    return (
        _shell_token_is_status_var(left, status_vars)
        and _shell_token_is_status_code(right)
    ) or (
        _shell_token_is_status_code(left)
        and _shell_token_is_status_var(right, status_vars)
    )


def _shell_status_exit_segment(tokens: list[str], status_vars: set[str]) -> bool:
    if not tokens or not status_vars:
        return False
    exit_tokens = [str(token or "") for token in tokens]
    if exit_tokens[0] in {"then", "else"}:
        exit_tokens = exit_tokens[1:]
    if len(exit_tokens) != 2 or exit_tokens[0] != "exit":
        return False
    return _shell_token_is_status_code(exit_tokens[1]) or _shell_token_is_status_var(
        exit_tokens[1],
        status_vars,
    )


def _shell_static_status_normalization_segment(
    tokens: list[str],
    status_vars: set[str],
) -> bool:
    if not tokens or not status_vars:
        return False
    head = str(tokens[0] or "")
    if head == "fi":
        return len(tokens) == 1
    return _shell_status_test_segment(tokens, status_vars) or _shell_status_exit_segment(
        tokens,
        status_vars,
    )


def _shell_task_output_local_command_was_modeled(result: dict[str, Any]) -> bool:
    effects = set(result.get("effects") or [])
    if "command.exec" not in effects:
        return False
    return bool(
        {
            "task_output_local_artifact_execution",
            "task_output_local_python_verify",
            "task_output_local_build_execution",
            "task_output_local_test_execution",
            "task_output_local_vcs_inspection",
            "task_output_local_vcs_patch_apply",
        }.intersection(set(result.get("rules") or []))
    )


def _shell_task_output_local_command_effects(
    tokens: list[str],
    shell_cwd: str | None,
    *,
    raw_tokens: list[str] | None = None,
    shell_text: str | None = None,
) -> dict[str, Any]:
    if not tokens:
        return _empty_shell_effects()
    command = Path(tokens[0]).name.lower()
    if command == "pytest":
        return _shell_pytest_task_output_command_effects(tokens[1:], shell_cwd)
    if command == "git":
        if _git_raw_tokens_have_execution_env(raw_tokens or tokens):
            return _empty_shell_effects()
        readonly = _shell_git_task_output_readonly_effects(tokens[1:], shell_cwd)
        if readonly["effects"]:
            return readonly
        return _shell_git_task_output_mutation_effects(tokens[1:], shell_cwd)
    if command == "jar":
        if (
            _build_raw_tokens_have_execution_env(raw_tokens or tokens)
            or _build_raw_tokens_have_privileged_wrapper(raw_tokens or tokens)
            or _jar_raw_tokens_have_disallowed_wrapper(raw_tokens or tokens)
        ):
            return _empty_shell_effects()
        return _shell_jar_task_output_readonly_effects(tokens[1:], shell_cwd)
    if command == "java":
        if (
            _build_raw_tokens_have_execution_env(raw_tokens or tokens)
            or _build_raw_tokens_have_privileged_wrapper(raw_tokens or tokens)
        ):
            return _empty_shell_effects()
        return _shell_java_task_output_command_effects(tokens, shell_cwd)
    if _is_python_interpreter_name(command):
        if _python_raw_tokens_have_execution_env(raw_tokens or tokens):
            return _empty_shell_effects()
        return _shell_python_task_output_command_effects(
            tokens,
            shell_cwd,
            inline_source=_inline_python_source(shell_text or ""),
        )
    if command == "uv":
        return _shell_uv_task_output_command_effects(tokens, shell_cwd)
    if command in _TASK_OUTPUT_LOCAL_BUILD_COMMANDS:
        if (
            _build_raw_tokens_have_execution_env(raw_tokens or tokens)
            or _build_raw_tokens_have_privileged_wrapper(raw_tokens or tokens)
        ):
            return _empty_shell_effects()
        if command in _MAVEN_LOCAL_BUILD_COMMANDS:
            exec_java = _shell_maven_exec_java_task_output_command_effects(tokens, shell_cwd)
            if exec_java["effects"]:
                return exec_java
        return _shell_local_build_task_output_command_effects(tokens, shell_cwd)
    return _empty_shell_effects()


def _shell_jar_task_output_readonly_effects(
    args: list[str],
    shell_cwd: str | None,
) -> dict[str, Any]:
    archive_path = _jar_list_archive_arg(args)
    if not archive_path:
        return _empty_shell_effects()
    target = _scope_task_output_build_artifact_target_for_path(archive_path, cwd=shell_cwd)
    if target is None:
        return _empty_shell_effects()
    return {
        "effects": ["filesystem.read", "filesystem.enumerate"],
        "targets": [target],
        "rules": ["task_output_local_archive_inspection"],
        "confidence": "medium",
    }


def _shell_java_task_output_command_effects(
    tokens: list[str],
    shell_cwd: str | None,
) -> dict[str, Any]:
    jar_invocation = _java_local_jar_invocation(tokens)
    if jar_invocation is not None:
        jar_path, jar_program_args = jar_invocation
        jar_target = _java_fat_jar_execution_target(jar_path, cwd=shell_cwd)
        if jar_target is None:
            return _empty_shell_effects()
        program_targets = _java_program_arg_targets(jar_program_args, cwd=shell_cwd)
        if program_targets is None:
            return _empty_shell_effects()
        has_task_data_input = any(
            _target_is_effective_scope_task_data_read(target)
            for target in program_targets
        )
        has_task_output_write = any(
            _target_is_effective_scope_task_output(target)
            and target.io_direction == "target"
            for target in program_targets
        )
        if not has_task_data_input or not has_task_output_write:
            return _empty_shell_effects()
        return {
            "effects": ["command.exec", "filesystem.read", "filesystem.write"],
            "targets": _dedupe_targets([jar_target, *program_targets]),
            "rules": ["task_output_local_fat_jar_execution", "task_output_local_io_execution"],
            "confidence": "medium",
        }

    parsed = _java_local_main_invocation(tokens)
    if parsed is None:
        return _empty_shell_effects()
    classpath_entries, _main_class, program_args = parsed
    targets: list[ActionEffectTarget] = []
    has_task_output_execution_target = False
    for entry in classpath_entries:
        target = _java_classpath_entry_target(entry, cwd=shell_cwd)
        if target is None:
            return _empty_shell_effects()
        targets.append(target)
        if _target_is_effective_scope_task_output(target):
            has_task_output_execution_target = True
    if not has_task_output_execution_target:
        return _empty_shell_effects()

    program_targets = _java_program_arg_targets(program_args, cwd=shell_cwd)
    if program_targets is None:
        return _empty_shell_effects()
    has_task_data_input = any(
        _target_is_effective_scope_task_data_read(target)
        for target in program_targets
    )
    has_task_output_write = any(
        _target_is_effective_scope_task_output(target)
        and target.io_direction == "target"
        for target in program_targets
    )
    if not has_task_data_input or not has_task_output_write:
        return _empty_shell_effects()
    targets.extend(program_targets)
    return {
        "effects": ["command.exec", "filesystem.read", "filesystem.write"],
        "targets": _dedupe_targets(targets),
        "rules": ["task_output_local_artifact_execution", "task_output_local_io_execution"],
        "confidence": "medium",
    }


def _shell_maven_exec_java_task_output_command_effects(
    tokens: list[str],
    shell_cwd: str | None,
) -> dict[str, Any]:
    cwd_target = _scope_task_output_target_for_path(".", cwd=shell_cwd)
    if cwd_target is None:
        return _empty_shell_effects()
    parsed = _maven_exec_java_invocation(tokens)
    if parsed is None:
        return _empty_shell_effects()
    _main_class, program_args = parsed
    program_targets = _java_program_arg_targets(program_args, cwd=shell_cwd)
    if program_targets is None:
        return _empty_shell_effects()
    has_task_data_input = any(
        _target_is_effective_scope_task_data_read(target)
        for target in program_targets
    )
    has_task_output_write = any(
        _target_is_effective_scope_task_output(target)
        and target.io_direction == "target"
        for target in program_targets
    )
    if not has_task_data_input or not has_task_output_write:
        return _empty_shell_effects()
    targets = [
        cwd_target.model_copy(update={"io_direction": "source"}),
        *program_targets,
    ]
    return {
        "effects": ["command.exec", "filesystem.read", "filesystem.write"],
        "targets": _dedupe_targets(targets),
        "rules": ["task_output_local_maven_exec_java", "task_output_local_io_execution"],
        "confidence": "medium",
    }


def _shell_python_task_output_command_effects(
    tokens: list[str],
    shell_cwd: str | None,
    *,
    inline_source: str | None = None,
) -> dict[str, Any]:
    if _python_version_probe_tokens(tokens):
        cwd_target = _scope_task_output_target_for_path(".", cwd=shell_cwd)
        if cwd_target is None:
            return _empty_shell_effects()
        return {
            "effects": ["environment.probe"],
            "targets": [_probe_target(" ".join(tokens[:2]) if len(tokens) > 1 else "python"), cwd_target],
            "rules": ["shell_capability_probe", "task_output_env_probe"],
            "confidence": "medium",
        }

    module_name, module_arg_index = _python_module_invocation(tokens)
    if module_name == "venv":
        return _shell_python_venv_effects(tokens[module_arg_index + 1:], shell_cwd)

    if module_name in {"pip", "pip3"}:
        return _shell_python_pip_effects(tokens, module_arg_index, shell_cwd)

    if module_name == "pytest":
        return _shell_pytest_task_output_command_effects(tokens[module_arg_index + 1:], shell_cwd)

    if module_name == "py_compile":
        paths = _python_py_compile_targets(tokens[module_arg_index + 1:])
        if not paths:
            return _empty_shell_effects()
        targets = [
            _target_for_path(path, role=_path_role_for_read(path), cwd=shell_cwd)
            for path in paths[:3]
        ]
        rules = ["python_module_py_compile"]
        if targets and all(_target_is_effective_scope_task_output(target) for target in targets):
            rules = ["task_output_local_python_verify"]
        return {
            "effects": ["command.exec", "filesystem.read"],
            "targets": targets,
            "rules": rules,
            "confidence": "medium",
        }

    if module_name == "compileall":
        paths = _python_compileall_targets(tokens[module_arg_index + 1:])
        if paths is None:
            cwd_target = _scope_task_output_target_for_path(".", cwd=shell_cwd)
            return {
                "effects": ["command.exec"],
                "targets": [cwd_target] if cwd_target is not None else [],
                "rules": ["wrapper_chain_unresolved", "python_local_verify_unresolved"],
                "confidence": "high",
            }
        if not paths:
            return _empty_shell_effects()
        targets = [
            _scope_task_output_target_for_path(path, cwd=shell_cwd)
            for path in paths[:3]
        ]
        if not targets or any(target is None for target in targets):
            return _empty_shell_effects()
        return {
            "effects": ["command.exec", "filesystem.read", "filesystem.enumerate", "filesystem.write"],
            "targets": [target for target in targets if target is not None],
            "rules": ["task_output_local_python_verify"],
            "confidence": "medium",
        }

    if module_name == "json.tool":
        paths = _python_json_tool_input_targets(tokens[module_arg_index + 1:])
        if not paths:
            return _empty_shell_effects()
        targets = [
            _scope_task_output_target_for_path(path, cwd=shell_cwd)
            for path in paths[:1]
        ]
        if not targets or any(target is None for target in targets):
            return _empty_shell_effects()
        return {
            "effects": ["command.exec", "filesystem.read"],
            "targets": [target for target in targets if target is not None],
            "rules": ["task_output_local_python_verify"],
            "confidence": "medium",
        }

    inline_code = _python_inline_code_arg(tokens)
    if inline_code is not None:
        return _shell_python_inline_task_output_verify_effects(inline_code, shell_cwd)
    if inline_source is not None and "-" in tokens[1:]:
        return _shell_python_inline_task_output_verify_effects(inline_source, shell_cwd)

    script_path = _python_script_path_arg(tokens)
    if script_path is None:
        return _empty_shell_effects()
    target = _scope_task_output_target_for_path(script_path, cwd=shell_cwd)
    if target is None:
        return _empty_shell_effects()
    return {
        "effects": ["command.exec", "filesystem.read"],
        "targets": [target],
        "rules": ["task_output_local_artifact_execution"],
        "confidence": "medium",
    }


def _shell_pytest_task_output_command_effects(
    args: list[str],
    shell_cwd: str | None,
) -> dict[str, Any]:
    cwd_target = _scope_task_output_target_for_path(".", cwd=shell_cwd)
    if cwd_target is None:
        return _empty_shell_effects()
    targets: list[ActionEffectTarget] = [cwd_target]
    for path in _pytest_path_args(args):
        target = _scope_task_output_target_for_path(path, cwd=shell_cwd)
        if target is None:
            return _empty_shell_effects()
        targets.append(target)
    return {
        "effects": ["command.exec", "filesystem.read", "filesystem.enumerate"],
        "targets": _dedupe_targets(targets),
        "rules": ["task_output_local_test_execution"],
        "confidence": "medium",
    }


def _shell_local_build_task_output_command_effects(
    tokens: list[str],
    shell_cwd: str | None,
) -> dict[str, Any]:
    cwd_target = _scope_task_output_target_for_path(".", cwd=shell_cwd)
    if cwd_target is None:
        return _empty_shell_effects()
    command = Path(tokens[0]).name.lower()
    args = tokens[1:]
    if any(_URL_RE.match(str(token or "").strip()) for token in tokens[1:]):
        return _empty_shell_effects()
    if not _local_build_command_shape_is_supported(command, args):
        return _empty_shell_effects()
    targets: list[ActionEffectTarget] = [cwd_target]
    for path in _local_build_path_args(args):
        target = _scope_task_output_target_for_path(path, cwd=shell_cwd)
        if target is None:
            return _empty_shell_effects()
        targets.append(target)
    return {
        "effects": [
            "command.exec",
            "filesystem.read",
            "filesystem.enumerate",
            "filesystem.write",
        ],
        "targets": _dedupe_targets(targets),
        "rules": ["task_output_local_build_execution"],
        "confidence": "medium",
    }


def _shell_git_task_output_readonly_effects(
    args: list[str],
    shell_cwd: str | None,
) -> dict[str, Any]:
    git_cwd = _git_effective_worktree_cwd(args, shell_cwd)
    cwd_target = _scope_task_output_target_for_path(".", cwd=git_cwd)
    if cwd_target is None:
        return _empty_shell_effects()
    if _git_readonly_has_disallowed_option(args):
        return _empty_shell_effects()
    parsed = _git_readonly_parse_args(args)
    if parsed is None:
        return _empty_shell_effects()
    subcommand, scoped_paths = parsed
    if subcommand not in {"status", "diff", "show", "log", "rev-parse", "ls-files"}:
        return _empty_shell_effects()
    targets: list[ActionEffectTarget] = [cwd_target]
    for path in scoped_paths:
        target = _scope_task_output_target_for_path(path, cwd=git_cwd)
        if target is None:
            return _empty_shell_effects()
        targets.append(target)
    return {
        "effects": ["command.exec", "filesystem.read", "filesystem.enumerate"],
        "targets": _dedupe_targets(targets),
        "rules": ["task_output_local_vcs_inspection"],
        "confidence": "medium",
    }


def _shell_git_task_output_mutation_effects(
    args: list[str],
    shell_cwd: str | None,
) -> dict[str, Any]:
    if _git_apply_has_disallowed_global_option(args):
        return _empty_shell_effects()
    git_cwd = _git_effective_worktree_cwd(args, shell_cwd)
    cwd_target = _scope_task_output_target_for_path(".", cwd=git_cwd)
    if cwd_target is None:
        return _empty_shell_effects()
    parsed = _git_parse_global_options_and_subcommand(args)
    if parsed is None:
        return _empty_shell_effects()
    subcommand, subcommand_args = parsed
    if subcommand != "apply":
        return _empty_shell_effects()
    if _git_apply_has_disallowed_option(subcommand_args):
        return _empty_shell_effects()
    patch_paths = _git_apply_patch_path_args(subcommand_args)
    if not patch_paths:
        return _empty_shell_effects()
    targets: list[ActionEffectTarget] = [cwd_target]
    source_targets: list[ActionEffectTarget] = []
    for path in patch_paths:
        if _URL_RE.match(str(path or "").strip()):
            return _empty_shell_effects()
        source_target = _scope_task_output_or_data_read_target_for_path(path, cwd=git_cwd)
        if source_target is None:
            return _empty_shell_effects()
        source_targets.append(source_target.model_copy(update={"io_direction": "source"}))
    targets.extend(source_targets[:3])
    return {
        "effects": ["command.exec", "filesystem.read", "filesystem.write"],
        "targets": _dedupe_targets(targets),
        "rules": ["task_output_local_vcs_patch_apply"],
        "confidence": "medium",
    }


def _shell_python_inline_task_output_verify_effects(
    code: str,
    shell_cwd: str | None,
) -> dict[str, Any]:
    source = _inline_python_source(code) or code
    targets = _python_local_verify_task_output_targets(source, cwd=shell_cwd)
    if not targets:
        return _empty_shell_effects()
    sys_path_targets = _python_sys_path_task_output_targets(source, cwd=shell_cwd)
    has_static_task_output_sys_path = bool(sys_path_targets)
    import_smoke_safe = _python_inline_import_smoke_test_is_scope_safe(source, cwd=shell_cwd)
    readonly_safe = _python_inline_verify_code_is_readonly(source)
    if has_static_task_output_sys_path and not import_smoke_safe:
        readonly_safe = False
    if (
        not readonly_safe
        and not import_smoke_safe
    ):
        return {
            "effects": ["command.exec"],
            "targets": targets,
            "rules": ["wrapper_chain_unresolved", "python_local_verify_unresolved"],
            "confidence": "high",
        }
    return {
        "effects": ["command.exec", "filesystem.read", "filesystem.enumerate"],
        "targets": targets,
        "rules": ["task_output_local_python_verify"],
        "confidence": "medium",
    }


def _shell_python_venv_effects(args: list[str], shell_cwd: str | None) -> dict[str, Any]:
    target_paths, parsed, upgrade_deps = _python_venv_target_paths(args)
    if not parsed or not target_paths:
        return _empty_shell_effects()
    if upgrade_deps:
        return {
            "effects": ["command.exec", "filesystem.write", "package.install", "network.fetch"],
            "targets": [
                _target_for_path(path, cwd=shell_cwd, io_direction="target")
                for path in target_paths[:3]
            ],
            "rules": ["python_module_venv", "python_venv_upgrade_deps", "package_install", "network_equivalent_fetch"],
            "confidence": "high",
        }
    targets = _python_venv_task_output_targets(target_paths, shell_cwd)
    if not targets:
        return {
            "effects": ["command.exec", "filesystem.write"],
            "targets": [
                _target_for_path(path, cwd=shell_cwd, io_direction="target")
                for path in target_paths[:3]
            ],
            "rules": ["python_module_venv"],
            "confidence": "medium",
        }
    return {
        "effects": ["command.exec", "filesystem.write"],
        "targets": targets,
        "rules": ["task_output_env_setup"],
        "confidence": "medium",
    }


def _shell_python_pip_effects(
    tokens: list[str],
    module_arg_index: int,
    shell_cwd: str | None,
) -> dict[str, Any]:
    pip_args = tokens[module_arg_index + 1:]
    subcommand, subcommand_index = _pip_install_subcommand(pip_args)
    if subcommand != "install":
        return _empty_shell_effects()
    preinstall_args = pip_args[:subcommand_index]
    install_args = pip_args[subcommand_index + 1:]
    if not _pip_preinstall_args_are_scope_safe(preinstall_args, shell_cwd):
        return _python_pip_unscoped_install_effects([*preinstall_args, *install_args], shell_cwd)
    if not _uv_pip_install_args_are_scope_safe(install_args, shell_cwd):
        return _python_pip_unscoped_install_effects(install_args, shell_cwd)

    targets: list[ActionEffectTarget] = []
    destination_targets: list[ActionEffectTarget] = []
    pip_python_path = _uv_option_path(preinstall_args, "--python")
    interpreter_path = pip_python_path or tokens[0]
    venv_path = _python_explicit_interpreter_venv_root(interpreter_path, shell_cwd=shell_cwd)
    if venv_path:
        target = _scope_task_output_target_for_path(venv_path, cwd=None)
        if target is not None:
            destination_targets.append(target)

    for path in _pip_output_paths(install_args):
        target = _scope_task_output_target_for_path(path, cwd=shell_cwd)
        if target is not None:
            destination_targets.append(target)

    if not destination_targets:
        return _empty_shell_effects()

    targets.extend(destination_targets)
    for path in _uv_editable_paths(install_args):
        target = _scope_task_output_target_for_path(path, cwd=shell_cwd)
        if target is not None:
            targets.append(target)

    targets = _dedupe_targets(targets)
    if not targets:
        return _empty_shell_effects()
    return {
        "effects": ["command.exec", "filesystem.write", "package.install"],
        "targets": targets,
        "rules": ["task_output_env_setup"],
        "confidence": "medium",
    }


def _shell_uv_task_output_command_effects(
    tokens: list[str],
    shell_cwd: str | None,
) -> dict[str, Any]:
    if _shell_tokens_have_remote_package_reference(tokens):
        return _empty_shell_effects()
    subcommand, subcommand_index = _uv_subcommand(tokens)
    if subcommand is None:
        return _empty_shell_effects()
    if not _uv_global_options_are_scope_safe(tokens[1:subcommand_index], shell_cwd):
        return _empty_shell_effects()
    if subcommand == "venv":
        return _shell_uv_venv_effects(tokens[subcommand_index + 1:], shell_cwd)
    if subcommand == "sync":
        return _shell_uv_sync_effects(tokens, tokens[subcommand_index + 1:], shell_cwd)
    if subcommand == "pip":
        return _shell_uv_pip_effects(tokens[subcommand_index + 1:], shell_cwd)
    if subcommand == "run":
        return _shell_uv_run_effects(tokens[subcommand_index + 1:], shell_cwd)
    return _empty_shell_effects()


def _shell_uv_venv_effects(args: list[str], shell_cwd: str | None) -> dict[str, Any]:
    if not _uv_task_output_lane_args_are_scope_safe(args, shell_cwd):
        return _empty_shell_effects()
    target_path = ".venv"
    index = 0
    value_flags = {"--python", "-p", "--seed", "--prompt", "--index-url"}
    while index < len(args):
        token = args[index]
        if token == "--":
            if index + 1 < len(args):
                target_path = args[index + 1]
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
        target_path = token
        break
    target = _scope_task_output_target_for_path(target_path, cwd=shell_cwd)
    if target is None:
        return _empty_shell_effects()
    return {
        "effects": ["command.exec", "filesystem.write"],
        "targets": [target],
        "rules": ["task_output_env_setup"],
        "confidence": "medium",
    }


def _shell_uv_sync_effects(tokens: list[str], args: list[str], shell_cwd: str | None) -> dict[str, Any]:
    if not _uv_task_output_lane_args_are_scope_safe(args, shell_cwd):
        return _empty_shell_effects()
    project_path = _uv_option_path(tokens, "--project") or _uv_option_path(tokens, "--directory") or "."
    target = _scope_task_output_target_for_path(project_path, cwd=shell_cwd)
    if target is None:
        return _empty_shell_effects()
    return {
        "effects": ["command.exec", "filesystem.write", "package.install"],
        "targets": [target],
        "rules": ["task_output_env_setup"],
        "confidence": "medium",
    }


def _shell_uv_pip_effects(args: list[str], shell_cwd: str | None) -> dict[str, Any]:
    subcommand, subcommand_index = _uv_pip_subcommand(args)
    if subcommand != "install":
        return _empty_shell_effects()
    preinstall_args = args[:subcommand_index]
    install_args = args[subcommand_index + 1:]
    if not _uv_pip_install_args_are_scope_safe(preinstall_args, shell_cwd):
        return _empty_shell_effects()
    if not _uv_pip_install_args_are_scope_safe(install_args, shell_cwd):
        return _empty_shell_effects()
    targets: list[ActionEffectTarget] = []
    option_args = [*preinstall_args, *install_args]
    python_path = _uv_option_path(option_args, "--python") or _uv_short_option_path(option_args, "-p")
    venv_path = _python_executable_venv_root(python_path, shell_cwd=shell_cwd)
    if venv_path:
        target = _scope_task_output_target_for_path(venv_path, cwd=None)
        if target is not None:
            targets.append(target)
    for editable_path in _uv_editable_paths(install_args):
        target = _scope_task_output_target_for_path(editable_path, cwd=shell_cwd)
        if target is not None:
            targets.append(target)
    cwd_target = _scope_task_output_target_for_path(".", cwd=shell_cwd)
    if cwd_target is not None:
        targets.append(cwd_target)
    targets = _dedupe_targets(targets)
    if not targets or not any(_target_is_effective_scope_task_output(target) for target in targets):
        return _empty_shell_effects()
    return {
        "effects": ["command.exec", "filesystem.write", "package.install"],
        "targets": targets,
        "rules": ["task_output_env_setup"],
        "confidence": "medium",
    }


def _shell_uv_run_effects(args: list[str], shell_cwd: str | None) -> dict[str, Any]:
    if not _uv_task_output_lane_args_are_scope_safe(args, shell_cwd):
        return _empty_shell_effects()
    command_tokens = _uv_run_command_tokens(args)
    if not command_tokens:
        return _empty_shell_effects()
    command = Path(command_tokens[0]).name.lower()
    if command == "pytest":
        return _shell_pytest_task_output_command_effects(command_tokens[1:], shell_cwd)
    if _is_python_interpreter_name(command):
        return _shell_python_task_output_command_effects(command_tokens, shell_cwd)
    script_path: str | None = None
    if _looks_like_path_arg(command_tokens[0]) or command_tokens[0].endswith(_EXECUTABLE_SUFFIXES):
        script_path = command_tokens[0]
    if script_path is None:
        return _empty_shell_effects()
    target = _scope_task_output_target_for_path(script_path, cwd=shell_cwd)
    if target is None:
        return _empty_shell_effects()
    return {
        "effects": ["command.exec", "filesystem.read"],
        "targets": [target],
        "rules": ["task_output_local_artifact_execution"],
        "confidence": "medium",
    }


def _shell_tokens_have_remote_package_reference(tokens: list[str]) -> bool:
    for token in tokens:
        lowered = str(token or "").strip().lower()
        if not lowered:
            continue
        if _URL_RE.search(lowered):
            return True
        if lowered.startswith(("git+", "hg+", "svn+", "bzr+", "ssh://", "git://", "file://")):
            return True
    return False


def _shell_c_payload(tokens: list[str]) -> str:
    for index, token in enumerate(tokens[:-1]):
        if token == "-c" or re.fullmatch(r"-[A-Za-z]*c[A-Za-z]*", token):
            return str(tokens[index + 1] or "")
    return ""


def _shell_write_payload_texts(text: str) -> list[str]:
    payloads: list[str] = []
    lines = str(text or "").splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        delimiter = _heredoc_delimiter_from_line(line)
        if not delimiter:
            index += 1
            continue
        if not (
            re.search(r"(?:^|\s)(?:cat|tee)\b[^;&|]*(?:>|tee)\s*", line)
            or re.search(r"(?:^|\s)cat\b.*\|\s*tee\b", line)
            or re.search(r"(?:^|\s)tee\b", line)
        ):
            index += 1
            continue
        strip_tabs = _heredoc_strips_leading_tabs(line)
        body: list[str] = []
        index += 1
        while index < len(lines) and lines[index].strip() != delimiter:
            body.append(lines[index].lstrip("\t") if strip_tabs else lines[index])
            index += 1
        if body:
            payloads.append("\n".join(body))
        if index < len(lines):
            index += 1
    return payloads
_SHELL_REDIRECT_TOKENS = frozenset({">", ">>", ">|", "<>", "<<", "&>", ">&"})


def _shell_markitdown_source_args(tokens: list[str]) -> list[str]:
    sources: list[str] = []
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token in {">", ">>", ">|", "<>", "<<"} or token.startswith((">", "<<")):
            break
        if token in _STDOUT_CONVERTER_OUTPUT_FLAGS or any(
            token.startswith(f"{flag}=") for flag in _STDOUT_CONVERTER_OUTPUT_FLAGS
        ):
            index += 2 if token in _STDOUT_CONVERTER_OUTPUT_FLAGS else 1
            continue
        if token == "--":
            sources.extend(_read_probe_source_args(tokens[index + 1:]))
            break
        if token.startswith("--") and "=" in token:
            index += 1
            continue
        if token in _STDOUT_CONVERTER_VALUE_FLAGS:
            index += 2
            continue
        if token.startswith("-") and token != "-":
            index += 1
            continue
        sources.append(token)
        index += 1
    return _read_probe_source_args(sources)


def _shell_python_module_markitdown_tokens(tokens: list[str]) -> list[str]:
    if len(tokens) < 4 or tokens[1] != "-m" or tokens[2] != "markitdown":
        return []
    return [tokens[2], *tokens[3:]]


def _shell_python_module_markitdown_source_args(tokens: list[str]) -> list[str]:
    markitdown_tokens = _shell_python_module_markitdown_tokens(tokens)
    if not markitdown_tokens:
        return []
    return _shell_markitdown_source_args(markitdown_tokens)


def _shell_python_module_zipfile_list_source_args(tokens: list[str]) -> list[str]:
    if len(tokens) < 5 or tokens[1] != "-m" or tokens[2] != "zipfile":
        return []
    args = tokens[3:]
    if not args:
        return []
    list_mode = False
    sources: list[str] = []
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            sources.extend(_read_probe_source_args(args[index + 1:]))
            break
        if token in {"-l", "--list"}:
            list_mode = True
            index += 1
            continue
        if token in {"-e", "--extract", "-c", "--create", "-t", "--test"}:
            return []
        if token.startswith("-"):
            index += 1
            continue
        sources.append(token)
        index += 1
    if not list_mode:
        return []
    return _read_probe_source_args(sources)


def _shell_stdout_path_enumerate_args(command: str, tokens: list[str]) -> list[str]:
    if command not in {"echo", "printf"}:
        return []
    args = tokens[1:]
    if command == "printf" and args:
        args = args[1:]
    candidates: list[str] = []
    for token in args:
        if token in {"--"}:
            continue
        if any(marker in token for marker in ("$(", "`", "(", ")")):
            continue
        if token.startswith("-") and not _looks_like_path_arg(token):
            continue
        if _shell_stdout_token_is_labelled_path(token):
            continue
        if _looks_like_path_arg(token) and ("/" in token or _path_has_glob(token)):
            candidates.append(_glob_base_path(token) if _path_has_glob(token) else token)
    return _dedupe_strings(candidates)


def _shell_stdout_token_is_labelled_path(token: str) -> bool:
    if re.match(r"^[A-Za-z]:[\\/]", token):
        return False
    return bool(re.match(r"^[A-Za-z_][A-Za-z0-9_.-]{1,31}:(?:/|~|\.{1,2}/)", token))


def _shell_pdftotext_positionals(tokens: list[str]) -> list[str]:
    return _shell_positionals_after_options(tokens, value_flags=_PDFTOTEXT_VALUE_FLAGS)


def _shell_pdftotext_source_args(tokens: list[str]) -> list[str]:
    positionals = _shell_pdftotext_positionals(tokens)
    return positionals[:1]


def _shell_pdftotext_write_targets(tokens: list[str]) -> tuple[list[str], bool]:
    positionals = _shell_pdftotext_positionals(tokens)
    if len(positionals) >= 2:
        output = positionals[1]
        return ([] if output == "-" else [output], False)
    if positionals:
        return ([], True)
    return ([], False)


def _shell_pandoc_source_args(tokens: list[str]) -> list[str]:
    sources = []
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if _shell_token_starts_redirect(token):
            break
        if _shell_token_is_output_flag(token, _STDOUT_CONVERTER_OUTPUT_FLAGS):
            index += 2 if token in _STDOUT_CONVERTER_OUTPUT_FLAGS else 1
            continue
        if token == "--":
            sources.extend(_read_probe_source_args(tokens[index + 1:]))
            break
        if token.startswith("--") and "=" in token:
            index += 1
            continue
        if token in _PANDOC_VALUE_FLAGS:
            index += 2
            continue
        if token.startswith("-") and token != "-":
            index += 1
            continue
        sources.append(token)
        index += 1
    return _read_probe_source_args(sources)


def _shell_strings_source_args(tokens: list[str]) -> list[str]:
    return [
        token
        for token in _shell_positionals_after_options(tokens, value_flags=_STRINGS_VALUE_FLAGS)
        if not re.fullmatch(r"\d+", token)
    ]


def _shell_pandoc_write_targets(tokens: list[str]) -> list[str]:
    return _shell_output_flag_targets(tokens, _STDOUT_CONVERTER_OUTPUT_FLAGS)


def _shell_unzip_source_args(tokens: list[str]) -> list[str]:
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if _shell_token_starts_redirect(token):
            return []
        if token == "--":
            return _read_probe_source_args(tokens[index + 1:index + 2])
        if token in {"-d", "-x", "-P", "-O", "-I"}:
            index += 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        return [token]
    return []


def _shell_unzip_write_targets(tokens: list[str]) -> tuple[list[str], bool]:
    if _shell_unzip_is_stdout_or_listing(tokens):
        return ([], False)
    targets = _shell_output_flag_targets(tokens, frozenset({"-d"}))
    return (targets, not targets and bool(_shell_unzip_source_args(tokens)))


def _shell_unzip_is_stdout_or_listing(tokens: list[str]) -> bool:
    return any(_unzip_token_is_read_mode(token) for token in tokens[1:])


def _shell_gzip_is_stdout_or_listing(command: str, tokens: list[str]) -> bool:
    if command == "zcat":
        return True
    return any(_gzip_token_is_read_mode(token) for token in tokens[1:])


def _shell_gzip_positionals(tokens: list[str]) -> list[str]:
    return _shell_positionals_after_options(tokens, value_flags=_GZIP_VALUE_FLAGS)


def _shell_gzip_stdout_source_args(command: str, tokens: list[str]) -> list[str]:
    if not _shell_gzip_is_stdout_or_listing(command, tokens):
        return []
    return _shell_gzip_positionals(tokens)


def _shell_gzip_has_unscoped_write_redirect(
    tokens: list[str],
    shell_cwd: str | None,
) -> bool:
    redirects = _shell_write_redirect_targets_from_tokens(tokens, shell_cwd)
    return any(_scope_task_output_target_for_path(path) is None for path in redirects)


def _shell_write_redirect_targets_from_tokens(
    tokens: list[str],
    shell_cwd: str | None,
) -> list[str]:
    paths: list[str] = []
    write_redirect_ops = {">", ">>", "&>", ">&", ">|"}
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


def _shell_docx2txt_positionals(tokens: list[str]) -> list[str]:
    return _shell_positionals_after_options(tokens, value_flags=_DOCX2TXT_VALUE_FLAGS)


def _shell_docx2txt_source_args(tokens: list[str]) -> list[str]:
    positionals = _shell_docx2txt_positionals(tokens)
    return positionals[:1]


def _shell_docx2txt_write_targets(tokens: list[str]) -> tuple[list[str], bool]:
    targets = _shell_output_flag_targets(tokens, _DOCX2TXT_IMAGE_OUTPUT_FLAGS)
    for token in tokens[1:]:
        if token.startswith("-i") and token != "-i" and not token.startswith("--"):
            targets.append(token[2:])
    positionals = _shell_docx2txt_positionals(tokens)
    if len(positionals) >= 2 and positionals[1] != "-":
        targets.append(positionals[1])
    return (_dedupe_strings(targets), False)


def _shell_soffice_has_convert_to(tokens: list[str]) -> bool:
    return any(token == "--convert-to" or token.startswith("--convert-to=") for token in tokens[1:])


def _shell_soffice_source_args(tokens: list[str]) -> list[str]:
    if not _shell_soffice_has_convert_to(tokens):
        return []
    return _shell_positionals_after_options(tokens, value_flags=_SOFFICE_VALUE_FLAGS)


def _shell_soffice_write_targets(tokens: list[str]) -> tuple[list[str], bool]:
    if not _shell_soffice_has_convert_to(tokens):
        return ([], False)
    targets = _shell_output_flag_targets(tokens, _SOFFICE_OUTPUT_FLAGS)
    unknown = bool(_shell_soffice_source_args(tokens)) and not targets
    return (_dedupe_strings(targets), unknown)


def _shell_bsdtar_option_value_target(tokens: list[str], flags: frozenset[str]) -> list[str]:
    targets: list[str] = []
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if _shell_token_starts_redirect(token):
            break
        if "-C" in flags and token.startswith("-C") and token != "-C" and not token.startswith("--"):
            targets.append(token[2:])
            index += 1
            continue
        if token in flags:
            if index + 1 < len(tokens):
                targets.append(tokens[index + 1])
            index += 2
            continue
        for flag in flags:
            if token.startswith(f"{flag}="):
                targets.append(token.split("=", 1)[1])
                break
        index += 1
    return targets


def _shell_bsdtar_short_option_letters(token: str) -> str:
    if not token.startswith("-") or token.startswith("--") or token == "-":
        return ""
    letters: list[str] = []
    for index, char in enumerate(token[1:]):
        letters.append(char)
        if char in {"C", "f"} and index + 1 < len(token[1:]):
            break
    return "".join(letters)


def _shell_bsdtar_source_args(tokens: list[str]) -> list[str]:
    sources: list[str] = []
    fallback_positionals: list[str] = []
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if _shell_token_starts_redirect(token):
            break
        if token == "--":
            fallback_positionals.extend(_read_probe_source_args(tokens[index + 1:index + 2]))
            break
        if token in _BSDTAR_VALUE_FLAGS:
            index += 2
            continue
        if any(token.startswith(f"{flag}=") for flag in _BSDTAR_VALUE_FLAGS if flag.startswith("--")):
            index += 1
            continue
        if token in {"-f", "--file"}:
            if index + 1 < len(tokens):
                sources.append(tokens[index + 1])
            index += 2
            continue
        if token.startswith("--file="):
            sources.append(token.split("=", 1)[1])
            index += 1
            continue
        if token.startswith("-") and not token.startswith("--"):
            options = token[1:]
            if "f" in options:
                after_file_flag = options.split("f", 1)[1]
                if after_file_flag:
                    sources.append(after_file_flag)
                    index += 1
                elif index + 1 < len(tokens):
                    sources.append(tokens[index + 1])
                    index += 2
                else:
                    index += 1
                continue
            index += 1
            continue
        fallback_positionals.append(token)
        index += 1
    return _read_probe_source_args(sources[:1] or fallback_positionals[:1])


def _shell_bsdtar_has_mode(tokens: list[str], *, long_names: frozenset[str], short_letters: str) -> bool:
    for token in tokens[1:]:
        if token in long_names:
            return True
        option_letters = _shell_bsdtar_short_option_letters(token)
        if option_letters:
            if any(letter in option_letters for letter in short_letters):
                return True
    return False


def _shell_bsdtar_has_exec_program_option(tokens: list[str]) -> bool:
    return any(
        token == "--use-compress-program"
        or token.startswith("--use-compress-program=")
        for token in tokens[1:]
    )


def _shell_bsdtar_is_stdout_or_listing(tokens: list[str]) -> bool:
    if _shell_bsdtar_has_mode(
        tokens,
        long_names=frozenset({"--list", "--test", "--to-stdout", "--stdout"}),
        short_letters="tO",
    ):
        return True
    return False


def _shell_bsdtar_write_targets(tokens: list[str]) -> tuple[list[str], bool]:
    if _shell_bsdtar_is_stdout_or_listing(tokens):
        return ([], False)
    if _shell_bsdtar_has_mode(tokens, long_names=frozenset({"--create"}), short_letters="c"):
        return (_shell_bsdtar_source_args(tokens), False)
    if _shell_bsdtar_has_mode(tokens, long_names=frozenset({"--extract", "--get"}), short_letters="x"):
        return (_shell_bsdtar_option_value_target(tokens, frozenset({"-C", "--directory"})), True)
    return ([], False)


def _shell_converter_write_targets(text: str) -> dict[str, Any]:
    targets: list[str] = []
    unknown_write = False
    for tokens in _shell_segments(text):
        if not tokens:
            continue
        command = Path(tokens[0]).name.lower()
        if command == "markitdown":
            targets.extend(_shell_output_flag_targets(tokens, _STDOUT_CONVERTER_OUTPUT_FLAGS))
        elif command in {"python", "python3"}:
            markitdown_tokens = _shell_python_module_markitdown_tokens(tokens)
            if markitdown_tokens:
                targets.extend(_shell_output_flag_targets(markitdown_tokens, _STDOUT_CONVERTER_OUTPUT_FLAGS))
        elif command == "pdftotext":
            write_targets, unknown = _shell_pdftotext_write_targets(tokens)
            targets.extend(write_targets)
            unknown_write = unknown_write or unknown
        elif command == "pandoc":
            targets.extend(_shell_pandoc_write_targets(tokens))
        elif command == "unzip":
            write_targets, unknown = _shell_unzip_write_targets(tokens)
            targets.extend(write_targets)
            unknown_write = unknown_write or unknown
        elif command == "bsdtar":
            write_targets, unknown = _shell_bsdtar_write_targets(tokens)
            targets.extend(write_targets)
            unknown_write = unknown_write or unknown
        elif command == "docx2txt":
            write_targets, unknown = _shell_docx2txt_write_targets(tokens)
            targets.extend(write_targets)
            unknown_write = unknown_write or unknown
        elif command in {"soffice", "libreoffice"}:
            write_targets, unknown = _shell_soffice_write_targets(tokens)
            targets.extend(write_targets)
            unknown_write = unknown_write or unknown
    return {"targets": _dedupe_strings(targets), "unknown_write": unknown_write}


def _shell_positionals_after_options(tokens: list[str], *, value_flags: frozenset[str]) -> list[str]:
    positionals: list[str] = []
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if _shell_token_starts_redirect(token):
            break
        if token == "--":
            positionals.extend(_read_probe_source_args(tokens[index + 1:]))
            break
        if token.startswith("--") and "=" in token:
            index += 1
            continue
        if token in value_flags:
            index += 2
            continue
        if token.startswith("-") and token != "-":
            index += 1
            continue
        positionals.append(token)
        index += 1
    return _read_probe_source_args(positionals)


def _shell_output_flag_targets(tokens: list[str], flags: frozenset[str]) -> list[str]:
    targets: list[str] = []
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if _shell_token_starts_redirect(token):
            break
        if token in flags:
            if index + 1 < len(tokens):
                targets.append(tokens[index + 1])
            index += 2
            continue
        for flag in flags:
            if token.startswith(f"{flag}="):
                targets.append(token.split("=", 1)[1])
                break
            if flag == "-o" and token.startswith("-o") and len(token) > 2:
                targets.append(token[2:])
                break
        index += 1
    return [target for target in targets if target and target != "-"]


def _shell_token_is_output_flag(token: str, flags: frozenset[str]) -> bool:
    return token in flags or any(token.startswith(f"{flag}=") for flag in flags)


def _shell_token_starts_redirect(token: str) -> bool:
    return token in _SHELL_REDIRECT_TOKENS or token.startswith((">", "<<"))


_SHELL_SEARCH_VALUE_OPTIONS = frozenset({
    "-A",
    "-B",
    "-C",
    "-m",
    "-e",
    "-f",
    "-g",
    "-t",
    "-T",
    "-j",
    "--after-context",
    "--before-context",
    "--context",
    "--max-count",
    "--regexp",
    "--file",
    "--glob",
    "--type",
    "--threads",
    "--include",
    "--exclude",
    "--exclude-dir",
})
_SHELL_SEARCH_INLINE_VALUE_OPTION_PREFIXES = ("-A", "-B", "-C", "-m")
_SHELL_SEARCH_PATTERN_OPTIONS = frozenset({"-e", "--regexp"})
_SHELL_SEARCH_PATTERN_FILE_OPTIONS = frozenset({"-f", "--file"})
_SHELL_SEARCH_AUXILIARY_FILE_OPTIONS = frozenset({
    "--exclude-from",
    "--ignore-file",
    "--path-to-ignore",
})
_SHELL_SEARCH_FILE_VALUE_OPTIONS = _SHELL_SEARCH_PATTERN_FILE_OPTIONS | _SHELL_SEARCH_AUXILIARY_FILE_OPTIONS
_SHELL_SEARCH_EXEC_OPTIONS = frozenset({"--pager", "--pre", "--pre-glob"})


def _shell_search_source_args(command: str, tokens: list[str]) -> list[str]:
    del command  # The search-family grammar is intentionally shared here.
    sources: list[str] = []
    positionals: list[str] = []
    pattern_from_option = False
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token in {">", ">>", ">|", "<>", "<<"} or token.startswith((">", "<<")):
            break
        if token == "<":
            if index + 1 < len(tokens):
                sources.append(tokens[index + 1])
            break
        if token == "--":
            positionals.extend(_read_probe_source_args(tokens[index + 1:]))
            break
        if token.startswith("--") and "=" in token:
            option, value = token.split("=", 1)
            if option in _SHELL_SEARCH_PATTERN_OPTIONS:
                pattern_from_option = True
            elif option in _SHELL_SEARCH_FILE_VALUE_OPTIONS:
                sources.append(value)
                if option in _SHELL_SEARCH_PATTERN_FILE_OPTIONS:
                    pattern_from_option = True
            index += 1
            continue
        if token in _SHELL_SEARCH_PATTERN_OPTIONS:
            pattern_from_option = True
            index += 2
            continue
        if token in _SHELL_SEARCH_FILE_VALUE_OPTIONS:
            if index + 1 < len(tokens):
                sources.append(tokens[index + 1])
            if token in _SHELL_SEARCH_PATTERN_FILE_OPTIONS:
                pattern_from_option = True
            index += 2
            continue
        if token.startswith("-e") and len(token) > 2 and not token.startswith("--"):
            pattern_from_option = True
            index += 1
            continue
        if token.startswith("-f") and len(token) > 2 and not token.startswith("--"):
            sources.append(token[2:])
            pattern_from_option = True
            index += 1
            continue
        if token in _SHELL_SEARCH_VALUE_OPTIONS:
            index += 2
            continue
        if any(
            token.startswith(prefix) and len(token) > len(prefix)
            for prefix in _SHELL_SEARCH_INLINE_VALUE_OPTION_PREFIXES
        ):
            index += 1
            continue
        if token.startswith("-") and token != "-":
            index += 1
            continue
        positionals.append(token)
        index += 1

    if pattern_from_option:
        sources.extend(positionals)
    elif positionals:
        sources.extend(positionals[1:])
    return _read_probe_source_args(sources)


def _shell_search_tokens_are_readonly(command: str, tokens: list[str]) -> bool:
    if _shell_search_tokens_have_execution_option(command, tokens):
        return False
    candidate_paths = [
        arg for arg in _shell_search_source_args(command, tokens)
        if _looks_like_path_arg(arg)
    ]
    if candidate_paths and not all(
        _is_scope_task_artifact_readonly_path(_glob_base_path(path))
        for path in candidate_paths
    ):
        return False
    return True


def _shell_search_tokens_have_execution_option(command: str, tokens: list[str]) -> bool:
    if command not in {"rg", "ripgrep", "ag"}:
        return False
    return any(
        token in _SHELL_SEARCH_EXEC_OPTIONS
        or any(token.startswith(f"{option}=") for option in _SHELL_SEARCH_EXEC_OPTIONS)
        for token in tokens[1:]
    )


_SHELL_JQ_FILTER_FILE_FLAGS = frozenset({"-f", "--from-file"})
_SHELL_JQ_FILE_VALUE_FLAGS = _SHELL_JQ_FILTER_FILE_FLAGS | frozenset({"-L", "--library-path", "--run-tests"})
_SHELL_JQ_NAMED_FILE_FLAGS = frozenset({"--argfile", "--slurpfile", "--rawfile"})
_SHELL_JQ_TWO_VALUE_FLAGS = frozenset({"--arg", "--argjson"})
_SHELL_JQ_ONE_VALUE_FLAGS = frozenset({"--indent", "--stream-errors", "--seq"})


def _shell_jq_source_args(tokens: list[str]) -> list[str]:
    sources: list[str] = []
    positionals: list[str] = []
    filter_from_file = False
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token in {">", ">>", ">|", "<>", "<<"} or token.startswith((">", "<<")):
            break
        if token == "<":
            if index + 1 < len(tokens):
                sources.append(tokens[index + 1])
            break
        if token == "--":
            positionals.extend(_read_probe_source_args(tokens[index + 1:]))
            break
        if token.startswith("--") and "=" in token:
            option, value = token.split("=", 1)
            if option in _SHELL_JQ_FILE_VALUE_FLAGS:
                sources.append(value)
                if option in _SHELL_JQ_FILTER_FILE_FLAGS:
                    filter_from_file = True
            index += 1
            continue
        if token in _SHELL_JQ_FILE_VALUE_FLAGS:
            if index + 1 < len(tokens):
                sources.append(tokens[index + 1])
            if token in _SHELL_JQ_FILTER_FILE_FLAGS:
                filter_from_file = True
            index += 2
            continue
        if token.startswith("-f") and len(token) > 2 and not token.startswith("--"):
            sources.append(token[2:])
            filter_from_file = True
            index += 1
            continue
        if token.startswith("-L") and len(token) > 2 and not token.startswith("--"):
            sources.append(token[2:])
            index += 1
            continue
        if token in _SHELL_JQ_NAMED_FILE_FLAGS:
            if index + 2 < len(tokens):
                sources.append(tokens[index + 2])
            index += 3
            continue
        if token in _SHELL_JQ_TWO_VALUE_FLAGS:
            index += 3
            continue
        if token in _SHELL_JQ_ONE_VALUE_FLAGS:
            index += 2
            continue
        if token.startswith("-") and token != "-":
            index += 1
            continue
        positionals.append(token)
        index += 1

    if filter_from_file:
        sources.extend(positionals)
    elif positionals:
        sources.extend(positionals[1:])
    return _read_probe_source_args(sources)


def _shell_jq_tokens_are_readonly(tokens: list[str]) -> bool:
    candidate_paths = [
        arg for arg in _shell_jq_source_args(tokens)
        if _looks_like_path_arg(arg)
    ]
    if candidate_paths and not all(
        _is_scope_task_artifact_readonly_path(_glob_base_path(path))
        for path in candidate_paths
    ):
        return False
    return True


def _shell_rg_files_source_args(tokens: list[str]) -> list[str]:
    sources: list[str] = []
    index = 1
    value_options = {"-g", "--glob", "-t", "-T", "--type", "-j", "--threads"}
    while index < len(tokens):
        token = tokens[index]
        if token in {">", ">>", ">|", "<>", "<<"} or token.startswith((">", "<<")):
            break
        if token == "--":
            sources.extend(_read_probe_source_args(tokens[index + 1:]))
            break
        if token.startswith("--") and "=" in token:
            index += 1
            continue
        if token in value_options:
            index += 2
            continue
        if token.startswith("-") and token != "-":
            index += 1
            continue
        sources.append(token)
        index += 1
    return _read_probe_source_args(sources)


def _analyze_powershell(text: str) -> dict[str, Any]:
    effects: list[str] = []
    targets: list[ActionEffectTarget] = []
    rules: list[str] = []
    confidence = "low"
    patterns = [
        r"Set-Content\s+(?:-Path\s+)?(?:['\"]([^'\"]+)['\"]|([^\s;|]+))",
        r"Out-File\s+(?:-FilePath\s+)?(?:['\"]([^'\"]+)['\"]|([^\s;|]+))",
    ]
    for pattern in patterns:
        for match in re.findall(pattern, text, flags=re.IGNORECASE):
            path = next((item for item in match if item), "") if isinstance(match, tuple) else match
            if not path:
                continue
            _add_effect(effects, "filesystem.write")
            targets.append(_target_for_path(path))
            _add_rule(rules, "powershell_file_write")
            confidence = "high"
    return {"effects": effects, "targets": targets, "rules": rules, "confidence": confidence}


def _shell_write_paths_include_future_execution_artifact(paths: list[str]) -> bool:
    for path in paths:
        target = _write_target_for_path(path)
        if target.path_role in {"future_execution.artifact", "bootstrap_loader"}:
            return True
    return False


def _shell_unobserved_stdin_writer_present(text: str) -> bool:
    tokens = _shell_tokens_with_punctuation(shell_command_surface(text))
    if not tokens:
        return False

    segment: list[str] = []
    previous_separator = ""
    for token in [*tokens, ";"]:
        if token and all(char in ";&|" for char in token):
            if segment and _shell_segment_consumes_unobserved_stdin(
                segment,
                previous_separator=previous_separator,
            ):
                return True
            previous_separator = token
            segment = []
            continue
        segment.append(token)
    return False


def _shell_segment_consumes_unobserved_stdin(
    tokens: list[str],
    *,
    previous_separator: str,
) -> bool:
    if previous_separator in {"|", "|&"}:
        return False
    effective = _shell_effective_tokens(tokens)
    if not effective:
        return False
    command = Path(effective[0]).name.lower()
    if command == "tee":
        return _shell_tee_segment_has_persistent_target(effective)
    if command == "cat":
        return _shell_cat_segment_writes_stdin(effective)
    if _shell_segment_has_write_redirect(effective):
        return not _shell_segment_has_visible_literal_stdout_payload(effective)
    return False


def _shell_tee_segment_has_persistent_target(tokens: list[str]) -> bool:
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token.startswith("-"):
            index += 1
            continue
        if token.startswith("<<"):
            index += 2
            continue
        return not _is_nonpersistent_redirect_target(token)
    return False


def _shell_cat_segment_writes_stdin(tokens: list[str]) -> bool:
    has_write_redirect = False
    input_operands: list[str] = []
    write_redirect_ops = {">", ">>", "&>", ">&", ">|"}
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token in write_redirect_ops:
            has_write_redirect = True
            index += 2
            continue
        if token == "<":
            index += 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        input_operands.append(token)
        index += 1
    if not has_write_redirect:
        return False
    return not input_operands or all(operand == "-" for operand in input_operands)


def _shell_segment_has_write_redirect(tokens: list[str]) -> bool:
    write_redirect_ops = {">", ">>", "&>", ">&", ">|"}
    return any(token in write_redirect_ops for token in tokens)


def _shell_segment_has_visible_literal_stdout_payload(tokens: list[str]) -> bool:
    if not tokens:
        return False
    command = Path(tokens[0]).name.lower()
    if command not in {"echo", "printf"}:
        return False
    payload_tokens = [token for token in tokens[1:] if token not in {">", ">>", "&>", ">&", ">|"}]
    if not payload_tokens:
        return False
    return not any(re.search(r"[$`]", token) for token in payload_tokens)


def _shell_input_redirection_executes_stdin(text: str) -> bool:
    for line in str(text or "").splitlines():
        for tokens in _shell_segments(line):
            if "<" not in tokens:
                continue
            if _shell_pipeline_consumer_executes_stdin(tokens):
                return True
    return False


def _shell_tokens_with_punctuation(text: str) -> list[str]:
    try:
        lexer = shlex.shlex(text, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        return list(lexer)
    except ValueError:
        return []


def _shell_command_head(tokens: list[str]) -> str:
    effective = _shell_effective_tokens(tokens)
    if not effective:
        return ""
    return Path(effective[0]).name.lower()


def _shell_effective_tokens(tokens: list[str]) -> list[str]:
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if not token:
            index += 1
            continue
        head = Path(token).name.lower()
        if head == "timeout":
            index = _shell_skip_timeout_wrapper(tokens, index)
            continue
        if head == "nice":
            index = _shell_skip_nice_wrapper(tokens, index)
            continue
        if head == "stdbuf":
            index = _shell_skip_stdbuf_wrapper(tokens, index)
            continue
        if head == "sudo":
            index = _shell_skip_sudo_wrapper(tokens, index)
            continue
        if head == "time":
            index = _shell_skip_time_wrapper(tokens, index)
            continue
        if head == "command":
            if index + 1 < len(tokens) and tokens[index + 1] in {"-v", "-V"}:
                return tokens[index:]
            index = _shell_skip_command_wrapper(tokens, index)
            continue
        if head in _SHELL_WRAPPER_COMMANDS or _shell_env_assignment(token):
            index += 1
            continue
        if head == "env":
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
                    index += 1
                    continue
                break
            continue
        return tokens[index:]
    return []


def _shell_skip_timeout_wrapper(tokens: list[str], index: int) -> int:
    index += 1
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            return index + 1
        if token in {"-k", "--kill-after", "-s", "--signal"}:
            index += 2
            continue
        if token.startswith(("--kill-after=", "--signal=")):
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        return index + 1
    return index


def _shell_skip_nice_wrapper(tokens: list[str], index: int) -> int:
    index += 1
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            return index + 1
        if token in {"-n", "--adjustment"}:
            index += 2
            continue
        if token.startswith("--adjustment=") or re.fullmatch(r"[+-]?\d+", token):
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        break
    return index


def _shell_skip_stdbuf_wrapper(tokens: list[str], index: int) -> int:
    index += 1
    value_flags = {"-i", "-o", "-e", "--input", "--output", "--error"}
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            return index + 1
        if token in value_flags:
            index += 2
            continue
        if token.startswith(("-i", "-o", "-e")) and len(token) > 2:
            index += 1
            continue
        if token.startswith(("--input=", "--output=", "--error=")):
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        break
    return index


def _shell_skip_sudo_wrapper(tokens: list[str], index: int) -> int:
    index += 1
    value_flags = {
        "-C",
        "-c",
        "-g",
        "-h",
        "-p",
        "-r",
        "-t",
        "-T",
        "-u",
        "--close-from",
        "--group",
        "--host",
        "--login-class",
        "--prompt",
        "--role",
        "--type",
        "--user",
    }
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            return index + 1
        if token in value_flags:
            index += 2
            continue
        if token.startswith("--") and "=" in token:
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        break
    return index


def _shell_skip_time_wrapper(tokens: list[str], index: int) -> int:
    index += 1
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            return index + 1
        if token in {"-f", "--format", "-o", "--output"}:
            index += 2
            continue
        if token.startswith(("--format=", "--output=")):
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        break
    return index


def _shell_skip_command_wrapper(tokens: list[str], index: int) -> int:
    index += 1
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            return index + 1
        if token == "-p":
            index += 1
            continue
        if token.startswith("-"):
            return index
        break
    return index


def _shell_env_assignment(token: str) -> bool:
    if "=" not in token or token.startswith("-"):
        return False
    name, _value = token.split("=", 1)
    return name.isidentifier()


def _shell_inline_command(tokens: list[str]) -> str | None:
    effective = _shell_effective_tokens(tokens)
    if not effective:
        return None
    head = Path(effective[0]).name.lower()
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


def _shell_command_invokes_network_fetch(text: str, *, depth: int = 0) -> bool:
    if depth > _MAX_SHELL_INLINE_DEPTH:
        return False
    for body in _shell_executable_heredoc_bodies(text):
        if _shell_command_invokes_network_fetch(body, depth=depth + 1):
            return True
    for tokens in _shell_segments(text):
        inline_command = _shell_inline_command(tokens)
        if inline_command and _shell_command_invokes_network_fetch(inline_command, depth=depth + 1):
            return True
        if _shell_command_head(tokens) in _NETWORK_FETCH_COMMANDS:
            return True
    return False


def _shell_command_invokes_package_install(text: str, *, depth: int = 0) -> bool:
    if depth > _MAX_SHELL_INLINE_DEPTH:
        return False
    for body in _shell_executable_heredoc_bodies(text):
        if _shell_command_invokes_package_install(body, depth=depth + 1):
            return True
    for tokens in _shell_segments(text):
        inline_command = _shell_inline_command(tokens)
        if inline_command and _shell_command_invokes_package_install(inline_command, depth=depth + 1):
            return True
        effective = _shell_effective_tokens(tokens)
        if _uv_invokes_package_install(effective):
            return True
        package_args = _shell_package_command_args(tokens)
        if package_args is None:
            continue
        if _package_install_subcommand_present(package_args):
            return True
    return False


def _shell_command_invokes_remote_package_reference(text: str, *, depth: int = 0) -> bool:
    if depth > _MAX_SHELL_INLINE_DEPTH:
        return False
    for body in _shell_executable_heredoc_bodies(text):
        if _shell_command_invokes_remote_package_reference(body, depth=depth + 1):
            return True
    for tokens in _shell_segments(text):
        inline_command = _shell_inline_command(tokens)
        if inline_command and _shell_command_invokes_remote_package_reference(inline_command, depth=depth + 1):
            return True
        effective = _shell_effective_tokens(tokens)
        if not _uv_invokes_package_install(effective) and _shell_package_command_args(tokens) is None:
            continue
        if _shell_tokens_have_remote_package_reference(effective):
            return True
    return False


def _shell_env_assignment_truthy(tokens: list[str], name: str) -> bool:
    for token in tokens:
        if not _shell_env_assignment(token):
            continue
        env_name, value = token.split("=", 1)
        if env_name != name:
            continue
        return str(value).strip().lower() not in {"", "0", "false", "no"}
    return False


def _shell_inline_depth_exceeded(text: str, *, depth: int = 0) -> bool:
    if depth > _MAX_SHELL_INLINE_DEPTH:
        return True
    for body in _shell_executable_heredoc_bodies(text):
        if _shell_inline_depth_exceeded(body, depth=depth + 1):
            return True
    for tokens in _shell_segments(text):
        inline_command = _shell_inline_command(tokens)
        if inline_command and _shell_inline_depth_exceeded(inline_command, depth=depth + 1):
            return True
    return False


def _shell_executable_heredoc_bodies(text: str) -> list[str]:
    if "<<" not in text:
        return []
    lines = text.splitlines()
    bodies: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        delimiter = _heredoc_delimiter_from_line(line)
        if not delimiter:
            index += 1
            continue
        strip_tabs = _heredoc_strips_leading_tabs(line)
        body_start = index + 1
        body_end = body_start
        while body_end < len(lines) and lines[body_end].strip() != delimiter:
            body_end += 1
        if _heredoc_line_invokes_shell_interpreter(line):
            body_lines = [
                body_line.lstrip("\t") if strip_tabs else body_line
                for body_line in lines[body_start:body_end]
            ]
            bodies.append("\n".join(body_lines))
        index = body_end + 1 if body_end < len(lines) else body_end
    return bodies


def _shell_package_command_args(tokens: list[str]) -> list[str] | None:
    effective = _shell_effective_tokens(tokens)
    if not effective:
        return None
    head = Path(effective[0]).name.lower()
    if head in _PACKAGE_COMMANDS:
        return effective[1:]
    if _python_module_invokes_pip(effective):
        pip_index = next(
            index + 1
            for index, token in enumerate(effective[:-1])
            if token == "-m" and Path(effective[index + 1]).name.lower() in {"pip", "pip3"}
        )
        return effective[pip_index + 1:]
    return None


def _looks_like_path_arg(value: str) -> bool:
    if value in {".", ".."}:
        return True
    return "/" in value or "." in Path(value).name


def _looks_like_python(text: str) -> bool:
    return bool(re.search(r"\bpython(?:\d+(?:\.\d+)?)?\b|\bopen\(|\bpathlib\b|\brequests\.", text))


def _looks_like_node(text: str) -> bool:
    return bool(re.search(r"\bnode\b|\bfs\.|writeFileSync|fetch\(", text))


def _looks_like_powershell(text: str) -> bool:
    return bool(re.search(r"\b(?:powershell|pwsh|Set-Content|Out-File)\b", text, re.IGNORECASE))


# --- late-bound cross-module names (mechanical split of normalizer.py) ---
# Placed after all definitions on purpose: modules in this package form
# import cycles that are only safe because every module completes its own
# definitions before this block runs. Do not move these imports to the top.
from clawsentry.gateway.effects.normalizer import (  # noqa: E402
    _BSDTAR_VALUE_FLAGS,
    _DOCX2TXT_IMAGE_OUTPUT_FLAGS,
    _DOCX2TXT_VALUE_FLAGS,
    _EXECUTABLE_SUFFIXES,
    _FIND_OUTPUT_PREDICATES,
    _GZIP_VALUE_FLAGS,
    _MAVEN_LOCAL_BUILD_COMMANDS,
    _MAX_SHELL_INLINE_DEPTH,
    _NETWORK_FETCH_COMMANDS,
    _NORMALIZER_CWD,
    _PACKAGE_COMMANDS,
    _PANDOC_VALUE_FLAGS,
    _PDFTOTEXT_VALUE_FLAGS,
    _PIPE_STDIN_EXEC_COMMANDS,
    _SOFFICE_OUTPUT_FLAGS,
    _SOFFICE_VALUE_FLAGS,
    _STDOUT_CONVERTER_OUTPUT_FLAGS,
    _STDOUT_CONVERTER_VALUE_FLAGS,
    _STRINGS_VALUE_FLAGS,
    _URL_RE,
    _add_effect,
    _add_rule,
    _analyze_encrypted_archive_creation,
    _build_raw_tokens_have_execution_env,
    _build_raw_tokens_have_privileged_wrapper,
    _copy_like_operations,
    _dd_output_paths,
    _dedupe_strings,
    _dedupe_targets,
    _directory_create_targets,
    _empty_shell_effects,
    _git_apply_has_disallowed_global_option,
    _git_apply_has_disallowed_option,
    _git_apply_patch_path_args,
    _git_effective_worktree_cwd,
    _git_parse_global_options_and_subcommand,
    _git_raw_tokens_have_execution_env,
    _git_readonly_has_disallowed_option,
    _git_readonly_parse_args,
    _glob_base_path,
    _gzip_token_is_read_mode,
    _heredoc_delimiter_from_line,
    _heredoc_line_invokes_shell_interpreter,
    _heredoc_strips_leading_tabs,
    _input_redirection_paths,
    _interpreter_script_target_role,
    _interpreter_script_targets,
    _is_nonpersistent_redirect_target,
    _is_python_interpreter_name,
    _is_shell_capability_probe,
    _is_static_inline_python_unresolved_writer_review,
    _jar_list_archive_arg,
    _jar_raw_tokens_have_disallowed_wrapper,
    _java_classpath_entry_target,
    _java_fat_jar_execution_target,
    _java_local_jar_invocation,
    _java_local_main_invocation,
    _java_program_arg_targets,
    _local_build_command_shape_is_supported,
    _local_build_path_args,
    _maven_exec_java_invocation,
    _max_confidence,
    _merge,
    _network_download_targets,
    _normalize_shell_compare_path,
    _normalized_path_set,
    _package_install_subcommand_present,
    _path_has_credential_marker,
    _path_has_glob,
    _path_has_script_asset_directory,
    _pip_install_subcommand,
    _pip_output_paths,
    _plain_archive_creation_targets,
    _probe_target,
    _pytest_path_args,
    _read_probe_source_args,
    _redirection_paths,
    _resolve_shell_target,
    _rm_delete_targets,
    _strip_safe_shell_path_format_substitutions,
    _strip_shell_heredoc_bodies,
    _target_for_path,
    _tee_paths,
    _unzip_token_is_read_mode,
    _updated_shell_cwd,
    _uv_editable_paths,
    _uv_invokes_package_install,
    _uv_option_path,
    _uv_pip_subcommand,
    _uv_run_command_tokens,
    _uv_short_option_path,
    _uv_subcommand,
    _write_target_for_path,
)
from clawsentry.gateway.effects.python_ast import (  # noqa: E402
    _inline_python_source,
    _python_compileall_targets,
    _python_executable_venv_root,
    _python_explicit_interpreter_venv_root,
    _python_implicit_customization_targets,
    _python_inline_code_arg,
    _python_inline_import_smoke_test_is_scope_safe,
    _python_inline_verify_code_is_readonly,
    _python_json_tool_input_targets,
    _python_local_verify_task_output_targets,
    _python_module_invocation,
    _python_module_invokes_pip,
    _python_pip_unscoped_install_effects,
    _python_py_compile_targets,
    _python_raw_tokens_have_execution_env,
    _python_script_path_arg,
    _python_sys_path_task_output_targets,
    _python_venv_target_paths,
    _python_venv_task_output_targets,
    _python_version_probe_tokens,
)
from clawsentry.gateway.effects.native_write import (  # noqa: E402
    _native_write_has_associated_script_surface,
    _native_write_has_associated_script_target,
    _native_write_payload_has_executable_script_marker,
    _native_write_payload_has_future_execution_marker,
    _native_write_payload_has_remote_network_indicator,
)
from clawsentry.gateway.effects.artifact_scope import (  # noqa: E402
    _TASK_OUTPUT_LOCAL_BUILD_COMMANDS,
    _append_task_output_env_probe_target,
    _inline_interpreter_task_data_targets,
    _is_scope_task_artifact_readonly_path,
    _is_scope_task_data_path,
    _is_scope_task_output_path,
    _is_static_inline_python_task_data_readonly,
    _is_static_inline_python_task_data_to_task_output_transform,
    _is_static_inline_python_task_output_write,
    _path_role,
    _path_role_for_enumerate,
    _path_role_for_read,
    _pip_preinstall_args_are_scope_safe,
    _scope_task_output_build_artifact_target_for_path,
    _scope_task_output_or_data_read_target_for_path,
    _scope_task_output_target_for_path,
    _target_is_effective_scope_task_data_read,
    _target_is_effective_scope_task_output,
    _task_output_extension_contract_violated,
    _uv_global_options_are_scope_safe,
    _uv_pip_install_args_are_scope_safe,
    _uv_task_output_lane_args_are_scope_safe,
)
