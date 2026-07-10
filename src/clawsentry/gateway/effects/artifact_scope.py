"""Session-scope task-artifact qualification for the effect normalizer.

Mechanically split from normalizer.py (single shared late-bound namespace;
see the bottom import block). Behavior-preserving: do not reorder segments.
"""

from __future__ import annotations

import ast
import contextvars
import posixpath
import re
from pathlib import Path, PurePosixPath
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
_TASK_OUTPUT_LOCAL_BUILD_COMMANDS = frozenset({
    "cmake",
    "ctest",
    "gmake",
    "gradle",
    "gradlew",
    "make",
    "mvn",
    "mvnw",
    "sbt",
})
_TASK_OUTPUT_LOCAL_BUILD_PRIVILEGED_WRAPPERS = frozenset({
    "doas",
    "pkexec",
    "su",
    "sudo",
})
_TASK_OUTPUT_LOCAL_BUILD_PATH_VALUE_OPTIONS = frozenset({
    "-b",
    "-B",
    "-C",
    "-c",
    "-f",
    "-gs",
    "-p",
    "-S",
    "-s",
    "--build",
    "--build-file",
    "--file",
    "--global-settings",
    "--gradle-user-home",
    "--project-dir",
    "--project-cache-dir",
    "--settings",
    "--settings-file",
    "--test-dir",
})
_TASK_OUTPUT_LOCAL_BUILD_JOINED_PATH_OPTIONS = frozenset({
    "-b",
    "-B",
    "-C",
    "-c",
    "-f",
    "-gs",
    "-I",
    "-p",
    "-S",
    "-s",
})
_TASK_OUTPUT_LOCAL_BUILD_OPAQUE_VALUE_OPTIONS = frozenset({
    "-D",
    "-P",
    "-pl",
    "-m",
    "-t",
    "--define",
    "--exclude-regex",
    "--include-regex",
    "--projects",
    "--tests",
})


def artifact_families(envelope: ActionEffectEnvelope) -> list[str]:
    return sorted({str(target.path_role) for target in envelope.targets if target.path_role})


def _scope_task_data_literal_reference_paths(text: str, *, cwd: str | None = None) -> list[str]:
    paths: list[str] = []
    for literal in re.findall(r"['\"]([^'\"]{1,512})['\"]", str(text or "")):
        candidate = literal.strip()
        if not candidate or _URL_RE.match(candidate):
            continue
        if not (candidate.startswith(("/", "./", "../", "~")) or "/" in candidate):
            continue
        artifact = resolve_scope_task_artifact(
            candidate,
            access="read",
            context=_NORMALIZER_CONTEXT.get(),
            cwd=cwd,
        )
        if (
            _artifact_decision_is_effective(artifact)
            and artifact.path_role == SCOPE_TASK_DATA_READ_PATH_ROLE
        ):
            paths.append(candidate)
    return _dedupe_strings(paths)


def _artifact_source_family(source: str | None) -> str:
    normalized = re.sub(r"[\s-]+", "_", str(source or "").strip().lower())
    if not normalized:
        return ""
    if normalized.startswith("instruction_"):
        return normalized
    if normalized.startswith("solution_"):
        return normalized
    return normalized


def _is_scope_task_artifact_readonly_path(path: str) -> bool:
    return _is_scope_task_data_path(path) or _is_scope_task_output_write_target(path)


def _append_task_output_env_probe_target(
    targets: list[ActionEffectTarget],
    rules: list[str],
    shell_cwd: str | None,
) -> None:
    task_output_cwd = _scope_task_output_target_for_path(".", cwd=shell_cwd)
    if task_output_cwd is None:
        return
    targets.append(task_output_cwd)
    _add_rule(rules, "task_output_env_probe")


def _scope_task_output_build_artifact_target_for_path(
    path: str,
    *,
    cwd: str | None,
) -> ActionEffectTarget | None:
    if not _jar_archive_path_is_supported(path):
        return None
    return _scope_task_output_build_child_target_for_path(path, cwd=cwd)


def _scope_task_output_build_child_target_for_path(
    path: str,
    *,
    cwd: str | None,
    allow_exact_direct: bool = True,
) -> ActionEffectTarget | None:
    direct = _scope_task_output_target_for_path(path, cwd=cwd)
    if allow_exact_direct and direct is not None and direct.artifact_match_type == "exact":
        return direct
    cwd_target = _scope_task_output_target_for_path(".", cwd=cwd)
    if cwd_target is None:
        return None
    normalized_path = normalize_task_artifact_path(path, cwd=cwd)
    normalized_cwd = normalize_task_artifact_path(".", cwd=cwd)
    if not normalized_path or not normalized_cwd:
        return None
    if not _path_string_is_within_root(normalized_path, normalized_cwd):
        return None
    relative = posixpath.relpath(normalized_path, normalized_cwd)
    first_part = relative.split("/", 1)[0]
    if first_part not in {"target", "build", "dist", "out", "bazel-bin", "bazel-out"}:
        return None
    return cwd_target.model_copy(update={
        "path_hash": _hash(normalized_path),
        "path_role": SCOPE_TASK_OUTPUT_PATH_ROLE,
        "workspace_relation": "task_output_artifact",
    })


def _scope_task_output_explicit_output_target_for_path(
    path: str,
    *,
    cwd: str | None,
) -> ActionEffectTarget | None:
    direct = _scope_task_output_target_for_path(path, cwd=cwd)
    if direct is not None and direct.artifact_match_type == "exact":
        return direct
    cwd_target = _scope_task_output_target_for_path(".", cwd=cwd)
    if cwd_target is None:
        return None
    normalized_path = normalize_task_artifact_path(path, cwd=cwd)
    normalized_cwd = normalize_task_artifact_path(".", cwd=cwd)
    if not normalized_path or not normalized_cwd:
        return None
    if not _path_string_is_within_root(normalized_path, normalized_cwd):
        return None
    relative = posixpath.relpath(normalized_path, normalized_cwd)
    if (
        not relative
        or relative == "."
        or "/" in relative
        or relative.startswith(".")
    ):
        return None
    return cwd_target.model_copy(update={
        "path_hash": _hash(normalized_path),
        "path_role": SCOPE_TASK_OUTPUT_PATH_ROLE,
        "workspace_relation": "task_output_artifact",
    })


def _java_task_data_input_target(
    path: str,
    *,
    cwd: str | None,
) -> ActionEffectTarget | None:
    target = _target_for_path(
        path,
        role=_path_role_for_read(path, cwd=cwd),
        cwd=cwd,
        io_direction="source",
    )
    if _target_is_effective_scope_task_data_read(target):
        return target
    return None


def _target_is_effective_scope_task_data_read(target: ActionEffectTarget) -> bool:
    return bool(
        target.kind == "path"
        and target.artifact_role == "task_data"
        and target.path_role == SCOPE_TASK_DATA_READ_PATH_ROLE
        and target.workspace_relation == SCOPE_TASK_DATA_WORKSPACE_RELATION
        and target.artifact_risk_adjusting is True
        and target.artifact_trust_confirmed is True
    )


def _pip_preinstall_args_are_scope_safe(args: list[str], shell_cwd: str | None) -> bool:
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
    while index < len(args):
        token = args[index]
        if token == "--":
            return True
        if token == "--python" and index + 1 < len(args):
            if not _uv_pip_install_python_arg_is_scope_safe(args[index + 1], shell_cwd):
                return False
            index += 2
            continue
        if token.startswith("--python="):
            if not _uv_pip_install_python_arg_is_scope_safe(token.split("=", 1)[1], shell_cwd):
                return False
            index += 1
            continue
        if token in value_flags and index + 1 < len(args):
            if not _uv_unknown_option_value_is_scope_safe(args[index + 1], shell_cwd):
                return False
            index += 2
            continue
        matched_value_prefix = next(
            (
                flag + "="
                for flag in value_flags
                if flag.startswith("--") and token.startswith(flag + "=")
            ),
            None,
        )
        if matched_value_prefix is not None:
            if not _uv_unknown_option_value_is_scope_safe(token.split("=", 1)[1], shell_cwd):
                return False
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        return False
    return True


def _uv_global_options_are_scope_safe(args: list[str], shell_cwd: str | None) -> bool:
    index = 0
    path_value_flags = {"--cache-dir", "--config-file", "--directory", "--project", "--python"}
    value_flags = {
        *path_value_flags,
        "--index-url",
        "--keyring-provider",
        "--link-mode",
        "--managed-python",
        "--refresh-package",
        "--resolution",
    }
    while index < len(args):
        token = args[index]
        if token == "--":
            return True
        if token in path_value_flags and index + 1 < len(args):
            value = args[index + 1]
            path_is_safe = (
                _uv_python_option_value_is_scope_safe(value, shell_cwd)
                if token == "--python"
                else _uv_pip_install_path_arg_is_scope_safe(value, shell_cwd)
            )
            if not path_is_safe:
                return False
            index += 2
            continue
        matched_path_prefix = next(
            (
                flag + "="
                for flag in path_value_flags
                if token.startswith(flag + "=")
            ),
            None,
        )
        if matched_path_prefix is not None:
            option_name = matched_path_prefix[:-1]
            value = token.split("=", 1)[1]
            path_is_safe = (
                _uv_python_option_value_is_scope_safe(value, shell_cwd)
                if option_name == "--python"
                else _uv_pip_install_path_arg_is_scope_safe(value, shell_cwd)
            )
            if not path_is_safe:
                return False
            index += 1
            continue
        if token in value_flags and index + 1 < len(args):
            if not _uv_unknown_option_value_is_scope_safe(args[index + 1], shell_cwd):
                return False
            index += 2
            continue
        matched_value_prefix = next(
            (
                flag + "="
                for flag in value_flags
                if flag.startswith("--") and token.startswith(flag + "=")
            ),
            None,
        )
        if matched_value_prefix is not None:
            if not _uv_unknown_option_value_is_scope_safe(token.split("=", 1)[1], shell_cwd):
                return False
            index += 1
            continue
        if token.startswith("--") and "=" in token:
            value = token.split("=", 1)[1]
            if not _uv_unknown_option_value_is_scope_safe(value, shell_cwd):
                return False
            index += 1
            continue
        if token.startswith("-") and not token.startswith("--") and len(token) > 2:
            value = token[2:]
            if not _uv_unknown_option_value_is_scope_safe(value, shell_cwd):
                return False
            index += 1
            continue
        index += 1
    return True


def _uv_python_option_value_is_scope_safe(value: str, shell_cwd: str | None) -> bool:
    if not _uv_option_value_looks_like_path_or_sensitive(value):
        return not _path_has_credential_marker(value)
    return _uv_pip_install_python_arg_is_scope_safe(value, shell_cwd)


def _uv_task_output_lane_args_are_scope_safe(args: list[str], shell_cwd: str | None) -> bool:
    value_flags = {
        "--cache-dir",
        "--config-file",
        "--config-setting",
        "--directory",
        "--env-file",
        "--exclude-newer",
        "--from",
        "--index-url",
        "--isolated",
        "--keyring-provider",
        "--link-mode",
        "--module",
        "--project",
        "--prompt",
        "--python",
        "--python-platform",
        "--refresh-package",
        "--resolution",
        "--with",
        "--with-editable",
    }
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            return all(
                _uv_pip_install_positional_arg_is_scope_safe(arg, shell_cwd)
                for arg in args[index + 1:]
            )
        if token in {"--python", "-p"} and index + 1 < len(args):
            if not _uv_python_option_value_is_scope_safe(args[index + 1], shell_cwd):
                return False
            index += 2
            continue
        if token.startswith("--python="):
            if not _uv_python_option_value_is_scope_safe(token.split("=", 1)[1], shell_cwd):
                return False
            index += 1
            continue
        if token.startswith("-p") and len(token) > 2:
            if not _uv_python_option_value_is_scope_safe(token[2:], shell_cwd):
                return False
            index += 1
            continue
        if token in value_flags and index + 1 < len(args):
            if not _uv_unknown_option_value_is_scope_safe(args[index + 1], shell_cwd):
                return False
            index += 2
            continue
        matched_value_prefix = next(
            (
                flag + "="
                for flag in value_flags
                if flag.startswith("--") and token.startswith(flag + "=")
            ),
            None,
        )
        if matched_value_prefix is not None:
            if not _uv_unknown_option_value_is_scope_safe(token.split("=", 1)[1], shell_cwd):
                return False
            index += 1
            continue
        if token.startswith("--") and "=" in token:
            if not _uv_unknown_option_value_is_scope_safe(token.split("=", 1)[1], shell_cwd):
                return False
            index += 1
            continue
        if token.startswith("-") and not token.startswith("--") and len(token) > 2:
            if not _uv_unknown_option_value_is_scope_safe(token[2:], shell_cwd):
                return False
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        if not _uv_pip_install_positional_arg_is_scope_safe(token, shell_cwd):
            return False
        index += 1
    return True


def _uv_pip_install_args_are_scope_safe(args: list[str], shell_cwd: str | None) -> bool:
    path_value_flags = {
        "--constraint",
        "--directory",
        "--editable",
        "--find-links",
        "--prefix",
        "--project",
        "--python",
        "--requirement",
        "--target",
        "-c",
        "-e",
        "-f",
        "-p",
        "-r",
        "-t",
    }
    value_flags = {
        *path_value_flags,
        "--config-setting",
        "--exclude-newer",
        "--extra-index-url",
        "--index-strategy",
        "--index-url",
        "--keyring-provider",
        "--link-mode",
        "--reinstall-package",
        "--resolution",
        "--upgrade-package",
    }
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            return all(
                _uv_pip_install_positional_arg_is_scope_safe(arg, shell_cwd)
                for arg in args[index + 1:]
            )
        if token in path_value_flags and index + 1 < len(args):
            path_is_safe = (
                _uv_python_option_value_is_scope_safe(args[index + 1], shell_cwd)
                if token in {"--python", "-p"}
                else _uv_pip_install_path_arg_is_scope_safe(args[index + 1], shell_cwd)
            )
            if not path_is_safe:
                return False
            index += 2
            continue
        matched_short_path = next(
            (
                flag
                for flag in ("-c", "-e", "-f", "-p", "-r", "-t")
                if token.startswith(flag) and len(token) > len(flag)
            ),
            None,
        )
        if matched_short_path is not None:
            value = token[len(matched_short_path):]
            path_is_safe = (
                _uv_python_option_value_is_scope_safe(value, shell_cwd)
                if matched_short_path == "-p"
                else _uv_pip_install_path_arg_is_scope_safe(value, shell_cwd)
            )
            if not path_is_safe:
                return False
            index += 1
            continue
        if token in value_flags and index + 1 < len(args):
            if not _uv_unknown_option_value_is_scope_safe(args[index + 1], shell_cwd):
                return False
            index += 2
            continue
        matched_path_prefix = next(
            (
                flag + "="
                for flag in path_value_flags
                if flag.startswith("--") and token.startswith(flag + "=")
            ),
            None,
        )
        if matched_path_prefix is not None:
            option_name = matched_path_prefix[:-1]
            value = token.split("=", 1)[1]
            path_is_safe = (
                _uv_python_option_value_is_scope_safe(value, shell_cwd)
                if option_name == "--python"
                else _uv_pip_install_path_arg_is_scope_safe(value, shell_cwd)
            )
            if not path_is_safe:
                return False
            index += 1
            continue
        matched_value_prefix = next(
            (
                flag + "="
                for flag in value_flags
                if flag.startswith("--") and token.startswith(flag + "=")
            ),
            None,
        )
        if matched_value_prefix is not None:
            if not _uv_unknown_option_value_is_scope_safe(token.split("=", 1)[1], shell_cwd):
                return False
            index += 1
            continue
        if token.startswith("--") and "=" in token:
            value = token.split("=", 1)[1]
            if not _uv_unknown_option_value_is_scope_safe(value, shell_cwd):
                return False
            index += 1
            continue
        if token.startswith("-") and not token.startswith("--") and len(token) > 2:
            value = token[2:]
            if not _uv_unknown_option_value_is_scope_safe(value, shell_cwd):
                return False
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        if not _uv_pip_install_positional_arg_is_scope_safe(token, shell_cwd):
            return False
        index += 1
    return True


def _uv_pip_install_positional_arg_is_scope_safe(arg: str, shell_cwd: str | None) -> bool:
    if _shell_tokens_have_remote_package_reference([arg]):
        return False
    if _path_has_credential_marker(arg):
        return False
    if _looks_like_path_arg(arg) or str(arg or "").startswith(("~", ".")):
        return _scope_task_output_target_for_path(arg, cwd=shell_cwd) is not None
    return True


def _uv_unknown_option_value_is_scope_safe(value: str, shell_cwd: str | None) -> bool:
    if _shell_tokens_have_remote_package_reference([value]):
        return False
    if not _uv_option_value_looks_like_path_or_sensitive(value):
        return True
    return _uv_pip_install_path_arg_is_scope_safe(value, shell_cwd)


def _uv_pip_install_path_arg_is_scope_safe(arg: str, shell_cwd: str | None) -> bool:
    if _shell_tokens_have_remote_package_reference([arg]):
        return False
    if _path_has_credential_marker(arg):
        return False
    return _scope_task_output_target_for_path(arg, cwd=shell_cwd) is not None


def _uv_pip_install_python_arg_is_scope_safe(arg: str, shell_cwd: str | None) -> bool:
    if _shell_tokens_have_remote_package_reference([arg]):
        return False
    if _path_has_credential_marker(arg):
        return False
    venv_root = _python_executable_venv_root(arg, shell_cwd=shell_cwd)
    if not venv_root:
        return False
    return _scope_task_output_target_for_path(venv_root, cwd=None) is not None


def _inline_interpreter_task_data_targets(text: str) -> list[str]:
    if not re.search(
        r"\b(?:python|python3|node|nodejs|bash|sh|zsh)\b[^;&|]*(?:<<|-c\b|-e\b|\s-\s)",
        text,
    ):
        return []
    python_sources = _inline_python_sources(text)
    if python_sources:
        targets: list[str] = []
        for source in python_sources:
            targets.extend(_python_scope_task_data_literal_targets(source))
        return _dedupe_strings(targets)[:3]
    return [
        path
        for path in _paths(text)
        if _is_scope_task_data_path(path)
    ][:3]


def _is_static_inline_python_task_data_readonly(text: str) -> bool:
    argv_token = _with_inline_python_argv_bindings(text)
    source = _inline_python_source(text)
    alias_tokens: tuple[contextvars.Token[set[str]], contextvars.Token[set[str]]] | None = None
    try:
        if source is None:
            return False
        alias_tokens = _with_python_sys_argv_aliases(source)
        if _python_source_has_disallowed_readonly_task_data_effect(source):
            return False
        if not _python_source_paths_are_scope_task_data_only(source):
            if _python_source_has_explicit_filesystem_path(source):
                return False
            argv_paths = list(_PYTHON_ARGV_PATH_BINDINGS.get().values())
            if argv_paths and not all(
                _is_scope_task_data_path(_glob_base_path(path)) for path in argv_paths
            ):
                return False
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return False
        if _python_ast_is_task_data_readonly_probe(tree):
            return True
        read_targets = _python_read_targets(source)
        enumerate_targets = _python_enumerate_targets(source)
        all_targets = [*read_targets, *enumerate_targets]
        return bool(all_targets) and all(
            _is_scope_task_data_path(_glob_base_path(path)) for path in all_targets
        )
    finally:
        if alias_tokens is not None:
            _reset_python_sys_argv_aliases(alias_tokens)
        _PYTHON_ARGV_PATH_BINDINGS.reset(argv_token)


def _is_static_inline_python_task_data_to_task_output_transform(text: str) -> bool:
    argv_token = _with_inline_python_argv_bindings(text)
    source = _inline_python_source(text)
    alias_tokens: tuple[contextvars.Token[set[str]], contextvars.Token[set[str]]] | None = None
    try:
        if source is None:
            return False
        alias_tokens = _with_python_sys_argv_aliases(source)
        path_bindings = _python_path_variable_bindings(source)
        path_sequence_bindings = _python_path_sequence_variable_bindings(source)
        write_targets = _python_write_targets(source, path_bindings, path_sequence_bindings)
        write_target_keys = {
            normalize_task_artifact_path(path, cwd=_NORMALIZER_CWD.get()).lower()
            for path in write_targets
        }
        if _python_source_has_disallowed_task_data_output_transform_effect(
            source,
            allowed_output_read_targets=write_target_keys,
        ):
            return False
        if not _python_source_paths_are_scope_task_data_or_output_only(source):
            return False
        read_targets = _python_read_targets(source, path_bindings, path_sequence_bindings)
        return (
            bool(read_targets)
            and bool(write_targets)
            and all(
                _is_scope_task_data_path(path)
                or (
                    _is_scope_task_output_write_target(path)
                    and normalize_task_artifact_path(path, cwd=_NORMALIZER_CWD.get()).lower()
                    in write_target_keys
                )
                for path in read_targets
            )
            and all(_is_scope_task_output_write_target(path) for path in write_targets)
        )
    finally:
        if alias_tokens is not None:
            _reset_python_sys_argv_aliases(alias_tokens)
        _PYTHON_ARGV_PATH_BINDINGS.reset(argv_token)


def _is_static_inline_python_task_output_write(text: str) -> bool:
    argv_token = _with_inline_python_argv_bindings(text)
    source = _inline_python_source(text)
    alias_tokens: tuple[contextvars.Token[set[str]], contextvars.Token[set[str]]] | None = None
    try:
        if source is None:
            return False
        alias_tokens = _with_python_sys_argv_aliases(source)
        path_bindings = _python_path_variable_bindings(source)
        path_sequence_bindings = _python_path_sequence_variable_bindings(source)
        write_targets = _python_write_targets(source, path_bindings, path_sequence_bindings)
        if not write_targets or not all(
            _is_scope_task_output_write_target(path) for path in write_targets
        ):
            return False
        write_target_keys = {
            normalize_task_artifact_path(path, cwd=_NORMALIZER_CWD.get()).lower()
            for path in write_targets
        }
        if _python_source_has_disallowed_task_data_output_transform_effect(
            source,
            allowed_output_read_targets=write_target_keys,
        ):
            return False
        if not _python_source_paths_are_scope_task_data_or_output_only(source):
            return False
        read_targets = _python_read_targets(source, path_bindings, path_sequence_bindings)
        enumerate_targets = _python_enumerate_targets(source, path_bindings, path_sequence_bindings)
        return all(
            _is_scope_task_output_write_target(path)
            and normalize_task_artifact_path(path, cwd=_NORMALIZER_CWD.get()).lower() in write_target_keys
            for path in [*read_targets, *enumerate_targets]
        )
    finally:
        if alias_tokens is not None:
            _reset_python_sys_argv_aliases(alias_tokens)
        _PYTHON_ARGV_PATH_BINDINGS.reset(argv_token)


def _scope_task_output_atomic_replace_staging_target(
    source_path: str,
    destination_path: str,
) -> ActionEffectTarget | None:
    destination_target = _scope_task_output_target_for_path(destination_path)
    if destination_target is None or destination_target.artifact_match_type != "exact":
        return None
    normalized_source = normalize_task_artifact_path(source_path, cwd=_NORMALIZER_CWD.get())
    normalized_destination = normalize_task_artifact_path(
        destination_path,
        cwd=_NORMALIZER_CWD.get(),
    )
    if not _path_is_task_output_atomic_replace_staging_path(
        normalized_source,
        normalized_destination,
    ):
        return None
    source_metadata = dict(destination_target.artifact_source_metadata or {})
    source_metadata.update({
        "derived_staging_relation": "atomic_replace_source",
    })
    return destination_target.model_copy(update={
        "path_hash": _hash(normalized_source),
        "path_role": SCOPE_TASK_OUTPUT_PATH_ROLE,
        "io_direction": "target",
        "workspace_relation": "task_output_artifact",
        "artifact_match_type": "derived_staging",
        "artifact_source_metadata": source_metadata,
    })


def _path_is_task_output_atomic_replace_staging_path(
    source_path: str,
    destination_path: str,
) -> bool:
    source = normalize_task_artifact_path(source_path, cwd=_NORMALIZER_CWD.get())
    destination = normalize_task_artifact_path(destination_path, cwd=_NORMALIZER_CWD.get())
    if not source or not destination or source == destination:
        return False
    if not source.startswith("/") or not destination.startswith("/"):
        return False
    if _path_has_credential_marker(source):
        return False
    source_parent = posixpath.dirname(source)
    destination_parent = posixpath.dirname(destination)
    if source_parent != destination_parent:
        return False
    source_name = posixpath.basename(source)
    destination_name = posixpath.basename(destination)
    if not source_name or not destination_name:
        return False
    if source == destination + ".tmp":
        return True
    if any(source == destination + suffix for suffix in _PYTHON_ATOMIC_REPLACE_STAGING_SUFFIXES):
        return True
    if source_name.startswith(f".{destination_name}."):
        suffix = source_name[len(destination_name) + 1 :]
        return suffix in _PYTHON_ATOMIC_REPLACE_STAGING_SUFFIXES
    return False


def _task_output_extension_contract_violated(
    sources: tuple[str, ...],
    destination: str,
    destination_target: ActionEffectTarget,
) -> bool:
    if _task_output_parent_escape_contract_violated(destination, destination_target):
        return True
    allowed_extensions = _target_allowed_output_extensions(destination_target)
    if not allowed_extensions:
        return False
    destination_suffix = Path(str(destination or "")).suffix.lower()
    candidate_suffixes: list[str] = []
    if destination_suffix:
        candidate_suffixes.append(destination_suffix)
    else:
        if not _destination_is_declared_task_output_root(destination):
            return True
        for source in sources:
            source_suffix = Path(str(source or "")).suffix.lower()
            candidate_suffixes.append(source_suffix)
        if not candidate_suffixes:
            return True
    return any(suffix not in allowed_extensions for suffix in candidate_suffixes)


def _direct_task_output_contract_violated(
    destination: str,
    destination_target: ActionEffectTarget,
) -> bool:
    return (
        _task_output_parent_escape_contract_violated(destination, destination_target)
        or _direct_task_output_extension_contract_violated(destination, destination_target)
    )


def _direct_task_output_extension_contract_violated(
    destination: str,
    destination_target: ActionEffectTarget,
) -> bool:
    allowed_extensions = _target_allowed_output_extensions(destination_target)
    if not allowed_extensions:
        return False
    destination_suffix = Path(str(destination or "")).suffix.lower()
    return destination_suffix not in allowed_extensions


def _task_output_parent_escape_contract_violated(
    destination: str,
    destination_target: ActionEffectTarget,
) -> bool:
    if destination_target.path_role == SCOPE_TASK_OUTPUT_PATH_ROLE:
        return False
    lexical_destination = _lexical_absolute_path(destination)
    if not lexical_destination or ".." not in PurePosixPath(lexical_destination).parts:
        return False
    canonical_destination = normalize_task_artifact_path(destination, cwd=_NORMALIZER_CWD.get())
    if not canonical_destination:
        return False
    for root in _declared_task_output_root_paths():
        if not _path_string_is_within_root(lexical_destination, root):
            continue
        return not _path_string_is_within_root(canonical_destination, root)
    return False


def _declared_task_output_root_paths() -> list[str]:
    context = _NORMALIZER_CONTEXT.get()
    profile = context.session_scope_profile if context is not None else None
    if profile is None or profile.confirmed is not True or profile.dry_run is True:
        return []
    roots: list[str] = []
    for rule in profile.task_artifacts or []:
        if rule.artifact_role != "task_output":
            continue
        if rule.artifact_trust_confirmed is not True:
            continue
        for path in rule.paths or []:
            normalized = normalize_task_artifact_path(path, cwd=_NORMALIZER_CWD.get())
            if normalized:
                roots.append(normalized)
    return _dedupe_strings(roots)


def _destination_is_declared_task_output_root(destination: str) -> bool:
    context = _NORMALIZER_CONTEXT.get()
    profile = context.session_scope_profile if context is not None else None
    if profile is None:
        return False
    normalized_destination = normalize_task_artifact_path(
        destination,
        cwd=_NORMALIZER_CWD.get(),
    )
    if not normalized_destination:
        return False
    for rule in profile.task_artifacts or []:
        if rule.artifact_role != "task_output":
            continue
        for path in rule.paths or []:
            if normalize_task_artifact_path(path, cwd=_NORMALIZER_CWD.get()) == normalized_destination:
                return True
    return False


def _target_is_effective_scope_task_output(target: ActionEffectTarget) -> bool:
    return bool(
        target.kind == "path"
        and target.artifact_role == "task_output"
        and (
            target.path_role == SCOPE_TASK_OUTPUT_PATH_ROLE
            or target.artifact_candidate_role == SCOPE_TASK_OUTPUT_PATH_ROLE
        )
        and target.workspace_relation in {"inside_workspace", "task_output_artifact"}
        and (
            target.artifact_risk_adjusting is True
            or target.effective_artifact_source == "scope_task_compat"
        )
    )


def _scope_task_output_target_for_path(
    path: str,
    *,
    cwd: str | None = None,
) -> ActionEffectTarget | None:
    target = _target_for_path(path, role=SCOPE_TASK_OUTPUT_PATH_ROLE, cwd=cwd)
    if _target_is_effective_scope_task_output(target):
        return target
    return None


def _scope_task_output_or_data_read_target_for_path(
    path: str,
    *,
    cwd: str | None = None,
) -> ActionEffectTarget | None:
    output_target = _scope_task_output_target_for_path(path, cwd=cwd)
    if output_target is not None:
        return output_target
    target = _target_for_path(path, role=_path_role_for_read(path), cwd=cwd)
    if target.path_role == SCOPE_TASK_DATA_READ_PATH_ROLE:
        return target
    return None


def _artifact_decision_is_effective(artifact: ScopeTaskArtifactDecision | None) -> bool:
    return bool(
        artifact is not None
        and artifact.path_role
        and (
            artifact.risk_adjusting
            or artifact.effective_artifact_source == "scope_task_compat"
        )
    )


def _path_role(path: str, *, cwd: str | None = None) -> str:
    context = _NORMALIZER_CONTEXT.get()
    effective_cwd = cwd if cwd is not None else _NORMALIZER_CWD.get()
    hard_role = hard_path_role(path, access="write", cwd=effective_cwd)
    if hard_role is not None:
        return hard_role
    artifact = resolve_scope_task_artifact(path, access="write", context=context, cwd=effective_cwd)
    if _artifact_decision_is_effective(artifact) and artifact.path_role:
        return artifact.path_role
    return "workspace_file"


def _is_scope_task_data_path(lowered_path: str) -> bool:
    artifact = resolve_scope_task_artifact(
        lowered_path,
        access="read",
        context=_NORMALIZER_CONTEXT.get(),
        cwd=_NORMALIZER_CWD.get(),
    )
    return bool(
        _artifact_decision_is_effective(artifact)
        and artifact.path_role == SCOPE_TASK_DATA_READ_PATH_ROLE
    )


def _is_scope_task_output_path(lowered_path: str) -> bool:
    artifact = resolve_scope_task_artifact(
        lowered_path,
        access="write",
        context=_NORMALIZER_CONTEXT.get(),
        cwd=_NORMALIZER_CWD.get(),
    )
    return bool(
        _artifact_decision_is_effective(artifact)
        and artifact.path_role == SCOPE_TASK_OUTPUT_PATH_ROLE
    )


def _is_scope_task_output_write_target(lowered_path: str) -> bool:
    artifact = resolve_scope_task_artifact(
        lowered_path,
        access="write",
        context=_NORMALIZER_CONTEXT.get(),
        cwd=_NORMALIZER_CWD.get(),
    )
    return bool(
        _artifact_decision_is_effective(artifact)
        and (
            artifact.artifact_role == "task_output"
            or artifact.path_role == SCOPE_TASK_OUTPUT_PATH_ROLE
            or artifact.candidate_role == SCOPE_TASK_OUTPUT_PATH_ROLE
        )
    )


def _path_role_for_read(path: str, *, cwd: str | None = None) -> str:
    context = _NORMALIZER_CONTEXT.get()
    effective_cwd = cwd if cwd is not None else _NORMALIZER_CWD.get()
    hard_role = hard_path_role(path, access="read", cwd=effective_cwd)
    if hard_role is not None:
        return hard_role
    artifact = resolve_scope_task_artifact(path, access="read", context=context, cwd=effective_cwd)
    if _artifact_decision_is_effective(artifact) and artifact.path_role:
        return artifact.path_role
    output_artifact = resolve_scope_task_artifact(path, access="write", context=context, cwd=effective_cwd)
    if (
        _task_output_write_decision_can_support_readonly_fallback(output_artifact)
    ):
        return SCOPE_TASK_OUTPUT_PATH_ROLE
    role = _path_role(path, cwd=effective_cwd)
    if role == "future_execution.artifact":
        return "workspace_file"
    if role == SCOPE_TASK_OUTPUT_PATH_ROLE:
        return "workspace_file"
    return role


def _path_role_for_enumerate(path: str, *, cwd: str | None = None) -> str:
    role = _path_role_for_read(path, cwd=cwd)
    if role in {SCOPE_TASK_DATA_READ_PATH_ROLE, SCOPE_TASK_OUTPUT_PATH_ROLE}:
        return role
    if is_skill_package_path(str(path or "").lower()):
        return "skill_package_read"
    return "workspace_directory"


def _artifact_decision_for_target(
    path: str,
    role: str | None,
    *,
    cwd: str | None = None,
) -> ScopeTaskArtifactDecision | None:
    context = _NORMALIZER_CONTEXT.get()
    effective_cwd = cwd if cwd is not None else _NORMALIZER_CWD.get()
    if role == SCOPE_TASK_DATA_READ_PATH_ROLE:
        access_order = ("read", "enumerate")
        for access in access_order:
            decision = resolve_scope_task_artifact(path, access=access, context=context, cwd=effective_cwd)
            if decision is not None:
                return decision
        return None

    write_decision = resolve_scope_task_artifact(path, access="write", context=context, cwd=effective_cwd)
    if _is_profile_contract_task_output_decision(write_decision):
        if _write_decision_can_attach_to_target(write_decision, role):
            return write_decision
    if _is_scope_task_compat_task_output_decision(write_decision):
        profile_task_data = _profile_task_data_decision_for_write_target(path, cwd=effective_cwd)
        if profile_task_data is not None:
            return profile_task_data
    if (
        write_decision is not None
        and write_decision.path_role == "future_execution.artifact"
        and write_decision.artifact_role != "task_output"
    ):
        profile_task_data = _profile_task_data_decision_for_write_target(path, cwd=effective_cwd)
        if profile_task_data is not None:
            return profile_task_data
    if write_decision is not None and not _artifact_decision_is_effective(write_decision):
        # A denied write candidate (e.g. an audit_only task_output rule) must not
        # shadow an effective task_data read qualification for the same path.
        profile_task_data = _profile_task_data_decision_for_write_target(path, cwd=effective_cwd)
        if profile_task_data is not None:
            return profile_task_data
    if role == SCOPE_TASK_OUTPUT_PATH_ROLE:
        return write_decision
    if write_decision is not None and _write_decision_can_attach_to_target(write_decision, role):
        return write_decision
    for access in ("read", "enumerate"):
        decision = resolve_scope_task_artifact(path, access=access, context=context, cwd=effective_cwd)
        if decision is not None:
            return decision
    return None


def _is_profile_contract_task_output_decision(decision: ScopeTaskArtifactDecision | None) -> bool:
    return bool(
        _artifact_decision_is_effective(decision)
        and decision.artifact_role == "task_output"
        and decision.effective_artifact_source == "profile_contract"
    )


def _is_scope_task_compat_task_output_decision(decision: ScopeTaskArtifactDecision | None) -> bool:
    return bool(
        _artifact_decision_is_effective(decision)
        and decision.artifact_role == "task_output"
        and decision.effective_artifact_source == "scope_task_compat"
    )


def _task_output_write_decision_can_support_readonly_fallback(
    decision: ScopeTaskArtifactDecision | None,
) -> bool:
    return bool(
        _artifact_decision_is_effective(decision)
        and decision.artifact_role == "task_output"
        and decision.path_role == SCOPE_TASK_OUTPUT_PATH_ROLE
        and not _task_output_decision_is_derived_parent(decision)
    )


def _task_output_decision_is_derived_parent(decision: ScopeTaskArtifactDecision | None) -> bool:
    return bool(
        decision is not None
        and decision.artifact_role == "task_output"
        and (decision.source_metadata or {}).get("derived_parent_of")
    )


def _profile_task_data_decision_for_write_target(
    path: str,
    *,
    cwd: str | None = None,
) -> ScopeTaskArtifactDecision | None:
    decision = resolve_scope_task_artifact(
        path,
        access="read",
        context=_NORMALIZER_CONTEXT.get(),
        cwd=cwd,
        include_legacy=False,
    )
    if (
        _artifact_decision_is_effective(decision)
        and decision.artifact_role == "task_data"
        and decision.path_role == SCOPE_TASK_DATA_READ_PATH_ROLE
    ):
        return decision
    return None


# --- late-bound cross-module names (mechanical split of normalizer.py) ---
# Placed after all definitions on purpose: modules in this package form
# import cycles that are only safe because every module completes its own
# definitions before this block runs. Do not move these imports to the top.
from clawsentry.gateway.effects.normalizer import (  # noqa: E402
    _NORMALIZER_CONTEXT,
    _NORMALIZER_CWD,
    _URL_RE,
    _add_rule,
    _dedupe_strings,
    _glob_base_path,
    _hash,
    _jar_archive_path_is_supported,
    _lexical_absolute_path,
    _path_has_credential_marker,
    _path_string_is_within_root,
    _paths,
    _reset_python_sys_argv_aliases,
    _target_allowed_output_extensions,
    _target_for_path,
    _uv_option_value_looks_like_path_or_sensitive,
    _write_decision_can_attach_to_target,
)
from clawsentry.gateway.effects.python_ast import (  # noqa: E402
    _PYTHON_ARGV_PATH_BINDINGS,
    _PYTHON_ATOMIC_REPLACE_STAGING_SUFFIXES,
    _inline_python_source,
    _inline_python_sources,
    _python_ast_is_task_data_readonly_probe,
    _python_enumerate_targets,
    _python_executable_venv_root,
    _python_path_sequence_variable_bindings,
    _python_path_variable_bindings,
    _python_read_targets,
    _python_scope_task_data_literal_targets,
    _python_source_has_disallowed_readonly_task_data_effect,
    _python_source_has_disallowed_task_data_output_transform_effect,
    _python_source_has_explicit_filesystem_path,
    _python_source_paths_are_scope_task_data_only,
    _python_source_paths_are_scope_task_data_or_output_only,
    _python_write_targets,
    _with_inline_python_argv_bindings,
    _with_python_sys_argv_aliases,
)
from clawsentry.gateway.effects.shell_model import (  # noqa: E402
    _looks_like_path_arg,
    _shell_tokens_have_remote_package_reference,
)
