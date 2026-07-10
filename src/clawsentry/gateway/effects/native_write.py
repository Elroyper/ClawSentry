"""Native write-payload scanning subsystem for the effect normalizer.

Mechanically split from normalizer.py (single shared late-bound namespace;
see the bottom import block). Behavior-preserving: do not reorder segments.
"""

from __future__ import annotations

import ast
import re
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


_NATIVE_WRITE_TOOLS = {
    "add",
    "add_file",
    "create",
    "write",
    "write_file",
    "edit",
    "edit_file",
    "multiedit",
    "multi_edit",
    "create_file",
    "delete",
    "delete_file",
    "remove",
    "remove_file",
    "apply_patch",
}


def _native_write_payload_has_remote_network_indicator(text: str) -> bool:
    return _native_write_scan_texts_have_remote_network_indicator(_native_write_payload_scan_texts(text))


def _native_write_scan_texts_have_remote_network_indicator(scan_texts: list[str]) -> bool:
    if _native_write_scan_texts_have_code_network_sink(scan_texts):
        return True
    for scan_text in scan_texts:
        if _python_source_has_network_fetch(scan_text) or _python_has_socket_or_raw_network(scan_text):
            return True
        if _web_text_has_remote_script_loader(scan_text):
            return True
        if not _URL_RE.search(scan_text):
            continue
        if re.search(
            r"\b(?:XMLHttpRequest|EventSource|WebSocket|sendBeacon)\b|"
            r"\baxios\.|"
            r"\b(?:requests|httpx)\.|"
            r"\burllib(?:\.request)?\.|"
            r"\bhttp\.client\b|"
            r"\bsocket\.|"
            r"\b(?:curl|wget|httpie?)\b|"
            r"\bscript\s*\.\s*src\b|"
            r"<script\b[^>]*\bsrc\s*=|"
            r"\bimport\s*\(\s*['\"]https?://|"
            r"\bfrom\s+['\"]https?://",
            scan_text,
            re.IGNORECASE,
        ):
            return True
    return False


def _native_write_scan_texts_have_wrapper_indicator(scan_texts: list[str]) -> bool:
    for scan_text in scan_texts:
        source = _inline_python_source(scan_text) or scan_text
        if _python_has_wrapper_execution(source) or _python_has_import_module_call(source):
            return True
        try:
            tree = ast.parse(source)
        except SyntaxError:
            tree = None
        if tree is not None and _python_ast_has_dynamic_code_call(tree):
            return True
        if re.search(
            r"\b(?:bash|sh|zsh|dash|ksh|python3?|node|perl|ruby|php)\s+-c\b|"
            r"\b(?:eval|exec)\s+|"
            r"\$\(",
            str(scan_text or ""),
            re.IGNORECASE,
        ):
            return True
        if _native_write_scan_text_has_shell_backtick_indicator(str(scan_text or "")):
            return True
    return False


def _native_write_scan_text_has_shell_backtick_indicator(text: str) -> bool:
    return bool(
        re.search(
            r"`\s*(?:sudo\s+)?"
            r"(?:awk|base64|bash|cat|chmod|chown|cp|curl|dash|echo|env|find|gpg|"
            r"grep|id|ksh|ls|mv|nc|ncat|node|openssl|perl|php|printenv|pwd|"
            r"python3?|rm|ruby|scp|sed|sh|ssh|tar|uname|unzip|wget|whoami|zsh)"
            r"\b[^`\n]*`",
            text,
            re.IGNORECASE,
        )
    )


def _native_write_scan_texts_have_package_indicator(scan_texts: list[str]) -> bool:
    for scan_text in _package_indicator_scan_texts(scan_texts):
        python_package_install = _python_source_has_executable_package_install(scan_text)
        if python_package_install is True:
            return True
        if python_package_install is False:
            continue
        if _shell_command_invokes_package_install(scan_text):
            return True
        if re.search(
            r"\b(?:pip3?|python3?\s+-m\s+pip|npm|yarn|pnpm)\b[^\n;]{0,120}"
            r"\b(?:install|add)\b",
            str(scan_text or ""),
            re.IGNORECASE,
        ):
            return True
    return False


def _native_write_scan_texts_have_destructive_indicator(scan_texts: list[str]) -> bool:
    for scan_text in scan_texts:
        text = str(scan_text or "")
        if re.search(
            r"\brm\s+-[^\n;|&]*r[^\n;|&]*f|"
            r"\brm\s+-[^\n;|&]*f[^\n;|&]*r|"
            r"\bshutil\s*\.\s*rmtree\s*\(|"
            r"\bos\s*\.\s*(?:remove|unlink|rmdir)\s*\(|"
            r"\bPath\s*\([^)]*\)\s*\.\s*(?:unlink|rmdir)\s*\(",
            text,
            re.IGNORECASE,
        ):
            return True
    return False


def _native_write_scan_texts_have_code_network_sink(scan_texts: list[str]) -> bool:
    for scan_text in scan_texts:
        if _native_write_text_has_code_network_sink(scan_text):
            return True
    return False


def _native_write_text_has_code_network_sink(text: str) -> bool:
    raw = _strip_markdown_fenced_blocks(str(text or ""))
    imported_request_aliases: set[str] = set()
    js_string_bindings = _js_static_string_bindings(raw)
    request_methods = {"get", "post", "put", "patch", "delete", "request", "head"}
    for match in re.finditer(r"\bfrom\s+(?:requests|httpx)\s+import\s+([A-Za-z0-9_, \t]+)", raw):
        for alias in match.group(1).split(","):
            parts = re.split(r"\s+as\s+", alias.strip(), maxsplit=1, flags=re.IGNORECASE)
            imported = parts[0].strip()
            bound = parts[-1].strip()
            if imported in request_methods and bound:
                imported_request_aliases.add(bound)
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//", "/*", "*", "<!--")):
            continue
        if _native_write_code_line_has_network_sink(
            stripped,
            imported_request_aliases,
            js_string_bindings=js_string_bindings,
        ):
            return True
    return False


def _native_write_code_line_has_network_sink(
    stripped_line: str,
    imported_request_aliases: set[str],
    *,
    js_string_bindings: dict[str, str] | None = None,
) -> bool:
    if _native_write_line_is_network_import(stripped_line):
        return True
    if re.match(r"^(?:curl|wget)\s+.*[$`]", stripped_line, re.IGNORECASE):
        return True
    if re.match(r"^http\s+(?:GET|POST|PUT|PATCH|DELETE)\b.*[$`]", stripped_line, re.IGNORECASE):
        return True

    qualified_dynamic_pattern = (
        r"\b[A-Za-z_]\w*\s*\.\s*"
        r"(?:urlopen|connect|send|sendall)\s*\("
    )
    qualified_dynamic_sink = bool(re.search(qualified_dynamic_pattern, stripped_line))
    line_starts_with_dynamic_match = re.match(
        rf"^(?:{qualified_dynamic_pattern})",
        stripped_line,
    )
    line_starts_with_dynamic_sink = bool(
        line_starts_with_dynamic_match
        and _native_write_line_starts_with_code_call_tail(
            stripped_line,
            open_paren_index=line_starts_with_dynamic_match.end() - 1,
        )
    )
    dynamic_getattr_pattern = (
        r"\bgetattr\s*\(\s*[A-Za-z_]\w*\s*,\s*"
        r"['\"](?:urlopen|connect|send|sendall)['\"]\s*\)\s*\("
    )
    dynamic_getattr_sink = bool(re.search(dynamic_getattr_pattern, stripped_line))
    known_dynamic_getattr_pattern = (
        r"\bgetattr\s*\(\s*(?:requests|httpx|urllib(?:\.request)?|socket)\s*,\s*"
        r"['\"](?:get|post|put|patch|delete|request|head|urlopen|connect|send|sendall)['\"]\s*\)\s*\("
    )
    known_dynamic_getattr_sink = bool(re.search(known_dynamic_getattr_pattern, stripped_line))
    line_starts_with_dynamic_getattr_match = re.match(
        rf"^(?:{dynamic_getattr_pattern})",
        stripped_line,
    )
    line_starts_with_dynamic_getattr_sink = bool(
        line_starts_with_dynamic_getattr_match
        and _native_write_line_starts_with_code_call_tail(
            stripped_line,
            open_paren_index=line_starts_with_dynamic_getattr_match.end() - 1,
        )
    )
    known_network_call_pattern = (
        r"\b(?:requests|httpx)\s*\.\s*(?:get|post|put|patch|delete|request|head)\s*\(|"
        r"\burllib(?:\.request)?\s*\.\s*(?:urlopen|Request)\s*\(|"
        r"\bsocket\s*\.\s*(?:socket|create_connection|connect|connect_ex|send|sendall|sendto)\s*\("
    )
    line_starts_with_known_network_match = re.match(known_network_call_pattern, stripped_line, re.IGNORECASE)
    line_starts_with_known_network_sink = bool(
        line_starts_with_known_network_match
        and _native_write_line_starts_with_code_call_tail(
            stripped_line,
            open_paren_index=line_starts_with_known_network_match.end() - 1,
        )
    )
    network_arg_pattern = (
        r"(?:"
        r"\b(?:url|uri|endpoint|host|addr|address|[A-Za-z_]\w*(?:url|uri|endpoint|host|addr|address)\w*)\b|"
        r"['\"](?:https?|ftp|ftps|tcp|udp)://|"
        r"\([^)]*\b(?:host|addr|address|port)\b[^)]*\)"
        r")"
    )
    generic_network_method_pattern = (
        rf"\b[A-Za-z_]\w*\s*\.\s*(?:post|put|patch|delete|head|urlopen|connect|connect_ex)\s*"
        rf"\(\s*{network_arg_pattern}"
    )
    generic_network_request_pattern = (
        rf"\b[A-Za-z_]\w*\s*\.\s*request\s*\(\s*['\"](?:GET|POST|PUT|PATCH|DELETE|HEAD)['\"]\s*,"
        rf"\s*{network_arg_pattern}"
    )
    generic_network_get_pattern = (
        rf"\b(?:client|session|http|http_client|request|requests|rq|conn|connection)\s*\.\s*get\s*"
        rf"\(\s*{network_arg_pattern}"
    )
    generic_network_method_sink = bool(
        re.search(generic_network_method_pattern, stripped_line, re.IGNORECASE)
        or re.search(generic_network_request_pattern, stripped_line, re.IGNORECASE)
        or re.search(generic_network_get_pattern, stripped_line, re.IGNORECASE)
    )
    code_context = bool(re.match(
        r"^(?:if|elif|else|for|while|try|except|with|return|await|async|def|class|"
        r"const|let|var)\b",
        stripped_line,
    ))
    code_context = code_context or bool(re.search(r"(?:^|[;{(]\s*)(?:return|await|if)\b", stripped_line))
    code_context = code_context or bool(re.search(r"\b[A-Za-z_]\w*\s*=\s*", stripped_line))
    code_context = (
        code_context
        or line_starts_with_dynamic_sink
        or line_starts_with_dynamic_getattr_sink
        or line_starts_with_known_network_sink
    )

    network_sink = bool(re.search(
        r"\b(?:requests|httpx|urllib(?:\.request)?|http\.client|socket|axios)\s*\.|"
        r"\bXMLHttpRequest\s*\(|\bEventSource\s*\(|\bWebSocket\s*\(|"
        r"\bnavigator\s*\.\s*sendBeacon\s*\(|"
        r"\b__import__\s*\(\s*['\"](?:requests|httpx|urllib|socket|http\.client)['\"]\s*\)|"
        r"\bimportlib\s*\.\s*import_module\s*\(\s*['\"](?:requests|httpx|urllib|socket|http\.client)['\"]\s*\)",
        stripped_line,
        re.IGNORECASE,
    ))
    network_sink = (
        network_sink
        or qualified_dynamic_sink
        or dynamic_getattr_sink
        or known_dynamic_getattr_sink
        or generic_network_method_sink
        or _js_fetch_call_has_remote_network_sink(
            stripped_line,
            string_bindings=js_string_bindings,
        )
    )
    if imported_request_aliases:
        alias_pattern = "|".join(re.escape(alias) for alias in sorted(imported_request_aliases))
        network_sink = network_sink or bool(re.search(rf"\b(?:{alias_pattern})\s*\(", stripped_line))
    if not network_sink:
        return False
    if code_context:
        return True
    return bool(re.match(
        r"^(?:fetch|XMLHttpRequest|EventSource|WebSocket|navigator\s*\.\s*sendBeacon|"
        r"__import__|importlib\s*\.\s*import_module)\b",
        stripped_line,
        re.IGNORECASE,
    ))


def _native_write_line_is_network_import(stripped_line: str) -> bool:
    try:
        tree = ast.parse(stripped_line)
    except SyntaxError:
        return False
    if len(tree.body) != 1:
        return False
    statement = tree.body[0]
    if isinstance(statement, ast.Import):
        for alias in statement.names:
            name = alias.name
            if name in {"requests", "httpx", "urllib", "urllib.request", "http.client", "socket"}:
                return True
        return False
    if isinstance(statement, ast.ImportFrom):
        module = str(statement.module or "")
        return module in {"requests", "httpx", "urllib", "urllib.request", "http.client", "socket"}
    return False


def _native_write_line_starts_with_code_call_tail(line: str, *, open_paren_index: int) -> bool:
    if open_paren_index < 0 or open_paren_index >= len(line) or line[open_paren_index] != "(":
        return False
    depth = 0
    quote = ""
    escaped = False
    for index in range(open_paren_index, len(line)):
        char = line[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char == "(":
            depth += 1
            continue
        if char != ")":
            continue
        depth -= 1
        if depth != 0:
            continue
        tail = line[index + 1:].strip()
        return not tail or tail.startswith(("#", ";", ".", ",", ")", "]", "}"))
    return False


def _native_write_payload_scan_texts(text: str) -> list[str]:
    raw = str(text or "")
    scan_texts = [raw]
    added_lines: list[str] = []
    in_patch_document_block = False
    for line in raw.splitlines():
        patch_path = _apply_patch_file_directive_path(line)
        if patch_path is not None:
            in_patch_document_block = _native_write_path_is_patch_document_artifact(patch_path)
            continue
        if line.strip().startswith("***"):
            in_patch_document_block = False
            continue
        if in_patch_document_block:
            continue
        if line.startswith("+") and not line.startswith("+++"):
            added_lines.append(line[1:])
    if added_lines:
        scan_texts.append("\n".join(added_lines))
    scan_texts.extend(
        body
        for path, body in _patch_added_file_payloads(raw)
        if not _native_write_path_is_patch_document_artifact(path)
    )
    return _dedupe_scan_texts(scan_texts)


def _native_write_payload_scan_texts_for_payload(payload: dict[str, Any], raw_text: str) -> list[str]:
    scan_texts = _native_write_payload_scan_texts(raw_text)
    for key in ("content", "text", "script", "code"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            scan_texts.append(value)
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
                    scan_texts.append(content)
    return _dedupe_scan_texts(scan_texts)


def _native_write_path_is_patch_document_artifact(path: str | None) -> bool:
    if not path:
        return False
    suffix = PurePosixPath(str(path).strip().strip("'\"")).suffix.lower()
    return suffix in {".diff", ".patch"}


def _native_write_script_target_paths(
    payload: dict[str, Any],
    raw_text: str,
    *,
    cwd: str | None,
    scan_texts: list[str],
) -> set[str]:
    script_targets: set[str] = set()
    for path, body in _patch_added_file_payloads(raw_text):
        if _native_write_path_is_patch_document_artifact(path):
            continue
        if _native_write_payload_has_future_execution_marker(body):
            normalized = normalize_task_artifact_path(path, cwd=cwd)
            if normalized:
                script_targets.add(normalized)
    explicit_paths = _payload_paths(payload, include_patch_targets=False)
    content_values = [
        value
        for key in ("content", "text", "script", "code")
        if isinstance((value := payload.get(key)), str) and value.strip()
    ]
    if any(_native_write_payload_has_future_execution_marker(value) for value in content_values):
        for path in explicit_paths:
            normalized = normalize_task_artifact_path(path, cwd=cwd)
            if normalized:
                script_targets.add(normalized)
    for key in ("changes", "files", "edits"):
        value = payload.get(key)
        if not isinstance(value, list):
            continue
        for item in value:
            if not isinstance(item, dict):
                continue
            item_paths = [
                str(item[path_key]).strip()
                for path_key in (
                    "path",
                    "file_path",
                    "relative_path",
                    "target",
                    "target_path",
                    "destination",
                    "destination_path",
                    "output_path",
                )
                if isinstance(item.get(path_key), str) and str(item[path_key]).strip()
            ]
            item_contents = [
                str(item[content_key])
                for content_key in ("content", "text", "script", "code")
                if isinstance(item.get(content_key), str) and str(item[content_key]).strip()
            ]
            if not item_paths or not any(
                _native_write_payload_has_future_execution_marker(content)
                for content in item_contents
            ):
                continue
            for path in item_paths:
                normalized = normalize_task_artifact_path(path, cwd=cwd)
                if normalized:
                    script_targets.add(normalized)
    if not script_targets and _native_write_scan_texts_have_future_execution_marker(scan_texts):
        if len(explicit_paths) != 1:
            return script_targets
        for path in explicit_paths:
            normalized = normalize_task_artifact_path(path, cwd=cwd)
            if normalized:
                script_targets.add(normalized)
    return script_targets


def _native_write_associated_payload_texts(
    payload: dict[str, Any],
    raw_text: str,
    *,
    cwd: str | None,
) -> list[str]:
    payloads: list[str] = []
    for path, body in _patch_added_file_payloads(raw_text):
        if _native_write_path_is_patch_document_artifact(path):
            continue
        target = _target_for_path(path, cwd=cwd)
        body_is_script = _native_write_payload_has_future_execution_marker(body)
        if body_is_script and _native_write_target_is_task_output(target):
            payloads.append(body)
            continue
        if (
            _native_write_has_associated_script_target([target])
            or (
                _native_write_target_is_task_output(target)
                and _native_write_payload_has_web_script_marker(body)
            )
        ):
            payloads.append(body)
    for path, body in _patch_updated_file_payloads(raw_text):
        if _native_write_path_is_patch_document_artifact(path):
            continue
        target = _target_for_path(path, cwd=cwd)
        if (
            _native_write_target_is_task_output(target)
            and not PurePosixPath(str(path or "")).suffix
            and _native_write_scan_texts_have_code_network_sink([body])
        ):
            payloads.append(body)
    explicit_paths = _payload_paths(payload, include_patch_targets=False)
    content_values = [
        value
        for key in ("content", "text", "script", "code")
        if isinstance((value := payload.get(key)), str) and value.strip()
    ]
    if len(explicit_paths) == 1 and content_values:
        target = _target_for_path(explicit_paths[0], cwd=cwd)
        if (
                _native_write_payload_has_future_execution_marker("\n".join(content_values))
            and _native_write_target_is_task_output(target)
        ) or _native_write_has_associated_script_target([target]):
            payloads.extend(content_values)
    for key in ("changes", "files", "edits"):
        value = payload.get(key)
        if not isinstance(value, list):
            continue
        for item in value:
            if not isinstance(item, dict):
                continue
            item_paths = [
                str(item[path_key]).strip()
                for path_key in (
                    "path",
                    "file_path",
                    "relative_path",
                    "target",
                    "target_path",
                    "destination",
                    "destination_path",
                    "output_path",
                )
                if isinstance(item.get(path_key), str) and str(item[path_key]).strip()
            ]
            item_contents = [
                str(item[content_key])
                for content_key in ("content", "text", "script", "code")
                if isinstance(item.get(content_key), str) and str(item[content_key]).strip()
            ]
            if not item_paths or not item_contents:
                continue
            joined_content = "\n".join(item_contents)
            for path in item_paths:
                target = _target_for_path(path, cwd=cwd)
                if (
                    (
                        _native_write_payload_has_future_execution_marker(joined_content)
                        and _native_write_target_is_task_output(target)
                    )
                    or _native_write_has_associated_script_target([target])
                    or (
                        _native_write_target_is_task_output(target)
                        and _native_write_payload_has_web_script_marker(joined_content)
                    )
                ):
                    payloads.extend(item_contents)
                    break
    return _dedupe_strings(payloads)


def _native_write_target_has_script_payload(
    path: str,
    *,
    script_targets: set[str],
    fallback: bool,
    cwd: str | None,
) -> bool:
    if not script_targets:
        return fallback
    normalized = normalize_task_artifact_path(path, cwd=cwd)
    return bool(normalized and normalized in script_targets)


def _native_write_has_associated_script_target(targets: list[ActionEffectTarget]) -> bool:
    return any(
        target.path_role in {"future_execution.artifact", "bootstrap_loader", "persistence_entrypoint"}
        for target in targets
    )


def _native_write_has_associated_script_surface(targets: list[ActionEffectTarget], text: str) -> bool:
    if _native_write_has_associated_script_target(targets):
        return True
    return _native_write_has_task_output_target(targets) and _native_write_payload_has_web_script_marker(text)


def _native_write_has_task_output_target(targets: list[ActionEffectTarget]) -> bool:
    return any(_native_write_target_is_task_output(target) for target in targets)


def _native_write_target_is_task_output(target: ActionEffectTarget) -> bool:
    return (
        target.path_role == SCOPE_TASK_OUTPUT_PATH_ROLE
        or target.artifact_role == "task_output"
        or target.artifact_candidate_role == SCOPE_TASK_OUTPUT_PATH_ROLE
    )


def _native_write_payload_has_web_script_marker(text: str) -> bool:
    return any(_web_text_has_remote_script_loader(scan_text) for scan_text in _native_write_payload_scan_texts(text))


def _native_write_payload_has_executable_script_marker(text: str) -> bool:
    return _native_write_scan_texts_have_executable_script_marker(_native_write_payload_scan_texts(text))


def _native_write_scan_texts_have_executable_script_marker(scan_texts: list[str]) -> bool:
    for scan_text in scan_texts:
        first_content_line = _first_meaningful_payload_line(scan_text)
        if first_content_line and _shebang_names_executable_script(first_content_line):
            return True
    return False


def _native_write_payload_has_future_execution_marker(text: str) -> bool:
    return _native_write_scan_texts_have_future_execution_marker(_native_write_payload_scan_texts(text))


def _native_write_scan_texts_have_future_execution_marker(scan_texts: list[str]) -> bool:
    return _native_write_scan_texts_have_executable_script_marker(scan_texts) or any(
        _web_text_has_remote_script_loader(scan_text)
        or _web_text_has_persistence_loader_contract(scan_text)
        for scan_text in scan_texts
    )


def _native_write_content_read_reference_paths(text: str, *, cwd: str | None = None) -> list[str]:
    paths: list[str] = []
    for path in [
        *_paths(text),
        *_embedded_command_paths(text),
        *_scope_task_data_literal_reference_paths(text, cwd=cwd),
    ]:
        role = _path_role_for_read(path)
        if role in {
            SCOPE_TASK_DATA_READ_PATH_ROLE,
            "credential_source",
            "hidden_oracle",
            SCOPE_CONTROL_METADATA_PATH_ROLE,
        }:
            paths.append(path)
            continue
        artifact = resolve_scope_task_artifact(path, access="read", context=_NORMALIZER_CONTEXT.get(), cwd=cwd)
        if (
            _artifact_decision_is_effective(artifact)
            and artifact.path_role == SCOPE_TASK_DATA_READ_PATH_ROLE
        ):
            paths.append(path)
    return _dedupe_strings(paths)


def _native_write_content_write_reference_targets(
    text: str,
    *,
    cwd: str | None = None,
) -> tuple[list[ActionEffectTarget], bool, bool]:
    targets: list[ActionEffectTarget] = []
    has_unscoped_write_reference = False
    has_auxiliary_write_reference = False
    for path in _python_write_targets(text):
        if _ASSOCIATED_SCRIPT_AUXILIARY_WRITE_PATH_RE.search(path):
            has_auxiliary_write_reference = True
        target = _scope_task_output_target_for_path(path, cwd=cwd)
        if target is not None:
            targets.append(target.model_copy(update={"io_direction": "target"}))
        else:
            has_unscoped_write_reference = True
    return _dedupe_targets(targets), has_unscoped_write_reference, has_auxiliary_write_reference


def _native_write_content_has_unresolved_write_reference(text: str) -> bool:
    try:
        tree = ast.parse(str(text or ""))
    except SyntaxError:
        return False
    path_bindings = _python_path_variable_bindings(text)
    path_sequence_bindings = _python_path_sequence_variable_bindings(text)
    return (
        _python_ast_has_unresolved_writer_method_call(
            tree,
            path_bindings,
            path_sequence_bindings,
        )
        or _python_ast_has_unresolved_path_writer_receiver_call(
            tree,
            path_bindings,
            path_sequence_bindings,
        )
        or _python_ast_has_invalidated_mapping_writer_method_call(tree)
    )


# --- late-bound cross-module names (mechanical split of normalizer.py) ---
# Placed after all definitions on purpose: modules in this package form
# import cycles that are only safe because every module completes its own
# definitions before this block runs. Do not move these imports to the top.
from clawsentry.gateway.effects.normalizer import (  # noqa: E402
    _ASSOCIATED_SCRIPT_AUXILIARY_WRITE_PATH_RE,
    _NORMALIZER_CONTEXT,
    _URL_RE,
    _apply_patch_file_directive_path,
    _dedupe_scan_texts,
    _dedupe_strings,
    _dedupe_targets,
    _embedded_command_paths,
    _first_meaningful_payload_line,
    _js_fetch_call_has_remote_network_sink,
    _js_static_string_bindings,
    _package_indicator_scan_texts,
    _patch_added_file_payloads,
    _patch_updated_file_payloads,
    _paths,
    _payload_paths,
    _shebang_names_executable_script,
    _strip_markdown_fenced_blocks,
    _target_for_path,
    _web_text_has_persistence_loader_contract,
    _web_text_has_remote_script_loader,
)
from clawsentry.gateway.effects.python_ast import (  # noqa: E402
    _inline_python_source,
    _python_ast_has_dynamic_code_call,
    _python_ast_has_invalidated_mapping_writer_method_call,
    _python_ast_has_unresolved_path_writer_receiver_call,
    _python_ast_has_unresolved_writer_method_call,
    _python_has_import_module_call,
    _python_has_socket_or_raw_network,
    _python_has_wrapper_execution,
    _python_path_sequence_variable_bindings,
    _python_path_variable_bindings,
    _python_source_has_executable_package_install,
    _python_source_has_network_fetch,
    _python_write_targets,
)
from clawsentry.gateway.effects.shell_model import (  # noqa: E402
    _shell_command_invokes_package_install,
)
from clawsentry.gateway.effects.artifact_scope import (  # noqa: E402
    _artifact_decision_is_effective,
    _path_role_for_read,
    _scope_task_data_literal_reference_paths,
    _scope_task_output_target_for_path,
)
