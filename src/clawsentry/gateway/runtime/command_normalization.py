"""Pure shell command normalization helpers for L3 trigger parsing."""

from __future__ import annotations

import ast
import re
import shlex
import subprocess
import string


_ENV_ASSIGNMENT_PATTERN = re.compile(r"^[a-z_][a-z0-9_]*=.*$", re.IGNORECASE)
_SHELL_PREFIX_TOKENS = frozenset({"sudo", "command", "builtin", "env", "nohup", "time", "stdbuf"})
_SHELL_WRAPPER_TOKENS = frozenset({"bash", "sh", "zsh", "dash"})
_PYTHON_SUBPROCESS_CALLS = frozenset({
    "run", "call", "popen", "check_call", "check_output", "getoutput", "getstatusoutput",
})

__all__ = ["matches_shell_command_token", "normalize_shell_command_head"]


def matches_shell_command_token(command_text: str, token: str) -> bool:
    for segment in _shell_command_segments(command_text):
        head = normalize_shell_command_head(segment)
        if head.startswith(token):
            return True
    return False


def normalize_shell_command_head(segment: str) -> str:
    parts = _split_shell_segment(segment)
    idx = 0

    while idx < len(parts):
        part = parts[idx]
        if _ENV_ASSIGNMENT_PATTERN.match(part):
            idx += 1
            continue
        if part in _SHELL_PREFIX_TOKENS:
            idx += 1
            if part == "env":
                while idx < len(parts) and _ENV_ASSIGNMENT_PATTERN.match(parts[idx]):
                    idx += 1
            continue
        break

    if idx < len(parts) and parts[idx] in _SHELL_WRAPPER_TOKENS:
        wrapped_command = _extract_shell_wrapper_command(parts[idx + 1:])
        if wrapped_command is not None:
            return normalize_shell_command_head(wrapped_command)

    if idx < len(parts) and _is_python_launcher(parts[idx]):
        wrapped_command = _extract_python_launcher_command(parts[idx + 1:])
        if wrapped_command is not None:
            return normalize_shell_command_head(wrapped_command)

    return " ".join(parts[idx:])


def _shell_command_segments(command_text: str) -> list[str]:
    command = str(command_text or "")
    segments: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escaped = False
    i = 0

    while i < len(command):
        ch = command[i]

        if escaped:
            current.append(ch)
            escaped = False
            i += 1
            continue

        if quote is not None:
            current.append(ch)
            if ch == "\\" and quote == '"':
                escaped = True
            elif ch == quote:
                quote = None
            i += 1
            continue

        if ch in {'"', "'"}:
            quote = ch
            current.append(ch)
            i += 1
            continue

        if command.startswith("&&", i) or command.startswith("||", i):
            segments.append("".join(current))
            current = []
            i += 2
            continue

        if ch in {";", "|"}:
            segments.append("".join(current))
            current = []
            i += 1
            continue

        current.append(ch)
        i += 1

    segments.append("".join(current))
    return segments


def _split_shell_segment(segment: str) -> list[str]:
    try:
        return shlex.split(str(segment or ""), posix=True)
    except ValueError:
        return str(segment or "").strip().split()


def _extract_shell_wrapper_command(args: list[str]) -> str | None:
    idx = 0
    while idx < len(args):
        arg = args[idx]
        if arg == "--":
            break
        if not arg.startswith("-"):
            return None
        if _shell_option_runs_command(arg):
            if idx + 1 < len(args):
                return args[idx + 1]
            return ""
        idx += 1
    return None


def _shell_option_runs_command(arg: str) -> bool:
    if not arg.startswith("-") or arg.startswith("--"):
        return False
    return "c" in arg[1:]


def _is_python_launcher(command: str) -> bool:
    if command == "python" or command == "python3":
        return True
    return bool(re.fullmatch(r"python\d+(?:\.\d+)?", command))


def _extract_python_launcher_command(args: list[str]) -> str | None:
    idx = 0
    while idx < len(args):
        arg = args[idx]
        if arg == "--":
            break
        if arg == "-c":
            if idx + 1 < len(args):
                return _extract_python_command_from_code(args[idx + 1])
            return ""
        idx += 1
    return None


def _extract_python_command_from_code(code: str) -> str | None:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return None

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        command = _python_call_command(node)
        if command is not None:
            return command
    return None


def _python_call_command(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        if func.value.id == "os" and func.attr in {"system", "popen"}:
            return _python_arg_to_command(node.args[0]) if node.args else None
        if func.value.id == "os" and func.attr == "execl":
            return _python_args_to_command(node.args[1:])
        if func.value.id == "os" and func.attr == "execlp":
            return _python_args_to_command(node.args[1:])
        if func.value.id == "os" and func.attr == "execle":
            return _python_args_to_command_with_trailing_env(node.args[1:])
        if func.value.id == "os" and func.attr == "execlpe":
            return _python_args_to_command_with_trailing_env(node.args[1:])
        if func.value.id == "os" and func.attr == "execv":
            if len(node.args) > 1:
                return _python_arg_to_command(node.args[1])
            return _python_keyword_args_to_command(node, "argv")
        if func.value.id == "os" and func.attr == "execve":
            if len(node.args) > 1:
                return _python_arg_to_command(node.args[1])
            return _python_keyword_args_to_command(node, "argv")
        if func.value.id == "os" and func.attr == "execvpe":
            if len(node.args) > 1:
                return _python_arg_to_command(node.args[1])
            return _python_keyword_args_to_command(node, "args")
        if func.value.id == "os" and func.attr == "execvp":
            if len(node.args) > 1:
                return _python_arg_to_command(node.args[1])
            return _python_keyword_args_to_command(node, "args")
        if func.value.id == "os" and func.attr == "spawnl":
            return _python_args_to_command(node.args[2:])
        if func.value.id == "os" and func.attr == "spawnlp":
            return _python_args_to_command(node.args[2:])
        if func.value.id == "os" and func.attr == "spawnle":
            return _python_args_to_command_with_trailing_env(node.args[2:])
        if func.value.id == "os" and func.attr == "spawnlpe":
            return _python_args_to_command_with_trailing_env(node.args[2:])
        if func.value.id == "os" and func.attr == "spawnv":
            if len(node.args) > 2:
                return _python_arg_to_command(node.args[2])
            return _python_keyword_args_to_command(node, "args")
        if func.value.id == "os" and func.attr == "spawnve":
            if len(node.args) > 2:
                return _python_arg_to_command(node.args[2])
            return _python_keyword_args_to_command(node, "args")
        if func.value.id == "os" and func.attr == "spawnvpe":
            if len(node.args) > 2:
                return _python_arg_to_command(node.args[2])
            return _python_keyword_args_to_command(node, "args")
        if func.value.id == "os" and func.attr == "spawnvp":
            if len(node.args) > 2:
                return _python_arg_to_command(node.args[2])
            return _python_keyword_args_to_command(node, "args")
        if func.value.id == "os" and func.attr == "posix_spawn":
            if len(node.args) > 1:
                return _python_arg_to_command(node.args[1])
            return _python_keyword_arg_to_command(node, "argv")
        if func.value.id == "os" and func.attr == "posix_spawnp":
            if len(node.args) > 1:
                return _python_arg_to_command(node.args[1])
            return _python_keyword_arg_to_command(node, "argv")
        if func.value.id == "subprocess" and func.attr.lower() in _PYTHON_SUBPROCESS_CALLS:
            if node.args:
                return _python_arg_to_command(node.args[0])
            if func.attr.lower() in {"getoutput", "getstatusoutput"}:
                return _python_keyword_arg_to_command(node, "cmd")
            return _python_keyword_arg_to_command(node, "args")
    return None


def _python_arg_to_command(arg: ast.AST) -> str | None:
    string_value = _python_string_arg_value(arg)
    if string_value is not None:
        return string_value
    parts = _python_sequence_arg_parts(arg)
    if parts is not None:
        return shlex.join(parts)
    return None


def _python_args_to_command(args: list[ast.AST]) -> str | None:
    if not args:
        return None
    parts: list[str] = []
    for arg in args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            parts.append(arg.value)
            continue
        if isinstance(arg, ast.Starred):
            starred_parts = _python_starred_arg_parts(arg.value)
            if starred_parts is None:
                return None
            parts.extend(starred_parts)
            continue
        return None
    return shlex.join(parts)


def _python_args_to_command_with_trailing_env(args: list[ast.AST]) -> str | None:
    if len(args) < 2 or not isinstance(args[-1], ast.Dict):
        return None
    return _python_args_to_command(args[:-1])


def _python_keyword_arg_to_command(node: ast.Call, keyword_name: str) -> str | None:
    for keyword in node.keywords:
        if keyword.arg == keyword_name:
            return _python_arg_to_command(keyword.value)
    return None


def _python_keyword_args_to_command(node: ast.Call, *keyword_names: str) -> str | None:
    for keyword_name in keyword_names:
        command = _python_keyword_arg_to_command(node, keyword_name)
        if command is not None:
            return command
    return None


def _python_string_arg_value(arg: ast.AST) -> str | None:
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        return arg.value
    if isinstance(arg, ast.JoinedStr):
        parts: list[str] = []
        for value in arg.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
                continue
            if isinstance(value, ast.FormattedValue) and value.conversion == -1 and value.format_spec is None:
                formatted = _python_string_arg_value(value.value)
                if formatted is None:
                    return None
                parts.append(formatted)
                continue
            return None
        return "".join(parts)
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
        left = _python_string_arg_value(arg.left)
        if left is None:
            return None
        right = _python_string_arg_value(arg.right)
        if right is None:
            return None
        return left + right
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Mod):
        template = _python_string_arg_value(arg.left)
        if template is None:
            return None
        values = _python_percent_format_values(arg.right)
        if values is None:
            return None
        try:
            return template % values
        except (TypeError, ValueError):
            return None
    if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute):
        if arg.func.attr in {"substitute", "safe_substitute"}:
            template = _python_template_string(arg.func.value)
            if template is None:
                return None
            if arg.func.attr == "safe_substitute":
                if len(arg.args) > 1:
                    return None
                if arg.args:
                    if arg.keywords:
                        return None
                    mapping = _python_string_mapping_from_dict(arg.args[0])
                else:
                    mapping = _python_string_mapping(arg.keywords)
            elif len(arg.args) > 1:
                return None
            elif arg.args:
                if arg.keywords:
                    return None
                mapping = _python_string_mapping_from_dict(arg.args[0])
            else:
                mapping = _python_string_mapping(arg.keywords)
            if mapping is None:
                return None
            try:
                if arg.func.attr == "safe_substitute":
                    return template.safe_substitute(mapping)
                return template.substitute(mapping)
            except (KeyError, ValueError):
                return None
        if isinstance(arg.func.value, ast.Name) and arg.func.value.id == "subprocess" and arg.func.attr == "list2cmdline":
            if len(arg.args) != 1 or arg.keywords:
                return None
            parts = _python_sequence_arg_parts(arg.args[0])
            if parts is None:
                return None
            return subprocess.list2cmdline(parts)
        if isinstance(arg.func.value, ast.Name) and arg.func.value.id == "shlex" and arg.func.attr == "join":
            if len(arg.args) != 1 or arg.keywords:
                return None
            parts = _python_sequence_arg_parts(arg.args[0])
            if parts is None:
                return None
            return shlex.join(parts)
        if arg.func.attr == "format":
            template = _python_string_arg_value(arg.func.value)
            if template is None:
                return None
            values: list[str] = []
            for value in arg.args:
                rendered = _python_string_arg_value(value)
                if rendered is None:
                    return None
                values.append(rendered)
            mapping = _python_string_mapping(arg.keywords)
            if mapping is None:
                return None
            try:
                return template.format(*values, **mapping)
            except (IndexError, KeyError, ValueError):
                return None
        if arg.func.attr == "format_map":
            template = _python_string_arg_value(arg.func.value)
            if template is None or len(arg.args) != 1 or arg.keywords:
                return None
            mapping = _python_string_mapping_from_dict(arg.args[0])
            if mapping is None:
                return None
            try:
                return template.format_map(mapping)
            except (KeyError, ValueError):
                return None
        separator = _python_string_arg_value(arg.func.value)
        if separator is None or arg.func.attr != "join" or len(arg.args) != 1 or arg.keywords:
            return None
        parts = _python_sequence_arg_parts(arg.args[0])
        if parts is None:
            return None
        return separator.join(parts)
    return None


def _python_template_string(arg: ast.AST) -> string.Template | None:
    if not isinstance(arg, ast.Call) or not isinstance(arg.func, ast.Attribute):
        return None
    if (
        not isinstance(arg.func.value, ast.Name)
        or arg.func.value.id != "string"
        or arg.func.attr.lower() != "template"
    ):
        return None
    if len(arg.args) != 1 or arg.keywords:
        return None
    template = _python_string_arg_value(arg.args[0])
    if template is None:
        return None
    return string.Template(template)


def _python_string_mapping(keywords: list[ast.keyword]) -> dict[str, str] | None:
    mapping: dict[str, str] = {}
    for keyword in keywords:
        if keyword.arg is None:
            expanded = _python_string_mapping_from_dict(keyword.value)
            if expanded is None:
                return None
            for key, value in expanded.items():
                if key in mapping:
                    return None
                mapping[key] = value
            continue
        rendered = _python_string_arg_value(keyword.value)
        if rendered is None or keyword.arg in mapping:
            return None
        mapping[keyword.arg] = rendered
    return mapping


def _python_string_mapping_from_dict(arg: ast.AST) -> dict[str, str] | None:
    mapping: dict[str, str] = {}
    if isinstance(arg, ast.Dict):
        for key, value in zip(arg.keys, arg.values):
            if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
                return None
            rendered = _python_string_arg_value(value)
            if rendered is None or key.value in mapping:
                return None
            mapping[key.value] = rendered
        return mapping
    if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Name) and arg.func.id == "dict":
        if arg.args:
            return None
        for keyword in arg.keywords:
            if keyword.arg is None:
                return None
            rendered = _python_string_arg_value(keyword.value)
            if rendered is None or keyword.arg in mapping:
                return None
            mapping[keyword.arg] = rendered
        return mapping
    return None


def _python_percent_format_values(arg: ast.AST) -> str | tuple[str, ...] | None:
    value = _python_string_arg_value(arg)
    if value is not None:
        return value
    parts = _python_sequence_arg_parts(arg)
    if parts is not None:
        return tuple(parts)
    return None


def _python_starred_arg_parts(arg: ast.AST) -> list[str] | None:
    return _python_sequence_arg_parts(arg)


def _python_sequence_arg_parts(arg: ast.AST) -> list[str] | None:
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
        left_parts = _python_sequence_arg_parts(arg.left)
        if left_parts is None:
            return None
        right_parts = _python_sequence_arg_parts(arg.right)
        if right_parts is None:
            return None
        return left_parts + right_parts
    if not isinstance(arg, (ast.List, ast.Tuple)):
        return None
    parts: list[str] = []
    for elt in arg.elts:
        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
            parts.append(elt.value)
            continue
        if isinstance(elt, ast.Starred):
            starred_parts = _python_starred_arg_parts(elt.value)
            if starred_parts is None:
                return None
            parts.extend(starred_parts)
            continue
        return None
    return parts
