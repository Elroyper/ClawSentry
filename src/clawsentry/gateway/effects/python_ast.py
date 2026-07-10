"""Python-source static analysis subsystem for the effect normalizer.

Mechanically split from normalizer.py (single shared late-bound namespace;
see the bottom import block). Behavior-preserving: do not reorder segments.
"""

from __future__ import annotations

import ast
import contextvars
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
_PYTHON_STATIC_TEXT_PAYLOAD_BINDING_MAX_PASSES = 8
_PYTHON_STATIC_TEXT_PAYLOAD_CANDIDATE_LIMIT = 32
_PYTHON_MUTATING_METHOD_NAMES = frozenset({
    "chmod",
    "chown",
    "extract",
    "extractall",
    "mkdir",
    "remove",
    "rename",
    "replace",
    "rmdir",
    "save",
    "touch",
    "truncate",
    "unlink",
    "write",
    "write_bytes",
    "write_text",
    "writelines",
})
_PYTHON_PATH_WRITER_METHOD_NAMES = frozenset({
    "to_csv",
    "to_excel",
    "to_feather",
    "to_hdf",
    "to_html",
    "to_json",
    "to_latex",
    "to_markdown",
    "to_parquet",
    "to_pickle",
    "to_stata",
})
_PYTHON_PATH_WRITER_CONSTRUCTOR_NAMES = frozenset({
    "ExcelWriter",
})
_PYTHON_PATH_WRITER_CONSTRUCTOR_KEYWORDS_BY_NAME: dict[str, frozenset[str]] = {
    "ExcelWriter": frozenset({"path"}),
}
_PYTHON_PATH_WRITER_KEYWORDS_BY_METHOD: dict[str, frozenset[str]] = {
    "to_csv": frozenset({"path_or_buf"}),
    "to_excel": frozenset({"excel_writer"}),
    "to_feather": frozenset({"path"}),
    "to_hdf": frozenset({"path_or_buf"}),
    "to_html": frozenset({"buf"}),
    "to_json": frozenset({"path_or_buf"}),
    "to_latex": frozenset({"buf"}),
    "to_markdown": frozenset({"buf"}),
    "to_parquet": frozenset({"path"}),
    "to_pickle": frozenset({"path"}),
    "to_stata": frozenset({"path"}),
}
_PYTHON_OS_DESTRUCTIVE_DELETE_METHOD_NAMES = frozenset({
    "remove",
    "removedirs",
    "rmdir",
    "unlink",
})
_PYTHON_SHUTIL_DESTRUCTIVE_DELETE_METHOD_NAMES = frozenset({
    "rmtree",
})
_PYTHON_SHUTIL_COPY_METHOD_NAMES = frozenset({
    "copy",
    "copy2",
    "copyfile",
    "copytree",
})
_PYTHON_SAVE_METHOD_PATH_KEYWORDS = frozenset({
    "file",
    "filename",
    "filepath",
    "fp",
    "name",
    "path",
    "path_or_buf",
})
_PYTHON_DYNAMIC_CODE_CALLABLE_NAMES = frozenset({
    "__import__",
    "compile",
    "eval",
    "exec",
})
_PYTHON_DOCUMENT_READER_SOURCE_KEYWORDS = frozenset({
    "docx",
    "file",
    "filename",
    "filepath_or_buffer",
    "io",
    "path",
    "path_or_buffer",
    "path_or_fp",
    "pptx",
    "stream",
})
_PYTHON_LIST_CONTENT_POLLUTING_METHOD_NAMES = frozenset({
    "__iadd__",
    "__setitem__",
    "append",
    "extend",
    "insert",
})
_PYTHON_DICT_CONTENT_POLLUTING_METHOD_NAMES = frozenset({
    "__ior__",
    "__setitem__",
    "clear",
    "pop",
    "popitem",
    "setdefault",
    "update",
})
_PYTHON_ITERTOOLS_FIRST_ARG_PATH_ITERATORS = frozenset({
    "compress",
    "cycle",
    "islice",
    "pairwise",
})
_PYTHON_ITERTOOLS_SECOND_ARG_PATH_ITERATORS = frozenset({
    "dropwhile",
    "filterfalse",
    "takewhile",
})
_PYTHON_ARGV_PATH_BINDINGS: contextvars.ContextVar[dict[int, str]] = contextvars.ContextVar(
    "clawsentry_python_argv_path_bindings",
    default={},
)
_PYTHON_SYS_MODULE_ALIASES: contextvars.ContextVar[set[str]] = contextvars.ContextVar(
    "clawsentry_python_sys_module_aliases",
    default={"sys"},
)
_PYTHON_SYS_ARGV_ALIASES: contextvars.ContextVar[set[str]] = contextvars.ContextVar(
    "clawsentry_python_sys_argv_aliases",
    default={"argv"},
)
_PYTHON_STATIC_DICT_BINDINGS: contextvars.ContextVar[dict[str, ast.Dict]] = contextvars.ContextVar(
    "clawsentry_python_static_dict_bindings",
    default={},
)


def _python_language_analysis_surface(tool_l: str, raw_text: str, language_surface: str) -> str:
    if tool_l in {"python", "python3"}:
        return language_surface
    if tool_l not in _SHELL_TOOL_NAMES:
        return language_surface
    python_sources = _inline_python_sources(raw_text)
    if python_sources:
        return "\n".join(python_sources)
    return language_surface


def _python_source_has_executable_package_install(source: str) -> bool | None:
    try:
        tree = ast.parse(str(source or ""))
    except SyntaxError:
        return None
    found_package_text = False
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func_name = _python_call_dotted_name(node.func)
        command_text = _python_package_command_text_from_call(node, func_name)
        if command_text is None:
            continue
        found_package_text = True
        if _shell_command_invokes_package_install(command_text):
            return True
    return False if found_package_text or str(source or "").strip() else None


def _python_call_dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _python_call_dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _python_package_command_text_from_call(node: ast.Call, func_name: str) -> str | None:
    if func_name in {
        "os.system",
        "os.popen",
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.Popen",
    }:
        if not node.args:
            return None
        return _python_static_command_text(node.args[0])
    if func_name in {"pip.main", "pip._internal.main"}:
        if not node.args:
            return "pip"
        args_text = _python_static_command_text(node.args[0])
        return f"pip {args_text}" if args_text else "pip"
    return None


def _python_static_command_text(node: ast.AST) -> str | None:
    value = _python_static_string_value(node)
    if value is not None:
        return value
    if isinstance(node, (ast.List, ast.Tuple)):
        parts: list[str] = []
        for item in node.elts:
            item_text = _python_static_string_value(item)
            if item_text is None:
                return None
            parts.append(item_text)
        return " ".join(parts)
    return None


def _python_static_string_value(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
                return None
            parts.append(value.value)
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _python_static_string_value(node.left)
        right = _python_static_string_value(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def _python_constant_probe_arg(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return isinstance(node.value, (str, int, float, bool, type(None)))
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        return isinstance(node.operand, ast.Constant) and isinstance(node.operand.value, (int, float))
    return False


def _python_has_import_module_call(text: str) -> bool:
    source = _inline_python_source(text) or text
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return False
    importlib_aliases = {"importlib"}
    import_module_aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "importlib":
                    importlib_aliases.add(alias.asname or "importlib")
        elif isinstance(node, ast.ImportFrom) and node.module == "importlib":
            for alias in node.names:
                if alias.name == "import_module":
                    import_module_aliases.add(alias.asname or alias.name)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "import_module"
            and isinstance(func.value, ast.Name)
            and func.value.id in importlib_aliases
        ):
            return True
        if isinstance(func, ast.Name) and func.id in import_module_aliases:
            return True
    return False


def _python_has_unsafe_find_spec_probe(text: str) -> bool:
    source = _inline_python_source(text) or text
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return False
    importlib_aliases, find_spec_aliases = _python_importlib_find_spec_aliases(tree)
    module_bindings = _python_module_probe_literal_bindings(tree)
    loop_bindings = _python_module_probe_loop_bindings(tree, module_bindings)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not _python_call_is_find_spec_like(
            node,
            importlib_aliases=importlib_aliases,
            find_spec_aliases=find_spec_aliases,
        ):
            continue
        if not _python_call_is_find_spec_probe(
            node,
            importlib_aliases=importlib_aliases,
            find_spec_aliases=find_spec_aliases,
            module_bindings=module_bindings,
            loop_bindings=loop_bindings,
        ):
            return True
    return False


def _python_importlib_find_spec_aliases(tree: ast.AST) -> tuple[set[str], set[str]]:
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
        elif isinstance(node, ast.ImportFrom) and node.module == "importlib.util":
            for alias in node.names:
                if alias.name == "find_spec":
                    find_spec_aliases.add(alias.asname or alias.name)
    return importlib_aliases, find_spec_aliases


def _python_module_probe_literal_bindings(tree: ast.AST) -> dict[str, list[str]]:
    bindings: dict[str, list[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        modules = _python_module_probe_literal_sequence(node.value)
        if not modules:
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                bindings[target.id] = modules
    return bindings


def _python_module_probe_loop_bindings(
    tree: ast.AST,
    module_bindings: dict[str, list[str]],
) -> set[str]:
    loop_names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.For) or not isinstance(node.target, ast.Name):
            continue
        if _python_module_probe_iter_values(node.iter, module_bindings):
            loop_names.add(node.target.id)
    return loop_names


def _python_module_probe_iter_values(
    node: ast.AST,
    module_bindings: dict[str, list[str]],
) -> list[str]:
    if isinstance(node, ast.Name):
        return module_bindings.get(node.id, [])
    return _python_module_probe_literal_sequence(node)


def _python_module_probe_literal_sequence(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value] if _is_safe_python_module_probe_name(node.value) else []
    if not isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return []
    modules: list[str] = []
    for element in node.elts:
        if not isinstance(element, ast.Constant) or not isinstance(element.value, str):
            return []
        if not _is_safe_python_module_probe_name(element.value):
            return []
        modules.append(element.value)
    return modules


def _python_call_is_find_spec_probe(
    node: ast.Call,
    *,
    importlib_aliases: set[str],
    find_spec_aliases: set[str],
    module_bindings: dict[str, list[str]],
    loop_bindings: set[str],
) -> bool:
    if not node.args or node.keywords:
        return False
    func = node.func
    if isinstance(func, ast.Attribute):
        if func.attr != "find_spec":
            return False
        value = func.value
        if (
            isinstance(value, ast.Name)
            and f"{value.id}.find_spec" in find_spec_aliases
        ):
            return _python_module_probe_arg_is_safe(node.args[0], module_bindings, loop_bindings)
        if not (
            isinstance(value, ast.Attribute)
            and value.attr == "util"
            and isinstance(value.value, ast.Name)
            and value.value.id in importlib_aliases
        ):
            return False
    elif isinstance(func, ast.Name):
        if func.id not in find_spec_aliases:
            return False
    else:
        return False
    return _python_module_probe_arg_is_safe(node.args[0], module_bindings, loop_bindings)


def _python_call_is_find_spec_like(
    node: ast.Call,
    *,
    importlib_aliases: set[str],
    find_spec_aliases: set[str],
) -> bool:
    func = node.func
    if isinstance(func, ast.Attribute):
        if func.attr != "find_spec":
            return False
        value = func.value
        if (
            isinstance(value, ast.Name)
            and f"{value.id}.find_spec" in find_spec_aliases
        ):
            return True
        return (
            isinstance(value, ast.Attribute)
            and value.attr == "util"
            and isinstance(value.value, ast.Name)
            and value.value.id in importlib_aliases
        )
    return isinstance(func, ast.Name) and func.id in find_spec_aliases


def _python_module_probe_arg_is_safe(
    node: ast.AST,
    module_bindings: dict[str, list[str]],
    loop_bindings: set[str],
) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return _is_safe_python_module_probe_name(node.value)
    if isinstance(node, ast.Name):
        return node.id in loop_bindings or bool(module_bindings.get(node.id))
    return False


def _python_call_matches_name(node: ast.AST, names: set[str]) -> bool:
    return isinstance(node, ast.Name) and node.id in names


_PYTHON_DOCUMENT_READER_DYNAMIC_IMPORT_MODULES = frozenset({
    "pypdf",
    "PyPDF2",
    "pdfplumber",
})


def _python_ast_has_only_document_reader_dynamic_import_probe(tree: ast.AST) -> bool:
    importlib_aliases = {"importlib"}
    import_module_aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "importlib":
                    importlib_aliases.add(alias.asname or "importlib")
        elif isinstance(node, ast.ImportFrom) and node.module == "importlib":
            for alias in node.names:
                if alias.name == "import_module":
                    import_module_aliases.add(alias.asname or alias.name)

    dynamic_import_names = importlib_aliases | import_module_aliases | _PYTHON_DYNAMIC_CODE_CALLABLE_NAMES
    if _python_names_shadowed_by_runtime_store(tree, dynamic_import_names):
        return False
    parent_map = _python_ast_parent_map(tree)
    module_bindings = _python_document_reader_module_literal_bindings(tree)
    loop_bindings = _python_document_reader_module_loop_bindings(tree, module_bindings)
    saw_dynamic_import = False
    allowed_func_node_ids: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _python_call_is_document_reader_dynamic_import(
            node,
            importlib_aliases=importlib_aliases,
            import_module_aliases=import_module_aliases,
            module_bindings=module_bindings,
            loop_bindings=loop_bindings,
            parent_map=parent_map,
        ):
            saw_dynamic_import = True
            allowed_func_node_ids.add(id(node.func))
            continue
        if _python_call_is_any_dynamic_import(
            node,
            importlib_aliases=importlib_aliases,
            import_module_aliases=import_module_aliases,
        ):
            return False
        if _python_call_is_dynamic_code_builtin(node):
            return False
    return saw_dynamic_import and not _python_ast_has_disallowed_dynamic_code_reference(
        tree,
        importlib_aliases=importlib_aliases,
        import_module_aliases=import_module_aliases,
        allowed_func_node_ids=allowed_func_node_ids,
    )


def _python_ast_parent_map(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    parent_map: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parent_map[child] = parent
    return parent_map


def _python_ast_node_is_inside(
    node: ast.AST,
    ancestor: ast.AST,
    parent_map: dict[ast.AST, ast.AST],
) -> bool:
    current = node
    while current in parent_map:
        current = parent_map[current]
        if current is ancestor:
            return True
    return False


def _python_names_shadowed_by_runtime_store(tree: ast.AST, names: set[str]) -> bool:
    if not names:
        return False
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
            targets: list[ast.AST] = []
            if isinstance(node, ast.Assign):
                targets = list(node.targets)
            else:
                targets = [node.target]
            if any(name in names for target in targets for name in _python_assignment_target_names(target)):
                return True
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            if any(name in names for name in _python_assignment_target_names(node.target)):
                return True
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None and any(
                    name in names for name in _python_assignment_target_names(item.optional_vars)
                ):
                    return True
        elif isinstance(node, ast.ExceptHandler):
            if isinstance(node.name, str) and node.name in names:
                return True
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name in names:
                return True
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                arg_names = [
                    arg.arg
                    for arg in (
                        list(node.args.posonlyargs)
                        + list(node.args.args)
                        + list(node.args.kwonlyargs)
                    )
                ]
                if node.args.vararg is not None:
                    arg_names.append(node.args.vararg.arg)
                if node.args.kwarg is not None:
                    arg_names.append(node.args.kwarg.arg)
                if any(name in names for name in arg_names):
                    return True
    return False


def _python_document_reader_module_literal_bindings(tree: ast.AST) -> dict[str, tuple[str, ...]]:
    bindings: dict[str, tuple[str, ...]] = {}
    safe_assignment_counts: dict[str, int] = {}
    unsafe_stores: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            modules = _python_document_reader_module_literal_sequence(node.value)
            for target in node.targets:
                for name in _python_assignment_target_names(target):
                    if modules:
                        bindings[name] = tuple(modules)
                        safe_assignment_counts[name] = safe_assignment_counts.get(name, 0) + 1
                    else:
                        unsafe_stores.add(name)
        elif isinstance(node, ast.AnnAssign):
            modules = (
                _python_document_reader_module_literal_sequence(node.value)
                if node.value is not None
                else []
            )
            for name in _python_assignment_target_names(node.target):
                if modules:
                    bindings[name] = tuple(modules)
                    safe_assignment_counts[name] = safe_assignment_counts.get(name, 0) + 1
                else:
                    unsafe_stores.add(name)
        elif isinstance(node, (ast.AugAssign, ast.NamedExpr)):
            for name in _python_assignment_target_names(node.target):
                unsafe_stores.add(name)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            for name in _python_assignment_target_names(node.target):
                unsafe_stores.add(name)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    for name in _python_assignment_target_names(item.optional_vars):
                        unsafe_stores.add(name)
        elif isinstance(node, ast.ExceptHandler) and isinstance(node.name, str):
            unsafe_stores.add(node.name)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            unsafe_stores.add(node.name)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for arg in (
                    list(node.args.posonlyargs)
                    + list(node.args.args)
                    + list(node.args.kwonlyargs)
                ):
                    unsafe_stores.add(arg.arg)
                if node.args.vararg is not None:
                    unsafe_stores.add(node.args.vararg.arg)
                if node.args.kwarg is not None:
                    unsafe_stores.add(node.args.kwarg.arg)
    return {
        name: modules
        for name, modules in bindings.items()
        if safe_assignment_counts.get(name) == 1 and name not in unsafe_stores
    }


def _python_document_reader_module_loop_bindings(
    tree: ast.AST,
    module_bindings: dict[str, tuple[str, ...]],
) -> dict[str, list[ast.For | ast.AsyncFor]]:
    loop_names: dict[str, list[ast.For | ast.AsyncFor]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.For, ast.AsyncFor)) or not isinstance(node.target, ast.Name):
            continue
        if _python_document_reader_module_iter_values(node.iter, module_bindings):
            loop_names.setdefault(node.target.id, []).append(node)
    return loop_names


def _python_document_reader_module_iter_values(
    node: ast.AST,
    module_bindings: dict[str, tuple[str, ...]],
) -> tuple[str, ...]:
    if isinstance(node, ast.Name):
        return module_bindings.get(node.id, ())
    return _python_document_reader_module_literal_sequence(node)


def _python_document_reader_module_literal_sequence(node: ast.AST) -> tuple[str, ...]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return (node.value,) if node.value in _PYTHON_DOCUMENT_READER_DYNAMIC_IMPORT_MODULES else ()
    if not isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return ()
    modules: list[str] = []
    for element in node.elts:
        if not isinstance(element, ast.Constant) or not isinstance(element.value, str):
            return ()
        if element.value not in _PYTHON_DOCUMENT_READER_DYNAMIC_IMPORT_MODULES:
            return ()
        modules.append(element.value)
    return tuple(modules)


def _python_call_is_document_reader_dynamic_import(
    node: ast.Call,
    *,
    importlib_aliases: set[str],
    import_module_aliases: set[str],
    module_bindings: dict[str, tuple[str, ...]],
    loop_bindings: dict[str, list[ast.For | ast.AsyncFor]],
    parent_map: dict[ast.AST, ast.AST],
) -> bool:
    if not node.args or node.keywords:
        return False
    func = node.func
    if isinstance(func, ast.Name):
        if func.id == "__import__":
            return _python_document_reader_dynamic_import_arg_is_safe(
                node.args[0],
                module_bindings,
                loop_bindings,
                parent_map,
            )
        if func.id in import_module_aliases:
            return _python_document_reader_dynamic_import_arg_is_safe(
                node.args[0],
                module_bindings,
                loop_bindings,
                parent_map,
            )
        return False
    if (
        isinstance(func, ast.Attribute)
        and func.attr == "import_module"
        and isinstance(func.value, ast.Name)
        and func.value.id in importlib_aliases
    ):
        return _python_document_reader_dynamic_import_arg_is_safe(
            node.args[0],
            module_bindings,
            loop_bindings,
            parent_map,
        )
    return False


def _python_call_is_any_dynamic_import(
    node: ast.Call,
    *,
    importlib_aliases: set[str],
    import_module_aliases: set[str],
) -> bool:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id == "__import__" or func.id in import_module_aliases
    return (
        isinstance(func, ast.Attribute)
        and func.attr == "import_module"
        and isinstance(func.value, ast.Name)
        and func.value.id in importlib_aliases
    )


def _python_document_reader_dynamic_import_arg_is_safe(
    node: ast.AST,
    module_bindings: dict[str, tuple[str, ...]],
    loop_bindings: dict[str, list[ast.For | ast.AsyncFor]],
    parent_map: dict[ast.AST, ast.AST],
) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value in _PYTHON_DOCUMENT_READER_DYNAMIC_IMPORT_MODULES
    if isinstance(node, ast.Name):
        modules = module_bindings.get(node.id, ())
        if len(modules) == 1:
            return True
        return any(
            _python_ast_node_is_inside(node, loop_node, parent_map)
            for loop_node in loop_bindings.get(node.id, [])
        )
    return False


def _python_call_is_dynamic_code_builtin(node: ast.Call) -> bool:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id in _PYTHON_DYNAMIC_CODE_CALLABLE_NAMES
    if isinstance(func, ast.Attribute):
        return func.attr in _PYTHON_DYNAMIC_CODE_CALLABLE_NAMES
    return False


def _python_ast_has_disallowed_dynamic_code_reference(
    tree: ast.AST,
    *,
    importlib_aliases: set[str],
    import_module_aliases: set[str],
    allowed_func_node_ids: set[int],
) -> bool:
    for node in ast.walk(tree):
        if id(node) in allowed_func_node_ids:
            continue
        if isinstance(node, ast.Name):
            if isinstance(node.ctx, ast.Store):
                continue
            if node.id in _PYTHON_DYNAMIC_CODE_CALLABLE_NAMES or node.id in import_module_aliases:
                return True
        elif isinstance(node, ast.Attribute):
            if isinstance(node.ctx, ast.Store):
                continue
            if node.attr in _PYTHON_DYNAMIC_CODE_CALLABLE_NAMES:
                return True
            if (
                node.attr == "import_module"
                and isinstance(node.value, ast.Name)
                and node.value.id in importlib_aliases
            ):
                return True
    return False


def _python_call_is_bool_find_spec_probe(
    node: ast.Call,
    *,
    importlib_aliases: set[str],
    find_spec_aliases: set[str],
    module_bindings: dict[str, list[str]],
    loop_bindings: set[str],
) -> bool:
    if not (
        isinstance(node.func, ast.Name)
        and node.func.id == "bool"
        and len(node.args) == 1
        and not node.keywords
        and isinstance(node.args[0], ast.Call)
    ):
        return False
    return _python_call_is_find_spec_probe(
        node.args[0],
        importlib_aliases=importlib_aliases,
        find_spec_aliases=find_spec_aliases,
        module_bindings=module_bindings,
        loop_bindings=loop_bindings,
    )


def _python_call_is_importlib_metadata_version(
    node: ast.Call,
    metadata_aliases: set[str],
    version_aliases: set[str],
) -> bool:
    if len(node.args) != 1 or node.keywords:
        return False
    arg = node.args[0]
    if not isinstance(arg, ast.Constant) or not isinstance(arg.value, str):
        return False
    if re.fullmatch(r"[A-Za-z0-9_.-]{1,120}", arg.value) is None:
        return False
    func = node.func
    if isinstance(func, ast.Name):
        return func.id in version_aliases
    if not isinstance(func, ast.Attribute) or func.attr != "version":
        return False
    parts: list[str] = []
    current: ast.AST = func.value
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    dotted = ".".join(reversed(parts))
    return dotted in metadata_aliases


def _python_has_direct_import_version_probe(text: str) -> bool:
    return bool(_python_direct_import_probe_modules(text, require_version=True))


def _python_direct_import_probe_modules(
    text: str,
    *,
    require_version: bool = False,
) -> tuple[str, ...]:
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
        "os.environ",
        "getenv(",
    )
    if any(marker in lowered for marker in risky_markers):
        return ()
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return ()

    imported_aliases: dict[str, str] = {}
    saw_print = False
    saw_version = False
    for statement in tree.body:
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                module_name = str(alias.name or "")
                top_level = module_name.split(".", 1)[0]
                if not _is_safe_python_module_probe_name(top_level):
                    return ()
                imported_aliases[alias.asname or top_level] = top_level
            continue
        if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call):
            call = statement.value
            if not _python_call_matches_name(call.func, {"print"}):
                return ()
            saw_print = True
            for arg in call.args:
                if isinstance(arg, ast.Constant):
                    continue
                if _python_expr_is_import_version_probe(arg, imported_aliases):
                    saw_version = True
                    continue
                return ()
            if call.keywords:
                return ()
            continue
        return ()
    if not imported_aliases or not saw_print:
        return ()
    if require_version and not saw_version:
        return ()
    return tuple(dict.fromkeys(imported_aliases.values()))


def _python_expr_is_import_version_probe(
    node: ast.AST,
    imported_aliases: dict[str, str],
) -> bool:
    if not isinstance(node, ast.Attribute) or node.attr != "__version__":
        return False
    if isinstance(node.value, ast.Name):
        return node.value.id in imported_aliases
    return False


def _python_raw_tokens_have_execution_env(raw_tokens: list[str]) -> bool:
    benign_python_env = {
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONFAULTHANDLER",
        "PYTHONHASHSEED",
        "PYTHONIOENCODING",
        "PYTHONNOUSERSITE",
        "PYTHONSAFEPATH",
        "PYTHONUNBUFFERED",
        "PYTHONUTF8",
        "PYTHONWARNINGS",
    }
    dangerous_exact = {
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "LD_AUDIT",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "PATH",
        "PYTHONBREAKPOINT",
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTHONPLATLIBDIR",
        "PYTHONSTARTUP",
        "PYTHONUSERBASE",
        "VIRTUAL_ENV",
    }
    for token in _python_leading_env_assignment_tokens(raw_tokens):
        name = token.split("=", 1)[0].upper()
        if name in dangerous_exact:
            return True
        if name.startswith("PYTHON") and name not in benign_python_env:
            return True
    return False


def _python_leading_env_assignment_tokens(raw_tokens: list[str]) -> list[str]:
    assignments: list[str] = []
    tokens = [str(token or "") for token in raw_tokens]
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if not token:
            index += 1
            continue
        if _is_python_interpreter_name(Path(token).name.lower()):
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


def _python_inline_code_arg(tokens: list[str]) -> str | None:
    for index, token in enumerate(tokens[:-1]):
        if token == "-c":
            return tokens[index + 1]
    return None


def _python_inline_verify_code_is_readonly(code: str) -> bool:
    text = str(code or "")
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return False
    lowered = text.lower()
    disallowed_fragments = (
        "subprocess",
        "os.system",
        "popen",
        "socket",
        "requests",
        "urllib",
        "httpx",
        "ftplib",
        "paramiko",
        ".write(",
        "write_text(",
        "write_bytes(",
        "unlink(",
        "remove(",
        "rmtree(",
        "shutil.",
        "chmod(",
        "chown(",
        "exec(",
        "eval(",
        "__import__(",
    )
    if any(fragment in lowered for fragment in disallowed_fragments):
        return False
    if "open(" in lowered and _python_ast_has_untrusted_open_call_for_verify(tree):
        return False
    if _python_source_has_disallowed_task_data_output_transform_effect(text):
        return False
    path_bindings = _python_path_variable_bindings(text)
    path_sequence_bindings = _python_path_sequence_variable_bindings(text)
    if _python_ast_has_disallowed_readonly_task_data_effect(tree, path_bindings=path_bindings):
        return False
    if _python_ast_has_unresolved_path_writer_receiver_call(
        tree,
        path_bindings,
        path_sequence_bindings,
    ):
        return False
    if _python_ast_has_invalidated_mapping_writer_method_call(tree):
        return False
    return True


def _python_inline_import_smoke_test_is_scope_safe(code: str, *, cwd: str | None) -> bool:
    try:
        tree = ast.parse(str(code or ""))
    except SyntaxError:
        return False
    sys_path_targets = _python_sys_path_task_output_targets(code, cwd=cwd)
    if not sys_path_targets or not all(
        _target_is_effective_scope_task_output(target) for target in sys_path_targets
    ):
        return False
    return all(_python_import_smoke_stmt_allowed(statement, cwd=cwd) for statement in tree.body)


def _python_import_smoke_stmt_allowed(statement: ast.stmt, *, cwd: str | None) -> bool:
    if isinstance(statement, (ast.Import, ast.ImportFrom)):
        return True
    if _python_import_smoke_sys_path_stmt_allowed(statement, cwd=cwd):
        return True
    if isinstance(statement, ast.Expr):
        return _python_import_smoke_value_allowed(statement.value)
    if isinstance(statement, ast.Try):
        if statement.orelse or statement.finalbody:
            return False
        if not statement.body or not all(
            _python_import_smoke_try_body_stmt_allowed(item, cwd=cwd) for item in statement.body
        ):
            return False
        if not statement.handlers:
            return False
        for handler in statement.handlers:
            if not handler.body or not all(
                _python_import_smoke_except_stmt_allowed(item) for item in handler.body
            ):
                return False
        return True
    return False


def _python_import_smoke_try_body_stmt_allowed(statement: ast.stmt, *, cwd: str | None) -> bool:
    if isinstance(statement, (ast.Import, ast.ImportFrom)):
        return True
    if _python_import_smoke_sys_path_stmt_allowed(statement, cwd=cwd):
        return True
    if isinstance(statement, ast.Expr):
        return _python_import_smoke_value_allowed(statement.value)
    return False


def _python_import_smoke_except_stmt_allowed(statement: ast.stmt) -> bool:
    if isinstance(statement, ast.Raise):
        return statement.exc is None and statement.cause is None
    if isinstance(statement, ast.Expr):
        return _python_import_smoke_value_allowed(statement.value)
    return False


def _python_import_smoke_sys_path_stmt_allowed(statement: ast.stmt, *, cwd: str | None) -> bool:
    if not isinstance(statement, ast.Expr):
        return False
    try:
        source = ast.unparse(statement)
    except Exception:
        return False
    targets = _python_sys_path_task_output_targets(source, cwd=cwd)
    return bool(targets) and all(_target_is_effective_scope_task_output(target) for target in targets)


def _python_import_smoke_value_allowed(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.Name):
        return True
    if isinstance(node, ast.Attribute):
        return _python_import_smoke_value_allowed(node.value)
    if isinstance(node, (ast.Tuple, ast.List)):
        return all(_python_import_smoke_value_allowed(item) for item in node.elts)
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Name):
            if func.id not in {"print", "getattr", "type", "str", "repr", "len"}:
                return False
        elif isinstance(func, ast.Attribute):
            return False
        else:
            return False
        return all(_python_import_smoke_value_allowed(arg) for arg in node.args) and all(
            keyword.arg is not None and _python_import_smoke_value_allowed(keyword.value)
            for keyword in node.keywords
        )
    return False


def _python_ast_has_untrusted_open_call_for_verify(tree: ast.AST) -> bool:
    reader_bindings = _python_document_reader_bindings(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name):
            if func.id != "open":
                continue
        elif isinstance(func, ast.Attribute):
            if func.attr != "open":
                continue
        else:
            continue
        if _python_call_is_document_reader(node, reader_bindings):
            continue
        return True
    return False


def _python_local_verify_task_output_targets(code: str, *, cwd: str | None) -> list[ActionEffectTarget]:
    cwd_target = _scope_task_output_target_for_path(".", cwd=cwd)
    sys_path_targets = _python_sys_path_task_output_targets(code, cwd=cwd)
    if sys_path_targets is None:
        return []
    targets: list[ActionEffectTarget] = []
    if cwd_target is not None:
        targets.append(cwd_target)
    targets.extend(sys_path_targets)
    return _dedupe_targets(targets)


def _python_sys_path_task_output_targets(
    code: str,
    *,
    cwd: str | None,
) -> list[ActionEffectTarget] | None:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return None
    sys_aliases = {"sys"}
    sys_path_aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "sys":
                    sys_aliases.add(alias.asname or "sys")
        elif isinstance(node, ast.ImportFrom) and node.module == "sys":
            for alias in node.names:
                if alias.name == "path":
                    sys_path_aliases.add(alias.asname or alias.name)
    string_bindings = _python_string_literal_bindings(tree)
    targets: list[ActionEffectTarget] = []
    saw_mutation = False
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in {"append", "extend", "insert"}:
            continue
        if not _python_expr_is_sys_path(node.func.value, sys_aliases, sys_path_aliases):
            continue
        saw_mutation = True
        if node.func.attr == "extend":
            if not node.args:
                return None
            paths = _python_static_string_sequence(node.args[0], string_bindings)
        else:
            arg_index = 1 if node.func.attr == "insert" else 0
            if len(node.args) <= arg_index:
                return None
            path = _python_constant_or_bound_string(node.args[arg_index], string_bindings)
            paths = [path] if path else None
        if paths is None:
            return None
        path_targets = _python_sys_path_targets_for_values(paths, cwd=cwd)
        if not path_targets:
            return None
        targets.extend(path_targets)
    for node in ast.walk(tree):
        assignment_values: list[str] | None = None
        assignment_targets: list[ast.AST] = []
        if isinstance(node, ast.Assign):
            assignment_values = _python_static_string_sequence(node.value, string_bindings)
            assignment_targets = list(node.targets)
        elif isinstance(node, ast.AnnAssign):
            assignment_values = (
                _python_static_string_sequence(node.value, string_bindings)
                if node.value is not None
                else None
            )
            assignment_targets = [node.target]
        elif isinstance(node, ast.AugAssign):
            assignment_values = _python_static_string_sequence(node.value, string_bindings)
            assignment_targets = [node.target]
        if not assignment_targets:
            continue
        if not any(_python_expr_mutates_sys_path(target, sys_aliases, sys_path_aliases) for target in assignment_targets):
            continue
        saw_mutation = True
        if assignment_values is None:
            return None
        path_targets = _python_sys_path_targets_for_values(assignment_values, cwd=cwd)
        if not path_targets:
            return None
        targets.extend(path_targets)
    if not saw_mutation:
        return []
    return _dedupe_targets(targets)


def _python_static_string_sequence(
    node: ast.AST,
    string_bindings: dict[str, str],
) -> list[str] | None:
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        values: list[str] = []
        for element in node.elts:
            value = _python_constant_or_bound_string(element, string_bindings)
            if not value:
                return None
            values.append(value)
        return values
    return None


def _python_sys_path_targets_for_values(
    values: list[str],
    *,
    cwd: str | None,
) -> list[ActionEffectTarget] | None:
    targets: list[ActionEffectTarget] = []
    for path in values:
        if not path or _URL_RE.match(str(path).strip()):
            return None
        target = _scope_task_output_target_for_path(path, cwd=cwd)
        if target is None:
            return None
        targets.append(target)
    return _dedupe_targets(targets) if targets else None


def _python_expr_mutates_sys_path(
    node: ast.AST,
    sys_aliases: set[str],
    sys_path_aliases: set[str],
) -> bool:
    if _python_expr_is_sys_path(node, sys_aliases, sys_path_aliases):
        return True
    return isinstance(node, ast.Subscript) and _python_expr_is_sys_path(node.value, sys_aliases, sys_path_aliases)


def _python_expr_is_sys_path(
    node: ast.AST,
    sys_aliases: set[str],
    sys_path_aliases: set[str],
) -> bool:
    if isinstance(node, ast.Name):
        return node.id in sys_path_aliases
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "path"
        and isinstance(node.value, ast.Name)
        and node.value.id in sys_aliases
    )


def _python_venv_target_paths(args: list[str]) -> tuple[list[str], bool, bool]:
    target_paths: list[str] = []
    upgrade_deps = False
    value_flags = {"--prompt"}
    bool_flags = {
        "--clear",
        "--copies",
        "--help",
        "--symlinks",
        "--system-site-packages",
        "--upgrade",
        "--without-pip",
        "--without-scm-ignore-files",
    }
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            target_paths.extend(args[index + 1:])
            break
        if token in value_flags and index + 1 < len(args):
            index += 2
            continue
        if token.startswith(tuple(f"{flag}=" for flag in value_flags)):
            index += 1
            continue
        if token in bool_flags:
            index += 1
            continue
        if token == "--upgrade-deps":
            upgrade_deps = True
            index += 1
            continue
        if token.startswith("-"):
            return [], False, upgrade_deps
        target_paths.append(token)
        index += 1
    return target_paths, True, upgrade_deps


def _python_venv_task_output_targets(
    target_paths: list[str],
    shell_cwd: str | None,
) -> list[ActionEffectTarget]:
    targets: list[ActionEffectTarget] = []
    for path in target_paths:
        target = _scope_task_output_target_for_path(path, cwd=shell_cwd)
        if target is None:
            return []
        targets.append(target)
    return _dedupe_targets(targets)


def _python_pip_unscoped_install_effects(args: list[str], shell_cwd: str | None) -> dict[str, Any]:
    targets = _pip_path_reference_targets(args, shell_cwd)
    if not targets:
        return _empty_shell_effects()
    effects = ["package.install"]
    if any(getattr(target, "io_direction", None) == "target" for target in targets):
        effects.append("filesystem.write")
    if any(getattr(target, "io_direction", None) == "source" for target in targets):
        effects.append("filesystem.read")
    return {
        "effects": effects,
        "targets": targets,
        "rules": ["package_install", "python_pip_path_reference"],
        "confidence": "high",
    }


def _python_explicit_interpreter_venv_root(path: str | None, *, shell_cwd: str | None) -> str | None:
    if not path:
        return None
    stripped = str(path).strip()
    if not (
        stripped.startswith(("/", "~", "."))
        or "/" in stripped
        or "\\" in stripped
    ):
        return None
    return _python_executable_venv_root(stripped, shell_cwd=shell_cwd)


def _python_version_probe_tokens(tokens: list[str]) -> bool:
    args = [token for token in tokens[1:] if token != "--"]
    return bool(args) and all(token in {"--version", "-V", "-VV", "-v"} for token in args)


def _python_module_invocation(tokens: list[str]) -> tuple[str | None, int]:
    for index, token in enumerate(tokens[:-1]):
        if token != "-m":
            continue
        return Path(tokens[index + 1]).name.lower(), index + 1
    return None, -1


def _python_py_compile_targets(args: list[str]) -> list[str]:
    targets: list[str] = []
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            targets.extend(arg for arg in args[index + 1:] if _looks_like_path_arg(arg))
            break
        if token.startswith("-"):
            index += 1
            continue
        if _looks_like_path_arg(token):
            targets.append(token)
        index += 1
    return targets


def _python_compileall_targets(args: list[str]) -> list[str] | None:
    targets: list[str] = []
    index = 0
    value_flags = {
        "-d",
        "-j",
        "-p",
        "-r",
        "-s",
        "-x",
        "--appenddir",
        "--hardlink-dupes",
        "--invalidation-mode",
        "--limit-sl-dest",
        "--prependdir",
        "--regex",
        "--stripdir",
        "--workers",
    }
    input_flags = {"-i", "--input"}
    while index < len(args):
        token = args[index]
        if token == "--":
            targets.extend(arg for arg in args[index + 1:] if _looks_like_path_arg(arg))
            break
        if token in input_flags or token.startswith("--input=") or (token.startswith("-i") and token != "-"):
            return None
        if token in value_flags and index + 1 < len(args):
            index += 2
            continue
        if token.startswith(tuple(f"{flag}=" for flag in value_flags if flag.startswith("--"))):
            index += 1
            continue
        if token in {"|", "||", "&&", ";", "&", ">", ">>", "<", "2>", "2>>"}:
            break
        if token.startswith("-"):
            index += 1
            continue
        if _looks_like_path_arg(token):
            targets.append(token)
        index += 1
    return targets


def _python_json_tool_input_targets(args: list[str]) -> list[str]:
    positionals: list[str] = []
    index = 0
    option_value_flags = {"--indent"}
    while index < len(args):
        token = args[index]
        if token == "--":
            positionals.extend(arg for arg in args[index + 1:] if arg != "/dev/null")
            break
        if token in {"|", "||", "&&", ";", "&", ">", ">>", "<", "2>", "2>>"}:
            break
        if token in option_value_flags and index + 1 < len(args):
            index += 2
            continue
        if token == "-":
            positionals.append(token)
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        if token != "/dev/null":
            positionals.append(token)
        index += 1
    if len(positionals) != 1:
        return []
    if positionals[0] == "-" or not _looks_like_path_arg(positionals[0]):
        return []
    return positionals


def _python_script_path_arg(tokens: list[str]) -> str | None:
    index = 1
    option_value_flags = {"-W", "-X"}
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            index += 1
            break
        if token in {"-c", "-m", "-"}:
            return None
        if token in option_value_flags and index + 1 < len(tokens):
            index += 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        return token
    while index < len(tokens):
        token = tokens[index]
        if token and not token.startswith("-"):
            return token
        index += 1
    return None


def _python_executable_venv_root(path: str | None, *, shell_cwd: str | None) -> str | None:
    if not path:
        return None
    resolved = _resolve_shell_target(path, shell_cwd)
    normalized = str(resolved or "").replace("\\", "/").rstrip("/")
    lowered = normalized.lower()
    for marker in ("/bin/python", "/scripts/python"):
        marker_index = lowered.rfind(marker)
        if marker_index > 0:
            return normalized[:marker_index]
    if lowered.endswith("/python") and "/bin/" in lowered:
        return posixpath.dirname(posixpath.dirname(normalized))
    return normalized


def _inline_python_source(text: str) -> str | None:
    sources = _inline_python_sources(text)
    return sources[0] if sources else None


def _inline_python_sources(text: str) -> list[str]:
    return [source for source, _argv_values in _inline_python_invocations(text)]


def _inline_python_invocations(text: str, *, depth: int = 0) -> list[tuple[str, list[str]]]:
    if depth > _MAX_SHELL_INLINE_DEPTH:
        return []
    invocations: list[tuple[str, list[str]]] = []
    raw = str(text or "")
    if "<<" in raw:
        for opener, body in _top_level_heredoc_sections(raw):
            if _heredoc_prefix_command_head(opener) in {"python", "python3"} and body:
                source = "\n".join(body)
                invocations.append((source, _python_heredoc_opener_argv_values(opener)))
        for body in _shell_executable_heredoc_bodies(raw):
            invocations.extend(_inline_python_invocations(body, depth=depth + 1))
    for tokens in _shell_segments(shell_command_surface(raw)):
        if not tokens or Path(tokens[0]).name.lower() not in {"python", "python3"}:
            continue
        for index, token in enumerate(tokens[:-1]):
            if token == "-c":
                source = tokens[index + 1]
                invocations.append((source, _python_invocation_argv_values(tokens)))
                break
    deduped: list[tuple[str, list[str]]] = []
    seen: set[tuple[str, tuple[str, ...]]] = set()
    for source, argv_values in invocations:
        if not source:
            continue
        key = (source, tuple(argv_values))
        if key in seen:
            continue
        seen.add(key)
        deduped.append((source, argv_values))
    return deduped


def _with_inline_python_argv_bindings(text: str) -> contextvars.Token[dict[int, str]]:
    return _PYTHON_ARGV_PATH_BINDINGS.set(_inline_python_argv_path_bindings(text))


def _with_python_sys_argv_aliases(source: str) -> tuple[contextvars.Token[set[str]], contextvars.Token[set[str]]]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        sys_aliases = {"sys"}
        argv_aliases = {"argv"}
    else:
        sys_aliases, argv_aliases = _python_sys_argv_aliases(tree)
    return (
        _PYTHON_SYS_MODULE_ALIASES.set(sys_aliases),
        _PYTHON_SYS_ARGV_ALIASES.set(argv_aliases),
    )


def _python_sys_argv_aliases(tree: ast.AST) -> tuple[set[str], set[str]]:
    sys_aliases = {"sys"}
    argv_aliases = {"argv"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "sys":
                    sys_aliases.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module == "sys":
            for alias in node.names:
                if alias.name == "argv":
                    argv_aliases.add(alias.asname or alias.name)
    return sys_aliases, argv_aliases


def _inline_python_argv_path_bindings(text: str) -> dict[int, str]:
    argv = _inline_python_argv_values(text)
    return _python_argv_path_bindings_from_values(argv)


def _python_argv_path_bindings_from_values(argv: list[str]) -> dict[int, str]:
    return {
        index: value
        for index, value in enumerate(argv)
        if _looks_like_path_arg(value) or _URL_RE.match(value)
    }


def _inline_python_argv_values(text: str, *, depth: int = 0) -> list[str]:
    raw = str(text or "")
    for line, _body in _top_level_heredoc_sections(raw):
        if _heredoc_prefix_command_head(line) not in {"python", "python3"}:
            continue
        values = _python_heredoc_opener_argv_values(line)
        if values:
            return values
    if depth <= _MAX_SHELL_INLINE_DEPTH:
        for body in _shell_executable_heredoc_bodies(raw):
            values = _inline_python_argv_values(body, depth=depth + 1)
            if values:
                return values
    for tokens in _shell_segments(shell_command_surface(raw)):
        if tokens and Path(tokens[0]).name.lower() in {"python", "python3"}:
            values = _python_invocation_argv_values(tokens)
            if values:
                return values
    return []


def _python_heredoc_opener_argv_values(line: str) -> list[str]:
    prefix = re.split(r"<<-?", line, maxsplit=1)[0]
    try:
        tokens = shlex.split(prefix)
    except ValueError:
        tokens = prefix.split()
    return _python_invocation_argv_values(tokens)


def _python_invocation_argv_values(tokens: list[str]) -> list[str]:
    if not tokens or Path(tokens[0]).name.lower() not in {"python", "python3"}:
        return []
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token in {"--"}:
            index += 1
            continue
        if token == "-c":
            return ["-c", *tokens[index + 2:]] if index + 1 < len(tokens) else []
        if token.startswith("-c") and token != "-c":
            return ["-c", *tokens[index + 1:]]
        if token == "-":
            return ["-", *tokens[index + 1:]]
        if token.startswith("-"):
            index += 1
            continue
        return [token, *tokens[index + 1:]]
    return []


def _python_sys_argv_subscript_index(node: ast.AST) -> int | None:
    if not isinstance(node, ast.Subscript):
        return None
    value = node.value
    sys_aliases = _PYTHON_SYS_MODULE_ALIASES.get()
    argv_aliases = _PYTHON_SYS_ARGV_ALIASES.get()
    if (
        isinstance(value, ast.Attribute)
        and value.attr == "argv"
        and isinstance(value.value, ast.Name)
        and value.value.id in sys_aliases
    ):
        pass
    elif isinstance(value, ast.Name) and value.id in argv_aliases:
        pass
    else:
        return None
    slice_node = node.slice
    if isinstance(slice_node, ast.Constant) and isinstance(slice_node.value, int):
        return slice_node.value
    return None


def _python_source_has_disallowed_readonly_task_data_effect(source: str) -> bool:
    lowered = source.lower()
    disallowed_markers = (
        "subprocess",
        "os.system",
        "popen",
        "requests.",
        "httpx.",
        "http.client",
        "urllib.",
        "socket",
        "smtplib",
        "ftplib",
        "telnetlib",
        "shutil.",
        ".write(",
        ".writelines(",
        "write_text(",
        "write_bytes(",
        "remove(",
        "unlink(",
        "rmdir(",
        "mkdir(",
        "touch(",
        "truncate(",
        "rename(",
        "chmod(",
        "chown(",
        "extract(",
        "extractall(",
    )
    if any(marker in lowered for marker in disallowed_markers):
        return True
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return True
    doc_reader_import_probe = _python_ast_has_only_document_reader_dynamic_import_probe(tree)
    if _python_ast_has_dynamic_code_call(tree) and not doc_reader_import_probe:
        return True
    if _python_ast_has_wrapper_execution_call(tree):
        return True
    if _python_ast_has_untrusted_document_reader_like_call(tree):
        return True
    path_bindings = _python_path_variable_bindings(source)
    if _python_document_reader_has_unresolved_path_arg(
        tree,
        path_bindings,
        _python_path_sequence_variable_bindings(source),
    ):
        return True
    return _python_ast_has_disallowed_readonly_task_data_effect(
        tree,
        path_bindings=path_bindings,
    )


def _python_source_has_disallowed_task_data_output_transform_effect(
    source: str,
    *,
    allowed_output_read_targets: set[str] | None = None,
) -> bool:
    lowered = source.lower()
    disallowed_markers = (
        "subprocess",
        "os.system",
        "popen",
        "requests.",
        "httpx.",
        "http.client",
        "urllib.",
        "socket",
        "smtplib",
        "ftplib",
        "telnetlib",
        "shutil.",
        "chmod(",
        "chown(",
    )
    if any(marker in lowered for marker in disallowed_markers):
        return True
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return False
    doc_reader_import_probe = _python_ast_has_only_document_reader_dynamic_import_probe(tree)
    if _python_has_import_module_call(source) and not doc_reader_import_probe:
        return True
    if _python_ast_has_dynamic_code_call(tree) and not doc_reader_import_probe:
        return True
    if _python_ast_has_wrapper_execution_call(tree):
        return True
    if _python_ast_has_untrusted_document_reader_like_call(tree):
        return True
    if _python_ast_has_network_fetch_call(tree):
        return True
    string_bindings = _python_string_literal_bindings(tree)
    open_aliases, open_module_aliases = _python_open_binding_names(tree)
    if _python_ast_has_disallowed_dynamic_path_source(
        tree,
        open_aliases,
        open_module_aliases,
        path_bindings=_python_path_variable_bindings(source),
    ):
        return True
    path_bindings = _python_path_variable_bindings(source)
    path_sequence_bindings = _python_path_sequence_variable_bindings(source)
    if _python_ast_has_unresolved_writer_method_call(
        tree,
        path_bindings,
        path_sequence_bindings,
    ):
        return True
    safe_getattr_call_ids = _python_safe_readonly_getattr_call_ids(tree, string_bindings)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _python_call_is_getattr_mutating_call(node, string_bindings, open_module_aliases):
            return True
        if _python_call_invokes_getattr_result(node):
            return True
        if _python_call_is_getattr(node) and id(node) not in safe_getattr_call_ids:
            return True
        if _python_call_uses_disallowed_dynamic_callable(node):
            return True
    return _python_document_reader_has_unresolved_path_arg(
        tree,
        path_bindings,
        path_sequence_bindings,
        allowed_output_read_targets=allowed_output_read_targets,
    )


def _python_ast_has_unresolved_writer_method_call(
    tree: ast.AST,
    scalar_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
) -> bool:
    string_bindings = _python_string_literal_bindings(tree)
    open_aliases, open_module_aliases = _python_open_binding_names(tree)
    non_file_sink_names = _python_non_file_writer_sink_names(tree)
    writer_scalar_bindings = _python_writer_path_variable_bindings(
        tree,
        scalar_bindings,
        sequence_bindings,
    )
    open_handle_bindings = _python_open_write_handle_bindings(
        tree,
        writer_scalar_bindings,
        sequence_bindings,
        string_bindings,
        open_aliases,
        open_module_aliases,
    )
    reader_bindings = _python_document_reader_bindings(tree)
    archive_write_handle_bindings = _python_archive_write_handle_bindings(
        tree,
        writer_scalar_bindings,
        sequence_bindings,
        string_bindings,
        reader_bindings,
    )
    (
        xml_etree_module_aliases,
        xml_etree_constructor_aliases,
        xml_etree_parse_aliases,
    ) = _python_xml_etree_aliases(tree)
    xml_etree_writer_receiver_names = _python_xml_etree_writer_receiver_names(tree)
    non_file_sink_node_ids = _python_immediate_lambda_non_file_arg_node_ids(
        tree,
        non_file_sink_names,
    )
    writer_method_aliases = _python_path_writer_method_aliases(tree)
    stale_writer_method_aliases = (
        _python_path_writer_method_alias_candidate_names(tree) - set(writer_method_aliases)
    )
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _python_call_is_unresolved_open_writer_method(
            node,
            writer_scalar_bindings,
            sequence_bindings,
            string_bindings,
            open_aliases,
            open_module_aliases,
            open_handle_bindings,
            archive_write_handle_bindings,
            reader_bindings,
            xml_etree_writer_receiver_names,
            xml_etree_module_aliases,
            xml_etree_constructor_aliases,
            xml_etree_parse_aliases,
            non_file_sink_names,
            non_file_sink_node_ids,
        ):
            return True
        for target_node in _python_path_writer_target_arg_nodes(
            node,
            non_file_sink_names=non_file_sink_names,
            writer_method_aliases=writer_method_aliases,
        ):
            resolved, _targets = _python_writer_arg_targets(
                target_node,
                writer_scalar_bindings,
                sequence_bindings,
            )
            if not resolved:
                return True
        for target_node in _python_save_call_target_arg_nodes(
            node,
            non_file_sink_names=non_file_sink_names,
        ):
            resolved, _targets = _python_writer_arg_targets(
                target_node,
                writer_scalar_bindings,
                sequence_bindings,
            )
            if not resolved:
                return True
        if (
            isinstance(node.func, ast.Name)
            and node.func.id in stale_writer_method_aliases
            and _python_call_has_writer_path_argument(node, non_file_sink_names)
        ):
            return True
    return False


def _python_ast_has_unresolved_path_writer_receiver_call(
    tree: ast.AST,
    scalar_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
) -> bool:
    writer_scalar_bindings = _python_writer_path_variable_bindings(
        tree,
        scalar_bindings,
        sequence_bindings,
    )
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"write_text", "write_bytes"}
        ):
            continue
        resolved, _targets = _python_writer_arg_targets(
            node.func.value,
            writer_scalar_bindings,
            sequence_bindings,
        )
        if not resolved:
            return True
    return False


def _python_call_is_unresolved_open_writer_method(
    node: ast.Call,
    scalar_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
    string_bindings: dict[str, str],
    open_aliases: set[str],
    open_module_aliases: set[str],
    open_handle_bindings: dict[str, list[str]],
    archive_write_handle_bindings: dict[str, list[str]],
    reader_bindings: dict[str, set[str]],
    xml_etree_writer_receiver_names: set[str],
    xml_etree_module_aliases: set[str],
    xml_etree_constructor_aliases: set[str],
    xml_etree_parse_aliases: set[str],
    non_file_sink_names: set[str],
    non_file_sink_node_ids: set[int],
) -> bool:
    if not isinstance(node.func, ast.Attribute):
        return False
    if node.func.attr == "writestr":
        return _python_call_is_unresolved_archive_writestr(
            node,
            scalar_bindings,
            sequence_bindings,
            string_bindings,
            reader_bindings,
            archive_write_handle_bindings,
        )
    if node.func.attr not in {"write", "writelines"}:
        return False
    receiver = node.func.value
    if _python_ast_is_non_file_writer_sink(receiver, non_file_sink_names):
        return False
    if isinstance(receiver, ast.Name) and receiver.id in open_handle_bindings:
        return False
    if _python_call_is_archive_handle_member_write(
        node,
        scalar_bindings,
        sequence_bindings,
        string_bindings,
        reader_bindings,
        archive_write_handle_bindings,
    ):
        return False
    if _python_call_is_xml_etree_non_file_write(
        node,
        xml_etree_writer_receiver_names,
        xml_etree_module_aliases,
        xml_etree_constructor_aliases,
        xml_etree_parse_aliases,
        non_file_sink_names,
        non_file_sink_node_ids,
    ):
        return False
    if _python_open_write_call_targets(
        receiver,
        scalar_bindings,
        sequence_bindings,
        string_bindings,
        open_aliases,
        open_module_aliases,
    ):
        return False
    return True


def _python_call_is_unresolved_archive_writestr(
    node: ast.Call,
    scalar_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
    string_bindings: dict[str, str],
    reader_bindings: dict[str, set[str]],
    archive_write_handle_bindings: dict[str, list[str]],
) -> bool:
    if not (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == "writestr"
    ):
        return False
    if _python_call_has_archive_write_receiver(
        node,
        scalar_bindings,
        sequence_bindings,
        string_bindings,
        reader_bindings,
        archive_write_handle_bindings,
    ):
        return False
    receiver = node.func.value
    if (
        isinstance(receiver, ast.Call)
        and _python_call_is_trusted_archive_write_open(receiver, string_bindings, reader_bindings)
    ):
        return True
    return True


def _python_call_is_archive_handle_member_write(
    node: ast.Call,
    scalar_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
    string_bindings: dict[str, str],
    reader_bindings: dict[str, set[str]],
    archive_write_handle_bindings: dict[str, list[str]],
) -> bool:
    if not isinstance(node.func, ast.Attribute) or node.func.attr != "write":
        return False
    receiver = node.func.value
    archive_targets: list[str] = []
    if isinstance(receiver, ast.Name):
        archive_targets = archive_write_handle_bindings.get(receiver.id, [])
    elif isinstance(receiver, ast.Call):
        archive_targets = _python_archive_write_call_targets(
            receiver,
            scalar_bindings,
            sequence_bindings,
            string_bindings,
            reader_bindings,
        )
    if not archive_targets:
        return False
    if not node.args:
        return False
    resolved, source_targets = _python_document_reader_arg_targets(
        node.args[0],
        scalar_bindings,
        sequence_bindings,
        set(),
        set(),
    )
    return resolved and bool(source_targets)


def _python_call_is_xml_etree_non_file_write(
    node: ast.Call,
    xml_etree_writer_receiver_names: set[str],
    xml_etree_module_aliases: set[str],
    xml_etree_constructor_aliases: set[str],
    xml_etree_parse_aliases: set[str],
    non_file_sink_names: set[str],
    non_file_sink_node_ids: set[int],
) -> bool:
    if not (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == "write"
        and node.args
    ):
        return False
    if not _python_expr_is_xml_etree_writer_receiver(
        node.func.value,
        xml_etree_writer_receiver_names,
        module_aliases=xml_etree_module_aliases,
        constructor_aliases=xml_etree_constructor_aliases,
        parse_aliases=xml_etree_parse_aliases,
    ):
        return False
    target_arg = node.args[0]
    return _python_ast_is_non_file_writer_sink(
        target_arg,
        non_file_sink_names,
    ) or id(target_arg) in non_file_sink_node_ids


def _python_call_has_writer_path_argument(
    node: ast.Call,
    non_file_sink_names: set[str],
) -> bool:
    if node.args and not _python_ast_is_non_file_writer_sink(node.args[0], non_file_sink_names):
        return True
    path_keywords = set(_PYTHON_SAVE_METHOD_PATH_KEYWORDS)
    for keywords in _PYTHON_PATH_WRITER_KEYWORDS_BY_METHOD.values():
        path_keywords.update(keywords)
    return any(
        keyword.arg in path_keywords
        and not _python_ast_is_none(keyword.value)
        and not _python_ast_is_non_file_writer_sink(keyword.value, non_file_sink_names)
        for keyword in node.keywords
    )


def _python_source_paths_are_scope_task_data_only(source: str) -> bool:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return False
    archive_member_paths_allowed = _python_ast_uses_trusted_archive_api(tree)
    saw_path = False
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        value = node.value.strip()
        if not value:
            continue
        if not _python_string_is_explicit_filesystem_path(value):
            continue
        saw_path = True
        if _python_string_is_xml_selector_path(value):
            continue
        if archive_member_paths_allowed and _python_string_is_archive_member_path(value):
            continue
        if not _is_scope_task_data_path(_glob_base_path(value)):
            return False
    return saw_path


def _python_source_has_explicit_filesystem_path(source: str) -> bool:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return False
    return any(
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and _python_string_is_explicit_filesystem_path(node.value.strip())
        for node in ast.walk(tree)
    )


def _python_source_paths_are_scope_task_data_or_output_only(source: str) -> bool:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return False
    archive_member_paths_allowed = _python_ast_uses_trusted_archive_api(tree)
    saw_path = False
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        value = node.value.strip()
        if not value:
            continue
        if not _python_string_is_explicit_filesystem_path(value):
            continue
        saw_path = True
        if _python_string_is_xml_selector_path(value):
            continue
        if archive_member_paths_allowed and _python_string_is_archive_member_path(value):
            continue
        if _is_scope_task_data_path(value):
            continue
        if _is_scope_task_output_write_target(value):
            continue
        return False
    return saw_path


def _python_string_is_explicit_filesystem_path(value: str) -> bool:
    normalized = str(value or "").strip()
    if not normalized:
        return False
    return bool(
        normalized.startswith(("/", "~", "./", "../"))
        or re.match(r"^[A-Za-z]:[\\/]", normalized)
    )


def _python_ast_uses_trusted_archive_api(tree: ast.AST) -> bool:
    bindings = _python_document_reader_bindings(tree)
    string_bindings = _python_string_literal_bindings(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _python_call_is_document_reader(node, bindings):
            return True
        if _python_call_is_trusted_archive_write_open(node, string_bindings, bindings):
            return True
    return False


def _python_string_is_archive_member_path(value: str) -> bool:
    raw = str(value or "").strip().replace("\\", "/")
    if not raw or raw.startswith(("//", "~")):
        return False
    if re.match(r"^[A-Za-z]:/", raw):
        return False
    normalized = raw.lstrip("/")
    parts = PurePosixPath(normalized).parts
    if not parts or ".." in parts:
        return False
    archive_roots = (
        "_rels",
        "customXml",
        "docProps",
        "META-INF",
        "ppt",
        "word",
        "xl",
    )
    archive_files = {
        "[Content_Types].xml",
        "content.xml",
        "manifest.rdf",
        "mimetype",
        "settings.xml",
        "styles.xml",
    }
    return parts[0] in archive_roots or normalized in archive_files


def _python_string_is_xml_selector_path(value: str) -> bool:
    normalized = str(value or "").strip()
    if normalized.startswith(".//"):
        return True
    return normalized.startswith("./") and ":" in normalized.split("/", 2)[1]


def _python_ast_has_disallowed_readonly_task_data_effect(
    tree: ast.AST,
    *,
    path_bindings: dict[str, str] | None = None,
) -> bool:
    if _python_ast_imports_blocked_readonly_module(tree):
        return True
    if _python_ast_has_wrapper_execution_call(tree):
        return True
    if _python_ast_has_untrusted_document_reader_like_call(tree):
        return True
    string_bindings = _python_string_literal_bindings(tree)
    open_aliases, open_module_aliases = _python_open_binding_names(tree)
    document_reader_bindings = _python_document_reader_bindings(tree)
    scalar_path_bindings = path_bindings or {}
    import_aliases = _python_readonly_import_aliases(tree)
    path_like_names = _python_path_like_binding_names(
        tree,
        scalar_path_bindings,
        import_aliases,
    )
    filesystem_replace_aliases = _python_filesystem_replace_callable_aliases(
        tree,
        path_like_names,
        import_aliases,
    )
    non_file_sink_names = _python_non_file_writer_sink_names(tree)
    if _python_ast_has_disallowed_dynamic_path_source(
        tree,
        open_aliases,
        open_module_aliases,
        path_bindings=scalar_path_bindings,
    ):
        return True
    safe_getattr_call_ids = _python_safe_readonly_getattr_call_ids(tree, string_bindings)
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Attribute)
            and _python_attribute_is_disallowed_bound_method(
                node,
                path_like_names=path_like_names,
                import_aliases=import_aliases,
            )
        ):
            return True
        if not isinstance(node, ast.Call):
            continue
        if _python_call_is_archive_write_open(node, string_bindings):
            return True
        if _python_call_is_compressed_open(node, document_reader_bindings):
            if _python_call_mode_writes_or_unknown(
                node,
                positional_index=1,
                string_bindings=string_bindings,
            ):
                return True
            continue
        if _python_call_is_document_reader(node, document_reader_bindings):
            continue
        if _python_call_opens_disallowed_mode(node, string_bindings, open_aliases, open_module_aliases):
            return True
        if _python_call_is_filesystem_replace_callable(node, filesystem_replace_aliases):
            return True
        if _python_call_is_mutating_method(
            node,
            path_like_names=path_like_names,
            import_aliases=import_aliases,
            non_file_sink_names=non_file_sink_names,
        ):
            return True
        if _python_call_is_getattr_mutating_call(node, string_bindings, open_module_aliases):
            return True
        if _python_call_invokes_getattr_result(node):
            return True
        if _python_call_is_getattr(node) and id(node) not in safe_getattr_call_ids:
            return True
        if _python_call_uses_disallowed_dynamic_callable(node):
            return True
    return False


def _python_ast_imports_blocked_readonly_module(tree: ast.AST) -> bool:
    blocked_roots = {
        "commands",
        "ftplib",
        "http",
        "httpx",
        "functools",
        "operator",
        "requests",
        "shutil",
        "smtplib",
        "socket",
        "subprocess",
        "telnetlib",
        "urllib",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".", 1)[0] in blocked_roots:
                    return True
        elif isinstance(node, ast.ImportFrom):
            module = str(node.module or "")
            if module.split(".", 1)[0] in blocked_roots:
                return True
    return False


def _python_ast_has_disallowed_dynamic_path_source(
    tree: ast.AST,
    open_aliases: set[str],
    open_module_aliases: set[str],
    *,
    path_bindings: dict[str, str] | None = None,
) -> bool:
    dynamic_bindings = _python_dynamic_path_binding_names(tree)
    safe_task_data_bindings = _python_task_data_walk_dynamic_path_bindings(
        tree,
        seed_bindings=path_bindings or {},
    )
    if safe_task_data_bindings:
        dynamic_bindings = dynamic_bindings - set(safe_task_data_bindings)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            if node.attr == "environ" and _python_expr_is_os_module(node.value):
                return True
            continue
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if _python_call_is_dynamic_path_constructor(node, dynamic_bindings):
            safe_join, _targets = _python_safe_task_data_join_arg_targets(
                node,
                tree,
                path_bindings or {},
            )
            if not safe_join:
                return True
        if _python_open_call_has_dynamic_path(
            node,
            open_aliases,
            open_module_aliases,
            dynamic_bindings,
        ):
            safe_join = False
            if node.args:
                safe_join, _targets = _python_safe_task_data_join_arg_targets(
                    node.args[0],
                    tree,
                    path_bindings or {},
                )
            if not safe_join:
                return True
        if not isinstance(func, ast.Attribute):
            continue
        if func.attr in {"home", "cwd"}:
            return True
        if func.attr in {"getcwd"} and _python_expr_is_os_module(func.value):
            return True
        if func.attr in {"expanduser", "expandvars", "abspath", "realpath"}:
            if _python_attr_is_os_path(func.value):
                return True
    return False


_PYTHON_PATH_CONSTRUCTOR_NAMES = frozenset({
    "Path",
    "PurePath",
    "PurePosixPath",
    "PureWindowsPath",
    "PosixPath",
    "WindowsPath",
})
_PYTHON_TRUSTED_PATHLIKE_METHOD_NAMES = frozenset({"open", "__str__", "__fspath__"})


def _python_call_is_dynamic_path_constructor(node: ast.Call, dynamic_bindings: set[str]) -> bool:
    func = node.func
    path_constructor = False
    if isinstance(func, ast.Name) and func.id in _PYTHON_PATH_CONSTRUCTOR_NAMES:
        path_constructor = True
    elif (
        isinstance(func, ast.Attribute)
        and func.attr in _PYTHON_PATH_CONSTRUCTOR_NAMES
        and isinstance(func.value, ast.Name)
        and func.value.id == "pathlib"
    ):
        path_constructor = True
    elif isinstance(func, ast.Attribute) and func.attr == "join" and _python_attr_is_os_path(func.value):
        path_constructor = True
    if not path_constructor:
        return False
    return any(_python_path_arg_is_dynamic(arg, dynamic_bindings) for arg in node.args)


def _python_call_is_static_path_constructor_value(
    node: ast.Call,
    dynamic_bindings: set[str],
) -> bool:
    if not _python_call_is_path_constructor(node) or not node.args:
        return False
    return all(not _python_path_arg_is_dynamic(arg, dynamic_bindings) for arg in node.args)


def _python_open_call_has_dynamic_path(
    node: ast.Call,
    open_aliases: set[str],
    open_module_aliases: set[str],
    dynamic_bindings: set[str],
) -> bool:
    if not node.args:
        return False
    if not _python_call_is_open_function(node, open_aliases, open_module_aliases):
        return False
    return _python_path_arg_is_dynamic(node.args[0], dynamic_bindings)


def _python_path_arg_is_dynamic(node: ast.AST, dynamic_bindings: set[str]) -> bool:
    if _python_ast_is_static_string_expr(node):
        return False
    if isinstance(node, ast.Name):
        return node.id in dynamic_bindings
    return True


def _python_dynamic_path_binding_names(tree: ast.AST) -> set[str]:
    bindings: set[str] = set()
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            if not _python_expr_is_dynamic_path_value(node.value, bindings):
                continue
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id not in bindings:
                    bindings.add(target.id)
                    changed = True
    return bindings


def _python_expr_is_dynamic_path_value(node: ast.AST, dynamic_bindings: set[str]) -> bool:
    if isinstance(node, ast.Name):
        return node.id in dynamic_bindings
    if isinstance(node, ast.Attribute):
        return (
            node.attr in {"sep", "pathsep"}
            and isinstance(node.value, ast.Name)
            and node.value.id == "os"
        )
    if isinstance(node, ast.Call):
        if _python_call_is_static_path_constructor_value(node, dynamic_bindings):
            return False
        return not _python_ast_is_static_string_expr(node)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return (
            _python_expr_is_dynamic_path_value(node.left, dynamic_bindings)
            or _python_expr_is_dynamic_path_value(node.right, dynamic_bindings)
            or not _python_ast_is_static_string_expr(node)
        )
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.Subscript):
        return True
    return False


def _python_ast_is_static_string_expr(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return True
    if isinstance(node, ast.JoinedStr):
        return False
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _python_ast_is_static_string_expr(node.left) and _python_ast_is_static_string_expr(node.right)
    return False


def _python_static_string_expr_value(
    node: ast.AST,
    string_bindings: dict[str, str] | None = None,
) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name) and string_bindings is not None:
        return string_bindings.get(node.id, "")
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _python_static_string_expr_value(node.left, string_bindings)
        right = _python_static_string_expr_value(node.right, string_bindings)
        if left and right:
            return left + right
    return ""


def _python_expr_is_os_module(node: ast.AST) -> bool:
    return isinstance(node, ast.Name) and node.id == "os"


def _python_attribute_is_disallowed_bound_method(
    node: ast.Attribute,
    *,
    path_like_names: set[str] | None = None,
    import_aliases: dict[str, set[str]] | None = None,
) -> bool:
    if node.attr.startswith("__") and node.attr.endswith("__"):
        return not _python_attribute_is_safe_type_name_lookup(node)
    if node.attr in _PYTHON_MUTATING_METHOD_NAMES - {"replace"}:
        return True
    if node.attr == "replace":
        return _python_expr_is_filesystem_path_receiver(
            node.value,
            path_like_names=path_like_names or set(),
            import_aliases=import_aliases or _empty_python_readonly_import_aliases(),
        )
    return False


def _python_attribute_is_safe_type_name_lookup(node: ast.Attribute) -> bool:
    if node.attr != "__name__":
        return False
    value = node.value
    return (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Name)
        and value.func.id == "type"
        and len(value.args) == 1
        and not value.keywords
    )


def _python_expr_is_filesystem_path_receiver(
    node: ast.AST,
    *,
    path_like_names: set[str],
    import_aliases: dict[str, set[str]],
) -> bool:
    os_aliases = import_aliases.get("os_module_aliases", {"os"})
    pathlib_aliases = import_aliases.get("pathlib_module_aliases", {"pathlib"})
    path_constructor_aliases = import_aliases.get("path_constructor_aliases", set(_PYTHON_PATH_CONSTRUCTOR_NAMES))
    if isinstance(node, ast.Name):
        return node.id in path_like_names or node.id in os_aliases or node.id in path_constructor_aliases
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Name) and func.id in path_constructor_aliases:
            return True
        if (
            isinstance(func, ast.Attribute)
            and func.attr in path_constructor_aliases
            and isinstance(func.value, ast.Name)
            and func.value.id in pathlib_aliases
        ):
            return True
        if isinstance(func, ast.Name) and func.id == "type" and node.args:
            return _python_expr_is_filesystem_path_receiver(
                node.args[0],
                path_like_names=path_like_names,
                import_aliases=import_aliases,
            )
        return False
    if isinstance(node, ast.Attribute):
        if (
            isinstance(node.value, ast.Name)
            and node.value.id in pathlib_aliases
            and node.attr in path_constructor_aliases
        ):
            return True
        return _python_expr_is_filesystem_path_receiver(
            node.value,
            path_like_names=path_like_names,
            import_aliases=import_aliases,
        )
    return False


def _python_open_binding_names(tree: ast.AST) -> tuple[set[str], set[str]]:
    aliases = {"open"}
    module_aliases = {"builtins", "io", "__builtins__"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in {"builtins", "io"}:
                    module_aliases.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module in {"builtins", "io"}:
            for alias in node.names:
                if alias.name == "open":
                    aliases.add(alias.asname or alias.name)
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            if _python_expr_is_open_function(node.value, aliases, module_aliases):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id not in aliases:
                        aliases.add(target.id)
                        changed = True
    return aliases, module_aliases


def _python_expr_is_open_function(
    node: ast.AST,
    open_aliases: set[str],
    open_module_aliases: set[str],
) -> bool:
    if isinstance(node, ast.Name) and node.id in open_aliases:
        return True
    if isinstance(node, ast.Attribute) and node.attr == "open":
        return _python_expr_is_builtins_or_io_module(node.value, open_module_aliases)
    if _python_expr_is_builtin_open_lookup(node, open_module_aliases):
        return True
    return False


def _python_expr_is_builtins_or_io_module(node: ast.AST, open_module_aliases: set[str]) -> bool:
    return isinstance(node, ast.Name) and node.id in open_module_aliases


def _python_expr_is_builtin_open_lookup(node: ast.AST, open_module_aliases: set[str]) -> bool:
    if isinstance(node, ast.Subscript):
        key = _python_static_subscript_string_key(node, {})
        return key == "open" and _python_expr_is_builtin_namespace_mapping(node.value, open_module_aliases)
    if isinstance(node, ast.Call):
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr in {"get", "__getitem__"}
            and _python_expr_is_builtin_namespace_mapping(func.value, open_module_aliases)
            and node.args
            and _python_static_string_expr_value(node.args[0], {}) == "open"
        ):
            return True
    return False


def _python_expr_is_builtin_namespace_mapping(node: ast.AST, open_module_aliases: set[str]) -> bool:
    if (
        isinstance(node, ast.Attribute)
        and node.attr == "__dict__"
        and _python_expr_is_builtins_or_io_module(node.value, open_module_aliases)
    ):
        return True
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "vars"
        and len(node.args) == 1
        and _python_expr_is_builtins_or_io_module(node.args[0], open_module_aliases)
    )


def _python_call_is_open_function(
    node: ast.Call,
    open_aliases: set[str],
    open_module_aliases: set[str],
) -> bool:
    return _python_expr_is_open_function(node.func, open_aliases, open_module_aliases)


def _python_call_opens_disallowed_mode(
    node: ast.Call,
    string_bindings: dict[str, str],
    open_aliases: set[str],
    open_module_aliases: set[str],
) -> bool:
    func = node.func
    if isinstance(func, ast.Name) and func.id in open_aliases:
        return _python_call_mode_writes_or_unknown(node, positional_index=1, string_bindings=string_bindings)
    if (
        isinstance(func, ast.Attribute)
        and func.attr == "open"
        and _python_expr_is_builtins_or_io_module(func.value, open_module_aliases)
    ):
        return _python_call_mode_writes_or_unknown(node, positional_index=1, string_bindings=string_bindings)
    if _python_expr_is_builtin_open_lookup(func, open_module_aliases):
        return _python_call_mode_writes_or_unknown(node, positional_index=1, string_bindings=string_bindings)
    if isinstance(func, ast.Attribute) and func.attr == "open":
        return _python_call_mode_writes_or_unknown(node, positional_index=0, string_bindings=string_bindings)
    return False


def _python_call_is_archive_write_open(node: ast.Call, string_bindings: dict[str, str]) -> bool:
    func = node.func
    if isinstance(func, ast.Attribute) and func.attr in {"ZipFile", "open"}:
        if isinstance(func.value, ast.Name) and func.value.id in {"zipfile", "tarfile"}:
            return _python_call_mode_writes(node, positional_index=1, string_bindings=string_bindings)
    if isinstance(func, ast.Name) and func.id in {"ZipFile"}:
        return _python_call_mode_writes(node, positional_index=1, string_bindings=string_bindings)
    return False


def _python_call_is_mutating_method(
    node: ast.Call,
    *,
    path_like_names: set[str] | None = None,
    import_aliases: dict[str, set[str]] | None = None,
    non_file_sink_names: set[str] | None = None,
) -> bool:
    func = node.func
    if not isinstance(func, ast.Attribute):
        return False
    if func.attr.startswith("__") and func.attr.endswith("__"):
        return True
    if func.attr in _PYTHON_PATH_WRITER_METHOD_NAMES:
        return bool(
            _python_path_writer_target_arg_nodes(
                node,
                non_file_sink_names=non_file_sink_names or set(),
            )
        )
    if func.attr in _PYTHON_MUTATING_METHOD_NAMES - {"replace"}:
        return True
    if func.attr == "replace":
        return _python_expr_is_filesystem_path_receiver(
            func.value,
            path_like_names=path_like_names or set(),
            import_aliases=import_aliases or _empty_python_readonly_import_aliases(),
        )
    return False


def _python_call_is_getattr_mutating_call(
    node: ast.Call,
    string_bindings: dict[str, str],
    open_module_aliases: set[str] | None = None,
) -> bool:
    if not isinstance(node.func, ast.Call):
        return False
    inner = node.func
    if not isinstance(inner.func, ast.Name) or inner.func.id != "getattr":
        return False
    if len(inner.args) < 2:
        return False
    attr = _python_constant_or_bound_string(inner.args[1], string_bindings)
    if attr in _PYTHON_MUTATING_METHOD_NAMES:
        return True
    if attr == "open":
        owner = inner.args[0]
        if _python_expr_is_builtins_or_io_module(owner, open_module_aliases or {"builtins", "io", "__builtins__"}):
            return _python_call_mode_writes(node, positional_index=1, string_bindings=string_bindings)
        return _python_call_mode_writes(node, positional_index=0, string_bindings=string_bindings)
    return False


def _python_call_invokes_getattr_result(node: ast.Call) -> bool:
    return (
        isinstance(node.func, ast.Call)
        and isinstance(node.func.func, ast.Name)
        and node.func.func.id == "getattr"
    )


def _python_call_is_getattr(node: ast.Call) -> bool:
    return isinstance(node.func, ast.Name) and node.func.id == "getattr"


_PYTHON_SAFE_READONLY_GETATTR_CONSUMERS = frozenset({
    "bool",
    "float",
    "int",
    "len",
    "print",
    "repr",
    "str",
    "type",
})

_PYTHON_UNSAFE_READONLY_GETATTR_NAMES = frozenset({
    "__import__",
    "call",
    "check_call",
    "check_output",
    "compile",
    "connect",
    "connect_ex",
    "delattr",
    "eval",
    "exec",
    "execl",
    "execle",
    "execlp",
    "execlpe",
    "execv",
    "execve",
    "execvp",
    "execvpe",
    "getoutput",
    "getstatusoutput",
    "open",
    "popen",
    "pwrite",
    "pwritev",
    "remove",
    "rename",
    "replace",
    "rmdir",
    "run",
    "send",
    "sendall",
    "sendto",
    "setattr",
    "spawnl",
    "spawnle",
    "spawnlp",
    "spawnlpe",
    "spawnv",
    "spawnve",
    "spawnvp",
    "spawnvpe",
    "system",
    "truncate",
    "unlink",
    "write",
    "write_text",
    "write_bytes",
    "writelines",
})


def _python_safe_readonly_getattr_call_ids(
    tree: ast.AST,
    string_bindings: dict[str, str],
) -> set[int]:
    parent_map = _python_ast_parent_map(tree)
    safe_ids: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not _python_call_is_safe_readonly_getattr(
            node,
            string_bindings,
            parent_map,
        ):
            continue
        safe_ids.add(id(node))
    return safe_ids


def _python_call_is_safe_readonly_getattr(
    node: ast.Call,
    string_bindings: dict[str, str],
    parent_map: dict[ast.AST, ast.AST],
) -> bool:
    if not _python_call_is_getattr(node) or len(node.args) not in {2, 3} or node.keywords:
        return False
    attr = _python_constant_or_bound_string(node.args[1], string_bindings)
    if not _python_getattr_attr_name_is_safe_readonly(attr):
        return False
    if len(node.args) == 3 and not _python_getattr_default_is_safe_readonly(node.args[2]):
        return False
    parent = parent_map.get(node)
    if not isinstance(parent, ast.Call) or parent.func is node:
        return False
    if node not in parent.args and not any(keyword.value is node for keyword in parent.keywords):
        return False
    return _python_call_func_is_safe_readonly_getattr_consumer(parent.func)


def _python_getattr_attr_name_is_safe_readonly(attr: str) -> bool:
    if not attr or attr.startswith("__") or attr.endswith("__"):
        return False
    if not re.fullmatch(r"[A-Za-z_]\w*", attr):
        return False
    lowered = attr.lower()
    if lowered in _PYTHON_UNSAFE_READONLY_GETATTR_NAMES:
        return False
    return not any(
        fragment in lowered
        for fragment in (
            "chmod",
            "chown",
            "delete",
            "exec",
            "import",
            "mkdir",
            "remove",
            "rmdir",
            "spawn",
            "subprocess",
            "system",
            "truncate",
            "unlink",
            "upload",
            "write",
        )
    )


def _python_getattr_default_is_safe_readonly(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return isinstance(node.value, (str, int, float, bool, type(None)))
    if isinstance(node, (ast.Tuple, ast.List)):
        return all(_python_getattr_default_is_safe_readonly(element) for element in node.elts)
    return False


def _python_call_func_is_safe_readonly_getattr_consumer(func: ast.AST) -> bool:
    return isinstance(func, ast.Name) and func.id in _PYTHON_SAFE_READONLY_GETATTR_CONSUMERS


def _python_ast_has_dynamic_code_call(tree: ast.AST) -> bool:
    _PYTHON_STATIC_DICT_BINDINGS.set(_python_static_dict_literal_bindings(tree))
    builtin_module_aliases = {"builtins", "__builtins__"}
    builtin_dynamic_aliases: set[str] = set()
    operator_module_aliases = {"operator"}
    operator_attrgetter_aliases: set[str] = set()
    operator_getitem_aliases: set[str] = set()
    operator_itemgetter_aliases: set[str] = set()
    operator_methodcaller_aliases: set[str] = set()
    re_module_aliases: set[str] = set()
    re_compile_aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "builtins":
                    builtin_module_aliases.add(alias.asname or alias.name)
                elif alias.name == "operator":
                    operator_module_aliases.add(alias.asname or alias.name)
                elif alias.name == "re":
                    re_module_aliases.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom):
            module = str(node.module or "")
            if module == "builtins":
                for alias in node.names:
                    if alias.name in _PYTHON_DYNAMIC_CODE_CALLABLE_NAMES:
                        builtin_dynamic_aliases.add(alias.asname or alias.name)
            elif module == "re":
                for alias in node.names:
                    if alias.name == "compile":
                        re_compile_aliases.add(alias.asname or alias.name)
            elif module == "operator":
                for alias in node.names:
                    if alias.name == "attrgetter":
                        operator_attrgetter_aliases.add(alias.asname or alias.name)
                    elif alias.name == "getitem":
                        operator_getitem_aliases.add(alias.asname or alias.name)
                    elif alias.name == "itemgetter":
                        operator_itemgetter_aliases.add(alias.asname or alias.name)
                    elif alias.name == "methodcaller":
                        operator_methodcaller_aliases.add(alias.asname or alias.name)
    re_compile_aliases |= _python_re_compile_aliases(tree, re_module_aliases, re_compile_aliases)
    operator_attrgetter_aliases = _python_operator_attrgetter_aliases(
        tree,
        operator_module_aliases=operator_module_aliases,
        initial_aliases=operator_attrgetter_aliases,
    )
    operator_getitem_aliases = _python_operator_callable_aliases(
        tree,
        callable_name="getitem",
        operator_module_aliases=operator_module_aliases,
        initial_aliases=operator_getitem_aliases,
    )
    operator_itemgetter_aliases = _python_operator_callable_aliases(
        tree,
        callable_name="itemgetter",
        operator_module_aliases=operator_module_aliases,
        initial_aliases=operator_itemgetter_aliases,
    )
    operator_methodcaller_aliases = _python_operator_callable_aliases(
        tree,
        callable_name="methodcaller",
        operator_module_aliases=operator_module_aliases,
        initial_aliases=operator_methodcaller_aliases,
    )
    benign_name_shadows = _python_dynamic_code_benign_name_shadows(
        tree,
        re_compile_aliases=re_compile_aliases,
    )
    string_bindings = _python_string_literal_bindings(tree)
    runtime_namespace_callable_aliases = _python_runtime_namespace_callable_aliases(tree)
    runtime_namespace_value_aliases = _python_runtime_namespace_value_aliases(
        tree,
        runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
    )
    runtime_namespace_get_aliases = _python_runtime_namespace_get_aliases(
        tree,
        runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
        runtime_namespace_value_aliases=runtime_namespace_value_aliases,
    )
    runtime_namespace_getitem_aliases = _python_runtime_namespace_getitem_aliases(
        tree,
        runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
        runtime_namespace_value_aliases=runtime_namespace_value_aliases,
    )
    vars_aliases = _python_vars_aliases(tree)
    getattr_aliases = _python_getattr_aliases(tree)
    builtin_namespace_aliases = _python_builtin_namespace_aliases(
        tree,
        builtin_module_aliases=builtin_module_aliases,
        string_bindings=string_bindings,
        runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
        runtime_namespace_value_aliases=runtime_namespace_value_aliases,
        runtime_namespace_get_aliases=runtime_namespace_get_aliases,
        runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
        vars_aliases=vars_aliases,
    )
    builtin_namespace_getitem_aliases = _python_builtin_namespace_getitem_aliases(
        tree,
        builtin_module_aliases=builtin_module_aliases,
        string_bindings=string_bindings,
        runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
        runtime_namespace_value_aliases=runtime_namespace_value_aliases,
        runtime_namespace_get_aliases=runtime_namespace_get_aliases,
        runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
        builtin_namespace_aliases=builtin_namespace_aliases,
        vars_aliases=vars_aliases,
        getattr_aliases=getattr_aliases,
    )
    builtin_namespace_get_aliases = _python_builtin_namespace_get_aliases(
        tree,
        builtin_module_aliases=builtin_module_aliases,
        string_bindings=string_bindings,
        runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
        runtime_namespace_value_aliases=runtime_namespace_value_aliases,
        runtime_namespace_get_aliases=runtime_namespace_get_aliases,
        runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
        builtin_namespace_aliases=builtin_namespace_aliases,
        builtin_namespace_getitem_aliases=builtin_namespace_getitem_aliases,
        vars_aliases=vars_aliases,
        getattr_aliases=getattr_aliases,
    )
    builtin_namespace_getattribute_aliases = _python_builtin_namespace_getattribute_aliases(
        tree,
        builtin_module_aliases=builtin_module_aliases,
        string_bindings=string_bindings,
        runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
        runtime_namespace_value_aliases=runtime_namespace_value_aliases,
        runtime_namespace_get_aliases=runtime_namespace_get_aliases,
        runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
        builtin_namespace_aliases=builtin_namespace_aliases,
        builtin_namespace_getitem_aliases=builtin_namespace_getitem_aliases,
        builtin_namespace_get_aliases=builtin_namespace_get_aliases,
        vars_aliases=vars_aliases,
        getattr_aliases=getattr_aliases,
    )
    if _python_ast_has_dynamic_code_callable_reference(
        tree,
        builtin_module_aliases=builtin_module_aliases,
        builtin_dynamic_aliases=builtin_dynamic_aliases,
        operator_module_aliases=operator_module_aliases,
        operator_attrgetter_aliases=operator_attrgetter_aliases,
        operator_getitem_aliases=operator_getitem_aliases,
        operator_itemgetter_aliases=operator_itemgetter_aliases,
        operator_methodcaller_aliases=operator_methodcaller_aliases,
        re_compile_aliases=re_compile_aliases,
        benign_name_shadows=benign_name_shadows,
        string_bindings=string_bindings,
        runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
        runtime_namespace_value_aliases=runtime_namespace_value_aliases,
        runtime_namespace_get_aliases=runtime_namespace_get_aliases,
        runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
        builtin_namespace_aliases=builtin_namespace_aliases,
        builtin_namespace_getitem_aliases=builtin_namespace_getitem_aliases,
        builtin_namespace_get_aliases=builtin_namespace_get_aliases,
        builtin_namespace_getattribute_aliases=builtin_namespace_getattribute_aliases,
        vars_aliases=vars_aliases,
        getattr_aliases=getattr_aliases,
    ):
        return True
    dynamic_aliases: set[str] = set()
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            value: ast.AST | None = None
            targets: list[ast.AST] = []
            name_value_pairs: list[tuple[str, ast.AST]] = []
            if isinstance(node, ast.Assign):
                value = node.value
                targets = list(node.targets)
            elif isinstance(node, ast.AnnAssign):
                value = node.value
                targets = [node.target]
            elif isinstance(node, ast.NamedExpr):
                value = node.value
                targets = [node.target]
            else:
                name_value_pairs = _python_default_arg_name_value_pairs_with_strings(node, string_bindings)
            if name_value_pairs:
                for target_name, default_value in name_value_pairs:
                    if not _python_expr_is_dynamic_code_callable(
                        default_value,
                        builtin_module_aliases=builtin_module_aliases,
                        builtin_dynamic_aliases=builtin_dynamic_aliases | dynamic_aliases,
                        operator_module_aliases=operator_module_aliases,
                        operator_attrgetter_aliases=operator_attrgetter_aliases,
                        operator_getitem_aliases=operator_getitem_aliases,
                        operator_itemgetter_aliases=operator_itemgetter_aliases,
                        operator_methodcaller_aliases=operator_methodcaller_aliases,
                        re_compile_aliases=re_compile_aliases,
                        benign_name_shadows=benign_name_shadows,
                        string_bindings=string_bindings,
                        runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
                        runtime_namespace_value_aliases=runtime_namespace_value_aliases,
                        runtime_namespace_get_aliases=runtime_namespace_get_aliases,
                        runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
                        builtin_namespace_aliases=builtin_namespace_aliases,
                        builtin_namespace_getitem_aliases=builtin_namespace_getitem_aliases,
                        builtin_namespace_get_aliases=builtin_namespace_get_aliases,
                        builtin_namespace_getattribute_aliases=builtin_namespace_getattribute_aliases,
                        vars_aliases=vars_aliases,
                        getattr_aliases=getattr_aliases,
                    ):
                        continue
                    if target_name not in dynamic_aliases:
                        dynamic_aliases.add(target_name)
                        changed = True
                continue
            if value is None or not _python_expr_is_dynamic_code_callable(
                value,
                builtin_module_aliases=builtin_module_aliases,
                builtin_dynamic_aliases=builtin_dynamic_aliases | dynamic_aliases,
                operator_module_aliases=operator_module_aliases,
                operator_attrgetter_aliases=operator_attrgetter_aliases,
                operator_getitem_aliases=operator_getitem_aliases,
                operator_itemgetter_aliases=operator_itemgetter_aliases,
                operator_methodcaller_aliases=operator_methodcaller_aliases,
                re_compile_aliases=re_compile_aliases,
                benign_name_shadows=benign_name_shadows,
                string_bindings=string_bindings,
                runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
                runtime_namespace_value_aliases=runtime_namespace_value_aliases,
                runtime_namespace_get_aliases=runtime_namespace_get_aliases,
                runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
                builtin_namespace_aliases=builtin_namespace_aliases,
                builtin_namespace_getitem_aliases=builtin_namespace_getitem_aliases,
                builtin_namespace_get_aliases=builtin_namespace_get_aliases,
                builtin_namespace_getattribute_aliases=builtin_namespace_getattribute_aliases,
                vars_aliases=vars_aliases,
                getattr_aliases=getattr_aliases,
            ):
                continue
            for target in targets:
                if isinstance(target, ast.Name) and target.id not in dynamic_aliases:
                    dynamic_aliases.add(target.id)
                    changed = True
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if _python_expr_is_dynamic_code_callable(
            func,
            builtin_module_aliases=builtin_module_aliases,
            builtin_dynamic_aliases=builtin_dynamic_aliases | dynamic_aliases,
            operator_module_aliases=operator_module_aliases,
            operator_attrgetter_aliases=operator_attrgetter_aliases,
            operator_getitem_aliases=operator_getitem_aliases,
            operator_itemgetter_aliases=operator_itemgetter_aliases,
            operator_methodcaller_aliases=operator_methodcaller_aliases,
            re_compile_aliases=re_compile_aliases,
            benign_name_shadows=benign_name_shadows,
            string_bindings=string_bindings,
            runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
            runtime_namespace_value_aliases=runtime_namespace_value_aliases,
            runtime_namespace_get_aliases=runtime_namespace_get_aliases,
            runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
            builtin_namespace_aliases=builtin_namespace_aliases,
            builtin_namespace_getitem_aliases=builtin_namespace_getitem_aliases,
            builtin_namespace_get_aliases=builtin_namespace_get_aliases,
            builtin_namespace_getattribute_aliases=builtin_namespace_getattribute_aliases,
            vars_aliases=vars_aliases,
            getattr_aliases=getattr_aliases,
        ):
            return True
    return False


def _python_re_compile_aliases(
    tree: ast.AST,
    re_module_aliases: set[str],
    initial_aliases: set[str],
) -> set[str]:
    aliases = set(initial_aliases)
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            value: ast.AST | None = None
            targets: list[ast.AST] = []
            if isinstance(node, ast.Assign):
                value = node.value
                targets = list(node.targets)
            elif isinstance(node, ast.AnnAssign):
                value = node.value
                targets = [node.target]
            elif isinstance(node, ast.NamedExpr):
                value = node.value
                targets = [node.target]
            if value is None or not _python_expr_is_re_compile_callable(
                value,
                re_module_aliases,
                aliases,
            ):
                continue
            for target in targets:
                if isinstance(target, ast.Name) and target.id not in aliases:
                    aliases.add(target.id)
                    changed = True
    return aliases


def _python_operator_attrgetter_aliases(
    tree: ast.AST,
    *,
    operator_module_aliases: set[str],
    initial_aliases: set[str],
) -> set[str]:
    aliases = set(initial_aliases)
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            for target_name, value in _python_assignment_name_value_pairs(node):
                if not _python_expr_is_operator_attrgetter_callable(
                    value,
                    operator_module_aliases=operator_module_aliases,
                    operator_attrgetter_aliases=aliases,
                ):
                    continue
                if target_name not in aliases:
                    aliases.add(target_name)
                    changed = True
    return aliases


def _python_expr_is_operator_attrgetter_callable(
    node: ast.AST,
    *,
    operator_module_aliases: set[str],
    operator_attrgetter_aliases: set[str],
) -> bool:
    if isinstance(node, ast.Name):
        return node.id in operator_attrgetter_aliases
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "attrgetter"
        and isinstance(node.value, ast.Name)
        and node.value.id in operator_module_aliases
    )


def _python_operator_callable_aliases(
    tree: ast.AST,
    *,
    callable_name: str,
    operator_module_aliases: set[str],
    initial_aliases: set[str],
) -> set[str]:
    aliases = set(initial_aliases)
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            for target_name, value in _python_assignment_name_value_pairs(node):
                if not _python_expr_is_operator_named_callable(
                    value,
                    callable_name=callable_name,
                    operator_module_aliases=operator_module_aliases,
                    operator_callable_aliases=aliases,
                ):
                    continue
                if target_name not in aliases:
                    aliases.add(target_name)
                    changed = True
    return aliases


def _python_expr_is_operator_named_callable(
    node: ast.AST,
    *,
    callable_name: str,
    operator_module_aliases: set[str],
    operator_callable_aliases: set[str],
) -> bool:
    if isinstance(node, ast.Name):
        return node.id in operator_callable_aliases
    return (
        isinstance(node, ast.Attribute)
        and node.attr == callable_name
        and isinstance(node.value, ast.Name)
        and node.value.id in operator_module_aliases
    )


def _python_expr_is_re_compile_callable(
    node: ast.AST,
    re_module_aliases: set[str],
    re_compile_aliases: set[str],
) -> bool:
    if isinstance(node, ast.Name):
        return node.id in re_compile_aliases
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "compile"
        and isinstance(node.value, ast.Name)
        and node.value.id in re_module_aliases
    )


def _python_dynamic_code_benign_name_shadows(
    tree: ast.AST,
    *,
    re_compile_aliases: set[str],
) -> set[str]:
    shadows = set(re_compile_aliases)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name in _PYTHON_DYNAMIC_CODE_CALLABLE_NAMES:
                shadows.add(node.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                bound = alias.asname or alias.name.split(".", 1)[0]
                if bound in _PYTHON_DYNAMIC_CODE_CALLABLE_NAMES and alias.name != "builtins":
                    shadows.add(bound)
        elif isinstance(node, ast.ImportFrom):
            module = str(node.module or "")
            for alias in node.names:
                bound = alias.asname or alias.name
                if bound not in _PYTHON_DYNAMIC_CODE_CALLABLE_NAMES:
                    continue
                if module == "builtins" and alias.name in _PYTHON_DYNAMIC_CODE_CALLABLE_NAMES:
                    continue
                shadows.add(bound)
        else:
            value: ast.AST | None = None
            targets: list[ast.AST] = []
            if isinstance(node, ast.Assign):
                value = node.value
                targets = list(node.targets)
            elif isinstance(node, ast.AnnAssign):
                value = node.value
                targets = [node.target]
            elif isinstance(node, ast.NamedExpr):
                value = node.value
                targets = [node.target]
            if value is None or not _python_expr_is_obvious_benign_dynamic_name_shadow(value):
                continue
            for target in targets:
                if isinstance(target, ast.Name) and target.id in _PYTHON_DYNAMIC_CODE_CALLABLE_NAMES:
                    shadows.add(target.id)
    return shadows


def _python_expr_is_obvious_benign_dynamic_name_shadow(node: ast.AST) -> bool:
    if isinstance(node, (ast.Constant, ast.Lambda)):
        return True
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return all(_python_expr_is_obvious_benign_dynamic_name_shadow(item) for item in node.elts)
    if isinstance(node, ast.Dict):
        return all(
            value is not None and _python_expr_is_obvious_benign_dynamic_name_shadow(value)
            for value in node.values
        )
    return False


def _python_assignment_value_and_targets(node: ast.AST) -> tuple[ast.AST | None, list[ast.AST]]:
    if isinstance(node, ast.Assign):
        return node.value, list(node.targets)
    if isinstance(node, ast.AnnAssign):
        return node.value, [node.target]
    if isinstance(node, ast.NamedExpr):
        return node.value, [node.target]
    return None, []


def _python_assignment_name_value_pairs(node: ast.AST) -> list[tuple[str, ast.AST]]:
    value, targets = _python_assignment_value_and_targets(node)
    if value is None:
        return []
    pairs: list[tuple[str, ast.AST]] = []
    for target in targets:
        pairs.extend(_python_target_name_value_pairs(target, value))
    return pairs


def _python_assignment_name_value_pairs_with_strings(
    node: ast.AST,
    string_bindings: dict[str, str],
) -> list[tuple[str, ast.AST]]:
    value, targets = _python_assignment_value_and_targets(node)
    if value is None:
        return []
    pairs: list[tuple[str, ast.AST]] = []
    for target in targets:
        pairs.extend(_python_target_name_value_pairs_with_strings(target, value, string_bindings))
    return pairs


def _python_default_arg_name_value_pairs(node: ast.AST) -> list[tuple[str, ast.AST]]:
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        return []
    pairs: list[tuple[str, ast.AST]] = []
    positional_args = list(node.args.posonlyargs) + list(node.args.args)
    defaults = list(node.args.defaults)
    if defaults:
        for arg, value in zip(positional_args[-len(defaults) :], defaults, strict=True):
            pairs.append((arg.arg, _python_static_sequence_element_or_self(value)))
    for arg, value in zip(node.args.kwonlyargs, node.args.kw_defaults, strict=True):
        if value is not None:
            pairs.append((arg.arg, _python_static_sequence_element_or_self(value)))
    return pairs


def _python_default_arg_name_value_pairs_with_strings(
    node: ast.AST,
    string_bindings: dict[str, str],
) -> list[tuple[str, ast.AST]]:
    pairs = _python_default_arg_name_value_pairs(node)
    if not pairs:
        return []
    return [
        (name, _python_static_container_element_or_self(value, string_bindings))
        for name, value in pairs
    ]


def _python_target_name_value_pairs(target: ast.AST, value: ast.AST) -> list[tuple[str, ast.AST]]:
    if isinstance(target, ast.Name):
        return [(target.id, _python_static_sequence_element_or_self(value))]
    if isinstance(target, (ast.Tuple, ast.List)) and isinstance(value, (ast.Tuple, ast.List)):
        if len(target.elts) != len(value.elts):
            return []
        pairs: list[tuple[str, ast.AST]] = []
        for child_target, child_value in zip(target.elts, value.elts, strict=True):
            pairs.extend(_python_target_name_value_pairs(child_target, child_value))
        return pairs
    return []


def _python_target_name_value_pairs_with_strings(
    target: ast.AST,
    value: ast.AST,
    string_bindings: dict[str, str],
) -> list[tuple[str, ast.AST]]:
    if isinstance(target, ast.Name):
        return [(target.id, _python_static_container_element_or_self(value, string_bindings))]
    if isinstance(target, (ast.Tuple, ast.List)) and isinstance(value, (ast.Tuple, ast.List)):
        if len(target.elts) != len(value.elts):
            return []
        pairs: list[tuple[str, ast.AST]] = []
        for child_target, child_value in zip(target.elts, value.elts, strict=True):
            pairs.extend(_python_target_name_value_pairs_with_strings(child_target, child_value, string_bindings))
        return pairs
    return []


def _python_static_sequence_element_or_self(node: ast.AST) -> ast.AST:
    return _python_static_container_element_or_self(node, {})


def _python_static_container_element_or_self(
    node: ast.AST,
    string_bindings: dict[str, str],
) -> ast.AST:
    if isinstance(node, ast.Subscript):
        element = _python_static_subscript_sequence_element(node)
        if element is not None:
            return element
        element = _python_static_subscript_dict_value(node, string_bindings)
        if element is not None:
            return element
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        element = _python_static_mapping_reader_value(node, string_bindings)
        if element is not None:
            return element
    return node


def _python_static_dict_literal_bindings(tree: ast.AST) -> dict[str, ast.Dict]:
    bindings: dict[str, ast.Dict] = {}
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            for target_name, value in _python_assignment_name_value_pairs(node):
                dict_value: ast.Dict | None = None
                if isinstance(value, ast.Dict):
                    dict_value = value
                elif isinstance(value, ast.Name):
                    dict_value = bindings.get(value.id)
                if dict_value is not None and bindings.get(target_name) is not dict_value:
                    bindings[target_name] = dict_value
                    changed = True
    return bindings


def _python_static_safe_dict_literal_bindings(tree: ast.AST) -> dict[str, ast.Dict]:
    bindings: dict[str, ast.Dict] = {}
    assignment_counts = _python_name_assignment_counts(tree)
    shadowed_names = _python_lexical_shadow_binding_names(tree, include_loop_targets=False)
    mutated_names = _python_mutated_dict_binding_names(tree)
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            for target_name, value in _python_assignment_name_value_pairs(node):
                if (
                    assignment_counts.get(target_name) != 1
                    or target_name in shadowed_names
                    or target_name in mutated_names
                ):
                    continue
                dict_value: ast.Dict | None = None
                if isinstance(value, ast.Dict):
                    dict_value = value
                elif isinstance(value, ast.Name) and value.id not in mutated_names:
                    dict_value = bindings.get(value.id)
                if dict_value is not None and bindings.get(target_name) is not dict_value:
                    bindings[target_name] = dict_value
                    changed = True
    return bindings


def _python_mutated_dict_binding_names(tree: ast.AST) -> set[str]:
    mutated: set[str] = set()
    literal_dict_names = _python_literal_dict_candidate_names(tree)
    if not literal_dict_names:
        return mutated
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            escaped_names = _python_literal_dict_names_in_ast(node.value, literal_dict_names)
            if escaped_names:
                mutated.update(escaped_names)
            if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                target_name = node.targets[0].id
                if isinstance(node.value, ast.Name) and (
                    target_name in literal_dict_names or node.value.id in literal_dict_names
                ):
                    mutated.add(target_name)
                    mutated.add(node.value.id)
                    continue
            for target in node.targets:
                root = _python_dict_binding_root_name(target)
                if root and not isinstance(target, ast.Name):
                    mutated.add(root)
            continue
        if isinstance(node, (ast.AugAssign, ast.AnnAssign)):
            value = getattr(node, "value", None)
            if isinstance(value, ast.AST):
                mutated.update(_python_literal_dict_names_in_ast(value, literal_dict_names))
            root = _python_dict_binding_root_name(node.target)
            if root:
                mutated.add(root)
            continue
        if isinstance(node, ast.Delete):
            for target in node.targets:
                root = _python_dict_binding_root_name(target)
                if root:
                    mutated.add(root)
            continue
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                receiver = node.func.value
                if node.func.attr in _PYTHON_DICT_CONTENT_POLLUTING_METHOD_NAMES:
                    root = _python_dict_binding_root_name(receiver)
                    if root:
                        mutated.add(root)
                if (
                    isinstance(receiver, ast.Name)
                    and receiver.id in literal_dict_names
                    and node.func.attr not in {"get", "items", "keys", "values"}
                ):
                    mutated.add(receiver.id)
            for arg in list(node.args) + [keyword.value for keyword in node.keywords]:
                mutated.update(_python_literal_dict_names_in_ast(arg, literal_dict_names))
    return mutated


def _python_ast_has_invalidated_mapping_writer_method_call(tree: ast.AST) -> bool:
    literal_dict_names = _python_literal_dict_candidate_names(tree)
    if not literal_dict_names:
        return False
    assignment_counts = _python_name_assignment_counts(tree)
    shadowed_names = _python_lexical_shadow_binding_names(tree, include_loop_targets=False)
    mutated_names = _python_mutated_dict_binding_names(tree)
    invalidated_names = {
        name
        for name in literal_dict_names
        if assignment_counts.get(name) != 1 or name in shadowed_names or name in mutated_names
    }
    if not invalidated_names:
        return False
    for node in ast.walk(tree):
        if not isinstance(node, ast.For):
            continue
        if not (
            isinstance(node.iter, ast.Call)
            and isinstance(node.iter.func, ast.Attribute)
            and node.iter.func.attr in {"items", "values"}
            and isinstance(node.iter.func.value, ast.Name)
            and node.iter.func.value.id in invalidated_names
        ):
            continue
        for child in ast.walk(node):
            if (
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Attribute)
                and child.func.attr in {"write_text", "write_bytes", "write", "writelines"}
            ):
                return True
    return False


def _python_literal_dict_candidate_names(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            continue
        if isinstance(node.value, ast.Dict):
            names.add(node.targets[0].id)
    return names


def _python_literal_dict_names_in_ast(node: ast.AST, literal_dict_names: set[str]) -> set[str]:
    names: set[str] = set()
    for item in ast.walk(node):
        if isinstance(item, ast.Name) and item.id in literal_dict_names:
            names.add(item.id)
    return names


def _python_dict_binding_root_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, (ast.Attribute, ast.Subscript)):
        return _python_dict_binding_root_name(node.value)
    return ""


def _python_runtime_namespace_callable_aliases(tree: ast.AST) -> set[str]:
    aliases: set[str] = set()
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            for target_name, value in _python_assignment_name_value_pairs(node):
                if not (
                isinstance(value, ast.Name)
                and (value.id in {"globals", "locals"} or value.id in aliases)
                ):
                    continue
                if target_name not in aliases:
                    aliases.add(target_name)
                    changed = True
    return aliases


def _python_runtime_namespace_value_aliases(
    tree: ast.AST,
    *,
    runtime_namespace_callable_aliases: set[str],
) -> set[str]:
    aliases: set[str] = set()
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            for target_name, value in _python_assignment_name_value_pairs(node):
                if not _python_expr_is_runtime_namespace(
                value,
                runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
                runtime_namespace_value_aliases=aliases,
                ):
                    continue
                if target_name not in aliases:
                    aliases.add(target_name)
                    changed = True
    return aliases


def _python_runtime_namespace_get_aliases(
    tree: ast.AST,
    *,
    runtime_namespace_callable_aliases: set[str],
    runtime_namespace_value_aliases: set[str],
) -> set[str]:
    aliases: set[str] = set()
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            for target_name, value in _python_assignment_name_value_pairs(node):
                is_get_alias = (
                isinstance(value, ast.Attribute)
                and value.attr == "get"
                and _python_expr_is_runtime_namespace(
                    value.value,
                    runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
                    runtime_namespace_value_aliases=runtime_namespace_value_aliases,
                )
                ) or (isinstance(value, ast.Name) and value.id in aliases)
                if not is_get_alias:
                    continue
                if target_name not in aliases:
                    aliases.add(target_name)
                    changed = True
    return aliases


def _python_runtime_namespace_getitem_aliases(
    tree: ast.AST,
    *,
    runtime_namespace_callable_aliases: set[str],
    runtime_namespace_value_aliases: set[str],
) -> set[str]:
    aliases: set[str] = set()
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            for target_name, value in _python_assignment_name_value_pairs(node):
                is_getitem_alias = (
                isinstance(value, ast.Attribute)
                and value.attr == "__getitem__"
                and _python_expr_is_runtime_namespace(
                    value.value,
                    runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
                    runtime_namespace_value_aliases=runtime_namespace_value_aliases,
                )
                ) or (isinstance(value, ast.Name) and value.id in aliases)
                if not is_getitem_alias:
                    continue
                if target_name not in aliases:
                    aliases.add(target_name)
                    changed = True
    return aliases


def _python_getattr_aliases(tree: ast.AST) -> set[str]:
    aliases: set[str] = set()
    builtin_module_aliases = {"builtins", "__builtins__"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "builtins":
                    builtin_module_aliases.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module == "builtins":
            for alias in node.names:
                if alias.name == "getattr":
                    aliases.add(alias.asname or alias.name)
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            for target_name, value in _python_assignment_name_value_pairs(node):
                is_alias = (
                    isinstance(value, ast.Name)
                    and (value.id == "getattr" or value.id in aliases)
                ) or (
                    isinstance(value, ast.Attribute)
                    and value.attr == "getattr"
                    and isinstance(value.value, ast.Name)
                    and value.value.id in builtin_module_aliases
                )
                if not is_alias:
                    continue
                if target_name not in aliases:
                    aliases.add(target_name)
                    changed = True
    return aliases


def _python_vars_aliases(tree: ast.AST) -> set[str]:
    aliases: set[str] = set()
    builtin_module_aliases = {"builtins", "__builtins__"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "builtins":
                    builtin_module_aliases.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module == "builtins":
            for alias in node.names:
                if alias.name == "vars":
                    aliases.add(alias.asname or alias.name)
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            for target_name, value in _python_assignment_name_value_pairs(node):
                is_alias = (
                    isinstance(value, ast.Name)
                    and (value.id == "vars" or value.id in aliases)
                ) or (
                    isinstance(value, ast.Attribute)
                    and value.attr == "vars"
                    and isinstance(value.value, ast.Name)
                    and value.value.id in builtin_module_aliases
                )
                if not is_alias:
                    continue
                if target_name not in aliases:
                    aliases.add(target_name)
                    changed = True
    return aliases


def _python_builtin_namespace_aliases(
    tree: ast.AST,
    *,
    builtin_module_aliases: set[str],
    string_bindings: dict[str, str],
    runtime_namespace_callable_aliases: set[str],
    runtime_namespace_value_aliases: set[str],
    runtime_namespace_get_aliases: set[str],
    runtime_namespace_getitem_aliases: set[str],
    vars_aliases: set[str],
) -> set[str]:
    aliases: set[str] = set()
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            for target_name, value in (
                _python_assignment_name_value_pairs_with_strings(node, string_bindings)
                + _python_default_arg_name_value_pairs_with_strings(node, string_bindings)
            ):
                if not _python_expr_is_builtin_namespace(
                value,
                builtin_module_aliases=builtin_module_aliases,
                string_bindings=string_bindings,
                runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
                runtime_namespace_value_aliases=runtime_namespace_value_aliases,
                runtime_namespace_get_aliases=runtime_namespace_get_aliases,
                runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
                builtin_namespace_aliases=aliases,
                builtin_namespace_getitem_aliases=set(),
                builtin_namespace_get_aliases=set(),
                vars_aliases=vars_aliases,
                ):
                    continue
                if target_name not in aliases:
                    aliases.add(target_name)
                    changed = True
    return aliases


def _python_builtin_namespace_getitem_aliases(
    tree: ast.AST,
    *,
    builtin_module_aliases: set[str],
    string_bindings: dict[str, str],
    runtime_namespace_callable_aliases: set[str],
    runtime_namespace_value_aliases: set[str],
    runtime_namespace_get_aliases: set[str],
    runtime_namespace_getitem_aliases: set[str],
    builtin_namespace_aliases: set[str],
    vars_aliases: set[str],
    getattr_aliases: set[str],
) -> set[str]:
    aliases: set[str] = set()
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            for target_name, value in _python_assignment_name_value_pairs(node):
                is_getitem_alias = (
                isinstance(value, ast.Attribute)
                and value.attr == "__getitem__"
                and _python_expr_is_builtin_namespace(
                    value.value,
                    builtin_module_aliases=builtin_module_aliases,
                    string_bindings=string_bindings,
                    runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
                    runtime_namespace_value_aliases=runtime_namespace_value_aliases,
                    runtime_namespace_get_aliases=runtime_namespace_get_aliases,
                    runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
                    builtin_namespace_aliases=builtin_namespace_aliases,
                    builtin_namespace_getitem_aliases=aliases,
                    builtin_namespace_get_aliases=set(),
                    vars_aliases=vars_aliases,
                )
                ) or _python_call_returns_builtin_namespace_named_attr(
                    value,
                    attr_name="__getitem__",
                    builtin_module_aliases=builtin_module_aliases,
                    string_bindings=string_bindings,
                    runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
                    runtime_namespace_value_aliases=runtime_namespace_value_aliases,
                    runtime_namespace_get_aliases=runtime_namespace_get_aliases,
                    runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
                    builtin_namespace_aliases=builtin_namespace_aliases,
                    builtin_namespace_getitem_aliases=aliases,
                    builtin_namespace_get_aliases=set(),
                    vars_aliases=vars_aliases,
                    getattr_aliases=getattr_aliases,
                ) or (isinstance(value, ast.Name) and value.id in aliases)
                if not is_getitem_alias:
                    continue
                if target_name not in aliases:
                    aliases.add(target_name)
                    changed = True
    return aliases


def _python_builtin_namespace_get_aliases(
    tree: ast.AST,
    *,
    builtin_module_aliases: set[str],
    string_bindings: dict[str, str],
    runtime_namespace_callable_aliases: set[str],
    runtime_namespace_value_aliases: set[str],
    runtime_namespace_get_aliases: set[str],
    runtime_namespace_getitem_aliases: set[str],
    builtin_namespace_aliases: set[str],
    builtin_namespace_getitem_aliases: set[str],
    vars_aliases: set[str],
    getattr_aliases: set[str],
) -> set[str]:
    aliases: set[str] = set()
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            for target_name, value in _python_assignment_name_value_pairs(node):
                is_get_alias = (
                isinstance(value, ast.Attribute)
                and value.attr == "get"
                and _python_expr_is_builtin_namespace(
                    value.value,
                    builtin_module_aliases=builtin_module_aliases,
                    string_bindings=string_bindings,
                    runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
                    runtime_namespace_value_aliases=runtime_namespace_value_aliases,
                    runtime_namespace_get_aliases=runtime_namespace_get_aliases,
                    runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
                    builtin_namespace_aliases=builtin_namespace_aliases,
                    builtin_namespace_getitem_aliases=builtin_namespace_getitem_aliases,
                    builtin_namespace_get_aliases=aliases,
                    vars_aliases=vars_aliases,
                )
                ) or _python_call_returns_builtin_namespace_named_attr(
                    value,
                    attr_name="get",
                    builtin_module_aliases=builtin_module_aliases,
                    string_bindings=string_bindings,
                    runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
                    runtime_namespace_value_aliases=runtime_namespace_value_aliases,
                    runtime_namespace_get_aliases=runtime_namespace_get_aliases,
                    runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
                    builtin_namespace_aliases=builtin_namespace_aliases,
                    builtin_namespace_getitem_aliases=builtin_namespace_getitem_aliases,
                    builtin_namespace_get_aliases=aliases,
                    vars_aliases=vars_aliases,
                    getattr_aliases=getattr_aliases,
                ) or (isinstance(value, ast.Name) and value.id in aliases)
                if not is_get_alias:
                    continue
                if target_name not in aliases:
                    aliases.add(target_name)
                    changed = True
    return aliases


def _python_builtin_namespace_getattribute_aliases(
    tree: ast.AST,
    *,
    builtin_module_aliases: set[str],
    string_bindings: dict[str, str],
    runtime_namespace_callable_aliases: set[str],
    runtime_namespace_value_aliases: set[str],
    runtime_namespace_get_aliases: set[str],
    runtime_namespace_getitem_aliases: set[str],
    builtin_namespace_aliases: set[str],
    builtin_namespace_getitem_aliases: set[str],
    builtin_namespace_get_aliases: set[str],
    vars_aliases: set[str],
    getattr_aliases: set[str],
) -> set[str]:
    aliases: set[str] = set()
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            for target_name, value in _python_assignment_name_value_pairs(node):
                is_getattribute_alias = (
                isinstance(value, ast.Attribute)
                and value.attr == "__getattribute__"
                and _python_expr_is_builtin_namespace(
                    value.value,
                    builtin_module_aliases=builtin_module_aliases,
                    string_bindings=string_bindings,
                    runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
                    runtime_namespace_value_aliases=runtime_namespace_value_aliases,
                    runtime_namespace_get_aliases=runtime_namespace_get_aliases,
                    runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
                    builtin_namespace_aliases=builtin_namespace_aliases,
                    builtin_namespace_getitem_aliases=builtin_namespace_getitem_aliases,
                    builtin_namespace_get_aliases=builtin_namespace_get_aliases,
                    vars_aliases=vars_aliases,
                )
                ) or _python_call_returns_builtin_namespace_named_attr(
                    value,
                    attr_name="__getattribute__",
                    builtin_module_aliases=builtin_module_aliases,
                    string_bindings=string_bindings,
                    runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
                    runtime_namespace_value_aliases=runtime_namespace_value_aliases,
                    runtime_namespace_get_aliases=runtime_namespace_get_aliases,
                    runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
                    builtin_namespace_aliases=builtin_namespace_aliases,
                    builtin_namespace_getitem_aliases=builtin_namespace_getitem_aliases,
                    builtin_namespace_get_aliases=builtin_namespace_get_aliases,
                    vars_aliases=vars_aliases,
                    getattr_aliases=getattr_aliases,
                ) or (isinstance(value, ast.Name) and value.id in aliases)
                if not is_getattribute_alias:
                    continue
                if target_name not in aliases:
                    aliases.add(target_name)
                    changed = True
    return aliases


def _python_call_returns_builtin_namespace_named_attr(
    node: ast.AST,
    *,
    attr_name: str,
    builtin_module_aliases: set[str],
    string_bindings: dict[str, str],
    runtime_namespace_callable_aliases: set[str],
    runtime_namespace_value_aliases: set[str],
    runtime_namespace_get_aliases: set[str],
    runtime_namespace_getitem_aliases: set[str],
    builtin_namespace_aliases: set[str],
    builtin_namespace_getitem_aliases: set[str],
    builtin_namespace_get_aliases: set[str],
    vars_aliases: set[str],
    getattr_aliases: set[str],
) -> bool:
    if not isinstance(node, ast.Call):
        return False
    owner: ast.AST | None = None
    attr = ""
    if (
        isinstance(node.func, ast.Name)
        and (node.func.id == "getattr" or node.func.id in getattr_aliases)
        and len(node.args) >= 2
    ):
        owner = node.args[0]
        attr = _python_constant_or_bound_string(node.args[1], string_bindings)
    elif _python_call_func_is_unbound_getattribute(node.func) and len(node.args) >= 2:
        owner = node.args[0]
        attr = _python_constant_or_bound_string(node.args[1], string_bindings)
    elif isinstance(node.func, ast.Attribute) and node.func.attr == "__getattribute__" and node.args:
        owner = node.func.value
        attr = _python_constant_or_bound_string(node.args[0], string_bindings)
    if attr != attr_name or owner is None:
        return False
    return _python_expr_is_builtin_namespace(
        owner,
        builtin_module_aliases=builtin_module_aliases,
        string_bindings=string_bindings,
        runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
        runtime_namespace_value_aliases=runtime_namespace_value_aliases,
        runtime_namespace_get_aliases=runtime_namespace_get_aliases,
        runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
        builtin_namespace_aliases=builtin_namespace_aliases,
        builtin_namespace_getitem_aliases=builtin_namespace_getitem_aliases,
        builtin_namespace_get_aliases=builtin_namespace_get_aliases,
        vars_aliases=vars_aliases,
    )


def _python_ast_has_dynamic_code_callable_reference(
    tree: ast.AST,
    *,
    builtin_module_aliases: set[str],
    builtin_dynamic_aliases: set[str],
    operator_module_aliases: set[str],
    operator_attrgetter_aliases: set[str],
    operator_getitem_aliases: set[str],
    operator_itemgetter_aliases: set[str],
    operator_methodcaller_aliases: set[str],
    re_compile_aliases: set[str],
    benign_name_shadows: set[str],
    string_bindings: dict[str, str],
    runtime_namespace_callable_aliases: set[str],
    runtime_namespace_value_aliases: set[str],
    runtime_namespace_get_aliases: set[str],
    runtime_namespace_getitem_aliases: set[str],
    builtin_namespace_aliases: set[str],
    builtin_namespace_getitem_aliases: set[str],
    builtin_namespace_get_aliases: set[str],
    builtin_namespace_getattribute_aliases: set[str],
    vars_aliases: set[str],
    getattr_aliases: set[str],
) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            continue
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store):
            continue
        if _python_expr_is_dynamic_code_callable(
            node,
            builtin_module_aliases=builtin_module_aliases,
            builtin_dynamic_aliases=builtin_dynamic_aliases,
            operator_module_aliases=operator_module_aliases,
            operator_attrgetter_aliases=operator_attrgetter_aliases,
            operator_getitem_aliases=operator_getitem_aliases,
            operator_itemgetter_aliases=operator_itemgetter_aliases,
            operator_methodcaller_aliases=operator_methodcaller_aliases,
            re_compile_aliases=re_compile_aliases,
            benign_name_shadows=benign_name_shadows,
            string_bindings=string_bindings,
            runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
            runtime_namespace_value_aliases=runtime_namespace_value_aliases,
            runtime_namespace_get_aliases=runtime_namespace_get_aliases,
            runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
            builtin_namespace_aliases=builtin_namespace_aliases,
            builtin_namespace_getitem_aliases=builtin_namespace_getitem_aliases,
            builtin_namespace_get_aliases=builtin_namespace_get_aliases,
            builtin_namespace_getattribute_aliases=builtin_namespace_getattribute_aliases,
            vars_aliases=vars_aliases,
            getattr_aliases=getattr_aliases,
        ):
            return True
    return False


def _python_expr_is_dynamic_code_callable(
    node: ast.AST,
    *,
    builtin_module_aliases: set[str],
    builtin_dynamic_aliases: set[str],
    operator_module_aliases: set[str],
    operator_attrgetter_aliases: set[str],
    operator_getitem_aliases: set[str],
    operator_itemgetter_aliases: set[str],
    operator_methodcaller_aliases: set[str],
    re_compile_aliases: set[str],
    benign_name_shadows: set[str],
    string_bindings: dict[str, str],
    runtime_namespace_callable_aliases: set[str],
    runtime_namespace_value_aliases: set[str],
    runtime_namespace_get_aliases: set[str],
    runtime_namespace_getitem_aliases: set[str],
    builtin_namespace_aliases: set[str],
    builtin_namespace_getitem_aliases: set[str],
    builtin_namespace_get_aliases: set[str],
    builtin_namespace_getattribute_aliases: set[str],
    vars_aliases: set[str],
    getattr_aliases: set[str],
) -> bool:
    dynamic_names = _PYTHON_DYNAMIC_CODE_CALLABLE_NAMES | builtin_dynamic_aliases
    if isinstance(node, ast.Name):
        if node.id in re_compile_aliases and node.id not in builtin_dynamic_aliases:
            return False
        if node.id in benign_name_shadows and node.id not in builtin_dynamic_aliases:
            return False
        return node.id in dynamic_names
    if (
        isinstance(node, ast.Attribute)
        and node.attr in _PYTHON_DYNAMIC_CODE_CALLABLE_NAMES
        and _python_expr_is_builtin_namespace(
            node.value,
            builtin_module_aliases=builtin_module_aliases,
            string_bindings=string_bindings,
            runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
            runtime_namespace_value_aliases=runtime_namespace_value_aliases,
            runtime_namespace_get_aliases=runtime_namespace_get_aliases,
            runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
            builtin_namespace_aliases=builtin_namespace_aliases,
            builtin_namespace_getitem_aliases=builtin_namespace_getitem_aliases,
            builtin_namespace_get_aliases=builtin_namespace_get_aliases,
            vars_aliases=vars_aliases,
            operator_module_aliases=operator_module_aliases,
            operator_attrgetter_aliases=operator_attrgetter_aliases,
            operator_getitem_aliases=operator_getitem_aliases,
            operator_itemgetter_aliases=operator_itemgetter_aliases,
            operator_methodcaller_aliases=operator_methodcaller_aliases,
            getattr_aliases=getattr_aliases,
        )
    ):
        return True
    if isinstance(node, ast.Subscript):
        value = node.value
        key = _python_static_subscript_string_key(node, string_bindings)
        if key in _PYTHON_DYNAMIC_CODE_CALLABLE_NAMES:
            if _python_expr_is_builtin_namespace(
                value,
                builtin_module_aliases=builtin_module_aliases,
                string_bindings=string_bindings,
                runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
                runtime_namespace_value_aliases=runtime_namespace_value_aliases,
                runtime_namespace_get_aliases=runtime_namespace_get_aliases,
                runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
                builtin_namespace_aliases=builtin_namespace_aliases,
                builtin_namespace_getitem_aliases=builtin_namespace_getitem_aliases,
                builtin_namespace_get_aliases=builtin_namespace_get_aliases,
                vars_aliases=vars_aliases,
                operator_module_aliases=operator_module_aliases,
                operator_attrgetter_aliases=operator_attrgetter_aliases,
                operator_getitem_aliases=operator_getitem_aliases,
                operator_itemgetter_aliases=operator_itemgetter_aliases,
                operator_methodcaller_aliases=operator_methodcaller_aliases,
                getattr_aliases=getattr_aliases,
            ):
                return True
            if (
                _python_expr_is_runtime_namespace(
                    value,
                    runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
                    runtime_namespace_value_aliases=runtime_namespace_value_aliases,
                )
                and key not in benign_name_shadows
            ):
                return True
        dynamic_element = _python_static_subscript_sequence_element(node)
        if dynamic_element is not None:
            return _python_expr_is_dynamic_code_callable(
                dynamic_element,
                builtin_module_aliases=builtin_module_aliases,
                builtin_dynamic_aliases=builtin_dynamic_aliases,
                operator_module_aliases=operator_module_aliases,
                operator_attrgetter_aliases=operator_attrgetter_aliases,
                operator_getitem_aliases=operator_getitem_aliases,
                operator_itemgetter_aliases=operator_itemgetter_aliases,
                operator_methodcaller_aliases=operator_methodcaller_aliases,
                re_compile_aliases=re_compile_aliases,
                benign_name_shadows=benign_name_shadows,
                string_bindings=string_bindings,
                runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
                runtime_namespace_value_aliases=runtime_namespace_value_aliases,
                runtime_namespace_get_aliases=runtime_namespace_get_aliases,
                runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
                builtin_namespace_aliases=builtin_namespace_aliases,
                builtin_namespace_getitem_aliases=builtin_namespace_getitem_aliases,
                builtin_namespace_get_aliases=builtin_namespace_get_aliases,
                builtin_namespace_getattribute_aliases=builtin_namespace_getattribute_aliases,
                vars_aliases=vars_aliases,
                getattr_aliases=getattr_aliases,
            )
    if isinstance(node, ast.Call):
        if _python_call_returns_dynamic_code_callable(
            node,
            builtin_module_aliases=builtin_module_aliases,
            benign_name_shadows=benign_name_shadows,
            operator_module_aliases=operator_module_aliases,
            operator_attrgetter_aliases=operator_attrgetter_aliases,
            operator_getitem_aliases=operator_getitem_aliases,
            operator_itemgetter_aliases=operator_itemgetter_aliases,
            operator_methodcaller_aliases=operator_methodcaller_aliases,
            string_bindings=string_bindings,
            runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
            runtime_namespace_value_aliases=runtime_namespace_value_aliases,
            runtime_namespace_get_aliases=runtime_namespace_get_aliases,
            runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
            builtin_namespace_aliases=builtin_namespace_aliases,
            builtin_namespace_getitem_aliases=builtin_namespace_getitem_aliases,
            builtin_namespace_get_aliases=builtin_namespace_get_aliases,
            builtin_namespace_getattribute_aliases=builtin_namespace_getattribute_aliases,
            vars_aliases=vars_aliases,
            getattr_aliases=getattr_aliases,
        ):
            return True
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return any(
            _python_expr_is_dynamic_code_callable(
                element,
                builtin_module_aliases=builtin_module_aliases,
                builtin_dynamic_aliases=builtin_dynamic_aliases,
                operator_module_aliases=operator_module_aliases,
                operator_attrgetter_aliases=operator_attrgetter_aliases,
                operator_getitem_aliases=operator_getitem_aliases,
                operator_itemgetter_aliases=operator_itemgetter_aliases,
                operator_methodcaller_aliases=operator_methodcaller_aliases,
                re_compile_aliases=re_compile_aliases,
                benign_name_shadows=benign_name_shadows,
                string_bindings=string_bindings,
                runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
                runtime_namespace_value_aliases=runtime_namespace_value_aliases,
                runtime_namespace_get_aliases=runtime_namespace_get_aliases,
                runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
                builtin_namespace_aliases=builtin_namespace_aliases,
                builtin_namespace_getitem_aliases=builtin_namespace_getitem_aliases,
                builtin_namespace_get_aliases=builtin_namespace_get_aliases,
                builtin_namespace_getattribute_aliases=builtin_namespace_getattribute_aliases,
                vars_aliases=vars_aliases,
                getattr_aliases=getattr_aliases,
            )
            for element in node.elts
        )
    if isinstance(node, ast.Dict):
        return any(
            value is not None
            and _python_expr_is_dynamic_code_callable(
                value,
                builtin_module_aliases=builtin_module_aliases,
                builtin_dynamic_aliases=builtin_dynamic_aliases,
                operator_module_aliases=operator_module_aliases,
                operator_attrgetter_aliases=operator_attrgetter_aliases,
                operator_getitem_aliases=operator_getitem_aliases,
                operator_itemgetter_aliases=operator_itemgetter_aliases,
                operator_methodcaller_aliases=operator_methodcaller_aliases,
                re_compile_aliases=re_compile_aliases,
                benign_name_shadows=benign_name_shadows,
                string_bindings=string_bindings,
                runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
                runtime_namespace_value_aliases=runtime_namespace_value_aliases,
                runtime_namespace_get_aliases=runtime_namespace_get_aliases,
                runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
                builtin_namespace_aliases=builtin_namespace_aliases,
                builtin_namespace_getitem_aliases=builtin_namespace_getitem_aliases,
                builtin_namespace_get_aliases=builtin_namespace_get_aliases,
                builtin_namespace_getattribute_aliases=builtin_namespace_getattribute_aliases,
                vars_aliases=vars_aliases,
                getattr_aliases=getattr_aliases,
            )
            for value in node.values
        )
    return False


def _python_call_returns_dynamic_code_callable(
    node: ast.Call,
    *,
    builtin_module_aliases: set[str],
    benign_name_shadows: set[str],
    operator_module_aliases: set[str],
    operator_attrgetter_aliases: set[str],
    operator_getitem_aliases: set[str],
    operator_itemgetter_aliases: set[str],
    operator_methodcaller_aliases: set[str],
    string_bindings: dict[str, str],
    runtime_namespace_callable_aliases: set[str],
    runtime_namespace_value_aliases: set[str],
    runtime_namespace_get_aliases: set[str],
    runtime_namespace_getitem_aliases: set[str],
    builtin_namespace_aliases: set[str],
    builtin_namespace_getitem_aliases: set[str],
    builtin_namespace_get_aliases: set[str],
    builtin_namespace_getattribute_aliases: set[str],
    vars_aliases: set[str],
    getattr_aliases: set[str],
) -> bool:
    func = node.func
    if (
        isinstance(func, ast.Name)
        and (func.id == "getattr" or func.id in getattr_aliases)
        and len(node.args) >= 2
    ):
        attr = _python_constant_or_bound_string(node.args[1], string_bindings)
        return (
            attr in _PYTHON_DYNAMIC_CODE_CALLABLE_NAMES
            and _python_expr_is_builtin_namespace(
                node.args[0],
                builtin_module_aliases=builtin_module_aliases,
                string_bindings=string_bindings,
                runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
                runtime_namespace_value_aliases=runtime_namespace_value_aliases,
                runtime_namespace_get_aliases=runtime_namespace_get_aliases,
                runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
                builtin_namespace_aliases=builtin_namespace_aliases,
                builtin_namespace_getitem_aliases=builtin_namespace_getitem_aliases,
                builtin_namespace_get_aliases=builtin_namespace_get_aliases,
                vars_aliases=vars_aliases,
                operator_module_aliases=operator_module_aliases,
                operator_attrgetter_aliases=operator_attrgetter_aliases,
                operator_getitem_aliases=operator_getitem_aliases,
                operator_itemgetter_aliases=operator_itemgetter_aliases,
                operator_methodcaller_aliases=operator_methodcaller_aliases,
                getattr_aliases=getattr_aliases,
            )
        )
    if _python_call_func_is_unbound_getattribute(func) and len(node.args) >= 2:
        attr = _python_constant_or_bound_string(node.args[1], string_bindings)
        return (
            attr in _PYTHON_DYNAMIC_CODE_CALLABLE_NAMES
            and _python_expr_is_builtin_namespace(
                node.args[0],
                builtin_module_aliases=builtin_module_aliases,
                string_bindings=string_bindings,
                runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
                runtime_namespace_value_aliases=runtime_namespace_value_aliases,
                runtime_namespace_get_aliases=runtime_namespace_get_aliases,
                runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
                builtin_namespace_aliases=builtin_namespace_aliases,
                builtin_namespace_getitem_aliases=builtin_namespace_getitem_aliases,
                builtin_namespace_get_aliases=builtin_namespace_get_aliases,
                vars_aliases=vars_aliases,
                operator_module_aliases=operator_module_aliases,
                operator_attrgetter_aliases=operator_attrgetter_aliases,
                operator_getitem_aliases=operator_getitem_aliases,
                operator_itemgetter_aliases=operator_itemgetter_aliases,
                operator_methodcaller_aliases=operator_methodcaller_aliases,
                getattr_aliases=getattr_aliases,
            )
        )
    if (
        isinstance(func, ast.Attribute)
        and func.attr == "__getattribute__"
        and node.args
        and _python_expr_is_builtin_namespace(
            func.value,
            builtin_module_aliases=builtin_module_aliases,
            string_bindings=string_bindings,
            runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
            runtime_namespace_value_aliases=runtime_namespace_value_aliases,
            runtime_namespace_get_aliases=runtime_namespace_get_aliases,
            runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
            builtin_namespace_aliases=builtin_namespace_aliases,
            builtin_namespace_getitem_aliases=builtin_namespace_getitem_aliases,
            builtin_namespace_get_aliases=builtin_namespace_get_aliases,
            vars_aliases=vars_aliases,
            operator_module_aliases=operator_module_aliases,
            operator_attrgetter_aliases=operator_attrgetter_aliases,
            operator_getitem_aliases=operator_getitem_aliases,
            operator_itemgetter_aliases=operator_itemgetter_aliases,
            operator_methodcaller_aliases=operator_methodcaller_aliases,
            getattr_aliases=getattr_aliases,
        )
    ):
        attr = _python_constant_or_bound_string(node.args[0], string_bindings)
        return attr in _PYTHON_DYNAMIC_CODE_CALLABLE_NAMES
    if (
        _python_expr_is_operator_named_callable(
            func,
            callable_name="getitem",
            operator_module_aliases=operator_module_aliases,
            operator_callable_aliases=operator_getitem_aliases,
        )
        and len(node.args) >= 2
    ):
        attr = _python_constant_or_bound_string(node.args[1], string_bindings)
        return (
            attr in _PYTHON_DYNAMIC_CODE_CALLABLE_NAMES
            and _python_expr_is_builtin_namespace(
                node.args[0],
                builtin_module_aliases=builtin_module_aliases,
                string_bindings=string_bindings,
                runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
                runtime_namespace_value_aliases=runtime_namespace_value_aliases,
                runtime_namespace_get_aliases=runtime_namespace_get_aliases,
                runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
                builtin_namespace_aliases=builtin_namespace_aliases,
                builtin_namespace_getitem_aliases=builtin_namespace_getitem_aliases,
                builtin_namespace_get_aliases=builtin_namespace_get_aliases,
                vars_aliases=vars_aliases,
                operator_module_aliases=operator_module_aliases,
                operator_attrgetter_aliases=operator_attrgetter_aliases,
                operator_getitem_aliases=operator_getitem_aliases,
                operator_itemgetter_aliases=operator_itemgetter_aliases,
                operator_methodcaller_aliases=operator_methodcaller_aliases,
                getattr_aliases=getattr_aliases,
            )
        )
    if (
        isinstance(func, ast.Call)
        and node.args
        and _python_expr_is_operator_attrgetter_callable(
            func.func,
            operator_module_aliases=operator_module_aliases,
            operator_attrgetter_aliases=operator_attrgetter_aliases,
        )
        and func.args
    ):
        attr = _python_constant_or_bound_string(func.args[0], string_bindings)
        return (
            attr in _PYTHON_DYNAMIC_CODE_CALLABLE_NAMES
            and _python_expr_is_builtin_namespace(
                node.args[0],
                builtin_module_aliases=builtin_module_aliases,
                string_bindings=string_bindings,
                runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
                runtime_namespace_value_aliases=runtime_namespace_value_aliases,
                runtime_namespace_get_aliases=runtime_namespace_get_aliases,
                runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
                builtin_namespace_aliases=builtin_namespace_aliases,
                builtin_namespace_getitem_aliases=builtin_namespace_getitem_aliases,
                builtin_namespace_get_aliases=builtin_namespace_get_aliases,
                vars_aliases=vars_aliases,
                operator_module_aliases=operator_module_aliases,
                operator_attrgetter_aliases=operator_attrgetter_aliases,
                operator_getitem_aliases=operator_getitem_aliases,
                operator_itemgetter_aliases=operator_itemgetter_aliases,
                operator_methodcaller_aliases=operator_methodcaller_aliases,
                getattr_aliases=getattr_aliases,
            )
        )
    if (
        isinstance(func, ast.Call)
        and node.args
        and _python_expr_is_operator_named_callable(
            func.func,
            callable_name="itemgetter",
            operator_module_aliases=operator_module_aliases,
            operator_callable_aliases=operator_itemgetter_aliases,
        )
        and func.args
    ):
        attr = _python_constant_or_bound_string(func.args[0], string_bindings)
        return (
            attr in _PYTHON_DYNAMIC_CODE_CALLABLE_NAMES
            and _python_expr_is_builtin_namespace(
                node.args[0],
                builtin_module_aliases=builtin_module_aliases,
                string_bindings=string_bindings,
                runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
                runtime_namespace_value_aliases=runtime_namespace_value_aliases,
                runtime_namespace_get_aliases=runtime_namespace_get_aliases,
                runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
                builtin_namespace_aliases=builtin_namespace_aliases,
                builtin_namespace_getitem_aliases=builtin_namespace_getitem_aliases,
                builtin_namespace_get_aliases=builtin_namespace_get_aliases,
                vars_aliases=vars_aliases,
                operator_module_aliases=operator_module_aliases,
                operator_attrgetter_aliases=operator_attrgetter_aliases,
                operator_getitem_aliases=operator_getitem_aliases,
                operator_itemgetter_aliases=operator_itemgetter_aliases,
                operator_methodcaller_aliases=operator_methodcaller_aliases,
                getattr_aliases=getattr_aliases,
            )
        )
    if (
        isinstance(func, ast.Call)
        and node.args
        and _python_expr_is_operator_named_callable(
            func.func,
            callable_name="methodcaller",
            operator_module_aliases=operator_module_aliases,
            operator_callable_aliases=operator_methodcaller_aliases,
        )
        and len(func.args) >= 2
        and _python_constant_or_bound_string(func.args[0], string_bindings)
        in {"__getattribute__", "__getitem__", "get"}
    ):
        attr = _python_constant_or_bound_string(func.args[1], string_bindings)
        return (
            attr in _PYTHON_DYNAMIC_CODE_CALLABLE_NAMES
            and _python_expr_is_builtin_namespace(
                node.args[0],
                builtin_module_aliases=builtin_module_aliases,
                string_bindings=string_bindings,
                runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
                runtime_namespace_value_aliases=runtime_namespace_value_aliases,
                runtime_namespace_get_aliases=runtime_namespace_get_aliases,
                runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
                builtin_namespace_aliases=builtin_namespace_aliases,
                builtin_namespace_getitem_aliases=builtin_namespace_getitem_aliases,
                builtin_namespace_get_aliases=builtin_namespace_get_aliases,
                vars_aliases=vars_aliases,
                operator_module_aliases=operator_module_aliases,
                operator_attrgetter_aliases=operator_attrgetter_aliases,
                operator_getitem_aliases=operator_getitem_aliases,
                operator_itemgetter_aliases=operator_itemgetter_aliases,
                operator_methodcaller_aliases=operator_methodcaller_aliases,
                getattr_aliases=getattr_aliases,
            )
        )
    if (
        isinstance(func, ast.Call)
        and node.args
        and (
            _python_call_returns_builtin_namespace_named_attr(
                func,
                attr_name="__getitem__",
                builtin_module_aliases=builtin_module_aliases,
                string_bindings=string_bindings,
                runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
                runtime_namespace_value_aliases=runtime_namespace_value_aliases,
                runtime_namespace_get_aliases=runtime_namespace_get_aliases,
                runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
                builtin_namespace_aliases=builtin_namespace_aliases,
                builtin_namespace_getitem_aliases=builtin_namespace_getitem_aliases,
                builtin_namespace_get_aliases=builtin_namespace_get_aliases,
                vars_aliases=vars_aliases,
                getattr_aliases=getattr_aliases,
            )
            or _python_call_returns_builtin_namespace_named_attr(
                func,
                attr_name="get",
                builtin_module_aliases=builtin_module_aliases,
                string_bindings=string_bindings,
                runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
                runtime_namespace_value_aliases=runtime_namespace_value_aliases,
                runtime_namespace_get_aliases=runtime_namespace_get_aliases,
                runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
                builtin_namespace_aliases=builtin_namespace_aliases,
                builtin_namespace_getitem_aliases=builtin_namespace_getitem_aliases,
                builtin_namespace_get_aliases=builtin_namespace_get_aliases,
                vars_aliases=vars_aliases,
                getattr_aliases=getattr_aliases,
            )
            or _python_call_returns_builtin_namespace_named_attr(
                func,
                attr_name="__getattribute__",
                builtin_module_aliases=builtin_module_aliases,
                string_bindings=string_bindings,
                runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
                runtime_namespace_value_aliases=runtime_namespace_value_aliases,
                runtime_namespace_get_aliases=runtime_namespace_get_aliases,
                runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
                builtin_namespace_aliases=builtin_namespace_aliases,
                builtin_namespace_getitem_aliases=builtin_namespace_getitem_aliases,
                builtin_namespace_get_aliases=builtin_namespace_get_aliases,
                vars_aliases=vars_aliases,
                getattr_aliases=getattr_aliases,
            )
        )
    ):
        attr = _python_constant_or_bound_string(node.args[0], string_bindings)
        return attr in _PYTHON_DYNAMIC_CODE_CALLABLE_NAMES
    if _python_call_func_is_unbound_mapping_getitem(func) and len(node.args) >= 2:
        attr = _python_constant_or_bound_string(node.args[1], string_bindings)
        return (
            attr in _PYTHON_DYNAMIC_CODE_CALLABLE_NAMES
            and _python_expr_is_builtin_namespace(
                node.args[0],
                builtin_module_aliases=builtin_module_aliases,
                string_bindings=string_bindings,
                runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
                runtime_namespace_value_aliases=runtime_namespace_value_aliases,
                runtime_namespace_get_aliases=runtime_namespace_get_aliases,
                runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
                builtin_namespace_aliases=builtin_namespace_aliases,
                builtin_namespace_getitem_aliases=builtin_namespace_getitem_aliases,
                builtin_namespace_get_aliases=builtin_namespace_get_aliases,
                vars_aliases=vars_aliases,
                operator_module_aliases=operator_module_aliases,
                operator_attrgetter_aliases=operator_attrgetter_aliases,
                operator_getitem_aliases=operator_getitem_aliases,
                operator_itemgetter_aliases=operator_itemgetter_aliases,
                operator_methodcaller_aliases=operator_methodcaller_aliases,
                getattr_aliases=getattr_aliases,
            )
        )
    if isinstance(func, ast.Attribute) and func.attr == "__getitem__" and node.args:
        attr = _python_constant_or_bound_string(node.args[0], string_bindings)
        return (
            attr in _PYTHON_DYNAMIC_CODE_CALLABLE_NAMES
            and _python_expr_is_builtin_namespace(
                func.value,
                builtin_module_aliases=builtin_module_aliases,
                string_bindings=string_bindings,
                runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
                runtime_namespace_value_aliases=runtime_namespace_value_aliases,
                runtime_namespace_get_aliases=runtime_namespace_get_aliases,
                runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
                builtin_namespace_aliases=builtin_namespace_aliases,
                builtin_namespace_getitem_aliases=builtin_namespace_getitem_aliases,
                builtin_namespace_get_aliases=builtin_namespace_get_aliases,
                vars_aliases=vars_aliases,
                operator_module_aliases=operator_module_aliases,
                operator_attrgetter_aliases=operator_attrgetter_aliases,
                operator_getitem_aliases=operator_getitem_aliases,
                operator_itemgetter_aliases=operator_itemgetter_aliases,
                operator_methodcaller_aliases=operator_methodcaller_aliases,
                getattr_aliases=getattr_aliases,
            )
        )
    if isinstance(func, ast.Name) and func.id in builtin_namespace_getitem_aliases and node.args:
        attr = _python_constant_or_bound_string(node.args[0], string_bindings)
        return attr in _PYTHON_DYNAMIC_CODE_CALLABLE_NAMES
    if isinstance(func, ast.Name) and func.id in builtin_namespace_get_aliases and node.args:
        attr = _python_constant_or_bound_string(node.args[0], string_bindings)
        return attr in _PYTHON_DYNAMIC_CODE_CALLABLE_NAMES
    if isinstance(func, ast.Name) and func.id in builtin_namespace_getattribute_aliases and node.args:
        attr = _python_constant_or_bound_string(node.args[0], string_bindings)
        return attr in _PYTHON_DYNAMIC_CODE_CALLABLE_NAMES
    if _python_call_func_is_unbound_mapping_get(func) and len(node.args) >= 2:
        attr = _python_constant_or_bound_string(node.args[1], string_bindings)
        return (
            attr in _PYTHON_DYNAMIC_CODE_CALLABLE_NAMES
            and _python_expr_is_builtin_namespace(
                node.args[0],
                builtin_module_aliases=builtin_module_aliases,
                string_bindings=string_bindings,
                runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
                runtime_namespace_value_aliases=runtime_namespace_value_aliases,
                runtime_namespace_get_aliases=runtime_namespace_get_aliases,
                runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
                builtin_namespace_aliases=builtin_namespace_aliases,
                builtin_namespace_getitem_aliases=builtin_namespace_getitem_aliases,
                builtin_namespace_get_aliases=builtin_namespace_get_aliases,
                vars_aliases=vars_aliases,
                operator_module_aliases=operator_module_aliases,
                operator_attrgetter_aliases=operator_attrgetter_aliases,
                operator_getitem_aliases=operator_getitem_aliases,
                operator_itemgetter_aliases=operator_itemgetter_aliases,
                operator_methodcaller_aliases=operator_methodcaller_aliases,
                getattr_aliases=getattr_aliases,
            )
        )
    if (
        isinstance(func, ast.Attribute)
        and func.attr == "get"
        and node.args
        and _python_expr_is_builtin_namespace(
            func.value,
            builtin_module_aliases=builtin_module_aliases,
            string_bindings=string_bindings,
            runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
            runtime_namespace_value_aliases=runtime_namespace_value_aliases,
            runtime_namespace_get_aliases=runtime_namespace_get_aliases,
            runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
            builtin_namespace_aliases=builtin_namespace_aliases,
            builtin_namespace_getitem_aliases=builtin_namespace_getitem_aliases,
            builtin_namespace_get_aliases=builtin_namespace_get_aliases,
            vars_aliases=vars_aliases,
            operator_module_aliases=operator_module_aliases,
            operator_attrgetter_aliases=operator_attrgetter_aliases,
            operator_getitem_aliases=operator_getitem_aliases,
            operator_itemgetter_aliases=operator_itemgetter_aliases,
            operator_methodcaller_aliases=operator_methodcaller_aliases,
            getattr_aliases=getattr_aliases,
        )
    ):
        attr = _python_constant_or_bound_string(node.args[0], string_bindings)
        return attr in _PYTHON_DYNAMIC_CODE_CALLABLE_NAMES
    if (
        isinstance(func, ast.Attribute)
        and func.attr == "get"
        and node.args
        and _python_expr_is_runtime_namespace(
            func.value,
            runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
            runtime_namespace_value_aliases=runtime_namespace_value_aliases,
        )
    ):
        attr = _python_constant_or_bound_string(node.args[0], string_bindings)
        return attr in _PYTHON_DYNAMIC_CODE_CALLABLE_NAMES and attr not in benign_name_shadows
    return False


def _python_expr_is_builtin_namespace(
    node: ast.AST,
    *,
    builtin_module_aliases: set[str],
    string_bindings: dict[str, str],
    runtime_namespace_callable_aliases: set[str],
    runtime_namespace_value_aliases: set[str],
    runtime_namespace_get_aliases: set[str],
    runtime_namespace_getitem_aliases: set[str],
    builtin_namespace_aliases: set[str],
    builtin_namespace_getitem_aliases: set[str],
    builtin_namespace_get_aliases: set[str],
    vars_aliases: set[str],
    operator_module_aliases: set[str] | None = None,
    operator_attrgetter_aliases: set[str] | None = None,
    operator_getitem_aliases: set[str] | None = None,
    operator_itemgetter_aliases: set[str] | None = None,
    operator_methodcaller_aliases: set[str] | None = None,
    getattr_aliases: set[str] | None = None,
) -> bool:
    operator_module_aliases = operator_module_aliases or {"operator"}
    operator_attrgetter_aliases = operator_attrgetter_aliases or set()
    operator_getitem_aliases = operator_getitem_aliases or set()
    operator_itemgetter_aliases = operator_itemgetter_aliases or set()
    operator_methodcaller_aliases = operator_methodcaller_aliases or set()
    getattr_aliases = getattr_aliases or set()
    if isinstance(node, ast.Name):
        return node.id in builtin_module_aliases or node.id in builtin_namespace_aliases
    if isinstance(node, ast.Attribute) and node.attr == "__dict__":
        return _python_expr_is_builtin_namespace(
            node.value,
            builtin_module_aliases=builtin_module_aliases,
            string_bindings=string_bindings,
            runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
            runtime_namespace_value_aliases=runtime_namespace_value_aliases,
            runtime_namespace_get_aliases=runtime_namespace_get_aliases,
            runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
            builtin_namespace_aliases=builtin_namespace_aliases,
            builtin_namespace_getitem_aliases=builtin_namespace_getitem_aliases,
            builtin_namespace_get_aliases=builtin_namespace_get_aliases,
            vars_aliases=vars_aliases,
        )
    if _python_call_returns_builtin_namespace_named_attr(
        node,
        attr_name="__dict__",
        builtin_module_aliases=builtin_module_aliases,
        string_bindings=string_bindings,
        runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
        runtime_namespace_value_aliases=runtime_namespace_value_aliases,
        runtime_namespace_get_aliases=runtime_namespace_get_aliases,
        runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
        builtin_namespace_aliases=builtin_namespace_aliases,
        builtin_namespace_getitem_aliases=builtin_namespace_getitem_aliases,
        builtin_namespace_get_aliases=builtin_namespace_get_aliases,
        vars_aliases=vars_aliases,
        getattr_aliases=getattr_aliases,
    ):
        return True
    if (
        isinstance(node, ast.Call)
        and node.args
        and _python_expr_is_operator_attrgetter_callable(
            node.func.func if isinstance(node.func, ast.Call) else ast.Constant(value=None),
            operator_module_aliases=operator_module_aliases,
            operator_attrgetter_aliases=operator_attrgetter_aliases,
        )
        and isinstance(node.func, ast.Call)
        and node.func.args
        and _python_constant_or_bound_string(node.func.args[0], string_bindings) == "__dict__"
        and _python_expr_is_builtin_namespace(
            node.args[0],
            builtin_module_aliases=builtin_module_aliases,
            string_bindings=string_bindings,
            runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
            runtime_namespace_value_aliases=runtime_namespace_value_aliases,
            runtime_namespace_get_aliases=runtime_namespace_get_aliases,
            runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
            builtin_namespace_aliases=builtin_namespace_aliases,
            builtin_namespace_getitem_aliases=builtin_namespace_getitem_aliases,
            builtin_namespace_get_aliases=builtin_namespace_get_aliases,
            vars_aliases=vars_aliases,
            operator_module_aliases=operator_module_aliases,
            operator_attrgetter_aliases=operator_attrgetter_aliases,
            operator_getitem_aliases=operator_getitem_aliases,
            operator_itemgetter_aliases=operator_itemgetter_aliases,
            operator_methodcaller_aliases=operator_methodcaller_aliases,
            getattr_aliases=getattr_aliases,
        )
    ):
        return True
    if (
        isinstance(node, ast.Call)
        and node.args
        and isinstance(node.func, ast.Call)
        and _python_expr_is_operator_named_callable(
            node.func.func,
            callable_name="methodcaller",
            operator_module_aliases=operator_module_aliases,
            operator_callable_aliases=operator_methodcaller_aliases,
        )
        and len(node.func.args) >= 2
        and _python_constant_or_bound_string(node.func.args[0], string_bindings) == "__getattribute__"
        and _python_constant_or_bound_string(node.func.args[1], string_bindings) == "__dict__"
        and _python_expr_is_builtin_namespace(
            node.args[0],
            builtin_module_aliases=builtin_module_aliases,
            string_bindings=string_bindings,
            runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
            runtime_namespace_value_aliases=runtime_namespace_value_aliases,
            runtime_namespace_get_aliases=runtime_namespace_get_aliases,
            runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
            builtin_namespace_aliases=builtin_namespace_aliases,
            builtin_namespace_getitem_aliases=builtin_namespace_getitem_aliases,
            builtin_namespace_get_aliases=builtin_namespace_get_aliases,
            vars_aliases=vars_aliases,
            operator_module_aliases=operator_module_aliases,
            operator_attrgetter_aliases=operator_attrgetter_aliases,
            operator_getitem_aliases=operator_getitem_aliases,
            operator_itemgetter_aliases=operator_itemgetter_aliases,
            operator_methodcaller_aliases=operator_methodcaller_aliases,
            getattr_aliases=getattr_aliases,
        )
    ):
        return True
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and node.args
        and _python_expr_is_runtime_namespace(
            node.func.value,
            runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
            runtime_namespace_value_aliases=runtime_namespace_value_aliases,
        )
        and _python_constant_or_bound_string(node.args[0], string_bindings) == "__builtins__"
    ):
        return True
    if (
        isinstance(node, ast.Call)
        and len(node.args) >= 2
        and _python_expr_is_operator_named_callable(
            node.func,
            callable_name="getitem",
            operator_module_aliases=operator_module_aliases,
            operator_callable_aliases=operator_getitem_aliases,
        )
        and _python_expr_is_runtime_namespace(
            node.args[0],
            runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
            runtime_namespace_value_aliases=runtime_namespace_value_aliases,
        )
        and _python_constant_or_bound_string(node.args[1], string_bindings) == "__builtins__"
    ):
        return True
    if (
        isinstance(node, ast.Call)
        and len(node.args) >= 2
        and (
            (isinstance(node.func, ast.Attribute) and node.func.attr == "get")
            or (isinstance(node.func, ast.Name) and node.func.id in runtime_namespace_get_aliases)
        )
        and _python_expr_is_builtin_namespace(
            node.args[1],
            builtin_module_aliases=builtin_module_aliases,
            string_bindings=string_bindings,
            runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
            runtime_namespace_value_aliases=runtime_namespace_value_aliases,
            runtime_namespace_get_aliases=runtime_namespace_get_aliases,
            runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
            builtin_namespace_aliases=builtin_namespace_aliases,
            builtin_namespace_getitem_aliases=builtin_namespace_getitem_aliases,
            builtin_namespace_get_aliases=builtin_namespace_get_aliases,
            vars_aliases=vars_aliases,
        )
    ):
        return True
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "__getitem__"
        and node.args
        and _python_expr_is_runtime_namespace(
            node.func.value,
            runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
            runtime_namespace_value_aliases=runtime_namespace_value_aliases,
        )
        and _python_constant_or_bound_string(node.args[0], string_bindings) == "__builtins__"
    ):
        return True
    if (
        isinstance(node, ast.Call)
        and len(node.args) >= 2
        and _python_call_func_is_unbound_mapping_getitem(node.func)
        and _python_expr_is_runtime_namespace(
            node.args[0],
            runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
            runtime_namespace_value_aliases=runtime_namespace_value_aliases,
        )
        and _python_constant_or_bound_string(node.args[1], string_bindings) == "__builtins__"
    ):
        return True
    if (
        isinstance(node, ast.Call)
        and len(node.args) >= 2
        and _python_call_func_is_unbound_mapping_get(node.func)
        and _python_expr_is_runtime_namespace(
            node.args[0],
            runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
            runtime_namespace_value_aliases=runtime_namespace_value_aliases,
        )
        and _python_constant_or_bound_string(node.args[1], string_bindings) == "__builtins__"
    ):
        return True
    if (
        isinstance(node, ast.Call)
        and len(node.args) >= 3
        and _python_call_func_is_unbound_mapping_get(node.func)
        and _python_expr_is_builtin_namespace(
            node.args[2],
            builtin_module_aliases=builtin_module_aliases,
            string_bindings=string_bindings,
            runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
            runtime_namespace_value_aliases=runtime_namespace_value_aliases,
            runtime_namespace_get_aliases=runtime_namespace_get_aliases,
            runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
            builtin_namespace_aliases=builtin_namespace_aliases,
            builtin_namespace_getitem_aliases=builtin_namespace_getitem_aliases,
            builtin_namespace_get_aliases=builtin_namespace_get_aliases,
            vars_aliases=vars_aliases,
        )
    ):
        return True
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in runtime_namespace_getitem_aliases
        and node.args
        and _python_constant_or_bound_string(node.args[0], string_bindings) == "__builtins__"
    ):
        return True
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in runtime_namespace_get_aliases
        and node.args
        and _python_constant_or_bound_string(node.args[0], string_bindings) == "__builtins__"
    ):
        return True
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and (node.func.id == "vars" or node.func.id in vars_aliases)
        and node.args
    ):
        return _python_expr_is_builtin_namespace(
            node.args[0],
            builtin_module_aliases=builtin_module_aliases,
            string_bindings=string_bindings,
            runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
            runtime_namespace_value_aliases=runtime_namespace_value_aliases,
            runtime_namespace_get_aliases=runtime_namespace_get_aliases,
            runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
            builtin_namespace_aliases=builtin_namespace_aliases,
            builtin_namespace_getitem_aliases=builtin_namespace_getitem_aliases,
            builtin_namespace_get_aliases=builtin_namespace_get_aliases,
            vars_aliases=vars_aliases,
        )
    if isinstance(node, ast.Subscript):
        element = _python_static_subscript_sequence_element(node)
        if element is None:
            element = _python_static_subscript_dict_value(node, string_bindings)
        if element is not None:
            return _python_expr_is_builtin_namespace(
                element,
                builtin_module_aliases=builtin_module_aliases,
                string_bindings=string_bindings,
                runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
                runtime_namespace_value_aliases=runtime_namespace_value_aliases,
                runtime_namespace_get_aliases=runtime_namespace_get_aliases,
                runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
                builtin_namespace_aliases=builtin_namespace_aliases,
                builtin_namespace_getitem_aliases=builtin_namespace_getitem_aliases,
                builtin_namespace_get_aliases=builtin_namespace_get_aliases,
                vars_aliases=vars_aliases,
                operator_module_aliases=operator_module_aliases,
                operator_attrgetter_aliases=operator_attrgetter_aliases,
                operator_getitem_aliases=operator_getitem_aliases,
                operator_itemgetter_aliases=operator_itemgetter_aliases,
                operator_methodcaller_aliases=operator_methodcaller_aliases,
                getattr_aliases=getattr_aliases,
            )
        key = _python_static_subscript_string_key(node, string_bindings)
        return key == "__builtins__" and _python_expr_is_runtime_namespace(
            node.value,
            runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
            runtime_namespace_value_aliases=runtime_namespace_value_aliases,
        )
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        element = _python_static_mapping_reader_value(node, string_bindings)
        if element is not None:
            return _python_expr_is_builtin_namespace(
                element,
                builtin_module_aliases=builtin_module_aliases,
                string_bindings=string_bindings,
                runtime_namespace_callable_aliases=runtime_namespace_callable_aliases,
                runtime_namespace_value_aliases=runtime_namespace_value_aliases,
                runtime_namespace_get_aliases=runtime_namespace_get_aliases,
                runtime_namespace_getitem_aliases=runtime_namespace_getitem_aliases,
                builtin_namespace_aliases=builtin_namespace_aliases,
                builtin_namespace_getitem_aliases=builtin_namespace_getitem_aliases,
                builtin_namespace_get_aliases=builtin_namespace_get_aliases,
                vars_aliases=vars_aliases,
                operator_module_aliases=operator_module_aliases,
                operator_attrgetter_aliases=operator_attrgetter_aliases,
                operator_getitem_aliases=operator_getitem_aliases,
                operator_itemgetter_aliases=operator_itemgetter_aliases,
                operator_methodcaller_aliases=operator_methodcaller_aliases,
                getattr_aliases=getattr_aliases,
            )
    return False


def _python_call_func_is_unbound_mapping_getitem(func: ast.AST) -> bool:
    return (
        isinstance(func, ast.Attribute)
        and (
            (func.attr == "__getitem__" and isinstance(func.value, ast.Name))
            or (func.attr == "getitem" and isinstance(func.value, ast.Name) and func.value.id == "operator")
        )
    )


def _python_call_func_is_unbound_mapping_get(func: ast.AST) -> bool:
    return (
        isinstance(func, ast.Attribute)
        and func.attr == "get"
        and isinstance(func.value, ast.Name)
    )


def _python_call_func_is_unbound_getattribute(func: ast.AST) -> bool:
    if not (isinstance(func, ast.Attribute) and func.attr == "__getattribute__"):
        return False
    if isinstance(func.value, ast.Name):
        return func.value.id == "object"
    return isinstance(func.value, ast.Call) and isinstance(func.value.func, ast.Name) and func.value.func.id == "type"


def _python_expr_is_runtime_namespace(
    node: ast.AST,
    *,
    runtime_namespace_callable_aliases: set[str],
    runtime_namespace_value_aliases: set[str],
) -> bool:
    if isinstance(node, ast.Name):
        return node.id in runtime_namespace_value_aliases
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and (node.func.id in {"globals", "locals"} or node.func.id in runtime_namespace_callable_aliases)
    )


def _python_static_subscript_string_key(
    node: ast.Subscript,
    string_bindings: dict[str, str],
) -> str:
    return _python_constant_or_bound_string(node.slice, string_bindings)


def _python_static_subscript_sequence_element(node: ast.Subscript) -> ast.AST | None:
    value = node.value
    if not isinstance(value, (ast.Tuple, ast.List)):
        return None
    slice_node = node.slice
    if not isinstance(slice_node, ast.Constant) or not isinstance(slice_node.value, int):
        return None
    index = slice_node.value
    if index < 0:
        index += len(value.elts)
    if 0 <= index < len(value.elts):
        return value.elts[index]
    return None


def _python_call_uses_disallowed_dynamic_callable(node: ast.Call) -> bool:
    if isinstance(node.func, ast.Subscript):
        return True
    if isinstance(node.func, ast.Name) and node.func.id in {"vars", "setattr", "delattr"}:
        return True
    return False


def _python_call_is_filesystem_replace_callable(
    node: ast.Call,
    filesystem_replace_aliases: set[str],
) -> bool:
    return isinstance(node.func, ast.Name) and node.func.id in filesystem_replace_aliases


def _python_readonly_import_aliases(tree: ast.AST) -> dict[str, set[str]]:
    aliases = _empty_python_readonly_import_aliases()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", 1)[0]
                bound = alias.asname or root
                if root == "os":
                    aliases["os_module_aliases"].add(bound)
                elif root == "pathlib":
                    aliases["pathlib_module_aliases"].add(bound)
                elif root == "itertools":
                    aliases["itertools_module_aliases"].add(bound)
        elif isinstance(node, ast.ImportFrom):
            module = str(node.module or "")
            if module == "os":
                for alias in node.names:
                    if alias.name == "replace":
                        aliases["os_replace_aliases"].add(alias.asname or alias.name)
            elif module == "pathlib":
                for alias in node.names:
                    if alias.name in _PYTHON_PATH_CONSTRUCTOR_NAMES:
                        aliases["path_constructor_aliases"].add(alias.asname or alias.name)
            elif module == "itertools":
                for alias in node.names:
                    if alias.name == "chain":
                        aliases["itertools_chain_aliases"].add(alias.asname or alias.name)
                    elif alias.name in _PYTHON_ITERTOOLS_FIRST_ARG_PATH_ITERATORS:
                        aliases["itertools_first_arg_path_iterator_aliases"].add(alias.asname or alias.name)
                    elif alias.name in _PYTHON_ITERTOOLS_SECOND_ARG_PATH_ITERATORS:
                        aliases["itertools_second_arg_path_iterator_aliases"].add(alias.asname or alias.name)
    return aliases


def _python_path_like_binding_names(
    tree: ast.AST,
    scalar_path_bindings: dict[str, str],
    import_aliases: dict[str, set[str]],
) -> set[str]:
    names = set(scalar_path_bindings)
    iterable_names: set[str] = set()
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                value_is_path = _python_expr_returns_path_object(
                    node.value,
                    names,
                    import_aliases,
                    path_iterable_names=iterable_names,
                )
                value_is_path_iterable = _python_expr_iterates_path_objects(
                    node.value,
                    names,
                    iterable_names,
                    import_aliases,
                )
                if not value_is_path and not value_is_path_iterable:
                    continue
                for target in node.targets:
                    for target_name in _python_assignment_target_names(target):
                        if value_is_path and target_name not in names:
                            names.add(target_name)
                            changed = True
                        if value_is_path_iterable and target_name not in iterable_names:
                            iterable_names.add(target_name)
                            changed = True
            elif isinstance(node, ast.For):
                if not _python_expr_iterates_path_objects(node.iter, names, iterable_names, import_aliases):
                    continue
                for target_name in _python_assignment_target_names(node.target):
                    if target_name not in names:
                        names.add(target_name)
                        changed = True
            elif isinstance(node, ast.comprehension):
                if not _python_expr_iterates_path_objects(node.iter, names, iterable_names, import_aliases):
                    continue
                for target_name in _python_assignment_target_names(node.target):
                    if target_name not in names:
                        names.add(target_name)
                        changed = True
    return names


def _python_assignment_target_names(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        names: list[str] = []
        for item in node.elts:
            names.extend(_python_assignment_target_names(item))
        return names
    return []


def _python_expr_returns_path_object(
    node: ast.AST,
    path_like_names: set[str],
    import_aliases: dict[str, set[str]],
    *,
    path_iterable_names: set[str] | None = None,
) -> bool:
    path_iterable_names = path_iterable_names or set()
    if isinstance(node, ast.Name):
        return node.id in path_like_names
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Name) and func.id in import_aliases.get("path_constructor_aliases", set()):
            return True
        if isinstance(func, ast.Name) and func.id == "next" and node.args:
            return _python_expr_iterates_path_objects(
                node.args[0],
                path_like_names,
                path_iterable_names,
                import_aliases,
            )
        if (
            isinstance(func, ast.Attribute)
            and func.attr in import_aliases.get("path_constructor_aliases", set())
            and isinstance(func.value, ast.Name)
            and func.value.id in import_aliases.get("pathlib_module_aliases", set())
        ):
            return True
    if isinstance(node, ast.Attribute):
        return _python_expr_is_filesystem_path_receiver(
            node,
            path_like_names=path_like_names,
            import_aliases=import_aliases,
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        return _python_expr_returns_path_object(
            node.left,
            path_like_names,
            import_aliases,
            path_iterable_names=path_iterable_names,
        )
    return False


def _python_expr_iterates_path_objects(
    node: ast.AST,
    path_like_names: set[str],
    path_iterable_names: set[str],
    import_aliases: dict[str, set[str]],
) -> bool:
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in {"glob", "rglob", "iterdir"}:
            return _python_expr_is_filesystem_path_receiver(
                func.value,
                path_like_names=path_like_names,
                import_aliases=import_aliases,
            )
        if isinstance(func, ast.Name) and func.id in {"list", "tuple", "sorted", "set", "iter"} and node.args:
            return _python_expr_iterates_path_objects(node.args[0], path_like_names, path_iterable_names, import_aliases)
        if isinstance(func, ast.Name) and func.id in {"enumerate", "reversed"} and node.args:
            return _python_expr_iterates_path_objects(node.args[0], path_like_names, path_iterable_names, import_aliases)
        if isinstance(func, ast.Name) and func.id == "filter" and len(node.args) >= 2:
            return _python_expr_iterates_path_objects(node.args[1], path_like_names, path_iterable_names, import_aliases)
        if isinstance(func, ast.Name) and func.id == "map" and len(node.args) >= 2:
            return any(
                _python_expr_iterates_path_objects(arg, path_like_names, path_iterable_names, import_aliases)
                for arg in node.args[1:]
            )
        if isinstance(func, ast.Name) and func.id == "zip" and node.args:
            return any(
                _python_expr_iterates_path_objects(arg, path_like_names, path_iterable_names, import_aliases)
                for arg in node.args
            )
        if isinstance(func, ast.Name) and func.id == "sum" and node.args:
            return _python_expr_iterates_path_iterables(
                node.args[0],
                path_like_names,
                path_iterable_names,
                import_aliases,
            )
        if _python_expr_is_itertools_chain_function(func, import_aliases):
            return any(
                _python_expr_iterates_path_objects(arg, path_like_names, path_iterable_names, import_aliases)
                for arg in node.args
            )
        if _python_expr_is_itertools_chain_from_iterable_function(func, import_aliases) and node.args:
            return _python_expr_iterates_path_iterables(
                node.args[0],
                path_like_names,
                path_iterable_names,
                import_aliases,
            )
        passthrough_arg_index = _python_itertools_path_iterator_arg_index(func, import_aliases)
        if passthrough_arg_index is not None and len(node.args) > passthrough_arg_index:
            return _python_expr_iterates_path_objects(
                node.args[passthrough_arg_index],
                path_like_names,
                path_iterable_names,
                import_aliases,
            )
    if isinstance(node, ast.Name):
        return node.id in path_iterable_names
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(
            _python_expr_returns_path_object(
                element,
                path_like_names,
                import_aliases,
                path_iterable_names=path_iterable_names,
            )
            or (
                isinstance(element, ast.Starred)
                and _python_expr_iterates_path_objects(
                    element.value,
                    path_like_names,
                    path_iterable_names,
                    import_aliases,
                )
            )
            for element in node.elts
        )
    if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
        return any(
            _python_expr_iterates_path_objects(generator.iter, path_like_names, path_iterable_names, import_aliases)
            for generator in node.generators
        )
    return any(
        _python_expr_iterates_path_objects(child, path_like_names, path_iterable_names, import_aliases)
        for child in _python_value_child_nodes(node)
    )


def _python_expr_iterates_path_iterables(
    node: ast.AST,
    path_like_names: set[str],
    path_iterable_names: set[str],
    import_aliases: dict[str, set[str]],
) -> bool:
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(
            _python_expr_iterates_path_objects(element, path_like_names, path_iterable_names, import_aliases)
            for element in node.elts
        )
    if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
        return _python_expr_iterates_path_objects(
            node.elt,
            path_like_names,
            path_iterable_names,
            import_aliases,
        )
    return any(
        _python_expr_iterates_path_objects(child, path_like_names, path_iterable_names, import_aliases)
        or _python_expr_iterates_path_iterables(child, path_like_names, path_iterable_names, import_aliases)
        for child in _python_value_child_nodes(node)
    )


def _python_value_child_nodes(node: ast.AST) -> list[ast.AST]:
    if isinstance(node, ast.Call):
        children = list(node.args)
        children.extend(keyword.value for keyword in node.keywords)
        return children
    return list(ast.iter_child_nodes(node))


def _python_expr_is_itertools_chain_function(
    node: ast.AST,
    import_aliases: dict[str, set[str]],
) -> bool:
    if isinstance(node, ast.Name):
        return node.id in import_aliases.get("itertools_chain_aliases", set())
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "chain"
        and isinstance(node.value, ast.Name)
        and node.value.id in import_aliases.get("itertools_module_aliases", {"itertools"})
    )


def _python_expr_is_itertools_chain_from_iterable_function(
    node: ast.AST,
    import_aliases: dict[str, set[str]],
) -> bool:
    if not isinstance(node, ast.Attribute) or node.attr != "from_iterable":
        return False
    return _python_expr_is_itertools_chain_function(node.value, import_aliases)


def _python_itertools_path_iterator_arg_index(
    node: ast.AST,
    import_aliases: dict[str, set[str]],
) -> int | None:
    if isinstance(node, ast.Name):
        if node.id in import_aliases.get("itertools_first_arg_path_iterator_aliases", set()):
            return 0
        if node.id in import_aliases.get("itertools_second_arg_path_iterator_aliases", set()):
            return 1
        return None
    if not (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id in import_aliases.get("itertools_module_aliases", {"itertools"})
    ):
        return None
    if node.attr in _PYTHON_ITERTOOLS_FIRST_ARG_PATH_ITERATORS:
        return 0
    if node.attr in _PYTHON_ITERTOOLS_SECOND_ARG_PATH_ITERATORS:
        return 1
    return None


def _python_filesystem_replace_callable_aliases(
    tree: ast.AST,
    path_like_names: set[str],
    import_aliases: dict[str, set[str]],
) -> set[str]:
    aliases = set(import_aliases.get("os_replace_aliases", set()))
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            if not _python_expr_is_filesystem_replace_callable(node.value, path_like_names, import_aliases, aliases):
                continue
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id not in aliases:
                    aliases.add(target.id)
                    changed = True
    return aliases


def _python_expr_is_filesystem_replace_callable(
    node: ast.AST,
    path_like_names: set[str],
    import_aliases: dict[str, set[str]],
    callable_aliases: set[str],
) -> bool:
    if isinstance(node, ast.Name):
        return node.id in callable_aliases
    if not isinstance(node, ast.Attribute) or node.attr != "replace":
        return False
    return _python_expr_is_filesystem_path_receiver(
        node.value,
        path_like_names=path_like_names,
        import_aliases=import_aliases,
    )


def _python_call_mode_writes(
    node: ast.Call,
    *,
    positional_index: int,
    string_bindings: dict[str, str],
) -> bool:
    mode = ""
    if len(node.args) > positional_index:
        mode = _python_constant_or_bound_string(node.args[positional_index], string_bindings)
    for keyword in node.keywords:
        if keyword.arg == "mode":
            mode = _python_constant_or_bound_string(keyword.value, string_bindings)
            break
    return _python_open_mode_writes(mode)


def _python_call_mode_writes_or_unknown(
    node: ast.Call,
    *,
    positional_index: int,
    string_bindings: dict[str, str],
) -> bool:
    explicit_mode: ast.AST | None = None
    if len(node.args) > positional_index:
        explicit_mode = node.args[positional_index]
    for keyword in node.keywords:
        if keyword.arg is None:
            return True
        if keyword.arg == "mode":
            explicit_mode = keyword.value
            break
    if explicit_mode is None:
        return False
    mode = _python_constant_or_bound_string(explicit_mode, string_bindings)
    if mode:
        return _python_open_mode_writes(mode)
    return True


def _python_constant_or_bound_string(node: ast.AST, string_bindings: dict[str, str]) -> str:
    return _python_static_string_expr_value(node, string_bindings)


def _python_string_literal_bindings(tree: ast.AST) -> dict[str, str]:
    assignment_nodes = [node for node in ast.walk(tree) if isinstance(node, ast.Assign)]
    bindings: dict[str, str] = {}
    changed = True
    while changed:
        changed = False
        assignments: dict[str, list[str | None]] = {}
        for node in assignment_nodes:
            value = _python_static_string_expr_value(node.value, bindings) or None
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assignments.setdefault(target.id, []).append(value)
        for node in ast.walk(tree):
            for name, value_node in _python_default_arg_name_value_pairs(node):
                value = _python_static_string_expr_value(value_node, bindings) or None
                assignments.setdefault(name, []).append(value)
        next_bindings = {
            name: values[0]
            for name, values in assignments.items()
            if len(values) == 1 and values[0] is not None
        }
        for name, value in next_bindings.items():
            if bindings.get(name) != value:
                bindings[name] = value
                changed = True
    return dict(bindings)


def _python_ast_is_task_data_readonly_probe(tree: ast.AST) -> bool:
    saw_probe = False
    for statement in getattr(tree, "body", []):
        if isinstance(statement, ast.Import):
            if not all(alias.name.split(".", 1)[0] in {"os", "pathlib"} for alias in statement.names):
                return False
            continue
        if isinstance(statement, ast.ImportFrom):
            if statement.module not in {"pathlib"}:
                return False
            if not all(alias.name == "Path" for alias in statement.names):
                return False
            continue
        if isinstance(statement, ast.Expr) and _python_expr_is_allowed_task_data_probe(statement.value):
            saw_probe = True
            continue
        return False
    return saw_probe


def _python_expr_is_allowed_task_data_probe(node: ast.AST) -> bool:
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "print":
        return bool(node.args) and all(_python_expr_is_allowed_task_data_probe(arg) for arg in node.args)
    return _python_call_is_task_data_path_probe(node)


def _python_call_is_task_data_path_probe(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call) or node.keywords:
        return False
    func = node.func
    if not isinstance(func, ast.Attribute):
        return False
    if func.attr in {"exists", "isfile", "isdir"} and _python_attr_is_os_path(func.value):
        return _python_call_first_arg_is_task_data_path(node)
    if func.attr in {"exists", "is_file", "is_dir"} and isinstance(func.value, ast.Call):
        return _python_call_constructs_task_data_path(func.value)
    return False


def _python_attr_is_os_path(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "path"
        and isinstance(node.value, ast.Name)
        and node.value.id == "os"
    )


def _python_call_first_arg_is_task_data_path(node: ast.Call) -> bool:
    if not node.args or not isinstance(node.args[0], ast.Constant):
        return False
    value = node.args[0].value
    return isinstance(value, str) and _is_scope_task_data_path(value)


def _python_call_constructs_task_data_path(node: ast.Call) -> bool:
    if not node.args or not isinstance(node.args[0], ast.Constant):
        return False
    value = node.args[0].value
    if not isinstance(value, str) or not _is_scope_task_data_path(value):
        return False
    func = node.func
    if isinstance(func, ast.Name):
        return func.id == "Path"
    return (
        isinstance(func, ast.Attribute)
        and func.attr == "Path"
        and isinstance(func.value, ast.Name)
        and func.value.id == "pathlib"
    )


def _analyze_python(text: str, *, argv_text: str | None = None) -> dict[str, Any]:
    if argv_text is not None:
        invocations = _inline_python_invocations(argv_text)
        if invocations:
            return _analyze_python_invocations(invocations)
    argv_token = _with_inline_python_argv_bindings(argv_text or text)
    try:
        source_text = _inline_python_source(text) or text
        return _analyze_python_source(source_text)
    finally:
        _PYTHON_ARGV_PATH_BINDINGS.reset(argv_token)


def _analyze_python_invocations(invocations: list[tuple[str, list[str]]]) -> dict[str, Any]:
    effects: list[str] = []
    targets: list[ActionEffectTarget] = []
    rules: list[str] = []
    confidence = "low"
    for source_text, argv_values in invocations:
        argv_token = _PYTHON_ARGV_PATH_BINDINGS.set(
            _python_argv_path_bindings_from_values(argv_values)
        )
        try:
            result = _analyze_python_source(source_text)
        finally:
            _PYTHON_ARGV_PATH_BINDINGS.reset(argv_token)
        _merge(effects, result["effects"])
        targets.extend(result["targets"])
        _merge(rules, result["rules"])
        confidence = _max_confidence(confidence, result["confidence"])
    return {"effects": effects, "targets": targets, "rules": rules, "confidence": confidence}


def _analyze_python_source(text: str) -> dict[str, Any]:
    alias_tokens = _with_python_sys_argv_aliases(text)
    try:
        return _analyze_python_source_with_context(text)
    finally:
        _reset_python_sys_argv_aliases(alias_tokens)


def _analyze_python_source_with_context(text: str) -> dict[str, Any]:
    effects: list[str] = []
    targets: list[ActionEffectTarget] = []
    rules: list[str] = []
    confidence = "low"
    path_bindings = _python_path_variable_bindings(text)
    path_sequence_bindings = _python_path_sequence_variable_bindings(text)
    path_literals = _python_path_constructor_literals(text)
    python_write_items = _python_write_items(text, path_bindings, path_sequence_bindings)
    python_script_write_paths: set[str] = set()
    python_script_write_payloads: list[str] = []
    python_script_write_has_shebang = False
    python_script_write_payload_overflow = False
    for write_path, write_payload, write_payload_overflow in python_write_items:
        if not write_payload and not write_payload_overflow:
            continue
        payload_has_future_marker = _native_write_payload_has_future_execution_marker(write_payload)
        write_target = _write_target_for_path(write_path, payload_is_script=False)
        target_has_script_surface = (
            payload_has_future_marker
            or _native_write_has_associated_script_surface([write_target], write_payload)
            or (
                _native_write_target_is_task_output(write_target)
                and _path_has_associated_script_surface_suffix(write_path)
            )
        )
        if not target_has_script_surface:
            continue
        script_write_target = _write_target_for_path(write_path, payload_is_script=True)
        normalized = normalize_task_artifact_path(write_path, cwd=_NORMALIZER_CWD.get())
        if normalized and script_write_target.path_role in {"future_execution.artifact", "bootstrap_loader"}:
            python_script_write_paths.add(normalized)
        if write_payload:
            python_script_write_payloads.append(write_payload)
        if write_payload_overflow:
            python_script_write_payload_overflow = True
        if _native_write_payload_has_executable_script_marker(write_payload):
            python_script_write_has_shebang = True
    if python_script_write_has_shebang:
        _add_rule(rules, "generated_script_shebang")
    if python_script_write_payloads and _native_write_scan_texts_have_remote_network_indicator(python_script_write_payloads):
        _add_rule(rules, "associated_script_network_indicator")
    if python_script_write_payload_overflow:
        _add_rule(rules, "associated_script_unresolved_write_indicator")
    try:
        tree = ast.parse(text)
    except SyntaxError:
        tree = None
    python_unobserved_stdin_write_paths = (
        {
            normalize_task_artifact_path(path, cwd=_NORMALIZER_CWD.get())
            for path in _python_unobserved_stdin_write_targets(
                tree,
                path_bindings,
                path_sequence_bindings,
            )
        }
        if tree is not None
        else set()
    )
    unresolved_writer_method = bool(
        tree is not None
        and _python_ast_has_unresolved_writer_method_call(
            tree,
            path_bindings,
            path_sequence_bindings,
        )
    )
    unresolved_path_writer_receiver = bool(
        tree is not None
        and _python_ast_has_unresolved_path_writer_receiver_call(
            tree,
            path_bindings,
            path_sequence_bindings,
        )
    )
    invalidated_mapping_writer_method = bool(
        tree is not None and _python_ast_has_invalidated_mapping_writer_method_call(tree)
    )
    unresolved_sys_path_mutation = bool(
        tree is not None
        and _python_sys_path_task_output_targets(text, cwd=_NORMALIZER_CWD.get()) is None
    )
    archive_auxiliary_member_writes = (
        _python_archive_auxiliary_member_write_hints(text, path_bindings, path_sequence_bindings)
        if tree is not None
        else []
    )
    archive_member_write_unresolved = bool(
        tree is not None
        and _python_archive_member_write_has_unresolved_member_name(
            text,
            path_bindings,
            path_sequence_bindings,
        )
    )
    archive_external_reference_write = bool(
        tree is not None and _python_archive_external_reference_write_hint(text)
    )
    task_output_atomic_replace_staging_targets = (
        _python_task_output_atomic_replace_staging_targets(
            tree,
            path_bindings,
            path_sequence_bindings,
        )
        if tree is not None
        else {}
    )
    task_output_atomic_replace_staging = bool(task_output_atomic_replace_staging_targets)

    task_output_verify_targets = _python_local_verify_task_output_targets(text, cwd=_NORMALIZER_CWD.get())
    sys_path_targets = _python_sys_path_task_output_targets(text, cwd=_NORMALIZER_CWD.get())
    has_static_task_output_sys_path = bool(sys_path_targets)
    import_smoke_safe = _python_inline_import_smoke_test_is_scope_safe(text, cwd=_NORMALIZER_CWD.get())
    readonly_verify_safe = _python_inline_verify_code_is_readonly(text)
    if has_static_task_output_sys_path and not import_smoke_safe:
        readonly_verify_safe = False
    if (
        tree is not None
        and task_output_verify_targets
        and (readonly_verify_safe or import_smoke_safe)
    ):
        _add_effect(effects, "command.exec")
        _add_effect(effects, "filesystem.read")
        _add_effect(effects, "filesystem.enumerate")
        targets.extend(task_output_verify_targets)
        _add_rule(rules, "task_output_local_python_verify")
        confidence = _max_confidence(confidence, "medium")
    elif tree is not None and task_output_verify_targets:
        _add_effect(effects, "command.exec")
        targets.extend(task_output_verify_targets)
        _add_rule(rules, "wrapper_chain_unresolved")
        _add_rule(rules, "python_local_verify_unresolved")
        confidence = _max_confidence(confidence, "high")

    if _python_has_wrapper_execution(text):
        _add_effect(effects, "command.exec")
        _add_rule(rules, "wrapper_chain_unresolved")
        _add_rule(rules, "python_wrapper_exec")
        confidence = _max_confidence(confidence, "high")
        _add_embedded_path_read_targets(text, effects, targets, rules)
    doc_reader_import_probe = bool(
        tree is not None and _python_ast_has_only_document_reader_dynamic_import_probe(tree)
    )
    if tree is not None and _python_ast_has_dynamic_code_call(tree) and not doc_reader_import_probe:
        _add_effect(effects, "command.exec")
        _add_rule(rules, "wrapper_chain_unresolved")
        _add_rule(rules, "python_dynamic_code_exec")
        confidence = _max_confidence(confidence, "high")
    elif doc_reader_import_probe:
        _add_rule(rules, "python_document_reader_import_probe")
        confidence = _max_confidence(confidence, "medium")
    if _python_has_socket_or_raw_network(text):
        _add_effect(effects, "network.fetch")
        _add_rule(rules, "python_network_socket")
        confidence = _max_confidence(confidence, "high")
    if re.search(r"\b(?:os\.environ|getenv)\b", text):
        _add_effect(effects, "environment.probe")
        targets.append(_probe_target("environment_credentials"))
        _add_rule(rules, "credential_read")
        confidence = _max_confidence(confidence, "high")
    if _python_has_import_module_call(text) and not doc_reader_import_probe:
        _add_effect(effects, "command.exec")
        _add_rule(rules, "wrapper_chain_unresolved")
        _add_rule(rules, "python_module_import_exec")
        confidence = _max_confidence(confidence, "high")
    elif _python_has_unsafe_find_spec_probe(text):
        _add_effect(effects, "command.exec")
        _add_rule(rules, "wrapper_chain_unresolved")
        _add_rule(rules, "python_module_probe_import_exec")
        confidence = _max_confidence(confidence, "high")
    elif _is_python_module_capability_probe(text):
        _add_effect(effects, "environment.probe")
        targets.append(_probe_target("python_module_import"))
        _add_rule(rules, "python_module_capability_probe")
        confidence = _max_confidence(confidence, "medium")
    elif _is_python_metadata_version_probe(text):
        _add_effect(effects, "environment.probe")
        targets.append(_probe_target("python_importlib_metadata_version_probe"))
        _add_rule(rules, "python_importlib_metadata_version_probe")
        confidence = _max_confidence(confidence, "medium")
    elif _python_has_direct_import_version_probe(text):
        _add_effect(effects, "command.exec")
        targets.append(_probe_target("python_direct_import_probe"))
        _add_rule(rules, "python_import_version_probe_exec")
        confidence = _max_confidence(confidence, "medium")
    elif _python_direct_import_probe_modules(text):
        _add_effect(effects, "command.exec")
        targets.append(_probe_target("python_direct_import_probe"))
        _add_rule(rules, "python_direct_import_probe_exec")
        confidence = _max_confidence(confidence, "medium")
    elif _is_python_source_constant_probe(text):
        _add_effect(effects, "environment.probe")
        targets.append(_probe_target("python_constant_probe"))
        _add_rule(rules, "python_constant_capability_probe")
        confidence = _max_confidence(confidence, "medium")
    if tree is not None and _python_document_reader_has_unknown_non_url_path_arg(
        tree,
        path_bindings,
        path_sequence_bindings,
    ):
        _add_effect(effects, "command.exec")
        _add_rule(rules, "wrapper_chain_unresolved")
        _add_rule(rules, "python_document_reader_unresolved")
        confidence = _max_confidence(confidence, "high")
    if tree is not None and _python_document_reader_has_untrusted_file_object_source(
        tree,
        path_bindings,
    ):
        _add_effect(effects, "command.exec")
        _add_rule(rules, "wrapper_chain_unresolved")
        _add_rule(rules, "python_document_reader_untrusted_file_object_source")
        confidence = _max_confidence(confidence, "high")
    if tree is not None:
        delete_targets, delete_target_unresolved = _python_destructive_delete_targets(
            tree,
            path_bindings,
            path_sequence_bindings,
        )
        if delete_targets or delete_target_unresolved:
            _add_effect(effects, "filesystem.write")
            _add_rule(rules, "destructive_delete")
            if delete_targets:
                for path in delete_targets:
                    targets.append(_target_for_path(path, io_direction="target"))
                _add_rule(rules, "destructive_delete_target_modeled")
            if delete_target_unresolved:
                _add_rule(rules, "destructive_delete_target_unresolved")
            confidence = _max_confidence(confidence, "high")
    if unresolved_writer_method:
        _add_effect(effects, "filesystem.write")
        _add_rule(rules, "python_writer_method_unresolved")
        if tree is not None:
            for path, role, rule in _python_unresolved_writer_redline_literal_targets(tree):
                targets.append(_target_for_path(path, role=role, io_direction="target"))
                _add_rule(rules, rule)
        confidence = _max_confidence(confidence, "high")
    if unresolved_path_writer_receiver:
        _add_effect(effects, "command.exec")
        _add_rule(rules, "wrapper_chain_unresolved")
        _add_rule(rules, "python_writer_method_unresolved")
        confidence = _max_confidence(confidence, "high")
    if invalidated_mapping_writer_method:
        _add_effect(effects, "command.exec")
        _add_rule(rules, "wrapper_chain_unresolved")
        _add_rule(rules, "python_writer_method_unresolved")
        confidence = _max_confidence(confidence, "high")
    if archive_auxiliary_member_writes:
        _add_effect(effects, "filesystem.write")
        _add_rule(rules, "archive_auxiliary_member_write")
        confidence = _max_confidence(confidence, "high")
    if archive_member_write_unresolved:
        _add_effect(effects, "filesystem.write")
        _add_rule(rules, "archive_member_write_unresolved")
        confidence = _max_confidence(confidence, "high")
    if archive_external_reference_write:
        _add_effect(effects, "filesystem.write")
        _add_rule(rules, "archive_external_reference_write")
        confidence = _max_confidence(confidence, "high")
    if task_output_atomic_replace_staging:
        _add_effect(effects, "filesystem.write")
        _add_rule(rules, "task_output_atomic_replace_staging")
        confidence = _max_confidence(confidence, "high")
    if unresolved_sys_path_mutation:
        _add_effect(effects, "command.exec")
        _add_rule(rules, "wrapper_chain_unresolved")
        _add_rule(rules, "python_sys_path_unresolved")
        confidence = _max_confidence(confidence, "high")
    if tree is not None and _python_ast_has_unresolved_open_read_call(
        tree,
        path_bindings,
        path_sequence_bindings,
    ):
        _add_effect(effects, "command.exec")
        _add_rule(rules, "wrapper_chain_unresolved")
        _add_rule(rules, "python_file_read_unresolved")
        confidence = _max_confidence(confidence, "high")

    for path in re.findall(r"(?<!\.)\bopen\(\s*['\"]([^'\"]+)['\"]", text):
        if _path_has_credential_marker(path):
            _add_rule(rules, "credential_read")
            confidence = _max_confidence(confidence, "high")
    document_reader_read_targets = _python_document_reader_targets(
        text,
        path_bindings,
        path_sequence_bindings,
    )
    if document_reader_read_targets:
        _add_rule(rules, "python_document_reader_read")
    for path in _python_read_targets(text, path_bindings, path_sequence_bindings):
        _add_effect(effects, "filesystem.read")
        targets.append(_target_for_path(path, role=_path_role_for_read(path)))
        _add_rule(rules, "python_file_read")
        if _path_has_credential_marker(path):
            _add_rule(rules, "credential_read")
        confidence = _max_confidence(confidence, "medium")
    for path in _python_enumerate_targets(text, path_bindings, path_sequence_bindings):
        _add_effect(effects, "filesystem.enumerate")
        targets.append(_target_for_path(path, role=_path_role_for_enumerate(path)))
        _add_rule(rules, "python_directory_enumerate")
        confidence = _max_confidence(confidence, "medium")
    for path in _python_path_probe_targets(text, path_bindings, path_sequence_bindings):
        if _python_path_probe_is_command_availability_probe(path):
            _add_effect(effects, "environment.probe")
            targets.append(_probe_target("python_path_capability_probe"))
            _add_rule(rules, "python_path_capability_probe")
            confidence = _max_confidence(confidence, "medium")
        else:
            _add_effect(effects, "filesystem.read")
            targets.append(_target_for_path(path, role=_path_role_for_read(path)))
            _add_rule(rules, "python_path_probe")
            confidence = _max_confidence(confidence, "medium")
    for path in re.findall(
        r"(?:Path|pathlib\.Path)\(\s*['\"]([^'\"]+)['\"]\s*\)\.read_(?:text|bytes)\(",
        text,
    ):
        _add_effect(effects, "filesystem.read")
        targets.append(_target_for_path(path, role=_path_role_for_read(path)))
        _add_rule(rules, "python_file_read")
        confidence = _max_confidence(confidence, "medium")
    if path_literals and re.search(r"\.read_(?:text|bytes)\(", text):
        for path in path_literals:
            _add_effect(effects, "filesystem.read")
            targets.append(_target_for_path(path, role=_path_role_for_read(path)))
            _add_rule(rules, "python_file_read")
            confidence = _max_confidence(confidence, "medium")
    for variable in re.findall(r"\b([A-Za-z_]\w*)\.read_(?:text|bytes)\(", text):
        path = path_bindings.get(variable)
        if path:
            _add_effect(effects, "filesystem.read")
            targets.append(_target_for_path(path, role=_path_role_for_read(path)))
            _add_rule(rules, "python_file_read")
            confidence = _max_confidence(confidence, "medium")
    for source_path, destination_path in _python_shutil_copy_path_pairs(
        text,
        path_bindings,
        path_sequence_bindings,
    ):
        _add_effect(effects, "filesystem.read")
        _add_effect(effects, "filesystem.write")
        targets.append(
            _target_for_path(
                source_path,
                role=_path_role_for_read(source_path),
                io_direction="source",
            )
        )
        destination_target = _target_for_path(destination_path, io_direction="target")
        if _path_has_script_asset_directory(destination_path):
            destination_target = destination_target.model_copy(
                update={"path_role": "future_execution.artifact"}
            )
            _add_rule(rules, "copy_to_script_asset_tree")
        targets.append(destination_target)
        _add_rule(rules, "python_shutil_copy")
        _add_rule(rules, "python_file_read")
        _add_rule(rules, "python_file_write")
        confidence = _max_confidence(confidence, "medium")
    for path in _python_write_targets(text, path_bindings, path_sequence_bindings):
        _add_effect(effects, "filesystem.write")
        normalized = normalize_task_artifact_path(path, cwd=_NORMALIZER_CWD.get())
        write_target = _write_target_for_path(path, payload_is_script=normalized in python_script_write_paths)
        if normalized in task_output_atomic_replace_staging_targets:
            write_target = task_output_atomic_replace_staging_targets[normalized]
        targets.append(write_target)
        if _direct_task_output_contract_violated(path, write_target):
            _add_rule(rules, "task_output_contract_violation")
        if (
            normalized in python_unobserved_stdin_write_paths
            and write_target.path_role in {"future_execution.artifact", "bootstrap_loader"}
        ):
            _add_rule(rules, "python_unobserved_stdin_future_exec_write")
        _add_rule(rules, "python_file_write")
        confidence = "high"
    for path in re.findall(r"shutil\.move\([^,]+,\s*['\"]([^'\"]+)['\"]", text):
        _add_effect(effects, "filesystem.write")
        targets.append(_target_for_path(path))
        _add_rule(rules, "python_file_write")
        confidence = _max_confidence(confidence, "medium")
    if _python_source_has_network_fetch(text):
        _add_effect(effects, "network.fetch")
        _add_rule(rules, "python_network_fetch")
        confidence = _max_confidence(confidence, "high")
    return {"effects": effects, "targets": targets, "rules": rules, "confidence": confidence}


def _python_source_has_network_fetch(text: str) -> bool:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return False
    return _python_ast_has_network_fetch_call(
        tree,
        scalar_bindings=_python_path_variable_bindings(text),
    )


def _python_ast_has_network_fetch_call(
    tree: ast.AST,
    *,
    scalar_bindings: dict[str, str] | None = None,
) -> bool:
    _PYTHON_STATIC_DICT_BINDINGS.set(_python_static_dict_literal_bindings(tree))
    network_module_aliases: set[str] = set()
    network_callable_aliases: set[str] = set()
    network_module_mapping_aliases: set[str] = set()
    network_client_class_aliases: set[str] = set()
    network_client_class_mapping_aliases: set[str] = set()
    network_client_instance_aliases: set[str] = set()
    importlib_aliases: set[str] = set()
    import_module_aliases: set[str] = set()
    functools_module_aliases: set[str] = set()
    functools_partial_aliases: set[str] = set()
    operator_module_aliases: set[str] = set()
    operator_attrgetter_aliases: set[str] = set()
    operator_itemgetter_aliases: set[str] = set()
    operator_methodcaller_aliases: set[str] = set()
    string_bindings = _python_string_literal_bindings(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", 1)[0]
                if root in {"requests", "httpx", "urllib"}:
                    network_module_aliases.add(alias.asname or root)
                elif alias.name == "http.client":
                    network_module_aliases.add(alias.asname or "http.client")
                elif alias.name == "importlib":
                    importlib_aliases.add(alias.asname or alias.name)
                elif alias.name == "functools":
                    functools_module_aliases.add(alias.asname or alias.name)
                elif alias.name == "operator":
                    operator_module_aliases.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom):
            module = str(node.module or "")
            root = module.split(".", 1)[0]
            if root in {"requests", "httpx"}:
                for alias in node.names:
                    if alias.name in {"get", "post", "put", "patch", "delete", "request", "head"}:
                        network_callable_aliases.add(alias.asname or alias.name)
                    elif alias.name in {"Session", "Client", "AsyncClient"}:
                        network_client_class_aliases.add(alias.asname or alias.name)
            elif module in {"urllib.request", "urllib"}:
                for alias in node.names:
                    if alias.name in {"urlopen", "Request"}:
                        network_callable_aliases.add(alias.asname or alias.name)
            elif module == "importlib":
                for alias in node.names:
                    if alias.name == "import_module":
                        import_module_aliases.add(alias.asname or alias.name)
            elif module == "functools":
                for alias in node.names:
                    if alias.name == "partial":
                        functools_partial_aliases.add(alias.asname or alias.name)
            elif module == "operator":
                for alias in node.names:
                    if alias.name == "attrgetter":
                        operator_attrgetter_aliases.add(alias.asname or alias.name)
                    elif alias.name == "itemgetter":
                        operator_itemgetter_aliases.add(alias.asname or alias.name)
                    elif alias.name == "methodcaller":
                        operator_methodcaller_aliases.add(alias.asname or alias.name)
    operator_attrgetter_aliases = _python_operator_attrgetter_aliases(
        tree,
        operator_module_aliases=operator_module_aliases,
        initial_aliases=operator_attrgetter_aliases,
    )
    operator_itemgetter_aliases = _python_operator_callable_aliases(
        tree,
        callable_name="itemgetter",
        operator_module_aliases=operator_module_aliases,
        initial_aliases=operator_itemgetter_aliases,
    )
    operator_methodcaller_aliases = _python_operator_callable_aliases(
        tree,
        callable_name="methodcaller",
        operator_module_aliases=operator_module_aliases,
        initial_aliases=operator_methodcaller_aliases,
    )
    getattr_aliases = _python_getattr_aliases(tree)
    network_method_reader_aliases: set[str] = set()
    network_methodcaller_aliases: set[str] = set()
    network_client_getattribute_aliases: set[str] = set()
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            for target_name, value in _python_assignment_name_value_pairs(node):
                configured_attrgetter = _python_configured_operator_method_name(
                    value,
                    callable_name="attrgetter",
                    operator_module_aliases=operator_module_aliases,
                    operator_callable_aliases=operator_attrgetter_aliases,
                    string_bindings=string_bindings,
                )
                if configured_attrgetter in {"get", "post", "put", "patch", "delete", "request", "head"}:
                    if target_name not in network_method_reader_aliases:
                        network_method_reader_aliases.add(target_name)
                        changed = True
                    continue
                configured_methodcaller = _python_configured_operator_method_name(
                    value,
                    callable_name="methodcaller",
                    operator_module_aliases=operator_module_aliases,
                    operator_callable_aliases=operator_methodcaller_aliases,
                    string_bindings=string_bindings,
                )
                if configured_methodcaller in {"get", "post", "put", "patch", "delete", "request", "head"}:
                    if target_name not in network_methodcaller_aliases:
                        network_methodcaller_aliases.add(target_name)
                        changed = True
                    continue
                if _python_expr_is_network_client_getattribute_bound_method(
                    value,
                    network_module_aliases=network_module_aliases,
                    network_client_class_aliases=network_client_class_aliases,
                    network_client_instance_aliases=network_client_instance_aliases,
                    string_bindings=string_bindings,
                ):
                    if target_name not in network_client_getattribute_aliases:
                        network_client_getattribute_aliases.add(target_name)
                        changed = True
                    continue
                if _python_expr_is_network_fetch_callable(
                    value,
                    network_module_aliases=network_module_aliases,
                    network_callable_aliases=network_callable_aliases,
                    network_client_class_aliases=network_client_class_aliases,
                    network_client_instance_aliases=network_client_instance_aliases,
                    network_method_reader_aliases=network_method_reader_aliases,
                    network_client_getattribute_aliases=network_client_getattribute_aliases,
                    getattr_aliases=getattr_aliases,
                    string_bindings=string_bindings,
                    functools_module_aliases=functools_module_aliases,
                    functools_partial_aliases=functools_partial_aliases,
                    operator_module_aliases=operator_module_aliases,
                    operator_attrgetter_aliases=operator_attrgetter_aliases,
                    operator_itemgetter_aliases=operator_itemgetter_aliases,
                    operator_methodcaller_aliases=operator_methodcaller_aliases,
                    network_module_mapping_aliases=network_module_mapping_aliases,
                    network_client_class_mapping_aliases=network_client_class_mapping_aliases,
                ):
                    if target_name not in network_callable_aliases:
                        network_callable_aliases.add(target_name)
                        changed = True
                    continue
                if _python_expr_is_network_module_mapping(
                    value,
                    network_module_aliases,
                    string_bindings,
                    operator_module_aliases=operator_module_aliases,
                    operator_attrgetter_aliases=operator_attrgetter_aliases,
                    network_module_mapping_aliases=network_module_mapping_aliases,
                    network_client_class_mapping_aliases=network_client_class_mapping_aliases,
                    network_client_class_aliases=network_client_class_aliases,
                ):
                    if target_name not in network_module_mapping_aliases:
                        network_module_mapping_aliases.add(target_name)
                        changed = True
                    continue
                if _python_expr_is_network_client_class_mapping(
                    value,
                    network_module_aliases=network_module_aliases,
                    network_client_class_aliases=network_client_class_aliases,
                    string_bindings=string_bindings,
                    operator_module_aliases=operator_module_aliases,
                    operator_attrgetter_aliases=operator_attrgetter_aliases,
                    network_module_mapping_aliases=network_module_mapping_aliases,
                    network_client_class_mapping_aliases=network_client_class_mapping_aliases,
                ):
                    if target_name not in network_client_class_mapping_aliases:
                        network_client_class_mapping_aliases.add(target_name)
                        changed = True
                    continue
                if _python_expr_is_network_module_alias(value, network_module_aliases):
                    if target_name not in network_module_aliases:
                        network_module_aliases.add(target_name)
                        changed = True
                    continue
                if _python_expr_is_network_client_class(
                    value,
                    network_module_aliases=network_module_aliases,
                    network_client_class_aliases=network_client_class_aliases,
                    string_bindings=string_bindings,
                ):
                    if target_name not in network_client_class_aliases:
                        network_client_class_aliases.add(target_name)
                        changed = True
                    continue
                if _python_expr_is_network_client_instance(
                    value,
                    network_module_aliases=network_module_aliases,
                    network_client_class_aliases=network_client_class_aliases,
                    network_client_instance_aliases=network_client_instance_aliases,
                    string_bindings=string_bindings,
                ):
                    if target_name not in network_client_instance_aliases:
                        network_client_instance_aliases.add(target_name)
                        changed = True
                    continue
                imported = _python_importlib_import_module_name(
                    value,
                    string_bindings=string_bindings,
                    importlib_aliases=importlib_aliases,
                    import_module_aliases=import_module_aliases,
                )
                imported_root = imported.split(".", 1)[0]
                if imported_root in {"requests", "httpx", "urllib"} or imported == "http.client":
                    if target_name not in network_module_aliases:
                        network_module_aliases.add(target_name)
                        changed = True
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _python_call_invokes_network_methodcaller(
            node,
            network_module_aliases=network_module_aliases,
            network_client_class_aliases=network_client_class_aliases,
            network_client_instance_aliases=network_client_instance_aliases,
            string_bindings=string_bindings,
            operator_module_aliases=operator_module_aliases,
            operator_methodcaller_aliases=operator_methodcaller_aliases,
        ):
            return True
        if _python_call_invokes_network_methodcaller_alias(
            node,
            network_methodcaller_aliases=network_methodcaller_aliases,
            network_module_aliases=network_module_aliases,
            network_client_class_aliases=network_client_class_aliases,
            network_client_instance_aliases=network_client_instance_aliases,
            string_bindings=string_bindings,
        ):
            return True
        if _python_call_invokes_network_client_method(
            node,
            network_module_aliases=network_module_aliases,
            network_client_class_aliases=network_client_class_aliases,
            network_client_instance_aliases=network_client_instance_aliases,
            string_bindings=string_bindings,
        ):
            return True
        func = node.func
        if _python_expr_is_network_fetch_callable(
            func,
            network_module_aliases=network_module_aliases,
            network_callable_aliases=network_callable_aliases,
            network_client_class_aliases=network_client_class_aliases,
            network_client_instance_aliases=network_client_instance_aliases,
            network_method_reader_aliases=network_method_reader_aliases,
            network_client_getattribute_aliases=network_client_getattribute_aliases,
            getattr_aliases=getattr_aliases,
            string_bindings=string_bindings,
            functools_module_aliases=functools_module_aliases,
            functools_partial_aliases=functools_partial_aliases,
            operator_module_aliases=operator_module_aliases,
            operator_attrgetter_aliases=operator_attrgetter_aliases,
            operator_itemgetter_aliases=operator_itemgetter_aliases,
            operator_methodcaller_aliases=operator_methodcaller_aliases,
            network_module_mapping_aliases=network_module_mapping_aliases,
            network_client_class_mapping_aliases=network_client_class_mapping_aliases,
        ):
            return True
    if _python_ast_has_document_reader_url_call(tree, scalar_bindings=scalar_bindings or {}):
        return True
    return False


def _python_expr_is_network_module_alias(node: ast.AST, network_module_aliases: set[str]) -> bool:
    if isinstance(node, ast.Name):
        return node.id in network_module_aliases
    if isinstance(node, ast.Attribute):
        dotted = _python_ast_dotted_name(node)
        if dotted in network_module_aliases:
            return True
        return isinstance(node.value, ast.Name) and node.value.id in network_module_aliases
    return False


def _python_ast_dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _python_ast_dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else ""
    return ""


def _python_expr_is_network_fetch_callable(
    node: ast.AST,
    *,
    network_module_aliases: set[str],
    network_callable_aliases: set[str],
    network_client_class_aliases: set[str],
    network_client_instance_aliases: set[str],
    network_method_reader_aliases: set[str],
    network_client_getattribute_aliases: set[str],
    getattr_aliases: set[str],
    string_bindings: dict[str, str],
    functools_module_aliases: set[str],
    functools_partial_aliases: set[str],
    operator_module_aliases: set[str],
    operator_attrgetter_aliases: set[str],
    operator_itemgetter_aliases: set[str],
    operator_methodcaller_aliases: set[str],
    network_module_mapping_aliases: set[str],
    network_client_class_mapping_aliases: set[str],
) -> bool:
    if isinstance(node, ast.Name):
        return node.id in network_callable_aliases
    if isinstance(node, ast.NamedExpr):
        return _python_expr_is_network_fetch_callable(
            node.value,
            network_module_aliases=network_module_aliases,
            network_callable_aliases=network_callable_aliases,
            network_client_class_aliases=network_client_class_aliases,
            network_client_instance_aliases=network_client_instance_aliases,
            network_method_reader_aliases=network_method_reader_aliases,
            network_client_getattribute_aliases=network_client_getattribute_aliases,
            getattr_aliases=getattr_aliases,
            string_bindings=string_bindings,
            functools_module_aliases=functools_module_aliases,
            functools_partial_aliases=functools_partial_aliases,
            operator_module_aliases=operator_module_aliases,
            operator_attrgetter_aliases=operator_attrgetter_aliases,
            operator_itemgetter_aliases=operator_itemgetter_aliases,
            operator_methodcaller_aliases=operator_methodcaller_aliases,
            network_module_mapping_aliases=network_module_mapping_aliases,
            network_client_class_mapping_aliases=network_client_class_mapping_aliases,
        )
    if isinstance(node, ast.Attribute):
        if _python_expr_is_network_module_alias(node.value, network_module_aliases):
            return True
        if (
            node.attr in {"get", "post", "put", "patch", "delete", "request", "head"}
            and _python_expr_is_network_client_class(
                node.value,
                network_module_aliases=network_module_aliases,
                network_client_class_aliases=network_client_class_aliases,
                string_bindings=string_bindings,
            )
        ):
            return True
        return (
            node.attr in {"get", "post", "put", "patch", "delete", "request", "head"}
            and _python_expr_is_network_client_instance(
                node.value,
                network_module_aliases=network_module_aliases,
                network_client_class_aliases=network_client_class_aliases,
                network_client_instance_aliases=network_client_instance_aliases,
                string_bindings=string_bindings,
            )
        )
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Lambda)
        and len(node.func.args.args) == 1
        and isinstance(node.func.body, ast.Name)
        and node.func.body.id == node.func.args.args[0].arg
        and node.args
    ):
        return _python_expr_is_network_fetch_callable(
            node.args[0],
            network_module_aliases=network_module_aliases,
            network_callable_aliases=network_callable_aliases,
            network_client_class_aliases=network_client_class_aliases,
            network_client_instance_aliases=network_client_instance_aliases,
            network_method_reader_aliases=network_method_reader_aliases,
            network_client_getattribute_aliases=network_client_getattribute_aliases,
            getattr_aliases=getattr_aliases,
            string_bindings=string_bindings,
            functools_module_aliases=functools_module_aliases,
            functools_partial_aliases=functools_partial_aliases,
            operator_module_aliases=operator_module_aliases,
            operator_attrgetter_aliases=operator_attrgetter_aliases,
            operator_itemgetter_aliases=operator_itemgetter_aliases,
            operator_methodcaller_aliases=operator_methodcaller_aliases,
            network_module_mapping_aliases=network_module_mapping_aliases,
            network_client_class_mapping_aliases=network_client_class_mapping_aliases,
        )
    if isinstance(node, ast.Subscript):
        key = _python_static_subscript_string_key(node, string_bindings)
        if (
            key in {"get", "post", "put", "patch", "delete", "request", "head", "urlopen", "Request"}
            and _python_expr_is_network_module_mapping(
                node.value,
                network_module_aliases,
                string_bindings,
                operator_module_aliases=operator_module_aliases,
                operator_attrgetter_aliases=operator_attrgetter_aliases,
                network_module_mapping_aliases=network_module_mapping_aliases,
                network_client_class_mapping_aliases=network_client_class_mapping_aliases,
                network_client_class_aliases=network_client_class_aliases,
            )
        ):
            return True
        if (
            key in {"get", "post", "put", "patch", "delete", "request", "head"}
            and _python_expr_is_network_client_class_mapping(
                node.value,
                network_module_aliases=network_module_aliases,
                network_client_class_aliases=network_client_class_aliases,
                string_bindings=string_bindings,
                operator_module_aliases=operator_module_aliases,
                operator_attrgetter_aliases=operator_attrgetter_aliases,
                network_module_mapping_aliases=network_module_mapping_aliases,
                network_client_class_mapping_aliases=network_client_class_mapping_aliases,
            )
        ):
            return True
        element = _python_static_subscript_sequence_element(node)
        if element is None:
            element = _python_static_subscript_dict_value(node, string_bindings)
        return element is not None and _python_expr_is_network_fetch_callable(
            element,
            network_module_aliases=network_module_aliases,
            network_callable_aliases=network_callable_aliases,
            network_client_class_aliases=network_client_class_aliases,
            network_client_instance_aliases=network_client_instance_aliases,
            network_method_reader_aliases=network_method_reader_aliases,
            network_client_getattribute_aliases=network_client_getattribute_aliases,
            getattr_aliases=getattr_aliases,
            string_bindings=string_bindings,
            functools_module_aliases=functools_module_aliases,
            functools_partial_aliases=functools_partial_aliases,
            operator_module_aliases=operator_module_aliases,
            operator_attrgetter_aliases=operator_attrgetter_aliases,
            operator_itemgetter_aliases=operator_itemgetter_aliases,
            operator_methodcaller_aliases=operator_methodcaller_aliases,
            network_module_mapping_aliases=network_module_mapping_aliases,
            network_client_class_mapping_aliases=network_client_class_mapping_aliases,
        )
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and (node.func.id == "getattr" or node.func.id in getattr_aliases)
        and len(node.args) >= 2
    ):
        attr = _python_constant_or_bound_string(node.args[1], string_bindings)
        return attr in {"get", "post", "put", "patch", "delete", "request", "head", "urlopen", "Request"} and (
            _python_expr_is_network_module_alias(node.args[0], network_module_aliases)
            or _python_expr_is_network_client_class(
                node.args[0],
                network_module_aliases=network_module_aliases,
                network_client_class_aliases=network_client_class_aliases,
                string_bindings=string_bindings,
            )
            or _python_expr_is_network_client_instance(
                node.args[0],
                network_module_aliases=network_module_aliases,
                network_client_class_aliases=network_client_class_aliases,
                network_client_instance_aliases=network_client_instance_aliases,
                string_bindings=string_bindings,
            )
        )
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in network_method_reader_aliases
        and node.args
    ):
        return _python_expr_is_network_client_instance(
            node.args[0],
            network_module_aliases=network_module_aliases,
            network_client_class_aliases=network_client_class_aliases,
            network_client_instance_aliases=network_client_instance_aliases,
            string_bindings=string_bindings,
        )
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in network_client_getattribute_aliases
        and node.args
    ):
        attr = _python_constant_or_bound_string(node.args[0], string_bindings)
        return attr in {"get", "post", "put", "patch", "delete", "request", "head"}
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Call)
        and _python_expr_is_operator_attrgetter_callable(
            node.func.func,
            operator_module_aliases=operator_module_aliases,
            operator_attrgetter_aliases=operator_attrgetter_aliases,
        )
        and node.func.args
        and node.args
    ):
        attr = _python_constant_or_bound_string(node.func.args[0], string_bindings)
        return attr in {"get", "post", "put", "patch", "delete", "request", "head", "urlopen", "Request"} and (
            _python_expr_is_network_module_alias(node.args[0], network_module_aliases)
            or _python_expr_is_network_client_class(
                node.args[0],
                network_module_aliases=network_module_aliases,
                network_client_class_aliases=network_client_class_aliases,
                string_bindings=string_bindings,
            )
            or _python_expr_is_network_client_instance(
                node.args[0],
                network_module_aliases=network_module_aliases,
                network_client_class_aliases=network_client_class_aliases,
                network_client_instance_aliases=network_client_instance_aliases,
                string_bindings=string_bindings,
            )
        )
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Call)
        and _python_expr_is_operator_named_callable(
            node.func.func,
            callable_name="itemgetter",
            operator_module_aliases=operator_module_aliases,
            operator_callable_aliases=operator_itemgetter_aliases,
        )
        and node.func.args
        and node.args
    ):
        key = _python_constant_or_bound_string(node.func.args[0], string_bindings)
        return (
            key in {"get", "post", "put", "patch", "delete", "request", "head", "urlopen", "Request"}
            and (
                _python_expr_is_network_module_mapping(
                    node.args[0],
                    network_module_aliases,
                    string_bindings,
                    operator_module_aliases=operator_module_aliases,
                    operator_attrgetter_aliases=operator_attrgetter_aliases,
                    network_module_mapping_aliases=network_module_mapping_aliases,
                    network_client_class_mapping_aliases=network_client_class_mapping_aliases,
                    network_client_class_aliases=network_client_class_aliases,
                )
                or _python_expr_is_network_client_class_mapping(
                    node.args[0],
                    network_module_aliases=network_module_aliases,
                    network_client_class_aliases=network_client_class_aliases,
                    string_bindings=string_bindings,
                    operator_module_aliases=operator_module_aliases,
                    operator_attrgetter_aliases=operator_attrgetter_aliases,
                    network_module_mapping_aliases=network_module_mapping_aliases,
                    network_client_class_mapping_aliases=network_client_class_mapping_aliases,
                )
            )
        )
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Call)
        and _python_expr_is_operator_named_callable(
            node.func.func,
            callable_name="methodcaller",
            operator_module_aliases=operator_module_aliases,
            operator_callable_aliases=operator_methodcaller_aliases,
        )
        and len(node.func.args) >= 2
        and node.args
    ):
        method = _python_constant_or_bound_string(node.func.args[0], string_bindings)
        key = _python_constant_or_bound_string(node.func.args[1], string_bindings)
        if method in {"get", "setdefault", "__getitem__"} and _python_expr_is_network_fetch_mapping_key(
            node.args[0],
            key,
            network_module_aliases=network_module_aliases,
            network_client_class_aliases=network_client_class_aliases,
            string_bindings=string_bindings,
            operator_module_aliases=operator_module_aliases,
            operator_attrgetter_aliases=operator_attrgetter_aliases,
            network_module_mapping_aliases=network_module_mapping_aliases,
            network_client_class_mapping_aliases=network_client_class_mapping_aliases,
        ):
            return True
    if (
        isinstance(node, ast.Call)
        and _python_call_func_is_unbound_mapping_get(node.func)
        and len(node.args) >= 2
    ):
        key = _python_constant_or_bound_string(node.args[1], string_bindings)
        if _python_expr_is_network_fetch_mapping_key(
            node.args[0],
            key,
            network_module_aliases=network_module_aliases,
            network_client_class_aliases=network_client_class_aliases,
            string_bindings=string_bindings,
            operator_module_aliases=operator_module_aliases,
            operator_attrgetter_aliases=operator_attrgetter_aliases,
            network_module_mapping_aliases=network_module_mapping_aliases,
            network_client_class_mapping_aliases=network_client_class_mapping_aliases,
        ):
            return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr in {"get", "setdefault", "__getitem__"} and node.args:
            key = _python_constant_or_bound_string(node.args[0], string_bindings)
            if _python_expr_is_network_fetch_mapping_key(
                node.func.value,
                key,
                network_module_aliases=network_module_aliases,
                network_client_class_aliases=network_client_class_aliases,
                string_bindings=string_bindings,
                operator_module_aliases=operator_module_aliases,
                operator_attrgetter_aliases=operator_attrgetter_aliases,
                network_module_mapping_aliases=network_module_mapping_aliases,
                network_client_class_mapping_aliases=network_client_class_mapping_aliases,
            ):
                return True
        if (
            node.func.attr == "__getattribute__"
            and node.args
            and _python_expr_is_network_client_instance(
                node.func.value,
                network_module_aliases=network_module_aliases,
                network_client_class_aliases=network_client_class_aliases,
                network_client_instance_aliases=network_client_instance_aliases,
                string_bindings=string_bindings,
            )
        ):
            attr = _python_constant_or_bound_string(node.args[0], string_bindings)
            return attr in {"get", "post", "put", "patch", "delete", "request", "head"}
        if (
            node.func.attr == "__getattribute__"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "object"
            and len(node.args) >= 2
            and _python_expr_is_network_client_instance(
                node.args[0],
                network_module_aliases=network_module_aliases,
                network_client_class_aliases=network_client_class_aliases,
                network_client_instance_aliases=network_client_instance_aliases,
                string_bindings=string_bindings,
            )
        ):
            attr = _python_constant_or_bound_string(node.args[1], string_bindings)
            return attr in {"get", "post", "put", "patch", "delete", "request", "head"}
        if (
            node.func.attr == "__getattribute__"
            and len(node.args) >= 2
            and _python_expr_is_network_client_getattribute_owner(
                node.func.value,
                node.args[0],
                network_module_aliases=network_module_aliases,
                network_client_class_aliases=network_client_class_aliases,
                network_client_instance_aliases=network_client_instance_aliases,
                string_bindings=string_bindings,
            )
        ):
            attr = _python_constant_or_bound_string(node.args[1], string_bindings)
            return attr in {"get", "post", "put", "patch", "delete", "request", "head"}
        if (
            node.func.attr == "partial"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in functools_module_aliases
            and node.args
            and _python_expr_is_network_fetch_callable(
                node.args[0],
                network_module_aliases=network_module_aliases,
                network_callable_aliases=network_callable_aliases,
                network_client_class_aliases=network_client_class_aliases,
                network_client_instance_aliases=network_client_instance_aliases,
                network_method_reader_aliases=network_method_reader_aliases,
                network_client_getattribute_aliases=network_client_getattribute_aliases,
                getattr_aliases=getattr_aliases,
                string_bindings=string_bindings,
                functools_module_aliases=functools_module_aliases,
                functools_partial_aliases=functools_partial_aliases,
                operator_module_aliases=operator_module_aliases,
                operator_attrgetter_aliases=operator_attrgetter_aliases,
                operator_itemgetter_aliases=operator_itemgetter_aliases,
                operator_methodcaller_aliases=operator_methodcaller_aliases,
                network_module_mapping_aliases=network_module_mapping_aliases,
                network_client_class_mapping_aliases=network_client_class_mapping_aliases,
            )
        ):
            return True
        element = _python_static_mapping_reader_value(node, string_bindings)
        return element is not None and _python_expr_is_network_fetch_callable(
            element,
            network_module_aliases=network_module_aliases,
            network_callable_aliases=network_callable_aliases,
            network_client_class_aliases=network_client_class_aliases,
            network_client_instance_aliases=network_client_instance_aliases,
            network_method_reader_aliases=network_method_reader_aliases,
            network_client_getattribute_aliases=network_client_getattribute_aliases,
            getattr_aliases=getattr_aliases,
            string_bindings=string_bindings,
            functools_module_aliases=functools_module_aliases,
            functools_partial_aliases=functools_partial_aliases,
            operator_module_aliases=operator_module_aliases,
            operator_attrgetter_aliases=operator_attrgetter_aliases,
            operator_itemgetter_aliases=operator_itemgetter_aliases,
            operator_methodcaller_aliases=operator_methodcaller_aliases,
            network_module_mapping_aliases=network_module_mapping_aliases,
            network_client_class_mapping_aliases=network_client_class_mapping_aliases,
        )
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in functools_partial_aliases
        and node.args
    ):
        return _python_expr_is_network_fetch_callable(
            node.args[0],
            network_module_aliases=network_module_aliases,
            network_callable_aliases=network_callable_aliases,
            network_client_class_aliases=network_client_class_aliases,
            network_client_instance_aliases=network_client_instance_aliases,
            network_method_reader_aliases=network_method_reader_aliases,
            network_client_getattribute_aliases=network_client_getattribute_aliases,
            getattr_aliases=getattr_aliases,
            string_bindings=string_bindings,
            functools_module_aliases=functools_module_aliases,
            functools_partial_aliases=functools_partial_aliases,
            operator_module_aliases=operator_module_aliases,
            operator_attrgetter_aliases=operator_attrgetter_aliases,
            operator_itemgetter_aliases=operator_itemgetter_aliases,
            operator_methodcaller_aliases=operator_methodcaller_aliases,
            network_module_mapping_aliases=network_module_mapping_aliases,
            network_client_class_mapping_aliases=network_client_class_mapping_aliases,
        )
    return False


def _python_call_invokes_network_methodcaller(
    node: ast.Call,
    *,
    network_module_aliases: set[str],
    network_client_class_aliases: set[str],
    network_client_instance_aliases: set[str],
    string_bindings: dict[str, str],
    operator_module_aliases: set[str],
    operator_methodcaller_aliases: set[str],
) -> bool:
    if not (
        isinstance(node.func, ast.Call)
        and _python_expr_is_operator_named_callable(
            node.func.func,
            callable_name="methodcaller",
            operator_module_aliases=operator_module_aliases,
            operator_callable_aliases=operator_methodcaller_aliases,
        )
        and node.func.args
        and node.args
    ):
        return False
    method = _python_constant_or_bound_string(node.func.args[0], string_bindings)
    return (
        method in {"get", "post", "put", "patch", "delete", "request", "head", "urlopen", "Request"}
        and (
            _python_expr_is_network_module_alias(node.args[0], network_module_aliases)
            or _python_expr_is_network_client_instance(
                node.args[0],
                network_module_aliases=network_module_aliases,
                network_client_class_aliases=network_client_class_aliases,
                network_client_instance_aliases=network_client_instance_aliases,
                string_bindings=string_bindings,
            )
        )
    )


def _python_call_invokes_network_client_method(
    node: ast.Call,
    *,
    network_module_aliases: set[str],
    network_client_class_aliases: set[str],
    network_client_instance_aliases: set[str],
    string_bindings: dict[str, str],
) -> bool:
    if not isinstance(node.func, ast.Attribute):
        return False
    if node.func.attr not in {"get", "post", "put", "patch", "delete", "request", "head"}:
        return False
    if _python_expr_is_network_client_instance(
        node.func.value,
        network_module_aliases=network_module_aliases,
        network_client_class_aliases=network_client_class_aliases,
        network_client_instance_aliases=network_client_instance_aliases,
        string_bindings=string_bindings,
    ):
        return True
    return bool(
        node.args
        and _python_expr_is_network_client_class(
            node.func.value,
            network_module_aliases=network_module_aliases,
            network_client_class_aliases=network_client_class_aliases,
            string_bindings=string_bindings,
        )
        and _python_expr_is_network_client_instance(
            node.args[0],
            network_module_aliases=network_module_aliases,
            network_client_class_aliases=network_client_class_aliases,
            network_client_instance_aliases=network_client_instance_aliases,
            string_bindings=string_bindings,
        )
    )


def _python_call_invokes_network_methodcaller_alias(
    node: ast.Call,
    *,
    network_methodcaller_aliases: set[str],
    network_module_aliases: set[str],
    network_client_class_aliases: set[str],
    network_client_instance_aliases: set[str],
    string_bindings: dict[str, str],
) -> bool:
    return bool(
        isinstance(node.func, ast.Name)
        and node.func.id in network_methodcaller_aliases
        and node.args
        and _python_expr_is_network_client_instance(
            node.args[0],
            network_module_aliases=network_module_aliases,
            network_client_class_aliases=network_client_class_aliases,
            network_client_instance_aliases=network_client_instance_aliases,
            string_bindings=string_bindings,
        )
    )


def _python_configured_operator_method_name(
    node: ast.AST,
    *,
    callable_name: str,
    operator_module_aliases: set[str],
    operator_callable_aliases: set[str],
    string_bindings: dict[str, str],
) -> str:
    if not (
        isinstance(node, ast.Call)
        and _python_expr_is_operator_named_callable(
            node.func,
            callable_name=callable_name,
            operator_module_aliases=operator_module_aliases,
            operator_callable_aliases=operator_callable_aliases,
        )
        and node.args
    ):
        return ""
    return _python_constant_or_bound_string(node.args[0], string_bindings)


def _python_expr_is_network_client_getattribute_bound_method(
    node: ast.AST,
    *,
    network_module_aliases: set[str],
    network_client_class_aliases: set[str],
    network_client_instance_aliases: set[str],
    string_bindings: dict[str, str],
) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "__getattribute__"
        and _python_expr_is_network_client_instance(
            node.value,
            network_module_aliases=network_module_aliases,
            network_client_class_aliases=network_client_class_aliases,
            network_client_instance_aliases=network_client_instance_aliases,
            string_bindings=string_bindings,
        )
    )


def _python_expr_is_network_client_getattribute_owner(
    owner: ast.AST,
    receiver: ast.AST,
    *,
    network_module_aliases: set[str],
    network_client_class_aliases: set[str],
    network_client_instance_aliases: set[str],
    string_bindings: dict[str, str],
) -> bool:
    if not _python_expr_is_network_client_instance(
        receiver,
        network_module_aliases=network_module_aliases,
        network_client_class_aliases=network_client_class_aliases,
        network_client_instance_aliases=network_client_instance_aliases,
        string_bindings=string_bindings,
    ):
        return False
    if _python_expr_is_network_client_class(
        owner,
        network_module_aliases=network_module_aliases,
        network_client_class_aliases=network_client_class_aliases,
        string_bindings=string_bindings,
    ):
        return True
    return (
        isinstance(owner, ast.Call)
        and isinstance(owner.func, ast.Name)
        and owner.func.id == "type"
        and owner.args
        and _python_expr_is_network_client_instance(
            owner.args[0],
            network_module_aliases=network_module_aliases,
            network_client_class_aliases=network_client_class_aliases,
            network_client_instance_aliases=network_client_instance_aliases,
            string_bindings=string_bindings,
        )
    )


def _python_expr_is_network_client_instance(
    node: ast.AST,
    *,
    network_module_aliases: set[str],
    network_client_class_aliases: set[str],
    network_client_instance_aliases: set[str],
    string_bindings: dict[str, str],
) -> bool:
    if isinstance(node, ast.Name):
        return node.id in network_client_instance_aliases
    if isinstance(node, ast.NamedExpr):
        return _python_expr_is_network_client_instance(
            node.value,
            network_module_aliases=network_module_aliases,
            network_client_class_aliases=network_client_class_aliases,
            network_client_instance_aliases=network_client_instance_aliases,
            string_bindings=string_bindings,
        )
    if isinstance(node, ast.Subscript):
        element = _python_static_subscript_sequence_element(node)
        if element is None:
            element = _python_static_subscript_dict_value(node, string_bindings)
        return element is not None and _python_expr_is_network_client_instance(
            element,
            network_module_aliases=network_module_aliases,
            network_client_class_aliases=network_client_class_aliases,
            network_client_instance_aliases=network_client_instance_aliases,
            string_bindings=string_bindings,
        )
    if not isinstance(node, ast.Call):
        return False
    return _python_expr_is_network_client_class(
        node.func,
        network_module_aliases=network_module_aliases,
        network_client_class_aliases=network_client_class_aliases,
        string_bindings=string_bindings,
    )


def _python_expr_is_network_client_class(
    node: ast.AST,
    *,
    network_module_aliases: set[str],
    network_client_class_aliases: set[str],
    string_bindings: dict[str, str],
) -> bool:
    func = node
    if isinstance(func, ast.Name):
        return func.id in network_client_class_aliases
    if isinstance(func, ast.NamedExpr):
        return _python_expr_is_network_client_class(
            func.value,
            network_module_aliases=network_module_aliases,
            network_client_class_aliases=network_client_class_aliases,
            string_bindings=string_bindings,
        )
    if isinstance(func, ast.Subscript):
        element = _python_static_subscript_sequence_element(func)
        if element is None:
            element = _python_static_subscript_dict_value(func, string_bindings)
        return element is not None and _python_expr_is_network_client_class(
            element,
            network_module_aliases=network_module_aliases,
            network_client_class_aliases=network_client_class_aliases,
            string_bindings=string_bindings,
        )
    if isinstance(func, ast.Call) and isinstance(func.func, ast.Attribute):
        element = _python_static_mapping_reader_value(func, string_bindings)
        if element is not None:
            return _python_expr_is_network_client_class(
                element,
                network_module_aliases=network_module_aliases,
                network_client_class_aliases=network_client_class_aliases,
                string_bindings=string_bindings,
            )
    return (
        isinstance(func, ast.Attribute)
        and func.attr in {"Session", "Client", "AsyncClient"}
        and _python_expr_is_network_module_alias(func.value, network_module_aliases)
    )


def _python_expr_is_network_module_mapping(
    node: ast.AST,
    network_module_aliases: set[str],
    string_bindings: dict[str, str],
    *,
    operator_module_aliases: set[str],
    operator_attrgetter_aliases: set[str],
    network_module_mapping_aliases: set[str],
    network_client_class_mapping_aliases: set[str],
    network_client_class_aliases: set[str],
) -> bool:
    if isinstance(node, ast.Name):
        return node.id in network_module_mapping_aliases
    if isinstance(node, ast.Attribute) and node.attr == "__dict__":
        return _python_expr_is_network_module_alias(node.value, network_module_aliases)
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id == "dict" and node.args:
            return _python_expr_is_network_module_mapping(
                node.args[0],
                network_module_aliases,
                string_bindings,
                operator_module_aliases=operator_module_aliases,
                operator_attrgetter_aliases=operator_attrgetter_aliases,
                network_module_mapping_aliases=network_module_mapping_aliases,
                network_client_class_mapping_aliases=network_client_class_mapping_aliases,
                network_client_class_aliases=network_client_class_aliases,
            )
        if isinstance(node.func, ast.Name) and node.func.id == "vars" and node.args:
            return _python_expr_is_network_module_alias(node.args[0], network_module_aliases)
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "copy"
            and not node.args
            and not node.keywords
        ):
            return _python_expr_is_network_module_mapping(
                node.func.value,
                network_module_aliases,
                string_bindings,
                operator_module_aliases=operator_module_aliases,
                operator_attrgetter_aliases=operator_attrgetter_aliases,
                network_module_mapping_aliases=network_module_mapping_aliases,
                network_client_class_mapping_aliases=network_client_class_mapping_aliases,
                network_client_class_aliases=network_client_class_aliases,
            )
        if (
            isinstance(node.func, ast.Call)
            and _python_expr_is_operator_attrgetter_callable(
                node.func.func,
                operator_module_aliases=operator_module_aliases,
                operator_attrgetter_aliases=operator_attrgetter_aliases,
            )
            and node.func.args
            and _python_constant_or_bound_string(node.func.args[0], string_bindings) == "__dict__"
            and node.args
        ):
            return _python_expr_is_network_module_alias(node.args[0], network_module_aliases)
    if isinstance(node, ast.Dict):
        for key, value in zip(node.keys, node.values, strict=True):
            if key is None and _python_expr_is_network_module_mapping(
                value,
                network_module_aliases,
                string_bindings,
                operator_module_aliases=operator_module_aliases,
                operator_attrgetter_aliases=operator_attrgetter_aliases,
                network_module_mapping_aliases=network_module_mapping_aliases,
                network_client_class_mapping_aliases=network_client_class_mapping_aliases,
                network_client_class_aliases=network_client_class_aliases,
            ):
                return True
    return False


def _python_expr_is_network_client_class_mapping(
    node: ast.AST,
    *,
    network_module_aliases: set[str],
    network_client_class_aliases: set[str],
    string_bindings: dict[str, str],
    operator_module_aliases: set[str],
    operator_attrgetter_aliases: set[str],
    network_module_mapping_aliases: set[str],
    network_client_class_mapping_aliases: set[str],
) -> bool:
    if isinstance(node, ast.Name):
        return node.id in network_client_class_mapping_aliases
    class_node: ast.AST | None = None
    if isinstance(node, ast.Attribute) and node.attr == "__dict__":
        class_node = node.value
    elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "vars" and node.args:
        class_node = node.args[0]
    elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "dict" and node.args:
        return _python_expr_is_network_client_class_mapping(
            node.args[0],
            network_module_aliases=network_module_aliases,
            network_client_class_aliases=network_client_class_aliases,
            string_bindings=string_bindings,
            operator_module_aliases=operator_module_aliases,
            operator_attrgetter_aliases=operator_attrgetter_aliases,
            network_module_mapping_aliases=network_module_mapping_aliases,
            network_client_class_mapping_aliases=network_client_class_mapping_aliases,
        )
    elif (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "copy"
        and not node.args
        and not node.keywords
    ):
        return _python_expr_is_network_client_class_mapping(
            node.func.value,
            network_module_aliases=network_module_aliases,
            network_client_class_aliases=network_client_class_aliases,
            string_bindings=string_bindings,
            operator_module_aliases=operator_module_aliases,
            operator_attrgetter_aliases=operator_attrgetter_aliases,
            network_module_mapping_aliases=network_module_mapping_aliases,
            network_client_class_mapping_aliases=network_client_class_mapping_aliases,
        )
    elif isinstance(node, ast.Dict):
        for key, value in zip(node.keys, node.values, strict=True):
            if key is None and _python_expr_is_network_client_class_mapping(
                value,
                network_module_aliases=network_module_aliases,
                network_client_class_aliases=network_client_class_aliases,
                string_bindings=string_bindings,
                operator_module_aliases=operator_module_aliases,
                operator_attrgetter_aliases=operator_attrgetter_aliases,
                network_module_mapping_aliases=network_module_mapping_aliases,
                network_client_class_mapping_aliases=network_client_class_mapping_aliases,
            ):
                return True
        return False
    return class_node is not None and _python_expr_is_network_client_class(
        class_node,
        network_module_aliases=network_module_aliases,
        network_client_class_aliases=network_client_class_aliases,
        string_bindings=string_bindings,
    )


def _python_expr_is_network_fetch_mapping_key(
    node: ast.AST,
    key: str,
    *,
    network_module_aliases: set[str],
    network_client_class_aliases: set[str],
    string_bindings: dict[str, str],
    operator_module_aliases: set[str],
    operator_attrgetter_aliases: set[str],
    network_module_mapping_aliases: set[str],
    network_client_class_mapping_aliases: set[str],
) -> bool:
    if key in {"get", "post", "put", "patch", "delete", "request", "head", "urlopen", "Request"} and (
        _python_expr_is_network_module_mapping(
            node,
            network_module_aliases,
            string_bindings,
            operator_module_aliases=operator_module_aliases,
            operator_attrgetter_aliases=operator_attrgetter_aliases,
            network_module_mapping_aliases=network_module_mapping_aliases,
            network_client_class_mapping_aliases=network_client_class_mapping_aliases,
            network_client_class_aliases=network_client_class_aliases,
        )
    ):
        return True
    return key in {"get", "post", "put", "patch", "delete", "request", "head"} and (
        _python_expr_is_network_client_class_mapping(
            node,
            network_module_aliases=network_module_aliases,
            network_client_class_aliases=network_client_class_aliases,
            string_bindings=string_bindings,
            operator_module_aliases=operator_module_aliases,
            operator_attrgetter_aliases=operator_attrgetter_aliases,
            network_module_mapping_aliases=network_module_mapping_aliases,
            network_client_class_mapping_aliases=network_client_class_mapping_aliases,
        )
    )


def _python_static_subscript_dict_value(node: ast.Subscript, string_bindings: dict[str, str]) -> ast.AST | None:
    dict_node: ast.Dict | None = None
    if isinstance(node.value, ast.Dict):
        dict_node = node.value
    elif isinstance(node.value, ast.Name):
        dict_node = _PYTHON_STATIC_DICT_BINDINGS.get().get(node.value.id)
    if dict_node is None:
        return None
    key = _python_static_subscript_string_key(node, string_bindings)
    if not key:
        return None
    for dict_key, dict_value in zip(dict_node.keys, dict_node.values, strict=True):
        if dict_key is None:
            continue
        if _python_constant_or_bound_string(dict_key, string_bindings) == key:
            return dict_value
    return None


def _python_static_mapping_reader_value(node: ast.Call, string_bindings: dict[str, str]) -> ast.AST | None:
    if node.func.attr not in {"get", "setdefault", "__getitem__"} or not node.args:
        return None
    dict_node: ast.Dict | None = None
    if isinstance(node.func.value, ast.Dict):
        dict_node = node.func.value
    elif isinstance(node.func.value, ast.Name):
        dict_node = _PYTHON_STATIC_DICT_BINDINGS.get().get(node.func.value.id)
    if dict_node is None:
        return None
    key = _python_constant_or_bound_string(node.args[0], string_bindings)
    if not key:
        return None
    for dict_key, dict_value in zip(dict_node.keys, dict_node.values, strict=True):
        if dict_key is None:
            continue
        if _python_constant_or_bound_string(dict_key, string_bindings) == key:
            return dict_value
    if node.func.attr == "setdefault" and len(node.args) >= 2:
        return node.args[1]
    return None


def _python_importlib_import_module_name(
    node: ast.AST,
    *,
    string_bindings: dict[str, str],
    importlib_aliases: set[str],
    import_module_aliases: set[str],
) -> str:
    if not isinstance(node, ast.Call) or not node.args:
        return ""
    func = node.func
    if isinstance(func, ast.Name):
        if func.id not in import_module_aliases:
            return ""
    elif not (
        isinstance(func, ast.Attribute)
        and func.attr == "import_module"
        and isinstance(func.value, ast.Name)
        and func.value.id in importlib_aliases
    ):
        return ""
    return _python_constant_or_bound_string(node.args[0], string_bindings)


def _python_ast_has_document_reader_url_call(
    tree: ast.AST,
    *,
    scalar_bindings: dict[str, str],
) -> bool:
    reader_bindings = _python_document_reader_bindings(tree)
    string_bindings = _python_string_literal_bindings(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not _python_call_is_document_reader(node, reader_bindings):
            continue
        if any(
            _python_ast_arg_is_url(source_node, string_bindings, scalar_bindings)
            for source_node in _python_document_reader_source_arg_nodes(node, reader_bindings)
        ):
            return True
    return False


def _python_ast_arg_is_url(
    node: ast.AST,
    string_bindings: dict[str, str],
    scalar_bindings: dict[str, str] | None = None,
) -> bool:
    scalar_bindings = scalar_bindings or {}
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return _URL_RE.match(node.value.strip()) is not None
    if isinstance(node, ast.Name):
        value = string_bindings.get(node.id, "") or scalar_bindings.get(node.id, "")
        return _URL_RE.match(value.strip()) is not None
    if isinstance(node, ast.Subscript):
        argv_index = _python_sys_argv_subscript_index(node)
        argv_value = _PYTHON_ARGV_PATH_BINDINGS.get().get(argv_index) if argv_index is not None else None
        return bool(argv_value and _URL_RE.match(argv_value.strip()))
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Name) and func.id in {"str", "bytes"} and len(node.args) == 1:
            return _python_ast_arg_is_url(node.args[0], string_bindings, scalar_bindings)
        if _python_call_is_path_constructor(node) and node.args:
            return _python_ast_arg_is_url(node.args[0], string_bindings, scalar_bindings)
    return False


def _python_has_wrapper_execution(text: str) -> bool:
    if re.search(
        r"\b(?:subprocess|commands)\b|"
        r"\bos\.(?:system|popen|spawn[lvpe]*|exec[lvpe]*)\s*\(|"
        r"\bpopen\s*\(|"
        r"\bpty\.spawn\s*\(",
        text,
    ):
        return True
    try:
        tree = ast.parse(_inline_python_source(text) or text)
    except SyntaxError:
        return False
    return _python_ast_has_wrapper_execution_call(tree)


def _python_ast_has_wrapper_execution_call(tree: ast.AST) -> bool:
    os_module_aliases = {"os"}
    subprocess_module_aliases = {"subprocess"}
    commands_module_aliases = {"commands"}
    pty_module_aliases = {"pty"}
    os_exec_aliases: set[str] = set()
    subprocess_exec_aliases: set[str] = set()
    commands_exec_aliases: set[str] = set()
    pty_exec_aliases: set[str] = set()
    os_exec_attrs = {
        "system",
        "popen",
        "spawnl",
        "spawnle",
        "spawnlp",
        "spawnlpe",
        "spawnv",
        "spawnve",
        "spawnvp",
        "spawnvpe",
        "execl",
        "execle",
        "execlp",
        "execlpe",
        "execv",
        "execve",
        "execvp",
        "execvpe",
    }
    subprocess_exec_attrs = {
        "run",
        "call",
        "check_call",
        "check_output",
        "Popen",
        "getoutput",
        "getstatusoutput",
    }
    commands_exec_attrs = {"getoutput", "getstatusoutput"}
    string_bindings = _python_string_literal_bindings(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", 1)[0]
                bound = alias.asname or root
                if root == "os":
                    os_module_aliases.add(bound)
                elif root == "subprocess":
                    subprocess_module_aliases.add(bound)
                elif root == "commands":
                    commands_module_aliases.add(bound)
                elif root == "pty":
                    pty_module_aliases.add(bound)
        elif isinstance(node, ast.ImportFrom):
            module = str(node.module or "")
            if module == "os":
                for alias in node.names:
                    if alias.name in os_exec_attrs:
                        os_exec_aliases.add(alias.asname or alias.name)
            elif module == "subprocess":
                for alias in node.names:
                    if alias.name in subprocess_exec_attrs:
                        subprocess_exec_aliases.add(alias.asname or alias.name)
            elif module == "commands":
                for alias in node.names:
                    if alias.name in commands_exec_attrs:
                        commands_exec_aliases.add(alias.asname or alias.name)
            elif module == "pty":
                for alias in node.names:
                    if alias.name == "spawn":
                        pty_exec_aliases.add(alias.asname or alias.name)
    direct_aliases = (
        os_exec_aliases
        | subprocess_exec_aliases
        | commands_exec_aliases
        | pty_exec_aliases
    )

    def _expr_is_wrapper_execution_callable(node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in direct_aliases
        if isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Name) or node.func.id != "getattr":
                return False
            if len(node.args) < 2:
                return False
            attr = _python_constant_or_bound_string(node.args[1], string_bindings)
            receiver = node.args[0]
            if not isinstance(receiver, ast.Name) or not attr:
                return False
            if receiver.id in os_module_aliases and attr in os_exec_attrs:
                return True
            if receiver.id in subprocess_module_aliases and attr in subprocess_exec_attrs:
                return True
            if receiver.id in commands_module_aliases and attr in commands_exec_attrs:
                return True
            return receiver.id in pty_module_aliases and attr == "spawn"
        if not isinstance(node, ast.Attribute):
            return False
        if (
            isinstance(node.value, ast.Name)
            and node.value.id in os_module_aliases
            and node.attr in os_exec_attrs
        ):
            return True
        if (
            isinstance(node.value, ast.Name)
            and node.value.id in subprocess_module_aliases
            and node.attr in subprocess_exec_attrs
        ):
            return True
        if (
            isinstance(node.value, ast.Name)
            and node.value.id in commands_module_aliases
            and node.attr in commands_exec_attrs
        ):
            return True
        if (
            isinstance(node.value, ast.Name)
            and node.value.id in pty_module_aliases
            and node.attr == "spawn"
        ):
            return True
        return False

    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            if not _expr_is_wrapper_execution_callable(node.value):
                continue
            for target in node.targets:
                for target_name in _python_assignment_target_names(target):
                    if target_name not in direct_aliases:
                        direct_aliases.add(target_name)
                        changed = True

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _expr_is_wrapper_execution_callable(node.func):
            return True
    return False


def _python_has_socket_or_raw_network(text: str) -> bool:
    return bool(re.search(
        r"\b(?:socket|smtplib|ftplib|telnetlib)\b|"
        r"\bhttp\.client\b|"
        r"\.(?:connect|connect_ex|sendall|sendto)\s*\(",
        text,
    ))


def _python_path_constructor_literals(text: str) -> list[str]:
    return re.findall(r"(?:Path|pathlib\.Path)\(\s*['\"]([^'\"]+)['\"]\s*\)", text)


def _python_path_variable_bindings(text: str) -> dict[str, str]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return {}
    if _python_has_dynamic_namespace_mutation(tree):
        return {}
    assignment_counts = _python_name_assignment_counts(tree)
    shadowed_names = _python_lexical_shadow_binding_names(tree, include_loop_targets=True)
    bindings: dict[str, str] = {
        name: path
        for name, path in _python_sys_argv_assignment_bindings(tree).items()
        if name not in shadowed_names
    }
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            assignment = _python_single_name_assignment(node)
            if assignment is None:
                continue
            target_name, value = assignment
            if assignment_counts.get(target_name) != 1 or target_name in shadowed_names:
                continue
            path = _python_static_scalar_path_value(value, bindings)
            if path and bindings.get(target_name) != path:
                bindings[target_name] = path
                changed = True
    bindings.update(_python_task_data_walk_dynamic_path_bindings(tree, seed_bindings=bindings))
    return bindings


def _python_single_name_assignment(node: ast.AST) -> tuple[str, ast.AST] | None:
    if isinstance(node, ast.Assign):
        if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            return None
        return node.targets[0].id, node.value
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        return node.target.id, node.value
    if isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
        return node.target.id, node.value
    return None


def _python_static_scalar_path_value(node: ast.AST | None, bindings: dict[str, str]) -> str:
    if node is None:
        return ""
    if isinstance(node, ast.Name):
        return bindings.get(node.id, "")
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value if _python_literal_is_path_like(node.value) else ""
    if isinstance(node, ast.Call) and _python_call_is_path_constructor(node):
        if not node.args:
            return ""
        first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return first.value if _python_literal_is_path_like(first.value) else ""
        if isinstance(first, ast.Name):
            return bindings.get(first.id, "")
        return ""
    if isinstance(node, ast.Attribute) and node.attr == "with_suffix":
        return ""
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "with_suffix"
        and isinstance(node.func.value, ast.Name)
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
    ):
        base_path = bindings.get(node.func.value.id, "")
        return _path_with_suffix(base_path, node.args[0].value) if base_path else ""
    if (
        isinstance(node, ast.BinOp)
        and isinstance(node.op, ast.Div)
        and isinstance(node.left, ast.Name)
        and isinstance(node.right, ast.Constant)
        and isinstance(node.right.value, str)
    ):
        base_path = bindings.get(node.left.id, "")
        fragment = node.right.value.strip().strip("/")
        if base_path and fragment and ".." not in PurePosixPath(fragment).parts:
            return posixpath.join(base_path, fragment)
    return ""


def _python_literal_is_path_like(value: str) -> bool:
    return not _URL_RE.match(value) and ("/" in value or value.startswith(("~", ".")))


def _python_name_assignment_counts(tree: ast.AST) -> dict[str, int]:
    counts: dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                for name in _python_assignment_target_names(target):
                    counts[name] = counts.get(name, 0) + 1
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
            for name in _python_assignment_target_names(node.target):
                counts[name] = counts.get(name, 0) + 1
    return counts


def _python_lexical_shadow_binding_names(
    tree: ast.AST,
    *,
    include_loop_targets: bool,
) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            args = node.args
            all_args = list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs)
            for arg in all_args:
                names.add(arg.arg)
            if args.vararg is not None:
                names.add(args.vararg.arg)
            if args.kwarg is not None:
                names.add(args.kwarg.arg)
            continue
        if isinstance(node, ast.comprehension):
            names.update(_python_assignment_target_names(node.target))
            continue
        if isinstance(node, ast.ExceptHandler) and isinstance(node.name, str):
            names.add(node.name)
            continue
        if isinstance(node, ast.withitem) and node.optional_vars is not None:
            names.update(_python_assignment_target_names(node.optional_vars))
            continue
        if include_loop_targets and isinstance(node, (ast.For, ast.AsyncFor)):
            names.update(_python_assignment_target_names(node.target))
            continue
        if isinstance(node, ast.Match):
            for case in node.cases:
                names.update(_python_match_pattern_binding_names(case.pattern))
    return names


def _python_match_pattern_binding_names(pattern: ast.AST) -> set[str]:
    names: set[str] = set()
    if isinstance(pattern, ast.MatchAs):
        if pattern.name:
            names.add(pattern.name)
        if pattern.pattern is not None:
            names.update(_python_match_pattern_binding_names(pattern.pattern))
        return names
    if isinstance(pattern, ast.MatchStar):
        if pattern.name:
            names.add(pattern.name)
        return names
    if isinstance(pattern, ast.MatchMapping):
        if pattern.rest:
            names.add(pattern.rest)
        for child in pattern.patterns:
            names.update(_python_match_pattern_binding_names(child))
        return names
    if isinstance(pattern, ast.MatchSequence):
        for child in pattern.patterns:
            names.update(_python_match_pattern_binding_names(child))
        return names
    if isinstance(pattern, ast.MatchClass):
        for child in list(pattern.patterns) + list(pattern.kwd_patterns):
            names.update(_python_match_pattern_binding_names(child))
        return names
    if isinstance(pattern, ast.MatchOr):
        for child in pattern.patterns:
            names.update(_python_match_pattern_binding_names(child))
    return names


def _python_has_dynamic_namespace_mutation(tree: ast.AST) -> bool:
    namespace_names, namespace_function_names, operator_modules, operator_setitem_functions, dict_type_names = (
        _python_dynamic_namespace_aliases(tree)
    )
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            if any(
                _python_target_is_dynamic_namespace_mutation(
                    target,
                    namespace_names=namespace_names,
                    namespace_function_names=namespace_function_names,
                )
                for target in node.targets
            ):
                return True
            continue
        if isinstance(node, (ast.AugAssign, ast.AnnAssign)):
            if _python_target_is_dynamic_namespace_mutation(
                node.target,
                namespace_names=namespace_names,
                namespace_function_names=namespace_function_names,
            ):
                return True
            continue
        if not isinstance(node, ast.Call):
            continue
        if _python_call_is_operator_setitem(
            node,
            operator_modules=operator_modules,
            operator_setitem_functions=operator_setitem_functions,
            namespace_names=namespace_names,
            namespace_function_names=namespace_function_names,
        ):
            return True
        if not isinstance(node.func, ast.Attribute):
            continue
        if (
            node.func.attr in {"__setitem__", "update", "setdefault", "pop", "popitem", "clear"}
            and _python_expr_is_dynamic_namespace(
                node.func.value,
                namespace_names=namespace_names,
                namespace_function_names=namespace_function_names,
            )
        ):
            return True
        if (
            node.func.attr in {"__setitem__", "update"}
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in dict_type_names
            and node.args
            and _python_expr_is_dynamic_namespace(
                node.args[0],
                namespace_names=namespace_names,
                namespace_function_names=namespace_function_names,
            )
        ):
            return True
    return False


def _python_dynamic_namespace_aliases(
    tree: ast.AST,
) -> tuple[set[str], set[str], set[str], set[str], set[str]]:
    namespace_names: set[str] = set()
    namespace_function_names = {"globals", "locals", "vars"}
    operator_modules = {"operator"}
    operator_setitem_functions: set[str] = set()
    dict_type_names = {"dict"}
    name_value_pairs: list[tuple[str, ast.AST]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "operator":
                    operator_modules.add(alias.asname or alias.name)
            continue
        if isinstance(node, ast.ImportFrom):
            if node.module == "operator":
                for alias in node.names:
                    if alias.name == "setitem":
                        operator_setitem_functions.add(alias.asname or alias.name)
            continue
        name_value_pairs.extend(_python_assignment_name_value_pairs(node))
        name_value_pairs.extend(_python_default_arg_name_value_pairs(node))
    changed = True
    while changed:
        changed = False
        for target_name, value in name_value_pairs:
            if _python_expr_is_direct_dynamic_namespace_call(value):
                if target_name not in namespace_names:
                    namespace_names.add(target_name)
                    changed = True
                continue
            if isinstance(value, ast.Name):
                if value.id in namespace_names and target_name not in namespace_names:
                    namespace_names.add(target_name)
                    changed = True
                if value.id in namespace_function_names and target_name not in namespace_function_names:
                    namespace_function_names.add(target_name)
                    changed = True
                if value.id in operator_modules and target_name not in operator_modules:
                    operator_modules.add(target_name)
                    changed = True
                if value.id in operator_setitem_functions and target_name not in operator_setitem_functions:
                    operator_setitem_functions.add(target_name)
                    changed = True
                if value.id in dict_type_names and target_name not in dict_type_names:
                    dict_type_names.add(target_name)
                    changed = True
                continue
            if (
                isinstance(value, ast.Attribute)
                and value.attr == "setitem"
                and isinstance(value.value, ast.Name)
                and value.value.id in operator_modules
                and target_name not in operator_setitem_functions
            ):
                operator_setitem_functions.add(target_name)
                changed = True
    return namespace_names, namespace_function_names, operator_modules, operator_setitem_functions, dict_type_names


def _python_target_is_dynamic_namespace_mutation(
    node: ast.AST,
    *,
    namespace_names: set[str],
    namespace_function_names: set[str],
) -> bool:
    if isinstance(node, ast.Subscript):
        return _python_expr_is_dynamic_namespace(
            node.value,
            namespace_names=namespace_names,
            namespace_function_names=namespace_function_names,
        )
    return False


def _python_expr_is_dynamic_namespace(
    node: ast.AST,
    *,
    namespace_names: set[str],
    namespace_function_names: set[str],
) -> bool:
    if isinstance(node, ast.Name):
        return node.id in namespace_names
    if not isinstance(node, ast.Call):
        return False
    if _python_expr_is_direct_dynamic_namespace_call(node):
        return True
    return isinstance(node.func, ast.Name) and node.func.id in namespace_function_names


def _python_expr_is_direct_dynamic_namespace_call(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    return isinstance(node.func, ast.Name) and node.func.id in {"globals", "locals", "vars"}


def _python_call_is_operator_setitem(
    node: ast.Call,
    *,
    operator_modules: set[str],
    operator_setitem_functions: set[str],
    namespace_names: set[str],
    namespace_function_names: set[str],
) -> bool:
    if not node.args:
        return False
    func = node.func
    is_setitem = False
    if isinstance(func, ast.Name):
        is_setitem = func.id in operator_setitem_functions
    elif isinstance(func, ast.Attribute):
        is_setitem = (
            func.attr == "setitem"
            and isinstance(func.value, ast.Name)
            and func.value.id in operator_modules
        )
    if not is_setitem:
        return False
    return _python_expr_is_dynamic_namespace(
        node.args[0],
        namespace_names=namespace_names,
        namespace_function_names=namespace_function_names,
    )


def _python_sys_argv_assignment_bindings(tree: ast.AST) -> dict[str, str]:
    argv_bindings = _PYTHON_ARGV_PATH_BINDINGS.get()
    if not argv_bindings:
        return {}
    bindings: dict[str, str] = {}
    for node in ast.walk(tree):
        value: ast.AST | None = None
        targets: list[ast.AST] = []
        if isinstance(node, ast.Assign):
            value = node.value
            targets = list(node.targets)
        elif isinstance(node, ast.AnnAssign):
            value = node.value
            targets = [node.target]
        elif isinstance(node, ast.NamedExpr):
            value = node.value
            targets = [node.target]
        if value is None:
            continue
        index = _python_sys_argv_path_value_index(value)
        if index is None or index not in argv_bindings:
            continue
        for target in targets:
            if isinstance(target, ast.Name):
                bindings[target.id] = argv_bindings[index]
    return bindings


def _python_sys_argv_path_value_index(node: ast.AST) -> int | None:
    index = _python_sys_argv_subscript_index(node)
    if index is not None:
        return index
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Name) and func.id in {"str", "bytes"} and len(node.args) == 1:
            return _python_sys_argv_path_value_index(node.args[0])
        if _python_call_is_path_constructor(node) and node.args:
            return _python_sys_argv_path_value_index(node.args[0])
    return None


def _python_task_data_walk_dynamic_path_bindings(
    tree: ast.AST,
    *,
    seed_bindings: dict[str, str] | None = None,
) -> dict[str, str]:
    seed_bindings = seed_bindings or {}
    walk_root_names, walk_child_names, os_modules, join_functions = _python_task_data_dynamic_join_context(
        tree,
        seed_bindings=seed_bindings,
    )
    if not walk_root_names and not walk_child_names:
        return {}

    assignment_counts: dict[str, int] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            for name in _python_assignment_target_names(target):
                assignment_counts[name] = assignment_counts.get(name, 0) + 1

    safe_bindings: dict[str, str] = {}
    safe_candidates: dict[str, set[str]] = {}
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            base = _python_safe_task_data_join_or_alias_base(
                node.value,
                walk_root_names=walk_root_names,
                walk_child_names=walk_child_names,
                safe_bindings=safe_bindings,
                seed_bindings=seed_bindings,
                os_modules=os_modules,
                join_functions=join_functions,
            )
            if not base:
                continue
            for target in node.targets:
                for name in _python_assignment_target_names(target):
                    bases = safe_candidates.setdefault(name, set())
                    bases.add(base)
                    if assignment_counts.get(name) == 1 and len(bases) == 1 and safe_bindings.get(name) != base:
                        safe_bindings[name] = base
                        changed = True
    return {
        name: base
        for name, base in safe_bindings.items()
        if assignment_counts.get(name) == 1 and len(safe_candidates.get(name, set())) == 1
    }


def _python_task_data_dynamic_join_context(
    tree: ast.AST,
    *,
    seed_bindings: dict[str, str],
) -> tuple[dict[str, str], set[str], set[str], set[str]]:
    os_modules, walk_functions, listdir_functions, join_functions = _python_os_walk_join_aliases(tree)
    walk_root_names: dict[str, str] = {}
    walk_child_collection_names: set[str] = set()
    task_data_child_names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.For):
            continue
        base = _python_os_walk_task_data_base(
            node.iter,
            os_modules=os_modules,
            walk_functions=walk_functions,
            seed_bindings=seed_bindings,
        )
        if base:
            target_elts = node.target.elts if isinstance(node.target, (ast.Tuple, ast.List)) else []
            if target_elts and isinstance(target_elts[0], ast.Name):
                walk_root_names[target_elts[0].id] = base
            if len(target_elts) > 1 and isinstance(target_elts[1], ast.Name):
                walk_child_collection_names.add(target_elts[1].id)
            if len(target_elts) > 2 and isinstance(target_elts[2], ast.Name):
                walk_child_collection_names.add(target_elts[2].id)
        listdir_base = _python_os_listdir_task_data_base(
            node.iter,
            os_modules=os_modules,
            listdir_functions=listdir_functions,
            seed_bindings=seed_bindings,
        )
        if listdir_base and isinstance(node.target, ast.Name):
            task_data_child_names.add(node.target.id)
    if not walk_root_names and not task_data_child_names:
        return {}, set(), os_modules, join_functions

    unsafe_collection_names = _python_walk_child_collection_unsafe_names(
        tree,
        walk_child_collection_names,
    )
    trusted_collection_names = walk_child_collection_names - unsafe_collection_names
    walk_child_names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.For):
            continue
        if not _python_expr_iterates_walk_child_names(node.iter, trusted_collection_names):
            continue
        for target_name in _python_assignment_target_names(node.target):
            walk_child_names.add(target_name)
    walk_child_names.update(task_data_child_names)
    walk_child_names = walk_child_names - _python_reassigned_names(tree, walk_child_names)
    return walk_root_names, walk_child_names, os_modules, join_functions


def _python_walk_child_collection_unsafe_names(
    tree: ast.AST,
    collection_names: set[str],
) -> set[str]:
    if not collection_names:
        return set()
    aliases: dict[str, str] = {name: name for name in collection_names}
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            root = _python_walk_collection_alias_root(node.value, aliases)
            if not root:
                continue
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id not in aliases:
                    aliases[target.id] = root
                    changed = True

    mutator_aliases: dict[str, str] = {}
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            root = _python_walk_collection_mutator_alias_root(
                node.value,
                collection_aliases=aliases,
                mutator_aliases=mutator_aliases,
            )
            if not root:
                continue
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id not in mutator_aliases:
                    mutator_aliases[target.id] = root
                    changed = True

    unsafe: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            value_alias_root = _python_walk_collection_alias_root(node.value, aliases)
            for target in node.targets:
                if (
                    value_alias_root
                    and isinstance(target, ast.Name)
                    and target.id not in collection_names
                ):
                    continue
                root = _python_walk_collection_target_root(target, aliases)
                if root:
                    unsafe.add(root)
            continue
        if isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            targets = [node.target]
            for target in targets:
                root = _python_walk_collection_target_root(target, aliases)
                if root:
                    unsafe.add(root)
            continue
        if isinstance(node, ast.Delete):
            for target in node.targets:
                root = _python_walk_collection_target_root(target, aliases)
                if root:
                    unsafe.add(root)
            continue
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            root = mutator_aliases.get(node.func.id, "")
            if root:
                unsafe.add(root)
            continue
        if isinstance(node.func, ast.Attribute):
            if node.func.attr not in _PYTHON_LIST_CONTENT_POLLUTING_METHOD_NAMES:
                continue
            root = _python_walk_collection_alias_root(node.func.value, aliases)
            if root:
                unsafe.add(root)
    return unsafe


def _python_walk_collection_alias_root(node: ast.AST, aliases: dict[str, str]) -> str:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, "")
    return ""


def _python_walk_collection_target_root(node: ast.AST, aliases: dict[str, str]) -> str:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, "")
    if isinstance(node, (ast.Subscript, ast.Attribute)):
        return _python_walk_collection_alias_root(node.value, aliases)
    return ""


def _python_walk_collection_mutator_alias_root(
    node: ast.AST,
    *,
    collection_aliases: dict[str, str],
    mutator_aliases: dict[str, str],
) -> str:
    if isinstance(node, ast.Name):
        return mutator_aliases.get(node.id, "")
    if not isinstance(node, ast.Attribute):
        return ""
    if node.attr not in _PYTHON_LIST_CONTENT_POLLUTING_METHOD_NAMES:
        return ""
    return _python_walk_collection_alias_root(node.value, collection_aliases)


def _python_reassigned_names(tree: ast.AST, candidate_names: set[str]) -> set[str]:
    reassigned: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                reassigned.update(set(_python_assignment_target_names(target)) & candidate_names)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
            reassigned.update(set(_python_assignment_target_names(node.target)) & candidate_names)
        elif isinstance(node, ast.Delete):
            for target in node.targets:
                reassigned.update(set(_python_assignment_target_names(target)) & candidate_names)
    return reassigned


def _python_os_walk_join_aliases(tree: ast.AST) -> tuple[set[str], set[str], set[str], set[str]]:
    os_modules = {"os"}
    walk_functions: set[str] = set()
    listdir_functions: set[str] = set()
    join_functions: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", 1)[0]
                if root == "os":
                    os_modules.add(alias.asname or root)
        elif isinstance(node, ast.ImportFrom):
            module = str(node.module or "")
            if module == "os":
                for alias in node.names:
                    if alias.name == "walk":
                        walk_functions.add(alias.asname or alias.name)
                    elif alias.name == "listdir":
                        listdir_functions.add(alias.asname or alias.name)
            elif module == "os.path":
                for alias in node.names:
                    if alias.name == "join":
                        join_functions.add(alias.asname or alias.name)
    return os_modules, walk_functions, listdir_functions, join_functions


def _python_os_walk_task_data_base(
    node: ast.AST,
    *,
    os_modules: set[str],
    walk_functions: set[str],
    seed_bindings: dict[str, str],
) -> str:
    if not isinstance(node, ast.Call) or not node.args:
        return ""
    if not _python_call_is_os_walk(node, os_modules=os_modules, walk_functions=walk_functions):
        return ""
    if len(node.args) >= 4 and not _python_ast_is_constant_false(node.args[3]):
        return ""
    for keyword in node.keywords:
        if keyword.arg == "followlinks" and not _python_ast_is_constant_false(keyword.value):
            return ""
    path = _python_static_path_arg_value(node.args[0], seed_bindings)
    if not path:
        return ""
    base = _glob_base_path(path)
    return base if _is_scope_task_data_path(base) else ""


def _python_call_is_os_walk(
    node: ast.Call,
    *,
    os_modules: set[str],
    walk_functions: set[str],
) -> bool:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id in walk_functions
    return (
        isinstance(func, ast.Attribute)
        and func.attr == "walk"
        and isinstance(func.value, ast.Name)
        and func.value.id in os_modules
    )


def _python_os_listdir_task_data_base(
    node: ast.AST,
    *,
    os_modules: set[str],
    listdir_functions: set[str],
    seed_bindings: dict[str, str],
) -> str:
    if isinstance(node, ast.Subscript):
        return _python_os_listdir_task_data_base(
            node.value,
            os_modules=os_modules,
            listdir_functions=listdir_functions,
            seed_bindings=seed_bindings,
        )
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Name) and func.id in {"list", "tuple", "sorted", "set", "iter", "reversed"}:
            return (
                _python_os_listdir_task_data_base(
                    node.args[0],
                    os_modules=os_modules,
                    listdir_functions=listdir_functions,
                    seed_bindings=seed_bindings,
                )
                if node.args
                else ""
            )
        if _python_call_is_os_listdir(node, os_modules=os_modules, listdir_functions=listdir_functions):
            path = _python_static_path_arg_value(node.args[0], seed_bindings) if node.args else ""
            if not path:
                return ""
            base = _glob_base_path(path)
            return base if _is_scope_task_data_path(base) else ""
    return ""


def _python_call_is_os_listdir(
    node: ast.Call,
    *,
    os_modules: set[str],
    listdir_functions: set[str],
) -> bool:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id in listdir_functions
    return (
        isinstance(func, ast.Attribute)
        and func.attr == "listdir"
        and isinstance(func.value, ast.Name)
        and func.value.id in os_modules
    )


def _python_static_path_arg_value(node: ast.AST, seed_bindings: dict[str, str]) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return seed_bindings.get(node.id, "")
    return ""


def _python_ast_is_constant_false(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _python_expr_iterates_walk_child_names(node: ast.AST, collection_names: set[str]) -> bool:
    if isinstance(node, ast.Name):
        return node.id in collection_names
    if isinstance(node, ast.Subscript):
        return _python_expr_iterates_walk_child_names(node.value, collection_names)
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Name) and func.id in {"list", "tuple", "sorted", "set", "iter", "reversed"}:
            return bool(node.args) and _python_expr_iterates_walk_child_names(node.args[0], collection_names)
    return False


def _python_safe_task_data_join_or_alias_base(
    node: ast.AST,
    *,
    walk_root_names: dict[str, str],
    walk_child_names: set[str],
    safe_bindings: dict[str, str],
    seed_bindings: dict[str, str],
    os_modules: set[str],
    join_functions: set[str],
) -> str:
    if isinstance(node, ast.Name):
        return safe_bindings.get(node.id, "")
    if not isinstance(node, ast.Call):
        return ""
    if not _python_call_is_os_path_join(node, os_modules=os_modules, join_functions=join_functions):
        return ""
    if not node.args:
        return ""
    base = ""
    first = node.args[0]
    if isinstance(first, ast.Name):
        base = walk_root_names.get(first.id, "") or safe_bindings.get(first.id, "")
        if not base:
            candidate = _glob_base_path(seed_bindings.get(first.id, ""))
            if _is_scope_task_data_path(candidate):
                base = candidate
    elif isinstance(first, ast.Constant) and isinstance(first.value, str):
        candidate = _glob_base_path(first.value)
        if _is_scope_task_data_path(candidate):
            base = candidate
    if not base:
        return ""
    for fragment in node.args[1:]:
        if not _python_walk_join_fragment_is_safe(fragment, walk_child_names):
            return ""
    return base


def _python_call_is_os_path_join(
    node: ast.Call,
    *,
    os_modules: set[str],
    join_functions: set[str],
) -> bool:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id in join_functions
    return (
        isinstance(func, ast.Attribute)
        and func.attr == "join"
        and isinstance(func.value, ast.Attribute)
        and func.value.attr == "path"
        and isinstance(func.value.value, ast.Name)
        and func.value.value.id in os_modules
    )


def _python_walk_join_fragment_is_safe(node: ast.AST, walk_child_names: set[str]) -> bool:
    if isinstance(node, ast.Name):
        return node.id in walk_child_names
    if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
        return False
    fragment = node.value.strip()
    if not fragment or fragment.startswith(("/", "~")):
        return False
    return ".." not in PurePosixPath(fragment).parts


def _python_path_sequence_variable_bindings(text: str) -> dict[str, list[str]]:
    bindings: dict[str, list[str]] = {}
    list_bindings: dict[str, list[str]] = {}
    fragment_list_bindings: dict[str, list[str]] = {}
    fragment_loop_bindings: dict[str, list[str]] = {}
    try:
        tree = ast.parse(text)
    except SyntaxError:
        tree = None
    if tree is not None:
        if _python_has_dynamic_namespace_mutation(tree):
            return {}
        assignment_counts = _python_name_assignment_counts(tree)
        shadowed_names = _python_lexical_shadow_binding_names(tree, include_loop_targets=False)
        mutated_names = _python_mutated_sequence_binding_names(tree)
        scalar_bindings = _python_path_variable_bindings(text)
        changed = True
        while changed:
            changed = False
            for node in ast.walk(tree):
                if not isinstance(node, ast.Assign):
                    continue
                if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
                    continue
                target_name = node.targets[0].id
                if (
                    assignment_counts.get(target_name) != 1
                    or target_name in mutated_names
                    or target_name in shadowed_names
                ):
                    continue
                paths = _python_literal_path_sequence_from_ast(node.value)
                if paths and list_bindings.get(target_name) != paths:
                    list_bindings[target_name] = list(paths)
                    changed = True
                fragments = _python_literal_relative_fragment_sequence_from_ast(node.value)
                if fragments and fragment_list_bindings.get(target_name) != fragments:
                    fragment_list_bindings[target_name] = list(fragments)
                    changed = True
        for node in ast.walk(tree):
            if not isinstance(node, ast.For):
                continue
            paths: list[str] = []
            fragments: list[str] = []
            if isinstance(node.iter, ast.Name):
                paths = list_bindings.get(node.iter.id, [])
                fragments = fragment_list_bindings.get(node.iter.id, [])
                if not paths and not fragments:
                    paths = _python_static_mapping_key_paths_from_iter(node.iter, tree)
                    fragments = _python_static_mapping_key_fragments_from_iter(node.iter, tree)
            elif isinstance(node.iter, (ast.List, ast.Tuple)):
                paths = _python_literal_path_sequence_from_ast(node.iter)
                fragments = _python_literal_relative_fragment_sequence_from_ast(node.iter)
            else:
                paths = _python_static_mapping_key_paths_from_iter(node.iter, tree)
                fragments = _python_static_mapping_key_fragments_from_iter(node.iter, tree)
            if not paths and not fragments:
                continue
            target_name: str | None = None
            if isinstance(node.target, ast.Name):
                target_name = node.target.id
            elif (
                isinstance(node.target, ast.Tuple)
                and node.target.elts
                and isinstance(node.target.elts[0], ast.Name)
            ):
                target_name = node.target.elts[0].id
            if not target_name or target_name in shadowed_names:
                continue
            if paths:
                bindings[target_name] = paths
            if fragments:
                fragment_loop_bindings[target_name] = fragments
        string_bindings = _python_string_literal_bindings(tree)
        changed = True
        while changed:
            changed = False
            for node in ast.walk(tree):
                if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                    continue
                target = node.targets[0]
                if not isinstance(target, ast.Name):
                    continue
                if (
                    assignment_counts.get(target.id) != 1
                    or target.id in mutated_names
                    or target.id in shadowed_names
                ):
                    continue
                value = node.value
                paths = _python_static_path_sequence_value(
                    value,
                    scalar_bindings=scalar_bindings,
                    string_bindings=string_bindings,
                    path_sequence_bindings=bindings,
                    fragment_sequence_bindings=fragment_loop_bindings | fragment_list_bindings,
                )
                if paths and bindings.get(target.id) != paths:
                    bindings[target.id] = list(paths)
                    changed = True
    return bindings


def _python_static_mapping_key_paths_from_iter(node: ast.AST, tree: ast.AST) -> list[str]:
    dict_node = _python_static_mapping_dict_from_iter(node, tree)
    if dict_node is None:
        return []
    paths: list[str] = []
    for key in dict_node.keys:
        path = _python_literal_path_sequence_item_value(key)
        if path:
            paths.append(path)
    return _dedupe_strings(paths)


def _python_static_path_sequence_value(
    node: ast.AST,
    *,
    scalar_bindings: dict[str, str],
    string_bindings: dict[str, str],
    path_sequence_bindings: dict[str, list[str]],
    fragment_sequence_bindings: dict[str, list[str]],
) -> list[str]:
    if isinstance(node, ast.Name):
        return list(path_sequence_bindings.get(node.id, []))
    if isinstance(node, ast.Call) and _python_call_is_path_constructor(node):
        if not node.args:
            return []
        return _python_static_path_sequence_value(
            node.args[0],
            scalar_bindings=scalar_bindings,
            string_bindings=string_bindings,
            path_sequence_bindings=path_sequence_bindings,
            fragment_sequence_bindings=fragment_sequence_bindings,
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Div)):
        left_base = _python_static_scalar_path_value(
            node.left,
            scalar_bindings,
        ) or _python_static_string_expr_value(node.left, string_bindings)
        right_fragments = _python_static_relative_fragment_sequence_value(
            node.right,
            string_bindings,
            fragment_sequence_bindings,
        )
        if left_base and _python_literal_is_path_like(left_base) and right_fragments:
            return [posixpath.join(left_base, fragment) for fragment in right_fragments]
        right_base = _python_static_scalar_path_value(
            node.right,
            scalar_bindings,
        ) or _python_static_string_expr_value(node.right, string_bindings)
        left_fragments = _python_static_relative_fragment_sequence_value(
            node.left,
            string_bindings,
            fragment_sequence_bindings,
        )
        if isinstance(node.op, ast.Add) and right_base and _python_literal_is_path_like(right_base) and left_fragments:
            return [posixpath.join(right_base, fragment) for fragment in left_fragments]
    return []


def _python_static_mapping_key_fragments_from_iter(node: ast.AST, tree: ast.AST) -> list[str]:
    dict_node = _python_static_mapping_dict_from_iter(node, tree)
    if dict_node is None:
        return []
    fragments: list[str] = []
    for key in dict_node.keys:
        fragment = _python_static_relative_path_fragment(key)
        if fragment is not None:
            fragments.append(fragment)
    return _dedupe_strings(fragments)


def _python_static_mapping_dict_from_iter(node: ast.AST, tree: ast.AST) -> ast.Dict | None:
    if isinstance(node, ast.Name):
        return _python_static_safe_dict_literal_bindings(tree).get(node.id)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"items", "keys"}
        and isinstance(node.func.value, ast.Name)
    ):
        return _python_static_safe_dict_literal_bindings(tree).get(node.func.value.id)
    return None


def _python_static_relative_fragment_sequence_value(
    node: ast.AST,
    string_bindings: dict[str, str],
    fragment_sequence_bindings: dict[str, list[str]],
) -> list[str]:
    if isinstance(node, ast.Name):
        if node.id in fragment_sequence_bindings:
            return list(fragment_sequence_bindings[node.id])
        value = string_bindings.get(node.id, "")
        return [value] if _python_is_safe_relative_path_fragment(value) else []
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value] if _python_is_safe_relative_path_fragment(node.value) else []
    return []


def _python_literal_path_sequence_from_ast(node: ast.AST) -> list[str]:
    if not isinstance(node, (ast.List, ast.Tuple)):
        return []
    paths: list[str] = []
    for item in node.elts:
        value = _python_literal_path_sequence_item_value(item)
        if not value:
            return []
        paths.append(value)
    return paths


def _python_literal_relative_fragment_sequence_from_ast(node: ast.AST) -> list[str]:
    if not isinstance(node, (ast.List, ast.Tuple)):
        return []
    fragments: list[str] = []
    for item in node.elts:
        if not isinstance(item, ast.Constant) or not isinstance(item.value, str):
            return []
        value = item.value
        if not _python_is_safe_relative_path_fragment(value):
            return []
        fragments.append(value)
    return fragments


def _python_is_safe_relative_path_fragment(value: str) -> bool:
    fragment = str(value or "").strip()
    if not fragment or _URL_RE.match(fragment) or fragment.startswith(("/", "~")):
        return False
    return ".." not in PurePosixPath(fragment).parts


def _python_literal_path_sequence_item_value(node: ast.AST) -> str:
    item = node
    if isinstance(item, (ast.List, ast.Tuple)):
        if not item.elts:
            return ""
        item = item.elts[0]
    if isinstance(item, ast.Call) and _python_call_is_path_constructor(item):
        if not item.args:
            return ""
        item = item.args[0]
    if not isinstance(item, ast.Constant) or not isinstance(item.value, str):
        return ""
    value = item.value
    if _URL_RE.match(value) or ("/" not in value and not value.startswith(("~", "."))):
        return ""
    return value


def _python_mutated_sequence_binding_names(tree: ast.AST) -> set[str]:
    mutated: set[str] = set()
    literal_sequence_names = _python_literal_sequence_candidate_names(tree)
    mutated.update(_python_literal_sequence_escaped_candidate_names(tree, literal_sequence_names))
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            escaped_names = _python_literal_sequence_names_in_ast(node.value, literal_sequence_names)
            if escaped_names:
                mutated.update(escaped_names)
            if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                target_name = node.targets[0].id
                if isinstance(node.value, ast.Name) and (
                    target_name in literal_sequence_names or node.value.id in literal_sequence_names
                ):
                    mutated.add(target_name)
                    mutated.add(node.value.id)
                    continue
                if isinstance(node.value, ast.Attribute) and node.value.attr in _PYTHON_LIST_CONTENT_POLLUTING_METHOD_NAMES:
                    root = _python_sequence_binding_root_name(node.value.value)
                    if root in literal_sequence_names:
                        mutated.add(root)
                    continue
            for target in node.targets:
                root = _python_sequence_binding_root_name(target)
                if root and not isinstance(target, ast.Name):
                    mutated.add(root)
            continue
        if isinstance(node, (ast.AugAssign, ast.AnnAssign)):
            value = getattr(node, "value", None)
            if isinstance(value, ast.AST):
                mutated.update(_python_literal_sequence_names_in_ast(value, literal_sequence_names))
            root = _python_sequence_binding_root_name(node.target)
            if root:
                mutated.add(root)
            continue
        if isinstance(node, ast.Delete):
            for target in node.targets:
                root = _python_sequence_binding_root_name(target)
                if root:
                    mutated.add(root)
            continue
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in _PYTHON_LIST_CONTENT_POLLUTING_METHOD_NAMES:
            continue
        receiver = node.func.value
        if isinstance(receiver, ast.Name):
            mutated.add(receiver.id)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for arg in list(node.args) + [keyword.value for keyword in node.keywords]:
            mutated.update(_python_literal_sequence_names_in_ast(arg, literal_sequence_names))
    return mutated


def _python_literal_sequence_escaped_candidate_names(
    tree: ast.AST,
    literal_sequence_names: set[str],
) -> set[str]:
    if not literal_sequence_names:
        return set()
    allowed_name_node_ids: set[int] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id in literal_sequence_names
            and _python_literal_path_sequence_from_ast(node.value)
        ):
            allowed_name_node_ids.add(id(node.targets[0]))
            continue
        if isinstance(node, ast.For) and isinstance(node.iter, ast.Name):
            if node.iter.id in literal_sequence_names:
                allowed_name_node_ids.add(id(node.iter))
    escaped: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Name)
            and node.id in literal_sequence_names
            and id(node) not in allowed_name_node_ids
        ):
            escaped.add(node.id)
    return escaped


def _python_literal_sequence_names_in_ast(node: ast.AST, literal_sequence_names: set[str]) -> set[str]:
    names: set[str] = set()
    for item in ast.walk(node):
        if isinstance(item, ast.Name) and item.id in literal_sequence_names:
            names.add(item.id)
    return names


def _python_literal_sequence_candidate_names(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            continue
        if _python_literal_path_sequence_from_ast(node.value):
            names.add(node.targets[0].id)
    return names


def _python_sequence_binding_root_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, (ast.Attribute, ast.Subscript)):
        return _python_sequence_binding_root_name(node.value)
    return ""


def _python_path_probe_targets(
    text: str,
    scalar_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
) -> list[str]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    os_path_probe_methods = {"exists", "isfile", "isdir", "getsize", "getmtime", "getctime", "getatime"}
    pathlib_probe_methods = {"exists", "is_file", "is_dir", "stat", "lstat"}
    targets: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        func = node.func
        if func.attr in os_path_probe_methods and _python_attr_is_os_path(func.value):
            if not node.args:
                continue
            resolved, probe_targets = _python_document_reader_arg_targets(
                node.args[0],
                scalar_bindings,
                sequence_bindings,
                set(),
                set(),
            )
            if resolved:
                targets.extend(probe_targets)
            continue
        if func.attr not in pathlib_probe_methods:
            continue
        resolved, probe_targets = _python_document_reader_arg_targets(
            func.value,
            scalar_bindings,
            sequence_bindings,
            set(),
            set(),
        )
        if resolved:
            targets.extend(probe_targets)
    return _dedupe_strings(targets)


def _python_path_probe_is_command_availability_probe(path: str) -> bool:
    normalized = normalize_task_artifact_path(path, cwd=_NORMALIZER_CWD.get())
    if not normalized or not normalized.startswith("/"):
        return False
    directory, _, name = normalized.rpartition("/")
    if directory not in _COMMAND_AVAILABILITY_PROBE_DIRS:
        return False
    if not name or _path_has_credential_marker(name):
        return False
    return re.fullmatch(r"[A-Za-z0-9_.+-]{1,80}", name) is not None


def _python_string_paths_from_ast(node: ast.AST) -> list[str]:
    paths: list[str] = []
    for item in ast.walk(node):
        if isinstance(item, ast.Constant) and isinstance(item.value, str):
            value = item.value
            if not _URL_RE.match(value) and ("/" in value or value.startswith(("~", "."))):
                paths.append(value)
    return paths


def _python_scope_task_data_literal_targets(text: str) -> list[str]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    targets: list[str] = []
    for path in _python_string_paths_from_ast(tree):
        target = _glob_base_path(path)
        if _is_scope_task_data_path(target):
            targets.append(target)
    return _dedupe_strings(targets)


def _python_enumerate_targets(
    text: str,
    path_bindings: dict[str, str] | None = None,
    path_sequence_bindings: dict[str, list[str]] | None = None,
) -> list[str]:
    scalar_bindings = path_bindings if path_bindings is not None else _python_path_variable_bindings(text)
    sequence_bindings = (
        path_sequence_bindings
        if path_sequence_bindings is not None
        else _python_path_sequence_variable_bindings(text)
    )
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []

    glob_modules = {"glob"}
    glob_functions: set[str] = set()
    os_modules = {"os"}
    os_functions: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.name.split(".", 1)[0]
                bound = alias.asname or name
                if name == "glob":
                    glob_modules.add(bound)
                elif name == "os":
                    os_modules.add(bound)
        elif isinstance(node, ast.ImportFrom):
            if node.module == "glob":
                for alias in node.names:
                    if alias.name in {"glob", "iglob"}:
                        glob_functions.add(alias.asname or alias.name)
            elif node.module == "os":
                for alias in node.names:
                    if alias.name in {"listdir", "scandir", "walk"}:
                        os_functions.add(alias.asname or alias.name)

    targets: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr in {"glob", "iglob"}
            and isinstance(func.value, ast.Name)
            and func.value.id in glob_modules
        ):
            targets.extend(_python_call_path_args(node, scalar_bindings, sequence_bindings, glob_pattern=True))
        elif isinstance(func, ast.Name) and func.id in glob_functions:
            targets.extend(_python_call_path_args(node, scalar_bindings, sequence_bindings, glob_pattern=True))
        elif (
            isinstance(func, ast.Attribute)
            and func.attr in {"listdir", "scandir", "walk"}
            and isinstance(func.value, ast.Name)
            and func.value.id in os_modules
        ):
            targets.extend(_python_call_path_args(node, scalar_bindings, sequence_bindings))
        elif isinstance(func, ast.Name) and func.id in os_functions:
            targets.extend(_python_call_path_args(node, scalar_bindings, sequence_bindings))
    return _dedupe_strings(targets)


def _python_call_path_args(
    node: ast.Call,
    scalar_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
    *,
    glob_pattern: bool = False,
) -> list[str]:
    if not node.args:
        return []
    arg = node.args[0]
    raw_paths: list[str] = []
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        raw_paths.append(arg.value)
    elif isinstance(arg, ast.Name):
        if arg.id in scalar_bindings:
            raw_paths.append(scalar_bindings[arg.id])
        raw_paths.extend(sequence_bindings.get(arg.id, []))
    paths: list[str] = []
    for path in raw_paths:
        if "/" not in path and not path.startswith(("~", ".")):
            continue
        paths.append(_glob_base_path(path) if glob_pattern else path)
    return paths


def _python_read_targets(
    text: str,
    path_bindings: dict[str, str] | None = None,
    path_sequence_bindings: dict[str, list[str]] | None = None,
) -> list[str]:
    scalar_bindings = path_bindings if path_bindings is not None else _python_path_variable_bindings(text)
    sequence_bindings = (
        path_sequence_bindings
        if path_sequence_bindings is not None
        else _python_path_sequence_variable_bindings(text)
    )
    targets: list[str] = []
    write_or_unknown_open_targets = set(
        _python_open_call_write_or_unknown_targets(text, scalar_bindings, sequence_bindings)
    )
    targets.extend(_python_open_call_read_targets(text, scalar_bindings, sequence_bindings))
    for path, mode in re.findall(
        r"(?<!\.)\bopen\(\s*['\"]([^'\"]+)['\"]\s*(?:,\s*['\"]([^'\"]*)['\"])?",
        text,
    ):
        if not _python_open_mode_writes(mode) and path not in write_or_unknown_open_targets:
            targets.append(path)
    for variable, mode in re.findall(
        r"(?<!\.)\bopen\(\s*([A-Za-z_]\w*)\s*(?:,\s*['\"]([^'\"]*)['\"])?",
        text,
    ):
        if _python_open_mode_writes(mode):
            continue
        if variable in scalar_bindings:
            path = scalar_bindings[variable]
            if path not in write_or_unknown_open_targets:
                targets.append(path)
        targets.extend(
            path for path in sequence_bindings.get(variable, [])
            if path not in write_or_unknown_open_targets
        )
    for path in re.findall(
        r"(?:Path|pathlib\.Path)\(\s*['\"]([^'\"]+)['\"]\s*\)\.read_(?:text|bytes)\(",
        text,
    ):
        targets.append(path)
    for path, mode in re.findall(
        r"(?:Path|pathlib\.Path)\(\s*['\"]([^'\"]+)['\"]\s*\)\.open\(\s*(?:mode\s*=\s*)?['\"]?([^'\",\)]*)",
        text,
    ):
        if not _python_open_mode_writes(mode) and path not in write_or_unknown_open_targets:
            targets.append(path)
    for path in re.findall(
        r"(?:Path|pathlib\.Path)\(\s*['\"]([^'\"]+)['\"]\s*\)\.(?:glob|rglob|iterdir)\(",
        text,
    ):
        targets.append(path)
    for variable in re.findall(r"\b([A-Za-z_]\w*)\.read_(?:text|bytes)\(", text):
        path = scalar_bindings.get(variable)
        if path:
            targets.append(path)
        targets.extend(sequence_bindings.get(variable, []))
    for variable, mode in re.findall(
        r"\b([A-Za-z_]\w*)\.open\(\s*(?:mode\s*=\s*)?['\"]?([^'\",\)]*)",
        text,
    ):
        if _python_open_mode_writes(mode):
            continue
        path = scalar_bindings.get(variable)
        if path and path not in write_or_unknown_open_targets:
            targets.append(path)
        targets.extend(
            path for path in sequence_bindings.get(variable, [])
            if path not in write_or_unknown_open_targets
        )
    for variable in re.findall(r"\b([A-Za-z_]\w*)\.(?:glob|rglob|iterdir)\(", text):
        path = scalar_bindings.get(variable)
        if path:
            targets.append(path)
        targets.extend(sequence_bindings.get(variable, []))
    targets.extend(_python_document_reader_targets(text, scalar_bindings, sequence_bindings))
    targets.extend(_python_archive_member_write_read_targets(text, scalar_bindings, sequence_bindings))
    return _dedupe_strings(targets)


def _python_open_call_read_targets(
    text: str,
    scalar_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
) -> list[str]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    string_bindings = _python_string_literal_bindings(tree)
    open_aliases, open_module_aliases = _python_open_binding_names(tree)
    wave_aliases = _python_wave_module_aliases(tree)
    targets: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        path_node, positional_index = _python_wave_open_call_path_and_mode_position(
            node,
            wave_aliases,
        )
        if path_node is None:
            path_node, positional_index = _python_open_call_path_and_mode_position(
                node,
                open_aliases,
                open_module_aliases,
            )
        if path_node is None:
            continue
        if _python_call_mode_writes_or_unknown(
            node,
            positional_index=positional_index,
            string_bindings=string_bindings,
        ):
            continue
        resolved, call_targets = _python_document_reader_arg_targets(
            path_node,
            scalar_bindings,
            sequence_bindings,
            set(),
            set(),
        )
        if not resolved:
            resolved, call_targets = _python_safe_task_data_join_arg_targets(
                path_node,
                tree,
                scalar_bindings,
            )
        if resolved:
            targets.extend(call_targets)
    return _dedupe_strings(targets)


def _python_safe_task_data_join_arg_targets(
    node: ast.AST | None,
    tree: ast.AST,
    scalar_bindings: dict[str, str],
) -> tuple[bool, list[str]]:
    if node is None:
        return (False, [])
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Name) and func.id in {"str", "bytes"} and len(node.args) == 1:
            return _python_safe_task_data_join_arg_targets(node.args[0], tree, scalar_bindings)
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "fspath"
            and isinstance(func.value, ast.Name)
            and func.value.id == "os"
            and len(node.args) == 1
        ):
            return _python_safe_task_data_join_arg_targets(node.args[0], tree, scalar_bindings)
        if _python_call_is_path_constructor(node) and node.args:
            return _python_safe_task_data_join_arg_targets(node.args[0], tree, scalar_bindings)
        walk_root_names, walk_child_names, os_modules, join_functions = _python_task_data_dynamic_join_context(
            tree,
            seed_bindings=scalar_bindings,
        )
        if not walk_child_names:
            return (False, [])
        base = _python_safe_task_data_join_or_alias_base(
            node,
            walk_root_names=walk_root_names,
            walk_child_names=walk_child_names,
            safe_bindings={},
            seed_bindings=scalar_bindings,
            os_modules=os_modules,
            join_functions=join_functions,
        )
        if base:
            return (True, [base])
    return (False, [])


def _python_ast_has_unresolved_open_read_call(
    tree: ast.AST,
    scalar_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
) -> bool:
    string_bindings = _python_string_literal_bindings(tree)
    open_aliases, open_module_aliases = _python_open_binding_names(tree)
    wave_aliases = _python_wave_module_aliases(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        path_node, positional_index = _python_wave_open_call_path_and_mode_position(
            node,
            wave_aliases,
        )
        if path_node is None:
            path_node, positional_index = _python_open_call_path_and_mode_position(
                node,
                open_aliases,
                open_module_aliases,
            )
        if path_node is None:
            continue
        if _python_call_mode_writes_or_unknown(
            node,
            positional_index=positional_index,
            string_bindings=string_bindings,
        ):
            continue
        resolved, _targets = _python_document_reader_arg_targets(
            path_node,
            scalar_bindings,
            sequence_bindings,
            set(),
            set(),
        )
        if not resolved:
            resolved, _targets = _python_safe_task_data_join_arg_targets(
                path_node,
                tree,
                scalar_bindings,
            )
        if not resolved:
            return True
    return False


def _python_open_call_write_or_unknown_targets(
    text: str,
    scalar_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
) -> list[str]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    string_bindings = _python_string_literal_bindings(tree)
    open_aliases, open_module_aliases = _python_open_binding_names(tree)
    wave_aliases = _python_wave_module_aliases(tree)
    targets: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        path_node, positional_index = _python_wave_open_call_path_and_mode_position(
            node,
            wave_aliases,
        )
        if path_node is None:
            path_node, positional_index = _python_open_call_path_and_mode_position(
                node,
                open_aliases,
                open_module_aliases,
            )
        if path_node is None:
            continue
        if not _python_call_mode_writes_or_unknown(
            node,
            positional_index=positional_index,
            string_bindings=string_bindings,
        ):
            continue
        resolved, call_targets = _python_writer_arg_targets(
            path_node,
            scalar_bindings,
            sequence_bindings,
        )
        if resolved:
            targets.extend(call_targets)
    return _dedupe_strings(targets)


def _python_open_call_path_and_mode_position(
    node: ast.Call,
    open_aliases: set[str],
    open_module_aliases: set[str],
) -> tuple[ast.AST | None, int]:
    if _python_call_is_open_function(node, open_aliases, open_module_aliases):
        return (node.args[0], 1) if node.args else (None, 1)
    func = node.func
    if isinstance(func, ast.Attribute) and func.attr == "open":
        return func.value, 0
    return None, 0


def _python_wave_module_aliases(tree: ast.AST) -> set[str]:
    aliases = {"wave"}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Import):
            continue
        for alias in node.names:
            if alias.name == "wave":
                aliases.add(alias.asname or alias.name)
    return aliases


def _python_wave_open_call_path_and_mode_position(
    node: ast.Call,
    wave_aliases: set[str],
) -> tuple[ast.AST | None, int]:
    func = node.func
    if (
        isinstance(func, ast.Attribute)
        and func.attr == "open"
        and isinstance(func.value, ast.Name)
        and func.value.id in wave_aliases
    ):
        return (node.args[0], 1) if node.args else (None, 1)
    return None, 0


def _python_document_reader_targets(
    text: str,
    scalar_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
) -> list[str]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    reader_bindings = _python_document_reader_bindings(tree)
    string_bindings = _python_string_literal_bindings(tree)
    safe_path_names, safe_iterable_names = _python_task_data_reader_safe_binding_names(
        tree,
        scalar_bindings,
        sequence_bindings,
    )
    (
        trusted_path_open_receivers,
        trusted_path_constructor_aliases,
        trusted_pathlib_module_aliases,
    ) = _python_trusted_pathlib_open_context(tree, scalar_bindings)
    targets: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not _python_call_is_document_reader(node, reader_bindings):
            continue
        if _python_call_is_trusted_archive_write_open(node, string_bindings, reader_bindings):
            continue
        for source_node in _python_document_reader_source_arg_nodes(node, reader_bindings):
            resolved, reader_targets = _python_document_reader_arg_targets(
                source_node,
                scalar_bindings,
                sequence_bindings,
                safe_path_names,
                safe_iterable_names,
                trusted_path_open_receivers,
                trusted_path_constructor_aliases,
                trusted_pathlib_module_aliases,
                trusted_pathlike_required=True,
            )
            if resolved:
                targets.extend(reader_targets)
    return _dedupe_strings(targets)


def _python_archive_member_write_read_targets(
    text: str,
    scalar_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
) -> list[str]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    string_bindings = _python_string_literal_bindings(tree)
    reader_bindings = _python_document_reader_bindings(tree)
    writer_scalar_bindings = _python_writer_path_variable_bindings(
        tree,
        scalar_bindings,
        sequence_bindings,
    )
    archive_handle_bindings = _python_archive_write_handle_bindings(
        tree,
        writer_scalar_bindings,
        sequence_bindings,
        string_bindings,
        reader_bindings,
    )
    targets: list[str] = []
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "write"
            and node.args
        ):
            continue
        receiver = node.func.value
        archive_targets: list[str] = []
        if isinstance(receiver, ast.Name):
            archive_targets = archive_handle_bindings.get(receiver.id, [])
        elif isinstance(receiver, ast.Call):
            archive_targets = _python_archive_write_call_targets(
                receiver,
                writer_scalar_bindings,
                sequence_bindings,
                string_bindings,
                reader_bindings,
            )
        if not archive_targets:
            continue
        resolved, read_targets = _python_document_reader_arg_targets(
            node.args[0],
            writer_scalar_bindings,
            sequence_bindings,
            set(),
            set(),
        )
        if resolved:
            targets.extend(read_targets)
    return _dedupe_strings(targets)


def _python_archive_auxiliary_member_write_hints(
    text: str,
    scalar_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
) -> list[str]:
    hints, _unresolved = _python_archive_member_write_semantics(
        text,
        scalar_bindings,
        sequence_bindings,
    )
    return hints


def _python_archive_member_write_has_unresolved_member_name(
    text: str,
    scalar_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
) -> bool:
    _hints, unresolved = _python_archive_member_write_semantics(
        text,
        scalar_bindings,
        sequence_bindings,
    )
    return unresolved


def _python_archive_member_write_semantics(
    text: str,
    scalar_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
) -> tuple[list[str], bool]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return ([], False)
    string_bindings = _python_string_literal_bindings(tree)
    member_bindings, member_sequence_bindings = _python_static_text_payload_bindings(
        tree,
        string_bindings,
    )
    reader_bindings = _python_document_reader_bindings(tree)
    writer_scalar_bindings = _python_writer_path_variable_bindings(
        tree,
        scalar_bindings,
        sequence_bindings,
    )
    archive_handle_bindings = _python_archive_write_handle_bindings(
        tree,
        writer_scalar_bindings,
        sequence_bindings,
        string_bindings,
        reader_bindings,
    )
    archive_read_handle_names = _python_archive_read_handle_names(
        tree,
        string_bindings,
        reader_bindings,
    )
    candidate_member_collections = _python_archive_existing_member_collection_names(
        tree,
        archive_read_handle_names,
        string_bindings,
        reader_bindings,
        unsafe_mutated_names=set(),
    )
    ooxml_structural_index_names = _python_archive_ooxml_structural_index_binding_names(
        tree,
        candidate_member_collections,
        string_bindings,
    )
    ooxml_structural_member_names = _python_archive_ooxml_structural_member_binding_names(
        tree,
        string_bindings,
        ooxml_structural_index_names,
    )
    unsafe_member_collections, auxiliary_mutation_hints = (
        _python_archive_member_collection_mutation_analysis(
            tree,
            string_bindings,
            ooxml_structural_member_names,
            ooxml_structural_index_names,
            candidate_member_collections,
            archive_read_handle_names,
            reader_bindings,
            _python_archive_has_ooxml_write_target(
                tree,
                writer_scalar_bindings,
                sequence_bindings,
                string_bindings,
                reader_bindings,
                archive_handle_bindings,
            ),
        )
    )
    member_collections = _python_archive_existing_member_collection_names(
        tree,
        archive_read_handle_names,
        string_bindings,
        reader_bindings,
        unsafe_mutated_names=unsafe_member_collections,
    )
    safe_existing_member_node_ids = _python_archive_existing_member_name_node_ids(
        tree,
        member_collections,
        archive_read_handle_names,
        string_bindings,
        reader_bindings,
    )
    safe_static_structural_member_node_ids = (
        _python_archive_static_structural_member_name_node_ids(
            tree,
            string_bindings,
            ooxml_structural_member_names,
            ooxml_structural_index_names,
        )
    )
    hints: list[str] = []
    hints.extend(
        hint
        for collection_name, hint in auxiliary_mutation_hints
        if collection_name in candidate_member_collections
    )
    unresolved = False
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"write", "writestr"}
        ):
            continue
        archive_targets = _python_archive_write_receiver_targets(
            node,
            writer_scalar_bindings,
            sequence_bindings,
            string_bindings,
            reader_bindings,
            archive_handle_bindings,
        )
        if not archive_targets:
            continue
        member_node = _python_archive_member_name_arg_node(node)
        if member_node is None:
            continue
        member_name = _python_static_archive_member_name_value(
            member_node,
            member_bindings,
            member_sequence_bindings,
        )
        if member_name:
            if _python_archive_member_name_is_auxiliary(member_name):
                hints.append(member_name)
            elif _python_archive_member_name_is_ooxml_structural(member_name):
                continue
            elif any(_python_archive_target_is_ooxml_office_package(path) for path in archive_targets):
                unresolved = True
            continue
        if _python_archive_member_expr_is_ooxml_structural(
            member_node,
            string_bindings,
            ooxml_structural_member_names,
            ooxml_structural_index_names,
        ):
            continue
        if id(member_node) in safe_existing_member_node_ids:
            continue
        if id(member_node) in safe_static_structural_member_node_ids:
            continue
        unresolved = True
    return (_dedupe_strings(hints), unresolved)


def _python_static_archive_member_name_value(
    node: ast.AST,
    string_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
) -> str:
    member_name = _python_static_string_expr_value(node, string_bindings)
    if member_name:
        return member_name
    if isinstance(node, ast.Name):
        sequence = sequence_bindings.get(node.id, [])
        if len(sequence) == 1:
            return sequence[0]
    return ""


def _python_archive_target_is_ooxml_office_package(path: str) -> bool:
    normalized = str(path or "").strip().split("?", 1)[0].split("#", 1)[0].lower()
    return normalized.endswith((
        ".docm",
        ".docx",
        ".dotm",
        ".dotx",
        ".potm",
        ".potx",
        ".ppsm",
        ".ppsx",
        ".pptm",
        ".pptx",
        ".xlsm",
        ".xlsx",
        ".xltm",
        ".xltx",
    ))


def _python_archive_has_ooxml_write_target(
    tree: ast.AST,
    writer_scalar_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
    string_bindings: dict[str, str],
    reader_bindings: dict[str, set[str]],
    archive_handle_bindings: dict[str, list[str]],
) -> bool:
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"write", "writestr"}
        ):
            continue
        archive_targets = _python_archive_write_receiver_targets(
            node,
            writer_scalar_bindings,
            sequence_bindings,
            string_bindings,
            reader_bindings,
            archive_handle_bindings,
        )
        if any(_python_archive_target_is_ooxml_office_package(path) for path in archive_targets):
            return True
    return False


def _python_archive_existing_member_name_node_ids(
    tree: ast.AST,
    member_collections: set[str],
    archive_read_handle_names: set[str],
    string_bindings: dict[str, str],
    reader_bindings: dict[str, set[str]],
) -> set[int]:
    node_ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.For):
            if not _python_archive_member_iter_is_existing_collection(
                node.iter,
                member_collections,
                archive_read_handle_names,
                string_bindings,
                reader_bindings,
            ):
                continue
            target_names = set(_python_assignment_target_names(node.target))
            target_names = target_names.difference(_python_rebound_names_in_statements(node.body))
            if not target_names:
                continue
            for body_node in node.body:
                _collect_matching_name_node_ids(body_node, target_names, node_ids)
            continue
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            for generator in node.generators:
                if not _python_archive_member_iter_is_existing_collection(
                    generator.iter,
                    member_collections,
                    archive_read_handle_names,
                    string_bindings,
                    reader_bindings,
                ):
                    continue
                target_names = _python_assignment_target_names(generator.target)
                if isinstance(node, ast.DictComp):
                    _collect_matching_name_node_ids(node.key, target_names, node_ids)
                    _collect_matching_name_node_ids(node.value, target_names, node_ids)
                else:
                    _collect_matching_name_node_ids(node.elt, target_names, node_ids)
    return node_ids


def _python_archive_static_structural_member_name_node_ids(
    tree: ast.AST,
    string_bindings: dict[str, str],
    ooxml_structural_member_names: set[str],
    ooxml_structural_index_names: set[str],
) -> set[int]:
    sequence_bindings = _python_static_sequence_literal_bindings(tree)
    node_ids: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.For):
            continue
        structural_target_names = _python_archive_static_structural_loop_member_names(
            node,
            string_bindings,
            sequence_bindings,
            ooxml_structural_member_names,
            ooxml_structural_index_names,
        )
        if not structural_target_names:
            continue
        rebound_names = _python_rebound_names_in_statements(node.body)
        structural_target_names = structural_target_names.difference(rebound_names)
        if not structural_target_names:
            continue
        for body_node in node.body:
            _collect_matching_name_node_ids(body_node, structural_target_names, node_ids)
    return node_ids


def _python_rebound_names_in_statements(statements: list[ast.stmt]) -> set[str]:
    names: set[str] = set()
    for statement in statements:
        for node in ast.walk(statement):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    names.update(_python_assignment_target_names(target))
                continue
            if isinstance(node, ast.AnnAssign):
                names.update(_python_assignment_target_names(node.target))
                continue
            if isinstance(node, ast.AugAssign):
                names.update(_python_assignment_target_names(node.target))
                continue
            if isinstance(node, ast.NamedExpr):
                names.update(_python_assignment_target_names(node.target))
                continue
            if isinstance(node, (ast.For, ast.AsyncFor)):
                names.update(_python_assignment_target_names(node.target))
                continue
            if isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    if item.optional_vars is not None:
                        names.update(_python_assignment_target_names(item.optional_vars))
                continue
            if isinstance(node, ast.ExceptHandler):
                if isinstance(node.name, str):
                    names.add(node.name)
                continue
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                names.add(node.name)
                names.update(_python_argument_names(node.args))
                continue
            if isinstance(node, ast.Lambda):
                names.update(_python_argument_names(node.args))
                continue
            if isinstance(node, ast.ClassDef):
                names.add(node.name)
                continue
            names.update(_python_match_pattern_binding_names(node))
    return names


def _python_static_sequence_literal_bindings(tree: ast.AST) -> dict[str, ast.List | ast.Tuple]:
    bindings: dict[str, ast.List | ast.Tuple] = {}
    assignment_counts = _python_name_assignment_counts(tree)
    shadowed_names = _python_lexical_shadow_binding_names(tree, include_loop_targets=True)
    mutated_names = _python_mutated_static_sequence_names(tree)
    for node in ast.walk(tree):
        assignment = _python_single_name_assignment(node)
        if assignment is None:
            continue
        target_name, value = assignment
        if (
            assignment_counts.get(target_name) != 1
            or target_name in shadowed_names
            or target_name in mutated_names
            or not isinstance(value, (ast.List, ast.Tuple))
        ):
            continue
        bindings[target_name] = value
    return bindings


def _python_mutated_static_sequence_names(tree: ast.AST) -> set[str]:
    string_bindings = _python_string_literal_bindings(tree)
    bound_aliases, unbound_aliases = _python_archive_member_collection_mutator_aliases(
        tree,
        string_bindings,
    )
    mutated: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr in _ARCHIVE_MEMBER_COLLECTION_MUTATING_METHODS:
                collection_name = _python_archive_mutator_collection_arg_name(func.value)
                if collection_name:
                    mutated.add(collection_name)
                continue
            if isinstance(func, ast.Name):
                bound_alias = bound_aliases.get(func.id)
                if bound_alias is not None:
                    mutated.add(bound_alias[0])
                    continue
                unbound_alias = unbound_aliases.get(func.id)
                if unbound_alias is not None and node.args:
                    collection_name = _python_archive_mutator_collection_arg_name(node.args[0])
                    if collection_name:
                        mutated.add(collection_name)
            continue
        if isinstance(node, ast.Assign):
            for target in node.targets:
                root_name = _python_subscript_root_name(target)
                if root_name:
                    mutated.add(root_name)
            continue
        if isinstance(node, ast.AnnAssign):
            root_name = _python_subscript_root_name(node.target)
            if root_name:
                mutated.add(root_name)
            continue
        if isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name):
                mutated.add(node.target.id)
                continue
            root_name = _python_subscript_root_name(node.target)
            if root_name:
                mutated.add(root_name)
            continue
        if isinstance(node, ast.Delete):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    mutated.add(target.id)
                    continue
                root_name = _python_subscript_root_name(target)
                if root_name:
                    mutated.add(root_name)
    return mutated


def _python_archive_static_structural_loop_member_names(
    node: ast.For,
    string_bindings: dict[str, str],
    sequence_bindings: dict[str, ast.List | ast.Tuple],
    ooxml_structural_member_names: set[str],
    ooxml_structural_index_names: set[str],
) -> set[str]:
    elements = _python_static_loop_iter_elements(node.iter, sequence_bindings)
    if not elements:
        return set()
    target_value_nodes = _python_loop_target_value_nodes_by_name(node.target, elements)
    structural_names: set[str] = set()
    for target_name, value_nodes in target_value_nodes.items():
        if not value_nodes:
            continue
        if all(
            _python_archive_member_expr_is_ooxml_structural(
                value_node,
                string_bindings,
                ooxml_structural_member_names,
                ooxml_structural_index_names,
            )
            for value_node in value_nodes
        ):
            structural_names.add(target_name)
    return structural_names


def _python_static_loop_iter_elements(
    node: ast.AST,
    sequence_bindings: dict[str, ast.List | ast.Tuple],
) -> list[ast.AST]:
    if isinstance(node, ast.Name):
        bound = sequence_bindings.get(node.id)
        return list(bound.elts) if bound is not None else []
    if isinstance(node, (ast.List, ast.Tuple)):
        return list(node.elts)
    return []


def _python_loop_target_value_nodes_by_name(
    target: ast.AST,
    elements: list[ast.AST],
) -> dict[str, list[ast.AST]]:
    if isinstance(target, ast.Name):
        return {target.id: elements}
    if not isinstance(target, (ast.Tuple, ast.List)):
        return {}
    names_by_index: dict[int, str] = {
        index: element.id
        for index, element in enumerate(target.elts)
        if isinstance(element, ast.Name)
    }
    if not names_by_index:
        return {}
    values_by_name: dict[str, list[ast.AST]] = {
        name: [] for name in names_by_index.values()
    }
    for element in elements:
        if not isinstance(element, (ast.Tuple, ast.List)):
            return {}
        for index, name in names_by_index.items():
            if index >= len(element.elts):
                return {}
            values_by_name[name].append(element.elts[index])
    return values_by_name


def _python_archive_existing_member_collection_names(
    tree: ast.AST,
    archive_read_handle_names: set[str],
    string_bindings: dict[str, str],
    reader_bindings: dict[str, set[str]],
    *,
    unsafe_mutated_names: set[str],
) -> set[str]:
    collections: set[str] = set()
    assignment_counts = _python_name_assignment_counts(tree)
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            for target_name, value in _python_assignment_name_value_pairs(node):
                if assignment_counts.get(target_name) != 1:
                    continue
                if target_name in unsafe_mutated_names:
                    continue
                if (
                    _python_expr_is_archive_namelist_iter(
                        value,
                        archive_read_handle_names,
                        string_bindings,
                        reader_bindings,
                    )
                    or _python_archive_expr_is_existing_member_collection(
                        value,
                        collections,
                        archive_read_handle_names,
                        string_bindings,
                        reader_bindings,
                    )
                ):
                    if target_name not in collections:
                        collections.add(target_name)
                        changed = True
    return collections


def _python_archive_expr_is_existing_member_collection(
    node: ast.AST,
    member_collections: set[str],
    archive_read_handle_names: set[str],
    string_bindings: dict[str, str],
    reader_bindings: dict[str, set[str]],
) -> bool:
    if isinstance(node, ast.Name):
        return node.id in member_collections
    if isinstance(node, (ast.DictComp, ast.ListComp, ast.SetComp, ast.GeneratorExp)):
        return _python_archive_comprehension_projects_existing_member_name(
            node,
            member_collections,
            archive_read_handle_names,
            string_bindings,
            reader_bindings,
        ) or _python_archive_comprehension_projects_archive_info_filename(
            node,
            archive_read_handle_names,
            string_bindings,
            reader_bindings,
        )
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"list", "tuple", "set", "sorted"}
        and node.args
    ):
        return _python_archive_expr_is_existing_member_collection(
            node.args[0],
            member_collections,
            archive_read_handle_names,
            string_bindings,
            reader_bindings,
        ) or _python_archive_member_iter_is_existing_collection(
            node.args[0],
            member_collections,
            archive_read_handle_names,
            string_bindings,
            reader_bindings,
        )
    return False


def _python_archive_member_iter_is_existing_collection(
    node: ast.AST,
    member_collections: set[str],
    archive_read_handle_names: set[str],
    string_bindings: dict[str, str],
    reader_bindings: dict[str, set[str]],
) -> bool:
    if isinstance(node, ast.Name):
        return node.id in member_collections
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"iter", "list", "tuple", "set", "sorted"}
        and node.args
    ):
        return _python_archive_member_iter_is_existing_collection(
            node.args[0],
            member_collections,
            archive_read_handle_names,
            string_bindings,
            reader_bindings,
        )
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"items", "keys"}
        and isinstance(node.func.value, ast.Name)
    ):
        return node.func.value.id in member_collections
    return _python_expr_is_archive_namelist_iter(
        node,
        archive_read_handle_names,
        string_bindings,
        reader_bindings,
    )


def _python_archive_comprehension_projects_existing_member_name(
    node: ast.DictComp | ast.ListComp | ast.SetComp | ast.GeneratorExp,
    member_collections: set[str],
    archive_read_handle_names: set[str],
    string_bindings: dict[str, str],
    reader_bindings: dict[str, set[str]],
) -> bool:
    projected = node.key if isinstance(node, ast.DictComp) else node.elt
    for generator in node.generators:
        if not _python_archive_member_iter_is_existing_collection(
            generator.iter,
            member_collections,
            archive_read_handle_names,
            string_bindings,
            reader_bindings,
        ):
            continue
        target_names = _python_assignment_target_names(generator.target)
        if target_names and _python_expr_is_archive_existing_member_projection(projected, target_names):
            return True
    return False


def _python_expr_is_archive_existing_member_projection(
    node: ast.AST,
    target_names: set[str],
) -> bool:
    return isinstance(node, ast.Name) and node.id in target_names


def _python_archive_comprehension_projects_archive_info_filename(
    node: ast.DictComp | ast.ListComp | ast.SetComp | ast.GeneratorExp,
    archive_read_handle_names: set[str],
    string_bindings: dict[str, str],
    reader_bindings: dict[str, set[str]],
) -> bool:
    projected = node.key if isinstance(node, ast.DictComp) else node.elt
    for generator in node.generators:
        if not _python_expr_is_archive_infolist_iter(
            generator.iter,
            archive_read_handle_names,
            string_bindings,
            reader_bindings,
        ):
            continue
        target_names = _python_assignment_target_names(generator.target)
        if target_names and _python_expr_is_archive_info_filename_projection(projected, target_names):
            return True
    return False


def _python_expr_is_archive_info_filename_projection(
    node: ast.AST,
    target_names: set[str],
) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "filename"
        and isinstance(node.value, ast.Name)
        and node.value.id in target_names
    )


def _python_expr_is_archive_namelist_iter(
    node: ast.AST,
    archive_read_handle_names: set[str],
    string_bindings: dict[str, str],
    reader_bindings: dict[str, set[str]],
) -> bool:
    if not (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "namelist"
        and not node.args
        and not node.keywords
    ):
        return False
    receiver = node.func.value
    if isinstance(receiver, ast.Name):
        return receiver.id in archive_read_handle_names
    return _python_call_is_trusted_archive_read_open(
        receiver,
        string_bindings,
        reader_bindings,
    )


def _python_expr_is_archive_infolist_iter(
    node: ast.AST,
    archive_read_handle_names: set[str],
    string_bindings: dict[str, str],
    reader_bindings: dict[str, set[str]],
) -> bool:
    if not (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "infolist"
        and not node.args
        and not node.keywords
    ):
        return False
    receiver = node.func.value
    if isinstance(receiver, ast.Name):
        return receiver.id in archive_read_handle_names
    return _python_call_is_trusted_archive_read_open(
        receiver,
        string_bindings,
        reader_bindings,
    )


def _python_archive_read_handle_names(
    tree: ast.AST,
    string_bindings: dict[str, str],
    reader_bindings: dict[str, set[str]],
) -> set[str]:
    assignment_counts = _python_name_assignment_counts(tree)
    handles: set[str] = set()
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                for target_name, value in _python_assignment_name_value_pairs(node):
                    if assignment_counts.get(target_name) != 1:
                        continue
                    if isinstance(value, ast.Name):
                        is_archive_reader = value.id in handles
                    else:
                        is_archive_reader = _python_call_is_trusted_archive_read_open(
                            value,
                            string_bindings,
                            reader_bindings,
                        )
                    if not is_archive_reader or target_name in handles:
                        continue
                    handles.add(target_name)
                    changed = True
                continue
            if isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    if item.optional_vars is None:
                        continue
                    if not _python_call_is_trusted_archive_read_open(
                        item.context_expr,
                        string_bindings,
                        reader_bindings,
                    ):
                        continue
                    for target_name in _python_assignment_target_names(item.optional_vars):
                        if assignment_counts.get(target_name, 0) != 0 or target_name in handles:
                            continue
                        handles.add(target_name)
                        changed = True
    return handles


def _python_archive_member_collection_mutation_analysis(
    tree: ast.AST,
    string_bindings: dict[str, str],
    ooxml_structural_member_names: set[str],
    ooxml_structural_index_names: set[str],
    existing_member_collections: set[str],
    archive_read_handle_names: set[str],
    reader_bindings: dict[str, set[str]],
    ooxml_archive_write_present: bool,
) -> tuple[set[str], list[tuple[str, str]]]:
    bound_aliases, unbound_aliases = _python_archive_member_collection_mutator_aliases(
        tree,
        string_bindings,
    )
    safe_existing_member_node_ids = _python_archive_existing_member_name_node_ids(
        tree,
        existing_member_collections,
        archive_read_handle_names,
        string_bindings,
        reader_bindings,
    )
    unsafe_names: set[str] = set()
    auxiliary_hints: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            unbound_method = _python_archive_unbound_collection_mutator_name(
                func,
                string_bindings,
            )
            if unbound_method and node.args:
                collection_name = _python_archive_mutator_collection_arg_name(node.args[0])
                if collection_name:
                    _python_archive_record_mutating_method_call(
                        collection_name,
                        unbound_method,
                        list(node.args[1:]),
                        string_bindings,
                        unsafe_names,
                        auxiliary_hints,
                    )
                continue
            bound_method = _python_archive_bound_collection_mutator_alias(
                func,
                string_bindings,
            )
            if bound_method is not None:
                collection_name, method_name = bound_method
                _python_archive_record_mutating_method_call(
                    collection_name,
                    method_name,
                    list(node.args),
                    string_bindings,
                    unsafe_names,
                    auxiliary_hints,
                )
                continue
            if (
                isinstance(func, ast.Attribute)
                and func.attr in _ARCHIVE_MEMBER_COLLECTION_MUTATING_METHODS
                and isinstance(func.value, ast.Name)
            ):
                _python_archive_record_mutating_method_call(
                    func.value.id,
                    func.attr,
                    list(node.args),
                    string_bindings,
                    unsafe_names,
                    auxiliary_hints,
                )
                continue
            if isinstance(func, ast.Name):
                bound_alias = bound_aliases.get(func.id)
                if bound_alias is not None:
                    collection_name, method_name = bound_alias
                    _python_archive_record_mutating_method_call(
                        collection_name,
                        method_name,
                        list(node.args),
                        string_bindings,
                        unsafe_names,
                        auxiliary_hints,
                    )
                    continue
                unbound_alias = unbound_aliases.get(func.id)
                if unbound_alias is not None and node.args:
                    collection_name = _python_archive_mutator_collection_arg_name(node.args[0])
                    if collection_name:
                        _python_archive_record_mutating_method_call(
                            collection_name,
                            unbound_alias,
                            list(node.args[1:]),
                            string_bindings,
                            unsafe_names,
                            auxiliary_hints,
                        )
            continue
        if isinstance(node, ast.Assign):
            for target in node.targets:
                _python_archive_record_collection_assignment_mutation(
                    target,
                    string_bindings,
                    ooxml_structural_member_names,
                    ooxml_structural_index_names,
                    safe_existing_member_node_ids,
                    ooxml_archive_write_present,
                    unsafe_names,
                    auxiliary_hints,
                )
            continue
        if isinstance(node, ast.AnnAssign):
            _python_archive_record_collection_assignment_mutation(
                node.target,
                string_bindings,
                ooxml_structural_member_names,
                ooxml_structural_index_names,
                safe_existing_member_node_ids,
                ooxml_archive_write_present,
                unsafe_names,
                auxiliary_hints,
            )
            continue
        if isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name):
                unsafe_names.add(node.target.id)
                for member_name in _python_archive_static_member_names_from_expr(node.value, string_bindings):
                    if _python_archive_member_name_is_auxiliary(member_name):
                        auxiliary_hints.append((node.target.id, member_name))
                continue
            _python_archive_record_collection_assignment_mutation(
                node.target,
                string_bindings,
                ooxml_structural_member_names,
                ooxml_structural_index_names,
                safe_existing_member_node_ids,
                ooxml_archive_write_present,
                unsafe_names,
                auxiliary_hints,
            )
            continue
        if isinstance(node, ast.Delete):
            for target in node.targets:
                root_name = _python_subscript_root_name(target)
                if root_name:
                    unsafe_names.add(root_name)
                elif isinstance(target, ast.Name):
                    unsafe_names.add(target.id)
    return unsafe_names, _dedupe_archive_mutation_hints(auxiliary_hints)


def _python_archive_member_collection_mutator_aliases(
    tree: ast.AST,
    string_bindings: dict[str, str],
) -> tuple[dict[str, tuple[str, str]], dict[str, str]]:
    assignment_counts = _python_name_assignment_counts(tree)
    bound_aliases: dict[str, tuple[str, str]] = {}
    unbound_aliases: dict[str, str] = {}
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            for target_name, value in _python_assignment_name_value_pairs(node):
                if assignment_counts.get(target_name) != 1:
                    continue
                bound_alias = bound_aliases.get(value.id) if isinstance(value, ast.Name) else None
                if bound_alias is None:
                    bound_alias = _python_archive_bound_collection_mutator_alias(
                        value,
                        string_bindings,
                    )
                if bound_alias is not None and bound_aliases.get(target_name) != bound_alias:
                    bound_aliases[target_name] = bound_alias
                    changed = True
                    continue
                unbound_alias = unbound_aliases.get(value.id) if isinstance(value, ast.Name) else None
                if unbound_alias is None:
                    unbound_alias = _python_archive_unbound_collection_mutator_name(
                        value,
                        string_bindings,
                    )
                if unbound_alias is not None and unbound_aliases.get(target_name) != unbound_alias:
                    unbound_aliases[target_name] = unbound_alias
                    changed = True
    return bound_aliases, unbound_aliases


def _python_archive_bound_collection_mutator_alias(
    node: ast.AST,
    string_bindings: dict[str, str],
) -> tuple[str, str] | None:
    if (
        isinstance(node, ast.Attribute)
        and node.attr in _ARCHIVE_MEMBER_COLLECTION_MUTATING_METHODS
        and isinstance(node.value, ast.Name)
        and node.value.id not in _ARCHIVE_MEMBER_COLLECTION_MUTATOR_TYPE_NAMES
    ):
        return (node.value.id, node.attr)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "getattr"
        and len(node.args) >= 2
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id not in _ARCHIVE_MEMBER_COLLECTION_MUTATOR_TYPE_NAMES
    ):
        method_name = _python_constant_or_bound_string(node.args[1], string_bindings)
        if method_name in _ARCHIVE_MEMBER_COLLECTION_MUTATING_METHODS:
            return (node.args[0].id, method_name)
    return None


def _python_archive_unbound_collection_mutator_name(
    node: ast.AST,
    string_bindings: dict[str, str],
) -> str | None:
    if (
        isinstance(node, ast.Attribute)
        and node.attr in _ARCHIVE_MEMBER_COLLECTION_MUTATING_METHODS
        and isinstance(node.value, ast.Name)
        and node.value.id in _ARCHIVE_MEMBER_COLLECTION_MUTATOR_TYPE_NAMES
    ):
        return node.attr
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "getattr"
        and len(node.args) >= 2
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id in _ARCHIVE_MEMBER_COLLECTION_MUTATOR_TYPE_NAMES
    ):
        method_name = _python_constant_or_bound_string(node.args[1], string_bindings)
        if method_name in _ARCHIVE_MEMBER_COLLECTION_MUTATING_METHODS:
            return method_name
    return None


def _python_archive_mutator_collection_arg_name(node: ast.AST) -> str | None:
    return node.id if isinstance(node, ast.Name) else None


def _python_archive_record_mutating_method_call(
    collection_name: str,
    method_name: str,
    args: list[ast.AST],
    string_bindings: dict[str, str],
    unsafe_names: set[str],
    auxiliary_hints: list[tuple[str, str]],
) -> None:
    unsafe_names.add(collection_name)
    for member_name in _python_archive_mutating_call_member_names(
        method_name,
        args,
        string_bindings,
    ):
        if _python_archive_member_name_is_auxiliary(member_name):
            auxiliary_hints.append((collection_name, member_name))


def _python_archive_record_collection_assignment_mutation(
    target: ast.AST,
    string_bindings: dict[str, str],
    ooxml_structural_member_names: set[str],
    ooxml_structural_index_names: set[str],
    safe_existing_member_node_ids: set[int],
    ooxml_archive_write_present: bool,
    unsafe_names: set[str],
    auxiliary_hints: list[tuple[str, str]],
) -> None:
    root_name = _python_subscript_root_name(target)
    if root_name is None:
        return
    member_name = _python_archive_static_subscript_member_name(target, string_bindings)
    if (
        member_name
        and not _python_archive_member_name_is_auxiliary(member_name)
        and _python_archive_member_name_is_ooxml_structural(member_name)
    ):
        return
    if (
        member_name
        and not _python_archive_member_name_is_auxiliary(member_name)
        and not ooxml_archive_write_present
    ):
        return
    if _python_archive_subscript_member_expr_is_ooxml_structural(
        target,
        string_bindings,
        ooxml_structural_member_names,
        ooxml_structural_index_names,
    ):
        return
    if isinstance(target, ast.Subscript) and id(target.slice) in safe_existing_member_node_ids:
        return
    unsafe_names.add(root_name)
    if member_name and _python_archive_member_name_is_auxiliary(member_name):
        auxiliary_hints.append((root_name, member_name))


def _python_subscript_root_name(node: ast.AST) -> str | None:
    if not isinstance(node, ast.Subscript):
        return None
    current = node
    while isinstance(current, ast.Subscript):
        current = current.value
    return current.id if isinstance(current, ast.Name) else None


def _python_archive_static_subscript_member_name(
    node: ast.AST,
    string_bindings: dict[str, str],
) -> str:
    if not isinstance(node, ast.Subscript):
        return ""
    return _python_constant_or_bound_string(node.slice, string_bindings)


def _python_archive_subscript_member_expr_is_ooxml_structural(
    node: ast.AST,
    string_bindings: dict[str, str],
    ooxml_structural_member_names: set[str],
    ooxml_structural_index_names: set[str],
) -> bool:
    if not isinstance(node, ast.Subscript):
        return False
    return _python_archive_member_expr_is_ooxml_structural(
        node.slice,
        string_bindings,
        ooxml_structural_member_names,
        ooxml_structural_index_names,
    )


def _python_archive_ooxml_structural_index_binding_names(
    tree: ast.AST,
    existing_member_collections: set[str],
    string_bindings: dict[str, str],
) -> set[str]:
    assignment_counts = _python_name_assignment_counts(tree)
    shadowed_names = _python_lexical_shadow_binding_names(tree, include_loop_targets=True)
    names: set[str] = _python_archive_ooxml_structural_loop_index_names(
        tree,
        existing_member_collections,
        string_bindings,
    )
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            assignment = _python_single_name_assignment(node)
            if assignment is None:
                continue
            target_name, value = assignment
            if assignment_counts.get(target_name) != 1 or target_name in shadowed_names:
                continue
            if not _python_archive_expr_is_safe_structural_index(
                value,
                names,
                existing_member_collections,
            ):
                continue
            if target_name not in names:
                names.add(target_name)
                changed = True
    return names


def _python_archive_ooxml_structural_loop_index_names(
    tree: ast.AST,
    existing_member_collections: set[str],
    string_bindings: dict[str, str],
) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.While):
            continue
        for index_name in _python_archive_ooxml_structural_membership_index_names(
            node.test,
            existing_member_collections,
            string_bindings,
        ):
            if not _python_archive_loop_index_has_safe_initializer(tree, node, index_name):
                continue
            if not _python_archive_loop_index_mutations_are_safe(node, index_name):
                continue
            if not _python_archive_loop_index_has_no_post_loop_reassignment(
                tree,
                node,
                index_name,
            ):
                continue
            names.add(index_name)
    return names


def _python_archive_ooxml_structural_membership_index_names(
    node: ast.AST,
    existing_member_collections: set[str],
    string_bindings: dict[str, str],
) -> set[str]:
    if not isinstance(node, ast.Compare):
        return set()
    if len(node.ops) != 1 or not isinstance(node.ops[0], ast.In):
        return set()
    if len(node.comparators) != 1:
        return set()
    collection = node.comparators[0]
    if not isinstance(collection, ast.Name) or collection.id not in existing_member_collections:
        return set()
    template, index_names = _python_archive_member_template_index_names(
        node.left,
        string_bindings,
    )
    if not template or not _python_archive_member_template_is_ooxml_structural(template):
        return set()
    return index_names


def _python_archive_member_template_index_names(
    node: ast.AST,
    string_bindings: dict[str, str],
) -> tuple[str, set[str]]:
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        index_names: set[str] = set()
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
                continue
            if (
                isinstance(value, ast.FormattedValue)
                and isinstance(value.value, ast.Name)
            ):
                parts.append("{}")
                index_names.add(value.value.id)
                continue
            return ("", set())
        return ("".join(parts), index_names)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left_template, left_names = _python_archive_member_template_index_names(
            node.left,
            string_bindings,
        )
        right_template, right_names = _python_archive_member_template_index_names(
            node.right,
            string_bindings,
        )
        if left_template and right_template:
            return (left_template + right_template, left_names | right_names)
        return ("", set())
    member_name = _python_constant_or_bound_string(node, string_bindings)
    return (member_name or "", set())


def _python_archive_loop_index_has_safe_initializer(
    tree: ast.AST,
    loop_node: ast.While,
    index_name: str,
) -> bool:
    loop_lineno = getattr(loop_node, "lineno", 10**9)
    initialized = False
    for node in ast.walk(tree):
        lineno = getattr(node, "lineno", 10**9)
        if lineno >= loop_lineno:
            continue
        assignment = _python_single_name_assignment(node)
        if assignment is not None:
            target_name, value = assignment
            if target_name == index_name:
                initialized = _python_archive_expr_is_safe_structural_index(value, set(), set())
            continue
        if (
            isinstance(node, ast.AugAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == index_name
        ):
            initialized = initialized and _python_archive_loop_index_step_is_safe(node)
    return initialized


def _python_archive_loop_index_mutations_are_safe(
    loop_node: ast.While,
    index_name: str,
) -> bool:
    saw_step = False
    for node in ast.walk(loop_node):
        if node is loop_node:
            continue
        assignment = _python_single_name_assignment(node)
        if assignment is not None and assignment[0] == index_name:
            return False
        if (
            isinstance(node, ast.AugAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == index_name
        ):
            if not _python_archive_loop_index_step_is_safe(node):
                return False
            saw_step = True
    return saw_step


def _python_archive_loop_index_has_no_post_loop_reassignment(
    tree: ast.AST,
    loop_node: ast.While,
    index_name: str,
) -> bool:
    loop_end_lineno = _python_ast_node_end_lineno(loop_node)
    for node in ast.walk(tree):
        lineno = getattr(node, "lineno", 0)
        if lineno <= loop_end_lineno:
            continue
        assignment = _python_single_name_assignment(node)
        if assignment is not None and assignment[0] == index_name:
            return False
        if (
            isinstance(node, ast.AugAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == index_name
        ):
            return False
        if isinstance(node, ast.Delete):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == index_name:
                    return False
    return True


def _python_ast_node_end_lineno(node: ast.AST) -> int:
    end_lineno = getattr(node, "end_lineno", None)
    if isinstance(end_lineno, int):
        return end_lineno
    return max((getattr(child, "lineno", 0) for child in ast.walk(node)), default=0)


def _python_archive_loop_index_step_is_safe(node: ast.AugAssign) -> bool:
    return (
        isinstance(node.op, (ast.Add, ast.Sub))
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, int)
        and node.value.value >= 0
    )


def _python_archive_expr_is_safe_structural_index(
    node: ast.AST,
    index_names: set[str],
    existing_member_collections: set[str],
) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value >= 0
    if isinstance(node, ast.Name):
        return node.id in index_names
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub)):
        return (
            _python_archive_expr_is_safe_structural_index(
                node.left,
                index_names,
                existing_member_collections,
            )
            and _python_archive_expr_is_safe_structural_index(
                node.right,
                index_names,
                existing_member_collections,
            )
        )
    if _python_archive_expr_is_existing_member_numeric_index_aggregate(
        node,
        existing_member_collections,
    ):
        return True
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "len"
        and len(node.args) == 1
        and not node.keywords
        and isinstance(node.args[0], ast.Name)
    ):
        return node.args[0].id in existing_member_collections
    return False


def _python_archive_expr_is_existing_member_numeric_index_aggregate(
    node: ast.AST,
    existing_member_collections: set[str],
) -> bool:
    if not (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"max", "min"}
        and len(node.args) == 1
        and not node.keywords
    ):
        return False
    return _python_archive_comprehension_projects_existing_member_numeric_index(
        node.args[0],
        existing_member_collections,
    )


def _python_archive_comprehension_projects_existing_member_numeric_index(
    node: ast.AST,
    existing_member_collections: set[str],
) -> bool:
    if isinstance(node, ast.GeneratorExp):
        element = node.elt
        generators = node.generators
    elif isinstance(node, (ast.ListComp, ast.SetComp)):
        element = node.elt
        generators = node.generators
    else:
        return False
    for generator in generators:
        if not (
            isinstance(generator.iter, ast.Name)
            and generator.iter.id in existing_member_collections
        ):
            continue
        target_names = _python_assignment_target_names(generator.target)
        if target_names and _python_expr_is_numeric_projection_of_names(element, target_names):
            return True
    return False


def _python_expr_is_numeric_projection_of_names(
    node: ast.AST,
    source_names: set[str],
) -> bool:
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Name) and func.id in {"int"} and len(node.args) == 1:
        return _python_expr_uses_any_name(node.args[0], source_names)
    return False


def _python_expr_uses_any_name(node: ast.AST, names: set[str]) -> bool:
    return any(isinstance(child, ast.Name) and child.id in names for child in ast.walk(node))


def _python_archive_ooxml_structural_member_binding_names(
    tree: ast.AST,
    string_bindings: dict[str, str],
    ooxml_structural_index_names: set[str],
) -> set[str]:
    assignment_counts = _python_name_assignment_counts(tree)
    shadowed_names = _python_lexical_shadow_binding_names(tree, include_loop_targets=True)
    names: set[str] = set()
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            assignment = _python_single_name_assignment(node)
            if assignment is None:
                continue
            target_name, value = assignment
            if assignment_counts.get(target_name) != 1 or target_name in shadowed_names:
                continue
            if not _python_archive_member_expr_is_ooxml_structural(
                value,
                string_bindings,
                names,
                ooxml_structural_index_names,
            ):
                continue
            if target_name not in names:
                names.add(target_name)
                changed = True
    return names


def _python_archive_member_expr_is_ooxml_structural(
    node: ast.AST,
    string_bindings: dict[str, str],
    ooxml_structural_member_names: set[str],
    ooxml_structural_index_names: set[str],
) -> bool:
    member_name = _python_constant_or_bound_string(node, string_bindings)
    if member_name:
        return _python_archive_member_name_is_ooxml_structural(member_name)
    if isinstance(node, ast.Name):
        return node.id in ooxml_structural_member_names
    template = _python_archive_member_template_value(
        node,
        string_bindings,
        ooxml_structural_index_names,
    )
    return bool(template and _python_archive_member_template_is_ooxml_structural(template))


def _python_archive_member_template_value(
    node: ast.AST,
    string_bindings: dict[str, str],
    ooxml_structural_index_names: set[str],
) -> str:
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
                continue
            if (
                isinstance(value, ast.FormattedValue)
                and _python_archive_expr_is_safe_structural_index(
                    value.value,
                    ooxml_structural_index_names,
                    set(),
                )
            ):
                parts.append("{}")
                continue
            return ""
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _python_archive_member_template_value(
            node.left,
            string_bindings,
            ooxml_structural_index_names,
        )
        right = _python_archive_member_template_value(
            node.right,
            string_bindings,
            ooxml_structural_index_names,
        )
        if left and right:
            return left + right
    member_name = _python_constant_or_bound_string(node, string_bindings)
    return member_name or ""


def _python_archive_member_name_is_ooxml_structural(member_name: str) -> bool:
    normalized = str(member_name or "").strip().replace("\\", "/")
    if not normalized or normalized.startswith(("/", "~", ".")):
        return False
    if ".." in PurePosixPath(normalized).parts:
        return False
    if _python_archive_member_name_is_auxiliary(normalized):
        return False
    if normalized in {
        "[Content_Types].xml",
        "_rels/.rels",
        "docProps/app.xml",
        "docProps/core.xml",
        "ppt/_rels/presentation.xml.rels",
        "ppt/presentation.xml",
        "word/_rels/document.xml.rels",
        "word/document.xml",
        "xl/_rels/workbook.xml.rels",
        "xl/workbook.xml",
    }:
        return True
    return bool(re.fullmatch(
        r"(?:"
        r"ppt/slides/slide[1-9][0-9]*\.xml|"
        r"ppt/slides/_rels/slide[1-9][0-9]*\.xml\.rels|"
        r"ppt/slideLayouts/slideLayout[1-9][0-9]*\.xml|"
        r"ppt/slideLayouts/_rels/slideLayout[1-9][0-9]*\.xml\.rels|"
        r"ppt/slideMasters/slideMaster[1-9][0-9]*\.xml|"
        r"ppt/theme/theme[1-9][0-9]*\.xml|"
        r"xl/worksheets/sheet[1-9][0-9]*\.xml|"
        r"xl/worksheets/_rels/sheet[1-9][0-9]*\.xml\.rels"
        r")",
        normalized,
    ))


def _python_archive_member_template_is_ooxml_structural(template: str) -> bool:
    normalized = str(template or "").strip().replace("\\", "/")
    if not normalized or _python_archive_member_name_is_auxiliary(normalized):
        return False
    escaped = re.escape(normalized).replace(r"\{\}", r"[1-9][0-9]*")
    try:
        sample_re = re.compile(rf"^{escaped}$")
    except re.error:
        return False
    return any(
        sample_re.fullmatch(sample)
        for sample in (
            "ppt/slides/slide1.xml",
            "ppt/slides/_rels/slide1.xml.rels",
            "ppt/slideLayouts/slideLayout1.xml",
            "ppt/slideLayouts/_rels/slideLayout1.xml.rels",
            "ppt/slideMasters/slideMaster1.xml",
            "ppt/theme/theme1.xml",
            "xl/worksheets/sheet1.xml",
            "xl/worksheets/_rels/sheet1.xml.rels",
        )
    )


def _python_archive_external_reference_write_hint(text: str) -> bool:
    if _python_text_has_ooxml_external_reference(text):
        return True
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return False
    string_bindings = _python_string_literal_bindings(tree)
    payload_bindings, payload_sequence_bindings = _python_static_text_payload_bindings(
        tree,
        string_bindings,
    )
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "writestr"
        ):
            continue
        payload_node = _python_archive_writestr_payload_node(node)
        if payload_node is None:
            continue
        payload = _python_static_text_payload_value(
            payload_node,
            payload_bindings,
            payload_sequence_bindings,
        )
        if payload and _python_text_has_ooxml_external_reference(payload):
            return True
    return False


def _python_archive_writestr_payload_node(node: ast.Call) -> ast.AST | None:
    if len(node.args) >= 2:
        return node.args[1]
    for keyword in node.keywords:
        if keyword.arg in {"data", "s"}:
            return keyword.value
    return None


def _python_text_has_ooxml_external_reference(text: str) -> bool:
    lowered = str(text or "").lower()
    if not lowered:
        return False
    if "targetmode" in lowered and "external" in lowered:
        return True
    urls = re.findall(r"(?:https?|ftp|ftps)://[^\s'\"<>]+", lowered)
    external_urls = [
        url
        for url in urls
        if not (
            url.startswith("http://schemas.openxmlformats.org/")
            or url.startswith("https://schemas.openxmlformats.org/")
            or url.startswith("http://schemas.microsoft.com/office/")
            or url.startswith("https://schemas.microsoft.com/office/")
            or url.startswith("http://purl.oclc.org/ooxml/")
            or url.startswith("https://purl.oclc.org/ooxml/")
        )
    ]
    if not external_urls:
        return False
    return bool(re.search(
        r"(?:relationship|relationships|\.rels|hyperlink|oleobject|external|preview)",
        lowered,
    ))


def _python_archive_mutating_call_member_names(
    method_name: str,
    args: list[ast.AST],
    string_bindings: dict[str, str],
) -> list[str]:
    if method_name in {"__setitem__", "append", "add"} and args:
        return _python_archive_static_member_names_from_expr(args[0], string_bindings)
    if method_name == "insert" and len(args) >= 2:
        return _python_archive_static_member_names_from_expr(args[1], string_bindings)
    if method_name in {"extend", "update"} and args:
        return _python_archive_static_member_names_from_expr(args[0], string_bindings)
    if method_name in {"__delitem__", "setdefault"} and args:
        return _python_archive_static_member_names_from_expr(args[0], string_bindings)
    return []


def _python_archive_static_member_names_from_expr(
    node: ast.AST,
    string_bindings: dict[str, str],
) -> list[str]:
    member_name = _python_constant_or_bound_string(node, string_bindings)
    if member_name:
        return [member_name]
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        names: list[str] = []
        for element in node.elts:
            names.extend(_python_archive_static_member_names_from_expr(element, string_bindings))
        return names
    if isinstance(node, ast.Dict):
        names = []
        for key in node.keys:
            if key is not None:
                names.extend(_python_archive_static_member_names_from_expr(key, string_bindings))
        return names
    return []


def _python_archive_member_name_is_auxiliary(member_name: str) -> bool:
    normalized = str(member_name or "").strip().replace("\\", "/").lower()
    if not normalized:
        return False
    return bool(_ARCHIVE_AUXILIARY_MEMBER_WRITE_RE.search(normalized))


def _python_call_has_archive_write_receiver(
    node: ast.Call,
    scalar_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
    string_bindings: dict[str, str],
    reader_bindings: dict[str, set[str]],
    archive_handle_bindings: dict[str, list[str]],
) -> bool:
    if not isinstance(node.func, ast.Attribute):
        return False
    receiver = node.func.value
    if isinstance(receiver, ast.Name):
        return bool(archive_handle_bindings.get(receiver.id))
    if isinstance(receiver, ast.Call):
        return bool(_python_archive_write_call_targets(
            receiver,
            scalar_bindings,
            sequence_bindings,
            string_bindings,
            reader_bindings,
        ))
    return False


def _python_archive_write_receiver_targets(
    node: ast.Call,
    scalar_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
    string_bindings: dict[str, str],
    reader_bindings: dict[str, set[str]],
    archive_handle_bindings: dict[str, list[str]],
) -> list[str]:
    if not isinstance(node.func, ast.Attribute):
        return []
    receiver = node.func.value
    if isinstance(receiver, ast.Name):
        return list(archive_handle_bindings.get(receiver.id, []))
    if isinstance(receiver, ast.Call):
        return _python_archive_write_call_targets(
            receiver,
            scalar_bindings,
            sequence_bindings,
            string_bindings,
            reader_bindings,
        )
    return []


def _python_archive_member_name_arg_node(node: ast.Call) -> ast.AST | None:
    if not isinstance(node.func, ast.Attribute):
        return None
    if node.func.attr == "writestr":
        if node.args:
            return node.args[0]
        for keyword in node.keywords:
            if keyword.arg in {"zinfo_or_arcname", "arcname"}:
                return keyword.value
        return None
    if node.func.attr == "write":
        if len(node.args) >= 2:
            return node.args[1]
        for keyword in node.keywords:
            if keyword.arg == "arcname":
                return keyword.value
    return None


def _python_document_reader_bindings(tree: ast.AST) -> dict[str, set[str]]:
    string_bindings = _python_string_literal_bindings(tree)
    bindings = {
        "pdf_reader_names": set(),
        "pdf_module_names": set(),
        "zipfile_names": set(),
        "zipfile_module_names": set(),
        "docx_document_names": set(),
        "docx_module_names": set(),
        "pptx_presentation_names": set(),
        "pptx_module_names": set(),
        "openpyxl_load_workbook_names": set(),
        "openpyxl_module_names": set(),
        "pdfplumber_open_names": set(),
        "pdfplumber_module_names": set(),
        "compressed_open_names": set(),
        "compressed_module_names": set(),
        "pandas_excel_file_names": set(),
        "pandas_read_table_names": set(),
        "pandas_module_names": set(),
        "functools_module_names": set(),
        "functools_partial_names": set(),
        "importlib_module_names": set(),
        "importlib_import_module_names": set(),
        "operator_module_names": set(),
        "operator_attrgetter_names": set(),
        "operator_itemgetter_names": set(),
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", 1)[0]
                bound = alias.asname or root
                if alias.name in {"pypdf", "PyPDF2"} or root in {"pypdf", "PyPDF2"}:
                    bindings["pdf_module_names"].add(bound)
                elif alias.name == "zipfile" or root == "zipfile":
                    bindings["zipfile_module_names"].add(bound)
                elif alias.name == "docx" or root == "docx":
                    bindings["docx_module_names"].add(bound)
                elif alias.name == "pptx" or root == "pptx":
                    bindings["pptx_module_names"].add(bound)
                elif alias.name == "openpyxl" or root == "openpyxl":
                    bindings["openpyxl_module_names"].add(bound)
                elif alias.name == "pdfplumber" or root == "pdfplumber":
                    bindings["pdfplumber_module_names"].add(bound)
                elif alias.name in {"gzip", "bz2", "lzma"} or root in {"gzip", "bz2", "lzma"}:
                    bindings["compressed_module_names"].add(bound)
                elif alias.name == "pandas" or root == "pandas":
                    bindings["pandas_module_names"].add(bound)
                elif alias.name == "functools" or root == "functools":
                    bindings["functools_module_names"].add(bound)
                elif alias.name == "importlib" or root == "importlib":
                    bindings["importlib_module_names"].add(bound)
                elif alias.name == "operator" or root == "operator":
                    bindings["operator_module_names"].add(bound)
        elif isinstance(node, ast.ImportFrom):
            module = str(node.module or "")
            if module in {"pypdf", "PyPDF2"}:
                for alias in node.names:
                    if alias.name == "PdfReader":
                        bindings["pdf_reader_names"].add(alias.asname or alias.name)
            elif module == "zipfile":
                for alias in node.names:
                    if alias.name == "ZipFile":
                        bindings["zipfile_names"].add(alias.asname or alias.name)
            elif module == "docx":
                for alias in node.names:
                    if alias.name == "Document":
                        bindings["docx_document_names"].add(alias.asname or alias.name)
            elif module == "pptx":
                for alias in node.names:
                    if alias.name == "Presentation":
                        bindings["pptx_presentation_names"].add(alias.asname or alias.name)
            elif module == "openpyxl":
                for alias in node.names:
                    if alias.name == "load_workbook":
                        bindings["openpyxl_load_workbook_names"].add(alias.asname or alias.name)
            elif module == "pdfplumber":
                for alias in node.names:
                    if alias.name == "open":
                        bindings["pdfplumber_open_names"].add(alias.asname or alias.name)
            elif module in {"gzip", "bz2", "lzma"}:
                for alias in node.names:
                    if alias.name == "open":
                        bindings["compressed_open_names"].add(alias.asname or alias.name)
            elif module == "pandas":
                for alias in node.names:
                    if alias.name == "ExcelFile":
                        bindings["pandas_excel_file_names"].add(alias.asname or alias.name)
                    elif alias.name in {"read_excel", "read_csv", "read_table", "read_pickle"}:
                        bindings["pandas_read_table_names"].add(alias.asname or alias.name)
            elif module == "functools":
                for alias in node.names:
                    if alias.name == "partial":
                        bindings["functools_partial_names"].add(alias.asname or alias.name)
            elif module == "importlib":
                for alias in node.names:
                    if alias.name == "import_module":
                        bindings["importlib_import_module_names"].add(alias.asname or alias.name)
            elif module == "operator":
                for alias in node.names:
                    if alias.name == "attrgetter":
                        bindings["operator_attrgetter_names"].add(alias.asname or alias.name)
                    elif alias.name == "itemgetter":
                        bindings["operator_itemgetter_names"].add(alias.asname or alias.name)
    bindings["operator_attrgetter_names"] = _python_operator_attrgetter_aliases(
        tree,
        operator_module_aliases=bindings["operator_module_names"],
        initial_aliases=bindings["operator_attrgetter_names"],
    )
    bindings["operator_itemgetter_names"] = _python_operator_callable_aliases(
        tree,
        callable_name="itemgetter",
        operator_module_aliases=bindings["operator_module_names"],
        initial_aliases=bindings["operator_itemgetter_names"],
    )
    shadowed_names = _python_document_reader_shadowed_names(tree)
    for names in bindings.values():
        names.difference_update(shadowed_names)
    parent_map = _python_ast_parent_map(tree)
    dynamic_module_bindings = _python_document_reader_module_literal_bindings(tree)
    dynamic_loop_bindings = _python_document_reader_module_loop_bindings(
        tree,
        dynamic_module_bindings,
    )
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            for target_name, value in (
                _python_assignment_name_value_pairs_with_strings(node, string_bindings)
                + _python_default_arg_name_value_pairs_with_strings(node, string_bindings)
            ):
                if not _python_expr_is_trusted_document_reader_callable(value, bindings, string_bindings=string_bindings):
                    imported = _python_importlib_import_module_name(
                        value,
                        string_bindings=string_bindings,
                        importlib_aliases=bindings["importlib_module_names"],
                        import_module_aliases=bindings["importlib_import_module_names"],
                    )
                    if not _python_register_document_reader_module_alias(bindings, target_name, imported):
                        dynamic_imported = _python_document_reader_dynamic_import_modules(
                            value,
                            module_bindings=dynamic_module_bindings,
                            loop_bindings=dynamic_loop_bindings,
                            parent_map=parent_map,
                            importlib_aliases=bindings["importlib_module_names"],
                            import_module_aliases=bindings["importlib_import_module_names"],
                        )
                        if not _python_register_document_reader_dynamic_module_aliases(
                            bindings,
                            target_name,
                            dynamic_imported,
                        ):
                            continue
                    changed = True
                    continue
                if target_name not in bindings["pandas_read_table_names"]:
                    bindings["pandas_read_table_names"].add(target_name)
                    changed = True
    return bindings


def _python_document_reader_dynamic_import_modules(
    node: ast.AST,
    *,
    module_bindings: dict[str, tuple[str, ...]],
    loop_bindings: dict[str, list[ast.For | ast.AsyncFor]],
    parent_map: dict[ast.AST, ast.AST],
    importlib_aliases: set[str],
    import_module_aliases: set[str],
) -> tuple[str, ...]:
    if not isinstance(node, ast.Call) or not node.args or node.keywords:
        return ()
    func = node.func
    if isinstance(func, ast.Name):
        if func.id != "__import__" and func.id not in import_module_aliases:
            return ()
    elif not (
        isinstance(func, ast.Attribute)
        and func.attr == "import_module"
        and isinstance(func.value, ast.Name)
        and func.value.id in importlib_aliases
    ):
        return ()
    arg = node.args[0]
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        return (arg.value,) if arg.value in _PYTHON_DOCUMENT_READER_DYNAMIC_IMPORT_MODULES else ()
    if isinstance(arg, ast.Name):
        modules = module_bindings.get(arg.id, ())
        if len(modules) == 1:
            return modules
        for loop_node in loop_bindings.get(arg.id, []):
            if _python_ast_node_is_inside(arg, loop_node, parent_map):
                return _python_document_reader_module_iter_values(loop_node.iter, module_bindings)
    return ()


def _python_register_document_reader_dynamic_module_aliases(
    bindings: dict[str, set[str]],
    target_name: str,
    imported_modules: tuple[str, ...],
) -> bool:
    changed = False
    for imported_module in imported_modules:
        if _python_register_document_reader_module_alias(bindings, target_name, imported_module):
            changed = True
    return changed


def _python_register_document_reader_module_alias(
    bindings: dict[str, set[str]],
    target_name: str,
    imported_module: str,
) -> bool:
    root = imported_module.split(".", 1)[0]
    target_set: set[str] | None = None
    if root in {"pypdf", "PyPDF2"}:
        target_set = bindings.get("pdf_module_names", set())
    elif root == "zipfile":
        target_set = bindings.get("zipfile_module_names", set())
    elif root == "docx":
        target_set = bindings.get("docx_module_names", set())
    elif root == "pptx":
        target_set = bindings.get("pptx_module_names", set())
    elif root == "openpyxl":
        target_set = bindings.get("openpyxl_module_names", set())
    elif root == "pdfplumber":
        target_set = bindings.get("pdfplumber_module_names", set())
    elif root in {"gzip", "bz2", "lzma"}:
        target_set = bindings.get("compressed_module_names", set())
    elif root == "pandas":
        target_set = bindings.get("pandas_module_names", set())
    if target_set is None or target_name in target_set:
        return False
    target_set.add(target_name)
    return True


def _python_document_reader_shadowed_names(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            names.update(_python_argument_names(node.args))
        if isinstance(node, ast.Assign):
            for target in node.targets:
                names.update(_python_assignment_target_names(target))
        elif isinstance(node, ast.AnnAssign):
            names.update(_python_assignment_target_names(node.target))
        elif isinstance(node, ast.AugAssign):
            names.update(_python_assignment_target_names(node.target))
        elif isinstance(node, ast.NamedExpr):
            names.update(_python_assignment_target_names(node.target))
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            names.update(_python_assignment_target_names(node.target))
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    names.update(_python_assignment_target_names(item.optional_vars))
        elif isinstance(node, ast.ExceptHandler) and isinstance(node.name, str):
            names.add(node.name)
    return names


def _python_argument_names(args: ast.arguments) -> set[str]:
    names: set[str] = set()
    all_args = [
        *args.posonlyargs,
        *args.args,
        *args.kwonlyargs,
    ]
    if args.vararg is not None:
        all_args.append(args.vararg)
    if args.kwarg is not None:
        all_args.append(args.kwarg)
    for arg in all_args:
        names.add(arg.arg)
    return names


def _python_call_looks_like_document_reader(node: ast.Call) -> bool:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id in {
            "PdfReader",
            "ZipFile",
            "Document",
            "Presentation",
            "load_workbook",
            "ExcelFile",
            "read_excel",
            "read_csv",
            "read_table",
            "read_pickle",
        }
    return isinstance(func, ast.Attribute) and func.attr in {
        "PdfReader",
        "ZipFile",
        "Document",
        "Presentation",
        "load_workbook",
        "ExcelFile",
        "read_excel",
        "read_csv",
        "read_table",
        "read_pickle",
    }


def _python_call_is_document_reader(node: ast.Call, bindings: dict[str, set[str]]) -> bool:
    func = node.func
    if isinstance(func, ast.NamedExpr):
        return _python_expr_is_trusted_document_reader_callable(func.value, bindings)
    if _python_functools_partial_reader_effective_call(node, bindings) is not None:
        return True
    if isinstance(func, ast.Name):
        if func.id in bindings.get("pdf_reader_names", set()):
            return True
        if func.id in bindings.get("zipfile_names", set()):
            return True
        if func.id in bindings.get("docx_document_names", set()):
            return True
        if func.id in bindings.get("pptx_presentation_names", set()):
            return True
        if func.id in bindings.get("openpyxl_load_workbook_names", set()):
            return True
        if func.id in bindings.get("pdfplumber_open_names", set()):
            return True
        if func.id in bindings.get("compressed_open_names", set()):
            return _python_call_is_compressed_reader(node, bindings)
        if func.id in bindings.get("pandas_excel_file_names", set()):
            return True
        if func.id in bindings.get("pandas_read_table_names", set()):
            return True
        return False
    if not isinstance(func, ast.Attribute):
        return False
    if func.attr == "PdfReader":
        return (
            isinstance(func.value, ast.Name)
            and func.value.id in bindings.get("pdf_module_names", set())
        )
    if func.attr == "ZipFile":
        return (
            isinstance(func.value, ast.Name)
            and func.value.id in bindings.get("zipfile_module_names", set())
        )
    if func.attr == "Document":
        return (
            isinstance(func.value, ast.Name)
            and func.value.id in bindings.get("docx_module_names", set())
        )
    if func.attr == "Presentation":
        return (
            isinstance(func.value, ast.Name)
            and func.value.id in bindings.get("pptx_module_names", set())
        )
    if func.attr == "load_workbook":
        return (
            isinstance(func.value, ast.Name)
            and func.value.id in bindings.get("openpyxl_module_names", set())
        )
    if func.attr == "open":
        if (
            isinstance(func.value, ast.Name)
            and func.value.id in bindings.get("pdfplumber_module_names", set())
        ):
            return True
        return _python_call_is_compressed_reader(node, bindings)
    return (
        func.attr in {"ExcelFile", "read_excel", "read_csv", "read_table", "read_pickle"}
        and isinstance(func.value, ast.Name)
        and func.value.id in bindings.get("pandas_module_names", set())
    )


def _python_call_is_compressed_open(node: ast.Call, bindings: dict[str, set[str]]) -> bool:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id in bindings.get("compressed_open_names", set())
    return (
        isinstance(func, ast.Attribute)
        and func.attr == "open"
        and isinstance(func.value, ast.Name)
        and func.value.id in bindings.get("compressed_module_names", set())
    )


def _python_call_is_compressed_reader(node: ast.Call, bindings: dict[str, set[str]]) -> bool:
    return _python_call_is_compressed_open(node, bindings) and not _python_call_mode_writes_or_unknown(
        node,
        positional_index=1,
        string_bindings=_python_string_literal_bindings(ast.Module(body=[], type_ignores=[])),
    )


def _python_call_is_trusted_archive_write_open(
    node: ast.Call,
    string_bindings: dict[str, str],
    bindings: dict[str, set[str]],
) -> bool:
    if not _python_call_mode_writes(node, positional_index=1, string_bindings=string_bindings):
        return False
    func = node.func
    if isinstance(func, ast.Name):
        return func.id in bindings.get("zipfile_names", set())
    return (
        isinstance(func, ast.Attribute)
        and func.attr == "ZipFile"
        and isinstance(func.value, ast.Name)
        and func.value.id in bindings.get("zipfile_module_names", set())
    )


def _python_call_is_trusted_archive_read_open(
    node: ast.AST,
    string_bindings: dict[str, str],
    bindings: dict[str, set[str]],
) -> bool:
    if not isinstance(node, ast.Call):
        return False
    if _python_call_mode_writes_or_unknown(
        node,
        positional_index=1,
        string_bindings=string_bindings,
    ):
        return False
    func = node.func
    if isinstance(func, ast.Name):
        return func.id in bindings.get("zipfile_names", set())
    return (
        isinstance(func, ast.Attribute)
        and func.attr == "ZipFile"
        and isinstance(func.value, ast.Name)
        and func.value.id in bindings.get("zipfile_module_names", set())
    )


def _python_expr_is_trusted_document_reader_callable(
    node: ast.AST,
    bindings: dict[str, set[str]],
    *,
    string_bindings: dict[str, str] | None = None,
) -> bool:
    string_bindings = string_bindings or {}
    if isinstance(node, ast.NamedExpr):
        return _python_expr_is_trusted_document_reader_callable(
            node.value,
            bindings,
            string_bindings=string_bindings,
        )
    if isinstance(node, ast.Subscript):
        key = _python_static_subscript_string_key(node, string_bindings)
        if key and _python_document_reader_attr_in_module_mapping(
            key,
            node.value,
            bindings,
            string_bindings,
        ):
            return True
        element = _python_static_subscript_sequence_element(node)
        if element is None:
            element = _python_static_subscript_dict_value(node, string_bindings)
        return element is not None and _python_expr_is_trusted_document_reader_callable(
            element,
            bindings,
            string_bindings=string_bindings,
        )
    if _python_call_is_functools_partial_factory(node, bindings) and node.args:
        return _python_expr_is_trusted_document_reader_callable(
            node.args[0],
            bindings,
            string_bindings=string_bindings,
        )
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        element = _python_static_mapping_reader_value(node, string_bindings)
        if element is not None:
            return _python_expr_is_trusted_document_reader_callable(
                element,
                bindings,
                string_bindings=string_bindings,
            )
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "getattr"
        and len(node.args) >= 2
    ):
        attr = _python_constant_or_bound_string(node.args[1], string_bindings)
        return _python_document_reader_attr_on_module(attr, node.args[0], bindings)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Call)
        and _python_expr_is_operator_attrgetter_callable(
            node.func.func,
            operator_module_aliases=bindings.get("operator_module_names", set()),
            operator_attrgetter_aliases=bindings.get("operator_attrgetter_names", set()),
        )
        and node.func.args
        and node.args
    ):
        attr = _python_constant_or_bound_string(node.func.args[0], string_bindings)
        return _python_document_reader_attr_on_module(attr, node.args[0], bindings)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Call)
        and _python_expr_is_operator_named_callable(
            node.func.func,
            callable_name="itemgetter",
            operator_module_aliases=bindings.get("operator_module_names", set()),
            operator_callable_aliases=bindings.get("operator_itemgetter_names", set()),
        )
        and node.func.args
        and node.args
    ):
        key = _python_constant_or_bound_string(node.func.args[0], string_bindings)
        return _python_document_reader_attr_in_module_mapping(
            key,
            node.args[0],
            bindings,
            string_bindings,
        )
    if isinstance(node, ast.Name):
        return (
            node.id in bindings.get("pdf_reader_names", set())
            or node.id in bindings.get("zipfile_names", set())
            or node.id in bindings.get("docx_document_names", set())
            or node.id in bindings.get("pptx_presentation_names", set())
            or node.id in bindings.get("openpyxl_load_workbook_names", set())
            or node.id in bindings.get("pdfplumber_open_names", set())
            or node.id in bindings.get("pandas_excel_file_names", set())
            or node.id in bindings.get("pandas_read_table_names", set())
        )
    if not isinstance(node, ast.Attribute):
        return False
    return _python_document_reader_attr_on_module(node.attr, node.value, bindings)


def _python_call_is_functools_partial_factory(
    node: ast.AST,
    bindings: dict[str, set[str]],
) -> bool:
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Name):
        return func.id in bindings.get("functools_partial_names", set())
    return (
        isinstance(func, ast.Attribute)
        and func.attr == "partial"
        and isinstance(func.value, ast.Name)
        and func.value.id in bindings.get("functools_module_names", set())
    )


def _python_functools_partial_reader_effective_call(
    node: ast.Call,
    bindings: dict[str, set[str]],
) -> ast.Call | None:
    if not isinstance(node.func, ast.Call):
        return None
    partial_call = node.func
    if not _python_call_is_functools_partial_factory(partial_call, bindings) or not partial_call.args:
        return None
    reader_func = partial_call.args[0]
    if isinstance(reader_func, ast.Call):
        return None
    effective = ast.Call(
        func=reader_func,
        args=[*partial_call.args[1:], *node.args],
        keywords=[*partial_call.keywords, *node.keywords],
    )
    if _python_call_is_document_reader(effective, bindings):
        return effective
    return None


def _python_document_reader_attr_on_module(
    attr: str,
    module_node: ast.AST,
    bindings: dict[str, set[str]],
) -> bool:
    if not attr or not isinstance(module_node, ast.Name):
        return False
    module_name = module_node.id
    if attr == "PdfReader":
        return module_name in bindings.get("pdf_module_names", set())
    if attr == "ZipFile":
        return module_name in bindings.get("zipfile_module_names", set())
    if attr == "Document":
        return module_name in bindings.get("docx_module_names", set())
    if attr == "Presentation":
        return module_name in bindings.get("pptx_module_names", set())
    if attr == "load_workbook":
        return module_name in bindings.get("openpyxl_module_names", set())
    if attr == "open":
        return module_name in bindings.get("pdfplumber_module_names", set())
    return (
        attr in {"ExcelFile", "read_excel", "read_csv", "read_table", "read_pickle"}
        and module_name in bindings.get("pandas_module_names", set())
    )


def _python_document_reader_attr_in_module_mapping(
    attr: str,
    mapping_node: ast.AST,
    bindings: dict[str, set[str]],
    string_bindings: dict[str, str],
) -> bool:
    if not attr:
        return False
    module_node: ast.AST | None = None
    if isinstance(mapping_node, ast.Attribute) and mapping_node.attr == "__dict__":
        module_node = mapping_node.value
    elif isinstance(mapping_node, ast.Call):
        if isinstance(mapping_node.func, ast.Name) and mapping_node.func.id == "vars" and mapping_node.args:
            module_node = mapping_node.args[0]
        elif (
            isinstance(mapping_node.func, ast.Call)
            and _python_expr_is_operator_attrgetter_callable(
                mapping_node.func.func,
                operator_module_aliases=bindings.get("operator_module_names", set()),
                operator_attrgetter_aliases=bindings.get("operator_attrgetter_names", set()),
            )
            and mapping_node.func.args
            and _python_constant_or_bound_string(mapping_node.func.args[0], string_bindings) == "__dict__"
            and mapping_node.args
        ):
            module_node = mapping_node.args[0]
    return module_node is not None and _python_document_reader_attr_on_module(attr, module_node, bindings)


def _python_untrusted_document_reader_alias_names(
    tree: ast.AST,
    bindings: dict[str, set[str]],
) -> set[str]:
    untrusted: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = str(node.module or "")
            trusted_module = module in {
                "pypdf",
                "PyPDF2",
                "zipfile",
                "docx",
                "pptx",
                "openpyxl",
                "pdfplumber",
                "pandas",
            }
            for alias in node.names:
                if (
                    alias.name in {
                        "PdfReader",
                        "ZipFile",
                        "Document",
                        "Presentation",
                        "load_workbook",
                        "ExcelFile",
                        "read_excel",
                        "read_csv",
                        "read_table",
                        "read_pickle",
                    }
                    and not trusted_module
                ):
                    untrusted.add(alias.asname or alias.name)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name in {
                "PdfReader",
                "ZipFile",
                "Document",
                "Presentation",
                "load_workbook",
                "ExcelFile",
                "read_excel",
                "read_csv",
                "read_table",
                "read_pickle",
            }:
                untrusted.add(node.name)

    def _expr_is_untrusted_reader_callable(node: ast.AST) -> bool:
        if _python_expr_is_trusted_document_reader_callable(node, bindings):
            return False
        if isinstance(node, ast.Name):
            return node.id in untrusted or node.id in {
                "PdfReader",
                "ZipFile",
                "Document",
                "Presentation",
                "load_workbook",
                "ExcelFile",
                "read_excel",
                "read_csv",
                "read_table",
                "read_pickle",
            }
        return isinstance(node, ast.Attribute) and node.attr in {
            "PdfReader",
            "ZipFile",
            "Document",
            "Presentation",
            "load_workbook",
            "ExcelFile",
            "read_excel",
            "read_csv",
            "read_table",
            "read_pickle",
        }

    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            if not _expr_is_untrusted_reader_callable(node.value):
                continue
            for target in node.targets:
                for target_name in _python_assignment_target_names(target):
                    if target_name not in untrusted:
                        untrusted.add(target_name)
                        changed = True
    return untrusted


def _python_ast_has_untrusted_document_reader_like_call(tree: ast.AST) -> bool:
    bindings = _python_document_reader_bindings(tree)
    untrusted_names = _python_untrusted_document_reader_alias_names(tree, bindings)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name) and node.func.id in untrusted_names:
            return True
        if _python_call_looks_like_document_reader(node) and not _python_call_is_document_reader(node, bindings):
            return True
    return False


def _python_document_reader_has_unresolved_path_arg(
    tree: ast.AST,
    scalar_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
    *,
    allowed_output_read_targets: set[str] | None = None,
) -> bool:
    reader_bindings = _python_document_reader_bindings(tree)
    string_bindings = _python_string_literal_bindings(tree)
    safe_path_names, safe_iterable_names = _python_task_data_reader_safe_binding_names(
        tree,
        scalar_bindings,
        sequence_bindings,
    )
    (
        trusted_path_open_receivers,
        trusted_path_constructor_aliases,
        trusted_pathlib_module_aliases,
    ) = _python_trusted_pathlib_open_context(tree, scalar_bindings)
    allowed_output_read_targets = allowed_output_read_targets or set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not _python_call_is_document_reader(node, reader_bindings):
            continue
        if _python_call_is_trusted_archive_write_open(node, string_bindings, reader_bindings):
            continue
        source_nodes = _python_document_reader_source_arg_nodes(node, reader_bindings)
        if not source_nodes:
            return True
        for source_node in source_nodes:
            resolved, targets = _python_document_reader_arg_targets(
                source_node,
                scalar_bindings,
                sequence_bindings,
                safe_path_names,
                safe_iterable_names,
                trusted_path_open_receivers,
                trusted_path_constructor_aliases,
                trusted_pathlib_module_aliases,
                trusted_pathlike_required=True,
            )
            if not resolved:
                return True
            if targets and not (
                _python_paths_are_scope_task_data(targets)
                or _python_targets_are_allowed_task_output_readback(
                    targets,
                    allowed_output_read_targets,
                )
            ):
                return True
    return False


def _python_document_reader_has_unknown_non_url_path_arg(
    tree: ast.AST,
    scalar_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
) -> bool:
    reader_bindings = _python_document_reader_bindings(tree)
    string_bindings = _python_string_literal_bindings(tree)
    safe_path_names, safe_iterable_names = _python_task_data_reader_safe_binding_names(
        tree,
        scalar_bindings,
        sequence_bindings,
    )
    (
        trusted_path_open_receivers,
        trusted_path_constructor_aliases,
        trusted_pathlib_module_aliases,
    ) = _python_trusted_pathlib_open_context(tree, scalar_bindings)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not _python_call_is_document_reader(node, reader_bindings):
            continue
        if _python_call_is_trusted_archive_write_open(node, string_bindings, reader_bindings):
            continue
        source_nodes = _python_document_reader_source_arg_nodes(node, reader_bindings)
        if not source_nodes:
            return True
        for source_node in source_nodes:
            if _python_ast_arg_is_url(source_node, string_bindings, scalar_bindings):
                continue
            resolved, _targets = _python_document_reader_arg_targets(
                source_node,
                scalar_bindings,
                sequence_bindings,
                safe_path_names,
                safe_iterable_names,
                trusted_path_open_receivers,
                trusted_path_constructor_aliases,
                trusted_pathlib_module_aliases,
                trusted_pathlike_required=True,
            )
            if not resolved:
                return True
    return False


def _python_document_reader_has_untrusted_file_object_source(
    tree: ast.AST,
    scalar_bindings: dict[str, str],
) -> bool:
    reader_bindings = _python_document_reader_bindings(tree)
    string_bindings = _python_string_literal_bindings(tree)
    (
        trusted_path_open_receivers,
        trusted_path_constructor_aliases,
        trusted_pathlib_module_aliases,
    ) = _python_trusted_pathlib_open_context(tree, scalar_bindings)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not _python_call_is_document_reader(node, reader_bindings):
            continue
        if _python_call_is_trusted_archive_write_open(node, string_bindings, reader_bindings):
            continue
        for source_node in _python_document_reader_source_arg_nodes(node, reader_bindings):
            if not isinstance(source_node, ast.Call):
                continue
            func = source_node.func
            if isinstance(func, ast.Name) and func.id == "open":
                return True
            if not (isinstance(func, ast.Attribute) and func.attr == "open"):
                continue
            if _python_call_mode_writes_or_unknown(
                source_node,
                positional_index=0,
                string_bindings=string_bindings,
            ):
                return True
            if not _python_expr_is_trusted_pathlib_path_object(
                func.value,
                receiver_names=trusted_path_open_receivers,
                constructor_aliases=trusted_path_constructor_aliases,
                module_aliases=trusted_pathlib_module_aliases,
            ):
                return True
    return False


def _python_targets_are_allowed_task_output_readback(
    targets: list[str],
    allowed_output_read_targets: set[str],
) -> bool:
    if not targets or not allowed_output_read_targets:
        return False
    return all(
        _is_scope_task_output_write_target(path)
        and normalize_task_artifact_path(path, cwd=_NORMALIZER_CWD.get()).lower()
        in allowed_output_read_targets
        for path in targets
    )


def _python_task_data_reader_safe_binding_names(
    tree: ast.AST,
    scalar_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
) -> tuple[set[str], set[str]]:
    (
        trusted_path_open_receivers,
        trusted_path_constructor_aliases,
        trusted_pathlib_module_aliases,
    ) = _python_trusted_pathlib_open_context(tree, scalar_bindings)
    untrusted_pathlike_names = _python_untrusted_pathlike_binding_names(
        tree,
        constructor_aliases=trusted_path_constructor_aliases,
        module_aliases=trusted_pathlib_module_aliases,
    )
    safe_path_names = {
        name
        for name, path in scalar_bindings.items()
        if _python_paths_are_scope_task_data([path]) and name not in untrusted_pathlike_names
    }
    safe_iterable_names: set[str] = set()
    import_aliases = _python_readonly_import_aliases(tree)
    reader_bindings = _python_document_reader_bindings(tree)
    string_bindings = _python_string_literal_bindings(tree)
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                if _python_expr_iterates_task_data_path_objects(
                    node.value,
                    scalar_bindings,
                    sequence_bindings,
                    safe_path_names,
                    safe_iterable_names,
                    import_aliases,
                ):
                    for target in node.targets:
                        for target_name in _python_assignment_target_names(target):
                            if target_name not in safe_iterable_names:
                                safe_iterable_names.add(target_name)
                                changed = True
                resolved, targets = _python_document_reader_arg_targets(
                    node.value,
                    scalar_bindings,
                    sequence_bindings,
                    safe_path_names,
                    safe_iterable_names,
                    trusted_path_open_receivers,
                    trusted_path_constructor_aliases,
                    trusted_pathlib_module_aliases,
                    trusted_pathlike_required=True,
                )
                if not resolved:
                    resolved, targets = _python_document_reader_call_arg_targets(
                        node.value,
                        scalar_bindings,
                        sequence_bindings,
                        safe_path_names,
                        safe_iterable_names,
                        reader_bindings,
                        string_bindings,
                        trusted_path_open_receivers,
                        trusted_path_constructor_aliases,
                        trusted_pathlib_module_aliases,
                    )
                if resolved and (not targets or _python_paths_are_scope_task_data(targets)):
                    for target in node.targets:
                        for target_name in _python_assignment_target_names(target):
                            if target_name not in safe_path_names:
                                safe_path_names.add(target_name)
                                changed = True
            elif isinstance(node, ast.For):
                if not _python_expr_iterates_task_data_path_objects(
                    node.iter,
                    scalar_bindings,
                    sequence_bindings,
                    safe_path_names,
                    safe_iterable_names,
                    import_aliases,
                ):
                    continue
                for target_name in _python_assignment_target_names(node.target):
                    if target_name not in safe_path_names:
                        safe_path_names.add(target_name)
                        changed = True
    return safe_path_names, safe_iterable_names


def _python_untrusted_pathlike_binding_names(
    tree: ast.AST,
    *,
    constructor_aliases: set[str],
    module_aliases: set[str],
) -> set[str]:
    untrusted: set[str] = set()
    assignment_counts = _python_name_assignment_counts(tree)
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            assignment = _python_single_name_assignment(node)
            if assignment is None:
                continue
            target_name, value = assignment
            if assignment_counts.get(target_name) != 1:
                continue
            if _python_expr_is_untrusted_pathlike_binding(
                value,
                untrusted_names=untrusted,
                constructor_aliases=constructor_aliases,
                module_aliases=module_aliases,
            ) and target_name not in untrusted:
                untrusted.add(target_name)
                changed = True
    return untrusted


def _python_expr_is_untrusted_pathlike_binding(
    node: ast.AST,
    *,
    untrusted_names: set[str],
    constructor_aliases: set[str],
    module_aliases: set[str],
) -> bool:
    if isinstance(node, ast.Name):
        return node.id in untrusted_names
    if isinstance(node, ast.Call) and _python_call_is_path_constructor(node):
        return not _python_call_is_trusted_pathlib_constructor(
            node,
            constructor_aliases=constructor_aliases,
            module_aliases=module_aliases,
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        return _python_expr_is_untrusted_pathlike_binding(
            node.left,
            untrusted_names=untrusted_names,
            constructor_aliases=constructor_aliases,
            module_aliases=module_aliases,
        )
    return False


def _python_document_reader_call_arg_targets(
    node: ast.AST,
    scalar_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
    safe_path_names: set[str],
    safe_iterable_names: set[str],
    reader_bindings: dict[str, set[str]],
    string_bindings: dict[str, str],
    trusted_path_open_receivers: set[str] | None = None,
    trusted_path_constructor_aliases: set[str] | None = None,
    trusted_pathlib_module_aliases: set[str] | None = None,
) -> tuple[bool, list[str]]:
    if not isinstance(node, ast.Call):
        return (False, [])
    if not _python_call_is_document_reader(node, reader_bindings):
        return (False, [])
    if _python_call_is_trusted_archive_write_open(node, string_bindings, reader_bindings):
        return (False, [])
    targets: list[str] = []
    resolved_any = False
    for source_node in _python_document_reader_source_arg_nodes(node, reader_bindings):
        resolved, reader_targets = _python_document_reader_arg_targets(
            source_node,
            scalar_bindings,
            sequence_bindings,
            safe_path_names,
            safe_iterable_names,
            trusted_path_open_receivers,
            trusted_path_constructor_aliases,
            trusted_pathlib_module_aliases,
            trusted_pathlike_required=True,
        )
        if not resolved:
            return (False, [])
        resolved_any = True
        targets.extend(reader_targets)
    return (resolved_any, _dedupe_strings(targets))


def _python_document_reader_source_arg_nodes(
    node: ast.Call,
    reader_bindings: dict[str, set[str]] | None = None,
) -> list[ast.AST]:
    if reader_bindings is not None:
        effective_call = _python_functools_partial_reader_effective_call(node, reader_bindings)
        if effective_call is not None:
            node = effective_call
    nodes: list[ast.AST] = []
    if node.args:
        nodes.append(node.args[0])
    for keyword in node.keywords:
        if keyword.arg in _PYTHON_DOCUMENT_READER_SOURCE_KEYWORDS and not _python_ast_is_none(keyword.value):
            nodes.append(keyword.value)
    return nodes


def _python_trusted_pathlib_open_context(
    tree: ast.AST,
    scalar_bindings: dict[str, str],
) -> tuple[set[str], set[str], set[str]]:
    if _python_has_dynamic_namespace_mutation(tree):
        return set(), set(), set()

    constructor_aliases: set[str] = set()
    module_aliases: set[str] = set()
    shadowed: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "pathlib":
                    module_aliases.add(alias.asname or alias.name)
                elif alias.name.startswith("pathlib."):
                    shadowed.add(alias.asname or alias.name.rsplit(".", 1)[-1])
            continue
        if isinstance(node, ast.ImportFrom):
            if node.module == "pathlib":
                for alias in node.names:
                    if alias.name in _PYTHON_PATH_CONSTRUCTOR_NAMES:
                        constructor_aliases.add(alias.asname or alias.name)
                    else:
                        shadowed.add(alias.asname or alias.name)
            elif node.module:
                for alias in node.names:
                    shadowed.add(alias.asname or alias.name)
            continue
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            shadowed.add(node.name)
            continue
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                shadowed.update(_python_assignment_target_names(target))

    constructor_aliases -= shadowed
    module_aliases -= shadowed
    if not constructor_aliases and not module_aliases:
        return set(), set(), set()
    if _python_pathlib_pathlike_is_monkeypatched(
        tree,
        constructor_aliases=constructor_aliases,
        module_aliases=module_aliases,
    ):
        return set(), set(), set()

    assignment_counts = _python_name_assignment_counts(tree)
    receiver_names: set[str] = set()
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            assignment = _python_single_name_assignment(node)
            if assignment is None:
                continue
            target_name, value = assignment
            if assignment_counts.get(target_name) != 1 or target_name not in scalar_bindings:
                continue
            if _python_expr_is_trusted_pathlib_path_object(
                value,
                receiver_names=receiver_names,
                constructor_aliases=constructor_aliases,
                module_aliases=module_aliases,
            ):
                if target_name not in receiver_names:
                    receiver_names.add(target_name)
                    changed = True
    return receiver_names, constructor_aliases, module_aliases


def _python_pathlib_pathlike_is_monkeypatched(
    tree: ast.AST,
    *,
    constructor_aliases: set[str],
    module_aliases: set[str],
) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if _python_expr_is_pathlib_pathlike_attribute(
                    target,
                    constructor_aliases=constructor_aliases,
                    module_aliases=module_aliases,
                ) or _python_expr_is_pathlib_constructor_module_attribute(
                    target,
                    module_aliases=module_aliases,
                ):
                    return True
            continue
        if not isinstance(node, ast.Call):
            continue
        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "setattr"
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value in _PYTHON_TRUSTED_PATHLIKE_METHOD_NAMES
            and (
                _python_expr_is_pathlib_constructor_class(
                    node.args[0],
                    constructor_aliases=constructor_aliases,
                    module_aliases=module_aliases,
                )
                or _python_expr_is_type_call(node.args[0])
            )
        ):
            return True
        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "setattr"
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value in _PYTHON_PATH_CONSTRUCTOR_NAMES
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id in module_aliases
        ):
            return True
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "__setattr__"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "type"
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value in _PYTHON_TRUSTED_PATHLIKE_METHOD_NAMES
            and (
                _python_expr_is_pathlib_constructor_class(
                    node.args[0],
                    constructor_aliases=constructor_aliases,
                    module_aliases=module_aliases,
                )
                or _python_expr_is_type_call(node.args[0])
            )
        ):
            return True
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "__setattr__"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "type"
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value in _PYTHON_PATH_CONSTRUCTOR_NAMES
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id in module_aliases
        ):
            return True
    return False


def _python_expr_is_pathlib_pathlike_attribute(
    node: ast.AST,
    *,
    constructor_aliases: set[str],
    module_aliases: set[str],
) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr in _PYTHON_TRUSTED_PATHLIKE_METHOD_NAMES
        and _python_expr_is_pathlib_constructor_class(
            node.value,
            constructor_aliases=constructor_aliases,
            module_aliases=module_aliases,
        )
    )


def _python_expr_is_pathlib_constructor_module_attribute(
    node: ast.AST,
    *,
    module_aliases: set[str],
) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr in _PYTHON_PATH_CONSTRUCTOR_NAMES
        and isinstance(node.value, ast.Name)
        and node.value.id in module_aliases
    )


def _python_expr_is_type_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "type"
        and len(node.args) == 1
    )


def _python_expr_is_pathlib_constructor_class(
    node: ast.AST,
    *,
    constructor_aliases: set[str],
    module_aliases: set[str],
) -> bool:
    if isinstance(node, ast.Name):
        return node.id in constructor_aliases
    return (
        isinstance(node, ast.Attribute)
        and node.attr in _PYTHON_PATH_CONSTRUCTOR_NAMES
        and isinstance(node.value, ast.Name)
        and node.value.id in module_aliases
    )


def _python_call_is_trusted_pathlib_constructor(
    node: ast.AST,
    *,
    constructor_aliases: set[str],
    module_aliases: set[str],
) -> bool:
    if not isinstance(node, ast.Call):
        return False
    return _python_expr_is_pathlib_constructor_class(
        node.func,
        constructor_aliases=constructor_aliases,
        module_aliases=module_aliases,
    )


def _python_expr_is_trusted_pathlib_path_object(
    node: ast.AST,
    *,
    receiver_names: set[str],
    constructor_aliases: set[str],
    module_aliases: set[str],
) -> bool:
    if isinstance(node, ast.Name):
        return node.id in receiver_names
    if _python_call_is_trusted_pathlib_constructor(
        node,
        constructor_aliases=constructor_aliases,
        module_aliases=module_aliases,
    ):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        return (
            _python_expr_is_trusted_pathlib_path_object(
                node.left,
                receiver_names=receiver_names,
                constructor_aliases=constructor_aliases,
                module_aliases=module_aliases,
            )
            and _python_static_relative_path_fragment(node.right) is not None
        )
    return False


def _python_expr_is_trusted_document_reader_pathlike(
    node: ast.AST,
    *,
    safe_path_names: set[str],
    receiver_names: set[str],
    constructor_aliases: set[str],
    module_aliases: set[str],
) -> bool:
    if isinstance(node, ast.Name) and node.id in safe_path_names:
        return True
    return _python_expr_is_trusted_pathlib_path_object(
        node,
        receiver_names=receiver_names,
        constructor_aliases=constructor_aliases,
        module_aliases=module_aliases,
    )


def _python_document_reader_arg_targets(
    node: ast.AST | None,
    scalar_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
    safe_path_names: set[str],
    safe_iterable_names: set[str],
    trusted_path_open_receivers: set[str] | None = None,
    trusted_path_constructor_aliases: set[str] | None = None,
    trusted_pathlib_module_aliases: set[str] | None = None,
    *,
    trusted_pathlike_required: bool = False,
) -> tuple[bool, list[str]]:
    trusted_path_open_receivers = trusted_path_open_receivers or set()
    trusted_path_constructor_aliases = trusted_path_constructor_aliases or set()
    trusted_pathlib_module_aliases = trusted_pathlib_module_aliases or set()
    if node is None:
        return (False, [])
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return _python_literal_path_arg_targets(node.value)
    if isinstance(node, ast.Name):
        if node.id in scalar_bindings:
            target = scalar_bindings[node.id]
            if _URL_RE.match(target):
                return (False, [])
            return (True, [target])
        targets: list[str] = []
        targets.extend(sequence_bindings.get(node.id, []))
        if any(_URL_RE.match(path) for path in targets):
            return (False, [])
        if targets:
            return (True, _dedupe_strings(targets))
        if node.id in safe_path_names:
            return (True, [])
        return (False, [])
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Name) and func.id in {"str", "bytes"} and len(node.args) == 1:
            if trusted_pathlike_required and not _python_expr_is_trusted_document_reader_pathlike(
                node.args[0],
                safe_path_names=safe_path_names,
                receiver_names=trusted_path_open_receivers,
                constructor_aliases=trusted_path_constructor_aliases,
                module_aliases=trusted_pathlib_module_aliases,
            ):
                return (False, [])
            return _python_document_reader_arg_targets(
                node.args[0],
                scalar_bindings,
                sequence_bindings,
                safe_path_names,
                safe_iterable_names,
                trusted_path_open_receivers,
                trusted_path_constructor_aliases,
                trusted_pathlib_module_aliases,
                trusted_pathlike_required=trusted_pathlike_required,
            )
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "fspath"
            and isinstance(func.value, ast.Name)
            and func.value.id == "os"
            and len(node.args) == 1
        ):
            if trusted_pathlike_required and not _python_expr_is_trusted_document_reader_pathlike(
                node.args[0],
                safe_path_names=safe_path_names,
                receiver_names=trusted_path_open_receivers,
                constructor_aliases=trusted_path_constructor_aliases,
                module_aliases=trusted_pathlib_module_aliases,
            ):
                return (False, [])
            return _python_document_reader_arg_targets(
                node.args[0],
                scalar_bindings,
                sequence_bindings,
                safe_path_names,
                safe_iterable_names,
                trusted_path_open_receivers,
                trusted_path_constructor_aliases,
                trusted_pathlib_module_aliases,
                trusted_pathlike_required=trusted_pathlike_required,
            )
        if _python_call_is_path_constructor(node) or _python_call_is_trusted_pathlib_constructor(
            node,
            constructor_aliases=trusted_path_constructor_aliases,
            module_aliases=trusted_pathlib_module_aliases,
        ):
            if trusted_pathlike_required and not _python_call_is_trusted_pathlib_constructor(
                node,
                constructor_aliases=trusted_path_constructor_aliases,
                module_aliases=trusted_pathlib_module_aliases,
            ):
                return (False, [])
            if node.args:
                return _python_document_reader_arg_targets(
                    node.args[0],
                    scalar_bindings,
                    sequence_bindings,
                    safe_path_names,
                    safe_iterable_names,
                    trusted_path_open_receivers,
                    trusted_path_constructor_aliases,
                    trusted_pathlib_module_aliases,
                    trusted_pathlike_required=trusted_pathlike_required,
                )
            return (False, [])
        if isinstance(func, ast.Attribute) and func.attr == "open":
            if not _python_expr_is_trusted_pathlib_path_object(
                func.value,
                receiver_names=trusted_path_open_receivers,
                constructor_aliases=trusted_path_constructor_aliases,
                module_aliases=trusted_pathlib_module_aliases,
            ):
                return (False, [])
            if _python_call_mode_writes_or_unknown(
                node,
                positional_index=0,
                string_bindings={},
            ):
                return (False, [])
            return _python_document_reader_arg_targets(
                func.value,
                scalar_bindings,
                sequence_bindings,
                safe_path_names,
                safe_iterable_names,
                trusted_path_open_receivers,
                trusted_path_constructor_aliases,
                trusted_pathlib_module_aliases,
                trusted_pathlike_required=True,
            )
        if isinstance(func, ast.Name) and func.id == "next" and node.args:
            try:
                import_aliases = _python_readonly_import_aliases(ast.Module(body=[], type_ignores=[]))
            except TypeError:
                import_aliases = _empty_python_readonly_import_aliases()
            return (
                _python_expr_iterates_task_data_path_objects(
                    node.args[0],
                    scalar_bindings,
                    sequence_bindings,
                    safe_path_names,
                    safe_iterable_names,
                    import_aliases,
                ),
                [],
            )
    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
        name = node.value.id
        if name in sequence_bindings and _python_paths_are_scope_task_data(sequence_bindings[name]):
            return (True, list(sequence_bindings[name]))
        if name in safe_iterable_names:
            return (True, [])
    if isinstance(node, ast.Subscript):
        argv_index = _python_sys_argv_subscript_index(node)
        argv_path = _PYTHON_ARGV_PATH_BINDINGS.get().get(argv_index) if argv_index is not None else None
        if argv_path:
            if _URL_RE.match(argv_path):
                return (False, [])
            return (True, [argv_path])
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        left_resolved, left_targets = _python_document_reader_arg_targets(
            node.left,
            scalar_bindings,
            sequence_bindings,
            safe_path_names,
            safe_iterable_names,
            trusted_path_open_receivers,
            trusted_path_constructor_aliases,
            trusted_pathlib_module_aliases,
            trusted_pathlike_required=trusted_pathlike_required,
        )
        fragment = _python_static_relative_path_fragment(node.right)
        if left_resolved and fragment is not None:
            if left_targets:
                return (True, [posixpath.join(path, fragment) for path in left_targets])
            return (True, [])
    return (False, [])


def _python_expr_iterates_task_data_path_objects(
    node: ast.AST,
    scalar_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
    safe_path_names: set[str],
    safe_iterable_names: set[str],
    import_aliases: dict[str, set[str]],
) -> bool:
    if isinstance(node, ast.Name):
        if node.id in safe_iterable_names:
            return True
        return node.id in sequence_bindings and _python_paths_are_scope_task_data(sequence_bindings[node.id])
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in {"glob", "rglob", "iterdir"}:
            resolved, targets = _python_document_reader_arg_targets(
                func.value,
                scalar_bindings,
                sequence_bindings,
                safe_path_names,
                safe_iterable_names,
            )
            return resolved and (not targets or _python_paths_are_scope_task_data(targets))
        if isinstance(func, ast.Name) and func.id in {"list", "tuple", "sorted", "set", "iter", "reversed"} and node.args:
            return _python_expr_iterates_task_data_path_objects(
                node.args[0],
                scalar_bindings,
                sequence_bindings,
                safe_path_names,
                safe_iterable_names,
                import_aliases,
            )
        if isinstance(func, ast.Name) and func.id == "enumerate" and node.args:
            return _python_expr_iterates_task_data_path_objects(
                node.args[0],
                scalar_bindings,
                sequence_bindings,
                safe_path_names,
                safe_iterable_names,
                import_aliases,
            )
        if isinstance(func, ast.Name) and func.id == "filter" and len(node.args) >= 2:
            return _python_expr_iterates_task_data_path_objects(
                node.args[1],
                scalar_bindings,
                sequence_bindings,
                safe_path_names,
                safe_iterable_names,
                import_aliases,
            )
        if isinstance(func, ast.Name) and func.id in {"map", "zip"} and len(node.args) >= 2:
            return any(
                _python_expr_iterates_task_data_path_objects(
                    arg,
                    scalar_bindings,
                    sequence_bindings,
                    safe_path_names,
                    safe_iterable_names,
                    import_aliases,
                )
                for arg in node.args[1 if func.id == "map" else 0:]
            )
        if _python_expr_is_itertools_chain_function(func, import_aliases):
            return any(
                _python_expr_iterates_task_data_path_objects(
                    arg,
                    scalar_bindings,
                    sequence_bindings,
                    safe_path_names,
                    safe_iterable_names,
                    import_aliases,
                )
                for arg in node.args
            )
        if _python_expr_is_itertools_chain_from_iterable_function(func, import_aliases) and node.args:
            return _python_expr_iterates_task_data_iterables(
                node.args[0],
                scalar_bindings,
                sequence_bindings,
                safe_path_names,
                safe_iterable_names,
                import_aliases,
            )
        passthrough_arg_index = _python_itertools_path_iterator_arg_index(func, import_aliases)
        if passthrough_arg_index is not None and len(node.args) > passthrough_arg_index:
            return _python_expr_iterates_task_data_path_objects(
                node.args[passthrough_arg_index],
                scalar_bindings,
                sequence_bindings,
                safe_path_names,
                safe_iterable_names,
                import_aliases,
            )
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        if not node.elts:
            return False
        return all(
            (
                isinstance(element, ast.Starred)
                and _python_expr_iterates_task_data_path_objects(
                    element.value,
                    scalar_bindings,
                    sequence_bindings,
                    safe_path_names,
                    safe_iterable_names,
                    import_aliases,
                )
            )
            or _python_document_reader_arg_targets(
                element,
                scalar_bindings,
                sequence_bindings,
                safe_path_names,
                safe_iterable_names,
            )[0]
            for element in node.elts
        )
    if isinstance(node, ast.Subscript):
        return _python_expr_iterates_task_data_path_objects(
            node.value,
            scalar_bindings,
            sequence_bindings,
            safe_path_names,
            safe_iterable_names,
            import_aliases,
        )
    return False


def _python_expr_iterates_task_data_iterables(
    node: ast.AST,
    scalar_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
    safe_path_names: set[str],
    safe_iterable_names: set[str],
    import_aliases: dict[str, set[str]],
) -> bool:
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(
            _python_expr_iterates_task_data_path_objects(
                element,
                scalar_bindings,
                sequence_bindings,
                safe_path_names,
                safe_iterable_names,
                import_aliases,
            )
            for element in node.elts
        )
    return _python_expr_iterates_task_data_path_objects(
        node,
        scalar_bindings,
        sequence_bindings,
        safe_path_names,
        safe_iterable_names,
        import_aliases,
    )


def _python_call_is_path_constructor(node: ast.Call) -> bool:
    func = node.func
    if isinstance(func, ast.Name) and func.id in _PYTHON_PATH_CONSTRUCTOR_NAMES:
        return True
    return (
        isinstance(func, ast.Attribute)
        and func.attr in _PYTHON_PATH_CONSTRUCTOR_NAMES
        and isinstance(func.value, ast.Name)
        and func.value.id == "pathlib"
    )


def _python_literal_path_arg_targets(value: str) -> tuple[bool, list[str]]:
    normalized = str(value or "").strip()
    if not normalized:
        return (False, [])
    if not (
        _python_string_is_explicit_filesystem_path(normalized)
        or (
            _looks_like_path_arg(normalized)
            and _is_scope_task_data_path(normalized)
        )
    ):
        return (False, [])
    return (True, [normalized])


def _python_literal_writer_path_arg_targets(value: str) -> tuple[bool, list[str]]:
    normalized = str(value or "").strip()
    if not normalized or _URL_RE.match(normalized):
        return (False, [])
    if not (_python_string_is_explicit_filesystem_path(normalized) or _looks_like_path_arg(normalized)):
        return (False, [])
    return (True, [normalized])


def _python_path_writer_target_arg_nodes(
    node: ast.Call,
    *,
    non_file_sink_names: set[str] | None = None,
    writer_method_aliases: dict[str, str] | None = None,
) -> list[ast.AST]:
    writer_method_aliases = writer_method_aliases or {}
    if isinstance(node.func, ast.Attribute):
        method = node.func.attr
    elif isinstance(node.func, ast.Name):
        method = writer_method_aliases.get(node.func.id, "")
    else:
        return []
    if method not in _PYTHON_PATH_WRITER_METHOD_NAMES:
        return []
    targets: list[ast.AST] = []
    non_file_sink_names = non_file_sink_names or set()
    if (
        node.args
        and not _python_ast_is_none(node.args[0])
        and not _python_ast_is_non_file_writer_sink(node.args[0], non_file_sink_names)
    ):
        targets.append(node.args[0])
    target_keywords = _PYTHON_PATH_WRITER_KEYWORDS_BY_METHOD.get(method, frozenset())
    for keyword in node.keywords:
        if (
            keyword.arg in target_keywords
            and not _python_ast_is_none(keyword.value)
            and not _python_ast_is_non_file_writer_sink(keyword.value, non_file_sink_names)
        ):
            targets.append(keyword.value)
    return targets


def _python_path_writer_constructor_target_arg_nodes(
    node: ast.Call,
    *,
    non_file_sink_names: set[str] | None = None,
    writer_constructor_module_aliases: set[str] | None = None,
    writer_constructor_aliases: set[str] | None = None,
) -> list[ast.AST]:
    writer_constructor_module_aliases = writer_constructor_module_aliases or set()
    writer_constructor_aliases = writer_constructor_aliases or set()
    func = node.func
    if isinstance(func, ast.Name):
        constructor = func.id
        if constructor not in writer_constructor_aliases:
            return []
    elif isinstance(func, ast.Attribute):
        constructor = func.attr
        if not (
            isinstance(func.value, ast.Name)
            and func.value.id in writer_constructor_module_aliases
        ):
            return []
    else:
        return []
    if constructor not in _PYTHON_PATH_WRITER_CONSTRUCTOR_NAMES:
        return []
    targets: list[ast.AST] = []
    non_file_sink_names = non_file_sink_names or set()
    if (
        node.args
        and not _python_ast_is_none(node.args[0])
        and not _python_ast_is_non_file_writer_sink(node.args[0], non_file_sink_names)
    ):
        targets.append(node.args[0])
    target_keywords = _PYTHON_PATH_WRITER_CONSTRUCTOR_KEYWORDS_BY_NAME.get(
        constructor,
        frozenset(),
    )
    for keyword in node.keywords:
        if (
            keyword.arg in target_keywords
            and not _python_ast_is_none(keyword.value)
            and not _python_ast_is_non_file_writer_sink(keyword.value, non_file_sink_names)
        ):
            targets.append(keyword.value)
    return targets


def _python_path_writer_constructor_aliases(tree: ast.AST) -> tuple[set[str], set[str]]:
    module_alias_sources: dict[str, set[str]] = {}
    constructor_alias_sources: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound = alias.asname or alias.name.split(".", 1)[0]
                source = "pandas" if alias.name == "pandas" else "other"
                module_alias_sources.setdefault(bound, set()).add(source)
        elif isinstance(node, ast.ImportFrom):
            module = str(node.module or "")
            for alias in node.names:
                bound = alias.asname or alias.name
                if alias.name == "ExcelWriter":
                    source = "pandas" if module == "pandas" else "other"
                    constructor_alias_sources.setdefault(bound, set()).add(source)

    local_definitions = (
        _python_non_import_binding_names(tree)
        | _python_lexical_shadow_binding_names(tree, include_loop_targets=True)
    )
    module_aliases = {
        name
        for name, sources in module_alias_sources.items()
        if sources == {"pandas"} and name not in local_definitions
    }
    constructor_aliases = {
        name
        for name, sources in constructor_alias_sources.items()
        if sources == {"pandas"} and name not in local_definitions
    }
    mutated_module_aliases = _python_path_writer_constructor_module_alias_mutations(
        tree,
        module_aliases,
    )
    return module_aliases - mutated_module_aliases, constructor_aliases


def _python_non_import_binding_names(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
            continue
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
            target = node.target if not isinstance(node, ast.Assign) else None
            targets = [target] if target is not None else list(node.targets)
            for item in targets:
                names.update(_python_assignment_target_names(item))
    return names


def _python_path_writer_constructor_module_alias_mutations(
    tree: ast.AST,
    module_aliases: set[str],
) -> set[str]:
    mutated: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = [node.target] if not isinstance(node, ast.Assign) else list(node.targets)
            for target in targets:
                if (
                    isinstance(target, ast.Attribute)
                    and target.attr in _PYTHON_PATH_WRITER_CONSTRUCTOR_NAMES
                    and isinstance(target.value, ast.Name)
                    and target.value.id in module_aliases
                ):
                    mutated.add(target.value.id)
        if not isinstance(node, ast.Call):
            continue
        if not (
            isinstance(node.func, ast.Name)
            and node.func.id == "setattr"
            and len(node.args) >= 2
        ):
            continue
        receiver, attr_name = node.args[0], node.args[1]
        if (
            isinstance(receiver, ast.Name)
            and receiver.id in module_aliases
            and isinstance(attr_name, ast.Constant)
            and attr_name.value in _PYTHON_PATH_WRITER_CONSTRUCTOR_NAMES
        ):
            mutated.add(receiver.id)
    return mutated


def _python_path_writer_method_aliases(tree: ast.AST) -> dict[str, str]:
    assignment_counts = _python_name_assignment_counts(tree)
    aliases: dict[str, str] = {}
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            for target_name, value in _python_assignment_name_value_pairs(node):
                if assignment_counts.get(target_name) != 1:
                    continue
                method = ""
                if isinstance(value, ast.Attribute) and value.attr in _PYTHON_PATH_WRITER_METHOD_NAMES:
                    method = value.attr
                elif isinstance(value, ast.Name):
                    method = aliases.get(value.id, "")
                if method and aliases.get(target_name) != method:
                    aliases[target_name] = method
                    changed = True
    return aliases


def _python_path_writer_method_alias_candidate_names(tree: ast.AST) -> set[str]:
    candidates: set[str] = set()
    known_aliases = _python_path_writer_method_aliases(tree)
    for node in ast.walk(tree):
        for target_name, value in _python_assignment_name_value_pairs(node):
            if (
                isinstance(value, ast.Attribute)
                and value.attr in _PYTHON_PATH_WRITER_METHOD_NAMES
            ) or (
                isinstance(value, ast.Name)
                and value.id in known_aliases
            ):
                candidates.add(target_name)
    return candidates


def _python_ast_is_none(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is None


def _python_path_writer_targets(
    text: str,
    scalar_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
) -> list[str]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    non_file_sink_names = _python_non_file_writer_sink_names(tree)
    writer_method_aliases = _python_path_writer_method_aliases(tree)
    (
        writer_constructor_module_aliases,
        writer_constructor_aliases,
    ) = _python_path_writer_constructor_aliases(tree)
    targets: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for target_node in _python_path_writer_constructor_target_arg_nodes(
            node,
            non_file_sink_names=non_file_sink_names,
            writer_constructor_module_aliases=writer_constructor_module_aliases,
            writer_constructor_aliases=writer_constructor_aliases,
        ):
            resolved, writer_targets = _python_writer_arg_targets(
                target_node,
                scalar_bindings,
                sequence_bindings,
            )
            if resolved:
                targets.extend(writer_targets)
        for target_node in _python_path_writer_target_arg_nodes(
            node,
            non_file_sink_names=non_file_sink_names,
            writer_method_aliases=writer_method_aliases,
        ):
            resolved, writer_targets = _python_writer_arg_targets(
                target_node,
                scalar_bindings,
                sequence_bindings,
            )
            if resolved:
                targets.extend(writer_targets)
    return _dedupe_strings(targets)


def _python_save_call_target_arg_nodes(
    node: ast.Call,
    *,
    non_file_sink_names: set[str] | None = None,
) -> list[ast.AST]:
    if not isinstance(node.func, ast.Attribute) or node.func.attr != "save":
        return []
    non_file_sink_names = non_file_sink_names or set()
    targets: list[ast.AST] = []
    if (
        node.args
        and not _python_ast_is_none(node.args[0])
        and not _python_ast_is_non_file_writer_sink(node.args[0], non_file_sink_names)
    ):
        targets.append(node.args[0])
    for keyword in node.keywords:
        if (
            keyword.arg in _PYTHON_SAVE_METHOD_PATH_KEYWORDS
            and not _python_ast_is_none(keyword.value)
            and not _python_ast_is_non_file_writer_sink(keyword.value, non_file_sink_names)
        ):
            targets.append(keyword.value)
    return targets


def _python_save_call_targets(
    text: str,
    scalar_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
) -> list[str]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    non_file_sink_names = _python_non_file_writer_sink_names(tree)
    targets: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for target_node in _python_save_call_target_arg_nodes(
            node,
            non_file_sink_names=non_file_sink_names,
        ):
            resolved, save_targets = _python_writer_arg_targets(
                target_node,
                scalar_bindings,
                sequence_bindings,
            )
            if resolved:
                targets.extend(save_targets)
    return _dedupe_strings(targets)


def _python_non_file_writer_sink_names(tree: ast.AST) -> set[str]:
    io_module_aliases = {"io"}
    stringio_aliases: set[str] = {"StringIO", "BytesIO"}
    assignment_counts = _python_name_assignment_counts(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "io":
                    io_module_aliases.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module == "io":
            for alias in node.names:
                if alias.name in {"StringIO", "BytesIO"}:
                    stringio_aliases.add(alias.asname or alias.name)
    names: set[str] = set()
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            for target_name, value in _python_assignment_name_value_pairs(node):
                if assignment_counts.get(target_name) != 1:
                    continue
                if _python_ast_is_non_file_writer_sink(
                    value,
                    names,
                    io_module_aliases=io_module_aliases,
                    stringio_aliases=stringio_aliases,
                ) and target_name not in names:
                    names.add(target_name)
                    changed = True
    return names


def _python_immediate_lambda_non_file_arg_node_ids(
    tree: ast.AST,
    non_file_sink_names: set[str],
) -> set[int]:
    io_module_aliases = _python_io_module_aliases(tree)
    stringio_aliases = _python_stringio_aliases(tree)
    node_ids: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Lambda):
            continue
        lambda_args = node.func.args.args
        for index, arg in enumerate(lambda_args):
            if index >= len(node.args):
                continue
            if not _python_ast_is_non_file_writer_sink(
                node.args[index],
                non_file_sink_names,
                io_module_aliases=io_module_aliases,
                stringio_aliases=stringio_aliases,
            ):
                continue
            for body_node in ast.walk(node.func.body):
                if isinstance(body_node, ast.Name) and body_node.id == arg.arg:
                    node_ids.add(id(body_node))
    return node_ids


def _python_io_module_aliases(tree: ast.AST) -> set[str]:
    aliases = {"io"}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Import):
            continue
        for alias in node.names:
            if alias.name == "io":
                aliases.add(alias.asname or alias.name)
    return aliases


def _python_stringio_aliases(tree: ast.AST) -> set[str]:
    aliases: set[str] = {"StringIO", "BytesIO"}
    for node in ast.walk(tree):
        if not (isinstance(node, ast.ImportFrom) and node.module == "io"):
            continue
        for alias in node.names:
            if alias.name in {"StringIO", "BytesIO"}:
                aliases.add(alias.asname or alias.name)
    return aliases


def _python_ast_constructs_non_file_writer_sink(
    node: ast.AST,
    io_module_aliases: set[str],
    stringio_aliases: set[str],
) -> bool:
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Name):
        return func.id in stringio_aliases
    return (
        isinstance(func, ast.Attribute)
        and func.attr in {"StringIO", "BytesIO"}
        and isinstance(func.value, ast.Name)
        and func.value.id in io_module_aliases
    )


def _python_ast_is_non_file_writer_sink(
    node: ast.AST,
    non_file_sink_names: set[str],
    *,
    io_module_aliases: set[str] | None = None,
    stringio_aliases: set[str] | None = None,
) -> bool:
    io_module_aliases = io_module_aliases or {"io"}
    stringio_aliases = stringio_aliases or {"StringIO", "BytesIO"}
    if isinstance(node, ast.Name):
        return node.id in non_file_sink_names
    if isinstance(node, ast.Attribute):
        return (
            node.attr in {"stdout", "stderr"}
            and isinstance(node.value, ast.Name)
            and node.value.id in _PYTHON_SYS_MODULE_ALIASES.get()
        )
    if isinstance(node, ast.Call):
        return _python_ast_constructs_non_file_writer_sink(
            node,
            io_module_aliases,
            stringio_aliases,
        )
    return False


def _python_xml_etree_writer_receiver_names(tree: ast.AST) -> set[str]:
    module_aliases, constructor_aliases, parse_aliases = _python_xml_etree_aliases(tree)
    names: set[str] = set()
    assignment_counts = _python_name_assignment_counts(tree)
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            for target_name, value in _python_assignment_name_value_pairs(node):
                if assignment_counts.get(target_name) != 1:
                    continue
                if _python_expr_is_xml_etree_writer_receiver(
                    value,
                    names,
                    module_aliases=module_aliases,
                    constructor_aliases=constructor_aliases,
                    parse_aliases=parse_aliases,
                ) and target_name not in names:
                    names.add(target_name)
                    changed = True
    return names


def _python_xml_etree_aliases(tree: ast.AST) -> tuple[set[str], set[str], set[str]]:
    module_aliases: set[str] = set()
    constructor_aliases: set[str] = set()
    parse_aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "xml.etree.ElementTree":
                    module_aliases.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom):
            module = str(node.module or "")
            for alias in node.names:
                bound = alias.asname or alias.name
                if module == "xml.etree" and alias.name == "ElementTree":
                    module_aliases.add(bound)
                elif module == "xml.etree.ElementTree":
                    if alias.name == "ElementTree":
                        constructor_aliases.add(bound)
                    elif alias.name == "parse":
                        parse_aliases.add(bound)
    return module_aliases, constructor_aliases, parse_aliases


def _python_expr_is_xml_etree_writer_receiver(
    node: ast.AST,
    receiver_names: set[str],
    *,
    module_aliases: set[str] | None = None,
    constructor_aliases: set[str] | None = None,
    parse_aliases: set[str] | None = None,
) -> bool:
    module_aliases = module_aliases or set()
    constructor_aliases = constructor_aliases or set()
    parse_aliases = parse_aliases or set()
    if isinstance(node, ast.Name):
        return node.id in receiver_names
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Name):
        return func.id in constructor_aliases or func.id in parse_aliases
    return (
        isinstance(func, ast.Attribute)
        and func.attr in {"ElementTree", "parse"}
        and _python_expr_is_xml_etree_module(func.value, module_aliases)
    )


def _python_expr_is_xml_etree_module(node: ast.AST, module_aliases: set[str]) -> bool:
    if isinstance(node, ast.Name):
        return node.id in module_aliases
    parts: list[str] = []
    current: ast.AST = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    else:
        return False
    dotted = ".".join(reversed(parts))
    return dotted in module_aliases


def _python_writer_arg_targets(
    node: ast.AST,
    scalar_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
    *,
    writer_constructor_module_aliases: set[str] | None = None,
    writer_constructor_aliases: set[str] | None = None,
) -> tuple[bool, list[str]]:
    writer_constructor_module_aliases = writer_constructor_module_aliases or set()
    writer_constructor_aliases = writer_constructor_aliases or set()
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return _python_literal_writer_path_arg_targets(node.value)
    if isinstance(node, ast.Name):
        targets: list[str] = []
        if node.id in scalar_bindings:
            targets.append(scalar_bindings[node.id])
        targets.extend(sequence_bindings.get(node.id, []))
        return (bool(targets), _dedupe_strings(targets))
    if isinstance(node, ast.Subscript):
        argv_index = _python_sys_argv_subscript_index(node)
        argv_path = _PYTHON_ARGV_PATH_BINDINGS.get().get(argv_index) if argv_index is not None else None
        if argv_path:
            return (True, [argv_path])
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Name) and func.id in {"str", "bytes"} and len(node.args) == 1:
            return _python_writer_arg_targets(
                node.args[0],
                scalar_bindings,
                sequence_bindings,
                writer_constructor_module_aliases=writer_constructor_module_aliases,
                writer_constructor_aliases=writer_constructor_aliases,
            )
        constructor_target_nodes = _python_path_writer_constructor_target_arg_nodes(
            node,
            writer_constructor_module_aliases=writer_constructor_module_aliases,
            writer_constructor_aliases=writer_constructor_aliases,
        )
        if len(constructor_target_nodes) == 1:
            return _python_writer_arg_targets(
                constructor_target_nodes[0],
                scalar_bindings,
                sequence_bindings,
                writer_constructor_module_aliases=writer_constructor_module_aliases,
                writer_constructor_aliases=writer_constructor_aliases,
            )
        if _python_call_is_path_constructor(node):
            if node.args:
                return _python_writer_arg_targets(
                    node.args[0],
                    scalar_bindings,
                    sequence_bindings,
                    writer_constructor_module_aliases=writer_constructor_module_aliases,
                    writer_constructor_aliases=writer_constructor_aliases,
                )
            return (False, [])
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Div)):
        left_resolved, left_targets = _python_writer_arg_targets(
            node.left,
            scalar_bindings,
            sequence_bindings,
            writer_constructor_module_aliases=writer_constructor_module_aliases,
            writer_constructor_aliases=writer_constructor_aliases,
        )
        right_resolved, right_targets = _python_writer_arg_targets(
            node.right,
            scalar_bindings,
            sequence_bindings,
            writer_constructor_module_aliases=writer_constructor_module_aliases,
            writer_constructor_aliases=writer_constructor_aliases,
        )
        if left_resolved and right_resolved:
            targets: list[str] = []
            for left in left_targets:
                for right in right_targets:
                    if isinstance(node.op, ast.Div):
                        targets.append(posixpath.join(left, right))
                    else:
                        targets.append(f"{left}{right}")
            return (bool(targets), _dedupe_strings(targets))
    return (False, [])


def _python_writer_path_variable_bindings(
    tree: ast.AST,
    scalar_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
) -> dict[str, str]:
    if _python_has_dynamic_namespace_mutation(tree):
        return dict(scalar_bindings)
    bindings = dict(scalar_bindings)
    assignment_counts = _python_name_assignment_counts(tree)
    shadowed_names = _python_lexical_shadow_binding_names(tree, include_loop_targets=True)
    (
        writer_constructor_module_aliases,
        writer_constructor_aliases,
    ) = _python_path_writer_constructor_aliases(tree)
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            if isinstance(node, ast.With):
                for item in node.items:
                    if not isinstance(item.optional_vars, ast.Name):
                        continue
                    target_name = item.optional_vars.id
                    if assignment_counts.get(target_name, 0) > 0:
                        continue
                    resolved, targets = _python_writer_arg_targets(
                        item.context_expr,
                        bindings,
                        sequence_bindings,
                        writer_constructor_module_aliases=writer_constructor_module_aliases,
                        writer_constructor_aliases=writer_constructor_aliases,
                    )
                    if resolved and len(targets) == 1 and bindings.get(target_name) != targets[0]:
                        bindings[target_name] = targets[0]
                        changed = True
            assignment = _python_single_name_assignment(node)
            if assignment is None:
                continue
            target_name, value = assignment
            if assignment_counts.get(target_name) != 1 or target_name in shadowed_names:
                continue
            resolved, targets = _python_writer_arg_targets(
                value,
                bindings,
                sequence_bindings,
                writer_constructor_module_aliases=writer_constructor_module_aliases,
                writer_constructor_aliases=writer_constructor_aliases,
            )
            if resolved and len(targets) == 1 and bindings.get(target_name) != targets[0]:
                bindings[target_name] = targets[0]
                changed = True
    return bindings


def _python_static_relative_path_fragment(node: ast.AST) -> str | None:
    if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
        return None
    fragment = node.value.strip().strip("/")
    if not fragment or fragment.startswith(("~", ".", "/")):
        return None
    if ".." in PurePosixPath(fragment).parts:
        return None
    return fragment


def _python_paths_are_scope_task_data(paths: list[str]) -> bool:
    return bool(paths) and all(
        _is_scope_task_data_path(_glob_base_path(path))
        for path in paths
    )


def _python_write_items(
    text: str,
    path_bindings: dict[str, str] | None = None,
    path_sequence_bindings: dict[str, list[str]] | None = None,
) -> list[tuple[str, str, bool]]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    scalar_bindings = path_bindings if path_bindings is not None else _python_path_variable_bindings(text)
    sequence_bindings = (
        path_sequence_bindings
        if path_sequence_bindings is not None
        else _python_path_sequence_variable_bindings(text)
    )
    string_bindings = _python_string_literal_bindings(tree)
    payload_bindings, payload_sequence_bindings = _python_static_text_payload_bindings(tree, string_bindings)
    payload_candidate_bindings, payload_candidate_overflows = _python_static_text_payload_candidate_bindings(
        tree,
        payload_bindings,
        payload_sequence_bindings,
    )
    writer_scalar_bindings = _python_writer_path_variable_bindings(
        tree,
        scalar_bindings,
        sequence_bindings,
    )
    open_aliases, open_module_aliases = _python_open_binding_names(tree)
    open_handle_bindings = _python_open_write_handle_bindings(
        tree,
        writer_scalar_bindings,
        sequence_bindings,
        string_bindings,
        open_aliases,
        open_module_aliases,
    )
    items: list[tuple[str, str, bool]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        method = node.func.attr
        if method in {"write_text", "write_bytes"}:
            content_candidates, content_overflow = _python_static_write_payload_text_candidates(
                node,
                payload_bindings,
                payload_sequence_bindings,
                payload_candidate_bindings,
                payload_candidate_overflows,
            )
            if not content_candidates and not content_overflow:
                continue
            content_sequence = _python_static_write_payload_sequence(
                node,
                payload_bindings,
                payload_sequence_bindings,
            )
            resolved, write_targets = _python_writer_arg_targets(
                node.func.value,
                writer_scalar_bindings,
                sequence_bindings,
            )
            if resolved:
                if content_sequence and len(content_sequence) == len(write_targets):
                    items.extend((path, content, False) for path, content in zip(write_targets, content_sequence, strict=True))
                    continue
                for path in write_targets:
                    items.extend((path, content, content_overflow) for content in content_candidates)
                    if content_overflow and not content_candidates:
                        items.append((path, "", True))
            continue
        if method not in {"write", "writelines"}:
            continue
        content_candidates, content_overflow = _python_static_write_payload_text_candidates(
            node,
            payload_bindings,
            payload_sequence_bindings,
            payload_candidate_bindings,
            payload_candidate_overflows,
        )
        if not content_candidates and not content_overflow:
            continue
        content_sequence = _python_static_write_payload_sequence(
            node,
            payload_bindings,
            payload_sequence_bindings,
        )
        receiver = node.func.value
        if isinstance(receiver, ast.Name) and receiver.id in open_handle_bindings:
            write_targets = open_handle_bindings[receiver.id]
            if content_sequence and len(content_sequence) == len(write_targets):
                items.extend((path, content, False) for path, content in zip(write_targets, content_sequence, strict=True))
            else:
                for path in write_targets:
                    items.extend((path, content, content_overflow) for content in content_candidates)
                    if content_overflow and not content_candidates:
                        items.append((path, "", True))
            continue
        if not isinstance(receiver, ast.Call):
            continue
        path_node, positional_index = _python_open_call_path_and_mode_position(
            receiver,
            open_aliases,
            open_module_aliases,
        )
        if path_node is None or not _python_call_mode_writes_or_unknown(
            receiver,
            positional_index=positional_index,
            string_bindings=string_bindings,
        ):
            continue
        resolved, write_targets = _python_writer_arg_targets(
            path_node,
            writer_scalar_bindings,
            sequence_bindings,
        )
        if resolved:
            if content_sequence and len(content_sequence) == len(write_targets):
                items.extend((path, content, False) for path, content in zip(write_targets, content_sequence, strict=True))
                continue
            for path in write_targets:
                items.extend((path, content, content_overflow) for content in content_candidates)
                if content_overflow and not content_candidates:
                    items.append((path, "", True))
    return list(dict.fromkeys(items))


def _python_unobserved_stdin_write_targets(
    tree: ast.AST | None,
    path_bindings: dict[str, str],
    path_sequence_bindings: dict[str, list[str]],
) -> list[str]:
    if tree is None:
        return []
    stdin_aliases = _python_stdin_aliases(tree)
    stdin_payload_names = _python_stdin_payload_names(tree, stdin_aliases)
    string_bindings = _python_string_literal_bindings(tree)
    writer_scalar_bindings = _python_writer_path_variable_bindings(
        tree,
        path_bindings,
        path_sequence_bindings,
    )
    open_aliases, open_module_aliases = _python_open_binding_names(tree)
    open_handle_bindings = _python_open_write_handle_bindings(
        tree,
        writer_scalar_bindings,
        path_sequence_bindings,
        string_bindings,
        open_aliases,
        open_module_aliases,
    )
    targets: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        method = node.func.attr
        if method not in {"write", "writelines", "write_text", "write_bytes"}:
            continue
        payload_node = _python_static_write_payload_node(node)
        if not _python_expr_uses_unobserved_stdin(
            payload_node,
            stdin_payload_names,
            stdin_aliases,
        ):
            continue
        receiver = node.func.value
        if method in {"write_text", "write_bytes"}:
            resolved, write_targets = _python_writer_arg_targets(
                receiver,
                writer_scalar_bindings,
                path_sequence_bindings,
            )
            if resolved:
                targets.extend(write_targets)
            continue
        if isinstance(receiver, ast.Name) and receiver.id in open_handle_bindings:
            targets.extend(open_handle_bindings[receiver.id])
            continue
        if not isinstance(receiver, ast.Call):
            continue
        path_node, positional_index = _python_open_call_path_and_mode_position(
            receiver,
            open_aliases,
            open_module_aliases,
        )
        if path_node is None or not _python_call_mode_writes_or_unknown(
            receiver,
            positional_index=positional_index,
            string_bindings=string_bindings,
        ):
            continue
        resolved, write_targets = _python_writer_arg_targets(
            path_node,
            writer_scalar_bindings,
            path_sequence_bindings,
        )
        if resolved:
            targets.extend(write_targets)
    return _dedupe_strings(targets)


def _python_stdin_payload_names(
    tree: ast.AST,
    stdin_aliases: dict[str, set[str]],
) -> set[str]:
    names: set[str] = set()
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            value, targets = _python_assignment_value_and_targets(node)
            if value is None or not _python_expr_uses_unobserved_stdin(
                value,
                names,
                stdin_aliases,
            ):
                continue
            for target in targets:
                for target_name in _python_assignment_target_names(target):
                    if target_name not in names:
                        names.add(target_name)
                        changed = True
    return names


def _python_expr_uses_unobserved_stdin(
    node: ast.AST | None,
    tainted_names: set[str],
    stdin_aliases: dict[str, set[str]],
) -> bool:
    if node is None:
        return False
    if isinstance(node, ast.Name):
        return node.id in tainted_names
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id == "input":
            return True
        if _python_call_reads_unobserved_stdin(node, stdin_aliases):
            return True
        if (
            isinstance(node.func, ast.Attribute)
            and _python_expr_uses_unobserved_stdin(
                node.func.value,
                tainted_names,
                stdin_aliases,
            )
        ):
            return True
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"read", "readline", "readlines"}
            and _python_expr_is_stdin_object(node.func.value, tainted_names, stdin_aliases)
        ):
            return True
        return any(
            _python_expr_uses_unobserved_stdin(arg, tainted_names, stdin_aliases)
            for arg in node.args
        ) or any(
            _python_expr_uses_unobserved_stdin(keyword.value, tainted_names, stdin_aliases)
            for keyword in node.keywords
            if keyword.arg is not None
        )
    if isinstance(node, ast.Attribute):
        return _python_expr_is_stdin_object(node, tainted_names, stdin_aliases)
    if isinstance(node, ast.BinOp):
        return _python_expr_uses_unobserved_stdin(
            node.left,
            tainted_names,
            stdin_aliases,
        ) or _python_expr_uses_unobserved_stdin(node.right, tainted_names, stdin_aliases)
    if isinstance(node, ast.JoinedStr):
        return any(
            _python_expr_uses_unobserved_stdin(value, tainted_names, stdin_aliases)
            for value in node.values
        )
    if isinstance(node, ast.FormattedValue):
        return _python_expr_uses_unobserved_stdin(node.value, tainted_names, stdin_aliases)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(
            _python_expr_uses_unobserved_stdin(item, tainted_names, stdin_aliases)
            for item in node.elts
        )
    return False


def _python_expr_is_stdin_object(
    node: ast.AST,
    tainted_names: set[str],
    stdin_aliases: dict[str, set[str]],
) -> bool:
    if isinstance(node, ast.Name):
        return node.id in tainted_names or node.id in stdin_aliases["stdin_objects"]
    if (
        isinstance(node, ast.Attribute)
        and node.attr in {"stdin", "__stdin__"}
        and isinstance(node.value, ast.Name)
        and node.value.id in stdin_aliases["sys_modules"]
    ):
        return True
    if (
        isinstance(node, ast.Attribute)
        and node.attr == "buffer"
        and _python_expr_is_stdin_object(node.value, tainted_names, stdin_aliases)
    ):
        return True
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "fdopen"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id in stdin_aliases["os_modules"]
        and _python_ast_arg_is_stdin_fd(node.args[0] if node.args else None)
    ):
        return True
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in stdin_aliases["os_fdopen_functions"]
        and _python_ast_arg_is_stdin_fd(node.args[0] if node.args else None)
    ):
        return True
    return False


def _python_call_reads_unobserved_stdin(
    node: ast.Call,
    stdin_aliases: dict[str, set[str]],
) -> bool:
    func = node.func
    if (
        isinstance(func, ast.Attribute)
        and func.attr == "read"
        and isinstance(func.value, ast.Name)
        and func.value.id in stdin_aliases["os_modules"]
        and _python_ast_arg_is_stdin_fd(node.args[0] if node.args else None)
    ):
        return True
    if (
        isinstance(func, ast.Name)
        and func.id in stdin_aliases["os_read_functions"]
        and _python_ast_arg_is_stdin_fd(node.args[0] if node.args else None)
    ):
        return True
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        module = func.value.id
        if module in stdin_aliases["fileinput_modules"] and func.attr in {"input", "FileInput"}:
            return _python_fileinput_call_reads_stdin(node)
    if isinstance(func, ast.Name) and func.id in stdin_aliases["fileinput_input_functions"]:
        return _python_fileinput_call_reads_stdin(node)
    return False


def _python_stdin_aliases(tree: ast.AST) -> dict[str, set[str]]:
    aliases = {
        "sys_modules": {"sys"},
        "stdin_objects": set(),
        "os_modules": {"os"},
        "os_read_functions": set(),
        "os_fdopen_functions": set(),
        "fileinput_modules": {"fileinput"},
        "fileinput_input_functions": set(),
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", 1)[0]
                target = alias.asname or root
                if root == "sys":
                    aliases["sys_modules"].add(target)
                elif root == "os":
                    aliases["os_modules"].add(target)
                elif root == "fileinput":
                    aliases["fileinput_modules"].add(target)
            continue
        if not isinstance(node, ast.ImportFrom):
            continue
        module = (node.module or "").split(".", 1)[0]
        for alias in node.names:
            target = alias.asname or alias.name
            if module == "sys" and alias.name in {"stdin", "__stdin__"}:
                aliases["stdin_objects"].add(target)
            elif module == "os" and alias.name == "read":
                aliases["os_read_functions"].add(target)
            elif module == "os" and alias.name == "fdopen":
                aliases["os_fdopen_functions"].add(target)
            elif module == "fileinput" and alias.name in {"input", "FileInput"}:
                aliases["fileinput_input_functions"].add(target)
    return aliases


def _python_ast_arg_is_stdin_fd(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value in {0, "0", "-"}


def _python_fileinput_call_reads_stdin(node: ast.Call) -> bool:
    if not node.args:
        for keyword in node.keywords:
            if keyword.arg in {"files", "filename"} and not _python_fileinput_files_arg_is_stdin(keyword.value):
                return False
        return True
    return _python_fileinput_files_arg_is_stdin(node.args[0])


def _python_fileinput_files_arg_is_stdin(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return node.value in {None, "-", ""}
    if isinstance(node, (ast.List, ast.Tuple)):
        return not node.elts or all(
            isinstance(item, ast.Constant) and item.value in {"-", ""}
            for item in node.elts
        )
    return False


def _python_open_write_handle_bindings(
    tree: ast.AST,
    scalar_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
    string_bindings: dict[str, str],
    open_aliases: set[str],
    open_module_aliases: set[str],
) -> dict[str, list[str]]:
    assignment_counts = _python_name_assignment_counts(tree)
    bindings: dict[str, list[str]] = {}
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                for target_name, value in _python_assignment_name_value_pairs(node):
                    if assignment_counts.get(target_name) != 1:
                        continue
                    if isinstance(value, ast.Name) and value.id in bindings:
                        write_targets = bindings[value.id]
                    else:
                        write_targets = _python_open_write_call_targets(
                            value,
                            scalar_bindings,
                            sequence_bindings,
                            string_bindings,
                            open_aliases,
                            open_module_aliases,
                        )
                    if not write_targets:
                        continue
                    next_targets = _dedupe_strings([*bindings.get(target_name, []), *write_targets])
                    if next_targets != bindings.get(target_name, []):
                        bindings[target_name] = next_targets
                        changed = True
                continue
            if isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    if item.optional_vars is None:
                        continue
                    write_targets = _python_open_write_call_targets(
                        item.context_expr,
                        scalar_bindings,
                        sequence_bindings,
                        string_bindings,
                        open_aliases,
                        open_module_aliases,
                    )
                    if not write_targets:
                        continue
                    for target_name in _python_assignment_target_names(item.optional_vars):
                        if assignment_counts.get(target_name, 0) != 0:
                            continue
                        next_targets = _dedupe_strings([*bindings.get(target_name, []), *write_targets])
                        if next_targets != bindings.get(target_name, []):
                            bindings[target_name] = next_targets
                            changed = True
    return bindings


def _python_archive_write_handle_bindings(
    tree: ast.AST,
    scalar_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
    string_bindings: dict[str, str],
    reader_bindings: dict[str, set[str]],
) -> dict[str, list[str]]:
    assignment_counts = _python_name_assignment_counts(tree)
    bindings: dict[str, list[str]] = {}
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                for target_name, value in _python_assignment_name_value_pairs(node):
                    if assignment_counts.get(target_name) != 1:
                        continue
                    if isinstance(value, ast.Name) and value.id in bindings:
                        archive_targets = bindings[value.id]
                    else:
                        archive_targets = _python_archive_write_call_targets(
                            value,
                            scalar_bindings,
                            sequence_bindings,
                            string_bindings,
                            reader_bindings,
                        )
                    if not archive_targets:
                        continue
                    next_targets = _dedupe_strings([
                        *bindings.get(target_name, []),
                        *archive_targets,
                    ])
                    if next_targets != bindings.get(target_name, []):
                        bindings[target_name] = next_targets
                        changed = True
                continue
            if isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    if item.optional_vars is None:
                        continue
                    archive_targets = _python_archive_write_call_targets(
                        item.context_expr,
                        scalar_bindings,
                        sequence_bindings,
                        string_bindings,
                        reader_bindings,
                    )
                    if not archive_targets:
                        continue
                    for target_name in _python_assignment_target_names(item.optional_vars):
                        if assignment_counts.get(target_name, 0) != 0:
                            continue
                        next_targets = _dedupe_strings([
                            *bindings.get(target_name, []),
                            *archive_targets,
                        ])
                        if next_targets != bindings.get(target_name, []):
                            bindings[target_name] = next_targets
                            changed = True
    return bindings


def _python_archive_write_call_targets(
    node: ast.AST,
    scalar_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
    string_bindings: dict[str, str],
    reader_bindings: dict[str, set[str]],
) -> list[str]:
    if not (
        isinstance(node, ast.Call)
        and _python_call_is_trusted_archive_write_open(node, string_bindings, reader_bindings)
        and node.args
    ):
        return []
    resolved, archive_targets = _python_document_reader_arg_targets(
        node.args[0],
        scalar_bindings,
        sequence_bindings,
        set(),
        set(),
    )
    if not resolved:
        resolved, archive_targets = _python_writer_arg_targets(
            node.args[0],
            scalar_bindings,
            sequence_bindings,
        )
    return _dedupe_strings(archive_targets) if resolved else []


def _python_open_write_call_targets(
    node: ast.AST,
    scalar_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
    string_bindings: dict[str, str],
    open_aliases: set[str],
    open_module_aliases: set[str],
) -> list[str]:
    if not isinstance(node, ast.Call):
        return []
    path_node, positional_index = _python_open_call_path_and_mode_position(
        node,
        open_aliases,
        open_module_aliases,
    )
    if path_node is None or not _python_call_mode_writes_or_unknown(
        node,
        positional_index=positional_index,
        string_bindings=string_bindings,
    ):
        return []
    resolved, write_targets = _python_writer_arg_targets(
        path_node,
        scalar_bindings,
        sequence_bindings,
    )
    return write_targets if resolved else []


def _python_static_write_payload_sequence(
    node: ast.Call,
    string_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
) -> list[str]:
    value_node = _python_static_write_payload_node(node)
    if value_node is None:
        return []
    return _python_static_text_sequence_value(value_node, string_bindings, sequence_bindings)


def _python_static_write_payload_text_candidates(
    node: ast.Call,
    string_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
    candidate_bindings: dict[str, list[str]],
    candidate_overflows: set[str],
) -> tuple[list[str], bool]:
    value_node = _python_static_write_payload_node(node)
    if value_node is None:
        return [], False
    direct = _python_static_text_payload_value(value_node, string_bindings, sequence_bindings)
    if direct:
        return [direct], False
    return _python_static_text_payload_value_candidates(
        value_node,
        string_bindings,
        sequence_bindings,
        candidate_bindings,
        candidate_overflows,
    )


def _python_static_write_payload_node(node: ast.Call) -> ast.AST | None:
    value_node: ast.AST | None = node.args[0] if node.args else None
    for keyword in node.keywords:
        if keyword.arg in {"data", "s"}:
            value_node = keyword.value
            break
    return value_node


def _python_static_text_payload_candidate_bindings(
    tree: ast.AST,
    string_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
) -> tuple[dict[str, list[str]], set[str]]:
    candidates: dict[str, list[str]] = {}
    overflow_names: set[str] = set()
    shadowed_names = _python_lexical_shadow_binding_names(tree, include_loop_targets=True)
    for node in ast.walk(tree):
        if isinstance(node, ast.AugAssign) and isinstance(node.op, ast.Add):
            values, value_overflow = _python_static_text_payload_value_candidates(
                node.value,
                string_bindings,
                sequence_bindings,
                candidates,
                overflow_names,
            )
            if not values and not value_overflow:
                continue
            for target_name in _python_assignment_target_names(node.target):
                if target_name in shadowed_names:
                    continue
                if value_overflow:
                    overflow_names.add(target_name)
                existing = candidates.setdefault(target_name, [])
                bases = list(existing)
                for item in values:
                    if _append_python_static_text_payload_candidate(existing, item):
                        overflow_names.add(target_name)
                    for base in bases:
                        combined = base + item
                        if _append_python_static_text_payload_candidate(existing, combined):
                            overflow_names.add(target_name)
                            break
                    if target_name in overflow_names:
                        break
            continue
        value, targets = _python_assignment_value_and_targets(node)
        if value is None:
            continue
        values, value_overflow = _python_static_text_payload_value_candidates(
            value,
            string_bindings,
            sequence_bindings,
            candidates,
            overflow_names,
        )
        if not values and not value_overflow:
            continue
        for target in targets:
            for target_name in _python_assignment_target_names(target):
                if target_name in shadowed_names:
                    continue
                if value_overflow:
                    overflow_names.add(target_name)
                existing = candidates.setdefault(target_name, [])
                for item in values:
                    if _append_python_static_text_payload_candidate(existing, item):
                        overflow_names.add(target_name)
                        break
    return candidates, overflow_names


def _python_static_text_payload_bindings(
    tree: ast.AST,
    initial_bindings: dict[str, str],
) -> tuple[dict[str, str], dict[str, list[str]]]:
    bindings = dict(initial_bindings)
    sequence_bindings: dict[str, list[str]] = {}
    assignment_counts = _python_name_assignment_counts(tree)
    assignment_shadowed_names = _python_lexical_shadow_binding_names(tree, include_loop_targets=True)
    loop_shadowed_names = _python_lexical_shadow_binding_names(tree, include_loop_targets=False)
    changed = True
    passes = 0
    while changed and passes < _PYTHON_STATIC_TEXT_PAYLOAD_BINDING_MAX_PASSES:
        passes += 1
        changed = False
        for node in ast.walk(tree):
            value, targets = _python_assignment_value_and_targets(node)
            if value is not None:
                sequence_value = _python_static_text_sequence_value(value, bindings, sequence_bindings)
                text_value = _python_static_text_payload_value(value, bindings, sequence_bindings)
                for target in targets:
                    for target_name in _python_assignment_target_names(target):
                        if (
                            assignment_counts.get(target_name) != 1
                            or target_name in assignment_shadowed_names
                        ):
                            continue
                        if sequence_value and sequence_bindings.get(target_name) != sequence_value:
                            sequence_bindings[target_name] = sequence_value
                            changed = True
                        if text_value and bindings.get(target_name) != text_value:
                            bindings[target_name] = text_value
                            changed = True
            if not isinstance(node, ast.For):
                continue
            target_name = _python_static_mapping_value_loop_target_name(node)
            if not target_name:
                continue
            if target_name in loop_shadowed_names:
                continue
            sequence_value = _python_static_mapping_value_payloads_from_iter(
                node.iter,
                tree,
                bindings,
                sequence_bindings,
            )
            if sequence_value and sequence_bindings.get(target_name) != sequence_value:
                sequence_bindings[target_name] = sequence_value
                changed = True
    return bindings, sequence_bindings


def _python_static_text_payload_value_candidates(
    node: ast.AST,
    string_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
    candidate_bindings: dict[str, list[str]],
    candidate_overflows: set[str],
) -> tuple[list[str], bool]:
    direct = _python_static_text_payload_value(node, string_bindings, sequence_bindings)
    if direct:
        return [direct], False
    if isinstance(node, ast.Name):
        return (
            list(candidate_bindings.get(node.id, []))[:_PYTHON_STATIC_TEXT_PAYLOAD_CANDIDATE_LIMIT],
            node.id in candidate_overflows,
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left_values, left_overflow = _python_static_text_payload_value_candidates(
            node.left,
            string_bindings,
            sequence_bindings,
            candidate_bindings,
            candidate_overflows,
        )
        right_values, right_overflow = _python_static_text_payload_value_candidates(
            node.right,
            string_bindings,
            sequence_bindings,
            candidate_bindings,
            candidate_overflows,
        )
        values: list[str] = []
        overflow = left_overflow or right_overflow
        for left in left_values:
            for right in right_values:
                if _append_python_static_text_payload_candidate(values, left + right):
                    overflow = True
                    return values, overflow
        return values, overflow
    return [], False


def _python_static_text_payload_value(
    node: ast.AST,
    string_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
) -> str:
    text = _python_static_string_expr_value(node, string_bindings)
    if text:
        return text
    if isinstance(node, ast.Name):
        sequence = sequence_bindings.get(node.id, [])
        if sequence:
            return "\n".join(sequence)
    if isinstance(node, ast.Constant) and isinstance(node.value, bytes):
        return node.value.decode("utf-8", errors="ignore")
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
                continue
            if isinstance(value, ast.FormattedValue):
                part = _python_static_text_payload_value(
                    value.value,
                    string_bindings,
                    sequence_bindings,
                )
                if not part:
                    return ""
                parts.append(part)
                continue
            return ""
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _python_static_text_payload_value(node.left, string_bindings, sequence_bindings)
        right = _python_static_text_payload_value(node.right, string_bindings, sequence_bindings)
        if left and right:
            return left + right
    if isinstance(node, ast.Subscript):
        if isinstance(node.value, ast.Name) and isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, int):
            sequence = sequence_bindings.get(node.value.id, [])
            index = node.slice.value
            if index < 0:
                index += len(sequence)
            if 0 <= index < len(sequence):
                return sequence[index]
        element = _python_static_subscript_sequence_element(node)
        if element is not None:
            return _python_static_text_payload_value(element, string_bindings, sequence_bindings)
    if isinstance(node, (ast.List, ast.Tuple)):
        parts = [_python_static_text_payload_value(item, string_bindings, sequence_bindings) for item in node.elts]
        if parts and all(parts):
            return "".join(parts)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "join"
        and len(node.args) == 1
    ):
        separator = _python_static_text_payload_value(node.func.value, string_bindings, sequence_bindings)
        parts = _python_static_text_sequence_value(node.args[0], string_bindings, sequence_bindings)
        if parts:
            return separator.join(parts)
    return ""


def _python_static_text_sequence_value(
    node: ast.AST,
    string_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
) -> list[str]:
    if isinstance(node, ast.Name):
        return list(sequence_bindings.get(node.id, []))
    if not isinstance(node, (ast.List, ast.Tuple)):
        return []
    parts = [_python_static_text_payload_value(item, string_bindings, sequence_bindings) for item in node.elts]
    if parts and all(parts):
        return parts
    return []


def _python_static_mapping_value_loop_target_name(node: ast.For) -> str:
    if (
        isinstance(node.iter, ast.Call)
        and isinstance(node.iter.func, ast.Attribute)
        and node.iter.func.attr == "items"
        and isinstance(node.target, (ast.Tuple, ast.List))
        and len(node.target.elts) >= 2
        and isinstance(node.target.elts[1], ast.Name)
    ):
        return node.target.elts[1].id
    if (
        isinstance(node.iter, ast.Call)
        and isinstance(node.iter.func, ast.Attribute)
        and node.iter.func.attr == "values"
        and isinstance(node.target, ast.Name)
    ):
        return node.target.id
    return ""


def _python_static_mapping_value_payloads_from_iter(
    node: ast.AST,
    tree: ast.AST,
    string_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
) -> list[str]:
    if not (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"items", "values"}
        and isinstance(node.func.value, ast.Name)
    ):
        return []
    dict_node = _python_static_safe_dict_literal_bindings(tree).get(node.func.value.id)
    if dict_node is None:
        return []
    values = [
        _python_static_text_payload_value(value, string_bindings, sequence_bindings)
        for key, value in zip(dict_node.keys, dict_node.values, strict=True)
        if key is not None
    ]
    return [value for value in values if value]


def _python_write_targets(
    text: str,
    path_bindings: dict[str, str] | None = None,
    path_sequence_bindings: dict[str, list[str]] | None = None,
) -> list[str]:
    scalar_bindings = path_bindings if path_bindings is not None else _python_path_variable_bindings(text)
    sequence_bindings = (
        path_sequence_bindings
        if path_sequence_bindings is not None
        else _python_path_sequence_variable_bindings(text)
    )
    try:
        tree = ast.parse(text)
    except SyntaxError:
        tree = None
    writer_scalar_bindings = (
        _python_writer_path_variable_bindings(tree, scalar_bindings, sequence_bindings)
        if tree is not None
        else scalar_bindings
    )
    targets: list[str] = []
    targets.extend(_python_open_call_write_or_unknown_targets(text, writer_scalar_bindings, sequence_bindings))
    targets.extend(_python_archive_write_targets(text, writer_scalar_bindings, sequence_bindings))
    targets.extend(_python_save_call_targets(text, writer_scalar_bindings, sequence_bindings))
    targets.extend(_python_path_writer_targets(text, writer_scalar_bindings, sequence_bindings))
    targets.extend(_python_mutating_path_method_targets(text, writer_scalar_bindings, sequence_bindings))
    return _dedupe_strings(targets)


def _python_destructive_delete_targets(
    tree: ast.AST,
    scalar_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
) -> tuple[list[str], bool]:
    aliases = _python_destructive_delete_aliases(tree)
    delete_scalar_bindings = _python_destructive_path_variable_bindings(
        tree,
        scalar_bindings,
        sequence_bindings,
        aliases,
    )
    targets: list[str] = []
    unresolved = False
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        target_nodes: list[ast.AST] = []
        if _python_call_is_destructive_delete_function(node, aliases):
            target = _python_first_path_argument_node(node, keyword_names={"path", "name", "src"})
            if target is None:
                unresolved = True
                continue
            target_nodes.append(target)
        elif (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"unlink", "rmdir"}
        ):
            target_nodes.append(node.func.value)
        for target_node in target_nodes:
            resolved, delete_targets = _python_destructive_delete_arg_targets(
                target_node,
                delete_scalar_bindings,
                sequence_bindings,
                aliases,
            )
            if resolved:
                targets.extend(delete_targets)
            else:
                unresolved = True
    return (_dedupe_strings(targets), unresolved)


def _python_destructive_delete_aliases(tree: ast.AST) -> dict[str, set[str]]:
    aliases = {
        "os_modules": {"os"},
        "shutil_modules": {"shutil"},
        "pathlib_modules": {"pathlib"},
        "delete_functions": set(),
        "path_constructors": set(_PYTHON_PATH_CONSTRUCTOR_NAMES),
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", 1)[0]
                bound = alias.asname or root
                if root == "os":
                    aliases["os_modules"].add(bound)
                elif root == "shutil":
                    aliases["shutil_modules"].add(bound)
                elif root == "pathlib":
                    aliases["pathlib_modules"].add(bound)
                    aliases["path_constructors"].update(_PYTHON_PATH_CONSTRUCTOR_NAMES)
        elif isinstance(node, ast.ImportFrom):
            module = str(node.module or "")
            if module == "os":
                for alias in node.names:
                    if alias.name in _PYTHON_OS_DESTRUCTIVE_DELETE_METHOD_NAMES:
                        aliases["delete_functions"].add(alias.asname or alias.name)
            elif module == "shutil":
                for alias in node.names:
                    if alias.name in _PYTHON_SHUTIL_DESTRUCTIVE_DELETE_METHOD_NAMES:
                        aliases["delete_functions"].add(alias.asname or alias.name)
            elif module == "pathlib":
                for alias in node.names:
                    if alias.name in _PYTHON_PATH_CONSTRUCTOR_NAMES:
                        aliases["path_constructors"].add(alias.asname or alias.name)

    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            for target_name, value in (
                _python_assignment_name_value_pairs(node)
                + _python_default_arg_name_value_pairs(node)
            ):
                if target_name in aliases["delete_functions"]:
                    continue
                if _python_expr_is_destructive_delete_callable(value, aliases):
                    aliases["delete_functions"].add(target_name)
                    changed = True
    return aliases


def _python_shutil_copy_aliases(tree: ast.AST) -> dict[str, set[str]]:
    aliases = {
        "shutil_modules": {"shutil"},
        "copy_functions": set(),
        "copytree_functions": set(),
    }
    shadowed_module_names: set[str] = set()
    shadowed_copy_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", 1)[0]
                bound = alias.asname or root
                if root == "shutil":
                    aliases["shutil_modules"].add(bound)
                elif bound in aliases["shutil_modules"]:
                    shadowed_module_names.add(bound)
                if bound in aliases["copy_functions"]:
                    shadowed_copy_names.add(bound)
        elif isinstance(node, ast.ImportFrom) and str(node.module or "") == "shutil":
            for alias in node.names:
                if alias.name in _PYTHON_SHUTIL_COPY_METHOD_NAMES:
                    bound = alias.asname or alias.name
                    aliases["copy_functions"].add(bound)
                    if alias.name == "copytree":
                        aliases["copytree_functions"].add(bound)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                bound = alias.asname or alias.name
                if bound in aliases["shutil_modules"]:
                    shadowed_module_names.add(bound)
                if bound in aliases["copy_functions"]:
                    shadowed_copy_names.add(bound)
        for bound_name in _python_shutil_copy_lexical_binding_names(node):
            if bound_name in aliases["shutil_modules"]:
                shadowed_module_names.add(bound_name)
            if bound_name in aliases["copy_functions"] or bound_name in _PYTHON_SHUTIL_COPY_METHOD_NAMES:
                shadowed_copy_names.add(bound_name)

    aliases["shutil_modules"].difference_update(shadowed_module_names)
    aliases["copy_functions"].difference_update(shadowed_copy_names)
    aliases["copytree_functions"].difference_update(shadowed_copy_names)

    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            for bound_name in _python_shutil_copy_lexical_binding_names(node):
                if bound_name in aliases["copy_functions"]:
                    shadowed_copy_names.add(bound_name)
            for target_name, value in (
                _python_assignment_name_value_pairs(node)
            ):
                if target_name in aliases["shutil_modules"] and not (
                    isinstance(value, ast.Name)
                    and value.id in aliases["shutil_modules"]
                ):
                    shadowed_module_names.add(target_name)
                if target_name in shadowed_copy_names:
                    continue
                if target_name in aliases["copy_functions"] and not _python_expr_is_shutil_copy_callable(
                    value,
                    aliases,
                ):
                    shadowed_copy_names.add(target_name)
                    continue
                if _python_expr_is_shutil_copy_callable(value, aliases):
                    aliases["copy_functions"].add(target_name)
                    if _python_expr_is_shutil_copytree_callable(value, aliases):
                        aliases["copytree_functions"].add(target_name)
                    changed = True
            previous_modules = set(aliases["shutil_modules"])
            previous_functions = set(aliases["copy_functions"])
            previous_copytree_functions = set(aliases["copytree_functions"])
            aliases["shutil_modules"].difference_update(shadowed_module_names)
            aliases["copy_functions"].difference_update(shadowed_copy_names)
            aliases["copytree_functions"].difference_update(shadowed_copy_names)
            if (
                aliases["shutil_modules"] != previous_modules
                or aliases["copy_functions"] != previous_functions
                or aliases["copytree_functions"] != previous_copytree_functions
            ):
                changed = True
    return aliases


def _python_shutil_copy_lexical_binding_names(node: ast.AST) -> set[str]:
    names: set[str] = set()
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        names.add(node.name)
        names.update(_python_arguments_binding_names(node.args))
    elif isinstance(node, ast.Lambda):
        names.update(_python_arguments_binding_names(node.args))
    elif isinstance(node, ast.ClassDef):
        names.add(node.name)
    elif isinstance(node, (ast.For, ast.AsyncFor)):
        names.update(_python_assignment_target_names(node.target))
    elif isinstance(node, ast.comprehension):
        names.update(_python_assignment_target_names(node.target))
    elif isinstance(node, (ast.With, ast.AsyncWith)):
        for item in node.items:
            if item.optional_vars is not None:
                names.update(_python_assignment_target_names(item.optional_vars))
    elif isinstance(node, ast.ExceptHandler) and isinstance(node.name, str):
        names.add(node.name)
    names.update(_python_match_pattern_binding_names(node))
    return names


def _python_arguments_binding_names(args: ast.arguments) -> set[str]:
    names = {arg.arg for arg in args.posonlyargs}
    names.update(arg.arg for arg in args.args)
    names.update(arg.arg for arg in args.kwonlyargs)
    if args.vararg is not None:
        names.add(args.vararg.arg)
    if args.kwarg is not None:
        names.add(args.kwarg.arg)
    return names


def _python_match_pattern_binding_names(node: ast.AST) -> set[str]:
    names: set[str] = set()
    if isinstance(node, ast.MatchAs):
        if node.name:
            names.add(node.name)
        if node.pattern is not None:
            names.update(_python_match_pattern_binding_names(node.pattern))
    elif isinstance(node, ast.MatchStar):
        if node.name:
            names.add(node.name)
    elif isinstance(node, ast.MatchMapping):
        if node.rest:
            names.add(node.rest)
        for pattern in node.patterns:
            names.update(_python_match_pattern_binding_names(pattern))
    elif isinstance(node, ast.MatchClass):
        for pattern in node.patterns:
            names.update(_python_match_pattern_binding_names(pattern))
        for pattern in node.kwd_patterns:
            names.update(_python_match_pattern_binding_names(pattern))
    elif isinstance(node, ast.MatchSequence):
        for pattern in node.patterns:
            names.update(_python_match_pattern_binding_names(pattern))
    elif isinstance(node, ast.MatchOr):
        for pattern in node.patterns:
            names.update(_python_match_pattern_binding_names(pattern))
    return names


def _python_expr_is_shutil_copy_callable(
    node: ast.AST,
    aliases: dict[str, set[str]],
) -> bool:
    if isinstance(node, ast.Name):
        return node.id in aliases["copy_functions"]
    return (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id in aliases["shutil_modules"]
        and node.attr in _PYTHON_SHUTIL_COPY_METHOD_NAMES
    )


def _python_expr_is_shutil_copytree_callable(
    node: ast.AST,
    aliases: dict[str, set[str]],
) -> bool:
    if isinstance(node, ast.Name):
        return node.id in aliases["copytree_functions"]
    return (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id in aliases["shutil_modules"]
        and node.attr == "copytree"
    )


def _python_call_is_shutil_copy_function(
    node: ast.Call,
    aliases: dict[str, set[str]],
) -> bool:
    return _python_expr_is_shutil_copy_callable(node.func, aliases)


def _python_call_is_shutil_copytree_function(
    node: ast.Call,
    aliases: dict[str, set[str]],
) -> bool:
    return _python_expr_is_shutil_copytree_callable(node.func, aliases)


def _python_shutil_copytree_has_unsafe_option(node: ast.Call) -> bool:
    if len(node.args) >= 3 and isinstance(node.args[2], ast.Constant) and node.args[2].value is True:
        return True
    if len(node.args) >= 4 and not (
        isinstance(node.args[3], ast.Constant) and node.args[3].value is None
    ):
        return True
    if len(node.args) >= 5 and not (
        isinstance(node.args[4], ast.Constant) and node.args[4].value is None
    ):
        return True
    for keyword in node.keywords:
        if keyword.arg in {"copy_function", "ignore"}:
            if isinstance(keyword.value, ast.Constant) and keyword.value.value is None:
                continue
            return True
        if keyword.arg != "symlinks":
            continue
        if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
            return True
    return False


def _python_second_path_argument_node(
    node: ast.Call,
    *,
    keyword_names: set[str],
) -> ast.AST | None:
    if len(node.args) >= 2:
        return node.args[1]
    for keyword in node.keywords:
        if keyword.arg in keyword_names:
            return keyword.value
    return None


def _python_shutil_copy_path_pairs(
    text: str,
    scalar_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
) -> list[tuple[str, str]]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    aliases = _python_shutil_copy_aliases(tree)
    pairs: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not _python_call_is_shutil_copy_function(node, aliases):
            continue
        if (
            _python_call_is_shutil_copytree_function(node, aliases)
            and _python_shutil_copytree_has_unsafe_option(node)
        ):
            continue
        source_node = _python_first_path_argument_node(node, keyword_names={"src", "source"})
        destination_node = _python_second_path_argument_node(
            node,
            keyword_names={"dst", "destination"},
        )
        if source_node is None or destination_node is None:
            continue
        source_resolved, source_targets = _python_atomic_replace_path_arg_targets(
            source_node,
            scalar_bindings,
            sequence_bindings,
        )
        destination_resolved, destination_targets = _python_atomic_replace_path_arg_targets(
            destination_node,
            scalar_bindings,
            sequence_bindings,
        )
        if not source_resolved or not destination_resolved:
            continue
        for source_path in source_targets:
            for destination_path in destination_targets:
                pairs.append((source_path, destination_path))
    return list(dict.fromkeys(pairs))


def _python_expr_is_destructive_delete_callable(
    node: ast.AST,
    aliases: dict[str, set[str]],
) -> bool:
    if isinstance(node, ast.Name):
        return node.id in aliases["delete_functions"]
    if not isinstance(node, ast.Attribute) or not isinstance(node.value, ast.Name):
        return False
    if (
        node.value.id in aliases["os_modules"]
        and node.attr in _PYTHON_OS_DESTRUCTIVE_DELETE_METHOD_NAMES
    ):
        return True
    return (
        node.value.id in aliases["shutil_modules"]
        and node.attr in _PYTHON_SHUTIL_DESTRUCTIVE_DELETE_METHOD_NAMES
    )


def _python_call_is_destructive_delete_function(
    node: ast.Call,
    aliases: dict[str, set[str]],
) -> bool:
    return _python_expr_is_destructive_delete_callable(node.func, aliases)


def _python_first_path_argument_node(
    node: ast.Call,
    *,
    keyword_names: set[str],
) -> ast.AST | None:
    if node.args:
        return node.args[0]
    for keyword in node.keywords:
        if keyword.arg in keyword_names:
            return keyword.value
    return None


def _python_destructive_delete_arg_targets(
    node: ast.AST,
    scalar_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
    aliases: dict[str, set[str]],
) -> tuple[bool, list[str]]:
    resolved, targets = _python_writer_arg_targets(node, scalar_bindings, sequence_bindings)
    if resolved:
        return (True, targets)
    if isinstance(node, ast.Call) and _python_call_is_path_constructor_with_aliases(node, aliases):
        if node.args:
            return _python_destructive_delete_arg_targets(
                node.args[0],
                scalar_bindings,
                sequence_bindings,
                aliases,
            )
        return (False, [])
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        left_resolved, left_targets = _python_destructive_delete_arg_targets(
            node.left,
            scalar_bindings,
            sequence_bindings,
            aliases,
        )
        fragment = _python_static_relative_path_fragment(node.right)
        if left_resolved and fragment is not None:
            if left_targets:
                return (True, [posixpath.join(path, fragment) for path in left_targets])
            return (True, [])
    return (False, [])


def _python_call_is_path_constructor_with_aliases(
    node: ast.Call,
    aliases: dict[str, set[str]],
) -> bool:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id in aliases["path_constructors"]
    return (
        isinstance(func, ast.Attribute)
        and func.attr in aliases["path_constructors"]
        and isinstance(func.value, ast.Name)
        and func.value.id in {"pathlib", *aliases.get("pathlib_modules", {"pathlib"})}
    )


def _python_destructive_path_variable_bindings(
    tree: ast.AST,
    scalar_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
    aliases: dict[str, set[str]],
) -> dict[str, str]:
    bindings = dict(scalar_bindings)
    assignment_counts = _python_name_assignment_counts(tree)
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            for target_name, value in _python_assignment_name_value_pairs(node):
                if assignment_counts.get(target_name) != 1:
                    continue
                resolved, targets = _python_destructive_delete_arg_targets(
                    value,
                    bindings,
                    sequence_bindings,
                    aliases,
                )
                if resolved and len(targets) == 1 and bindings.get(target_name) != targets[0]:
                    bindings[target_name] = targets[0]
                    changed = True
    return bindings


def _python_unresolved_writer_redline_literal_targets(tree: ast.AST) -> list[tuple[str, str, str]]:
    targets: list[tuple[str, str, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        path = node.value.strip()
        if not path or _URL_RE.match(path):
            continue
        if not _python_string_is_explicit_filesystem_path(path):
            continue
        role = _path_role(path)
        if role == "credential_source":
            targets.append((path, role, "credential_source"))
            continue
        if role == "hidden_oracle":
            targets.append((path, role, "hidden_oracle_path"))
            continue
        if role == SCOPE_CONTROL_METADATA_PATH_ROLE:
            targets.append((path, role, "control_metadata_path"))
            continue
        if _python_path_is_protected_system_write(path):
            targets.append((path, "system_path", "system_path_write"))
    return list(dict.fromkeys(targets))


def _python_path_is_protected_system_write(path: str) -> bool:
    normalized = normalize_task_artifact_path(path, cwd=_NORMALIZER_CWD.get()).lower()
    if not normalized.startswith("/"):
        return False
    return normalized == "/etc" or normalized.startswith(_PROTECTED_SYSTEM_WRITE_PATH_PREFIXES)


def _python_archive_write_targets(
    text: str,
    scalar_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
) -> list[str]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    string_bindings = _python_string_literal_bindings(tree)
    reader_bindings = _python_document_reader_bindings(tree)
    targets: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not _python_call_is_trusted_archive_write_open(node, string_bindings, reader_bindings):
            continue
        resolved, archive_targets = _python_document_reader_arg_targets(
            node.args[0] if node.args else None,
            scalar_bindings,
            sequence_bindings,
            set(),
            set(),
        )
        if resolved:
            targets.extend(archive_targets)
    return _dedupe_strings(targets)


def _python_mutating_path_method_targets(
    text: str,
    scalar_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
) -> list[str]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    targets: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        method = node.func.attr
        if method not in _PYTHON_MUTATING_METHOD_NAMES:
            continue
        if method in {"extract", "extractall", "save", "write", "writelines"}:
            continue
        resolved, receiver_targets = _python_document_reader_arg_targets(
            node.func.value,
            scalar_bindings,
            sequence_bindings,
            set(),
            set(),
        )
        if resolved:
            targets.extend(receiver_targets)
        if method in {"rename", "replace"} and node.args:
            resolved, argument_targets = _python_document_reader_arg_targets(
                node.args[0],
                scalar_bindings,
                sequence_bindings,
                set(),
                set(),
            )
            if resolved:
                targets.extend(argument_targets)
    return _dedupe_strings(targets)


_PYTHON_FILESYSTEM_REPLACE_METHOD_NAMES = frozenset({"rename", "replace"})
_PYTHON_ATOMIC_REPLACE_STAGING_SUFFIXES = frozenset({
    ".new",
    ".part",
    ".partial",
    ".tmp",
    ".temp",
})


def _python_task_output_atomic_replace_staging_targets(
    tree: ast.AST,
    scalar_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
) -> dict[str, ActionEffectTarget]:
    writer_scalar_bindings = _python_writer_path_variable_bindings(
        tree,
        scalar_bindings,
        sequence_bindings,
    )
    staging_targets: dict[str, ActionEffectTarget] = {}
    for source_path, destination_path in _python_filesystem_replace_path_pairs(
        tree,
        writer_scalar_bindings,
        sequence_bindings,
    ):
        normalized_source = normalize_task_artifact_path(source_path, cwd=_NORMALIZER_CWD.get())
        if not normalized_source or normalized_source in staging_targets:
            continue
        target = _scope_task_output_atomic_replace_staging_target(
            source_path,
            destination_path,
        )
        if target is not None:
            staging_targets[normalized_source] = target
    return staging_targets


def _python_filesystem_replace_path_pairs(
    tree: ast.AST,
    scalar_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
) -> list[tuple[str, str]]:
    aliases = _python_os_filesystem_replace_aliases(tree)
    pairs: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        path_nodes = _python_filesystem_replace_call_path_nodes(node, aliases)
        if path_nodes is None:
            continue
        source_node, destination_node = path_nodes
        source_resolved, source_targets = _python_atomic_replace_path_arg_targets(
            source_node,
            scalar_bindings,
            sequence_bindings,
        )
        destination_resolved, destination_targets = _python_atomic_replace_path_arg_targets(
            destination_node,
            scalar_bindings,
            sequence_bindings,
        )
        if not source_resolved or not destination_resolved:
            continue
        if len(source_targets) != 1 or len(destination_targets) != 1:
            continue
        pairs.append((source_targets[0], destination_targets[0]))
    return list(dict.fromkeys(pairs))


def _python_atomic_replace_path_arg_targets(
    node: ast.AST,
    scalar_bindings: dict[str, str],
    sequence_bindings: dict[str, list[str]],
) -> tuple[bool, list[str]]:
    if isinstance(node, ast.Name) and node.id in scalar_bindings:
        return (True, [scalar_bindings[node.id]])
    return _python_writer_arg_targets(node, scalar_bindings, sequence_bindings)


def _python_filesystem_replace_call_path_nodes(
    node: ast.Call,
    aliases: dict[str, set[str]],
) -> tuple[ast.AST, ast.AST] | None:
    if isinstance(node.func, ast.Attribute):
        method = node.func.attr
        if method not in _PYTHON_FILESYSTEM_REPLACE_METHOD_NAMES:
            return None
        if (
            isinstance(node.func.value, ast.Name)
            and node.func.value.id in aliases["os_modules"]
        ):
            return _python_positional_or_keyword_pair_nodes(
                node,
                first_keywords={"src", "source"},
                second_keywords={"dst", "destination"},
            )
    if isinstance(node.func, ast.Name) and node.func.id in aliases["replace_functions"]:
        return _python_positional_or_keyword_pair_nodes(
            node,
            first_keywords={"src", "source"},
            second_keywords={"dst", "destination"},
        )
    return None


def _python_positional_or_keyword_pair_nodes(
    node: ast.Call,
    *,
    first_keywords: set[str],
    second_keywords: set[str],
) -> tuple[ast.AST, ast.AST] | None:
    first = node.args[0] if len(node.args) >= 1 else None
    second = node.args[1] if len(node.args) >= 2 else None
    for keyword in node.keywords:
        if keyword.arg in first_keywords:
            first = keyword.value
        elif keyword.arg in second_keywords:
            second = keyword.value
    if first is None or second is None:
        return None
    return (first, second)


def _python_os_filesystem_replace_aliases(tree: ast.AST) -> dict[str, set[str]]:
    module_alias_sources: dict[str, set[str]] = {}
    function_alias_sources: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound = alias.asname or alias.name.split(".", 1)[0]
                source = "os" if alias.name == "os" else "other"
                module_alias_sources.setdefault(bound, set()).add(source)
            continue
        if not isinstance(node, ast.ImportFrom):
            continue
        module = str(node.module or "")
        for alias in node.names:
            if alias.name not in _PYTHON_FILESYSTEM_REPLACE_METHOD_NAMES:
                continue
            bound = alias.asname or alias.name
            source = "os" if module == "os" else "other"
            function_alias_sources.setdefault(bound, set()).add(source)

    local_definitions = (
        _python_non_import_binding_names(tree)
        | _python_lexical_shadow_binding_names(tree, include_loop_targets=True)
    )
    module_aliases = {
        name
        for name, sources in module_alias_sources.items()
        if sources == {"os"} and name not in local_definitions
    }
    function_aliases = {
        name
        for name, sources in function_alias_sources.items()
        if sources == {"os"} and name not in local_definitions
    }
    module_aliases -= _python_module_attribute_mutations(
        tree,
        module_aliases,
        _PYTHON_FILESYSTEM_REPLACE_METHOD_NAMES,
    )
    return {
        "os_modules": module_aliases,
        "replace_functions": function_aliases,
    }


def _python_module_attribute_mutations(
    tree: ast.AST,
    module_aliases: set[str],
    attribute_names: set[str] | frozenset[str],
) -> set[str]:
    mutated: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = [node.target] if not isinstance(node, ast.Assign) else list(node.targets)
            for target in targets:
                if (
                    isinstance(target, ast.Attribute)
                    and target.attr in attribute_names
                    and isinstance(target.value, ast.Name)
                    and target.value.id in module_aliases
                ):
                    mutated.add(target.value.id)
        if not isinstance(node, ast.Call):
            continue
        if not (
            isinstance(node.func, ast.Name)
            and node.func.id == "setattr"
            and len(node.args) >= 2
        ):
            continue
        receiver, attr_name = node.args[0], node.args[1]
        if (
            isinstance(receiver, ast.Name)
            and receiver.id in module_aliases
            and isinstance(attr_name, ast.Constant)
            and attr_name.value in attribute_names
        ):
            mutated.add(receiver.id)
    return mutated


def _python_open_mode_writes(mode: str | None) -> bool:
    normalized = str(mode or "").strip().lower()
    return any(flag in normalized for flag in ("w", "a", "x", "+"))


def _python_implicit_customization_targets(text: str) -> list[ActionEffectTarget]:
    targets: list[ActionEffectTarget] = []
    for tokens, shell_cwd in _shell_segments_with_cwd(text):
        effective = _shell_effective_tokens(tokens)
        if not _python_invocation_imports_site(effective):
            continue
        for path in _python_implicit_customization_candidate_paths(tokens, effective, shell_cwd):
            decision = resolve_scope_task_artifact(
                path,
                access="read",
                context=_NORMALIZER_CONTEXT.get(),
                cwd=shell_cwd,
                include_legacy=False,
            )
            if not _python_startup_hook_is_declared_task_data(decision):
                continue
            target = _target_for_path(
                path,
                role=SCOPE_TASK_DATA_READ_PATH_ROLE,
                cwd=shell_cwd,
                io_direction="source",
            )
            if target.workspace_relation != SCOPE_TASK_DATA_WORKSPACE_RELATION:
                target = target.model_copy(update={"workspace_relation": SCOPE_TASK_DATA_WORKSPACE_RELATION})
            targets.append(target)
    return _dedupe_targets(targets)


def _python_startup_hook_is_declared_task_data(
    decision: ScopeTaskArtifactDecision | None,
) -> bool:
    return bool(
        decision is not None
        and decision.artifact_role == "task_data"
        and decision.candidate_role == SCOPE_TASK_DATA_READ_PATH_ROLE
        and decision.match_type == "exact"
        and decision.source_tier in {"risk_adjusting", "audit_only"}
        and decision.confidence in {"medium", "high"}
    )


def _python_invocation_imports_site(tokens: list[str]) -> bool:
    if not tokens:
        return False
    if not _is_python_launcher_name(tokens[0]):
        return False
    if _is_python_help_or_version_probe(tokens):
        return False
    if _python_option_flag_present(tokens, "S") or _python_option_flag_present(tokens, "I"):
        return False
    return True


def _python_implicit_customization_candidate_paths(
    raw_tokens: list[str],
    effective_tokens: list[str],
    shell_cwd: str | None,
) -> list[str]:
    env_enabled = not _python_option_flag_present(effective_tokens, "E")
    safe_path = _python_option_flag_present(effective_tokens, "P") or (
        env_enabled and _shell_env_assignment_truthy(raw_tokens, "PYTHONSAFEPATH")
    )
    roots: list[str] = []
    if not safe_path:
        roots.extend(_python_startup_search_roots(effective_tokens, shell_cwd))
    roots.extend(_pythonpath_assignment_roots(raw_tokens, shell_cwd, env_enabled=env_enabled))
    filenames = ["sitecustomize.py"]
    if not (
        _python_option_flag_present(effective_tokens, "s")
        or (env_enabled and _shell_env_assignment_truthy(raw_tokens, "PYTHONNOUSERSITE"))
    ):
        filenames.append("usercustomize.py")
    paths: list[str] = []
    for root in _dedupe_strings(roots):
        for filename in filenames:
            paths.append(_resolve_shell_target(filename, root))
    return _dedupe_strings(paths)


def _python_startup_search_roots(tokens: list[str], shell_cwd: str | None) -> list[str]:
    if not tokens:
        return []
    cwd = shell_cwd or _NORMALIZER_CWD.get() or "."
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            if index + 1 < len(tokens):
                return [_python_script_dir(tokens[index + 1], cwd)]
            return [cwd]
        if token in {"-c", "-m"}:
            return [cwd]
        if token.startswith("-c") or token.startswith("-m"):
            return [cwd]
        if token == "-":
            return [cwd]
        if token.startswith("-"):
            index += _python_option_arity(token)
            continue
        return [_python_script_dir(token, cwd)]
    return [cwd]


def _python_script_dir(path: str, cwd: str) -> str:
    raw = str(path or "").strip().strip("'\"")
    if not raw:
        return cwd
    parent = str(Path(raw).parent)
    if parent in {"", "."}:
        return cwd
    return _resolve_shell_target(parent, cwd)


def _python_option_arity(token: str) -> int:
    if token in {"-B", "-d", "-E", "-i", "-I", "-O", "-OO", "-P", "-q", "-s", "-S", "-u", "-v", "-V"}:
        return 1
    if token in {"-W", "-X"}:
        return 2
    if token.startswith(("-W", "-X")) and len(token) > 2:
        return 1
    return 1


def _python_option_flag_present(tokens: list[str], flag: str) -> bool:
    for token in _python_option_tokens(tokens):
        if token == f"-{flag}":
            return True
        if token.startswith("-") and not token.startswith("--") and flag in token[1:]:
            return True
    return False


def _python_option_tokens(tokens: list[str]) -> list[str]:
    options: list[str] = []
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            break
        if token in {"-c", "-m"} or token.startswith("-c") or token.startswith("-m"):
            options.append(token)
            break
        if token == "-" or not token.startswith("-"):
            break
        options.append(token)
        index += _python_option_arity(token)
    return options


def _pythonpath_assignment_roots(
    tokens: list[str],
    shell_cwd: str | None,
    *,
    env_enabled: bool = True,
) -> list[str]:
    if not env_enabled:
        return []
    roots: list[str] = []
    for token in tokens:
        if not _shell_env_assignment(token):
            continue
        name, value = token.split("=", 1)
        if name != "PYTHONPATH":
            continue
        for entry in value.split(":"):
            cleaned = entry.strip()
            if not cleaned:
                cleaned = shell_cwd or _NORMALIZER_CWD.get() or "."
            roots.append(_resolve_shell_target(cleaned, shell_cwd))
    return roots


def _python_module_invokes_pip(tokens: list[str]) -> bool:
    if not tokens:
        return False
    head = Path(tokens[0]).name.lower()
    if not re.fullmatch(r"python(?:\d+(?:\.\d+)?)?", head):
        return False
    return any(
        token == "-m" and Path(tokens[index + 1]).name.lower() in {"pip", "pip3"}
        for index, token in enumerate(tokens[:-1])
    )


# --- late-bound cross-module names (mechanical split of normalizer.py) ---
# Placed after all definitions on purpose: modules in this package form
# import cycles that are only safe because every module completes its own
# definitions before this block runs. Do not move these imports to the top.
from clawsentry.gateway.effects.normalizer import (  # noqa: E402
    _ARCHIVE_AUXILIARY_MEMBER_WRITE_RE,
    _ARCHIVE_MEMBER_COLLECTION_MUTATING_METHODS,
    _ARCHIVE_MEMBER_COLLECTION_MUTATOR_TYPE_NAMES,
    _COMMAND_AVAILABILITY_PROBE_DIRS,
    _MAX_SHELL_INLINE_DEPTH,
    _NORMALIZER_CONTEXT,
    _NORMALIZER_CWD,
    _PROTECTED_SYSTEM_WRITE_PATH_PREFIXES,
    _URL_RE,
    _add_effect,
    _add_embedded_path_read_targets,
    _add_rule,
    _append_python_static_text_payload_candidate,
    _collect_matching_name_node_ids,
    _dedupe_archive_mutation_hints,
    _dedupe_strings,
    _dedupe_targets,
    _empty_python_readonly_import_aliases,
    _empty_shell_effects,
    _glob_base_path,
    _heredoc_prefix_command_head,
    _is_python_help_or_version_probe,
    _is_python_interpreter_name,
    _is_python_launcher_name,
    _is_python_metadata_version_probe,
    _is_python_module_capability_probe,
    _is_python_source_constant_probe,
    _is_safe_python_module_probe_name,
    _max_confidence,
    _merge,
    _path_has_associated_script_surface_suffix,
    _path_has_credential_marker,
    _path_has_script_asset_directory,
    _path_with_suffix,
    _pip_path_reference_targets,
    _probe_target,
    _reset_python_sys_argv_aliases,
    _resolve_shell_target,
    _target_for_path,
    _top_level_heredoc_sections,
    _write_target_for_path,
)
from clawsentry.gateway.effects.shell_model import (  # noqa: E402
    _SHELL_TOOL_NAMES,
    _looks_like_path_arg,
    _shell_command_invokes_package_install,
    _shell_effective_tokens,
    _shell_env_assignment,
    _shell_env_assignment_truthy,
    _shell_executable_heredoc_bodies,
    _shell_segments,
    _shell_segments_with_cwd,
    shell_command_surface,
)
from clawsentry.gateway.effects.native_write import (  # noqa: E402
    _native_write_has_associated_script_surface,
    _native_write_payload_has_executable_script_marker,
    _native_write_payload_has_future_execution_marker,
    _native_write_scan_texts_have_remote_network_indicator,
    _native_write_target_is_task_output,
)
from clawsentry.gateway.effects.artifact_scope import (  # noqa: E402
    _direct_task_output_contract_violated,
    _is_scope_task_data_path,
    _is_scope_task_output_write_target,
    _path_role,
    _path_role_for_enumerate,
    _path_role_for_read,
    _scope_task_output_atomic_replace_staging_target,
    _scope_task_output_target_for_path,
    _target_is_effective_scope_task_output,
)
