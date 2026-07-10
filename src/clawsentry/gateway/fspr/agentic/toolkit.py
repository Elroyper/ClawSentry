"""Read-only toolkit and tool argument handling for agentic FSPR."""

from __future__ import annotations

import json
import re
import time
from pathlib import Path, PurePosixPath
from typing import Any

from clawsentry import _tomllib as tomllib

from ..static_rules import (
    _agentic_runtime_body_excluded_path,
    _fspr_visible_text,
    _safe_read_text,
)


class FSPRReadOnlyToolkit:
    """Skill-root-scoped read-only toolkit for FSPR roles."""

    MAX_FILE_READ_BYTES = 64_000
    MAX_FILE_RANGE_READ_BYTES = 1_000_000
    MAX_SEARCH_FILES = 2_000
    MAX_SEARCH_SECONDS = 2.0

    def __init__(self, skill_root: str | Path) -> None:
        self.skill_root = Path(skill_root).resolve(strict=False)

    def _resolve_in_root(self, path: str | Path) -> Path:
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = self.skill_root / candidate
        resolved = candidate.resolve(strict=False)
        if resolved != self.skill_root and self.skill_root not in resolved.parents:
            raise ValueError("FSPR toolkit read outside skill root")
        return resolved

    def read_file(
        self, path: str | Path, *, max_bytes: int = MAX_FILE_READ_BYTES
    ) -> str:
        resolved = self._resolve_in_root(path)
        rel = resolved.relative_to(self.skill_root).as_posix()
        if _agentic_runtime_body_excluded_path(rel):
            raise ValueError(
                "FSPR toolkit body read blocked for internal or sensitive path"
            )
        return _fspr_visible_text(resolved, max_bytes=max_bytes)

    def read_file_range(
        self, path: str | Path, *, start_line: int = 1, max_lines: int = 80
    ) -> str:
        resolved = self._resolve_in_root(path)
        rel = resolved.relative_to(self.skill_root).as_posix()
        if _agentic_runtime_body_excluded_path(rel):
            raise ValueError(
                "FSPR toolkit body read blocked for internal or sensitive path"
            )
        text = _fspr_visible_text(resolved, max_bytes=self.MAX_FILE_RANGE_READ_BYTES)
        lines = text.splitlines()
        start = max(start_line, 1) - 1
        return "\n".join(lines[start : start + max_lines])

    def list_directory(self, path: str | Path = ".") -> list[str]:
        directory = self._resolve_in_root(path)
        return sorted(item.name for item in directory.iterdir())

    def search_codebase(
        self,
        pattern: str,
        *,
        glob: str = "*",
        max_results: int = 50,
    ) -> list[dict[str, Any]]:
        if not str(pattern or "").strip():
            return [{"error": "empty search pattern"}]
        try:
            regex = re.compile(pattern, flags=re.IGNORECASE)
        except re.error as exc:
            return [{"error": f"invalid regex: {exc}"}]
        results: list[dict[str, Any]] = []
        scanned_files = 0
        deadline = time.monotonic() + self.MAX_SEARCH_SECONDS
        for path in sorted(
            item for item in self.skill_root.rglob(glob) if item.is_file()
        ):
            if time.monotonic() > deadline or scanned_files >= self.MAX_SEARCH_FILES:
                break
            resolved = self._resolve_in_root(path)
            rel = resolved.relative_to(self.skill_root).as_posix()
            if _agentic_runtime_body_excluded_path(rel):
                continue
            scanned_files += 1
            try:
                lines = _fspr_visible_text(resolved).splitlines()
            except OSError:
                continue
            for line_no, text in enumerate(lines, start=1):
                if regex.search(text):
                    results.append({"path": rel, "line": line_no, "text": text})
                    if len(results) >= max_results:
                        return results
        return results

    def read_package_manifest(self, path: str | Path) -> dict[str, Any]:
        resolved = self._resolve_in_root(path)
        rel = resolved.relative_to(self.skill_root).as_posix()
        if resolved.name == "package.json":
            payload = json.loads(_safe_read_text(resolved))
            return {
                "path": rel,
                "dependencies": dict(payload.get("dependencies") or {}),
                "dev_dependencies": dict(payload.get("devDependencies") or {}),
            }
        if resolved.name == "pyproject.toml":
            payload = tomllib.loads(_safe_read_text(resolved))
            project = payload.get("project") if isinstance(payload, dict) else {}
            return {
                "path": rel,
                "dependencies": list(project.get("dependencies") or []),
                "dev_dependencies": dict(project.get("optional-dependencies") or {}),
            }
        return {"path": rel, "unsupported": True}


_FSPR_AGENTIC_READONLY_TOOLS = frozenset(
    {
        "list_directory",
        "read_file",
        "read_file_range",
        "search_codebase",
    }
)

_AGENTIC_PRIORITY_SUFFIXES = (
    ".md",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".py",
    ".sh",
    ".js",
    ".ts",
)

_AGENTIC_AUTOMATIC_PRIORITY_READ_SUFFIXES = frozenset(
    {
        ".sh",
        ".bash",
        ".py",
        ".js",
        ".ts",
        ".mjs",
        ".cjs",
        ".rb",
        ".pl",
        ".ps1",
    }
)

_AGENTIC_PRIORITY_BASENAMES = frozenset({"Dockerfile", "Makefile"})


def _agentic_absolute_or_traversal_path(value: str) -> tuple[bool, bool]:
    text = value.replace("\x00", "")
    normalized = text.replace("\\", "/")
    drive_absolute = bool(re.match(r"^[A-Za-z]:/", normalized))
    unc_absolute = normalized.startswith("//")
    posix_absolute = normalized.startswith("/")
    traversal = ".." in Path(normalized).parts or any(
        part == ".." for part in normalized.split("/")
    )
    return posix_absolute or drive_absolute or unc_absolute, traversal


def _agentic_path_in_skill_root(root: Path, path: str | Path) -> bool:
    text = str(path)
    absolute, traversal = _agentic_absolute_or_traversal_path(text)
    if absolute or traversal:
        return False
    candidate = Path(text)
    resolved = (root / candidate).resolve(strict=False)
    return resolved == root or root in resolved.parents


def _agentic_priority_path(path: str, *, root: Path | None = None) -> bool:
    lowered = path.lower()
    if Path(lowered).name == "bundle_manifest.json":
        return False
    basename = Path(path).name
    if (
        lowered.startswith("_fspr_context/")
        or lowered.startswith("scripts/")
        or lowered.startswith("references/")
        or lowered.startswith("assets/")
        or Path(path).suffix.lower() in _AGENTIC_PRIORITY_SUFFIXES
        or basename in _AGENTIC_PRIORITY_BASENAMES
    ):
        return True
    if root is None or Path(path).suffix:
        return False
    candidate = root / path
    try:
        if candidate.stat().st_mode & 0o111:
            return True
        with candidate.open("rb") as handle:
            return handle.read(2) == b"#!"
    except OSError:
        return False


def _agentic_priority_path_rank(path: str, *, root: Path) -> tuple[int, str]:
    lowered = path.lower()
    suffix = Path(path).suffix.lower()
    basename = Path(path).name
    if lowered.startswith(("scripts/", "script/", "bin/", "tools/")):
        return (0, lowered)
    if basename in _AGENTIC_PRIORITY_BASENAMES:
        return (1, lowered)
    if lowered.startswith("_fspr_context/"):
        return (2, lowered)
    if lowered.startswith(("assets/", "references/", "reference/")):
        return (4, lowered)
    if _agentic_automatic_priority_read_path(path, root=root):
        return (0, lowered)
    if suffix in {".json", ".yaml", ".yml", ".toml"}:
        return (3, lowered)
    if suffix == ".md":
        return (5, lowered)
    return (6, lowered)


def _agentic_manifest_hint_paths(root: Path, existing: set[str]) -> list[str]:
    manifest = root / "BUNDLE_MANIFEST.json"
    if not manifest.is_file():
        return []
    try:
        payload = json.loads(_safe_read_text(manifest))
    except (OSError, json.JSONDecodeError, TypeError):
        return []
    source_files = payload.get("source_files") if isinstance(payload, dict) else None
    if not isinstance(source_files, list):
        return []
    hints: list[str] = []
    for item in source_files:
        if not isinstance(item, dict):
            continue
        raw = item.get("bundle_path")
        if not isinstance(raw, str) or not raw:
            continue
        parts = Path(raw).parts
        absolute, traversal = _agentic_absolute_or_traversal_path(raw)
        if absolute or traversal:
            continue
        candidates = ["/".join(parts[index:]) for index in range(len(parts))]
        for candidate in candidates:
            if (
                candidate in existing
                and _agentic_path_in_skill_root(root, candidate)
                and _agentic_priority_path(candidate, root=root)
            ):
                hints.append(candidate)
                break
    return hints


def _execute_agentic_readonly_tool(
    toolkit: FSPRReadOnlyToolkit,
    tool_name: str,
    tool_args: dict[str, Any],
) -> Any:
    if tool_name == "list_directory":
        return toolkit.list_directory(
            tool_args.get("path") or tool_args.get("relative_path") or "."
        )
    if tool_name == "read_file":
        path = tool_args.get("path") or tool_args.get("relative_path") or ""
        return toolkit.read_file(path)
    if tool_name == "read_file_range":
        path = tool_args.get("path") or tool_args.get("relative_path") or ""
        return toolkit.read_file_range(
            path,
            start_line=int(tool_args.get("start_line") or 1),
            max_lines=int(tool_args.get("max_lines") or 80),
        )
    if tool_name == "search_codebase":
        return toolkit.search_codebase(
            str(tool_args.get("pattern") or ""),
            glob=str(tool_args.get("glob") or "*"),
            max_results=int(tool_args.get("max_results") or 50),
        )
    raise ValueError(f"agentic-readonly tool not allowed: {tool_name}")


def _agentic_safe_tool_path(toolkit: FSPRReadOnlyToolkit, value: Any) -> str:
    text = str(value or "")
    if not text:
        return ""
    try:
        resolved = toolkit._resolve_in_root(text)
        return resolved.relative_to(toolkit.skill_root).as_posix()
    except Exception:  # noqa: BLE001 - trace must not preserve unsafe raw paths.
        return "<outside_skill_root>"


def _agentic_safe_tool_arg_value(value: Any) -> Any:
    if isinstance(value, str):
        absolute, traversal = _agentic_absolute_or_traversal_path(value)
        if absolute or traversal:
            return "<absolute_path>" if absolute else "<path_traversal>"
        return value
    if isinstance(value, list):
        return [_agentic_safe_tool_arg_value(item) for item in value[:20]]
    if isinstance(value, dict):
        return {
            str(key)[:80]: _agentic_safe_tool_arg_value(item)
            for key, item in list(value.items())[:30]
        }
    return value


def _agentic_safe_tool_args(
    toolkit: FSPRReadOnlyToolkit,
    tool_args: dict[str, Any],
) -> dict[str, Any]:
    safe_args: dict[str, Any] = {}
    for key, item in list(tool_args.items())[:30]:
        safe_key = str(key)[:80]
        if safe_key in {"path", "relative_path"}:
            safe_args[safe_key] = _agentic_safe_tool_path(toolkit, item)
        else:
            safe_args[safe_key] = _agentic_safe_tool_arg_value(item)
    return safe_args


def _agentic_search_counts_as_followup(pattern: Any) -> bool:
    return bool(str(pattern or "").strip())


_AGENTIC_TRUNCATION_FOLLOWUP_RISK_PATTERNS: tuple[tuple[re.Pattern[str], int], ...] = (
    (re.compile(r"\b(?:requests|httpx)\.(?:get|post|put|patch|delete)\s*\(", re.I), 4),
    (re.compile(r"\b(?:curl|wget)\b|fetch\s*\(|axios\.", re.I), 4),
    (re.compile(r"\burllib\.request\b", re.I), 4),
    (re.compile(r"\b(?:bash|sh)\b[^\n]*(?:scripts?/|\.sh\b)", re.I), 3),
    (re.compile(r"\b(?:powershell|chmod\s+\+x|sudo)\b", re.I), 3),
    (
        re.compile(
            r"\b(?:api[_-]?key|token|secret|password|credential|authorization|bearer)\b",
            re.I,
        ),
        2,
    ),
    (
        re.compile(
            r"\b(?:exfiltrat|webhook|callback|endpoint|upload|collect|send)\b", re.I
        ),
        2,
    ),
    (re.compile(r"\b(?:clipboard|pbpaste|xclip|xsel)\b", re.I), 3),
    (
        re.compile(
            r"\b(?:backdoor|dev_admin|admin\s+account|default\s+account)\b", re.I
        ),
        3,
    ),
    (
        re.compile(r"\b(?:sql\s+injection|security\s+test|penetration\s+test)\b", re.I),
        3,
    ),
    (
        re.compile(
            r"\b(?:skip|disable|do\s+not\s+write|do\s+not\s+run)\b[^\n]*(?:test|validation|verification)",
            re.I,
        ),
        3,
    ),
    (
        re.compile(
            r"\b(?:server-side|server\s+side)\b[^\n]*(?:verification|validation)", re.I
        ),
        3,
    ),
    (re.compile(r"\bgit\s+remote\s+(?:add|set-url)\b", re.I), 2),
    (
        re.compile(
            r"\b(?:backup|sync|mirror|archive|telemetry|analytics|diagnostic|system info|ip address|location)\b",
            re.I,
        ),
        1,
    ),
)


def _agentic_truncation_followup_line_score(line: str) -> int:
    return sum(
        weight
        for pattern, weight in _AGENTIC_TRUNCATION_FOLLOWUP_RISK_PATTERNS
        if pattern.search(line)
    )


def _agentic_followup_start_for_line(
    line_no: int,
    *,
    total_lines: int,
    max_lines: int,
) -> int:
    start = line_no - (max_lines // 2)
    max_start = max(1, total_lines - max_lines + 1)
    return min(max(start, 1), max_start)


def _agentic_add_followup_start(
    starts: list[int],
    start: int,
    *,
    max_lines: int,
    max_starts: int,
) -> None:
    if len(starts) >= max_starts:
        return
    candidate_end = start + max_lines - 1
    for existing_start in starts:
        existing_end = existing_start + max_lines - 1
        if existing_start <= start and candidate_end <= existing_end:
            return
        overlap = min(candidate_end, existing_end) - max(start, existing_start) + 1
        if overlap >= max_lines // 2:
            return
    starts.append(start)


_AGENTIC_REFERENCED_SCRIPT_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_./-])"
    r"((?:\./)?(?:scripts?|bin|tools)/[A-Za-z0-9_./-]+"
    r"(?:\.(?:sh|bash|py|js|ts|mjs|cjs|rb|pl|ps1))?)"
)

_AGENTIC_REFERENCED_SCRIPT_BASENAME_RE = re.compile(
    r"(?<![A-Za-z0-9_./-])"
    r"([A-Za-z0-9_.-]+\.(?:sh|bash|py|js|ts|mjs|cjs|rb|pl|ps1))"
    r"(?![A-Za-z0-9_./-])"
)


def _agentic_automatic_priority_read_path(path: str, *, root: Path) -> bool:
    if (
        not path
        or not _agentic_path_in_skill_root(root, path)
        or _agentic_runtime_body_excluded_path(path)
    ):
        return False
    candidate = root / path
    if not candidate.is_file() or not _agentic_priority_path(path, root=root):
        return False
    lowered = path.lower()
    if lowered.startswith(("scripts/", "script/", "bin/", "tools/")):
        return True
    if (
        lowered.startswith(("references/", "reference/"))
        and Path(path).suffix.lower() == ".md"
    ):
        return True
    if Path(path).suffix.lower() in _AGENTIC_AUTOMATIC_PRIORITY_READ_SUFFIXES:
        return True
    try:
        if candidate.stat().st_mode & 0o111:
            return True
        with candidate.open("rb") as handle:
            return handle.read(2) == b"#!"
    except OSError:
        return False


_AGENTIC_REFERENCED_PATH_RISK_MARKERS = (
    "permission",
    "credential",
    "secret",
    "token",
    "password",
    "upload",
    "collect",
    "exfil",
    "webhook",
    "callback",
    "endpoint",
    "backup",
    "sync",
    "remote",
    "chmod",
    "admin",
    "auth",
    "key",
    "telemetry",
    "analytics",
    "diagnostic",
)


def _agentic_referenced_priority_path_score(path: str) -> int:
    lowered = path.lower()
    return sum(
        1 for marker in _AGENTIC_REFERENCED_PATH_RISK_MARKERS if marker in lowered
    )


def _agentic_normalized_referenced_priority_path(
    rel: str,
    *,
    root: Path,
) -> str | None:
    path = PurePosixPath(rel)
    if path.is_absolute() or ".." in path.parts:
        return None
    normalized = path.as_posix()
    candidate = root / normalized
    if (
        not _agentic_path_in_skill_root(root, normalized)
        or not candidate.is_file()
        or _agentic_runtime_body_excluded_path(normalized)
        or not _agentic_priority_path(normalized, root=root)
    ):
        return None
    return normalized


def _agentic_referenced_priority_paths(
    content: Any,
    *,
    root: Path,
    limit: int = 2,
) -> list[str]:
    candidates: list[tuple[int, str]] = []
    seen: set[str] = set()
    order = 0

    def add_candidate(rel: str) -> None:
        nonlocal order
        normalized = _agentic_normalized_referenced_priority_path(rel, root=root)
        if normalized is None or normalized in seen:
            return
        seen.add(normalized)
        candidates.append((order, normalized))
        order += 1

    for match in _AGENTIC_REFERENCED_SCRIPT_PATH_RE.finditer(str(content or "")):
        raw = match.group(1).strip("`'\"").rstrip("),.;:")
        add_candidate(raw)
    for match in _AGENTIC_REFERENCED_SCRIPT_BASENAME_RE.finditer(str(content or "")):
        basename = match.group(1).strip("`'\"").rstrip("),.;:")
        for directory in ("scripts", "script", "bin", "tools"):
            add_candidate(f"{directory}/{basename}")
    if len(candidates) <= limit:
        return [path for _order, path in candidates]
    chosen = sorted(
        candidates,
        key=lambda item: (
            -_agentic_referenced_priority_path_score(item[1]),
            item[0],
        ),
    )[:limit]
    return [path for _order, path in sorted(chosen)]


def _agentic_required_truncation_followup_starts(
    content: Any,
    *,
    max_lines: int = 80,
    max_starts: int = 3,
) -> list[int]:
    lines = str(content or "").splitlines()
    total_lines = max(len(lines), 1)
    if total_lines <= max_lines:
        return [1]
    starts: list[int] = []
    scored_lines = [
        (
            -score,
            index,
            _agentic_followup_start_for_line(
                index,
                total_lines=total_lines,
                max_lines=max_lines,
            ),
        )
        for index, line in enumerate(lines, start=1)
        if (score := _agentic_truncation_followup_line_score(line)) >= 2
    ]
    for _negative_score, _line_no, start in sorted(scored_lines):
        _agentic_add_followup_start(
            starts,
            start,
            max_lines=max_lines,
            max_starts=max_starts,
        )
    middle_start = max(1, (total_lines // 2) - (max_lines // 2) + 1)
    tail_start = max(1, total_lines - max_lines + 1)
    for start in (middle_start, tail_start):
        _agentic_add_followup_start(
            starts,
            start,
            max_lines=max_lines,
            max_starts=max_starts,
        )
    return sorted(starts)
