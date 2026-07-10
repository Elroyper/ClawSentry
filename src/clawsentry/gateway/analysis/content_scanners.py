"""Normalized request-local content scanner plugins.

Scanners return evidence metadata only. They intentionally do not return policy
verdicts or decision recommendations.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


CONTENT_SCANNER_VERSION = "content_scanners.normalized@v1"

_LOCAL_WEB_RESOURCE_LITERAL_RE = (
    r"\s*['\"]"
    r"(?!(?:[a-z][a-z0-9+.-]*:|//))"
    r"(?!(?:(?:\.{1,2}/)|/)*(?:api|remote|upload|download|webhook|callback|endpoint|url|uri|host|addr|address)(?:[/.?#]|$))"
    r"(?:\.{0,2}/|[A-Za-z0-9._~-]+/)"
)
_REMOTE_REFERENCE_URI_RE = re.compile(
    r"\b(?:https?|s3|gs|az|azure|ftp|ssh|git(?:\+ssh)?)://[^\s`'\"<>),;]+",
    re.IGNORECASE,
)
_EXTERNAL_REFERENCE_DIRECTIVE_RE = re.compile(
    r"\b(?:"
    r"include[-_\s]*from|"
    r"import[-_\s]*from|"
    r"source[-_\s]*from|"
    r"load[-_\s]*from|"
    r"fetch[-_\s]*from|"
    r"download[-_\s]*from|"
    r"pull[-_\s]*from|"
    r"sync[-_\s]*from|"
    r"apply\s+(?:the\s+)?(?:patch|diff)\s+from|"
    r"(?:use|apply|load|fetch|download|pull|import|include)\s+"
    r"(?:the\s+)?(?:external|remote)\s+(?:patch|diff|artifact|reference|source)|"
    r"preserve\s+(?:this\s+)?line\s+exactly|"
    r"keep\s+(?:this\s+)?line\s+exactly|"
    r"copy\s+(?:this\s+)?line\s+exactly"
    r")\b",
    re.IGNORECASE,
)
_EXTERNAL_REFERENCE_DIRECTIVE_WINDOW_CHARS = 320


@dataclass(frozen=True)
class ContentScanResult:
    derived_rules: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    budget_truncated: bool = False
    policy_action: None = None


def scan_content(
    content: str | bytes,
    *,
    language: str,
    source_path: str | Path | None = None,
    local_module_roots: Iterable[str | Path] | None = None,
    max_bytes: int = 262_144,
    max_local_modules: int = 8,
) -> ContentScanResult:
    """Scan a bounded content fragment and return normalized evidence rules."""

    raw_len = len(content if isinstance(content, bytes) else content.encode("utf-8", errors="replace"))
    metadata: dict[str, Any] = {
        "language": language,
        "source_path_label": Path(source_path).name if source_path is not None else None,
    }
    if raw_len > max_bytes:
        metadata["omitted_bytes"] = raw_len
        return ContentScanResult(
            derived_rules=[_rule("content_evidence_incomplete", "medium")],
            metadata=metadata,
            budget_truncated=True,
        )

    if isinstance(content, bytes):
        metadata.update(_document_metadata(content, source_path))
        return ContentScanResult(
            derived_rules=[_rule("read_content_unsupported_binary", "medium")],
            metadata=metadata,
        )

    language_l = language.strip().lower()
    if language_l in {"shell", "bash", "sh", "zsh"}:
        text = _capture_shell_embedded(content)
        return ContentScanResult(derived_rules=_scan_text_rules(text, language="shell"), metadata=metadata)
    if language_l in {"javascript", "js", "node", "nodejs"}:
        return ContentScanResult(derived_rules=_scan_text_rules(content, language="javascript"), metadata=metadata)
    if language_l in {"powershell", "pwsh"}:
        return ContentScanResult(derived_rules=_scan_text_rules(content, language="powershell"), metadata=metadata)
    if language_l == "python":
        rules = _scan_text_rules(content, language="python")
        rules.extend(_python_syntax_rules(content))
        rules.extend(_local_module_rules(content, source_path=source_path, roots=local_module_roots, max_modules=max_local_modules))
        return ContentScanResult(derived_rules=_dedupe_rules(rules), metadata=metadata)
    if language_l in {"document", "binary"}:
        metadata.update(_document_metadata(content.encode("utf-8", errors="replace"), source_path))
        return ContentScanResult(derived_rules=[_rule("read_content_unsupported_binary", "medium")], metadata=metadata)
    return ContentScanResult(derived_rules=[_rule("content_evidence_incomplete", "medium")], metadata=metadata)


def _scan_text_rules(text: str, *, language: str) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    lower = text.lower()
    if _text_has_network_upload_sink(text, language=language):
        rules.append(_rule("associated_script_network_sink", "high"))
    elif _text_has_network_indicator(text, language=language):
        rules.append(_rule("associated_script_network_indicator", "low"))
    if text_has_external_reference_instruction(text):
        rules.append(_rule("external_reference_instruction", "high"))
    if re.search(r"\b(?:hf_token|api[_-]?key|password|secret|token|\$env:)\b", lower) and rules:
        rules.append(_rule("credential_source_to_network_sink", "high"))
    if re.search(r"\b(?:rm\s+-rf|remove-item\s+-recurse|del\s+/f)\b", lower):
        rules.append(_rule("destructive_operation", "high"))
    if re.search(r"\b(?:crontab|launchagents|systemd|startup)\b", lower):
        rules.append(_rule("persistence_entrypoint", "medium"))
    return _dedupe_rules(rules)


def text_has_external_reference_instruction(text: str) -> bool:
    raw = str(text or "")
    uri_matches = list(_REMOTE_REFERENCE_URI_RE.finditer(raw))
    if not uri_matches or _EXTERNAL_REFERENCE_DIRECTIVE_RE.search(raw) is None:
        return False
    for match in uri_matches:
        start = max(0, match.start() - _EXTERNAL_REFERENCE_DIRECTIVE_WINDOW_CHARS)
        end = min(len(raw), match.end() + _EXTERNAL_REFERENCE_DIRECTIVE_WINDOW_CHARS)
        if _EXTERNAL_REFERENCE_DIRECTIVE_RE.search(raw[start:end]):
            return True
    return False


def _text_has_network_upload_sink(text: str, *, language: str) -> bool:
    raw = str(text or "")
    lowered = raw.lower()
    if re.search(
        r"\b(?:requests|httpx|aiohttp)\s*\.\s*(?:post|put|patch|delete|request)\s*\([^)]*"
        r"\b(?:data|files|json|content|body)\s*=",
        raw,
        re.IGNORECASE | re.DOTALL,
    ):
        return True
    if re.search(
        r"\burllib(?:\.request)?\s*\.\s*[A-Za-z_]\w*\s*\([^)]*\bdata\s*=",
        raw,
        re.IGNORECASE | re.DOTALL,
    ):
        return True
    if re.search(
        r"\bfetch\s*\([^)]*(?:\bbody\s*:|\bmethod\s*:\s*['\"](?:post|put|patch|delete)['\"])",
        raw,
        re.IGNORECASE | re.DOTALL,
    ):
        return True
    if re.search(
        r"\baxios\s*\.\s*(?:post|put|patch|delete)\s*\(",
        raw,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        r"\baxios\s*\.\s*request\s*\([^)]*(?:\bdata\s*:|\bmethod\s*:\s*['\"](?:post|put|patch|delete)['\"])",
        raw,
        re.IGNORECASE | re.DOTALL,
    ):
        return True
    if re.search(r"\bXMLHttpRequest\s*\([^)]*\)|\bnavigator\s*\.\s*sendBeacon\s*\(", raw, re.IGNORECASE):
        return bool(re.search(r"\.\s*send\s*\(|sendBeacon\s*\(", raw, re.IGNORECASE))
    if re.search(
        r"\bcurl\b[^\n]*(?:\s(?:-F|--form|--form-string|-d|--data(?:-[A-Za-z-]+)?|--upload-file)(?:\s|=)|"
        r"\s-X\s*(?:POST|PUT|PATCH|DELETE)\b)",
        raw,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        r"\bwget\b[^\n]*(?:--post-data|--post-file|--body-data|--body-file|--method=(?:POST|PUT|PATCH|DELETE))",
        raw,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        r"\binvoke-webrequest\b[^\n]*(?:\b-method\s+(?:post|put|patch|delete)\b|\b-body\b)",
        lowered,
        re.IGNORECASE,
    ):
        return True
    return False


def _text_has_network_indicator(text: str, *, language: str) -> bool:
    raw = str(text or "")
    if re.search(r"\b(?:import|from)\s+(?:requests|httpx|urllib|aiohttp|socket)\b", raw):
        return True
    if re.search(r"\b(?:requests|httpx|aiohttp)\s*\.\s*(?:get|head|request)\s*\(", raw, re.IGNORECASE):
        return True
    if re.search(r"\burllib(?:\.request)?\s*\.\s*(?:urlopen|Request)\s*\(", raw, re.IGNORECASE):
        return True
    if re.search(
        rf"\bfetch\s*\(\s*(?!{_LOCAL_WEB_RESOURCE_LITERAL_RE})",
        raw,
        re.IGNORECASE,
    ):
        return True
    if re.search(r"\bXMLHttpRequest\s*\(|\bEventSource\s*\(|\bWebSocket\s*\(", raw, re.IGNORECASE):
        return True
    if re.search(r"\b(?:curl|wget)\b[^\n]*https?://", raw, re.IGNORECASE):
        return True
    if re.search(r"\binvoke-webrequest\b[^\n]*https?://", raw, re.IGNORECASE):
        return True
    if re.search(r"<script\b[^>]*\bsrc\s*=\s*['\"]https?://", raw, re.IGNORECASE):
        return True
    return False


def _python_syntax_rules(text: str) -> list[dict[str, Any]]:
    try:
        ast.parse(text)
    except SyntaxError:
        return [_rule("content_evidence_syntax_error", "low")]
    return []


def _local_module_rules(
    text: str,
    *,
    source_path: str | Path | None,
    roots: Iterable[str | Path] | None,
    max_modules: int,
) -> list[dict[str, Any]]:
    if source_path is None:
        return []
    root_paths = [Path(root).resolve(strict=False) for root in (roots or [])]
    if not root_paths:
        return []
    imported = re.findall(r"(?m)^\s*import\s+([A-Za-z_][A-Za-z0-9_]*)\s*$", text)
    rules: list[dict[str, Any]] = []
    for index, module_name in enumerate(imported):
        if index >= max_modules:
            rules.append(_rule("content_evidence_incomplete", "medium"))
            break
        candidate = Path(source_path).parent / f"{module_name}.py"
        try:
            real = candidate.resolve(strict=True)
        except OSError:
            continue
        if not any(_is_relative_to(real, root) for root in root_paths):
            rules.append(_rule("content_evidence_incomplete", "medium"))
            continue
        rules.extend(_scan_text_rules(real.read_text(encoding="utf-8", errors="replace"), language="python"))
    return rules


def _capture_shell_embedded(text: str) -> str:
    captures = [text]
    for match in re.finditer(r"\b(?:python|python3|node)\s+-[ce]\s+(['\"])(?P<body>.*?)(?<!\\)\1", text, re.DOTALL):
        captures.append(match.group("body"))
    heredoc = re.search(r"<<['\"]?(?P<tag>[A-Za-z_][A-Za-z0-9_]*)['\"]?\n(?P<body>.*?)\n(?P=tag)\b", text, re.DOTALL)
    if heredoc:
        captures.append(heredoc.group("body"))
    return "\n".join(captures)


def _document_metadata(data: bytes, source_path: str | Path | None) -> dict[str, Any]:
    path = Path(source_path) if source_path is not None else Path("")
    return {
        "extension": path.suffix.lower(),
        "size_bytes": len(data),
        "mime_guess": _mime_guess(path.suffix.lower()),
        "macro_indicator": path.suffix.lower() in {".docm", ".xlsm", ".pptm"},
    }


def _mime_guess(extension: str) -> str:
    return {
        ".pdf": "application/pdf",
        ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    }.get(extension, "application/octet-stream")


def _rule(rule_id: str, severity: str) -> dict[str, Any]:
    return {"rule_id": rule_id, "severity": severity, "extractor": CONTENT_SCANNER_VERSION}


def _dedupe_rules(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for rule in rules:
        rule_id = str(rule.get("rule_id") or "")
        if rule_id and rule_id not in seen:
            seen.add(rule_id)
            result.append(rule)
    return result


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False
