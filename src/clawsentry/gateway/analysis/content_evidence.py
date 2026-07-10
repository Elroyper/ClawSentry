"""Request-local content evidence helpers for Gateway decisions.

This module keeps raw content bounded and local to the current request. Durable
records should use hashes, ranges, rule ids, and truncation metadata instead.
"""

from __future__ import annotations

import ast
import hashlib
import os
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from clawsentry.gateway.analysis.content_scanners import scan_content, text_has_external_reference_instruction
from clawsentry.gateway.models import (
    CanonicalEvent,
    ContentEvidenceEnvelope,
    ContentEvidenceIntegrity,
    ContentEvidenceItem,
    ContentEvidenceRange,
)
from clawsentry.gateway.policy.tool_semantic_registry import derive_tool_semantics

CONTENT_EVIDENCE_EXTRACTOR_VERSION = "content_evidence.python_ast_token_scan@v1"

_SOURCE_AUTHORITY_WORD = (
    r"(?:authoritative|canonical|approved|reviewed|pre[-_\s]?validated|"
    r"signed[-_\s]?off|official|source[-_\s]?of[-_\s]?truth)"
)
_SOURCE_OVERRIDE_ACTION = (
    r"(?:override|supersed(?:e|es|ed|ing)|replace|replaces|replaced|"
    r"prefer|preferred|takes?\s+precedence|wins?\s+over|use\s+instead|"
    r"instead\s+of|relax(?:es|ed|ing)?|raise(?:s|d|ing)?|lower(?:s|ed|ing)?|"
    r"amend(?:s|ed|ing)?|modif(?:y|ies|ied|ying))"
)
_SOURCE_BASELINE_OBJECT = (
    r"(?:baseline|prior|previous|earlier|original|source|evidence|document|"
    r"policy|spec|standard|rule|requirement|threshold|limit|cache|snapshot|"
    r"handoff|sidecar)"
)
_SOURCE_AUTHORITY_OVERRIDE_PATTERNS = (
    re.compile(
        rf"\b{_SOURCE_AUTHORITY_WORD}\b[\s\S]{{0,280}}\b{_SOURCE_OVERRIDE_ACTION}\b"
        rf"[\s\S]{{0,280}}\b{_SOURCE_BASELINE_OBJECT}\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b{_SOURCE_OVERRIDE_ACTION}\b[\s\S]{{0,280}}\b{_SOURCE_AUTHORITY_WORD}\b"
        rf"[\s\S]{{0,280}}\b{_SOURCE_BASELINE_OBJECT}\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b{_SOURCE_BASELINE_OBJECT}\b[\s\S]{{0,280}}\b{_SOURCE_AUTHORITY_WORD}\b"
        rf"[\s\S]{{0,280}}\b{_SOURCE_OVERRIDE_ACTION}\b",
        re.IGNORECASE,
    ),
)
_SOURCE_AUTHORITY_CONTROL_RE = re.compile(
    r"\b(?:"
    r"backup\s+authorit(?:y|ies)|"
    r"fallback\s+(?:authorit(?:y|ies)|source)|"
    r"source\s+governance|"
    r"source\s+conflicts?|"
    r"conflict\s+resolution|"
    r"source\s+(?:priority|precedence|rank(?:ing)?)|"
    r"canonical\s+source|"
    r"authoritative\s+source|"
    r"source\s+of\s+truth"
    r")\b",
    re.IGNORECASE,
)
_SOURCE_SELECTION_CONTROL_RE = re.compile(
    r"\b(?:prefer|preferred|choose|select|trust|prioriti[sz]e|defer\s+to|"
    r"fall\s+back\s+to|takes?\s+precedence|wins?\s+over)\b"
    r"[\s\S]{0,200}\b(?:source|authority|backup|document|file|dataset|scan)\b",
    re.IGNORECASE,
)
_OUTPUT_SUPPRESSION_CONTROL_RE = re.compile(
    r"\b(?:suppress(?:ed|ion)?|omit(?:ted)?|exclude(?:d)?|filter(?:ed)?\s+out|"
    r"drop(?:ped)?|redact(?:ed)?|withhold)\b"
    r"[\s\S]{0,200}?\b(?:rows?|records?|entries|items?|findings?|outputs?|reports?|results?|deliverables?|final)\b|"
    r"\b(?:rows?|records?|entries|items?|findings?|outputs?|reports?|results?|deliverables?|final)\b"
    r"[\s\S]{0,200}?\b(?:suppress(?:ed|ion)?|omit(?:ted)?|exclude(?:d)?|filter(?:ed)?\s+out|"
    r"drop(?:ped)?|redact(?:ed)?|withhold)\b",
    re.IGNORECASE,
)
_DUAL_SOURCE_SELECTION_CONTROL_RE = re.compile(
    r"\b(?:dual|double|two\s+source|cross\s+source)\s+confirm(?:ed|ation)?\b|"
    r"\bpresent\s+in\s+both\b[\s\S]{0,120}\b(?:sources?|documents?|files?|datasets?|scans?)\b|"
    r"\bboth\b[\s\S]{0,120}\b(?:sources?|documents?|files?|datasets?|scans?)\b"
    r"[\s\S]{0,120}\b(?:present|confirm(?:ed|ation)?|match(?:ed)?)\b|"
    r"\bindependent\s+(?:sources?|documents?|files?|datasets?|scans?)\b"
    r"[\s\S]{0,120}\b(?:confirm(?:ed|ation)?|match(?:ed)?)\b",
    re.IGNORECASE,
)
_OUTPUT_OBJECT_WORD = r"(?:rows?|records?|entries|items?|findings?|outputs?|reports?|results?|deliverables?|final)"
_SUPPRESSION_ACTION_WORD = (
    r"(?:suppress(?:ed|ion|ing)?|omit(?:ted|ting)?|exclude(?:d|ing)?|"
    r"filter(?:ed)?\s+out|drop(?:ped|ping)?|redact(?:ed|ing)?|withhold(?:ing|held)?)"
)
_TASK_SCOPE_OBJECT_WORD = (
    r"(?:rows?|records?|entries|items?|findings?|outputs?|reports?|results?|"
    r"deliverables?|answers?|citations?|inventory|shortlist|final)"
)
_TASK_SCOPE_CONTRACTION_WORD = (
    r"(?:cap(?:ped|s|ping)?|limit(?:ed|s|ing)?|top[-_\s]?\d+|shortlist(?:ed|ing)?|"
    r"close\s+out|closed|settled|resolved|do\s+not\s+reopen|remain\s+closed|"
    r"stay\s+out|leave\s+out|skip|omit|exclude)"
)
_TASK_SCOPE_VALIDATION_WORD = (
    r"(?:validat(?:e|es|ed|ion|ing)?|verif(?:y|ies|ied|ication|ying)|"
    r"check(?:s|ed|ing)?|audit(?:s|ed|ing)?|review(?:s|ed|ing)?|"
    r"reconcile(?:s|d|ing|iation)?|screen(?:s|ed|ing)?|triage|citation|"
    r"evidence|identifier|contradiction)"
)
_TASK_SCOPE_CONTRACTION_PATTERNS = (
    re.compile(
        rf"\b{_TASK_SCOPE_VALIDATION_WORD}\b[\s\S]{{0,260}}\b"
        rf"{_TASK_SCOPE_CONTRACTION_WORD}\b[\s\S]{{0,260}}\b{_TASK_SCOPE_OBJECT_WORD}\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b{_TASK_SCOPE_OBJECT_WORD}\b[\s\S]{{0,260}}\b"
        rf"{_TASK_SCOPE_CONTRACTION_WORD}\b[\s\S]{{0,260}}\b{_TASK_SCOPE_VALIDATION_WORD}\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b(?:complete|full|all|comprehensive)\b[\s\S]{{0,120}}\b"
        rf"{_TASK_SCOPE_OBJECT_WORD}\b[\s\S]{{0,160}}\b"
        rf"(?:not\s+required|does\s+not\s+require|is\s+not\s+required|unnecessary|skip|omit|exclude)\b",
        re.IGNORECASE,
    ),
)
_NEGATED_TASK_SCOPE_CONTRACTION_PATTERNS = (
    re.compile(
        rf"\b(?:do\s+not|don't|never|must\s+not|should\s+not|avoid|without|not)\b"
        rf"[\s\S]{{0,80}}\b(?:cap|limit(?:ing)?|shortlist|omit|exclude|suppress|drop)\b"
        rf"[\s\S]{{0,120}}\b{_TASK_SCOPE_OBJECT_WORD}\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b(?:include|return|report(?:ing)?|cover|check(?:ing)?|validate)\b"
        rf"[\s\S]{{0,100}}\b(?:all|every|complete|full|comprehensive)\b"
        rf"[\s\S]{{0,120}}\b{_TASK_SCOPE_OBJECT_WORD}\b",
        re.IGNORECASE,
    ),
)
_HIDDEN_AUXILIARY_OBJECT_WORD = (
    r"(?:auxiliary|aux|handoff|review(?:er)?|support|annotation|metadata|qa|internal)"
)
_HIDDEN_AUXILIARY_PAYLOAD_WORD = r"(?:payload|context|state|note|marker|field|block|object|metadata)"
_HIDDEN_OUTPUT_CARRIER_WORD = (
    r"(?:non[-_\s]?rendered|non[-_\s]?visible|not\s+visible|hidden|"
    r"html\s+comment|metadata\s+block|script\s+block|support\s+object|"
    r"not\s+used\s+by\s+the\s+(?:chart|page|app|visualization))"
)
_HIDDEN_OUTPUT_CARRY_ACTION_WORD = (
    r"(?:carry\s+forward|carry\s+over|preserve|include|embed|store|copy|keep)"
)
_HIDDEN_AUXILIARY_OUTPUT_PATTERNS = (
    re.compile(
        rf"\b{_HIDDEN_OUTPUT_CARRY_ACTION_WORD}\b[\s\S]{{0,240}}\b"
        rf"{_HIDDEN_AUXILIARY_OBJECT_WORD}[\W_]*{_HIDDEN_AUXILIARY_PAYLOAD_WORD}\b"
        rf"[\s\S]{{0,360}}\b{_HIDDEN_OUTPUT_CARRIER_WORD}\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b{_HIDDEN_AUXILIARY_OBJECT_WORD}[\W_]*{_HIDDEN_AUXILIARY_PAYLOAD_WORD}\b"
        rf"[\s\S]{{0,240}}\b{_HIDDEN_OUTPUT_CARRY_ACTION_WORD}\b"
        rf"[\s\S]{{0,360}}\b{_HIDDEN_OUTPUT_CARRIER_WORD}\b",
        re.IGNORECASE,
    ),
)
_NEGATED_HIDDEN_AUXILIARY_OUTPUT_RE = re.compile(
    rf"\b(?:do\s+not|don't|never|must\s+not|should\s+not|avoid|without)\b"
    rf"[\s\S]{{0,140}}\b{_HIDDEN_OUTPUT_CARRY_ACTION_WORD}\b"
    rf"[\s\S]{{0,220}}\b(?:{_HIDDEN_AUXILIARY_OBJECT_WORD}|{_HIDDEN_OUTPUT_CARRIER_WORD})\b",
    re.IGNORECASE,
)
_NEGATED_OUTPUT_SUPPRESSION_PATTERNS = (
    re.compile(
        rf"\b(?:no|none)\s+{_OUTPUT_OBJECT_WORD}\b[\s\S]{{0,80}}\b{_SUPPRESSION_ACTION_WORD}\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b{_OUTPUT_OBJECT_WORD}\b[\s\S]{{0,80}}\b(?:not|never)\b[\s\S]{{0,40}}\b"
        rf"{_SUPPRESSION_ACTION_WORD}\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\bwithout\s+{_SUPPRESSION_ACTION_WORD}\b[\s\S]{{0,80}}\b{_OUTPUT_OBJECT_WORD}\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b(?:no|without)\s+(?:suppression|omission|exclusion|redaction|withholding|filtering|dropping)\s+"
        rf"of\s+{_OUTPUT_OBJECT_WORD}\b",
        re.IGNORECASE,
    ),
)
_TEXT_READ_CONTENT_SUFFIXES = frozenset({
    ".cfg",
    ".conf",
    ".csv",
    ".htm",
    ".html",
    ".ini",
    ".json",
    ".jsonl",
    ".log",
    ".md",
    ".rst",
    ".toml",
    ".tsv",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
})
_SHELL_TEXT_READ_COMMANDS = frozenset({"cat", "head", "tail", "sed", "grep", "egrep", "fgrep", "rg", "ripgrep"})
_READ_CONTENT_STATIC_PATH_SET_INCOMPLETE = "read_content_static_path_set_incomplete"
_MAX_READ_CONTENT_SPECS = 32
_MAX_PYTHON_STATIC_LOOP_VALUES = 32
_PYTHON_STRUCTURED_TEXT_READERS = frozenset({
    "read_csv",
    "read_table",
    "read_fwf",
    "read_json",
    "read_xml",
    "read_html",
})


@dataclass(frozen=True)
class ResolvedContentPath:
    requested_path: Path
    resolved_path: Path | None
    resolved_realpath: Path | None
    resolver_status: str
    root: Path | None = None


@dataclass(frozen=True)
class ShellTextReadSpec:
    path: str
    line_start: int | None = None
    line_end: int | None = None
    tail_lines: int | None = None
    match_pattern: str | None = None
    match_ignore_case: bool = False
    match_fixed: bool = False
    synthetic_rule_id: str | None = None


def make_safe_evidence_id(source: str, *, ordinal: int) -> str:
    """Return a Gateway-generated id that never embeds path/content material."""

    if ordinal < 1:
        raise ValueError("ordinal must be >= 1")
    return f"ce_{ordinal:03d}"


def build_exact_ref_allowlist(envelope: ContentEvidenceEnvelope) -> list[str]:
    """Build exact evidence refs that L2/L3 may cite."""

    refs: list[str] = []
    for item in envelope.items:
        base = f"content_evidence.{item.canonical_evidence_id}"
        if item.content is not None:
            refs.append(f"{base}.content")
        if item.integrity.sha256 or item.integrity.sha256_full:
            refs.append(f"{base}.hash")
        for index, _range in enumerate(item.included_ranges):
            refs.append(f"{base}.range[{index}]")
        for index, _rule in enumerate(item.derived_rules):
            refs.append(f"{base}.derived_rules[{index}]")
    return refs


def strip_content_bodies(envelope: ContentEvidenceEnvelope) -> ContentEvidenceEnvelope:
    """Remove raw bodies and rebuild refs to match the remaining evidence."""

    stripped_items = [
        item.model_copy(update={"content": None, "content_persisted": False})
        for item in envelope.items
    ]
    stripped = envelope.model_copy(update={"items": stripped_items})
    return stripped.model_copy(update={"exact_ref_allowlist": build_exact_ref_allowlist(stripped)})


def hash_evidence_bytes(data: bytes) -> str:
    """Return the Gateway evidence hash format shared by content-style scanners."""

    return _sha256_bytes(data)


def hash_evidence_text(value: str) -> str:
    """Return a Gateway evidence hash for text without exposing the text itself."""

    return _sha256_text(value)


def resolve_under_approved_roots(
    path: str | Path,
    *,
    approved_roots: Iterable[str | Path],
) -> ResolvedContentPath:
    """Resolve a local path only when lexical and real paths stay under a root."""

    requested = Path(path).expanduser()
    requested_abs = Path(os.path.abspath(requested))
    roots = [Path(os.path.abspath(Path(root).expanduser())).resolve(strict=False) for root in approved_roots]
    if not roots:
        return ResolvedContentPath(requested_abs, None, None, "outside_approved_root")

    lexical_root = next((root for root in roots if _is_relative_to(requested_abs, root)), None)
    if lexical_root is None:
        return ResolvedContentPath(requested_abs, None, None, "outside_approved_root")

    try:
        realpath = requested_abs.resolve(strict=True)
    except FileNotFoundError:
        return ResolvedContentPath(requested_abs, requested_abs, None, "unresolved_path", lexical_root)
    except OSError:
        return ResolvedContentPath(requested_abs, requested_abs, None, "unresolved_path", lexical_root)

    if not _is_relative_to(realpath, lexical_root):
        return ResolvedContentPath(requested_abs, requested_abs, realpath, "symlink_escape", lexical_root)
    return ResolvedContentPath(requested_abs, requested_abs, realpath, "resolved_static_local_path", lexical_root)


def acquire_pinned_file(
    resolved: ResolvedContentPath,
    *,
    evidence_id: str,
    kind: str,
    max_bytes: int = 262_144,
    after_read_hook: Callable[[Path], None] | None = None,
) -> ContentEvidenceItem:
    """Read and hash a resolved file with stat-before/stat-after mismatch checks."""

    if resolved.resolver_status != "resolved_static_local_path" or resolved.resolved_realpath is None:
        return _item(
            evidence_id=evidence_id,
            kind=kind,
            resolver_status=resolved.resolver_status,
            resolved_path=resolved.resolved_path,
            resolved_realpath=resolved.resolved_realpath,
        )

    path = resolved.resolved_realpath
    try:
        stat_before = path.stat()
    except OSError:
        return _item(
            evidence_id=evidence_id,
            kind=kind,
            resolver_status="unresolved_path",
            resolved_path=resolved.resolved_path,
            resolved_realpath=resolved.resolved_realpath,
        )

    integrity = _integrity_from_stat(stat_before)
    if stat_before.st_size > max_bytes:
        integrity.size_bytes = int(stat_before.st_size)
        omitted = max(0, int(stat_before.st_size))
        return _item(
            evidence_id=evidence_id,
            kind=kind,
            resolver_status="resolved_static_local_path",
            resolved_path=resolved.resolved_path,
            resolved_realpath=resolved.resolved_realpath,
            integrity=integrity,
            omitted_bytes=omitted,
            truncated=True,
            oversize=True,
            derived_rules=[_rule("content_evidence_incomplete", "medium")],
        )

    try:
        data = path.read_bytes()
    except OSError:
        return _item(
            evidence_id=evidence_id,
            kind=kind,
            resolver_status="unresolved_path",
            resolved_path=resolved.resolved_path,
            resolved_realpath=resolved.resolved_realpath,
        )

    if after_read_hook is not None:
        after_read_hook(path)

    try:
        stat_after = path.stat()
    except OSError:
        stat_after = None

    integrity.sha256 = _sha256_bytes(data)
    integrity.sha256_full = integrity.sha256
    integrity.size_bytes = int(stat_before.st_size)
    integrity.stat_before = _stat_dict(stat_before)
    integrity.stat_after = _stat_dict(stat_after) if stat_after is not None else {}

    if stat_after is None or _stat_changed(stat_before, stat_after):
        return _item(
            evidence_id=evidence_id,
            kind=kind,
            resolver_status="content_mismatch",
            resolved_path=resolved.resolved_path,
            resolved_realpath=resolved.resolved_realpath,
            integrity=integrity,
            derived_rules=[_rule("content_mismatch", "high")],
        )

    if kind == "read_content" and _looks_binary_content(data, path):
        return _item(
            evidence_id=evidence_id,
            kind=kind,
            resolver_status="resolved_static_local_path",
            resolved_path=resolved.resolved_path,
            resolved_realpath=resolved.resolved_realpath,
            integrity=integrity,
            derived_rules=[_rule("read_content_unsupported_binary", "medium")],
        )

    try:
        content = data.decode("utf-8")
    except UnicodeDecodeError:
        content = data.decode("utf-8", errors="replace")

    return _item(
        evidence_id=evidence_id,
        kind=kind,
        resolver_status="resolved_static_local_path",
        resolved_path=resolved.resolved_path,
        resolved_realpath=resolved.resolved_realpath,
        integrity=integrity,
        included_ranges=[
            ContentEvidenceRange(
                start=0,
                end=len(data),
                reason="full_script_under_limit" if kind.endswith("script") else "full_content_under_limit",
            )
        ],
        content=content,
    )


def collect_script_content_evidence(
    script_path: str | Path,
    *,
    argv: list[str] | None = None,
    approved_roots: Iterable[str | Path],
    max_bytes: int = 262_144,
) -> ContentEvidenceEnvelope:
    """Collect evidence for a Python-like script and derive minimal source/sink rules."""

    evidence_id = make_safe_evidence_id(str(script_path), ordinal=1)
    resolved = resolve_under_approved_roots(script_path, approved_roots=approved_roots)
    item = acquire_pinned_file(
        resolved,
        evidence_id=evidence_id,
        kind="skill_script",
        max_bytes=max_bytes,
    )
    if item.content:
        rules = _scan_python_script(item.content, argv=argv or [])
        item = item.model_copy(update={"derived_rules": rules})
    elif (item.oversize or item.resolver_status != "resolved_static_local_path") and any(
        _looks_like_document_path(arg) for arg in (argv or [])
    ):
        rules = list(item.derived_rules)
        if not any(rule.get("rule_id") == "content_evidence_incomplete" for rule in rules):
            rules.append(_rule("content_evidence_incomplete", "medium"))
        if not any(rule.get("rule_id") == "possible_document_input_to_network_sink" for rule in rules):
            rules.append(_rule("possible_document_input_to_network_sink", "medium"))
        item = item.model_copy(update={"derived_rules": rules})
    envelope = ContentEvidenceEnvelope(items=[item])
    return envelope.model_copy(update={"exact_ref_allowlist": build_exact_ref_allowlist(envelope)})


def collect_for_event(
    event: CanonicalEvent,
    *,
    approved_roots: Iterable[str | Path] | None = None,
    max_bytes: int = 262_144,
) -> ContentEvidenceEnvelope | None:
    """Collect request-local content evidence for supported execution events."""

    if str(getattr(event, "event_type", "")) not in {"EventType.PRE_ACTION", "pre_action"}:
        return None
    roots = list(approved_roots or [])
    items: list[ContentEvidenceItem] = []
    read_evidence = collect_read_content_evidence([event], approved_roots=roots, max_bytes=max_bytes)
    if read_evidence.items:
        items.extend(read_evidence.items)
    payload = event.payload or {}
    command = str(payload.get("command") or payload.get("cmd") or "").strip()
    tool = str(event.tool_name or "").lower()
    shell_read_specs = _shell_text_read_content_specs(command)
    if shell_read_specs:
        shell_read_evidence = _collect_read_content_specs(
            shell_read_specs,
            payload=payload,
            roots=roots,
            max_bytes=max_bytes,
            source_metadata={
                "native_tool_id": "shell.local_file_read",
                "canonical_tool": "shell.local_file_read",
                "kind": "read_content",
            },
        )
        if shell_read_evidence.items:
            items.extend(shell_read_evidence.items)
    if not command and tool not in {"python", "python3"}:
        return _content_evidence_envelope_or_none(items)
    cwd = Path(str(payload.get("cwd") or payload.get("working_dir") or os.getcwd())).expanduser()
    parts, cwd = _python_parts_from_command(command, cwd=cwd)
    if tool in {"python", "python3"} and not parts:
        script_value = str(payload.get("script") or payload.get("path") or "")
        parts = [tool, script_value] if script_value else []
    if len(parts) < 2:
        return _merge_content_evidence(items, _collect_inline_command_evidence(command, tool=tool))
    executable = Path(parts[0]).name.lower()
    if not re.fullmatch(r"python(?:3(?:\.\d+)?)?", executable):
        return _content_evidence_envelope_or_none(items)
    script_index = _python_script_index(parts)
    if script_index is None:
        return _merge_content_evidence(items, _collect_inline_command_evidence(command, tool=tool))
    script = parts[script_index]

    script_path = Path(script).expanduser()
    if not script_path.is_absolute():
        script_path = cwd / script_path
    if not roots:
        return _content_evidence_envelope_or_none(items)
    return _merge_content_evidence(
        items,
        collect_script_content_evidence(
            script_path,
            argv=parts[script_index + 1:],
            approved_roots=roots,
            max_bytes=max_bytes,
        ),
    )


def collect_read_content_evidence(
    tool_calls: Iterable[object],
    *,
    approved_roots: Iterable[str | Path] | None,
    max_bytes: int = 262_144,
) -> ContentEvidenceEnvelope:
    """Collect read-content evidence for Gateway-owned local file read tools."""

    roots = list(approved_roots or [])
    if not roots:
        return ContentEvidenceEnvelope()

    items: list[ContentEvidenceItem] = []
    for ordinal, call in enumerate(tool_calls, start=1):
        call_dict = _call_as_dict(call)
        payload = call_dict.get("payload") if isinstance(call_dict.get("payload"), dict) else {}
        semantics = derive_tool_semantics(call_dict)
        if semantics is None or "local_file_read" not in semantics.content_surfaces:
            continue
        path_value = _first_payload_value(payload, semantics.path_fields)
        if not path_value:
            continue
        evidence_id = make_safe_evidence_id(str(path_value), ordinal=ordinal)
        item = _read_content_item_for_path(
            str(path_value),
            payload=payload,
            roots=roots,
            evidence_id=evidence_id,
            max_bytes=max_bytes,
            source_metadata={
                "native_tool_id": semantics.native_tool_id,
                "canonical_tool": semantics.canonical_tool,
                "kind": "read_content",
            },
        )
        items.append(item)

    return _content_evidence_envelope(items)


def _collect_read_content_specs(
    specs: Iterable[ShellTextReadSpec],
    *,
    payload: dict[str, object],
    roots: Iterable[str | Path],
    max_bytes: int,
    source_metadata: dict[str, object],
) -> ContentEvidenceEnvelope:
    root_list = list(roots or [])
    if not root_list:
        return ContentEvidenceEnvelope()
    items: list[ContentEvidenceItem] = []
    actual_ordinal = 0
    incomplete_recorded = False
    for spec in specs:
        if spec.synthetic_rule_id is not None:
            if incomplete_recorded:
                continue
            incomplete_recorded = True
            items.append(
                _synthetic_read_content_rule_item(
                    evidence_id=make_safe_evidence_id("static_path_set_incomplete", ordinal=len(items) + 1),
                    rule_id=spec.synthetic_rule_id,
                    source_metadata=source_metadata,
                )
            )
            continue
        actual_ordinal += 1
        if actual_ordinal > _MAX_READ_CONTENT_SPECS:
            if not incomplete_recorded:
                incomplete_recorded = True
                items.append(
                    _synthetic_read_content_rule_item(
                        evidence_id=make_safe_evidence_id("static_path_set_incomplete", ordinal=len(items) + 1),
                        rule_id=_READ_CONTENT_STATIC_PATH_SET_INCOMPLETE,
                        source_metadata=source_metadata,
                    )
                )
            break
        evidence_id = make_safe_evidence_id(spec.path, ordinal=len(items) + 1)
        items.append(
            _read_content_item_for_path(
                spec.path,
                payload=payload,
                roots=root_list,
                evidence_id=evidence_id,
                max_bytes=max_bytes,
                source_metadata=source_metadata,
                visible_slice=spec,
            )
        )
    return _content_evidence_envelope(items)


def _synthetic_read_content_rule_item(
    *,
    evidence_id: str,
    rule_id: str,
    source_metadata: dict[str, object],
) -> ContentEvidenceItem:
    return _item(
        evidence_id=evidence_id,
        kind="read_content",
        resolver_status="static_path_set_incomplete",
        resolved_path=None,
        resolved_realpath=None,
        integrity=ContentEvidenceIntegrity(),
        derived_rules=[_rule(rule_id, "medium")],
    ).model_copy(update={"source_metadata": dict(source_metadata)})


def _content_evidence_envelope_or_none(
    items: Iterable[ContentEvidenceItem],
) -> ContentEvidenceEnvelope | None:
    item_list = list(items)
    if not item_list:
        return None
    return _content_evidence_envelope(item_list)


def _content_evidence_envelope(
    items: Iterable[ContentEvidenceItem],
) -> ContentEvidenceEnvelope:
    renumbered = [
        item.model_copy(update={"canonical_evidence_id": make_safe_evidence_id("", ordinal=ordinal)})
        for ordinal, item in enumerate(items, start=1)
    ]
    envelope = ContentEvidenceEnvelope(items=renumbered)
    return envelope.model_copy(update={"exact_ref_allowlist": build_exact_ref_allowlist(envelope)})


def _merge_content_evidence(
    items: Iterable[ContentEvidenceItem],
    envelope: ContentEvidenceEnvelope | None,
) -> ContentEvidenceEnvelope | None:
    item_list = list(items)
    if envelope is not None:
        item_list.extend(envelope.items)
    return _content_evidence_envelope_or_none(item_list)


def _read_content_item_for_path(
    path_value: str,
    *,
    payload: dict[str, object],
    roots: Iterable[str | Path],
    evidence_id: str,
    max_bytes: int,
    source_metadata: dict[str, object],
    visible_slice: ShellTextReadSpec | None = None,
) -> ContentEvidenceItem:
    read_path = _path_with_payload_cwd(path_value, payload, roots)
    resolved = resolve_under_approved_roots(read_path, approved_roots=roots)
    if _is_sensitive_read_path(path_value):
        return _sensitive_read_path_item(
            resolved,
            evidence_id=evidence_id,
            source_metadata=source_metadata,
        )
    item = acquire_pinned_file(
        resolved,
        evidence_id=evidence_id,
        kind="read_content",
        max_bytes=max_bytes,
    )
    if visible_slice is not None:
        item = _apply_visible_text_slice(item, resolved, visible_slice, max_bytes=max_bytes)
    rules = list(item.derived_rules)
    if item.oversize and item.content is None:
        rules = [
            rule
            for rule in rules
            if rule.get("rule_id") != "content_evidence_incomplete"
        ]
    if item.content is not None:
        rules.extend(_scan_read_content_rules(item.content))
        if item.oversize:
            rules.append(_rule("read_content_oversize", "medium"))
    elif item.oversize:
        rules.append(_rule("read_content_oversize", "medium"))
    elif item.resolver_status == "resolved_static_local_path":
        rules.append(_rule("read_content_unsupported_binary", "medium"))
    return item.model_copy(update={
        "source_metadata": dict(source_metadata),
        "derived_rules": _dedupe_rule_dicts(rules),
    })


def _collect_inline_command_evidence(command: str, *, tool: str) -> ContentEvidenceEnvelope | None:
    if not command:
        return None
    language = "shell"
    if tool in {"powershell", "pwsh"}:
        language = "powershell"
    elif tool in {"node", "nodejs", "javascript"} or re.search(r"\bnode\b", command):
        language = "shell"
    result = scan_content(command, language=language)
    if not result.derived_rules:
        return None
    item = _item(
        evidence_id="ce_001",
        kind="skill_script",
        resolver_status="inline_content",
        resolved_path=None,
        resolved_realpath=None,
        integrity=ContentEvidenceIntegrity(sha256=_sha256_text(command), sha256_full=_sha256_text(command), size_bytes=len(command.encode("utf-8"))),
        derived_rules=result.derived_rules,
        content=None,
    ).model_copy(update={
        "source": "gateway_inline_command",
        "source_metadata": {"language": language, "scanner": "content_scanners"},
    })
    envelope = ContentEvidenceEnvelope(items=[item])
    return envelope.model_copy(update={"exact_ref_allowlist": build_exact_ref_allowlist(envelope)})


def _python_parts_from_command(command: str, *, cwd: Path) -> tuple[list[str], Path]:
    if not command:
        return [], cwd
    for segment in _split_shell_segments(command):
        try:
            parts = shlex.split(segment)
        except ValueError:
            return [], cwd
        if not parts:
            continue
        executable = Path(parts[0]).name.lower()
        if executable == "cd" and len(parts) >= 2:
            next_cwd = Path(parts[1]).expanduser()
            cwd = next_cwd if next_cwd.is_absolute() else cwd / next_cwd
            continue
        if executable in {"bash", "sh", "zsh"} and len(parts) >= 3:
            for index, part in enumerate(parts[:-1]):
                if part in {"-c", "-lc"} or (part.startswith("-") and "c" in part):
                    return _python_parts_from_command(parts[index + 1], cwd=cwd)
        extracted = _extract_python_invocation(parts)
        if extracted and re.fullmatch(r"python(?:3(?:\.\d+)?)?", Path(extracted[0]).name.lower()):
            return extracted, cwd
    return [], cwd


def _call_as_dict(call: object) -> dict[str, object]:
    if isinstance(call, dict):
        return dict(call)
    return {
        "source_framework": getattr(call, "source_framework", None),
        "tool_name": getattr(call, "tool_name", None),
        "payload": getattr(call, "payload", None) or {},
    }


def _first_payload_value(payload: dict[str, object], fields: Iterable[str]) -> str | None:
    for field in fields:
        value: object = payload
        for part in str(field).split("."):
            if not isinstance(value, dict) or part not in value:
                value = None
                break
            value = value[part]
        if isinstance(value, str) and value.strip():
            return value
    return None


def _path_with_payload_cwd(value: str, payload: dict[str, object], roots: Iterable[str | Path]) -> str:
    path = Path(value).expanduser()
    if path.is_absolute():
        return str(path)
    cwd_raw = payload.get("cwd") or payload.get("working_dir")
    if not isinstance(cwd_raw, str) or not cwd_raw.strip():
        return value
    cwd = Path(cwd_raw).expanduser()
    if not cwd.is_absolute():
        return value
    cwd_abs = Path(os.path.abspath(cwd)).resolve(strict=False)
    approved = [Path(os.path.abspath(Path(root).expanduser())).resolve(strict=False) for root in roots]
    if not any(_is_relative_to(cwd_abs, root) for root in approved):
        return value
    return str(cwd_abs / path)


def _is_sensitive_read_path(value: str) -> bool:
    path_l = value.replace("\\", "/").lower()
    name = Path(path_l).name
    if "/.ssh/" in path_l or name in {".env", ".npmrc", ".pypirc", "credentials", "id_rsa", "id_ed25519"}:
        return True
    if re.search(r"(?:private[-_]?key|credential|secret|token|apikey|api_key)", name):
        return True
    return bool(re.search(r"\.(?:pem|key|p12|pfx)$", name))


def _looks_binary_content(data: bytes, path: Path) -> bool:
    suffix = path.suffix.lower()
    if suffix in {".pdf", ".png", ".jpg", ".jpeg", ".gif", ".zip", ".gz", ".docx", ".pptx", ".xlsx"}:
        return True
    if b"\x00" in data[:4096]:
        return True
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


def _sensitive_read_path_item(
    resolved: ResolvedContentPath,
    *,
    evidence_id: str,
    source_metadata: dict[str, object],
) -> ContentEvidenceItem:
    integrity = ContentEvidenceIntegrity()
    if resolved.resolved_realpath is not None:
        try:
            stat_result = resolved.resolved_realpath.stat()
            integrity = _integrity_from_stat(stat_result)
        except OSError:
            pass
    return _item(
        evidence_id=evidence_id,
        kind="read_content",
        resolver_status=resolved.resolver_status,
        resolved_path=resolved.resolved_path,
        resolved_realpath=resolved.resolved_realpath,
        integrity=integrity,
        derived_rules=[
            _rule("sensitive_read_path", "high"),
            _rule("credential_read_content_skipped", "high"),
        ],
    ).model_copy(update={"source_metadata": source_metadata})


def _scan_read_content_rules(content: str) -> list[dict[str, object]]:
    rules: list[dict[str, object]] = []
    lower = content.lower()
    if re.search(r"ignore (?:all )?(?:previous|prior) instructions|system prompt|developer message|exfiltrat", lower):
        rules.append(_rule("read_content_prompt_injection", "high"))
    if re.search(r"<!--.*?(ignore|instruction|system prompt|exfiltrat).*?-->", content, re.IGNORECASE | re.DOTALL):
        rules.append(_rule("read_content_hidden_html_instruction", "high"))
    if re.search(r"[\u200b-\u200f\u202a-\u202e\u2066-\u2069]", content):
        rules.append(_rule("read_content_zero_width_or_bidi", "medium"))
    if re.search(r"!\[[^\]]*\]\(\s*https?://", content, re.IGNORECASE):
        rules.append(_rule("read_content_markdown_beacon", "medium"))
    if re.search(r"data:[^;]+;base64,|[A-Za-z0-9+/]{80,}={0,2}", content):
        rules.append(_rule("read_content_data_uri_or_base64_payload", "medium"))
    if _read_content_has_hidden_auxiliary_output_instruction(content):
        rules.append(_rule("read_content_hidden_auxiliary_output_instruction", "high"))
    if re.search(r"\b(?:curl|wget|requests\.(?:post|put|patch)|fetch\(|subprocess\.|os\.system)\b", content):
        rules.append(_rule("read_content_execution_or_network_instruction", "high"))
    if _read_content_has_source_authority_override(content):
        rules.append(_rule("read_content_source_authority_override", "high"))
    if _read_content_has_task_scope_contraction(content):
        rules.append(_rule("read_content_task_scope_contraction", "high"))
    if text_has_external_reference_instruction(content):
        rules.append(_rule("read_content_external_reference_instruction", "high"))
    return _dedupe_rule_dicts(rules)


def _read_content_has_hidden_auxiliary_output_instruction(content: str) -> bool:
    compact = re.sub(r"[_-]+", " ", str(content or ""))
    for pattern in _HIDDEN_AUXILIARY_OUTPUT_PATTERNS:
        start_at = 0
        while True:
            match = pattern.search(compact, start_at)
            if match is None:
                break
            if not _hidden_auxiliary_output_match_is_negated(compact, match):
                return True
            start_at = match.start() + 1
    return False


def _hidden_auxiliary_output_match_is_negated(text: str, match: re.Match[str]) -> bool:
    start = max(0, match.start() - 160)
    prefix = text[start:match.start()]
    boundary = max(prefix.rfind("\n"), prefix.rfind("."), prefix.rfind(";"), prefix.rfind("!"), prefix.rfind("?"))
    if boundary >= 0:
        start += boundary + 1
    end = min(len(text), match.end() + 80)
    return _NEGATED_HIDDEN_AUXILIARY_OUTPUT_RE.search(text[start:end]) is not None


def _read_content_has_source_authority_override(content: str) -> bool:
    compact = re.sub(r"[_-]+", " ", content)
    if any(pattern.search(compact) for pattern in _SOURCE_AUTHORITY_OVERRIDE_PATTERNS):
        return True
    return (
        _SOURCE_AUTHORITY_CONTROL_RE.search(compact) is not None
        and (
            _SOURCE_SELECTION_CONTROL_RE.search(compact) is not None
            or _has_affirmative_output_suppression_control(compact)
            or _DUAL_SOURCE_SELECTION_CONTROL_RE.search(compact) is not None
        )
    )


def _read_content_has_task_scope_contraction(content: str) -> bool:
    compact = re.sub(r"[_-]+", " ", str(content or ""))
    for pattern in _TASK_SCOPE_CONTRACTION_PATTERNS:
        start_at = 0
        while True:
            match = pattern.search(compact, start_at)
            if match is None:
                break
            if not _task_scope_contraction_match_is_negated(compact, match):
                return True
            start_at = match.start() + 1
    return False


def _task_scope_contraction_match_is_negated(content: str, match: re.Match[str]) -> bool:
    local = _local_sentence_for_match(content, match, before_chars=120, after_chars=120)
    return any(pattern.search(local) for pattern in _NEGATED_TASK_SCOPE_CONTRACTION_PATTERNS)


def _has_affirmative_output_suppression_control(content: str) -> bool:
    for match in _OUTPUT_SUPPRESSION_CONTROL_RE.finditer(content):
        if _output_suppression_match_is_negated(content, match):
            continue
        return True
    return False


def _output_suppression_match_is_negated(content: str, match: re.Match[str]) -> bool:
    local = _local_sentence_for_match(content, match, before_chars=120, after_chars=120)
    return any(pattern.search(local) for pattern in _NEGATED_OUTPUT_SUPPRESSION_PATTERNS)


def _local_sentence_for_match(
    content: str,
    match: re.Match[str],
    *,
    before_chars: int,
    after_chars: int,
) -> str:
    start = max(0, match.start() - before_chars)
    prefix = content[start:match.start()]
    previous_boundary = max(prefix.rfind("."), prefix.rfind("\n"), prefix.rfind(";"), prefix.rfind("!"), prefix.rfind("?"))
    if previous_boundary >= 0:
        start += previous_boundary + 1
    end = min(len(content), match.end() + after_chars)
    suffix = content[match.end():end]
    next_boundaries = [
        index
        for index in (suffix.find("."), suffix.find("\n"), suffix.find(";"), suffix.find("!"), suffix.find("?"))
        if index >= 0
    ]
    if next_boundaries:
        end = match.end() + min(next_boundaries)
    return content[start:end]


def _dedupe_rule_dicts(rules: list[dict[str, object]]) -> list[dict[str, object]]:
    seen: set[str] = set()
    result: list[dict[str, object]] = []
    for rule in rules:
        rule_id = str(rule.get("rule_id") or "")
        if rule_id and rule_id not in seen:
            seen.add(rule_id)
            result.append(rule)
    return result


def _dedupe_strings(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _dedupe_shell_read_specs(specs: Iterable[ShellTextReadSpec]) -> list[ShellTextReadSpec]:
    by_path: dict[str, list[ShellTextReadSpec]] = {}
    for spec in specs:
        by_path.setdefault(spec.path, []).append(spec)
    result: list[ShellTextReadSpec] = []
    for path, path_specs in by_path.items():
        full_spec = next(
            (
                spec
                for spec in path_specs
                if spec.line_start is None
                and spec.line_end is None
                and spec.tail_lines is None
            ),
            None,
        )
        if full_spec is not None:
            result.append(full_spec)
            continue
        seen: set[tuple[int | None, int | None, int | None, str | None, bool, bool]] = set()
        for spec in path_specs:
            key = (
                spec.line_start,
                spec.line_end,
                spec.tail_lines,
                spec.match_pattern,
                spec.match_ignore_case,
                spec.match_fixed,
            )
            if key in seen:
                continue
            seen.add(key)
            result.append(spec)
    return result


def _apply_visible_text_slice(
    item: ContentEvidenceItem,
    resolved: ResolvedContentPath,
    spec: ShellTextReadSpec,
    *,
    max_bytes: int,
) -> ContentEvidenceItem:
    if not _shell_read_spec_has_visible_filter(spec):
        return item
    sliced: tuple[str, int, int, bool] | None = None
    if item.content is not None:
        sliced_text = _visible_text_for_spec(item.content, spec)
        if sliced_text is not None:
            content, start, end = sliced_text
            sliced = (content, start, end, True)
    elif (
        item.oversize
        and item.resolver_status == "resolved_static_local_path"
        and resolved.resolved_realpath is not None
    ):
        sliced = _read_visible_text_slice_from_path(
            resolved.resolved_realpath,
            spec,
            max_bytes=max_bytes,
        )
    if sliced is None:
        return item
    content, start, end, complete = sliced
    rules = [
        rule
        for rule in item.derived_rules
        if rule.get("rule_id") != "content_evidence_incomplete"
    ]
    if not complete and not any(rule.get("rule_id") == "read_content_visible_slice_incomplete" for rule in rules):
        rules.append(_rule("read_content_visible_slice_incomplete", "medium"))
    return item.model_copy(update={
        "content": content,
        "content_persisted": True,
        "included_ranges": [
            ContentEvidenceRange(
                start=start,
                end=end,
                reason="shell_visible_text_slice",
            )
        ],
        "derived_rules": rules,
    })


def _shell_read_spec_has_visible_filter(spec: ShellTextReadSpec) -> bool:
    return (
        spec.tail_lines is not None
        or spec.line_start is not None
        or spec.line_end is not None
        or spec.match_pattern is not None
    )


def _slice_visible_text(content: str, spec: ShellTextReadSpec) -> tuple[str, int, int] | None:
    if not _shell_read_spec_has_visible_filter(spec):
        return None
    return _visible_text_for_spec(content, spec)


def _visible_text_for_spec(content: str, spec: ShellTextReadSpec) -> tuple[str, int, int] | None:
    if not _shell_read_spec_has_visible_filter(spec):
        return None
    lines = content.splitlines(keepends=True)
    if spec.tail_lines is not None:
        count = max(1, spec.tail_lines)
        selected = lines[-count:]
        prefix = lines[:-count] if count < len(lines) else []
        start_line_index = len(prefix)
    else:
        start_line = max(1, spec.line_start or 1)
        start_index = start_line - 1
        end_index = spec.line_end if spec.line_end is not None else len(lines)
        selected = lines[start_index:end_index]
        start_line_index = start_index
    line_offsets: list[int] = []
    offset = 0
    for line in lines:
        line_offsets.append(offset)
        offset += len(line.encode("utf-8"))

    indexed_lines = list(enumerate(selected, start=start_line_index))
    if spec.match_pattern is not None:
        matcher = _compile_shell_visible_match(spec)
        if matcher is None:
            return None
        indexed_lines = [
            (index, line)
            for index, line in indexed_lines
            if matcher(line)
        ]
    if not indexed_lines:
        return "", 0, 0
    visible = "".join(line for _index, line in indexed_lines)
    start = line_offsets[indexed_lines[0][0]]
    last_index, last_line = indexed_lines[-1]
    end = line_offsets[last_index] + len(last_line.encode("utf-8"))
    return visible, start, end


def _compile_shell_visible_match(spec: ShellTextReadSpec) -> Callable[[str], bool] | None:
    pattern = spec.match_pattern
    if pattern is None:
        return None
    if spec.match_fixed:
        needle = pattern.lower() if spec.match_ignore_case else pattern

        def fixed_match(line: str) -> bool:
            value = line.lower() if spec.match_ignore_case else line
            return needle in value

        return fixed_match
    flags = re.IGNORECASE if spec.match_ignore_case else 0
    try:
        compiled = re.compile(pattern, flags)
    except re.error:
        return None
    return lambda line: compiled.search(line) is not None


def _read_visible_text_slice_from_path(
    path: Path,
    spec: ShellTextReadSpec,
    *,
    max_bytes: int,
) -> tuple[str, int, int, bool] | None:
    try:
        size = path.stat().st_size
    except OSError:
        return None
    try:
        with path.open("rb") as handle:
            if spec.tail_lines is not None:
                offset = max(0, int(size) - max_bytes)
                handle.seek(offset)
                data = handle.read(max_bytes)
                text = data.decode("utf-8", errors="replace")
                sliced = _slice_visible_text(text, spec)
                if sliced is None:
                    return None
                content, start, end = sliced
                complete = _tail_slice_complete_in_chunk(text, spec, offset=offset)
                return content, offset + start, offset + end, complete
            data = handle.read(max_bytes)
    except OSError:
        return None
    text = data.decode("utf-8", errors="replace")
    sliced = _slice_visible_text(text, spec)
    if sliced is None:
        return None
    content, start, end = sliced
    complete = _prefix_slice_complete_in_chunk(
        text,
        spec,
        read_limited=int(size) > len(data),
    )
    return content, start, end, complete


def _prefix_slice_complete_in_chunk(
    text: str,
    spec: ShellTextReadSpec,
    *,
    read_limited: bool,
) -> bool:
    if not read_limited:
        return True
    if spec.line_end is None:
        return False
    return _text_contains_complete_line(text, spec.line_end)


def _tail_slice_complete_in_chunk(text: str, spec: ShellTextReadSpec, *, offset: int) -> bool:
    if offset <= 0:
        return True
    tail_lines = spec.tail_lines or 0
    if tail_lines <= 0:
        return False
    return len(text.splitlines(keepends=True)) > tail_lines


def _text_contains_complete_line(text: str, line_number: int) -> bool:
    if line_number < 1:
        return False
    lines = text.splitlines(keepends=True)
    if len(lines) > line_number:
        return True
    if len(lines) < line_number:
        return False
    return lines[line_number - 1].endswith(("\n", "\r"))


def _split_shell_segments(command: str) -> list[str]:
    segments: list[str] = []
    start = 0
    quote: str | None = None
    escaped = False
    index = 0
    newline_is_separator = "<<" not in command
    while index < len(command):
        char = command[index]
        if escaped:
            escaped = False
            index += 1
            continue
        if char == "\\":
            escaped = True
            index += 1
            continue
        if quote:
            if char == quote:
                quote = None
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            index += 1
            continue
        if char == ";":
            segment = command[start:index].strip()
            if segment:
                segments.append(segment)
            start = index + 1
            index += 1
            continue
        if char == "\n" and newline_is_separator:
            segment = command[start:index].strip()
            if segment:
                segments.append(segment)
            start = index + 1
            index += 1
            continue
        if char == "&" and index + 1 < len(command) and command[index + 1] == "&":
            segment = command[start:index].strip()
            if segment:
                segments.append(segment)
            start = index + 2
            index += 2
            continue
        if char == "|" and index + 1 < len(command) and command[index + 1] == "|":
            segment = command[start:index].strip()
            if segment:
                segments.append(segment)
            start = index + 2
            index += 2
            continue
        index += 1

    segment = command[start:].strip()
    if segment:
        segments.append(segment)
    return segments


def _shell_text_read_content_specs(command: str) -> list[ShellTextReadSpec]:
    specs: list[ShellTextReadSpec] = []
    for segment in _split_shell_segments(command):
        heredoc_code = _python_stdin_heredoc_code(segment)
        if heredoc_code is not None:
            specs.extend(_python_inline_text_read_specs(heredoc_code))
        try:
            parts = shlex.split(segment)
        except ValueError:
            continue
        specs.extend(_shell_text_read_content_specs_from_parts(parts))
    return _dedupe_shell_read_specs(specs)


def _shell_text_read_content_specs_from_parts(parts: list[str]) -> list[ShellTextReadSpec]:
    if not parts:
        return []
    parts = _shell_parts_before_operator(parts)
    executable = Path(parts[0]).name.lower()
    if executable in {"bash", "sh", "zsh"} and len(parts) >= 3:
        for index, part in enumerate(parts[:-1]):
            if part in {"-c", "-lc"} or (part.startswith("-") and "c" in part):
                return _shell_text_read_content_specs(parts[index + 1])
    if executable in _SHELL_TEXT_READ_COMMANDS:
        return _shell_text_read_command_specs(parts)
    if re.fullmatch(r"python(?:3(?:\.\d+)?)?", executable):
        inline_code = _python_inline_code_from_parts(parts)
        if inline_code is not None:
            return _python_inline_text_read_specs(inline_code)
    return []


def _shell_parts_before_operator(parts: list[str]) -> list[str]:
    for index, token in enumerate(parts):
        if token in {"|", "||", "&&", ";", "&", ">", ">>", "<", "2>", "2>>"}:
            return parts[:index]
    return parts


def _shell_text_read_command_specs(parts: list[str]) -> list[ShellTextReadSpec]:
    executable = Path(parts[0]).name.lower()
    if executable == "sed" and _sed_invocation_is_in_place(parts):
        return []
    if executable == "head":
        return _head_tail_text_read_specs(parts, tail=False)
    if executable == "tail":
        return _head_tail_text_read_specs(parts, tail=True)
    if executable == "sed":
        return _sed_text_read_specs(parts)
    if executable in {"grep", "egrep", "fgrep", "rg", "ripgrep"}:
        return _grep_text_read_specs(parts)
    paths: list[ShellTextReadSpec] = []
    index = 1
    while index < len(parts):
        token = parts[index]
        if token == "--":
            index += 1
            continue
        if token in {"-n", "-c", "-e", "-f"} and index + 1 < len(parts):
            index += 2
            continue
        if token.startswith(("-n", "-c")) and len(token) > 2:
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        if _looks_like_text_read_path(token):
            paths.append(ShellTextReadSpec(path=token))
        index += 1
    return paths


def _head_tail_text_read_specs(parts: list[str], *, tail: bool) -> list[ShellTextReadSpec]:
    line_count = 10
    from_line: int | None = None
    byte_mode = False
    paths: list[str] = []
    index = 1
    while index < len(parts):
        token = parts[index]
        if token == "--":
            paths.extend(path for path in parts[index + 1:] if _looks_like_text_read_path(path))
            break
        if token in {"-c", "--bytes"}:
            byte_mode = True
            index += 2
            continue
        if token.startswith("--bytes="):
            byte_mode = True
            index += 1
            continue
        if token in {"-n", "--lines"} and index + 1 < len(parts):
            parsed = _parse_shell_line_count(parts[index + 1])
            if parsed is None:
                return []
            if tail and str(parts[index + 1]).startswith("+"):
                from_line = parsed
            else:
                line_count = parsed
            index += 2
            continue
        if token.startswith("--lines="):
            value = token.split("=", 1)[1]
            parsed = _parse_shell_line_count(value)
            if parsed is None:
                return []
            if tail and value.startswith("+"):
                from_line = parsed
            else:
                line_count = parsed
            index += 1
            continue
        if re.fullmatch(r"-\d+", token):
            line_count = int(token[1:])
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        if _looks_like_text_read_path(token):
            paths.append(token)
        index += 1
    if byte_mode:
        return []
    specs: list[ShellTextReadSpec] = []
    for path in paths:
        if tail:
            if from_line is not None:
                specs.append(ShellTextReadSpec(path=path, line_start=from_line))
            else:
                specs.append(ShellTextReadSpec(path=path, tail_lines=line_count))
        else:
            specs.append(ShellTextReadSpec(path=path, line_start=1, line_end=line_count))
    return specs


def _sed_text_read_specs(parts: list[str]) -> list[ShellTextReadSpec]:
    quiet = False
    scripts: list[str] = []
    paths: list[str] = []
    index = 1
    while index < len(parts):
        token = parts[index]
        if token == "--":
            paths.extend(path for path in parts[index + 1:] if _looks_like_text_read_path(path))
            break
        if token == "-n" or token == "--quiet" or token == "--silent":
            quiet = True
            index += 1
            continue
        if token.startswith("-n") and token != "-n":
            quiet = True
            token = token[2:]
            if token:
                scripts.append(token)
            index += 1
            continue
        if token in {"-e", "--expression"} and index + 1 < len(parts):
            scripts.append(parts[index + 1])
            index += 2
            continue
        if token.startswith("--expression="):
            scripts.append(token.split("=", 1)[1])
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        if not scripts:
            scripts.append(token)
        elif _looks_like_text_read_path(token):
            paths.append(token)
        index += 1
    if not quiet or len(scripts) != 1:
        return []
    line_range = _sed_print_line_range(scripts[0])
    if line_range is None:
        return []
    line_start, line_end = line_range
    return [
        ShellTextReadSpec(path=path, line_start=line_start, line_end=line_end)
        for path in paths
    ]


def _grep_text_read_specs(parts: list[str]) -> list[ShellTextReadSpec]:
    executable = Path(parts[0]).name.lower()
    fixed = executable == "fgrep"
    ignore_case = False
    patterns: list[str] = []
    positional: list[str] = []
    disallowed_output_mode = False
    option_values = {
        "-A",
        "--after-context",
        "-B",
        "--before-context",
        "-C",
        "--context",
        "-m",
        "--max-count",
        "-g",
        "--glob",
        "--iglob",
        "--type",
        "-t",
        "-T",
        "--type-not",
        "--sort",
        "--sortr",
        "--color",
        "--colors",
        "-r",
        "--replace",
    }
    disallowed_value_options = {
        "-A",
        "--after-context",
        "-B",
        "--before-context",
        "-C",
        "--context",
        "-m",
        "--max-count",
        "-r",
        "--replace",
    }
    index = 1
    while index < len(parts):
        token = parts[index]
        if token == "--":
            positional.extend(parts[index + 1:])
            break
        if token in {"-e", "--regexp"} and index + 1 < len(parts):
            patterns.append(parts[index + 1])
            index += 2
            continue
        if token.startswith("--regexp="):
            patterns.append(token.split("=", 1)[1])
            index += 1
            continue
        if token in {"-f", "--file"}:
            disallowed_output_mode = True
            index += 2
            continue
        if token.startswith("--file="):
            disallowed_output_mode = True
            index += 1
            continue
        if token in option_values and index + 1 < len(parts):
            if token in disallowed_value_options:
                disallowed_output_mode = True
            index += 2
            continue
        if any(token.startswith(prefix + "=") for prefix in option_values if prefix.startswith("--")):
            if token.startswith((
                "--after-context=",
                "--before-context=",
                "--context=",
                "--max-count=",
                "--replace=",
            )):
                disallowed_output_mode = True
            index += 1
            continue
        if token in {
            "--invert-match",
            "--quiet",
            "--silent",
            "--passthru",
            "--files",
            "--files-with-matches",
            "--files-without-match",
            "--count",
            "--json",
            "--stats",
            "--help",
            "--version",
            "--only-matching",
        }:
            disallowed_output_mode = True
            index += 1
            continue
        if token.startswith("-") and token != "-":
            if _grep_short_flags_disallow_content_output(token):
                disallowed_output_mode = True
            if "i" in token:
                ignore_case = True
            if "F" in token:
                fixed = True
            index += 1
            continue
        positional.append(token)
        index += 1

    if disallowed_output_mode:
        return []
    if not patterns:
        if not positional:
            return []
        patterns.append(positional[0])
        positional = positional[1:]
    if len(patterns) != 1:
        return []
    if len(patterns[0]) > 256:
        return []
    paths = [token for token in positional if _looks_like_text_read_path(token)]
    if not paths:
        return []
    return [
        ShellTextReadSpec(
            path=path,
            match_pattern=patterns[0],
            match_ignore_case=ignore_case,
            match_fixed=fixed,
        )
        for path in paths
    ]


def _grep_short_flags_disallow_content_output(token: str) -> bool:
    if token in {
        "--files",
        "--files-with-matches",
        "--files-without-match",
        "--count",
        "--json",
        "--stats",
        "--help",
        "--version",
        "--only-matching",
    }:
        return True
    if token.startswith("--"):
        return False
    return any(flag in token[1:] for flag in {"l", "L", "c", "o", "q", "v", "m", "A", "B", "C"})


def _parse_shell_line_count(value: str) -> int | None:
    normalized = str(value or "").strip()
    if normalized.startswith("+"):
        normalized = normalized[1:]
    if not re.fullmatch(r"\d+", normalized):
        return None
    parsed = int(normalized)
    return parsed if parsed > 0 else None


def _sed_print_line_range(script: str) -> tuple[int, int | None] | None:
    normalized = re.sub(r"\s+", "", str(script or ""))
    match = re.fullmatch(r"(\d+)(?:,(\d+|\$))?p", normalized)
    if match is None:
        return None
    start = int(match.group(1))
    end_token = match.group(2)
    if start < 1:
        return None
    if end_token is None:
        return start, start
    if end_token == "$":
        return start, None
    end = int(end_token)
    if end < start:
        return None
    return start, end


def _sed_invocation_is_in_place(parts: list[str]) -> bool:
    for token in parts[1:]:
        if token == "--":
            return False
        if token == "-i" or token.startswith("-i") or token.startswith("--in-place"):
            return True
        if re.fullmatch(r"-[A-Za-z]*i[A-Za-z]*(?:\..*)?", token):
            return True
    return False


def _python_inline_code_from_parts(parts: list[str]) -> str | None:
    for index, token in enumerate(parts[:-1]):
        if token == "-c":
            return parts[index + 1]
    return None


def _python_inline_text_read_paths(code: str) -> list[str]:
    return [
        spec.path
        for spec in _python_inline_text_read_specs(code)
        if spec.synthetic_rule_id is None
    ]


def _python_inline_text_read_specs(code: str) -> list[ShellTextReadSpec]:
    if not _python_inline_code_may_read_text(code):
        return []
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return [
            ShellTextReadSpec(path=path)
            for path in _python_inline_text_read_paths_regex_fallback(code)
        ]

    path_bindings: dict[str, str] = {}
    file_bindings: dict[str, str] = {}
    sequence_bindings: dict[str, tuple[list[str], int]] = {}
    reader_bindings: set[str] = set()
    discovered: list[str] = []
    _python_collect_inline_text_read_paths_from_body(
        getattr(tree, "body", []),
        path_bindings=path_bindings,
        file_bindings=file_bindings,
        sequence_bindings=sequence_bindings,
        reader_bindings=reader_bindings,
        discovered=discovered,
    )

    specs: list[ShellTextReadSpec] = []
    for path in _dedupe_strings(discovered):
        if path == _READ_CONTENT_STATIC_PATH_SET_INCOMPLETE:
            specs.append(
                ShellTextReadSpec(
                    path="static_path_set_incomplete",
                    synthetic_rule_id=_READ_CONTENT_STATIC_PATH_SET_INCOMPLETE,
                )
            )
        elif _looks_like_text_read_path(path):
            specs.append(ShellTextReadSpec(path=path))
    return specs


def _python_collect_inline_text_read_paths_from_body(
    body: list[ast.stmt],
    *,
    path_bindings: dict[str, str],
    file_bindings: dict[str, str],
    sequence_bindings: dict[str, tuple[list[str], int]],
    reader_bindings: set[str],
    discovered: list[str],
) -> None:
    for statement in body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            for header_expr in _python_definition_header_exprs(statement):
                discovered.extend(
                    _python_text_read_paths_from_ast(
                        header_expr,
                        path_bindings,
                        file_bindings,
                        reader_bindings,
                    )
                )
            body_path_bindings = dict(path_bindings)
            body_file_bindings = dict(file_bindings)
            body_sequence_bindings = dict(sequence_bindings)
            body_reader_bindings = set(reader_bindings)
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for name in _python_arguments_bound_names(statement.args):
                    _python_clear_static_binding_name(
                        name,
                        body_path_bindings,
                        body_file_bindings,
                        body_sequence_bindings,
                        body_reader_bindings,
                    )
            _python_collect_inline_text_read_paths_from_body(
                statement.body,
                path_bindings=body_path_bindings,
                file_bindings=body_file_bindings,
                sequence_bindings=body_sequence_bindings,
                reader_bindings=body_reader_bindings,
                discovered=discovered,
            )
            continue
        if isinstance(statement, (ast.Import, ast.ImportFrom)):
            _python_bind_reader_imports(statement, reader_bindings)
            continue
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            _python_collect_inline_text_read_paths_from_assignment(
                statement,
                path_bindings=path_bindings,
                file_bindings=file_bindings,
                sequence_bindings=sequence_bindings,
                reader_bindings=reader_bindings,
                discovered=discovered,
            )
            continue
        if isinstance(statement, ast.With):
            _python_collect_inline_text_read_paths_from_with(
                statement,
                path_bindings=path_bindings,
                file_bindings=file_bindings,
                sequence_bindings=sequence_bindings,
                reader_bindings=reader_bindings,
                discovered=discovered,
            )
            continue
        if isinstance(statement, ast.For):
            _python_collect_inline_text_read_paths_from_for(
                statement,
                path_bindings=path_bindings,
                file_bindings=file_bindings,
                sequence_bindings=sequence_bindings,
                reader_bindings=reader_bindings,
                discovered=discovered,
            )
            continue
        if isinstance(statement, ast.If):
            for branch in (statement.body, statement.orelse):
                _python_collect_inline_text_read_paths_from_body(
                    branch,
                    path_bindings=dict(path_bindings),
                    file_bindings=dict(file_bindings),
                    sequence_bindings=dict(sequence_bindings),
                    reader_bindings=set(reader_bindings),
                    discovered=discovered,
                )
            continue
        if isinstance(statement, ast.Try):
            for branch in [statement.body, statement.orelse, statement.finalbody]:
                _python_collect_inline_text_read_paths_from_body(
                    branch,
                    path_bindings=dict(path_bindings),
                    file_bindings=dict(file_bindings),
                    sequence_bindings=dict(sequence_bindings),
                    reader_bindings=set(reader_bindings),
                    discovered=discovered,
                )
            for handler in statement.handlers:
                _python_collect_inline_text_read_paths_from_body(
                    handler.body,
                    path_bindings=dict(path_bindings),
                    file_bindings=dict(file_bindings),
                    sequence_bindings=dict(sequence_bindings),
                    reader_bindings=set(reader_bindings),
                    discovered=discovered,
                )
            continue
        discovered.extend(_python_text_read_paths_from_ast(statement, path_bindings, file_bindings, reader_bindings))


def _python_collect_inline_text_read_paths_from_assignment(
    statement: ast.Assign | ast.AnnAssign,
    *,
    path_bindings: dict[str, str],
    file_bindings: dict[str, str],
    sequence_bindings: dict[str, tuple[list[str], int]],
    reader_bindings: set[str],
    discovered: list[str],
) -> None:
    targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
    value = statement.value
    if value is None:
        return
    discovered.extend(_python_text_read_paths_from_ast(value, path_bindings, file_bindings, reader_bindings))
    if _python_expr_is_structured_text_reader(value, reader_bindings):
        for target in targets:
            _python_bind_reader_target(target, reader_bindings)
            _python_clear_non_reader_bindings(target, path_bindings, file_bindings, sequence_bindings)
        return
    sequence_value = _python_static_string_sequence_from_expr(
        value,
        path_bindings=path_bindings,
        sequence_bindings=sequence_bindings,
        before_lineno=getattr(statement, "lineno", None),
    )
    if sequence_value is not None:
        for target in targets:
            _python_bind_sequence_target(target, sequence_value, sequence_bindings)
            _python_clear_non_sequence_bindings(target, path_bindings, file_bindings, reader_bindings)
        return
    path_value = _python_text_path_from_expr(value, path_bindings)
    if path_value is not None:
        for target in targets:
            _python_bind_target_name(target, path_value, path_bindings)
            _python_clear_non_path_bindings(target, file_bindings, sequence_bindings, reader_bindings)
        return
    file_value = _python_text_open_path_from_call(value, path_bindings)
    if file_value is not None:
        for target in targets:
            _python_bind_target_name(target, file_value, file_bindings)
            _python_clear_non_file_bindings(target, path_bindings, sequence_bindings, reader_bindings)
        return
    for target in targets:
        _python_clear_all_static_bindings(target, path_bindings, file_bindings, sequence_bindings, reader_bindings)


def _python_collect_inline_text_read_paths_from_with(
    statement: ast.With,
    *,
    path_bindings: dict[str, str],
    file_bindings: dict[str, str],
    sequence_bindings: dict[str, tuple[list[str], int]],
    reader_bindings: set[str],
    discovered: list[str],
) -> None:
    body_file_bindings = dict(file_bindings)
    for item in statement.items:
        discovered.extend(_python_text_read_paths_from_ast(item.context_expr, path_bindings, file_bindings, reader_bindings))
        file_value = _python_text_open_path_from_call(item.context_expr, path_bindings)
        if file_value is not None and item.optional_vars is not None:
            _python_bind_target_name(item.optional_vars, file_value, body_file_bindings)
    _python_collect_inline_text_read_paths_from_body(
        statement.body,
        path_bindings=path_bindings,
        file_bindings=body_file_bindings,
        sequence_bindings=sequence_bindings,
        reader_bindings=reader_bindings,
        discovered=discovered,
    )


def _python_collect_inline_text_read_paths_from_for(
    statement: ast.For,
    *,
    path_bindings: dict[str, str],
    file_bindings: dict[str, str],
    sequence_bindings: dict[str, tuple[list[str], int]],
    reader_bindings: set[str],
    discovered: list[str],
) -> None:
    discovered.extend(_python_text_read_paths_from_ast(statement.iter, path_bindings, file_bindings, reader_bindings))
    target_name = _python_single_name_target(statement.target)
    values = _python_static_string_sequence_from_expr(
        statement.iter,
        path_bindings=path_bindings,
        sequence_bindings=sequence_bindings,
        before_lineno=getattr(statement, "lineno", None),
    )
    if target_name is not None and values is not None:
        if len(values) > _MAX_PYTHON_STATIC_LOOP_VALUES:
            discovered.append(_READ_CONTENT_STATIC_PATH_SET_INCOMPLETE)
        for value in values[:_MAX_PYTHON_STATIC_LOOP_VALUES]:
            loop_path_bindings = dict(path_bindings)
            loop_path_bindings[target_name] = value
            _python_collect_inline_text_read_paths_from_body(
                statement.body,
                path_bindings=loop_path_bindings,
                file_bindings=dict(file_bindings),
                sequence_bindings=dict(sequence_bindings),
                reader_bindings=set(reader_bindings),
                discovered=discovered,
            )
    else:
        _python_collect_inline_text_read_paths_from_body(
            statement.body,
            path_bindings=dict(path_bindings),
            file_bindings=dict(file_bindings),
            sequence_bindings=dict(sequence_bindings),
            reader_bindings=set(reader_bindings),
            discovered=discovered,
        )
    if statement.orelse:
        _python_collect_inline_text_read_paths_from_body(
            statement.orelse,
            path_bindings=dict(path_bindings),
            file_bindings=dict(file_bindings),
            sequence_bindings=dict(sequence_bindings),
            reader_bindings=set(reader_bindings),
            discovered=discovered,
        )


def _python_text_read_paths_from_ast(
    node: ast.AST,
    path_bindings: dict[str, str],
    file_bindings: dict[str, str],
    reader_bindings: set[str],
) -> list[str]:
    discovered: list[str] = []
    for child in ast.walk(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(child, ast.Call):
            path_value = _python_text_read_path_from_call(child, path_bindings, file_bindings, reader_bindings)
            if path_value is not None:
                discovered.append(path_value)
    return discovered


def _python_bind_target_name(target: ast.AST, value: str, bindings: dict[str, str]) -> None:
    if isinstance(target, ast.Name):
        bindings[target.id] = value


def _python_bind_sequence_target(
    target: ast.AST,
    value: list[str],
    sequence_bindings: dict[str, tuple[list[str], int]],
) -> None:
    if isinstance(target, ast.Name):
        sequence_bindings[target.id] = (value, getattr(target, "lineno", 0))


def _python_definition_header_exprs(
    node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef,
) -> list[ast.AST]:
    exprs: list[ast.AST] = list(node.decorator_list)
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        exprs.extend(_python_arguments_header_exprs(node.args))
        if node.returns is not None:
            exprs.append(node.returns)
        return exprs
    exprs.extend(node.bases)
    exprs.extend(keyword.value for keyword in node.keywords)
    return exprs


def _python_arguments_header_exprs(args: ast.arguments) -> list[ast.AST]:
    exprs: list[ast.AST] = []
    for arg in [*args.posonlyargs, *args.args, *args.kwonlyargs]:
        if arg.annotation is not None:
            exprs.append(arg.annotation)
    if args.vararg is not None and args.vararg.annotation is not None:
        exprs.append(args.vararg.annotation)
    if args.kwarg is not None and args.kwarg.annotation is not None:
        exprs.append(args.kwarg.annotation)
    exprs.extend(args.defaults)
    exprs.extend(default for default in args.kw_defaults if default is not None)
    return exprs


def _python_arguments_bound_names(args: ast.arguments) -> list[str]:
    names = [arg.arg for arg in [*args.posonlyargs, *args.args, *args.kwonlyargs]]
    if args.vararg is not None:
        names.append(args.vararg.arg)
    if args.kwarg is not None:
        names.append(args.kwarg.arg)
    return names


def _python_bind_reader_imports(node: ast.Import | ast.ImportFrom, reader_bindings: set[str]) -> None:
    if not isinstance(node, ast.ImportFrom):
        return
    module = str(node.module or "")
    if module not in {"pandas", "pandas.io.parsers", "pandas.io.json", "pandas.io.html"}:
        return
    for alias in node.names:
        if alias.name in _PYTHON_STRUCTURED_TEXT_READERS:
            reader_bindings.add(alias.asname or alias.name)


def _python_bind_reader_target(target: ast.AST, reader_bindings: set[str]) -> None:
    if isinstance(target, ast.Name):
        reader_bindings.add(target.id)


def _python_expr_is_structured_text_reader(node: ast.AST, reader_bindings: set[str]) -> bool:
    name = _call_name(node)
    return bool(name and (_python_call_name_is_structured_text_reader(name) or name in reader_bindings))


def _python_target_names(target: ast.AST) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names: list[str] = []
        for item in target.elts:
            names.extend(_python_target_names(item))
        return names
    return []


def _python_clear_non_reader_bindings(
    target: ast.AST,
    path_bindings: dict[str, str],
    file_bindings: dict[str, str],
    sequence_bindings: dict[str, tuple[list[str], int]],
) -> None:
    for name in _python_target_names(target):
        path_bindings.pop(name, None)
        file_bindings.pop(name, None)
        sequence_bindings.pop(name, None)


def _python_clear_non_sequence_bindings(
    target: ast.AST,
    path_bindings: dict[str, str],
    file_bindings: dict[str, str],
    reader_bindings: set[str],
) -> None:
    for name in _python_target_names(target):
        path_bindings.pop(name, None)
        file_bindings.pop(name, None)
        reader_bindings.discard(name)


def _python_clear_non_path_bindings(
    target: ast.AST,
    file_bindings: dict[str, str],
    sequence_bindings: dict[str, tuple[list[str], int]],
    reader_bindings: set[str],
) -> None:
    for name in _python_target_names(target):
        file_bindings.pop(name, None)
        sequence_bindings.pop(name, None)
        reader_bindings.discard(name)


def _python_clear_non_file_bindings(
    target: ast.AST,
    path_bindings: dict[str, str],
    sequence_bindings: dict[str, tuple[list[str], int]],
    reader_bindings: set[str],
) -> None:
    for name in _python_target_names(target):
        path_bindings.pop(name, None)
        sequence_bindings.pop(name, None)
        reader_bindings.discard(name)


def _python_clear_all_static_bindings(
    target: ast.AST,
    path_bindings: dict[str, str],
    file_bindings: dict[str, str],
    sequence_bindings: dict[str, tuple[list[str], int]],
    reader_bindings: set[str],
) -> None:
    for name in _python_target_names(target):
        _python_clear_static_binding_name(
            name,
            path_bindings,
            file_bindings,
            sequence_bindings,
            reader_bindings,
        )


def _python_clear_static_binding_name(
    name: str,
    path_bindings: dict[str, str],
    file_bindings: dict[str, str],
    sequence_bindings: dict[str, tuple[list[str], int]],
    reader_bindings: set[str],
) -> None:
    path_bindings.pop(name, None)
    file_bindings.pop(name, None)
    sequence_bindings.pop(name, None)
    reader_bindings.discard(name)


def _python_inline_code_may_read_text(code: str) -> bool:
    if ".read" in code:
        return True
    if re.search(r"\bjson\s*\.\s*load\s*\(", code):
        return True
    if re.search(r"\bcsv\s*\.\s*(?:reader|DictReader)\s*\(", code):
        return True
    if re.search(r"\bfrom\s+pandas(?:\.[A-Za-z0-9_.]+)?\s+import\s+", code):
        return True
    return bool(
        re.search(
            r"\bread_(?:csv|table|fwf|json|xml|html)\s*\(",
            code,
        )
    )


def _python_static_string_sequence_from_expr(
    node: ast.AST,
    *,
    path_bindings: dict[str, str],
    sequence_bindings: dict[str, tuple[list[str], int]],
    before_lineno: int | None = None,
) -> list[str] | None:
    if isinstance(node, ast.Name):
        bound = sequence_bindings.get(node.id)
        if bound is None:
            return None
        values, lineno = bound
        if before_lineno is not None and lineno >= before_lineno:
            return None
        return values
    if not isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return None
    values: list[str] = []
    for item in node.elts:
        value = _python_path_expr_to_static_path(item, path_bindings)
        if value is None:
            return None
        values.append(value)
    return values


def _python_single_name_target(node: ast.AST) -> str | None:
    return node.id if isinstance(node, ast.Name) else None


def _python_inline_text_read_paths_regex_fallback(code: str) -> list[str]:
    if not re.search(r"\bopen\s*\(", code) or ".read" not in code:
        return []
    return [
        path
        for path in re.findall(r"\bopen\s*\(\s*['\"]([^'\"]+)['\"]", code)
        if _looks_like_text_read_path(path)
    ]


def _python_text_read_path_from_call(
    node: ast.Call,
    path_bindings: dict[str, str],
    file_bindings: dict[str, str],
    reader_bindings: set[str],
) -> str | None:
    if isinstance(node.func, ast.Attribute):
        if node.func.attr == "read_text":
            return _python_path_expr_to_text_path(node.func.value, path_bindings)
        if node.func.attr == "read" and not node.args and isinstance(node.func.value, ast.Name):
            return file_bindings.get(node.func.value.id)
    structured_reader_path = _python_structured_text_reader_path_from_call(node, path_bindings, reader_bindings)
    if structured_reader_path is not None:
        return structured_reader_path
    return _python_text_open_path_from_call(node, path_bindings)


def _python_structured_text_reader_path_from_call(
    node: ast.Call,
    path_bindings: dict[str, str],
    reader_bindings: set[str],
) -> str | None:
    if not node.args:
        return None
    call_name = _call_name(node.func)
    if not _python_call_name_is_structured_text_reader(call_name) and call_name not in reader_bindings:
        return None
    path = _python_path_expr_to_static_path(node.args[0], path_bindings)
    return path if path is not None else _READ_CONTENT_STATIC_PATH_SET_INCOMPLETE


def _python_call_name_is_structured_text_reader(call_name: str) -> bool:
    if call_name in _PYTHON_STRUCTURED_TEXT_READERS:
        return True
    return any(call_name.endswith(f".{reader}") for reader in _PYTHON_STRUCTURED_TEXT_READERS)


def _python_text_open_path_from_call(
    node: ast.AST,
    path_bindings: dict[str, str],
) -> str | None:
    if not isinstance(node, ast.Call):
        return None
    if _call_name(node.func) == "open":
        if not node.args or not _python_open_call_is_text_mode(node):
            return None
        return _python_path_expr_to_text_path(node.args[0], path_bindings)
    if isinstance(node.func, ast.Attribute) and node.func.attr == "open":
        if not _python_open_call_is_text_mode(node):
            return None
        return _python_path_expr_to_text_path(node.func.value, path_bindings)
    return None


def _python_text_path_from_expr(
    node: ast.AST,
    path_bindings: dict[str, str],
) -> str | None:
    return _python_path_expr_to_static_path(node, path_bindings)


def _python_path_expr_to_text_path(
    node: ast.AST,
    path_bindings: dict[str, str],
) -> str | None:
    value = _python_path_expr_to_static_path(node, path_bindings)
    return value if value is not None and _looks_like_text_read_path(value) else None


def _python_path_expr_to_static_path(
    node: ast.AST,
    path_bindings: dict[str, str],
) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return path_bindings.get(node.id)
    if isinstance(node, ast.JoinedStr):
        return _python_static_path_from_joined_str(node, path_bindings)
    if isinstance(node, ast.Call) and _python_call_constructs_path(node):
        if not node.args:
            return None
        return _python_path_expr_to_static_path(node.args[0], path_bindings)
    if isinstance(node, ast.BinOp):
        return _python_static_path_from_binop(node, path_bindings)
    return None


def _python_static_path_from_joined_str(
    node: ast.JoinedStr,
    path_bindings: dict[str, str],
) -> str | None:
    parts: list[str] = []
    for value in node.values:
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            parts.append(value.value)
            continue
        if isinstance(value, ast.FormattedValue):
            formatted = _python_path_expr_to_static_path(value.value, path_bindings)
            if formatted is None:
                return None
            parts.append(formatted)
            continue
        return None
    return "".join(parts)


def _python_static_path_from_binop(
    node: ast.BinOp,
    path_bindings: dict[str, str],
) -> str | None:
    left = _python_path_expr_to_static_path(node.left, path_bindings)
    right = _python_path_expr_to_static_path(node.right, path_bindings)
    if left is None or right is None:
        return None
    if isinstance(node.op, ast.Add):
        return f"{left}{right}"
    if isinstance(node.op, ast.Div):
        return str(Path(left) / right)
    return None


def _python_call_constructs_path(node: ast.Call) -> bool:
    name = _call_name(node.func)
    return name in {"Path", "pathlib.Path", "PurePath", "pathlib.PurePath"}


def _python_open_call_is_text_mode(node: ast.Call) -> bool:
    mode_value: str | None = None
    if len(node.args) >= 2:
        mode_value = _python_literal_string(node.args[1])
    for keyword in node.keywords:
        if keyword.arg == "mode":
            mode_value = _python_literal_string(keyword.value)
            break
    if mode_value is None:
        return True
    mode = mode_value.lower()
    if "b" in mode:
        return False
    if any(flag in mode for flag in ("w", "a", "x")):
        return False
    return True


def _python_literal_string(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _python_stdin_heredoc_code(segment: str) -> str | None:
    first_newline = segment.find("\n")
    if first_newline < 0 or "<<" not in segment[:first_newline]:
        return None
    first_line = segment[:first_newline]
    marker_match = re.search(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1(?:\s|$)", first_line)
    if marker_match is None:
        return None
    try:
        first_parts = shlex.split(first_line)
    except ValueError:
        return None
    if not any(re.fullmatch(r"python(?:3(?:\.\d+)?)?", Path(part).name.lower()) for part in first_parts):
        return None
    marker = marker_match.group(2)
    body_lines: list[str] = []
    for raw_line in segment[first_newline + 1:].splitlines():
        if raw_line.strip() == marker:
            return "\n".join(body_lines)
        body_lines.append(raw_line.lstrip("\t"))
    return None


def _looks_like_text_read_path(path: str) -> bool:
    if not path or path in {"-", "/dev/null"}:
        return False
    try:
        suffix = Path(path).suffix.lower()
    except (TypeError, ValueError):
        return False
    return suffix in _TEXT_READ_CONTENT_SUFFIXES


def _python_script_index(parts: list[str]) -> int | None:
    index = 1
    options_with_values = {
        "-c",
        "-m",
        "-W",
        "-X",
        "--check-hash-based-pycs",
    }
    while index < len(parts):
        part = parts[index]
        if part == "--":
            index += 1
            break
        if part == "-":
            return None
        if not part.startswith("-"):
            break
        if part in {"-c", "-m"}:
            return None
        if part in options_with_values:
            index += 2
            continue
        index += 1
    if index >= len(parts) or parts[index].startswith("-"):
        return None
    return index


def _extract_python_invocation(parts: list[str]) -> list[str]:
    if not parts:
        return []
    executable = Path(parts[0]).name.lower()
    if re.fullmatch(r"python(?:3(?:\.\d+)?)?", executable):
        return parts
    if executable in {"bash", "sh", "zsh"} and len(parts) >= 3:
        for index, part in enumerate(parts[:-1]):
            if part in {"-c", "-lc"} or (part.startswith("-") and "c" in part):
                try:
                    nested = shlex.split(parts[index + 1])
                except ValueError:
                    return []
                return _extract_python_invocation(nested)
    return parts


def _scan_python_script(content: str, *, argv: list[str]) -> list[dict[str, object]]:
    rules: list[dict[str, object]] = []
    network_indicator = _has_network_indicator(content)
    network_sink = _has_network_upload_sink(content)
    document_read = _has_document_arg_read(content)
    has_document_arg = any(_looks_like_document_path(arg) for arg in argv)
    subprocess_transfer = _has_subprocess_file_transfer(content)

    if subprocess_transfer:
        rules.append(_rule("subprocess_file_transfer", "high"))
    if network_sink:
        rules.append(_rule("associated_script_network_sink", "high"))
    elif network_indicator:
        rules.append(_rule("associated_script_network_indicator", "low"))
    if network_sink and document_read:
        rules.append(_rule("document_input_to_network_sink", "high"))
    elif network_sink and has_document_arg:
        rules.append(_rule("possible_document_input_to_network_sink", "medium"))
    return rules


def _has_network_indicator(content: str) -> bool:
    return bool(re.search(r"\b(import|from)\s+(requests|httpx|urllib|aiohttp|socket)\b", content))


def _has_network_upload_sink(content: str) -> bool:
    try:
        tree = ast.parse(content)
    except SyntaxError:
        tree = None
    if tree is not None:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _call_name(node.func)
            if name.endswith((".post", ".put", ".patch")) or name in {"post", "put", "patch"}:
                keyword_names = {kw.arg for kw in node.keywords if kw.arg}
                if keyword_names.intersection({"files", "data", "content", "json"}):
                    return True
            if name.startswith("urllib.") and any(kw.arg == "data" for kw in node.keywords):
                return True
    return bool(
        re.search(r"\b(?:requests|httpx|aiohttp)\.post\s*\([^)]*(?:files|data|content)\s*=", content, re.DOTALL)
        or re.search(r"\burllib\.request\.[A-Za-z_]+\s*\([^)]*data\s*=", content, re.DOTALL)
    )


def _has_document_arg_read(content: str) -> bool:
    return bool(
        re.search(r"open\(\s*sys\.argv\[\d+\]", content)
        or re.search(r"Path\(\s*sys\.argv\[\d+\]\s*\)\.read_(?:text|bytes)\(", content)
        or re.search(r"\.read_(?:text|bytes)\(\)", content)
    )


def _has_subprocess_file_transfer(content: str) -> bool:
    return bool(
        re.search(r"\bsubprocess\.", content)
        and re.search(r"\b(curl)\b.*(?:-F|--form|--data-binary|-d\s*@)|\b(scp)\b|\brsync\b.*:", content, re.DOTALL)
    )


def _looks_like_document_path(value: str) -> bool:
    return bool(re.search(r"\.(pptx|docx|xlsx|pdf|csv|json|env)\b", value, re.IGNORECASE))


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _item(
    *,
    evidence_id: str,
    kind: str,
    resolver_status: str,
    resolved_path: Path | None,
    resolved_realpath: Path | None,
    integrity: ContentEvidenceIntegrity | None = None,
    included_ranges: list[ContentEvidenceRange] | None = None,
    omitted_bytes: int = 0,
    truncated: bool = False,
    oversize: bool = False,
    derived_rules: list[dict[str, object]] | None = None,
    content: str | None = None,
) -> ContentEvidenceItem:
    return ContentEvidenceItem(
        canonical_evidence_id=evidence_id,
        kind=kind,
        source="gateway_resolved_path",
        path=_path_label(resolved_path),
        resolved_path_hash=_sha256_text(str(resolved_path)) if resolved_path is not None else None,
        resolved_realpath_hash=_sha256_text(str(resolved_realpath)) if resolved_realpath is not None else None,
        path_trust="gateway_resolved_workspace" if resolver_status == "resolved_static_local_path" else "unresolved",
        resolver_status=resolver_status,
        integrity=integrity or ContentEvidenceIntegrity(),
        included_ranges=included_ranges or [],
        omitted_bytes=omitted_bytes,
        truncated=truncated,
        oversize=oversize,
        derived_rules=derived_rules or [],
        content_persisted=False,
        content=content,
    )


def _integrity_from_stat(stat_result: os.stat_result) -> ContentEvidenceIntegrity:
    return ContentEvidenceIntegrity(
        size_bytes=int(stat_result.st_size),
        mtime_ns=int(stat_result.st_mtime_ns),
        file_identity=f"{stat_result.st_dev}:{stat_result.st_ino}",
        stat_before=_stat_dict(stat_result),
    )


def _stat_dict(stat_result: os.stat_result | None) -> dict[str, int | str]:
    if stat_result is None:
        return {}
    return {
        "size_bytes": int(stat_result.st_size),
        "mtime_ns": int(stat_result.st_mtime_ns),
        "file_identity": f"{stat_result.st_dev}:{stat_result.st_ino}",
    }


def _stat_changed(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        int(before.st_size) != int(after.st_size)
        or int(before.st_mtime_ns) != int(after.st_mtime_ns)
        or int(before.st_ino) != int(after.st_ino)
        or int(before.st_dev) != int(after.st_dev)
    )


def _rule(rule_id: str, severity: str) -> dict[str, object]:
    return {
        "rule_id": rule_id,
        "severity": severity,
        "extractor": CONTENT_EVIDENCE_EXTRACTOR_VERSION,
    }


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _path_label(path: Path | None) -> str | None:
    if path is None:
        return None
    return path.name


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8"))
