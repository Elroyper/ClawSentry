"""Agentic FSPR semantic review validation and provider parsing."""

from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath
from typing import Any, Sequence

from ..provider import (
    _extract_provider_json,
    _iter_provider_json_objects,
    _normalize_provider_confidence,
    _normalize_provider_findings,
    _normalize_provider_severity,
    _normalize_provider_verdict,
)
from ..static_rules import _agentic_runtime_body_excluded_path, _review_axis_from_value
from ..types import (
    FSPRAgenticSemanticReviewError,
    FSPRProviderSchemaError,
    _sha256,
)
from .risk_cues import (
    _AGENTIC_READ_FILE_STRONG_RISK_CUE_TYPES,
    _AGENTIC_STRONG_RISK_CUE_TYPES,
    _agentic_centered_excerpt,
    _agentic_strict_evidence_marker_index,
    _agentic_strict_evidence_excerpt,
    _agentic_strict_risk_cues,
)
from .toolkit import _agentic_absolute_or_traversal_path

_AGENTIC_SEMANTIC_DIMENSIONS = (
    "prompt_injection",
    "credential_theft",
    "hidden_capability",
    "privilege_escalation",
    "delayed_poisoning",
    "context_pollution",
    "result_exfiltration",
    "audit_visibility",
    "action_materialization",
    "result_integrity",
    "description_mismatch",
)

_AGENTIC_SEMANTIC_STATUSES = frozenset(
    {
        "clean",
        "suspicious",
        "not_enough_evidence",
    }
)

_AGENTIC_SEMANTIC_DIMENSION_AXES = {
    "prompt_injection": "instruction_channel_integrity",
    "credential_theft": "data_boundary_control",
    "hidden_capability": "capability_manifest_alignment",
    "privilege_escalation": "capability_manifest_alignment",
    "delayed_poisoning": "state_mutation_scope",
    "context_pollution": "instruction_channel_integrity",
    "result_exfiltration": "data_boundary_control",
    "audit_visibility": "review_evidence_quality",
    "action_materialization": "data_boundary_control",
    "result_integrity": "state_mutation_scope",
    "description_mismatch": "package_identity_integrity",
}

_AGENTIC_SEMANTIC_DIMENSION_GUIDANCE = {
    "prompt_injection": (
        "Instructions inside the skill package that try to override, persist, "
        "or redirect the agent's governing instructions."
    ),
    "credential_theft": (
        "Requests to read, preserve, reveal, log, or transmit secrets, tokens, "
        "keys, cookies, credentials, or private configuration."
    ),
    "hidden_capability": (
        "Behavior that adds undeclared network, shell, file, API, persistence, "
        "wrapper/shim layers, or data-boundary capabilities beyond the skill "
        "description."
    ),
    "privilege_escalation": (
        "Requests for broader workspace, account, repository, host, or service "
        "authority than the user task requires, including package-supplied "
        "approval, clearance, prevalidated, readiness, or review-decision status."
    ),
    "delayed_poisoning": (
        "Instructions that plant, preserve, or activate state for later tasks, "
        "future runs, updates, or downstream consumers. Declared, user-visible "
        "technical plans or reports are not suspicious merely because they guide "
        "later work."
    ),
    "context_pollution": (
        "Untrusted sidecar, carryover, addendum, handoff, hidden, or non-rendered "
        "material that the skill asks to preserve, trust, merge into context, or "
        "pass to downstream handoff/reconciliation, including package-local "
        "approval, clearance, prevalidated, readiness, review-decision packets, "
        "reviewed/prechecked status, archived profile material, cache/snapshot "
        "values, eval seed or sandbox seed material, query override or retrieval "
        "override instructions, diagnostic snapshots, or companion reconciliation "
        "files whose values are carried into the result."
    ),
    "result_exfiltration": (
        "Requests to add extra packets, reports, metadata, logs, artifacts, or "
        "task outputs that carry data outside the user's requested result boundary."
    ),
    "audit_visibility": (
        "Instructions that hide, move, suppress, erase, archive, or make "
        "user-invisible audit logs, traces, history, provenance, errors, or "
        "review evidence, even when described as retention or cleanup."
    ),
    "action_materialization": (
        "Instructions that create, duplicate, or preserve ready-to-use action "
        "artifacts outside the requested result that could trigger real-world or "
        "security-sensitive action, including payment or commitment requests, "
        "outbound messages, approval packets, reset mail, or other actionable "
        "documents. User-visible technical reports, test plans, target shortlists, "
        "or harness guidance are not action materialization by themselves."
    ),
    "result_integrity": (
        "Instructions that can make the user's requested result stale, unverifiable, "
        "or falsely validated, including reusing stale snapshots or cached/precomputed "
        "answers, skipping required recalculation, comparison, validation, tests, or "
        "fresh evidence checks, trusting package-supplied output over task data, or "
        "injecting reviewed/prechecked, archived profile, cache/snapshot, eval seed, "
        "query override, diagnostic snapshot, locked, consensus, companion, or "
        "reconciliation values into final fields, rankings, thresholds, labels, or "
        "workbook/source-data outputs."
    ),
    "description_mismatch": (
        "Mismatch between the declared skill purpose and extra sidecar/handoff, "
        "output mutation, authority, clearance, approval, or data-flow behavior "
        "in package evidence."
    ),
}

_AGENTIC_SEMANTIC_EVIDENCE_MAX_ITEMS = 8

_AGENTIC_SEMANTIC_EVIDENCE_MAX_CHARS = 900

_AGENTIC_STRICT_FINAL_EVIDENCE_MAX_ITEMS = 3

_AGENTIC_STRICT_FINAL_EVIDENCE_MAX_CHARS = 320

_AGENTIC_STRICT_FINAL_REDACTION_MAX_CHARS = 100_000

_AGENTIC_SEMANTIC_DIMENSION_STRICT_GUIDANCE = {
    "prompt_injection": "Skill package tries to override or persist agent instructions.",
    "credential_theft": "Reads, preserves, reveals, logs, or transmits credentials, tokens, passwords, or private config.",
    "hidden_capability": "Undeclared network, shell, file, API, persistence, wrapper/shim, or data-boundary capability.",
    "privilege_escalation": "Uses package approval, clearance, prevalidated status, or broader authority than needed.",
    "delayed_poisoning": "Plants hidden or forced-trust state for future runs, downstream users, or later activation.",
    "context_pollution": "Untrusted sidecar, carryover, downstream handoff, reviewed/prechecked status, archived profile, cache/snapshot, eval seed, query override, diagnostic snapshot, approval, clearance, prevalidated packet, or companion reconciliation material.",
    "result_exfiltration": "Extra logs, uploads, hidden metadata, side packets, or artifacts outside the requested result.",
    "audit_visibility": "Hides, suppresses, erases, archives, or makes audit logs/traces/history/review evidence user-invisible.",
    "action_materialization": "Creates ready-to-use commitment, payment, approval, reset mail, outbound message, or other real-world/security-sensitive action packet.",
    "result_integrity": "Reviewed/prechecked status, archived profile, stale cache/snapshot, eval seed, query override, diagnostic snapshot, cached/precomputed answer, skipped recalculation/validation, or locked/companion/reconciliation values in final output.",
    "description_mismatch": "Declared purpose differs from actual sidecar, handoff, mutation, authority, or data-flow behavior.",
}


def _parse_agentic_tool_call_response(
    raw: str,
) -> tuple[str, dict[str, Any], bool] | None:
    try:
        payload = json.loads(_extract_provider_json(raw))
    except (json.JSONDecodeError, TypeError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    tool_call = payload.get("tool_call")
    if not isinstance(tool_call, dict):
        return None
    tool_name = str(tool_call.get("name") or "")
    tool_args = tool_call.get("arguments") or {}
    if not isinstance(tool_args, dict):
        tool_args = {}
    if not tool_name:
        return None
    return tool_name, tool_args, bool(payload.get("done", False))


def _agentic_safe_value(value: Any, *, max_len: int = 240) -> Any:
    if isinstance(value, str):
        text = value.replace("\x00", "")
        return text[:max_len] + "...[truncated]" if len(text) > max_len else text
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, list):
        return [_agentic_safe_value(item, max_len=max_len) for item in value[:20]]
    if isinstance(value, dict):
        safe: dict[str, Any] = {}
        for key, item in list(value.items())[:30]:
            safe[str(key)[:80]] = _agentic_safe_value(item, max_len=max_len)
        return safe
    return _agentic_safe_value(str(value), max_len=max_len)


def _agentic_bound_content(
    content: Any, *, max_chars: int
) -> tuple[Any, bool, str, int]:
    serialized = (
        content
        if isinstance(content, str)
        else json.dumps(content, ensure_ascii=False, sort_keys=True)
    )
    content_hash = _sha256(serialized.encode("utf-8", errors="replace"))
    truncated = len(serialized) > max_chars
    if truncated:
        marker_index = _agentic_strict_evidence_marker_index(serialized)
        if marker_index is not None:
            bounded = _agentic_centered_excerpt(
                serialized,
                index=marker_index,
                max_chars=max_chars,
            )
        else:
            marker = "\n...[truncated middle]...\n"
            if max_chars <= len(marker) + 2:
                bounded = serialized[:max_chars] + "\n[truncated]"
            else:
                remaining = max_chars - len(marker)
                head_chars = max(1, remaining // 2)
                tail_chars = max(1, remaining - head_chars)
                bounded = serialized[:head_chars] + marker + serialized[-tail_chars:]
    else:
        bounded = serialized
    return bounded, truncated, content_hash, len(serialized)


def _agentic_redact_semantic_prompt_text(text: str, *, max_chars: int) -> str:
    def redacted_absolute_path(match: re.Match[str]) -> str:
        raw_path = match.group(0)
        basename = PurePosixPath(raw_path.replace("\\", "/")).name
        safe_basename = re.sub(r"[^A-Za-z0-9._-]+", "_", basename).strip("._-")
        if safe_basename:
            return f"<absolute_path>/{safe_basename[:80]}"
        return "<absolute_path>"

    redacted = str(text or "").replace("\x00", "")
    redacted = re.sub(
        r"\b(?:akia[0-9a-z]{8,}|ghp_[0-9a-z_]{8,}|glpat-[0-9a-z_-]{8,}|"
        r"sk-[0-9a-z_-]{8,}|hf_[0-9a-z_-]{12,})\b",
        "<secret>",
        redacted,
        flags=re.I,
    )
    redacted = re.sub(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        "<private_key>",
        redacted,
        flags=re.S,
    )
    redacted = re.sub(
        r"\b(?:api[_-]?key|token|secret|password)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]",
        "<secret_assignment>",
        redacted,
        flags=re.I,
    )
    redacted = re.sub(
        r"(?<![\w:])/(?:[^\s/\"']+/){1,}[^\s\"']*",
        redacted_absolute_path,
        redacted,
    )
    redacted = re.sub(
        r"\b[A-Za-z]:[\\/][^\s\"']+",
        redacted_absolute_path,
        redacted,
    )
    for token in _AGENTIC_FORBIDDEN_FINDING_TOKENS:
        redacted = re.sub(re.escape(token), "<benchmark_label>", redacted, flags=re.I)
    if len(redacted) > max_chars:
        bounded, _, _, _ = _agentic_bound_content(redacted, max_chars=max_chars)
        return str(bounded)
    return redacted


def _agentic_semantic_evidence_item_from_envelope(
    envelope: dict[str, Any],
) -> dict[str, Any] | None:
    path = str(envelope.get("path") or "")
    if not path or path.startswith("<") or _agentic_runtime_body_excluded_path(path):
        return None
    evidence_ref = str(envelope.get("evidence_ref") or f"file:{path}")
    range_info = envelope.get("range")
    content = str(envelope.get("content") or "")
    redacted = _agentic_redact_semantic_prompt_text(
        content,
        max_chars=_AGENTIC_STRICT_FINAL_REDACTION_MAX_CHARS,
    )
    return {
        "evidence_ref": evidence_ref,
        "path": path,
        "range": range_info if isinstance(range_info, dict) else None,
        "sha256_full": envelope.get("sha256_full"),
        "truncated": bool(envelope.get("truncated")),
        "content_chars": envelope.get("content_chars"),
        "content": _agentic_strict_evidence_excerpt(
            redacted,
            max_chars=_AGENTIC_SEMANTIC_EVIDENCE_MAX_CHARS,
        ),
        "content_trust": "untrusted_skill_package_evidence",
    }


def _agentic_semantic_evidence_for_prompt(
    semantic_evidence: list[dict[str, Any]],
) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in semantic_evidence:
        evidence_ref = str(item.get("evidence_ref") or "")
        file_hash = str(item.get("sha256_full") or "")
        key = f"{evidence_ref}|{file_hash}"
        if not evidence_ref or key in seen:
            continue
        seen.add(key)
        items.append(
            {
                "evidence_ref": evidence_ref,
                "path": _agentic_safe_evidence_ref(str(item.get("path") or "")),
                "sha256_full": item.get("sha256_full"),
                "truncated": bool(item.get("truncated")),
                "content_chars": item.get("content_chars"),
                "content": item.get("content"),
                "content_trust": "untrusted_skill_package_evidence",
            }
        )
        range_info = item.get("range")
        if isinstance(range_info, dict):
            items[-1]["range"] = range_info
        if len(items) >= _AGENTIC_SEMANTIC_EVIDENCE_MAX_ITEMS:
            break
    return {
        "schema": "clawsentry.fspr_agentic_semantic_evidence.v1",
        "source": "agentic_readonly_files_actually_read",
        "items": items,
    }


_AGENTIC_NORMAL_DOCUMENT_WORKFLOW_DIMS = frozenset(
    {
        "context_pollution",
        "audit_visibility",
        "result_integrity",
    }
)

_AGENTIC_NORMAL_DOCUMENT_WORKFLOW_MARKERS = (
    "docx",
    "raw docx xml",
    "raw xml",
    "tracked changes",
    "pack the document",
    "pack.py",
    "unpack.py",
    "validate.py",
    "validate the resulting document",
    "pandoc --track-changes",
)


def _agentic_normal_document_workflow_ref(ref: str) -> bool:
    base = _agentic_base_evidence_ref(ref)
    if base == "file:SKILL.md":
        return True
    return base in {
        "file:ooxml/scripts/pack.py",
        "file:ooxml/scripts/unpack.py",
        "file:ooxml/scripts/validate.py",
    }


def _agentic_downgrade_normal_document_workflow_result(
    role_result: dict[str, Any],
    *,
    semantic_evidence: Sequence[dict[str, Any]],
) -> bool:
    if str(role_result.get("verdict") or "") not in {"suspicious", "inconsistent"}:
        return False
    if _agentic_strict_risk_cues(semantic_evidence):
        return False
    semantic_review = _sanitize_agentic_semantic_dimension_review(
        role_result.get("semantic_dimension_review")
    )
    suspicious = [
        item
        for item in semantic_review
        if str(item.get("status") or "") == "suspicious"
    ]
    if not suspicious:
        return False
    dimensions = {str(item.get("dimension") or "") for item in suspicious}
    if not dimensions.issubset(_AGENTIC_NORMAL_DOCUMENT_WORKFLOW_DIMS):
        return False
    refs = {
        str(ref)
        for item in suspicious
        for ref in list(item.get("evidence_refs") or [])
        if isinstance(ref, str)
    }
    if not refs or any(not _agentic_normal_document_workflow_ref(ref) for ref in refs):
        return False
    content = " ".join(
        str(item.get("content") or "") for item in semantic_evidence
    ).lower()
    if not any(
        marker in content for marker in _AGENTIC_NORMAL_DOCUMENT_WORKFLOW_MARKERS
    ):
        return False
    role_result["verdict"] = "consistent"
    role_result["severity"] = "low"
    role_result["confidence"] = min(
        _normalize_provider_confidence(role_result.get("confidence")),
        0.78,
    )
    role_result["findings"] = []
    role_result["semantic_dimension_review"] = _agentic_clean_semantic_review(
        confidence=role_result["confidence"]
    )
    role_result["agentic_normal_operation_calibration"] = "downgraded_document_workflow"
    return True


def _agentic_calibrate_role_result_with_risk_cues(
    role_result: dict[str, Any],
    *,
    semantic_evidence: Sequence[dict[str, Any]],
    deterministic_findings: Sequence[dict[str, Any]],
) -> bool:
    cues = _agentic_strict_risk_cues(semantic_evidence)
    strong_cues = [
        cue
        for cue in cues
        if str(cue.get("type") or "") in _AGENTIC_STRONG_RISK_CUE_TYPES
        and (
            _agentic_base_evidence_ref(str(cue.get("ref") or "")) == "file:SKILL.md"
            or str(cue.get("type") or "") in _AGENTIC_READ_FILE_STRONG_RISK_CUE_TYPES
        )
    ]
    semantic_review = _sanitize_agentic_semantic_dimension_review(
        role_result.get("semantic_dimension_review")
    )
    verdict = str(role_result.get("verdict") or "insufficient_evidence")
    severity = str(role_result.get("severity") or "low")
    confidence = _normalize_provider_confidence(role_result.get("confidence"))
    changed = False

    if strong_cues and verdict in {"consistent", "insufficient_evidence"}:
        by_dimension = {
            str(item.get("dimension") or ""): dict(item) for item in semantic_review
        }
        for cue in strong_cues:
            cue_ref = str(cue.get("ref") or "")
            for dimension in _agentic_string_list(cue.get("dims")):
                if dimension not in _AGENTIC_SEMANTIC_DIMENSIONS:
                    continue
                by_dimension[dimension] = {
                    "dimension": dimension,
                    "status": "suspicious",
                    "evidence_refs": [cue_ref] if cue_ref else [],
                    "rationale": "Cue-backed read evidence marks this dimension suspicious.",
                    "confidence": max(confidence, 0.72),
                }
        role_result["semantic_dimension_review"] = list(by_dimension.values())
        role_result["verdict"] = "suspicious"
        role_result["severity"] = "medium" if severity == "low" else severity
        role_result["confidence"] = max(confidence, 0.72)
        role_result["agentic_risk_cue_calibration"] = "raised_from_clean"
        changed = True

    return changed


def _agentic_semantic_evidence_repair_refs(
    semantic_evidence: Sequence[dict[str, Any]],
) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in semantic_evidence:
        evidence_ref = str(item.get("evidence_ref") or "")
        if not evidence_ref or evidence_ref in seen:
            continue
        seen.add(evidence_ref)
        refs.append(
            {
                "evidence_ref": evidence_ref,
                "path": _agentic_safe_evidence_ref(str(item.get("path") or "")),
                "range": item.get("range")
                if isinstance(item.get("range"), dict)
                else None,
                "content": _agentic_safe_value(item.get("content"), max_len=520),
            }
        )
        if len(refs) >= 12:
            break
    return refs


def _agentic_tool_evidence_envelope(
    *,
    tool_name: str,
    tool_args: dict[str, Any],
    result: Any,
    max_content_chars: int,
) -> dict[str, Any]:
    path = tool_args.get("path") or tool_args.get("relative_path") or "."
    content = result
    range_info = None
    if isinstance(result, dict):
        if "path" in result:
            path = result.get("path")
        if "content" in result:
            content = result.get("content")
        if "start_line" in result or "end_line" in result:
            range_info = {
                "start_line": result.get("start_line"),
                "end_line": result.get("end_line"),
            }
    if range_info is None and tool_name == "read_file_range":
        start_line = max(int(tool_args.get("start_line") or 1), 1)
        line_count = len(str(content or "").splitlines())
        end_line = start_line + max(line_count, 1) - 1
        range_info = {
            "start_line": start_line,
            "end_line": end_line,
        }
    bounded, truncated, content_hash, content_chars = _agentic_bound_content(
        content,
        max_chars=max_content_chars,
    )
    safe_path = _agentic_safe_value(path, max_len=240)
    evidence_ref = f"file:{safe_path}"
    if isinstance(range_info, dict):
        start_line = range_info.get("start_line")
        end_line = range_info.get("end_line")
        if isinstance(start_line, int) and isinstance(end_line, int):
            evidence_ref = f"{evidence_ref}:L{start_line}-L{end_line}"
    envelope: dict[str, Any] = {
        "schema": "clawsentry.fspr_agentic_tool_evidence.v1",
        "tool": tool_name,
        "source": "skill_package",
        "path": safe_path,
        "evidence_ref": evidence_ref,
        "truncated": truncated,
        "sha256_full": content_hash,
        "content_chars": content_chars,
        "content": _agentic_redact_semantic_prompt_text(
            str(bounded),
            max_chars=max_content_chars,
        ),
        "content_trust": "untrusted",
    }
    if range_info is not None:
        envelope["range"] = range_info
    return envelope


def _agentic_json_payload(raw: str) -> dict[str, Any] | None:
    try:
        payload = json.loads(_extract_provider_json(raw))
    except (json.JSONDecodeError, TypeError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def _agentic_exploration_done_payload(payload: dict[str, Any] | None) -> bool:
    return bool(payload and payload.get("done") is True and "tool_call" not in payload)


def _agentic_final_like_payload(payload: dict[str, Any] | None) -> bool:
    if not payload:
        return False
    final_keys = {
        "verdict",
        "final_verdict",
        "decision",
        "status",
        "adjudication",
        "approved",
        "findings",
        "severity",
        "risk_level",
        "risk",
        "level",
    }
    return bool(final_keys.intersection(payload))


def _agentic_mixed_final_tool_payload(payload: dict[str, Any] | None) -> bool:
    return bool(
        payload
        and isinstance(payload.get("tool_call"), dict)
        and _agentic_final_like_payload(payload)
    )


_AGENTIC_FINDING_ALLOWED_KEYS = frozenset(
    {
        "id",
        "rule_id",
        "category",
        "review_axis",
        "severity",
        "confidence",
        "evidence_refs",
        "language",
        "deterministic_source",
        "decision_affecting",
        "capability",
        "declared_capabilities",
        "observed_capabilities",
        "scanner_version",
        "budget_truncated",
    }
)

_AGENTIC_FORBIDDEN_FINDING_TOKENS = frozenset(
    {
        "case_id",
        "source_bench",
        "expected_family",
        "expected_families",
        "expected_min_verdict",
        "direct_toxic",
    }
)


def _agentic_safe_finding_identifier(value: Any, *, prefix: str) -> str:
    text = str(value or "").replace("\x00", "").strip()
    if (
        text
        and len(text) <= 120
        and re.fullmatch(r"[a-z0-9][a-z0-9_.:-]*", text)
        and text not in _AGENTIC_FORBIDDEN_FINDING_TOKENS
    ):
        return text
    return f"{prefix}-" + _sha256(text.encode("utf-8", errors="replace"))[7:19]


def _agentic_safe_finding_category(value: Any) -> str:
    text = str(value or "").replace("\x00", "").strip()
    if (
        text
        and len(text) <= 80
        and re.fullmatch(r"[a-z0-9][a-z0-9_.:-]*", text)
        and text not in _AGENTIC_FORBIDDEN_FINDING_TOKENS
    ):
        return text
    return "provider_reported_risk"


def _agentic_safe_finding_value(key: str, value: Any) -> Any:
    if key == "id":
        return _agentic_safe_finding_identifier(value, prefix="provider-finding")
    if key == "rule_id":
        return _agentic_safe_finding_identifier(value, prefix="provider-rule")
    if key == "review_axis":
        return _review_axis_from_value(value) or "review_evidence_quality"
    if key == "decision_affecting":
        return bool(value)
    if key in {"category", "language", "capability", "scanner_version"}:
        return _agentic_safe_finding_category(value)
    if key == "deterministic_source":
        return _agentic_safe_finding_category(value)
    if key in {"declared_capabilities", "observed_capabilities"}:
        values = value if isinstance(value, list) else [value]
        return [_agentic_safe_finding_category(item) for item in values[:20]]
    return _agentic_safe_value(value, max_len=240)


def _agentic_safe_evidence_ref(ref: str) -> str:
    text = ref.replace("\x00", "").strip()
    if text.startswith(("file:", "package:")):
        explained_ref = re.match(
            r"^((?:file|package):[^\s()]+(?::L?\d+(?:-L?\d+)?)?)(?:\s+.+)?$",
            text,
        )
        if explained_ref:
            text = explained_ref.group(1)
    prefix = ""
    path_text = text
    for candidate_prefix in ("file:", "package:"):
        if text.startswith(candidate_prefix):
            prefix = candidate_prefix
            path_text = text[len(candidate_prefix) :]
            break
    candidate = Path(path_text)
    absolute, traversal = _agentic_absolute_or_traversal_path(path_text)
    if absolute:
        return f"{prefix}<absolute_path>"
    if traversal:
        return f"{prefix}<path_traversal>"
    return _agentic_safe_value(text, max_len=240)


def _agentic_extract_evidence_ref(value: Any) -> str | None:
    if isinstance(value, str):
        return _agentic_safe_evidence_ref(value)
    if not isinstance(value, dict):
        return None
    for key in ("evidence_ref", "ref"):
        ref = value.get(key)
        if isinstance(ref, str) and ref.strip():
            return _agentic_safe_evidence_ref(ref)
    path = value.get("path")
    if not isinstance(path, str) or not path.strip():
        return None
    ref = path if path.startswith(("file:", "package:")) else f"file:{path}"
    ref_range = value.get("range")
    if isinstance(ref_range, dict):
        start = ref_range.get("start_line")
        end = ref_range.get("end_line")
        if (
            isinstance(start, int)
            and isinstance(end, int)
            and start > 0
            and end >= start
        ):
            ref = f"{ref}:L{start}-L{end}"
    return _agentic_safe_evidence_ref(ref)


def _agentic_evidence_ref_values(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (str, dict)):
        return [value]
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return list(value)
    return []


def _sanitize_agentic_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sanitized: list[dict[str, Any]] = []
    for finding in findings:
        item: dict[str, Any] = {}
        legacy_axis = _review_axis_from_value(finding.get("finding_family"))
        for key, value in finding.items():
            if key not in _AGENTIC_FINDING_ALLOWED_KEYS:
                continue
            if key == "evidence_refs":
                refs = [
                    _agentic_extract_evidence_ref(ref)
                    for ref in _agentic_evidence_ref_values(value)
                ]
                item[key] = [ref for ref in refs if ref][:20]
            else:
                item[key] = _agentic_safe_finding_value(key, value)
        if legacy_axis and "review_axis" not in item:
            item["review_axis"] = legacy_axis
        if item:
            sanitized.append(item)
    return sanitized


def _normalize_agentic_semantic_status(value: Any) -> str:
    text = str(value or "").strip().lower()
    normalized = text.replace("-", "_").replace(" ", "_").replace("/", "_")
    normalized = re.sub(r"_+", "_", normalized).strip("_")
    if normalized in _AGENTIC_SEMANTIC_STATUSES:
        return normalized
    if normalized in {
        "safe",
        "ok",
        "pass",
        "passed",
        "clear",
        "benign",
        "none",
        "no_risk",
        "not_suspicious",
    }:
        return "clean"
    if normalized in {
        "risk",
        "risky",
        "flag",
        "flagged",
        "warning",
        "warn",
    }:
        return "suspicious"
    if normalized in {
        "unknown",
        "incomplete",
        "insufficient",
        "insufficient_evidence",
        "needs_more_evidence",
    }:
        return "not_enough_evidence"
    if re.match(
        r"^(clean|clear|benign|safe|ok|pass|passed|none|no_risk|not_suspicious)_",
        normalized,
    ):
        return "clean"
    if re.match(r"^(suspicious|risk|risky|flag|flagged|warning|warn)_", normalized):
        return "suspicious"
    if re.match(
        r"^(not_enough_evidence|not_enough|insufficient_evidence|insufficient|unknown|incomplete|needs_more_evidence)_",
        normalized,
    ):
        return "not_enough_evidence"
    return normalized


def _agentic_evidence_refs(findings: list[dict[str, Any]]) -> list[str]:
    refs: list[str] = []
    for finding in findings:
        for ref in _agentic_evidence_ref_values(finding.get("evidence_refs")):
            extracted = _agentic_extract_evidence_ref(ref)
            if extracted and extracted not in refs:
                refs.append(extracted)
    return refs


def _agentic_base_evidence_ref(ref: str) -> str:
    match = re.match(r"^(file:[^:]+):(?:\d+|L\d+(?:-L\d+)?)$", ref)
    return match.group(1) if match else ref


def _agentic_evidence_ref_matches_allowed(ref: str, allowed_refs: set[str]) -> bool:
    return ref in allowed_refs or _agentic_base_evidence_ref(ref) in allowed_refs


def _agentic_evidence_refs_overlap(left_refs: set[str], right_refs: set[str]) -> bool:
    return any(
        _agentic_evidence_ref_matches_allowed(left_ref, right_refs)
        or _agentic_evidence_ref_matches_allowed(right_ref, left_refs)
        for left_ref in left_refs
        for right_ref in right_refs
    )


def _agentic_apply_finding_defaults(
    findings: list[dict[str, Any]],
    *,
    provider_severity: str,
) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    severity = (
        provider_severity
        if provider_severity in {"low", "medium", "high", "critical"}
        else "medium"
    )
    for finding in findings:
        item = dict(finding)
        refs = [
            ref
            for ref in (
                _agentic_extract_evidence_ref(raw)
                for raw in _agentic_evidence_ref_values(item.get("evidence_refs"))
            )
            if ref
        ]
        item["evidence_refs"] = refs
        if not item.get("id"):
            item["id"] = _agentic_safe_finding_identifier(
                "|".join(refs) or json.dumps(item, sort_keys=True),
                prefix="provider-finding",
            )
        if not item.get("review_axis"):
            item["review_axis"] = "review_evidence_quality"
        if not item.get("severity"):
            item["severity"] = severity
        normalized.append(item)
    return normalized


def _agentic_ensure_semantic_findings(
    findings: list[dict[str, Any]],
    semantic_review: list[dict[str, Any]],
    *,
    provider_severity: str,
) -> list[dict[str, Any]]:
    normalized = [dict(finding) for finding in findings]
    severity = (
        provider_severity
        if provider_severity in {"medium", "high", "critical"}
        else "medium"
    )
    for item in semantic_review:
        if str(item.get("status") or "") != "suspicious":
            continue
        dimension = str(item.get("dimension") or "")
        axis = _AGENTIC_SEMANTIC_DIMENSION_AXES.get(dimension)
        refs = {
            ref for ref in list(item.get("evidence_refs") or []) if isinstance(ref, str)
        }
        if not axis or not refs:
            continue
        if any(
            str(finding.get("review_axis") or "") == axis
            and _agentic_evidence_refs_overlap(
                refs,
                {
                    ref
                    for ref in list(finding.get("evidence_refs") or [])
                    if isinstance(ref, str)
                },
            )
            for finding in normalized
        ):
            continue
        normalized.append(
            {
                "id": f"provider-semantic-{dimension}",
                "rule_id": f"provider-semantic-{dimension}",
                "category": "provider_semantic_dimension_suspicious",
                "review_axis": axis,
                "severity": severity,
                "confidence": item.get("confidence", 0.8),
                "evidence_refs": sorted(refs),
            }
        )
    return normalized


def _sanitize_agentic_semantic_dimension_review(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        raw_items = []
        for raw_dimension, raw_status in value.items():
            if isinstance(raw_status, dict):
                item = dict(raw_status)
                item.setdefault("dimension", raw_dimension)
            else:
                item = {"dimension": raw_dimension, "status": raw_status}
            raw_items.append(item)
    else:
        raw_items = value if isinstance(value, list) else []
    sanitized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_item in list(raw_items)[:24]:
        if not isinstance(raw_item, dict):
            continue
        dimension = str(raw_item.get("dimension") or "").strip().lower()
        status = _normalize_agentic_semantic_status(raw_item.get("status"))
        if dimension not in _AGENTIC_SEMANTIC_DIMENSIONS or dimension in seen:
            continue
        if status not in _AGENTIC_SEMANTIC_STATUSES:
            continue
        refs: list[str] = []
        for raw_ref in _agentic_evidence_ref_values(raw_item.get("evidence_refs")):
            ref = _agentic_extract_evidence_ref(raw_ref)
            if not ref or any(
                token in ref.lower() for token in _AGENTIC_FORBIDDEN_FINDING_TOKENS
            ):
                continue
            refs.append(ref)
        refs = refs[:8]
        rationale = _agentic_redact_semantic_prompt_text(
            str(raw_item.get("rationale") or ""),
            max_chars=360,
        )
        sanitized.append(
            {
                "dimension": dimension,
                "status": status,
                "evidence_refs": refs,
                "rationale": rationale,
                "confidence": _normalize_provider_confidence(
                    raw_item.get("confidence")
                ),
            }
        )
        seen.add(dimension)
    return sanitized


def _agentic_string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _agentic_semantic_review_from_minimal_dimensions(
    payload: dict[str, Any],
) -> list[dict[str, Any]]:
    refs = [
        ref
        for ref in (
            _agentic_extract_evidence_ref(raw_ref)
            for raw_ref in _agentic_evidence_ref_values(payload.get("evidence_refs"))
        )
        if ref
    ][:8]
    review: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_dimension in _agentic_string_list(payload.get("risk_dimensions")):
        dimension = raw_dimension.strip().lower().replace("-", "_").replace(" ", "_")
        if dimension not in _AGENTIC_SEMANTIC_DIMENSIONS or dimension in seen:
            continue
        review.append(
            {
                "dimension": dimension,
                "status": "suspicious",
                "evidence_refs": refs,
                "rationale": "Minimal final marked this risk dimension suspicious.",
                "confidence": _normalize_provider_confidence(payload.get("confidence")),
            }
        )
        seen.add(dimension)
    for raw_dimension in _agentic_string_list(
        payload.get("not_enough_evidence_dimensions")
    ):
        dimension = raw_dimension.strip().lower().replace("-", "_").replace(" ", "_")
        if dimension not in _AGENTIC_SEMANTIC_DIMENSIONS or dimension in seen:
            continue
        review.append(
            {
                "dimension": dimension,
                "status": "not_enough_evidence",
                "evidence_refs": refs,
                "rationale": "Minimal final marked this dimension as unresolved.",
                "confidence": _normalize_provider_confidence(payload.get("confidence")),
            }
        )
        seen.add(dimension)
    return review


def _agentic_semantic_review_refs(
    semantic_review: list[dict[str, Any]],
) -> set[str]:
    refs: set[str] = set()
    for item in semantic_review:
        for ref in list(item.get("evidence_refs") or []):
            if isinstance(ref, str):
                refs.add(ref)
                refs.add(_agentic_base_evidence_ref(ref))
    return refs


def _agentic_default_semantic_ref(read_paths: set[str]) -> str | None:
    if "SKILL.md" in read_paths:
        return "file:SKILL.md"
    visible = sorted(path for path in read_paths if path and not path.startswith("<"))
    return f"file:{visible[0]}" if len(visible) == 1 else None


def _agentic_fill_non_suspicious_semantic_refs(
    semantic_review: list[dict[str, Any]],
    *,
    read_paths: set[str],
) -> list[dict[str, Any]]:
    default_ref = _agentic_default_semantic_ref(read_paths)
    if not default_ref:
        return semantic_review
    filled: list[dict[str, Any]] = []
    for item in semantic_review:
        copied = dict(item)
        if str(copied.get("status") or "") != "suspicious" and not copied.get(
            "evidence_refs"
        ):
            copied["evidence_refs"] = [default_ref]
        filled.append(copied)
    return filled


def _agentic_fill_suspicious_semantic_refs(
    semantic_review: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    *,
    read_paths: set[str],
) -> list[dict[str, Any]]:
    default_ref = _agentic_default_semantic_ref(read_paths)
    filled: list[dict[str, Any]] = []
    for item in semantic_review:
        copied = dict(item)
        if str(copied.get("status") or "") != "suspicious" or copied.get(
            "evidence_refs"
        ):
            filled.append(copied)
            continue
        dimension = str(copied.get("dimension") or "")
        axis = _AGENTIC_SEMANTIC_DIMENSION_AXES.get(dimension)
        refs: list[str] = []
        if axis:
            for finding in findings:
                if str(finding.get("review_axis") or "") != axis:
                    continue
                for ref in list(finding.get("evidence_refs") or []):
                    if isinstance(ref, str):
                        safe_ref = _agentic_safe_evidence_ref(ref)
                        if safe_ref not in refs:
                            refs.append(safe_ref)
        if not refs and default_ref:
            refs = [default_ref]
        copied["evidence_refs"] = refs[:8]
        filled.append(copied)
    return filled


def _agentic_semantic_evidence_content_fallback_ref(
    ref: str,
    *,
    read_paths: set[str],
    semantic_evidence: Sequence[dict[str, Any]] | None,
) -> str | None:
    text = str(ref or "").strip()
    lowered = text.lower()
    if not lowered.startswith("semantic_evidence"):
        return None
    allowed_refs = _agentic_allowed_semantic_refs(
        read_paths=read_paths,
        deterministic_findings=[],
    )
    index_match = re.match(
        r"^semantic_evidence(?:\.items)?\[(\d+)\]\.(?:content|path|evidence_ref)(?::.*)?$",
        lowered,
    )
    if index_match and semantic_evidence is not None:
        index = int(index_match.group(1))
        if 0 <= index < len(semantic_evidence):
            candidate = _agentic_safe_evidence_ref(
                str(semantic_evidence[index].get("evidence_ref") or "")
            )
            if candidate and _agentic_evidence_ref_matches_allowed(
                candidate, allowed_refs
            ):
                return candidate
    default_ref = _agentic_default_semantic_ref(read_paths)
    if default_ref and _agentic_evidence_ref_matches_allowed(default_ref, allowed_refs):
        return default_ref
    return None


def _agentic_rewrite_refs_to_read_evidence(
    refs: Sequence[Any],
    *,
    read_paths: set[str],
    semantic_evidence: Sequence[dict[str, Any]] | None,
) -> list[str]:
    allowed_refs = _agentic_allowed_semantic_refs(
        read_paths=read_paths,
        deterministic_findings=[],
    )
    rewritten: list[str] = []
    for raw_ref in refs:
        safe_ref = _agentic_extract_evidence_ref(raw_ref)
        if not safe_ref:
            continue
        if allowed_refs and _agentic_evidence_ref_matches_allowed(
            safe_ref, allowed_refs
        ):
            candidate = safe_ref
        else:
            candidate = (
                _agentic_semantic_evidence_content_fallback_ref(
                    str(raw_ref),
                    read_paths=read_paths,
                    semantic_evidence=semantic_evidence,
                )
                or safe_ref
            )
        if candidate and candidate not in rewritten:
            rewritten.append(candidate)
    return rewritten[:8]


def _agentic_rewrite_finding_refs_to_read_evidence(
    findings: list[dict[str, Any]],
    *,
    read_paths: set[str],
    semantic_evidence: Sequence[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    rewritten: list[dict[str, Any]] = []
    for finding in findings:
        copied = dict(finding)
        copied["evidence_refs"] = _agentic_rewrite_refs_to_read_evidence(
            list(copied.get("evidence_refs") or []),
            read_paths=read_paths,
            semantic_evidence=semantic_evidence,
        )
        rewritten.append(copied)
    return rewritten


def _agentic_rewrite_semantic_refs_to_read_evidence(
    semantic_review: list[dict[str, Any]],
    *,
    read_paths: set[str],
    semantic_evidence: Sequence[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    rewritten: list[dict[str, Any]] = []
    for item in semantic_review:
        copied = dict(item)
        copied["evidence_refs"] = _agentic_rewrite_refs_to_read_evidence(
            list(copied.get("evidence_refs") or []),
            read_paths=read_paths,
            semantic_evidence=semantic_evidence,
        )
        rewritten.append(copied)
    return rewritten


def _agentic_fill_compact_semantic_dimensions(
    semantic_review: list[dict[str, Any]],
    *,
    read_paths: set[str],
) -> list[dict[str, Any]]:
    if not semantic_review:
        return semantic_review
    default_ref = _agentic_default_semantic_ref(read_paths)
    existing = {str(item.get("dimension") or "") for item in semantic_review}
    filled = list(semantic_review)
    for dimension in _AGENTIC_SEMANTIC_DIMENSIONS:
        if dimension in existing:
            continue
        filled.append(
            {
                "dimension": dimension,
                "status": "clean",
                "evidence_refs": [default_ref] if default_ref else [],
                "rationale": (
                    "No suspicious evidence was reported for this dimension in the "
                    "compact final result."
                ),
                "confidence": 0.8,
            }
        )
    return filled


def _agentic_semantic_review_from_findings(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    semantic_review: list[dict[str, Any]] = []
    seen: set[str] = set()
    for finding in findings:
        axis = str(finding.get("review_axis") or "")
        refs = [
            ref
            for ref in list(finding.get("evidence_refs") or [])
            if isinstance(ref, str)
        ]
        for dimension, dimension_axis in _AGENTIC_SEMANTIC_DIMENSION_AXES.items():
            if dimension_axis != axis or dimension in seen:
                continue
            semantic_review.append(
                {
                    "dimension": dimension,
                    "status": "suspicious",
                    "evidence_refs": refs,
                    "rationale": (
                        "Provider compact final reported a finding on this review axis."
                    ),
                    "confidence": _normalize_provider_confidence(
                        finding.get("confidence")
                    ),
                }
            )
            seen.add(dimension)
    return semantic_review


def _agentic_finding_refs(findings: list[dict[str, Any]]) -> set[str]:
    refs: set[str] = set()
    for finding in findings:
        for ref in list(finding.get("evidence_refs") or []):
            if isinstance(ref, str):
                refs.add(ref)
                refs.add(_agentic_base_evidence_ref(ref))
    return refs


def _agentic_allowed_semantic_refs(
    *,
    read_paths: set[str],
    deterministic_findings: list[dict[str, Any]],
) -> set[str]:
    _ = deterministic_findings
    return {f"file:{path}" for path in read_paths if path and not path.startswith("<")}


def _agentic_semantic_review_errors(
    *,
    semantic_review: list[dict[str, Any]],
    read_paths: set[str],
    deterministic_findings: list[dict[str, Any]],
    final_findings: list[dict[str, Any]],
    provider_verdict: str,
) -> list[str]:
    errors: list[str] = []
    dimensions = [str(item.get("dimension") or "") for item in semantic_review]
    required_dimensions = set(_AGENTIC_SEMANTIC_DIMENSIONS)
    if set(dimensions) != required_dimensions or len(dimensions) != len(
        required_dimensions
    ):
        missing = sorted(required_dimensions - set(dimensions))
        extra = sorted(set(dimensions) - required_dimensions)
        errors.append(
            "semantic_dimension_review must include exactly the required dimensions"
            f"; missing={missing}; extra={extra}"
        )
    allowed_refs = _agentic_allowed_semantic_refs(
        read_paths=read_paths,
        deterministic_findings=deterministic_findings,
    )
    for item in semantic_review:
        dimension = str(item.get("dimension") or "")
        status = str(item.get("status") or "")
        rationale = str(item.get("rationale") or "")
        if dimension not in required_dimensions:
            errors.append(f"invalid semantic dimension: {dimension}")
            continue
        if status not in _AGENTIC_SEMANTIC_STATUSES:
            errors.append(f"invalid semantic status for {dimension}: {status}")
        item_refs = {
            ref for ref in list(item.get("evidence_refs") or []) if isinstance(ref, str)
        }
        if not item_refs:
            errors.append(f"{dimension} semantic review must cite read evidence")
        if re.search(
            r"\b(?:local summary|local-summary|summary counts|"
            r"coverage satisfied|coverage-only)\b",
            rationale,
            flags=re.I,
        ):
            errors.append(
                f"{dimension} rationale relies on local-summary counts or coverage satisfaction"
            )
        for ref in item_refs:
            if ref.startswith("file:<") or ref.startswith("<"):
                errors.append(f"{dimension} uses unsafe evidence ref")
            if not allowed_refs:
                errors.append(f"{dimension} has no read evidence available")
            elif not _agentic_evidence_ref_matches_allowed(ref, allowed_refs):
                errors.append(
                    f"{dimension} uses unread or unsupported evidence ref: {ref}"
                )
    review_refs = _agentic_semantic_review_refs(semantic_review)
    low_risk_final = provider_verdict in {"consistent", "insufficient_evidence"}
    if low_risk_final:
        entry_refs = (
            {"file:SKILL.md"}
            if "SKILL.md" in read_paths
            else {f"file:{path}" for path in sorted(read_paths)[:1]}
        )
        if entry_refs and not any(
            _agentic_evidence_ref_matches_allowed(ref, review_refs)
            for ref in entry_refs
        ):
            errors.append(
                "low-risk final must cite SKILL.md or the entry file in semantic_dimension_review"
            )
    suspicious_items = [
        item
        for item in semantic_review
        if str(item.get("status") or "") == "suspicious"
    ]
    not_enough_items = [
        item
        for item in semantic_review
        if str(item.get("status") or "") == "not_enough_evidence"
    ]
    if provider_verdict == "insufficient_evidence" and not not_enough_items:
        errors.append(
            "insufficient_evidence requires at least one not_enough_evidence "
            "semantic dimension explaining the unresolved evidence gap"
        )
    if provider_verdict == "consistent" and not_enough_items:
        errors.append(
            "consistent final cannot contain not_enough_evidence semantic dimensions"
        )
    risk_final = provider_verdict in {"suspicious", "inconsistent"}
    if risk_final:
        if not suspicious_items:
            errors.append(
                "risk final requires at least one suspicious semantic dimension"
            )
        if not final_findings:
            errors.append("risk final requires at least one finding")
    if suspicious_items:
        if not final_findings:
            errors.append(
                "suspicious semantic dimensions require corresponding findings"
            )
        for item in suspicious_items:
            dimension = str(item.get("dimension") or "")
            axis = _AGENTIC_SEMANTIC_DIMENSION_AXES.get(dimension)
            item_refs = {
                ref
                for ref in list(item.get("evidence_refs") or [])
                if isinstance(ref, str)
            }
            axis_findings = [
                finding
                for finding in final_findings
                if axis and str(finding.get("review_axis") or "") == axis
            ]
            if axis and not axis_findings:
                errors.append(
                    f"{dimension} suspicious status requires a finding on {axis}"
                )
                continue
            if not item_refs:
                errors.append(
                    f"{dimension} suspicious status requires semantic evidence refs"
                )
                continue
            if not any(
                _agentic_evidence_refs_overlap(
                    item_refs,
                    {
                        ref
                        for ref in list(finding.get("evidence_refs") or [])
                        if isinstance(ref, str)
                    },
                )
                for finding in axis_findings
            ):
                errors.append(
                    f"{dimension} suspicious evidence is not represented in findings"
                )
    return errors


def _sanitize_agentic_strict_role_result(result: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "role",
        "verdict",
        "severity",
        "confidence",
        "findings",
        "semantic_dimension_review",
        "degraded",
    }
    return {key: result[key] for key in allowed if key in result}


def _parse_agentic_provider_role_result(raw: str) -> dict[str, Any]:
    payload = json.loads(_extract_provider_json(raw))
    if not isinstance(payload, dict):
        raise FSPRProviderSchemaError("provider_invalid_schema")
    forbidden = {
        "recommended_action",
        "recommended_policy_action",
        "recommended_review_tier",
    }
    if any(field in payload for field in forbidden):
        raise FSPRProviderSchemaError("provider_invalid_schema")
    result = dict(payload)
    result.setdefault("role", "agentic_readonly")
    result["verdict"] = _normalize_provider_verdict(result)
    result["severity"] = _normalize_provider_severity(result)
    result["confidence"] = _normalize_provider_confidence(result.get("confidence"))
    result["findings"] = _normalize_provider_findings(result.get("findings"))
    result["semantic_dimension_review"] = _sanitize_agentic_semantic_dimension_review(
        result.get("semantic_dimension_review")
    )
    minimal_review = _agentic_semantic_review_from_minimal_dimensions(result)
    if minimal_review:
        by_dimension = {
            str(item.get("dimension") or ""): item
            for item in result["semantic_dimension_review"]
        }
        for item in minimal_review:
            by_dimension[str(item.get("dimension") or "")] = item
        result["semantic_dimension_review"] = [
            by_dimension[dimension]
            for dimension in _AGENTIC_SEMANTIC_DIMENSIONS
            if dimension in by_dimension
        ]
    elif not result["semantic_dimension_review"]:
        result["semantic_dimension_review"] = minimal_review
    result.setdefault("degraded", False)
    return result


_AGENTIC_PROSE_RISK_MARKERS = (
    "suspicious",
    "red flag",
    "problematic",
    "violation",
    "compromised",
    "exfiltrat",
    "hidden channel",
    "hidden json",
    "hidden credential",
    "credential handoff",
    "carries credentials",
    "out of the requested result boundary",
    "bypasses",
    "goes beyond documentation",
    "trying to influence",
    "clear context pollution",
    "warrants a suspicious verdict",
    "verdict should be suspicious",
)

_AGENTIC_PROSE_CLEAN_MARKERS = (
    "clean",
    "no evidence",
    "not suspicious",
    "not injection",
    "not necessarily",
    "no hidden",
    "no credentials",
    "no undeclared",
    "no untrusted",
    "no extra",
    "no hiding",
    "no ready-to-use",
    "no stale",
    "no discrepancies",
    "no suspicious",
    "doesn't appear",
    "does not appear",
    "normal declared",
    "legitimate",
    "standard documentation",
    "declared workflow",
    "declared outputs",
    "expected behavior",
    "expected outputs",
    "purpose aligns",
    "aligns with",
)


def _agentic_clean_semantic_review(*, confidence: float = 0.65) -> list[dict[str, Any]]:
    return [
        {
            "dimension": dimension,
            "status": "clean",
            "evidence_refs": [],
            "rationale": "Strict final response reported no suspicious evidence.",
            "confidence": confidence,
        }
        for dimension in _AGENTIC_SEMANTIC_DIMENSIONS
    ]


def _agentic_prose_has_suspicious_verdict(lowered: str) -> bool:
    return bool(
        re.search(
            r"\b(?:verdict|finding|instruction|behavior)\b[^.\n]{0,80}"
            r"\b(?:suspicious|problematic|violation|red flag)\b",
            lowered,
        )
        or re.search(
            r"\b(?:warrants?|should be|is)\b[^.\n]{0,40}"
            r"\bsuspicious\b[^.\n]{0,30}\bverdict\b",
            lowered,
        )
    )


def _agentic_prose_section_is_clean(section: str) -> bool:
    return any(marker in section for marker in _AGENTIC_PROSE_CLEAN_MARKERS)


def _agentic_prose_section_is_suspicious(section: str) -> bool:
    if _agentic_prose_section_is_clean(section):
        return False
    return any(marker in section for marker in _AGENTIC_PROSE_RISK_MARKERS)


def _agentic_prose_has_clean_conclusion(lowered: str) -> bool:
    return bool(
        "no risk dimensions" in lowered
        or "no suspicious" in lowered
        or "no hidden malicious" in lowered
        or "package is clean" in lowered
        or "verdict should be clean" in lowered
        or "straightforward" in lowered
        or "declared purpose aligns" in lowered
    )


def _agentic_strict_final_prose_role_result(raw: str) -> dict[str, Any] | None:
    text = raw.replace("\x00", " ").strip()
    if not text or "{" in text or "```" in text:
        return None
    return {
        "role": "agentic_readonly",
        "verdict": "insufficient_evidence",
        "severity": "low",
        "confidence": 0.0,
        "findings": [],
        "semantic_dimension_review": [
            {
                "dimension": "description_mismatch",
                "status": "not_enough_evidence",
                "evidence_refs": [],
                "rationale": "Strict final response was prose-only, not final JSON.",
                "confidence": 0.0,
            }
        ],
        "degraded": False,
        "agentic_parse_status": "prose_only_incomplete_final",
    }


def _agentic_decode_prefix_json_field(text: str, key: str) -> Any:
    match = re.search(rf'"{re.escape(key)}"\s*:', text)
    if not match:
        return None
    decoder = json.JSONDecoder()
    try:
        value, _end = decoder.raw_decode(text[match.end() :].lstrip())
    except json.JSONDecodeError:
        return None
    return value


def _agentic_strict_final_prefix_role_result(raw: str) -> dict[str, Any] | None:
    text = str(raw or "")
    start = text.find("{")
    if start < 0:
        return None
    candidate = text[start:]
    payload: dict[str, Any] = {}
    for key in (
        "role",
        "verdict",
        "severity",
        "confidence",
        "risk_dimensions",
        "evidence_refs",
        "not_enough_evidence_dimensions",
        "degraded",
    ):
        value = _agentic_decode_prefix_json_field(candidate, key)
        if value is not None:
            payload[key] = value
    required = {
        "role",
        "verdict",
        "severity",
        "confidence",
        "risk_dimensions",
        "degraded",
    }
    if not required.issubset(payload):
        return None
    risk_dimensions = _agentic_string_list(payload.get("risk_dimensions"))
    if risk_dimensions and not _agentic_string_list(payload.get("evidence_refs")):
        return None
    payload.setdefault("findings", [])
    payload.setdefault("semantic_dimension_review", [])
    return _parse_agentic_provider_role_result(
        json.dumps(payload, ensure_ascii=True, sort_keys=True)
    )


def _agentic_validate_semantic_role_result(
    role_result: dict[str, Any],
    *,
    read_paths: set[str],
    deterministic_findings: list[dict[str, Any]],
    semantic_evidence: Sequence[dict[str, Any]] | None = None,
) -> None:
    semantic_review = _sanitize_agentic_semantic_dimension_review(
        role_result.get("semantic_dimension_review")
    )
    provider_severity = str(role_result.get("severity") or "low")
    findings = _agentic_apply_finding_defaults(
        _sanitize_agentic_findings(
            _normalize_provider_findings(role_result.get("findings"))
        ),
        provider_severity=provider_severity,
    )
    findings = _agentic_rewrite_finding_refs_to_read_evidence(
        findings,
        read_paths=read_paths,
        semantic_evidence=semantic_evidence,
    )
    if not semantic_review and findings:
        semantic_review = _agentic_semantic_review_from_findings(findings)
    if (
        not semantic_review
        and not findings
        and str(role_result.get("verdict") or "") == "consistent"
    ):
        semantic_review = _agentic_clean_semantic_review(
            confidence=_normalize_provider_confidence(role_result.get("confidence"))
        )
    semantic_review = _agentic_fill_compact_semantic_dimensions(
        semantic_review,
        read_paths=read_paths,
    )
    semantic_review = _agentic_rewrite_semantic_refs_to_read_evidence(
        semantic_review,
        read_paths=read_paths,
        semantic_evidence=semantic_evidence,
    )
    semantic_review = _agentic_fill_suspicious_semantic_refs(
        semantic_review,
        findings,
        read_paths=read_paths,
    )
    semantic_review = _agentic_fill_non_suspicious_semantic_refs(
        semantic_review,
        read_paths=read_paths,
    )
    findings = _agentic_ensure_semantic_findings(
        findings,
        semantic_review,
        provider_severity=provider_severity,
    )
    semantic_dimensions = {str(item.get("dimension") or "") for item in semantic_review}
    semantic_statuses = {str(item.get("status") or "") for item in semantic_review}
    if "suspicious" in semantic_statuses:
        if str(role_result.get("verdict") or "") in {
            "consistent",
            "insufficient_evidence",
        }:
            role_result["verdict"] = "suspicious"
        if str(role_result.get("severity") or "low") == "low":
            role_result["severity"] = "medium"
        provider_severity = str(role_result.get("severity") or provider_severity)
        findings = _agentic_ensure_semantic_findings(
            findings,
            semantic_review,
            provider_severity=provider_severity,
        )
    if (
        str(role_result.get("verdict") or "") == "insufficient_evidence"
        and not findings
        and semantic_dimensions == set(_AGENTIC_SEMANTIC_DIMENSIONS)
        and "not_enough_evidence" not in semantic_statuses
    ):
        role_result["verdict"] = "consistent"
        role_result["severity"] = "low"
    role_result["semantic_dimension_review"] = semantic_review
    role_result["findings"] = findings
    errors = _agentic_semantic_review_errors(
        semantic_review=semantic_review,
        read_paths=read_paths,
        deterministic_findings=deterministic_findings,
        final_findings=findings,
        provider_verdict=str(role_result.get("verdict") or "insufficient_evidence"),
    )
    if errors:
        raise FSPRAgenticSemanticReviewError(errors)


def _parse_agentic_strict_final_role_result(raw: str) -> dict[str, Any]:
    required = {
        "role",
        "verdict",
        "severity",
        "confidence",
        "findings",
        "degraded",
    }
    saw_json_object = False
    selected: str | None = None
    for candidate in _iter_provider_json_objects(raw):
        payload = json.loads(candidate)
        if not isinstance(payload, dict):
            continue
        saw_json_object = True
        minimal_required = {
            "role",
            "verdict",
            "severity",
            "confidence",
            "degraded",
        }
        if (
            (required.issubset(payload) or minimal_required.issubset(payload))
            and "tool_call" not in payload
            and "done" not in payload
        ):
            selected = candidate
    if selected is not None:
        return _sanitize_agentic_strict_role_result(
            _parse_agentic_provider_role_result(selected)
        )
    prefix_result = _agentic_strict_final_prefix_role_result(raw)
    if prefix_result is not None:
        return _sanitize_agentic_strict_role_result(prefix_result)
    if saw_json_object:
        raise FSPRProviderSchemaError("provider_invalid_schema")
    prose_result = _agentic_strict_final_prose_role_result(raw)
    if prose_result is not None:
        return _sanitize_agentic_strict_role_result(prose_result)
    payload = json.loads(_extract_provider_json(raw))
    if not isinstance(payload, dict):
        raise FSPRProviderSchemaError("provider_invalid_schema")
    raise FSPRProviderSchemaError("provider_invalid_schema")


def _agentic_parse_diagnostic(raw: str) -> dict[str, Any]:
    payload = _agentic_json_payload(raw)
    has_tool_call = bool(payload and isinstance(payload.get("tool_call"), dict))
    if payload is None:
        error_type = (
            "provider_invalid_json"
            if "{" in raw or "```" in raw
            else "provider_refusal_or_prose_only"
        )
    elif has_tool_call:
        error_type = "provider_tool_call_invalid"
    else:
        error_type = "provider_invalid_schema"
    return {
        "response_hash": _sha256(raw.encode("utf-8", errors="replace")),
        "response_chars": len(raw),
        "has_markdown_fence": "```" in raw,
        "has_tool_call": has_tool_call,
        "error_type": error_type,
    }


def _agentic_degradation_reason_for_diagnostic(diagnostic: dict[str, Any]) -> str:
    error_type = str(diagnostic.get("error_type") or "")
    if error_type == "provider_tool_call_invalid":
        return "provider_tool_call_invalid"
    if error_type == "provider_invalid_schema":
        return "provider_invalid_schema"
    return "provider_invalid_json"
