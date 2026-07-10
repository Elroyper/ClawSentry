"""Request-side trust metadata normalization and redaction helpers."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from clawsentry.gateway.models import (
    CanonicalEvent,
    DecisionContext,
    LineageEvent,
    McpContext,
    SkillRegistryRecord,
    SkillTrustContext,
)
from clawsentry.gateway.trust.skill_trust import (
    bind_runtime_skill_refs,
    derive_skill_trust_grade,
    resolve_skill_trust,
)

_SAFE_LINEAGE_KEYS = {
    "presented_skill_name",
    "skill_root_path_hash",
    "runtime_root_path_hash",
    "runtime_path_status",
    "runtime_binding_reason",
    "runtime_content_status",
    "workspace_relation",
    "metadata_record_id",
    "runtime_evidence_kind",
    "observed_name",
    "ref_ordinal",
    "current_runner_contract_id",
    "runtime_skill_ref_summaries",
    "skill_manifest_hash",
    "content_hash",
    "field_availability",
    "output_provenance_label",
    "parent_event_id",
    "native_tool_label",
    "tool_called",
    "skill_invocation_id",
    "metadata_source",
}

_BLOCKED_SKILL_LINEAGE_MATCH_KEYS = (
    "runtime_root_path_hash",
    "metadata_record_id",
    "content_hash",
    "skill_root_path_hash",
    "skill_manifest_hash",
    "observed_name",
    "presented_skill_name",
)


def _lineage_summary_from_event(event: dict[str, Any]) -> dict[str, Any] | None:
    """Extract redacted skill lineage metadata and remove unsafe raw fields."""

    payload = event.get("payload")
    if not isinstance(payload, dict):
        return None
    meta = payload.get("_clawsentry_meta")
    if not isinstance(meta, dict):
        return None
    raw = meta.get("skill_lineage_raw")
    if not isinstance(raw, dict):
        return None

    summary: dict[str, Any] = {}
    for key, value in raw.items():
        if key not in _SAFE_LINEAGE_KEYS or value is None:
            continue
        safe_value = _safe_lineage_value(key, value)
        if safe_value is not None:
            summary[key] = safe_value
    summary["redaction_policy_version"] = "cs.skill_lineage.redaction.v1"
    if len(summary) == 1:
        summary["redacted"] = True
    meta["skill_lineage_raw"] = dict(summary)
    return summary


def _lineage_event_from_summary(
    *,
    event: dict[str, Any],
    decision: dict[str, Any],
    context: DecisionContext | None,
    summary: dict[str, Any],
) -> dict[str, Any] | None:
    """Build the typed replay lineage event from redacted lineage metadata."""

    event_id = str(event.get("event_id") or "").strip()
    session_id = str(event.get("session_id") or "").strip()
    tool_name = str(
        summary.get("native_tool_label")
        or summary.get("tool_called")
        or event.get("tool_name")
        or ""
    ).strip()
    policy_version = str(decision.get("policy_version") or "").strip()
    if not event_id or not session_id or not tool_name or not policy_version:
        return None

    skill_trust = _lineage_skill_trust_from_summary(context, summary)
    ledger_decision = _lineage_decision_value(decision.get("decision"))
    observed_identity = (
        str(summary.get("observed_name") or getattr(skill_trust, "presented_name", None) or "").strip()
    )
    observed_identity_key = (
        "observed_name_hash:" + hashlib.sha256(observed_identity.lower().encode("utf-8")).hexdigest()
        if observed_identity
        else "observed_name_hash:unknown"
    )
    metadata_or_observed_key = (
        getattr(skill_trust, "metadata_record_id", None)
        or summary.get("metadata_record_id")
        or observed_identity_key
    )
    try:
        lineage = LineageEvent(
            event_id=event_id,
            session_id=session_id,
            canonical_skill_id=(
                skill_trust.canonical_skill_id
                if skill_trust is not None
                else None
            ),
            occurred_at=str(event.get("occurred_at")) if event.get("occurred_at") else None,
            ref_ordinal=(
                int(summary.get("ref_ordinal"))
                if isinstance(summary.get("ref_ordinal"), int)
                else getattr(skill_trust, "ref_ordinal", None) if skill_trust is not None else None
            ),
            dedupe_key=(
                f"{session_id}:{event_id}:"
                f"{summary.get('ref_ordinal') if isinstance(summary.get('ref_ordinal'), int) else 0}:"
                f"{metadata_or_observed_key}:"
                f"{summary.get('runtime_root_path_hash') or 'no-runtime-root'}:"
                f"{summary.get('runtime_evidence_kind') or getattr(skill_trust, 'runtime_evidence_kind', None) or 'unknown'}"
            ),
            tool_name=tool_name,
            observed_name=(
                str(summary.get("observed_name") or getattr(skill_trust, "presented_name", None) or "")
                or None
            ),
            runtime_path_status=(
                summary.get("runtime_path_status")
                or getattr(skill_trust, "runtime_path_status", None)
            ),
            runtime_root_path_hash=(
                str(summary.get("runtime_root_path_hash"))
                if summary.get("runtime_root_path_hash")
                else getattr(skill_trust, "runtime_root_path_hash", None)
            ),
            runtime_content_status=(
                summary.get("runtime_content_status")
                or getattr(skill_trust, "runtime_content_status", None)
            ),
            runtime_evidence_kind=(
                summary.get("runtime_evidence_kind")
                or getattr(skill_trust, "runtime_evidence_kind", None)
            ),
            current_runner_contract_id=(
                summary.get("current_runner_contract_id")
                or getattr(skill_trust, "current_runner_contract_id", None)
            ),
            metadata_record_id=(
                str(summary.get("metadata_record_id"))
                if summary.get("metadata_record_id")
                else getattr(skill_trust, "metadata_record_id", None)
            ),
            decision=ledger_decision,
            risk_level=str(decision.get("risk_level") or "unknown"),
            invariant_violations=(
                list(getattr(skill_trust, "invariant_violations", []) or [])
                if skill_trust is not None
                else []
            ),
            output_provenance_label=(
                str(summary.get("output_provenance_label") or summary.get("tool_called"))
                if summary.get("output_provenance_label") or summary.get("tool_called")
                else None
            ),
            parent_event_id=(
                str(summary.get("parent_event_id"))
                if summary.get("parent_event_id")
                else None
            ),
            content_hash=(
                str(summary.get("content_hash"))
                if summary.get("content_hash")
                else None
            ),
            policy_version=policy_version,
        )
    except Exception:
        return None
    return lineage.model_dump(mode="json")


def _lineage_skill_trust_from_summary(
    context: DecisionContext | None,
    summary: dict[str, Any],
) -> SkillTrustContext | None:
    if context is None:
        return None
    refs = list(context.skill_trust_refs or [])
    if refs:
        summary_ordinal = summary.get("ref_ordinal")
        summary_record_id = summary.get("metadata_record_id")
        for ref in refs:
            if isinstance(summary_ordinal, int) and ref.ref_ordinal == summary_ordinal:
                return ref
            if summary_record_id and ref.metadata_record_id == summary_record_id:
                return ref
    return context.skill_trust


def _lineage_decision_value(value: Any) -> str:
    normalized = str(value or "").strip().lower().replace("_", "-")
    if normalized in {"allow", "allow-once", "allow-always"}:
        return "allow"
    if normalized in {"block", "deny"}:
        return "block"
    if normalized == "defer":
        return "defer"
    if normalized == "error":
        return "error"
    return "unknown"


def _lineage_events_from_summary(
    *,
    event: dict[str, Any],
    decision: dict[str, Any],
    context: DecisionContext | None,
    summary: dict[str, Any],
) -> list[dict[str, Any]]:
    ref_summaries = summary.get("runtime_skill_ref_summaries")
    if not isinstance(ref_summaries, list) and context is not None and context.skill_trust_refs:
        ref_summaries = [
            {
                "observed_name": ref.presented_name,
                "ref_ordinal": ref.ref_ordinal,
                "runtime_path_status": ref.runtime_path_status,
                "runtime_root_path_hash": ref.runtime_root_path_hash,
                "runtime_content_status": ref.runtime_content_status,
                "metadata_record_id": ref.metadata_record_id,
                "runtime_evidence_kind": ref.runtime_evidence_kind,
            }
            for ref in context.skill_trust_refs
        ]
    if isinstance(ref_summaries, list) and ref_summaries:
        entries: list[dict[str, Any]] = []
        base_summary = {
            key: value for key, value in summary.items()
            if key != "runtime_skill_ref_summaries"
        }
        for ref_summary in ref_summaries:
            if not isinstance(ref_summary, dict):
                continue
            merged_summary = dict(base_summary)
            merged_summary.update(ref_summary)
            entry = _lineage_event_from_summary(
                event=event,
                decision=decision,
                context=context,
                summary=merged_summary,
            )
            if entry is not None:
                entries.append(entry)
        if entries:
            return entries
    entry = _lineage_event_from_summary(
        event=event,
        decision=decision,
        context=context,
        summary=summary,
    )
    return [entry] if entry is not None else []


def _blocked_skill_lineage_match_from_session(
    lineage_summary: dict[str, Any] | None,
    session_stats: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if not isinstance(lineage_summary, dict) or not isinstance(session_stats, dict):
        return None
    facts = session_stats.get("blocked_skill_lineage_facts")
    if not isinstance(facts, list):
        return None
    for fact in reversed(facts):
        if not isinstance(fact, dict):
            continue
        for key in _BLOCKED_SKILL_LINEAGE_MATCH_KEYS:
            current_value = lineage_summary.get(key)
            if current_value is None or fact.get(key) != current_value:
                continue
            return {
                "matched_key": key,
                "matched_value": current_value,
                "block_source": str(fact.get("block_source") or "session_blocked_skill_lineage"),
                "blocked_event_id": str(fact.get("event_id") or ""),
            }
    return None


def _context_with_blocked_skill_lineage_match(
    context: DecisionContext | None,
    match: dict[str, Any] | None,
) -> DecisionContext | None:
    if not match:
        return context
    summary = dict(context.session_risk_summary or {}) if context is not None else {}
    summary["blocked_skill_lineage_match"] = dict(match)
    if context is None:
        return DecisionContext(session_risk_summary=summary)
    return context.model_copy(update={"session_risk_summary": summary})


def _context_with_prior_fspr_hard_block(
    context: DecisionContext | None,
    session_stats: dict[str, Any] | None,
) -> DecisionContext | None:
    if not isinstance(session_stats, dict) or not session_stats.get("prior_fspr_hard_block"):
        return context
    summary = dict(context.session_risk_summary or {}) if context is not None else {}
    summary["prior_fspr_hard_block"] = True
    event_id = session_stats.get("prior_fspr_hard_block_event_id")
    if event_id:
        summary["prior_fspr_hard_block_event_id"] = str(event_id)
    if context is None:
        return DecisionContext(session_risk_summary=summary)
    return context.model_copy(update={"session_risk_summary": summary})


def _safe_lineage_value(key: str, value: Any) -> Any | None:
    if key in {"skill_root_path_hash", "runtime_root_path_hash", "skill_manifest_hash", "content_hash"}:
        if isinstance(value, str) and _is_sha256_digest(value):
            return value[:256]
        return None
    if key in {"runtime_path_status", "runtime_content_status", "runtime_evidence_kind", "workspace_relation"}:
        return _safe_identity_label(value, max_len=80)
    if key in {"runtime_binding_reason", "observed_name", "current_runner_contract_id"}:
        return _safe_identity_label(value, max_len=256)
    if key == "metadata_record_id":
        if isinstance(value, str) and value.startswith("sha256:"):
            return value[:256]
        return None
    if key == "ref_ordinal":
        return value if isinstance(value, int) and 0 <= value < 1000 else None
    if key == "runtime_skill_ref_summaries":
        if not isinstance(value, list):
            return None
        safe_items: list[dict[str, Any]] = []
        for item in value[:20]:
            if not isinstance(item, dict):
                continue
            safe_item: dict[str, Any] = {}
            for item_key, item_value in item.items():
                if item_key in _SAFE_LINEAGE_KEYS and item_key != "runtime_skill_ref_summaries":
                    safe_value = _safe_lineage_value(str(item_key), item_value)
                    if safe_value is not None:
                        safe_item[str(item_key)] = safe_value
            if safe_item:
                safe_items.append(safe_item)
        return safe_items
    if key == "field_availability":
        if not isinstance(value, dict):
            return None
        return {
            str(field): bool(available)
            for field, available in value.items()
            if isinstance(field, str)
            and isinstance(available, bool)
            and len(field) <= 80
        }
    if isinstance(value, str):
        return _redacted_target_preview(value, max_len=256)
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value
    return None


def _is_sha256_digest(value: str) -> bool:
    return re.fullmatch(r"sha256:[0-9a-fA-F]{64}", value.strip()) is not None


def _is_pathlike_label(value: str) -> bool:
    return (
        "/" in value
        or "\\" in value
        or value.startswith("~")
        or "://" in value
        or re.search(r"\b[A-Za-z]:\\", value) is not None
    )


def _safe_identity_label(value: Any, *, max_len: int = 256) -> str | None:
    if not isinstance(value, str):
        return None
    label = value.strip()
    if not label or len(label) > max_len or _is_pathlike_label(label):
        return None
    return label[:max_len]


def _safe_skill_trust_raw_value(key: str, value: Any) -> Any | None:
    if key in {
        "presented_name",
        "canonical_skill_id",
        "canonical_name",
        "provenance_claim",
        "tool_label",
    }:
        return _safe_identity_label(value)
    if key == "framework":
        framework = _safe_identity_label(value, max_len=64)
        if framework in {
            "a3s-code",
            "claude-code",
            "codex",
            "gemini-cli",
            "kimi-cli",
            "openclaw",
        }:
            return framework
        return None
    if key == "scope":
        scope = _safe_identity_label(value, max_len=64)
        if scope in {"benchmark", "global", "project", "user", "workspace"}:
            return scope
        return None
    if key == "skill_root_path_hash" and isinstance(value, str) and _is_sha256_digest(value):
        return value[:256]
    if key == "gateway_owned_metadata" and isinstance(value, bool):
        return value
    if key == "content_hashes" and isinstance(value, dict):
        safe_hashes: dict[str, str] = {}
        for name, digest in value.items():
            safe_name = _safe_identity_label(name, max_len=120)
            if safe_name and isinstance(digest, str):
                safe_hashes[safe_name] = digest[:256]
        return safe_hashes
    if key == "control_language_findings" and isinstance(value, list):
        return [str(item)[:120] for item in value[:20] if isinstance(item, str)]
    if key == "provenance_label_conflict" and isinstance(value, bool):
        return value
    if key == "skill_trust_grade":
        grade = _safe_identity_label(value, max_len=32)
        if grade in {"trusted", "review", "restricted", "blocked", "disabled"}:
            return grade
    return None


def _redact_skill_trust_raw_from_event(event: dict[str, Any]) -> dict[str, Any] | None:
    """Keep replay-safe skill trust metadata and drop raw registry/source payloads."""

    payload = event.get("payload")
    if not isinstance(payload, dict):
        return None
    meta = payload.get("_clawsentry_meta")
    if not isinstance(meta, dict):
        return None
    raw = meta.get("skill_trust_raw")
    if not isinstance(raw, dict):
        return None

    summary: dict[str, Any] = {}
    records_payload = raw.get("registry_records")
    if isinstance(records_payload, list):
        summary["registry_record_count"] = len(records_payload)
        record_summaries: list[dict[str, Any]] = []
        for item in records_payload[:20]:
            if not isinstance(item, dict):
                continue
            record_summary: dict[str, Any] = {}
            for key in ("canonical_skill_id", "canonical_name"):
                safe_value = _safe_identity_label(item.get(key))
                if safe_value is not None:
                    record_summary[key] = safe_value
            policy_fingerprint = item.get("policy_fingerprint")
            if isinstance(policy_fingerprint, str):
                record_summary["policy_fingerprint"] = policy_fingerprint[:256]
            record_summary.update({
                "trust_level": "local_unreviewed",
                "status": "local_unreviewed",
                "list_state": "unlisted",
                "runtime_claim_trusted": False,
            })
            aliases = item.get("aliases")
            if isinstance(aliases, list):
                safe_aliases = [
                    safe_alias
                    for alias in aliases[:20]
                    if (safe_alias := _safe_identity_label(alias, max_len=120)) is not None
                ]
                if safe_aliases:
                    record_summary["aliases"] = safe_aliases
            content_hashes = item.get("content_hashes")
            if isinstance(content_hashes, dict):
                safe_hash_keys = [
                    safe_name
                    for name in sorted(
                        key for key in content_hashes if isinstance(key, str)
                    )[:20]
                    if (safe_name := _safe_identity_label(name, max_len=120)) is not None
                ]
                if safe_hash_keys:
                    record_summary["content_hash_keys"] = safe_hash_keys
            if record_summary:
                record_summaries.append(record_summary)
        if record_summaries:
            summary["registry_records"] = record_summaries

    gateway_owned = raw.get("gateway_owned_metadata") is True
    for key, value in raw.items():
        if key in {"admission_scan_id", "admission_risk", "policy_fingerprint"}:
            if gateway_owned and isinstance(value, str):
                summary[str(key)] = value[:256]
            continue
        safe_value = _safe_skill_trust_raw_value(str(key), value)
        if safe_value is not None:
            summary[str(key)] = safe_value

    summary["redaction_policy_version"] = "cs.skill_trust_raw.redaction.v1"
    summary["redacted"] = True
    meta["skill_trust_raw"] = summary
    return summary


def _redacted_target_preview(value: Any, *, max_len: int = 96) -> str:
    text = str(value or "").replace("\n", " ").strip()
    if not text:
        return ""
    text = re.sub(r"/workspace/[^\s'\"<>|)]+", "/workspace/<redacted>", text)
    text = re.sub(r"/home/[^\s'\"<>|)]+", "/home/<redacted>", text)
    text = re.sub(r"~/?[^\s'\"<>|)]*", "~/<redacted>", text)
    text = re.sub(r"(?i)(token|password|secret|api_key)=([^\s&]+)", r"\1=<redacted>", text)
    if len(text) > max_len:
        text = text[: max_len - 1] + "…"
    return text


def _safe_mcp_raw_value(key: str, value: Any) -> Any | None:
    if key in {"server_name", "tool_name", "resource_kind", "resource_uri_hash", "trust_level", "status"} and isinstance(value, str):
        return value[:256]
    return None


def _redact_mcp_raw_from_event(event: dict[str, Any]) -> dict[str, Any] | None:
    """Keep replay-safe MCP metadata and drop raw resource URIs/payloads."""

    payload = event.get("payload")
    if not isinstance(payload, dict):
        return None
    meta = payload.get("_clawsentry_meta")
    if not isinstance(meta, dict):
        return None
    raw = meta.get("mcp_raw")
    if not isinstance(raw, dict):
        return None

    summary: dict[str, Any] = {}
    for key, value in raw.items():
        safe_value = _safe_mcp_raw_value(str(key), value)
        if safe_value is not None:
            summary[str(key)] = safe_value
    summary["redaction_policy_version"] = "cs.mcp_raw.redaction.v1"
    summary["redacted"] = True
    meta["mcp_raw"] = summary
    return summary


def _context_with_mcp_raw(
    context: DecisionContext | None,
    event: CanonicalEvent,
) -> DecisionContext | None:
    """Resolve raw MCP metadata from event meta into DecisionContext evidence."""

    payload = event.payload or {}
    meta = payload.get("_clawsentry_meta")
    if not isinstance(meta, dict):
        if context is not None and context.mcp_context is not None:
            return context.model_copy(update={"mcp_context": None})
        return context
    raw = meta.get("mcp_raw")
    if not isinstance(raw, dict):
        if context is not None and context.mcp_context is not None:
            return context.model_copy(update={"mcp_context": None})
        return context

    context_payload = {
        key: value
        for key, value in raw.items()
        if key in {"server_name", "tool_name", "resource_kind", "resource_uri_hash", "trust_level", "status"}
    }
    expected_server, expected_tool = _mcp_identity_from_event_tool(event.tool_name)
    if expected_server is not None:
        raw_server = str(context_payload.get("server_name") or "")
        raw_tool = str(context_payload.get("tool_name") or "")
        if raw_server != expected_server or raw_tool != expected_tool:
            if context is not None and context.mcp_context is not None:
                return context.model_copy(update={"mcp_context": None})
            return context
    try:
        mcp_context = McpContext.model_validate(context_payload)
    except Exception:
        return context
    if context is None:
        return DecisionContext(mcp_context=mcp_context)
    return context.model_copy(update={"mcp_context": mcp_context})


def _mcp_identity_from_event_tool(tool_name: str | None) -> tuple[str | None, str | None]:
    parts = str(tool_name or "").split("__")
    if len(parts) >= 3 and parts[0] == "mcp":
        return parts[1], "__".join(parts[2:])
    return None, None


def _downgrade_request_skill_trust(skill_trust: SkillTrustContext) -> SkillTrustContext:
    """Treat request context skill identity as untrusted adapter evidence."""

    presented_name = skill_trust.presented_name or skill_trust.canonical_skill_id
    violations = set(skill_trust.invariant_violations)
    violations.add("request_context_skill_trust_untrusted")
    return skill_trust.model_copy(update={
        "registry_status": "unknown" if presented_name else "unbound",
        "canonical_skill_id": None,
        "presented_name": presented_name,
        "admission_risk": "unknown",
        "trust_list_state": "unlisted",
        "invariant_violations": sorted(violations),
        "policy_fingerprint": "sha256:request-context-skill-trust-untrusted",
    })


def _context_with_skill_trust_raw(
    context: DecisionContext | None,
    event: CanonicalEvent,
    trusted_records: list[SkillRegistryRecord] | None = None,
    deadline_at: float | None = None,
    detection_config: Any | None = None,
    *,
    gateway_owned_skill_trust_bundle_fn: Any | None = None,
    gateway_observed_runtime_skill_refs_fn: Any | None = None,
    gateway_current_runner_contract_id_fn: Any | None = None,
    gateway_owned_skill_trust_metadata_fn: Any | None = None,
    apply_gateway_owned_first_use_scan_fn: Any | None = None,
    apply_gateway_owned_first_use_package_review_fn: Any | None = None,
) -> DecisionContext | None:
    """Resolve raw skill metadata from event meta into DecisionContext evidence."""

    if (
        gateway_owned_skill_trust_bundle_fn is None
        or gateway_observed_runtime_skill_refs_fn is None
        or gateway_current_runner_contract_id_fn is None
        or gateway_owned_skill_trust_metadata_fn is None
        or apply_gateway_owned_first_use_scan_fn is None
        or apply_gateway_owned_first_use_package_review_fn is None
    ):
        from . import fspr_bridge

        gateway_owned_skill_trust_bundle_fn = (
            gateway_owned_skill_trust_bundle_fn
            or fspr_bridge._gateway_owned_skill_trust_bundle
        )
        gateway_observed_runtime_skill_refs_fn = (
            gateway_observed_runtime_skill_refs_fn
            or fspr_bridge._gateway_observed_runtime_skill_refs
        )
        gateway_current_runner_contract_id_fn = (
            gateway_current_runner_contract_id_fn
            or fspr_bridge._gateway_current_runner_contract_id
        )
        gateway_owned_skill_trust_metadata_fn = (
            gateway_owned_skill_trust_metadata_fn
            or fspr_bridge._gateway_owned_skill_trust_metadata
        )
        apply_gateway_owned_first_use_scan_fn = (
            apply_gateway_owned_first_use_scan_fn
            or fspr_bridge._apply_gateway_owned_first_use_scan
        )
        apply_gateway_owned_first_use_package_review_fn = (
            apply_gateway_owned_first_use_package_review_fn
            or fspr_bridge._apply_gateway_owned_first_use_package_review
        )

    gateway_records = list(trusted_records or [])
    payload = event.payload or {}
    meta = payload.get("_clawsentry_meta")
    if not isinstance(meta, dict):
        if context is not None and context.skill_trust is not None:
            return context.model_copy(update={"skill_trust": _downgrade_request_skill_trust(context.skill_trust)})
        return context
    raw = meta.get("skill_trust_raw")
    if not isinstance(raw, dict):
        if context is not None and context.skill_trust is not None:
            return context.model_copy(update={"skill_trust": _downgrade_request_skill_trust(context.skill_trust)})
        return context
    runtime_records_added = isinstance(raw.get("registry_records"), list)
    raw_metadata = _sanitize_request_skill_trust_raw(raw)
    for key in (
        "gateway_owned_metadata",
        "admission_scan_id",
        "admission_risk",
        "policy_fingerprint",
        "skill_root_path",
    ):
        raw.pop(key, None)

    def _with_gateway_owned_fspr_evidence(
        bound_refs: list[SkillTrustContext],
    ) -> list[SkillTrustContext]:
        if not bound_refs:
            return bound_refs
        enriched_refs: list[SkillTrustContext] = []
        for index, ref in enumerate(bound_refs):
            owned_raw = gateway_owned_skill_trust_metadata_fn(
                ref.presented_name or raw_metadata.get("presented_name")
            )
            if not owned_raw:
                enriched_refs.append(ref)
                continue
            owned_metadata = dict(raw_metadata)
            owned_metadata.update(owned_raw)
            apply_gateway_owned_first_use_scan_fn(owned_metadata, deadline_at=deadline_at)
            apply_gateway_owned_first_use_package_review_fn(
                owned_metadata,
                event=event,
                detection_config=detection_config,
                deadline_at=deadline_at,
            )
            update = {
                key: owned_metadata[key]
                for key in (
                    "admission_scan_id",
                    "admission_risk",
                    "policy_fingerprint",
                    "content_hashes",
                    "admission_scan_requested",
                    "admission_scan_failure_class",
                    "first_use_package_review",
                    "fspr_review_summary",
                )
                if key in owned_metadata
            }
            if index == 0:
                raw.update(owned_raw)
                raw.update(update)
            resolved = resolve_skill_trust(list(gateway_records), owned_metadata)
            ref_update: dict[str, Any] = {
                "first_use_scan": resolved.first_use_scan,
                "first_use_package_review": resolved.first_use_package_review,
                "fspr_review_summary": resolved.fspr_review_summary,
            }
            if ref.runtime_path_status in {"verified_source", "verified_mirror", "verified_name"}:
                ref_update.update({
                    "admission_scan_id": resolved.admission_scan_id,
                    "admission_risk": resolved.admission_risk,
                    "trust_list_state": resolved.trust_list_state,
                    "invariant_violations": sorted({
                        *ref.invariant_violations,
                        *resolved.invariant_violations,
                    }),
                    "policy_fingerprint": resolved.policy_fingerprint or ref.policy_fingerprint,
                })
            enriched_refs.append(ref.model_copy(update=ref_update))
        return enriched_refs

    runtime_refs = gateway_observed_runtime_skill_refs_fn(meta, context, event)
    if runtime_refs:
        metadata_bundle = gateway_owned_skill_trust_bundle_fn()
        if metadata_bundle is not None:
            bound_refs = bind_runtime_skill_refs(
                metadata_bundle,
                runtime_refs,
                framework_contract_allows_name_only=True,
                current_runner_contract_id=gateway_current_runner_contract_id_fn(meta, context),
                mirror_hash_max_files=(
                    detection_config.skill_trust_mirror_hash_max_files
                    if detection_config is not None
                    else None
                ),
                mirror_hash_max_file_bytes=(
                    detection_config.skill_trust_mirror_hash_max_file_bytes
                    if detection_config is not None
                    else None
                ),
                mirror_hash_max_total_ms=(
                    detection_config.skill_trust_mirror_hash_max_total_ms
                    if detection_config is not None
                    else None
                ),
            )
            binding_decisive_statuses = {
                "verified_source",
                "verified_mirror",
                "verified_name",
                "disallowed",
                "ambiguous_runtime_source",
                "name_only_unverified",
                "path_fragment_unverified",
            }
            if bound_refs and any(
                ref.runtime_path_status in binding_decisive_statuses
                for ref in bound_refs
            ):
                bound_refs = _with_gateway_owned_fspr_evidence(bound_refs)
                primary = bound_refs[0]
                if context is None:
                    return DecisionContext(
                        skill_trust=primary,
                        skill_trust_refs=bound_refs,
                    )
                return context.model_copy(update={
                    "skill_trust": primary,
                    "skill_trust_refs": bound_refs,
                })
    owned_raw = gateway_owned_skill_trust_metadata_fn(raw_metadata.get("presented_name"))
    records: list[SkillRegistryRecord] = []
    if owned_raw:
        records = list(gateway_records)
        raw_metadata.update(owned_raw)
        apply_gateway_owned_first_use_scan_fn(raw_metadata, deadline_at=deadline_at)
        apply_gateway_owned_first_use_package_review_fn(
            raw_metadata,
            event=event,
            detection_config=detection_config,
            deadline_at=deadline_at,
        )
        raw.update(owned_raw)
        for key in (
            "admission_scan_id",
            "admission_risk",
            "policy_fingerprint",
            "content_hashes",
            "admission_scan_requested",
            "admission_scan_failure_class",
            "first_use_package_review",
        ):
            if key in raw_metadata:
                raw[key] = raw_metadata[key]
    elif raw_metadata.get("presented_name"):
        raw_metadata["_request_skill_trust_raw_untrusted"] = True
    if runtime_records_added:
        raw_metadata["_registry_records_untrusted"] = True
        if not gateway_records:
            raw_metadata = {
                "presented_name": raw_metadata.get("presented_name"),
                "_registry_records_untrusted": True,
            }
    skill_trust = resolve_skill_trust(records, raw_metadata)
    if runtime_records_added and "runtime_registry_claim_untrusted" in skill_trust.invariant_violations:
        skill_trust = skill_trust.model_copy(update={
            "canonical_skill_id": None,
            "registry_status": (
                "unknown"
                if skill_trust.registry_status == "matched"
                else skill_trust.registry_status
            ),
            "trust_list_state": "unlisted",
        })
    raw["skill_trust_grade"] = derive_skill_trust_grade(
        skill_trust.model_dump(mode="json")
    )
    if context is None:
        return DecisionContext(skill_trust=skill_trust)
    return context.model_copy(update={"skill_trust": skill_trust})


def _sanitize_request_skill_trust_raw(raw: dict[str, Any]) -> dict[str, Any]:
    """Keep request skill-trust fields observational, not decision-derived."""

    allowed = {
        "presented_name",
        "provenance_claim",
        "content_hashes",
        "admission_scan_requested",
        "admission_scan_budget_exhausted",
        "admission_scan_failure_class",
    }
    return {key: value for key, value in raw.items() if key in allowed}
