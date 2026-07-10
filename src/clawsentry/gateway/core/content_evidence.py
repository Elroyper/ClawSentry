"""Content-evidence helpers for gateway decision flow."""

from __future__ import annotations

import re
from typing import Any

from clawsentry.gateway.models import ContentEvidenceEnvelope, DecisionContext

_BROAD_CONTENT_EVIDENCE_ROOTS = frozenset({
    "/",
    "/app",
    "/home",
    "/root",
    "/tmp",
    "/usr",
    "/var",
    "/workspace",
})


def _content_evidence_approved_roots(
    context: DecisionContext | None,
    *,
    allow_confirmed_profile_roots: bool = False,
) -> list[str]:
    """Return trusted roots for request-local content evidence collection."""

    if context is None or context.session_scope_profile is None:
        return []
    session_summary = (
        context.session_risk_summary
        if isinstance(context.session_risk_summary, dict)
        else {}
    )
    has_gateway_default_marker = (
        session_summary.get("content_evidence_roots_source")
        == "gateway_default_session_scope"
    )
    if not has_gateway_default_marker and not allow_confirmed_profile_roots:
        return []
    roots: list[Any] = []
    if has_gateway_default_marker:
        task_rules = getattr(context.session_scope_profile, "task_rules", None)
        roots.extend(getattr(task_rules, "allowed_path_prefixes", []) or [])
    profile = context.session_scope_profile
    if getattr(profile, "confirmed", False) and not getattr(profile, "dry_run", True):
        for artifact_rule in getattr(profile, "task_artifacts", []) or []:
            if not _task_data_artifact_rule_can_feed_content_evidence(artifact_rule):
                continue
            roots.extend(getattr(artifact_rule, "paths", []) or [])
    return [
        str(root)
        for root in dict.fromkeys(roots)
        if str(root).strip() and str(root).strip() != "/"
    ]


def _task_data_artifact_rule_can_feed_content_evidence(artifact_rule: Any) -> bool:
    if getattr(artifact_rule, "artifact_role", None) != "task_data":
        return False
    if getattr(artifact_rule, "source_tier", None) != "risk_adjusting":
        return False
    if getattr(artifact_rule, "confidence", None) != "high":
        return False
    if not getattr(artifact_rule, "artifact_trust_confirmed", False):
        return False
    if getattr(artifact_rule, "match_type", None) == "glob":
        return False
    allowed_effects = set(getattr(artifact_rule, "allowed_effects", []) or [])
    if allowed_effects and not allowed_effects.intersection({"filesystem.read", "filesystem.enumerate"}):
        return False
    metadata = getattr(artifact_rule, "source_metadata", None)
    if isinstance(metadata, dict) and metadata.get("broad_root_suppressed") is True:
        return False
    return all(
        not _is_broad_content_evidence_root(path)
        for path in getattr(artifact_rule, "paths", []) or []
    )


def _is_broad_content_evidence_root(path: str) -> bool:
    normalized = "/" + str(path or "").strip().replace("\\", "/").strip("/")
    if normalized == "/.":
        normalized = "/"
    normalized = normalized.rstrip("/")
    if normalized in _BROAD_CONTENT_EVIDENCE_ROOTS:
        return True
    return re.fullmatch(
        r"/home/[^/]+/(?:build|workspace|work|project|projects)(?:/failed)?",
        normalized,
    ) is not None


def _content_evidence_rule_ids_from_envelope(
    envelope: ContentEvidenceEnvelope | None,
) -> set[str]:
    if envelope is None:
        return set()
    rule_ids: set[str] = set()
    for item in envelope.items:
        for rule in item.derived_rules:
            if isinstance(rule, dict) and rule.get("rule_id"):
                rule_ids.add(str(rule["rule_id"]))
    return rule_ids


def _content_evidence_metric_flags(
    envelope: ContentEvidenceEnvelope | None,
) -> dict[str, bool]:
    rule_ids = _content_evidence_rule_ids_from_envelope(envelope)
    return {
        "collected": envelope is not None,
        "incomplete": "content_evidence_incomplete" in rule_ids,
        "mismatch": "content_mismatch" in rule_ids,
        "execution_unverified": "execution_content_unverified" in rule_ids,
    }


def _snapshot_has_content_evidence_rule(snapshot_dict: dict[str, Any]) -> bool:
    rule_hits = {str(rule) for rule in snapshot_dict.get("rule_hits") or []}
    content_rule_ids = {
        "associated_script_network_sink",
        "associated_script_network_indicator",
        "document_input_to_network_sink",
        "document_input_encoded_to_network_sink",
        "credential_source_to_network_sink",
        "subprocess_file_transfer",
        "possible_document_input_to_network_sink",
        "content_evidence_incomplete",
        "content_mismatch",
        "execution_content_unverified",
    }
    return bool(rule_hits.intersection(content_rule_ids))


def _l3_trace_has_content_evidence_signal(l3_trace: dict[str, Any] | None) -> bool:
    if not isinstance(l3_trace, dict):
        return False
    reason = str(l3_trace.get("trigger_reason") or "")
    return reason in {
        "associated_script_network_sink",
        "document_input_to_network_sink",
        "possible_document_input_to_network_sink",
        "content_evidence_incomplete",
        "content_mismatch",
        "execution_content_unverified",
    }
