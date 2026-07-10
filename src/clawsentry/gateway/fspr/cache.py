"""FSPR cache keys, cache metadata, and cacheable result helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Sequence

from .inventory import build_fspr_inventory
from .types import (
    FSPR_CAPABILITY_MANIFEST_SCHEMA_VERSION,
    FSPR_EVIDENCE_CAPSULE_SCHEMA_VERSION,
    FSPR_EXTRACTOR_VERSION,
    FSPR_PROMPT_VERSION,
    FSPR_SCANNER_VERSION,
    FSPRInventory,
    FSPRResult,
    _fspr_evidence_capsule,
    _sha256,
)

_FSPR_PROVIDER_HEALTH_DEGRADATION_REASONS = frozenset(
    {
        "provider_invalid_json",
        "provider_unavailable",
        "provider_call_timeout",
    }
)


def build_fspr_cache_key(
    skill_root: str | Path,
    *,
    registry_snapshot_id: str,
    policy_fingerprint: str,
    input_mode: str = "raw_skill_only",
    context_hash: str | None = None,
    prompt_version: str = FSPR_PROMPT_VERSION,
    role_set_version: str = "roles.v1",
    policy_profile: str = "normal",
    budget_class: str = "default",
    scanner_version: str = FSPR_SCANNER_VERSION,
    extractor_version: str = FSPR_EXTRACTOR_VERSION,
    capability_manifest_schema_version: str = FSPR_CAPABILITY_MANIFEST_SCHEMA_VERSION,
    lineage_event_hash: str | None = None,
    final_claim_hash: str | None = None,
) -> str:
    inventory = build_fspr_inventory(skill_root)
    material = {
        "skill_root_hash": inventory.skill_root_hash,
        "input_mode": input_mode,
        "context_hash": context_hash or "",
        "registry_snapshot_id": registry_snapshot_id,
        "policy_fingerprint": policy_fingerprint,
        "prompt_version": prompt_version,
        "role_set_version": role_set_version,
        "policy_profile": policy_profile,
        "budget_class": budget_class,
        "scanner_version": scanner_version,
        "extractor_version": extractor_version,
        "capability_manifest_schema_version": capability_manifest_schema_version,
        "lineage_event_hash": lineage_event_hash or "",
        "final_claim_hash": final_claim_hash or "",
    }
    return _sha256(json.dumps(material, sort_keys=True).encode("utf-8"))


def _deterministic_inventory_role_result(
    verdict: str,
    findings: list[dict[str, Any]],
    *,
    degraded: bool = False,
    degradation_reason: str | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "role": "deterministic_inventory",
        "verdict": verdict,
        "findings": findings,
        "degraded": degraded,
    }
    if degradation_reason is not None:
        result["degradation_reason"] = degradation_reason
    return result


def _fspr_cache_summary(cache_key: str, *, hit: bool) -> dict[str, Any]:
    return {
        "key": cache_key,
        "hit": hit,
        "prompt_version": FSPR_PROMPT_VERSION,
    }


def _result_with_cache_hit(result: FSPRResult) -> FSPRResult:
    if result.cache_key is None:
        return result.model_copy(update={"cache_hit": True})
    return result.model_copy(
        update={
            "cache_hit": True,
            "cache": _fspr_cache_summary(result.cache_key, hit=True),
        }
    )


def _fspr_result_cacheable(result: FSPRResult) -> bool:
    if result.degradation_reason in _FSPR_PROVIDER_HEALTH_DEGRADATION_REASONS:
        return False
    for role_result in result.role_results:
        if (
            isinstance(role_result, dict)
            and role_result.get("degradation_reason")
            in _FSPR_PROVIDER_HEALTH_DEGRADATION_REASONS
        ):
            return False
    return True


def _fspr_prompt_file_entry(file_info: dict[str, Any]) -> dict[str, Any]:
    return {
        "evidence_id": file_info.get("evidence_id"),
        "evidence_ref": file_info.get("evidence_ref"),
        "path": file_info.get("path"),
        "size": file_info.get("size"),
    }


def _fspr_prompt_script_summary(summary: dict[str, Any]) -> dict[str, Any]:
    imports = [str(item) for item in summary.get("imports") or []]
    calls = [str(item) for item in summary.get("calls") or []]
    compact = {
        "path": summary.get("path"),
        "entrypoint_declared": bool(summary.get("entrypoint_declared")),
        "import_count": len(imports),
        "call_count": len(calls),
        "imports_sample": imports[:8],
        "calls_sample": calls[:12],
    }
    if len(imports) > len(compact["imports_sample"]):
        compact["omitted_import_count"] = len(imports) - len(compact["imports_sample"])
    if len(calls) > len(compact["calls_sample"]):
        compact["omitted_call_count"] = len(calls) - len(compact["calls_sample"])
    return compact


def _fspr_agentic_prompt_evidence_capsule(
    inventory: FSPRInventory,
    *,
    include_deterministic_findings: bool = True,
) -> dict[str, Any]:
    capsule = _fspr_evidence_capsule(
        inventory,
        include_deterministic_findings=include_deterministic_findings,
    )
    compacted = False

    files = [
        _fspr_prompt_file_entry(file_info)
        for file_info in inventory.files[:160]
        if isinstance(file_info, dict)
    ]
    if len(inventory.files) > len(files):
        compacted = True
        capsule["omitted_file_count"] = len(inventory.files) - len(files)
    if files != capsule.get("files"):
        compacted = True
    capsule["files"] = files

    script_summaries = [
        _fspr_prompt_script_summary(summary)
        for summary in inventory.script_summaries
        if isinstance(summary, dict)
    ]
    if script_summaries != capsule.get("script_summaries"):
        compacted = True
    capsule["script_summaries"] = script_summaries

    if compacted:
        capsule["prompt_capsule_note"] = "large_inventory_compacted"
        capsule["script_summaries_compacted"] = True
    return capsule


def _is_hard_finding(finding: dict[str, Any]) -> bool:
    return bool(
        finding.get("decision_affecting")
        or finding.get("severity") in {"high", "critical"}
    )


def _has_hard_deterministic_findings(inventory: FSPRInventory) -> bool:
    return any(_is_hard_finding(finding) for finding in inventory.findings) or any(
        _is_hard_finding(finding) for finding in inventory.deterministic_findings
    )


def _timeout_result(
    *,
    timing_mode: str,
    cache_key: str,
    evidence_capsule: dict[str, Any] | None = None,
) -> FSPRResult:
    capsule = dict(evidence_capsule or {})
    capsule.setdefault("schema", FSPR_EVIDENCE_CAPSULE_SCHEMA_VERSION)
    return FSPRResult(
        timing_mode=timing_mode,
        verdict="insufficient_evidence",
        severity="low",
        confidence=0.0,
        role_results=[
            _deterministic_inventory_role_result(
                "insufficient_evidence",
                [],
                degraded=True,
                degradation_reason="timeout",
            )
        ],
        evidence_capsule=capsule,
        degraded=True,
        degradation_reason="timeout",
        cache_key=cache_key,
        cache=_fspr_cache_summary(cache_key, hit=False),
    )


def _raw_input_contamination_cache_key(
    skill_root: str | Path,
    *,
    paths: Sequence[str],
    registry_snapshot_id: str,
    policy_fingerprint: str,
    input_mode: str,
    context_hash: str | None,
    role_set_version: str,
    policy_profile: str,
) -> str:
    material = {
        "reason": "raw_input_contamination",
        "evidence_capsule_schema_version": FSPR_EVIDENCE_CAPSULE_SCHEMA_VERSION,
        "prompt_version": FSPR_PROMPT_VERSION,
        "skill_root": str(Path(skill_root).resolve(strict=False)),
        "paths": list(paths),
        "registry_snapshot_id": registry_snapshot_id,
        "policy_fingerprint": policy_fingerprint,
        "input_mode": input_mode,
        "context_hash": context_hash or "",
        "role_set_version": role_set_version,
        "policy_profile": policy_profile,
    }
    return _sha256(json.dumps(material, sort_keys=True).encode("utf-8"))


def _raw_input_contamination_result(
    *,
    timing_mode: str,
    paths: Sequence[str],
    cache_key: str,
) -> FSPRResult:
    return FSPRResult(
        timing_mode=timing_mode,
        verdict="insufficient_evidence",
        severity="low",
        confidence=0.0,
        role_results=[
            _deterministic_inventory_role_result(
                "insufficient_evidence",
                [],
                degraded=True,
                degradation_reason="raw_input_contamination",
            )
        ],
        final_findings=[],
        evidence_capsule={
            "schema": FSPR_EVIDENCE_CAPSULE_SCHEMA_VERSION,
            "raw_input_contamination": {
                "paths": list(paths),
            },
        },
        degraded=True,
        degradation_reason="raw_input_contamination",
        cache_key=cache_key,
        cache=_fspr_cache_summary(cache_key, hit=False),
    )
