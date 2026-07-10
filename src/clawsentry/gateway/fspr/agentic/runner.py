"""Agentic read-only FSPR runner orchestration."""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Callable, MutableMapping, Sequence

from ..cache import (
    _deterministic_inventory_role_result,
    _fspr_cache_summary,
    _fspr_result_cacheable,
    _has_hard_deterministic_findings,
    _raw_input_contamination_cache_key,
    _raw_input_contamination_result,
    _result_with_cache_hit,
    build_fspr_cache_key,
)
from ..inventory import build_fspr_inventory
from ..provider import (
    _MISSING_ATTR,
    _admission_recommendation_for_inventory,
    _append_fspr_replay_call,
    _call_provider_review_role_with_replay_suppressed,
    _normalize_provider_confidence,
    _normalize_provider_findings,
)
from ..static_rules import (
    _agentic_runtime_body_excluded_path,
    _max_fspr_severity,
    _merge_fspr_final_findings,
    _raw_fspr_input_contamination_paths,
    _verdict_for_findings,
)
from ..types import (
    FSPRAgenticSemanticReviewError,
    FSPRProviderSchemaError,
    FSPRResult,
    FSPRRoleProvider,
    _fspr_evidence_capsule,
    _sha256,
)
from .prompts import (
    _AGENTIC_COVERAGE_PROFILE,
    _AGENTIC_PROTOCOL_VERSION,
    _agentic_coverage_incomplete_prompt,
    _agentic_coverage_state,
    _agentic_readonly_continue_prompt,
    _agentic_schema_repair_prompt,
    _agentic_strict_final_prompt,
    _agentic_strict_final_repair_prompt,
    _build_agentic_coverage_plan,
    build_fspr_agentic_readonly_prompt,
)
from .risk_cues import (
    _AGENTIC_READ_EVIDENCE_SHORT_CIRCUIT_CUE_TYPES,
    _AGENTIC_READ_FILE_STRONG_RISK_CUE_TYPES,
    _agentic_strict_risk_cues,
)
from .toolkit import (
    FSPRReadOnlyToolkit,
    _FSPR_AGENTIC_READONLY_TOOLS,
    _agentic_automatic_priority_read_path,
    _agentic_path_in_skill_root,
    _agentic_referenced_priority_paths,
    _agentic_required_truncation_followup_starts,
    _agentic_safe_tool_args,
    _agentic_search_counts_as_followup,
    _execute_agentic_readonly_tool,
)
from .validation import (
    _agentic_apply_finding_defaults,
    _agentic_base_evidence_ref,
    _agentic_calibrate_role_result_with_risk_cues,
    _agentic_clean_semantic_review,
    _agentic_default_semantic_ref,
    _agentic_degradation_reason_for_diagnostic,
    _agentic_downgrade_normal_document_workflow_result,
    _agentic_evidence_refs,
    _agentic_exploration_done_payload,
    _agentic_final_like_payload,
    _agentic_json_payload,
    _agentic_mixed_final_tool_payload,
    _agentic_parse_diagnostic,
    _agentic_safe_value,
    _agentic_semantic_evidence_item_from_envelope,
    _agentic_tool_evidence_envelope,
    _agentic_validate_semantic_role_result,
    _parse_agentic_provider_role_result,
    _parse_agentic_strict_final_role_result,
    _parse_agentic_tool_call_response,
    _sanitize_agentic_findings,
    _sanitize_agentic_semantic_dimension_review,
    _sanitize_agentic_strict_role_result,
)


def _agentic_trace_summary(trace: dict[str, Any]) -> dict[str, Any]:
    return {
        "mode": trace.get("mode"),
        "tool_calls_used": trace.get("tool_calls_used"),
        "files_read": trace.get("files_read", []),
        "file_ranges_read": trace.get("file_ranges_read", []),
        "searches": trace.get("searches", []),
        "coverage_incomplete_prompts": trace.get("coverage_incomplete_prompts", 0),
        "tool_budget": trace.get("tool_budget", {}),
    }


def _build_agentic_trace(
    *,
    turns: list[dict[str, Any]],
    start: float,
    degraded: bool,
    degradation_reason: str | None,
    final_verdict: dict[str, Any] | None,
    max_tool_calls: int,
    remaining_tool_calls: int,
    coverage_plan: dict[str, Any] | None = None,
    read_paths: set[str] | None = None,
    coverage_incomplete_prompts: int = 0,
    repair_attempted: bool = False,
    parse_diagnostics: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    tool_turns = [turn for turn in turns if turn.get("type") == "tool_call"]
    files_read = sorted(
        {
            str(turn.get("path") or "")
            for turn in tool_turns
            if turn.get("tool_name") == "read_file" and turn.get("path")
        }
    )
    file_ranges_read = [
        {
            "path": str(turn.get("path") or ""),
            "start_line": turn.get("range", {}).get("start_line"),
            "end_line": turn.get("range", {}).get("end_line"),
        }
        for turn in tool_turns
        if turn.get("tool_name") == "read_file_range"
        and turn.get("path")
        and isinstance(turn.get("range"), dict)
    ]
    searches = [
        {
            "pattern": _agentic_safe_value(
                turn.get("tool_args", {}).get("pattern", ""), max_len=160
            ),
            "glob": _agentic_safe_value(
                turn.get("tool_args", {}).get("glob", "*"), max_len=120
            ),
        }
        for turn in tool_turns
        if turn.get("tool_name") == "search_codebase"
    ]
    truncated_read_paths = {
        str(turn.get("path") or "")
        for turn in tool_turns
        if turn.get("tool_name") == "read_file"
        and turn.get("path")
        and turn.get("result_truncated") is True
    }
    range_read_paths = {
        str(turn.get("path") or "")
        for turn in tool_turns
        if turn.get("tool_name") == "read_file_range" and turn.get("path")
    }
    return {
        "schema": "clawsentry.fspr_agentic_readonly_trace.v1",
        "mode": "agentic-readonly",
        "turns": turns,
        "final_verdict": final_verdict,
        "tool_calls_used": len(tool_turns),
        "files_read": files_read,
        "file_ranges_read": file_ranges_read,
        "searches": searches,
        "coverage_state": _agentic_coverage_state(
            coverage_plan or {},
            read_paths or set(files_read),
            truncated_read_paths=truncated_read_paths,
            range_read_paths=range_read_paths,
            searches_performed=sum(
                1
                for search in searches
                if _agentic_search_counts_as_followup(search.get("pattern"))
            ),
        ),
        "coverage_incomplete_prompts": coverage_incomplete_prompts,
        "repair_attempted": repair_attempted,
        "parse_diagnostics": parse_diagnostics or [],
        "tool_budget": {
            "max_tool_calls": max_tool_calls,
            "remaining_tool_calls": remaining_tool_calls,
        },
        "total_latency_ms": round((time.monotonic() - start) * 1000.0, 3),
        "degraded": degraded,
        "degradation_reason": degradation_reason,
    }


def _agentic_role_degradation_result(
    *,
    role_results: list[dict[str, Any]],
    reason: str,
    trace: dict[str, Any],
) -> list[dict[str, Any]]:
    return [
        *role_results,
        {
            "role": "agentic_readonly",
            "verdict": "insufficient_evidence",
            "severity": "low",
            "confidence": 0.0,
            "findings": [],
            "degraded": True,
            "coverage": "degraded",
            "degradation_reason": reason,
            "agent_trace": trace,
        },
    ]


def run_agentic_readonly_fspr_review(
    skill_root: str | Path,
    *,
    provider: FSPRRoleProvider,
    timeout_s: float = 180.0,
    timing_mode: str = "pre_use_gate",
    registry_snapshot_id: str = "unknown",
    policy_fingerprint: str = "unknown",
    input_mode: str = "raw_skill_only",
    context_hash: str | None = None,
    max_turns: int = 16,
    max_tool_calls: int = 12,
    max_tool_result_chars: int = 4_000,
    coverage_guard_enabled: bool = True,
    strict_final_enabled: bool = True,
    repair_retry_limit: int = 1,
    structured_output_mode: str = "auto",
    structured_output_supported: bool = False,
    deterministic_floor_short_circuit: bool = True,
    cache: MutableMapping[str, FSPRResult] | None = None,
    cache_enabled: bool = False,
) -> FSPRResult:
    return _run_agentic_readonly_fspr_review(
        skill_root,
        provider=provider,
        timeout_s=timeout_s,
        timing_mode=timing_mode,
        registry_snapshot_id=registry_snapshot_id,
        policy_fingerprint=policy_fingerprint,
        input_mode=input_mode,
        context_hash=context_hash,
        max_turns=max_turns,
        max_tool_calls=max_tool_calls,
        max_tool_result_chars=max_tool_result_chars,
        coverage_guard_enabled=coverage_guard_enabled,
        strict_final_enabled=strict_final_enabled,
        repair_retry_limit=repair_retry_limit,
        structured_output_mode=structured_output_mode,
        structured_output_supported=structured_output_supported,
        deterministic_floor_short_circuit=deterministic_floor_short_circuit,
        cache=cache,
        cache_enabled=cache_enabled,
    )


def _run_agentic_readonly_fspr_review(
    skill_root: str | Path,
    *,
    provider: FSPRRoleProvider,
    cache_key_builder: Callable[..., str] = build_fspr_cache_key,
    agentic_protocol_version: str = _AGENTIC_PROTOCOL_VERSION,
    timeout_s: float = 180.0,
    timing_mode: str = "pre_use_gate",
    registry_snapshot_id: str = "unknown",
    policy_fingerprint: str = "unknown",
    input_mode: str = "raw_skill_only",
    context_hash: str | None = None,
    max_turns: int = 16,
    max_tool_calls: int = 12,
    max_tool_result_chars: int = 4_000,
    coverage_guard_enabled: bool = True,
    strict_final_enabled: bool = True,
    repair_retry_limit: int = 1,
    structured_output_mode: str = "auto",
    structured_output_supported: bool = False,
    deterministic_floor_short_circuit: bool = True,
    cache: MutableMapping[str, FSPRResult] | None = None,
    cache_enabled: bool = False,
) -> FSPRResult:
    started_at = time.monotonic()

    def timed_out() -> bool:
        return timeout_s <= 0 or (time.monotonic() - started_at) >= timeout_s

    agentic_role_set_version = ":".join(
        [
            "roles.v1",
            "agentic-readonly",
            agentic_protocol_version,
            _AGENTIC_COVERAGE_PROFILE,
            f"turns={max(1, int(max_turns))}",
            f"tools={max(0, min(int(max_tool_calls), 100))}",
            f"tool_chars={max(0, int(max_tool_result_chars))}",
            f"coverage={int(bool(coverage_guard_enabled))}",
            f"strict={int(bool(strict_final_enabled))}",
            f"repair={max(0, int(repair_retry_limit))}",
            f"structured={str(structured_output_mode or 'auto')}",
            f"structured_supported={int(bool(structured_output_supported))}",
            f"timeout_ms={int(max(0.0, float(timeout_s)) * 1000)}",
            f"det_floor={int(bool(deterministic_floor_short_circuit))}",
        ]
    )
    contamination_paths = (
        _raw_fspr_input_contamination_paths(skill_root)
        if input_mode == "raw_skill_only"
        else []
    )
    if contamination_paths:
        cache_key = _raw_input_contamination_cache_key(
            skill_root,
            paths=contamination_paths,
            registry_snapshot_id=registry_snapshot_id,
            policy_fingerprint=policy_fingerprint,
            input_mode=input_mode,
            context_hash=context_hash,
            role_set_version=agentic_role_set_version,
            policy_profile="agentic-readonly",
        )
        if cache_enabled and cache is not None and cache_key in cache:
            return _result_with_cache_hit(cache[cache_key])
        result = _raw_input_contamination_result(
            timing_mode=timing_mode,
            paths=contamination_paths,
            cache_key=cache_key,
        )
        if cache_enabled and cache is not None and _fspr_result_cacheable(result):
            cache[cache_key] = result
        return result
    cache_key = cache_key_builder(
        skill_root,
        registry_snapshot_id=registry_snapshot_id,
        policy_fingerprint=policy_fingerprint,
        input_mode=input_mode,
        context_hash=context_hash,
        role_set_version=agentic_role_set_version,
        policy_profile="agentic-readonly",
    )
    if cache_enabled and cache is not None and cache_key in cache:
        return _result_with_cache_hit(cache[cache_key])

    inventory = build_fspr_inventory(skill_root)
    evidence_capsule = _fspr_evidence_capsule(inventory)
    deterministic_verdict = "inconsistent" if inventory.findings else "consistent"
    deterministic_severity = "high" if inventory.findings else "low"
    deterministic_role_result = _deterministic_inventory_role_result(
        deterministic_verdict,
        inventory.findings,
    )
    admission_recommendation = _admission_recommendation_for_inventory(
        inventory,
        cache_key=cache_key,
        registry_snapshot_id=registry_snapshot_id,
        severity=deterministic_severity,
    )
    role_results: list[dict[str, Any]] = [deterministic_role_result]
    toolkit = FSPRReadOnlyToolkit(skill_root)
    coverage_plan = _build_agentic_coverage_plan(inventory, inventory.skill_root)
    read_paths: set[str] = set()
    truncated_read_paths: set[str] = set()
    range_read_paths: set[str] = set()
    searches_performed = 0
    semantic_evidence: list[dict[str, Any]] = []
    coverage_incomplete_prompts = 0
    repair_attempted = False
    parse_diagnostics: list[dict[str, Any]] = []
    turns: list[dict[str, Any]] = []
    messages: list[dict[str, Any]] = [
        {
            "role": "user",
            "content": build_fspr_agentic_readonly_prompt(
                inventory,
                include_deterministic_findings=deterministic_floor_short_circuit,
            ),
        }
    ]
    remaining_tool_calls = max(0, min(int(max_tool_calls), 100))

    def remaining_timeout_ms() -> float:
        if timeout_s <= 0:
            return 0.0
        return max(0.0, (timeout_s - (time.monotonic() - started_at)) * 1000.0)

    def current_coverage_state() -> dict[str, Any]:
        return _agentic_coverage_state(
            coverage_plan,
            read_paths,
            truncated_read_paths=truncated_read_paths,
            range_read_paths=range_read_paths,
            searches_performed=searches_performed,
        )

    def final_response_format() -> dict[str, object] | None:
        mode = str(structured_output_mode or "auto")
        if mode == "on" or (mode == "auto" and structured_output_supported):
            return {"type": "json_object"}
        return None

    def ready_for_fast_strict_final_after_tool() -> bool:
        if not strict_final_enabled or coverage_guard_enabled:
            return False
        coverage_state = current_coverage_state()
        return bool(coverage_state.get("required_read_paths_satisfied"))

    def provider_review(
        *,
        role: str,
        prompt: str,
        phase: str = "exploration",
        response_format: dict[str, object] | None = None,
    ) -> str:
        budget_ms = remaining_timeout_ms()
        if budget_ms <= 1.0:
            raise TimeoutError("fspr_timeout_budget_exhausted")
        previous_timeout = getattr(provider, "_timeout_ms", _MISSING_ATTR)
        can_restore_timeout = previous_timeout is not _MISSING_ATTR
        if isinstance(previous_timeout, (int, float)):
            try:
                setattr(
                    provider,
                    "_timeout_ms",
                    max(1.0, min(float(previous_timeout), budget_ms)),
                )
            except Exception:
                can_restore_timeout = False
        call_started = time.monotonic()
        try:
            response = _call_provider_review_role_with_replay_suppressed(
                provider,
                role=role,
                prompt=prompt,
                response_format=response_format,
            )
        except TimeoutError as exc:
            _append_fspr_replay_call(
                role=role,
                phase=phase,
                prompt=prompt,
                response=str(exc) or type(exc).__name__,
                status="timeout",
                elapsed_ms=(time.monotonic() - call_started) * 1000.0,
                response_format=response_format,
            )
            raise
        except Exception as exc:
            _append_fspr_replay_call(
                role=role,
                phase=phase,
                prompt=prompt,
                response=f"{type(exc).__name__}: {exc}",
                status="error",
                elapsed_ms=(time.monotonic() - call_started) * 1000.0,
                response_format=response_format,
            )
            raise
        finally:
            if can_restore_timeout:
                try:
                    setattr(provider, "_timeout_ms", previous_timeout)
                except Exception:
                    pass
        _append_fspr_replay_call(
            role=role,
            phase=phase,
            prompt=prompt,
            response=response,
            status="ok",
            elapsed_ms=(time.monotonic() - call_started) * 1000.0,
            response_format=response_format,
        )
        return response

    def degraded_result(reason: str) -> FSPRResult:
        local_findings = list(inventory.findings)
        locally_supported = bool(local_findings)
        trace = _build_agentic_trace(
            turns=turns,
            start=started_at,
            degraded=True,
            degradation_reason=reason,
            final_verdict=None,
            max_tool_calls=max_tool_calls,
            remaining_tool_calls=remaining_tool_calls,
            coverage_plan=coverage_plan,
            read_paths=read_paths,
            coverage_incomplete_prompts=coverage_incomplete_prompts,
            repair_attempted=repair_attempted,
            parse_diagnostics=parse_diagnostics,
        )
        result = FSPRResult(
            timing_mode=timing_mode,
            verdict=("inconsistent" if inventory.findings else "insufficient_evidence"),
            severity=("high" if inventory.findings else "low"),
            confidence=(0.8 if inventory.findings else 0.0),
            admission_recommendation=admission_recommendation,
            deterministic_findings_preserved=True,
            role_results=_agentic_role_degradation_result(
                role_results=role_results,
                reason=reason,
                trace=trace,
            ),
            final_findings=(local_findings if inventory.findings else []),
            evidence_capsule=evidence_capsule,
            degraded=not locally_supported,
            degradation_reason=None if locally_supported else reason,
            cache_key=cache_key,
            cache=_fspr_cache_summary(cache_key, hit=False),
        )
        if cache_enabled and cache is not None and _fspr_result_cacheable(result):
            cache[cache_key] = result
        return result

    def finalized_result(role_result: dict[str, Any]) -> FSPRResult:
        role_result["role"] = "agentic_readonly"
        role_result["semantic_dimension_review"] = (
            _sanitize_agentic_semantic_dimension_review(
                role_result.get("semantic_dimension_review")
            )
        )
        role_result["findings"] = _sanitize_agentic_findings(
            _normalize_provider_findings(role_result.get("findings"))
        )
        provider_verdict = str(role_result.get("verdict") or "insufficient_evidence")
        provider_severity = str(role_result.get("severity") or "low")
        role_result["findings"] = _agentic_apply_finding_defaults(
            list(role_result.get("findings") or []),
            provider_severity=provider_severity,
        )
        provider_findings = list(role_result.get("findings") or [])
        final_findings = _merge_fspr_final_findings(
            inventory.findings,
            provider_findings,
        )
        suspicious_semantic = any(
            str(item.get("status") or "") == "suspicious"
            for item in role_result["semantic_dimension_review"]
        )
        if suspicious_semantic:
            if provider_verdict in {"consistent", "insufficient_evidence"}:
                provider_verdict = "suspicious"
            if provider_severity == "low":
                provider_severity = "medium"
            for finding in provider_findings:
                if str(finding.get("severity") or "") == "low":
                    finding["severity"] = "medium"
            final_findings = _merge_fspr_final_findings(
                inventory.findings,
                provider_findings,
            )
        role_result["findings"] = provider_findings
        role_result["verdict"] = provider_verdict
        role_result["severity"] = provider_severity
        result_verdict = provider_verdict
        result_severity = provider_severity
        if final_findings:
            result_verdict = _verdict_for_findings(provider_verdict, final_findings)
            result_severity = _max_fspr_severity(provider_severity, final_findings)
        final_verdict = {
            "verdict": result_verdict,
            "severity": result_severity,
            "confidence": _normalize_provider_confidence(role_result.get("confidence")),
            "finding_count": len(final_findings),
            "evidence_refs": _agentic_evidence_refs(final_findings),
        }
        trace = _build_agentic_trace(
            turns=turns,
            start=started_at,
            degraded=False,
            degradation_reason=None,
            final_verdict=final_verdict,
            max_tool_calls=max_tool_calls,
            remaining_tool_calls=remaining_tool_calls,
            coverage_plan=coverage_plan,
            read_paths=read_paths,
            coverage_incomplete_prompts=coverage_incomplete_prompts,
            repair_attempted=repair_attempted,
            parse_diagnostics=parse_diagnostics,
        )
        role_result["agent_trace"] = trace
        result = FSPRResult(
            timing_mode=timing_mode,
            verdict=result_verdict,
            severity=result_severity,
            confidence=_normalize_provider_confidence(role_result.get("confidence")),
            admission_recommendation=admission_recommendation,
            deterministic_findings_preserved=True,
            role_results=[*role_results, role_result],
            final_findings=final_findings,
            semantic_dimension_review=list(role_result["semantic_dimension_review"]),
            evidence_capsule=evidence_capsule,
            degraded=False,
            cache_key=cache_key,
            cache=_fspr_cache_summary(cache_key, hit=False),
        )
        if cache_enabled and cache is not None:
            cache[cache_key] = result
        return result

    def deterministic_floor_result() -> FSPRResult:
        final_findings = list(inventory.findings)
        final_verdict = {
            "verdict": "inconsistent",
            "severity": "high",
            "confidence": 0.8,
            "finding_count": len(final_findings),
            "evidence_refs": _agentic_evidence_refs(final_findings),
        }
        trace = _build_agentic_trace(
            turns=[],
            start=started_at,
            degraded=False,
            degradation_reason=None,
            final_verdict=final_verdict,
            max_tool_calls=max_tool_calls,
            remaining_tool_calls=remaining_tool_calls,
            coverage_plan=coverage_plan,
            read_paths=read_paths,
            coverage_incomplete_prompts=coverage_incomplete_prompts,
            repair_attempted=repair_attempted,
            parse_diagnostics=parse_diagnostics,
        )
        role_result = {
            "role": "agentic_readonly",
            "verdict": "inconsistent",
            "severity": "high",
            "confidence": 0.8,
            "findings": _sanitize_agentic_findings(
                _normalize_provider_findings(final_findings)
            ),
            "degraded": False,
            "deterministic_floor_short_circuit": True,
            "agent_trace": trace,
        }
        result = FSPRResult(
            timing_mode=timing_mode,
            verdict="inconsistent",
            severity="high",
            confidence=0.8,
            admission_recommendation=admission_recommendation,
            deterministic_findings_preserved=True,
            role_results=[*role_results, role_result],
            final_findings=final_findings,
            evidence_capsule=evidence_capsule,
            degraded=False,
            cache_key=cache_key,
            cache=_fspr_cache_summary(cache_key, hit=False),
        )
        if cache_enabled and cache is not None:
            cache[cache_key] = result
        return result

    def deterministic_findings_for_semantic_validation() -> list[dict[str, Any]]:
        if not deterministic_floor_short_circuit:
            return []
        return _sanitize_agentic_findings(
            _normalize_provider_findings(inventory.findings)
        )

    def validate_agentic_final_role_result(
        role_result: dict[str, Any],
    ) -> dict[str, Any]:
        deterministic_findings = deterministic_findings_for_semantic_validation()
        _agentic_validate_semantic_role_result(
            role_result,
            read_paths=read_paths,
            deterministic_findings=deterministic_findings,
            semantic_evidence=semantic_evidence,
        )
        if _agentic_calibrate_role_result_with_risk_cues(
            role_result,
            semantic_evidence=semantic_evidence,
            deterministic_findings=deterministic_findings,
        ):
            _agentic_validate_semantic_role_result(
                role_result,
                read_paths=read_paths,
                deterministic_findings=deterministic_findings,
                semantic_evidence=semantic_evidence,
            )
        if _agentic_downgrade_normal_document_workflow_result(
            role_result,
            semantic_evidence=semantic_evidence,
        ):
            _agentic_validate_semantic_role_result(
                role_result,
                read_paths=read_paths,
                deterministic_findings=deterministic_findings,
                semantic_evidence=semantic_evidence,
            )
        return role_result

    def cue_backed_invalid_final_role_result(
        *,
        parse_status: str,
    ) -> dict[str, Any] | None:
        deterministic_findings = deterministic_findings_for_semantic_validation()
        candidate: dict[str, Any] = {
            "role": "agentic_readonly",
            "verdict": "insufficient_evidence",
            "severity": "low",
            "confidence": 0.0,
            "findings": [],
            "semantic_dimension_review": _agentic_clean_semantic_review(confidence=0.0),
            "degraded": False,
            "agentic_parse_status": parse_status,
        }
        if not _agentic_calibrate_role_result_with_risk_cues(
            candidate,
            semantic_evidence=semantic_evidence,
            deterministic_findings=deterministic_findings,
        ):
            return None
        candidate["agentic_risk_cue_calibration"] = "raised_from_invalid_final"
        try:
            _agentic_validate_semantic_role_result(
                candidate,
                read_paths=read_paths,
                deterministic_findings=deterministic_findings,
                semantic_evidence=semantic_evidence,
            )
        except FSPRAgenticSemanticReviewError:
            return None
        return candidate

    def cue_backed_read_evidence_role_result() -> dict[str, Any] | None:
        if not current_coverage_state().get("required_read_paths_satisfied"):
            return None
        short_circuit_cues = [
            cue
            for cue in _agentic_strict_risk_cues(semantic_evidence)
            if str(cue.get("type") or "")
            in _AGENTIC_READ_EVIDENCE_SHORT_CIRCUIT_CUE_TYPES
            and (
                _agentic_base_evidence_ref(str(cue.get("ref") or "")) == "file:SKILL.md"
                or str(cue.get("type") or "")
                in _AGENTIC_READ_FILE_STRONG_RISK_CUE_TYPES
            )
        ]
        if not short_circuit_cues:
            return None
        deterministic_findings = deterministic_findings_for_semantic_validation()
        candidate: dict[str, Any] = {
            "role": "agentic_readonly",
            "verdict": "consistent",
            "severity": "low",
            "confidence": 0.0,
            "findings": [],
            "semantic_dimension_review": _agentic_clean_semantic_review(confidence=0.0),
            "degraded": False,
        }
        if not _agentic_calibrate_role_result_with_risk_cues(
            candidate,
            semantic_evidence=semantic_evidence,
            deterministic_findings=deterministic_findings,
        ):
            return None
        candidate["agentic_risk_cue_calibration"] = "raised_from_read_evidence"
        try:
            _agentic_validate_semantic_role_result(
                candidate,
                read_paths=read_paths,
                deterministic_findings=deterministic_findings,
                semantic_evidence=semantic_evidence,
            )
        except FSPRAgenticSemanticReviewError:
            return None
        return candidate

    def cue_backed_read_evidence_result() -> FSPRResult | None:
        role_result = cue_backed_read_evidence_role_result()
        if role_result is None:
            return None
        return finalized_result(role_result)

    def clean_read_evidence_role_result(
        *,
        fast_path: str = "no_local_or_read_evidence_risk_cues",
    ) -> dict[str, Any] | None:
        if strict_final_enabled:
            return None
        if inventory.findings or inventory.deterministic_findings:
            return None
        if not current_coverage_state().get("satisfied"):
            return None
        if not semantic_evidence:
            return None
        if _agentic_strict_risk_cues(semantic_evidence):
            return None
        return {
            "role": "agentic_readonly",
            "verdict": "consistent",
            "severity": "low",
            "confidence": 0.72,
            "findings": [],
            "semantic_dimension_review": _agentic_clean_semantic_review(
                confidence=0.72
            ),
            "degraded": False,
            "agentic_fast_clean_path": fast_path,
        }

    def clean_read_evidence_result(
        *,
        fast_path: str = "no_local_or_read_evidence_risk_cues",
    ) -> FSPRResult | None:
        role_result = clean_read_evidence_role_result(fast_path=fast_path)
        if role_result is None:
            return None
        return finalized_result(role_result)

    def incomplete_final_role_result(parse_status: str) -> dict[str, Any]:
        default_ref = _agentic_default_semantic_ref(read_paths)
        semantic_review = _agentic_clean_semantic_review(confidence=0.0)
        for item in semantic_review:
            item["evidence_refs"] = [default_ref] if default_ref else []
        for item in semantic_review:
            if item.get("dimension") == "description_mismatch":
                item["status"] = "not_enough_evidence"
                item["rationale"] = (
                    "Provider did not return a usable final structured analysis."
                )
                break
        return {
            "role": "agentic_readonly",
            "verdict": "insufficient_evidence",
            "severity": "low",
            "confidence": 0.0,
            "findings": [],
            "semantic_dimension_review": semantic_review,
            "degraded": False,
            "agentic_parse_status": parse_status,
        }

    def incomplete_final_result(parse_status: str) -> FSPRResult:
        role_result = cue_backed_invalid_final_role_result(parse_status=parse_status)
        if role_result is not None:
            return finalized_result(role_result)
        return finalized_result(incomplete_final_role_result(parse_status))

    def repair_budget_too_low() -> bool:
        threshold_ms = min(35_000.0, max(1_000.0, float(timeout_s) * 1000.0 * 0.35))
        return remaining_timeout_ms() < threshold_ms

    def semantic_errors_allow_incomplete_fallback(errors: Sequence[str] | None) -> bool:
        if not errors:
            return True
        disallowed = re.compile(
            r"unread or unsupported|unsafe evidence|local-summary|"
            r"coverage satisfaction|no read evidence available",
            re.I,
        )
        return not any(disallowed.search(str(error or "")) for error in errors)

    def should_use_incomplete_final_fallback(
        *,
        parse_status: str,
        parsed_role_result: dict[str, Any] | None,
        semantic_errors: Sequence[str] | None,
        repair_exhausted: bool = False,
    ) -> bool:
        if _agentic_strict_risk_cues(semantic_evidence):
            return False
        if parse_status == "provider_call_timeout":
            return True
        if parse_status not in {
            "provider_invalid_json",
            "provider_invalid_schema",
            "provider_semantic_review_invalid",
        }:
            return False
        if parse_status == "provider_invalid_schema" and parsed_role_result is None:
            return False
        if (
            not repair_exhausted
            and max(0, int(repair_retry_limit)) > 0
            and not repair_budget_too_low()
        ):
            return False
        if not semantic_errors_allow_incomplete_fallback(semantic_errors):
            return False
        if parsed_role_result is None:
            return parse_status == "provider_invalid_json"
        parsed_verdict = str(parsed_role_result.get("verdict") or "")
        parsed_findings = list(parsed_role_result.get("findings") or [])
        return (
            parsed_verdict in {"consistent", "insufficient_evidence"}
            and not parsed_findings
        )

    def coverage_ready_for_incomplete_final() -> bool:
        return not coverage_guard_enabled or bool(current_coverage_state()["satisfied"])

    def parse_inline_final_role_result(raw_response: str) -> dict[str, Any]:
        return validate_agentic_final_role_result(
            _sanitize_agentic_strict_role_result(
                _parse_agentic_provider_role_result(raw_response)
            )
        )

    def strict_final_result() -> FSPRResult:
        nonlocal repair_attempted
        trace_for_prompt = _build_agentic_trace(
            turns=turns,
            start=started_at,
            degraded=False,
            degradation_reason=None,
            final_verdict=None,
            max_tool_calls=max_tool_calls,
            remaining_tool_calls=remaining_tool_calls,
            coverage_plan=coverage_plan,
            read_paths=read_paths,
            coverage_incomplete_prompts=coverage_incomplete_prompts,
            repair_attempted=repair_attempted,
            parse_diagnostics=parse_diagnostics,
        )
        strict_prompt = _agentic_strict_final_prompt(
            trace_summary=_agentic_trace_summary(trace_for_prompt),
            coverage_state=trace_for_prompt["coverage_state"],
            deterministic_findings=deterministic_findings_for_semantic_validation(),
            semantic_evidence=semantic_evidence,
        )
        provider_start = time.monotonic()
        try:
            raw_final = provider_review(
                role="agentic_readonly",
                prompt=strict_prompt,
                phase="strict_final",
                response_format=final_response_format(),
            )
        except TimeoutError:
            return incomplete_final_result("provider_call_timeout")
        except Exception:
            return degraded_result("provider_unavailable")
        turns.append(
            {
                "turn": len(turns) + 1,
                "type": "llm_call",
                "phase": "strict_final",
                "prompt_length": len(strict_prompt),
                "response_chars": len(raw_final),
                "response_hash": _sha256(raw_final.encode("utf-8", errors="replace")),
                "latency_ms": round((time.monotonic() - provider_start) * 1000.0, 3),
            }
        )
        role_result: dict[str, Any] | None = None
        repair_errors: list[str] | None = None
        repair_source_responses = [raw_final]
        last_degradation_reason = "provider_invalid_schema"
        parsed_role_result: dict[str, Any] | None = None
        try:
            parsed_role_result = _parse_agentic_strict_final_role_result(raw_final)
            role_result = validate_agentic_final_role_result(parsed_role_result)
        except FSPRAgenticSemanticReviewError as exc:
            repair_errors = list(exc.errors)
            last_degradation_reason = "provider_semantic_review_invalid"
            parse_diagnostics.append(
                {
                    "response_hash": _sha256(
                        raw_final.encode("utf-8", errors="replace")
                    ),
                    "response_chars": len(raw_final),
                    "has_markdown_fence": "```" in raw_final,
                    "has_tool_call": False,
                    "error_type": "provider_semantic_review_invalid",
                    "semantic_errors": repair_errors,
                }
            )
        except (FSPRProviderSchemaError, json.JSONDecodeError, ValueError):
            diagnostic = _agentic_parse_diagnostic(raw_final)
            parse_diagnostics.append(diagnostic)
            last_degradation_reason = _agentic_degradation_reason_for_diagnostic(
                diagnostic
            )
        if role_result is None:
            role_result = cue_backed_invalid_final_role_result(
                parse_status=last_degradation_reason
            )
        if role_result is None and should_use_incomplete_final_fallback(
            parse_status=last_degradation_reason,
            parsed_role_result=parsed_role_result,
            semantic_errors=repair_errors,
        ):
            return finalized_result(
                incomplete_final_role_result(last_degradation_reason)
            )
        repair_attempts = 0
        while role_result is None and repair_attempts < max(0, repair_retry_limit):
            repair_attempts += 1
            repair_attempted = True
            repair_prompt = _agentic_strict_final_repair_prompt(
                strict_prompt,
                semantic_errors=repair_errors,
                previous_response="\n\n".join(repair_source_responses[-3:]),
                semantic_evidence=semantic_evidence,
            )
            repair_start = time.monotonic()
            try:
                repaired = provider_review(
                    role="agentic_readonly",
                    prompt=repair_prompt,
                    phase="strict_final_repair",
                    response_format=final_response_format(),
                )
            except TimeoutError:
                return degraded_result("provider_call_timeout")
            except Exception:
                return degraded_result("provider_unavailable")
            turns.append(
                {
                    "turn": len(turns) + 1,
                    "type": "llm_call",
                    "phase": "strict_final_repair",
                    "repair_attempt": repair_attempts,
                    "prompt_length": len(repair_prompt),
                    "response_chars": len(repaired),
                    "response_hash": _sha256(
                        repaired.encode("utf-8", errors="replace")
                    ),
                    "latency_ms": round((time.monotonic() - repair_start) * 1000.0, 3),
                }
            )
            try:
                parsed_role_result = _parse_agentic_strict_final_role_result(repaired)
                role_result = validate_agentic_final_role_result(parsed_role_result)
            except FSPRAgenticSemanticReviewError as exc:
                repair_errors = list(exc.errors)
                repair_source_responses.append(repaired)
                last_degradation_reason = "provider_semantic_review_invalid"
                parse_diagnostics.append(
                    {
                        "response_hash": _sha256(
                            repaired.encode("utf-8", errors="replace")
                        ),
                        "response_chars": len(repaired),
                        "has_markdown_fence": "```" in repaired,
                        "has_tool_call": False,
                        "error_type": "provider_semantic_review_invalid",
                        "semantic_errors": repair_errors,
                    }
                )
            except (FSPRProviderSchemaError, json.JSONDecodeError, ValueError):
                diagnostic = _agentic_parse_diagnostic(repaired)
                parse_diagnostics.append(diagnostic)
                repair_errors = None
                repair_source_responses.append(repaired)
                last_degradation_reason = _agentic_degradation_reason_for_diagnostic(
                    diagnostic
                )
        if role_result is None:
            if should_use_incomplete_final_fallback(
                parse_status=last_degradation_reason,
                parsed_role_result=parsed_role_result,
                semantic_errors=repair_errors,
                repair_exhausted=True,
            ):
                return finalized_result(
                    incomplete_final_role_result(last_degradation_reason)
                )
            return degraded_result(last_degradation_reason)
        return finalized_result(role_result)

    def auto_read_priority_path(
        path: str,
        *,
        trace_flag: str,
        allow_required: bool = False,
    ) -> Any | None:
        if path in read_paths:
            return None
        can_auto_read = _agentic_automatic_priority_read_path(
            path,
            root=toolkit.skill_root,
        )
        if not can_auto_read and allow_required:
            required_paths = {
                str(required_path)
                for required_path in coverage_plan.get("required_read_paths", [])
                if isinstance(required_path, str)
            }
            candidate = toolkit.skill_root / path
            can_auto_read = (
                path in required_paths
                and _agentic_path_in_skill_root(toolkit.skill_root, path)
                and not _agentic_runtime_body_excluded_path(path)
                and candidate.is_file()
            )
        if not can_auto_read:
            return None
        auto_tool_start = time.monotonic()
        auto_args = {"path": path}
        try:
            auto_result = toolkit.read_file(path)
        except Exception as exc:  # noqa: BLE001 - record automatic read health.
            auto_result = {"error": str(exc)}
        auto_envelope = _agentic_tool_evidence_envelope(
            tool_name="read_file",
            tool_args=auto_args,
            result=auto_result,
            max_content_chars=max_tool_result_chars,
        )
        if not (isinstance(auto_result, dict) and "error" in auto_result):
            read_paths.add(path)
            if bool(auto_envelope.get("truncated")):
                truncated_read_paths.add(path)
            semantic_item = _agentic_semantic_evidence_item_from_envelope(auto_envelope)
            if semantic_item is not None:
                semantic_evidence.append(semantic_item)
        turns.append(
            {
                "turn": len(turns) + 1,
                "type": "tool_call",
                "tool_name": "read_file",
                "tool_args": _agentic_safe_value(auto_args, max_len=200),
                "path": auto_envelope.get("path"),
                "range": auto_envelope.get("range"),
                "result_hash": auto_envelope.get("sha256_full"),
                "tool_result_length": auto_envelope.get("content_chars"),
                "result_truncated": auto_envelope.get("truncated"),
                trace_flag: True,
                "latency_ms": round((time.monotonic() - auto_tool_start) * 1000.0, 3),
            }
        )
        messages.append(
            {
                "role": "user",
                "content": {
                    trace_flag: True,
                    "tool_result": auto_envelope,
                },
            }
        )
        if isinstance(auto_result, dict) and "error" in auto_result:
            return None
        return auto_result

    def auto_read_required_truncation_followups(
        path: str,
        source_content: Any,
        *,
        trace_flag: str,
    ) -> None:
        if path not in truncated_read_paths or path in range_read_paths:
            return
        followup_source = source_content
        try:
            followup_source = toolkit.read_file(
                path,
                max_bytes=toolkit.MAX_FILE_RANGE_READ_BYTES,
            )
        except Exception:  # noqa: BLE001 - truncated evidence is still usable.
            pass
        for start_line in _agentic_required_truncation_followup_starts(followup_source):
            auto_tool_start = time.monotonic()
            auto_args = {
                "path": path,
                "start_line": start_line,
                "max_lines": 80,
            }
            try:
                auto_result = toolkit.read_file_range(
                    path,
                    start_line=start_line,
                    max_lines=80,
                )
            except Exception as exc:  # noqa: BLE001 - record coverage follow-up health.
                auto_result = {"error": str(exc)}
            auto_envelope = _agentic_tool_evidence_envelope(
                tool_name="read_file_range",
                tool_args=auto_args,
                result=auto_result,
                max_content_chars=max_tool_result_chars,
            )
            if not (isinstance(auto_result, dict) and "error" in auto_result):
                range_read_paths.add(path)
                semantic_item = _agentic_semantic_evidence_item_from_envelope(
                    auto_envelope
                )
                if semantic_item is not None:
                    semantic_evidence.append(semantic_item)
            turns.append(
                {
                    "turn": len(turns) + 1,
                    "type": "tool_call",
                    "tool_name": "read_file_range",
                    "tool_args": _agentic_safe_value(auto_args, max_len=200),
                    "path": auto_envelope.get("path"),
                    "range": auto_envelope.get("range"),
                    "result_hash": auto_envelope.get("sha256_full"),
                    "tool_result_length": auto_envelope.get("content_chars"),
                    "result_truncated": auto_envelope.get("truncated"),
                    trace_flag: True,
                    "latency_ms": round(
                        (time.monotonic() - auto_tool_start) * 1000.0, 3
                    ),
                }
            )
            messages.append(
                {
                    "role": "user",
                    "content": {
                        trace_flag: True,
                        "tool_result": auto_envelope,
                    },
                }
            )

    def auto_read_referenced_priority_paths(
        source_content: Any,
        *,
        source_path: str,
    ) -> None:
        if source_path != "SKILL.md":
            return
        for referenced_path in _agentic_referenced_priority_paths(
            source_content,
            root=toolkit.skill_root,
            limit=2,
        ):
            auto_read_priority_path(
                referenced_path,
                trace_flag="automatic_referenced_priority_read",
            )

    def auto_read_next_coverage_priority_paths() -> None:
        coverage_state = current_coverage_state()
        for priority_path in list(coverage_state.get("next_priority_paths") or []):
            if not isinstance(priority_path, str):
                continue
            auto_read_priority_path(
                priority_path,
                trace_flag="automatic_priority_coverage_read",
            )

    if deterministic_floor_short_circuit and _has_hard_deterministic_findings(
        inventory
    ):
        return deterministic_floor_result()

    def preflight_clean_result() -> FSPRResult | None:
        if inventory.findings or inventory.deterministic_findings:
            return None
        if strict_final_enabled and not coverage_guard_enabled:
            return None
        read_paths_snapshot = set(read_paths)
        range_read_paths_snapshot = set(range_read_paths)
        truncated_read_paths_snapshot = set(truncated_read_paths)
        semantic_evidence_len = len(semantic_evidence)
        turns_len = len(turns)
        messages_len = len(messages)
        for required_path in list(coverage_plan.get("required_read_paths") or []):
            if not isinstance(required_path, str):
                continue
            required_result = auto_read_priority_path(
                required_path,
                trace_flag="automatic_clean_preflight_read",
                allow_required=True,
            )
            if required_path == "SKILL.md" and required_result is not None:
                auto_read_referenced_priority_paths(
                    required_result,
                    source_path=required_path,
                )
            if required_result is not None:
                auto_read_required_truncation_followups(
                    required_path,
                    required_result,
                    trace_flag="automatic_clean_preflight_range_followup",
                )
        auto_read_next_coverage_priority_paths()
        cue_result = cue_backed_read_evidence_result()
        if cue_result is not None:
            return cue_result
        if strict_final_enabled:
            read_paths.clear()
            read_paths.update(read_paths_snapshot)
            range_read_paths.clear()
            range_read_paths.update(range_read_paths_snapshot)
            truncated_read_paths.clear()
            truncated_read_paths.update(truncated_read_paths_snapshot)
            del semantic_evidence[semantic_evidence_len:]
            del turns[turns_len:]
            del messages[messages_len:]
            return None
        return clean_read_evidence_result(
            fast_path="preflight_no_local_or_read_evidence_risk_cues"
        )

    preflight_result = preflight_clean_result()
    if preflight_result is not None:
        return preflight_result

    if timed_out():
        return degraded_result("timeout")

    for turn_index in range(1, max(1, int(max_turns)) + 1):
        if timed_out():
            return degraded_result("timeout")
        prompt = _agentic_readonly_continue_prompt(messages)
        provider_start = time.monotonic()
        try:
            raw = provider_review(
                role="agentic_readonly",
                prompt=prompt,
                phase="exploration",
            )
        except TimeoutError:
            if coverage_ready_for_incomplete_final():
                return incomplete_final_result("provider_call_timeout")
            return degraded_result("provider_call_timeout")
        except Exception:
            if coverage_ready_for_incomplete_final():
                return incomplete_final_result("provider_unavailable")
            return degraded_result("provider_unavailable")
        turns.append(
            {
                "turn": len(turns) + 1,
                "type": "llm_call",
                "prompt_length": len(prompt),
                "response_chars": len(raw),
                "response_hash": _sha256(raw.encode("utf-8", errors="replace")),
                "latency_ms": round((time.monotonic() - provider_start) * 1000.0, 3),
            }
        )

        protocol_payload = _agentic_json_payload(raw)
        if _agentic_mixed_final_tool_payload(protocol_payload):
            if strict_final_enabled and (
                not coverage_guard_enabled or current_coverage_state()["satisfied"]
            ):
                return strict_final_result()
            if coverage_ready_for_incomplete_final():
                return incomplete_final_result("provider_invalid_schema")
            return degraded_result("provider_invalid_schema")

        parsed = _parse_agentic_tool_call_response(raw)
        if parsed is None:
            payload = protocol_payload
            transition_to_final = _agentic_exploration_done_payload(
                payload
            ) or _agentic_final_like_payload(payload)
            if not transition_to_final:
                if payload is not None:
                    if strict_final_enabled and (
                        not coverage_guard_enabled
                        or current_coverage_state()["satisfied"]
                    ):
                        return strict_final_result()
                    if coverage_ready_for_incomplete_final():
                        return incomplete_final_result("provider_invalid_json")
                    return degraded_result("provider_invalid_json")
                if strict_final_enabled and current_coverage_state()["satisfied"]:
                    return strict_final_result()
                if coverage_ready_for_incomplete_final():
                    return incomplete_final_result("provider_invalid_json")
                try:
                    repair_prompt = _agentic_schema_repair_prompt(prompt)
                    repair_start = time.monotonic()
                    repaired = provider_review(
                        role="agentic_readonly",
                        prompt=repair_prompt,
                        phase="exploration_repair",
                    )
                    turns.append(
                        {
                            "turn": len(turns) + 1,
                            "type": "llm_call",
                            "phase": "exploration_repair",
                            "prompt_length": len(repair_prompt),
                            "response_chars": len(repaired),
                            "response_hash": _sha256(
                                repaired.encode("utf-8", errors="replace")
                            ),
                            "latency_ms": round(
                                (time.monotonic() - repair_start) * 1000.0, 3
                            ),
                        }
                    )
                    repaired_parsed = _parse_agentic_tool_call_response(repaired)
                    if repaired_parsed is not None:
                        parsed = repaired_parsed
                    else:
                        repaired_payload = _agentic_json_payload(repaired)
                        transition_to_final = _agentic_exploration_done_payload(
                            repaired_payload
                        ) or _agentic_final_like_payload(repaired_payload)
                        payload = repaired_payload
                        raw = repaired
                    if parsed is None and not transition_to_final:
                        if strict_final_enabled and (
                            not coverage_guard_enabled
                            or current_coverage_state()["satisfied"]
                        ):
                            return strict_final_result()
                        if coverage_ready_for_incomplete_final():
                            return incomplete_final_result("provider_invalid_json")
                        return degraded_result("provider_invalid_json")
                except TimeoutError:
                    if coverage_ready_for_incomplete_final():
                        return incomplete_final_result("provider_call_timeout")
                    return degraded_result("provider_call_timeout")
                except Exception:
                    if coverage_ready_for_incomplete_final():
                        return incomplete_final_result("provider_invalid_json")
                    return degraded_result("provider_invalid_json")
            if parsed is not None:
                pass
            else:
                coverage_state = current_coverage_state()
                if coverage_guard_enabled and not coverage_state["satisfied"]:
                    coverage_incomplete_prompts += 1
                    turns.append(
                        {
                            "turn": len(turns) + 1,
                            "type": "coverage_incomplete",
                            "reason": "read_required_and_priority_paths_before_final",
                            "missing_required_paths": coverage_state[
                                "missing_required_paths"
                            ],
                            "next_priority_paths": coverage_state[
                                "next_priority_paths"
                            ],
                        }
                    )
                    messages.append(
                        {
                            "role": "user",
                            "content": _agentic_coverage_incomplete_prompt(
                                coverage_state
                            ),
                        }
                    )
                    continue
                if strict_final_enabled:
                    return strict_final_result()
                if not _agentic_final_like_payload(payload):
                    if coverage_ready_for_incomplete_final():
                        return incomplete_final_result("provider_invalid_json")
                    return degraded_result("provider_invalid_json")
                try:
                    return finalized_result(parse_inline_final_role_result(raw))
                except FSPRAgenticSemanticReviewError:
                    if coverage_ready_for_incomplete_final():
                        return incomplete_final_result(
                            "provider_semantic_review_invalid"
                        )
                    return degraded_result("provider_semantic_review_invalid")
                except FSPRProviderSchemaError:
                    if coverage_ready_for_incomplete_final():
                        return incomplete_final_result("provider_invalid_schema")
                    return degraded_result("provider_invalid_schema")
                except (json.JSONDecodeError, ValueError):
                    if coverage_ready_for_incomplete_final():
                        return incomplete_final_result("provider_invalid_json")
                    return degraded_result("provider_invalid_json")

        tool_name, tool_args, done = parsed
        if done:
            coverage_state = current_coverage_state()
            if coverage_guard_enabled and not coverage_state["satisfied"]:
                coverage_incomplete_prompts += 1
                turns.append(
                    {
                        "turn": len(turns) + 1,
                        "type": "coverage_incomplete",
                        "reason": "read_required_and_priority_paths_before_final",
                        "missing_required_paths": coverage_state[
                            "missing_required_paths"
                        ],
                        "next_priority_paths": coverage_state["next_priority_paths"],
                    }
                )
                messages.append(
                    {
                        "role": "user",
                        "content": _agentic_coverage_incomplete_prompt(coverage_state),
                    }
                )
                continue
            if strict_final_enabled:
                return strict_final_result()
            return incomplete_final_result("provider_invalid_json")
        if tool_name not in _FSPR_AGENTIC_READONLY_TOOLS:
            return degraded_result("agentic_tool_not_allowed")
        if (
            strict_final_enabled
            and coverage_guard_enabled
            and current_coverage_state()["satisfied"]
        ):
            return strict_final_result()
        if remaining_tool_calls <= 0:
            if (
                not coverage_guard_enabled or current_coverage_state()["satisfied"]
            ) and strict_final_enabled:
                return strict_final_result()
            if coverage_ready_for_incomplete_final():
                return incomplete_final_result("agentic_tool_budget_exhausted")
            return degraded_result("agentic_tool_budget_exhausted")
        tool_start = time.monotonic()
        try:
            tool_result = _execute_agentic_readonly_tool(toolkit, tool_name, tool_args)
        except Exception as exc:  # noqa: BLE001 - record as tool health, not skill risk.
            tool_result = {"error": str(exc)}
        remaining_tool_calls -= 1
        safe_tool_args = _agentic_safe_tool_args(toolkit, tool_args)
        envelope = _agentic_tool_evidence_envelope(
            tool_name=tool_name,
            tool_args=safe_tool_args,
            result=tool_result,
            max_content_chars=max_tool_result_chars,
        )
        if tool_name == "search_codebase" and _agentic_search_counts_as_followup(
            safe_tool_args.get("pattern")
        ):
            searches_performed += 1
        if tool_name in {"read_file", "read_file_range"} and not (
            isinstance(tool_result, dict) and "error" in tool_result
        ):
            safe_path = str(envelope.get("path") or "")
            if safe_path and not safe_path.startswith("<"):
                if tool_name == "read_file":
                    read_paths.add(safe_path)
                    if bool(envelope.get("truncated")):
                        truncated_read_paths.add(safe_path)
                elif tool_name == "read_file_range":
                    range_read_paths.add(safe_path)
                semantic_item = _agentic_semantic_evidence_item_from_envelope(envelope)
                if semantic_item is not None:
                    semantic_evidence.append(semantic_item)
        turns.append(
            {
                "turn": len(turns) + 1,
                "type": "tool_call",
                "tool_name": tool_name,
                "tool_args": _agentic_safe_value(safe_tool_args, max_len=200),
                "path": envelope.get("path"),
                "range": envelope.get("range"),
                "result_hash": envelope.get("sha256_full"),
                "tool_result_length": envelope.get("content_chars"),
                "result_truncated": envelope.get("truncated"),
                "latency_ms": round((time.monotonic() - tool_start) * 1000.0, 3),
            }
        )
        messages.append(
            {
                "role": "assistant",
                "content": json.dumps(
                    {
                        "tool_call": {"name": tool_name, "arguments": safe_tool_args},
                        "done": False,
                    },
                    ensure_ascii=True,
                    sort_keys=True,
                ),
            }
        )
        messages.append({"role": "user", "content": {"tool_result": envelope}})
        auto_safe_path = str(envelope.get("path") or "")
        required_paths = {
            str(path)
            for path in coverage_plan.get("required_read_paths", [])
            if isinstance(path, str)
        }
        if (
            tool_name == "read_file"
            and auto_safe_path in required_paths
            and auto_safe_path not in range_read_paths
            and bool(envelope.get("truncated"))
            and not (isinstance(tool_result, dict) and "error" in tool_result)
        ):
            followup_source = tool_result
            try:
                followup_source = toolkit.read_file(
                    auto_safe_path,
                    max_bytes=toolkit.MAX_FILE_RANGE_READ_BYTES,
                )
            except Exception:  # noqa: BLE001 - truncated evidence is still usable.
                followup_source = tool_result
            for start_line in _agentic_required_truncation_followup_starts(
                followup_source
            ):
                auto_tool_start = time.monotonic()
                auto_args = {
                    "path": auto_safe_path,
                    "start_line": start_line,
                    "max_lines": 80,
                }
                try:
                    auto_result = toolkit.read_file_range(
                        auto_safe_path,
                        start_line=start_line,
                        max_lines=80,
                    )
                except Exception as exc:  # noqa: BLE001 - record coverage follow-up health.
                    auto_result = {"error": str(exc)}
                auto_envelope = _agentic_tool_evidence_envelope(
                    tool_name="read_file_range",
                    tool_args=auto_args,
                    result=auto_result,
                    max_content_chars=max_tool_result_chars,
                )
                if not (isinstance(auto_result, dict) and "error" in auto_result):
                    range_read_paths.add(auto_safe_path)
                    semantic_item = _agentic_semantic_evidence_item_from_envelope(
                        auto_envelope
                    )
                    if semantic_item is not None:
                        semantic_evidence.append(semantic_item)
                turns.append(
                    {
                        "turn": len(turns) + 1,
                        "type": "tool_call",
                        "tool_name": "read_file_range",
                        "tool_args": _agentic_safe_value(auto_args, max_len=200),
                        "path": auto_envelope.get("path"),
                        "range": auto_envelope.get("range"),
                        "result_hash": auto_envelope.get("sha256_full"),
                        "tool_result_length": auto_envelope.get("content_chars"),
                        "result_truncated": auto_envelope.get("truncated"),
                        "automatic_coverage_followup": True,
                        "latency_ms": round(
                            (time.monotonic() - auto_tool_start) * 1000.0, 3
                        ),
                    }
                )
                messages.append(
                    {
                        "role": "user",
                        "content": {
                            "automatic_coverage_followup": True,
                            "tool_result": auto_envelope,
                        },
                    }
                )
                if not (isinstance(auto_result, dict) and "error" in auto_result):
                    auto_read_referenced_priority_paths(
                        auto_result,
                        source_path=auto_safe_path,
                    )
        if (
            tool_name == "read_file"
            and auto_safe_path == "SKILL.md"
            and not (isinstance(tool_result, dict) and "error" in tool_result)
        ):
            auto_read_referenced_priority_paths(tool_result, source_path=auto_safe_path)
            auto_read_next_coverage_priority_paths()
        cue_result = cue_backed_read_evidence_result()
        if cue_result is not None:
            return cue_result
        clean_result = clean_read_evidence_result()
        if clean_result is not None:
            return clean_result
        if ready_for_fast_strict_final_after_tool():
            return strict_final_result()

    cue_result = cue_backed_read_evidence_result()
    if cue_result is not None:
        return cue_result
    clean_result = clean_read_evidence_result()
    if clean_result is not None:
        return clean_result
    if strict_final_enabled and (
        not coverage_guard_enabled or current_coverage_state()["satisfied"]
    ):
        return strict_final_result()
    if coverage_ready_for_incomplete_final():
        return incomplete_final_result("agentic_max_turns_exceeded")
    return degraded_result("agentic_max_turns_exceeded")
