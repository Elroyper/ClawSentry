"""Gateway-owned skill trust FSPR review integration helpers."""

from __future__ import annotations

import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from clawsentry.gateway.config.detection_config import DetectionConfig
from clawsentry.gateway.models import CanonicalEvent, DecisionContext, EventType, RuntimeSkillRef
from clawsentry.gateway.trust.skill_trust import AdmissionScanner, load_skill_trust_runtime_metadata_bundle

_FSPR_REVIEW_CACHE_MAX_ENTRIES = 256
_FSPR_REVIEW_CACHE: dict[str, Any] = {}
_LOGGER = logging.getLogger("clawsentry.fspr")


def _trim_fspr_review_cache(cache: dict[str, Any] | None = None) -> None:
    review_cache = _FSPR_REVIEW_CACHE if cache is None else cache
    while len(review_cache) > _FSPR_REVIEW_CACHE_MAX_ENTRIES:
        review_cache.pop(next(iter(review_cache)))


def _skill_trust_identity_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(value or "").strip().lower()).strip("-")


def _gateway_owned_skill_trust_bundle():
    metadata_path = os.environ.get("CS_SKILL_TRUST_METADATA_PATH")
    if not metadata_path:
        return None
    path = Path(metadata_path)
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    return load_skill_trust_runtime_metadata_bundle(payload)


def _trusted_gateway_observed(
    meta: dict[str, Any],
    context: DecisionContext | None,
) -> dict[str, Any] | None:
    observed = meta.get("_gateway_observed")
    if not isinstance(observed, dict):
        return None
    adapter_origin = str(observed.get("adapter_origin") or "")
    caller_adapter = str(context.caller_adapter if context else "")
    trusted_origin = (
        adapter_origin == "a3s_gateway_harness"
        and caller_adapter in {"a3s_gateway_harness", "a3s-adapter.v1"}
    )
    if not trusted_origin:
        return None
    return observed


def _gateway_current_runner_contract_id(
    meta: dict[str, Any],
    context: DecisionContext | None,
) -> str | None:
    observed = _trusted_gateway_observed(meta, context)
    if observed is None:
        return None
    value = observed.get("current_runner_contract_id")
    return _safe_identity_label(value, max_len=256) if value else None


def _gateway_observed_runtime_skill_refs(
    meta: dict[str, Any],
    context: DecisionContext | None,
    event: CanonicalEvent,
) -> list[RuntimeSkillRef]:
    observed = _trusted_gateway_observed(meta, context)
    if observed is None:
        return []
    adapter_origin = str(observed.get("adapter_origin") or "")
    values = observed.get("runtime_skill_refs")
    if not isinstance(values, list):
        return []
    refs: list[RuntimeSkillRef] = []
    for value in values[:20]:
        if not isinstance(value, dict):
            continue
        try:
            ref = RuntimeSkillRef.model_validate(value)
        except ValidationError:
            continue
        if ref.adapter_observed and ref.adapter_origin == adapter_origin:
            refs.append(ref)
    return refs


def _gateway_owned_skill_trust_metadata(presented_name: Any) -> dict[str, Any]:
    if not presented_name:
        return {}
    bundle = _gateway_owned_skill_trust_bundle()
    if bundle is None:
        return {}
    raw_by_skill = bundle.raw_metadata_by_skill
    wanted = _skill_trust_identity_key(presented_name)
    for key, value in raw_by_skill.items():
        if _skill_trust_identity_key(key) == wanted and isinstance(value, dict):
            owned = {
                field: value[field]
                for field in (
                    "canonical_skill_id",
                    "canonical_name",
                    "framework",
                    "scope",
                    "control_language_findings",
                    "provenance_label_conflict",
                    "admission_scan_id",
                    "admission_risk",
                    "policy_fingerprint",
                    "metadata_record_id",
                    "source_root_path",
                    "source_root_path_hash",
                    "allowed_runtime_roots",
                    "allowed_runtime_root_hashes",
                    "mirror_integrity_mode",
                    "trusted_runner_contract_id",
                    "runner_contract_attestation_required",
                    "skill_root_path",
                    "skill_root_path_hash",
                )
                if field in value
            }
            owned["gateway_owned_metadata"] = True
            return owned
    return {}


def _apply_gateway_owned_first_use_scan(
    raw_metadata: dict[str, Any],
    *,
    deadline_at: float | None = None,
) -> None:
    """Run synchronous first-use scan only for Gateway-owned skill metadata."""

    if raw_metadata.get("admission_scan_id") or not raw_metadata.get("gateway_owned_metadata"):
        return
    root_value = raw_metadata.get("skill_root_path")
    if not isinstance(root_value, str) or not root_value.strip():
        return
    raw_metadata["admission_scan_requested"] = True
    if deadline_at is not None and (deadline_at - time.monotonic()) * 1000 <= 25:
        raw_metadata["admission_scan_budget_exhausted"] = True
        return
    try:
        root = Path(root_value)
        if not root.is_dir() or not (root / "SKILL.md").is_file():
            raw_metadata["admission_scan_failure_class"] = "input_invalid"
            return
        report = AdmissionScanner().scan(root, deadline_at=deadline_at)
    except TimeoutError:
        raw_metadata["admission_scan_budget_exhausted"] = True
        return
    except Exception:
        raw_metadata["admission_scan_failure_class"] = "scan_failed"
        return
    raw_metadata["admission_scan_id"] = report.scan_id
    raw_metadata["admission_risk"] = report.admission_risk.value
    raw_metadata["policy_fingerprint"] = report.policy_fingerprint
    raw_metadata["content_hashes"] = report.content_hashes


def _fspr_timing_mode_for_event(
    event: CanonicalEvent,
    detection_config: DetectionConfig | None,
) -> str | None:
    if detection_config is None or not detection_config.skill_trust_fspr_enabled:
        return None
    if (
        event.event_type == EventType.PRE_ACTION
        and detection_config.skill_trust_fspr_pre_use_enabled
    ):
        return "pre_use_gate"
    if (
        event.event_type == EventType.POST_ACTION
        and detection_config.skill_trust_fspr_post_action_enabled
    ):
        return "post_action_incremental_evidence"
    return None


def _fspr_provider_sync_enabled(detection_config: DetectionConfig | None) -> bool:
    if detection_config is None or not detection_config.skill_trust_fspr_provider_enabled:
        return False
    mode = str(detection_config.mode or "normal").strip().lower()
    profiles = {
        str(profile).strip().lower()
        for profile in detection_config.skill_trust_fspr_provider_sync_profiles
        if str(profile).strip()
    }
    return mode in profiles


class _UnavailableFSPRProvider:
    """Fail loudly when config requested provider-backed FSPR but none resolved."""

    def review_role(
        self,
        *,
        role: str,
        prompt: str,
        response_format: dict[str, object] | None = None,
    ) -> str:
        del role, prompt, response_format
        raise RuntimeError("provider_unavailable")


def _fspr_failure_reason_for_exception(exc: BaseException) -> str:
    message = str(exc or "").strip()
    normalized = message.split(":", 1)[0].strip().lower()
    if isinstance(exc, TimeoutError):
        return "provider_call_timeout"
    if normalized.startswith("provider_"):
        return normalized
    if "unknown scheme for proxy url" in message.lower():
        return "provider_unavailable"
    if "proxy url" in message.lower() and "socks://" in message.lower():
        return "provider_unavailable"
    if "inventory" in message.lower():
        return "inventory_failure"
    if isinstance(exc, (FileNotFoundError, PermissionError, OSError)):
        return "inventory_failure"
    return "runner_exception"


def _fspr_failure_message(exc: BaseException) -> str:
    message = str(exc or "").strip()
    if not message:
        return type(exc).__name__
    return message[:500]


def _fspr_review_mode_for_config(
    detection_config: DetectionConfig | None,
) -> str:
    review_mode = str(
        getattr(detection_config, "skill_trust_fspr_review_mode", "agentic-readonly")
        if detection_config is not None
        else "agentic-readonly"
    ).strip().lower()
    role_set = str(
        getattr(detection_config, "skill_trust_fspr_role_set", "default")
        if detection_config is not None
        else "default"
    ).strip().lower()
    if role_set not in {"", "default", "final-only", "final_only"}:
        return f"unknown_review_mode:removed_role_set:{role_set}"
    if (
        role_set in {"final-only", "final_only"}
        and review_mode in {"", "default", "agentic-readonly", "agentic_readonly"}
    ):
        return "final-only"
    if review_mode in {"", "default", "agentic-readonly", "agentic_readonly"}:
        return "agentic-readonly"
    if review_mode in {"final-only", "final_only"}:
        return "final-only"
    return f"unknown_review_mode:{review_mode}"


def _fspr_review_summary(
    *,
    detection_config: DetectionConfig | None,
    review_state: str,
    timing_mode: str | None = None,
    review_mode: str | None = None,
    provider_used: bool = False,
    verdict: str | None = None,
    severity: str | None = None,
    confidence: float | None = None,
    degraded: bool | None = None,
    degradation_reason: str | None = None,
    failure_reason: str | None = None,
    reason: str | None = None,
) -> dict[str, object]:
    return {
        key: value
        for key, value in {
            "schema": "clawsentry.fspr_review_summary.v1",
            "enabled": bool(getattr(detection_config, "skill_trust_fspr_enabled", False)),
            "pre_use_enabled": bool(getattr(detection_config, "skill_trust_fspr_pre_use_enabled", False)),
            "post_action_enabled": bool(getattr(detection_config, "skill_trust_fspr_post_action_enabled", False)),
            "review_state": review_state,
            "timing_mode": timing_mode,
            "review_mode": review_mode,
            "provider_sync_enabled": bool(_fspr_provider_sync_enabled(detection_config)),
            "provider_used": provider_used,
            "verdict": verdict,
            "severity": severity,
            "confidence": confidence,
            "degraded": degraded,
            "degradation_reason": degradation_reason,
            "failure_reason": failure_reason,
            "reason": reason,
        }.items()
        if value is not None
    }


def _apply_gateway_owned_first_use_package_review(
    raw_metadata: dict[str, Any],
    *,
    event: CanonicalEvent,
    detection_config: DetectionConfig | None,
    deadline_at: float | None = None,
    run_first_use_skill_package_review_fn: Any | None = None,
    run_agentic_readonly_fspr_review_fn: Any | None = None,
    build_provider_from_env_fn: Any | None = None,
    fspr_llm_role_provider_cls: Any | None = None,
    evidence_capsule_schema_version: str = "clawsentry.fspr_evidence_capsule.v2",
    review_cache: dict[str, Any] | None = None,
) -> None:
    """Attach bounded FSPR evidence only for Gateway-owned skill metadata."""

    existing_review = raw_metadata.get("first_use_package_review")
    if isinstance(existing_review, dict):
        raw_metadata.setdefault(
            "fspr_review_summary",
            _fspr_review_summary(
                detection_config=detection_config,
                review_state="degraded" if existing_review.get("degraded") else "completed",
                timing_mode=existing_review.get("timing_mode"),
                verdict=existing_review.get("verdict"),
                severity=existing_review.get("severity"),
                confidence=existing_review.get("confidence"),
                degraded=bool(existing_review.get("degraded", False)),
                degradation_reason=existing_review.get("degradation_reason"),
            ),
        )
        return
    if not raw_metadata.get("gateway_owned_metadata"):
        raw_metadata["fspr_review_summary"] = _fspr_review_summary(
            detection_config=detection_config,
            review_state="not_gateway_owned",
        )
        return
    if detection_config is not None and not detection_config.skill_trust_fspr_enabled:
        raw_metadata["fspr_review_summary"] = _fspr_review_summary(
            detection_config=detection_config,
            review_state="disabled_by_config",
        )
        return
    timing_mode = _fspr_timing_mode_for_event(event, detection_config)
    if timing_mode is None:
        raw_metadata["fspr_review_summary"] = _fspr_review_summary(
            detection_config=detection_config,
            review_state="not_applicable",
            reason="timing_mode_unavailable",
        )
        return
    root_value = raw_metadata.get("skill_root_path")
    if not isinstance(root_value, str) or not root_value.strip():
        raw_metadata["fspr_review_summary"] = _fspr_review_summary(
            detection_config=detection_config,
            review_state="not_applicable",
            timing_mode=timing_mode,
            reason="skill_root_path_missing",
        )
        return
    timeout_s = (
        max(0.0, float(detection_config.skill_trust_fspr_timeout_ms) / 1000.0)
        if detection_config is not None
        else 120.0
    )
    if deadline_at is not None:
        timeout_s = min(timeout_s, max(0.0, deadline_at - time.monotonic()))
    max_turns = max(
        1,
        int(
            getattr(
                detection_config,
                "skill_trust_fspr_max_turns",
                16,
            )
        ),
    )
    provider = None
    review_mode = _fspr_review_mode_for_config(detection_config)
    if _fspr_provider_sync_enabled(detection_config):
        if build_provider_from_env_fn is None:
            raw_provider = None
        else:
            raw_provider = build_provider_from_env_fn()
        if raw_provider is not None and fspr_llm_role_provider_cls is not None:
            provider = fspr_llm_role_provider_cls(raw_provider, timeout_ms=timeout_s * 1000.0)
        else:
            provider = _UnavailableFSPRProvider()
    try:
        active_cache = _FSPR_REVIEW_CACHE if review_cache is None else review_cache
        cache = (
            active_cache
            if detection_config is None or detection_config.skill_trust_fspr_cache_enabled
            else None
        )
        cache_enabled = (
            detection_config.skill_trust_fspr_cache_enabled
            if detection_config is not None
            else True
        )
        if review_mode == "agentic-readonly" and provider is not None:
            if run_agentic_readonly_fspr_review_fn is None:
                raise RuntimeError("agentic_fspr_runner_unavailable")
            result = run_agentic_readonly_fspr_review_fn(
                root_value,
                timeout_s=timeout_s,
                timing_mode=timing_mode,
                registry_snapshot_id=str(raw_metadata.get("registry_snapshot_id") or "unknown"),
                policy_fingerprint=str(raw_metadata.get("policy_fingerprint") or "unknown"),
                cache=cache,
                cache_enabled=cache_enabled,
                provider=provider,
                max_turns=max_turns,
            )
        else:
            selected_roles: tuple[str, ...] | None = None
            if review_mode == "final-only" and provider is not None:
                selected_roles = ()
            elif review_mode.startswith("unknown_review_mode:"):
                selected_roles = (
                    f"unknown_role_set:{review_mode.removeprefix('unknown_review_mode:')}",
                )
            if run_first_use_skill_package_review_fn is None:
                raise RuntimeError("fspr_runner_unavailable")
            result = run_first_use_skill_package_review_fn(
                root_value,
                timeout_s=timeout_s,
                timing_mode=timing_mode,
                registry_snapshot_id=str(raw_metadata.get("registry_snapshot_id") or "unknown"),
                policy_fingerprint=str(raw_metadata.get("policy_fingerprint") or "unknown"),
                policy_profile=str(getattr(detection_config, "mode", None) or "normal"),
                budget_class=(
                    "custom"
                    if detection_config is not None
                    and detection_config.skill_trust_fspr_timeout_ms != 120_000
                    else "default"
                ),
                cache=cache,
                cache_enabled=cache_enabled,
                provider=provider,
                selected_roles=selected_roles,
            )
        _trim_fspr_review_cache(active_cache)
    except Exception as exc:
        failure_reason = _fspr_failure_reason_for_exception(exc)
        _LOGGER.exception(
            "Gateway-owned FSPR review failed: reason=%s type=%s",
            failure_reason,
            type(exc).__name__,
        )
        raw_metadata["fspr_review_summary"] = _fspr_review_summary(
            detection_config=detection_config,
            review_state="failed",
            timing_mode=timing_mode,
            review_mode=review_mode,
            provider_used=provider is not None,
            verdict="insufficient_evidence",
            severity="low",
            confidence=0.0,
            degraded=True,
            degradation_reason=failure_reason,
            failure_reason=failure_reason,
        )
        raw_metadata["first_use_package_review"] = {
            "schema": "clawsentry.first_use_skill_package_review.v1",
            "timing_mode": timing_mode,
            "verdict": "insufficient_evidence",
            "severity": "low",
            "confidence": 0.0,
            "deterministic_findings_preserved": True,
            "role_results": [
                {
                    "role": "deterministic_inventory",
                    "verdict": "insufficient_evidence",
                    "findings": [],
                    "degraded": True,
                    "coverage": "degraded",
                    "degradation_reason": failure_reason,
                }
            ],
            "final_findings": [],
            "evidence_capsule": {
                "schema": evidence_capsule_schema_version,
                "failure_class": failure_reason,
                "failure_type": type(exc).__name__,
                "failure_message": _fspr_failure_message(exc),
            },
            "degraded": True,
            "degradation_reason": failure_reason,
            "cache_hit": False,
            "cache": {"hit": False, "reason": "not_cached"},
        }
        return
    raw_metadata["fspr_review_summary"] = _fspr_review_summary(
        detection_config=detection_config,
        review_state="degraded" if result.degraded else "completed",
        timing_mode=result.timing_mode,
        review_mode=review_mode,
        provider_used=provider is not None,
        verdict=result.verdict,
        severity=result.severity,
        confidence=result.confidence,
        degraded=result.degraded,
        degradation_reason=result.degradation_reason,
    )
    raw_metadata["first_use_package_review"] = result.model_dump(mode="json")


def _safe_identity_label(value: Any, *, max_len: int = 256) -> str | None:
    if not isinstance(value, str):
        return None
    label = value.strip()
    if not label or len(label) > max_len or _is_pathlike_label(label):
        return None
    return label[:max_len]


def _is_pathlike_label(value: str) -> bool:
    return (
        "/" in value
        or "\\" in value
        or value.startswith("~")
        or "://" in value
        or re.search(r"\b[A-Za-z]:\\", value) is not None
    )
