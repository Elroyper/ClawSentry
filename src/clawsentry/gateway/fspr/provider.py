"""FSPR provider bridge, replay, and provider response normalization."""

from __future__ import annotations

import asyncio
import inspect
import json
import os
import re
import threading
from pathlib import Path
from typing import Any, Callable, Sequence

from .cache import _fspr_cache_summary
from .static_rules import normalize_fspr_findings
from .types import (
    FSPRInventory,
    FSPRProviderSchemaError,
    FSPRResult,
    FSPRRoleProvider,
    _sha256,
)


def _markdown_text_fence(text: str) -> str:
    longest = 0
    current = 0
    for char in text:
        if char == "`":
            current += 1
            longest = max(longest, current)
        else:
            current = 0
    fence = "`" * max(3, longest + 1)
    return f"{fence}text\n{text}\n{fence}"


def _fspr_replay_needs_summary(*, phase: str, prompt: str, response: str) -> bool:
    phase_l = str(phase or "").lower()
    combined = f"{prompt}\n{response}"
    return bool(
        phase_l.startswith("strict_final")
        or "clawsentry.fspr_agentic_tool_evidence.v1" in combined
        or '"tool_result"' in combined
        or "semantic_evidence" in combined
    )


def _fspr_replay_summary_text(value: str, *, label: str) -> str:
    text = str(value or "")
    return json.dumps(
        {
            "redacted": True,
            "redaction_reason": "agentic_evidence_payload",
            f"{label}_chars": len(text),
            f"{label}_sha256": _sha256(text.encode("utf-8", errors="replace")),
        },
        ensure_ascii=True,
        sort_keys=True,
    )


def _fspr_replay_redaction_enabled() -> bool:
    raw = os.environ.get("CS_FSPR_REVIEW_REPLAY_RAW", "")
    return str(raw).strip().lower() not in {"1", "true", "yes", "on"}


def _append_fspr_replay_call(
    *,
    role: str,
    phase: str,
    prompt: str,
    response: str,
    status: str,
    elapsed_ms: float,
    response_format: dict[str, object] | None,
) -> None:
    replay_path = os.environ.get("CS_FSPR_REVIEW_REPLAY_PATH", "").strip()
    if not replay_path:
        return
    try:
        if _fspr_replay_redaction_enabled() and _fspr_replay_needs_summary(
            phase=phase,
            prompt=prompt,
            response=response,
        ):
            prompt = _fspr_replay_summary_text(prompt, label="prompt")
            response = _fspr_replay_summary_text(response, label="response")
        path = Path(replay_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        existing = (
            path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
        )
        call_index = existing.count("### FSPR Call ") + 1
        chunk = "\n".join(
            [
                f"### FSPR Call {call_index}: {phase}",
                "",
                f"- role: {role}",
                f"- status: {status}",
                f"- elapsed_ms: {round(float(elapsed_ms), 3)}",
                f"- structured_output_requested: {str(response_format is not None).lower()}",
                "",
                "#### Prompt",
                "",
                _markdown_text_fence(prompt),
                "",
                "#### Response",
                "",
                _markdown_text_fence(response),
                "",
            ]
        )
        with path.open("a", encoding="utf-8") as handle:
            if existing and not existing.endswith("\n"):
                handle.write("\n")
            if existing:
                handle.write("\n")
            handle.write(chunk)
    except Exception:
        return


_FSPR_REPLAY_OUTER_WRAPPER_ATTR = "_clawsentry_fspr_replay_outer_wrapper_active"
_MISSING_ATTR = object()
_FSPR_DEFAULT_MAX_TOKENS = 1024
_FSPR_AGENTIC_STRICT_FINAL_MAX_TOKENS = 1152
def _fspr_review_role_max_tokens(
    *,
    role: str,
    prompt: str,
    response_format: dict[str, object] | None = None,
) -> int:
    prompt_text = str(prompt or "")
    if str(role or "") == "agentic_readonly" and (
        response_format is not None
        or prompt_text.startswith("Strict final JSON phase for agentic-readonly FSPR.")
        or "previous strict final response was not valid JSON" in prompt_text
    ):
        return _FSPR_AGENTIC_STRICT_FINAL_MAX_TOKENS
    return _FSPR_DEFAULT_MAX_TOKENS


def _call_provider_review_role_with_replay_suppressed(
    provider: FSPRRoleProvider,
    *,
    role: str,
    prompt: str,
    response_format: dict[str, object] | None = None,
) -> str:
    previous = getattr(provider, _FSPR_REPLAY_OUTER_WRAPPER_ATTR, _MISSING_ATTR)
    can_restore = True
    try:
        setattr(provider, _FSPR_REPLAY_OUTER_WRAPPER_ATTR, True)
    except Exception:
        can_restore = False
    try:
        if response_format is None:
            return provider.review_role(role=role, prompt=prompt)
        return provider.review_role(
            role=role,
            prompt=prompt,
            response_format=response_format,
        )
    finally:
        if can_restore:
            try:
                if previous is _MISSING_ATTR:
                    delattr(provider, _FSPR_REPLAY_OUTER_WRAPPER_ATTR)
                else:
                    setattr(provider, _FSPR_REPLAY_OUTER_WRAPPER_ATTR, previous)
            except Exception:
                pass


class FSPRLLMRoleProvider:
    """Synchronous FSPR role provider bridge for the shared async LLM provider."""

    def __init__(self, provider: Any, *, timeout_ms: float = 120_000.0) -> None:
        self._provider = provider
        self._timeout_ms = max(float(timeout_ms), 1.0)

    def review_role(
        self,
        *,
        role: str,
        prompt: str,
        response_format: dict[str, object] | None = None,
    ) -> str:
        system_prompt = (
            "You are a ClawSentry First-Use Skill Package Review role. "
            "Return compact JSON only."
        )
        result: dict[str, Any] = {}

        def run_complete() -> None:
            try:
                kwargs: dict[str, Any] = {
                    "system_prompt": system_prompt,
                    "user_message": prompt,
                    "timeout_ms": self._timeout_ms,
                    "max_tokens": _fspr_review_role_max_tokens(
                        role=role,
                        prompt=prompt,
                        response_format=response_format,
                    ),
                }
                if response_format is not None:
                    kwargs["response_format"] = response_format

                async def complete_once() -> str:
                    try:
                        return str(await self._provider.complete(**kwargs))
                    finally:
                        close = getattr(self._provider, "aclose", None)
                        if callable(close):
                            close_result = close()
                            if inspect.isawaitable(close_result):
                                await close_result

                result["value"] = asyncio.run(complete_once())
            except Exception as exc:
                result["error"] = exc

        thread = threading.Thread(target=run_complete, daemon=True)
        thread.start()
        thread.join(self._timeout_ms / 1000.0)
        if thread.is_alive():
            raise TimeoutError("provider_timeout")
        if "error" in result:
            raise result["error"]
        return str(result.get("value") or "")


def _role_degradation_result(role: str, reason: str) -> dict[str, Any]:
    return {
        "role": role,
        "verdict": "insufficient_evidence",
        "findings": [],
        "degraded": True,
        "coverage": "degraded",
        "degradation_reason": reason,
    }


def _parse_provider_role_result(
    role: str,
    raw: str,
    *,
    semantic_dimension_review_sanitizer: Callable[[Any], list[dict[str, Any]]]
    | None = None,
) -> dict[str, Any]:
    payload = json.loads(_extract_provider_json(raw))
    if not isinstance(payload, dict):
        raise ValueError("role result must be a JSON object")
    forbidden = {
        "recommended_action",
        "recommended_policy_action",
        "recommended_review_tier",
    }
    if any(field in payload for field in forbidden):
        raise FSPRProviderSchemaError("provider_invalid_schema")
    result = dict(payload)
    result.setdefault("role", role)
    result["verdict"] = _normalize_provider_verdict(result)
    result["severity"] = _normalize_provider_severity(result)
    result["confidence"] = _normalize_provider_confidence(result.get("confidence"))
    result["findings"] = normalize_fspr_findings(
        _normalize_provider_findings(result.get("findings"))
    )
    if (
        "semantic_dimension_review" in result
        and semantic_dimension_review_sanitizer is not None
    ):
        result["semantic_dimension_review"] = semantic_dimension_review_sanitizer(
            result.get("semantic_dimension_review")
        )
    result.setdefault("degraded", False)
    return result


def _extract_provider_json(raw: str) -> str:
    text = str(raw or "").strip()
    for fenced in re.finditer(
        r"```(?:json)?\s*(.*?)\s*```", text, flags=re.IGNORECASE | re.DOTALL
    ):
        objects = _json_objects_in_text(fenced.group(1).strip())
        if objects:
            return objects[0]
    objects = _json_objects_in_text(text)
    return objects[0] if objects else text


def _iter_provider_json_objects(raw: str) -> Sequence[str]:
    text = str(raw or "").strip()
    sources = [
        fenced.group(1).strip()
        for fenced in re.finditer(
            r"```(?:json)?\s*(.*?)\s*```", text, flags=re.IGNORECASE | re.DOTALL
        )
    ]
    sources.append(text)
    objects: list[str] = []
    seen: set[str] = set()
    for source in sources:
        for item in _json_objects_in_text(source):
            if item in seen:
                continue
            objects.append(item)
            seen.add(item)
    return objects


def _json_objects_in_text(text: str) -> list[str]:
    decoder = json.JSONDecoder()
    objects: list[str] = []
    offset = 0
    while True:
        start = text.find("{", offset)
        if start < 0:
            break
        try:
            _, end = decoder.raw_decode(text[start:])
        except json.JSONDecodeError:
            offset = start + 1
            continue
        objects.append(text[start : start + end])
        offset = start + 1
    return objects


def _normalize_provider_verdict(payload: dict[str, Any]) -> str:
    allowed = {"consistent", "suspicious", "inconsistent", "insufficient_evidence"}
    for key in ("verdict", "final_verdict", "decision", "status", "adjudication"):
        raw = payload.get(key)
        if raw is None:
            continue
        value = str(raw).strip().lower().replace("-", "_").replace(" ", "_")
        if value in allowed:
            return value
        if value in {
            "reject",
            "rejected",
            "deny",
            "denied",
            "block",
            "blocked",
            "unsafe",
            "malicious",
        }:
            return "inconsistent"
        if value in {
            "flag",
            "flagged",
            "warn",
            "warning",
            "review",
            "needs_review",
            "risky",
        }:
            return "suspicious"
        if value in {
            "allow",
            "allowed",
            "approve",
            "approved",
            "safe",
            "pass",
            "passed",
            "ok",
            "clean",
            "clear",
            "benign",
            "no_risk",
            "not_suspicious",
        }:
            return "consistent"
    approved = payload.get("approved")
    if approved is False:
        return "inconsistent"
    if approved is True:
        return "consistent"
    return "insufficient_evidence"


def _normalize_provider_severity(payload: dict[str, Any]) -> str:
    allowed = {"low", "medium", "high", "critical"}
    for key in ("severity", "risk_level", "risk", "level"):
        raw = payload.get(key)
        if raw is None:
            continue
        value = str(raw).strip().lower().replace("-", "_").replace(" ", "_")
        if value in allowed:
            return value
        if value in {"none", "no_risk", "minimal", "negligible", "informational"}:
            return "low"
        if value in {"severe", "blocker"}:
            return "critical"
        if value in {"moderate", "warning"}:
            return "medium"
    verdict = _normalize_provider_verdict(payload)
    if verdict == "inconsistent":
        return "high"
    if verdict == "suspicious":
        return "medium"
    return "low"


def _normalize_provider_confidence(value: Any) -> float:
    if value is None:
        return 0.0
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        return max(0.0, min(1.0, float(value)))
    normalized = str(value).strip().lower()
    if normalized in {"high", "certain", "strong"}:
        return 0.85
    if normalized in {"medium", "moderate"}:
        return 0.6
    if normalized in {"low", "weak"}:
        return 0.35
    try:
        return max(0.0, min(1.0, float(normalized)))
    except ValueError:
        return 0.0


def _normalize_provider_findings(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if isinstance(value, dict):
        return [dict(value)]
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, dict)]


def _provider_schema_repair_prompt(role: str, original_prompt: str) -> str:
    return (
        f"{original_prompt}\n\n"
        "The previous provider response was not a valid JSON object for the "
        "First-Use Skill Package Review role result schema. Retry once and "
        "return only one JSON object with these fields: role, verdict, severity, "
        "confidence, findings, degraded. Do not wrap it in prose or markdown."
    )


def _admission_recommendation_for_inventory(
    inventory: FSPRInventory,
    *,
    cache_key: str,
    registry_snapshot_id: str,
    severity: str,
) -> dict[str, Any] | None:
    if not inventory.findings:
        return None
    return {
        "recommendation_id": f"fspr-rec-{cache_key.removeprefix('sha256:')[:16]}",
        "source": "fspr",
        "canonical_skill_id": f"skill:{inventory.skill_name}",
        "metadata_record_id": None,
        "session_id": None,
        "severity": severity,
        "recommended_state": "greylist",
        "evidence_refs": [
            evidence_ref
            for finding in inventory.findings
            for evidence_ref in finding.get("evidence_refs", [])
            if isinstance(evidence_ref, str)
        ],
        "registry_snapshot_id": registry_snapshot_id,
    }


def _provider_degradation_result(
    *,
    timing_mode: str,
    inventory: FSPRInventory,
    role_results: list[dict[str, Any]],
    role: str,
    reason: str,
    evidence_capsule: dict[str, Any],
    cache_key: str,
    admission_recommendation: dict[str, Any] | None,
) -> FSPRResult:
    has_deterministic_findings = bool(inventory.findings)
    return FSPRResult(
        timing_mode=timing_mode,
        verdict="inconsistent"
        if has_deterministic_findings
        else "insufficient_evidence",
        severity="high" if has_deterministic_findings else "low",
        confidence=0.8 if has_deterministic_findings else 0.0,
        admission_recommendation=admission_recommendation,
        deterministic_findings_preserved=True,
        role_results=[
            *role_results,
            _role_degradation_result(role, reason),
        ],
        final_findings=list(inventory.findings) if has_deterministic_findings else [],
        evidence_capsule=evidence_capsule,
        degraded=True,
        degradation_reason=reason,
        cache_key=cache_key,
        cache=_fspr_cache_summary(cache_key, hit=False),
    )
