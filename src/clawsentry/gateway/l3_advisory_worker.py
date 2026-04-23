"""Explicit L3 advisory worker adapters.

Workers in this module are deliberately pull-based: callers pass a queued job
id, and the worker consumes only the frozen evidence snapshot attached to that
job. Nothing here starts a scheduler or changes canonical decisions.
"""

from __future__ import annotations

import asyncio
import json
import os
import threading
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from .trajectory_store import TrajectoryStore


_RISK_LEVEL_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_TRUTHY_VALUES = {"1", "true", "yes", "on"}


class L3AdvisoryWorker(Protocol):
    """Contract for explicit advisory workers."""

    runner_name: str

    def build_review_update(
        self,
        *,
        snapshot: dict[str, Any],
        records: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Return fields used to complete an advisory review."""


@dataclass(frozen=True)
class LLMAdvisoryProviderConfig:
    """Configuration shell for future real LLM advisory providers."""

    enabled: bool
    provider: str
    model: str
    api_key: str | None = None
    base_url: str | None = None
    dry_run: bool = True
    temperature: float = 1.0
    deadline_ms: int = 30_000


class LLMAdvisoryProvider(Protocol):
    """Provider-neutral completion interface for advisory workers."""

    provider_name: str

    def validate(self) -> str | None:
        """Return an error reason when the provider cannot run."""

    def complete(self, request: dict[str, Any]) -> dict[str, Any]:
        """Return a worker response payload."""


class AsyncCompletionProvider(Protocol):
    """Subset of the existing LLM provider contract used by advisory smoke."""

    @property
    def provider_id(self) -> str: ...

    async def complete(
        self,
        system_prompt: str,
        user_message: str,
        timeout_ms: float,
        max_tokens: int = 256,
    ) -> str: ...


class _ProviderShellBase:
    provider_name = "unknown"

    def __init__(self, config: LLMAdvisoryProviderConfig) -> None:
        self.config = config

    def validate(self) -> str | None:
        if not self.config.enabled:
            return "provider disabled"
        if not self.config.api_key:
            return "missing api key"
        if not self.config.model.strip():
            return "missing model"
        return None

    @staticmethod
    def _degraded(reason_code: str, finding: str) -> dict[str, Any]:
        return {
            "schema_version": "cs.l3_advisory.worker_response.v1",
            "risk_level": "medium",
            "findings": [finding],
            "confidence": None,
            "recommended_operator_action": "inspect",
            "l3_state": "degraded",
            "l3_reason_code": reason_code,
        }

    def complete(self, request: dict[str, Any]) -> dict[str, Any]:
        validation_error = self.validate()
        if validation_error is not None:
            return self._degraded(
                _provider_validation_reason_code(validation_error),
                validation_error,
            )
        return self._degraded(
            "provider_not_implemented",
            f"{self.provider_name} advisory provider not implemented",
        )


class OpenAIAdvisoryProvider(_ProviderShellBase):
    provider_name = "openai"


class AnthropicAdvisoryProvider(_ProviderShellBase):
    provider_name = "anthropic"


class LLMProviderBridgeAdvisoryProvider(_ProviderShellBase):
    """Bridge advisory worker requests to the existing async LLM provider API."""

    def __init__(
        self,
        *,
        config: LLMAdvisoryProviderConfig,
        provider: AsyncCompletionProvider,
    ) -> None:
        super().__init__(config)
        self.provider = provider
        self.provider_name = config.provider.strip().lower() or provider.provider_id

    def complete(self, request: dict[str, Any]) -> dict[str, Any]:
        validation_error = self.validate()
        if validation_error is not None:
            return self._degraded(
                _provider_validation_reason_code(validation_error),
                validation_error,
            )
        if self.config.dry_run:
            return self._degraded(
                "provider_not_implemented",
                f"{self.provider_name} advisory provider dry-run",
            )
        try:
            raw = _run_async_completion_sync(
                self.provider.complete(
                    system_prompt=_advisory_provider_system_prompt(),
                    user_message=_advisory_provider_user_message(request),
                    timeout_ms=float(request.get("deadline_ms") or 30_000),
                    max_tokens=int((request.get("budget") or {}).get("max_tokens") or 512),
                )
            )
        except TimeoutError:
            return self._degraded("provider_timeout", f"{self.provider_name} advisory provider timeout")
        except Exception as exc:
            return self._degraded("provider_error", str(exc)[:200])

        try:
            payload = extract_l3_advisory_response_json(raw)
        except (TypeError, ValueError, json.JSONDecodeError):
            return self._degraded(
                "provider_response_invalid",
                "provider response was not valid JSON",
            )
        return payload


def _provider_validation_reason_code(validation_error: str) -> str:
    if validation_error == "provider disabled":
        return "provider_disabled"
    if validation_error == "missing api key":
        return "provider_missing_key"
    if validation_error == "missing model":
        return "provider_missing_model"
    return "provider_invalid_config"


def _advisory_provider_system_prompt() -> str:
    return (
        "You are ClawSentry's advisory-only L3 reviewer. "
        "Read only the provided frozen evidence snapshot request. "
        "Do not assume access to live session state. "
        "Return only JSON matching schema cs.l3_advisory.worker_response.v1 "
        "with fields: schema_version, risk_level, findings, confidence, "
        "recommended_operator_action, l3_state, l3_reason_code."
    )


def _advisory_provider_user_message(request: dict[str, Any]) -> str:
    """Render a compact non-JSON prompt for OpenAI-compatible providers.

    Some OpenAI-compatible endpoints return empty content when the user message
    is a raw JSON object. Keep the schema and frozen boundary explicit while
    presenting the evidence as plain text.
    """

    event_range = request.get("event_range") or {}
    risk_summary = request.get("risk_summary") or {}
    lines = [
        "Frozen L3 advisory review request.",
        f"Request schema: {request.get('schema_version')}",
        f"Provider: {request.get('provider')} model: {request.get('model')}",
        f"Snapshot: {request.get('snapshot_id')}",
        f"Session: {request.get('session_id')}",
        f"Trigger: {request.get('trigger_reason')} detail: {request.get('trigger_detail') or '-'}",
        (
            "Frozen record range: "
            f"{event_range.get('from_record_id')}..{event_range.get('to_record_id')}"
        ),
        (
            "Risk summary: "
            f"current={risk_summary.get('current_risk_level')}; "
            f"high_count={risk_summary.get('high_risk_event_count')}; "
            f"decisions={risk_summary.get('decision_distribution')}"
        ),
    ]
    events = request.get("events") if isinstance(request.get("events"), list) else []
    highest_event_risk = "low"
    for event in events:
        event_risk = str(event.get("risk_level") or "low").lower()
        if _RISK_LEVEL_RANK.get(event_risk, 0) > _RISK_LEVEL_RANK.get(highest_event_risk, 0):
            highest_event_risk = event_risk
    lines.append(
        f"Frozen event summary: count={len(events)} highest_event_risk={highest_event_risk}."
    )
    lines.extend(
        [
            "",
            "Return only a JSON object with schema_version=cs.l3_advisory.worker_response.v1.",
            "Use l3_state=completed if this advisory review completed.",
            "Output exactly this JSON shape, changing values as needed:",
            (
                '{"schema_version":"cs.l3_advisory.worker_response.v1",'
                '"risk_level":"high","findings":["advisory review completed"],'
                '"confidence":0.5,"recommended_operator_action":"inspect",'
                '"l3_state":"completed","l3_reason_code":null}'
            ),
        ]
    )
    return "\n".join(lines)


def extract_l3_advisory_response_json(raw: str) -> dict[str, Any]:
    """Extract a provider response JSON object from raw model text."""

    text = str(raw or "").strip()
    if not text:
        raise ValueError("empty provider response")

    candidates = [text]
    fenced = _extract_fenced_json_blocks(text)
    candidates = fenced + candidates
    object_text = _extract_first_json_object(text)
    if object_text and object_text not in candidates:
        candidates.append(object_text)

    for candidate in candidates:
        try:
            payload = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            return payload
    raise ValueError("provider response did not contain a JSON object")


def _extract_fenced_json_blocks(text: str) -> list[str]:
    blocks: list[str] = []
    marker = "```"
    start = 0
    while True:
        open_idx = text.find(marker, start)
        if open_idx == -1:
            break
        content_start = open_idx + len(marker)
        newline_idx = text.find("\n", content_start)
        if newline_idx == -1:
            break
        fence_label = text[content_start:newline_idx].strip().lower()
        close_idx = text.find(marker, newline_idx + 1)
        if close_idx == -1:
            break
        content = text[newline_idx + 1:close_idx].strip()
        if not fence_label or fence_label == "json":
            blocks.append(content)
        start = close_idx + len(marker)
    return blocks


def _extract_first_json_object(text: str) -> str | None:
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    in_string = False
    escape = False
    for idx in range(start, len(text)):
        char = text[idx]
        if escape:
            escape = False
            continue
        if char == "\\":
            escape = True
            continue
        if char == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start:idx + 1]
    return None


def _run_async_completion_sync(coro: Any) -> str:
    """Run an async provider completion from the synchronous worker path.

    FastAPI calls this worker through an async endpoint, so ``asyncio.run`` may be
    illegal in the current thread. A short-lived thread keeps the bridge usable
    from both sync and async callers without starting a scheduler.
    """

    box: dict[str, Any] = {}

    def target() -> None:
        try:
            box["result"] = asyncio.run(coro)
        except BaseException as exc:  # noqa: BLE001 - propagate exactly below
            box["error"] = exc

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join()
    if "error" in box:
        error = box["error"]
        if isinstance(error, TimeoutError):
            raise error
        raise error
    return str(box.get("result", ""))


class DisabledAdvisoryProvider(_ProviderShellBase):
    provider_name = "disabled"

    def __init__(self, config: LLMAdvisoryProviderConfig) -> None:
        super().__init__(config)
        self.provider_name = config.provider.strip().lower() or "disabled"


class UnsupportedAdvisoryProvider(_ProviderShellBase):
    """Degrading shell used when explicit advisory provider config is invalid."""

    def __init__(self, config: LLMAdvisoryProviderConfig) -> None:
        super().__init__(config)
        self.provider_name = config.provider.strip().lower() or "unknown"

    def validate(self) -> str | None:
        return None

    def complete(self, request: dict[str, Any]) -> dict[str, Any]:
        return self._degraded(
            "provider_unsupported",
            f"unsupported advisory provider: {self.provider_name}",
        )


def _env(
    name: str,
    *,
    environ: Mapping[str, str] | None = None,
    default: str = "",
) -> str:
    source = environ if environ is not None else os.environ
    return str(source.get(name, default))


def _env_bool(
    name: str,
    *,
    environ: Mapping[str, str] | None = None,
    default: bool = False,
) -> bool:
    raw = _env(name, environ=environ).strip()
    if not raw:
        return default
    return raw.lower() in _TRUTHY_VALUES


def _env_bool_default_true(
    name: str,
    *,
    environ: Mapping[str, str] | None = None,
) -> bool:
    raw = _env(name, environ=environ).strip()
    if not raw:
        return True
    return raw.lower() in _TRUTHY_VALUES


def _env_float(
    name: str,
    *,
    environ: Mapping[str, str] | None = None,
    default: float,
) -> float:
    raw = _env(name, environ=environ).strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_int(
    name: str,
    *,
    environ: Mapping[str, str] | None = None,
    default: int,
) -> int:
    raw = _env(name, environ=environ).strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _resolve_advisory_api_key(
    provider: str,
    *,
    environ: Mapping[str, str] | None = None,
) -> str | None:
    explicit = _env("CS_L3_ADVISORY_API_KEY", environ=environ).strip()
    if explicit:
        return explicit
    if provider == "openai":
        return _env("OPENAI_API_KEY", environ=environ).strip() or None
    if provider == "anthropic":
        return _env("ANTHROPIC_API_KEY", environ=environ).strip() or None
    return None


def resolve_l3_advisory_provider_config(
    *,
    environ: Mapping[str, str] | None = None,
) -> LLMAdvisoryProviderConfig:
    """Resolve explicit advisory-provider configuration.

    This intentionally does not inherit ``CS_LLM_PROVIDER`` / ``CS_LLM_MODEL``.
    Async advisory provider execution must be opted in separately so existing L2
    or synchronous L3 deployments cannot accidentally start advisory workers.
    """

    enabled = _env_bool("CS_L3_ADVISORY_PROVIDER_ENABLED", environ=environ)
    provider = _env("CS_L3_ADVISORY_PROVIDER", environ=environ).strip().lower()
    model = _env("CS_L3_ADVISORY_MODEL", environ=environ).strip()
    base_url = _env("CS_L3_ADVISORY_BASE_URL", environ=environ).strip() or None
    api_key = _resolve_advisory_api_key(provider, environ=environ) if enabled else None
    dry_run = _env_bool_default_true("CS_L3_ADVISORY_PROVIDER_DRY_RUN", environ=environ)
    temperature = _env_float("CS_L3_ADVISORY_TEMPERATURE", environ=environ, default=1.0)
    deadline_ms = _env_int("CS_L3_ADVISORY_DEADLINE_MS", environ=environ, default=30_000)
    return LLMAdvisoryProviderConfig(
        enabled=enabled,
        provider=provider if enabled else "",
        model=model if enabled else "",
        api_key=api_key,
        base_url=base_url if enabled else None,
        dry_run=dry_run,
        temperature=temperature,
        deadline_ms=deadline_ms,
    )


def build_l3_advisory_provider(config: LLMAdvisoryProviderConfig) -> LLMAdvisoryProvider:
    """Build a guarded provider shell from explicit advisory config."""

    provider = config.provider.strip().lower()
    normalized = LLMAdvisoryProviderConfig(
        enabled=bool(config.enabled),
        provider=provider,
        model=config.model.strip(),
        api_key=(config.api_key.strip() if isinstance(config.api_key, str) else None),
        base_url=(config.base_url.strip() if isinstance(config.base_url, str) else None),
        dry_run=bool(config.dry_run),
        temperature=float(config.temperature),
        deadline_ms=int(config.deadline_ms),
    )
    if not normalized.enabled:
        return DisabledAdvisoryProvider(normalized)
    if not normalized.dry_run and provider in {"openai", "anthropic"}:
        from .llm_provider import AnthropicProvider, LLMProviderConfig, OpenAIProvider

        provider_config = LLMProviderConfig(
            api_key=normalized.api_key or "",
            model=normalized.model,
            base_url=normalized.base_url,
            temperature=normalized.temperature,
        )
        async_provider: AsyncCompletionProvider
        if provider == "openai":
            async_provider = OpenAIProvider(provider_config)
        else:
            async_provider = AnthropicProvider(provider_config)
        return LLMProviderBridgeAdvisoryProvider(
            config=normalized,
            provider=async_provider,
        )
    if provider == "openai":
        return OpenAIAdvisoryProvider(normalized)
    if provider == "anthropic":
        return AnthropicAdvisoryProvider(normalized)
    return UnsupportedAdvisoryProvider(normalized)


def build_l3_advisory_worker_request(
    *,
    snapshot: dict[str, Any],
    records: list[dict[str, Any]],
    provider: str,
    model: str,
    deadline_ms: int,
    budget: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a provider-agnostic L3 advisory worker request.

    The request intentionally contains only snapshot-bounded record summaries,
    never a live session cursor.
    """

    event_range = snapshot.get("event_range") or {}
    events: list[dict[str, Any]] = []
    for record in records:
        event = record.get("event") or {}
        decision = record.get("decision") or {}
        risk_snapshot = record.get("risk_snapshot") or {}
        events.append(
            {
                "record_id": record.get("record_id"),
                "recorded_at": record.get("recorded_at"),
                "event_id": event.get("event_id"),
                "event_type": event.get("event_type"),
                "tool_name": event.get("tool_name"),
                "payload": event.get("payload") if isinstance(event.get("payload"), dict) else {},
                "decision": decision.get("decision"),
                "risk_level": decision.get("risk_level") or risk_snapshot.get("risk_level"),
                "reason": decision.get("reason"),
            }
        )
    return {
        "schema_version": "cs.l3_advisory.worker_request.v1",
        "provider": provider,
        "model": model,
        "snapshot_id": snapshot["snapshot_id"],
        "session_id": snapshot["session_id"],
        "trigger_event_id": snapshot.get("trigger_event_id"),
        "trigger_reason": snapshot.get("trigger_reason"),
        "trigger_detail": snapshot.get("trigger_detail"),
        "event_range": {
            "from_record_id": int(event_range.get("from_record_id") or 0),
            "to_record_id": int(event_range.get("to_record_id") or 0),
        },
        "trajectory_fingerprint": snapshot.get("trajectory_fingerprint"),
        "risk_summary": snapshot.get("risk_summary") or {},
        "deadline_ms": int(deadline_ms),
        "budget": dict(budget or {}),
        "events": events,
    }


def parse_l3_advisory_worker_response(payload: dict[str, Any]) -> dict[str, Any]:
    """Normalize a provider response into a review patch."""

    if not isinstance(payload, dict) or payload.get("schema_version") != "cs.l3_advisory.worker_response.v1":
        return {
            "schema_version": "cs.l3_advisory.worker_response.v1",
            "risk_level": "medium",
            "findings": ["provider response invalid"],
            "confidence": None,
            "recommended_operator_action": "inspect",
            "l3_state": "degraded",
            "l3_reason_code": "provider_response_invalid",
        }

    risk_level = str(payload.get("risk_level") or "medium").lower()
    if risk_level not in _RISK_LEVEL_RANK:
        risk_level = "medium"
    findings = payload.get("findings")
    if not isinstance(findings, list):
        findings = ["provider response missing findings"]
    action = str(payload.get("recommended_operator_action") or _recommended_action_for_risk(risk_level))
    confidence = payload.get("confidence")
    if not isinstance(confidence, (int, float)):
        confidence = None
    l3_state = str(payload.get("l3_state") or "completed")
    if l3_state not in {"completed", "failed", "degraded"}:
        l3_state = "degraded"
    return {
        "schema_version": "cs.l3_advisory.worker_response.v1",
        "risk_level": risk_level,
        "findings": [str(item) for item in findings],
        "confidence": confidence,
        "recommended_operator_action": action,
        "l3_state": l3_state,
        "l3_reason_code": payload.get("l3_reason_code"),
    }


def _highest_risk_level(records: list[dict[str, Any]]) -> str:
    highest = "low"
    for record in records:
        risk_level = str(
            record.get("decision", {}).get("risk_level")
            or record.get("risk_snapshot", {}).get("risk_level")
            or "low"
        ).lower()
        if _RISK_LEVEL_RANK.get(risk_level, 0) > _RISK_LEVEL_RANK.get(highest, 0):
            highest = risk_level
    return highest


def _recommended_action_for_risk(risk_level: str) -> str:
    if risk_level == "critical":
        return "escalate"
    if risk_level in {"high", "medium"}:
        return "inspect"
    return "none"


def _event_ids(records: list[dict[str, Any]]) -> list[str]:
    return [
        event_id
        for record in records
        if (event_id := str(record.get("event", {}).get("event_id") or ""))
    ]


class FakeLLMAdvisoryWorker:
    """Dry-run LLM-shaped worker that never calls an external model."""

    runner_name = "fake_llm"

    def build_review_update(
        self,
        *,
        snapshot: dict[str, Any],
        records: list[dict[str, Any]],
    ) -> dict[str, Any]:
        event_ids = _event_ids(records)
        risk_level = _highest_risk_level(records)
        event_range = snapshot.get("event_range") or {}
        return {
            "risk_level": risk_level,
            "findings": [
                f"fake_llm reviewed {len(records)} frozen record(s)",
                f"Source events: {', '.join(event_ids) or '-'}",
                f"Trigger: {snapshot.get('trigger_reason') or 'unknown'}",
            ],
            "confidence": 0.5,
            "recommended_operator_action": _recommended_action_for_risk(risk_level),
            "l3_state": "completed",
            "extra_fields": {
                "evidence_record_count": len(records),
                "evidence_event_ids": event_ids,
                "source_record_range": {
                    "from_record_id": int(event_range.get("from_record_id") or 0),
                    "to_record_id": int(event_range.get("to_record_id") or 0),
                },
                "review_runner": self.runner_name,
                "worker_backend": self.runner_name,
            },
        }


class FakeProviderAdvisoryWorker:
    """Provider-shaped fake completion backend for request/response tests."""

    provider = "fake"

    def complete(self, request: dict[str, Any]) -> dict[str, Any]:
        events = request.get("events") if isinstance(request.get("events"), list) else []
        risk_level = "low"
        for event in events:
            current = str(event.get("risk_level") or "low").lower()
            if _RISK_LEVEL_RANK.get(current, 0) > _RISK_LEVEL_RANK.get(risk_level, 0):
                risk_level = current
        return {
            "schema_version": "cs.l3_advisory.worker_response.v1",
            "risk_level": risk_level,
            "findings": [
                f"fake provider reviewed {len(events)} frozen event(s)",
                f"Snapshot: {request.get('snapshot_id')}",
            ],
            "confidence": 0.5,
            "recommended_operator_action": _recommended_action_for_risk(risk_level),
            "l3_state": "completed",
            "l3_reason_code": None,
        }


class LLMProviderAdvisoryWorker:
    """Explicit provider-backed worker shell with conservative safety gates."""

    runner_name = "llm_provider"

    def __init__(
        self,
        config: LLMAdvisoryProviderConfig | None = None,
        provider: LLMAdvisoryProvider | None = None,
    ) -> None:
        self.config = config or resolve_l3_advisory_provider_config()
        self.provider = provider or build_l3_advisory_provider(self.config)

    def build_review_update(
        self,
        *,
        snapshot: dict[str, Any],
        records: list[dict[str, Any]],
    ) -> dict[str, Any]:
        provider_name = str(
            getattr(self.provider, "provider_name", "") or self.config.provider or "unknown"
        )
        request = build_l3_advisory_worker_request(
            snapshot=snapshot,
            records=records,
            provider=provider_name,
            model=self.config.model,
            deadline_ms=self.config.deadline_ms,
            budget={
                "max_tool_calls": 0,
                "max_tokens": 4096,
                "network_calls_enabled": False,
                "dry_run": True,
            },
        )
        parsed = parse_l3_advisory_worker_response(self.provider.complete(request))
        parsed["extra_fields"] = {
            "review_runner": self.runner_name,
            "worker_backend": provider_name,
            "provider_model": self.config.model,
            "provider_enabled": bool(self.config.enabled),
            "provider_dry_run": bool(self.config.dry_run),
            "worker_request_schema": request["schema_version"],
        }
        return parsed


def run_l3_advisory_worker_job(
    *,
    store: TrajectoryStore,
    job_id: str,
    worker: L3AdvisoryWorker,
) -> dict[str, Any]:
    """Run a queued advisory job with a provided worker adapter."""

    job = store.get_l3_advisory_job(job_id)
    if job is None:
        raise ValueError(f"job {job_id!r} was not found")
    if job.get("runner") != worker.runner_name:
        raise ValueError(
            f"job runner {job.get('runner')!r} does not match worker {worker.runner_name!r}"
        )
    snapshot = store.get_l3_evidence_snapshot(str(job.get("snapshot_id") or ""))
    if snapshot is None:
        raise ValueError(f"snapshot {job.get('snapshot_id')!r} was not found")
    records = store.replay_l3_evidence_snapshot(snapshot["snapshot_id"])
    if not records:
        raise ValueError(f"snapshot {snapshot['snapshot_id']!r} has no replayable records")

    claimed = store.claim_l3_advisory_job(job_id, expected_runner=worker.runner_name)
    if claimed is None:
        raise ValueError(f"job {job_id!r} is not queued and cannot be rerun")
    try:
        review = store.record_l3_advisory_review(
            snapshot_id=snapshot["snapshot_id"],
            risk_level=_highest_risk_level(records),
            findings=[],
            recommended_operator_action="inspect",
            l3_state="pending",
        )
        store.update_l3_advisory_review(
            review["review_id"],
            l3_state="running",
            findings=[f"{worker.runner_name} advisory worker started"],
            extra_fields={
                "review_runner": worker.runner_name,
                "worker_backend": worker.runner_name,
            },
        )
        update = worker.build_review_update(snapshot=snapshot, records=records)
        completed_review = store.update_l3_advisory_review(
            review["review_id"],
            risk_level=update.get("risk_level"),
            findings=update.get("findings"),
            confidence=update.get("confidence"),
            recommended_operator_action=update.get("recommended_operator_action"),
            l3_state=update.get("l3_state") or "completed",
            l3_reason_code=update.get("l3_reason_code"),
            extra_fields=update.get("extra_fields"),
        )
    except Exception as exc:
        failed = store.update_l3_advisory_job(job_id, job_state="failed", error=str(exc))
        raise ValueError(str(exc)) from exc

    completed_job = store.update_l3_advisory_job(
        job_id,
        job_state="completed",
        review_id=completed_review["review_id"],
    )
    return {"job": completed_job, "review": completed_review}
