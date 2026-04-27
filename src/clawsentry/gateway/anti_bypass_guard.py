"""Compact PRE_ACTION anti-bypass follow-up guard.

The guard keeps a bounded, per-session memory of final risky decisions using
only hashes, fingerprints, ids, and labels.  It never stores raw commands,
payloads, prompts, environment variables, or L3 traces.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Deque

from .command_normalization import normalize_shell_command_head
from .detection_config import DetectionConfig
from .models import CanonicalDecision, CanonicalEvent, EventType, RiskSnapshot


_RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_DESTRUCTIVE_HEADS = {
    "rm",
    "rmdir",
    "unlink",
    "shred",
    "dd",
    "mkfs",
    "chmod",
    "chown",
    "curl",
    "wget",
    "scp",
    "rsync",
    "ssh",
    "git",
}


@dataclass(frozen=True)
class AntiBypassRecord:
    event_id: str
    record_id: int
    session_id_hash: str
    tool_name: str
    raw_payload_hash: str
    normalized_action_fingerprint: str
    destructive_intent_label: str
    destructive_intent_fingerprint: str
    normalized_feature_hashes: tuple[str, ...]
    policy_id: str
    decision: str
    risk_level: str
    occurred_at: str
    recorded_at: str
    expires_at: str
    source_framework: str


@dataclass(frozen=True)
class AntiBypassMatch:
    match_type: str
    action: str
    prior_event_id: str
    prior_record_id: int
    prior_policy_id: str
    prior_risk_level: str
    raw_payload_hash: str
    normalized_action_fingerprint: str
    destructive_intent_fingerprint: str
    destructive_intent_label: str = ""
    similarity: float | None = None

    def to_metadata(self) -> dict[str, Any]:
        meta = {
            "matched": True,
            "match_type": self.match_type,
            "action": self.action,
            "prior_event_id": self.prior_event_id,
            "prior_record_id": self.prior_record_id,
            "prior_policy_id": self.prior_policy_id,
            "prior_risk_level": self.prior_risk_level,
            "raw_payload_hash": self.raw_payload_hash,
            "normalized_action_fingerprint": self.normalized_action_fingerprint,
            "destructive_intent_fingerprint": self.destructive_intent_fingerprint,
        }
        if self.destructive_intent_label:
            meta["destructive_intent_label"] = self.destructive_intent_label
        if self.similarity is not None:
            meta["similarity"] = round(self.similarity, 4)
        if self.action in ("force_l2", "force_l3"):
            meta["forced_tier"] = "L2" if self.action == "force_l2" else "L3"
        return meta


@dataclass(frozen=True)
class _EventFingerprints:
    raw_payload_hash: str
    normalized_action_fingerprint: str
    destructive_intent_fingerprint: str
    destructive_intent_label: str
    normalized_feature_hashes: frozenset[str]


class AntiBypassGuard:
    """Bounded per-session anti-bypass memory and matcher."""

    def __init__(self) -> None:
        self._records: dict[str, Deque[AntiBypassRecord]] = defaultdict(deque)
        self.memory_evictions: int = 0

    def match_pre_action(
        self,
        event: CanonicalEvent,
        context: Any,
        config: DetectionConfig,
    ) -> AntiBypassMatch | None:
        del context  # reserved for future compact context-derived features
        if not config.anti_bypass_guard_enabled:
            return None
        if event.event_type != EventType.PRE_ACTION:
            return None

        session_id = str(event.session_id or "")
        self._evict(session_id, config)
        current = _fingerprints_for_event(event)
        tool_name = str(event.tool_name or "")
        for prior in reversed(self._records.get(session_id, ())):
            if not _eligible_prior(prior, config):
                continue
            if prior.tool_name == tool_name and prior.raw_payload_hash == current.raw_payload_hash:
                return AntiBypassMatch(
                    match_type="exact_raw_repeat",
                    action=config.anti_bypass_exact_repeat_action,
                    prior_event_id=prior.event_id,
                    prior_record_id=prior.record_id,
                    prior_policy_id=prior.policy_id,
                    prior_risk_level=prior.risk_level,
                    raw_payload_hash=current.raw_payload_hash,
                    normalized_action_fingerprint=current.normalized_action_fingerprint,
                    destructive_intent_fingerprint=current.destructive_intent_fingerprint,
                    destructive_intent_label=current.destructive_intent_label,
                    similarity=1.0,
                )
            if (
                prior.normalized_action_fingerprint
                and prior.normalized_action_fingerprint == current.normalized_action_fingerprint
            ):
                if prior.tool_name == tool_name:
                    return AntiBypassMatch(
                        match_type="normalized_destructive_repeat",
                        action=config.anti_bypass_normalized_destructive_repeat_action,
                        prior_event_id=prior.event_id,
                        prior_record_id=prior.record_id,
                        prior_policy_id=prior.policy_id,
                        prior_risk_level=prior.risk_level,
                        raw_payload_hash=current.raw_payload_hash,
                        normalized_action_fingerprint=current.normalized_action_fingerprint,
                        destructive_intent_fingerprint=current.destructive_intent_fingerprint,
                        destructive_intent_label=current.destructive_intent_label,
                        similarity=1.0,
                    )
                return AntiBypassMatch(
                    match_type="cross_tool_script_similarity",
                    action=config.anti_bypass_cross_tool_similarity_action,
                    prior_event_id=prior.event_id,
                    prior_record_id=prior.record_id,
                    prior_policy_id=prior.policy_id,
                    prior_risk_level=prior.risk_level,
                    raw_payload_hash=current.raw_payload_hash,
                    normalized_action_fingerprint=current.normalized_action_fingerprint,
                    destructive_intent_fingerprint=current.destructive_intent_fingerprint,
                    destructive_intent_label=current.destructive_intent_label,
                    similarity=1.0,
                )
            if (
                prior.tool_name != tool_name
                and prior.destructive_intent_label != "non-destructive"
                and prior.destructive_intent_fingerprint == current.destructive_intent_fingerprint
            ):
                return AntiBypassMatch(
                    match_type="cross_tool_script_similarity",
                    action=config.anti_bypass_cross_tool_similarity_action,
                    prior_event_id=prior.event_id,
                    prior_record_id=prior.record_id,
                    prior_policy_id=prior.policy_id,
                    prior_risk_level=prior.risk_level,
                    raw_payload_hash=current.raw_payload_hash,
                    normalized_action_fingerprint=current.normalized_action_fingerprint,
                    destructive_intent_fingerprint=current.destructive_intent_fingerprint,
                    destructive_intent_label=current.destructive_intent_label,
                    similarity=1.0,
                )

            similarity = _jaccard(
                frozenset(prior.normalized_feature_hashes),
                current.normalized_feature_hashes,
            )
            if prior.tool_name != tool_name and similarity >= config.anti_bypass_similarity_threshold:
                return AntiBypassMatch(
                    match_type="cross_tool_script_similarity",
                    action=config.anti_bypass_cross_tool_similarity_action,
                    prior_event_id=prior.event_id,
                    prior_record_id=prior.record_id,
                    prior_policy_id=prior.policy_id,
                    prior_risk_level=prior.risk_level,
                    raw_payload_hash=current.raw_payload_hash,
                    normalized_action_fingerprint=current.normalized_action_fingerprint,
                    destructive_intent_fingerprint=current.destructive_intent_fingerprint,
                    destructive_intent_label=current.destructive_intent_label,
                    similarity=similarity,
                )
        return None

    def record_final_decision(
        self,
        event: CanonicalEvent,
        decision: CanonicalDecision,
        snapshot: RiskSnapshot | None,
        meta: dict[str, Any],
        record_id: int,
        config: DetectionConfig,
    ) -> None:
        del snapshot, meta  # memory is intentionally compact and recomputed
        if not config.anti_bypass_guard_enabled:
            return
        if event.event_type != EventType.PRE_ACTION:
            return
        if getattr(decision, "final", None) is not True:
            return

        decision_value = str(getattr(decision.decision, "value", decision.decision))
        if decision_value == "allow" and not config.anti_bypass_record_allow_decisions:
            return
        if decision_value not in set(config.anti_bypass_prior_verdicts) and not (
            decision_value == "allow" and config.anti_bypass_record_allow_decisions
        ):
            return

        risk_level = str(getattr(decision.risk_level, "value", decision.risk_level))
        if _risk_rank(risk_level) < _risk_rank(config.anti_bypass_min_prior_risk):
            return

        session_id = str(event.session_id or "")
        self._evict(session_id, config)
        fp = _fingerprints_for_event(event)
        now = time.time()
        record = AntiBypassRecord(
            event_id=str(event.event_id or ""),
            record_id=int(record_id or 0),
            session_id_hash=_sha256(session_id),
            tool_name=str(event.tool_name or ""),
            raw_payload_hash=fp.raw_payload_hash,
            normalized_action_fingerprint=fp.normalized_action_fingerprint,
            destructive_intent_fingerprint=fp.destructive_intent_fingerprint,
            destructive_intent_label=fp.destructive_intent_label,
            normalized_feature_hashes=tuple(sorted(fp.normalized_feature_hashes)),
            policy_id=str(decision.policy_id or ""),
            decision=decision_value,
            risk_level=risk_level,
            occurred_at=str(event.occurred_at or ""),
            recorded_at=_iso_from_ts(now),
            expires_at=_iso_from_ts(now + float(config.anti_bypass_memory_ttl_s)),
            source_framework=str(event.source_framework or ""),
        )
        records = self._records[session_id]
        records.append(record)
        while len(records) > config.anti_bypass_memory_max_records_per_session:
            records.popleft()
            self.memory_evictions += 1

    def records_for_session(self, session_id: str) -> list[dict[str, Any]]:
        """Return serialized compact records for tests and reporting hooks."""
        return [asdict(record) for record in self._records.get(str(session_id or ""), ())]

    def _evict(self, session_id: str, config: DetectionConfig) -> None:
        records = self._records.get(session_id)
        if not records:
            return
        now = time.time()
        while records and _parse_iso(records[0].expires_at) <= now:
            records.popleft()
            self.memory_evictions += 1


def _eligible_prior(record: AntiBypassRecord, config: DetectionConfig) -> bool:
    return (
        record.decision in set(config.anti_bypass_prior_verdicts)
        and _risk_rank(record.risk_level) >= _risk_rank(config.anti_bypass_min_prior_risk)
    )


def _fingerprints_for_event(event: CanonicalEvent) -> _EventFingerprints:
    raw_projection = {
        "event_type": event.event_type.value,
        "tool_name": str(event.tool_name or ""),
        "payload": _canonical_payload_projection(event.payload or {}),
    }
    normalized_text = _normalized_action_text(event)
    normalized_feature_hashes = frozenset(_sha256(token) for token in _tokenize(normalized_text))
    destructive_intent = _destructive_intent_label(normalized_text)
    return _EventFingerprints(
        raw_payload_hash=_sha256_json(raw_projection),
        normalized_action_fingerprint=_sha256(normalized_text),
        destructive_intent_label=destructive_intent,
        destructive_intent_fingerprint=_sha256(destructive_intent),
        normalized_feature_hashes=normalized_feature_hashes,
    )


def _canonical_payload_projection(payload: dict[str, Any]) -> Any:
    def project(value: Any) -> Any:
        if isinstance(value, dict):
            return {str(k): project(v) for k, v in sorted(value.items(), key=lambda item: str(item[0]))}
        if isinstance(value, (list, tuple)):
            return [project(v) for v in value]
        if isinstance(value, (str, int, float, bool)) or value is None:
            return value
        return str(type(value).__name__)

    return project(payload)


def _normalized_action_text(event: CanonicalEvent) -> str:
    payload = event.payload or {}
    command = _first_text(payload, ("command", "cmd", "shell_command", "script", "code", "input"))
    if command:
        return normalize_shell_command_head(command).strip().lower()
    projected = {
        "tool_name": str(event.tool_name or ""),
        "payload_keys": sorted(str(key) for key in payload.keys()),
        "action": _first_text(payload, ("action", "operation", "name", "path", "target_path", "file_path")),
    }
    return json.dumps(projected, sort_keys=True, separators=(",", ":")).lower()


def _first_text(payload: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return ""


def _destructive_intent_label(normalized_text: str) -> str:
    tokens = _tokenize(normalized_text)
    head = tokens[0] if tokens else ""
    if head in _DESTRUCTIVE_HEADS:
        return head
    if any(token in {"delete", "remove", "destroy", "exfiltrate", "download", "upload"} for token in tokens):
        return "destructive-generic"
    return "non-destructive"


def _tokenize(text: str) -> list[str]:
    return [token for token in "".join(ch if ch.isalnum() else " " for ch in text.lower()).split() if token]


def _jaccard(left: frozenset[str], right: frozenset[str]) -> float:
    if not left or not right:
        return 0.0
    return len(left & right) / len(left | right)


def _risk_rank(value: str) -> int:
    return _RISK_ORDER.get(str(value).lower(), 0)


def _sha256(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _sha256_json(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return _sha256(payload)


def _iso_from_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()


def _parse_iso(value: str) -> float:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return 0.0
