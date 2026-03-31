"""Self-evolving risk pattern repository (E-5).

Extends AttackPattern with lifecycle metadata (status, confidence, source)
to enable feedback-driven pattern evolution.
"""
from __future__ import annotations

import contextlib
import enum
import logging
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import yaml

from .models import RiskLevel
from .pattern_matcher import AttackPattern

logger = logging.getLogger(__name__)


class PatternStatus(str, enum.Enum):
    """Lifecycle status for evolved patterns (Sigma-inspired)."""
    CANDIDATE = "candidate"
    EXPERIMENTAL = "experimental"
    STABLE = "stable"
    DEPRECATED = "deprecated"


@dataclass
class EvolvedPattern(AttackPattern):
    """AttackPattern subclass with evolution lifecycle metadata.

    Inherits all detection/trigger/matching logic from AttackPattern.
    Adds status tracking, confidence scoring, and provenance fields.
    """
    status: PatternStatus = PatternStatus.CANDIDATE
    confidence: float = 0.0
    source_framework: str = ""
    confirmed_count: int = 0
    false_positive_count: int = 0
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_triggered_at: Optional[str] = None

    @property
    def is_active(self) -> bool:
        """Only experimental and stable patterns participate in detection."""
        return self.status in (PatternStatus.EXPERIMENTAL, PatternStatus.STABLE)


# ---------------------------------------------------------------------------
# Persistent store
# ---------------------------------------------------------------------------


class EvolvedPatternStore:
    """Persistent store for evolved patterns backed by a YAML file.

    Features:
    - Atomic write (tempfile + os.replace) to prevent corruption
    - ID-based dedup to prevent duplicates
    - Configurable max_patterns cap to prevent unbounded growth
    """

    def __init__(self, path: str, *, max_patterns: int = 500) -> None:
        self._path = path
        self._max_patterns = max_patterns
        self._patterns: dict[str, EvolvedPattern] = {}
        self._load()

    def _load(self) -> None:
        p = Path(self._path)
        if not p.is_file():
            return
        try:
            with open(p, encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if not data or not isinstance(data.get("patterns"), list):
                return
            for raw in data["patterns"]:
                try:
                    ep = self._deserialize(raw)
                    self._patterns[ep.id] = ep
                except Exception:
                    logger.warning("skipping malformed evolved pattern: %s", raw.get("id", "?"))
        except Exception:
            logger.warning("failed to load evolved patterns from %s", self._path, exc_info=True)

    def _deserialize(self, raw: dict) -> EvolvedPattern:
        status_str = raw.get("status", "candidate")
        try:
            status = PatternStatus(status_str)
        except ValueError:
            status = PatternStatus.CANDIDATE

        return EvolvedPattern(
            id=raw["id"],
            category=raw.get("category", "unknown"),
            description=raw.get("description", ""),
            risk_level=RiskLevel(raw.get("risk_level", "medium")),
            triggers=raw.get("triggers", {}),
            detection=raw.get("detection", {}),
            false_positive_filters=raw.get("false_positive_filters", []),
            risk_escalation=raw.get("risk_escalation"),
            references=raw.get("references"),
            mitre_attack=raw.get("mitre_attack"),
            status=status,
            confidence=float(raw.get("confidence", 0.0)),
            source_framework=raw.get("source_framework", ""),
            confirmed_count=int(raw.get("confirmed_count", 0)),
            false_positive_count=int(raw.get("false_positive_count", 0)),
            created_at=raw.get("created_at", ""),
            last_triggered_at=raw.get("last_triggered_at"),
        )

    def _serialize(self, ep: EvolvedPattern) -> dict:
        d: dict[str, Any] = {
            "id": ep.id,
            "category": ep.category,
            "description": ep.description,
            "risk_level": ep.risk_level.value,
            "triggers": ep.triggers,
            "detection": {
                k: v for k, v in ep.detection.items() if not k.startswith("_")
            },
            "status": ep.status.value,
            "confidence": round(ep.confidence, 4),
            "source_framework": ep.source_framework,
            "confirmed_count": ep.confirmed_count,
            "false_positive_count": ep.false_positive_count,
            "created_at": ep.created_at,
        }
        if ep.false_positive_filters:
            d["false_positive_filters"] = ep.false_positive_filters
        if ep.risk_escalation:
            d["risk_escalation"] = ep.risk_escalation
        if ep.references:
            d["references"] = ep.references
        if ep.mitre_attack:
            d["mitre_attack"] = ep.mitre_attack
        if ep.last_triggered_at:
            d["last_triggered_at"] = ep.last_triggered_at
        return d

    @property
    def all_patterns(self) -> list[EvolvedPattern]:
        return list(self._patterns.values())

    def get(self, pattern_id: str) -> Optional[EvolvedPattern]:
        return self._patterns.get(pattern_id)

    def add(self, pattern: EvolvedPattern) -> bool:
        """Add a pattern. Returns False if duplicate ID or at cap."""
        if pattern.id in self._patterns:
            return False
        if len(self._patterns) >= self._max_patterns:
            evicted = False
            for status in (PatternStatus.DEPRECATED, PatternStatus.CANDIDATE):
                for pid, p in sorted(self._patterns.items(), key=lambda x: x[1].created_at):
                    if p.status == status:
                        del self._patterns[pid]
                        evicted = True
                        break
                if evicted:
                    break
            if not evicted:
                return False
        self._patterns[pattern.id] = pattern
        return True

    def save(self) -> None:
        """Atomically write all patterns to YAML."""
        if not self._patterns:
            return
        data = {
            "version": "1.0",
            "evolved": True,
            "patterns": [self._serialize(p) for p in self._patterns.values()],
        }
        parent = os.path.dirname(self._path) or "."
        os.makedirs(parent, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=parent, suffix=".yaml.tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
            os.replace(tmp, self._path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise


# ---------------------------------------------------------------------------
# Confidence scoring + promotion logic
# ---------------------------------------------------------------------------

PROMOTION_THRESHOLDS = {
    "stable_min_confirms": 3,
    "stable_min_confidence": 0.7,
    "deprecate_fp_rate": 0.3,  # FP / (FP + confirms) > 30% → deprecate
    "deprecate_min_total": 3,  # need at least 3 data points before deprecating
}


def compute_confidence(
    confirmed_count: int,
    false_positive_count: int,
    trigger_count: int,
    framework_count: int,
    days_since_last: float,
) -> float:
    """Compute a 0.0-1.0 confidence score for an evolved pattern."""
    total = confirmed_count + false_positive_count
    confirmation_ratio = confirmed_count / max(total, 1)
    frequency_score = min(trigger_count / 10.0, 1.0)

    # Cross-framework bonus: 0.0 (single) / 0.5 (2) / 1.0 (3+)
    cross_fw = min((framework_count - 1) / 2.0, 1.0) if framework_count > 0 else 0.0

    fp_rate = false_positive_count / max(total, 1)
    accuracy = 1.0 - fp_rate

    # Time decay: recent = 1.0, 30d = 0.5, 90d+ = 0.2
    if days_since_last <= 7:
        recency = 1.0
    elif days_since_last <= 30:
        recency = 0.5
    else:
        recency = 0.2

    return (
        0.30 * confirmation_ratio
        + 0.20 * frequency_score
        + 0.20 * cross_fw
        + 0.20 * accuracy
        + 0.10 * recency
    )


def promote_pattern(
    store: EvolvedPatternStore,
    pattern_id: str,
    *,
    confirmed: bool,
) -> str:
    """Process a user confirmation/rejection and update pattern status.

    Returns a string describing what happened.
    """
    p = store.get(pattern_id)
    if p is None:
        return "not_found"

    if confirmed:
        p.confirmed_count += 1
    else:
        p.false_positive_count += 1

    # Check FP-rate deprecation
    total = p.confirmed_count + p.false_positive_count
    if total >= PROMOTION_THRESHOLDS["deprecate_min_total"]:
        fp_rate = p.false_positive_count / total
        if fp_rate > PROMOTION_THRESHOLDS["deprecate_fp_rate"]:
            p.status = PatternStatus.DEPRECATED
            return "deprecated_high_fp"

    if not confirmed:
        return "fp_recorded"

    # Promotion: candidate → experimental (first confirm)
    if p.status == PatternStatus.CANDIDATE:
        p.status = PatternStatus.EXPERIMENTAL
        return "promoted_to_experimental"

    # Promotion: experimental → stable
    if p.status == PatternStatus.EXPERIMENTAL:
        if (
            p.confirmed_count >= PROMOTION_THRESHOLDS["stable_min_confirms"]
            and compute_confidence(
                p.confirmed_count, p.false_positive_count,
                p.confirmed_count + p.false_positive_count,
                1,  # framework_count tracked externally
                0,  # assume recent
            ) >= PROMOTION_THRESHOLDS["stable_min_confidence"]
        ):
            p.status = PatternStatus.STABLE
            return "promoted_to_stable"
        return "confirmed"

    return "confirmed"


# ---------------------------------------------------------------------------
# Manager — orchestrates the full lifecycle
# ---------------------------------------------------------------------------

import hashlib
import re as _re


def _sanitize_for_regex(command: str) -> str:
    """Extract a sanitized regex pattern from a command string.

    Replaces specific values (URLs, IPs, paths) with generic placeholders
    to produce a reusable pattern.  Uses a marker-based approach to avoid
    corrupting regex metacharacters inside replacement fragments.
    """
    # Phase 1: Replace concrete values with unique markers
    _placeholders: dict[str, str] = {}
    _counter = 0

    def _mark(match: _re.Match, replacement: str) -> str:
        nonlocal _counter
        key = f"__PH{_counter}__"
        _counter += 1
        _placeholders[key] = replacement
        return key

    tmp = command
    tmp = _re.sub(
        r'https?://[^\s"\'|&;]+',
        lambda m: _mark(m, r"https?://\S+"),
        tmp,
    )
    tmp = _re.sub(
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
        lambda m: _mark(m, r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),
        tmp,
    )
    tmp = _re.sub(
        r'/[\w./-]+',
        lambda m: _mark(m, r"[\w./-]+"),
        tmp,
    )

    # Phase 2: Escape everything (markers become literal __PHN__)
    escaped = _re.escape(tmp)

    # Phase 3: Restore markers with actual regex fragments
    for key, regex_frag in _placeholders.items():
        escaped = escaped.replace(_re.escape(key), regex_frag)

    return escaped


def _infer_category(tool_name: str, command: str, reasons: list[str]) -> str:
    """Infer attack category from event context."""
    cmd_lower = command.lower()
    for reason in reasons:
        if "ASI01" in reason:
            return "goal_hijack"
        if "ASI02" in reason:
            return "data_exfiltration"
        if "ASI03" in reason:
            return "privilege_abuse"
        if "ASI04" in reason:
            return "supply_chain"
        if "ASI05" in reason:
            return "code_execution"
    if any(kw in cmd_lower for kw in ("curl", "wget", "nc ", "ncat")):
        return "data_exfiltration"
    if any(kw in cmd_lower for kw in ("sudo", "chmod", "chown")):
        return "privilege_abuse"
    if any(kw in cmd_lower for kw in ("eval", "exec", "python -c", "bash -c")):
        return "code_execution"
    return "unknown"


class PatternEvolutionManager:
    """Orchestrates the full evolved-pattern lifecycle.

    - extract_candidate(): create candidate patterns from high-risk events
    - confirm(): process user confirmation/rejection
    - list_patterns(): list all evolved patterns with status
    """

    def __init__(
        self,
        store_path: str,
        *,
        enabled: bool = False,
        max_patterns: int = 500,
    ) -> None:
        self._enabled = enabled
        self._store_path = store_path
        if enabled and not store_path.strip():
            raise ValueError(
                "store_path must be non-empty when pattern evolution is enabled; "
                "set CS_EVOLVED_PATTERNS_PATH"
            )
        self.store = EvolvedPatternStore(store_path, max_patterns=max_patterns) if enabled else None
        self._command_hashes: dict[str, str] = {}  # hash → pattern_id (dedup)

    @property
    def enabled(self) -> bool:
        """Whether pattern evolution is active."""
        return self._enabled

    def extract_candidate(
        self,
        *,
        event_id: str,
        session_id: str,
        tool_name: str,
        command: str,
        risk_level: RiskLevel,
        source_framework: str,
        reasons: list[str],
    ) -> Optional[str]:
        """Extract a candidate pattern from a high-risk event.

        Returns the pattern ID if created/found, None if disabled.
        """
        if not self._enabled or self.store is None:
            return None

        # Dedup by command content hash
        cmd_hash = hashlib.sha256(f"{tool_name}:{command}".encode()).hexdigest()[:16]
        if cmd_hash in self._command_hashes:
            return self._command_hashes[cmd_hash]

        pattern_id = f"EV-{cmd_hash[:8].upper()}"
        existing = self.store.get(pattern_id)
        if existing is not None:
            self._command_hashes[cmd_hash] = pattern_id
            return pattern_id

        # Build detection regex from command
        regex_pattern = _sanitize_for_regex(command)

        ep = EvolvedPattern(
            id=pattern_id,
            category=_infer_category(tool_name, command, reasons),
            description=f"Auto-extracted from event {event_id}: {command[:80]}",
            risk_level=risk_level,
            triggers={"tool_names": [tool_name]} if tool_name else {},
            detection={"regex_patterns": [{"pattern": regex_pattern, "weight": 6}]},
            status=PatternStatus.CANDIDATE,
            source_framework=source_framework,
        )
        if self.store.add(ep):
            self._command_hashes[cmd_hash] = pattern_id
            self.store.save()
            return pattern_id
        return None

    def confirm(self, pattern_id: str, *, confirmed: bool) -> str:
        """Process user confirmation/rejection of a pattern."""
        if not self._enabled or self.store is None:
            return "disabled"
        result = promote_pattern(self.store, pattern_id, confirmed=confirmed)
        self.store.save()
        return result

    def list_patterns(self) -> list[dict[str, Any]]:
        """List all evolved patterns as dicts for API/CLI."""
        if not self._enabled or self.store is None:
            return []
        return [
            {
                "id": p.id,
                "category": p.category,
                "description": p.description,
                "risk_level": p.risk_level.value,
                "status": p.status.value,
                "confidence": p.confidence,
                "source_framework": p.source_framework,
                "confirmed_count": p.confirmed_count,
                "false_positive_count": p.false_positive_count,
                "created_at": p.created_at,
            }
            for p in self.store.all_patterns
        ]
