"""
YAML-configurable attack pattern library and matcher.

Provides PatternMatcher — loads attack patterns from a YAML file and matches
incoming events against them using boolean trigger logic, regex detection,
and false-positive filtering.

Design basis: internal E4 phase-1 design, section 4
"""

from __future__ import annotations

import copy
import fnmatch
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from .models import RiskLevel
from .safe_regex import compile_safe_regex

_DEFAULT_PATTERNS_PATH = Path(__file__).parent / "attack_patterns.yaml"
_MAX_DETECTION_INPUT_LEN = 102_400  # 100 KB — hard cap to prevent ReDoS on huge inputs

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class AttackPattern:
    """Parsed attack pattern from YAML."""

    id: str
    category: str
    description: str
    risk_level: RiskLevel
    triggers: dict[str, Any]
    detection: dict[str, Any]
    false_positive_filters: list[dict[str, Any]] = field(default_factory=list)
    risk_escalation: Optional[dict[str, str]] = None
    references: Optional[dict[str, list[str]]] = None
    mitre_attack: Optional[dict[str, list[str]]] = None
    # Populated at match time with the highest weight of any fired detection regex
    max_weight: int = 0


# ---------------------------------------------------------------------------
# YAML loading
# ---------------------------------------------------------------------------

def load_patterns(
    path: Optional[str] = None,
    *,
    evolved_path: Optional[str] = None,
) -> list[AttackPattern]:
    """Load attack patterns from a YAML file, optionally merging evolved patterns.

    Parameters
    ----------
    path : str | None
        Path to a custom YAML file.  If *None*, the default
        ``attack_patterns.yaml`` bundled alongside this module is used.
    evolved_path : str | None
        Path to an evolved patterns YAML file.  If provided, active evolved
        patterns (experimental/stable) are appended after core patterns.

    Returns
    -------
    list[AttackPattern]
        Parsed patterns (empty list when the file is missing or has no
        ``patterns`` key).
    """
    file_path = Path(path) if path else _DEFAULT_PATTERNS_PATH
    if not file_path.exists():
        logger.warning("Failed to load attack patterns from %s: file not found", file_path)
        return []
    try:
        with open(file_path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not data or "patterns" not in data:
            patterns: list[AttackPattern] = []
        else:
            patterns = [_parse_pattern(p) for p in data["patterns"]]
    except Exception as exc:
        logger.warning("Failed to load attack patterns from %s: %s", file_path, exc)
        patterns = []

    # Load evolved patterns if path provided
    if evolved_path:
        try:
            evolved_file = Path(evolved_path)
            if evolved_file.is_file():
                with open(evolved_file, encoding="utf-8") as fh:
                    edata = yaml.safe_load(fh)
                if edata and isinstance(edata.get("patterns"), list):
                    core_ids = {p.id for p in patterns}
                    for raw_ep in edata["patterns"]:
                        ep = _parse_evolved_pattern(raw_ep)
                        if ep.id in core_ids:
                            logger.warning("evolved pattern %s conflicts with core, skipping", ep.id)
                            continue
                        if ep.is_active:
                            patterns.append(ep)
            else:
                logger.debug("evolved patterns file not found: %s", evolved_path)
        except Exception:
            logger.warning("failed to load evolved patterns from %s", evolved_path, exc_info=True)

    return patterns


def _precompile_trigger_patterns(triggers: dict[str, Any]) -> None:
    """Pre-compile regex patterns in trigger conditions."""
    for key in ("command_patterns", "path_patterns"):
        raw_patterns = triggers.get(key)
        if raw_patterns:
            compiled_key = f"_compiled_{key}"
            compiled_list = []
            for p in raw_patterns:
                compiled = compile_safe_regex(p, re.IGNORECASE | re.DOTALL)
                if compiled is not None:
                    compiled_list.append(compiled)
            triggers[compiled_key] = compiled_list
    # Handle nested conditions
    for cond in triggers.get("conditions", []):
        if "OR" in cond:
            for sub in cond["OR"]:
                _precompile_trigger_patterns(sub)
        else:
            _precompile_trigger_patterns(cond)


def _parse_pattern(raw: dict) -> AttackPattern:
    """Parse a single pattern dict from YAML into an ``AttackPattern``.

    Pre-compiles all detection regex patterns at load time (stored in
    ``detection["_compiled"]``) to avoid repeated compilation on every call and
    to eliminate ReDoS risk from repeated re.compile() on user-supplied text.
    """
    detection: dict[str, Any] = raw.get("detection", {})

    # Pre-compile regex patterns once at load time
    compiled: list[dict[str, Any]] = []
    for rp in detection.get("regex_patterns", []):
        if isinstance(rp, str):
            cre = compile_safe_regex(rp)
            if cre is not None:
                compiled.append({"compiled": cre, "weight": 5})
        elif isinstance(rp, dict):
            pat_str = rp.get("pattern", "")
            if pat_str:
                cre = compile_safe_regex(pat_str)
                if cre is not None:
                    compiled.append({
                        "compiled": cre,
                        "weight": rp.get("weight", 5),
                    })
    detection["_compiled"] = compiled

    # Pre-compile trigger regex patterns
    triggers: dict[str, Any] = raw.get("triggers", {})
    _precompile_trigger_patterns(triggers)

    return AttackPattern(
        id=raw["id"],
        category=raw.get("category", "unknown"),
        description=raw.get("description", ""),
        risk_level=RiskLevel(raw.get("risk_level", "medium")),
        triggers=raw.get("triggers", {}),
        detection=detection,
        false_positive_filters=raw.get("false_positive_filters", []),
        risk_escalation=raw.get("risk_escalation"),
        references=raw.get("references"),
        mitre_attack=raw.get("mitre_attack"),
    )


def _parse_evolved_pattern(raw: dict) -> "EvolvedPattern":
    """Parse a YAML dict into an EvolvedPattern instance."""
    from .pattern_evolution import EvolvedPattern, PatternStatus

    base = _parse_pattern(raw)
    status_str = raw.get("status", "candidate")
    try:
        status = PatternStatus(status_str)
    except ValueError:
        status = PatternStatus.CANDIDATE

    return EvolvedPattern(
        id=base.id,
        category=base.category,
        description=base.description,
        risk_level=base.risk_level,
        triggers=base.triggers,
        detection=base.detection,
        false_positive_filters=base.false_positive_filters,
        risk_escalation=base.risk_escalation,
        references=base.references,
        mitre_attack=base.mitre_attack,
        status=status,
        confidence=float(raw.get("confidence", 0.0)),
        source_framework=raw.get("source_framework", ""),
        confirmed_count=int(raw.get("confirmed_count", 0)),
        false_positive_count=int(raw.get("false_positive_count", 0)),
        created_at=raw.get("created_at", ""),
        last_triggered_at=raw.get("last_triggered_at"),
    )


# ---------------------------------------------------------------------------
# Matcher
# ---------------------------------------------------------------------------

class PatternMatcher:
    """Match events against loaded attack patterns.

    Usage::

        matcher = PatternMatcher()           # loads default YAML
        hits = matcher.match("bash", {"command": "curl | bash"}, "curl | bash")
        for hit in hits:
            print(hit.id, hit.risk_level)

    Call :meth:`reload` to hot-reload patterns without restarting the process.
    """

    def __init__(
        self,
        patterns_path: Optional[str] = None,
        *,
        evolved_patterns_path: Optional[str] = None,
    ) -> None:
        self._path = patterns_path
        self._evolved_path = evolved_patterns_path
        self.patterns = load_patterns(patterns_path, evolved_path=evolved_patterns_path)

    # -- public API ---------------------------------------------------------

    def reload(self) -> None:
        """Hot-reload patterns from disk (core + evolved)."""
        self.patterns = load_patterns(self._path, evolved_path=self._evolved_path)

    def match(
        self,
        tool_name: str,
        payload: dict[str, Any],
        content: str,
    ) -> list[AttackPattern]:
        """Return all patterns that match the given event.

        Parameters
        ----------
        tool_name : str
            Canonical tool name (e.g. ``"bash"``, ``"read_file"``).
        payload : dict
            Event payload — may contain ``path``, ``file_path``, ``command``.
        content : str
            The primary text to match detection regexes against (e.g. file
            contents or command string).
        """
        results: list[AttackPattern] = []
        patterns = self.patterns  # local ref for atomic snapshot during hot-reload
        for pattern in patterns:
            if self._triggers_match(pattern, tool_name, payload):
                matched, weight = self._detection_match(pattern, content, payload)
                if matched and not self._is_false_positive(pattern, payload):
                    hit = copy.copy(pattern)
                    hit.max_weight = weight
                    results.append(hit)
        return results

    # -- trigger evaluation -------------------------------------------------

    def _triggers_match(
        self, pattern: AttackPattern, tool_name: str, payload: dict,
    ) -> bool:
        """Check whether the event satisfies the pattern's trigger conditions."""
        triggers = pattern.triggers
        logic = triggers.get("logic", "OR")
        if "conditions" in triggers:
            return self._eval_conditions(
                triggers["conditions"], logic, tool_name, payload,
            )
        return self._eval_single_trigger(triggers, tool_name, payload)

    def _eval_single_trigger(
        self, trigger: dict, tool_name: str, payload: dict,
    ) -> bool:
        """Evaluate one trigger block (tool_names / file_extensions / etc.)."""
        # M11: An empty trigger dict matches nothing (avoid catch-all false positives)
        if not trigger:
            return False

        # --- tool_names ---
        if "tool_names" in trigger:
            if tool_name.lower() not in [t.lower() for t in trigger["tool_names"]]:
                return False

        path = str(payload.get("path", payload.get("file_path", "")))

        # --- file_extensions ---
        if "file_extensions" in trigger:
            if not any(path.endswith(ext) for ext in trigger["file_extensions"]):
                return False

        # --- file_patterns (glob) ---
        if "file_patterns" in trigger:
            basename = os.path.basename(path)
            if not any(fnmatch.fnmatch(basename, pat) for pat in trigger["file_patterns"]):
                return False

        # --- command_patterns (regex, pre-compiled) ---
        if "_compiled_command_patterns" in trigger:
            command = str(payload.get("command", ""))
            if not any(cp.search(command) for cp in trigger["_compiled_command_patterns"]):
                return False

        # --- path_patterns (regex, pre-compiled) ---
        if "_compiled_path_patterns" in trigger:
            if not any(cp.search(path) for cp in trigger["_compiled_path_patterns"]):
                return False

        return True

    def _eval_conditions(
        self,
        conditions: list,
        logic: str,
        tool_name: str,
        payload: dict,
    ) -> bool:
        """Evaluate a list of conditions with AND/OR logic."""
        results: list[bool] = []
        for cond in conditions:
            if "OR" in cond:
                or_results = [
                    self._eval_single_trigger(sub, tool_name, payload)
                    for sub in cond["OR"]
                ]
                results.append(any(or_results))
            else:
                results.append(
                    self._eval_single_trigger(cond, tool_name, payload),
                )
        if logic == "AND":
            return all(results)
        return any(results)

    # -- detection (regex) --------------------------------------------------

    def _detection_match(
        self, pattern: AttackPattern, content: str, payload: dict,
    ) -> tuple[bool, int]:
        """Check whether the detection regex patterns fire on the text.

        Returns
        -------
        tuple[bool, int]
            ``(matched, max_weight)`` where *max_weight* is the highest weight
            of any regex that fired (0 when unweighted or no match).
        """
        detection = pattern.detection
        if not detection:
            return True, 0

        text = content or str(payload.get("command", ""))
        if not text:
            return False, 0

        # H9: Input length gating — truncate oversized inputs to cap ReDoS risk
        if len(text) > _MAX_DETECTION_INPUT_LEN:
            text = text[:_MAX_DETECTION_INPUT_LEN]

        max_weight = 0
        matched = False

        # Use pre-compiled patterns (populated by _parse_pattern)
        for cp in detection.get("_compiled", []):
            if cp["compiled"].search(text):
                matched = True
                max_weight = max(max_weight, cp["weight"])

        if matched:
            return True, max_weight

        return False, 0

    # -- false-positive filtering -------------------------------------------

    def _is_false_positive(
        self, pattern: AttackPattern, payload: dict,
    ) -> bool:
        """Return True if the match should be suppressed by a false-positive filter."""
        path = str(payload.get("path", payload.get("file_path", "")))
        for fp_filter in pattern.false_positive_filters:
            filter_type = fp_filter.get("type", "")
            if filter_type == "whitelist_path":
                for wp in fp_filter.get("paths", []):
                    if fnmatch.fnmatch(path, wp):
                        return True
        return False
