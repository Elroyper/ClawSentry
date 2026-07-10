"""Agent-facing feedback payload helpers."""

from __future__ import annotations

from typing import Any, Literal, Optional

from clawsentry.gateway.models import (
    AgentAdvisoryFeedback,
    AgentSafetyFeedback,
    CanonicalDecision,
    CanonicalEvent,
    DecisionContext,
    DecisionVerdict,
)

_RISK_LEVEL_RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _risk_rank(risk_level: Optional[str]) -> int:
    return _RISK_LEVEL_RANK.get(str(risk_level or "low").lower(), 0)


def _risk_points(risk_level: Any) -> int:
    """Return the display/L3-explainability ordinal for a risk level."""
    return _risk_rank(str(risk_level or "low"))


def _agent_safety_feedback(
    *,
    decision: CanonicalDecision,
    event: CanonicalEvent,
    snapshot: dict[str, Any],
    delivery: str,
) -> dict[str, Any] | None:
    """Return redacted feedback for an agent after a critical pre-action block."""

    if decision.decision != DecisionVerdict.BLOCK:
        return None
    risk_level = str(snapshot.get("risk_level") or decision.risk_level.value)
    if _risk_rank(risk_level) < _risk_rank("critical"):
        return None
    rule_hits = snapshot.get("rule_hits")
    if not isinstance(rule_hits, list):
        rule_hits = []
    if event.payload.get("command") is not None:
        blocked_surface = "command"
    elif event.tool_name:
        blocked_surface = "tool"
    else:
        blocked_surface = "artifact"
    evidence_refs = [f"rule:{str(item)}" for item in rule_hits[:8]]
    if not evidence_refs and decision.policy_id:
        evidence_refs = [f"policy:{decision.policy_id}"]
    feedback = AgentSafetyFeedback(
        delivery=delivery,
        risk_level="critical",
        decision_id=event.event_id,
        blocked_surface=blocked_surface,
        reason_summary=(
            "ClawSentry blocked this action because the supervisor classified "
            "the requested surface as critical risk."
        ),
        safe_next_step=(
            "Use a read-only inspection step or ask the operator to review a "
            "narrower alternative before retrying."
        ),
        evidence_refs=evidence_refs,
    )
    return feedback.model_dump(mode="json", by_alias=True)


def _agent_safety_feedback_delivery(
    context: DecisionContext | None,
    event: CanonicalEvent,
) -> Literal["prompt_injection", "response", "audit_only", "unsupported"]:
    caller_adapter = str(context.caller_adapter if context else "" or "").lower()
    source_framework = str(event.source_framework or "").lower()
    signals = (caller_adapter, source_framework)
    if any("a3s" in signal for signal in signals) or any(
        "openclaw" in signal for signal in signals
    ):
        return "response"
    if any(
        marker in signal for signal in signals for marker in ("codex", "gemini", "kimi")
    ):
        return "audit_only"
    return "unsupported"


def _agent_advisory_feedback(
    *,
    decision: CanonicalDecision,
    event: CanonicalEvent,
    delivery: str,
) -> dict[str, Any] | None:
    """Return a separate redacted advisory envelope for greylist scope warnings."""

    scope = decision.scope_evaluation
    if scope is None:
        return None
    greylist_warning_reasons = [
        reason
        for reason in scope.reason_codes
        if "skill_trust_state greylist" in reason
        and (reason.startswith("scope_defer:") or reason.startswith("scope_deny:"))
    ]
    if not greylist_warning_reasons:
        return None
    if decision.decision not in {
        DecisionVerdict.ALLOW,
        DecisionVerdict.DEFER,
        DecisionVerdict.BLOCK,
    }:
        return None
    feedback = AgentAdvisoryFeedback(
        delivery=delivery,
        advisory_type="greylist_skill",
        severity="warning",
        decision_id=event.event_id,
        affected_surface="skill",
        reason_summary=(
            "ClawSentry routed this action through the configured greylist "
            "Skill Trust policy."
        ),
        safe_next_step=(
            "Prefer read-only inspection or ask the operator to review the "
            "skill before continuing with state-changing work."
        ),
        evidence_refs=[f"scope:{reason}" for reason in greylist_warning_reasons[:8]],
    )
    return feedback.model_dump(mode="json", by_alias=True)
