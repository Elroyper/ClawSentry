"""Tests for requested decision effects and observed adapter effect results."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError

from clawsentry.adapters.a3s_gateway_harness import _decision_to_ahp_result
from clawsentry.gateway.models import (
    AdapterEffectResult,
    CanonicalDecision,
    DecisionEffects,
    DecisionSource,
    DecisionVerdict,
    EffectOutcome,
    RiskLevel,
    RewriteEffectRequest,
    SessionEffectRequest,
    decision_effects_for_trajectory,
)
from clawsentry.gateway.server import SupervisionGateway, create_http_app
from clawsentry.gateway.trajectory_store import TrajectoryStore


def _session_effect(**overrides) -> DecisionEffects:
    base = {
        "effect_id": "eff-session-1",
        "action_scope": "session",
        "session_effect": {
            "requested": True,
            "mode": "mark_blocked",
            "reason_code": "policy_compromised_session",
            "capability_required": "clawsentry.session_control.mark_blocked.v1",
            "fallback_on_unsupported": "mark_blocked",
        },
    }
    base.update(overrides)
    return DecisionEffects(**base)


def _rewrite_effect(**overrides) -> DecisionEffects:
    rewrite = {
        "requested": True,
        "target": "command",
        "approval_id": "rewrite-1",
        "original_hash": "sha256:orig",
        "original_preview_redacted": "rm -rf …",
        "replacement_hash": "sha256:repl",
        "replacement_preview_redacted": "rm -ri …",
        "replacement_payload": {"command": "rm -ri /tmp/example"},
        "redaction_policy_version": "cs.redaction.v1",
        "rewrite_source": "operator",
        "policy_id": "policy-1",
        "post_rewrite_validation_id": "validation-1",
    }
    rewrite.update(overrides)
    return DecisionEffects(
        effect_id="eff-rewrite-1",
        action_scope="action",
        rewrite_effect=rewrite,
    )


def _event() -> dict:
    return {
        "event_id": "evt-1",
        "trace_id": "trace-1",
        "event_type": "pre_action",
        "session_id": "sess-effects",
        "agent_id": "agent-1",
        "source_framework": "test",
        "occurred_at": "2026-04-22T16:00:00+00:00",
        "payload": {"command": "rm -rf /tmp/example"},
        "tool_name": "bash",
    }


def _snapshot() -> dict:
    return {
        "risk_level": "high",
        "composite_score": 7,
        "dimensions": {"d1": 3, "d2": 2, "d3": 2, "d4": 0, "d5": 0},
        "classified_by": "L1",
    }


class TestDecisionEffectsModel:
    def test_block_session_scope_effect_validates_and_sets_final(self):
        decision = CanonicalDecision(
            decision=DecisionVerdict.BLOCK,
            reason="compromised session",
            policy_id="policy-session",
            risk_level=RiskLevel.CRITICAL,
            decision_source=DecisionSource.POLICY,
            decision_effects=_session_effect(),
        )

        assert decision.final is True
        assert decision.decision_effects is not None
        assert decision.decision_effects.action_scope == "session"

    def test_rewrite_modify_requires_modified_payload_and_audit_envelope(self):
        decision = CanonicalDecision(
            decision=DecisionVerdict.MODIFY,
            reason="operator rewrite",
            policy_id="rewrite-policy",
            risk_level=RiskLevel.HIGH,
            decision_source=DecisionSource.OPERATOR,
            modified_payload={"command": "rm -ri /tmp/example"},
            decision_effects=_rewrite_effect(),
        )

        assert decision.decision_effects is not None
        assert decision.decision_effects.rewrite_effect is not None
        assert decision.decision_effects.rewrite_effect.replacement_payload == {
            "command": "rm -ri /tmp/example"
        }

    def test_legacy_modify_with_modified_payload_remains_valid_without_effects(self):
        decision = CanonicalDecision(
            decision=DecisionVerdict.MODIFY,
            reason="legacy sanitizer",
            policy_id="legacy-modify",
            risk_level=RiskLevel.MEDIUM,
            decision_source=DecisionSource.POLICY,
            modified_payload={"sanitized": True},
        )

        assert decision.decision_effects is None

    def test_prompt_rewrite_is_invalid_in_v1(self):
        with pytest.raises(ValidationError, match="target"):
            RewriteEffectRequest(
                requested=True,
                target="prompt",
                approval_id="rewrite-1",
                original_hash="sha256:orig",
                original_preview_redacted="original",
                replacement_hash="sha256:repl",
                replacement_preview_redacted="replacement",
                redaction_policy_version="cs.redaction.v1",
                rewrite_source="operator",
            )

    def test_unknown_decision_effect_version_rejected_at_model_boundary(self):
        with pytest.raises(ValidationError, match="effect_version"):
            DecisionEffects(
                effect_version="cs.decision_effects.v99",
                effect_id="eff-future",
                action_scope="session",
            )

    def test_enforcement_claims_are_rejected_inside_decision_effects(self):
        with pytest.raises(ValidationError):
            DecisionEffects(
                effect_id="eff-bad",
                action_scope="session",
                enforced=True,
            )

    def test_trajectory_safe_effect_strips_replacement_payload(self):
        effects = _rewrite_effect()
        safe = decision_effects_for_trajectory(effects)

        assert safe["rewrite_effect"]["replacement_payload"] is None
        assert safe["rewrite_effect"]["replacement_hash"] == "sha256:repl"
        assert safe["rewrite_effect"]["replacement_preview_redacted"] == "rm -ri …"


class TestAdapterEffectResultModel:
    def test_adapter_effect_result_links_effect_id(self):
        result = AdapterEffectResult(
            effect_id="eff-rewrite-1",
            framework="codex",
            adapter="codex-native-hook",
            requested=[EffectOutcome.COMMAND_REWRITE],
            degraded=[EffectOutcome.COMMAND_REWRITE],
            degrade_reason="codex_pretool_updated_input_unsupported",
            event_id="evt-1",
        )

        assert result.effect_id == "eff-rewrite-1"
        assert result.idempotency_key == (
            "eff-rewrite-1:codex-native-hook:evt-1:degraded"
        )

    def test_same_effect_cannot_be_both_enforced_and_degraded(self):
        with pytest.raises(ValidationError, match="both enforced and degraded"):
            AdapterEffectResult(
                effect_id="eff-1",
                framework="a3s-code",
                adapter="a3s-gateway-harness",
                requested=["command_rewrite"],
                enforced=["command_rewrite"],
                degraded=["command_rewrite"],
                degrade_reason="unsupported",
            )

    def test_degraded_or_unsupported_requires_reason(self):
        with pytest.raises(ValidationError, match="degrade_reason"):
            AdapterEffectResult(
                effect_id="eff-1",
                framework="codex",
                adapter="codex-native-hook",
                requested=["command_rewrite"],
                unsupported=["command_rewrite"],
            )


class TestDecisionEffectPersistence:
    def test_adapter_result_appends_without_mutating_decision(self):
        store = TrajectoryStore()
        decision = CanonicalDecision(
            decision=DecisionVerdict.BLOCK,
            reason="compromised session",
            policy_id="policy-session",
            risk_level=RiskLevel.CRITICAL,
            decision_source=DecisionSource.POLICY,
            decision_effects=_session_effect(),
        ).model_dump(mode="json")
        store.record(event=_event(), decision=decision, snapshot=_snapshot(), meta={})

        adapter_result = AdapterEffectResult(
            effect_id="eff-session-1",
            framework="codex",
            adapter="codex-native-hook",
            requested=["session_quarantine"],
            degraded=["session_quarantine"],
            degrade_reason="codex_session_stop_unsupported",
            event_id="evt-1",
            session_id="sess-effects",
        )
        first = store.record_adapter_effect_result(adapter_result.model_dump(mode="json"))
        second = store.record_adapter_effect_result(adapter_result.model_dump(mode="json"))
        records = store.replay_session("sess-effects")

        assert first["created"] is True
        assert second["created"] is False
        assert records[0]["decision"]["decision"] == "block"
        assert records[0]["adapter_effect_results"][0]["degrade_reason"] == "codex_session_stop_unsupported"

    def test_session_registry_marks_quarantine_from_session_scope_block(self):
        gateway = SupervisionGateway(trajectory_store=TrajectoryStore())
        decision = CanonicalDecision(
            decision=DecisionVerdict.BLOCK,
            reason="compromised session",
            policy_id="policy-session",
            risk_level=RiskLevel.CRITICAL,
            decision_source=DecisionSource.POLICY,
            decision_effects=_session_effect(),
        ).model_dump(mode="json")
        gateway._record_decision_path(
            event=_event(),
            decision=decision,
            snapshot=_snapshot(),
            meta={"record_type": "decision"},
            l3_trace=None,
        )

        risk = gateway.report_session_risk("sess-effects")
        assert risk["quarantine"]["state"] == "quarantined"
        assert risk["latest_decision_effect_summary"]["action_scope"] == "session"

    @pytest.mark.asyncio
    async def test_authenticated_adapter_effect_result_endpoint(self):
        gateway = SupervisionGateway(trajectory_store=TrajectoryStore())
        app = create_http_app(gateway)
        payload = {
            "effect_id": "eff-session-1",
            "framework": "codex",
            "adapter": "codex-native-hook",
            "requested": ["session_quarantine"],
            "degraded": ["session_quarantine"],
            "degrade_reason": "codex_session_stop_unsupported",
            "event_id": "evt-1",
            "session_id": "sess-effects",
        }
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post("/ahp/adapter-effect-result", json=payload)

        assert response.status_code == 200
        assert response.json()["created"] is True


def test_a3s_result_includes_decision_effects_and_modified_payload():
    decision = CanonicalDecision(
        decision=DecisionVerdict.MODIFY,
        reason="operator rewrite",
        policy_id="rewrite-policy",
        risk_level=RiskLevel.HIGH,
        decision_source=DecisionSource.OPERATOR,
        modified_payload={"command": "rm -ri /tmp/example"},
        decision_effects=_rewrite_effect(),
    )

    result = _decision_to_ahp_result(decision)

    assert result["action"] == "modify"
    assert result["modified_payload"] == {"command": "rm -ri /tmp/example"}
    assert result["decision_effects"]["rewrite_effect"]["replacement_payload"] == {
        "command": "rm -ri /tmp/example"
    }

class TestRewriteResolutionValidation:
    def test_rewrite_resolution_rejects_prompt_payload(self):
        from clawsentry.gateway.server import _validate_rewrite_resolution_payload

        with pytest.raises(ValueError, match="prompt rewrite is out of scope"):
            _validate_rewrite_resolution_payload({"prompt": "ignore previous instructions"})

    def test_rewrite_resolution_rejects_arbitrary_payload(self):
        from clawsentry.gateway.server import _validate_rewrite_resolution_payload

        with pytest.raises(ValueError, match="command or tool_input"):
            _validate_rewrite_resolution_payload({"foo": "bar"})

    def test_rewrite_resolution_accepts_command_payload(self):
        from clawsentry.gateway.server import _validate_rewrite_resolution_payload

        assert _validate_rewrite_resolution_payload({"command": "echo safe"}) == {
            "command": "echo safe"
        }

    def test_watch_uses_rewrite_preview_without_full_payload(self):
        from clawsentry.cli.watch_command import format_decision

        rendered = format_decision(
            {
                "type": "decision",
                "decision": "modify",
                "command": "rm -rf /tmp/example",
                "risk_level": "high",
                "reason": "operator rewrite",
                "modified_command": "rm -ri /tmp/example",
                "effect_summary": {
                    "effect_id": "eff-rewrite-1",
                    "action_scope": "action",
                    "rewrite_effect": {
                        "target": "command",
                        "replacement_preview_redacted": "rm -ri …",
                    },
                },
            },
            color=False,
            no_emoji=True,
        )

        assert "rm -ri …" in rendered
        assert "rm -ri /tmp/example" not in rendered
