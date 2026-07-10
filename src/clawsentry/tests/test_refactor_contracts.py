"""Refactor contracts for legacy gateway and FSPR import paths."""

from __future__ import annotations

import hashlib
import importlib
import json
import sys
from pathlib import Path

import pytest


def test_gateway_server_legacy_exports_remain_available() -> None:
    gateway_server = importlib.import_module("clawsentry.gateway.server")
    expected = [
        "SupervisionGateway",
        "create_http_app",
        "start_uds_server",
        "run_gateway",
        "main",
        "TrajectoryStore",
        "EventBus",
        "AlertRegistry",
        "_RateLimiter",
        "_gateway_args_from_env",
        "_make_auth_dependency",
        "_read_auth_token",
        "_context_with_skill_trust_raw",
        "_apply_gateway_owned_first_use_package_review",
        "_validate_rewrite_resolution_payload",
        "_find_and_reload_pattern_matcher",
        "_read_skill_trust_registry_payload",
        "_write_skill_trust_registry_payload",
        "_l3_trace_for_persistence",
        "_build_window_risk_summary",
        "_lineage_summary_from_event",
        "_lineage_event_from_summary",
        "_lineage_events_from_summary",
        "apply_lifecycle_transition",
        "_infer_source_framework",
    ]
    missing = [name for name in expected if not hasattr(gateway_server, name)]
    assert missing == []


def test_first_use_skill_review_legacy_exports_remain_available() -> None:
    fspr_review = importlib.import_module("clawsentry.gateway.first_use_skill_review")
    expected = [
        "FSPRResult",
        "FSPRLLMRoleProvider",
        "FSPRReadOnlyToolkit",
        "build_fspr_cache_key",
        "build_fspr_agentic_readonly_prompt",
        "build_fspr_inventory",
        "build_fspr_role_prompt",
        "run_agentic_readonly_fspr_review",
        "run_first_use_skill_package_review",
        "tomllib",
        "_build_agentic_coverage_plan",
        "_parse_agentic_tool_call_response",
        "_agentic_strict_final_prompt",
        "_AGENTIC_PROTOCOL_VERSION",
    ]
    missing = [name for name in expected if not hasattr(fspr_review, name)]
    assert missing == []


def test_gateway_server_fspr_cache_monkeypatch_contract(monkeypatch) -> None:
    gateway_server = importlib.import_module("clawsentry.gateway.server")
    replacement: dict[str, object] = {}
    monkeypatch.setattr(gateway_server, "_FSPR_REVIEW_CACHE", replacement)
    assert gateway_server._FSPR_REVIEW_CACHE is replacement


def test_gateway_server_provider_factory_monkeypatch_contract(monkeypatch) -> None:
    gateway_server = importlib.import_module("clawsentry.gateway.server")
    sentinel = object()
    monkeypatch.setattr(gateway_server, "build_provider_from_env", lambda: sentinel)
    assert gateway_server.build_provider_from_env() is sentinel


def test_supervision_gateway_init_uses_facade_provider_factory(monkeypatch) -> None:
    from clawsentry.gateway.config.detection_config import DetectionConfig

    gateway_server = importlib.import_module("clawsentry.gateway.server")

    class _Provider:
        @property
        def provider_id(self) -> str:
            return "contract-provider"

        async def complete(self, *args, **kwargs) -> str:
            del args, kwargs
            return "{}"

    provider = _Provider()
    monkeypatch.setattr(gateway_server, "build_provider_from_env", lambda: provider)

    gateway = gateway_server.SupervisionGateway(
        detection_config=DetectionConfig(anti_bypass_llm_recognition_enabled=True),
    )

    assert getattr(gateway.anti_bypass_llm_provider, "_inner", None) is provider


def test_gateway_server_lifecycle_monkeypatch_contract(monkeypatch) -> None:
    gateway_server = importlib.import_module("clawsentry.gateway.server")
    sentinel = object()
    monkeypatch.setattr(
        gateway_server,
        "apply_lifecycle_transition",
        lambda *args, **kwargs: sentinel,
    )
    assert gateway_server.apply_lifecycle_transition() is sentinel


@pytest.mark.asyncio
async def test_skill_trust_transition_http_uses_facade_lifecycle(
    monkeypatch,
    tmp_path,
) -> None:
    from httpx import ASGITransport, AsyncClient

    gateway_server = importlib.import_module("clawsentry.gateway.server")
    DetectionConfig = importlib.import_module(
        "clawsentry.gateway.config.detection_config"
    ).DetectionConfig

    registry = tmp_path / "skill-registry.json"
    registry.write_text(
        json.dumps(
            {
                "schema_version": "clawsentry.skill_registry.v1",
                "records": [
                    {
                        "canonical_skill_id": "skill:docs-reader",
                        "canonical_name": "docs-reader",
                        "source": {"path_hash": "sha256:" + "0" * 64},
                        "trust_level": "trusted",
                        "list_state": "allowlist",
                        "status": "trusted",
                        "policy_fingerprint": "sha256:test-policy",
                    }
                ],
                "transition_events": [],
            }
        ),
        encoding="utf-8",
    )
    gateway = gateway_server.SupervisionGateway(
        trajectory_db_path=":memory:",
        detection_config=DetectionConfig(skill_trust_registry_path=str(registry)),
    )
    app = gateway_server.create_http_app(gateway)
    original_apply = gateway_server.apply_lifecycle_transition
    calls: list[dict[str, object]] = []

    def patched_apply_lifecycle_transition(*args, **kwargs):
        calls.append(kwargs)
        return original_apply(*args, **kwargs)

    monkeypatch.setattr(
        gateway_server,
        "apply_lifecycle_transition",
        patched_apply_lifecycle_transition,
    )

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        listed = await client.get("/skill-trust/registry")
        snapshot_id = listed.json()["registry_snapshot_id"]
        changed = await client.post(
            "/skill-trust/transition",
            json={
                "canonical_skill_id": "skill:docs-reader",
                "target_state": "revoked",
                "reason_code": "operator_revoke",
                "expected_registry_snapshot_id": snapshot_id,
                "idempotency_key": "contract-facade-lifecycle",
                "operator_id_hash": "sha256:" + "2" * 64,
            },
        )

    assert changed.status_code == 200
    assert calls
    assert calls[0]["target_state"] == "revoked"


def test_gateway_owned_fspr_uses_facade_review_runner(monkeypatch, tmp_path) -> None:
    from clawsentry.gateway.config.detection_config import DetectionConfig
    from clawsentry.gateway.first_use_skill_review import FSPRResult
    from clawsentry.gateway.models import CanonicalEvent, EventType

    gateway_server = importlib.import_module("clawsentry.gateway.server")
    skill_root = tmp_path / "contract-skill"
    skill_root.mkdir()
    (skill_root / "SKILL.md").write_text(
        "---\nname: contract-skill\n---\nCreate a concise status report.\n",
        encoding="utf-8",
    )
    raw_metadata = {
        "gateway_owned_metadata": True,
        "skill_root_path": str(skill_root),
        "registry_snapshot_id": "registry-contract",
        "policy_fingerprint": "policy-contract",
    }
    event = CanonicalEvent(
        schema_version="ahp.1.0",
        event_id="evt-contract-fspr",
        trace_id="trace-contract-fspr",
        event_type=EventType.PRE_ACTION,
        session_id="sess-contract-fspr",
        agent_id="agent-contract",
        source_framework="test",
        occurred_at="2026-05-19T00:00:00+00:00",
        tool_name="read_file",
        payload={"path": "/workspace/README.md"},
    )

    calls: list[dict[str, object]] = []

    def fake_review(skill_root_arg, **kwargs):
        calls.append({"skill_root": skill_root_arg, **kwargs})
        return FSPRResult(
            schema="clawsentry.first_use_skill_package_review.v1",
            timing_mode=kwargs["timing_mode"],
            verdict="consistent",
            severity="low",
            confidence=0.99,
            role_results=[],
            final_findings=[],
            evidence_capsule={
                "schema": "clawsentry.fspr_evidence_capsule.v1",
            },
            cache={"hit": False, "reason": "not_cached"},
        )

    replacement_cache: dict[str, object] = {}
    monkeypatch.setattr(
        gateway_server, "run_first_use_skill_package_review", fake_review
    )
    monkeypatch.setattr(gateway_server, "_FSPR_REVIEW_CACHE", replacement_cache)

    gateway_server._apply_gateway_owned_first_use_package_review(
        raw_metadata,
        event=event,
        detection_config=DetectionConfig(
            skill_trust_fspr_enabled=True,
            skill_trust_fspr_pre_use_enabled=True,
            skill_trust_fspr_provider_enabled=False,
            skill_trust_fspr_cache_enabled=True,
        ),
    )

    assert calls
    assert calls[0]["skill_root"] == str(skill_root)
    assert calls[0]["cache"] is replacement_cache
    assert raw_metadata["first_use_package_review"]["verdict"] == "consistent"


@pytest.mark.asyncio
async def test_supervision_gateway_fspr_flow_uses_facade_review_runner(
    monkeypatch,
    tmp_path,
) -> None:
    from clawsentry.gateway.config.detection_config import DetectionConfig
    from clawsentry.gateway.first_use_skill_review import FSPRResult
    from clawsentry.gateway.models import RPC_VERSION

    gateway_server = importlib.import_module("clawsentry.gateway.server")
    skill_root = tmp_path / "contract-flow-skill"
    skill_root.mkdir()
    (skill_root / "SKILL.md").write_text(
        "---\nname: contract-flow-skill\n---\nCreate a concise status report.\n",
        encoding="utf-8",
    )
    metadata = tmp_path / "skill-trust-runtime.json"
    metadata.write_text(
        json.dumps(
            {
                "raw_metadata_by_skill": {
                    "contract-flow-skill": {
                        "canonical_skill_id": "skill:contract-flow-skill",
                        "canonical_name": "contract-flow-skill",
                        "skill_root_path": str(skill_root),
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("CS_SKILL_TRUST_METADATA_PATH", str(metadata))

    calls: list[dict[str, object]] = []

    def fake_review(skill_root_arg, **kwargs):
        calls.append({"skill_root": skill_root_arg, **kwargs})
        return FSPRResult(
            schema="clawsentry.first_use_skill_package_review.v1",
            timing_mode=kwargs["timing_mode"],
            verdict="consistent",
            severity="low",
            confidence=0.99,
            role_results=[],
            final_findings=[],
            evidence_capsule={
                "schema": "clawsentry.fspr_evidence_capsule.v1",
            },
            cache={"hit": False, "reason": "not_cached"},
        )

    monkeypatch.setattr(
        gateway_server, "run_first_use_skill_package_review", fake_review
    )
    gateway = gateway_server.SupervisionGateway(
        trajectory_db_path=":memory:",
        detection_config=DetectionConfig(
            skill_trust_fspr_enabled=True,
            skill_trust_fspr_pre_use_enabled=True,
            skill_trust_fspr_provider_enabled=False,
        ),
    )
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "ahp/sync_decision",
        "params": {
            "rpc_version": RPC_VERSION,
            "request_id": "req-contract-fspr-flow",
            "deadline_ms": 1000,
            "decision_tier": "L1",
            "event": {
                "event_id": "evt-contract-fspr-flow",
                "trace_id": "trace-contract-fspr-flow",
                "event_type": "pre_action",
                "session_id": "sess-contract-fspr-flow",
                "agent_id": "agent-contract",
                "source_framework": "test",
                "occurred_at": "2026-05-19T00:00:00+00:00",
                "tool_name": "read_file",
                "payload": {
                    "path": "/workspace/README.md",
                    "_clawsentry_meta": {
                        "skill_trust_raw": {
                            "presented_name": "contract-flow-skill",
                        }
                    },
                },
            },
        },
    }

    response = await gateway.handle_jsonrpc(json.dumps(body).encode("utf-8"))

    assert "result" in response
    assert calls
    assert calls[0]["skill_root"] == str(skill_root)
    records = gateway.replay_session("sess-contract-fspr-flow")["records"]
    assert records


@pytest.mark.asyncio
async def test_supervision_gateway_default_fspr_flow_wires_agentic_runner(
    monkeypatch,
    tmp_path,
) -> None:
    from clawsentry.gateway.config.detection_config import DetectionConfig
    from clawsentry.gateway.first_use_skill_review import FSPRResult
    from clawsentry.gateway.models import RPC_VERSION

    core_gateway = importlib.import_module(
        "clawsentry.gateway.core.supervision_gateway"
    )
    fspr_review = importlib.import_module("clawsentry.gateway.first_use_skill_review")
    skill_root = tmp_path / "contract-core-agentic-skill"
    skill_root.mkdir()
    (skill_root / "SKILL.md").write_text(
        "---\nname: contract-core-agentic-skill\n---\nCreate a concise status report.\n",
        encoding="utf-8",
    )
    metadata = tmp_path / "skill-trust-runtime.json"
    metadata.write_text(
        json.dumps(
            {
                "raw_metadata_by_skill": {
                    "contract-core-agentic-skill": {
                        "canonical_skill_id": "skill:contract-core-agentic-skill",
                        "canonical_name": "contract-core-agentic-skill",
                        "skill_root_path": str(skill_root),
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("CS_SKILL_TRUST_METADATA_PATH", str(metadata))

    calls: list[dict[str, object]] = []

    def fake_agentic_review(skill_root_arg, **kwargs):
        calls.append({"skill_root": skill_root_arg, **kwargs})
        return FSPRResult(
            schema="clawsentry.first_use_skill_package_review.v1",
            timing_mode=kwargs["timing_mode"],
            verdict="suspicious",
            severity="medium",
            confidence=0.88,
            role_results=[],
            final_findings=[],
            evidence_capsule={
                "schema": "clawsentry.fspr_evidence_capsule.v2",
            },
            cache={"hit": False, "reason": "not_cached"},
        )

    class _Provider:
        async def complete(self, *args, **kwargs) -> str:
            del args, kwargs
            return "{}"

    monkeypatch.setattr(
        core_gateway,
        "_apply_gateway_owned_first_use_package_review_hook",
        core_gateway._apply_default_gateway_owned_first_use_package_review,
    )
    monkeypatch.setattr(
        core_gateway,
        "_build_provider_from_env_hook",
        lambda: _Provider(),
    )
    monkeypatch.setattr(
        fspr_review,
        "run_agentic_readonly_fspr_review",
        fake_agentic_review,
    )
    gateway = core_gateway.SupervisionGateway(
        trajectory_db_path=":memory:",
        detection_config=DetectionConfig(
            mode="normal",
            skill_trust_fspr_enabled=True,
            skill_trust_fspr_pre_use_enabled=True,
            skill_trust_fspr_review_mode="agentic-readonly",
            skill_trust_fspr_provider_enabled=True,
            skill_trust_fspr_provider_sync_profiles=("normal",),
        ),
    )
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "ahp/sync_decision",
        "params": {
            "rpc_version": RPC_VERSION,
            "request_id": "req-core-agentic-fspr-flow",
            "deadline_ms": 1000,
            "decision_tier": "L1",
            "event": {
                "event_id": "evt-core-agentic-fspr-flow",
                "trace_id": "trace-core-agentic-fspr-flow",
                "event_type": "pre_action",
                "session_id": "sess-core-agentic-fspr-flow",
                "agent_id": "agent-contract",
                "source_framework": "test",
                "occurred_at": "2026-05-19T00:00:00+00:00",
                "tool_name": "read_file",
                "payload": {
                    "path": "/workspace/README.md",
                    "_clawsentry_meta": {
                        "skill_trust_raw": {
                            "presented_name": "contract-core-agentic-skill",
                        }
                    },
                },
            },
        },
    }

    response = await gateway.handle_jsonrpc(json.dumps(body).encode("utf-8"))

    assert "result" in response
    assert calls
    assert calls[0]["skill_root"] == str(skill_root)
    assert calls[0]["provider"] is not None
    records = gateway.replay_session("sess-core-agentic-fspr-flow")["records"]
    assert records


def test_gateway_owned_fspr_uses_facade_agentic_runner(monkeypatch, tmp_path) -> None:
    from clawsentry.gateway.config.detection_config import DetectionConfig
    from clawsentry.gateway.first_use_skill_review import FSPRResult
    from clawsentry.gateway.models import CanonicalEvent, EventType

    gateway_server = importlib.import_module("clawsentry.gateway.server")
    skill_root = tmp_path / "contract-agentic-skill"
    skill_root.mkdir()
    (skill_root / "SKILL.md").write_text(
        "---\nname: contract-agentic-skill\n---\nCreate a concise status report.\n",
        encoding="utf-8",
    )
    raw_metadata = {
        "gateway_owned_metadata": True,
        "skill_root_path": str(skill_root),
        "registry_snapshot_id": "registry-contract",
        "policy_fingerprint": "policy-contract",
    }
    event = CanonicalEvent(
        schema_version="ahp.1.0",
        event_id="evt-contract-agentic",
        trace_id="trace-contract-agentic",
        event_type=EventType.PRE_ACTION,
        session_id="sess-contract-agentic",
        agent_id="agent-contract",
        source_framework="test",
        occurred_at="2026-05-19T00:00:00+00:00",
        tool_name="read_file",
        payload={"path": "/workspace/README.md"},
    )

    calls: list[dict[str, object]] = []

    def fake_agentic_review(skill_root_arg, **kwargs):
        calls.append({"skill_root": skill_root_arg, **kwargs})
        return FSPRResult(
            schema="clawsentry.first_use_skill_package_review.v1",
            timing_mode=kwargs["timing_mode"],
            verdict="suspicious",
            severity="medium",
            confidence=0.88,
            role_results=[],
            final_findings=[],
            evidence_capsule={
                "schema": "clawsentry.fspr_evidence_capsule.v1",
            },
            cache={"hit": False, "reason": "not_cached"},
        )

    class _Provider:
        def review_role(self, *, role: str, prompt: str) -> str:
            raise AssertionError(
                "facade-patched agentic runner should replace provider calls"
            )

    monkeypatch.setattr(
        gateway_server,
        "run_agentic_readonly_fspr_review",
        fake_agentic_review,
    )
    monkeypatch.setattr(gateway_server, "build_provider_from_env", lambda: _Provider())

    gateway_server._apply_gateway_owned_first_use_package_review(
        raw_metadata,
        event=event,
        detection_config=DetectionConfig(
            skill_trust_fspr_enabled=True,
            skill_trust_fspr_pre_use_enabled=True,
            skill_trust_fspr_review_mode="agentic-readonly",
            skill_trust_fspr_provider_enabled=True,
            skill_trust_fspr_provider_sync_profiles=("normal",),
        ),
    )

    assert calls
    assert raw_metadata["first_use_package_review"]["verdict"] == "suspicious"
    assert raw_metadata["fspr_review_summary"]["provider_used"] is True


def test_first_use_review_uses_facade_cache_key(monkeypatch, tmp_path) -> None:
    fspr_review = importlib.import_module("clawsentry.gateway.first_use_skill_review")
    skill_root = tmp_path / "contract-cache-skill"
    skill_root.mkdir()
    (skill_root / "SKILL.md").write_text(
        "---\nname: contract-cache-skill\n---\nCreate a concise status report.\n",
        encoding="utf-8",
    )

    calls: list[object] = []

    def fake_cache_key(*args, **kwargs):
        calls.append((args, kwargs))
        return "contract-cache-key"

    monkeypatch.setattr(fspr_review, "build_fspr_cache_key", fake_cache_key)
    cache = {}
    first = fspr_review.run_first_use_skill_package_review(
        skill_root,
        registry_snapshot_id="registry",
        policy_fingerprint="policy",
        cache=cache,
    )
    second = fspr_review.run_first_use_skill_package_review(
        skill_root,
        registry_snapshot_id="registry",
        policy_fingerprint="policy",
        cache=cache,
    )

    assert calls
    assert first.cache_hit is False
    assert second.cache_hit is True
    assert list(cache) == ["contract-cache-key"]


def test_fspr_cache_key_direct_monkeypatch_contract(monkeypatch, tmp_path) -> None:
    fspr_review = importlib.import_module("clawsentry.gateway.first_use_skill_review")
    skill_root = tmp_path / "contract-skill"
    skill_root.mkdir()
    (skill_root / "SKILL.md").write_text(
        "---\nname: contract-skill\n---\nCreate a concise status report.\n",
        encoding="utf-8",
    )

    calls: list[object] = []

    def fake_cache_key(*args, **kwargs):
        calls.append((args, kwargs))
        return "contract-cache-key"

    monkeypatch.setattr(fspr_review, "build_fspr_cache_key", fake_cache_key)
    assert (
        fspr_review.build_fspr_cache_key(
            skill_root,
            registry_snapshot_id="registry",
            policy_fingerprint="policy",
        )
        == "contract-cache-key"
    )
    assert calls


def _contract_skill_root(tmp_path: Path) -> Path:
    skill_root = tmp_path / "contract-skill"
    skill_root.mkdir()
    (skill_root / "SKILL.md").write_text(
        "---\nname: contract-skill\n---\n"
        "Create a concise status report from local notes.\n",
        encoding="utf-8",
    )
    (skill_root / "helper.py").write_text(
        "from pathlib import Path\n"
        "def read_notes(path: str) -> str:\n"
        "    return Path(path).read_text(encoding='utf-8')\n",
        encoding="utf-8",
    )
    return skill_root


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _normalize_prompt(prompt: str, skill_root: Path) -> str:
    return prompt.replace(str(skill_root), "<SKILL_ROOT>")


FSPR_CONTRACT_ROLE_PROMPT_SHA256 = (
    "2810dbec6fabff85ed459e71149f4480a28c4b3b852bbda4791b583b88a87000"
)
FSPR_CONTRACT_AGENTIC_PROMPT_SHA256 = (
    "40b0d1a9a014e6f60bbd3c5c5a5bd9c95baec1ddb548b662e98bb596b660f57e"
)
FSPR_CONTRACT_STRICT_PROMPT_SHA256 = (
    "b4d34cfd34e0380173fe343886c7de1721f4b9670c1103ef748c9ae534087674"
)
FSPR_CONTRACT_CACHE_KEY = (
    "sha256:5cf8e51e9d65ee1b991501c16f9809517262309ee29e13f6bc865f8080926d43"
)


def test_fspr_prompt_contract_hashes(tmp_path: Path) -> None:
    from clawsentry.gateway import first_use_skill_review as fspr_review
    from clawsentry.gateway.first_use_skill_review import (
        build_fspr_agentic_readonly_prompt,
        build_fspr_inventory,
        build_fspr_role_prompt,
    )

    skill_root = _contract_skill_root(tmp_path)
    inventory = build_fspr_inventory(skill_root)
    role_prompt = _normalize_prompt(
        build_fspr_role_prompt("final_adjudicator", inventory),
        skill_root,
    )
    agentic_prompt = _normalize_prompt(
        build_fspr_agentic_readonly_prompt(inventory),
        skill_root,
    )
    strict_prompt = _normalize_prompt(
        fspr_review._agentic_strict_final_prompt(
            trace_summary={},
            coverage_state={
                "satisfied": True,
                "missing_required_paths": [],
                "missing_truncation_followups": [],
            },
            semantic_evidence=[
                {
                    "evidence_ref": "file:SKILL.md",
                    "content": "Create a concise status report.",
                }
            ],
            deterministic_findings=[],
        ),
        skill_root,
    )

    assert _sha256_text(role_prompt) == FSPR_CONTRACT_ROLE_PROMPT_SHA256
    assert _sha256_text(agentic_prompt) == FSPR_CONTRACT_AGENTIC_PROMPT_SHA256
    assert _sha256_text(strict_prompt) == FSPR_CONTRACT_STRICT_PROMPT_SHA256


def test_fspr_cache_key_contract(tmp_path: Path) -> None:
    from clawsentry.gateway.first_use_skill_review import build_fspr_cache_key

    skill_root = _contract_skill_root(tmp_path)
    assert (
        build_fspr_cache_key(
            skill_root,
            registry_snapshot_id="registry-contract",
            policy_fingerprint="policy-contract",
            role_set_version="roles.contract",
            policy_profile="normal",
            budget_class="default",
        )
        == FSPR_CONTRACT_CACHE_KEY
    )


GATEWAY_DIRECTORY_IMPORT_PAIRS = {
    "clawsentry.gateway.agent_analyzer": "clawsentry.gateway.analysis.agent_analyzer",
    "clawsentry.gateway.detection_config": "clawsentry.gateway.config.detection_config",
    "clawsentry.gateway.effect_normalizer": "clawsentry.gateway.effects.normalizer",
    "clawsentry.gateway.llm_factory": "clawsentry.gateway.llm.factory",
    "clawsentry.gateway.llm_provider": "clawsentry.gateway.llm.provider",
    "clawsentry.gateway.policy_engine": "clawsentry.gateway.policy.engine",
    "clawsentry.gateway.review_skills": "clawsentry.gateway.review.skills",
    "clawsentry.gateway.pattern_matcher": "clawsentry.gateway.rules.pattern_matcher",
    "clawsentry.gateway.codex_watcher": "clawsentry.gateway.runtime.codex_watcher",
    "clawsentry.gateway.trajectory_store": "clawsentry.gateway.storage.trajectory_store",
    "clawsentry.gateway.metrics": "clawsentry.gateway.telemetry.metrics",
    "clawsentry.gateway.l3_trigger": "clawsentry.gateway.l3.trigger",
    "clawsentry.gateway.skill_trust": "clawsentry.gateway.trust.skill_trust",
}


def test_gateway_grouped_import_paths_are_available() -> None:
    for new_path in GATEWAY_DIRECTORY_IMPORT_PAIRS.values():
        assert importlib.import_module(new_path).__name__ == new_path


def test_gateway_legacy_import_paths_alias_new_modules() -> None:
    gateway_pkg = importlib.import_module("clawsentry.gateway")
    alias_map = gateway_pkg._legacy_aliases()
    assert len(alias_map) >= len(GATEWAY_DIRECTORY_IMPORT_PAIRS)

    for old_name, new_suffix in alias_map.items():
        old_path = f"clawsentry.gateway.{old_name}"
        new_path = f"clawsentry.gateway.{new_suffix}"
        try:
            delattr(gateway_pkg, old_name)
        except AttributeError:
            pass
        sys.modules.pop(old_path, None)
        # Keep canonical modules intact. Pytest may already have collected tests
        # with live references to classes from these modules; replacing the
        # canonical module object would create split globals for later tests.
        old_module = importlib.import_module(old_path)
        new_module = importlib.import_module(new_path)
        assert old_module is new_module
        assert getattr(gateway_pkg, old_name) is new_module
        assert old_module.__name__ == new_path
        assert old_module.__spec__ is not None
        assert old_module.__spec__.name == new_path


def test_gateway_package_import_does_not_eagerly_load_legacy_modules() -> None:
    gateway_pkg = importlib.import_module("clawsentry.gateway")
    for old_name in gateway_pkg._legacy_aliases():
        sys.modules.pop(f"clawsentry.gateway.{old_name}", None)

    importlib.reload(gateway_pkg)

    loaded_legacy_modules = [
        old_name
        for old_name in gateway_pkg._legacy_aliases()
        if f"clawsentry.gateway.{old_name}" in sys.modules
    ]
    assert loaded_legacy_modules == []


def test_gateway_legacy_alias_finder_installs_once() -> None:
    gateway_pkg = importlib.import_module("clawsentry.gateway")
    gateway_pkg._install_legacy_alias_finder()
    gateway_pkg._install_legacy_alias_finder()

    markers = [
        getattr(finder, "_marker", None)
        for finder in sys.meta_path
        if getattr(finder, "_marker", None)
        == "clawsentry-gateway-legacy-alias-finder"
    ]
    assert markers == ["clawsentry-gateway-legacy-alias-finder"]


def test_gateway_old_from_imports_remain_compatible() -> None:
    from clawsentry.gateway.policy_engine import L1PolicyEngine
    from clawsentry.gateway.pattern_matcher import PatternMatcher
    from clawsentry.gateway.trajectory_store import TrajectoryStore

    assert L1PolicyEngine.__module__ == "clawsentry.gateway.policy.engine"
    assert PatternMatcher.__module__ == "clawsentry.gateway.rules.pattern_matcher"
    assert TrajectoryStore.__module__ == "clawsentry.gateway.storage.trajectory_store"


def test_gateway_directory_slimming_layout() -> None:
    gateway_root = Path(__file__).resolve().parents[1] / "gateway"
    removed_top_level_files = [
        "agent_analyzer.py",
        "detection_config.py",
        "effect_normalizer.py",
        "llm_factory.py",
        "llm_provider.py",
        "pattern_matcher.py",
        "policy_engine.py",
        "review_skills.py",
        "skill_trust.py",
        "trajectory_store.py",
    ]
    remaining_entry_files = [
        "__init__.py",
        "first_use_skill_review.py",
        "models.py",
        "server.py",
        "stack.py",
    ]

    for filename in removed_top_level_files:
        assert not (gateway_root / filename).exists()
    for filename in remaining_entry_files:
        assert (gateway_root / filename).exists()


def test_gateway_stack_remains_module_execution_wrapper() -> None:
    stack_module = importlib.import_module("clawsentry.gateway.stack")
    runtime_stack = importlib.import_module("clawsentry.gateway.runtime.stack")

    assert stack_module.main is runtime_stack.main
    assert stack_module.__file__ is not None
    assert stack_module.__file__.endswith("gateway/stack.py")


def test_gateway_runtime_stack_imports_latch_from_top_level_package() -> None:
    runtime_stack = importlib.import_module("clawsentry.gateway.runtime.stack")
    source = Path(runtime_stack.__file__).read_text(encoding="utf-8")

    assert "from clawsentry.latch.hub_bridge import LatchHubBridge" in source
    assert "from ..latch.hub_bridge import LatchHubBridge" not in source
