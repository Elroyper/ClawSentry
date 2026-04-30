"""Tests for explicit L3 advisory worker adapters."""

from __future__ import annotations

import json

from clawsentry.gateway.l3_advisory_worker import (
    FakeLLMAdvisoryWorker,
    FakeProviderAdvisoryWorker,
    LLMProviderBridgeAdvisoryProvider,
    LLMProviderAdvisoryWorker,
    LLMAdvisoryProviderConfig,
    OpenAIAdvisoryProvider,
    AnthropicAdvisoryProvider,
    build_l3_advisory_provider,
    extract_l3_advisory_response_json,
    build_l3_advisory_worker_request,
    parse_l3_advisory_worker_response,
    resolve_l3_advisory_provider_config,
    run_l3_advisory_worker_job,
)
from clawsentry.gateway.trajectory_store import TrajectoryStore
from clawsentry.tests.test_l3_advisory_foundation import _record


def test_fake_llm_worker_consumes_only_frozen_snapshot_records() -> None:
    store = TrajectoryStore(retention_seconds=0)
    first_record_id = _record(
        store,
        session_id="sess-l3-worker",
        event_id="evt-worker-1",
        decision="allow",
        risk_level="low",
        recorded_at_ts=1.0,
    )
    second_record_id = _record(
        store,
        session_id="sess-l3-worker",
        event_id="evt-worker-2",
        decision="block",
        risk_level="critical",
        recorded_at_ts=2.0,
    )
    snapshot = store.create_l3_evidence_snapshot(
        session_id="sess-l3-worker",
        trigger_event_id="evt-worker-2",
        trigger_reason="threshold",
        to_record_id=second_record_id,
    )
    job = store.enqueue_l3_advisory_job(
        snapshot["snapshot_id"],
        runner=FakeLLMAdvisoryWorker.runner_name,
    )
    _record(
        store,
        session_id="sess-l3-worker",
        event_id="evt-live-after-worker-snapshot",
        decision="block",
        risk_level="critical",
        recorded_at_ts=3.0,
    )

    result = run_l3_advisory_worker_job(
        store=store,
        job_id=job["job_id"],
        worker=FakeLLMAdvisoryWorker(),
    )

    assert result["job"]["job_state"] == "completed"
    assert result["job"]["review_id"] == result["review"]["review_id"]
    assert result["review"]["review_runner"] == "fake_llm"
    assert result["review"]["worker_backend"] == "fake_llm"
    assert result["review"]["risk_level"] == "critical"
    assert result["review"]["recommended_operator_action"] == "escalate"
    assert result["review"]["evidence_event_ids"] == ["evt-worker-1", "evt-worker-2"]
    assert "evt-live-after-worker-snapshot" not in result["review"]["evidence_event_ids"]
    assert result["review"]["source_record_range"] == {
        "from_record_id": first_record_id,
        "to_record_id": second_record_id,
    }
    assert any("fake_llm" in finding for finding in result["review"]["findings"])


def test_worker_rejects_mismatched_job_runner() -> None:
    store = TrajectoryStore(retention_seconds=0)
    record_id = _record(
        store,
        session_id="sess-l3-worker",
        event_id="evt-worker-mismatch",
        decision="block",
        risk_level="high",
        recorded_at_ts=1.0,
    )
    snapshot = store.create_l3_evidence_snapshot(
        session_id="sess-l3-worker",
        trigger_event_id="evt-worker-mismatch",
        trigger_reason="threshold",
        to_record_id=record_id,
    )
    job = store.enqueue_l3_advisory_job(snapshot["snapshot_id"], runner="deterministic_local")

    try:
        run_l3_advisory_worker_job(
            store=store,
            job_id=job["job_id"],
            worker=FakeLLMAdvisoryWorker(),
        )
    except ValueError as exc:
        assert "does not match worker" in str(exc)
    else:
        raise AssertionError("worker mismatch should have raised")


def test_worker_request_schema_is_bounded_to_snapshot_records() -> None:
    store = TrajectoryStore(retention_seconds=0)
    first_record_id = _record(
        store,
        session_id="sess-l3-schema",
        event_id="evt-schema-1",
        decision="allow",
        risk_level="low",
        recorded_at_ts=1.0,
    )
    second_record_id = _record(
        store,
        session_id="sess-l3-schema",
        event_id="evt-schema-2",
        decision="block",
        risk_level="high",
        recorded_at_ts=2.0,
    )
    snapshot = store.create_l3_evidence_snapshot(
        session_id="sess-l3-schema",
        trigger_event_id="evt-schema-2",
        trigger_reason="threshold",
        to_record_id=second_record_id,
    )
    _record(
        store,
        session_id="sess-l3-schema",
        event_id="evt-live-after-schema",
        decision="block",
        risk_level="critical",
        recorded_at_ts=3.0,
    )

    request = build_l3_advisory_worker_request(
        snapshot=snapshot,
        records=store.replay_l3_evidence_snapshot(snapshot["snapshot_id"]),
        provider="fake",
        model="fake-l3",
        deadline_ms=1200,
        budget={"max_tool_calls": 0, "max_tokens": 512},
    )

    assert request["schema_version"] == "cs.l3_advisory.worker_request.v1"
    assert request["provider"] == "fake"
    assert request["model"] == "fake-l3"
    assert request["snapshot_id"] == snapshot["snapshot_id"]
    assert request["event_range"] == {
        "from_record_id": first_record_id,
        "to_record_id": second_record_id,
    }
    assert request["deadline_ms"] == 1200
    assert request["budget"] == {"max_tool_calls": 0, "max_tokens": 512}
    assert [event["event_id"] for event in request["events"]] == ["evt-schema-1", "evt-schema-2"]
    assert "evt-live-after-schema" not in str(request)


def test_fake_provider_worker_response_conforms_to_review_patch_schema() -> None:
    store = TrajectoryStore(retention_seconds=0)
    record_id = _record(
        store,
        session_id="sess-l3-provider",
        event_id="evt-provider",
        decision="block",
        risk_level="critical",
        recorded_at_ts=1.0,
    )
    snapshot = store.create_l3_evidence_snapshot(
        session_id="sess-l3-provider",
        trigger_event_id="evt-provider",
        trigger_reason="threshold",
        to_record_id=record_id,
    )
    request = build_l3_advisory_worker_request(
        snapshot=snapshot,
        records=store.replay_l3_evidence_snapshot(snapshot["snapshot_id"]),
        provider="fake",
        model="fake-l3",
        deadline_ms=1000,
        budget={"max_tokens": 512},
    )

    raw_response = FakeProviderAdvisoryWorker().complete(request)
    parsed = parse_l3_advisory_worker_response(raw_response)

    assert parsed["schema_version"] == "cs.l3_advisory.worker_response.v1"
    assert parsed["risk_level"] == "critical"
    assert parsed["recommended_operator_action"] == "escalate"
    assert parsed["confidence"] == 0.5
    assert parsed["l3_state"] == "completed"
    assert any("fake provider" in finding for finding in parsed["findings"])


def test_worker_response_parser_degrades_invalid_provider_payload() -> None:
    parsed = parse_l3_advisory_worker_response({"not": "valid"})

    assert parsed["risk_level"] == "medium"
    assert parsed["recommended_operator_action"] == "inspect"
    assert parsed["l3_state"] == "degraded"
    assert parsed["l3_reason_code"] == "provider_response_invalid"
    assert parsed["confidence"] is None


def test_provider_response_json_extractor_accepts_fenced_json() -> None:
    payload = extract_l3_advisory_response_json(
        "Here is the advisory result:\n"
        "```json\n"
        "{\"schema_version\":\"cs.l3_advisory.worker_response.v1\","
        "\"risk_level\":\"high\",\"findings\":[\"fenced\"],"
        "\"recommended_operator_action\":\"inspect\",\"l3_state\":\"completed\"}"
        "\n```\n"
    )

    assert payload["schema_version"] == "cs.l3_advisory.worker_response.v1"
    assert payload["findings"] == ["fenced"]


def test_l3_advisory_provider_config_defaults_to_disabled() -> None:
    config = resolve_l3_advisory_provider_config(environ={})

    assert config.enabled is False
    assert config.provider == ""
    assert config.model == ""
    assert config.api_key is None
    assert config.dry_run is True


def test_l3_advisory_provider_config_inherits_global_openai_settings() -> None:
    config = resolve_l3_advisory_provider_config(
        environ={
            "CS_LLM_PROVIDER": "openai",
            "CS_LLM_MODEL": "gpt-shared",
            "CS_LLM_BASE_URL": "https://llm.example/v1",
            "CS_LLM_TEMPERATURE": "0.2",
            "CS_LLM_PROVIDER_TIMEOUT_MS": "45000",
            "OPENAI_API_KEY": "sk-shared",
        }
    )

    assert config.enabled is True
    assert config.provider == "openai"
    assert config.model == "gpt-shared"
    assert config.api_key == "sk-shared"
    assert config.base_url == "https://llm.example/v1"
    assert config.temperature == 0.2
    assert config.deadline_ms == 45000
    assert config.dry_run is False


def test_l3_advisory_provider_config_resolves_explicit_openai_key() -> None:
    config = resolve_l3_advisory_provider_config(
        environ={
            "CS_L3_ADVISORY_PROVIDER_ENABLED": "true",
            "CS_L3_ADVISORY_PROVIDER": "OpenAI",
            "CS_L3_ADVISORY_MODEL": "gpt-advisory",
            "OPENAI_API_KEY": "sk-openai-test",
        }
    )

    assert config.enabled is True
    assert config.provider == "openai"
    assert config.model == "gpt-advisory"
    assert config.api_key == "sk-openai-test"
    assert config.dry_run is True


def test_l3_advisory_provider_config_requires_explicit_dry_run_disable() -> None:
    config = resolve_l3_advisory_provider_config(
        environ={
            "CS_L3_ADVISORY_PROVIDER_ENABLED": "true",
            "CS_L3_ADVISORY_PROVIDER": "openai",
            "CS_L3_ADVISORY_MODEL": "gpt-advisory",
            "CS_L3_ADVISORY_PROVIDER_DRY_RUN": "false",
            "CS_L3_ADVISORY_TEMPERATURE": "0.7",
            "CS_L3_ADVISORY_DEADLINE_MS": "120000",
            "OPENAI_API_KEY": "sk-openai-test",
        }
    )

    assert config.enabled is True
    assert config.dry_run is False
    assert config.temperature == 0.7
    assert config.deadline_ms == 120000


def test_provider_builder_preserves_explicit_dry_run_disable() -> None:
    provider = build_l3_advisory_provider(
        LLMAdvisoryProviderConfig(
            enabled=True,
            provider="openai",
            model="gpt-advisory",
            api_key="sk-test",
            dry_run=False,
        )
    )

    assert isinstance(provider, LLMProviderBridgeAdvisoryProvider)
    assert provider.config.dry_run is False
    assert provider.config.temperature == 1.0


def test_llm_provider_worker_degrades_when_provider_disabled() -> None:
    store = TrajectoryStore(retention_seconds=0)
    record_id = _record(
        store,
        session_id="sess-l3-provider-gate",
        event_id="evt-provider-gate-disabled",
        decision="block",
        risk_level="high",
        recorded_at_ts=1.0,
    )
    snapshot = store.create_l3_evidence_snapshot(
        session_id="sess-l3-provider-gate",
        trigger_event_id="evt-provider-gate-disabled",
        trigger_reason="threshold",
        to_record_id=record_id,
    )
    job = store.enqueue_l3_advisory_job(
        snapshot["snapshot_id"],
        runner=LLMProviderAdvisoryWorker.runner_name,
    )

    result = run_l3_advisory_worker_job(
        store=store,
        job_id=job["job_id"],
        worker=LLMProviderAdvisoryWorker(
            LLMAdvisoryProviderConfig(
                enabled=False,
                provider="openai",
                model="gpt-advisory",
                api_key="sk-test",
            )
        ),
    )

    assert result["job"]["job_state"] == "completed"
    assert result["review"]["l3_state"] == "degraded"
    assert result["review"]["l3_reason_code"] == "provider_disabled"
    assert result["review"]["review_runner"] == "llm_provider"
    assert result["review"]["worker_backend"] == "openai"
    assert any("provider disabled" in finding for finding in result["review"]["findings"])


def test_llm_provider_worker_degrades_when_api_key_missing() -> None:
    store = TrajectoryStore(retention_seconds=0)
    record_id = _record(
        store,
        session_id="sess-l3-provider-gate",
        event_id="evt-provider-gate-missing-key",
        decision="block",
        risk_level="high",
        recorded_at_ts=1.0,
    )
    snapshot = store.create_l3_evidence_snapshot(
        session_id="sess-l3-provider-gate",
        trigger_event_id="evt-provider-gate-missing-key",
        trigger_reason="threshold",
        to_record_id=record_id,
    )
    job = store.enqueue_l3_advisory_job(
        snapshot["snapshot_id"],
        runner=LLMProviderAdvisoryWorker.runner_name,
    )

    result = run_l3_advisory_worker_job(
        store=store,
        job_id=job["job_id"],
        worker=LLMProviderAdvisoryWorker(
            LLMAdvisoryProviderConfig(
                enabled=True,
                provider="openai",
                model="gpt-advisory",
                api_key=None,
            )
        ),
    )

    assert result["review"]["l3_state"] == "degraded"
    assert result["review"]["l3_reason_code"] == "provider_missing_key"
    assert result["review"]["worker_backend"] == "openai"
    assert any("missing api key" in finding for finding in result["review"]["findings"])


def test_llm_provider_worker_degrades_when_model_missing() -> None:
    store = TrajectoryStore(retention_seconds=0)
    record_id = _record(
        store,
        session_id="sess-l3-provider-gate",
        event_id="evt-provider-gate-missing-model",
        decision="block",
        risk_level="high",
        recorded_at_ts=1.0,
    )
    snapshot = store.create_l3_evidence_snapshot(
        session_id="sess-l3-provider-gate",
        trigger_event_id="evt-provider-gate-missing-model",
        trigger_reason="threshold",
        to_record_id=record_id,
    )
    job = store.enqueue_l3_advisory_job(
        snapshot["snapshot_id"],
        runner=LLMProviderAdvisoryWorker.runner_name,
    )

    result = run_l3_advisory_worker_job(
        store=store,
        job_id=job["job_id"],
        worker=LLMProviderAdvisoryWorker(
            LLMAdvisoryProviderConfig(
                enabled=True,
                provider="anthropic",
                model="",
                api_key="sk-ant-test",
            )
        ),
    )

    assert result["review"]["l3_state"] == "degraded"
    assert result["review"]["l3_reason_code"] == "provider_missing_model"
    assert result["review"]["worker_backend"] == "anthropic"
    assert any("missing model" in finding for finding in result["review"]["findings"])


def test_llm_provider_worker_degrades_unsupported_provider() -> None:
    store = TrajectoryStore(retention_seconds=0)
    record_id = _record(
        store,
        session_id="sess-l3-provider-gate",
        event_id="evt-provider-gate-unsupported",
        decision="block",
        risk_level="critical",
        recorded_at_ts=1.0,
    )
    snapshot = store.create_l3_evidence_snapshot(
        session_id="sess-l3-provider-gate",
        trigger_event_id="evt-provider-gate-unsupported",
        trigger_reason="threshold",
        to_record_id=record_id,
    )
    job = store.enqueue_l3_advisory_job(
        snapshot["snapshot_id"],
        runner=LLMProviderAdvisoryWorker.runner_name,
    )

    result = run_l3_advisory_worker_job(
        store=store,
        job_id=job["job_id"],
        worker=LLMProviderAdvisoryWorker(
            LLMAdvisoryProviderConfig(
                enabled=True,
                provider="gemini",
                model="gemini-test",
                api_key="key-test",
            )
        ),
    )

    assert result["review"]["l3_state"] == "degraded"
    assert result["review"]["l3_reason_code"] == "provider_unsupported"
    assert result["review"]["worker_backend"] == "gemini"
    assert any("unsupported advisory provider" in finding for finding in result["review"]["findings"])


def test_llm_provider_bridge_can_complete_from_mock_async_provider() -> None:
    class MockAsyncProvider:
        provider_id = "openai"

        async def complete(self, system_prompt, user_message, timeout_ms, max_tokens=256):
            assert "cs.l3_advisory.worker_request.v1" in user_message
            assert max_tokens >= 4096
            return json.dumps(
                {
                    "schema_version": "cs.l3_advisory.worker_response.v1",
                    "risk_level": "high",
                    "findings": ["mock provider completed advisory review"],
                    "confidence": 0.77,
                    "recommended_operator_action": "inspect",
                    "l3_state": "completed",
                    "l3_reason_code": None,
                }
            )

    store = TrajectoryStore(retention_seconds=0)
    record_id = _record(
        store,
        session_id="sess-l3-provider-real",
        event_id="evt-provider-real",
        decision="block",
        risk_level="high",
        recorded_at_ts=1.0,
    )
    snapshot = store.create_l3_evidence_snapshot(
        session_id="sess-l3-provider-real",
        trigger_event_id="evt-provider-real",
        trigger_reason="operator",
        to_record_id=record_id,
    )
    job = store.enqueue_l3_advisory_job(
        snapshot["snapshot_id"],
        runner=LLMProviderAdvisoryWorker.runner_name,
    )
    config = LLMAdvisoryProviderConfig(
        enabled=True,
        provider="openai",
        model="gpt-advisory",
        api_key="sk-test",
        dry_run=False,
    )

    result = run_l3_advisory_worker_job(
        store=store,
        job_id=job["job_id"],
        worker=LLMProviderAdvisoryWorker(
            config,
            provider=LLMProviderBridgeAdvisoryProvider(
                config=config,
                provider=MockAsyncProvider(),
            ),
        ),
    )

    assert result["review"]["l3_state"] == "completed"
    assert result["review"]["risk_level"] == "high"
    assert result["review"]["confidence"] == 0.77
    assert result["review"]["worker_backend"] == "openai"
    assert result["review"]["provider_dry_run"] is False
    assert result["review"]["worker_request_schema"] == "cs.l3_advisory.worker_request.v1"
    assert result["review"]["findings"] == ["mock provider completed advisory review"]


def test_llm_provider_bridge_accepts_fenced_json_response() -> None:
    class MockFencedProvider:
        provider_id = "anthropic"

        async def complete(self, system_prompt, user_message, timeout_ms, max_tokens=256):
            return (
                "```json\n"
                "{\"schema_version\":\"cs.l3_advisory.worker_response.v1\","
                "\"risk_level\":\"critical\",\"findings\":[\"fenced completion\"],"
                "\"confidence\":0.88,\"recommended_operator_action\":\"escalate\","
                "\"l3_state\":\"completed\",\"l3_reason_code\":null}"
                "\n```"
            )

    store = TrajectoryStore(retention_seconds=0)
    record_id = _record(
        store,
        session_id="sess-l3-provider-fenced",
        event_id="evt-provider-fenced",
        decision="block",
        risk_level="critical",
        recorded_at_ts=1.0,
    )
    snapshot = store.create_l3_evidence_snapshot(
        session_id="sess-l3-provider-fenced",
        trigger_event_id="evt-provider-fenced",
        trigger_reason="operator",
        to_record_id=record_id,
    )
    job = store.enqueue_l3_advisory_job(
        snapshot["snapshot_id"],
        runner=LLMProviderAdvisoryWorker.runner_name,
    )
    config = LLMAdvisoryProviderConfig(
        enabled=True,
        provider="anthropic",
        model="claude-advisory",
        api_key="sk-ant-test",
        dry_run=False,
    )

    result = run_l3_advisory_worker_job(
        store=store,
        job_id=job["job_id"],
        worker=LLMProviderAdvisoryWorker(
            config,
            provider=LLMProviderBridgeAdvisoryProvider(
                config=config,
                provider=MockFencedProvider(),
            ),
        ),
    )

    assert result["review"]["l3_state"] == "completed"
    assert result["review"]["risk_level"] == "critical"
    assert result["review"]["recommended_operator_action"] == "escalate"
    assert result["review"]["findings"] == ["fenced completion"]


def test_openai_provider_shell_requires_explicit_enable_and_api_key() -> None:
    disabled = OpenAIAdvisoryProvider(
        LLMAdvisoryProviderConfig(
            enabled=False,
            provider="openai",
            model="gpt-test",
            api_key="sk-test",
        )
    )
    missing_key = OpenAIAdvisoryProvider(
        LLMAdvisoryProviderConfig(
            enabled=True,
            provider="openai",
            model="gpt-test",
            api_key=None,
        )
    )

    assert disabled.validate() == "provider disabled"
    assert missing_key.validate() == "missing api key"

    response = disabled.complete({"schema_version": "cs.l3_advisory.worker_request.v1"})
    parsed = parse_l3_advisory_worker_response(response)
    assert parsed["l3_state"] == "degraded"
    assert parsed["l3_reason_code"] == "provider_disabled"


def test_anthropic_provider_shell_does_not_make_network_calls() -> None:
    provider = AnthropicAdvisoryProvider(
        LLMAdvisoryProviderConfig(
            enabled=True,
            provider="anthropic",
            model="claude-test",
            api_key="sk-ant-test",
            dry_run=True,
        )
    )

    response = provider.complete({"schema_version": "cs.l3_advisory.worker_request.v1"})
    parsed = parse_l3_advisory_worker_response(response)

    assert parsed["l3_state"] == "degraded"
    assert parsed["l3_reason_code"] == "provider_not_implemented"
    assert any("not implemented" in finding for finding in parsed["findings"])
