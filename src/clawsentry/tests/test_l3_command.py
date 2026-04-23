"""Tests for ``clawsentry l3`` operator commands."""

from __future__ import annotations

import json
from io import BytesIO

from clawsentry.cli.l3_command import (
    build_full_review_payload,
    run_l3_full_review,
    run_l3_jobs_drain,
    run_l3_jobs_list,
    run_l3_jobs_run_next,
)


def test_build_full_review_payload_defaults_to_single_deterministic_run() -> None:
    payload = build_full_review_payload(
        trigger_event_id=None,
        trigger_detail=None,
        from_record_id=None,
        to_record_id=42,
        max_records=100,
        max_tool_calls=0,
        runner="deterministic_local",
        queue_only=False,
    )

    assert payload == {
        "trigger_event_id": "operator_full_review",
        "trigger_detail": "operator_requested_full_review",
        "to_record_id": 42,
        "max_records": 100,
        "max_tool_calls": 0,
        "runner": "deterministic_local",
        "run": True,
    }


def test_run_l3_full_review_posts_to_gateway(monkeypatch, capsys) -> None:
    captured: dict[str, object] = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return None

        def read(self):
            return json.dumps(
                {
                    "snapshot": {"snapshot_id": "snap-1"},
                    "job": {"job_id": "job-1", "job_state": "completed"},
                    "review": {"review_id": "rev-1", "l3_state": "completed"},
                    "advisory_only": True,
                    "canonical_decision_mutated": False,
                }
            ).encode()

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["headers"] = dict(request.header_items())
        captured["body"] = json.loads(request.data.decode())
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    code = run_l3_full_review(
        gateway_url="http://127.0.0.1:8080/",
        token="token-123",
        session_id="sess-1",
        trigger_event_id="op-1",
        trigger_detail=None,
        from_record_id=None,
        to_record_id=7,
        max_records=100,
        max_tool_calls=0,
        runner="deterministic_local",
        queue_only=False,
        json_mode=True,
        timeout=12.5,
    )

    assert code == 0
    assert captured["url"] == "http://127.0.0.1:8080/report/session/sess-1/l3-advisory/full-review"
    assert captured["headers"]["Authorization"] == "Bearer token-123"
    assert captured["body"]["trigger_event_id"] == "op-1"
    assert captured["body"]["to_record_id"] == 7
    assert captured["body"]["run"] is True
    assert captured["timeout"] == 12.5
    assert json.loads(capsys.readouterr().out)["review"]["review_id"] == "rev-1"


def test_run_l3_full_review_renders_summary(monkeypatch, capsys) -> None:
    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return None

        def read(self):
            return b'{"snapshot":{"snapshot_id":"snap-1"},"job":{"job_id":"job-1","job_state":"queued"},"review":null,"advisory_only":true,"canonical_decision_mutated":false}'

    monkeypatch.setattr("urllib.request.urlopen", lambda request, timeout: FakeResponse())

    code = run_l3_full_review(
        gateway_url="http://127.0.0.1:8080",
        token=None,
        session_id="sess-1",
        trigger_event_id=None,
        trigger_detail=None,
        from_record_id=None,
        to_record_id=None,
        max_records=100,
        max_tool_calls=0,
        runner="deterministic_local",
        queue_only=True,
        json_mode=False,
        timeout=10.0,
    )

    out = capsys.readouterr().out
    assert code == 0
    assert "snapshot: snap-1" in out
    assert "job:      job-1 (queued)" in out
    assert "review:   queued only" in out


def test_run_l3_jobs_list_posts_filters_and_renders_json(monkeypatch, capsys) -> None:
    captured: dict[str, object] = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return None

        def read(self):
            return b'{"jobs":[{"job_id":"job-1","job_state":"queued","runner":"deterministic_local","snapshot_id":"snap-1"}],"advisory_only":true,"canonical_decision_mutated":false}'

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    code = run_l3_jobs_list(
        gateway_url="http://127.0.0.1:8080/",
        token=None,
        session_id="sess-1",
        state="queued",
        runner="deterministic_local",
        json_mode=True,
        timeout=3.0,
    )

    assert code == 0
    assert captured["url"] == "http://127.0.0.1:8080/report/l3-advisory/jobs?session_id=sess-1&state=queued&runner=deterministic_local"
    assert json.loads(capsys.readouterr().out)["jobs"][0]["job_id"] == "job-1"


def test_run_l3_jobs_run_next_and_drain_post_bounded_payload(monkeypatch, capsys) -> None:
    captured: list[dict[str, object]] = []

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return None

        def read(self):
            return b'{"selected_jobs":[],"results":[],"ran_count":0,"dry_run":true,"advisory_only":true,"canonical_decision_mutated":false}'

    def fake_urlopen(request, timeout):
        captured.append({
            "url": request.full_url,
            "body": json.loads(request.data.decode()),
            "timeout": timeout,
        })
        return FakeResponse()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    assert run_l3_jobs_run_next(
        gateway_url="http://gw",
        token="tok",
        runner="deterministic_local",
        session_id="sess-1",
        dry_run=True,
        json_mode=False,
        timeout=4.0,
    ) == 0
    assert run_l3_jobs_drain(
        gateway_url="http://gw",
        token=None,
        runner="fake_llm",
        session_id=None,
        max_jobs=2,
        dry_run=True,
        json_mode=False,
        timeout=5.0,
    ) == 0

    assert captured[0]["url"] == "http://gw/report/l3-advisory/jobs/run-next"
    assert captured[0]["body"] == {"runner": "deterministic_local", "session_id": "sess-1", "dry_run": True}
    assert captured[1]["url"] == "http://gw/report/l3-advisory/jobs/drain"
    assert captured[1]["body"] == {"runner": "fake_llm", "session_id": None, "max_jobs": 2, "dry_run": True}
    out = capsys.readouterr().out
    assert "canonical_decision_mutated: False" in out
