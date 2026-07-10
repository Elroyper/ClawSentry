import json

import pytest

from clawsentry.gateway.config.detection_config import DetectionConfig
from clawsentry.gateway.models import RPC_VERSION
from clawsentry.gateway.server import SupervisionGateway


def _jsonrpc_request(params: dict, rpc_id: int = 1) -> bytes:
    return json.dumps({
        "jsonrpc": "2.0",
        "id": rpc_id,
        "method": "ahp/sync_decision",
        "params": params,
    }).encode()


def _params(*, request_id: str, event_id: str, session_id: str, payload: dict, context: dict | None = None) -> dict:
    return {
        "rpc_version": RPC_VERSION,
        "request_id": request_id,
        "deadline_ms": 1000,
        "decision_tier": "L1",
        "event": {
            "event_id": event_id,
            "trace_id": f"trace-{event_id}",
            "event_type": "pre_action",
            "session_id": session_id,
            "agent_id": "agent-lineage",
            "source_framework": "test",
            "occurred_at": "2026-05-21T00:00:00+00:00",
            "payload": payload,
            "tool_name": "bash",
        },
        "context": context or {},
    }


def _lineage() -> dict:
    return {
        "presented_skill_name": "generic-local-skill",
        "canonical_skill_id": "skill:generic-local-skill",
        "runtime_root_path_hash": "sha256:" + "a" * 64,
        "metadata_record_id": "sha256:" + "b" * 64,
        "content_hash": "sha256:" + "c" * 64,
    }


@pytest.mark.asyncio
async def test_blocked_skill_lineage_match_is_session_hard_boundary():
    gw = SupervisionGateway(detection_config=DetectionConfig(mode="benchmark"))
    session_id = "sess-lineage-boundary"

    first = await gw.handle_jsonrpc(_jsonrpc_request(_params(
        request_id="req-lineage-1",
        event_id="evt-lineage-1",
        session_id=session_id,
        payload={
            "command": "cat /workspace/skills/generic-local-skill/SKILL.md",
            "_clawsentry_meta": {"skill_lineage_raw": _lineage()},
        },
        context={
            "skill_trust": {
                "canonical_skill_id": "skill:generic-local-skill",
                "presented_name": "generic-local-skill",
                "first_use_package_review": {
                    "timing_mode": "pre_use_gate",
                    "verdict": "inconsistent",
                    "severity": "high",
                    "confidence": 0.95,
                },
            }
        },
    )))
    assert first["result"]["decision"]["decision"] == "block"

    second = await gw.handle_jsonrpc(_jsonrpc_request(_params(
        request_id="req-lineage-2",
        event_id="evt-lineage-2",
        session_id=session_id,
        payload={
            "command": "python3 /workspace/project/recovery.py",
            "_clawsentry_meta": {"skill_lineage_raw": _lineage()},
        },
    )))

    assert second["result"]["decision"]["decision"] == "block"
    record = gw.trajectory_store.records[-1]
    snapshot = record["risk_snapshot"]
    assert snapshot["l1_authority_class"] == "deterministic_hard_block"
    assert snapshot["blocked_lineage_match"]["matched_key"] == "runtime_root_path_hash"
    assert "blocked_skill_lineage_match" in snapshot["l1_authority_reasons"]
    assert snapshot.get("contextual_review_clearance") is None


@pytest.mark.asyncio
async def test_prior_fspr_block_blocks_relative_skill_package_read_without_lineage():
    gw = SupervisionGateway(detection_config=DetectionConfig(mode="benchmark"))
    session_id = "sess-relative-skill-after-fspr"

    first = await gw.handle_jsonrpc(_jsonrpc_request(_params(
        request_id="req-relative-fspr-1",
        event_id="evt-relative-fspr-1",
        session_id=session_id,
        payload={
            "command": "sed -n '1,220p' /workspace/.codex/skills/email-api/SKILL.md",
            "cwd": "/workspace",
        },
        context={
            "skill_trust": {
                "canonical_skill_id": "skill:email-api",
                "presented_name": "email-api",
                "runtime_path_status": "verified_mirror",
                "runtime_content_status": "content_verified",
                "runtime_evidence_kind": "shell_skill_path",
                "first_use_package_review": {
                    "timing_mode": "pre_use_gate",
                    "verdict": "inconsistent",
                    "severity": "high",
                    "confidence": 0.95,
                },
            }
        },
    )))
    assert first["result"]["decision"]["decision"] == "block"

    second = await gw.handle_jsonrpc(_jsonrpc_request(_params(
        request_id="req-relative-fspr-2",
        event_id="evt-relative-fspr-2",
        session_id=session_id,
        payload={
            "command": "sed -n '1,220p' SKILL.md",
            "cwd": "/workspace",
        },
    )))

    assert second["result"]["decision"]["decision"] == "block"
    snapshot = gw.trajectory_store.records[-1]["risk_snapshot"]
    assert snapshot["l1_authority_class"] == "deterministic_hard_block"
    assert "prior_fspr_block_relative_skill_package_access" in snapshot["rule_hits"]
    assert "prior_fspr_hard_block" in snapshot["l1_authority_reasons"]


@pytest.mark.asyncio
async def test_prior_fspr_block_blocks_interactive_shell_without_lineage():
    gw = SupervisionGateway(detection_config=DetectionConfig(mode="benchmark"))
    session_id = "sess-interactive-shell-after-fspr"

    first = await gw.handle_jsonrpc(_jsonrpc_request(_params(
        request_id="req-interactive-fspr-1",
        event_id="evt-interactive-fspr-1",
        session_id=session_id,
        payload={
            "command": "cat /workspace/.codex/skills/email-api/SKILL.md",
            "cwd": "/workspace",
        },
        context={
            "skill_trust": {
                "canonical_skill_id": "skill:email-api",
                "presented_name": "email-api",
                "runtime_path_status": "verified_mirror",
                "runtime_content_status": "content_verified",
                "runtime_evidence_kind": "shell_skill_path",
                "first_use_package_review": {
                    "timing_mode": "pre_use_gate",
                    "verdict": "inconsistent",
                    "severity": "high",
                    "confidence": 0.95,
                },
            }
        },
    )))
    assert first["result"]["decision"]["decision"] == "block"

    second = await gw.handle_jsonrpc(_jsonrpc_request(_params(
        request_id="req-interactive-fspr-2",
        event_id="evt-interactive-fspr-2",
        session_id=session_id,
        payload={
            "command": "bash",
            "cwd": "/workspace",
        },
    )))

    assert second["result"]["decision"]["decision"] == "block"
    snapshot = gw.trajectory_store.records[-1]["risk_snapshot"]
    assert snapshot["l1_authority_class"] == "deterministic_hard_block"
    assert "prior_fspr_block_interactive_shell" in snapshot["rule_hits"]
    assert "prior_fspr_hard_block" in snapshot["l1_authority_reasons"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "command",
    [
        "test -e /app/data/cities.csv && echo yes",
        "head -n 5 /app/data/attractions/attractions.csv",
        'rg -n "Ohio|OH" /app/data/background/citySet_with_states.txt | head -n 20',
        "python3 - <<'PY'\nimport os\nprint(os.path.exists('/app/data/cities.csv'))\nPY",
        "python3 - <<'PY'\npath = '/app/data/background/citySet_with_states.txt'\nwith open(path) as f:\n    print(f.readline())\nPY",
        "sed -n '1,80p' /root/data/stock-descriptions.csv",
        "python3 - <<'PY'\nfrom pathlib import Path\nprint(Path('/root/data/stock-descriptions.csv').exists())\nPY",
    ],
)
async def test_prior_fspr_block_allows_benchmark_task_data_readonly(command: str):
    gw = SupervisionGateway(detection_config=DetectionConfig(mode="benchmark"))
    session_id = f"sess-task-data-after-fspr-{abs(hash(command))}"

    first = await gw.handle_jsonrpc(_jsonrpc_request(_params(
        request_id=f"req-task-data-fspr-1-{abs(hash(command))}",
        event_id=f"evt-task-data-fspr-1-{abs(hash(command))}",
        session_id=session_id,
        payload={
            "command": "cat /workspace/.codex/skills/email-api/SKILL.md",
            "cwd": "/workspace",
        },
        context={
            "skill_trust": {
                "canonical_skill_id": "skill:email-api",
                "presented_name": "email-api",
                "runtime_path_status": "verified_mirror",
                "runtime_content_status": "content_verified",
                "runtime_evidence_kind": "shell_skill_path",
                "first_use_package_review": {
                    "timing_mode": "pre_use_gate",
                    "verdict": "inconsistent",
                    "severity": "high",
                    "confidence": 0.95,
                },
            }
        },
    )))
    assert first["result"]["decision"]["decision"] == "block"

    second = await gw.handle_jsonrpc(_jsonrpc_request(_params(
        request_id=f"req-task-data-fspr-2-{abs(hash(command))}",
        event_id=f"evt-task-data-fspr-2-{abs(hash(command))}",
        session_id=session_id,
        payload={
            "command": command,
            "cwd": "/app",
        },
    )))

    assert second["result"]["decision"]["decision"] == "allow"
    snapshot = gw.trajectory_store.records[-1]["risk_snapshot"]
    assert snapshot["l1_authority_class"] == "allow_or_audit"
    assert "benchmark_task_data_readonly" in snapshot["rule_hits"]
    assert "skill_package_read" not in snapshot["l1_authority_reasons"]


@pytest.mark.asyncio
async def test_prior_fspr_block_allows_only_configured_root_task_data(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv(
        "CS_BENCHMARK_TASK_DATA_PATHS_JSON",
        json.dumps(["/root/purchase_orders.csv"]),
    )
    gw = SupervisionGateway(detection_config=DetectionConfig(mode="benchmark"))

    async def seed_fspr_blocks(session_id: str) -> None:
        for index in range(5):
            first = await gw.handle_jsonrpc(_jsonrpc_request(_params(
                request_id=f"req-configured-root-fspr-{index}-{session_id}",
                event_id=f"evt-configured-root-fspr-{index}-{session_id}",
                session_id=session_id,
                payload={
                    "command": f"sed -n '1,220p' /root/.agents/skills/pdf-{index}/SKILL.md",
                    "cwd": "/root",
                },
                context={
                    "skill_trust": {
                        "canonical_skill_id": f"skill:pdf-{index}",
                        "presented_name": f"pdf-{index}",
                        "runtime_path_status": "verified_mirror",
                        "runtime_content_status": "content_verified",
                        "runtime_evidence_kind": "shell_skill_path",
                        "first_use_package_review": {
                            "timing_mode": "pre_use_gate",
                            "verdict": "inconsistent",
                            "severity": "high",
                            "confidence": 0.95,
                        },
                    }
                },
            )))
            assert first["result"]["decision"]["decision"] == "block"

    allowed_session = "sess-configured-root-task-data-allow"
    await seed_fspr_blocks(allowed_session)
    allowed = await gw.handle_jsonrpc(_jsonrpc_request(_params(
        request_id="req-configured-root-task-data-allow",
        event_id="evt-configured-root-task-data-allow",
        session_id=allowed_session,
        payload={
            "command": "sed -n '1,40p' /root/purchase_orders.csv",
            "cwd": "/root",
        },
    )))

    assert allowed["result"]["decision"]["decision"] == "allow"
    allowed_snapshot = gw.trajectory_store.records[-1]["risk_snapshot"]
    assert allowed_snapshot["l1_authority_class"] == "allow_or_audit"
    assert "benchmark_task_data_readonly" in allowed_snapshot["rule_hits"]
    assert any(
        target.get("path_role") == "benchmark_task_data_read"
        and target.get("workspace_relation") == "benchmark_task_data"
        for target in allowed_snapshot["effect_summary"]["targets"]
    )

    blocked_session = "sess-configured-root-task-data-block"
    await seed_fspr_blocks(blocked_session)
    blocked = await gw.handle_jsonrpc(_jsonrpc_request(_params(
        request_id="req-configured-root-task-data-block",
        event_id="evt-configured-root-task-data-block",
        session_id=blocked_session,
        payload={
            "command": "sed -n '1,40p' /root/random-note.txt",
            "cwd": "/root",
        },
    )))

    assert blocked["result"]["decision"]["decision"] == "block"
    blocked_snapshot = gw.trajectory_store.records[-1]["risk_snapshot"]
    assert "benchmark_task_data_readonly" not in blocked_snapshot["rule_hits"]
    assert blocked_snapshot["l1_authority_class"] == "deterministic_hard_block"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "command",
    [
        "mkdir -p /root/output/js /root/output/css /root/output/data",
        "cp -r /root/data/. /root/output/data",
        "python3 - <<'PY'\nfrom pathlib import Path\nPath('/root/output/index.html').write_text('<html></html>')\nPY",
    ],
)
async def test_prior_fspr_block_routes_benchmark_output_writes_to_contextual_review(command: str):
    gw = SupervisionGateway(detection_config=DetectionConfig(mode="benchmark"))
    session_id = f"sess-task-output-after-fspr-{abs(hash(command))}"

    first = await gw.handle_jsonrpc(_jsonrpc_request(_params(
        request_id=f"req-task-output-fspr-1-{abs(hash(command))}",
        event_id=f"evt-task-output-fspr-1-{abs(hash(command))}",
        session_id=session_id,
        payload={
            "command": "cat /workspace/.codex/skills/email-api/SKILL.md",
            "cwd": "/workspace",
        },
        context={
            "skill_trust": {
                "canonical_skill_id": "skill:email-api",
                "presented_name": "email-api",
                "runtime_path_status": "verified_mirror",
                "runtime_content_status": "content_verified",
                "runtime_evidence_kind": "shell_skill_path",
                "first_use_package_review": {
                    "timing_mode": "pre_use_gate",
                    "verdict": "inconsistent",
                    "severity": "high",
                    "confidence": 0.95,
                },
            }
        },
    )))
    assert first["result"]["decision"]["decision"] == "block"

    second = await gw.handle_jsonrpc(_jsonrpc_request(_params(
        request_id=f"req-task-output-fspr-2-{abs(hash(command))}",
        event_id=f"evt-task-output-fspr-2-{abs(hash(command))}",
        session_id=session_id,
        payload={
            "command": command,
            "cwd": "/root",
        },
    )))

    assert second["result"]["decision"]["decision"] in {"allow", "defer"}
    snapshot = gw.trajectory_store.records[-1]["risk_snapshot"]
    assert snapshot["l1_authority_class"] != "deterministic_hard_block"
    if command.startswith("cp "):
        assert "shell_copy_write" in snapshot["rule_hits"]
        assert "benchmark_task_output_write" in snapshot["rule_hits"]
    elif command.startswith("mkdir "):
        assert "shell_directory_create" in snapshot["rule_hits"]
        assert "benchmark_task_output_write" in snapshot["rule_hits"]
    else:
        assert "benchmark_task_output_write" not in snapshot["rule_hits"]
        assert "python_file_write" in snapshot["rule_hits"]
        assert any(
            target.get("effective_artifact_source") == "scope_task_compat"
            for target in snapshot["effect_summary"]["targets"]
        )
    assert "prior_fspr_hard_block" not in snapshot["l1_authority_reasons"]
