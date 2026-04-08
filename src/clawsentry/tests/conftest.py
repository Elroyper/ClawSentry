"""Shared fixtures for clawsentry test suite."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest


class StubTrajectoryStore:
    """In-memory trajectory store that returns N identical records per session."""

    def __init__(self, record_template: dict[str, Any] | None = None) -> None:
        self._template = record_template or {
            "recorded_at": "2026-03-21T12:00:00+00:00",
            "event": {"tool_name": "bash"},
            "decision": {"risk_level": "high"},
        }

    def replay_session(self, session_id: str, limit: int = 100) -> list[dict[str, Any]]:
        rec = {**self._template}
        rec.setdefault("event", {})["session_id"] = session_id
        return [rec for _ in range(limit)]


@pytest.fixture(autouse=True)
def isolated_clawsentry_env():
    """Keep repo-local .env loads and auth mutations from leaking across tests."""
    keys = ("CS_AUTH_TOKEN", "CS_FRAMEWORK", "CS_ENABLED_FRAMEWORKS")
    previous = {key: os.environ.get(key) for key in keys}
    for key in keys:
        os.environ.pop(key, None)
    yield
    for key, value in previous.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


@pytest.fixture()
def stub_trajectory_store() -> StubTrajectoryStore:
    """Return a default StubTrajectoryStore instance."""
    return StubTrajectoryStore()


@pytest.fixture()
def skills_dir(tmp_path: Path) -> Path:
    """Create a temp directory with credential-audit + general-review skill YAML files."""
    d = tmp_path / "skills"
    d.mkdir()
    (d / "credential-audit.yaml").write_text(
        "name: credential-audit\n"
        "description: 审查凭证相关操作\n"
        "triggers:\n"
        "  risk_hints:\n"
        "    - credential_exfiltration\n"
        "  tool_names:\n"
        "    - bash\n"
        "  payload_patterns:\n"
        "    - token\n"
        "system_prompt: |\n"
        "  你是一个凭证审查专家。\n"
        "evaluation_criteria:\n"
        "  - name: credential_exposure\n"
        "    severity: critical\n"
        "    description: 凭证内容是否被暴露\n",
        encoding="utf-8",
    )
    (d / "general-review.yaml").write_text(
        "name: general-review\n"
        "description: 通用兜底审查\n"
        "triggers:\n"
        "  risk_hints: []\n"
        "  tool_names: []\n"
        "  payload_patterns: []\n"
        "system_prompt: |\n"
        "  你是一个通用安全审查专家。\n"
        "evaluation_criteria:\n"
        "  - name: general_risk\n"
        "    severity: medium\n"
        "    description: 整体风险评估\n",
        encoding="utf-8",
    )
    return d
