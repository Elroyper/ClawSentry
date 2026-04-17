"""Regression tests for the 2026-04-17 L3 trigger design PRD."""

from __future__ import annotations

import os
from unittest.mock import patch

from clawsentry.gateway.detection_config import (
    build_detection_config_from_env,
    build_detection_config_with_preset,
)
from clawsentry.gateway.l3_runtime import build_l3_runtime_info, infer_l3_reason_code
from clawsentry.gateway.models import DecisionTier
from clawsentry.gateway.project_config import load_project_config


def test_env_parses_l3_trigger_design_fields() -> None:
    env = {
        "CS_L3_ROUTING_MODE": "replace_l2",
        "CS_L3_TRIGGER_PROFILE": "eager",
        "CS_L3_BUDGET_TUNING_ENABLED": "true",
    }

    with patch.dict(os.environ, env, clear=True):
        cfg = build_detection_config_from_env()

    assert cfg.l3_routing_mode == "replace_l2"
    assert cfg.l3_trigger_profile == "eager"
    assert cfg.l3_budget_tuning_enabled is True


def test_build_detection_config_with_preset_layers_new_fields_with_env_precedence() -> None:
    project_overrides = {
        "l3_routing_mode": "normal",
        "l3_trigger_profile": "default",
        "l3_budget_tuning_enabled": False,
    }
    env = {
        "CS_L3_ROUTING_MODE": "replace_l2",
        "CS_L3_TRIGGER_PROFILE": "eager",
        "CS_L3_BUDGET_TUNING_ENABLED": "true",
    }

    with patch.dict(os.environ, env, clear=True):
        cfg = build_detection_config_with_preset("medium", project_overrides)

    assert cfg.l3_routing_mode == "replace_l2"
    assert cfg.l3_trigger_profile == "eager"
    assert cfg.l3_budget_tuning_enabled is True


def test_project_config_round_trips_l3_trigger_design_overrides(tmp_path) -> None:
    (tmp_path / ".clawsentry.toml").write_text(
        "\n".join(
            [
                "[project]",
                'preset = "medium"',
                "",
                "[overrides]",
                'l3_routing_mode = "replace_l2"',
                'l3_trigger_profile = "eager"',
                "l3_budget_tuning_enabled = true",
            ]
        ),
        encoding="utf-8",
    )

    cfg = load_project_config(tmp_path).to_detection_config()

    assert cfg.l3_routing_mode == "replace_l2"
    assert cfg.l3_trigger_profile == "eager"
    assert cfg.l3_budget_tuning_enabled is True


def test_infer_l3_reason_code_recognizes_local_l3_unavailable() -> None:
    assert infer_l3_reason_code(
        state="skipped",
        reason="Local L3 unavailable for replacement mode",
        trigger_reason="",
        degraded=False,
    ) == "local_l3_unavailable"


def test_build_l3_runtime_info_surfaces_unavailable_replacement_mode_honestly() -> None:
    info = build_l3_runtime_info(
        requested_tier=DecisionTier.L2,
        effective_tier=DecisionTier.L3,
        actual_tier=DecisionTier.L2,
        l3_available=False,
        l3_trace=None,
        l3_reason="Local L3 unavailable for replacement mode",
        l3_reason_code="local_l3_unavailable",
    )

    assert info["l3_available"] is False
    assert info["l3_requested"] is True
    assert info["l3_state"] == "skipped"
    assert info["l3_reason_code"] == "local_l3_unavailable"
