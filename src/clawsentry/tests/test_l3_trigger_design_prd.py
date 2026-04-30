"""L3 trigger design regression tests for env-first runtime config."""

from __future__ import annotations

from clawsentry.gateway.detection_config import build_detection_config_from_env, from_preset


def test_cs_preset_strict_drives_runtime_detection_config(monkeypatch):
    monkeypatch.setenv("CS_PRESET", "strict")
    cfg = build_detection_config_from_env()
    assert cfg.threshold_critical == from_preset("strict").threshold_critical


def test_env_override_still_wins_over_preset(monkeypatch):
    monkeypatch.setenv("CS_PRESET", "strict")
    monkeypatch.setenv("CS_THRESHOLD_CRITICAL", "2.0")
    assert build_detection_config_from_env().threshold_critical == 2.0
