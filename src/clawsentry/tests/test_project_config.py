"""Env-first config and preset compatibility tests."""

from __future__ import annotations

import pytest

from clawsentry.gateway.detection_config import DetectionConfig, PRESETS, build_detection_config_from_env, from_preset
from clawsentry.gateway.env_config import parse_enabled_frameworks, resolve_effective_config


class TestPresets:
    def test_four_presets_exist(self):
        assert set(PRESETS.keys()) == {"low", "medium", "high", "strict"}

    def test_medium_matches_defaults(self):
        assert from_preset("medium") == DetectionConfig()

    def test_preset_threshold_ordering(self):
        assert from_preset("low").threshold_critical > from_preset("high").threshold_critical

    def test_unknown_preset_raises(self):
        with pytest.raises(KeyError):
            from_preset("nonexistent")


class TestEnvFirstConfig:
    def test_effective_config_ignores_inert_legacy_file(self, tmp_path):
        (tmp_path / (".clawsentry" + ".toml")).write_text('[project]\npreset="strict"\n')
        eff = resolve_effective_config(environ={})
        assert eff.values["project.preset"] == "medium"
        assert eff.sources["project.preset"] == "default"

    def test_effective_config_process_env_over_env_file(self, tmp_path):
        from clawsentry.cli.dotenv_loader import parse_env_file
        env_file = tmp_path / ".clawsentry.env.local"
        env_file.write_text("CS_LLM_PROVIDER=env-file\nCS_LLM_MODEL=env-file-model\n")
        parsed = parse_env_file(env_file)
        eff = resolve_effective_config(environ={"CS_LLM_PROVIDER": "process"}, env_file=parsed)
        assert eff.values["llm.provider"] == "process"
        assert eff.sources["llm.provider"] == "process-env"
        assert eff.values["llm.model"] == "env-file-model"
        assert eff.sources["llm.model"] == "env-file"

    def test_frameworks_parse_from_env(self):
        assert parse_enabled_frameworks({"CS_ENABLED_FRAMEWORKS": "codex,openclaw", "CS_FRAMEWORK": "codex"}) == (["codex", "openclaw"], "codex")

    def test_runtime_preset_env_applies_without_project_file(self, monkeypatch):
        monkeypatch.setenv("CS_PRESET", "strict")
        cfg = build_detection_config_from_env()
        assert cfg.threshold_critical == from_preset("strict").threshold_critical
