"""Tests for project-level .clawsentry.toml configuration."""

from __future__ import annotations

import pytest

from clawsentry.gateway.detection_config import DetectionConfig, PRESETS, from_preset
from clawsentry.cli.dotenv_loader import parse_env_file
from clawsentry.gateway.project_config import (
    ProjectConfig,
    load_project_config,
    read_project_frameworks,
    remove_project_framework,
    resolve_effective_config,
    update_project_framework,
)


class TestPresets:
    """Test preset security level definitions."""

    def test_four_presets_exist(self):
        assert set(PRESETS.keys()) == {"low", "medium", "high", "strict"}

    def test_medium_matches_defaults(self):
        """medium preset should produce the same config as DetectionConfig()."""
        medium = from_preset("medium")
        default = DetectionConfig()
        assert medium.threshold_critical == default.threshold_critical
        assert medium.threshold_high == default.threshold_high
        assert medium.threshold_medium == default.threshold_medium

    def test_preset_threshold_ordering(self):
        """low should be more permissive than high."""
        low = from_preset("low")
        high = from_preset("high")
        assert low.threshold_critical > high.threshold_critical

    def test_all_presets_valid(self):
        """All presets should produce valid DetectionConfig instances."""
        for name in PRESETS:
            cfg = from_preset(name)
            assert isinstance(cfg, DetectionConfig)

    def test_preset_with_overrides(self):
        """Presets should accept additional overrides."""
        cfg = from_preset("high", l2_budget_ms=3000.0)
        assert cfg.threshold_critical == 1.8
        assert cfg.l2_budget_ms == 3000.0

    def test_unknown_preset_raises(self):
        with pytest.raises(KeyError):
            from_preset("nonexistent")

    def test_risk_event_action_presets(self):
        """Higher presets should move runtime detector findings from broadcast toward blocking."""
        low = from_preset("low")
        medium = from_preset("medium")
        high = from_preset("high")
        strict = from_preset("strict")

        assert low.trajectory_alert_action == "broadcast"
        assert medium.trajectory_alert_action == "broadcast"
        assert high.trajectory_alert_action == "defer"
        assert strict.trajectory_alert_action == "block"

        assert low.post_action_finding_action == "broadcast"
        assert medium.post_action_finding_action == "broadcast"
        assert high.post_action_finding_action == "defer"
        assert strict.post_action_finding_action == "block"


class TestProjectConfig:
    """Test .clawsentry.toml loading."""

    def test_load_from_toml(self, tmp_path):
        toml = tmp_path / ".clawsentry.toml"
        toml.write_text('[project]\nenabled = true\npreset = "high"\n')
        cfg = load_project_config(tmp_path)
        assert cfg.enabled is True
        assert cfg.preset == "high"

    def test_load_missing_file_returns_defaults(self, tmp_path):
        cfg = load_project_config(tmp_path)
        assert cfg.enabled is True
        assert cfg.preset == "medium"

    def test_disabled_project(self, tmp_path):
        toml = tmp_path / ".clawsentry.toml"
        toml.write_text('[project]\nenabled = false\n')
        cfg = load_project_config(tmp_path)
        assert cfg.enabled is False

    def test_custom_overrides(self, tmp_path):
        toml = tmp_path / ".clawsentry.toml"
        toml.write_text(
            '[project]\npreset = "low"\n\n'
            '[overrides]\nthreshold_critical = 2.5\n'
        )
        cfg = load_project_config(tmp_path)
        assert cfg.preset == "low"
        assert cfg.overrides == {"threshold_critical": 2.5}

    def test_build_detection_config_from_project(self, tmp_path):
        toml = tmp_path / ".clawsentry.toml"
        toml.write_text(
            '[project]\npreset = "high"\n\n'
            '[overrides]\nl2_budget_ms = 3000.0\n'
        )
        cfg = load_project_config(tmp_path)
        dc = cfg.to_detection_config()
        assert dc.threshold_critical == 1.8  # high preset
        assert dc.l2_budget_ms == 3000.0     # custom override

    def test_invalid_toml_returns_defaults(self, tmp_path):
        toml = tmp_path / ".clawsentry.toml"
        toml.write_text("invalid [[[ toml content")
        cfg = load_project_config(tmp_path)
        assert cfg.enabled is True
        assert cfg.preset == "medium"

    def test_frameworks_parse_from_toml(self, tmp_path):
        toml = tmp_path / ".clawsentry.toml"
        toml.write_text(
            '[frameworks]\nenabled = ["codex", "openclaw"]\ndefault = "codex"\n'
            "\n[frameworks.codex]\nmanaged_hooks = false\n"
        )

        cfg = load_project_config(tmp_path)

        assert cfg.frameworks["enabled"] == ["codex", "openclaw"]
        assert cfg.frameworks["default"] == "codex"
        assert cfg.frameworks["codex"]["managed_hooks"] is False

    def test_update_and_remove_project_frameworks(self, tmp_path):
        path = update_project_framework(tmp_path, "codex")
        update_project_framework(tmp_path, "openclaw")

        enabled, default = read_project_frameworks(tmp_path)
        assert path == tmp_path / ".clawsentry.toml"
        assert enabled == ["codex", "openclaw"]
        assert default == "codex"

        remove_project_framework(tmp_path, "codex")
        enabled, default = read_project_frameworks(tmp_path)
        assert enabled == ["openclaw"]
        assert default == "openclaw"

    def test_effective_config_precedence_process_env_over_env_file_over_project(self, tmp_path):
        (tmp_path / ".clawsentry.toml").write_text('[llm]\nprovider = "project"\nmodel = "project-model"\n')
        env_file = tmp_path / ".clawsentry.env.local"
        env_file.write_text("CS_LLM_PROVIDER=env-file\nCS_LLM_MODEL=env-file-model\n")
        parsed = parse_env_file(env_file)

        eff = resolve_effective_config(
            tmp_path,
            environ={"CS_LLM_PROVIDER": "process"},
            env_file_values=parsed.values,
            env_file_provenance=parsed,
        )

        assert eff.values["llm.provider"] == "process"
        assert eff.sources["llm.provider"] == "process-env"
        assert eff.values["llm.model"] == "env-file-model"
        assert eff.sources["llm.model"] == "env-file"

    def test_effective_config_project_beats_legacy_alias(self, tmp_path):
        (tmp_path / ".clawsentry.toml").write_text("[budgets]\nl2_timeout_ms = 1234\n")

        eff = resolve_effective_config(tmp_path, environ={"CS_L2_BUDGET_MS": "9999"})

        assert eff.values["budgets.l2_timeout_ms"] == 1234
        assert eff.sources["budgets.l2_timeout_ms"] == "project"

    def test_effective_config_redacts_env_file_secret_with_source_detail(self, tmp_path):
        (tmp_path / ".clawsentry.toml").write_text('[llm]\nprovider = "openai"\n')
        env_file = tmp_path / ".clawsentry.env.local"
        env_file.write_text("CS_LLM_API_KEY=sk-test-secret-value\n")
        parsed = parse_env_file(env_file)

        eff = resolve_effective_config(
            tmp_path,
            environ={},
            env_file_values=parsed.values,
            env_file_provenance=parsed,
        )

        assert eff.values["llm.api_key"] != "sk-test-secret-value"
        assert eff.values["llm.api_key"].startswith("sk-t")
        assert eff.sources["llm.api_key"] == "env-file"
        assert eff.source_detail_for("llm.api_key") == f"{env_file}:1"


class TestGatewayPresetApplication:
    """Test that Gateway applies preset from harness params."""

    def test_preset_overrides_detection_config(self):
        """strict preset should produce lower thresholds."""
        cfg = from_preset("strict")
        assert cfg.threshold_critical == 1.3
        assert cfg.d6_injection_multiplier == 1.0

    def test_preset_with_project_overrides(self):
        """Project overrides should take precedence over preset defaults."""
        cfg = from_preset("high", threshold_critical=2.0)
        assert cfg.threshold_critical == 2.0  # override wins
        assert cfg.threshold_high == 1.2      # high preset

    def test_env_overrides_still_work(self, monkeypatch):
        """CS_ env vars should still work with build_detection_config_from_env."""
        monkeypatch.setenv("CS_THRESHOLD_CRITICAL", "2.5")
        from clawsentry.gateway.detection_config import build_detection_config_from_env
        cfg = build_detection_config_from_env()
        assert cfg.threshold_critical == 2.5

    def test_build_config_with_preset_applies_env_on_top(self, monkeypatch):
        """build_detection_config_with_preset should layer env vars on top of preset."""
        from clawsentry.gateway.detection_config import build_detection_config_with_preset
        monkeypatch.setenv("CS_THRESHOLD_CRITICAL", "1.5")
        cfg = build_detection_config_with_preset("strict", {})
        # env var wins over strict preset's 1.3
        assert cfg.threshold_critical == 1.5
        # strict preset values still apply for non-overridden fields
        assert cfg.d6_injection_multiplier == 1.0

    def test_build_config_with_preset_applies_overrides(self):
        """build_detection_config_with_preset should apply project overrides."""
        from clawsentry.gateway.detection_config import build_detection_config_with_preset
        cfg = build_detection_config_with_preset("high", {"l2_budget_ms": 3000.0})
        assert cfg.threshold_critical == 1.8  # high preset
        assert cfg.l2_budget_ms == 3000.0     # project override

    def test_build_config_with_preset_medium_equals_default(self):
        """medium preset with no overrides should match DetectionConfig()."""
        from clawsentry.gateway.detection_config import build_detection_config_with_preset
        cfg = build_detection_config_with_preset("medium", {})
        default = DetectionConfig()
        assert cfg.threshold_critical == default.threshold_critical
        assert cfg.threshold_high == default.threshold_high

    def test_build_config_with_preset_unknown_falls_back(self):
        """Unknown preset should fall back to DetectionConfig defaults."""
        from clawsentry.gateway.detection_config import build_detection_config_with_preset
        cfg = build_detection_config_with_preset("nonexistent", {})
        default = DetectionConfig()
        assert cfg.threshold_critical == default.threshold_critical


class TestGatewayPresetFromEvent:
    """Test Gateway extracting preset config from event metadata."""

    def test_extract_preset_from_canonical_event_payload(self):
        """Gateway should detect preset info in event payload _clawsentry_meta."""
        from clawsentry.gateway.server import _extract_project_config
        payload = {
            "tool": "Bash",
            "_clawsentry_meta": {
                "content_origin": "user",
                "project_preset": "strict",
                "project_overrides": {"l2_budget_ms": 2000.0},
            },
        }
        preset, overrides = _extract_project_config(payload)
        assert preset == "strict"
        assert overrides == {"l2_budget_ms": 2000.0}

    def test_extract_no_preset_returns_none(self):
        """When no preset info in metadata, should return None."""
        from clawsentry.gateway.server import _extract_project_config
        payload = {
            "tool": "Bash",
            "_clawsentry_meta": {"content_origin": "user"},
        }
        preset, overrides = _extract_project_config(payload)
        assert preset is None
        assert overrides == {}

    def test_extract_from_empty_payload(self):
        """Empty/None payload should not crash."""
        from clawsentry.gateway.server import _extract_project_config
        preset, overrides = _extract_project_config({})
        assert preset is None
        assert overrides == {}
        preset2, overrides2 = _extract_project_config(None)
        assert preset2 is None
        assert overrides2 == {}


class TestPolicyEngineConfigOverride:
    """Test L1PolicyEngine.evaluate with per-request config override."""

    def test_evaluate_with_config_override(self):
        """evaluate() should use config override when provided."""
        from clawsentry.gateway.policy_engine import L1PolicyEngine
        from clawsentry.gateway.models import (
            CanonicalEvent, EventType, DecisionTier,
        )

        engine = L1PolicyEngine()  # default config
        default_cfg = DetectionConfig()
        strict_cfg = from_preset("strict")

        # Create a dangerous event that might score differently with different thresholds
        event = CanonicalEvent(
            event_id="test-1",
            trace_id="trace-1",
            event_type=EventType.PRE_ACTION,
            session_id="sess-1",
            agent_id="agent-1",
            source_framework="test",
            occurred_at="2026-03-30T00:00:00Z",
            payload={"command": "rm -rf /tmp/test", "tool": "Bash"},
            tool_name="Bash",
        )

        # Evaluate with default config
        decision_default, snapshot_default, _ = engine.evaluate(event)

        # Evaluate with strict config override
        decision_strict, snapshot_strict, _ = engine.evaluate(
            event, config=strict_cfg,
        )

        # Strict config has lower thresholds, so for the same event,
        # the risk level should be >= the default risk level
        from clawsentry.gateway.models import RISK_LEVEL_ORDER
        assert RISK_LEVEL_ORDER[snapshot_strict.risk_level] >= RISK_LEVEL_ORDER[snapshot_default.risk_level]

    def test_evaluate_without_config_override_uses_default(self):
        """evaluate() without config should use engine's default config."""
        from clawsentry.gateway.policy_engine import L1PolicyEngine
        from clawsentry.gateway.models import CanonicalEvent, EventType

        engine = L1PolicyEngine()
        event = CanonicalEvent(
            event_id="test-2",
            trace_id="trace-2",
            event_type=EventType.PRE_ACTION,
            session_id="sess-2",
            agent_id="agent-2",
            source_framework="test",
            occurred_at="2026-03-30T00:00:00Z",
            payload={"command": "ls", "tool": "Bash"},
            tool_name="Bash",
        )
        decision, snapshot, tier = engine.evaluate(event)
        # Should succeed with default config
        assert snapshot is not None
        assert decision is not None


class TestHarnessPresetPassthrough:
    """Test that harness passes preset info through to events."""

    @pytest.mark.asyncio
    async def test_preset_injected_into_payload_meta(self, tmp_path):
        """When .clawsentry.toml has preset=strict, harness should inject it."""
        from clawsentry.adapters.a3s_adapter import A3SCodeAdapter
        from clawsentry.adapters.a3s_gateway_harness import (
            A3SGatewayHarness,
            _project_config_cache,
        )

        toml = tmp_path / ".clawsentry.toml"
        toml.write_text('[project]\npreset = "strict"\n')

        adapter = A3SCodeAdapter(
            uds_path="/tmp/clawsentry-nonexistent.sock",
            source_framework="claude-code",
            default_deadline_ms=500,
            max_rpc_retries=0,
        )
        harness = A3SGatewayHarness(adapter)
        _project_config_cache.clear()

        # With gateway unreachable, it should fail-open, so this just tests
        # that the preset info doesn't cause errors.
        response = await harness.dispatch_async({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
            "session_id": "test",
            "cwd": str(tmp_path),
        })
        assert response is None  # fail-open

    @pytest.mark.asyncio
    async def test_medium_preset_not_injected(self, tmp_path):
        """medium preset (default) should still be injected for explicit config."""
        from clawsentry.adapters.a3s_adapter import A3SCodeAdapter
        from clawsentry.adapters.a3s_gateway_harness import (
            A3SGatewayHarness,
            _project_config_cache,
        )

        # No .clawsentry.toml — defaults to medium, no injection needed
        adapter = A3SCodeAdapter(
            uds_path="/tmp/clawsentry-nonexistent.sock",
            source_framework="claude-code",
            default_deadline_ms=500,
            max_rpc_retries=0,
        )
        harness = A3SGatewayHarness(adapter)
        _project_config_cache.clear()

        response = await harness.dispatch_async({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
            "session_id": "test",
            "cwd": str(tmp_path),
        })
        assert response is None  # fail-open
