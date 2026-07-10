"""Gateway package with legacy module aliases for moved implementations."""

from __future__ import annotations

import importlib
import importlib.abc
import importlib.machinery
import importlib.util
import sys
from types import ModuleType


_LEGACY_MODULE_ALIASES: dict[str, str] = {
    "agent_analyzer": "analysis.agent_analyzer",
    "anti_bypass_guard": "analysis.anti_bypass_guard",
    "anti_bypass_llm_recognizer": "analysis.anti_bypass_llm_recognizer",
    "content_evidence": "analysis.content_evidence",
    "content_scanners": "analysis.content_scanners",
    "injection_detector": "analysis.injection_detector",
    "post_action_analyzer": "analysis.post_action_analyzer",
    "risk_signals": "analysis.risk_signals",
    "risk_snapshot": "analysis.risk_snapshot",
    "semantic_analyzer": "analysis.semantic_analyzer",
    "trajectory_analyzer": "analysis.trajectory_analyzer",
    "detection_config": "config.detection_config",
    "env_config": "config.env_config",
    "llm_settings": "config.llm_settings",
    "project_config": "config.project_config",
    "effect_normalizer": "effects.normalizer",
    "llm_factory": "llm.factory",
    "llm_provider": "llm.provider",
    "defer_manager": "policy.defer_manager",
    "policy_engine": "policy.engine",
    "session_enforcement": "policy.session_enforcement",
    "session_scope": "policy.session_scope",
    "tool_permissions": "policy.tool_permissions",
    "tool_semantic_registry": "policy.tool_semantic_registry",
    "review_skills": "review.skills",
    "review_toolkit": "review.toolkit",
    "managed_benchmark_warnings": "rules.managed_benchmark_warnings",
    "pattern_evolution": "rules.pattern_evolution",
    "pattern_matcher": "rules.pattern_matcher",
    "rule_governance": "rules.rule_governance",
    "safe_regex": "rules.safe_regex",
    "codex_watcher": "runtime.codex_watcher",
    "command_normalization": "runtime.command_normalization",
    "text_utils": "runtime.text_utils",
    "alert_registry": "storage.alert_registry",
    "idempotency": "storage.idempotency",
    "session_registry": "storage.session_registry",
    "trajectory_store": "storage.trajectory_store",
    "event_bus": "telemetry.event_bus",
    "metrics": "telemetry.metrics",
    "l3_advisory_worker": "l3.advisory_worker",
    "l3_runtime": "l3.runtime",
    "l3_trigger": "l3.trigger",
    "skill_trust": "trust.skill_trust",
    "skill_trust_lifecycle": "trust.lifecycle",
}


def _legacy_aliases() -> dict[str, str]:
    """Return old gateway module names mapped to their new module paths."""
    return dict(_LEGACY_MODULE_ALIASES)


class _GatewayLegacyAliasLoader(importlib.abc.Loader):
    def __init__(self, old_name: str, new_name: str) -> None:
        self.old_name = old_name
        self.new_name = new_name
        self._target_spec: importlib.machinery.ModuleSpec | None = None

    def create_module(self, spec: importlib.machinery.ModuleSpec) -> ModuleType:
        del spec
        module = importlib.import_module(f"{__name__}.{self.new_name}")
        self._target_spec = module.__spec__
        self._restore_target_metadata(module)
        sys.modules[f"{__name__}.{self.old_name}"] = module
        setattr(sys.modules[__name__], self.old_name, module)
        return module

    def exec_module(self, module: ModuleType) -> None:
        self._restore_target_metadata(module)

    def _restore_target_metadata(self, module: ModuleType) -> None:
        target_spec = self._target_spec
        if target_spec is None:
            target_spec = importlib.util.find_spec(f"{__name__}.{self.new_name}")
        if target_spec is not None:
            module.__spec__ = target_spec
            module.__loader__ = target_spec.loader
            module.__package__ = target_spec.parent


class _GatewayLegacyAliasFinder(importlib.abc.MetaPathFinder):
    _marker = "clawsentry-gateway-legacy-alias-finder"

    def find_spec(
        self,
        fullname: str,
        path: object | None,
        target: ModuleType | None = None,
    ) -> importlib.machinery.ModuleSpec | None:
        del path, target
        prefix = f"{__name__}."
        if not fullname.startswith(prefix):
            return None
        old_name = fullname[len(prefix):]
        if "." in old_name:
            return None
        new_name = _LEGACY_MODULE_ALIASES.get(old_name)
        if new_name is None:
            return None
        loader = _GatewayLegacyAliasLoader(old_name, new_name)
        return importlib.machinery.ModuleSpec(fullname, loader)


def _install_legacy_alias_finder() -> None:
    if any(
        getattr(finder, "_marker", None) == _GatewayLegacyAliasFinder._marker
        for finder in sys.meta_path
    ):
        return
    sys.meta_path.insert(0, _GatewayLegacyAliasFinder())


def __getattr__(name: str) -> ModuleType:
    new_name = _LEGACY_MODULE_ALIASES.get(name)
    if new_name is None:
        raise AttributeError(name)
    module = importlib.import_module(f"{__name__}.{new_name}")
    sys.modules[f"{__name__}.{name}"] = module
    setattr(sys.modules[__name__], name, module)
    return module


_install_legacy_alias_finder()
