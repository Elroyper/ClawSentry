"""Gateway config and compatibility field resolution helpers."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Optional

from clawsentry.gateway.models import RiskLevel, SessionScopeProfile
from clawsentry.gateway.policy.scope_task_artifacts import task_artifact_manifest_to_profile
from clawsentry.gateway.policy.session_enforcement import EnforcementAction


def _load_default_session_scope_profile() -> SessionScopeProfile | None:
    """Load the optional default scope profile applied to incoming requests."""

    raw_json = os.getenv("CS_SESSION_SCOPE_PROFILE_JSON", "").strip()
    if raw_json:
        try:
            payload = json.loads(raw_json)
            return SessionScopeProfile.model_validate(payload)
        except Exception as exc:  # noqa: BLE001 - startup-time config surface
            raise RuntimeError(f"Failed to load CS_SESSION_SCOPE_PROFILE_JSON: {exc}") from exc

    raw_manifest_json = os.getenv("CS_SESSION_SCOPE_MANIFEST_JSON", "").strip()
    if raw_manifest_json:
        try:
            payload = json.loads(raw_manifest_json)
            return task_artifact_manifest_to_profile(
                payload,
                input_channel="manifest_env_json",
            ).profile
        except Exception as exc:  # noqa: BLE001 - startup-time config surface
            raise RuntimeError(f"Failed to load CS_SESSION_SCOPE_MANIFEST_JSON: {exc}") from exc

    raw_path = (
        os.getenv("CS_SESSION_SCOPE_PROFILE_FILE")
        or os.getenv("CS_SESSION_SCOPE_PROFILE")
        or ""
    ).strip()
    if raw_path:
        path = Path(raw_path).expanduser()
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            return SessionScopeProfile.model_validate(payload)
        except Exception as exc:  # noqa: BLE001 - startup-time config surface
            raise RuntimeError(
                f"Failed to load CS_SESSION_SCOPE_PROFILE_FILE={path}: {exc}"
            ) from exc

    raw_manifest_path = os.getenv("CS_SESSION_SCOPE_MANIFEST_FILE", "").strip()
    if not raw_manifest_path:
        return None
    manifest_path = Path(raw_manifest_path).expanduser()
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        return task_artifact_manifest_to_profile(
            payload,
            input_channel="manifest_env_file",
        ).profile
    except Exception as exc:  # noqa: BLE001 - startup-time config surface
        raise RuntimeError(
            f"Failed to load CS_SESSION_SCOPE_MANIFEST_FILE={manifest_path}: {exc}"
        ) from exc


def _risk_level_from_string(risk_level: str) -> RiskLevel:
    try:
        return RiskLevel(str(risk_level or "high").lower())
    except ValueError:
        return RiskLevel.HIGH


def _enforcement_action_from_config(action: str) -> EnforcementAction:
    if action == "block":
        return EnforcementAction.BLOCK
    if action == "defer":
        return EnforcementAction.DEFER
    return EnforcementAction.DEFER


def _extract_project_config(
    payload: Optional[dict[str, Any]],
) -> tuple[Optional[str], dict[str, Any]]:
    """Extract project preset/overrides from event payload metadata.

    Returns ``(preset_name, overrides)`` where *preset_name* is ``None``
    when no project preset is specified.
    """
    if not payload or not isinstance(payload, dict):
        return None, {}
    meta = payload.get("_clawsentry_meta")
    if not isinstance(meta, dict):
        return None, {}
    preset = meta.get("project_preset")
    overrides = meta.get("project_overrides", {})
    if not isinstance(overrides, dict):
        overrides = {}
    return preset, overrides


_ADAPTER_SOURCE_FRAMEWORK_MAP: dict[str, str] = {
    "a3s-http": "a3s-code",
    "a3s-uds": "a3s-code",
    "a3s-harness": "a3s-code",
    "a3s-adapter.v1": "a3s-code",
    "a3s-http-adapter.v1": "a3s-code",
    "codex-http": "codex",
    "codex-adapter.v1": "codex",
    "openclaw": "openclaw",
    "openclaw-adapter.v1": "openclaw",
    "claude-code": "claude-code",
    "claude-code-adapter.v1": "claude-code",
}


def _infer_source_framework(
    source_framework: str | None,
    caller_adapter: str | None,
) -> str:
    """Infer framework from caller_adapter when source framework is missing."""
    explicit = str(source_framework or "").strip()
    if explicit and explicit.lower() != "unknown":
        return explicit

    adapter = str(caller_adapter or "").strip().lower()
    inferred = _ADAPTER_SOURCE_FRAMEWORK_MAP.get(adapter, "")
    if inferred:
        return inferred

    return "unknown"


def _extract_compat_event_fields(
    event: dict[str, Any],
) -> tuple[Optional[str], Optional[dict[str, Any]]]:
    payload = event.get("payload")
    if not isinstance(payload, dict):
        return None, None

    meta = payload.get("_clawsentry_meta")
    if not isinstance(meta, dict):
        return None, None

    compat_event_type: Optional[str] = None
    ahp_compat = meta.get("ahp_compat")
    if isinstance(ahp_compat, dict):
        raw_event_type = str(ahp_compat.get("raw_event_type") or "").strip()
        canonical_event_type = str(event.get("event_type") or "").strip()
        if raw_event_type and raw_event_type != canonical_event_type:
            compat_event_type = raw_event_type

    compat_observation = meta.get("compat_observation")
    if isinstance(compat_observation, dict):
        compat_observation = dict(compat_observation)
    else:
        compat_observation = None

    return compat_event_type, compat_observation
