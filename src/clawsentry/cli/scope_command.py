"""Deterministic session-scope validation and preview commands."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from ..gateway.models import CanonicalEvent, DecisionContext, SessionScopeProfile, TaskArtifactManifest
from ..gateway.policy.scope_task_artifacts import (
    hash_session_scope_profile,
    task_artifact_manifest_to_profile,
)
from ..gateway.policy.session_scope import evaluate_session_scope, scope_protection_statement
from ..gateway.policy.tool_permissions import resolve_tool_permission


def run_scope_validate(
    *,
    profile_path: Path | None = None,
    manifest_path: Path | None = None,
    json_mode: bool = False,
) -> int:
    """Validate a scope profile or task artifact manifest file."""

    try:
        _validate_scope_input_choice(profile_path=profile_path, manifest_path=manifest_path)
        if manifest_path is not None:
            conversion = task_artifact_manifest_to_profile(_load_manifest(manifest_path))
            payload = {
                "input": "manifest",
                **conversion.summary(),
                "profile": _profile_summary(conversion.profile),
            }
        else:
            if profile_path is None:
                raise ValueError("--profile or --manifest is required")
            profile = _load_profile(profile_path)
            payload = _profile_summary(profile)
    except (OSError, json.JSONDecodeError, ValidationError, ValueError) as exc:
        print(f"scope validation failed: {exc}", file=sys.stderr)
        return 1

    if json_mode:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    if manifest_path is not None:
        print(f"Task artifact manifest {payload['manifest_id']}: valid")
        print(f"  converted profile: {payload['profile_id']}")
        print(f"  scope task compat ready: {payload['scope_task_compat_ready_count']}")
        print(f"  rejected rules: {payload['rejected_rule_count']}")
    else:
        print(f"Scope profile {payload['profile_id']}: valid")
        print(f"  source: {payload['source']}")
        print(f"  dry_run: {payload['dry_run']}")
        print(f"  confirmed: {payload['confirmed']}")
        print(f"  enforced: {payload['enforced']}")
        print(f"  {payload['protection_statement']}")
    return 0


def run_scope_convert(
    *,
    manifest_path: Path,
    out_path: Path | None = None,
    json_mode: bool = False,
) -> int:
    """Convert a task artifact manifest into a SessionScopeProfile."""

    try:
        conversion = task_artifact_manifest_to_profile(_load_manifest(manifest_path))
    except (OSError, json.JSONDecodeError, ValidationError, ValueError) as exc:
        print(f"scope convert failed: {exc}", file=sys.stderr)
        return 1

    profile_payload = conversion.profile.model_dump(mode="json", by_alias=True)
    payload = {
        **conversion.summary(),
        "profile": profile_payload,
    }
    if out_path is not None:
        out_path.write_text(
            json.dumps(profile_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        payload["out"] = str(out_path)
    if json_mode:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    print(f"Converted manifest {conversion.manifest.manifest_id} -> {conversion.profile.profile_id}")
    if out_path is not None:
        print(f"  wrote: {out_path}")
    print(f"  scope manifest hash: {conversion.manifest_hash}")
    print(f"  derived profile hash: {conversion.derived_profile_hash}")
    print(f"  rejected rules: {conversion.rejected_rule_count}")
    return 0


def run_scope_preview(
    *,
    profile_path: Path | None = None,
    manifest_path: Path | None = None,
    event_path: Path,
    confirm: bool = False,
    json_mode: bool = False,
) -> int:
    """Preview how a profile or manifest evaluates one canonical event."""

    try:
        _validate_scope_input_choice(profile_path=profile_path, manifest_path=manifest_path)
        manifest_summary: dict[str, Any] | None = None
        if manifest_path is not None:
            conversion = task_artifact_manifest_to_profile(_load_manifest(manifest_path))
            profile = conversion.profile
            manifest_summary = conversion.summary()
        else:
            if profile_path is None:
                raise ValueError("--profile or --manifest is required")
            profile = _load_profile(profile_path)
        if confirm:
            profile = profile.model_copy(update={"confirmed": True, "dry_run": False})
        event = _load_event(event_path)
        evaluation = evaluate_session_scope(
            event,
            DecisionContext(session_scope_profile=profile),
        )
    except (OSError, json.JSONDecodeError, ValidationError, ValueError) as exc:
        print(f"scope preview failed: {exc}", file=sys.stderr)
        return 1

    summary = evaluation.summary().model_dump(mode="json") if evaluation else None
    enforced = bool(summary and summary.get("enforced"))
    payload = {
        "valid": True,
        "mode": "enforced" if enforced else "dry_run_only",
        "profile": _profile_summary(profile),
        "manifest": manifest_summary,
        "scope_evaluation": summary,
        "tool_permission": resolve_tool_permission(
            event.tool_name,
            session_state="critical" if profile.confirmed and not profile.dry_run else "baseline",
        ).to_dict(),
        "protection_statement": scope_protection_statement(enforced=enforced),
    }
    if json_mode:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    print(f"Scope preview for {profile.profile_id}: {payload['mode']}")
    if summary:
        print(f"  verdict: {summary['verdict']}")
        print(f"  enforced: {summary['enforced']}")
        for reason in summary.get("reason_codes") or []:
            print(f"  - {reason}")
    permission = payload["tool_permission"]
    print(f"  tool group: {permission['group']} ({permission['action']})")
    print(f"  {payload['protection_statement']}")
    return 0


def _validate_scope_input_choice(
    *,
    profile_path: Path | None,
    manifest_path: Path | None,
) -> None:
    if profile_path is not None and manifest_path is not None:
        raise ValueError("use either --profile or --manifest, not both")


def _load_profile(path: Path) -> SessionScopeProfile:
    return SessionScopeProfile.model_validate(_read_json(path))


def _load_manifest(path: Path) -> TaskArtifactManifest:
    return TaskArtifactManifest.model_validate(_read_json(path))


def _load_event(path: Path) -> CanonicalEvent:
    return CanonicalEvent.model_validate(_read_json(path))


def _read_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def _profile_summary(profile: SessionScopeProfile) -> dict[str, Any]:
    enforced = bool(profile.confirmed and not profile.dry_run)
    task_artifacts = list(profile.task_artifacts or [])
    risk_adjusting_ready = [
        artifact
        for artifact in task_artifacts
        if (
            enforced
            and artifact.source_tier == "risk_adjusting"
            and artifact.confidence == "high"
            and artifact.artifact_trust_confirmed
        )
    ]
    return {
        "valid": True,
        "profile_id": profile.profile_id,
        "source": profile.source.value,
        "confirmed": profile.confirmed,
        "dry_run": profile.dry_run,
        "enforced": enforced,
        "scope_profile_hash": hash_session_scope_profile(profile),
        "task_artifacts": {
            "count": len(task_artifacts),
            "risk_adjusting_ready_count": len(risk_adjusting_ready),
            "scope_task_compat_ready_count": len([
                artifact
                for artifact in task_artifacts
                if _scope_task_compat_ready_for_summary(enforced, artifact)
            ]),
            "source_tiers": sorted({artifact.source_tier for artifact in task_artifacts}),
            "roles": sorted({artifact.artifact_role for artifact in task_artifacts}),
        },
        "protection_statement": scope_protection_statement(enforced=enforced),
    }


def _scope_task_compat_ready_for_summary(enforced: bool, artifact: Any) -> bool:
    if not enforced:
        return False
    if artifact.source_tier != "legacy_compat":
        return False
    if artifact.confidence != "high" or not artifact.artifact_trust_confirmed:
        return False
    metadata = artifact.source_metadata or {}
    source_family = _source_family(metadata.get("source_kind"))
    source = _source_family(artifact.source)
    declaration_source = _source_family(metadata.get("declaration_source"))
    excluded = {
        "instruction_derived",
        "instruction_based",
        "instruction_solution_match",
        "solution_observed",
        "solution_only",
        "solution_trace",
        "heuristic",
        "audit_only_candidate",
        "manual_case_patch",
        "agent_trajectory",
        "wide_glob",
    }
    if source_family in excluded or source in excluded:
        return False
    return declaration_source in {
        "user",
        "task_author",
        "operator",
        "project_template",
        "runner",
        "verifier",
    }


def _source_family(value: Any) -> str:
    return re.sub(r"[\s-]+", "_", str(value or "").strip().lower())
