"""Scope-owned task-artifact path classification.

This module classifies task data and task output paths for narrow, profile
confirmed risk adjustment. It does not implement session-scope enforcement and
it does not treat task artifact matches as filesystem sandbox authorization.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import posixpath
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Literal

from clawsentry.gateway.models import (
    DecisionContext,
    SessionScopeProfile,
    SessionScopeSource,
    SessionScopeTaskArtifactRule,
    TASK_ARTIFACT_MANIFEST_VERSION,
    TaskArtifactManifest,
    TaskArtifactManifestPathEntry,
)


LEGACY_TASK_DATA_PATHS_ENV = "CS_BENCHMARK_TASK_DATA_PATHS_JSON"
TASK_DATA_COMPAT_ROOTS = ("/app/data", "/root/data")
TASK_OUTPUT_COMPAT_ROOTS = ("/app/output", "/root/output")
SCOPE_TASK_DATA_READ_PATH_ROLE = "benchmark_task_data_read"
SCOPE_TASK_DATA_WORKSPACE_RELATION = "benchmark_task_data"
SCOPE_TASK_OUTPUT_PATH_ROLE = "benchmark_task_output"
SCOPE_CONTROL_METADATA_PATH_ROLE = "benchmark_control_metadata"
SCOPE_CONTROL_METADATA_RELATION = "benchmark_control_metadata"
TASK_ARTIFACT_SOURCE_MODULE = "scope_task_artifacts"
TASK_ARTIFACT_MANIFEST_CONVERSION_MARKER = "clawsentry.task_artifact_manifest.converted.v1"
TASK_ARTIFACT_MANIFEST_INPUT_CHANNELS = frozenset({
    "api",
    "manifest_convert",
    "manifest_env_file",
    "manifest_env_json",
})
TASK_ARTIFACT_RELATIONS = {
    SCOPE_TASK_DATA_WORKSPACE_RELATION,
    "task_output_artifact",
    "inside_workspace",
}

_CREDENTIAL_WORD_RE = re.compile(
    r"(?:^|[._-])(?:credentials?|secrets?|tokens?|passwords?)(?:$|[._-])",
    re.IGNORECASE,
)
_HIDDEN_ORACLE_MARKERS = (
    "hidden_oracle",
    "/hidden-oracle/",
    "/oracle/expected",
    "expected_answer",
)
_CONTROL_ORACLE_MARKERS = (
    "/control/",
    "/hidden_oracle/",
    "/hidden-oracle/",
    "/oracle/",
    "/verifier/",
    "/judge/",
    "/groundtruth/",
    "answer_key",
    "expected_answer",
    "ground_truth",
    "groundtruth",
    "observer_trace",
    "runtime_observer",
    "task_control",
    "task-control",
)
_PERSISTENCE_MARKERS = (
    ".bashrc",
    ".zshrc",
    ".profile",
    ".config/autostart/",
    "crontab",
    "/cron.",
    "/systemd/",
    ".service",
    "launchagents",
    "launchdaemons",
)
_EXECUTABLE_SUFFIXES = (".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ps1", ".bat", ".cmd")
_PACKAGE_MANIFEST_FILENAMES = frozenset({
    "package.json",
    "pyproject.toml",
})
_UNSAFE_PATH_PREFIXES = (
    "/proc/self/fd/",
    "/dev/fd/",
    "/dev/stdin",
    "/dev/stdout",
    "/dev/stderr",
)
_SYSTEM_SENSITIVE_PREFIXES = (
    "/bin/",
    "/etc/",
    "/lib/",
    "/lib64/",
    "/proc/",
    "/sbin/",
    "/sys/",
    "/usr/",
    "/boot/",
    "/dev/",
)
_BROAD_ABSOLUTE_PREFIX_ROOTS = frozenset({
    "/app",
    "/home",
    "/mnt",
    "/opt",
    "/root",
    "/tmp",
    "/var",
    "/workspace",
})
_PROFILE_REVIEWABLE_HARD_ROLES = frozenset({
    "future_execution.artifact",
})


@dataclass(frozen=True)
class ScopeTaskArtifactDecision:
    matched: bool
    path_role: str | None = None
    workspace_relation: str | None = None
    artifact_role: str | None = None
    candidate_role: str | None = None
    source: str | None = None
    source_tier: str | None = None
    confidence: str | None = None
    artifact_trust_confirmed: bool = False
    risk_adjusting: bool = False
    profile_id: str | None = None
    profile_hash: str | None = None
    case_id: str | None = None
    match_type: str | None = None
    source_module: str = TASK_ARTIFACT_SOURCE_MODULE
    deny_reason: str | None = None
    effective_artifact_source: str | None = None
    profile_candidate_present: bool = False
    profile_candidate_source_tier: str | None = None
    profile_candidate_confidence: str | None = None
    profile_candidate_deny_reason: str | None = None
    profile_shadowed_by_scope_task: bool = False
    scope_task_fallback_used: bool = False
    scope_task_io_preserved: bool = False
    scope_task_fallback_blocked_by_redline_reason: str | None = None
    scope_input_channel: str | None = None
    scope_manifest_id: str | None = None
    scope_manifest_schema: str | None = None
    scope_manifest_hash: str | None = None
    derived_scope_profile_hash: str | None = None
    scope_declaration_source: str | None = None
    scope_declaration_confirmed: bool | None = None
    source_metadata: dict[str, Any] | None = None

    def target_metadata(self) -> dict[str, Any]:
        metadata: dict[str, Any] = {
            "artifact_source_module": self.source_module,
        }
        if self.artifact_role:
            metadata["artifact_role"] = self.artifact_role
        if self.candidate_role:
            metadata["artifact_candidate_role"] = self.candidate_role
        if self.source:
            metadata["artifact_source"] = self.source
        if self.source_tier:
            metadata["artifact_source_tier"] = self.source_tier
        if self.confidence:
            metadata["artifact_confidence"] = self.confidence
        metadata["artifact_trust_confirmed"] = bool(self.artifact_trust_confirmed)
        metadata["artifact_risk_adjusting"] = bool(self.risk_adjusting)
        if self.profile_id:
            metadata["artifact_profile_id"] = self.profile_id
        if self.profile_hash:
            metadata["artifact_profile_hash"] = self.profile_hash
        if self.case_id:
            metadata["artifact_case_id"] = self.case_id
        if self.match_type:
            metadata["artifact_match_type"] = self.match_type
        if self.deny_reason:
            metadata["artifact_deny_reason"] = self.deny_reason
        if self.source_metadata:
            metadata["artifact_source_metadata"] = dict(self.source_metadata)
        if self.effective_artifact_source:
            metadata["effective_artifact_source"] = self.effective_artifact_source
        if self.profile_candidate_present:
            metadata["profile_candidate_present"] = True
        if self.profile_candidate_source_tier:
            metadata["profile_candidate_source_tier"] = self.profile_candidate_source_tier
        if self.profile_candidate_confidence:
            metadata["profile_candidate_confidence"] = self.profile_candidate_confidence
        if self.profile_candidate_deny_reason:
            metadata["profile_candidate_deny_reason"] = self.profile_candidate_deny_reason
        if self.profile_shadowed_by_scope_task:
            metadata["profile_shadowed_by_scope_task"] = True
        if self.scope_task_fallback_used:
            metadata["scope_task_fallback_used"] = True
        if self.scope_task_io_preserved:
            metadata["scope_task_io_preserved"] = True
        if self.scope_task_fallback_blocked_by_redline_reason:
            metadata["scope_task_fallback_blocked_by_redline_reason"] = (
                self.scope_task_fallback_blocked_by_redline_reason
            )
        if self.scope_input_channel:
            metadata["scope_input_channel"] = self.scope_input_channel
        if self.scope_manifest_id:
            metadata["scope_manifest_id"] = self.scope_manifest_id
        if self.scope_manifest_schema:
            metadata["scope_manifest_schema"] = self.scope_manifest_schema
        if self.scope_manifest_hash:
            metadata["scope_manifest_hash"] = self.scope_manifest_hash
        if self.derived_scope_profile_hash:
            metadata["derived_scope_profile_hash"] = self.derived_scope_profile_hash
        if self.scope_declaration_source:
            metadata["scope_declaration_source"] = self.scope_declaration_source
        if self.scope_declaration_confirmed is not None:
            metadata["scope_declaration_confirmed"] = self.scope_declaration_confirmed
        return metadata


@dataclass(frozen=True)
class TaskArtifactManifestConversion:
    """Conversion result for public task artifact manifests."""

    manifest: TaskArtifactManifest
    profile: SessionScopeProfile
    manifest_hash: str
    derived_profile_hash: str
    input_channel: str = "manifest_convert"
    conversion_warnings: tuple[str, ...] = ()
    rejected_rule_count: int = 0

    def summary(self) -> dict[str, Any]:
        task_artifacts = list(self.profile.task_artifacts or [])
        risk_adjusting_ready = [
            rule
            for rule in task_artifacts
            if (
                self.profile.confirmed
                and not self.profile.dry_run
                and rule.source_tier == "risk_adjusting"
                and rule.confidence == "high"
                and rule.artifact_trust_confirmed
            )
        ]
        scope_task_compat_ready = [
            rule for rule in task_artifacts if _rule_scope_task_compat_ready(self.profile, rule)
        ]
        return {
            "valid": True,
            "manifest_id": self.manifest.manifest_id,
            "manifest_schema": self.manifest.schema_,
            "scope_manifest_hash": self.manifest_hash,
            "derived_scope_profile_hash": self.derived_profile_hash,
            "profile_id": self.profile.profile_id,
            "scope_input_channel": self.input_channel,
            "scope_declaration_source": self.manifest.declaration_source,
            "conversion_warnings": list(self.conversion_warnings),
            "validation_mode": "dry_run" if self.profile.dry_run else "enforced",
            "risk_adjusting_ready_count": len(risk_adjusting_ready),
            "scope_task_compat_ready_count": len(scope_task_compat_ready),
            "rejected_rule_count": self.rejected_rule_count,
        }


def hash_session_scope_profile(profile: SessionScopeProfile | dict[str, Any]) -> str:
    """Return the canonical sha256 for a loaded session scope profile."""

    if isinstance(profile, SessionScopeProfile):
        payload = profile.model_dump(mode="json", by_alias=True)
    else:
        payload = profile
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def hash_task_artifact_manifest(manifest: TaskArtifactManifest | dict[str, Any]) -> str:
    """Return the canonical sha256 for a task artifact manifest."""

    if isinstance(manifest, TaskArtifactManifest):
        payload = manifest.model_dump(mode="json", by_alias=True)
    else:
        payload = manifest
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def task_artifact_manifest_to_profile(
    manifest: TaskArtifactManifest | dict[str, Any],
    *,
    input_channel: str = "manifest_convert",
) -> TaskArtifactManifestConversion:
    """Convert a public task artifact manifest into a session scope profile.

    User/operator declarations become bounded scope task I/O compatibility
    evidence. They do not become risk-adjusting profile contracts.
    """

    manifest_model = (
        manifest
        if isinstance(manifest, TaskArtifactManifest)
        else TaskArtifactManifest.model_validate(manifest)
    )
    manifest_hash = hash_task_artifact_manifest(manifest_model)
    warnings: list[str] = []
    rejected_rule_count = 0
    rules: list[SessionScopeTaskArtifactRule] = []

    for entry in _manifest_entries(manifest_model):
        rejection = _manifest_entry_rejection_reason(manifest_model, entry)
        if rejection is not None:
            rejected_rule_count += 1
            warnings.append(f"{entry.rule_id}:{rejection}")
            continue
        effective_path = _manifest_entry_effective_path(manifest_model, entry)
        effects = _manifest_entry_allowed_effects(entry)
        metadata = dict(manifest_model.source_metadata or {})
        metadata.update(entry.source_metadata or {})
        metadata.update({
            "manifest_conversion_marker": TASK_ARTIFACT_MANIFEST_CONVERSION_MARKER,
            "source_kind": _normalize_source_family(manifest_model.source_family),
            "manifest_id": manifest_model.manifest_id,
            "manifest_schema": manifest_model.schema_,
            "manifest_hash": manifest_hash,
            "task_id": manifest_model.task_id,
            "task_instance_id": manifest_model.task_instance_id,
            "declared_by": manifest_model.declared_by,
            "declaration_source": manifest_model.declaration_source,
            "scope_input_channel": input_channel,
            "workspace_root_ref": manifest_model.workspace_root_ref,
            "workspace_root_hash": manifest_model.workspace_root_hash,
            "task_cwd": manifest_model.task_cwd,
            "task_cwd_hash": manifest_model.task_cwd_hash,
            "path_base": manifest_model.path_base,
            "declared_path": entry.path,
            "canonical_path": effective_path,
            "match_type": entry.match_type,
            "evidence_ref": manifest_model.evidence_ref,
            "evidence_sha256": manifest_model.evidence_sha256,
            "expires_at": manifest_model.expires_at,
        })
        rules.append(
            SessionScopeTaskArtifactRule(
                artifact_role=entry.artifact_role,
                allowed_effects=effects,
                match_type=entry.match_type,
                paths=[effective_path],
                source=manifest_model.source_family or "task_artifact_manifest",
                source_tier="legacy_compat",
                confidence=_min_confidence(manifest_model.confidence, entry.confidence),
                artifact_trust_confirmed=bool(manifest_model.confirmed and not manifest_model.dry_run),
                source_metadata=metadata,
            )
        )

    profile = SessionScopeProfile(
        profile_id=manifest_model.profile_id
        or f"task-artifact-manifest:{manifest_model.manifest_id}",
        source=_manifest_profile_source(manifest_model.declaration_source),
        confirmed=manifest_model.confirmed,
        dry_run=manifest_model.dry_run,
        task_artifacts=rules,
    )
    derived_hash = hash_session_scope_profile(profile)
    return TaskArtifactManifestConversion(
        manifest=manifest_model,
        profile=profile,
        manifest_hash=manifest_hash,
        derived_profile_hash=derived_hash,
        input_channel=input_channel,
        conversion_warnings=tuple(warnings),
        rejected_rule_count=rejected_rule_count,
    )


def _manifest_entries(manifest: TaskArtifactManifest) -> list[TaskArtifactManifestPathEntry]:
    entries: list[TaskArtifactManifestPathEntry] = list(manifest.path_entries or [])
    for index, path in enumerate(manifest.task_data_paths or [], start=1):
        entries.append(
            TaskArtifactManifestPathEntry(
                rule_id=f"task_data_paths[{index}]",
                artifact_role="task_data",
                path=path,
                allowed_effects=["filesystem.read", "filesystem.enumerate"],
                confidence=manifest.confidence,
            )
        )
    for index, path in enumerate(manifest.task_output_paths or [], start=1):
        entries.append(
            TaskArtifactManifestPathEntry(
                rule_id=f"task_output_paths[{index}]",
                artifact_role="task_output",
                path=path,
                allowed_effects=["filesystem.write"],
                confidence=manifest.confidence,
            )
        )
    return entries


def _manifest_entry_allowed_effects(entry: TaskArtifactManifestPathEntry) -> list[str]:
    role_effects = (
        {"filesystem.read", "filesystem.enumerate"}
        if entry.artifact_role == "task_data"
        else {"filesystem.write"}
    )
    return sorted(role_effects.intersection(set(entry.allowed_effects or []))) or sorted(role_effects)


def _manifest_profile_source(value: str) -> SessionScopeSource:
    mapping = {
        "user": SessionScopeSource.USER,
        "task_author": SessionScopeSource.TASK_AUTHOR,
        "operator": SessionScopeSource.OPERATOR,
        "project_template": SessionScopeSource.PROJECT_TEMPLATE,
        "runner": SessionScopeSource.RUNNER,
        "verifier": SessionScopeSource.VERIFIER,
    }
    return mapping.get(str(value or "").strip().lower(), SessionScopeSource.OPERATOR)


def _min_confidence(left: str, right: str) -> str:
    order = {"low": 0, "medium": 1, "high": 2}
    return left if order.get(left, 0) <= order.get(right, 0) else right


def _manifest_entry_rejection_reason(
    manifest: TaskArtifactManifest,
    entry: TaskArtifactManifestPathEntry,
) -> str | None:
    binding_rejection = _manifest_path_binding_rejection_reason(manifest, entry.path)
    if binding_rejection is not None:
        return binding_rejection
    path = _manifest_entry_effective_path(manifest, entry)
    if not path or path == "/" or _path_is_canonically_unsafe(path):
        return "canonical_path_unsafe"
    if entry.path.strip().startswith("~"):
        return "home_path_disallowed"
    hard_role = hard_path_role(path, access="read" if entry.artifact_role == "task_data" else "write")
    if hard_role is not None and hard_role not in _PROFILE_REVIEWABLE_HARD_ROLES:
        return "hard_path_role"
    if entry.match_type == "prefix" and _manifest_prefix_is_too_wide(path):
        return "prefix_too_wide"
    if entry.match_type == "glob" and _manifest_glob_is_unsafe(path):
        return "glob_unsafe"
    if _manifest_is_expired(manifest):
        return "manifest_expired"
    return None


def _manifest_path_binding_rejection_reason(
    manifest: TaskArtifactManifest,
    raw_path: str,
) -> str | None:
    raw = str(raw_path or "").strip().strip("'\"").replace("\\", "/")
    if not raw:
        return "canonical_path_unsafe"
    if raw.startswith("/") or raw.startswith("~"):
        return None
    if _has_path_traversal(raw):
        return "path_traversal"
    if manifest.path_base == "absolute_only":
        return "relative_path_requires_base"
    if manifest.path_base == "task_cwd":
        task_cwd = normalize_task_artifact_path(manifest.task_cwd or "")
        if not task_cwd.startswith("/") or task_cwd in {"", "/"}:
            return "task_cwd_unbound"
        return None
    if manifest.path_base == "workspace_root":
        workspace_root = normalize_task_artifact_path(manifest.workspace_root_ref or "")
        if not workspace_root.startswith("/") or workspace_root in {"", "/"}:
            return "workspace_root_unbound"
        return None
    return "path_base_unbound"


def _manifest_entry_effective_path(
    manifest: TaskArtifactManifest,
    entry: TaskArtifactManifestPathEntry,
) -> str:
    raw = str(entry.path or "").strip().strip("'\"").replace("\\", "/")
    if raw.startswith("/") or raw.startswith("~"):
        return normalize_task_artifact_path(raw)
    if manifest.path_base == "task_cwd":
        return normalize_task_artifact_path(raw, cwd=manifest.task_cwd)
    if manifest.path_base == "workspace_root":
        return normalize_task_artifact_path(raw, cwd=manifest.workspace_root_ref)
    return normalize_task_artifact_path(raw)


def _manifest_prefix_is_too_wide(path: str) -> bool:
    normalized = normalize_task_artifact_path(path)
    lowered = normalized.lower().rstrip("/")
    if lowered in {"", "/"} or lowered in _BROAD_ABSOLUTE_PREFIX_ROOTS:
        return True
    parts = [part for part in lowered.split("/") if part]
    if normalized.startswith("/") and len(parts) < 3:
        return True
    return False


def _manifest_glob_is_unsafe(path: str) -> bool:
    raw = str(path or "").strip().replace("\\", "/")
    lowered = raw.lower()
    if "**" in lowered or lowered in {"*", "/*", "/root/*", "/app/*", "/workspace/*"}:
        return True
    if re.search(r"(?:^|/)\.[^/]*[*?[]", lowered):
        return True
    if lowered.count("*") + lowered.count("?") + lowered.count("[") > 2:
        return True
    normalized_parent = normalize_task_artifact_path(str(PurePosixPath(raw).parent))
    return _manifest_prefix_is_too_wide(normalized_parent)


def _manifest_is_expired(manifest: TaskArtifactManifest) -> bool:
    if not manifest.expires_at:
        return False
    try:
        expires = datetime.fromisoformat(str(manifest.expires_at).replace("Z", "+00:00"))
    except ValueError:
        return True
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    return expires <= datetime.now(timezone.utc)


def normalize_task_artifact_path(path: str, *, cwd: str | None = None) -> str:
    raw = str(path or "").strip().strip("'\"").replace("\\", "/")
    if not raw:
        return ""
    if "\x00" in raw:
        return ""
    if raw.startswith("~"):
        return posixpath.normpath(raw)
    if raw.startswith("/"):
        return posixpath.normpath(raw).rstrip("/") or "/"
    if cwd:
        cwd_norm = str(cwd or "").strip().strip("'\"").replace("\\", "/").rstrip("/")
        if cwd_norm.startswith("/") and not _has_path_traversal(raw):
            return posixpath.normpath(cwd_norm + "/" + raw).rstrip("/") or "/"
    return posixpath.normpath(raw).rstrip("/") or "."


def _path_has_credential_marker(lowered_path: str) -> bool:
    for part in str(lowered_path or "").replace("\\", "/").split("/"):
        name = part.strip().lower()
        if not name:
            continue
        if name in {".ssh", "credentials", "credential"}:
            return True
        if (
            name == "id_rsa"
            or name.startswith("id_rsa.")
            or name == "id_ed25519"
            or name.startswith("id_ed25519.")
        ):
            return True
        if name == ".env" or name.startswith(".env."):
            return True
        if _CREDENTIAL_WORD_RE.search(name):
            return True
    return False


def hard_path_role(path: str, *, access: str | None = None, cwd: str | None = None) -> str | None:
    normalized = normalize_task_artifact_path(path, cwd=cwd)
    lowered = normalized.lower()
    if not lowered:
        return None
    if _path_has_credential_marker(lowered):
        return "credential_source"
    if any(marker in lowered for marker in _HIDDEN_ORACLE_MARKERS):
        return "hidden_oracle"
    if any(marker in lowered for marker in _CONTROL_ORACLE_MARKERS):
        return SCOPE_CONTROL_METADATA_PATH_ROLE
    if is_skill_package_path(lowered):
        return "skill_package_read"
    if any(marker in lowered for marker in _PERSISTENCE_MARKERS):
        return "persistence_entrypoint"
    if "loader" in lowered or "bootstrap" in lowered:
        return "bootstrap_loader"
    if access != "read" and posixpath.basename(lowered) in _PACKAGE_MANIFEST_FILENAMES:
        return "future_execution.artifact"
    if access != "read" and (lowered.endswith(_EXECUTABLE_SUFFIXES) or "/bin/" in lowered):
        return "future_execution.artifact"
    return None


def is_skill_package_path(lowered_path: str) -> bool:
    known_roots = (
        "/.codex/skills/",
        "/.codex/skills",
        "/.claude/skills/",
        "/.claude/skills",
        "/.agents/skills/",
        "/.agents/skills",
        "/.gemini/skills/",
        "/.gemini/skills",
        "/.goose/skills/",
        "/.goose/skills",
        "/.factory/skills/",
        "/.factory/skills",
        "/.opencode/skill",
        "/root/skills/",
        "/root/skills",
        "/app/skills/",
        "/app/skills",
        "/workspace/skills/",
        "/workspace/skills",
        "/skills/",
        "/skills",
        ".codex/skills/",
        ".codex/skills",
        ".claude/skills/",
        ".claude/skills",
        ".agents/skills/",
        ".agents/skills",
        ".gemini/skills/",
        ".gemini/skills",
        ".goose/skills/",
        ".goose/skills",
        ".factory/skills/",
        ".factory/skills",
        ".opencode/skill",
    )
    if any(marker in lowered_path for marker in known_roots):
        return True
    if re.search(r"/(?:codex|claude|gemini|kimi|agents?)/skills/[^/]+(?:/|$)", lowered_path):
        return True
    return bool(re.search(r"(?:^|/)skills/[^/]+/skill\.md$", lowered_path))


def resolve_scope_task_artifact(
    path: str,
    *,
    access: Literal["read", "enumerate", "write"],
    context: DecisionContext | None = None,
    cwd: str | None = None,
    include_legacy: bool = True,
) -> ScopeTaskArtifactDecision | None:
    """Classify *path* as a task artifact for *access* if a scoped rule matches."""

    normalized = normalize_task_artifact_path(path, cwd=cwd)
    if not normalized or _path_is_canonically_unsafe(normalized):
        return ScopeTaskArtifactDecision(
            matched=True,
            deny_reason="canonical_path_unsafe",
            scope_task_fallback_blocked_by_redline_reason="canonical_path_unsafe",
        )

    denied_role = hard_path_role(normalized, access=access)
    if denied_role is not None and denied_role not in _PROFILE_REVIEWABLE_HARD_ROLES:
        return ScopeTaskArtifactDecision(
            matched=True,
            path_role=denied_role,
            workspace_relation=SCOPE_CONTROL_METADATA_RELATION
            if denied_role == SCOPE_CONTROL_METADATA_PATH_ROLE
            else None,
            deny_reason=f"deny_override:{denied_role}",
            scope_task_fallback_blocked_by_redline_reason=f"deny_override:{denied_role}",
        )

    profile_decision = _resolve_profile_task_artifact(
        normalized,
        access=access,
        context=context,
        cwd=cwd,
    )
    if profile_decision is not None and (
        profile_decision.effective_artifact_source == "profile_contract"
        or profile_decision.effective_artifact_source == "scope_task_compat"
    ):
        return profile_decision

    if include_legacy:
        legacy_decision = _resolve_legacy_task_artifact(normalized, access=access)
        if legacy_decision is not None and denied_role in _PROFILE_REVIEWABLE_HARD_ROLES:
            legacy_decision = _apply_reviewable_hard_role_to_scope_task(
                legacy_decision,
                denied_role=denied_role,
            )
        if legacy_decision is not None and profile_decision is not None:
            return _merge_profile_candidate_with_scope_task_fallback(
                profile_decision,
                legacy_decision,
            )
        if legacy_decision is not None:
            return legacy_decision
    if denied_role is not None:
        return ScopeTaskArtifactDecision(
            matched=True,
            path_role=denied_role,
            deny_reason=f"deny_override:{denied_role}",
            profile_candidate_present=profile_decision is not None,
            profile_candidate_source_tier=profile_decision.source_tier if profile_decision else None,
            profile_candidate_confidence=profile_decision.confidence if profile_decision else None,
            profile_candidate_deny_reason=profile_decision.deny_reason if profile_decision else None,
            scope_task_fallback_blocked_by_redline_reason=f"deny_override:{denied_role}",
        )
    return profile_decision


def _resolve_profile_task_artifact(
    normalized_path: str,
    *,
    access: str,
    context: DecisionContext | None,
    cwd: str | None,
) -> ScopeTaskArtifactDecision | None:
    profile = context.session_scope_profile if context is not None else None
    if profile is None or not profile.task_artifacts:
        return None
    profile_hash = hash_session_scope_profile(profile)
    profile_enforced = bool(profile.confirmed and not profile.dry_run)
    candidates = _candidate_match_paths(normalized_path, cwd=cwd)
    matched_decisions: list[ScopeTaskArtifactDecision] = []
    for rule in profile.task_artifacts:
        if not _rule_allows_access(rule, access):
            continue
        if not _rule_matches(rule, candidates):
            continue
        source_metadata = dict(rule.source_metadata or {})
        binding_deny_reason = _manifest_runtime_binding_deny_reason(source_metadata, context, cwd)
        relative_path_deny_reason = _relative_risk_adjusting_path_deny_reason(rule, source_metadata)
        broad_root_deny_reason = _broad_root_risk_adjusting_path_deny_reason(rule)
        risk_adjusting = (
            binding_deny_reason is None
            and relative_path_deny_reason is None
            and broad_root_deny_reason is None
            and profile_enforced
            and rule.source_tier == "risk_adjusting"
            and rule.confidence == "high"
            and rule.artifact_trust_confirmed
        )
        scope_task_compat = (
            binding_deny_reason is None
            and _rule_scope_task_compat_ready(profile, rule)
        )
        effective_source = (
            "profile_contract"
            if risk_adjusting
            else "scope_task_compat"
            if scope_task_compat
            else None
        )
        deny_reason = (
            None
            if effective_source
            else (
                binding_deny_reason
                or relative_path_deny_reason
                or broad_root_deny_reason
                or _profile_gate_reason(profile, rule)
            )
        )
        derived_profile_hash = (
            profile_hash
            if _is_manifest_derived_rule(source_metadata)
            else source_metadata.get("derived_scope_profile_hash")
        )
        matched_decisions.append(ScopeTaskArtifactDecision(
            matched=True,
            path_role=rule.path_role if effective_source else None,
            workspace_relation=rule.workspace_relation if effective_source else None,
            artifact_role=rule.artifact_role,
            candidate_role=rule.path_role,
            source=rule.source,
            source_tier=rule.source_tier,
            confidence=rule.confidence,
            artifact_trust_confirmed=rule.artifact_trust_confirmed,
            risk_adjusting=risk_adjusting,
            profile_id=profile.profile_id,
            profile_hash=profile_hash,
            case_id=rule.case_id,
            match_type=rule.match_type,
            deny_reason=deny_reason,
            effective_artifact_source=effective_source,
            profile_candidate_present=not risk_adjusting,
            profile_candidate_source_tier=rule.source_tier,
            profile_candidate_confidence=rule.confidence,
            profile_candidate_deny_reason=deny_reason,
            scope_task_io_preserved=scope_task_compat,
            scope_input_channel=source_metadata.get("scope_input_channel"),
            scope_manifest_id=source_metadata.get("manifest_id"),
            scope_manifest_schema=source_metadata.get("manifest_schema"),
            scope_manifest_hash=source_metadata.get("manifest_hash"),
            derived_scope_profile_hash=derived_profile_hash,
            scope_declaration_source=source_metadata.get("declaration_source"),
            scope_declaration_confirmed=bool(profile.confirmed and not profile.dry_run),
            source_metadata=source_metadata,
        ))
    if not matched_decisions:
        return None
    return _select_profile_task_artifact_decision(matched_decisions)


def _select_profile_task_artifact_decision(
    decisions: list[ScopeTaskArtifactDecision],
) -> ScopeTaskArtifactDecision:
    effective = [decision for decision in decisions if decision.effective_artifact_source]
    if not effective:
        return decisions[0]
    return max(
        effective,
        key=lambda decision: (
            decision.risk_adjusting,
            decision.effective_artifact_source == "profile_contract",
            decision.source_tier == "risk_adjusting",
            decision.confidence == "high",
            decision.artifact_trust_confirmed,
            decision.match_type == "exact",
        ),
    )


def _resolve_legacy_task_artifact(
    normalized_path: str,
    *,
    access: str,
) -> ScopeTaskArtifactDecision | None:
    lowered = normalized_path.lower()
    if access in {"read", "enumerate"}:
        if _legacy_builtin_data_path(lowered):
            return ScopeTaskArtifactDecision(
                matched=True,
                path_role=SCOPE_TASK_DATA_READ_PATH_ROLE,
                workspace_relation=SCOPE_TASK_DATA_WORKSPACE_RELATION,
                artifact_role="task_data",
                candidate_role=SCOPE_TASK_DATA_READ_PATH_ROLE,
                source="legacy_task_artifact_builtin_root",
                source_tier="legacy_compat",
                confidence="high",
                artifact_trust_confirmed=True,
                risk_adjusting=False,
                match_type="prefix",
                effective_artifact_source="scope_task_compat",
                scope_task_io_preserved=True,
            )
        if lowered in _configured_task_data_paths():
            return ScopeTaskArtifactDecision(
                matched=True,
                path_role=SCOPE_TASK_DATA_READ_PATH_ROLE,
                workspace_relation=SCOPE_TASK_DATA_WORKSPACE_RELATION,
                artifact_role="task_data",
                candidate_role=SCOPE_TASK_DATA_READ_PATH_ROLE,
                source="legacy_task_artifact_env",
                source_tier="legacy_compat",
                confidence="high",
                artifact_trust_confirmed=True,
                risk_adjusting=False,
                match_type="exact",
                effective_artifact_source="scope_task_compat",
                scope_task_io_preserved=True,
            )
    if access == "write" and _legacy_builtin_output_path(lowered):
        return ScopeTaskArtifactDecision(
            matched=True,
            path_role=SCOPE_TASK_OUTPUT_PATH_ROLE,
            workspace_relation="inside_workspace",
            artifact_role="task_output",
            candidate_role=SCOPE_TASK_OUTPUT_PATH_ROLE,
            source="legacy_task_artifact_builtin_root",
            source_tier="legacy_compat",
            confidence="high",
            artifact_trust_confirmed=True,
            risk_adjusting=False,
            match_type="prefix",
            effective_artifact_source="scope_task_compat",
            scope_task_io_preserved=True,
        )
    return None


def _legacy_builtin_data_path(lowered_path: str) -> bool:
    return any(lowered_path == root or lowered_path.startswith(root + "/") for root in TASK_DATA_COMPAT_ROOTS)


def _legacy_builtin_output_path(lowered_path: str) -> bool:
    return any(lowered_path == root or lowered_path.startswith(root + "/") for root in TASK_OUTPUT_COMPAT_ROOTS)


def _configured_task_data_paths() -> tuple[str, ...]:
    raw_value = os.environ.get(LEGACY_TASK_DATA_PATHS_ENV, "").strip()
    if not raw_value:
        return ()
    try:
        parsed = json.loads(raw_value)
    except json.JSONDecodeError:
        return ()
    candidates: Iterable[Any]
    if isinstance(parsed, dict):
        candidates = parsed.get("paths", ())
    elif isinstance(parsed, list):
        candidates = parsed
    else:
        return ()
    paths: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        if not isinstance(candidate, str):
            continue
        normalized = normalize_task_artifact_path(candidate).lower()
        if not normalized.startswith("/") or normalized == "/":
            continue
        if any(token in normalized for token in ("*", "?", "[")) or re.search(r"\{[^/{}]+\}", normalized):
            continue
        if hard_path_role(normalized, access="read") is not None:
            continue
        if normalized not in seen:
            seen.add(normalized)
            paths.append(normalized)
    return tuple(paths)


def _rule_allows_access(rule: SessionScopeTaskArtifactRule, access: str) -> bool:
    effect = {
        "read": "filesystem.read",
        "enumerate": "filesystem.enumerate",
        "write": "filesystem.write",
    }[access]
    return effect in set(rule.allowed_effects or [])


def _rule_matches(rule: SessionScopeTaskArtifactRule, candidates: set[str]) -> bool:
    rule_paths = {_normalize_rule_path(path) for path in rule.paths}
    rule_paths.discard("")
    if not rule_paths:
        return False
    if rule.match_type == "exact":
        return bool(candidates.intersection(rule_paths))
    if rule.match_type == "prefix":
        for rule_path in rule_paths:
            prefix = rule_path.rstrip("/") + "/"
            if any(candidate == rule_path or candidate.startswith(prefix) for candidate in candidates):
                return True
        return False
    if rule.match_type == "glob":
        return any(fnmatch.fnmatchcase(candidate, rule_path) for rule_path in rule_paths for candidate in candidates)
    return False


def _candidate_match_paths(normalized_path: str, *, cwd: str | None) -> set[str]:
    candidates = {normalized_path, normalized_path.lower()}
    cwd_norm = normalize_task_artifact_path(cwd or "") if cwd else ""
    if cwd_norm and cwd_norm.startswith("/") and normalized_path.startswith(cwd_norm + "/"):
        rel = normalized_path[len(cwd_norm) + 1 :]
        if rel:
            candidates.add(rel)
            candidates.add(rel.lower())
    return candidates


def _normalize_rule_path(path: str) -> str:
    raw = str(path or "").strip().strip("'\"").replace("\\", "/")
    if not raw:
        return ""
    if raw.startswith("/"):
        return posixpath.normpath(raw).rstrip("/") or "/"
    return posixpath.normpath(raw).rstrip("/") or "."


def _relative_risk_adjusting_path_deny_reason(
    rule: SessionScopeTaskArtifactRule,
    source_metadata: dict[str, Any],
) -> str | None:
    if rule.source_tier != "risk_adjusting":
        return None
    relative_paths = [
        normalized
        for normalized in (_normalize_rule_path(path) for path in rule.paths)
        if normalized and not normalized.startswith("/")
    ]
    if not relative_paths:
        return None
    if _relative_rule_paths_have_runtime_binding(source_metadata):
        return None
    return "relative_path_unbound"


def _broad_root_risk_adjusting_path_deny_reason(rule: SessionScopeTaskArtifactRule) -> str | None:
    if rule.source_tier != "risk_adjusting":
        return None
    for path in rule.paths:
        normalized = _normalize_rule_path(path).lower().rstrip("/")
        if normalized in {"", "/"} or normalized in _BROAD_ABSOLUTE_PREFIX_ROOTS:
            return "broad_root_path_too_wide"
    return None


def _relative_rule_paths_have_runtime_binding(source_metadata: dict[str, Any]) -> bool:
    if not _is_manifest_derived_rule(source_metadata):
        return False
    path_base = str(source_metadata.get("path_base") or "")
    if path_base == "task_cwd":
        return bool(source_metadata.get("task_cwd") or source_metadata.get("task_cwd_hash"))
    if path_base == "workspace_root":
        return bool(source_metadata.get("workspace_root_ref") or source_metadata.get("workspace_root_hash"))
    return False


def _profile_gate_reason(
    profile: SessionScopeProfile,
    rule: SessionScopeTaskArtifactRule,
) -> str:
    if not profile.confirmed:
        return "profile_unconfirmed"
    if profile.dry_run:
        return "profile_dry_run"
    if rule.source_tier != "risk_adjusting":
        return f"source_tier:{rule.source_tier}"
    if rule.confidence != "high":
        return f"confidence:{rule.confidence}"
    if not rule.artifact_trust_confirmed:
        return "artifact_trust_unconfirmed"
    return "profile_gate_closed"


def _normalize_source_family(value: Any) -> str:
    return re.sub(r"[\s-]+", "_", str(value or "").strip().lower())


def _rule_scope_task_compat_ready(
    profile: SessionScopeProfile,
    rule: SessionScopeTaskArtifactRule,
) -> bool:
    if not profile.confirmed or profile.dry_run:
        return False
    if rule.confidence != "high" or not rule.artifact_trust_confirmed:
        return False
    if rule.source_tier != "legacy_compat":
        return False
    if not _is_manifest_derived_rule(rule.source_metadata):
        return False
    source_family = _normalize_source_family(rule.source_metadata.get("source_kind"))
    source = _normalize_source_family(rule.source)
    declaration_source = _normalize_source_family(rule.source_metadata.get("declaration_source"))
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


def _is_manifest_derived_rule(source_metadata: dict[str, Any]) -> bool:
    return (
        str(source_metadata.get("manifest_conversion_marker") or "") == TASK_ARTIFACT_MANIFEST_CONVERSION_MARKER
        and bool(source_metadata.get("manifest_id"))
        and str(source_metadata.get("manifest_schema") or "") == TASK_ARTIFACT_MANIFEST_VERSION
        and bool(source_metadata.get("manifest_hash"))
        and bool(source_metadata.get("task_id"))
        and str(source_metadata.get("scope_input_channel") or "") in TASK_ARTIFACT_MANIFEST_INPUT_CHANNELS
    )


def _manifest_runtime_binding_deny_reason(
    source_metadata: dict[str, Any],
    context: DecisionContext | None,
    cwd: str | None,
) -> str | None:
    if not _is_manifest_derived_rule(source_metadata):
        return None
    summary = context.session_risk_summary if context is not None else None
    if not isinstance(summary, dict):
        summary = {}

    task_id = _first_context_value(summary, "task_id", "current_task_id", "benchmark_task_id")
    declared_task_id = source_metadata.get("task_id")
    if declared_task_id:
        if not task_id:
            return "manifest_task_id_missing"
        if str(task_id) != str(declared_task_id):
            return "manifest_task_id_mismatch"

    if str(source_metadata.get("match_type") or "") == "prefix" and not any(
        source_metadata.get(key)
        for key in (
            "workspace_root_ref",
            "workspace_root_hash",
            "task_cwd",
            "task_cwd_hash",
        )
    ):
        return "manifest_runtime_binding_missing"

    task_instance_id = _first_context_value(summary, "task_instance_id", "case_instance_id")
    declared_task_instance_id = source_metadata.get("task_instance_id")
    if declared_task_instance_id:
        if not task_instance_id:
            return "manifest_task_instance_id_missing"
        if str(task_instance_id) != str(declared_task_instance_id):
            return "manifest_task_instance_id_mismatch"

    workspace_root_hash = _first_context_value(summary, "workspace_root_hash")
    declared_workspace_root_hash = source_metadata.get("workspace_root_hash")
    if declared_workspace_root_hash:
        if not workspace_root_hash:
            return "manifest_workspace_root_hash_missing"
        if str(workspace_root_hash) != str(declared_workspace_root_hash):
            return "manifest_workspace_root_hash_mismatch"

    workspace_root = _first_context_value(summary, "workspace_root", "workspace_root_ref")
    declared_workspace_root = source_metadata.get("workspace_root_ref")
    if declared_workspace_root:
        if not workspace_root:
            return "manifest_workspace_root_missing"
        if normalize_task_artifact_path(str(workspace_root)) != normalize_task_artifact_path(str(declared_workspace_root)):
            return "manifest_workspace_root_mismatch"

    task_cwd_hash = _first_context_value(summary, "task_cwd_hash", "cwd_hash")
    declared_task_cwd_hash = source_metadata.get("task_cwd_hash")
    if declared_task_cwd_hash:
        if not task_cwd_hash:
            return "manifest_task_cwd_hash_missing"
        if str(task_cwd_hash) != str(declared_task_cwd_hash):
            return "manifest_task_cwd_hash_mismatch"

    context_cwd = cwd or _first_context_value(summary, "task_cwd", "cwd", "working_directory")
    declared_task_cwd = source_metadata.get("task_cwd")
    if declared_task_cwd:
        if not context_cwd:
            return "manifest_task_cwd_missing"
        if normalize_task_artifact_path(str(context_cwd)) != normalize_task_artifact_path(str(declared_task_cwd)):
            return "manifest_task_cwd_mismatch"
    return None


def _first_context_value(summary: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = summary.get(key)
        if value not in (None, ""):
            return value
    return None


def _merge_profile_candidate_with_scope_task_fallback(
    profile_decision: ScopeTaskArtifactDecision,
    fallback_decision: ScopeTaskArtifactDecision,
) -> ScopeTaskArtifactDecision:
    return ScopeTaskArtifactDecision(
        matched=fallback_decision.matched,
        path_role=fallback_decision.path_role,
        workspace_relation=fallback_decision.workspace_relation,
        artifact_role=fallback_decision.artifact_role,
        candidate_role=fallback_decision.candidate_role,
        source=fallback_decision.source,
        source_tier=fallback_decision.source_tier,
        confidence=fallback_decision.confidence,
        artifact_trust_confirmed=fallback_decision.artifact_trust_confirmed,
        risk_adjusting=fallback_decision.risk_adjusting,
        profile_id=profile_decision.profile_id,
        profile_hash=profile_decision.profile_hash,
        case_id=fallback_decision.case_id or profile_decision.case_id,
        match_type=fallback_decision.match_type,
        source_module=fallback_decision.source_module,
        deny_reason=fallback_decision.deny_reason,
        effective_artifact_source=fallback_decision.effective_artifact_source,
        profile_candidate_present=True,
        profile_candidate_source_tier=profile_decision.source_tier,
        profile_candidate_confidence=profile_decision.confidence,
        profile_candidate_deny_reason=profile_decision.deny_reason,
        profile_shadowed_by_scope_task=True,
        scope_task_fallback_used=True,
        scope_task_io_preserved=True,
        scope_input_channel=fallback_decision.scope_input_channel,
        scope_manifest_id=fallback_decision.scope_manifest_id,
        scope_manifest_schema=fallback_decision.scope_manifest_schema,
        scope_manifest_hash=fallback_decision.scope_manifest_hash,
        derived_scope_profile_hash=fallback_decision.derived_scope_profile_hash,
        scope_declaration_source=fallback_decision.scope_declaration_source,
        scope_declaration_confirmed=fallback_decision.scope_declaration_confirmed,
        source_metadata=fallback_decision.source_metadata,
    )


def _apply_reviewable_hard_role_to_scope_task(
    decision: ScopeTaskArtifactDecision,
    *,
    denied_role: str,
) -> ScopeTaskArtifactDecision:
    return ScopeTaskArtifactDecision(
        matched=decision.matched,
        path_role=denied_role,
        workspace_relation=decision.workspace_relation,
        artifact_role=decision.artifact_role,
        candidate_role=decision.candidate_role or decision.path_role,
        source=decision.source,
        source_tier=decision.source_tier,
        confidence=decision.confidence,
        artifact_trust_confirmed=decision.artifact_trust_confirmed,
        risk_adjusting=decision.risk_adjusting,
        profile_id=decision.profile_id,
        profile_hash=decision.profile_hash,
        case_id=decision.case_id,
        match_type=decision.match_type,
        source_module=decision.source_module,
        deny_reason=None,
        effective_artifact_source=decision.effective_artifact_source,
        profile_candidate_present=decision.profile_candidate_present,
        profile_candidate_source_tier=decision.profile_candidate_source_tier,
        profile_candidate_confidence=decision.profile_candidate_confidence,
        profile_candidate_deny_reason=decision.profile_candidate_deny_reason,
        profile_shadowed_by_scope_task=decision.profile_shadowed_by_scope_task,
        scope_task_fallback_used=decision.scope_task_fallback_used,
        scope_task_io_preserved=decision.scope_task_io_preserved,
        scope_task_fallback_blocked_by_redline_reason=decision.scope_task_fallback_blocked_by_redline_reason,
        scope_input_channel=decision.scope_input_channel,
        scope_manifest_id=decision.scope_manifest_id,
        scope_manifest_schema=decision.scope_manifest_schema,
        scope_manifest_hash=decision.scope_manifest_hash,
        derived_scope_profile_hash=decision.derived_scope_profile_hash,
        scope_declaration_source=decision.scope_declaration_source,
        scope_declaration_confirmed=decision.scope_declaration_confirmed,
        source_metadata=decision.source_metadata,
    )


def _path_is_canonically_unsafe(normalized_path: str) -> bool:
    if not normalized_path or normalized_path == "/":
        return True
    if _has_path_traversal(normalized_path):
        return True
    lowered = normalized_path.lower()
    if any(lowered.startswith(prefix) for prefix in _UNSAFE_PATH_PREFIXES):
        return True
    if lowered.startswith(_SYSTEM_SENSITIVE_PREFIXES) and not lowered.startswith(("/app/", "/root/", "/workspace/")):
        return True
    path = Path(normalized_path)
    try:
        path_exists = path.exists()
    except OSError:
        path_exists = False
    if path_exists:
        try:
            resolved = str(path.resolve(strict=True)).replace("\\", "/").lower()
            if any(resolved.startswith(prefix) for prefix in _UNSAFE_PATH_PREFIXES):
                return True
            if _path_has_credential_marker(resolved) or any(
                marker in resolved for marker in _CONTROL_ORACLE_MARKERS
            ):
                return True
            if path.is_symlink():
                return True
            stat_result = path.stat()
            if stat_result.st_nlink > 1 and path.is_file():
                return True
        except (OSError, RuntimeError, ValueError):
            return True
    else:
        parent = path.parent
        if str(parent) not in {"", "."}:
            try:
                parent_exists = parent.exists()
            except OSError:
                parent_exists = False
            if parent_exists:
                try:
                    resolved_parent = str(parent.resolve(strict=True)).replace("\\", "/").lower()
                    if any(resolved_parent.startswith(prefix) for prefix in _UNSAFE_PATH_PREFIXES):
                        return True
                    if _path_has_credential_marker(resolved_parent) or any(
                        marker in resolved_parent for marker in _CONTROL_ORACLE_MARKERS
                    ):
                        return True
                    if parent.is_symlink():
                        return True
                except (OSError, RuntimeError, ValueError):
                    return True
    return False


def _has_path_traversal(path: str) -> bool:
    try:
        return ".." in PurePosixPath(path).parts
    except Exception:  # noqa: BLE001 - defensive for malformed path-like input
        return True
