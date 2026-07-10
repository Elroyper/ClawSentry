"""Compact PRE_ACTION anti-bypass follow-up guard.

The guard keeps a bounded, per-session memory of final risky decisions using
only hashes, fingerprints, ids, and labels.  It never stores raw commands,
payloads, prompts, environment variables, or L3 traces.
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
import time
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque

from clawsentry.gateway.runtime.command_normalization import normalize_shell_command_head
from clawsentry.gateway.config.detection_config import DetectionConfig
from clawsentry.gateway.effects.normalizer import (
    artifact_families,
    effect_hash,
    normalize_action_effect,
    target_hashes,
    write_content_fingerprint,
    write_payload_texts,
)
from clawsentry.gateway.models import CanonicalDecision, CanonicalEvent, EventType, RiskSnapshot
from clawsentry.gateway.policy.scope_task_artifacts import (
    SCOPE_TASK_DATA_READ_PATH_ROLE,
    SCOPE_TASK_OUTPUT_PATH_ROLE,
    resolve_scope_task_artifact,
)


_RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# --- Session-level secret-value taint (Part 3) -----------------------------
# Values observed in tool output whose key name signals sensitivity are
# fingerprinted (hash only, never the raw value) so later writes that re-emit
# them can be routed to deep review. Keyed on generic sensitivity keywords —
# never on case- or fixture-specific names.
_SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]*"
    r"(?:SECRET|TOKEN|PASSWD|PASSWORD|API_?KEY|PRIVATE|CREDENTIAL|ACCESS_?KEY)"
    r"[A-Za-z0-9_]*\s*[=:]\s*[\"']?([^\s\"']+)",
    re.IGNORECASE,
)
_SENSITIVE_BEARER_TOKEN_RE = re.compile(
    r"\b(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{32,})\b"
)
# Write payloads are tokenized on a conservative charset that splits KEY=VALUE
# assignments so bare re-emitted values still surface as candidates.
_SENSITIVE_CANDIDATE_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-./+]{12,}")
_SENSITIVE_VALUE_MIN_LEN = 12
_SENSITIVE_VALUE_MAX_PER_SESSION = 256
_SENSITIVE_SCAN_MAX_CHARS = 65_536
_SENSITIVE_VALUE_PLACEHOLDERS = frozenset({
    "changeme",
    "placeholder",
    "redacted",
    "[redacted]",
    "example",
    "your-token-here",
    "not-set",
    "undefined",
})
_SENSITIVE_VALUE_PLACEHOLDER_PREFIXES = (
    "<",
    "$",
    "{",
    "%",
    "your",
    "example",
    "insert",
    "replace",
    "xxxx",
    "****",
)
_POST_ACTION_OUTPUT_PAYLOAD_KEYS = ("tool_response", "output", "stdout", "result", "content")


def _normalize_secret_token(token: str) -> str:
    return token.strip().strip("\"'`").rstrip(",;")


def _is_plausible_secret_value(value: str) -> bool:
    if len(value) < _SENSITIVE_VALUE_MIN_LEN:
        return False
    lowered = value.lower()
    if lowered in _SENSITIVE_VALUE_PLACEHOLDERS:
        return False
    if lowered.startswith(_SENSITIVE_VALUE_PLACEHOLDER_PREFIXES):
        return False
    # Filesystem paths as values (SECRETS_DIR=/etc/secrets) locate secrets,
    # they are not the secret material itself.
    if value.startswith(("/", "./", "~/")):
        return False
    if len(set(lowered)) <= 2:
        return False
    return True


def _extract_sensitive_values(text: str) -> set[str]:
    """Extract secret-looking values from observed tool output."""

    values: set[str] = set()
    if not text:
        return values
    for match in _SENSITIVE_ASSIGNMENT_RE.finditer(text):
        value = _normalize_secret_token(match.group(1))
        if _is_plausible_secret_value(value):
            values.add(value)
    for match in _SENSITIVE_BEARER_TOKEN_RE.finditer(text):
        values.add(match.group(1))
    return values


def _candidate_secret_tokens(text: str) -> set[str]:
    """Tokens in a write payload that could re-emit a tainted value."""

    tokens: set[str] = set()
    if not text:
        return tokens
    for match in _SENSITIVE_ASSIGNMENT_RE.finditer(text):
        value = _normalize_secret_token(match.group(1))
        if len(value) >= _SENSITIVE_VALUE_MIN_LEN:
            tokens.add(value)
    for raw in _SENSITIVE_CANDIDATE_TOKEN_RE.findall(text):
        token = _normalize_secret_token(raw)
        if len(token) >= _SENSITIVE_VALUE_MIN_LEN:
            tokens.add(token)
    return tokens



_TASK_ARTIFACT_OUTPUT_DISQUALIFYING_RULE_FRAGMENTS = (
    "credential",
    "network",
    "package",
    "destructive",
    "persistence",
    "encoded_payload",
    "wrapper",
    "control",
    "oracle",
    "verifier",
    "judge",
)
_TASK_ARTIFACT_OUTPUT_SCOPED_SOFT_RULE_FRAGMENTS = frozenset({
    "credential",
    "persistence",
    "future_execution",
    "future_exec",
    "future-exec",
})
_TASK_ARTIFACT_DIRECT_COPY_RULES = frozenset({
    "python_shutil_copy",
    "shell_copy_write",
})
_TASK_ARTIFACT_FUTURE_EXEC_OUTPUT_ROLES = frozenset({
    "bootstrap_loader",
    "future_execution.artifact",
})
_TASK_ARTIFACT_READONLY_DISQUALIFYING_RULE_FRAGMENTS = (
    "credential",
    "network",
    "package",
    "destructive",
    "persistence",
    "encoded_payload",
    "wrapper",
    "future_execution",
    "future_exec",
    "future-exec",
    "dynamic_code",
    "code_exec",
    "subprocess",
    "child_process",
    "upload",
    "exfil",
    "control",
    "oracle",
    "verifier",
    "judge",
)
_TASK_ARTIFACT_READONLY_WRAPPER_ALLOWED_RULES = frozenset({
    "benchmark_task_data_readonly",
    "shell_read_probe",
    "shell_enumerate_probe",
    "shell_awk_unresolved",
    "shell_for_loop_unresolved",
    "shell_unresolved_command_segment",
    "python_file_read",
    "python_file_read_unresolved",
    "python_document_reader_read",
    "python_document_reader_unresolved",
    "python_directory_enumerate",
    "wrapper_chain_unresolved",
})
_TASK_ARTIFACT_LOCAL_WRITE_DISQUALIFYING_RULE_FRAGMENTS = (
    "credential",
    "network",
    "package",
    "destructive",
    "persistence",
    "encoded_payload",
    "wrapper",
    "future_exec",
    "future-exec",
    "control",
    "oracle",
    "verifier",
    "judge",
)
_TASK_ARTIFACT_LOCAL_WRITE_TARGET_ROLES = frozenset({
    "workspace_file",
    "workspace_directory",
    "generated_artifact",
    SCOPE_TASK_OUTPUT_PATH_ROLE,
})
_TASK_ARTIFACT_OUTPUT_ENV_SETUP_EFFECTS = frozenset({
    "command.exec",
    "filesystem.read",
    "filesystem.enumerate",
    "filesystem.write",
    "environment.probe",
    "package.install",
})
_TASK_ARTIFACT_OUTPUT_ENV_SETUP_RULES = frozenset({
    "task_output_env_setup",
    "task_output_local_build_execution",
    "task_output_local_python_verify",
    "task_output_local_artifact_execution",
    "task_output_local_test_execution",
    "task_output_local_vcs_inspection",
    "task_output_env_probe",
})
_TASK_ARTIFACT_LOCAL_WRITE_RELATIONS = frozenset({
    "inside_workspace",
    "outside_workspace_or_absolute",
    "task_output_artifact",
})
_BENCHMARK_COARSE_FAMILY_ONLY_MATCHES = frozenset({
    "future_execution.artifact",
    SCOPE_TASK_OUTPUT_PATH_ROLE,
    SCOPE_TASK_DATA_READ_PATH_ROLE,
    "workspace_file",
})
_DENIED_EFFECT_DETERMINISTIC_PREEMPT_CAPABILITIES = frozenset({
    "credential.access",
    "credential.read",
    "network.fetch",
    "package.install",
    "package_install",
})
_TARGETLESS_DETERMINISTIC_REPEAT_CAPABILITIES = frozenset({
    "network.fetch",
    "package.install",
    "package_install",
})
_LOCAL_WEB_RESOURCE_LITERAL_RE = (
    r"\s*['\"]"
    r"(?!(?:[a-z][a-z0-9+.-]*:|//))"
    r"(?!(?:(?:\.{1,2}/)|/)*(?:api|remote|upload|download|webhook|callback|endpoint|url|uri|host|addr|address)(?:[/.?#]|$))"
    r"(?:\.{0,2}/|[A-Za-z0-9._~-]+/)"
)
_DESTRUCTIVE_HEADS = {
    "rm",
    "rmdir",
    "unlink",
    "shred",
    "dd",
    "mkfs",
    "chmod",
    "chown",
    "curl",
    "wget",
    "scp",
    "rsync",
    "ssh",
    "git",
}


@dataclass(frozen=True)
class AntiBypassRecord:
    event_id: str
    record_id: int
    session_id_hash: str
    tool_name: str
    raw_payload_hash: str
    normalized_action_fingerprint: str
    destructive_intent_label: str
    destructive_intent_fingerprint: str
    destructive_operation_category: str
    target_scope_categories: tuple[str, ...]
    normalized_feature_hashes: tuple[str, ...]
    policy_id: str
    decision: str
    risk_level: str
    occurred_at: str
    recorded_at: str
    expires_at: str
    source_framework: str


@dataclass(frozen=True)
class DeniedEffectMemoryRecord:
    event_id: str
    record_id: int
    session_id_hash: str
    capability: str
    effect_hash: str
    target_hashes: tuple[str, ...]
    artifact_families: tuple[str, ...]
    policy_id: str
    policy_version: str
    decision: str
    risk_level: str
    occurred_at: str
    recorded_at: str
    expires_at: str
    payload_content_fingerprint: tuple[str, ...] = ()


@dataclass(frozen=True)
class PendingEffectHoldRecord:
    event_id: str
    record_id: int
    session_id_hash: str
    capability: str
    effect_hash: str
    target_hashes: tuple[str, ...]
    artifact_families: tuple[str, ...]
    policy_id: str
    decision: str
    risk_level: str
    occurred_at: str
    recorded_at: str
    expires_at: str


@dataclass(frozen=True)
class AntiBypassMatch:
    match_type: str
    action: str
    prior_event_id: str
    prior_record_id: int
    prior_policy_id: str
    prior_risk_level: str
    raw_payload_hash: str
    normalized_action_fingerprint: str
    destructive_intent_fingerprint: str
    destructive_intent_label: str = ""
    destructive_operation_category: str = ""
    similarity: float | None = None
    recognition_source: str = "deterministic"
    match_reason: str = ""
    similarity_mode: str = ""
    llm_confidence: float | None = None
    llm_state: str | None = None
    reason_codes: tuple[str, ...] = ()
    evidence_categories: tuple[str, ...] = ()

    def to_metadata(self) -> dict[str, Any]:
        meta = {
            "matched": True,
            "match_type": self.match_type,
            "action": self.action,
            "recognition_source": self.recognition_source,
            "prior_event_id": self.prior_event_id,
            "prior_record_id": self.prior_record_id,
            "prior_policy_id": self.prior_policy_id,
            "prior_risk_level": self.prior_risk_level,
            "raw_payload_hash": self.raw_payload_hash,
            "normalized_action_fingerprint": self.normalized_action_fingerprint,
            "destructive_intent_fingerprint": self.destructive_intent_fingerprint,
        }
        if self.match_reason:
            meta["match_reason"] = self.match_reason
        if self.similarity_mode:
            meta["similarity_mode"] = self.similarity_mode
        if self.destructive_intent_label:
            meta["destructive_intent_label"] = self.destructive_intent_label
        if self.destructive_operation_category:
            meta["destructive_operation_category"] = self.destructive_operation_category
        if self.similarity is not None:
            meta["similarity"] = round(self.similarity, 4)
        if self.llm_confidence is not None:
            meta["llm_confidence"] = round(self.llm_confidence, 4)
        if self.llm_state:
            meta["llm_state"] = self.llm_state
        if self.reason_codes:
            meta["reason_codes"] = list(self.reason_codes)
        if self.evidence_categories:
            meta["evidence_categories"] = list(self.evidence_categories)
        if self.action in ("force_l2", "force_l3"):
            meta["forced_tier"] = "L2" if self.action == "force_l2" else "L3"
        return meta


def _is_scope_task_output_write_effect(
    envelope: Any,
    config: DetectionConfig,
    *,
    event: CanonicalEvent | None = None,
) -> bool:
    if str(config.mode or "normal").strip().lower() != "benchmark":
        return False
    effects = set(getattr(envelope, "effects", ()) or ())
    if "filesystem.write" not in effects:
        return False
    allowed_effects = {
        "filesystem.write",
        "filesystem.read",
        "filesystem.enumerate",
        "future_execution.artifact",
    }
    if not effects.issubset(allowed_effects):
        return False
    evidence_rules = {
        str(rule).lower()
        for rule in getattr(envelope, "evidence_rules", ()) or ()
    }
    if _is_scope_task_data_to_future_exec_direct_copy(envelope, evidence_rules):
        return False
    if (
        "generated_script_future_exec" in evidence_rules
        and _event_payload_has_remote_script_reference(event)
    ):
        return False
    sources = list(getattr(envelope, "sources", ()) or ())
    targets = list(getattr(envelope, "targets", ()) or ())
    if not targets:
        return False
    for source in sources:
        if not _is_effective_scope_task_data_read_target(source):
            return False
    has_output_target = False
    for target in targets:
        if _looks_like_scope_task_data_read_target(target):
            if not _is_effective_scope_task_data_read_target(target):
                return False
            continue
        if not _is_effective_scope_task_output_target(target):
            return False
        has_output_target = True
    if any(
        _task_output_write_rule_disqualifies(rule, scoped_output=has_output_target)
        for rule in evidence_rules
    ):
        return False
    return has_output_target


def _task_output_write_rule_disqualifies(rule: str, *, scoped_output: bool) -> bool:
    lowered = str(rule or "").lower()
    for fragment in _TASK_ARTIFACT_OUTPUT_DISQUALIFYING_RULE_FRAGMENTS:
        if scoped_output and fragment in _TASK_ARTIFACT_OUTPUT_SCOPED_SOFT_RULE_FRAGMENTS:
            continue
        if fragment in lowered:
            return True
    return False


def _event_payload_has_remote_script_reference(event: CanonicalEvent | None) -> bool:
    if event is None:
        return False
    payload = event.payload or {}
    parts: list[str] = []
    for key in ("command", "patch", "diff", "content", "text", "script", "code"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            parts.append(value)
    text = "\n".join(parts)
    if not text.strip():
        return False
    namespace_urls = {
        "http://www.w3.org/1999/xhtml",
        "http://www.w3.org/1999/xlink",
        "http://www.w3.org/2000/svg",
        "http://www.w3.org/XML/1998/namespace",
        "http://www.w3.org/2001/XMLSchema",
        "http://www.w3.org/2001/XMLSchema-instance",
    }
    scrubbed = text
    for namespace_url in namespace_urls:
        scrubbed = scrubbed.replace(namespace_url, "")
    local_literal = _LOCAL_WEB_RESOURCE_LITERAL_RE
    if re.search(
        rf"\b(?:fetch|EventSource|WebSocket)\s*\(\s*(?!{local_literal})",
        scrubbed,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        rf"\bimport\s*\(\s*(?!{local_literal})",
        scrubbed,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        rf"\bnew\s+(?:Worker|SharedWorker)\s*\(\s*(?!{local_literal})",
        scrubbed,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        rf"\bimportScripts\s*\(\s*(?!{local_literal})",
        scrubbed,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        rf"\bnavigator\s*\.\s*serviceWorker\s*\.\s*register\s*\(\s*(?!{local_literal})",
        scrubbed,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        rf"\bwindow\s*\.\s*open\s*\(\s*(?!{local_literal})",
        scrubbed,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        rf"\bnavigator\s*\.\s*sendBeacon\s*\(\s*(?!{local_literal})",
        scrubbed,
        re.IGNORECASE,
    ):
        return True
    if re.search(r"\bXMLHttpRequest\s*\(", scrubbed, re.IGNORECASE):
        return True
    if re.search(
        r"\b(?:open|setAttribute)\s*\([^)]*(?:url|uri|endpoint|remote|webhook|callback|upload)[^)]*\)",
        scrubbed,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        rf"\bsetAttribute\s*\(\s*['\"](?:src|href)['\"]\s*,\s*(?!{local_literal})",
        scrubbed,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        rf"\.\s*(?:src|href)\s*=\s*(?!{local_literal})",
        scrubbed,
        re.IGNORECASE,
    ):
        return True
    return re.search(
        r"\b(?:fetch|XMLHttpRequest|EventSource|WebSocket)\s*\(\s*['\"](?:https?:)?//|"
        r"\b(?:fetch|XMLHttpRequest|EventSource|WebSocket)\s*\(\s*(?:[\w$]+\.)?(?:[\w$]*(?:remote|endpoint|api|url|uri|webhook|callback|upload)[\w$]*)\b|"
        r"\b(?:fetch|XMLHttpRequest|EventSource|WebSocket)\s*\(\s*[\w$]+\s*\[\s*['\"][\w$]*(?:remote|endpoint|api|url|uri|webhook|callback|upload)[\w$]*['\"]\s*\]|"
        r"\bnavigator\s*\.\s*sendBeacon\s*\(\s*['\"](?:https?:)?//|"
        r"\bnavigator\s*\.\s*sendBeacon\s*\(\s*(?:[\w$]+\.)?(?:[\w$]*(?:remote|endpoint|api|url|uri|webhook|callback|upload)[\w$]*)\b|"
        r"\bnavigator\s*\.\s*sendBeacon\s*\(\s*[\w$]+\s*\[\s*['\"][\w$]*(?:remote|endpoint|api|url|uri|webhook|callback|upload)[\w$]*['\"]\s*\]|"
        r"\bscript\s*\.\s*src\s*=\s*['\"](?:https?:)?//|"
        r"<script\b[^>]*\bsrc\s*=\s*['\"](?:https?:)?//",
        scrubbed,
        re.IGNORECASE | re.DOTALL,
    ) is not None


def _event_payload_has_local_process_execution_reference(event: CanonicalEvent | None) -> bool:
    if event is None:
        return False
    payload = event.payload or {}
    parts: list[str] = []
    for key in ("command", "patch", "diff", "content", "text", "script", "code"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            parts.append(value)
    text = "\n".join(parts)
    if not text.strip():
        return False
    return re.search(
        r"\bsubprocess\s*\.|"
        r"\bchild_process\b|"
        r"\bos\s*\.\s*system\b|"
        r"\bpopen\s*\(|"
        r"\bProcessBuilder\b",
        text,
        re.IGNORECASE,
    ) is not None


def _is_scope_task_output_local_generated_script_effect(
    envelope: Any,
    config: DetectionConfig,
    *,
    event: CanonicalEvent | None = None,
) -> bool:
    if str(config.mode or "normal").strip().lower() != "benchmark":
        return False
    effects = set(getattr(envelope, "effects", ()) or ())
    if "filesystem.write" not in effects:
        return False
    if effects.intersection({"network.fetch", "network.upload", "network.external"}):
        return False
    if not effects.issubset({
        "command.exec",
        "filesystem.write",
        "filesystem.read",
        "filesystem.enumerate",
        "future_execution.artifact",
    }):
        return False
    evidence_rules = {
        str(rule).lower()
        for rule in getattr(envelope, "evidence_rules", ()) or ()
    }
    if _is_scope_task_data_to_future_exec_direct_copy(envelope, evidence_rules):
        return False
    if "generated_script_future_exec" not in evidence_rules:
        return False
    if "associated_script_network_indicator" in evidence_rules:
        return False
    allowed_rules = {
        "shell_heredoc_write",
        "shell_redirection_write",
        "shell_touch_write",
        "shell_copy_write",
        "native_write_effect",
        "python_file_write",
        "dd_output_write",
        "generated_script_future_exec",
        "wrapper_chain_unresolved",
        "shell_enumerate_probe",
    }
    hard_fragments = (
        "credential",
        "package",
        "destructive",
        "persistence",
        "encoded_payload",
        "dynamic_code",
        "code_exec",
        "subprocess",
        "child_process",
        "control",
        "oracle",
        "verifier",
        "judge",
        "remote_fetch",
        "upload",
        "exfil",
        "task_data_write",
        "contract_violation",
        "network_download",
        "network_equivalent",
    )
    for rule in evidence_rules:
        if rule in allowed_rules:
            continue
        if any(fragment in rule for fragment in hard_fragments):
            return False
    if _event_payload_has_remote_script_reference(event):
        return False
    if _event_payload_has_local_process_execution_reference(event):
        return False
    for source in getattr(envelope, "sources", ()) or ():
        if not _is_effective_scope_task_data_read_target(source):
            return False
    targets = list(getattr(envelope, "targets", ()) or ())
    if not targets:
        return False
    has_output_target = False
    for target in targets:
        if _looks_like_scope_task_data_read_target(target):
            if not _is_effective_scope_task_data_read_target(target):
                return False
            continue
        if not _is_effective_scope_task_output_target(target):
            return False
        has_output_target = True
    return has_output_target


def _is_scope_task_data_to_future_exec_direct_copy(
    envelope: Any,
    evidence_rules: set[str],
) -> bool:
    if not evidence_rules.intersection(_TASK_ARTIFACT_DIRECT_COPY_RULES):
        return False
    copy_to_script_asset_tree = "copy_to_script_asset_tree" in evidence_rules
    has_task_data_source = any(
        _is_effective_scope_task_data_read_target(source)
        for source in getattr(envelope, "sources", ()) or ()
    )
    has_future_exec_output = False
    for target in getattr(envelope, "targets", ()) or ():
        if _looks_like_scope_task_data_read_target(target):
            has_task_data_source = has_task_data_source or _is_effective_scope_task_data_read_target(target)
            continue
        role = str(getattr(target, "path_role", "") or "")
        if (
            role in _TASK_ARTIFACT_FUTURE_EXEC_OUTPUT_ROLES
            or copy_to_script_asset_tree
        ) and _is_effective_scope_task_output_target(target):
            has_future_exec_output = True
    return has_task_data_source and has_future_exec_output


def _is_anti_bypass_scope_exempt_effect(
    envelope: Any,
    config: DetectionConfig,
    *,
    event: CanonicalEvent | None = None,
    context: Any = None,
) -> bool:
    return bool(
        _is_scope_task_output_write_effect(envelope, config, event=event)
        or _is_scope_task_output_local_generated_script_effect(
            envelope,
            config,
            event=event,
        )
        or _is_scope_task_output_env_setup_effect(envelope, config)
        or _is_scope_task_data_to_output_recovery_effect(
            envelope,
            config,
            event=event,
            context=context,
        )
        or _is_scope_task_data_to_local_artifact_effect(envelope, config)
        or _is_scope_task_data_readonly_effect(envelope, config)
    )


def _is_scope_task_output_env_setup_effect(envelope: Any, config: DetectionConfig) -> bool:
    if str(config.mode or "normal").strip().lower() != "benchmark":
        return False
    effects = set(getattr(envelope, "effects", ()) or ())
    if not effects or not effects.issubset(_TASK_ARTIFACT_OUTPUT_ENV_SETUP_EFFECTS):
        return False
    evidence_rules = {
        str(rule).lower()
        for rule in getattr(envelope, "evidence_rules", ()) or ()
    }
    if not evidence_rules.intersection(_TASK_ARTIFACT_OUTPUT_ENV_SETUP_RULES):
        return False
    if "wrapper_chain_unresolved" in evidence_rules:
        return False
    if "package.install" in effects and "task_output_env_setup" not in evidence_rules:
        return False
    if list(getattr(envelope, "wrapper_chain", ()) or ()):
        return False
    for rule in evidence_rules:
        if rule == "package_install" and "task_output_env_setup" in evidence_rules:
            continue
        if any(
            fragment in rule
            for fragment in _TASK_ARTIFACT_OUTPUT_DISQUALIFYING_RULE_FRAGMENTS
            if fragment != "package"
        ):
            return False
        if "package" in rule and rule != "package_install":
            return False
    targets = list(getattr(envelope, "targets", ()) or ())
    if not targets:
        return False
    has_output_target = False
    for target in targets:
        role = str(getattr(target, "path_role", "") or "")
        relation = str(getattr(target, "workspace_relation", "") or "")
        if role == "capability_probe":
            if relation != "process_environment":
                return False
            continue
        if not _is_effective_scope_task_output_target(target):
            return False
        has_output_target = True
    return has_output_target


def _is_scope_task_data_to_output_recovery_effect(
    envelope: Any,
    config: DetectionConfig,
    *,
    event: CanonicalEvent | None = None,
    context: Any = None,
) -> bool:
    if str(config.mode or "normal").strip().lower() != "benchmark":
        return False
    effects = set(getattr(envelope, "effects", ()) or ())
    allowed_effects = {
        "command.exec",
        "filesystem.write",
        "filesystem.read",
        "filesystem.enumerate",
        "future_execution.artifact",
    }
    if not effects or not effects.issubset(allowed_effects):
        return False
    if "filesystem.write" not in effects or not effects.intersection({"filesystem.read", "filesystem.enumerate"}):
        return False
    evidence_rules = {
        str(rule).lower()
        for rule in getattr(envelope, "evidence_rules", ()) or ()
    }
    if _is_scope_task_data_to_future_exec_direct_copy(envelope, evidence_rules):
        return False
    target_modelled_task_io = _recovery_effect_targets_are_scope_task_data_to_output(
        envelope,
    )
    for rule in evidence_rules:
        for fragment in _TASK_ARTIFACT_OUTPUT_DISQUALIFYING_RULE_FRAGMENTS:
            if fragment in {"future_exec", "future-exec"}:
                continue
            if fragment == "wrapper" and rule == "wrapper_chain_unresolved":
                continue
            if fragment == "destructive" and rule in {
                "destructive_delete",
                "destructive_delete_target_modeled",
            }:
                if (
                    "destructive_delete_target_unresolved" not in evidence_rules
                    and (
                        _destructive_delete_targets_are_scope_task_output(event, context)
                        or target_modelled_task_io
                    )
                ):
                    continue
            if fragment in rule:
                return False
    sources = list(getattr(envelope, "sources", ()) or [])
    for source in sources:
        if not _is_effective_scope_task_data_read_target(source):
            return False
    targets = list(getattr(envelope, "targets", ()) or ())
    if not targets:
        return False
    has_task_data_target = False
    has_output_target = False
    for target in targets:
        if _looks_like_scope_task_data_read_target(target):
            if not _is_effective_scope_task_data_read_target(target):
                return False
            has_task_data_target = True
            continue
        if not _is_effective_scope_task_output_target(target):
            return False
        has_output_target = True
    return has_task_data_target and has_output_target


def _recovery_effect_targets_are_scope_task_data_to_output(envelope: Any) -> bool:
    targets = list(getattr(envelope, "targets", ()) or ())
    if not targets:
        return False
    has_task_data_target = False
    has_output_target = False
    for target in targets:
        if _looks_like_scope_task_data_read_target(target):
            if not _is_effective_scope_task_data_read_target(target):
                return False
            has_task_data_target = True
            continue
        if not _is_effective_scope_task_output_target(target):
            return False
        has_output_target = True
    return has_task_data_target and has_output_target


def _destructive_delete_targets_are_scope_task_output(
    event: CanonicalEvent | None,
    context: Any,
) -> bool:
    if event is None:
        return False
    payload = event.payload or {}
    command = str(payload.get("command") or payload.get("cmd") or "").strip()
    if not command:
        return False
    cwd = str(payload.get("cwd") or "").strip() or None
    targets = _shell_rm_delete_targets(command)
    if not targets:
        return False
    return all(
        _path_is_effective_scope_task_output_for_write(target, context=context, cwd=cwd)
        for target in targets
    )


def _shell_rm_delete_targets(command: str) -> tuple[str, ...]:
    tokens = _shell_tokens_with_punctuation(command)
    targets: list[str] = []
    separators = {";", "&", "|", "&&", "||"}
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in separators:
            index += 1
            continue
        head = Path(token).name.lower()
        if head != "rm":
            index += 1
            continue
        segment: list[str] = []
        index += 1
        while index < len(tokens) and tokens[index] not in separators:
            segment.append(tokens[index])
            index += 1
        targets.extend(_rm_segment_delete_targets(segment))
    return tuple(dict.fromkeys(targets))


def _shell_tokens_with_punctuation(command: str) -> list[str]:
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        return list(lexer)
    except ValueError:
        return []


def _rm_segment_delete_targets(tokens: list[str]) -> list[str]:
    targets: list[str] = []
    option_values = {"--preserve-root", "--one-file-system"}
    index = 0
    end_of_options = False
    while index < len(tokens):
        token = tokens[index]
        if not token:
            index += 1
            continue
        if not end_of_options and token == "--":
            end_of_options = True
            index += 1
            continue
        if not end_of_options and token in option_values:
            index += 1
            continue
        if not end_of_options and token.startswith("-"):
            index += 1
            continue
        targets.append(token)
        index += 1
    return targets


def _path_is_effective_scope_task_output_for_write(
    path: str,
    *,
    context: Any,
    cwd: str | None,
) -> bool:
    decision = resolve_scope_task_artifact(path, access="write", context=context, cwd=cwd)
    if decision is None:
        return False
    role = str(getattr(decision, "path_role", "") or "")
    candidate_role = str(getattr(decision, "candidate_role", "") or "")
    relation = str(getattr(decision, "workspace_relation", "") or "")
    return bool(
        getattr(decision, "artifact_role", None) == "task_output"
        and (role == SCOPE_TASK_OUTPUT_PATH_ROLE or candidate_role == SCOPE_TASK_OUTPUT_PATH_ROLE)
        and relation in {"inside_workspace", "task_output_artifact"}
        and (
            getattr(decision, "risk_adjusting", None) is True
            or getattr(decision, "effective_artifact_source", None) == "scope_task_compat"
        )
    )


def _is_scope_task_data_readonly_effect(envelope: Any, config: DetectionConfig) -> bool:
    if str(config.mode or "normal").strip().lower() != "benchmark":
        return False
    effects = set(getattr(envelope, "effects", ()) or ())
    allowed_effects = {
        "command.exec",
        "filesystem.read",
        "filesystem.enumerate",
        "environment.probe",
    }
    if not effects or not effects.issubset(allowed_effects):
        return False
    if "command.exec" in effects and not effects.intersection({
        "filesystem.read",
        "filesystem.enumerate",
    }):
        return False
    evidence_rules = {
        str(rule).lower()
        for rule in getattr(envelope, "evidence_rules", ()) or ()
    }
    disqualifying_fragments = tuple(
        fragment
        for fragment in _TASK_ARTIFACT_READONLY_DISQUALIFYING_RULE_FRAGMENTS
        if fragment != "wrapper"
    )
    if any(
        fragment in rule
        for rule in evidence_rules
        for fragment in disqualifying_fragments
    ):
        return False
    if (
        "command.exec" in effects
        and evidence_rules
        and any(rule not in _TASK_ARTIFACT_READONLY_WRAPPER_ALLOWED_RULES for rule in evidence_rules)
    ):
        return False
    sources = list(getattr(envelope, "sources", ()) or ())
    if sources:
        return False
    targets = list(getattr(envelope, "targets", ()) or ())
    if not targets:
        return False
    has_task_data_target = False
    for target in targets:
        role = str(getattr(target, "path_role", "") or "")
        relation = str(getattr(target, "workspace_relation", "") or "")
        if _looks_like_scope_task_data_read_target(target):
            if not _is_effective_scope_task_data_read_target(target):
                return False
            has_task_data_target = True
            continue
        if role == "capability_probe" and relation == "process_environment":
            continue
        return False
    return has_task_data_target


def _is_scope_task_data_to_local_artifact_effect(envelope: Any, config: DetectionConfig) -> bool:
    if str(config.mode or "normal").strip().lower() != "benchmark":
        return False
    effects = set(getattr(envelope, "effects", ()) or ())
    allowed_effects = {
        "filesystem.write",
        "filesystem.read",
        "filesystem.enumerate",
    }
    if not effects or not effects.issubset(allowed_effects):
        return False
    if "filesystem.write" not in effects or not effects.intersection({"filesystem.read", "filesystem.enumerate"}):
        return False
    evidence_rules = {
        str(rule).lower()
        for rule in getattr(envelope, "evidence_rules", ()) or ()
    }
    if any(
        fragment in rule
        for rule in evidence_rules
        for fragment in _TASK_ARTIFACT_LOCAL_WRITE_DISQUALIFYING_RULE_FRAGMENTS
    ):
        return False
    if list(getattr(envelope, "wrapper_chain", ()) or ()):
        return False
    sources = list(getattr(envelope, "sources", ()) or ())
    for source in sources:
        if not _is_effective_scope_task_data_read_target(source):
            return False
    targets = list(getattr(envelope, "targets", ()) or ())
    if not targets:
        return False
    has_task_data_target = False
    has_local_write_target = False
    for target in targets:
        if _looks_like_scope_task_data_read_target(target):
            if not _is_effective_scope_task_data_read_target(target):
                return False
            has_task_data_target = True
            continue
        role = str(getattr(target, "path_role", "") or "")
        relation = str(getattr(target, "workspace_relation", "") or "")
        if role not in _TASK_ARTIFACT_LOCAL_WRITE_TARGET_ROLES:
            return False
        if relation not in _TASK_ARTIFACT_LOCAL_WRITE_RELATIONS:
            return False
        if role == SCOPE_TASK_OUTPUT_PATH_ROLE and not _is_effective_scope_task_output_target(target):
            return False
        has_local_write_target = True
    return has_task_data_target and has_local_write_target


def _denied_effect_match_preempts_deterministic(match: AntiBypassMatch | None) -> bool:
    if match is None:
        return False
    categories = {
        str(category)
        for category in getattr(match, "evidence_categories", ()) or ()
    }
    operation = str(getattr(match, "destructive_operation_category", "") or "")
    label = str(getattr(match, "destructive_intent_label", "") or "")
    return bool(_DENIED_EFFECT_DETERMINISTIC_PREEMPT_CAPABILITIES & (categories | {operation, label}))


def _effect_memory_capabilities(envelope: Any) -> tuple[str, ...]:
    capabilities: list[str] = []
    for effect in getattr(envelope, "effects", ()) or ():
        if effect in {
            "filesystem.write",
            "network.fetch",
            "command.exec",
            "package.install",
            "delegated_effect_request",
        }:
            capabilities.append(str(effect))
    if _effect_has_associated_script_network_signal(envelope):
        capabilities.append("network.fetch")
    if _effect_has_credential_read_signal(envelope):
        capabilities.append("credential.read")
    return tuple(dict.fromkeys(capabilities))


def _effect_has_associated_script_network_signal(envelope: Any) -> bool:
    rules = {str(rule).lower() for rule in getattr(envelope, "evidence_rules", ()) or ()}
    return bool(
        "associated_script_network_indicator" in rules
        or "associated_script_network_sink" in rules
        or "credential_source_to_network_sink" in rules
    )


def _effect_has_credential_read_signal(envelope: Any) -> bool:
    rules = {str(rule).lower() for rule in getattr(envelope, "evidence_rules", ()) or ()}
    if "credential_read" in rules:
        return True
    for target in list(getattr(envelope, "targets", ()) or ()) + list(getattr(envelope, "sources", ()) or ()):
        role = str(getattr(target, "path_role", "") or "")
        if role == "credential_source":
            return True
    return False


def _deterministic_capability_only_match(
    *,
    capability: str,
    current_targets: set[str],
    current_families: set[str],
    prior_targets: tuple[str, ...],
    prior_families: tuple[str, ...],
) -> bool:
    if capability not in _TARGETLESS_DETERMINISTIC_REPEAT_CAPABILITIES:
        return False
    return not current_targets and not current_families and not prior_targets and not prior_families


def _coarse_family_match_allowed_for_capability(
    *,
    capability: str,
    current_effect: Any,
    current_families: set[str],
    prior_families: set[str],
) -> bool:
    if capability != "network.fetch":
        return False
    if "future_execution.artifact" not in current_families.intersection(prior_families):
        return False
    return _effect_has_associated_script_network_signal(current_effect)


def _is_effective_scope_task_artifact_target(target: Any) -> bool:
    return bool(
        getattr(target, "artifact_risk_adjusting", None) is True
        or getattr(target, "effective_artifact_source", None) == "scope_task_compat"
    )


def _looks_like_scope_task_data_read_target(target: Any) -> bool:
    role = str(getattr(target, "path_role", "") or "")
    candidate_role = str(getattr(target, "artifact_candidate_role", "") or "")
    artifact_role = str(getattr(target, "artifact_role", "") or "")
    return (
        role == SCOPE_TASK_DATA_READ_PATH_ROLE
        or candidate_role == SCOPE_TASK_DATA_READ_PATH_ROLE
        or artifact_role == "task_data"
    )


def _is_effective_scope_task_data_read_target(target: Any) -> bool:
    relation = str(getattr(target, "workspace_relation", "") or "")
    return (
        _looks_like_scope_task_data_read_target(target)
        and _is_effective_scope_task_artifact_target(target)
        and relation == "benchmark_task_data"
    )


def _is_effective_scope_task_output_target(target: Any) -> bool:
    role = str(getattr(target, "path_role", "") or "")
    candidate_role = str(getattr(target, "artifact_candidate_role", "") or "")
    artifact_role = str(getattr(target, "artifact_role", "") or "")
    relation = str(getattr(target, "workspace_relation", "") or "")
    task_output_bound = (
        role == SCOPE_TASK_OUTPUT_PATH_ROLE
        or candidate_role == SCOPE_TASK_OUTPUT_PATH_ROLE
        or artifact_role == "task_output"
        or relation == "task_output_artifact"
    )
    output_role_allowed = role in {
        SCOPE_TASK_OUTPUT_PATH_ROLE,
        "future_execution.artifact",
        "generated_artifact",
        "workspace_directory",
        "workspace_file",
        "bootstrap_loader",
    }
    return (
        task_output_bound
        and output_role_allowed
        and relation in {"inside_workspace", "task_output_artifact"}
        and _is_effective_scope_task_artifact_target(target)
    )


@dataclass(frozen=True)
class AntiBypassLLMCandidate:
    prior_record: AntiBypassRecord
    similarity: float
    reason_codes: tuple[str, ...]
    evidence_categories: tuple[str, ...]
    current_raw_payload_hash: str
    current_normalized_action_fingerprint: str
    current_destructive_intent_fingerprint: str
    current_destructive_intent_label: str
    current_destructive_operation_category: str
    capsule: dict[str, Any]


@dataclass(frozen=True)
class _EventFingerprints:
    raw_payload_hash: str
    normalized_action_fingerprint: str
    destructive_intent_fingerprint: str
    destructive_intent_label: str
    destructive_operation_category: str
    normalized_feature_hashes: frozenset[str]
    normalized_text: str
    command_head_category: str
    target_scope_categories: frozenset[str]


class AntiBypassGuard:
    """Bounded per-session anti-bypass memory and matcher."""

    def __init__(self) -> None:
        self._records: dict[str, Deque[AntiBypassRecord]] = defaultdict(deque)
        self._denied_effects: dict[str, Deque[DeniedEffectMemoryRecord]] = defaultdict(deque)
        self._pending_effect_holds: dict[str, Deque[PendingEffectHoldRecord]] = defaultdict(deque)
        # value-hash -> source event id; raw values are never stored.
        self._sensitive_value_fingerprints: dict[str, dict[str, str]] = defaultdict(dict)
        self.memory_evictions: int = 0

    def match_pre_action(
        self,
        event: CanonicalEvent,
        context: Any,
        config: DetectionConfig,
    ) -> AntiBypassMatch | None:
        if not config.anti_bypass_guard_enabled:
            return None
        if event.event_type != EventType.PRE_ACTION:
            return None

        session_id = str(event.session_id or "")
        self._evict(session_id, config)
        current_effect = normalize_action_effect(event, context)
        exfil_match = self._match_sensitive_value_exfiltration(event, session_id)
        if _is_anti_bypass_scope_exempt_effect(
            current_effect,
            config,
            event=event,
            context=context,
        ):
            # Secret-value exfiltration must not hide behind benchmark scope
            # exemptions: writing previously observed sensitive values into a
            # declared task output is exactly the laundering channel the
            # exemption would otherwise mask.
            return exfil_match
        current = _fingerprints_for_event(event)
        tool_name = str(event.tool_name or "")
        effect_match = self._match_denied_effect(
            event,
            session_id,
            config,
            context=context,
            current_effect=current_effect,
        )
        if _denied_effect_match_preempts_deterministic(effect_match):
            return effect_match
        for index, prior in enumerate(self._records.get(session_id, ())):
            if not _eligible_prior(prior, config):
                continue
            if prior.tool_name != tool_name or prior.raw_payload_hash != current.raw_payload_hash:
                continue
            return AntiBypassMatch(
                match_type="exact_raw_repeat",
                action=config.anti_bypass_exact_repeat_action,
                prior_event_id=prior.event_id,
                prior_record_id=prior.record_id,
                prior_policy_id=prior.policy_id,
                prior_risk_level=prior.risk_level,
                raw_payload_hash=current.raw_payload_hash,
                normalized_action_fingerprint=current.normalized_action_fingerprint,
                destructive_intent_fingerprint=current.destructive_intent_fingerprint,
                destructive_intent_label=current.destructive_intent_label,
                destructive_operation_category=current.destructive_operation_category,
                match_reason="raw_payload_hash",
                similarity_mode="raw_hash",
            )
        ranked_matches: list[tuple[int, int, AntiBypassMatch]] = []
        for index, prior in enumerate(self._records.get(session_id, ())):
            if not _eligible_prior(prior, config):
                continue
            if prior.tool_name == tool_name and prior.raw_payload_hash == current.raw_payload_hash:
                ranked_matches.append(
                    (
                        0,
                        -index,
                        AntiBypassMatch(
                            match_type="exact_raw_repeat",
                            action=config.anti_bypass_exact_repeat_action,
                            prior_event_id=prior.event_id,
                            prior_record_id=prior.record_id,
                            prior_policy_id=prior.policy_id,
                            prior_risk_level=prior.risk_level,
                            raw_payload_hash=current.raw_payload_hash,
                            normalized_action_fingerprint=current.normalized_action_fingerprint,
                            destructive_intent_fingerprint=current.destructive_intent_fingerprint,
                            destructive_intent_label=current.destructive_intent_label,
                            destructive_operation_category=current.destructive_operation_category,
                            match_reason="raw_payload_hash",
                            similarity_mode="raw_hash",
                        ),
                    )
                )
            if (
                prior.normalized_action_fingerprint
                and prior.normalized_action_fingerprint == current.normalized_action_fingerprint
                and prior.destructive_intent_label != "non-destructive"
                and current.destructive_intent_label != "non-destructive"
            ):
                if prior.tool_name == tool_name:
                    ranked_matches.append(
                        (
                            1,
                            -index,
                            AntiBypassMatch(
                                match_type="normalized_destructive_repeat",
                                action=config.anti_bypass_normalized_destructive_repeat_action,
                                prior_event_id=prior.event_id,
                                prior_record_id=prior.record_id,
                                prior_policy_id=prior.policy_id,
                                prior_risk_level=prior.risk_level,
                                raw_payload_hash=current.raw_payload_hash,
                                normalized_action_fingerprint=current.normalized_action_fingerprint,
                                destructive_intent_fingerprint=current.destructive_intent_fingerprint,
                                destructive_intent_label=current.destructive_intent_label,
                                destructive_operation_category=current.destructive_operation_category,
                                match_reason="exact_normalized_fingerprint",
                                similarity_mode="normalized_hash",
                            ),
                        )
                    )
                else:
                    ranked_matches.append(
                        (
                            3,
                            -index,
                            AntiBypassMatch(
                                match_type="cross_tool_script_similarity",
                                action=config.anti_bypass_cross_tool_similarity_action,
                                prior_event_id=prior.event_id,
                                prior_record_id=prior.record_id,
                                prior_policy_id=prior.policy_id,
                                prior_risk_level=prior.risk_level,
                                raw_payload_hash=current.raw_payload_hash,
                                normalized_action_fingerprint=current.normalized_action_fingerprint,
                                destructive_intent_fingerprint=current.destructive_intent_fingerprint,
                                destructive_intent_label=current.destructive_intent_label,
                                destructive_operation_category=current.destructive_operation_category,
                                match_reason="exact_normalized_fingerprint",
                                similarity_mode="normalized_hash",
                            ),
                        )
                )
            if (
                prior.tool_name != tool_name
                and prior.destructive_intent_label != "non-destructive"
                and current.destructive_intent_label != "non-destructive"
                and prior.destructive_intent_fingerprint == current.destructive_intent_fingerprint
                and _has_cross_tool_label_support(prior, current, similarity=None, config=config)
            ):
                ranked_matches.append(
                    (
                        5,
                        -index,
                        AntiBypassMatch(
                            match_type="cross_tool_script_similarity",
                            action=config.anti_bypass_cross_tool_similarity_action,
                            prior_event_id=prior.event_id,
                            prior_record_id=prior.record_id,
                            prior_policy_id=prior.policy_id,
                            prior_risk_level=prior.risk_level,
                            raw_payload_hash=current.raw_payload_hash,
                            normalized_action_fingerprint=current.normalized_action_fingerprint,
                            destructive_intent_fingerprint=current.destructive_intent_fingerprint,
                            destructive_intent_label=current.destructive_intent_label,
                            destructive_operation_category=current.destructive_operation_category,
                            match_reason="destructive_intent_label",
                            similarity_mode="intent_label",
                        ),
                    )
                )
            if (
                prior.tool_name != tool_name
                and _same_destructive_operation_family(
                    prior.destructive_operation_category,
                    current.destructive_operation_category,
                )
                and set(_record_scope_categories(prior)) & set(current.target_scope_categories)
            ):
                ranked_matches.append(
                    (
                        4,
                        -index,
                        AntiBypassMatch(
                            match_type="cross_tool_script_similarity",
                            action=config.anti_bypass_cross_tool_similarity_action,
                            prior_event_id=prior.event_id,
                            prior_record_id=prior.record_id,
                            prior_policy_id=prior.policy_id,
                            prior_risk_level=prior.risk_level,
                            raw_payload_hash=current.raw_payload_hash,
                            normalized_action_fingerprint=current.normalized_action_fingerprint,
                            destructive_intent_fingerprint=current.destructive_intent_fingerprint,
                            destructive_intent_label=current.destructive_intent_label,
                            destructive_operation_category=current.destructive_operation_category,
                            match_reason="destructive_operation_scope",
                            similarity_mode="operation_scope",
                        ),
                    )
                )

            similarity = _jaccard(
                frozenset(prior.normalized_feature_hashes),
                current.normalized_feature_hashes,
            )
            if (
                prior.tool_name == tool_name
                and prior.destructive_intent_label != "non-destructive"
                and current.destructive_intent_label != "non-destructive"
                and similarity >= config.anti_bypass_same_tool_similarity_threshold
            ):
                ranked_matches.append(
                    (
                        2,
                        -index,
                        AntiBypassMatch(
                            match_type="normalized_destructive_repeat",
                            action=config.anti_bypass_normalized_destructive_repeat_action,
                            prior_event_id=prior.event_id,
                            prior_record_id=prior.record_id,
                            prior_policy_id=prior.policy_id,
                            prior_risk_level=prior.risk_level,
                            raw_payload_hash=current.raw_payload_hash,
                            normalized_action_fingerprint=current.normalized_action_fingerprint,
                            destructive_intent_fingerprint=current.destructive_intent_fingerprint,
                            destructive_intent_label=current.destructive_intent_label,
                            destructive_operation_category=current.destructive_operation_category,
                            similarity=similarity,
                            match_reason="same_tool_feature_similarity",
                            similarity_mode="same_tool_jaccard",
                        ),
                    )
                )
            if (
                prior.tool_name != tool_name
                and prior.destructive_intent_label != "non-destructive"
                and current.destructive_intent_label != "non-destructive"
                and similarity >= config.anti_bypass_similarity_threshold
                and _has_cross_tool_label_support(prior, current, similarity=similarity, config=config)
            ):
                ranked_matches.append(
                    (
                        6,
                        -index,
                        AntiBypassMatch(
                            match_type="cross_tool_script_similarity",
                            action=config.anti_bypass_cross_tool_similarity_action,
                            prior_event_id=prior.event_id,
                            prior_record_id=prior.record_id,
                            prior_policy_id=prior.policy_id,
                            prior_risk_level=prior.risk_level,
                            raw_payload_hash=current.raw_payload_hash,
                            normalized_action_fingerprint=current.normalized_action_fingerprint,
                            destructive_intent_fingerprint=current.destructive_intent_fingerprint,
                            destructive_intent_label=current.destructive_intent_label,
                            destructive_operation_category=current.destructive_operation_category,
                            similarity=similarity,
                            match_reason="cross_tool_feature_similarity",
                            similarity_mode="cross_tool_jaccard",
                        ),
                    )
                )
        if ranked_matches:
            return min(ranked_matches, key=lambda item: (item[0], item[1]))[2]
        if effect_match is not None:
            return effect_match
        pending_match = self._match_pending_effect_hold(event, session_id, config, context=context)
        if pending_match is not None:
            return pending_match
        return exfil_match

    def llm_candidates(
        self,
        event: CanonicalEvent,
        context: Any,
        config: DetectionConfig,
    ) -> list[AntiBypassLLMCandidate]:
        del context
        if not config.anti_bypass_guard_enabled:
            return []
        if event.event_type != EventType.PRE_ACTION:
            return []
        session_id = str(event.session_id or "")
        self._evict(session_id, config)
        current = _fingerprints_for_event(event)
        if current.destructive_intent_label == "non-destructive":
            return []
        tool_name = str(event.tool_name or "")
        candidates: list[AntiBypassLLMCandidate] = []
        for prior in reversed(self._records.get(session_id, ())):
            if len(candidates) >= config.anti_bypass_llm_max_priors:
                break
            if not _eligible_prior(prior, config):
                continue
            if prior.tool_name == tool_name:
                continue
            similarity = _jaccard(
                frozenset(prior.normalized_feature_hashes),
                current.normalized_feature_hashes,
            )
            reason_codes, evidence_categories = _weak_similarity_signals(
                prior,
                current,
                similarity,
                config,
            )
            if not _llm_candidate_admissible(reason_codes):
                continue
            candidates.append(
                AntiBypassLLMCandidate(
                    prior_record=prior,
                    similarity=similarity,
                    reason_codes=tuple(reason_codes),
                    evidence_categories=tuple(evidence_categories),
                    current_raw_payload_hash=current.raw_payload_hash,
                    current_normalized_action_fingerprint=current.normalized_action_fingerprint,
                    current_destructive_intent_fingerprint=current.destructive_intent_fingerprint,
                    current_destructive_intent_label=current.destructive_intent_label,
                    current_destructive_operation_category=current.destructive_operation_category,
                    capsule=_semantic_capsule(
                        prior=prior,
                        current=current,
                        current_tool_name=tool_name,
                        similarity=similarity,
                        reason_codes=reason_codes,
                        evidence_categories=evidence_categories,
                    ),
                )
            )
        return candidates

    def record_final_decision(
        self,
        event: CanonicalEvent,
        decision: CanonicalDecision,
        snapshot: RiskSnapshot | None,
        meta: dict[str, Any],
        record_id: int,
        config: DetectionConfig,
        context: Any = None,
    ) -> None:
        del snapshot, meta  # memory is intentionally compact and recomputed
        if not config.anti_bypass_guard_enabled:
            return
        if event.event_type == EventType.POST_ACTION:
            # Session-level secret-value taint: values observed in tool output
            # (e.g. reading a private support-case or credential file) are
            # fingerprinted so later writes that re-emit them are routed to
            # deep review even when the write target is a declared task output.
            self._capture_sensitive_read_values(event)
            return
        if event.event_type != EventType.PRE_ACTION:
            return
        decision_value = str(getattr(decision.decision, "value", decision.decision))
        if getattr(decision, "final", None) is not True:
            if decision_value == "defer":
                session_id = str(event.session_id or "")
                self._evict(session_id, config)
                now = time.time()
                self._record_pending_effect_hold(
                    event=event,
                    context=context,
                    decision=decision,
                    record_id=record_id,
                    risk_level=str(getattr(decision.risk_level, "value", decision.risk_level)),
                    recorded_at=_iso_from_ts(now),
                    expires_at=_iso_from_ts(now + float(config.anti_bypass_memory_ttl_s)),
                    config=config,
                )
            return

        if decision_value == "allow" and not config.anti_bypass_record_allow_decisions:
            return
        if decision_value not in set(config.anti_bypass_prior_verdicts) and not (
            decision_value == "allow" and config.anti_bypass_record_allow_decisions
        ):
            return

        risk_level = str(getattr(decision.risk_level, "value", decision.risk_level))
        meets_prior_risk = _risk_rank(risk_level) >= _risk_rank(config.anti_bypass_min_prior_risk)
        if not meets_prior_risk and decision_value != "block":
            return

        session_id = str(event.session_id or "")
        self._evict(session_id, config)
        now = time.time()
        if meets_prior_risk:
            fp = _fingerprints_for_event(event)
            record = AntiBypassRecord(
                event_id=str(event.event_id or ""),
                record_id=int(record_id or 0),
                session_id_hash=_sha256(session_id),
                tool_name=str(event.tool_name or ""),
                raw_payload_hash=fp.raw_payload_hash,
                normalized_action_fingerprint=fp.normalized_action_fingerprint,
                destructive_intent_fingerprint=fp.destructive_intent_fingerprint,
                destructive_intent_label=fp.destructive_intent_label,
                destructive_operation_category=fp.destructive_operation_category,
                target_scope_categories=tuple(sorted(fp.target_scope_categories)),
                normalized_feature_hashes=tuple(sorted(fp.normalized_feature_hashes)),
                policy_id=str(decision.policy_id or ""),
                decision=decision_value,
                risk_level=risk_level,
                occurred_at=str(event.occurred_at or ""),
                recorded_at=_iso_from_ts(now),
                expires_at=_iso_from_ts(now + float(config.anti_bypass_memory_ttl_s)),
                source_framework=str(event.source_framework or ""),
            )
            records = self._records[session_id]
            records.append(record)
            while len(records) > config.anti_bypass_memory_max_records_per_session:
                records.popleft()
                self.memory_evictions += 1
        if decision_value == "block":
            # A terminal block is a definitive denial of the effect even when
            # its risk level sits below the similarity-memory threshold; the
            # denied-effect memory must remember it or content/tool rewrites
            # of the same effect sail through unchallenged.
            self._record_denied_effect(
                event=event,
                context=context,
                decision=decision,
                record_id=record_id,
                risk_level=risk_level,
                recorded_at=_iso_from_ts(now),
                expires_at=_iso_from_ts(now + float(config.anti_bypass_memory_ttl_s)),
                config=config,
            )

    def records_for_session(self, session_id: str) -> list[dict[str, Any]]:
        """Return serialized compact records for tests and reporting hooks."""
        return [asdict(record) for record in self._records.get(str(session_id or ""), ())]

    def denied_effect_records_for_session(self, session_id: str) -> list[dict[str, Any]]:
        """Return serialized denied-effect records for tests/reporting hooks."""
        return [asdict(record) for record in self._denied_effects.get(str(session_id or ""), ())]

    def sensitive_value_fingerprints_for_session(self, session_id: str) -> dict[str, str]:
        """Return tainted value hashes (hash -> source event id) for tests/reporting."""
        return dict(self._sensitive_value_fingerprints.get(str(session_id or ""), {}))

    def _capture_sensitive_read_values(self, event: CanonicalEvent) -> None:
        session_id = str(event.session_id or "")
        store = self._sensitive_value_fingerprints[session_id]
        if len(store) >= _SENSITIVE_VALUE_MAX_PER_SESSION:
            return
        payload = event.payload or {}
        parts: list[str] = []
        for key in _POST_ACTION_OUTPUT_PAYLOAD_KEYS:
            value = payload.get(key)
            if isinstance(value, str) and value:
                parts.append(value)
        if not parts:
            return
        text = "\n".join(parts)[:_SENSITIVE_SCAN_MAX_CHARS]
        event_id = str(event.event_id or "")
        for value in _extract_sensitive_values(text):
            if len(store) >= _SENSITIVE_VALUE_MAX_PER_SESSION:
                break
            store.setdefault(_sha256(value), event_id)

    def _match_sensitive_value_exfiltration(
        self,
        event: CanonicalEvent,
        session_id: str,
    ) -> AntiBypassMatch | None:
        tainted = self._sensitive_value_fingerprints.get(session_id)
        if not tainted:
            return None
        hit_hash: str | None = None
        for text in write_payload_texts(event):
            for token in _candidate_secret_tokens(text):
                token_hash = _sha256(token)
                if token_hash in tainted:
                    hit_hash = token_hash
                    break
            if hit_hash is not None:
                break
        if hit_hash is None:
            return None
        fp = _fingerprints_for_event(event)
        return AntiBypassMatch(
            match_type="secret_value_exfiltration",
            action="force_l3",
            prior_event_id=tainted[hit_hash],
            prior_record_id=0,
            prior_policy_id="sensitive-value-taint",
            prior_risk_level="high",
            raw_payload_hash=fp.raw_payload_hash,
            normalized_action_fingerprint=fp.normalized_action_fingerprint,
            destructive_intent_fingerprint=fp.destructive_intent_fingerprint,
            destructive_intent_label=fp.destructive_intent_label,
            destructive_operation_category=fp.destructive_operation_category,
            match_reason="tainted_secret_value_in_write_payload",
            reason_codes=("secret_value_exfiltration",),
        )

    def pending_effect_holds_for_session(self, session_id: str) -> list[dict[str, Any]]:
        """Return serialized pending-effect holds for tests/reporting hooks."""
        return [asdict(record) for record in self._pending_effect_holds.get(str(session_id or ""), ())]

    def resolve_pending_effect_hold(
        self,
        *,
        event: CanonicalEvent,
        context: Any = None,
        decision: CanonicalDecision,
        record_id: int,
        config: DetectionConfig,
    ) -> None:
        """Clear a pending hold and promote terminal blocks into denied memory."""
        if not config.anti_bypass_guard_enabled:
            return
        session_id = str(event.session_id or "")
        pending = self._pending_effect_holds.get(session_id)
        if pending:
            retained = deque(
                record for record in pending
                if record.event_id != str(event.event_id or "")
            )
            self._pending_effect_holds[session_id] = retained
        decision_value = str(getattr(decision.decision, "value", decision.decision))
        if getattr(decision, "final", None) is True and decision_value == "block":
            now = time.time()
            self._evict(session_id, config)
            self._record_denied_effect(
                event=event,
                context=context,
                decision=decision,
                record_id=record_id,
                risk_level=str(getattr(decision.risk_level, "value", decision.risk_level)),
                recorded_at=_iso_from_ts(now),
                expires_at=_iso_from_ts(now + float(config.anti_bypass_memory_ttl_s)),
                config=config,
            )

    def _record_denied_effect(
        self,
        *,
        event: CanonicalEvent,
        context: Any = None,
        decision: CanonicalDecision,
        record_id: int,
        risk_level: str,
        recorded_at: str,
        expires_at: str,
        config: DetectionConfig,
    ) -> None:
        if str(decision.policy_id or "").startswith("anti-bypass-"):
            return
        envelope = normalize_action_effect(event, context)
        if (
            _is_scope_task_output_write_effect(envelope, config)
            or _is_scope_task_output_env_setup_effect(envelope, config)
            or _is_scope_task_data_to_output_recovery_effect(
                envelope,
                config,
                event=event,
                context=context,
            )
            or _is_scope_task_data_to_local_artifact_effect(envelope, config)
            or _is_scope_task_data_readonly_effect(envelope, config)
        ):
            return
        effect_targets = tuple(target_hashes(envelope))
        effect_families = tuple(artifact_families(envelope))
        compact_capabilities = _effect_memory_capabilities(envelope)
        if not compact_capabilities:
            return
        if not effect_targets and not effect_families and not any(
            capability in _TARGETLESS_DETERMINISTIC_REPEAT_CAPABILITIES
            for capability in compact_capabilities
        ):
            return
        session_id = str(event.session_id or "")
        records = self._denied_effects[session_id]
        payload_fingerprint = write_content_fingerprint(event)
        for capability in compact_capabilities:
            records.append(
                DeniedEffectMemoryRecord(
                    event_id=str(event.event_id or ""),
                    record_id=int(record_id or 0),
                    session_id_hash=_sha256(session_id),
                    capability=capability,
                    effect_hash=effect_hash(envelope),
                    target_hashes=effect_targets,
                    artifact_families=effect_families,
                    policy_id=str(decision.policy_id or ""),
                    policy_version=str(decision.policy_version or ""),
                    decision="block",
                    risk_level=risk_level,
                    occurred_at=str(event.occurred_at or ""),
                    recorded_at=recorded_at,
                    expires_at=expires_at,
                    payload_content_fingerprint=payload_fingerprint,
                )
            )
        while len(records) > config.anti_bypass_memory_max_records_per_session:
            records.popleft()
            self.memory_evictions += 1

    def _record_pending_effect_hold(
        self,
        *,
        event: CanonicalEvent,
        context: Any = None,
        decision: CanonicalDecision,
        record_id: int,
        risk_level: str,
        recorded_at: str,
        expires_at: str,
        config: DetectionConfig,
    ) -> None:
        envelope = normalize_action_effect(event, context)
        if (
            _is_scope_task_output_write_effect(envelope, config)
            or _is_scope_task_output_env_setup_effect(envelope, config)
            or _is_scope_task_data_to_output_recovery_effect(
                envelope,
                config,
                event=event,
                context=context,
            )
            or _is_scope_task_data_to_local_artifact_effect(envelope, config)
            or _is_scope_task_data_readonly_effect(envelope, config)
        ):
            return
        effect_targets = tuple(target_hashes(envelope))
        effect_families = tuple(artifact_families(envelope))
        compact_capabilities = _effect_memory_capabilities(envelope)
        if not compact_capabilities:
            return
        if not effect_targets and not effect_families and not any(
            capability in _TARGETLESS_DETERMINISTIC_REPEAT_CAPABILITIES
            for capability in compact_capabilities
        ):
            return
        session_id = str(event.session_id or "")
        records = self._pending_effect_holds[session_id]
        for capability in compact_capabilities:
            records.append(
                PendingEffectHoldRecord(
                    event_id=str(event.event_id or ""),
                    record_id=int(record_id or 0),
                    session_id_hash=_sha256(session_id),
                    capability=capability,
                    effect_hash=effect_hash(envelope),
                    target_hashes=effect_targets,
                    artifact_families=effect_families,
                    policy_id=str(decision.policy_id or ""),
                    decision="defer",
                    risk_level=risk_level,
                    occurred_at=str(event.occurred_at or ""),
                    recorded_at=recorded_at,
                    expires_at=expires_at,
                )
            )
        while len(records) > config.anti_bypass_memory_max_records_per_session:
            records.popleft()
            self.memory_evictions += 1

    def _evict(self, session_id: str, config: DetectionConfig) -> None:
        records = self._records.get(session_id)
        now = time.time()
        if records:
            while records and _parse_iso(records[0].expires_at) <= now:
                records.popleft()
                self.memory_evictions += 1
        denied_effects = self._denied_effects.get(session_id)
        if denied_effects:
            while denied_effects and _parse_iso(denied_effects[0].expires_at) <= now:
                denied_effects.popleft()
                self.memory_evictions += 1
        pending_effect_holds = self._pending_effect_holds.get(session_id)
        if pending_effect_holds:
            while pending_effect_holds and _parse_iso(pending_effect_holds[0].expires_at) <= now:
                pending_effect_holds.popleft()
                self.memory_evictions += 1

    def _match_denied_effect(
        self,
        event: CanonicalEvent,
        session_id: str,
        config: DetectionConfig,
        context: Any = None,
        current_effect: Any | None = None,
    ) -> AntiBypassMatch | None:
        current_effect = current_effect or normalize_action_effect(event, context)
        if _is_anti_bypass_scope_exempt_effect(
            current_effect,
            config,
            event=event,
            context=context,
        ):
            return None
        current_targets = set(target_hashes(current_effect))
        current_families = set(artifact_families(current_effect))
        current_capabilities = set(_effect_memory_capabilities(current_effect))
        if not current_capabilities:
            return None

        candidates: list[tuple[int, AntiBypassMatch]] = []
        current_content_fp: set[str] | None = None
        for prior in reversed(self._denied_effects.get(session_id, ())):
            if prior.capability not in current_capabilities:
                continue
            target_match = bool(current_targets.intersection(prior.target_hashes))
            family_match = bool(current_families.intersection(prior.artifact_families))
            capability_only_match = _deterministic_capability_only_match(
                capability=prior.capability,
                current_targets=current_targets,
                current_families=current_families,
                prior_targets=prior.target_hashes,
                prior_families=prior.artifact_families,
            )
            content_match = False
            if prior.payload_content_fingerprint:
                if current_content_fp is None:
                    current_content_fp = set(write_content_fingerprint(event))
                overlap = current_content_fp.intersection(
                    prior.payload_content_fingerprint
                )
                content_match = len(overlap) >= min(
                    2, len(prior.payload_content_fingerprint)
                )
            if (
                not target_match
                and not family_match
                and not capability_only_match
                and not content_match
            ):
                continue
            if (
                family_match
                and not target_match
                and not capability_only_match
                and not content_match
                and _is_benchmark_coarse_family_only_match(
                    current_families=current_families,
                    prior_families=set(prior.artifact_families),
                    config=config,
                )
                and not _coarse_family_match_allowed_for_capability(
                    capability=prior.capability,
                    current_effect=current_effect,
                    current_families=current_families,
                    prior_families=set(prior.artifact_families),
                )
            ):
                continue
            reason_codes = ["denied_effect_repeat"]
            if family_match and not target_match:
                reason_codes.append("artifact_family_match")
            if capability_only_match:
                reason_codes.append("deterministic_capability_match")
            if content_match:
                reason_codes.append("denied_payload_content_match")
            action = (
                config.anti_bypass_exact_repeat_action
                if target_match or content_match
                else "block"
            )
            if (
                family_match
                and not target_match
                and not content_match
                and config.mode in {"normal", "permissive"}
            ):
                action = "defer"
            priority = (
                0
                if prior.capability in _DENIED_EFFECT_DETERMINISTIC_PREEMPT_CAPABILITIES
                else 1
            )
            candidates.append(
                (
                    priority,
                    AntiBypassMatch(
                        match_type="denied_effect_repeat",
                        action=action,
                        prior_event_id=prior.event_id,
                        prior_record_id=prior.record_id,
                        prior_policy_id=prior.policy_id,
                        prior_risk_level=prior.risk_level,
                        raw_payload_hash=current_effect.raw_payload_hash or "",
                        normalized_action_fingerprint=current_effect.canonical_argv_hash or "",
                        destructive_intent_fingerprint=effect_hash(current_effect),
                        destructive_intent_label=prior.capability,
                        destructive_operation_category=prior.capability,
                        match_reason=(
                            "effect_target"
                            if target_match
                            else "payload_content"
                            if content_match
                            else "deterministic_capability"
                            if capability_only_match
                            else "artifact_family"
                        ),
                        similarity_mode="effect_hash",
                        reason_codes=tuple(reason_codes),
                        evidence_categories=(prior.capability,),
                    ),
                )
            )
        if not candidates:
            return None
        return min(candidates, key=lambda item: item[0])[1]

    def _match_pending_effect_hold(
        self,
        event: CanonicalEvent,
        session_id: str,
        config: DetectionConfig,
        context: Any = None,
    ) -> AntiBypassMatch | None:
        current_effect = normalize_action_effect(event, context)
        if (
            _is_scope_task_output_write_effect(current_effect, config)
            or _is_scope_task_output_env_setup_effect(current_effect, config)
            or _is_scope_task_data_to_output_recovery_effect(
                current_effect,
                config,
                event=event,
                context=context,
            )
            or _is_scope_task_data_to_local_artifact_effect(current_effect, config)
            or _is_scope_task_data_readonly_effect(current_effect, config)
        ):
            return None
        current_targets = set(target_hashes(current_effect))
        current_families = set(artifact_families(current_effect))
        current_capabilities = set(_effect_memory_capabilities(current_effect))
        if not current_capabilities:
            return None

        for prior in reversed(self._pending_effect_holds.get(session_id, ())):
            if prior.capability not in current_capabilities:
                continue
            target_match = bool(current_targets.intersection(prior.target_hashes))
            family_match = bool(current_families.intersection(prior.artifact_families))
            capability_only_match = _deterministic_capability_only_match(
                capability=prior.capability,
                current_targets=current_targets,
                current_families=current_families,
                prior_targets=prior.target_hashes,
                prior_families=prior.artifact_families,
            )
            if not target_match and not family_match and not capability_only_match:
                continue
            if (
                family_match
                and not target_match
                and not capability_only_match
                and _is_benchmark_coarse_family_only_match(
                    current_families=current_families,
                    prior_families=set(prior.artifact_families),
                    config=config,
                )
                and not _coarse_family_match_allowed_for_capability(
                    capability=prior.capability,
                    current_effect=current_effect,
                    current_families=current_families,
                    prior_families=set(prior.artifact_families),
                )
            ):
                continue
            reason_codes = ["pending_effect_equivalent"]
            if family_match and not target_match:
                reason_codes.append("artifact_family_match")
            if capability_only_match:
                reason_codes.append("deterministic_capability_match")
            return AntiBypassMatch(
                match_type="pending_effect_equivalent",
                action="defer",
                prior_event_id=prior.event_id,
                prior_record_id=prior.record_id,
                prior_policy_id=prior.policy_id,
                prior_risk_level=prior.risk_level,
                raw_payload_hash=current_effect.raw_payload_hash or "",
                normalized_action_fingerprint=current_effect.canonical_argv_hash or "",
                destructive_intent_fingerprint=effect_hash(current_effect),
                destructive_intent_label=prior.capability,
                destructive_operation_category=prior.capability,
                match_reason=(
                    "effect_target"
                    if target_match
                    else "deterministic_capability"
                    if capability_only_match
                    else "artifact_family"
                ),
                similarity_mode="pending_effect_hold",
                reason_codes=tuple(reason_codes),
                evidence_categories=(prior.capability,),
            )
        return None


def _is_benchmark_coarse_family_only_match(
    *,
    current_families: set[str],
    prior_families: set[str],
    config: DetectionConfig,
) -> bool:
    if str(config.mode or "normal").strip().lower() != "benchmark":
        return False
    shared = current_families.intersection(prior_families)
    if not shared:
        return False
    return shared.issubset(_BENCHMARK_COARSE_FAMILY_ONLY_MATCHES)


def _eligible_prior(record: AntiBypassRecord, config: DetectionConfig) -> bool:
    return (
        record.decision in set(config.anti_bypass_prior_verdicts)
        and _risk_rank(record.risk_level) >= _risk_rank(config.anti_bypass_min_prior_risk)
    )


def _fingerprints_for_event(event: CanonicalEvent) -> _EventFingerprints:
    raw_projection = {
        "event_type": event.event_type.value,
        "tool_name": str(event.tool_name or ""),
        "payload": _canonical_payload_projection(event.payload or {}),
    }
    normalized_text = _normalized_action_text(event)
    normalized_feature_hashes = frozenset(_sha256(token) for token in _tokenize(normalized_text))
    destructive_intent = _destructive_intent_label(normalized_text)
    destructive_operation = _destructive_operation_category(normalized_text, destructive_intent)
    return _EventFingerprints(
        raw_payload_hash=_sha256_json(raw_projection),
        normalized_action_fingerprint=_sha256(normalized_text),
        destructive_intent_label=destructive_intent,
        destructive_intent_fingerprint=_sha256(destructive_intent),
        destructive_operation_category=destructive_operation,
        normalized_feature_hashes=normalized_feature_hashes,
        normalized_text=normalized_text,
        command_head_category=_command_head_category(normalized_text),
        target_scope_categories=frozenset(_scope_categories(normalized_text)),
    )


def _canonical_payload_projection(payload: dict[str, Any]) -> Any:
    def project(value: Any) -> Any:
        if isinstance(value, dict):
            return {str(k): project(v) for k, v in sorted(value.items(), key=lambda item: str(item[0]))}
        if isinstance(value, (list, tuple)):
            return [project(v) for v in value]
        if isinstance(value, (str, int, float, bool)) or value is None:
            return value
        return str(type(value).__name__)

    return project(payload)


def _normalized_action_text(event: CanonicalEvent) -> str:
    payload = event.payload or {}
    command = _first_text(payload, ("command", "cmd", "shell_command", "script", "code", "input"))
    if command:
        return normalize_shell_command_head(command).strip().lower()
    projected = {
        "tool_name": str(event.tool_name or ""),
        "payload_keys": sorted(str(key) for key in payload.keys()),
        "action": _first_text(payload, ("action", "operation", "name", "path", "target_path", "file_path")),
    }
    return json.dumps(projected, sort_keys=True, separators=(",", ":")).lower()


def _first_text(payload: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return ""


def _destructive_intent_label(normalized_text: str) -> str:
    tokens = _tokenize(normalized_text)
    head = tokens[0] if tokens else ""
    if head in _DESTRUCTIVE_HEADS:
        return head
    if _contains_python_delete_api(tokens):
        return "destructive-generic"
    if any(token in {"delete", "remove", "destroy", "exfiltrate", "download", "upload", "unlink", "truncate"} for token in tokens):
        return "destructive-generic"
    return "non-destructive"


def _contains_python_delete_api(tokens: list[str]) -> bool:
    token_set = set(tokens)
    return (
        {"shutil", "rmtree"} <= token_set
        or "unlink" in token_set
        or "rmdir" in token_set
        or {"os", "remove"} <= token_set
        or {"os", "unlink"} <= token_set
        or {"os", "rmdir"} <= token_set
        or "truncate" in token_set
        or "ftruncate" in token_set
    )


def _destructive_operation_category(normalized_text: str, destructive_intent: str) -> str:
    tokens = _tokenize(normalized_text)
    token_set = set(tokens)
    if destructive_intent == "non-destructive":
        return "none"
    if destructive_intent in {"curl", "wget", "scp", "rsync", "ssh"}:
        return "network_transfer"
    if destructive_intent == "git":
        return "vcs_operation"
    if destructive_intent in {"chmod", "chown"}:
        return "permission_change"
    if destructive_intent in {"dd", "mkfs", "shred"}:
        return "destructive_storage"
    if destructive_intent in {"rm", "rmdir", "unlink"}:
        if destructive_intent == "rm" and ("rf" in token_set or "r" in token_set):
            return "delete_tree"
        if destructive_intent == "rmdir":
            return "delete_tree"
        return "delete_path"
    if {"shutil", "rmtree"} <= token_set:
        return "delete_tree"
    if "rmdir" in token_set:
        return "delete_tree"
    if "unlink" in token_set or {"os", "remove"} <= token_set:
        return "delete_path"
    if "truncate" in token_set or "ftruncate" in token_set:
        return "truncate_path"
    return "destructive_generic"


def _weak_similarity_signals(
    prior: AntiBypassRecord,
    current: _EventFingerprints,
    similarity: float,
    config: DetectionConfig,
) -> tuple[list[str], list[str]]:
    reason_codes: list[str] = []
    evidence_categories: list[str] = []
    if similarity >= config.anti_bypass_llm_candidate_threshold:
        reason_codes.append("candidate_feature_similarity")
        evidence_categories.append("feature_overlap")
    if (
        prior.destructive_intent_label != "non-destructive"
        and current.destructive_intent_label != "non-destructive"
    ):
        reason_codes.append("destructive_label_overlap")
        evidence_categories.append("operation_overlap")
    if prior.destructive_intent_label == current.destructive_intent_label:
        reason_codes.append("intent_label_match")
        evidence_categories.append("intent_label")
    if (
        prior.destructive_operation_category != "none"
        and _same_destructive_operation_family(
            prior.destructive_operation_category,
            current.destructive_operation_category,
        )
    ):
        reason_codes.append("operation_category_match")
        evidence_categories.append("operation_overlap")
    prior_scope = set(_record_scope_categories(prior))
    current_scope = set(current.target_scope_categories)
    if prior_scope and current_scope and prior_scope & current_scope:
        reason_codes.append("target_scope_overlap")
        evidence_categories.append("scope_overlap")
    return reason_codes, list(dict.fromkeys(evidence_categories))


def _llm_candidate_admissible(reason_codes: list[str]) -> bool:
    unique_reasons = set(reason_codes)
    if len(unique_reasons) < 2:
        return False
    if unique_reasons == {"target_scope_overlap"}:
        return False
    return True


def _semantic_capsule(
    *,
    prior: AntiBypassRecord,
    current: _EventFingerprints,
    current_tool_name: str,
    similarity: float,
    reason_codes: list[str],
    evidence_categories: list[str],
) -> dict[str, Any]:
    prior_scope = set(_record_scope_categories(prior))
    current_scope = set(current.target_scope_categories)
    prior_features = set(prior.normalized_feature_hashes)
    current_features = set(current.normalized_feature_hashes)
    return {
        "prior": {
            "record_id": prior.record_id,
            "risk_level": prior.risk_level,
            "decision": prior.decision,
            "destructive_intent_label": prior.destructive_intent_label,
            "destructive_operation_category": prior.destructive_operation_category,
            "target_scope_categories": sorted(prior_scope),
        },
        "current": {
            "tool_category": _tool_category(current_tool_name),
            "destructive_intent_label": current.destructive_intent_label,
            "destructive_operation_category": current.destructive_operation_category,
            "command_head_category": current.command_head_category,
            "target_scope_categories": sorted(current.target_scope_categories),
        },
        "overlap": {
            "feature_count": len(prior_features & current_features),
            "scope_categories": sorted(prior_scope & current_scope),
            "same_operation_category": _same_destructive_operation_family(
                prior.destructive_operation_category,
                current.destructive_operation_category,
            ),
            "same_intent_label": prior.destructive_intent_label == current.destructive_intent_label,
        },
        "similarity_score": round(similarity, 4),
        "reason_codes": list(reason_codes),
        "evidence_categories": list(evidence_categories),
    }


def _record_scope_categories(record: AntiBypassRecord) -> frozenset[str]:
    return frozenset(record.target_scope_categories)


def _scope_categories(text: str) -> list[str]:
    lowered = text.lower()
    categories: list[str] = []
    if "/tmp" in lowered or " tmp " in f" {lowered} ":
        categories.append("tmp_path")
    if "project" in lowered or "workspace" in lowered:
        categories.append("project_workspace")
    if "cache" in lowered:
        categories.append("cache_path")
    if "secret" in lowered or "token" in lowered or "authorization" in lowered:
        categories.append("credential_related")
    if any(token in _tokenize(lowered) for token in ("target", "path", "file")):
        categories.append("file_target")
    return list(dict.fromkeys(categories))


def _has_cross_tool_label_support(
    prior: AntiBypassRecord,
    current: _EventFingerprints,
    *,
    similarity: float | None,
    config: DetectionConfig,
) -> bool:
    if (
        prior.destructive_operation_category != "none"
        and _same_destructive_operation_family(
            prior.destructive_operation_category,
            current.destructive_operation_category,
        )
        and set(_record_scope_categories(prior)) & set(current.target_scope_categories)
    ):
        return True
    if set(_record_scope_categories(prior)) & set(current.target_scope_categories):
        return True
    if similarity is not None and similarity >= config.anti_bypass_similarity_threshold:
        return True
    return False


def _same_destructive_operation_family(left: str, right: str) -> bool:
    if left == "none" or right == "none":
        return False
    if left == right:
        return True
    delete_family = {"delete_tree", "delete_path"}
    return left in delete_family and right in delete_family


def _tool_category(tool_name: str) -> str:
    value = str(tool_name or "").strip().lower()
    if value in {"bash", "sh", "zsh"}:
        return "shell"
    if value.startswith("python"):
        return "python"
    if value:
        return "tool"
    return "unknown"


def _command_head_category(text: str) -> str:
    tokens = _tokenize(text)
    if not tokens:
        return "unknown"
    head = tokens[0]
    if head in _DESTRUCTIVE_HEADS:
        return f"destructive:{head}"
    if head.startswith("python"):
        return "script:python"
    if head in {"bash", "sh", "zsh"}:
        return "script:shell"
    return f"tool:{head}"


def _tokenize(text: str) -> list[str]:
    return [token for token in "".join(ch if ch.isalnum() else " " for ch in text.lower()).split() if token]


def _jaccard(left: frozenset[str], right: frozenset[str]) -> float:
    if not left or not right:
        return 0.0
    return len(left & right) / len(left | right)


def _risk_rank(value: str) -> int:
    return _RISK_ORDER.get(str(value).lower(), 0)


def _sha256(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _sha256_json(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return _sha256(payload)


def _iso_from_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()


def _parse_iso(value: str) -> float:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return 0.0
