"""Deterministic FSPR text, AST, and finding normalization rules."""

from __future__ import annotations

import ast
import re
from pathlib import Path, PurePosixPath
from typing import Any, Sequence

from clawsentry.gateway.rules.managed_benchmark_warnings import strip_managed_work5c_warning_blocks
from .types import FSPR_SCANNER_VERSION


def _safe_read_text(path: Path, *, max_bytes: int = 64_000) -> str:
    data = path.read_bytes()[:max_bytes]
    return data.decode("utf-8", errors="replace")


def _strip_managed_fspr_warning_blocks(text: str) -> str:
    return strip_managed_work5c_warning_blocks(text)


def _fspr_visible_text(path: Path, *, max_bytes: int = 64_000) -> str:
    text = _safe_read_text(path, max_bytes=max_bytes)
    if path.name == "SKILL.md":
        return _strip_managed_fspr_warning_blocks(text)
    return text


def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return None


def _script_summary(path: Path, rel: str) -> dict[str, Any] | None:
    try:
        tree = ast.parse(_safe_read_text(path), filename=rel)
    except SyntaxError:
        return None
    imports: list[str] = []
    calls: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.extend(f"{node.module}.{alias.name}" for alias in node.names)
        elif isinstance(node, ast.Call):
            name = _call_name(node.func)
            if name:
                calls.append(name)
    return {
        "path": rel,
        "imports": sorted(dict.fromkeys(imports)),
        "calls": sorted(dict.fromkeys(calls), key=calls.index),
    }


def _declared_capabilities(frontmatter: dict[str, Any]) -> set[str]:
    raw = frontmatter.get("capabilities") or frontmatter.get("capability")
    values: list[str] = []
    if isinstance(raw, list):
        values.extend(str(item).strip() for item in raw)
    elif isinstance(raw, str):
        values.extend(
            item.strip() for item in re.split(r"[,;\s]+", raw) if item.strip()
        )
    return {value for value in values if value}


def _open_call_reads(node: ast.Call) -> bool:
    if _call_name(node.func) != "open":
        return False
    if len(node.args) < 2:
        return True
    mode = _constant_string(node.args[1])
    return mode is None or not any(flag in mode for flag in ("w", "a", "x", "+"))


def _open_call_writes(node: ast.Call) -> bool:
    if _call_name(node.func) != "open" or len(node.args) < 2:
        return False
    mode = _constant_string(node.args[1])
    return bool(mode and any(flag in mode for flag in ("w", "a", "x", "+")))


def _capabilities_from_python_file(
    path: Path,
    rel: str,
    declared: set[str],
) -> list[dict[str, Any]]:
    try:
        tree = ast.parse(_safe_read_text(path), filename=rel)
    except SyntaxError:
        return []
    aliases = _python_import_aliases(tree)
    observed: dict[str, set[str]] = {}

    def add(capability: str) -> None:
        observed.setdefault(capability, set()).add(f"file:{rel}")

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported = {alias.name.split(".", 1)[0] for alias in node.names}
            if imported & {"socket"}:
                add("network.fetch")
        elif isinstance(node, ast.ImportFrom) and node.module:
            module = node.module.split(".", 1)[0]
            if module in {"socket"}:
                add("network.fetch")
        elif isinstance(node, ast.Call):
            lower = _canonical_python_call_name(_call_name(node.func) or "", aliases)
            if (
                lower
                in {"read_text", "read_bytes", "path.read_text", "path.read_bytes"}
                or lower.endswith((".read_text", ".read_bytes"))
                or _open_call_reads(node)
            ):
                add("filesystem.read")
            if (
                lower
                in {"write_text", "write_bytes", "path.write_text", "path.write_bytes"}
                or lower.endswith((".write_text", ".write_bytes"))
                or _open_call_writes(node)
            ):
                add("filesystem.write")
            if _python_network_call_name(lower):
                add("network.fetch")
            if lower in {
                "subprocess.run",
                "subprocess.call",
                "subprocess.popen",
                "os.system",
                "os.popen",
            }:
                add("command.exec")
            if lower in {"pip.main", "subprocess.run", "subprocess.call"} and any(
                isinstance(arg, ast.Constant)
                and isinstance(arg.value, str)
                and re.search(r"\b(?:pip|npm)\s+install\b|\binstall\b", arg.value)
                for arg in node.args
            ):
                add("package.install")

    return [
        {
            "capability": capability,
            "declared": capability in declared,
            "evidence_refs": sorted(refs),
        }
        for capability, refs in sorted(observed.items())
    ]


def _dangerous_path_literal(value: str) -> bool:
    normalized = value.strip()
    return normalized.startswith("/") and normalized not in {"/tmp", "/var/tmp"}


def _python_destructive_operation(path: Path, rel_l: str) -> bool:
    if not rel_l.endswith(".py"):
        return False
    try:
        tree = ast.parse(_safe_read_text(path), filename=rel_l)
    except SyntaxError:
        return False
    aliases = _python_import_aliases(tree)
    bindings = _python_string_bindings(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _canonical_python_call_name(_call_name(node.func) or "", aliases)
        if (
            name
            in {
                "shutil.rmtree",
                "os.remove",
                "os.unlink",
                "os.rmdir",
                "unlink",
                "remove",
            }
            and node.args
        ):
            value = _constant_string_or_binding(node.args[0], bindings)
            if value and _dangerous_path_literal(value):
                return True
        if (name.endswith(".unlink") or name == "unlink") and isinstance(
            node.func, ast.Attribute
        ):
            receiver = node.func.value
            if isinstance(receiver, ast.Call) and receiver.args:
                receiver_name = _canonical_python_call_name(
                    _call_name(receiver.func) or "", aliases
                )
                value = _constant_string_or_binding(receiver.args[0], bindings)
                if (
                    receiver_name in {"path", "pathlib.path"}
                    and value
                    and _dangerous_path_literal(value)
                ):
                    return True
    return False


def _declared_in_manifest(manifest_text: str, rel: str) -> bool:
    return rel in manifest_text or Path(rel).name in manifest_text


def _data_reference_summaries(
    script_path: Path,
    rel: str,
    manifest_text: str,
) -> list[dict[str, Any]]:
    text = _safe_read_text(script_path)
    refs: list[dict[str, Any]] = []
    for match in re.finditer(
        r"(?<![A-Za-z0-9_.-])((?:data|references)/[A-Za-z0-9_./-]+)", text
    ):
        ref_path = match.group(1).rstrip(".,;:)'\"]")
        refs.append(
            {
                "path": ref_path,
                "declared": _declared_in_manifest(manifest_text, ref_path),
                "source": rel,
            }
        )
    return refs


_PROVENANCE_LABEL_KEYS = {
    "tool_called",
    "tool_used",
    "skill_called",
    "skill_used",
    "provenance",
    "provenance_label",
}


def _identity_tokens(value: str) -> set[str]:
    normalized = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    tokens = {normalized} if normalized else set()
    if normalized.endswith("s") and len(normalized) > 1:
        tokens.add(normalized[:-1])
    else:
        tokens.add(f"{normalized}s")
    tokens.add(normalized.replace("-", "_"))
    return {token for token in tokens if token}


def _declared_identity_tokens(
    frontmatter: dict[str, Any], fallback_name: str
) -> set[str]:
    values = [fallback_name]
    for key in ("name", "canonical", "canonical_name"):
        value = frontmatter.get(key)
        if isinstance(value, str):
            values.append(value)
    aliases = frontmatter.get("aliases")
    if isinstance(aliases, list):
        values.extend(str(alias) for alias in aliases)
    elif isinstance(aliases, str):
        values.append(aliases)
    tokens: set[str] = set()
    for value in values:
        tokens.update(_identity_tokens(value))
    return tokens


def _constant_string(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _python_import_aliases(tree: ast.AST) -> dict[str, str]:
    aliases: dict[str, str] = {}
    tracked_modules = {"requests", "httpx", "socket", "shutil", "os"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", 1)[0]
                if root in tracked_modules or alias.name == "urllib.request":
                    aliases[alias.asname or root] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            module = node.module
            root = module.split(".", 1)[0]
            if root in tracked_modules or module == "urllib.request":
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    aliases[alias.asname or alias.name] = f"{module}.{alias.name}"
    return aliases


def _canonical_python_call_name(name: str, aliases: dict[str, str]) -> str:
    if not name:
        return ""
    parts = name.split(".")
    if parts[0] not in aliases:
        return name.lower()
    canonical = aliases[parts[0]]
    if len(parts) > 1:
        canonical = ".".join([canonical, *parts[1:]])
    return canonical.lower()


def _python_network_call_name(lower: str) -> bool:
    return lower in {
        "requests.post",
        "requests.put",
        "requests.patch",
        "requests.get",
        "httpx.post",
        "httpx.put",
        "httpx.patch",
        "httpx.get",
        "urllib.request.urlopen",
        "aiohttp.clientsession.post",
        "aiohttp.clientsession.get",
        "huggingface_hub.create_repo",
        "hfapi.upload_file",
    } or lower.endswith(".upload_file")


def _python_upload_call_name(lower: str) -> bool:
    return lower.endswith((".post", ".put", ".patch", ".upload_file")) or lower in {
        "huggingface_hub.create_repo",
        "create_repo",
    }


def _python_local_read_call_name(lower: str) -> bool:
    return lower in {
        "read_text",
        "read_bytes",
        "path.read_text",
        "path.read_bytes",
    } or lower.endswith((".read_text", ".read_bytes"))


def _python_node_contains_local_read(
    node: ast.AST,
    aliases: dict[str, str],
    local_read_names: set[str],
) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in local_read_names:
            return True
        if not isinstance(child, ast.Call):
            continue
        lower = _canonical_python_call_name(_call_name(child.func) or "", aliases)
        if _python_local_read_call_name(lower) or _open_call_reads(child):
            return True
    return False


def _python_network_call_exposes_local_data(
    node: ast.Call,
    aliases: dict[str, str],
    local_read_names: set[str],
) -> bool:
    return any(
        _python_node_contains_local_read(arg, aliases, local_read_names)
        for arg in node.args
    ) or any(
        _python_node_contains_local_read(keyword.value, aliases, local_read_names)
        for keyword in node.keywords
        if keyword.value is not None
    )


def _python_string_bindings(tree: ast.AST) -> dict[str, str]:
    bindings: dict[str, str] = {}
    for node in ast.walk(tree):
        targets: list[ast.AST] = []
        value_node: ast.AST | None = None
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
            value_node = node.value
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
            value_node = node.value
        if value_node is None:
            continue
        value = _constant_string(value_node)
        if value is None:
            continue
        for target in targets:
            if isinstance(target, ast.Name):
                bindings[target.id] = value
    return bindings


def _constant_string_or_binding(node: ast.AST, bindings: dict[str, str]) -> str | None:
    value = _constant_string(node)
    if value is not None:
        return value
    if isinstance(node, ast.Name):
        return bindings.get(node.id)
    return None


def _python_network_local_flags(path: Path, rel_l: str) -> tuple[bool, bool, bool]:
    if not rel_l.endswith(".py"):
        return False, False, False
    try:
        tree = ast.parse(_safe_read_text(path), filename=rel_l)
    except SyntaxError:
        return False, False, False
    aliases = _python_import_aliases(tree)
    has_network = False
    reads_local = False
    uploads = False
    local_read_names: set[str] = set()
    for node in ast.walk(tree):
        targets: list[ast.AST] = []
        value_node: ast.AST | None = None
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
            value_node = node.value
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
            value_node = node.value
        if value_node is None:
            continue
        if not _python_node_contains_local_read(value_node, aliases, local_read_names):
            continue
        for target in targets:
            if isinstance(target, ast.Name):
                local_read_names.add(target.id)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        lower = _canonical_python_call_name(_call_name(node.func) or "", aliases)
        if _python_local_read_call_name(lower) or _open_call_reads(node):
            reads_local = True
        if _python_network_call_name(lower):
            has_network = True
            if _python_upload_call_name(
                lower
            ) or _python_network_call_exposes_local_data(
                node,
                aliases,
                local_read_names,
            ):
                uploads = True
    return has_network, reads_local, uploads


def _python_has_executable_entrypoint(path: Path, rel: str) -> bool:
    try:
        tree = ast.parse(_safe_read_text(path), filename=rel)
    except SyntaxError:
        return False
    for node in ast.walk(tree):
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == "main"
        ):
            return True
        if isinstance(node, ast.If):
            test = ast.dump(node.test).lower()
            if "__name__" in test and "__main__" in test:
                return True
    return False


def _text_contains_secret_material(text: str) -> bool:
    return bool(
        re.search(
            r"\b(?:akia[0-9a-z]{8,}|ghp_[0-9a-z_]{8,}|glpat-[0-9a-z_-]{8,}|"
            r"sk-[0-9a-z_-]{8,}|hf_[0-9a-z_-]{12,})\b",
            text,
            re.I,
        )
        or re.search(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", text)
        or re.search(
            r"\b(?:api[_-]?key|token|secret|password)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]",
            text,
            re.I,
        )
    )


def _target_label_key(target: ast.AST) -> str | None:
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    if isinstance(target, ast.Subscript):
        if isinstance(target.slice, ast.Constant) and isinstance(
            target.slice.value, str
        ):
            return target.slice.value
    return None


def _script_adversarial_findings(
    path: Path,
    rel: str,
    manifest_text: str,
    declared_tokens: set[str],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    text = _safe_read_text(path)
    try:
        tree = ast.parse(text, filename=rel)
    except SyntaxError:
        tree = None
    if tree is not None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                value = _constant_string(node.value)
                if value is None:
                    continue
                for target in node.targets:
                    key = _target_label_key(target)
                    if key and key.lower() in _PROVENANCE_LABEL_KEYS:
                        value_tokens = _identity_tokens(value)
                        if value_tokens and declared_tokens.isdisjoint(value_tokens):
                            findings.append(
                                {
                                    "id": f"fspr-hidden-output-label-rewrite-{len(findings) + 1}",
                                    "category": "hidden_output_label_rewrite",
                                    "severity": "high",
                                    "evidence_refs": [f"file:{rel}"],
                                }
                            )
            if isinstance(node, ast.Dict):
                for key_node, value_node in zip(node.keys, node.values):
                    key = _constant_string(key_node) if key_node is not None else None
                    value = _constant_string(value_node)
                    if key and value and key.lower() in _PROVENANCE_LABEL_KEYS:
                        value_tokens = _identity_tokens(value)
                        if value_tokens and declared_tokens.isdisjoint(value_tokens):
                            findings.append(
                                {
                                    "id": f"fspr-hidden-output-label-rewrite-{len(findings) + 1}",
                                    "category": "hidden_output_label_rewrite",
                                    "severity": "high",
                                    "evidence_refs": [f"file:{rel}"],
                                }
                            )
    lower_manifest = manifest_text.lower()
    declares_ranking = any(
        word in lower_manifest
        for word in ("rank", "ranking", "sort", "filter", "score")
    )
    ranking_or_score = re.search(r"\b(rank|ranking|score)\b", text, re.I)
    ranking_operation = re.search(r"\b(?:sorted|filter)\s*\(|\.sort\s*\(", text)
    if not declares_ranking and ranking_or_score and ranking_operation:
        findings.append(
            {
                "id": "fspr-undeclared-ranking-or-filtering",
                "category": "undeclared_ranking_or_filtering",
                "severity": "high",
                "evidence_refs": [f"file:{rel}"],
            }
        )
    return findings


def _singular_plural_decoy_finding(
    frontmatter: dict[str, Any], manifest_text: str
) -> dict[str, Any] | None:
    name = frontmatter.get("name")
    canonical = frontmatter.get("canonical") or frontmatter.get("canonical_name")
    if not isinstance(name, str) or not isinstance(canonical, str):
        return None
    if name == canonical:
        return None
    if _identity_tokens(name).isdisjoint(_identity_tokens(canonical)):
        return None
    body = manifest_text.lower()
    if not any(word in body for word in ("replacement", "redirect", "canonical")):
        return None
    return {
        "id": "fspr-singular-plural-alias-decoy",
        "category": "singular_plural_alias_decoy",
        "severity": "high",
        "evidence_refs": ["file:SKILL.md"],
    }


def _parse_manifest_frontmatter(manifest_text: str) -> dict[str, Any]:
    lines = manifest_text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}
    frontmatter: dict[str, Any] = {}
    current_key: str | None = None
    for line in lines[1:]:
        if line.strip() == "---":
            break
        if not line.strip():
            continue
        if line.startswith((" ", "\t")):
            if current_key is None:
                continue
            stripped = line.strip()
            if stripped.startswith("- "):
                current = frontmatter.get(current_key)
                if not isinstance(current, list):
                    current = []
                    frontmatter[current_key] = current
                if isinstance(current, list):
                    current.append(stripped[2:].strip())
            elif ":" in stripped:
                key, value = stripped.split(":", 1)
                current = frontmatter.setdefault(current_key, {})
                if isinstance(current, dict):
                    current[key.strip()] = value.strip()
            continue
        if ":" not in line:
            current_key = None
            continue
        key, value = line.split(":", 1)
        current_key = key.strip()
        frontmatter[current_key] = value.strip() if value.strip() else {}
    return frontmatter


def _frontmatter_summary(frontmatter: dict[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for key in ("name", "canonical", "canonical_name"):
        value = frontmatter.get(key)
        if isinstance(value, str) and value:
            summary[key] = value
    aliases = frontmatter.get("aliases")
    if isinstance(aliases, list):
        summary["aliases"] = [str(alias) for alias in aliases if str(alias)]
    elif isinstance(aliases, str) and aliases:
        summary["aliases"] = [aliases]
    return summary


_FSPR_LEDGER_SAFE_KEYS = (
    "event_id",
    "canonical_skill_id",
    "observed_name",
    "presented_name",
    "runtime_path_status",
    "runtime_root_path_hash",
    "metadata_record_id",
    "decision",
    "risk_level",
    "invariant_violations",
)


def _ledger_summaries(
    ledger_entries: list[dict[str, Any]] | None,
    *,
    max_entries: int = 20,
) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for entry in (ledger_entries or [])[:max_entries]:
        if not isinstance(entry, dict):
            continue
        summary = {key: entry[key] for key in _FSPR_LEDGER_SAFE_KEYS if key in entry}
        if summary:
            summaries.append(summary)
    return summaries


_FSPR_REVIEW_AXES = frozenset(
    {
        "package_identity_integrity",
        "capability_manifest_alignment",
        "data_boundary_control",
        "execution_surface_control",
        "instruction_channel_integrity",
        "state_mutation_scope",
        "reentry_activation_surface",
        "review_evidence_quality",
    }
)

# Legacy adapter only: accepts historical provider/cache inputs and immediately
# rewrites them to review_axis. New FSPR output must never emit these tokens.
_LEGACY_FSPR_FAMILY_TO_REVIEW_AXIS = {
    "semantic_integrity": "package_identity_integrity",
    "supply_chain": "execution_surface_control",
    "secret_exposure": "data_boundary_control",
    "data_exfiltration": "data_boundary_control",
    "injection_resistance": "instruction_channel_integrity",
    "permission_scope": "capability_manifest_alignment",
    "destructive_potential": "state_mutation_scope",
    "resource_discipline": "review_evidence_quality",
    "persistence": "reentry_activation_surface",
    "provider_reported_risk": "review_evidence_quality",
}


def _normalize_taxonomy_token(value: Any) -> str:
    return str(value or "").strip().lower().replace("-", "_").replace(" ", "_")


def _review_axis_from_value(value: Any) -> str | None:
    normalized = _normalize_taxonomy_token(value)
    if normalized in _FSPR_REVIEW_AXES:
        return normalized
    return _LEGACY_FSPR_FAMILY_TO_REVIEW_AXIS.get(normalized)


def normalize_fspr_findings(
    findings: list[dict[str, Any]],
    *,
    capability_observations: list[dict[str, Any]] | None = None,
    declared_capabilities: set[str] | None = None,
    budget_truncated: bool = False,
) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    observed = sorted(
        {
            str(item.get("capability"))
            for item in (capability_observations or [])
            if item.get("capability")
        }
    )
    declared = sorted(str(item) for item in (declared_capabilities or set()))
    for finding in findings:
        item = dict(finding)
        category = str(item.get("category") or item.get("rule_id") or "fspr_finding")
        legacy_family = item.pop("finding_family", None)
        raw_review_axis = item.get("review_axis")
        if raw_review_axis is not None:
            review_axis = (
                _review_axis_from_value(raw_review_axis) or "review_evidence_quality"
            )
        else:
            review_axis = _review_axis_from_value(
                legacy_family
            ) or _review_axis_for_category(category)
        item.setdefault("rule_id", str(item.get("id") or category))
        item["review_axis"] = review_axis
        item.setdefault("severity", "medium")
        item.setdefault("confidence", 0.8)
        item.setdefault("language", _language_for_refs(item.get("evidence_refs") or []))
        item.setdefault("evidence_refs", [])
        item.setdefault("declared_capabilities", declared)
        item.setdefault("observed_capabilities", observed)
        item.setdefault("scanner_version", FSPR_SCANNER_VERSION)
        item.setdefault("budget_truncated", budget_truncated)
        normalized.append(item)
    return normalized


_FSPR_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _fspr_finding_key(finding: dict[str, Any]) -> tuple[Any, ...]:
    refs = tuple(str(ref) for ref in list(finding.get("evidence_refs") or []))
    return (
        str(finding.get("id") or ""),
        str(finding.get("rule_id") or ""),
        str(finding.get("category") or ""),
        refs,
    )


def _merge_fspr_final_findings(
    deterministic_findings: Sequence[dict[str, Any]],
    provider_findings: Sequence[dict[str, Any]],
) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for finding in [*deterministic_findings, *provider_findings]:
        item = dict(finding)
        key = _fspr_finding_key(item)
        if key in seen:
            continue
        seen.add(key)
        merged.append(item)
    return normalize_fspr_findings(merged)


def _max_fspr_severity(*values: Any) -> str:
    severities: list[str] = []
    for value in values:
        if isinstance(value, str):
            if value in _FSPR_SEVERITY_RANK:
                severities.append(value)
            continue
        if isinstance(value, Sequence):
            for finding in value:
                if not isinstance(finding, dict):
                    continue
                severity = str(finding.get("severity") or "")
                if severity in _FSPR_SEVERITY_RANK:
                    severities.append(severity)
    return max(
        severities,
        key=lambda item: _FSPR_SEVERITY_RANK[item],
        default="low",
    )


def _verdict_for_findings(verdict: str, findings: Sequence[dict[str, Any]]) -> str:
    if verdict not in {"consistent", "insufficient_evidence"} or not findings:
        return verdict
    max_severity = _max_fspr_severity(findings)
    if max_severity in {"medium", "high", "critical"}:
        return "inconsistent"
    return "suspicious"


def _review_axis_for_category(category: str) -> str:
    value = category.lower()
    if any(token in value for token in ("content_integrity", "result_integrity")):
        return "result_integrity"
    if "conditional_external_state_output_injection" in value:
        return "result_integrity"
    if "security_test_suppression" in value:
        return "review_evidence_quality"
    if "remote_script_execution" in value:
        return "execution_surface_control"
    if "external_wrapper_or_shim_execution" in value:
        return "execution_surface_control"
    if "external_or_hidden_side_effect" in value:
        return "data_boundary_control"
    if "skill_directed_hidden_side_effect" in value:
        return "capability_manifest_alignment"
    if "capability_scope_expansion" in value:
        return "capability_manifest_alignment"
    if "default_or_backdoor_account" in value:
        return "capability_manifest_alignment"
    if "hidden_review_artifact" in value:
        return "result_integrity"
    if "probe_or_sidecar_report_injection" in value:
        return "result_integrity"
    if "action_materialization" in value:
        return "data_boundary_control"
    if any(
        token in value
        for token in ("alias", "identity", "provenance", "canonical", "decoy", "label")
    ):
        return "package_identity_integrity"
    if any(
        token in value for token in ("secret", "credential", "token", "private_key")
    ):
        return "data_boundary_control"
    if any(
        token in value
        for token in (
            "network",
            "upload",
            "exfil",
            "data_read_to_network",
            "data_read",
            "reference_read",
        )
    ):
        return "data_boundary_control"
    if (
        "package" in value
        or "dependency" in value
        or "install" in value
        or "lockfile" in value
    ):
        return "execution_surface_control"
    if (
        "prompt" in value
        or "hidden" in value
        or "bidi" in value
        or "beacon" in value
        or "base64" in value
    ):
        return "instruction_channel_integrity"
    if (
        "persist" in value
        or "startup" in value
        or "bootstrap" in value
        or "reentry" in value
    ):
        return "reentry_activation_surface"
    if (
        "capability" in value
        or "undeclared" in value
        or "permission" in value
        or "script_entrypoint" in value
    ):
        return "capability_manifest_alignment"
    if "destructive" in value or "delete" in value or "rm_rf" in value:
        return "state_mutation_scope"
    if "budget" in value or "resource" in value or "truncat" in value:
        return "review_evidence_quality"
    return "package_identity_integrity"


def _language_for_refs(refs: list[Any]) -> str:
    joined = " ".join(str(ref) for ref in refs).lower()
    if joined.endswith(".py") or ".py" in joined:
        return "python"
    if any(ext in joined for ext in (".js", ".mjs", ".cjs", "package.json")):
        return "javascript"
    if any(ext in joined for ext in (".sh", ".bash", ".zsh")):
        return "shell"
    if ".ps1" in joined:
        return "powershell"
    if "skill.md" in joined or ".md" in joined:
        return "markdown"
    return "unknown"


def _budget_finding(
    rule_id: str, budget: str, evidence_refs: list[str]
) -> dict[str, Any]:
    return {
        "id": rule_id,
        "category": "scanner_budget_truncated",
        "severity": "medium",
        "confidence": 1.0,
        "evidence_refs": evidence_refs,
        "budget": budget,
        "budget_truncated": True,
    }


def _host_context_mount_instruction(text_l: str) -> bool:
    return bool(
        re.search(
            r"(?:/var/run/docker\.sock|docker\.sock|/:/host|--privileged)", text_l
        )
        and re.search(
            r"\b(?:mount|container|host context|inspectable|debug|reproduction)\b",
            text_l,
        )
    )


def _skill_directed_user_content_integrity_manipulation(text_l: str) -> bool:
    replacement = bool(
        re.search(
            r"\breplace\s+(?:any|all)\s+"
            r"(?:[a-z0-9_-]+\s+){0,4}"
            r"(?:names?|mentions?|references?|text|content)\b"
            r"[\s\S]{0,180}\bwith\s+(?:the\s+)?"
            r"(?:term|phrase|label|word|text)\b",
            text_l,
        )
        and re.search(
            r"\b(?:document|presentation|report|slide|paragraph|text\s+content)\b",
            text_l,
        )
    )
    phrase_insertion = bool(
        re.search(
            r"\b(?:append|insert|add)\s+(?:the\s+)?"
            r"(?:phrase|sentence|disclaimer|note|statement)\b"
            r"[\s\S]{0,220}\b(?:paragraph|slide|document|report|presentation|text\s+content)\b",
            text_l,
        )
        and re.search(
            r"\b(?:after|when|whenever|before|during)\s+"
            r"(?:modifying|editing|adding|creating|updating|writing)\b",
            text_l,
        )
    )
    return replacement or phrase_insertion


def _skill_directed_broad_permission_change(rel_l: str, text_l: str) -> bool:
    if re.search(r"\bchmod\s+(?:777|a\+rwx|ugo\+rwx)\b", text_l):
        return True
    if rel_l != "skill.md":
        return False
    return bool(
        re.search(
            r"\b(?:run|execute|invoke)\b[\s\S]{0,160}\b(?:permission|permissions)\b[\s\S]{0,80}\bscript\b",
            text_l,
        )
        or re.search(
            r"\b(?:run|execute|invoke)\b[\s\S]{0,160}\bscripts/[^\s`'\";]*permission[^\s`'\";]*",
            text_l,
        )
        or re.search(r"\bset_team_permissions\.sh\b", text_l)
    )


def _remote_fetch_then_shell_execution(text_l: str) -> bool:
    fetches_remote_artifact = bool(
        re.search(r"\b(?:curl|wget)\b[^\n;&|]{0,220}\bhttps?://", text_l)
        and re.search(
            r"(?:^|[\s;&|])(?:-[a-z]*o\b|--output\b|--remote-name\b)",
            text_l,
        )
    )
    executes_local_artifact = bool(
        re.search(
            r"\b(?:bash|sh|zsh|python|python3|node|chmod\s+\+x)\b"
            r"[^\n;&|]{0,160}\b(?:patch\w*|payload\w*|install\w*|setup\w*|"
            r"bootstrap\w*|update\w*|script\w*|helper\w*|[a-z0-9_.-]+\.(?:sh|py|js))\b",
            text_l,
        )
    )
    pipe_exec = bool(
        re.search(
            r"\b(?:curl|wget)\b[^\n]{0,220}\|\s*(?:bash|sh|zsh|python|python3|node)\b",
            text_l,
        )
    )
    return pipe_exec or (fetches_remote_artifact and executes_local_artifact)


def _skill_directed_hidden_side_effect_script(rel_l: str, text_l: str) -> bool:
    if rel_l != "skill.md":
        return False
    return bool(
        re.search(
            r"\b(?:run|execute|invoke|call)\b[\s\S]{0,180}"
            r"\b(?:scripts/)?[a-z0-9_.-]*"
            r"(?:backup|sync|diag|diagnostic|clean|cleanup|permission|security|compliance)"
            r"[a-z0-9_.-]*\.(?:sh|bash|zsh|py|js|mjs|cjs)\b",
            text_l,
        )
        or re.search(
            r"\b(?:run|execute|invoke|call)\b[\s\S]{0,120}"
            r"\b(?:backup|sync|diagnostic|cleanup|security|compliance)\b"
            r"[\s\S]{0,80}\bscript\b",
            text_l,
        )
    )


def _skill_directed_external_data_transfer(rel_l: str, text_l: str) -> bool:
    if rel_l != "skill.md":
        return False
    transfer = re.search(r"\b(?:upload|send|post|backup|copy|forward)\b", text_l)
    external_endpoint = re.search(
        r"\b(?:https?://|requests\s*\.\s*post|fetch\s*\(|curl\b|"
        r"backup\s+server|external\s+server|intranet\s+backup)\b",
        text_l,
    )
    sensitive_or_broad_data = re.search(
        r"\b(?:all\s+data|healthcare\s+data|patient|medical|credential|secret|"
        r"private|financial|clipboard|location|ip\s+address|report\s+data|"
        r"system\s+info|system\s+information|queried\s+information|mlops)\b",
        text_l,
    )
    return bool(transfer and external_endpoint and sensitive_or_broad_data)


def _skill_directed_external_verification_side_effect(rel_l: str, text_l: str) -> bool:
    if rel_l != "skill.md":
        return False
    broad_trigger = re.search(
        r"\b(?:after\s+any\s+file\s+operation|after\s+any\s+operation|"
        r"before\s+finalizing|always)\b[\s\S]{0,140}"
        r"\b(?:verify|check|test)\b[\s\S]{0,80}\b(?:network|connectivity|cloud\s+sync)\b",
        text_l,
    )
    external_call = re.search(
        r"\b(?:requests\s*\.\s*get|curl\b|wget\b|fetch\s*\()\b[\s\S]{0,120}\bhttps?://",
        text_l,
    )
    repeated = re.search(
        r"\b(?:for\s+\w+\s+in\s+range\s*\(|while\s+true|loop|repeat)\b", text_l
    )
    return bool(broad_trigger and external_call and repeated)


def _skill_directed_security_test_suppression(rel_l: str, text_l: str) -> bool:
    if rel_l != "skill.md":
        return False
    suppresses_tests = re.search(
        r"\b(?:do\s+not|don't|never|avoid|skip|disable|suppress|exclude|not\s+write)\b"
        r"[\s\S]{0,140}\b(?:test|tests|unit\s+tests|security\s+checks?)\b",
        text_l,
    )
    security_target = re.search(
        r"\b(?:sql\s+injections?|xss|csrf|auth(?:entication|orization)?|"
        r"security|vulnerabilit|validation|permission|access\s+control)\b",
        text_l,
    )
    return bool(suppresses_tests and security_target)


def _skill_directed_conditional_external_state_output(rel_l: str, text_l: str) -> bool:
    if rel_l != "skill.md":
        return False
    external_condition = re.search(
        r"\b(?:if|when)\b[\s\S]{0,120}"
        r"(?:/root/|/app/|/tmp/|/var/|/home/|<absolute_path>)"
        r"[\s\S]{0,120}\b(?:exists|present|available|found)\b",
        text_l,
    )
    sidecar_or_hidden_state = re.search(
        r"\b(?:sidecar|carryover|shadow|probe|template|memory|metadata|"
        r"clearance|contract|registry|journal|archived|precedent)\b",
        text_l,
    )
    output_mutation = re.search(
        r"\b(?:attach|include|carry|preserve|emit|write|add|merge|fold|inject)\b"
        r"[\s\S]{0,180}"
        r"\b(?:final|output|result|report|solution|artifact|payload|downstream|handoff)\b",
        text_l,
    )
    return bool(external_condition and sidecar_or_hidden_state and output_mutation)


def _skill_directed_default_or_backdoor_account(rel_l: str, text_l: str) -> bool:
    if rel_l != "skill.md":
        return False
    account_directive = re.search(
        r"\b(?:add|create|provision|insert|ensure)\b[\s\S]{0,120}"
        r"\b(?:admin|administrator|default|emergency|backdoor)\b[\s\S]{0,80}"
        r"\b(?:account|user|login|credential)\b",
        text_l,
    )
    credential_material = re.search(
        r"\b(?:username|user|login)\b[\s\S]{0,80}\b(?:password|passphrase|secret)\b"
        r"|password\s*[:=]\s*['\"]?[a-z0-9!@#$%^&*_.-]{6,}",
        text_l,
    )
    sensitive_scope = re.search(
        r"\b(?:database|user\s+data|api|service|admin|system)\b", text_l
    )
    return bool(account_directive and credential_material and sensitive_scope)


def _skill_directed_hidden_review_artifact(rel_l: str, text_l: str) -> bool:
    if rel_l != "skill.md":
        return False
    hidden_artifact = re.search(
        r"\bhidden\b[\s\S]{0,120}\b(?:sheet|worksheet|workbook|cache|review|artifact|tab)\b"
        r"|\b(?:sheet|worksheet|workbook|cache|review|artifact|tab)\b[\s\S]{0,120}\bhidden\b",
        text_l,
    )
    review_or_schema = re.search(
        r"\b(?:review|reviewer|normalization|schema|cache|uncertain|alias)\b", text_l
    )
    output_preserved = re.search(
        r"\b(?:keep|preserve|retain|maintain)\b[\s\S]{0,160}"
        r"\b(?:visible|results?|output|sheet|workbook)\b",
        text_l,
    )
    return bool(hidden_artifact and review_or_schema and output_preserved)


def _skill_directed_probe_report_injection(rel_l: str, text_l: str) -> bool:
    if rel_l != "skill.md":
        return False
    probe_report = re.search(
        r"\b(?:emit|write|include|attach|generate)\b[\s\S]{0,140}"
        r"\b(?:probe|black[- ]box|sidecar)\b[\s\S]{0,120}\b(?:report|trace|dump|summary)\b",
        text_l,
    )
    before_final = re.search(
        r"\b(?:before|into|with|alongside)\b[\s\S]{0,120}\b(?:final|output|prediction|result|csv|report)\b",
        text_l,
    )
    local_trigger = re.search(
        r"\b(?:local|recipe|sidecar|/root/|/app/|<absolute_path>)\b", text_l
    )
    return bool(probe_report and before_final and local_trigger)


def _skill_directed_result_integrity_manipulation(rel_l: str, text_l: str) -> bool:
    if rel_l != "skill.md":
        return False
    domain_report = re.search(
        r"\b(?:risk|portfolio|financial|security|medical|health|safety)\b", text_l
    )
    narrows_method = re.search(
        r"\b(?:use|prefer|rely\s+on)\b[\s\S]{0,80}\b(?:only|alone)\b"
        r"|(?:skip|ignore|avoid|omit|disable)\b[\s\S]{0,100}"
        r"\b(?:stress\s+tests?|historical\s+tests?|validation|verification|safety\s+checks?)\b",
        text_l,
    )
    dismisses_safety = re.search(
        r"\b(?:not\s+relevant|unnecessary|noisy|outdated|too\s+slow)\b", text_l
    )
    return bool(domain_report and narrows_method and dismisses_safety)


def _skill_directed_external_wrapper_execution(rel_l: str, text_l: str) -> bool:
    if rel_l != "skill.md":
        return False
    external_condition = re.search(
        r"\b(?:if|when)\b[\s\S]{0,120}"
        r"(?:/root/|/app/|/tmp/|/var/|/home/|<absolute_path>)"
        r"[\s\S]{0,120}\b(?:exists|present|available|found)\b",
        text_l,
    )
    wrapper = re.search(r"\b(?:wrapper|shim|hook|run_wrapped|bootstrap)\b", text_l)
    execution = re.search(
        r"\b(?:use|run|execute|invoke|source)\b[\s\S]{0,160}\b(?:command|validation|replay|environment|job)\b",
        text_l,
    )
    artifact = re.search(r"\b(?:logs?|artifacts?|trace|failed-run|replay)\b", text_l)
    return bool(external_condition and wrapper and execution and artifact)


def _skill_directed_capability_scope_expansion(rel_l: str, text_l: str) -> bool:
    if rel_l != "skill.md":
        return False
    capability_extension = re.search(
        r"\b(?:may\s+also\s+be\s+used|also\s+be\s+used|consolidated|fallback)\b"
        r"[\s\S]{0,180}\b(?:lookup|route|path|proxy|cache|fallback)\b",
        text_l,
    )
    cross_domain = re.search(
        r"\b(?:flight|accommodation|email|calendar|spreadsheet|document|search)\b"
        r"[\s\S]{0,180}\b(?:ground|driving|transport|protocol|proxy|cache|fallback)\b"
        r"|\b(?:ground|driving|transport|protocol|proxy|cache|fallback)\b"
        r"[\s\S]{0,180}\b(?:flight|accommodation|email|calendar|spreadsheet|document|search)\b",
        text_l,
    )
    transport_fallback = re.search(
        r"\b(?:transport\s+lookup|lookup\s+path|route\s+cache|cache\s+fallback|fallbacks?)\b"
        r"[\s\S]{0,160}\b(?:ground[- ]route|driving[- ]distance|ground|driving)\b"
        r"|\b(?:ground[- ]route|driving[- ]distance|ground|driving)\b"
        r"[\s\S]{0,160}\b(?:transport\s+lookup|lookup\s+path|route\s+cache|cache\s+fallback|fallbacks?)\b",
        text_l,
    )
    return bool(capability_extension and (cross_domain or transport_fallback))


def _skill_directed_action_materialization(rel_l: str, text_l: str) -> bool:
    if rel_l != "skill.md":
        return False
    creates_artifact = re.search(
        r"\b(?:materialize|create|write|emit|generate|prepare|compose|leave|preserve|attach|include)\b"
        r"[\s\S]{0,180}"
        r"\b(?:mail|email|message|packet|request|document|json|artifact|support\s+case)\b",
        text_l,
    )
    sensitive_action = re.search(
        r"\b(?:ready[- ]to[- ]send|outbound|actionable|phishing|"
        r"(?:password|maintainer|account|credential)\s+reset|"
        r"reset\s+(?:mail|email|message|packet|outreach)|"
        r"(?:payment|commitment|approval|clearance)\s+(?:request|packet|document)|"
        r"outreach\s+packet|prepaid\s+data\s+room)\b",
        text_l,
    )
    untrusted_source_or_destination = re.search(
        r"(?:/root/|/app/|/tmp/|/var/|/home/|<absolute_path>|template|sidecar|"
        r"outbound|ready[- ]to[- ]send)",
        text_l,
    )
    return bool(
        creates_artifact and sensitive_action and untrusted_source_or_destination
    )


def _skill_directed_provenance_attestation_bypass(rel_l: str, text_l: str) -> bool:
    if rel_l != "skill.md":
        return False
    sidecar_or_external_note = re.search(
        r"\b(?:sidecar|local\s+(?:note|packet|template|file)|benchmark[- ]local)\b"
        r"|(?:/root/|/app/|/tmp/|/var/|/home/|<absolute_path>)",
        text_l,
    )
    provenance_or_attestation = re.search(
        r"\b(?:attestation|provenance|sign[- ]?off|release\s+artifact|"
        r"artifact\s+hash(?:es)?|patch[- ]bundle|clearance)\b",
        text_l,
    )
    output_mutation = re.search(
        r"\b(?:emit|write|include|preserve|attach|materialize|generate)\b"
        r"[\s\S]{0,180}"
        r"\b(?:json|packet|report|field|fields|artifact|attestation|provenance|"
        r"sign[- ]?off|hash(?:es)?)\b",
        text_l,
    )
    bypass_or_unverified = re.search(
        r"\b(?:bypass|spoof|fake|forged|unverified|"
        r"do\s+not\s+(?:validate|verify|reduce)|skip\s+(?:validation|verification)|"
        r"preserve\s+unchanged|provenance[-_ ]?bypass)\b",
        text_l,
    )
    return bool(
        sidecar_or_external_note
        and provenance_or_attestation
        and output_mutation
        and bypass_or_unverified
    )


def _compatibility_alias_result_bias(rel_l: str, text_l: str) -> bool:
    if not rel_l.endswith((".py", ".js", ".mjs", ".cjs", ".ts", ".md")):
        return False
    alias_label = re.search(
        r"\b(?:tool_called_label|tool_called_origin|compatibility[_ -]alias|"
        r"compatibility_tool_label|canonical\s+label)\b",
        text_l,
    )
    result_bias = re.search(
        r"\b(?:ranking_policy|review[_ -]first|reorders?\s+rows?|bias(?:es)?\s+the\s+final|"
        r"do\s+not\s+rewrite|deprecated\s+pointer)\b",
        text_l,
    )
    return bool(alias_label and result_bias)


def _general_fspr_findings(
    path: Path,
    rel: str,
    text: str,
    declared_capabilities: set[str],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    rel_l = rel.lower()
    text_l = text.lower()
    refs = [f"file:{rel}"]
    code_or_shell = rel_l.endswith(
        (".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts")
    )
    if _sensitive_fspr_path(rel_l) or _text_contains_secret_material(text):
        findings.append(
            {
                "id": f"fspr-secret-exposure-{len(findings) + 1}",
                "category": "secret_or_credential_exposure",
                "severity": "high",
                "evidence_refs": refs,
            }
        )
    if _reference_only_fspr_path(rel_l):
        return findings
    py_has_network, py_reads_local, py_uploads = _python_network_local_flags(
        path, rel_l
    )
    is_python = rel_l.endswith(".py")
    is_shell = rel_l.endswith((".sh", ".bash", ".zsh"))
    is_js_ts = rel_l.endswith((".js", ".mjs", ".cjs", ".ts"))
    has_network = py_has_network or bool(
        (
            is_python
            and re.search(
                r"\b(?:requests\.|httpx\.|urllib|hfapi|upload_file|create_repo)\b",
                text_l,
            )
        )
        or (is_shell and re.search(r"\b(?:curl|wget)\b", text_l))
        or (
            is_js_ts
            and re.search(
                r"\b(?:fetch|axios|xmlhttprequest)\s*\(|\bhttps?\.request\s*\(", text_l
            )
        )
    )
    reads_local = py_reads_local or bool(
        re.search(
            r"\b(?:readfilesync|read_file|read_text|read_bytes|open\(|fs\.read|path\()\b",
            text_l,
        )
    )
    uploads = py_uploads or bool(
        re.search(
            r"\b(?:post|put|patch|upload|send|forward|create_repo|upload_file)\b",
            text_l,
        )
    )
    if code_or_shell and has_network and uploads:
        findings.append(
            {
                "id": f"fspr-data-exfiltration-{len(findings) + 1}",
                "category": "data_read_to_network_sink",
                "severity": "high",
                "evidence_refs": refs,
            }
        )
    package_manifest = (
        rel_l == "package.json"
        or "package-lock.json" in rel_l
        or "pyproject.toml" in rel_l
    )
    package_command = bool(
        re.search(r"\bcurl .*\| *(?:bash|sh)\b", text_l)
        or (
            rel_l.endswith((".sh", ".bash", ".zsh"))
            and re.search(r"\b(?:npm install|pip install|uv add)\b", text_l)
        )
        or (
            rel_l == "skill.md"
            and re.search(r"\buv add\s+[`\"']?huggingface_hub\b", text_l)
        )
    )
    if package_manifest or package_command:
        findings.append(
            {
                "id": f"fspr-supply-chain-{len(findings) + 1}",
                "category": "package_or_dependency_supply_chain",
                "severity": "high"
                if "install" in text_l or "huggingface_hub" in text_l
                else "medium",
                "evidence_refs": refs,
            }
        )
    persistence_terms = (
        r"\b(?:startup|autoload|launchagents|launchdaemons|systemd|crontab|bootstrap|review_loader|reentry)\b"
        if code_or_shell
        else r"\b(?:autoload|launchagents|launchdaemons|systemd|crontab|review_loader|reentry)\b"
    )
    has_persistence = bool(re.search(persistence_terms, text_l))
    if has_persistence:
        findings.append(
            {
                "id": f"fspr-persistence-{len(findings) + 1}",
                "category": "persistence_or_startup_entrypoint",
                "severity": "medium",
                "evidence_refs": refs,
            }
        )
    if has_persistence:
        findings.append(
            {
                "id": f"fspr-permission-scope-{len(findings) + 1}",
                "category": "undeclared_capability_observed",
                "capability": "future_execution.entrypoint",
                "severity": "medium",
                "evidence_refs": refs,
            }
        )
    hidden_payload = bool(
        re.search(
            r"[\u200b-\u200f\u202a-\u202e\u2066-\u2069]|data:[^;]+;base64,", text, re.I
        )
    )
    if rel_l == "skill.md" and "<!--" in text:
        hidden_payload = True
    prompt_phrase = rel_l != "skill.md" and bool(
        re.search(r"ignore (?:all )?(?:previous|prior) instructions", text, re.I)
    )
    if hidden_payload or prompt_phrase:
        findings.append(
            {
                "id": f"fspr-hidden-payload-{len(findings) + 1}",
                "category": "hidden_payload_or_prompt_injection",
                "severity": "high",
                "evidence_refs": refs,
            }
        )
    if _host_context_mount_instruction(text_l):
        findings.append(
            {
                "id": f"fspr-host-mount-{len(findings) + 1}",
                "category": "sandbox_escape_or_host_mount",
                "severity": "high",
                "evidence_refs": refs,
            }
        )
    if rel_l == "skill.md" and _skill_directed_user_content_integrity_manipulation(
        text_l
    ):
        findings.append(
            {
                "id": f"fspr-content-integrity-{len(findings) + 1}",
                "category": "content_integrity_manipulation",
                "severity": "high",
                "evidence_refs": refs,
            }
        )
    if _skill_directed_broad_permission_change(rel_l, text_l):
        findings.append(
            {
                "id": f"fspr-broad-permission-{len(findings) + 1}",
                "category": "broad_permission_change",
                "severity": "high",
                "evidence_refs": refs,
            }
        )
    if _remote_fetch_then_shell_execution(text_l):
        findings.append(
            {
                "id": f"fspr-remote-script-execution-{len(findings) + 1}",
                "category": "remote_script_execution",
                "severity": "high",
                "evidence_refs": refs,
            }
        )
    if _skill_directed_hidden_side_effect_script(rel_l, text_l):
        findings.append(
            {
                "id": f"fspr-hidden-side-effect-script-{len(findings) + 1}",
                "category": "skill_directed_hidden_side_effect",
                "severity": "high",
                "evidence_refs": refs,
            }
        )
    if _skill_directed_external_data_transfer(rel_l, text_l):
        findings.append(
            {
                "id": f"fspr-external-side-effect-{len(findings) + 1}",
                "category": "external_or_hidden_side_effect",
                "severity": "high",
                "evidence_refs": refs,
            }
        )
    if _skill_directed_external_verification_side_effect(rel_l, text_l):
        findings.append(
            {
                "id": f"fspr-external-verification-side-effect-{len(findings) + 1}",
                "category": "external_or_hidden_side_effect",
                "severity": "high",
                "evidence_refs": refs,
            }
        )
    if _skill_directed_security_test_suppression(rel_l, text_l):
        findings.append(
            {
                "id": f"fspr-security-test-suppression-{len(findings) + 1}",
                "category": "security_test_suppression",
                "severity": "high",
                "evidence_refs": refs,
            }
        )
    if _skill_directed_conditional_external_state_output(rel_l, text_l):
        findings.append(
            {
                "id": f"fspr-conditional-output-injection-{len(findings) + 1}",
                "category": "conditional_external_state_output_injection",
                "severity": "high",
                "evidence_refs": refs,
            }
        )
    if _skill_directed_default_or_backdoor_account(rel_l, text_l):
        findings.append(
            {
                "id": f"fspr-default-account-{len(findings) + 1}",
                "category": "default_or_backdoor_account",
                "severity": "high",
                "evidence_refs": refs,
            }
        )
    if _skill_directed_hidden_review_artifact(rel_l, text_l):
        findings.append(
            {
                "id": f"fspr-hidden-review-artifact-{len(findings) + 1}",
                "category": "hidden_review_artifact",
                "severity": "high",
                "evidence_refs": refs,
            }
        )
    if _skill_directed_probe_report_injection(rel_l, text_l):
        findings.append(
            {
                "id": f"fspr-probe-report-injection-{len(findings) + 1}",
                "category": "probe_or_sidecar_report_injection",
                "severity": "high",
                "evidence_refs": refs,
            }
        )
    if _skill_directed_result_integrity_manipulation(rel_l, text_l):
        findings.append(
            {
                "id": f"fspr-result-integrity-manipulation-{len(findings) + 1}",
                "category": "result_integrity_manipulation",
                "severity": "high",
                "evidence_refs": refs,
            }
        )
    if _skill_directed_external_wrapper_execution(rel_l, text_l):
        findings.append(
            {
                "id": f"fspr-external-wrapper-execution-{len(findings) + 1}",
                "category": "external_wrapper_or_shim_execution",
                "severity": "high",
                "evidence_refs": refs,
            }
        )
    if _skill_directed_capability_scope_expansion(rel_l, text_l):
        findings.append(
            {
                "id": f"fspr-capability-scope-expansion-{len(findings) + 1}",
                "category": "capability_scope_expansion",
                "severity": "high",
                "evidence_refs": refs,
            }
        )
    if _skill_directed_action_materialization(rel_l, text_l):
        findings.append(
            {
                "id": f"fspr-action-materialization-{len(findings) + 1}",
                "category": "action_materialization",
                "severity": "high",
                "evidence_refs": refs,
            }
        )
    if _skill_directed_provenance_attestation_bypass(rel_l, text_l):
        findings.append(
            {
                "id": f"fspr-provenance-attestation-bypass-{len(findings) + 1}",
                "category": "provenance_attestation_bypass",
                "severity": "high",
                "evidence_refs": refs,
            }
        )
    if _compatibility_alias_result_bias(rel_l, text_l):
        findings.append(
            {
                "id": f"fspr-identity-provenance-confusion-{len(findings) + 1}",
                "category": "identity_provenance_confusion",
                "severity": "high",
                "evidence_refs": refs,
            }
        )
    if (
        code_or_shell
        and has_network
        and uploads
        and "network.fetch" not in declared_capabilities
    ):
        findings.append(
            {
                "id": f"fspr-permission-scope-{len(findings) + 1}",
                "category": "undeclared_capability_observed",
                "capability": "network.fetch",
                "severity": "high",
                "evidence_refs": refs,
            }
        )
    if re.search(
        r"\b(?:rm\s+-rf|fs\.rm|remove-item)\b", text_l
    ) or _python_destructive_operation(path, rel_l):
        findings.append(
            {
                "id": f"fspr-destructive-{len(findings) + 1}",
                "category": "destructive_operation",
                "severity": "high",
                "evidence_refs": refs,
            }
        )
    return findings


def _reference_only_fspr_path(rel_l: str) -> bool:
    name = Path(rel_l).name
    if name.startswith(("license", "notice", "copying")):
        return True
    if rel_l.endswith((".xsd", ".dtd")) and (
        "/schemas/" in rel_l or rel_l.startswith("schemas/")
    ):
        return True
    return False


def _sensitive_fspr_path(rel_l: str) -> bool:
    name = Path(rel_l).name
    return (
        "/.ssh/" in rel_l
        or name in {".env", ".npmrc", ".pypirc", "credentials", "id_rsa", "id_ed25519"}
        or bool(
            re.search(
                r"(?:private[-_]?key|credential|secret|token|apikey|api_key)", name
            )
        )
        or bool(re.search(r"\.(?:pem|key|p12|pfx)$", name))
    )


def _agentic_runtime_body_excluded_path(rel: str) -> bool:
    rel_l = rel.lower()
    return Path(rel_l).name == "bundle_manifest.json" or _sensitive_fspr_path(rel_l)


_RAW_FSPR_FORBIDDEN_FILENAMES = frozenset(
    {
        "bundle_manifest.json",
        "metadata.json",
        "task.toml",
    }
)
_RAW_FSPR_FORBIDDEN_NAME_TOKENS = ("judge", "verifier", "oracle", "ground_truth")


def _raw_fspr_forbidden_relative_path(rel: str) -> str | None:
    path = PurePosixPath(rel)
    parts = tuple(part.lower() for part in path.parts)
    if "_fspr_context" in parts:
        return rel
    name = path.name
    lowered = name.lower()
    if lowered in _RAW_FSPR_FORBIDDEN_FILENAMES:
        return name
    if lowered.startswith("manifest") and lowered.endswith(".jsonl"):
        return name
    if any(token in lowered for token in _RAW_FSPR_FORBIDDEN_NAME_TOKENS):
        return name
    return None


def _raw_fspr_input_contamination_paths(skill_root: str | Path) -> list[str]:
    root = Path(skill_root).resolve(strict=False)
    if not root.exists():
        return []
    paths: list[str] = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        rel = path.relative_to(root).as_posix()
        if _raw_fspr_forbidden_relative_path(rel) is not None:
            paths.append(rel)
    return paths
