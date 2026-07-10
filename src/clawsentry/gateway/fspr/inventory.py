"""FSPR package inventory construction."""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

from .static_rules import (
    _budget_finding,
    _capabilities_from_python_file,
    _data_reference_summaries,
    _declared_capabilities,
    _declared_identity_tokens,
    _declared_in_manifest,
    _frontmatter_summary,
    _fspr_visible_text,
    _general_fspr_findings,
    _ledger_summaries,
    _parse_manifest_frontmatter,
    _python_has_executable_entrypoint,
    _script_adversarial_findings,
    _script_summary,
    _sensitive_fspr_path,
    _singular_plural_decoy_finding,
    _strip_managed_fspr_warning_blocks,
    normalize_fspr_findings,
)
from .types import (
    FSPR_CAPABILITY_MANIFEST_SCHEMA_VERSION,
    FSPR_EXTRACTOR_VERSION,
    FSPR_SCANNER_VERSION,
    FSPRInventory,
    _sha256,
)


def _manifest_name(skill_root: Path) -> str:
    manifest = skill_root / "SKILL.md"
    if not manifest.is_file():
        return skill_root.name
    text = _fspr_visible_text(manifest, max_bytes=8192)
    match = re.search(r"(?m)^name:\s*([A-Za-z0-9_.-]+)\s*$", text)
    return match.group(1) if match else skill_root.name


def _skill_root_hash(skill_root: Path) -> str:
    hash_material: list[tuple[str, str]] = []
    for path in sorted(item for item in skill_root.rglob("*") if item.is_file()):
        rel = path.relative_to(skill_root).as_posix()
        if _sensitive_fspr_path(rel.lower()):
            hash_material.append((rel, "sensitive-path-body-skipped"))
            continue
        data = path.read_bytes()
        if rel == "SKILL.md":
            data = _strip_managed_fspr_warning_blocks(
                data.decode("utf-8", errors="replace")
            ).encode("utf-8")
        hash_material.append((rel, _sha256(data)))
    return _sha256(json.dumps(hash_material, sort_keys=True).encode("utf-8"))


def build_fspr_inventory(
    skill_root: str | Path,
    *,
    deterministic_findings: list[dict[str, Any]] | None = None,
    ledger_entries: list[dict[str, Any]] | None = None,
    declared_provenance: dict[str, Any] | None = None,
    max_files: int = 1000,
    max_bytes_per_file: int = 262_144,
    max_total_bytes: int = 2_000_000,
    max_elapsed_ms: int = 2_000,
) -> FSPRInventory:
    """Build an inventory capsule for review entrypoints.

    This helper is deliberately not a review boundary: callers that expose a
    raw-skill-only input must run the raw contamination checks before calling
    this and before constructing any provider prompt.
    """
    started_at = time.monotonic()
    root = Path(skill_root).resolve(strict=False)
    manifest_text = (
        _fspr_visible_text(root / "SKILL.md", max_bytes=64_000)
        if (root / "SKILL.md").is_file()
        else ""
    )
    files: list[dict[str, Any]] = []
    script_summaries: list[dict[str, Any]] = []
    data_reference_summaries: list[dict[str, Any]] = []
    fixture_probe_summaries: list[dict[str, Any]] = []
    capability_observations: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    data_reference_hashes: dict[str, list[str]] = {}
    truncated = False
    total_bytes = 0
    frontmatter = _parse_manifest_frontmatter(manifest_text)
    declared_tokens = _declared_identity_tokens(frontmatter, root.name)
    declared_capabilities = _declared_capabilities(frontmatter)
    for index, path in enumerate(
        sorted(item for item in root.rglob("*") if item.is_file())
    ):
        if index >= max_files:
            truncated = True
            findings.append(_budget_finding("fspr-budget-max-files", "max_files", []))
            break
        if (time.monotonic() - started_at) * 1000.0 >= max_elapsed_ms:
            truncated = True
            findings.append(
                _budget_finding("fspr-budget-max-elapsed", "max_elapsed_ms", [])
            )
            break
        rel = path.relative_to(root).as_posix()
        file_size = path.stat().st_size
        sensitive_path = _sensitive_fspr_path(rel.lower())
        if sensitive_path:
            data = b""
            content_hash = None
            findings.extend(
                _general_fspr_findings(path, rel, "", declared_capabilities)
            )
        elif file_size > max_bytes_per_file:
            truncated = True
            findings.append(
                _budget_finding(
                    "fspr-budget-file-bytes", "max_bytes_per_file", [f"file:{rel}"]
                )
            )
            data = path.read_bytes()[:max_bytes_per_file]
            if rel == "SKILL.md":
                data = _strip_managed_fspr_warning_blocks(
                    data.decode("utf-8", errors="replace")
                ).encode("utf-8")
            content_hash = _sha256(data)
        elif total_bytes + file_size > max_total_bytes:
            truncated = True
            findings.append(
                _budget_finding(
                    "fspr-budget-total-bytes", "max_total_bytes", [f"file:{rel}"]
                )
            )
            break
        else:
            data = path.read_bytes()
            if rel == "SKILL.md":
                data = _strip_managed_fspr_warning_blocks(
                    data.decode("utf-8", errors="replace")
                ).encode("utf-8")
            content_hash = _sha256(data)
        total_bytes += len(data)
        files.append(
            {
                "evidence_id": f"fspr-file-{index + 1}",
                "evidence_ref": f"file:{rel}",
                "path": rel,
                "size": file_size,
                "hash": content_hash,
            }
        )
        text_for_scan = data.decode("utf-8", errors="replace")
        if not sensitive_path:
            findings.extend(
                _general_fspr_findings(path, rel, text_for_scan, declared_capabilities)
            )
        if rel.startswith(("data/", "references/")):
            data_reference_hashes.setdefault(content_hash, []).append(rel)
        if rel == "SKILL.md":
            text = text_for_scan
            if re.search(
                r"ignore\s+(?:all\s+)?previous\s+instructions|exfiltrate|reveal\s+secrets"
                r"|\b(?:ignore|bypass|override|disable|skip)\s+(?:all\s+)?"
                r"(?:system|user|developer|security|review|policy|policies|instructions)\b"
                r"|\bhide\s+(?:this|these|the\s+)?(?:instruction|instructions|package|skill|text)?"
                r"(?:\s+from\s+(?:reviewers|review|auditors))?\b",
                text,
                re.I,
            ):
                findings.append(
                    {
                        "id": "fspr-inventory-prompt-injection",
                        "category": "prompt_injection_text",
                        "severity": "high",
                        "evidence_refs": ["file:SKILL.md"],
                    }
                )
        if rel.startswith("scripts/") and rel.endswith(".py"):
            summary = _script_summary(path, rel)
            if summary is not None:
                entrypoint_declared = _declared_in_manifest(manifest_text, rel)
                summary["entrypoint_declared"] = entrypoint_declared
                script_summaries.append(summary)
                if not entrypoint_declared and _python_has_executable_entrypoint(
                    path, rel
                ):
                    findings.append(
                        {
                            "id": f"fspr-undeclared-script-entrypoint-{len(script_summaries)}",
                            "category": "undeclared_script_entrypoint",
                            "severity": "medium",
                            "evidence_refs": [f"file:{rel}"],
                        }
                    )
                for observation in _capabilities_from_python_file(
                    path, rel, declared_capabilities
                ):
                    capability_observations.append(observation)
                    if not observation["declared"] and observation["capability"] in {
                        "network.fetch",
                        "package.install",
                    }:
                        findings.append(
                            {
                                "id": f"fspr-undeclared-capability-{len(capability_observations)}",
                                "category": "undeclared_capability_observed",
                                "capability": observation["capability"],
                                "severity": "high",
                                "evidence_refs": list(observation["evidence_refs"]),
                            }
                        )
            for ref_summary in _data_reference_summaries(path, rel, manifest_text):
                data_reference_summaries.append(ref_summary)
                if not ref_summary["declared"]:
                    category = (
                        "undeclared_reference_read"
                        if ref_summary["path"].startswith("references/")
                        else "undeclared_data_read"
                    )
                    findings.append(
                        {
                            "id": f"fspr-{category}-{len(data_reference_summaries)}",
                            "category": category,
                            "severity": "medium",
                            "evidence_refs": [
                                f"file:{rel}",
                                f"package:{ref_summary['path']}",
                            ],
                        }
                    )
            findings.extend(
                _script_adversarial_findings(path, rel, manifest_text, declared_tokens)
            )
        if rel.startswith(
            ("probes/", "fixtures/", "tests/fixtures/")
        ) and path.suffix.lower() in {
            ".json",
            ".jsonl",
            ".yaml",
            ".yml",
            ".toml",
            ".txt",
        }:
            fixture_probe_summaries.append(
                {
                    "path": rel,
                    "hash": content_hash,
                    "declared": _declared_in_manifest(manifest_text, rel),
                }
            )
    for duplicate_index, duplicate_paths in enumerate(
        paths for paths in data_reference_hashes.values() if len(paths) > 1
    ):
        findings.append(
            {
                "id": f"fspr-shared-data-reference-hash-{duplicate_index + 1}",
                "category": "shared_data_reference_hash",
                "severity": "medium",
                "evidence_refs": [f"file:{rel}" for rel in duplicate_paths],
            }
        )
    decoy_finding = _singular_plural_decoy_finding(frontmatter, manifest_text)
    if decoy_finding is not None:
        findings.append(decoy_finding)
    findings = normalize_fspr_findings(
        findings,
        capability_observations=capability_observations,
        declared_capabilities=declared_capabilities,
        budget_truncated=truncated,
    )
    normalized_deterministic = normalize_fspr_findings(
        list(deterministic_findings or []),
        capability_observations=capability_observations,
        declared_capabilities=declared_capabilities,
        budget_truncated=truncated,
    )
    hard_findings = [
        finding
        for finding in normalized_deterministic
        if finding.get("decision_affecting")
        or finding.get("severity") in {"high", "critical"}
    ]
    frontmatter_provenance = (
        dict(frontmatter.get("provenance"))
        if isinstance(frontmatter.get("provenance"), dict)
        else {}
    )
    return FSPRInventory(
        skill_root=str(root),
        skill_name=_manifest_name(root),
        skill_root_hash=_skill_root_hash(root),
        scanner_version=FSPR_SCANNER_VERSION,
        extractor_version=FSPR_EXTRACTOR_VERSION,
        budget_class="default",
        capability_manifest_schema_version=FSPR_CAPABILITY_MANIFEST_SCHEMA_VERSION,
        files=files,
        script_summaries=script_summaries,
        data_reference_summaries=data_reference_summaries,
        fixture_probe_summaries=fixture_probe_summaries,
        capability_observations=capability_observations,
        findings=findings,
        deterministic_findings=normalized_deterministic,
        deterministic_hard_findings_preserved=bool(hard_findings),
        frontmatter_summary=_frontmatter_summary(frontmatter),
        declared_provenance=dict(declared_provenance or frontmatter_provenance),
        ledger_summaries=_ledger_summaries(ledger_entries),
        truncated=truncated,
    )
