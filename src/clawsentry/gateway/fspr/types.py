"""FSPR shared types and schema constants."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, Sequence

from clawsentry.gateway.analysis.content_evidence import hash_evidence_bytes
from clawsentry.gateway.models import FirstUseSkillPackageReview

FSPR_SCANNER_VERSION = "fspr.deterministic_inventory@v2"
FSPR_EXTRACTOR_VERSION = "fspr.python_ast_capability_scan@v1"
FSPR_CAPABILITY_MANIFEST_SCHEMA_VERSION = "fspr.capability_manifest@v1"
FSPR_EVIDENCE_CAPSULE_SCHEMA_VERSION = "clawsentry.fspr_evidence_capsule.v2"
FSPR_PROMPT_VERSION = "fspr.v2-review-axis"


def _sha256(data: bytes) -> str:
    return hash_evidence_bytes(data)


@dataclass(frozen=True)
class FSPRInventory:
    skill_root: str
    skill_name: str
    skill_root_hash: str
    scanner_version: str = FSPR_SCANNER_VERSION
    extractor_version: str = FSPR_EXTRACTOR_VERSION
    budget_class: str = "default"
    capability_manifest_schema_version: str = FSPR_CAPABILITY_MANIFEST_SCHEMA_VERSION
    files: list[dict[str, Any]] = field(default_factory=list)
    script_summaries: list[dict[str, Any]] = field(default_factory=list)
    data_reference_summaries: list[dict[str, Any]] = field(default_factory=list)
    fixture_probe_summaries: list[dict[str, Any]] = field(default_factory=list)
    capability_observations: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    deterministic_findings: list[dict[str, Any]] = field(default_factory=list)
    deterministic_hard_findings_preserved: bool = False
    frontmatter_summary: dict[str, Any] = field(default_factory=dict)
    declared_provenance: dict[str, Any] = field(default_factory=dict)
    ledger_summaries: list[dict[str, Any]] = field(default_factory=list)
    truncated: bool = False

    @property
    def evidence_capsule(self) -> dict[str, Any]:
        return _fspr_evidence_capsule(self)


class FSPRResult(FirstUseSkillPackageReview):
    """Concrete FSPR result model returned by the package review runner."""


class FSPRProviderSchemaError(ValueError):
    """Provider returned a policy/action field outside the evidence-only schema."""


class FSPRAgenticSemanticReviewError(FSPRProviderSchemaError):
    """Provider returned an incomplete agentic semantic review."""

    def __init__(self, errors: Sequence[str]):
        self.errors = [str(error) for error in errors]
        super().__init__("provider_semantic_review_invalid")


class FSPRRoleProvider(Protocol):
    def review_role(
        self,
        *,
        role: str,
        prompt: str,
        response_format: dict[str, object] | None = None,
    ) -> str:
        """Return a JSON role result for one read-only FSPR role."""


def _fspr_evidence_capsule(
    inventory: FSPRInventory,
    *,
    include_deterministic_findings: bool = True,
) -> dict[str, Any]:
    capsule = {
        "schema": FSPR_EVIDENCE_CAPSULE_SCHEMA_VERSION,
        "skill_name": inventory.skill_name,
        "skill_root_hash": inventory.skill_root_hash,
        "scanner_version": inventory.scanner_version,
        "extractor_version": inventory.extractor_version,
        "budget_class": inventory.budget_class,
        "capability_manifest_schema_version": inventory.capability_manifest_schema_version,
        "file_count": len(inventory.files),
        "finding_count": len(inventory.findings),
        "truncated": inventory.truncated,
        "frontmatter_summary": dict(inventory.frontmatter_summary),
        "declared_provenance": dict(inventory.declared_provenance),
        "ledger_summaries": list(inventory.ledger_summaries),
        "files": [
            {
                "evidence_id": file_info.get("evidence_id"),
                "evidence_ref": file_info.get("evidence_ref"),
                "path": file_info.get("path"),
                "size": file_info.get("size"),
                "hash": file_info.get("hash"),
            }
            for file_info in inventory.files
        ],
        "script_summaries": list(inventory.script_summaries),
        "data_reference_summaries": list(inventory.data_reference_summaries),
        "fixture_probe_summaries": list(inventory.fixture_probe_summaries),
        "capability_observations": list(inventory.capability_observations),
    }
    if include_deterministic_findings:
        capsule.update(
            {
                "deterministic_findings": list(inventory.findings),
                "external_deterministic_findings": list(
                    inventory.deterministic_findings
                ),
                "deterministic_hard_findings_preserved": inventory.deterministic_hard_findings_preserved,
            }
        )
    return capsule
