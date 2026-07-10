"""Skill trust registry read/write and lifecycle helpers."""

from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
from pathlib import Path
from typing import Any

from clawsentry.gateway.models import SkillRegistryRecord, utc_now_iso
from clawsentry.gateway.trust.skill_trust import record_with_skill_trust_grade
from clawsentry.gateway.trust.lifecycle import apply_expired_lifecycle_windows


def _skill_trust_registry_snapshot_id(payload: dict[str, Any]) -> str:
    records = [
        {key: value for key, value in row.items() if key != "skill_trust_grade"}
        if isinstance(row, dict)
        else row
        for row in payload.get("records", [])
    ]
    material = {
        "schema_version": payload.get("schema_version"),
        "records": records,
        "transition_events": payload.get("transition_events", []),
    }
    encoded = json.dumps(material, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


_SKILL_TRUST_REGISTRY_LOCKS: dict[str, threading.RLock] = {}
_SKILL_TRUST_REGISTRY_LOCKS_GUARD = threading.Lock()


def _skill_trust_registry_lock(path: Path) -> threading.RLock:
    key = str(path.expanduser().resolve(strict=False))
    with _SKILL_TRUST_REGISTRY_LOCKS_GUARD:
        lock = _SKILL_TRUST_REGISTRY_LOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _SKILL_TRUST_REGISTRY_LOCKS[key] = lock
        return lock


def _skill_trust_transition_sidecar_path(path: Path) -> Path:
    return path.with_name(f"{path.name}.transitions.jsonl")


def _transition_event_id(event: Any) -> str:
    if isinstance(event, dict):
        return str(event.get("transition_id") or "")
    return ""


def _read_skill_trust_transition_sidecar(path: Path) -> list[dict[str, Any]]:
    sidecar = _skill_trust_transition_sidecar_path(path)
    if not sidecar.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(sidecar.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        row = json.loads(line)
        if not isinstance(row, dict):
            raise ValueError(
                f"skill registry transition sidecar row {line_number} must be a JSON object"
            )
        rows.append(row)
    return rows


def _merge_transition_events(
    embedded_events: list[Any],
    sidecar_events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    sidecar_ids = {
        event_id for event_id in (_transition_event_id(event) for event in sidecar_events)
        if event_id
    }
    merged: list[dict[str, Any]] = [
        event
        for event in embedded_events
        if isinstance(event, dict)
        and (
            not _transition_event_id(event)
            or _transition_event_id(event) not in sidecar_ids
        )
    ]
    merged.extend(sidecar_events)
    return merged


def _write_skill_trust_transition_sidecar(
    path: Path,
    events: list[Any],
) -> None:
    event_rows = [event for event in events if isinstance(event, dict)]
    if not event_rows:
        return
    sidecar = _skill_trust_transition_sidecar_path(path)
    existing_rows = _read_skill_trust_transition_sidecar(path)
    existing_ids = {
        event_id for event_id in (_transition_event_id(row) for row in existing_rows)
        if event_id
    }
    rows = list(existing_rows)
    for event in event_rows:
        event_id = _transition_event_id(event)
        if event_id and event_id in existing_ids:
            continue
        rows.append(event)
        if event_id:
            existing_ids.add(event_id)
    if len(rows) == len(existing_rows):
        return
    sidecar.parent.mkdir(parents=True, exist_ok=True)
    temp_path = sidecar.with_name(f".{sidecar.name}.{uuid.uuid4().hex}.tmp")
    temp_path.write_text(
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    os.replace(temp_path, sidecar)


def _read_skill_trust_registry_payload(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, list):
        payload = {
            "schema_version": "clawsentry.skill_registry.v1",
            "records": payload,
            "transition_events": [],
        }
    if not isinstance(payload, dict):
        raise ValueError("skill registry must be a JSON object")
    payload.setdefault("schema_version", "clawsentry.skill_registry.v1")
    payload.setdefault("records", [])
    payload.setdefault("transition_events", [])
    payload.setdefault("transition_recommendations", [])
    if not isinstance(payload["records"], list):
        raise ValueError("skill registry records must be a list")
    if not isinstance(payload["transition_events"], list):
        raise ValueError("skill registry transition_events must be a list")
    if not isinstance(payload["transition_recommendations"], list):
        raise ValueError("skill registry transition_recommendations must be a list")
    payload["transition_events"] = _merge_transition_events(
        payload["transition_events"],
        _read_skill_trust_transition_sidecar(path),
    )
    payload["records"] = [
        record_with_skill_trust_grade(row) if isinstance(row, dict) else row
        for row in payload["records"]
    ]
    payload["registry_snapshot_id"] = _skill_trust_registry_snapshot_id(payload)
    return payload


def _write_skill_trust_registry_payload(
    path: Path,
    payload: dict[str, Any],
    *,
    expected_registry_snapshot_id: str | None = None,
) -> dict[str, Any]:
    with _skill_trust_registry_lock(path):
        if expected_registry_snapshot_id is not None:
            current_payload = _read_skill_trust_registry_payload(path)
            current_snapshot_id = current_payload["registry_snapshot_id"]
            if current_snapshot_id != expected_registry_snapshot_id:
                raise ValueError("registry snapshot conflict")
        payload = dict(payload)
        payload["records"] = [
            record_with_skill_trust_grade(row) if isinstance(row, dict) else row
            for row in payload.get("records", [])
        ]
        payload["registry_snapshot_id"] = _skill_trust_registry_snapshot_id(payload)
        path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        temp_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(temp_path, path)
        _write_skill_trust_transition_sidecar(path, payload.get("transition_events", []))
        return payload


def _consume_expired_skill_trust_lifecycle_windows(
    path: Path,
    payload: dict[str, Any],
) -> dict[str, Any]:
    records: list[SkillRegistryRecord] = []
    for row in payload.get("records", []):
        if not isinstance(row, dict):
            continue
        records.append(SkillRegistryRecord.model_validate(row))
    updated_records, events = apply_expired_lifecycle_windows(
        records,
        now=utc_now_iso(),
        policy_fingerprint="sha256:skill-trust-lifecycle-v1",
    )
    if not events:
        return payload
    updated_payload = dict(payload)
    updated_payload["records"] = [
        record.model_dump(mode="json") for record in updated_records
    ]
    updated_payload["transition_events"] = [
        *[
            event for event in payload.get("transition_events", [])
            if isinstance(event, dict)
        ],
        *[event.model_dump(mode="json") for event in events],
    ]
    return _write_skill_trust_registry_payload(
        path,
        updated_payload,
        expected_registry_snapshot_id=payload["registry_snapshot_id"],
    )


def _transition_request_optional_str(body: dict[str, Any], key: str) -> str | None:
    value = body.get(key)
    return str(value) if value else None


def _transition_request_evidence_refs(body: dict[str, Any]) -> list[str]:
    return [
        str(item) for item in body.get("evidence_refs", [])
        if isinstance(item, str)
    ]


def _transition_idempotency_matches(
    event: dict[str, Any],
    body: dict[str, Any],
) -> bool:
    requested_reason_code = str(body["reason_code"])
    expected_reason_code = (
        "operator_override"
        if (
            body.get("override_id")
            and str(body["target_state"]) == "allowlist"
            and requested_reason_code != "trusted_migration"
        )
        else requested_reason_code
    )
    required_matches = {
        "canonical_skill_id": str(body["canonical_skill_id"]),
        "to_state": str(body["target_state"]),
        "reason_code": expected_reason_code,
        "operator_id_hash": _transition_request_optional_str(body, "operator_id_hash"),
        "override_id": _transition_request_optional_str(body, "override_id"),
        "override_indefinite_reason": _transition_request_optional_str(
            body,
            "override_indefinite_reason",
        ),
        "expires_at": _transition_request_optional_str(body, "expires_at"),
        "disabled_until": _transition_request_optional_str(body, "disabled_until"),
        "restore_target_state": _transition_request_optional_str(body, "restore_target_state"),
    }
    for key, expected in required_matches.items():
        actual = event.get(key)
        if (str(actual) if actual is not None else None) != expected:
            return False
    return list(event.get("evidence_refs") or []) == _transition_request_evidence_refs(body)


def _find_transition_event_by_idempotency_key(
    payload: dict[str, Any],
    idempotency_key: str,
) -> dict[str, Any] | None:
    for event in payload.get("transition_events", []):
        if isinstance(event, dict) and str(event.get("idempotency_key") or "") == idempotency_key:
            return event
    return None


def _registry_record_evidence_hashes(record: SkillRegistryRecord) -> list[str]:
    values = {
        value for value in record.content_hashes.values()
        if isinstance(value, str) and value.strip()
    }
    for key in ("skill_root_hash", "path_hash", "metadata_record_id"):
        value = record.source.get(key)
        if isinstance(value, str) and value.strip():
            values.add(value)
    return sorted(values)
