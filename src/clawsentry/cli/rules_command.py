"""`clawsentry rules` - authoring-time governance for rule surfaces."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

from clawsentry.gateway.rule_governance import (
    RuleDryRunReport,
    RuleGovernanceReport,
    dry_run_rule_governance,
    load_rule_governance,
)


def run_rules_lint(
    *,
    patterns_path: str | Path | None = None,
    evolved_patterns_path: str | Path | None = None,
    skills_dir: str | Path | None = None,
    as_json: bool = False,
) -> int:
    report = load_rule_governance(
        patterns_path=patterns_path,
        evolved_patterns_path=evolved_patterns_path,
        skills_dir=skills_dir,
    )
    if as_json:
        print(json.dumps(_lint_json_payload(report), ensure_ascii=False, sort_keys=True))
    else:
        print(_render_lint_report(report))
    return 1 if report.findings else 0


def run_rules_dry_run(
    *,
    events_path: str | Path,
    patterns_path: str | Path | None = None,
    evolved_patterns_path: str | Path | None = None,
    skills_dir: str | Path | None = None,
    as_json: bool = False,
) -> int:
    try:
        normalized_events_path, cleanup_path = _normalize_dry_run_events_path(events_path)
    except OSError as exc:
        print(
            f"clawsentry rules dry-run: unable to read events file {events_path}: {exc}",
            file=sys.stderr,
        )
        return 2
    except ValueError as exc:
        print(f"clawsentry rules dry-run: {exc}", file=sys.stderr)
        return 2

    try:
        report = dry_run_rule_governance(
            events_path=normalized_events_path,
            patterns_path=patterns_path,
            evolved_patterns_path=evolved_patterns_path,
            skills_dir=skills_dir,
        )
    finally:
        if cleanup_path is not None:
            cleanup_path.unlink(missing_ok=True)

    if as_json:
        print(json.dumps(_dry_run_json_payload(report), ensure_ascii=False, sort_keys=True))
    else:
        print(_render_dry_run_report(report))
    return 1 if report.findings else 0


def run_rules_report(
    *,
    output_path: str | Path,
    events_path: str | Path | None = None,
    patterns_path: str | Path | None = None,
    evolved_patterns_path: str | Path | None = None,
    skills_dir: str | Path | None = None,
    as_json: bool = False,
) -> int:
    """Write a combined rule-governance report for CI/release artifacts."""
    lint_report = load_rule_governance(
        patterns_path=patterns_path,
        evolved_patterns_path=evolved_patterns_path,
        skills_dir=skills_dir,
    )
    dry_run_report: RuleDryRunReport | None = None
    dry_run_input_error: str | None = None
    if events_path is not None:
        try:
            normalized_events_path, cleanup_path = _normalize_dry_run_events_path(events_path)
        except OSError as exc:
            dry_run_input_error = f"unable to read events file {events_path}: {exc}"
            cleanup_path = None
        except ValueError as exc:
            dry_run_input_error = str(exc)
            cleanup_path = None
        else:
            try:
                dry_run_report = dry_run_rule_governance(
                    events_path=normalized_events_path,
                    patterns_path=patterns_path,
                    evolved_patterns_path=evolved_patterns_path,
                    skills_dir=skills_dir,
                )
            finally:
                if cleanup_path is not None:
                    cleanup_path.unlink(missing_ok=True)

    exit_code = _report_exit_code(lint_report, dry_run_report, dry_run_input_error)
    payload = _report_json_payload(
        lint_report=lint_report,
        dry_run_report=dry_run_report,
        dry_run_input_error=dry_run_input_error,
        output_path=Path(output_path),
        exit_code=exit_code,
    )
    _write_json_report(Path(output_path), payload)

    if as_json:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    else:
        print(_render_ci_report_summary(payload, Path(output_path)))
    return exit_code


def _render_lint_report(report: RuleGovernanceReport) -> str:
    lines = [
        "ClawSentry Rule Governance",
        f"Fingerprint: {report.fingerprint}",
        f"Attack patterns: {len(report.attack_patterns)}",
        f"Review skills: {len(report.review_skills)}",
    ]
    if not report.findings:
        lines.append("PASS: no findings")
        return "\n".join(lines)
    for finding in report.findings:
        lines.append(f"FAIL [{finding.kind}] {finding.message}")
    return "\n".join(lines)


def _render_dry_run_report(report: RuleDryRunReport) -> str:
    lines = [
        "ClawSentry Rule Dry Run",
        f"Fingerprint: {report.fingerprint}",
    ]
    for event in report.events:
        matched = ", ".join(event.matched_pattern_ids) or "-"
        selected_skill = event.selected_skill or "-"
        lines.append(
            f"{event.event_id}: patterns={matched} skill={selected_skill}"
        )
    if report.findings:
        for finding in report.findings:
            lines.append(f"FAIL [{finding.kind}] {finding.message}")
    else:
        lines.append("PASS: no findings")
    return "\n".join(lines)


def _to_jsonable(value: Any) -> Any:
    if is_dataclass(value):
        return {key: _to_jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, tuple):
        return [_to_jsonable(item) for item in value]
    if isinstance(value, list):
        return [_to_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {key: _to_jsonable(item) for key, item in value.items()}
    return value


def _lint_json_payload(report: RuleGovernanceReport) -> dict[str, Any]:
    return {
        "fingerprint": report.fingerprint,
        "version_summary": _to_jsonable(report.version_summary),
        "source_summaries": _to_jsonable(report.source_summaries),
        "findings": _to_jsonable(report.findings),
        "attack_pattern_ids": [pattern.id for pattern in report.attack_patterns],
        "review_skill_names": [skill.name for skill in report.review_skills],
        "cwd": os.getcwd(),
    }


def _dry_run_json_payload(report: RuleDryRunReport) -> dict[str, Any]:
    return {
        "fingerprint": report.fingerprint,
        "events": _to_jsonable(report.events),
        "findings": _to_jsonable(report.findings),
        "cwd": os.getcwd(),
    }


def _report_exit_code(
    lint_report: RuleGovernanceReport,
    dry_run_report: RuleDryRunReport | None,
    dry_run_input_error: str | None,
) -> int:
    if dry_run_input_error is not None:
        return 2
    if lint_report.findings or (dry_run_report is not None and dry_run_report.findings):
        return 1
    return 0


def _report_status(exit_code: int) -> str:
    if exit_code == 0:
        return "pass"
    if exit_code == 1:
        return "fail"
    return "input_error"


def _report_json_payload(
    *,
    lint_report: RuleGovernanceReport,
    dry_run_report: RuleDryRunReport | None,
    dry_run_input_error: str | None,
    output_path: Path,
    exit_code: int,
) -> dict[str, Any]:
    lint_payload = _lint_json_payload(lint_report)
    dry_run_payload = _dry_run_json_payload(dry_run_report) if dry_run_report is not None else None
    return {
        "report_schema_version": "cs-01.rule-governance.ci-report.v1",
        "status": _report_status(exit_code),
        "exit_code": exit_code,
        "fingerprint": lint_report.fingerprint,
        "output_path": str(output_path),
        "cwd": os.getcwd(),
        "checks": {
            "lint": {
                "status": "fail" if lint_report.findings else "pass",
                "finding_count": len(lint_report.findings),
            },
            "dry_run": {
                "status": _dry_run_status(dry_run_report, dry_run_input_error),
                "event_count": len(dry_run_report.events) if dry_run_report is not None else 0,
                "finding_count": len(dry_run_report.findings) if dry_run_report is not None else 0,
                "input_error": dry_run_input_error,
            },
        },
        "lint": lint_payload,
        "dry_run": dry_run_payload,
    }


def _dry_run_status(
    dry_run_report: RuleDryRunReport | None,
    input_error: str | None,
) -> str:
    if input_error is not None:
        return "input_error"
    if dry_run_report is None:
        return "skipped"
    return "fail" if dry_run_report.findings else "pass"


def _write_json_report(output_path: Path, payload: dict[str, Any]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _render_ci_report_summary(payload: dict[str, Any], output_path: Path) -> str:
    status = str(payload["status"]).upper()
    checks = payload["checks"]
    lines = [
        f"{status}: wrote rules report {output_path}",
        f"Fingerprint: {payload['fingerprint']}",
        (
            "Lint: "
            f"{checks['lint']['status']} "
            f"({checks['lint']['finding_count']} findings)"
        ),
        (
            "Dry run: "
            f"{checks['dry_run']['status']} "
            f"({checks['dry_run']['event_count']} events, "
            f"{checks['dry_run']['finding_count']} findings)"
        ),
    ]
    if checks["dry_run"]["input_error"]:
        lines.append(f"Input error: {checks['dry_run']['input_error']}")
    return "\n".join(lines)


def _normalize_dry_run_events_path(events_path: str | Path) -> tuple[Path, Path | None]:
    source_path = Path(events_path)
    raw_text = source_path.read_text(encoding="utf-8")
    stripped = raw_text.strip()
    if not stripped:
        return source_path, None

    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError:
        return source_path, None

    if isinstance(parsed, dict):
        events = [parsed]
    elif isinstance(parsed, list):
        events = parsed
    else:
        raise ValueError(
            "events input must be a JSON object, JSON array, or JSONL file"
        )

    normalized_events: list[dict[str, Any]] = []
    for index, event in enumerate(events, start=1):
        if not isinstance(event, dict):
            raise ValueError(f"events JSON array item {index} must be an object")
        normalized_events.append(event)

    temp_file = tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False, encoding="utf-8")
    try:
        for event in normalized_events:
            temp_file.write(json.dumps(event, ensure_ascii=False, sort_keys=True))
            temp_file.write("\n")
    finally:
        temp_file.close()
    temp_path = Path(temp_file.name)
    return temp_path, temp_path
