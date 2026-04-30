"""Docs/config benchmark contract tests for env-first model."""

from __future__ import annotations

from clawsentry.cli.config_command import run_config_wizard
from clawsentry.gateway.env_config import resolve_effective_config


def test_non_interactive_wizard_writes_env_template_without_project_file(tmp_path, monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    run_config_wizard(target_dir=tmp_path, non_interactive=True, framework="codex", mode="benchmark")
    assert (tmp_path / ".clawsentry.env.example").exists()
    assert not (tmp_path / (".clawsentry" + ".toml")).exists()


def test_effective_config_has_source_labels():
    eff = resolve_effective_config(environ={"CS_MODE": "benchmark"})
    assert eff.sources["project.mode"] == "process-env"
