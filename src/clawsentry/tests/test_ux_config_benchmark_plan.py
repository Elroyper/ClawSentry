"""UX config benchmark plan tests for env-first model."""

from __future__ import annotations

from clawsentry.cli.config_command import run_config_init, run_config_set
from clawsentry.gateway.env_config import resolve_effective_config


def test_env_template_contains_runtime_effective_sections(tmp_path):
    run_config_init(target_dir=tmp_path, preset="high")
    text = (tmp_path / ".clawsentry.env.example").read_text()
    assert "CS_PRESET=high" in text
    assert "CS_LLM_TOKEN_BUDGET_ENABLED" in text
    assert "CS_DEFER_BRIDGE_ENABLED" in text
    assert not (tmp_path / (".clawsentry" + ".toml")).exists()


def test_config_set_default_prints_export_not_file(tmp_path, capsys):
    run_config_set(target_dir=tmp_path, key="project.mode", value="benchmark")
    assert "export CS_MODE=benchmark" in capsys.readouterr().out
    assert not (tmp_path / (".clawsentry" + ".toml")).exists()


def test_effective_config_defaults_are_env_first():
    eff = resolve_effective_config(environ={})
    assert eff.values["project.mode"] == "normal"
    assert eff.sources["project.mode"] == "default"
