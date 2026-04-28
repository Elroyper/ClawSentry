"""Tests for clawsentry config CLI commands."""

from __future__ import annotations

from pathlib import Path

import pytest

from clawsentry.cli.config_command import (
    run_config_init,
    run_config_show,
    run_config_set,
    run_config_disable,
    run_config_enable,
    run_config_wizard,
)


class TestConfigInit:
    def test_creates_toml_with_default_preset(self, tmp_path):
        run_config_init(target_dir=tmp_path)
        toml_path = tmp_path / ".clawsentry.toml"
        assert toml_path.exists()
        content = toml_path.read_text()
        assert 'preset = "medium"' in content

    def test_creates_toml_with_specified_preset(self, tmp_path):
        run_config_init(target_dir=tmp_path, preset="strict")
        content = (tmp_path / ".clawsentry.toml").read_text()
        assert 'preset = "strict"' in content

    def test_no_overwrite_without_force(self, tmp_path):
        run_config_init(target_dir=tmp_path)
        with pytest.raises(FileExistsError):
            run_config_init(target_dir=tmp_path)

    def test_overwrite_with_force(self, tmp_path):
        run_config_init(target_dir=tmp_path, preset="low")
        run_config_init(target_dir=tmp_path, preset="high", force=True)
        content = (tmp_path / ".clawsentry.toml").read_text()
        assert 'preset = "high"' in content


class TestConfigShow:
    def test_show_default_when_no_toml(self, tmp_path, capsys):
        run_config_show(target_dir=tmp_path)
        out = capsys.readouterr().out
        assert "medium" in out

    def test_show_project_config(self, tmp_path, capsys):
        (tmp_path / ".clawsentry.toml").write_text(
            '[project]\npreset = "strict"\n'
        )
        run_config_show(target_dir=tmp_path)
        out = capsys.readouterr().out
        assert "strict" in out


class TestConfigSet:
    def test_set_preset(self, tmp_path):
        run_config_init(target_dir=tmp_path)
        run_config_set(target_dir=tmp_path, preset="high")
        content = (tmp_path / ".clawsentry.toml").read_text()
        assert 'preset = "high"' in content

    def test_set_invalid_preset_raises(self, tmp_path):
        run_config_init(target_dir=tmp_path)
        with pytest.raises(ValueError):
            run_config_set(target_dir=tmp_path, preset="nonexistent")


class TestConfigDisableEnable:
    def test_disable_creates_toml_if_missing(self, tmp_path):
        run_config_disable(target_dir=tmp_path)
        content = (tmp_path / ".clawsentry.toml").read_text()
        assert "enabled = false" in content

    def test_enable_after_disable(self, tmp_path):
        run_config_disable(target_dir=tmp_path)
        run_config_enable(target_dir=tmp_path)
        content = (tmp_path / ".clawsentry.toml").read_text()
        assert "enabled = true" in content

    def test_disable_preserves_preset(self, tmp_path):
        run_config_init(target_dir=tmp_path, preset="strict")
        run_config_disable(target_dir=tmp_path)
        content = (tmp_path / ".clawsentry.toml").read_text()
        assert "enabled = false" in content
        assert 'preset = "strict"' in content


class TestConfigWizard:
    def test_interactive_wizard_labels_runtime_boundaries(self, tmp_path, monkeypatch, capsys):
        answers = iter([
            "codex",
            "normal",
            "openai",
            "gpt-4o-mini",
            "",
            "y",
            "n",
            "1000",
        ])
        monkeypatch.setattr("sys.stdin.isatty", lambda: True)

        def fake_input(prompt=""):
            print(prompt, end="")
            return next(answers)

        monkeypatch.setattr("builtins.input", fake_input)

        run_config_wizard(target_dir=tmp_path, interactive=True)

        out = capsys.readouterr().out
        assert "Writes only runtime-effective .clawsentry.toml fields" in out
        assert "API key values are env-only" in out
        assert "process env and .env.clawsentry still win" in out
        assert "features.l3 requests L3" in out
        assert "anti-bypass" in out
        assert "DEFER" in out
        assert "config show --effective" in out

    def test_interactive_wizard_prompts_and_writes_choices(self, tmp_path, monkeypatch, capsys):
        answers = iter([
            "claude-code",
            "strict",
            "openai",
            "gpt-4o-mini",
            "https://llm.example/v1",
            "y",
            "y",
            "250000",
        ])
        monkeypatch.setattr("sys.stdin.isatty", lambda: True)
        def fake_input(prompt=""):
            print(prompt, end="")
            return next(answers)
        monkeypatch.setattr("builtins.input", fake_input)

        run_config_wizard(target_dir=tmp_path, interactive=True)

        out = capsys.readouterr().out
        text = (tmp_path / ".clawsentry.toml").read_text(encoding="utf-8")
        assert "ClawSentry Setup" in out
        assert "Step 1/5" in out
        assert "L2/L3 can improve semantic detection" in out
        assert "Enable L2 semantic analysis" in out
        assert "Step 5/5" in out
        assert "Next: run `clawsentry start --framework claude-code`." in out
        assert 'mode = "strict"' in text
        assert 'provider = "openai"' in text
        assert 'model = "gpt-4o-mini"' in text
        assert 'base_url = "https://llm.example/v1"' in text
        assert "l2 = true" in text
        assert "l3 = true" in text
        assert "llm_daily_token_budget = 250000" in text
        assert "Preferred framework for guided setup" in text

    def test_interactive_wizard_accepts_numbered_choices(self, tmp_path, monkeypatch, capsys):
        answers = iter([
            "codex",
            "2",
            "2",
            "gpt-4o-mini",
            "",
            "y",
            "n",
            "1000",
        ])
        monkeypatch.setattr("sys.stdin.isatty", lambda: True)

        def fake_input(prompt=""):
            print(prompt, end="")
            return next(answers)

        monkeypatch.setattr("builtins.input", fake_input)

        run_config_wizard(target_dir=tmp_path, interactive=True)

        out = capsys.readouterr().out
        text = (tmp_path / ".clawsentry.toml").read_text(encoding="utf-8")
        assert "1) normal" in out
        assert "2) strict" in out
        assert "1) none" in out
        assert "2) openai" in out
        assert 'mode = "strict"' in text
        assert 'provider = "openai"' in text

    def test_non_tty_ci_wizard_is_deterministic_and_plain(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin.isatty", lambda: False)
        monkeypatch.setenv("CI", "true")
        monkeypatch.setenv("NO_COLOR", "1")

        run_config_wizard(target_dir=tmp_path, framework="codex", llm_provider="none")

        out = capsys.readouterr().out
        assert "Non-interactive/CI-safe wizard path" in out
        assert "Step 1/5" not in out
        assert "\x1b[" not in out
        assert (tmp_path / ".clawsentry.toml").is_file()

    def test_interactive_wizard_reprompts_invalid_choice(self, tmp_path, monkeypatch, capsys):
        answers = iter([
            "bad-framework",
            "codex",
            "normal",
            "none",
            "0",
        ])
        monkeypatch.setattr("sys.stdin.isatty", lambda: True)
        def fake_input(prompt=""):
            print(prompt, end="")
            return next(answers)
        monkeypatch.setattr("builtins.input", fake_input)

        run_config_wizard(target_dir=tmp_path, interactive=True)

        out = capsys.readouterr().out
        text = (tmp_path / ".clawsentry.toml").read_text(encoding="utf-8")
        assert "Choose one of" in out
        assert "No LLM provider selected; L2 and L3 review are disabled." in out
        assert 'provider = ""' in text
        assert "l2 = false" in text
        assert "l3 = false" in text


class TestA3SDemoTemplate:
    def test_a3s_demo_sanitized_project_config_template_is_secret_safe(self):
        template = Path("demostation_projects/a3s_demo/.clawsentry.toml.example")

        assert template.is_file()
        text = template.read_text(encoding="utf-8")
        assert '[project]' in text
        assert '[llm]' in text
        assert 'api_key_env = "CS_LLM_API_KEY"' in text
        assert '[features]' in text
        assert '[budgets]' in text
        assert 'features.l3 requests runtime L3 only when provider support is available' in text
        assert "sk-" not in text
        assert "OPENAI_API_KEY=" not in text
        assert "ANTHROPIC_API_KEY=" not in text
        assert "CS_LLM_API_KEY=" not in text

    def test_explicit_interactive_wizard_requires_tty(self, tmp_path, monkeypatch):
        monkeypatch.setattr("sys.stdin.isatty", lambda: False)

        with pytest.raises(RuntimeError, match="requires a TTY"):
            run_config_wizard(
                target_dir=tmp_path,
                interactive=True,
                framework="gemini-cli",
                mode="benchmark",
                llm_provider="none",
            )

        assert not (tmp_path / ".clawsentry.toml").exists()

    def test_non_interactive_wizard_writes_supplied_values_without_tty(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin.isatty", lambda: False)

        run_config_wizard(
            target_dir=tmp_path,
            non_interactive=True,
            framework="gemini-cli",
            mode="benchmark",
            llm_provider="none",
        )

        out = capsys.readouterr().out
        text = (tmp_path / ".clawsentry.toml").read_text(encoding="utf-8")
        assert "Interactive wizard is not available in this terminal" not in out
        assert 'mode = "benchmark"' in text

    def test_wizard_forces_l2_l3_off_without_provider(self, tmp_path):
        run_config_wizard(
            target_dir=tmp_path,
            non_interactive=True,
            llm_provider="none",
            l2=True,
            l3=True,
        )

        text = (tmp_path / ".clawsentry.toml").read_text(encoding="utf-8")
        assert 'provider = ""' in text
        assert "l2 = false" in text
        assert "l3 = false" in text
