"""Tests for Kimi CLI initializer under TOML-first config model."""

from __future__ import annotations

from clawsentry.cli.initializers import FRAMEWORK_INITIALIZERS
from clawsentry.cli.initializers.kimi_cli import KimiCLIInitializer
from clawsentry.gateway.project_config import read_project_frameworks


def test_registry_includes_kimi_cli():
    assert FRAMEWORK_INITIALIZERS["kimi-cli"] is KimiCLIInitializer


def test_generate_config_creates_toml_with_kimi_config_suggestion(tmp_path, monkeypatch):
    kimi_home = tmp_path / "kimi-home"
    result = KimiCLIInitializer().generate_config(tmp_path, kimi_home=kimi_home)

    assert (tmp_path / ".clawsentry.toml").exists()
    assert not (tmp_path / ".env.clawsentry").exists()
    assert result.env_vars["CLAW_SENTRY_FRAMEWORK"] == "kimi-cli"
    assert result.env_vars["CS_KIMI_CONFIG_PATH"].endswith("kimi-home/config.toml")
    assert result.env_vars["CS_KIMI_HOOKS_ENABLED"] == "true"
    assert read_project_frameworks(tmp_path)[0] == ["kimi-cli"]


def test_setup_kimi_hooks_writes_marker_managed_toml_and_preserves_user_hooks(tmp_path):
    kimi_home = tmp_path / "kimi-home"
    kimi_home.mkdir()
    config_path = kimi_home / "config.toml"
    config_path.write_text(
        "\n".join(
            [
                'default_model = "moonshot"',
                "",
                "[[hooks]]",
                'event = "PreToolUse"',
                'matcher = "Shell"',
                'command = "user-safety-hook"',
                "timeout = 5",
                "",
                "[[hooks]]",
                'event = "PreToolUse"',
                'matcher = "Shell"',
                'command = "clawsentry harness --framework kimi-cli --old"',
                "timeout = 1",
                "",
            ]
        ),
        encoding="utf-8",
    )

    result = KimiCLIInitializer().setup_kimi_hooks(
        target_dir=tmp_path,
        kimi_home=kimi_home,
        dry_run=False,
    )

    text = config_path.read_text(encoding="utf-8")
    assert result.files_modified == [config_path]
    assert 'default_model = "moonshot"' in text
    assert 'command = "user-safety-hook"' in text
    assert "--old" not in text
    assert text.count("clawsentry harness --framework kimi-cli") == 13
    assert 'event = "PreToolUse"' in text
    assert 'event = "SessionStart"' in text
    assert '--async' in text


def test_setup_kimi_hooks_is_idempotent(tmp_path):
    kimi_home = tmp_path / "kimi-home"
    init = KimiCLIInitializer()
    init.setup_kimi_hooks(target_dir=tmp_path, kimi_home=kimi_home, dry_run=False)
    first = (kimi_home / "config.toml").read_text(encoding="utf-8")
    init.setup_kimi_hooks(target_dir=tmp_path, kimi_home=kimi_home, dry_run=False)
    second = (kimi_home / "config.toml").read_text(encoding="utf-8")

    assert second == first


def test_uninstall_removes_only_clawsentry_kimi_hooks(tmp_path):
    kimi_home = tmp_path / "kimi-home"
    kimi_home.mkdir()
    config_path = kimi_home / "config.toml"
    config_path.write_text(
        "\n".join(
            [
                "[[hooks]]",
                'event = "PreToolUse"',
                'matcher = "Shell"',
                'command = "user-safety-hook"',
                "",
            ]
        ),
        encoding="utf-8",
    )
    init = KimiCLIInitializer()
    init.setup_kimi_hooks(target_dir=tmp_path, kimi_home=kimi_home, dry_run=False)

    result = init.uninstall(target_dir=tmp_path, kimi_home=kimi_home)

    text = config_path.read_text(encoding="utf-8")
    assert result.next_steps
    assert "clawsentry harness --framework kimi-cli" not in text
    assert 'command = "user-safety-hook"' in text
