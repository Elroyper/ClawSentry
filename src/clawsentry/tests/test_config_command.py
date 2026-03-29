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
