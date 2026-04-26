"""Tests for Docker deployment files — YAML syntax + Dockerfile basic validation."""

from __future__ import annotations

from pathlib import Path

_DOCKER_DIR = Path(__file__).resolve().parents[3] / "docker"


class TestDockerfile:
    def test_exists(self) -> None:
        assert (_DOCKER_DIR / "Dockerfile").is_file()

    def test_has_from(self) -> None:
        content = (_DOCKER_DIR / "Dockerfile").read_text()
        assert "FROM python:3.12-slim" in content

    def test_non_root_user(self) -> None:
        content = (_DOCKER_DIR / "Dockerfile").read_text()
        assert "USER clawsentry" in content

    def test_healthcheck(self) -> None:
        content = (_DOCKER_DIR / "Dockerfile").read_text()
        assert "HEALTHCHECK" in content

    def test_expose_port(self) -> None:
        content = (_DOCKER_DIR / "Dockerfile").read_text()
        assert "EXPOSE 8080" in content


class TestDockerCompose:
    def test_exists(self) -> None:
        assert (_DOCKER_DIR / "docker-compose.yml").is_file()

    def test_valid_yaml(self) -> None:
        # Basic YAML parsing without pyyaml dependency
        content = (_DOCKER_DIR / "docker-compose.yml").read_text()
        assert "services:" in content
        assert "gateway:" in content

    def test_has_volume(self) -> None:
        content = (_DOCKER_DIR / "docker-compose.yml").read_text()
        assert "volumes:" in content
        assert "clawsentry-data" in content

    def test_healthcheck(self) -> None:
        content = (_DOCKER_DIR / "docker-compose.yml").read_text()
        assert "healthcheck:" in content


class TestEnvExample:
    def test_exists(self) -> None:
        assert (_DOCKER_DIR / ".env.example").is_file()

    def test_has_auth_token(self) -> None:
        content = (_DOCKER_DIR / ".env.example").read_text()
        assert "CS_AUTH_TOKEN" in content

    def test_uses_canonical_budget_and_timeout_names(self) -> None:
        content = (_DOCKER_DIR / ".env.example").read_text()
        assert "CS_L2_TIMEOUT_MS" in content
        assert "CS_LLM_TOKEN_BUDGET_ENABLED" in content
        assert "CS_LLM_DAILY_BUDGET_USD" not in content
        assert "CS_L2_BUDGET_MS" not in content
