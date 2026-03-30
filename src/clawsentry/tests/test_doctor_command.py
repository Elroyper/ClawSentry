"""Tests for ``clawsentry doctor`` configuration audit command."""

from __future__ import annotations

import json
import os
import stat
import tempfile

import pytest

from clawsentry.cli.doctor_command import (
    DoctorCheck,
    _shannon_entropy,
    check_auth_entropy,
    check_auth_length,
    check_auth_presence,
    check_defer_bridge,
    check_hub_bridge,
    check_l2_budget,
    check_listen_address,
    check_llm_config,
    check_openclaw_secret,
    check_threshold_ordering,
    check_trajectory_db,
    check_uds_permissions,
    check_weight_bounds,
    check_whitelist_regex,
    compute_exit_code,
    format_json,
    format_table,
    run_all_checks,
    run_doctor,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DOCTOR_ENV_KEYS = [
    "CS_AUTH_TOKEN",
    "CS_UDS_PATH",
    "CS_THRESHOLD_MEDIUM",
    "CS_THRESHOLD_HIGH",
    "CS_THRESHOLD_CRITICAL",
    "CS_COMPOSITE_WEIGHT_MAX_D123",
    "CS_COMPOSITE_WEIGHT_D4",
    "CS_COMPOSITE_WEIGHT_D5",
    "CS_D6_INJECTION_MULTIPLIER",
    "CS_LLM_PROVIDER",
    "CS_LLM_API_KEY",
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "CS_OPENCLAW_TOKEN",
    "CS_OPENCLAW_WEBHOOK_SECRET",
    "CS_HTTP_HOST",
    "CS_POST_ACTION_WHITELIST",
    "CS_L2_BUDGET_MS",
    "CS_TRAJECTORY_DB_PATH",
]


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove all doctor-relevant env vars before each test."""
    for key in _DOCTOR_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)


# ===== Shannon entropy =====

class TestShannonEntropy:
    def test_empty_string(self) -> None:
        assert _shannon_entropy("") == 0.0

    def test_single_char(self) -> None:
        assert _shannon_entropy("aaaa") == 0.0

    def test_two_chars_equal(self) -> None:
        # "ab" repeated = 1.0 bits/char
        assert abs(_shannon_entropy("ab") - 1.0) < 0.01

    def test_high_entropy(self) -> None:
        # All unique characters → high entropy
        s = "abcdefghijklmnopqrstuvwxyz0123456789"
        assert _shannon_entropy(s) > 3.5


# ===== AUTH_PRESENCE =====

class TestAuthPresence:
    def test_pass_when_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CS_AUTH_TOKEN", "some-token")
        r = check_auth_presence()
        assert r.status == "PASS"
        assert r.check_id == "AUTH_PRESENCE"

    def test_fail_when_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CS_AUTH_TOKEN", "")
        r = check_auth_presence()
        assert r.status == "FAIL"

    def test_fail_when_unset(self) -> None:
        r = check_auth_presence()
        assert r.status == "FAIL"


# ===== AUTH_LENGTH =====

class TestAuthLength:
    def test_pass_32_plus(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CS_AUTH_TOKEN", "a" * 32)
        r = check_auth_length()
        assert r.status == "PASS"

    def test_warn_16_to_31(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CS_AUTH_TOKEN", "a" * 20)
        r = check_auth_length()
        assert r.status == "WARN"

    def test_fail_under_16(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CS_AUTH_TOKEN", "short")
        r = check_auth_length()
        assert r.status == "FAIL"

    def test_fail_unset(self) -> None:
        r = check_auth_length()
        assert r.status == "FAIL"


# ===== AUTH_ENTROPY =====

class TestAuthEntropy:
    def test_pass_high_entropy(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CS_AUTH_TOKEN",
                           "aB3$xY7!mN9@pQ2&kL5^wR8*")
        r = check_auth_entropy()
        assert r.status == "PASS"

    def test_warn_low_entropy(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CS_AUTH_TOKEN", "aaaaaabbbbbb")
        r = check_auth_entropy()
        assert r.status == "WARN"

    def test_warn_unset(self) -> None:
        r = check_auth_entropy()
        assert r.status == "WARN"


# ===== UDS_PERMISSIONS =====

class TestUdsPermissions:
    def test_pass_no_socket(self, monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
        monkeypatch.setenv("CS_UDS_PATH", str(tmp_path / "nonexistent.sock"))
        r = check_uds_permissions()
        assert r.status == "PASS"

    def test_pass_600(self, monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
        sock = tmp_path / "test.sock"
        sock.touch()
        sock.chmod(0o600)
        monkeypatch.setenv("CS_UDS_PATH", str(sock))
        r = check_uds_permissions()
        assert r.status == "PASS"

    def test_warn_644(self, monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
        sock = tmp_path / "test.sock"
        sock.touch()
        sock.chmod(0o644)
        monkeypatch.setenv("CS_UDS_PATH", str(sock))
        r = check_uds_permissions()
        assert r.status == "WARN"


# ===== THRESHOLD_ORDERING =====

class TestThresholdOrdering:
    def test_pass_defaults(self) -> None:
        r = check_threshold_ordering()
        assert r.status == "PASS"

    def test_pass_custom_ordered(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CS_THRESHOLD_MEDIUM", "1.0")
        monkeypatch.setenv("CS_THRESHOLD_HIGH", "2.0")
        monkeypatch.setenv("CS_THRESHOLD_CRITICAL", "3.0")
        r = check_threshold_ordering()
        assert r.status == "PASS"

    def test_fail_reversed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CS_THRESHOLD_MEDIUM", "3.0")
        monkeypatch.setenv("CS_THRESHOLD_HIGH", "2.0")
        monkeypatch.setenv("CS_THRESHOLD_CRITICAL", "1.0")
        r = check_threshold_ordering()
        assert r.status == "FAIL"

    def test_fail_non_numeric(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CS_THRESHOLD_MEDIUM", "abc")
        r = check_threshold_ordering()
        assert r.status == "FAIL"


# ===== WEIGHT_BOUNDS =====

class TestWeightBounds:
    def test_pass_defaults(self) -> None:
        r = check_weight_bounds()
        assert r.status == "PASS"

    def test_pass_all_positive(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CS_COMPOSITE_WEIGHT_MAX_D123", "0.5")
        monkeypatch.setenv("CS_COMPOSITE_WEIGHT_D4", "0.3")
        r = check_weight_bounds()
        assert r.status == "PASS"

    def test_fail_negative(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CS_COMPOSITE_WEIGHT_D4", "-1.0")
        r = check_weight_bounds()
        assert r.status == "FAIL"

    def test_fail_invalid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CS_COMPOSITE_WEIGHT_D4", "not_a_number")
        r = check_weight_bounds()
        assert r.status == "FAIL"


# ===== LLM_CONFIG =====

class TestLlmConfig:
    def test_pass_nothing_configured(self) -> None:
        r = check_llm_config()
        assert r.status == "PASS"

    def test_pass_provider_and_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CS_LLM_PROVIDER", "anthropic")
        monkeypatch.setenv("CS_LLM_API_KEY", "sk-test")
        r = check_llm_config()
        assert r.status == "PASS"

    def test_warn_provider_no_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CS_LLM_PROVIDER", "anthropic")
        r = check_llm_config()
        assert r.status == "WARN"

    def test_pass_anthropic_key_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CS_LLM_PROVIDER", "anthropic")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
        r = check_llm_config()
        assert r.status == "PASS"


# ===== OPENCLAW_SECRET =====

class TestOpenclawSecret:
    def test_pass_not_configured(self) -> None:
        r = check_openclaw_secret()
        assert r.status == "PASS"

    def test_pass_both_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CS_OPENCLAW_TOKEN", "tok")
        monkeypatch.setenv("CS_OPENCLAW_WEBHOOK_SECRET", "secret")
        r = check_openclaw_secret()
        assert r.status == "PASS"

    def test_warn_token_no_secret(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CS_OPENCLAW_TOKEN", "tok")
        r = check_openclaw_secret()
        assert r.status == "WARN"


# ===== LISTEN_ADDRESS =====

class TestListenAddress:
    def test_pass_localhost(self) -> None:
        r = check_listen_address()
        assert r.status == "PASS"

    def test_pass_explicit_localhost(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CS_HTTP_HOST", "127.0.0.1")
        r = check_listen_address()
        assert r.status == "PASS"

    def test_warn_wildcard(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CS_HTTP_HOST", "0.0.0.0")
        r = check_listen_address()
        assert r.status == "WARN"

    def test_pass_ipv6_localhost(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CS_HTTP_HOST", "::1")
        r = check_listen_address()
        assert r.status == "PASS"


# ===== WHITELIST_REGEX =====

class TestWhitelistRegex:
    def test_pass_empty(self) -> None:
        r = check_whitelist_regex()
        assert r.status == "PASS"

    def test_pass_valid_patterns(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CS_POST_ACTION_WHITELIST", r"^/tmp/.*,\.log$")
        r = check_whitelist_regex()
        assert r.status == "PASS"

    def test_fail_invalid_pattern(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CS_POST_ACTION_WHITELIST", "[invalid")
        r = check_whitelist_regex()
        assert r.status == "FAIL"


# ===== L2_BUDGET =====

class TestL2Budget:
    def test_pass_default(self) -> None:
        r = check_l2_budget()
        assert r.status == "PASS"

    def test_pass_positive(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CS_L2_BUDGET_MS", "3000")
        r = check_l2_budget()
        assert r.status == "PASS"

    def test_fail_zero(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CS_L2_BUDGET_MS", "0")
        r = check_l2_budget()
        assert r.status == "FAIL"

    def test_fail_negative(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CS_L2_BUDGET_MS", "-100")
        r = check_l2_budget()
        assert r.status == "FAIL"

    def test_fail_non_numeric(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CS_L2_BUDGET_MS", "abc")
        r = check_l2_budget()
        assert r.status == "FAIL"


# ===== TRAJECTORY_DB =====

class TestTrajectoryDb:
    def test_pass_writable_dir(self, monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
        db = tmp_path / "test.db"
        monkeypatch.setenv("CS_TRAJECTORY_DB_PATH", str(db))
        r = check_trajectory_db()
        assert r.status == "PASS"

    def test_warn_nonexistent_dir(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CS_TRAJECTORY_DB_PATH",
                           "/nonexistent/dir/test.db")
        r = check_trajectory_db()
        assert r.status == "WARN"


# ===== DEFER_BRIDGE =====

class TestDeferBridge:
    def test_check_defer_bridge_enabled(self) -> None:
        """No env vars set -> PASS with 'bridge enabled'."""
        from unittest.mock import patch
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CS_DEFER_BRIDGE_ENABLED", None)
            os.environ.pop("CS_DEFER_TIMEOUT_ACTION", None)
            os.environ.pop("CS_DEFER_TIMEOUT_S", None)
            r = check_defer_bridge()
        assert r.status == "PASS"
        assert r.check_id == "DEFER_BRIDGE"
        assert "bridge enabled" in r.message.lower()

    def test_check_defer_bridge_disabled(self) -> None:
        """CS_DEFER_BRIDGE_ENABLED=false -> PASS with 'disabled'."""
        from unittest.mock import patch
        with patch.dict(os.environ, {"CS_DEFER_BRIDGE_ENABLED": "false"}):
            r = check_defer_bridge()
        assert r.status == "PASS"
        assert "disabled" in r.message.lower()


# ===== HUB_BRIDGE =====

class TestHubBridge:
    def test_check_hub_bridge_disabled(self) -> None:
        """CS_HUB_BRIDGE_ENABLED=false -> PASS with 'disabled'."""
        from unittest.mock import patch
        with patch.dict(os.environ, {"CS_HUB_BRIDGE_ENABLED": "false"}):
            r = check_hub_bridge()
        assert r.status == "PASS"
        assert "disabled" in r.message.lower()


# ===== Integration =====

class TestRunAllChecks:
    def test_returns_all_checks(self) -> None:
        from clawsentry.cli.doctor_command import ALL_CHECKS
        results = run_all_checks()
        assert len(results) == len(ALL_CHECKS)

    def test_all_have_check_id(self) -> None:
        from clawsentry.cli.doctor_command import ALL_CHECKS
        results = run_all_checks()
        ids = [r.check_id for r in results]
        assert len(set(ids)) == len(ALL_CHECKS)  # all unique


class TestExitCode:
    def test_all_pass(self) -> None:
        results = [DoctorCheck("X", "PASS", "ok")]
        assert compute_exit_code(results) == 0

    def test_has_fail(self) -> None:
        results = [
            DoctorCheck("X", "PASS", "ok"),
            DoctorCheck("Y", "FAIL", "bad"),
        ]
        assert compute_exit_code(results) == 1

    def test_warn_only(self) -> None:
        results = [
            DoctorCheck("X", "PASS", "ok"),
            DoctorCheck("Y", "WARN", "hmm"),
        ]
        assert compute_exit_code(results) == 2

    def test_fail_trumps_warn(self) -> None:
        results = [
            DoctorCheck("X", "WARN", "hmm"),
            DoctorCheck("Y", "FAIL", "bad"),
        ]
        assert compute_exit_code(results) == 1


class TestFormatTable:
    def test_contains_check_ids(self) -> None:
        results = [DoctorCheck("FOO", "PASS", "ok")]
        out = format_table(results, color=False)
        assert "FOO" in out
        assert "PASS" in out

    def test_no_color(self) -> None:
        results = [DoctorCheck("FOO", "FAIL", "bad")]
        out = format_table(results, color=False)
        assert "\033[" not in out

    def test_color_present(self) -> None:
        results = [DoctorCheck("FOO", "FAIL", "bad")]
        out = format_table(results, color=True)
        assert "\033[31m" in out  # red for FAIL


class TestFormatJson:
    def test_valid_json(self) -> None:
        results = [DoctorCheck("FOO", "PASS", "ok", "detail")]
        out = format_json(results)
        data = json.loads(out)
        assert len(data) == 1
        assert data[0]["check_id"] == "FOO"
        assert data[0]["status"] == "PASS"
        assert data[0]["detail"] == "detail"


class TestRunDoctor:
    def test_json_mode(self, capsys: pytest.CaptureFixture[str]) -> None:
        code = run_doctor(json_mode=True, color=False)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        from clawsentry.cli.doctor_command import ALL_CHECKS
        assert len(data) == len(ALL_CHECKS)
        assert isinstance(code, int)

    def test_table_mode(self, capsys: pytest.CaptureFixture[str]) -> None:
        code = run_doctor(json_mode=False, color=False)
        captured = capsys.readouterr()
        assert "ClawSentry Doctor Report" in captured.out
        assert isinstance(code, int)

    def test_all_pass_exit_0(self, monkeypatch: pytest.MonkeyPatch,
                              capsys: pytest.CaptureFixture[str],
                              tmp_path) -> None:
        from unittest import mock
        # Set up env for all-pass scenario
        monkeypatch.setenv("CS_AUTH_TOKEN",
                           "aB3xY7mN9pQ2kL5wR8vZ1cD4fG6hJ0tE")  # 33 chars, high entropy
        monkeypatch.setenv("CS_UDS_PATH", str(tmp_path / "no.sock"))
        monkeypatch.setenv("CS_TRAJECTORY_DB_PATH",
                           str(tmp_path / "test.db"))
        # Mock Latch binary as installed + executable, and hub as healthy
        fake_binary = tmp_path / "latch"
        fake_binary.write_text("#!/bin/sh\necho ok")
        fake_binary.chmod(0o755)
        mock_resp = mock.MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = mock.MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = mock.MagicMock(return_value=False)
        with mock.patch(
            "clawsentry.latch.binary_manager.BinaryManager.is_installed",
            new_callable=mock.PropertyMock, return_value=True,
        ), mock.patch(
            "clawsentry.latch.binary_manager.BinaryManager.binary_path",
            new_callable=mock.PropertyMock, return_value=fake_binary,
        ), mock.patch(
            "urllib.request.urlopen", return_value=mock_resp,
        ):
            code = run_doctor(json_mode=False, color=False)
        assert code == 0

    def test_fail_exit_1(self, monkeypatch: pytest.MonkeyPatch,
                          capsys: pytest.CaptureFixture[str]) -> None:
        monkeypatch.setenv("CS_L2_BUDGET_MS", "-1")
        code = run_doctor(json_mode=False, color=False)
        assert code == 1

    def test_warn_exit_2(self, monkeypatch: pytest.MonkeyPatch,
                          capsys: pytest.CaptureFixture[str],
                          tmp_path) -> None:
        # All PASS except listen address WARN
        monkeypatch.setenv("CS_AUTH_TOKEN",
                           "aB3xY7mN9pQ2kL5wR8vZ1cD4fG6hJ0t")
        monkeypatch.setenv("CS_HTTP_HOST", "0.0.0.0")
        monkeypatch.setenv("CS_UDS_PATH", str(tmp_path / "no.sock"))
        monkeypatch.setenv("CS_TRAJECTORY_DB_PATH",
                           str(tmp_path / "test.db"))
        code = run_doctor(json_mode=False, color=False)
        assert code == 2
