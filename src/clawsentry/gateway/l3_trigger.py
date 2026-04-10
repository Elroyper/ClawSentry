"""Deterministic L3 trigger policy for Phase 5.2."""

from __future__ import annotations

import json
import ast
import re
import shlex
from typing import Any

from .models import CanonicalEvent, DecisionContext, RiskLevel, RiskSnapshot


_RISK_LEVEL_SCORE = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}

_HIGH_RISK_TOOLS = frozenset({
    "bash", "shell", "exec", "sudo", "chmod", "chown", "write", "edit",
    "write_file", "edit_file", "create_file",
})

_MANUAL_FLAGS = ("l3_escalate", "force_l3", "manual_l3_escalation")
_CUMULATIVE_THRESHOLD = 5
_COMPLEX_PAYLOAD_LENGTH = 512
_COMPLEX_PAYLOAD_DEPTH = 3
_COMPLEX_PAYLOAD_KEYS = 6
_READ_TOOLS = frozenset({"read_file", "read", "cat", "head", "tail"})
_WRITE_TOOLS = frozenset({
    "write_file", "edit_file", "create_file", "write", "edit", "chmod", "chown",
})
_EXEC_TOOLS = frozenset({"bash", "shell", "exec", "sudo"})
_NETWORK_TOOLS = frozenset({"http_request", "fetch", "web_fetch"})
_CREDENTIAL_HINTS = frozenset({
    "credential_access",
    "credential_exfiltration",
    "credential_exfiltration_confirmed",
    "secret_access",
    "key_access",
    "env_access",
    "config_access",
})
_NETWORK_HINTS = frozenset({
    "data_exfiltration",
    "network_exfiltration",
    "suspicious_network",
})
_SENSITIVE_TOKENS = (
    ".env",
    ".pem",
    ".key",
    ".ssh",
    "id_rsa",
    "credentials",
    "secret",
    "token",
    "password",
    "api_key",
)
_NETWORK_TOKENS = (
    "curl",
    "wget",
    "http://",
    "https://",
    "scp",
    "rsync",
    "nc ",
    "ncat",
    "socat",
    "dig ",
    "nslookup",
)
_TMP_TOKENS = (
    "/tmp/",
    "/var/tmp/",
)
_STAGING_TOKENS = (
    "cp ",
    "mv ",
    "tee ",
    "tar ",
    "zip ",
    "gzip ",
    "base64 ",
    ">",
)
_ARCHIVE_TOKENS = (
    "tar ",
    "zip ",
    "gzip ",
    "base64 ",
)
_BASE64_DECODE_TOKENS = (
    "base64 -d",
    "base64 --decode",
    "base64 -d ",
    "base64 --decode ",
)
_ARCHIVE_RESTORE_TOKENS = (
    "tar -x",
    "tar x",
    "tar --extract",
    "unzip ",
    "gunzip ",
    "gzip -d",
    "gzip --decompress",
)
_ARCHIVE_INSPECTION_TOKENS = (
    "tar -t",
    "tar t",
    "tar --list",
    "gzip -l",
    "gzip -t",
    "gzip --list",
    "gzip --test",
    "zip -t",
    "zip --test",
    "zip -sf",
    "zip --show-files",
)
_SHELL_PREFIX_TOKENS = frozenset({"sudo", "command", "builtin", "env", "nohup", "time", "stdbuf"})
_SHELL_WRAPPER_TOKENS = frozenset({"bash", "sh", "zsh", "dash"})
_PYTHON_SUBPROCESS_CALLS = frozenset({
    "run", "call", "popen", "check_call", "check_output", "getoutput", "getstatusoutput",
})
_ENV_ASSIGNMENT_PATTERN = re.compile(r"^[a-z_][a-z0-9_]*=.*$", re.IGNORECASE)
_RECON_TOKENS = (
    "whoami",
    "id",
    "uname",
    "hostname",
    "printenv",
    "env",
    "/etc/os-release",
    "ps -",
    "ss -",
    "ifconfig",
    "ip addr",
)


class L3TriggerPolicy:
    """Decide when to escalate from L2 to L3 deep review."""

    def trigger_metadata(
        self,
        event: CanonicalEvent,
        context: DecisionContext | None,
        l1_snapshot: RiskSnapshot,
        session_risk_history: list[Any],
    ) -> dict[str, str] | None:
        if self._has_manual_flag(context):
            return {"trigger_reason": "manual_l3_escalate"}
        pattern_detail = self._suspicious_pattern_detail(event, session_risk_history)
        if pattern_detail is not None:
            return {
                "trigger_reason": "suspicious_pattern",
                "trigger_detail": pattern_detail,
            }
        if self._cumulative_risk_score(session_risk_history, l1_snapshot) >= _CUMULATIVE_THRESHOLD:
            return {"trigger_reason": "cumulative_risk"}
        if self._is_high_risk_tool(event) and self._payload_complexity(event.payload or {}):
            return {"trigger_reason": "high_risk_complex_payload"}
        return None

    def trigger_reason(
        self,
        event: CanonicalEvent,
        context: DecisionContext | None,
        l1_snapshot: RiskSnapshot,
        session_risk_history: list[Any],
    ) -> str | None:
        metadata = self.trigger_metadata(event, context, l1_snapshot, session_risk_history)
        return None if metadata is None else metadata["trigger_reason"]

    def should_trigger(
        self,
        event: CanonicalEvent,
        context: DecisionContext | None,
        l1_snapshot: RiskSnapshot,
        session_risk_history: list[Any],
    ) -> bool:
        return self.trigger_metadata(event, context, l1_snapshot, session_risk_history) is not None

    def _has_manual_flag(self, context: DecisionContext | None) -> bool:
        if context is None or not isinstance(context.session_risk_summary, dict):
            return False
        return any(bool(context.session_risk_summary.get(flag)) for flag in _MANUAL_FLAGS)

    def _cumulative_risk_score(self, history: list[Any], current: RiskSnapshot) -> int:
        total = 0
        for item in history:
            level = self._extract_risk_level(item)
            total += _RISK_LEVEL_SCORE.get(level, 0)
        total += _RISK_LEVEL_SCORE.get(current.risk_level, 0)
        return total

    def _extract_risk_level(self, item: Any) -> Any:
        if isinstance(item, RiskSnapshot):
            return item.risk_level
        if isinstance(item, dict):
            if "risk_level" in item:
                return str(item.get("risk_level") or "").lower()
            decision = item.get("decision", {})
            if isinstance(decision, dict):
                return str(decision.get("risk_level") or "").lower()
        return None

    def _is_high_risk_tool(self, event: CanonicalEvent) -> bool:
        return str(event.tool_name or "").lower() in _HIGH_RISK_TOOLS

    def _detect_suspicious_pattern(
        self,
        event: CanonicalEvent,
        history: list[Any],
    ) -> bool:
        return self._suspicious_pattern_detail(event, history) is not None

    def _suspicious_pattern_detail(
        self,
        event: CanonicalEvent,
        history: list[Any],
    ) -> str | None:
        signals = [self._history_event_signal(item) for item in history]
        signals.append(self._event_signal(event))

        if len(signals) < 2:
            return None

        if self._has_secret_plus_network_pattern(signals):
            return "secret_plus_network"
        if self._has_privilege_escalation_chain(signals):
            return "privilege_escalation_chain"
        if self._has_tmp_staging_exfil_pattern(signals):
            return "tmp_staging_exfil"
        if self._has_recon_then_sudo_pattern(signals):
            return "recon_then_sudo"
        if self._has_secret_harvest_archive_pattern(signals):
            return "secret_harvest_archive"
        return None

    def _history_event_signal(self, item: Any) -> dict[str, bool]:
        if isinstance(item, dict):
            event = item.get("event", {})
            if isinstance(event, dict):
                return self._event_signal(
                    CanonicalEvent(
                        event_id=str(event.get("event_id") or "history"),
                        trace_id=str(event.get("trace_id") or "history"),
                        event_type=event.get("event_type") or "pre_action",
                        session_id=str(event.get("session_id") or "history"),
                        agent_id=str(event.get("agent_id") or "history"),
                        source_framework=str(event.get("source_framework") or "history"),
                        occurred_at=str(event.get("occurred_at") or "2026-01-01T00:00:00+00:00"),
                        payload=event.get("payload") if isinstance(event.get("payload"), dict) else {},
                        tool_name=event.get("tool_name"),
                        risk_hints=event.get("risk_hints") if isinstance(event.get("risk_hints"), list) else [],
                    )
                )
        return {
            "credential_access": False,
            "network_activity": False,
            "read_action": False,
            "write_action": False,
            "exec_action": False,
            "sudo_action": False,
            "tmp_staging": False,
            "tmp_exfil": False,
            "recon_action": False,
            "archive_action": False,
            "archive_sensitive_material": False,
        }

    def _event_signal(self, event: CanonicalEvent) -> dict[str, bool]:
        tool_name = str(event.tool_name or "").lower()
        payload_text = self._payload_text(event.payload or {})
        command_text = self._command_text(event.payload or {}, payload_text)
        hints = {str(h).lower() for h in (event.risk_hints or [])}

        credential_access = (
            bool(hints.intersection(_CREDENTIAL_HINTS))
            or tool_name in _READ_TOOLS
            and any(token in payload_text for token in _SENSITIVE_TOKENS)
        )
        network_activity = (
            tool_name in _NETWORK_TOOLS
            or bool(hints.intersection(_NETWORK_HINTS))
            or any(token in payload_text for token in _NETWORK_TOKENS)
        )
        tmp_path_touched = any(token in payload_text for token in _TMP_TOKENS)
        staging_activity = tool_name in _WRITE_TOOLS or any(token in payload_text for token in _STAGING_TOKENS)
        recon_action = (
            tool_name in _READ_TOOLS
            or tool_name in _EXEC_TOOLS
            or tool_name == "bash"
        ) and any(token in payload_text for token in _RECON_TOKENS)
        archive_restore_action = self._is_archive_restore_action(command_text)
        archive_inspection_action = self._is_archive_inspection_action(command_text)
        archive_action = (
            tool_name in _EXEC_TOOLS
            and any(self._matches_shell_command_token(command_text, token) for token in _ARCHIVE_TOKENS)
            and not archive_restore_action
            and not archive_inspection_action
        )
        archive_sensitive_material = archive_action and any(
            token in payload_text for token in _SENSITIVE_TOKENS
        )

        return {
            "credential_access": credential_access,
            "network_activity": network_activity,
            "read_action": tool_name in _READ_TOOLS,
            "write_action": tool_name in _WRITE_TOOLS,
            "exec_action": tool_name in _EXEC_TOOLS or "chmod" in payload_text or "install " in payload_text,
            "sudo_action": tool_name == "sudo" or "sudo " in payload_text,
            "tmp_staging": tmp_path_touched and staging_activity,
            "tmp_exfil": tmp_path_touched and network_activity,
            "recon_action": recon_action,
            "archive_action": archive_action,
            "archive_sensitive_material": archive_sensitive_material,
        }

    def _is_archive_restore_action(self, command_text: str) -> bool:
        return any(self._matches_shell_command_token(command_text, token) for token in _BASE64_DECODE_TOKENS) or any(
            self._matches_shell_command_token(command_text, token) for token in _ARCHIVE_RESTORE_TOKENS
        )

    def _is_archive_inspection_action(self, command_text: str) -> bool:
        return any(self._matches_shell_command_token(command_text, token) for token in _ARCHIVE_INSPECTION_TOKENS)

    def _command_text(self, payload: dict[str, Any], payload_text: str) -> str:
        command = payload.get("command") if isinstance(payload, dict) else None
        if isinstance(command, str):
            return command.lower()
        return payload_text

    def _matches_command_token(self, payload_text: str, token: str) -> bool:
        pattern = re.compile(rf"(?<![a-z0-9_-]){re.escape(token)}")
        return pattern.search(payload_text) is not None

    def _matches_shell_command_token(self, command_text: str, token: str) -> bool:
        for segment in self._shell_command_segments(command_text):
            head = self._shell_command_head(segment)
            if head.startswith(token):
                return True
        return False

    def _shell_command_segments(self, command_text: str) -> list[str]:
        segments: list[str] = []
        current: list[str] = []
        quote: str | None = None
        escaped = False
        i = 0

        while i < len(command_text):
            ch = command_text[i]

            if escaped:
                current.append(ch)
                escaped = False
                i += 1
                continue

            if quote is not None:
                current.append(ch)
                if ch == "\\" and quote == '"':
                    escaped = True
                elif ch == quote:
                    quote = None
                i += 1
                continue

            if ch in {'"', "'"}:
                quote = ch
                current.append(ch)
                i += 1
                continue

            if command_text.startswith("&&", i) or command_text.startswith("||", i):
                segments.append("".join(current))
                current = []
                i += 2
                continue

            if ch in {";", "|"}:
                segments.append("".join(current))
                current = []
                i += 1
                continue

            current.append(ch)
            i += 1

        segments.append("".join(current))
        return segments

    def _shell_command_head(self, segment: str) -> str:
        parts = self._split_shell_segment(segment)
        idx = 0

        while idx < len(parts):
            part = parts[idx]
            if _ENV_ASSIGNMENT_PATTERN.match(part):
                idx += 1
                continue
            if part in _SHELL_PREFIX_TOKENS:
                idx += 1
                if part == "env":
                    while idx < len(parts) and _ENV_ASSIGNMENT_PATTERN.match(parts[idx]):
                        idx += 1
                continue
            break

        if idx < len(parts) and parts[idx] in _SHELL_WRAPPER_TOKENS:
            wrapped_command = self._extract_shell_wrapper_command(parts[idx + 1:])
            if wrapped_command is not None:
                return self._shell_command_head(wrapped_command)

        if idx < len(parts) and self._is_python_launcher(parts[idx]):
            wrapped_command = self._extract_python_launcher_command(parts[idx + 1:])
            if wrapped_command is not None:
                return self._shell_command_head(wrapped_command)

        return " ".join(parts[idx:])

    def _split_shell_segment(self, segment: str) -> list[str]:
        try:
            return shlex.split(segment, posix=True)
        except ValueError:
            return segment.strip().split()

    def _extract_shell_wrapper_command(self, args: list[str]) -> str | None:
        idx = 0
        while idx < len(args):
            arg = args[idx]
            if arg == "--":
                break
            if not arg.startswith("-"):
                return None
            if self._shell_option_runs_command(arg):
                if idx + 1 < len(args):
                    return args[idx + 1]
                return ""
            idx += 1
        return None

    def _shell_option_runs_command(self, arg: str) -> bool:
        if not arg.startswith("-") or arg.startswith("--"):
            return False
        return "c" in arg[1:]

    def _is_python_launcher(self, command: str) -> bool:
        if command == "python" or command == "python3":
            return True
        return bool(re.fullmatch(r"python\d+(?:\.\d+)?", command))

    def _extract_python_launcher_command(self, args: list[str]) -> str | None:
        idx = 0
        while idx < len(args):
            arg = args[idx]
            if arg == "--":
                break
            if arg == "-c":
                if idx + 1 < len(args):
                    return self._extract_python_command_from_code(args[idx + 1])
                return ""
            idx += 1
        return None

    def _extract_python_command_from_code(self, code: str) -> str | None:
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return None

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            command = self._python_call_command(node)
            if command is not None:
                return command
        return None

    def _python_call_command(self, node: ast.Call) -> str | None:
        func = node.func
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            if func.value.id == "os" and func.attr in {"system", "popen"}:
                return self._python_arg_to_command(node.args[0]) if node.args else None
            if func.value.id == "os" and func.attr == "execl":
                return self._python_args_to_command(node.args[1:])
            if func.value.id == "os" and func.attr == "execlp":
                return self._python_args_to_command(node.args[1:])
            if func.value.id == "os" and func.attr == "execle":
                return self._python_args_to_command_with_trailing_env(node.args[1:])
            if func.value.id == "os" and func.attr == "execv":
                return self._python_arg_to_command(node.args[1]) if len(node.args) > 1 else None
            if func.value.id == "os" and func.attr == "execve":
                return self._python_arg_to_command(node.args[1]) if len(node.args) > 1 else None
            if func.value.id == "os" and func.attr == "execvpe":
                return self._python_arg_to_command(node.args[1]) if len(node.args) > 1 else None
            if func.value.id == "os" and func.attr == "execvp":
                return self._python_arg_to_command(node.args[1]) if len(node.args) > 1 else None
            if func.value.id == "os" and func.attr == "spawnl":
                return self._python_args_to_command(node.args[2:])
            if func.value.id == "os" and func.attr == "spawnlp":
                return self._python_args_to_command(node.args[2:])
            if func.value.id == "os" and func.attr == "spawnle":
                return self._python_args_to_command_with_trailing_env(node.args[2:])
            if func.value.id == "os" and func.attr == "spawnv":
                return self._python_arg_to_command(node.args[2]) if len(node.args) > 2 else None
            if func.value.id == "os" and func.attr == "spawnve":
                return self._python_arg_to_command(node.args[2]) if len(node.args) > 2 else None
            if func.value.id == "os" and func.attr == "spawnvpe":
                return self._python_arg_to_command(node.args[2]) if len(node.args) > 2 else None
            if func.value.id == "os" and func.attr == "spawnvp":
                return self._python_arg_to_command(node.args[2]) if len(node.args) > 2 else None
            if func.value.id == "subprocess" and func.attr.lower() in _PYTHON_SUBPROCESS_CALLS:
                return self._python_arg_to_command(node.args[0]) if node.args else None
        return None

    def _python_arg_to_command(self, arg: ast.AST) -> str | None:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            return arg.value
        if isinstance(arg, (ast.List, ast.Tuple)):
            parts: list[str] = []
            for elt in arg.elts:
                if not isinstance(elt, ast.Constant) or not isinstance(elt.value, str):
                    return None
                parts.append(elt.value)
            return shlex.join(parts)
        return None

    def _python_args_to_command(self, args: list[ast.AST]) -> str | None:
        if not args:
            return None
        parts: list[str] = []
        for arg in args:
            if not isinstance(arg, ast.Constant) or not isinstance(arg.value, str):
                return None
            parts.append(arg.value)
        return shlex.join(parts)

    def _python_args_to_command_with_trailing_env(self, args: list[ast.AST]) -> str | None:
        if len(args) < 2 or not isinstance(args[-1], ast.Dict):
            return None
        return self._python_args_to_command(args[:-1])

    def _has_secret_plus_network_pattern(self, signals: list[dict[str, bool]]) -> bool:
        saw_credential = False
        saw_network = False
        for signal in signals:
            saw_credential = saw_credential or signal["credential_access"]
            saw_network = saw_network or signal["network_activity"]
            if saw_credential and saw_network:
                return True
        return False

    def _has_privilege_escalation_chain(self, signals: list[dict[str, bool]]) -> bool:
        saw_read = False
        saw_write = False
        saw_exec = False
        for signal in signals:
            if signal["read_action"]:
                saw_read = True
            if signal["write_action"] and saw_read:
                saw_write = True
            if signal["exec_action"] and saw_write:
                saw_exec = True
            if signal["sudo_action"] and (saw_write or saw_exec):
                return True
        return False

    def _has_tmp_staging_exfil_pattern(self, signals: list[dict[str, bool]]) -> bool:
        saw_tmp_staging = False
        for signal in signals:
            if signal["tmp_staging"]:
                saw_tmp_staging = True
            if signal["tmp_exfil"] and saw_tmp_staging:
                return True
        return False

    def _has_recon_then_sudo_pattern(self, signals: list[dict[str, bool]]) -> bool:
        saw_recon = False
        for signal in signals:
            if signal["recon_action"]:
                saw_recon = True
            if signal["sudo_action"] and saw_recon:
                return True
        return False

    def _has_secret_harvest_archive_pattern(self, signals: list[dict[str, bool]]) -> bool:
        credential_reads = 0
        for signal in signals:
            if signal["credential_access"]:
                credential_reads += 1
            if signal["archive_sensitive_material"] and credential_reads >= 2:
                return True
        return False

    def _payload_text(self, payload: dict[str, Any]) -> str:
        return json.dumps(payload, ensure_ascii=False, sort_keys=True).lower()

    def _payload_complexity(self, payload: Any) -> bool:
        serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        if len(serialized) >= _COMPLEX_PAYLOAD_LENGTH:
            return True
        if self._max_depth(payload) >= _COMPLEX_PAYLOAD_DEPTH:
            return True
        if isinstance(payload, dict) and len(payload) >= _COMPLEX_PAYLOAD_KEYS:
            return True
        return False

    def _max_depth(self, value: Any, depth: int = 1) -> int:
        if isinstance(value, dict) and value:
            return max(self._max_depth(v, depth + 1) for v in value.values())
        if isinstance(value, list) and value:
            return max(self._max_depth(v, depth + 1) for v in value)
        return depth
