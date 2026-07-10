"""Gateway capability narrowing profiles and summaries."""

from __future__ import annotations

from clawsentry.gateway.config.detection_config import DetectionConfig
from clawsentry.gateway.models import (
    SessionScopeBaseRules,
    SessionScopeProfile,
    SessionScopeTaskRules,
)
from clawsentry.gateway.policy.tool_permissions import resolve_tool_permission

_CAPABILITY_NARROWING_READONLY_TOOLS = (
    "read_file",
    "list_dir",
    "search",
    "grep",
    "glob",
    "list_files",
    "read",
    "find",
    "cat",
    "head",
    "tail",
)
_CAPABILITY_NARROWING_DENIED_TOOLS = (
    "write_file",
    "edit_file",
    "create_file",
    "edit",
    "write",
    "bash",
    "shell",
    "terminal",
    "command",
    "exec",
    "http_request",
    "fetch",
    "web_fetch",
    "install_package",
)


def _capability_narrowing_profile(
    reason_code: str,
    config: DetectionConfig | None = None,
) -> SessionScopeProfile:
    """Build a Gateway-enforced scope profile for critical session risk."""

    allowed_groups = (
        tuple(config.capability_narrowing_allowed_tool_permission_groups)
        if config is not None
        else ("read_only",)
    )
    denied_groups = (
        tuple(config.capability_narrowing_denied_tool_permission_groups)
        if config is not None
        else ("write", "network", "credentialed", "destructive", "mcp_admin", "unknown")
    )
    denied_tools = [
        tool
        for tool in _CAPABILITY_NARROWING_DENIED_TOOLS
        if resolve_tool_permission(tool).group in denied_groups
    ]
    greylist_action = (
        str(
            (
                config.capability_narrowing_greylist_action
                if config is not None
                else "defer"
            )
            or "defer"
        )
        .strip()
        .lower()
    )
    denied_skill_trust_states = (
        list(config.capability_narrowing_denied_skill_trust_states)
        if config is not None
        else ["blacklist", "revoked"]
    )
    allowed_skill_trust_states = (
        list(config.capability_narrowing_allowed_skill_trust_states)
        if config is not None
        else ["allowlist"]
    )
    if greylist_action == "block":
        denied_skill_trust_states.append("greylist")
    elif greylist_action == "allow":
        allowed_skill_trust_states.append("greylist")
    denied_skill_trust_states = list(dict.fromkeys(denied_skill_trust_states))
    allowed_skill_trust_states = list(dict.fromkeys(allowed_skill_trust_states))
    denied_mcp_servers = (
        list(config.capability_narrowing_denied_mcp_servers)
        if config is not None
        else []
    )
    denied_mcp_tools = (
        list(config.capability_narrowing_denied_mcp_tools)
        if config is not None
        else ["fetch.fetch"]
    )
    denied_mcp_statuses = (
        list(config.capability_narrowing_denied_mcp_statuses)
        if config is not None
        else ["blacklist", "revoked", "disabled"]
    )
    denied_mcp_trust_levels = (
        list(config.capability_narrowing_denied_mcp_trust_levels)
        if config is not None
        else ["untrusted", "unknown", "local_unreviewed"]
    )
    allowed_mcp_servers = (
        list(config.capability_narrowing_allowed_mcp_servers)
        if config is not None
        else []
    )
    allowed_mcp_tools = (
        list(config.capability_narrowing_allowed_mcp_tools)
        if config is not None
        else ["filesystem.read_file"]
    )
    allowed_mcp_statuses = (
        list(config.capability_narrowing_allowed_mcp_statuses)
        if config is not None
        else []
    )
    allowed_mcp_trust_levels = (
        list(config.capability_narrowing_allowed_mcp_trust_levels)
        if config is not None
        else []
    )
    denied_capabilities = (
        list(config.capability_narrowing_denied_capabilities)
        if config is not None
        else []
    )
    allowed_capabilities = (
        list(config.capability_narrowing_allowed_capabilities)
        if config is not None
        else []
    )
    queued_capabilities = (
        list(config.capability_narrowing_queued_capabilities)
        if config is not None
        else []
    )
    return SessionScopeProfile(
        profile_id=f"capability-narrowing:{reason_code}",
        confirmed=True,
        dry_run=False,
        base_rules=SessionScopeBaseRules(
            denied_tools=denied_tools,
            denied_skill_trust_states=denied_skill_trust_states,
            denied_mcp_servers=denied_mcp_servers,
            denied_mcp_tools=denied_mcp_tools,
            denied_mcp_statuses=denied_mcp_statuses,
            denied_mcp_trust_levels=denied_mcp_trust_levels,
            denied_capabilities=denied_capabilities,
            denied_tool_permission_groups=list(denied_groups),
            denied_command_prefixes=[
                "rm ",
                "sudo ",
                "chmod ",
                "curl ",
                "wget ",
            ],
        ),
        task_rules=SessionScopeTaskRules(
            allowed_tools=list(_CAPABILITY_NARROWING_READONLY_TOOLS),
            allowed_tool_permission_groups=list(allowed_groups),
            allowed_skill_trust_states=allowed_skill_trust_states,
            allowed_mcp_servers=allowed_mcp_servers,
            allowed_mcp_tools=allowed_mcp_tools,
            allowed_mcp_statuses=allowed_mcp_statuses,
            allowed_mcp_trust_levels=allowed_mcp_trust_levels,
            allowed_capabilities=allowed_capabilities,
            queued_capabilities=queued_capabilities,
            queued_categories=["network"],
        ),
    )


def _capability_narrowing_policy_summary(
    config: DetectionConfig,
) -> dict[str, list[str]]:
    return {
        "allowed_tool_permission_groups": list(
            config.capability_narrowing_allowed_tool_permission_groups
        ),
        "denied_tool_permission_groups": list(
            config.capability_narrowing_denied_tool_permission_groups
        ),
        "allowed_skill_trust_states": list(
            config.capability_narrowing_allowed_skill_trust_states
        ),
        "denied_skill_trust_states": list(
            config.capability_narrowing_denied_skill_trust_states
        ),
        "allowed_mcp_servers": list(config.capability_narrowing_allowed_mcp_servers),
        "denied_mcp_servers": list(config.capability_narrowing_denied_mcp_servers),
        "allowed_mcp_tools": list(config.capability_narrowing_allowed_mcp_tools),
        "denied_mcp_tools": list(config.capability_narrowing_denied_mcp_tools),
        "allowed_mcp_statuses": list(config.capability_narrowing_allowed_mcp_statuses),
        "denied_mcp_statuses": list(config.capability_narrowing_denied_mcp_statuses),
        "allowed_mcp_trust_levels": list(
            config.capability_narrowing_allowed_mcp_trust_levels
        ),
        "denied_mcp_trust_levels": list(
            config.capability_narrowing_denied_mcp_trust_levels
        ),
        "allowed_capabilities": list(config.capability_narrowing_allowed_capabilities),
        "denied_capabilities": list(config.capability_narrowing_denied_capabilities),
        "queued_capabilities": list(config.capability_narrowing_queued_capabilities),
    }
