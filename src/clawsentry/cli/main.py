"""Unified CLI entry point for clawsentry."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .initializers import FRAMEWORK_INITIALIZERS


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="clawsentry",
        description="ClawSentry — AHP unified safety supervision framework.",
    )
    sub = parser.add_subparsers(dest="command")

    # --- init ---
    init_parser = sub.add_parser(
        "init",
        help="Initialize framework integration.",
    )
    init_parser.add_argument(
        "framework",
        choices=sorted(FRAMEWORK_INITIALIZERS.keys()),
        help="Target framework to initialize.",
    )
    init_parser.add_argument(
        "--dir",
        type=Path,
        default=Path("."),
        help="Directory to write config files (default: current dir).",
    )
    init_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing config files.",
    )
    init_parser.add_argument(
        "--auto-detect",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Auto-detect existing framework configuration (default: on).",
    )
    init_parser.add_argument(
        "--setup",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Auto-configure framework settings for ClawSentry integration (default: off).",
    )
    init_parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Preview OpenClaw config changes without applying (use with --setup).",
    )
    init_parser.add_argument(
        "--openclaw-home",
        type=Path,
        default=None,
        help="Custom OpenClaw config directory (default: ~/.openclaw/).",
    )
    init_parser.add_argument(
        "--uninstall",
        action="store_true",
        default=False,
        help=(
            "Disable one framework integration in project env and remove "
            "supported framework hooks."
        ),
    )
    init_parser.add_argument(
        "--restore",
        action="store_true",
        default=False,
        help="Restore framework settings from ClawSentry backups (currently OpenClaw).",
    )

    # --- gateway ---
    sub.add_parser(
        "gateway",
        help="Start Supervision Gateway (auto-enables OpenClaw when configured).",
        add_help=False,
    )

    # --- stack ---
    sub.add_parser(
        "stack",
        help="Start full stack (Gateway + OpenClaw). Alias for gateway.",
        add_help=False,
    )

    # --- harness ---
    sub.add_parser(
        "harness",
        help="Start a3s-code stdio harness.",
        add_help=False,
    )

    # --- watch ---
    _watch_port = os.environ.get("CS_HTTP_PORT", "8080")
    _watch_default_url = f"http://127.0.0.1:{_watch_port}"
    watch_parser = sub.add_parser(
        "watch",
        help="Watch real-time SSE events from the Supervision Gateway.",
    )
    watch_parser.add_argument(
        "--gateway-url",
        default=_watch_default_url,
        help=f"Gateway base URL (default: {_watch_default_url}).",
    )
    watch_parser.add_argument(
        "--token",
        default=os.environ.get("CS_AUTH_TOKEN"),
        help="Bearer token for Gateway authentication [CS_AUTH_TOKEN].",
    )
    watch_parser.add_argument(
        "--filter",
        default=None,
        help="Comma-separated event types to subscribe to (e.g. decision,alert).",
    )
    watch_parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output raw JSON instead of formatted text.",
    )
    watch_parser.add_argument(
        "--no-color",
        action="store_true",
        default=False,
        help="Disable ANSI colour codes in output.",
    )
    watch_parser.add_argument(
        "--interactive",
        "-i",
        action="store_true",
        default=False,
        help="Prompt operator to Allow/Deny/Skip on DEFER decisions.",
    )
    watch_parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        default=False,
        help="Show detailed information for all decisions (including ALLOW).",
    )
    watch_parser.add_argument(
        "--no-emoji",
        action="store_true",
        default=False,
        help="Disable emoji (for plain text / narrow terminal environments).",
    )
    watch_parser.add_argument(
        "--compact",
        action="store_true",
        default=False,
        help="Use compact format without Unicode box drawing for session groups.",
    )

    # --- audit ---
    audit_parser = sub.add_parser(
        "audit",
        help="Query offline audit logs from trajectory database.",
    )
    audit_parser.add_argument(
        "--db",
        default=None,
        help="Database path (default: CS_TRAJECTORY_DB_PATH or /tmp/clawsentry-trajectory.db).",
    )
    audit_parser.add_argument(
        "--session",
        default=None,
        help="Filter by session ID.",
    )
    audit_parser.add_argument(
        "--since",
        default=None,
        help="Time window (e.g. 1h, 24h, 7d, 30m).",
    )
    audit_parser.add_argument(
        "--risk",
        default=None,
        choices=["low", "medium", "high", "critical"],
        help="Filter by risk level.",
    )
    audit_parser.add_argument(
        "--decision",
        default=None,
        choices=["allow", "block", "defer", "modify"],
        help="Filter by decision verdict.",
    )
    audit_parser.add_argument(
        "--tool",
        default=None,
        help="Filter by tool name.",
    )
    audit_parser.add_argument(
        "--format",
        default="table",
        choices=["table", "json", "csv"],
        dest="output_format",
        help="Output format (default: table).",
    )
    audit_parser.add_argument(
        "--stats",
        action="store_true",
        default=False,
        help="Show aggregate statistics only.",
    )
    audit_parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Maximum records to return (default: 100).",
    )
    audit_parser.add_argument(
        "--no-color",
        action="store_true",
        default=False,
        help="Disable ANSI colour codes in output.",
    )

    # --- doctor ---
    doc_parser = sub.add_parser(
        "doctor",
        help="Audit configuration for security issues.",
    )
    doc_parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output results as JSON.",
    )
    doc_parser.add_argument(
        "--no-color",
        action="store_true",
        default=False,
        help="Disable ANSI colour codes in output.",
    )

    # --- test-llm ---
    test_llm_parser = sub.add_parser(
        "test-llm",
        help="Test LLM API connectivity, latency, and L2/L3 functionality.",
    )
    test_llm_parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output results as JSON.",
    )
    test_llm_parser.add_argument(
        "--no-color",
        action="store_true",
        default=False,
        help="Disable ANSI colour codes in output.",
    )
    test_llm_parser.add_argument(
        "--skip-l3",
        action="store_true",
        default=False,
        help="Skip L3 agent review test.",
    )

    # --- service ---
    service_parser = sub.add_parser(
        "service",
        help="Manage auto-start system service (systemd/launchd).",
    )
    service_sub = service_parser.add_subparsers(dest="service_command")
    service_install = service_sub.add_parser("install", help="Install and enable auto-start service.")
    service_install.add_argument(
        "--no-enable",
        action="store_true",
        default=False,
        help="Install service file without enabling/starting.",
    )
    service_sub.add_parser("uninstall", help="Stop and remove auto-start service.")
    service_sub.add_parser("status", help="Show service status.")

    # --- config ---
    config_parser = sub.add_parser(
        "config",
        help="Manage project-level .clawsentry.toml configuration.",
    )
    config_sub = config_parser.add_subparsers(dest="config_command")

    config_init = config_sub.add_parser("init", help="Create .clawsentry.toml in current directory.")
    config_init.add_argument("--preset", default="medium", choices=["low", "medium", "high", "strict"])
    config_init.add_argument("--force", action="store_true", default=False)

    config_sub.add_parser("show", help="Show current project config.")

    config_set = config_sub.add_parser("set", help="Change project preset.")
    config_set.add_argument("preset", choices=["low", "medium", "high", "strict"])

    config_sub.add_parser("disable", help="Disable ClawSentry for this project.")
    config_sub.add_parser("enable", help="Enable ClawSentry for this project.")

    # --- rules ---
    rules_parser = sub.add_parser(
        "rules",
        help="Lint and dry-run rule authoring surfaces.",
    )
    rules_sub = rules_parser.add_subparsers(dest="rules_command")
    rules_sub.required = True

    rules_lint = rules_sub.add_parser("lint", help="Validate current rule surfaces.")
    rules_lint.add_argument("--attack-patterns", default=None, help="Path to attack patterns YAML.")
    rules_lint.add_argument("--evolved-patterns", default=None, help="Path to evolved patterns YAML.")
    rules_lint.add_argument("--skills-dir", default=None, help="Directory containing review skill YAML files.")
    rules_lint.add_argument("--json", action="store_true", default=False, help="Output lint report as JSON.")

    rules_dry_run = rules_sub.add_parser("dry-run", help="Dry-run rule matching against sample events.")
    rules_dry_run.add_argument("--events", required=True, help="JSON/JSONL file containing canonical sample events.")
    rules_dry_run.add_argument("--attack-patterns", default=None, help="Path to attack patterns YAML.")
    rules_dry_run.add_argument("--evolved-patterns", default=None, help="Path to evolved patterns YAML.")
    rules_dry_run.add_argument("--skills-dir", default=None, help="Directory containing review skill YAML files.")
    rules_dry_run.add_argument("--json", action="store_true", default=False, help="Output dry-run report as JSON.")

    # --- latch ---
    latch_parser = sub.add_parser(
        "latch",
        help="Manage Latch integration (install/uninstall/start/stop/status).",
    )
    latch_sub = latch_parser.add_subparsers(dest="latch_command")

    latch_install_parser = latch_sub.add_parser("install", help="Download and install Latch binary.")
    latch_install_parser.add_argument(
        "--no-shortcut",
        action="store_true",
        default=False,
        help="Skip desktop shortcut creation after install.",
    )

    _latch_default_gw_port = int(os.environ.get("CS_HTTP_PORT", "8080"))
    latch_start_parser = latch_sub.add_parser("start", help="Start Gateway + Latch Hub.")
    latch_start_parser.add_argument(
        "--gateway-port",
        type=int,
        default=_latch_default_gw_port,
        help=f"Gateway HTTP port (default: {_latch_default_gw_port}).",
    )
    latch_start_parser.add_argument(
        "--hub-port",
        type=int,
        default=3006,
        help="Latch Hub port (default: 3006).",
    )
    latch_start_parser.add_argument(
        "--no-browser",
        action="store_true",
        default=False,
        help="Don't open browser after start.",
    )

    latch_sub.add_parser("stop", help="Stop Gateway + Latch Hub.")
    latch_sub.add_parser("status", help="Show Latch stack status.")

    latch_uninstall_parser = latch_sub.add_parser("uninstall", help="Uninstall Latch binary and data.")
    latch_uninstall_parser.add_argument(
        "--keep-data",
        action="store_true",
        default=False,
        help="Keep data directories (only remove binary and shortcut).",
    )

    # --- integrations ---
    integrations_parser = sub.add_parser(
        "integrations",
        help="Inspect configured framework integrations.",
    )
    integrations_sub = integrations_parser.add_subparsers(dest="integrations_command")
    integrations_status = integrations_sub.add_parser(
        "status",
        help="Show enabled framework integrations.",
    )
    integrations_status.add_argument(
        "--dir",
        type=Path,
        default=Path("."),
        help="Directory containing .env.clawsentry (default: current dir).",
    )
    integrations_status.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output status as JSON.",
    )

    # --- start ---
    start_parser = sub.add_parser(
        "start",
        help="One-command launch: auto-init + gateway (background) + watch (foreground).",
    )
    start_parser.add_argument(
        "--framework",
        choices=sorted(FRAMEWORK_INITIALIZERS.keys()),
        default=None,
        help="Target framework (auto-detected if omitted).",
    )
    start_parser.add_argument(
        "--frameworks",
        default=None,
        help=(
            "Comma-separated frameworks to enable together "
            "(for example: a3s-code,codex,openclaw)."
        ),
    )
    start_parser.add_argument(
        "--setup-openclaw",
        action=argparse.BooleanOptionalAction,
        default=False,
        help=(
            "When OpenClaw is enabled, also update ~/.openclaw/ for "
            "gateway exec approvals (default: off)."
        ),
    )
    start_parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Gateway bind host (default: 127.0.0.1).",
    )
    start_parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("CS_HTTP_PORT", "8080")),
        help="Gateway HTTP port (default: 8080 or CS_HTTP_PORT).",
    )
    start_parser.add_argument(
        "--no-watch",
        action="store_true",
        default=False,
        help="Start gateway in background only, without watch.",
    )
    start_parser.add_argument(
        "--interactive",
        "-i",
        action="store_true",
        default=False,
        help="Enable interactive DEFER handling in watch.",
    )
    start_parser.add_argument(
        "--open-browser",
        action="store_true",
        default=False,
        help="Open the Web UI in a browser after gateway starts.",
    )
    start_parser.add_argument(
        "--with-latch",
        action="store_true",
        default=False,
        help="Start with Latch Hub (requires 'clawsentry latch install' first).",
    )
    start_parser.add_argument(
        "--hub-port",
        type=int,
        default=3006,
        help="Latch Hub port (default: 3006). Only used with --with-latch.",
    )

    # --- stop ---
    sub.add_parser("stop", help="Stop running gateway.")

    # --- status ---
    sub.add_parser("status", help="Check gateway status.")

    return parser


def main(argv: list[str] | None = None) -> None:
    from .dotenv_loader import load_dotenv
    load_dotenv()
    parser = _build_parser()
    args, remaining = parser.parse_known_args(argv)

    if args.command is None:
        parser.print_help()
        return
    if remaining and args.command not in {"gateway", "stack", "harness"}:
        parser.error(f"unrecognized arguments: {' '.join(remaining)}")

    if args.command == "init":
        # Handle --restore for openclaw
        if getattr(args, "restore", False):
            if args.framework == "openclaw":
                from .initializers.openclaw import OpenClawInitializer
                init = OpenClawInitializer()
                result = init.restore_openclaw_config(
                    openclaw_home=getattr(args, "openclaw_home", None),
                    dry_run=getattr(args, "dry_run", False),
                )
                if result.dry_run:
                    print("  [DRY RUN] The following restore changes would be applied:")
                else:
                    print("  OpenClaw configuration restore:")
                for change in result.changes_applied:
                    print(f"    - {change}")
                for w in result.warnings:
                    print(f"  WARNING: {w}")
                sys.exit(0)
            else:
                print(f"--restore is only supported for openclaw, got: {args.framework}", file=sys.stderr)
                sys.exit(1)

        # Handle --uninstall for framework env/hooks
        if getattr(args, "uninstall", False):
            from .init_command import run_uninstall
            code = run_uninstall(
                framework=args.framework,
                target_dir=args.dir,
            )
            sys.exit(code)

        from .init_command import run_init

        code = run_init(
            framework=args.framework,
            target_dir=args.dir,
            force=args.force,
            auto_detect=getattr(args, "auto_detect", False),
            setup=getattr(args, "setup", False),
            dry_run=getattr(args, "dry_run", False),
            openclaw_home=getattr(args, "openclaw_home", None),
        )
        sys.exit(code)

    elif args.command == "gateway":
        from ..gateway.stack import main as stack_main
        # Replace sys.argv so the delegated main() can re-parse its own flags
        sys.argv = ["clawsentry-gateway"] + remaining
        stack_main()

    elif args.command == "stack":
        from ..gateway.stack import main as stack_main
        sys.argv = ["clawsentry-stack"] + remaining
        stack_main()

    elif args.command == "harness":
        from ..adapters.a3s_gateway_harness import main as harness_main
        sys.argv = ["clawsentry-harness"] + remaining
        harness_main()

    elif args.command == "watch":
        from .watch_command import run_watch

        run_watch(
            gateway_url=args.gateway_url,
            token=args.token,
            filter_types=args.filter,
            json_mode=args.json,
            color=not args.no_color,
            interactive=args.interactive,
            verbose=args.verbose,
            no_emoji=args.no_emoji,
            compact=args.compact,
        )

    elif args.command == "audit":
        from .audit_command import run_audit

        code = run_audit(
            db_path=args.db,
            session_id=args.session,
            since=args.since,
            risk=args.risk,
            decision=args.decision,
            tool=args.tool,
            fmt=args.output_format,
            stats_mode=args.stats,
            limit=args.limit,
            color=not args.no_color,
        )
        sys.exit(code)

    elif args.command == "doctor":
        from .doctor_command import run_doctor

        code = run_doctor(
            json_mode=args.json,
            color=not args.no_color,
        )
        sys.exit(code)

    elif args.command == "test-llm":
        from .test_llm_command import run_test_llm

        code = run_test_llm(
            color=not args.no_color,
            skip_l3=args.skip_l3,
            json_mode=args.json,
        )
        sys.exit(code)

    elif args.command == "service":
        from .service_command import (
            run_service_install, run_service_uninstall, run_service_status,
        )
        if args.service_command == "install":
            sys.exit(run_service_install(no_enable=args.no_enable))
        elif args.service_command == "uninstall":
            sys.exit(run_service_uninstall())
        elif args.service_command == "status":
            sys.exit(run_service_status())
        else:
            print("Usage: clawsentry service {install,uninstall,status}")

    elif args.command == "config":
        from .config_command import (
            run_config_init, run_config_show, run_config_set,
            run_config_disable, run_config_enable,
        )
        target = Path(".")
        if args.config_command == "init":
            run_config_init(target_dir=target, preset=args.preset, force=args.force)
        elif args.config_command == "show":
            run_config_show(target_dir=target)
        elif args.config_command == "set":
            run_config_set(target_dir=target, preset=args.preset)
        elif args.config_command == "disable":
            run_config_disable(target_dir=target)
        elif args.config_command == "enable":
            run_config_enable(target_dir=target)
        else:
            print("Usage: clawsentry config {init,show,set,disable,enable}")

    elif args.command == "rules":
        from .rules_command import run_rules_dry_run, run_rules_lint

        if args.rules_command == "lint":
            sys.exit(
                run_rules_lint(
                    patterns_path=args.attack_patterns,
                    evolved_patterns_path=args.evolved_patterns,
                    skills_dir=args.skills_dir,
                    as_json=args.json,
                )
            )
        elif args.rules_command == "dry-run":
            sys.exit(
                run_rules_dry_run(
                    events_path=args.events,
                    patterns_path=args.attack_patterns,
                    evolved_patterns_path=args.evolved_patterns,
                    skills_dir=args.skills_dir,
                    as_json=args.json,
                )
            )

    elif args.command == "latch":
        from .latch_command import (
            run_latch_install, run_latch_start, run_latch_stop, run_latch_status,
            run_latch_uninstall,
        )
        if args.latch_command == "install":
            sys.exit(run_latch_install(no_shortcut=args.no_shortcut))
        elif args.latch_command == "uninstall":
            sys.exit(run_latch_uninstall(keep_data=args.keep_data))
        elif args.latch_command == "start":
            sys.exit(run_latch_start(
                gateway_port=args.gateway_port,
                hub_port=args.hub_port,
                no_browser=args.no_browser,
            ))
        elif args.latch_command == "stop":
            sys.exit(run_latch_stop())
        elif args.latch_command == "status":
            sys.exit(run_latch_status())
        else:
            print("Usage: clawsentry latch {install,uninstall,start,stop,status}")

    elif args.command == "integrations":
        from .integrations_command import run_integrations_status

        if args.integrations_command == "status":
            sys.exit(run_integrations_status(
                target_dir=args.dir,
                json_mode=args.json,
            ))
        print("Usage: clawsentry integrations {status}")

    elif args.command == "start":
        from .start_command import detect_framework, run_start

        framework = args.framework
        enabled_frameworks = None
        if args.frameworks:
            enabled_frameworks = [
                item.strip() for item in args.frameworks.split(",") if item.strip()
            ]
            unknown = [
                item for item in enabled_frameworks
                if item not in FRAMEWORK_INITIALIZERS
            ]
            if unknown:
                print(
                    f"Unknown framework(s): {', '.join(unknown)}",
                    file=sys.stderr,
                )
                sys.exit(1)
            if not enabled_frameworks:
                print("--frameworks requires at least one framework.", file=sys.stderr)
                sys.exit(1)
            if framework is None:
                framework = enabled_frameworks[0]

        auto_detected = False
        if framework is None:
            framework = detect_framework()
            if framework is None:
                print(
                    "Could not auto-detect framework.\n"
                    "Use: clawsentry start --framework <a3s-code|claude-code|codex|openclaw>",
                    file=sys.stderr,
                )
                sys.exit(1)
            auto_detected = True

        run_start(
            framework=framework,
            host=args.host,
            port=args.port,
            no_watch=args.no_watch,
            interactive=args.interactive,
            setup_openclaw=args.setup_openclaw,
            open_browser=args.open_browser,
            with_latch=args.with_latch,
            hub_port=args.hub_port,
            auto_detected=auto_detected,
            enabled_frameworks=enabled_frameworks,
        )

    elif args.command == "stop":
        from .start_command import run_stop
        run_stop()

    elif args.command == "status":
        from .start_command import run_status
        run_status()


if __name__ == "__main__":
    main()
