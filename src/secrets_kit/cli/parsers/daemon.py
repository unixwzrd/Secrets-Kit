"""
secrets_kit.cli.parsers.daemon

Parser registration for daemon commands.
"""

from __future__ import annotations

import argparse

from secrets_kit.cli.commands.daemon import (
    cmd_daemon_ping,
    cmd_daemon_restart,
    cmd_daemon_run,
    cmd_daemon_service_install,
    cmd_daemon_service_status,
    cmd_daemon_service_uninstall,
    cmd_daemon_start,
    cmd_daemon_status,
    cmd_daemon_stop,
)
from secrets_kit.locale import msg


def register_daemon_commands(
    *, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    p_daemon = subparsers.add_parser("daemon", help=msg("cli.daemon.daemon_help_text"))
    daemon_sub = p_daemon.add_subparsers(dest="daemon_command", required=True)

    p_start = daemon_sub.add_parser("start", help=msg("cli.daemon.start_help_text"))
    p_start.set_defaults(func=cmd_daemon_start)

    p_stop = daemon_sub.add_parser("stop", help=msg("cli.daemon.stop_help_text"))
    p_stop.set_defaults(func=cmd_daemon_stop)

    p_restart = daemon_sub.add_parser("restart", help=msg("cli.daemon.restart_help_text"))
    p_restart.set_defaults(func=cmd_daemon_restart)

    p_status = daemon_sub.add_parser("status", help=msg("cli.daemon.status_help_text"))
    p_status.set_defaults(func=cmd_daemon_status)

    p_ping = daemon_sub.add_parser("ping", help=msg("cli.daemon.ping_help_text"))
    p_ping.set_defaults(func=cmd_daemon_ping)

    p_run = daemon_sub.add_parser("run", help=msg("cli.daemon.run_help_text"))
    p_run.set_defaults(func=cmd_daemon_run)

    p_service = daemon_sub.add_parser("service", help=msg("cli.daemon.service_help_text"))
    service_sub = p_service.add_subparsers(dest="daemon_service_command", required=True)
    p_install = service_sub.add_parser("install", help=msg("cli.daemon.install_help_text"))
    p_install.set_defaults(func=cmd_daemon_service_install)
    p_uninstall = service_sub.add_parser("uninstall", help=msg("cli.daemon.uninstall_help_text"))
    p_uninstall.set_defaults(func=cmd_daemon_service_uninstall)
    p_service_status = service_sub.add_parser("status", help=msg("cli.daemon.status_help_text"))
    p_service_status.set_defaults(func=cmd_daemon_service_status)


__all__ = ["register_daemon_commands"]
