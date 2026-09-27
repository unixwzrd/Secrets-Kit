"""secrets_kit.cli.parsers.host: host installation identity CLI."""

from __future__ import annotations

import argparse

from secrets_kit.cli.commands.host import (
    cmd_host_activate,
    cmd_host_configure,
    cmd_host_join,
    cmd_host_register,
    cmd_host_show,
)
from secrets_kit.locale import msg


def register_host_commands(*, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register administrator configuration and per-user opt-in commands."""
    host = subparsers.add_parser("host", help=msg("cli.host.help"))
    actions = host.add_subparsers(dest="host_command", required=True)
    configure = actions.add_parser("configure", help=msg("cli.host.configure_help"))
    configure.add_argument("--prefix", required=True)
    configure.add_argument("--environment", required=True, choices=("dev", "qa", "production"))
    configure.add_argument("--organization", required=True)
    configure.add_argument("--client", required=True)
    configure.add_argument("--organization-id", help="Reuse an existing organization UUID on another host")
    configure.add_argument("--client-id", help="Reuse an existing client UUID on another host")
    configure.set_defaults(func=cmd_host_configure)
    show = actions.add_parser("show", help=msg("cli.host.show_help"))
    show.add_argument("--prefix", required=True)
    show.add_argument("--joined", action="store_true", help="Show this Unix user's verified host membership")
    show.set_defaults(func=cmd_host_show)
    join = actions.add_parser("join", help=msg("cli.host.join_help"))
    join.add_argument("--prefix", required=True)
    join.add_argument("--environment", required=True, choices=("dev", "qa", "production"))
    join.set_defaults(func=cmd_host_join)
    register = actions.add_parser("register", help=msg("cli.host.register_help"))
    register.add_argument("--prefix", required=True)
    register.add_argument("--user", required=True)
    register.set_defaults(func=cmd_host_register)
    activate = actions.add_parser("activate", help=msg("cli.host.activate_help"))
    activate.add_argument("--prefix", required=True)
    activate.add_argument("--generation", required=True)
    activate.set_defaults(func=cmd_host_activate)


__all__ = ["register_host_commands"]
