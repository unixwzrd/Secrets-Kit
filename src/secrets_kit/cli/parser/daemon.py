"""Argparse wiring for ``seckit daemon`` and its subcommands.

Registers ``daemon`` with nested ``ping``, ``status``, ``sync-status``,
``submit-outbound``, and ``serve``. All user-visible strings are
``STRINGS[...]`` keys from :mod:`secrets_kit.cli.strings.en`. Sub-handlers are
``cmd_daemon_*`` from :mod:`secrets_kit.cli.commands.daemon`.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Type

from secrets_kit.cli.commands.daemon import (
    cmd_daemon_ping,
    cmd_daemon_serve,
    cmd_daemon_status,
    cmd_daemon_submit_outbound,
    cmd_daemon_sync_status,
)
from secrets_kit.cli.strings.en import STRINGS


def add_daemon_commands(
    sub: argparse._SubParsersAction,
    *,
    formatter_class: Type[argparse.HelpFormatter],
) -> None:
    """Register ``daemon`` and all nested daemon subcommands on *sub*.

    Args:
        sub: The root parser's subparser action (from ``add_subparsers``).
        formatter_class: Help layout class; use
            :class:`~secrets_kit.cli.parser.formatter.SeckitHelpFormatter` for
            multi-line epilogs and default suffixes on flags that have defaults.

    Returns:
        None. Mutates *sub* in place.

    Side effects:
        Defines parsers and ``set_defaults(func=...)`` bindings only; does not
        parse ``sys.argv``.
    """
    p_daemon = sub.add_parser(
        "daemon",
        help=STRINGS["DAEMON_HELP"],
        epilog=STRINGS["DAEMON_EPILOG"],
        formatter_class=formatter_class,
    )
    daemon_sub = p_daemon.add_subparsers(dest="daemon_command", required=True)
    p_daemon_ping = daemon_sub.add_parser("ping", help=STRINGS["DAEMON_PING_HELP"])
    p_daemon_ping.add_argument(
        "--socket", type=Path, default=None, help=STRINGS["DAEMON_SOCKET_HELP"]
    )
    p_daemon_ping.add_argument("--timeout", type=float, default=30.0, help=STRINGS["DAEMON_TIMEOUT_HELP"])
    p_daemon_ping.set_defaults(func=cmd_daemon_ping)
    p_daemon_status = daemon_sub.add_parser("status", help=STRINGS["DAEMON_STATUS_HELP"])
    p_daemon_status.add_argument("--socket", type=Path, default=None)
    p_daemon_status.add_argument("--timeout", type=float, default=30.0)
    p_daemon_status.set_defaults(func=cmd_daemon_status)
    p_daemon_sync = daemon_sub.add_parser(
        "sync-status",
        help=STRINGS["DAEMON_SYNC_STATUS_HELP"],
    )
    p_daemon_sync.add_argument("--socket", type=Path, default=None)
    p_daemon_sync.add_argument("--timeout", type=float, default=30.0)
    p_daemon_sync.set_defaults(func=cmd_daemon_sync_status)
    p_daemon_submit = daemon_sub.add_parser(
        "submit-outbound",
        help=STRINGS["DAEMON_SUBMIT_OUTBOUND_HELP"],
    )
    p_daemon_submit.add_argument("--socket", type=Path, default=None)
    p_daemon_submit.add_argument("--timeout", type=float, default=30.0)
    p_daemon_submit.add_argument(
        "--payload-file", required=True, help=STRINGS["DAEMON_PAYLOAD_FILE_HELP"]
    )
    p_daemon_submit.add_argument(
        "--payload-type", dest="payload_type", default="", help=STRINGS["DAEMON_PAYLOAD_TYPE_HELP"]
    )
    p_daemon_submit.add_argument("--client-ref", default="", help=STRINGS["DAEMON_CLIENT_REF_HELP"])
    p_daemon_submit.add_argument(
        "--route-key",
        default="",
        help=STRINGS["DAEMON_ROUTE_KEY_HELP"],
    )
    p_daemon_submit.set_defaults(func=cmd_daemon_submit_outbound)
    p_daemon_serve = daemon_sub.add_parser(
        "serve",
        help=STRINGS["DAEMON_SERVE_HELP"],
        epilog=STRINGS["DAEMON_SERVE_EPILOG"],
        formatter_class=formatter_class,
    )
    p_daemon_serve.add_argument("--socket", type=Path, default=None)
    p_daemon_serve.set_defaults(func=cmd_daemon_serve)
