"""
secrets_kit.cli.parsers.peer

Parser registration for peer admission commands.
"""

from __future__ import annotations

import argparse

from secrets_kit.backends.common import BACKEND_CHOICES
from secrets_kit.cli.commands.peer import (
    cmd_peer_accept,
    cmd_peer_export_identity,
    cmd_peer_import_acceptance,
    cmd_peer_import_request,
    cmd_peer_list,
    cmd_peer_reject,
    cmd_peer_request,
    cmd_peer_show,
)
from secrets_kit.locale import msg


def register_peer_commands(
    *, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    peer = subparsers.add_parser("peer", help=msg("cli.peer.peer_help_text"))
    peer_sub = peer.add_subparsers(dest="peer_command", required=True)

    request_parser = peer_sub.add_parser("request", help=msg("cli.peer.request_help_text"))
    request_parser.add_argument("--backend", choices=list(BACKEND_CHOICES))
    request_parser.add_argument("--service-address", default="")
    request_parser.add_argument("--comment", default="")
    request_parser.add_argument("--json", action="store_true")
    request_parser.set_defaults(func=cmd_peer_request)

    import_request_parser = peer_sub.add_parser(
        "import-request",
        help=msg("cli.peer.import_request_help_text"),
    )
    import_request_parser.add_argument("--backend", choices=list(BACKEND_CHOICES))
    import_request_parser.add_argument("--file")
    import_request_parser.set_defaults(func=cmd_peer_import_request)

    accept_parser = peer_sub.add_parser("accept", help=msg("cli.peer.accept_help_text"))
    accept_parser.add_argument("--backend", choices=list(BACKEND_CHOICES))
    accept_parser.add_argument("node_id")
    accept_parser.add_argument("--comment", default="")
    accept_parser.add_argument("--service", help=msg("cli.peer.scope_service_help"))
    accept_parser.add_argument("--account", help=msg("cli.peer.scope_account_help"))
    accept_parser.add_argument(
        "--service-group-id",
        action="append",
        default=[],
        help=msg("cli.peer.service_group_id_help_text"),
    )
    accept_parser.add_argument(
        "--all-service-groups",
        action="store_true",
        help=msg("cli.peer.all_service_groups_help_text"),
    )
    accept_parser.add_argument("--json", action="store_true")
    accept_parser.set_defaults(func=cmd_peer_accept)

    import_acceptance_parser = peer_sub.add_parser(
        "import-acceptance",
        help=msg("cli.peer.import_acceptance_help_text"),
    )
    import_acceptance_parser.add_argument("--backend", choices=list(BACKEND_CHOICES))
    import_acceptance_parser.add_argument("--file")
    import_acceptance_parser.set_defaults(func=cmd_peer_import_acceptance)

    reject_parser = peer_sub.add_parser("reject", help=msg("cli.peer.reject_help_text"))
    reject_parser.add_argument("--backend", choices=list(BACKEND_CHOICES))
    reject_parser.add_argument("node_id")
    reject_parser.add_argument("--comment", default="")
    reject_parser.add_argument("--json", action="store_true")
    reject_parser.set_defaults(func=cmd_peer_reject)

    export_parser = peer_sub.add_parser(
        "export-identity",
        help=msg("cli.peer.export_identity_help_text"),
    )
    export_parser.add_argument("--backend", choices=list(BACKEND_CHOICES))
    export_parser.add_argument("--json", action="store_true")
    export_parser.set_defaults(func=cmd_peer_export_identity)

    list_parser = peer_sub.add_parser("list", help=msg("cli.peer.list_help_text"))
    list_parser.add_argument("--backend", choices=list(BACKEND_CHOICES))
    list_parser.add_argument("--json", action="store_true")
    list_parser.set_defaults(func=cmd_peer_list)

    show_parser = peer_sub.add_parser("show", help=msg("cli.peer.show_help_text"))
    show_parser.add_argument("--backend", choices=list(BACKEND_CHOICES))
    show_parser.add_argument("--json", action="store_true")
    show_parser.add_argument("node_id")
    show_parser.set_defaults(func=cmd_peer_show)


__all__ = ["register_peer_commands"]
