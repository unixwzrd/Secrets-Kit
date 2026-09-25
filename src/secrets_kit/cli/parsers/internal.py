"""
secrets_kit.cli.parsers.internal

Parser registration for internal commands.
"""

from __future__ import annotations

import argparse

from secrets_kit.cli.commands.internal import (
    cmd_internal_apply_envelope,
    cmd_internal_deliver_pending,
    cmd_internal_register_endpoint,
    cmd_internal_runtime_access,
    cmd_internal_sign_transport_binding,
    cmd_internal_status,
    cmd_internal_transport_routes,
    cmd_internal_verify_transport_binding,
)


def register_internal_commands(
    *, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    p_internal = subparsers.add_parser("internal", help=argparse.SUPPRESS)
    subparsers._choices_actions = [  # noqa: SLF001 - argparse has no public API to hide a registered subparser.
        action
        for action in subparsers._choices_actions
        if action.dest != "internal"
    ]
    internal_sub = p_internal.add_subparsers(dest="internal_command", required=True)
    p_apply = internal_sub.add_parser("apply-envelope", help=argparse.SUPPRESS)
    p_apply.add_argument("--stdin", action="store_true", required=True)
    p_apply.set_defaults(func=cmd_internal_apply_envelope)
    p_deliver = internal_sub.add_parser("deliver-pending", help=argparse.SUPPRESS)
    p_deliver.add_argument(
        "--recovered-peer",
        action="append",
        default=[],
        help=argparse.SUPPRESS,
    )
    p_deliver.set_defaults(func=cmd_internal_deliver_pending)
    p_status = internal_sub.add_parser("status", help=argparse.SUPPRESS)
    p_status.set_defaults(func=cmd_internal_status)
    p_access = internal_sub.add_parser("runtime-access", help=argparse.SUPPRESS)
    p_access.add_argument("--stdin", action="store_true", required=True)
    p_access.set_defaults(func=cmd_internal_runtime_access)
    p_register = internal_sub.add_parser("register-endpoint", help=argparse.SUPPRESS)
    p_register.add_argument("--endpoint", required=True)
    p_register.set_defaults(func=cmd_internal_register_endpoint)
    p_routes = internal_sub.add_parser("transport-routes", help=argparse.SUPPRESS)
    p_routes.set_defaults(func=cmd_internal_transport_routes)
    p_sign_binding = internal_sub.add_parser(
        "sign-transport-binding", help=argparse.SUPPRESS
    )
    p_sign_binding.set_defaults(func=cmd_internal_sign_transport_binding)
    p_verify_binding = internal_sub.add_parser(
        "verify-transport-binding", help=argparse.SUPPRESS
    )
    p_verify_binding.set_defaults(func=cmd_internal_verify_transport_binding)


__all__ = ["register_internal_commands"]
