"""
secrets_kit.cli.parsers.rss

Parser registration for Remote Secrets Sync customer configuration.
"""

from __future__ import annotations

import argparse

from secrets_kit.cli.commands.rss import (
    cmd_rss_billing_portal,
    cmd_rss_checkout,
    cmd_rss_configure,
    cmd_rss_devices_list,
    cmd_rss_devices_revoke,
    cmd_rss_enroll,
    cmd_rss_identity_export,
    cmd_rss_identity_import,
    cmd_rss_local_status,
    cmd_rss_owner_claim,
    cmd_rss_owner_recover,
)
from secrets_kit.locale import msg


def register_rss_commands(
    *, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    """Register the customer-facing RSS configuration command."""
    rss = subparsers.add_parser("rss", help=msg("cli.rss.help"))
    rss_sub = rss.add_subparsers(dest="rss_command", required=True)
    checkout = rss_sub.add_parser("checkout", help=msg("cli.rss.checkout_help"))
    checkout.add_argument(
        "--connection-units",
        type=int,
        default=None,
        help=msg("cli.rss.connection_units_help"),
    )
    checkout.add_argument(
        "--operator-url",
        default=None,
        help=msg("cli.rss.operator_url_help"),
    )
    checkout.set_defaults(func=cmd_rss_checkout)
    enroll = rss_sub.add_parser("enroll", help=msg("cli.rss.enroll_help"))
    enroll.add_argument("--bundle-stdin", action="store_true", help=argparse.SUPPRESS)
    enroll.set_defaults(func=cmd_rss_enroll)
    rss_sub.add_parser("local-status", help=argparse.SUPPRESS).set_defaults(
        func=cmd_rss_local_status
    )
    owner = rss_sub.add_parser("owner", help="Claim or recover RSS billing-owner authority")
    owner_sub = owner.add_subparsers(dest="rss_owner_command", required=True)
    owner_sub.add_parser("claim", help="Claim an enrolled paid account").set_defaults(
        func=cmd_rss_owner_claim
    )
    recover = owner_sub.add_parser("recover", help="Recover owner authority with an offline code")
    recover.add_argument("--account-id", required=True)
    recover.add_argument("--operator-url", default=None)
    recover.set_defaults(func=cmd_rss_owner_recover)
    devices = rss_sub.add_parser("devices", help="List or revoke RSS devices")
    devices_sub = devices.add_subparsers(dest="rss_devices_command", required=True)
    devices_sub.add_parser("list", help="List this account's devices and capacity").set_defaults(
        func=cmd_rss_devices_list
    )
    revoke = devices_sub.add_parser("revoke", help="Permanently revoke one device")
    revoke.add_argument("connection_id")
    revoke.set_defaults(func=cmd_rss_devices_revoke)
    billing = rss_sub.add_parser("billing", help="Manage the existing RSS subscription")
    billing_sub = billing.add_subparsers(dest="rss_billing_command", required=True)
    billing_sub.add_parser("portal", help="Get the Stripe billing portal URL").set_defaults(
        func=cmd_rss_billing_portal
    )
    configure = rss_sub.add_parser("configure", help=msg("cli.rss.configure_help"))
    configure.add_argument(
        "--enrollment-token-file",
        help=msg("cli.rss.enrollment_token_file_help"),
    )
    configure.add_argument(
        "--entitlement-id", required=True, help=msg("cli.rss.entitlement_id_help")
    )
    configure.add_argument("--connection-id", help=msg("cli.rss.connection_id_help"))
    configure.add_argument(
        "--relay-peer",
        action="append",
        required=True,
        help=msg("cli.rss.relay_peer_help"),
    )
    configure.add_argument(
        "--enrollment-url", required=True, help=msg("cli.rss.enrollment_url_help")
    )
    configure.set_defaults(func=cmd_rss_configure)
    identity = rss_sub.add_parser("identity", help=msg("cli.rss.identity_help"))
    identity_sub = identity.add_subparsers(dest="rss_identity_command", required=True)
    export = identity_sub.add_parser("export", help=msg("cli.rss.identity_export_help"))
    export.add_argument("--output", required=True, help=msg("cli.rss.identity_output_help"))
    export.set_defaults(func=cmd_rss_identity_export)
    import_parser = identity_sub.add_parser("import", help=msg("cli.rss.identity_import_help"))
    import_parser.add_argument("--input", required=True, help=msg("cli.rss.identity_input_help"))
    import_parser.set_defaults(func=cmd_rss_identity_import)


__all__ = ["register_rss_commands"]
