"""
secrets_kit.cli.parsers.rss

Parser registration for Remote Secrets Sync customer configuration.
"""

from __future__ import annotations

import argparse
from urllib.parse import urlsplit

from secrets_kit.cli.commands.rss import (
    cmd_rss_checkout,
    cmd_rss_configure,
    cmd_rss_enroll,
    cmd_rss_identity_export,
    cmd_rss_identity_import,
)
from secrets_kit.cli.update_check import _safe_install_state
from secrets_kit.locale import msg
from secrets_kit.protocol.rss_provisioning import DEFAULT_RSS_OPERATOR_URL


def _installed_operator_url() -> str:
    """Use the HTTPS operator origin recorded by the verified installer."""

    recorded = _safe_install_state().get("rss_operator_url")
    if not recorded:
        return DEFAULT_RSS_OPERATOR_URL
    if not isinstance(recorded, str) or not recorded.startswith("https://"):
        raise ValueError("invalid installed RSS operator origin")
    parsed = urlsplit(recorded)
    if not parsed.netloc or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("invalid installed RSS operator origin")
    return recorded.rstrip("/")


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
        default=2,
        help=msg("cli.rss.connection_units_help"),
    )
    checkout.add_argument(
        "--operator-url",
        default=_installed_operator_url(),
        help=msg("cli.rss.operator_url_help"),
    )
    checkout.set_defaults(func=cmd_rss_checkout)
    enroll = rss_sub.add_parser("enroll", help=msg("cli.rss.enroll_help"))
    enroll.set_defaults(func=cmd_rss_enroll)
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
