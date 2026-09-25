"""
secrets_kit.cli.commands.rss

Customer-side Remote Secrets Sync Checkout, enrollment, and identity commands.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

from secrets_kit.cli.io import _fatal
from secrets_kit.daemon.client import DaemonError, request_daemon_status
from secrets_kit.daemon.service import DaemonServiceError, install_service
from secrets_kit.locale import msg
from secrets_kit.protocol.rss_auth import (
    RSSAuthenticationError,
    configure_rss_client,
    export_rss_authentication_identity,
    import_rss_authentication_identity,
)
from secrets_kit.protocol.rss_provisioning import (
    complete_rss_enrollment,
    start_rss_checkout,
)


def _report_configuration(*, profile: Path) -> int:
    """Report local configuration separately from daemon-observed RSS authentication.

    Reads same-user daemon status once with a bounded timeout. Never retries
    enrollment, changes credentials, or prints arbitrary provider errors.
    """
    try:
        status = request_daemon_status()
    except (DaemonError, OSError):
        status = {}
    rss = status.get("rss", {})
    count = rss.get("authenticated_relays", 0) if isinstance(rss, dict) else 0
    authenticated = type(count) is int and count > 0
    error = "rss_authorization_pending"
    routing = status.get("routing", {})
    discovery = routing.get("discovery", {}) if isinstance(routing, dict) else {}
    events = discovery.get("events", []) if isinstance(discovery, dict) else []
    if isinstance(events, list) and any(
        isinstance(event, dict)
        and event.get("event") == "rss_authentication_failed"
        and event.get("error") == "RSS device capacity is fully provisioned"
        for event in events
    ):
        error = "device_capacity_exhausted"
    result = {"configured": True, "profile": str(profile), "rss_authenticated": authenticated}
    if not authenticated:
        result["error"] = error
    print(json.dumps(result, sort_keys=True))
    if not authenticated:
        return _fatal(message=msg("cli.rss." + error), code=1)
    return 0


def cmd_rss_checkout(*, args: argparse.Namespace) -> int:
    """Start Stripe Checkout; read an optional beta invitation without echoing it."""
    try:
        invite_code = None
        if sys.stdin.isatty():
            invite_code = getpass.getpass(
                "Beta invitation code (press Enter if none): "
            ).strip() or None
        checkout_url, receipt = start_rss_checkout(
            connection_units=args.connection_units,
            operator_url=args.operator_url,
            invite_code=invite_code,
        )
    except (OSError, RSSAuthenticationError) as exc:
        return _fatal(message=str(exc), code=1)
    print(json.dumps({"checkout_url": checkout_url, "receipt": str(receipt)}, sort_keys=True))
    return 0


def cmd_rss_enroll(*, args: argparse.Namespace) -> int:
    """Turn the verified paid Checkout receipt into local RSS configuration."""
    _ = args
    try:
        profile = complete_rss_enrollment()
    except (OSError, RSSAuthenticationError) as exc:
        return _fatal(message=str(exc), code=1)
    try:
        install_service(reload_runtime=True)
    except DaemonServiceError:
        return _fatal(
            message=(
                "RSS configuration completed, but managed daemon installation failed; "
                "run: seckit daemon service install"
            ),
            code=1,
        )
    return _report_configuration(profile=profile)


def cmd_rss_configure(*, args: argparse.Namespace) -> int:
    """Create a protected local RSS identity and daemon profile."""
    try:
        profile = configure_rss_client(
            enrollment_token_file=args.enrollment_token_file,
            entitlement_id=args.entitlement_id,
            connection_id=args.connection_id,
            relay_peers=list(args.relay_peer),
            enrollment_url=args.enrollment_url,
        )
    except (OSError, RSSAuthenticationError) as exc:
        return _fatal(message=str(exc), code=1)
    try:
        install_service(reload_runtime=True)
    except DaemonServiceError:
        return _fatal(
            message=(
                "RSS configuration completed, but managed daemon installation failed; "
                "run: seckit daemon service install"
            ),
            code=1,
        )
    return _report_configuration(profile=profile)


def cmd_rss_identity_export(*, args: argparse.Namespace) -> int:
    """Export the protected customer RSS identity for peer handoff."""
    try:
        path = export_rss_authentication_identity(path=args.output)
    except (OSError, RSSAuthenticationError) as exc:
        return _fatal(message=str(exc), code=1)
    print(json.dumps({"exported": True, "path": str(path)}, sort_keys=True))
    return 0


def cmd_rss_identity_import(*, args: argparse.Namespace) -> int:
    """Import the protected customer RSS identity on a clean peer."""
    try:
        path = import_rss_authentication_identity(path=args.input)
    except (OSError, RSSAuthenticationError) as exc:
        return _fatal(message=str(exc), code=1)
    try:
        install_service(reload_runtime=True)
    except DaemonServiceError:
        return _fatal(
            message=(
                "RSS identity import completed, but managed daemon installation failed; "
                "run: seckit daemon service install"
            ),
            code=1,
        )
    print(json.dumps({"imported": True, "path": str(path)}, sort_keys=True))
    return 0


__all__ = [
    "cmd_rss_checkout",
    "cmd_rss_configure",
    "cmd_rss_enroll",
    "cmd_rss_identity_export",
    "cmd_rss_identity_import",
]
