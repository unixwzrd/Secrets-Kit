"""
secrets_kit.cli.commands.rss

Customer-side Remote Secrets Sync Checkout, enrollment, and identity commands.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

from secrets_kit.backends.sqlite.exceptions import SQLiteBackendError
from secrets_kit.backends.sqlite.peer_admission import list_peer_admissions
from secrets_kit.cli.io import _fatal
from secrets_kit.cli.update_check import _safe_install_state
from secrets_kit.daemon.client import DaemonError, request_daemon_status
from secrets_kit.daemon.service import DaemonServiceError, install_service
from secrets_kit.locale import msg
from secrets_kit.protocol.rss_admin import (
    admin_action,
    claim_customer_admin,
    customer_admin_account_id,
    finish_customer_admin_claim,
    pending_customer_admin_codes,
    recover_customer_admin,
)
from secrets_kit.protocol.rss_auth import (
    RSSAuthenticationError,
    configure_rss_client,
    export_rss_authentication_identity,
    import_rss_authentication_identity,
    load_rss_relay_credentials_from_environment,
)
from secrets_kit.protocol.rss_provisioning import (
    DEFAULT_RSS_OPERATOR_URL,
    complete_rss_enrollment,
    configure_rss_provisioning_bundle,
    rss_enrollment_token_expired,
    start_rss_checkout,
)


def _installed_operator_url() -> str:
    """Resolve the verified installer origin only when Checkout is requested.

    A shared generation carries its environment and origin beside the runtime;
    unlike a per-user installation it does not write a user-owned receipt.
    """
    runtime = Path(sys.prefix)
    environment_file = runtime / "seckit-environment"
    if environment_file.is_file():
        # The administrator-selected shared environment outranks a preserved
        # per-user receipt from that user's previous installation.
        environment = environment_file.read_text(encoding="utf-8").strip()
        if environment not in {"dev", "qa", "production"}:
            raise ValueError("invalid shared runtime environment")
        origin_file = runtime / "seckit-rss-operator-url"
        recorded = origin_file.read_text(encoding="utf-8").strip() if origin_file.is_file() else ""
        if environment != "production" and not recorded:
            raise ValueError("shared runtime RSS operator origin is missing")
    else:
        recorded = _safe_install_state().get("rss_operator_url")
    if not recorded:
        return DEFAULT_RSS_OPERATOR_URL
    if not isinstance(recorded, str) or not recorded.startswith("https://"):
        raise ValueError("invalid installed RSS operator origin")
    parsed = urlsplit(recorded)
    if not parsed.netloc or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("invalid installed RSS operator origin")
    return recorded.rstrip("/")


def _report_configuration(*, profile: Path, wait_seconds: float = 12.0) -> int:
    """Report local configuration separately from daemon-observed RSS authentication.

    Waits briefly on same-user daemon status after its service reload. This is
    a bounded local readiness check, not a network enrollment retry; it never
    changes credentials or prints arbitrary provider errors.
    """
    deadline = time.monotonic() + max(0.0, wait_seconds)
    while True:
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
        if authenticated or error == "device_capacity_exhausted":
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(1.0, remaining))
    result = {"configured": True, "profile": str(profile), "rss_authenticated": authenticated}
    if not authenticated:
        result["error"] = error
    print(json.dumps(result, sort_keys=True))
    if not authenticated:
        return _fatal(message=msg("cli.rss." + error), code=1)
    return 0


def _suggested_connection_units() -> int:
    """Suggest capacity for this node and its authorized synchronization peers.

    Checkout remains usable before initialization or when the local store is
    unavailable. In either case the established two-connection minimum is the
    conservative suggestion.
    """
    try:
        peer_ids = {
            peer.node_id
            for peer in list_peer_admissions()
            if peer.synchronization_eligible
        }
    except (OSError, SQLiteBackendError):
        return 2
    return max(2, 1 + len(peer_ids))


def _checkout_connection_units(*, requested: int | None, interactive: bool) -> int:
    """Resolve an explicit quantity or an interactive, visible suggestion."""
    if requested is not None:
        units = requested
    elif not interactive:
        # Preserve the existing script/non-interactive default.
        units = 2
    else:
        suggestion = _suggested_connection_units()
        answer = input(f"RSS connection units [{suggestion}]: ").strip()
        if not answer:
            units = suggestion
        elif not answer.isascii() or not answer.isdecimal():
            raise ValueError("RSS connection units must be an integer of at least two")
        else:
            units = int(answer)
    if type(units) is not int or units < 2:
        raise ValueError("RSS connection units must be an integer of at least two")
    return units


def cmd_rss_checkout(*, args: argparse.Namespace) -> int:
    """Start Stripe Checkout; read an optional beta invitation without echoing it."""
    try:
        invite_code = None
        interactive = sys.stdin.isatty()
        connection_units = _checkout_connection_units(
            requested=args.connection_units,
            interactive=interactive,
        )
        if interactive:
            invite_code = getpass.getpass(
                "Beta invitation code (press Enter if none): "
            ).strip() or None
        checkout_url, receipt = start_rss_checkout(
            connection_units=connection_units,
            operator_url=args.operator_url or _installed_operator_url(),
            invite_code=invite_code,
        )
    except (OSError, ValueError, RSSAuthenticationError) as exc:
        return _fatal(message=str(exc), code=1)
    print(json.dumps({"checkout_url": checkout_url, "receipt": str(receipt)}, sort_keys=True))
    return 0


def cmd_rss_enroll(*, args: argparse.Namespace) -> int:
    """Turn the verified paid Checkout receipt into local RSS configuration."""
    try:
        if getattr(args, "bundle_stdin", False):
            raw = sys.stdin.buffer.read(16 * 1024 + 1)
            if len(raw) > 16 * 1024:
                raise RSSAuthenticationError("RSS enrollment bundle is too large")
            bundle = json.loads(raw.decode("utf-8"))
            if not isinstance(bundle, dict):
                raise RSSAuthenticationError("RSS enrollment bundle is invalid")
            profile = configure_rss_provisioning_bundle(
                bundle=bundle, expected_operator_url=_installed_operator_url()
            )
        else:
            profile = complete_rss_enrollment()
    except (OSError, UnicodeError, json.JSONDecodeError, RSSAuthenticationError) as exc:
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


def cmd_rss_local_status(*, args: argparse.Namespace) -> int:
    """Expose only non-secret local RSS identity for SSH install decisions."""
    _ = args
    try:
        credentials = load_rss_relay_credentials_from_environment()
    except (OSError, RSSAuthenticationError) as exc:
        return _fatal(message=str(exc), code=1)
    result: dict[str, object] = {"configured": credentials is not None}
    if credentials is not None:
        result.update({
            "entitlement_id": credentials.entitlement_id,
            "connection_id": credentials.connection_id,
            "enrolled": credentials.enrollment_token is None,
        })
        if credentials.enrollment_token is not None:
            result["enrollment_token_expired"] = rss_enrollment_token_expired(
                token=credentials.enrollment_token
            )
    print(json.dumps(result, sort_keys=True))
    return 0


def _show_recovery_codes(codes: tuple[str, ...]) -> int:
    """Require an interactive offline-code acknowledgement before local cleanup."""
    print(f"Save this RSS account ID and owner recovery codes offline: {customer_admin_account_id()}")
    print("Each code works once:")
    for code in codes:
        print(code)
    answer = input("I saved the recovery codes offline [y/N]: ").strip().lower()
    if answer not in {"y", "yes"}:
        print("Recovery codes remain in the owner-only pending file until you confirm.")
        return 1
    finish_customer_admin_claim()
    print("RSS owner authority is ready.")
    return 0


def cmd_rss_owner_claim(*, args: argparse.Namespace) -> int:
    """Bind paid Checkout to a separate owner key on its enrolled first peer."""
    _ = args
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        return _fatal(message="RSS owner setup requires an interactive terminal", code=1)
    try:
        codes = pending_customer_admin_codes() or claim_customer_admin()
        return _show_recovery_codes(codes)
    except (OSError, ValueError, RSSAuthenticationError) as exc:
        return _fatal(message=str(exc), code=1)


def cmd_rss_owner_recover(*, args: argparse.Namespace) -> int:
    """Rotate owner authority using one offline one-time code."""
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        return _fatal(message="RSS owner recovery requires an interactive terminal", code=1)
    try:
        codes = pending_customer_admin_codes()
        if codes is None:
            code = getpass.getpass("One-time RSS owner recovery code: ").strip()
            codes = recover_customer_admin(
                account_id=args.account_id,
                operator_url=args.operator_url or _installed_operator_url(),
                code=code,
            )
        return _show_recovery_codes(codes)
    except (OSError, ValueError, RSSAuthenticationError) as exc:
        return _fatal(message=str(exc), code=1)


def cmd_rss_devices_list(*, args: argparse.Namespace) -> int:
    """List only devices belonging to this owner's paid account."""
    _ = args
    try:
        status, result = admin_action(action="devices.list", parameters={})
        if status != 200:
            raise RSSAuthenticationError("RSS device list was not confirmed")
    except (OSError, ValueError, RSSAuthenticationError) as exc:
        return _fatal(message=str(exc), code=1)
    print(json.dumps(result, sort_keys=True))
    return 0


def cmd_rss_devices_revoke(*, args: argparse.Namespace) -> int:
    """Permanently revoke one selected device, not the subscription quantity."""
    if not sys.stdin.isatty():
        return _fatal(message="RSS device revocation requires an interactive terminal", code=1)
    answer = input(
        f"Permanently revoke RSS device {args.connection_id} and free its slot? "
        "The old credential cannot be restored. [y/N] "
    ).strip().lower()
    if answer not in {"y", "yes"}:
        return _fatal(message="RSS device revocation cancelled", code=1)
    try:
        status, result = admin_action(
            action="devices.revoke",
            parameters={"connection_id": args.connection_id, "confirm": True},
        )
        if status != 200:
            raise RSSAuthenticationError("RSS device revocation was not confirmed")
    except (OSError, ValueError, RSSAuthenticationError) as exc:
        return _fatal(message=str(exc), code=1)
    print(json.dumps(result, sort_keys=True))
    return 0


def cmd_rss_billing_portal(*, args: argparse.Namespace) -> int:
    """Open a Stripe-hosted billing session for the signed account owner."""
    _ = args
    try:
        status, result = admin_action(action="billing.portal", parameters={})
        url = result.get("portal_url")
        if status != 200 or not isinstance(url, str) or not url.startswith("https://billing.stripe.com/"):
            raise RSSAuthenticationError("Stripe billing portal is unavailable")
    except (OSError, ValueError, RSSAuthenticationError) as exc:
        return _fatal(message=str(exc), code=1)
    print(json.dumps({"portal_url": url}, sort_keys=True))
    return 0


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
