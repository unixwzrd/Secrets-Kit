"""
secrets_kit.cli.commands.internal

Internal command implementations used by seckitd.
"""

from __future__ import annotations

import argparse
import json
import sys

from secrets_kit.backends.sqlite.peer_endpoints import (
    reregister_local_endpoint,
)
from secrets_kit.cli.io import _fatal
from secrets_kit.runtime.agent_access import handle_runtime_access_request
from secrets_kit.runtime.endpoint_routes import build_endpoint_routes
from secrets_kit.runtime.inbound_envelopes import apply_inbound_transaction_envelope_bytes
from secrets_kit.runtime.outbound_delivery import configured_delivery_schedule
from secrets_kit.runtime.status import build_runtime_status
from secrets_kit.runtime.transport_identity import (
    sign_transport_binding,
    verify_transport_binding,
)


def _read_stdin_bytes() -> bytes:
    buffer = getattr(sys.stdin, "buffer", None)
    if buffer is not None:
        return buffer.read()
    return sys.stdin.read().encode("utf-8")


def cmd_internal_apply_envelope(*, args: argparse.Namespace) -> int:
    if not args.stdin:
        return _fatal(message="internal apply-envelope requires --stdin", code=1)
    raw = _read_stdin_bytes()
    try:
        apply_inbound_transaction_envelope_bytes(data=raw)
    except Exception as exc:
        return _fatal(message=f"failed to apply envelope: {exc}", code=1)
    return 0


def cmd_internal_deliver_pending(*, args: argparse.Namespace) -> int:
    """Process due durable outbound envelopes through the runtime boundary."""
    try:
        sent_count, next_attempt_at = configured_delivery_schedule(
            recovered_peer_ids=getattr(args, "recovered_peer", ()) or ()
        )
    except Exception as exc:
        return _fatal(message=f"failed to deliver pending envelopes: {exc}", code=1)
    print(
        json.dumps(
            {
                "version": 1,
                "sent_count": sent_count,
                "next_attempt_at": next_attempt_at,
            },
            sort_keys=True,
        )
    )
    return 0


def cmd_internal_status(*, args: argparse.Namespace) -> int:
    """Return runtime-owned status for the daemon control plane."""
    _ = args
    print(json.dumps(build_runtime_status(), sort_keys=True))
    return 0


def cmd_internal_runtime_access(*, args: argparse.Namespace) -> int:
    """Resolve one bounded access request inside protected authority handling."""
    if not args.stdin:
        return _fatal(message="internal runtime-access requires --stdin", code=1)
    response = handle_runtime_access_request(data=_read_stdin_bytes())
    sys.stdout.buffer.write(response)
    return 0


def cmd_internal_register_endpoint(*, args: argparse.Namespace) -> int:
    """Persist the daemon's currently active endpoint through the runtime."""
    try:
        # Endpoint registration is canonical runtime state.  Propagate the
        # lifecycle transaction so admitted peers can replace stale routes
        # after a daemon restart or endpoint rebind.
        reregister_local_endpoint(endpoint=args.endpoint, propagate=True)
    except Exception as exc:
        return _fatal(message=f"failed to register endpoint: {exc}", code=1)
    return 0


def cmd_internal_transport_routes(*, args: argparse.Namespace) -> int:
    """Return runtime-owned active endpoint records for daemon route refresh."""
    _ = args
    try:
        print(json.dumps(build_endpoint_routes(), sort_keys=True))
    except Exception as exc:
        return _fatal(message=f"failed to read endpoint routes: {exc}", code=1)


def cmd_internal_sign_transport_binding(*, args: argparse.Namespace) -> int:
    """Sign a daemon-supplied opaque transport identity and challenge."""
    _ = args
    try:
        value = json.loads(_read_stdin_bytes().decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("transport binding request must be an object")
        claim = sign_transport_binding(
            challenge=value.get("challenge"),
            transport_identity=value.get("transport_identity"),
        )
        print(json.dumps({"version": 1, "claim": claim}, sort_keys=True))
    except Exception as exc:
        return _fatal(message=f"failed to sign transport binding: {exc}", code=1)
    return 0


def cmd_internal_verify_transport_binding(*, args: argparse.Namespace) -> int:
    """Verify a daemon-supplied remote transport binding claim."""
    _ = args
    try:
        value = json.loads(_read_stdin_bytes().decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("transport binding verification request must be an object")
        node_id = verify_transport_binding(
            claim=value.get("claim"),
            expected_challenge=value.get("expected_challenge"),
            expected_transport_identity=value.get("expected_transport_identity"),
        )
        print(json.dumps({"version": 1, "valid": True, "node_id": node_id}, sort_keys=True))
    except Exception as exc:
        return _fatal(message=f"failed to verify transport binding: {exc}", code=1)
    return 0


__all__ = [
    "cmd_internal_apply_envelope",
    "cmd_internal_deliver_pending",
    "cmd_internal_register_endpoint",
    "cmd_internal_runtime_access",
    "cmd_internal_status",
    "cmd_internal_sign_transport_binding",
    "cmd_internal_transport_routes",
    "cmd_internal_verify_transport_binding",
]
