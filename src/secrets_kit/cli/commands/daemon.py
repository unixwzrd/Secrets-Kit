"""
secrets_kit.cli.commands.daemon

``seckit daemon …`` — control local ``seckitd`` over Unix sockets.
"""

from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path

from secrets_kit.cli.constants.exit_codes import EXIT_CODES
from secrets_kit.cli.support.interaction import _fatal
from secrets_kit.seckitd.client import ipc_call
from secrets_kit.seckitd.paths import default_socket_path


def _socket_path(args: argparse.Namespace) -> Path:
    """Resolve the Unix socket path for daemon IPC.

    Defaults to ``default_socket_path()``; overridden by ``--socket``.
    """
    return Path(args.socket) if getattr(args, "socket", None) else default_socket_path()


def cmd_daemon_ping(*, args: argparse.Namespace) -> int:
    """Send a ``ping`` op to ``seckitd`` and print the JSON response."""
    path = _socket_path(args)
    try:
        resp = ipc_call(
            socket_path=path,
            request={"op": "ping"},
            timeout_s=args.timeout,
        )
    except OSError as exc:
        return _fatal(message=f"daemon ping: cannot connect ({exc})", code=EXIT_CODES["ECONNREFUSED"])
    print(json.dumps(resp, indent=2, sort_keys=True))
    return 0 if resp.get("ok") else EXIT_CODES["EPERM"]


def cmd_daemon_status(*, args: argparse.Namespace) -> int:
    """Send a ``status`` op to ``seckitd`` and print the JSON response."""
    path = _socket_path(args)
    try:
        resp = ipc_call(
            socket_path=path,
            request={"op": "status"},
            timeout_s=args.timeout,
        )
    except OSError as exc:
        return _fatal(message=f"daemon status: cannot connect ({exc})", code=EXIT_CODES["ECONNREFUSED"])
    print(json.dumps(resp, indent=2, sort_keys=True))
    return 0 if resp.get("ok") else EXIT_CODES["EPERM"]


def cmd_daemon_submit_outbound(*, args: argparse.Namespace) -> int:
    """Submit a base64-encoded payload to ``seckitd`` for outbound routing.

    The file at ``--payload-file`` is read as raw bytes, base64-encoded,
    and sent as a ``submit_outbound`` IPC request. Optional ``--payload-type``,
    ``--client-ref``, and ``--route-key`` are forwarded verbatim.
    """
    path = _socket_path(args)
    raw = Path(args.payload_file).expanduser().read_bytes()
    b64 = base64.standard_b64encode(raw).decode("ascii")
    payload: dict = {
        "op": "submit_outbound",
        "payload_b64": b64,
    }
    if args.payload_type:
        payload["payload_type"] = args.payload_type
    if args.client_ref:
        payload["client_ref"] = args.client_ref
    rk = getattr(args, "route_key", "") or ""
    if rk.strip():
        payload["route_key"] = rk.strip()
    try:
        resp = ipc_call(socket_path=path, request=payload, timeout_s=args.timeout)
    except OSError as exc:
        return _fatal(message=f"daemon submit-outbound: cannot connect ({exc})", code=EXIT_CODES["ECONNREFUSED"])
    print(json.dumps(resp, indent=2, sort_keys=True))
    return 0 if resp.get("ok") else EXIT_CODES["EPERM"]


def cmd_daemon_sync_status(*, args: argparse.Namespace) -> int:
    """Send a ``sync_status`` op to ``seckitd`` and print the JSON response."""
    path = _socket_path(args)
    try:
        resp = ipc_call(
            socket_path=path,
            request={"op": "sync_status"},
            timeout_s=args.timeout,
        )
    except OSError as exc:
        return _fatal(message=f"daemon sync-status: cannot connect ({exc})", code=EXIT_CODES["ECONNREFUSED"])
    print(json.dumps(resp, indent=2, sort_keys=True))
    return 0 if resp.get("ok") else EXIT_CODES["EPERM"]


def cmd_daemon_serve(*, args: argparse.Namespace) -> int:
    """Start the local ``seckitd`` server (blocks until interrupted)."""
    from secrets_kit.seckitd.server import serve_forever

    serve_forever(socket_path=_socket_path(args))
    return 0
