"""``seckit daemon …`` — control local ``seckitd`` over Unix sockets."""

from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path

from secrets_kit.cli.support.interaction import _fatal
from secrets_kit.seckitd.client import ipc_call
from secrets_kit.seckitd.paths import default_socket_path


def _socket_path(args: argparse.Namespace) -> Path:
    return Path(args.socket) if getattr(args, "socket", None) else default_socket_path()


def cmd_daemon_ping(*, args: argparse.Namespace) -> int:
    path = _socket_path(args)
    try:
        resp = ipc_call(
            socket_path=path,
            request={"op": "ping"},
            timeout_s=args.timeout,
        )
    except OSError as exc:
        return _fatal(message=f"daemon ping: cannot connect ({exc})", code=1)
    print(json.dumps(resp, indent=2, sort_keys=True))
    return 0 if resp.get("ok") else 1


def cmd_daemon_status(*, args: argparse.Namespace) -> int:
    path = _socket_path(args)
    try:
        resp = ipc_call(
            socket_path=path,
            request={"op": "status"},
            timeout_s=args.timeout,
        )
    except OSError as exc:
        return _fatal(message=f"daemon status: cannot connect ({exc})", code=1)
    print(json.dumps(resp, indent=2, sort_keys=True))
    return 0 if resp.get("ok") else 1


def cmd_daemon_submit_outbound(*, args: argparse.Namespace) -> int:
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
    try:
        resp = ipc_call(socket_path=path, request=payload, timeout_s=args.timeout)
    except OSError as exc:
        return _fatal(message=f"daemon submit-outbound: cannot connect ({exc})", code=1)
    print(json.dumps(resp, indent=2, sort_keys=True))
    return 0 if resp.get("ok") else 1


def cmd_daemon_serve(*, args: argparse.Namespace) -> int:
    from secrets_kit.seckitd.server import serve_forever

    serve_forever(socket_path=_socket_path(args))
    return 0
