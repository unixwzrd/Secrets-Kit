"""
secrets_kit.seckitd.client

``seckitd`` IPC client (length-prefixed JSON over Unix socket).
"""

from __future__ import annotations

import socket
from pathlib import Path
from typing import Any, Mapping

from secrets_kit.transport.framing import frame_json, parse_json_object, read_frame
from secrets_kit.transport.unix import configure_unix_ipc_socket


def ipc_call(*, socket_path: Path, request: Mapping[str, Any], timeout_s: float = 30.0) -> dict[str, Any]:
    """Send one request and read one response (one round-trip per connection)."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    configure_unix_ipc_socket(sock)
    sock.settimeout(timeout_s)
    sock.connect(str(socket_path))
    try:
        sock.sendall(frame_json(request))
        body = read_frame(sock)
        return parse_json_object(body)
    finally:
        sock.close()
