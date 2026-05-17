"""Unix domain socket transport helpers for same-host runtime IPC."""

from __future__ import annotations

import os
import socket
import sys
from pathlib import Path
from typing import Any


class UnixTransportError(RuntimeError):
    """Unix transport setup or validation failed."""


def configure_unix_ipc_socket(sock: socket.socket) -> None:
    """Apply platform socket options before ``bind`` or ``connect``."""
    if sys.platform == "darwin" and hasattr(socket, "SO_NOSIGPIPE"):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_NOSIGPIPE, 1)


def connect_unix_socket(path: Path, *, timeout_s: float = 30.0) -> socket.socket:
    """Return a connected Unix stream socket."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    configure_unix_ipc_socket(sock)
    sock.settimeout(timeout_s)
    sock.connect(str(path))
    return sock


def probe_unix_socket(path: Path, *, timeout_s: float = 0.25) -> bool:
    """Return True when ``path`` accepts a Unix stream connection."""
    try:
        sock = connect_unix_socket(path, timeout_s=timeout_s)
    except OSError:
        return False
    try:
        return True
    finally:
        sock.close()


def bind_unix_socket_path(path: Path, *, backlog: int = 8) -> socket.socket:
    """Bind and listen on ``path`` after caller has validated stale state."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    configure_unix_ipc_socket(sock)
    sock.bind(str(path))
    os.chmod(path, 0o600)
    sock.listen(backlog)
    return sock


def close_socket_quietly(sock: Any) -> None:
    """Close socket-like object and ignore close errors."""
    try:
        sock.close()
    except OSError:
        pass

