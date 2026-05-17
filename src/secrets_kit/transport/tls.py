"""Optional stdlib TLS wrapping for stream transports."""

from __future__ import annotations

import socket
import ssl
from typing import Optional


def wrap_client_socket(
    sock: socket.socket,
    *,
    server_hostname: Optional[str],
    context: Optional[ssl.SSLContext] = None,
) -> ssl.SSLSocket:
    """Wrap a connected client socket with TLS."""
    ctx = context or ssl.create_default_context()
    return ctx.wrap_socket(sock, server_hostname=server_hostname)


def wrap_server_socket(
    sock: socket.socket,
    *,
    context: ssl.SSLContext,
) -> ssl.SSLSocket:
    """Wrap an accepted server socket with TLS."""
    return context.wrap_socket(sock, server_side=True)

