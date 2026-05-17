"""Plain TCP stream helpers for peer/runtime transports."""

from __future__ import annotations

import socket
from dataclasses import dataclass


@dataclass(frozen=True)
class TcpEndpoint:
    """Discovered TCP endpoint address. This is not peer identity."""

    host: str
    port: int


def connect_tcp(endpoint: TcpEndpoint, *, timeout_s: float = 30.0) -> socket.socket:
    """Open a blocking TCP stream connection."""
    sock = socket.create_connection((endpoint.host, int(endpoint.port)), timeout=timeout_s)
    return sock


def listen_tcp(endpoint: TcpEndpoint, *, backlog: int = 8) -> socket.socket:
    """Create a blocking TCP listener for explicit peer/relay experiments."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((endpoint.host, int(endpoint.port)))
    sock.listen(backlog)
    return sock

