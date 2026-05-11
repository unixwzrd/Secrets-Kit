"""Minimal loopback opaque transport for Phase 5D runtime testing (no framework)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class LoopbackTransport:
    """In-process transport: connect/disconnect and send opaque bytes; counts only.

    ``inject_connect_failures`` / ``inject_send_failures`` consume one failure per event for tests.
    """

    bytes_sent: int = 0
    chunks: List[bytes] = field(default_factory=list)
    _connected: bool = False
    inject_connect_failures: int = 0
    inject_send_failures: int = 0
    connect_calls: int = 0
    disconnect_calls: int = 0

    @property
    def connected(self) -> bool:
        return self._connected

    def connect(self) -> None:
        self.connect_calls += 1
        if self.inject_connect_failures > 0:
            self.inject_connect_failures -= 1
            raise ConnectionError("loopback injected connect failure")
        self._connected = True

    def disconnect(self) -> None:
        self.disconnect_calls += 1
        self._connected = False

    def send_opaque(self, data: bytes) -> None:
        if not self._connected:
            raise ConnectionError("loopback not connected")
        if self.inject_send_failures > 0:
            self.inject_send_failures -= 1
            self._connected = False
            raise BrokenPipeError("loopback injected send failure")
        self.bytes_sent += len(data)
        self.chunks.append(bytes(data))

    def reset_counts(self) -> None:
        """Test helper: clear tallies without changing connection state."""
        self.bytes_sent = 0
        self.chunks.clear()
