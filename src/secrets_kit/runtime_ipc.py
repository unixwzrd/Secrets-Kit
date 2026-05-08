"""Documentary IPC / transport contracts for future local runtime mediators.

Unstable scaffolding only: **not** a wire codec, **not** a daemon, **not** an RPC framework.
Types here exist to align code with repository docs:
``docs/IPC_SEMANTICS_ADR.md`` and ``docs/RUNTIME_SESSION_ADR.md``.

**Do not** add secret plaintext fields to envelope metadata types. Payload bytes on the wire are **TBD**;
``RuntimeMediatorProtocol`` is a byte-stream shape hint, not an implemented socket.

Avoid naming that implies a multi-tenant broker or mesh (no ``Rpc*``, ``Broker*``, ``Grpc*``, ``Mesh*``).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Mapping, Protocol


class RuntimeIpcOperation(str, Enum):
    """Documentary operation labels for future local IPC; **not** a stable wire opcode set."""

    ping = "ping"
    noop = "noop"


class RuntimeIpcErrorCode(str, Enum):
    """Documentary error categories for redacted, deterministic failures — not a full IPC contract."""

    not_implemented = "not_implemented"
    unavailable = "unavailable"
    unauthorized = "unauthorized"
    invalid_request = "invalid_request"
    internal = "internal"


@dataclass(frozen=True)
class RuntimeIpcEnvelope:
    """Metadata-only request/response envelope — **no** plaintext secret fields.

    ``metadata`` must contain only non-secret routing or correlation keys (e.g. request_id, locale).
    Secret material belongs in a future **opaque** payload layer **not** modeled as structured fields here.
    """

    request_id: str
    operation: RuntimeIpcOperation
    metadata: Mapping[str, str]

    def __repr__(self) -> str:
        return (
            f"RuntimeIpcEnvelope(request_id={self.request_id!r}, "
            f"operation={self.operation!r}, metadata=<{len(self.metadata)} keys>)"
        )


@dataclass(frozen=True)
class RuntimeIpcFailure:
    """Structured failure surface for documentation — **must not** carry secret values."""

    code: RuntimeIpcErrorCode
    message: str

    def __repr__(self) -> str:
        return f"RuntimeIpcFailure(code={self.code!r}, message=<redacted_len={len(self.message)}>)"


class RuntimeMediatorProtocol(Protocol):
    """Transport mediator byte duplex (documentary).

    Same-user local IPC may carry opaque or future-framed bytes; **no** default implementation here.
    """

    def send_bytes(self, data: bytes) -> None:
        """Send one logical unit (framing TBD)."""

    def recv_bytes(self) -> bytes:
        """Receive one logical unit (framing TBD)."""


class LocalRuntimeTransport(RuntimeMediatorProtocol, Protocol):
    """Same-user, same-host **local** stream transport — documentary Protocol specialization."""


class RuntimeRouterTransport(RuntimeMediatorProtocol, Protocol):
    """User-scoped **runtime router** transport — documentary Protocol specialization."""
