"""Layered runtime identity helpers."""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass
from typing import Optional

from secrets_kit.identity.core import HostIdentity
from secrets_kit.runtime.paths import DEFAULT_INSTANCE, runtime_instance

AGENT_ENV = "SECKIT_AGENT_ID"


@dataclass(frozen=True)
class RuntimeIdentity:
    """Identity layers for runtime routing.

    ``node_id`` comes from persistent host identity. ``agent_id`` and
    ``instance_id`` identify runtime participants and must not be derived from
    host:port addresses.
    """

    node_id: str
    signing_fingerprint: str
    agent_id: str
    instance_id: str


def default_agent_id(raw: Optional[str] = None) -> str:
    """Return an operator-provided agent id or a stable default label."""
    val = raw if raw is not None else os.environ.get(AGENT_ENV, "seckitd")
    val = str(val).strip() or "seckitd"
    if "/" in val or "\x00" in val or val in {".", ".."}:
        raise ValueError(f"invalid agent id: {val!r}")
    return val


def new_session_id() -> str:
    """Return a new per-connection session id."""
    return str(uuid.uuid4())


def runtime_identity(
    *,
    host_identity: HostIdentity,
    agent_id: Optional[str] = None,
    instance_id: Optional[str] = None,
) -> RuntimeIdentity:
    """Build a runtime identity from host identity plus runtime layers."""
    return RuntimeIdentity(
        node_id=host_identity.host_id,
        signing_fingerprint=host_identity.signing_fingerprint_hex(),
        agent_id=default_agent_id(agent_id),
        instance_id=runtime_instance(instance_id or DEFAULT_INSTANCE),
    )

