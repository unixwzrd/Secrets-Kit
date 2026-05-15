"""Documentary types for runtime authority vocabulary (non-contract).

This module exists to reduce drift between docs and code. It does **not** define a stable
public API for daemons, IPC, caching, or lease enforcement.

**Do not** use :class:`RuntimeAccessResult` as a return type for :class:`~secrets_kit.backends.base.BackendStore`
methods; :class:`~secrets_kit.backends.base.ResolvedEntry` remains the resolve primitive.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional


class RuntimeExposureLevel(str, Enum):
    """Descriptive operational vocabulary only — not formal security classifications."""

    index_only = "index_only"
    resolved_within_handling = "resolved_within_handling"
    materialized = "materialized"
    injected = "injected"
    exported = "exported"


class MaterializationMode(str, Enum):
    """Channel hints for materialization paths (documentation-oriented)."""

    stdout = "stdout"
    env_child = "env_child"
    file = "file"
    ipc_future = "ipc_future"


class ResolveIntent(str, Enum):
    """Lightweight intent labels; no policy enforcement in this phase."""

    metadata_preference = "metadata_preference"
    full_authority = "full_authority"


@dataclass
class RuntimeLease:
    """Placeholder for future lease/time-bound policy (not enforced).

    Out of scope for this phase: enforcement, revocation, TTL validation, auditing,
    caching guarantees, MFA, remote issuance, and stable lease APIs.
    """

    lease_id: Optional[str] = None
    issued_at: Optional[str] = None
    expires_at: Optional[str] = None
    notes: Optional[str] = None


@dataclass(frozen=True)
class RuntimeAccessResult:
    """Informational snapshot for docs/diagrams — not an API or IPC contract.

    Must not be used as a return type for :meth:`~secrets_kit.backends.base.BackendStore.resolve_by_entry_id`,
    :meth:`~secrets_kit.backends.base.BackendStore.resolve_by_locator`, or related store methods.
    Does not imply caching, lease validity, or cross-process semantics.
    """

    entry_id: Optional[str] = None
    intent: Optional[ResolveIntent] = None
    lease: Optional[RuntimeLease] = None


#: Maps :class:`BackendStore` abstract surface names to :class:`RuntimeExposureLevel` for doc/tests drift
#: guards only — not used for authorization or runtime behavior.
BACKEND_INTERFACE_EXPOSURE: Dict[str, RuntimeExposureLevel] = {
    "security_posture": RuntimeExposureLevel.index_only,
    "capabilities": RuntimeExposureLevel.index_only,
    "set_entry": RuntimeExposureLevel.resolved_within_handling,
    "get_secret": RuntimeExposureLevel.resolved_within_handling,
    "metadata": RuntimeExposureLevel.resolved_within_handling,
    "resolve_by_entry_id": RuntimeExposureLevel.resolved_within_handling,
    "resolve_by_locator": RuntimeExposureLevel.resolved_within_handling,
    "delete_entry": RuntimeExposureLevel.resolved_within_handling,
    "exists": RuntimeExposureLevel.index_only,
    "iter_index": RuntimeExposureLevel.index_only,
    "iter_unlocked": RuntimeExposureLevel.resolved_within_handling,
    "rename_entry": RuntimeExposureLevel.resolved_within_handling,
    "rebuild_index": RuntimeExposureLevel.resolved_within_handling,
}


def _abstract_backend_method_names() -> frozenset[str]:
    """Return abstract method names defined on :class:`~secrets_kit.backends.base.BackendStore`."""
    from secrets_kit.backends.base import BackendStore

    return frozenset(getattr(BackendStore, "__abstractmethods__", frozenset()))


def backend_interface_exposure_complete() -> bool:
    """Return True if :data:`BACKEND_INTERFACE_EXPOSURE` keys match abstract ``BackendStore`` names."""
    names = _abstract_backend_method_names()
    if not names:
        return False
    return names == frozenset(BACKEND_INTERFACE_EXPOSURE.keys())
