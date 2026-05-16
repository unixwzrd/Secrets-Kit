"""
secrets_kit.schemas.backend

Mirrors for :class:`~secrets_kit.backends.base.BackendSecurityPosture` / ``BackendCapabilities`` ``asdict`` shapes.
"""

from __future__ import annotations

from typing import Any, Dict, Literal

from secrets_kit.schemas.base import BaseSchema

SetAtomicity = Literal["atomic", "eventual", "best_effort"]


class BackendSecurityPostureDict(BaseSchema):
    metadata_encrypted: bool
    safe_index_supported: bool
    requires_unlock_for_metadata: bool
    supports_secure_delete: bool


class BackendCapabilitiesDict(BaseSchema):
    supports_safe_index: bool
    supports_unlock_enumeration: bool
    supports_atomic_rename: bool
    supports_tombstones: bool
    supports_backend_migrate: bool
    supports_transactional_set: bool
    supports_selective_resolve: bool
    set_atomicity: SetAtomicity
    supports_peer_lineage_merge: bool
    supports_reconcile_transaction: bool


def validate_security_posture_dict(data: Dict[str, Any]) -> BackendSecurityPostureDict:
    return BackendSecurityPostureDict.model_validate(data)


def validate_capabilities_dict(data: Dict[str, Any]) -> BackendCapabilitiesDict:
    return BackendCapabilitiesDict.model_validate(data)
