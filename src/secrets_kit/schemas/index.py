"""Mirrors for :meth:`~secrets_kit.backends.base.IndexRow.to_safe_dict` / ``to_diag_dict``."""

from __future__ import annotations

from typing import Any, Dict, Optional

from secrets_kit.schemas.base import BaseSchema


class IndexRowSafeDict(BaseSchema):
    """Shape emitted by :meth:`secrets_kit.backends.base.IndexRow.to_safe_dict`."""

    entry_id: str
    locator_hash: str
    locator_hint: str
    updated_at: str
    deleted: bool
    deleted_at: str
    generation: int
    tombstone_generation: int
    index_schema_version: int
    payload_schema_version: int
    backend_impl_version: int


class IndexRowDiagDict(BaseSchema):
    """Shape emitted by :meth:`secrets_kit.backends.base.IndexRow.to_diag_dict`."""

    entry_id: str
    locator_hash: str
    locator_hint: str
    updated_at: str
    deleted: bool
    deleted_at: str
    generation: int
    tombstone_generation: int
    index_schema_version: int
    payload_schema_version: int
    backend_impl_version: int
    payload_ref: Optional[str] = None
    corrupt: bool = False
    corrupt_reason: str = ""
    last_validation_at: str = ""


def validate_safe_index_dict(row: Dict[str, Any]) -> IndexRowSafeDict:
    """Validate a listing dict (tests and CLI-adjacent checks)."""
    return IndexRowSafeDict.model_validate(row)


def validate_diag_index_dict(row: Dict[str, Any]) -> IndexRowDiagDict:
    """Validate a diagnostics dict (tests and optional doctor checks)."""
    return IndexRowDiagDict.model_validate(row)
