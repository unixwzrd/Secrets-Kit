"""
secrets_kit.schemas.metadata

Mirrors for :class:`~secrets_kit.models.core.EntryMetadata` dict shapes and slim registry rows.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import field_validator
from secrets_kit.models.core import (
    EntryMetadata,
    normalize_custom,
    normalize_domains,
    validate_entry_kind,
    validate_entry_type,
)
from secrets_kit.schemas.base import BaseSchema


class EntryMetadataCanonicalDict(BaseSchema):
    """Canonical ``EntryMetadata.to_dict()`` / ``asdict`` shape (all keys present).

    Validators delegate to ``models.core`` so normalization rules stay single-sourced.
    """

    name: str
    entry_type: str
    entry_kind: str
    tags: List[str]
    comment: str
    service: str
    account: str
    created_at: str
    updated_at: str
    source: str
    schema_version: int
    source_url: str
    source_label: str
    rotation_days: Optional[int] = None
    rotation_warn_days: Optional[int] = None
    last_rotated_at: str
    expires_at: str
    domains: List[str]
    custom: Dict[str, Any]
    entry_id: str
    content_hash: str = ""

    @field_validator("domains", mode="before")
    @classmethod
    def _domains(cls, v: object) -> List[str]:
        return normalize_domains(v)

    @field_validator("custom", mode="before")
    @classmethod
    def _custom(cls, v: object) -> Dict[str, Any]:
        return normalize_custom(v)

    @field_validator("entry_type", mode="after")
    @classmethod
    def _entry_type(cls, v: str) -> str:
        return validate_entry_type(entry_type=v)

    @field_validator("entry_kind", mode="after")
    @classmethod
    def _entry_kind(cls, v: str) -> str:
        return validate_entry_kind(entry_kind=v)

    @field_validator("tags", mode="before")
    @classmethod
    def _tags(cls, v: object) -> List[str]:
        """Normalize tags to a list of strings; ``None`` becomes ``[]``."""
        if v is None:
            return []
        if not isinstance(v, list):
            raise TypeError("tags must be a list")
        return [str(x) for x in v]


class RegistrySlimEntryDict(BaseSchema):
    """One v2 ``registry.json`` index row (allowed keys only)."""

    name: str
    service: str
    account: str
    entry_id: str = ""
    created_at: str = ""
    updated_at: str = ""
    sync_origin_host: str = ""

    @field_validator("entry_id", "created_at", "updated_at", "sync_origin_host", mode="before")
    @classmethod
    def _null_to_empty(cls, v: object) -> str:
        """Coerce ``None`` to empty string for optional string fields."""
        if v is None:
            return ""
        return str(v)


def assert_metadata_canonical_dict(meta: EntryMetadata) -> None:
    """Assert :meth:`~secrets_kit.models.core.EntryMetadata.to_dict` matches the canonical mirror."""
    EntryMetadataCanonicalDict.model_validate(meta.to_dict())


def parse_full_registry_metadata_with_schema_check(payload: Dict[str, Any]) -> EntryMetadata:
    """Parse legacy full registry metadata and validate canonical dict parity.

    Use when ``SECKIT_VALIDATE_REGISTRY_METADATA=1``. Authority remains
    :class:`~secrets_kit.models.core.EntryMetadata`.
    """
    meta = EntryMetadata.from_dict(payload)
    EntryMetadataCanonicalDict.model_validate(meta.to_dict())
    return meta


def validate_slim_registry_entry(payload: Dict[str, Any]) -> RegistrySlimEntryDict:
    """Validate a slim v2 registry row dict."""
    return RegistrySlimEntryDict.model_validate(payload)
