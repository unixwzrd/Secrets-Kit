"""
secrets_kit.internal_metadata

Internal metadata field names reserved for backend sync/lineage state.
"""

from __future__ import annotations

ENTRY_ID_CUSTOM_KEY = "seckit_entry_id"
SYNC_ORIGIN_CUSTOM_KEY = "seckit_sync_origin_host"
INTERNAL_CUSTOM_FIELDS = frozenset({ENTRY_ID_CUSTOM_KEY, SYNC_ORIGIN_CUSTOM_KEY})
RESERVED_CUSTOM_PREFIX = "seckit_"


def is_internal_custom_field(field_name: str) -> bool:
    """Return whether a custom key is internal backend metadata."""
    return field_name in INTERNAL_CUSTOM_FIELDS


def is_reserved_custom_field(field_name: str) -> bool:
    """Return whether a custom key is reserved for Seckit internals."""
    return field_name.startswith(RESERVED_CUSTOM_PREFIX)


__all__ = [
    "ENTRY_ID_CUSTOM_KEY",
    "INTERNAL_CUSTOM_FIELDS",
    "SYNC_ORIGIN_CUSTOM_KEY",
    "is_internal_custom_field",
    "is_reserved_custom_field",
]
