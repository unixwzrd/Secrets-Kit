"""
secrets_kit.taxonomy.uuid

Deterministic vocabulary UUIDs from stored names.
"""

from __future__ import annotations

import uuid

from secrets_kit.taxonomy.normalize import resolve_stored_taxonomy_name

_TAXONOMY_NAMESPACE = uuid.UUID("f47ac10b-58cc-4372-a567-0e02b2c3d479")


def taxonomy_uuid(*, kind: str, name: str, force_raw: bool = False) -> str:
    """Return deterministic UUID string for a vocabulary kind + stored name."""
    stored = resolve_stored_taxonomy_name(raw=name, force_raw=force_raw)
    return str(uuid.uuid5(_TAXONOMY_NAMESPACE, f"{kind}:{stored}"))


def entry_type_id_for_name(*, name: str, force_raw: bool = False) -> str:
    return taxonomy_uuid(kind="entry_type", name=name, force_raw=force_raw)


def entry_kind_id_for_name(*, name: str, force_raw: bool = False) -> str:
    return taxonomy_uuid(kind="entry_kind", name=name, force_raw=force_raw)


def tag_id_for_name(*, name: str, force_raw: bool = False) -> str:
    return taxonomy_uuid(kind="tag", name=name, force_raw=force_raw)


__all__ = [
    "entry_kind_id_for_name",
    "entry_type_id_for_name",
    "tag_id_for_name",
    "taxonomy_uuid",
]
