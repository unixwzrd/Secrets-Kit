"""
secrets_kit.taxonomy.uuid

Deterministic vocabulary UUIDs from stored names.
"""

from __future__ import annotations

from secrets_kit.identifiers import deterministic_identifier, deterministic_uuid_text
from secrets_kit.taxonomy.normalize import resolve_stored_taxonomy_name

_TAXONOMY_NAMESPACE = "taxonomy"


def taxonomy_uuid(*, kind: str, name: str, force_raw: bool = False) -> str:
    """Return deterministic UUID string for a vocabulary kind + stored name."""
    stored = resolve_stored_taxonomy_name(raw=name, force_raw=force_raw)
    return deterministic_uuid_text(namespace=_TAXONOMY_NAMESPACE, name=f"{kind}:{stored}")


def entry_type_id_for_name(*, name: str, force_raw: bool = False) -> str:
    stored = resolve_stored_taxonomy_name(raw=name, force_raw=force_raw)
    return deterministic_identifier(
        identifier_type="entry_type",
        namespace=_TAXONOMY_NAMESPACE,
        name=f"entry_type:{stored}",
    )


def entry_kind_id_for_name(*, name: str, force_raw: bool = False) -> str:
    stored = resolve_stored_taxonomy_name(raw=name, force_raw=force_raw)
    return deterministic_identifier(
        identifier_type="entry_kind",
        namespace=_TAXONOMY_NAMESPACE,
        name=f"entry_kind:{stored}",
    )


def tag_id_for_name(*, name: str, force_raw: bool = False) -> str:
    return taxonomy_uuid(kind="tag", name=name, force_raw=force_raw)


__all__ = [
    "entry_kind_id_for_name",
    "entry_type_id_for_name",
    "tag_id_for_name",
    "taxonomy_uuid",
]
