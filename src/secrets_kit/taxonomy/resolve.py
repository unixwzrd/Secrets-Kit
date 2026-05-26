"""
secrets_kit.taxonomy.resolve

Resolve and register vocabulary names for writes (registry authority).
"""

from __future__ import annotations

from dataclasses import dataclass

from secrets_kit.taxonomy.normalize import resolve_stored_taxonomy_name
from secrets_kit.taxonomy.registry_doc import TaxonomyRegistryDocument
from secrets_kit.taxonomy.validate import (
    policy_mode_active,
    require_known_entry_kind,
    require_known_entry_type,
)


@dataclass
class ResolvedVocabularyNames:
    """Canonical type/kind/tag strings for one metadata write."""

    entry_type: str
    entry_kind: str
    tags: list[str]


def resolve_vocabulary_for_write(
    *,
    registry: TaxonomyRegistryDocument,
    entry_type: str,
    entry_kind: str,
    tags: list[str],
    sqlite_dev_mode: bool = False,
    policy_mode: bool = False,
    force_raw: bool = False,
    auto_register: bool = True,
) -> tuple[ResolvedVocabularyNames, TaxonomyRegistryDocument]:
    """
    Resolve vocabulary names and optionally register unknown type/kind locally.

    Tags are normalized but registered softly (no strict policy on unknown tags).
    """
    stored_type = resolve_stored_taxonomy_name(raw=entry_type, force_raw=force_raw)
    stored_kind = resolve_stored_taxonomy_name(raw=entry_kind, force_raw=force_raw)
    strict = policy_mode_active(sqlite_dev_mode=sqlite_dev_mode, force_policy=policy_mode)

    require_known_entry_type(registry=registry, name=stored_type, policy_mode=strict)
    require_known_entry_kind(registry=registry, name=stored_kind, policy_mode=strict)

    if auto_register or not strict:
        registry.upsert_entry_type(name=stored_type, force_raw=force_raw)
        registry.upsert_entry_kind(name=stored_kind, force_raw=force_raw)

    stored_tags: list[str] = []
    seen: set[str] = set()
    for raw_tag in tags:
        stored_tag = resolve_stored_taxonomy_name(raw=str(raw_tag), force_raw=force_raw)
        key = stored_tag.lower()
        if key in seen:
            continue
        seen.add(key)
        stored_tags.append(stored_tag)
        if auto_register:
            registry.upsert_tag(name=stored_tag, force_raw=force_raw)

    return (
        ResolvedVocabularyNames(entry_type=stored_type, entry_kind=stored_kind, tags=stored_tags),
        registry,
    )


__all__ = ["ResolvedVocabularyNames", "resolve_vocabulary_for_write"]
