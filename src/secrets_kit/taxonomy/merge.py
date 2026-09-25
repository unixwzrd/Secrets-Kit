"""
secrets_kit.taxonomy.merge

Add-only merge of taxonomy registry documents.
"""

from __future__ import annotations

from dataclasses import dataclass

from secrets_kit.taxonomy.registry_doc import TaxonomyEntry, TaxonomyRegistryDocument


@dataclass
class TaxonomyMergeResult:
    """Result of merging taxonomy seed data into a registry."""

    document: TaxonomyRegistryDocument
    added_types: int = 0
    added_kinds: int = 0
    added_tags: int = 0


def _merge_list(
    *,
    base: list[TaxonomyEntry],
    overlay: list[TaxonomyEntry],
) -> tuple[list[TaxonomyEntry], int]:
    by_name = {item.name: item for item in base}
    added = 0
    for item in overlay:
        if item.name in by_name:
            existing = by_name[item.name]
            if existing.builtin and not item.builtin:
                continue
            if item.operator_comment and not existing.operator_comment:
                by_name[item.name] = TaxonomyEntry(
                    id=existing.id,
                    name=existing.name,
                    builtin=existing.builtin,
                    operator_comment=item.operator_comment,
                )
            continue
        by_name[item.name] = item
        added += 1
    return sorted(by_name.values(), key=lambda entry: entry.name), added


def merge_taxonomy_documents(
    *,
    base: TaxonomyRegistryDocument,
    overlay: TaxonomyRegistryDocument,
) -> TaxonomyMergeResult:
    """
    Add-only merge overlay into base by canonical name.

    Never removes or renames builtins silently.
    """
    types, added_types = _merge_list(base=list(base.entry_types), overlay=list(overlay.entry_types))
    kinds, added_kinds = _merge_list(base=list(base.entry_kinds), overlay=list(overlay.entry_kinds))
    tags, added_tags = _merge_list(base=list(base.tags), overlay=list(overlay.tags))
    version = max(base.registry_version, overlay.registry_version)
    return TaxonomyMergeResult(
        document=TaxonomyRegistryDocument(
            registry_version=version,
            entry_types=types,
            entry_kinds=kinds,
            tags=tags,
        ),
        added_types=added_types,
        added_kinds=added_kinds,
        added_tags=added_tags,
    )


def merge_seed_into_registry(
    *,
    registry: TaxonomyRegistryDocument,
    seeds: TaxonomyRegistryDocument,
) -> TaxonomyMergeResult:
    """Merge seed document into an existing registry."""
    if seeds.registry_version > registry.registry_version:
        registry.registry_version = seeds.registry_version
    return merge_taxonomy_documents(base=registry, overlay=seeds)


__all__ = ["TaxonomyMergeResult", "merge_seed_into_registry", "merge_taxonomy_documents"]
