"""
secrets_kit.taxonomy.register

Persist vocabulary registry updates for CLI writes (set, import).
"""

from __future__ import annotations

from typing import Optional

from secrets_kit.taxonomy.export import export_taxonomy_registry_text
from secrets_kit.taxonomy.registry_store import load_taxonomy_registry, save_taxonomy_registry
from secrets_kit.taxonomy.resolve import ResolvedVocabularyNames, resolve_vocabulary_for_write


def sync_vocabulary_on_write(
    *,
    entry_type: str,
    entry_kind: str,
    tags: list[str],
    backend: str,
    keychain_path: Optional[str] = None,
    sqlite_dev_mode: bool = False,
    auto_register: bool = True,
) -> ResolvedVocabularyNames:
    """
    Load taxonomy registry, register type/kind/tags for one write, persist when changed.

    Caller must already have applied canonical-name policy (CLI prompts / flags).
    """
    registry = load_taxonomy_registry(
        backend=backend,
        keychain_path=keychain_path,
        sqlite_dev_mode=sqlite_dev_mode,
    )
    before = export_taxonomy_registry_text(document=registry.to_dict())
    vocab, registry = resolve_vocabulary_for_write(
        registry=registry,
        entry_type=entry_type,
        entry_kind=entry_kind,
        tags=tags,
        sqlite_dev_mode=sqlite_dev_mode,
        auto_register=auto_register,
    )
    after = export_taxonomy_registry_text(document=registry.to_dict())
    if after != before:
        save_taxonomy_registry(
            registry=registry,
            backend=backend,
            keychain_path=keychain_path,
            sqlite_dev_mode=sqlite_dev_mode,
        )
    return vocab


__all__ = ["sync_vocabulary_on_write"]
