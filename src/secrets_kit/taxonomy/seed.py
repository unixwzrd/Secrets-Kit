"""
secrets_kit.taxonomy.seed

Load bundled and user taxonomy seed JSON (bootstrap only).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

from secrets_kit.models import ValidationError
from secrets_kit.taxonomy.merge import merge_taxonomy_documents
from secrets_kit.taxonomy.registry_doc import TaxonomyEntry, TaxonomyRegistryDocument
from secrets_kit.taxonomy.uuid import (
    entry_kind_id_for_name,
    entry_type_id_for_name,
    tag_id_for_name,
)

_BUILTIN_DIR = Path(__file__).resolve().parent / "builtin"


def _assign_ids(*, document: TaxonomyRegistryDocument) -> TaxonomyRegistryDocument:
    """Fill missing entry ids from canonical names."""
    types: List[TaxonomyEntry] = []
    for item in document.entry_types:
        entry_id = item.id or entry_type_id_for_name(name=item.name)
        types.append(
            TaxonomyEntry(
                id=entry_id,
                name=item.name,
                builtin=item.builtin,
                operator_comment=item.operator_comment,
            )
        )
    kinds: List[TaxonomyEntry] = []
    for item in document.entry_kinds:
        entry_id = item.id or entry_kind_id_for_name(name=item.name)
        kinds.append(
            TaxonomyEntry(
                id=entry_id,
                name=item.name,
                builtin=item.builtin,
                operator_comment=item.operator_comment,
            )
        )
    tags: List[TaxonomyEntry] = []
    for item in document.tags:
        entry_id = item.id or tag_id_for_name(name=item.name)
        tags.append(
            TaxonomyEntry(
                id=entry_id,
                name=item.name,
                builtin=item.builtin,
                operator_comment=item.operator_comment,
            )
        )
    return TaxonomyRegistryDocument(
        registry_version=document.registry_version,
        entry_types=types,
        entry_kinds=kinds,
        tags=tags,
    )


def _load_seed_file(*, path: Path) -> TaxonomyRegistryDocument:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValidationError(f"taxonomy seed must be a JSON object: {path}")
    partial = TaxonomyRegistryDocument.from_dict(payload)
    return _assign_ids(document=partial)


def load_bundled_taxonomy_seeds() -> TaxonomyRegistryDocument:
    """Merge bundled taxonomy seed files into one document."""
    merged = TaxonomyRegistryDocument.empty()
    if not _BUILTIN_DIR.is_dir():
        return merged
    for path in sorted(_BUILTIN_DIR.glob("*.json")):
        piece = _load_seed_file(path=path)
        merged = merge_taxonomy_documents(base=merged, overlay=piece).document
    return merged


def load_user_taxonomy_seeds(*, user_dir: Path | None = None) -> TaxonomyRegistryDocument:
    """Load optional ~/.config/seckit/taxonomy/*.json seed files."""
    if user_dir is None:
        user_dir = Path.home() / ".config" / "seckit" / "taxonomy"
    if not user_dir.is_dir():
        return TaxonomyRegistryDocument.empty()
    merged = TaxonomyRegistryDocument.empty()
    for path in sorted(user_dir.glob("*.json")):
        piece = _load_seed_file(path=path)
        merged = merge_taxonomy_documents(base=merged, overlay=piece).document
    return merged


def load_taxonomy_seed_document(*, paths: List[Path] | None = None) -> TaxonomyRegistryDocument:
    """Load seeds from explicit paths or default bundled+user locations."""
    if paths:
        merged = TaxonomyRegistryDocument.empty()
        for path in paths:
            piece = _load_seed_file(path=path)
            merged = merge_taxonomy_documents(base=merged, overlay=piece).document
        return merged
    bundled = load_bundled_taxonomy_seeds()
    user = load_user_taxonomy_seeds()
    return merge_taxonomy_documents(base=bundled, overlay=user).document


__all__ = [
    "load_bundled_taxonomy_seeds",
    "load_taxonomy_seed_document",
    "load_user_taxonomy_seeds",
]
