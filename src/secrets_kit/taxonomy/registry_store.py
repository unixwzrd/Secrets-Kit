"""
secrets_kit.taxonomy.registry_store

Load and persist the canonical taxonomy registry on the taxonomy_registry system object.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from secrets_kit.backends.common import BackendError, normalize_backend
from secrets_kit.backends.dispatch import read_secret_entry, write_secret
from secrets_kit.backends.sqlite.exceptions import SQLiteBackendError
from secrets_kit.models import EntryMetadata, ValidationError, now_utc_iso
from secrets_kit.system_objects import SystemObjectKind, locator_for_kind
from secrets_kit.taxonomy.export import export_taxonomy_registry_text
from secrets_kit.taxonomy.merge import merge_seed_into_registry
from secrets_kit.taxonomy.registry_doc import TaxonomyRegistryDocument
from secrets_kit.taxonomy.seed import load_taxonomy_seed_document

_REGISTRY_PLACEHOLDER_VALUE = "seckit-taxonomy-registry"
_REGISTRY_SOURCE = "taxonomy-registry"


def _registry_metadata(*, payload_json: str) -> EntryMetadata:
    locator = locator_for_kind(kind=SystemObjectKind.TAXONOMY_REGISTRY)
    return EntryMetadata(
        name=locator.name,
        service=locator.service,
        account=locator.account,
        entry_type="secret",
        entry_kind="generic",
        source=_REGISTRY_SOURCE,
        comment=payload_json,
        schema_id="builtin.secret.generic",
        schema_version=1,
        updated_at=now_utc_iso(),
    )


def load_taxonomy_registry(
    *,
    backend: str,
    keychain_path: Optional[str] = None,
    sqlite_dev_mode: bool = False,
    bootstrap_if_missing: bool = True,
) -> TaxonomyRegistryDocument:
    """Load taxonomy registry from the canonical system object."""
    normalize_backend(backend)
    locator = locator_for_kind(kind=SystemObjectKind.TAXONOMY_REGISTRY)
    try:
        _value, metadata = read_secret_entry(
            service=locator.service,
            account=locator.account,
            name=locator.name,
            backend=backend,
            keychain_path=keychain_path,
            sqlite_dev_mode=sqlite_dev_mode,
        )
        raw = metadata.comment or "{}"
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValidationError("taxonomy registry payload must be a JSON object")
        document = TaxonomyRegistryDocument.from_dict(payload)
        if bootstrap_if_missing and not document.entry_types and not document.entry_kinds:
            raise ValidationError("taxonomy registry is empty")
        return document
    except (BackendError, SQLiteBackendError, ValidationError, json.JSONDecodeError, KeyError):
        if not bootstrap_if_missing:
            return TaxonomyRegistryDocument.empty()
        empty = TaxonomyRegistryDocument.empty()
        seeds = load_taxonomy_seed_document()
        merged = merge_seed_into_registry(registry=empty, seeds=seeds)
        save_taxonomy_registry(
            registry=merged.document,
            backend=backend,
            keychain_path=keychain_path,
            sqlite_dev_mode=sqlite_dev_mode,
        )
        return merged.document


def save_taxonomy_registry(
    *,
    registry: TaxonomyRegistryDocument,
    backend: str,
    keychain_path: Optional[str] = None,
    sqlite_dev_mode: bool = False,
) -> None:
    """Persist taxonomy registry through normal backend write semantics."""
    normalize_backend(backend)
    locator = locator_for_kind(kind=SystemObjectKind.TAXONOMY_REGISTRY)
    payload_json = export_taxonomy_registry_text(document=registry.to_dict())
    metadata = _registry_metadata(payload_json=payload_json)
    write_secret(
        service=locator.service,
        account=locator.account,
        name=locator.name,
        value=_REGISTRY_PLACEHOLDER_VALUE,
        metadata=metadata,
        backend=backend,
        keychain_path=keychain_path,
        sqlite_dev_mode=sqlite_dev_mode,
        label=locator.name,
    )


def merge_seed_files_into_taxonomy_store(
    *,
    backend: str,
    paths: Optional[list] = None,
    keychain_path: Optional[str] = None,
    sqlite_dev_mode: bool = False,
) -> TaxonomyRegistryDocument:
    """Load store registry, merge seeds, save, return updated document."""
    current = load_taxonomy_registry(
        backend=backend,
        keychain_path=keychain_path,
        sqlite_dev_mode=sqlite_dev_mode,
        bootstrap_if_missing=True,
    )
    if paths:
        seeds = load_taxonomy_seed_document(paths=[Path(item) for item in paths])
    else:
        seeds = load_taxonomy_seed_document()
    merged = merge_seed_into_registry(registry=current, seeds=seeds)
    save_taxonomy_registry(
        registry=merged.document,
        backend=backend,
        keychain_path=keychain_path,
        sqlite_dev_mode=sqlite_dev_mode,
    )
    return merged.document


__all__ = [
    "load_taxonomy_registry",
    "merge_seed_files_into_taxonomy_store",
    "save_taxonomy_registry",
]
