"""
secrets_kit.schemas.registry_store

Load and persist the canonical schema registry on the schema_registry system object.
"""

from __future__ import annotations

import json
from typing import Optional

from secrets_kit.backends.common import BackendError, normalize_backend
from secrets_kit.backends.dispatch import read_secret_entry, write_secret
from secrets_kit.backends.sqlite.exceptions import SQLiteBackendError
from secrets_kit.models import EntryMetadata, ValidationError, now_utc_iso
from secrets_kit.schemas.merge import merge_seed_into_registry
from secrets_kit.schemas.registry_doc import SchemaRegistryDocument
from secrets_kit.schemas.seed import load_seed_descriptors
from secrets_kit.system_objects import SystemObjectKind, locator_for_kind

_REGISTRY_PLACEHOLDER_VALUE = "seckit-schema-registry"
_REGISTRY_SOURCE = "schema-registry"


def _registry_metadata(*, payload_json: str) -> EntryMetadata:
    locator = locator_for_kind(kind=SystemObjectKind.SCHEMA_REGISTRY)
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


def load_schema_registry(
    *,
    backend: str,
    keychain_path: Optional[str] = None,
    sqlite_dev_mode: bool = False,
    bootstrap_if_missing: bool = True,
) -> SchemaRegistryDocument:
    """
    Load schema registry from the canonical system object.

    When missing and bootstrap_if_missing, merge bundled seeds and persist.
    """
    normalize_backend(backend)
    locator = locator_for_kind(kind=SystemObjectKind.SCHEMA_REGISTRY)
    try:
        _value, metadata = read_secret_entry(
            service=locator.service,
            account=locator.account,
            name=locator.name,
            backend=backend,
            keychain_path=keychain_path,
            sqlite_dev_mode=sqlite_dev_mode,
        )
        _ = _value
        raw = metadata.comment or "{}"
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValidationError("schema registry payload must be a JSON object")
        document = SchemaRegistryDocument.from_dict(payload)
        if bootstrap_if_missing and not document.schemas:
            raise ValidationError("schema registry is empty")
        return document
    except (BackendError, SQLiteBackendError, ValidationError, json.JSONDecodeError, KeyError):
        if not bootstrap_if_missing:
            return SchemaRegistryDocument.empty()
        empty = SchemaRegistryDocument.empty()
        seeds = load_seed_descriptors()
        merged = merge_seed_into_registry(registry=empty, seeds=seeds, allow_replace=False)
        save_schema_registry(
            registry=merged.document,
            backend=backend,
            keychain_path=keychain_path,
            sqlite_dev_mode=sqlite_dev_mode,
        )
        return merged.document


def save_schema_registry(
    *,
    registry: SchemaRegistryDocument,
    backend: str,
    keychain_path: Optional[str] = None,
    sqlite_dev_mode: bool = False,
) -> None:
    """Persist schema registry through normal backend write semantics."""
    normalize_backend(backend)
    locator = locator_for_kind(kind=SystemObjectKind.SCHEMA_REGISTRY)
    from secrets_kit.schemas.export import export_registry_text

    payload_json = export_registry_text(document=registry.to_dict())
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


def merge_seed_files_into_store(
    *,
    backend: str,
    paths: Optional[list] = None,
    allow_replace: bool = False,
    keychain_path: Optional[str] = None,
    sqlite_dev_mode: bool = False,
) -> SchemaRegistryDocument:
    """Load store registry, merge seeds, save, return updated document."""
    from pathlib import Path

    from secrets_kit.schemas.seed import load_seed_document

    current = load_schema_registry(
        backend=backend,
        keychain_path=keychain_path,
        sqlite_dev_mode=sqlite_dev_mode,
        bootstrap_if_missing=True,
    )
    if paths:
        seeds = load_seed_document(paths=[Path(item) for item in paths])
    else:
        seeds = load_seed_descriptors()
    merged = merge_seed_into_registry(registry=current, seeds=seeds, allow_replace=allow_replace)
    save_schema_registry(
        registry=merged.document,
        backend=backend,
        keychain_path=keychain_path,
        sqlite_dev_mode=sqlite_dev_mode,
    )
    return merged.document


__all__ = [
    "load_schema_registry",
    "merge_seed_files_into_store",
    "save_schema_registry",
]
