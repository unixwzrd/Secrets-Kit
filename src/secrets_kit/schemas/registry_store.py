"""
secrets_kit.schemas.registry_store

Load and persist the canonical schema registry on the schema_registry system object.
"""

from __future__ import annotations

from pathlib import Path

from secrets_kit.backends.common import normalize_backend
from secrets_kit.models import ValidationError
from secrets_kit.registry.storage import RegistryError, read_catalog, save_catalog
from secrets_kit.schemas.merge import merge_seed_into_registry
from secrets_kit.schemas.registry_doc import SchemaRegistryDocument
from secrets_kit.schemas.seed import load_seed_descriptors


def load_schema_registry(
    *,
    backend: str,
    keychain_path: str | None = None,
    bootstrap_if_missing: bool = False,
    home: Path | None = None,
) -> SchemaRegistryDocument:
    """
    Load schema registry from registry.json.

    When missing and bootstrap_if_missing, merge bundled seeds and persist.
    """
    # Keep backend arguments for existing call sites; registry.json is local catalog state.
    _ = normalize_backend(backend), keychain_path
    try:
        document = read_catalog(home=home)
        if not document.schemas:
            raise ValidationError("schema registry is empty")
        return document
    except (RegistryError, ValidationError) as exc:
        if not bootstrap_if_missing:
            raise ValidationError(str(exc)) from exc
        empty = SchemaRegistryDocument.empty()
        seeds = load_seed_descriptors()
        merged = merge_seed_into_registry(registry=empty, seeds=seeds, allow_replace=False)
        save_catalog(document=merged.document, home=home)
        return merged.document


def save_schema_registry(
    *,
    registry: SchemaRegistryDocument,
    backend: str,
    keychain_path: str | None = None,
    home: Path | None = None,
) -> None:
    """Persist schema registry to registry.json."""
    _ = normalize_backend(backend), keychain_path
    save_catalog(document=registry, home=home)


def merge_seed_files_into_store(
    *,
    backend: str,
    paths: list[str | Path] | None = None,
    allow_replace: bool = False,
    keychain_path: str | None = None,
    home: Path | None = None,
) -> SchemaRegistryDocument:
    """Load store registry, merge seeds, save, return updated document."""
    from secrets_kit.schemas.seed import load_seed_document

    current = load_schema_registry(
        backend=backend,
        keychain_path=keychain_path,
        bootstrap_if_missing=True,
        home=home,
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
        home=home,
    )
    return merged.document


__all__ = [
    "load_schema_registry",
    "merge_seed_files_into_store",
    "save_schema_registry",
]
