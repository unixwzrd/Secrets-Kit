"""
secrets_kit.registry

Local inventory and operator-defaults persistence (registry.json, defaults.json).

Metadata resolution lives in ``secrets_kit.registry.resolve``.
"""

from __future__ import annotations

from secrets_kit.registry.resolve import merge_import_metadata, read_metadata, resolve_status
from secrets_kit.registry.storage import (
    RegistryError,
    defaults_path,
    delete_metadata,
    ensure_defaults_storage,
    ensure_registry_storage,
    load_defaults,
    load_registry,
    registry_dir,
    registry_path,
    save_defaults,
    save_registry,
    upsert_metadata,
)

__all__ = [
    "merge_import_metadata",
    "read_metadata",
    "resolve_status",
    "RegistryError",
    "defaults_path",
    "delete_metadata",
    "ensure_defaults_storage",
    "ensure_registry_storage",
    "load_defaults",
    "load_registry",
    "registry_dir",
    "registry_path",
    "save_defaults",
    "save_registry",
    "upsert_metadata",
]
