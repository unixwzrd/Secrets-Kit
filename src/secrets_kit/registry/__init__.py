"""
secrets_kit.registry

Local inventory and operator-defaults persistence (registry.json, defaults.json).

Metadata resolution lives in ``secrets_kit.registry.resolve``.
"""

from __future__ import annotations

import importlib

from secrets_kit.registry.storage import (
    RegistryError,
    defaults_path,
    ensure_defaults_storage,
    ensure_registry_storage,
    load_catalog,
    load_defaults,
    read_catalog,
    read_defaults,
    registry_dir,
    registry_path,
    save_catalog,
    save_defaults,
)

_RESOLVE_EXPORTS = frozenset({"merge_import_metadata", "read_metadata", "resolve_status"})


def __getattr__(name: str):
    if name in _RESOLVE_EXPORTS:
        resolve = importlib.import_module("secrets_kit.registry.resolve")
        value = getattr(resolve, name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "merge_import_metadata",
    "read_metadata",
    "resolve_status",
    "RegistryError",
    "defaults_path",
    "ensure_defaults_storage",
    "ensure_registry_storage",
    "load_catalog",
    "load_defaults",
    "read_catalog",
    "read_defaults",
    "registry_dir",
    "registry_path",
    "save_catalog",
    "save_defaults",
]
