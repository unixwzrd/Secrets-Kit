"""
secrets_kit.taxonomy.export

Deterministic JSON serialization for taxonomy registry export.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Mapping


def normalize_taxonomy_document(document: Mapping[str, Any]) -> Dict[str, Any]:
    """Return registry document with sorted lists and keys."""
    def _sort_entries(key: str) -> list[Dict[str, Any]]:
        raw = document.get(key, [])
        if not isinstance(raw, list):
            raw = []
        items = [dict(item) for item in raw if isinstance(item, dict)]
        return sorted(items, key=lambda row: str(row.get("name", "")))

    return {
        "registry_version": int(document.get("registry_version", 1)),
        "entry_types": _sort_entries("entry_types"),
        "entry_kinds": _sort_entries("entry_kinds"),
        "tags": _sort_entries("tags"),
    }


def export_taxonomy_registry_text(*, document: Mapping[str, Any]) -> str:
    """Serialize taxonomy registry to canonical JSON text."""
    normalized = normalize_taxonomy_document(document=document)
    return json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def export_taxonomy_registry_bytes(*, document: Mapping[str, Any]) -> bytes:
    return export_taxonomy_registry_text(document=document).encode("utf-8")


__all__ = [
    "export_taxonomy_registry_bytes",
    "export_taxonomy_registry_text",
    "normalize_taxonomy_document",
]
