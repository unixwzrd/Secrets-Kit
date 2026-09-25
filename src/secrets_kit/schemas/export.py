"""
secrets_kit.schemas.export

Deterministic JSON serialization for schema registry export.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Mapping


def _sorted_fields(fields: Mapping[str, Any]) -> Dict[str, Any]:
    return {key: fields[key] for key in sorted(fields.keys())}


def normalize_descriptor_dict(descriptor: Mapping[str, Any]) -> Dict[str, Any]:
    """Return descriptor dict with sorted field keys for canonical export."""
    fields = descriptor.get("fields", {})
    if not isinstance(fields, dict):
        fields = {}
    return {
        "schema_id": descriptor["schema_id"],
        "schema_version": descriptor["schema_version"],
        "entry_type": descriptor["entry_type"],
        "entry_kind": descriptor["entry_kind"],
        "fields": _sorted_fields(fields),
    }


def normalize_registry_document(document: Mapping[str, Any]) -> Dict[str, Any]:
    """Return registry document with sorted schema and deprecated keys."""
    schemas_raw = document.get("schemas", {})
    if not isinstance(schemas_raw, dict):
        schemas_raw = {}
    schemas: Dict[str, Any] = {}
    for schema_id in sorted(schemas_raw.keys()):
        item = schemas_raw[schema_id]
        if isinstance(item, dict):
            normalized = dict(item)
            normalized["schema_id"] = schema_id
            schemas[schema_id] = normalize_descriptor_dict(normalized)

    deprecated_raw = document.get("deprecated", {})
    if not isinstance(deprecated_raw, dict):
        deprecated_raw = {}
    deprecated = {key: deprecated_raw[key] for key in sorted(deprecated_raw.keys())}

    return {
        "registry_version": int(document.get("registry_version", 1)),
        "schemas": schemas,
        "deprecated": deprecated,
    }


def export_registry_bytes(*, document: Mapping[str, Any]) -> bytes:
    """Serialize registry document to canonical UTF-8 JSON bytes."""
    normalized = normalize_registry_document(document=document)
    return json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def export_registry_text(*, document: Mapping[str, Any]) -> str:
    """Serialize registry document to canonical JSON text."""
    return export_registry_bytes(document=document).decode("utf-8")


def export_descriptor_bytes(*, descriptor: Mapping[str, Any]) -> bytes:
    """Serialize one descriptor to canonical JSON bytes."""
    normalized = normalize_descriptor_dict(descriptor)
    return json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


__all__ = [
    "export_descriptor_bytes",
    "export_registry_bytes",
    "export_registry_text",
    "normalize_descriptor_dict",
    "normalize_registry_document",
]
