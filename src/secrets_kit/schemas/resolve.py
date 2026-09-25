"""
secrets_kit.schemas.resolve

Resolve schema_id from registry and entry metadata hints.
"""

from __future__ import annotations

from typing import Optional

from secrets_kit.schemas.descriptor import SchemaDescriptor
from secrets_kit.schemas.registry_doc import SchemaRegistryDocument


def default_schema_id(*, entry_type: str, entry_kind: str) -> str:
    """Infer builtin schema_id from entry_type and entry_kind."""
    return f"builtin.{entry_type}.{entry_kind}"


def resolve_schema_id(
    *,
    registry: SchemaRegistryDocument,
    schema_id: Optional[str] = None,
    entry_type: str = "secret",
    entry_kind: str = "generic",
) -> str:
    """Resolve schema_id using explicit id or builtin naming convention."""
    if schema_id:
        candidate = schema_id.strip()
        if candidate in registry.schemas:
            return candidate
        if registry.get_descriptor(candidate) is not None:
            return candidate
        return candidate
    builtin = default_schema_id(entry_type=entry_type, entry_kind=entry_kind)
    if builtin in registry.schemas:
        return builtin
    generic = default_schema_id(entry_type=entry_type, entry_kind="generic")
    if generic in registry.schemas:
        return generic
    fallback = default_schema_id(entry_type="secret", entry_kind="generic")
    if fallback in registry.schemas:
        return fallback
    if registry.schemas:
        return sorted(registry.schemas.keys())[0]
    return builtin


def resolve_descriptor(
    *,
    registry: SchemaRegistryDocument,
    schema_id: Optional[str] = None,
    entry_type: str = "secret",
    entry_kind: str = "generic",
) -> SchemaDescriptor:
    """Resolve a descriptor from the registry."""
    from secrets_kit.schemas.validate import ensure_schema_allowed

    resolved_id = resolve_schema_id(
        registry=registry,
        schema_id=schema_id,
        entry_type=entry_type,
        entry_kind=entry_kind,
    )
    return ensure_schema_allowed(registry=registry, schema_id=resolved_id)


__all__ = ["default_schema_id", "resolve_descriptor", "resolve_schema_id"]
