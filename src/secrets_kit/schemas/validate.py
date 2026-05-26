"""
secrets_kit.schemas.validate

Validate entry metadata custom fields against schema descriptors.
"""

from __future__ import annotations

from typing import Any, Dict

from secrets_kit.models import EntryMetadata, ValidationError
from secrets_kit.schemas.constants import SECKIT_UNDEFINED
from secrets_kit.schemas.descriptor import SchemaDescriptor
from secrets_kit.schemas.registry_doc import SchemaRegistryDocument


def is_custom_value_set(value: Any) -> bool:
    """Return whether a custom field value counts as set (not retired)."""
    if value is None:
        return False
    if isinstance(value, str) and value == SECKIT_UNDEFINED:
        return False
    if isinstance(value, str) and not value.strip():
        return False
    return True


def validate_custom(*, metadata: EntryMetadata, descriptor: SchemaDescriptor) -> EntryMetadata:
    """
    Validate and coerce custom metadata against a descriptor.

    Raises:
        ValidationError: Unknown custom keys or invalid types.
    """
    allowed = set(descriptor.fields.keys())
    normalized: Dict[str, Any] = {}
    for key, value in metadata.custom.items():
        if not is_custom_value_set(value):
            if key in allowed:
                normalized[key] = SECKIT_UNDEFINED if value == SECKIT_UNDEFINED else value
            continue
        if key not in allowed:
            raise ValidationError(
                f"custom field {key!r} is not allowed for schema {descriptor.schema_id!r}; "
                f"allowed: {', '.join(sorted(allowed)) or '(none)'}"
            )
        spec = descriptor.fields[key]
        if spec.get("type") == "string":
            normalized[key] = str(value)
        else:
            normalized[key] = value

    merged_custom = dict(metadata.custom)
    merged_custom.update(normalized)
    for key in list(merged_custom.keys()):
        if key not in allowed and is_custom_value_set(merged_custom[key]):
            raise ValidationError(
                f"custom field {key!r} is not allowed for schema {descriptor.schema_id!r}"
            )

    metadata.custom = merged_custom
    if not metadata.schema_id:
        metadata.schema_id = descriptor.schema_id
    if metadata.schema_version < 1:
        metadata.schema_version = descriptor.schema_version
    return metadata


def ensure_schema_allowed(*, registry: SchemaRegistryDocument, schema_id: str) -> SchemaDescriptor:
    """Resolve descriptor and reject deprecated schema ids."""
    if registry.is_deprecated(schema_id):
        raise ValidationError(f"schema_id {schema_id!r} is deprecated")
    descriptor = registry.get_descriptor(schema_id)
    if descriptor is None:
        known = ", ".join(sorted(registry.schemas.keys())[:12])
        raise ValidationError(f"unknown schema_id {schema_id!r}; known schemas include: {known}")
    return descriptor


__all__ = [
    "ensure_schema_allowed",
    "is_custom_value_set",
    "validate_custom",
]
