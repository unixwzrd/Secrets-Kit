"""
secrets_kit.schemas.descriptor

Simple flat schema descriptor model (no JSONSchema).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Mapping

from secrets_kit.models import ValidationError


@dataclass
class SchemaDescriptor:
    """One object schema definition in the registry."""

    schema_id: str
    schema_version: int
    entry_type: str
    entry_kind: str
    fields: Dict[str, Dict[str, str]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a plain dict for registry storage."""
        return {
            "schema_id": self.schema_id,
            "schema_version": self.schema_version,
            "entry_type": self.entry_type,
            "entry_kind": self.entry_kind,
            "fields": dict(self.fields),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "SchemaDescriptor":
        """Parse and validate a descriptor dict."""
        return parse_descriptor(payload=payload)


def parse_descriptor(*, payload: Mapping[str, Any]) -> SchemaDescriptor:
    """
    Parse and validate a schema descriptor mapping.

    Raises:
        ValidationError: Invalid or unknown descriptor shape.
    """
    allowed_top = {"schema_id", "schema_version", "entry_type", "entry_kind", "fields"}
    extra = set(payload.keys()) - allowed_top
    if extra:
        raise ValidationError(f"unknown descriptor keys: {', '.join(sorted(extra))}")

    schema_id = str(payload.get("schema_id", "")).strip()
    if not schema_id:
        raise ValidationError("schema_id is required")

    entry_type = str(payload.get("entry_type", "")).strip()
    entry_kind = str(payload.get("entry_kind", "")).strip()
    if not entry_type or not entry_kind:
        raise ValidationError("entry_type and entry_kind are required")

    try:
        schema_version = int(payload.get("schema_version", 0))
    except (TypeError, ValueError) as exc:
        raise ValidationError("schema_version must be a positive integer") from exc
    if schema_version < 1:
        raise ValidationError("schema_version must be a positive integer")

    raw_fields = payload.get("fields", {})
    if not isinstance(raw_fields, dict):
        raise ValidationError("fields must be an object")
    fields: Dict[str, Dict[str, str]] = {}
    for key, spec in raw_fields.items():
        field_name = str(key).strip()
        if not field_name:
            raise ValidationError("fields keys cannot be empty")
        if not isinstance(spec, dict):
            raise ValidationError(f"field {field_name!r} must be an object")
        spec_extra = set(spec.keys()) - {"type"}
        if spec_extra:
            raise ValidationError(
                f"field {field_name!r} has unknown keys: {', '.join(sorted(spec_extra))}"
            )
        field_type = str(spec.get("type", "")).strip()
        if field_type != "string":
            raise ValidationError(f"field {field_name!r} type must be 'string' in v1")
        fields[field_name] = {"type": "string"}

    return SchemaDescriptor(
        schema_id=schema_id,
        schema_version=schema_version,
        entry_type=entry_type,
        entry_kind=entry_kind,
        fields=fields,
    )


def field_definitions_equal(*, left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    """Return whether two field spec dicts are identical."""
    return dict(left) == dict(right)


def bump_schema_version(descriptor: SchemaDescriptor) -> SchemaDescriptor:
    """Return a copy with schema_version incremented by one."""
    return SchemaDescriptor(
        schema_id=descriptor.schema_id,
        schema_version=descriptor.schema_version + 1,
        entry_type=descriptor.entry_type,
        entry_kind=descriptor.entry_kind,
        fields=dict(descriptor.fields),
    )


__all__ = [
    "SchemaDescriptor",
    "bump_schema_version",
    "field_definitions_equal",
    "parse_descriptor",
]
