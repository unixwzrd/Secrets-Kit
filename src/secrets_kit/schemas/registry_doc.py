"""
secrets_kit.schemas.registry_doc

In-memory schema registry document structure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional

from secrets_kit.models import ValidationError, now_utc_iso
from secrets_kit.schemas.descriptor import SchemaDescriptor, bump_schema_version, parse_descriptor


@dataclass
class DeprecatedEntry:
    """Metadata for a deprecated schema_id."""

    deprecated_at: str
    reason: str = ""
    replacement_schema_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"deprecated_at": self.deprecated_at}
        if self.reason:
            out["reason"] = self.reason
        if self.replacement_schema_id:
            out["replacement_schema_id"] = self.replacement_schema_id
        return out

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "DeprecatedEntry":
        return cls(
            deprecated_at=str(payload.get("deprecated_at", now_utc_iso())),
            reason=str(payload.get("reason", "")),
            replacement_schema_id=str(payload.get("replacement_schema_id", "")),
        )


@dataclass
class SchemaRegistryDocument:
    """Canonical schema registry payload stored on the schema_registry system object."""

    registry_version: int = 1
    schemas: Dict[str, SchemaDescriptor] = field(default_factory=dict)
    deprecated: Dict[str, DeprecatedEntry] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "registry_version": self.registry_version,
            "schemas": {key: value.to_dict() for key, value in sorted(self.schemas.items())},
            "deprecated": {key: value.to_dict() for key, value in sorted(self.deprecated.items())},
        }

    @classmethod
    def empty(cls) -> "SchemaRegistryDocument":
        return cls(registry_version=1, schemas={}, deprecated={})

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "SchemaRegistryDocument":
        allowed = {"registry_version", "schemas", "deprecated"}
        extra = set(payload.keys()) - allowed
        if extra:
            raise ValidationError(f"unknown registry keys: {', '.join(sorted(extra))}")

        schemas_raw = payload.get("schemas", {})
        if not isinstance(schemas_raw, dict):
            raise ValidationError("schemas must be an object")
        schemas: Dict[str, SchemaDescriptor] = {}
        for schema_id, item in schemas_raw.items():
            if not isinstance(item, dict):
                raise ValidationError(f"schema {schema_id!r} must be an object")
            descriptor = parse_descriptor(payload=item)
            if descriptor.schema_id != schema_id:
                descriptor = SchemaDescriptor(
                    schema_id=schema_id,
                    schema_version=descriptor.schema_version,
                    entry_type=descriptor.entry_type,
                    entry_kind=descriptor.entry_kind,
                    fields=dict(descriptor.fields),
                )
            schemas[schema_id] = descriptor

        deprecated_raw = payload.get("deprecated", {})
        if not isinstance(deprecated_raw, dict):
            raise ValidationError("deprecated must be an object")
        deprecated = {
            str(key): DeprecatedEntry.from_dict(value if isinstance(value, dict) else {})
            for key, value in deprecated_raw.items()
        }

        try:
            registry_version = int(payload.get("registry_version", 1))
        except (TypeError, ValueError) as exc:
            raise ValidationError("registry_version must be an integer") from exc

        return cls(registry_version=registry_version, schemas=schemas, deprecated=deprecated)

    def get_descriptor(self, schema_id: str) -> Optional[SchemaDescriptor]:
        return self.schemas.get(schema_id)

    def is_deprecated(self, schema_id: str) -> bool:
        return schema_id in self.deprecated

    def bump_descriptor(self, schema_id: str) -> None:
        descriptor = self.schemas.get(schema_id)
        if descriptor is None:
            return
        self.schemas[schema_id] = bump_schema_version(descriptor)


__all__ = ["DeprecatedEntry", "SchemaRegistryDocument"]
