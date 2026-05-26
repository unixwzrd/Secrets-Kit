"""
secrets_kit.schemas.merge

Merge seed descriptors into the canonical registry document.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Mapping, Tuple

from secrets_kit.models import ValidationError
from secrets_kit.schemas.descriptor import (
    SchemaDescriptor,
    bump_schema_version,
    field_definitions_equal,
)
from secrets_kit.schemas.registry_doc import SchemaRegistryDocument


@dataclass
class FieldCollision:
    """One field definition conflict during install."""

    schema_id: str
    field_name: str
    existing: Dict[str, str]
    incoming: Dict[str, str]


@dataclass
class MergeSeedResult:
    """Outcome of merging seeds into a registry document."""

    document: SchemaRegistryDocument
    added_schema_ids: List[str]
    added_fields: List[Tuple[str, str]]
    replaced_fields: List[Tuple[str, str]]
    collisions: List[FieldCollision]
    removed_fields: List[Tuple[str, str]]


def _merge_descriptor_fields(
    *,
    existing: SchemaDescriptor,
    incoming: SchemaDescriptor,
    allow_replace: bool,
) -> Tuple[
    SchemaDescriptor, List[Tuple[str, str]], List[Tuple[str, str]], List[FieldCollision], bool
]:
    """
    Merge field maps for one schema_id.

    Returns:
        merged descriptor, added field keys, replaced field keys, collisions, changed flag.
    """
    merged_fields = dict(existing.fields)
    added: List[Tuple[str, str]] = []
    replaced: List[Tuple[str, str]] = []
    collisions: List[FieldCollision] = []
    changed = False

    for field_name, incoming_spec in incoming.fields.items():
        if field_name not in merged_fields:
            merged_fields[field_name] = dict(incoming_spec)
            added.append((existing.schema_id, field_name))
            changed = True
            continue
        current_spec = merged_fields[field_name]
        if field_definitions_equal(left=current_spec, right=incoming_spec):
            continue
        if not allow_replace:
            collisions.append(
                FieldCollision(
                    schema_id=existing.schema_id,
                    field_name=field_name,
                    existing=dict(current_spec),
                    incoming=dict(incoming_spec),
                )
            )
            continue
        merged_fields[field_name] = dict(incoming_spec)
        replaced.append((existing.schema_id, field_name))
        changed = True

    if not changed:
        return existing, added, replaced, collisions, False

    updated = SchemaDescriptor(
        schema_id=existing.schema_id,
        schema_version=existing.schema_version,
        entry_type=existing.entry_type or incoming.entry_type,
        entry_kind=existing.entry_kind or incoming.entry_kind,
        fields=merged_fields,
    )
    if not updated.entry_type:
        updated = SchemaDescriptor(
            schema_id=updated.schema_id,
            schema_version=updated.schema_version,
            entry_type=incoming.entry_type,
            entry_kind=updated.entry_kind,
            fields=merged_fields,
        )
    if not updated.entry_kind:
        updated = SchemaDescriptor(
            schema_id=updated.schema_id,
            schema_version=updated.schema_version,
            entry_type=updated.entry_type,
            entry_kind=incoming.entry_kind,
            fields=merged_fields,
        )
    return bump_schema_version(updated), added, replaced, collisions, True


def merge_seed_into_registry(
    *,
    registry: SchemaRegistryDocument,
    seeds: Mapping[str, SchemaDescriptor],
    allow_replace: bool = False,
) -> MergeSeedResult:
    """
    Merge seed descriptors into registry (non-destructive for type/kind by default).

    Raises:
        ValidationError: Field definition collisions when allow_replace is false.
    """
    document = SchemaRegistryDocument(
        registry_version=registry.registry_version,
        schemas={key: value for key, value in registry.schemas.items()},
        deprecated={key: value for key, value in registry.deprecated.items()},
    )
    added_schema_ids: List[str] = []
    added_fields: List[Tuple[str, str]] = []
    replaced_fields: List[Tuple[str, str]] = []
    collisions: List[FieldCollision] = []

    for schema_id, incoming in seeds.items():
        existing = document.schemas.get(schema_id)
        if existing is None:
            initial_version = incoming.schema_version if incoming.schema_version >= 1 else 1
            document.schemas[schema_id] = SchemaDescriptor(
                schema_id=schema_id,
                schema_version=initial_version,
                entry_type=incoming.entry_type,
                entry_kind=incoming.entry_kind,
                fields=dict(incoming.fields),
            )
            added_schema_ids.append(schema_id)
            continue

        entry_type = existing.entry_type or incoming.entry_type
        entry_kind = existing.entry_kind or incoming.entry_kind
        if (
            existing.entry_type
            and incoming.entry_type
            and existing.entry_type != incoming.entry_type
        ):
            entry_type = existing.entry_type
        if (
            existing.entry_kind
            and incoming.entry_kind
            and existing.entry_kind != incoming.entry_kind
        ):
            entry_kind = existing.entry_kind

        base = SchemaDescriptor(
            schema_id=schema_id,
            schema_version=existing.schema_version,
            entry_type=entry_type,
            entry_kind=entry_kind,
            fields=dict(existing.fields),
        )
        merged, added, replaced, field_collisions, changed = _merge_descriptor_fields(
            existing=base,
            incoming=incoming,
            allow_replace=allow_replace,
        )
        collisions.extend(field_collisions)
        added_fields.extend(added)
        replaced_fields.extend(replaced)
        if changed:
            document.schemas[schema_id] = merged

    if collisions:
        lines = [
            "field definition collision(s); use --replace to overwrite registry definitions:",
        ]
        for item in collisions:
            lines.append(
                f"  {item.schema_id}.{item.field_name}: existing={item.existing!r} incoming={item.incoming!r}"
            )
        raise ValidationError("\n".join(lines))

    return MergeSeedResult(
        document=document,
        added_schema_ids=added_schema_ids,
        added_fields=added_fields,
        replaced_fields=replaced_fields,
        collisions=collisions,
        removed_fields=[],
    )


def remove_field_from_descriptor(
    *,
    registry: SchemaRegistryDocument,
    schema_id: str,
    field_name: str,
) -> SchemaRegistryDocument:
    """Remove one field from a descriptor and bump schema_version."""
    descriptor = registry.schemas.get(schema_id)
    if descriptor is None:
        raise ValidationError(f"unknown schema_id: {schema_id}")
    if field_name not in descriptor.fields:
        raise ValidationError(f"field {field_name!r} is not defined on schema {schema_id!r}")
    fields = {key: value for key, value in descriptor.fields.items() if key != field_name}
    registry.schemas[schema_id] = bump_schema_version(
        SchemaDescriptor(
            schema_id=descriptor.schema_id,
            schema_version=descriptor.schema_version,
            entry_type=descriptor.entry_type,
            entry_kind=descriptor.entry_kind,
            fields=fields,
        )
    )
    return registry


__all__ = [
    "FieldCollision",
    "MergeSeedResult",
    "merge_seed_into_registry",
    "remove_field_from_descriptor",
]
