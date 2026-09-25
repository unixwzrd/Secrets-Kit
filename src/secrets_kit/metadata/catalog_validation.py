"""
secrets_kit.metadata.catalog_validation

Validate backend metadata instances against the local registry catalog.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from secrets_kit.internal_metadata import is_internal_custom_field
from secrets_kit.models import EntryMetadata
from secrets_kit.schemas.registry_doc import SchemaRegistryDocument
from secrets_kit.schemas.resolve import resolve_descriptor
from secrets_kit.schemas.validate import is_custom_value_set


@dataclass(frozen=True)
class MetadataIssue:
    """One catalog validation issue for a metadata instance."""

    name: str
    service: str
    account: str
    field: str
    issue: str
    detail: str = ""

    def to_dict(self) -> dict[str, str]:
        payload = {
            "name": self.name,
            "service": self.service,
            "account": self.account,
            "field": self.field,
            "issue": self.issue,
        }
        if self.detail:
            payload["detail"] = self.detail
        return payload


@dataclass
class MetadataValidationReport:
    """Catalog validation report for one metadata instance."""

    missing_required_fields: list[MetadataIssue] = field(default_factory=list)
    unknown_fields: list[MetadataIssue] = field(default_factory=list)
    invalid_field_types: list[MetadataIssue] = field(default_factory=list)
    normalization_candidates: list[MetadataIssue] = field(default_factory=list)

    def extend(self, other: "MetadataValidationReport") -> None:
        self.missing_required_fields.extend(other.missing_required_fields)
        self.unknown_fields.extend(other.unknown_fields)
        self.invalid_field_types.extend(other.invalid_field_types)
        self.normalization_candidates.extend(other.normalization_candidates)

    def to_status_dict(self) -> dict[str, list[dict[str, str]]]:
        return {
            "missing_required_fields": [
                item.to_dict() for item in self.missing_required_fields
            ],
            "unknown_fields": [item.to_dict() for item in self.unknown_fields],
            "invalid_field_types": [item.to_dict() for item in self.invalid_field_types],
            "normalization_candidates": [
                item.to_dict() for item in self.normalization_candidates
            ],
        }

    def has_failures(self) -> bool:
        return bool(
            self.missing_required_fields or self.unknown_fields or self.invalid_field_types
        )


def _issue(*, metadata: EntryMetadata, field_name: str, issue: str, detail: str = "") -> MetadataIssue:
    return MetadataIssue(
        name=metadata.name,
        service=metadata.service,
        account=metadata.account,
        field=field_name,
        issue=issue,
        detail=detail,
    )


def validate_metadata_against_catalog(
    *, metadata: EntryMetadata, catalog: SchemaRegistryDocument
) -> MetadataValidationReport:
    """Validate one backend metadata instance against the catalog."""
    report = MetadataValidationReport()
    descriptor = resolve_descriptor(
        registry=catalog,
        schema_id=metadata.schema_id or None,
        entry_type=metadata.entry_type,
        entry_kind=metadata.entry_kind,
    )
    allowed_fields = set(descriptor.fields)
    for field_name, value in sorted(metadata.custom.items()):
        if is_internal_custom_field(field_name):
            continue
        if field_name not in allowed_fields and is_custom_value_set(value):
            report.unknown_fields.append(
                _issue(
                    metadata=metadata,
                    field_name=f"custom.{field_name}",
                    issue="unknown-field",
                    detail=f"not defined by {descriptor.schema_id}",
                )
            )
            continue
        spec = descriptor.fields.get(field_name)
        if spec and spec.get("type") == "string" and is_custom_value_set(value) and not isinstance(value, str):
            report.invalid_field_types.append(
                _issue(
                    metadata=metadata,
                    field_name=f"custom.{field_name}",
                    issue="invalid-type",
                    detail="expected string",
                )
            )

    for field_name, spec in sorted(descriptor.fields.items()):
        value: Any = metadata.custom.get(field_name)
        if is_custom_value_set(value):
            continue
        if "default" in spec:
            report.normalization_candidates.append(
                _issue(
                    metadata=metadata,
                    field_name=f"custom.{field_name}",
                    issue="default-available",
                    detail=str(spec["default"]),
                )
            )
            continue
        if spec.get("required"):
            report.missing_required_fields.append(
                _issue(
                    metadata=metadata,
                    field_name=f"custom.{field_name}",
                    issue="missing-required",
                    detail=f"required by {descriptor.schema_id}",
                )
            )
    return report


__all__ = [
    "MetadataIssue",
    "MetadataValidationReport",
    "validate_metadata_against_catalog",
]
