"""
secrets_kit.schemas.references

Scan operator secrets for schema field usage.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from secrets_kit.backends.common import normalize_backend
from secrets_kit.backends.dispatch import list_secret_metadata
from secrets_kit.models import EntryMetadata
from secrets_kit.schemas.validate import is_custom_value_set
from secrets_kit.system_objects import is_operator_metadata


@dataclass(frozen=True)
class FieldReference:
    """One secret referencing a schema custom field."""

    service: str
    account: str
    name: str
    schema_id: str
    attribute: str

    def locator(self) -> str:
        return f"{self.service}::{self.account}::{self.name}"


def _metadata_schema_id(*, metadata: EntryMetadata) -> str:
    if metadata.schema_id:
        return metadata.schema_id
    return f"builtin.{metadata.entry_type}.{metadata.entry_kind}"


def find_field_references(
    *,
    schema_id: str,
    field_name: str,
    backend: str,
    keychain_path: Optional[str] = None,
    sqlite_dev_mode: bool = False,
    service: Optional[str] = None,
    account: Optional[str] = None,
) -> List[FieldReference]:
    """Return operator secrets that reference a custom field on a schema."""
    normalize_backend(backend)
    references: List[FieldReference] = []
    entries = list_secret_metadata(
        backend=backend,
        service=service,
        account=account,
        keychain_path=keychain_path,
        sqlite_dev_mode=sqlite_dev_mode,
    )
    for meta in entries:
        if not is_operator_metadata(metadata=meta):
            continue
        meta_schema = _metadata_schema_id(metadata=meta)
        if meta_schema != schema_id:
            continue
        value = meta.custom.get(field_name)
        if not is_custom_value_set(value):
            continue
        references.append(
            FieldReference(
                service=meta.service,
                account=meta.account,
                name=meta.name,
                schema_id=meta_schema,
                attribute=field_name,
            )
        )
    return sorted(references, key=lambda item: item.locator())


def find_schema_id_references(
    *,
    schema_id: str,
    backend: str,
    keychain_path: Optional[str] = None,
    sqlite_dev_mode: bool = False,
) -> List[EntryMetadata]:
    """Return operator secrets using a schema_id."""
    entries = list_secret_metadata(
        backend=backend,
        keychain_path=keychain_path,
        sqlite_dev_mode=sqlite_dev_mode,
    )
    matched: List[EntryMetadata] = []
    for meta in entries:
        if not is_operator_metadata(metadata=meta):
            continue
        if _metadata_schema_id(metadata=meta) == schema_id:
            matched.append(meta)
    return matched


def format_field_reference_error(
    *,
    schema_id: str,
    field_name: str,
    references: List[FieldReference],
) -> str:
    """Build operator-actionable error text for blocked field removal."""
    lines = [
        f'ERROR: cannot remove field "{field_name}" from schema "{schema_id}": '
        f"{len(references)} secret(s) still reference it",
        "",
        f"  {'service::account::name'.ljust(32)} {'schema_id'.ljust(28)} attribute",
    ]
    for ref in references:
        lines.append(f"  {ref.locator().ljust(32)} {ref.schema_id.ljust(28)} {ref.attribute}")
    lines.extend(
        [
            "",
            "Re-run with --force after backing up, or clear/update the attribute on each secret first.",
            "Export current schemas: seckit schema export -o schemas-backup.json",
        ]
    )
    return "\n".join(lines)


__all__ = [
    "FieldReference",
    "find_field_references",
    "find_schema_id_references",
    "format_field_reference_error",
]
