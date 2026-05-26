"""
secrets_kit.metadata.merge

Layered merge for EntryMetadata on secret writes.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

from secrets_kit.models import (
    EntryMetadata,
    normalize_custom,
    normalize_domains,
    normalize_tags,
    now_utc_iso,
)
from secrets_kit.schemas.descriptor import SchemaDescriptor
from secrets_kit.schemas.validate import validate_custom


def _is_set_scalar(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    return True


def merge_entry_metadata(
    *,
    operator_defaults: Mapping[str, object],
    descriptor: SchemaDescriptor,
    base: Optional[EntryMetadata],
    overlay: Optional[EntryMetadata],
) -> EntryMetadata:
    """
    Merge metadata: defaults.json → descriptor gaps → base → overlay.

    Does not blindly overwrite entry_type/entry_kind on base when overlay differs.
    """
    name = ""
    service = str(operator_defaults.get("service", "seckit"))
    account = str(operator_defaults.get("account", "default"))
    if overlay is not None:
        name = overlay.name
        service = overlay.service or service
        account = overlay.account or account
    elif base is not None:
        name = base.name
        service = base.service or service
        account = base.account or account

    entry_type = str(operator_defaults.get("type", descriptor.entry_type))
    entry_kind = str(operator_defaults.get("kind", descriptor.entry_kind))
    if base is not None:
        if base.entry_type:
            entry_type = base.entry_type
        if base.entry_kind:
            entry_kind = base.entry_kind
    if not entry_type:
        entry_type = descriptor.entry_type
    if not entry_kind:
        entry_kind = descriptor.entry_kind

    created_at = now_utc_iso()
    if base is not None and base.created_at:
        created_at = base.created_at

    merged = EntryMetadata(
        name=name,
        entry_type=entry_type,  # type: ignore[arg-type]
        entry_kind=entry_kind,  # type: ignore[arg-type]
        service=service,
        account=account,
        created_at=created_at,
        updated_at=now_utc_iso(),
        schema_id=descriptor.schema_id,
        schema_version=descriptor.schema_version,
        source="manual",
    )

    if base is not None:
        merged.tags = list(base.tags)
        merged.comment = base.comment
        merged.source = base.source or merged.source
        merged.source_url = base.source_url
        merged.source_label = base.source_label
        merged.rotation_days = base.rotation_days
        merged.rotation_warn_days = base.rotation_warn_days
        merged.last_rotated_at = base.last_rotated_at
        merged.expires_at = base.expires_at
        merged.domains = list(base.domains)
        merged.custom = dict(base.custom)
        if base.schema_id:
            merged.schema_id = base.schema_id
        if base.schema_version >= 1:
            merged.schema_version = base.schema_version

    if overlay is not None:
        if _is_set_scalar(overlay.comment):
            merged.comment = overlay.comment
        if overlay.tags:
            merged.tags = normalize_tags(tags=overlay.tags)
        if overlay.domains:
            merged.domains = normalize_domains(overlay.domains)
        if overlay.source:
            merged.source = overlay.source
        if _is_set_scalar(overlay.source_url):
            merged.source_url = overlay.source_url
        if _is_set_scalar(overlay.source_label):
            merged.source_label = overlay.source_label
        if overlay.rotation_days is not None:
            merged.rotation_days = overlay.rotation_days
        if overlay.rotation_warn_days is not None:
            merged.rotation_warn_days = overlay.rotation_warn_days
        if _is_set_scalar(overlay.last_rotated_at):
            merged.last_rotated_at = overlay.last_rotated_at
        if _is_set_scalar(overlay.expires_at):
            merged.expires_at = overlay.expires_at
        if overlay.schema_id:
            merged.schema_id = overlay.schema_id
        if overlay.custom:
            merged_custom = dict(merged.custom)
            merged_custom.update(normalize_custom(overlay.custom))
            merged.custom = merged_custom

    if not merged.schema_id:
        merged.schema_id = descriptor.schema_id

    if not merged.entry_type:
        merged.entry_type = descriptor.entry_type  # type: ignore[assignment]
    if not merged.entry_kind:
        merged.entry_kind = descriptor.entry_kind  # type: ignore[assignment]

    return validate_custom(metadata=merged, descriptor=descriptor)


__all__ = ["merge_entry_metadata"]
