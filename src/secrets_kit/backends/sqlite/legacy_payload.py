"""Migration-only SQLite legacy payload parsing.

Normal SQLite runtime code must use ``payload_codec.parse_current_payload``.
This module exists only for ordered open-time migrations.
"""

from __future__ import annotations

import json
from typing import Optional, Tuple

from secrets_kit.models.core import EntryMetadata, now_utc_iso


def parse_legacy_payload(
    *,
    plain: bytes,
    legacy_metadata_json: Optional[str],
    service: str,
    account: str,
    name: str,
) -> Tuple[str, EntryMetadata]:
    """Parse a pre-current SQLite payload during migration only."""
    text = plain.decode("utf-8")
    if legacy_metadata_json and legacy_metadata_json.strip():
        parsed = EntryMetadata.from_keychain_comment(legacy_metadata_json)
        if parsed is not None:
            return text, parsed
    return text, _minimal_metadata_locator(service=service, account=account, name=name)


def parse_current_or_legacy_payload_for_migration(
    *,
    plain: bytes,
    legacy_metadata_json: Optional[str],
    service: str,
    account: str,
    name: str,
    current_version: int,
) -> Tuple[str, EntryMetadata]:
    """Parse current payloads or legacy sidecar payloads while promoting old rows."""
    text = plain.decode("utf-8")
    try:
        obj = json.loads(text)
        if isinstance(obj, dict) and obj.get("v") == current_version and "secret" in obj and "metadata" in obj:
            meta_raw = obj["metadata"]
            if isinstance(meta_raw, dict):
                return str(obj["secret"]), EntryMetadata.from_dict(meta_raw)
    except (json.JSONDecodeError, TypeError, KeyError, ValueError):
        pass
    return parse_legacy_payload(
        plain=plain,
        legacy_metadata_json=legacy_metadata_json,
        service=service,
        account=account,
        name=name,
    )


def _minimal_metadata_locator(*, service: str, account: str, name: str) -> EntryMetadata:
    """Create minimal metadata for old SQLite rows without embedded metadata."""
    ts = now_utc_iso()
    return EntryMetadata(
        name=name,
        service=service,
        account=account,
        source="migrated-sqlite",
        created_at=ts,
        updated_at=ts,
    )

