"""Keychain comment migration helpers.

Keychain items created before current metadata comments are promoted when an
item is actually resolved. Decrypt-free index scans do not rewrite Keychain
state.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import replace

from secrets_kit.models.core import EntryMetadata

_ENTRY_ID_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


def stable_entry_id_from_locator(*, service: str, account: str, name: str) -> str:
    """Return deterministic id for old items without an ``entry_id`` comment."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"seckit:keychain:{service}:{account}:{name}"))


def entry_id_from_comment(comment: str) -> str:
    """Extract an entry id from current or historical comment text."""
    parsed = EntryMetadata.from_keychain_comment(comment)
    if parsed is not None and str(parsed.entry_id).strip():
        return str(parsed.entry_id).strip()
    m = _ENTRY_ID_UUID_RE.search(comment or "")
    return m.group(0) if m else ""


def metadata_and_entry_id(
    *, service: str, account: str, name: str, comment: str
) -> tuple[EntryMetadata, str, bool]:
    """Return current metadata, entry id, and whether the comment should be rewritten."""
    parsed = EntryMetadata.from_keychain_comment(comment)
    if parsed is None:
        eid = stable_entry_id_from_locator(service=service, account=account, name=name)
        meta = EntryMetadata(
            name=name,
            service=service,
            account=account,
            source="keychain-migrated",
            comment="",
            entry_id=eid,
        )
        return meta, eid, True

    meta = replace(parsed, name=name, service=service, account=account)
    eid = str(meta.entry_id).strip()
    if eid:
        return meta, eid, False

    eid = stable_entry_id_from_locator(service=service, account=account, name=name)
    return replace(meta, entry_id=eid), eid, True

