"""
secrets_kit.backends.keychain.comment_codec

Keychain comment-field JSON codec for EntryMetadata.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from secrets_kit.models import EntryMetadata


def format_keychain_comment(*, metadata: EntryMetadata) -> str:
    """Serialize metadata into the Keychain comment payload."""
    return json.dumps(metadata.to_dict(), separators=(",", ":"), sort_keys=True)


def parse_keychain_comment(*, comment: str) -> Optional[EntryMetadata]:
    """Parse metadata from a Keychain comment field."""
    from secrets_kit.models import EntryMetadata

    stripped = comment.strip()
    if not stripped:
        return None
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    if "name" not in payload or "service" not in payload or "account" not in payload:
        return None
    return EntryMetadata.from_dict(payload)


__all__ = ["format_keychain_comment", "parse_keychain_comment"]
