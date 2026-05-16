"""
secrets_kit.sync.canonical_record

Canonical record hashing (Phase 6A integrity metadata, SHA-256).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, replace
from typing import Any

from secrets_kit.models.core import EntryMetadata, normalize_custom

_SYNC_INJECTED_ORIGIN_KEY = "seckit_sync_origin_host"


def metadata_stripped_for_peer_hash_verify(metadata: EntryMetadata) -> EntryMetadata:
    """Return metadata as used for import-time row hash verification (no injected sync-origin key)."""
    if not metadata.custom or _SYNC_INJECTED_ORIGIN_KEY not in metadata.custom:
        return metadata
    stripped = dict(metadata.custom)
    stripped.pop(_SYNC_INJECTED_ORIGIN_KEY, None)
    return replace(metadata, custom=normalize_custom(stripped))


def computed_peer_row_content_hash(*, secret: str, metadata: EntryMetadata) -> str:
    """SHA-256 hex for ``secret`` + metadata after :func:`metadata_stripped_for_peer_hash_verify`."""
    return compute_record_content_hash(
        secret=secret, metadata=metadata_stripped_for_peer_hash_verify(metadata)
    )


def _metadata_body_for_hash(metadata: EntryMetadata) -> dict[str, Any]:
    """Metadata dict for hashing; omits ``content_hash`` so the digest is self-describing."""
    d = asdict(metadata)
    d.pop("content_hash", None)
    return d


def canonical_record_bytes(*, secret: str, metadata: EntryMetadata) -> bytes:
    """Deterministic UTF-8 payload bytes covered by :func:`compute_record_content_hash`."""
    body = {
        "metadata": _metadata_body_for_hash(metadata),
        "secret": secret,
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_record_content_hash(*, secret: str, metadata: EntryMetadata) -> str:
    """SHA-256 hex digest of the canonical record (secret + metadata without ``content_hash``)."""
    return hashlib.sha256(canonical_record_bytes(secret=secret, metadata=metadata)).hexdigest()


def attach_content_hash(*, secret: str, metadata: EntryMetadata) -> EntryMetadata:
    """Return metadata with ``content_hash`` populated from ``secret`` and non-hash fields."""
    from dataclasses import replace

    base = replace(metadata, content_hash="")
    digest = compute_record_content_hash(secret=secret, metadata=base)
    return replace(base, content_hash=digest)


def verify_incoming_row_content_hash(
    *, secret: str, metadata: EntryMetadata, row_content_hash: str | None
) -> bool:
    """True if no row hash, or digest matches payload (lowercase hex)."""
    expected = (row_content_hash or "").strip().lower()
    if not expected:
        return True
    meta = metadata_stripped_for_peer_hash_verify(metadata)
    got = compute_record_content_hash(secret=secret, metadata=meta)
    return got.lower() == expected
