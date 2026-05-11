"""Unit tests for Phase 6A canonical record hashing."""

from __future__ import annotations

import unittest
from dataclasses import replace

from secrets_kit.models.core import EntryMetadata
from secrets_kit.sync.canonical_record import (
    attach_content_hash,
    computed_peer_row_content_hash,
    compute_record_content_hash,
    verify_incoming_row_content_hash,
)


def _meta() -> EntryMetadata:
    return EntryMetadata(
        name="N",
        service="s",
        account="a",
        updated_at="2026-05-01T00:00:00Z",
        entry_id="550e8400-e29b-41d4-a716-446655440000",
    )


class CanonicalRecordTest(unittest.TestCase):
    def test_digest_ignores_metadata_content_hash_field(self) -> None:
        base = replace(_meta(), content_hash="")
        h0 = compute_record_content_hash(secret="x", metadata=base)
        alt = replace(base, content_hash="ab" * 32)
        self.assertEqual(compute_record_content_hash(secret="x", metadata=alt), h0)

    def test_attach_round_trip_verifies(self) -> None:
        m = _meta()
        mh = attach_content_hash(secret="secret", metadata=m)
        self.assertTrue(mh.content_hash)
        self.assertTrue(
            verify_incoming_row_content_hash(
                secret="secret",
                metadata=mh,
                row_content_hash=mh.content_hash,
            )
        )

    def test_computed_peer_row_matches_declared_export_shape(self) -> None:
        m = _meta()
        h = compute_record_content_hash(secret="v", metadata=replace(m, content_hash=""))
        peer = computed_peer_row_content_hash(secret="v", metadata=m)
        self.assertEqual(peer, h)


if __name__ == "__main__":
    unittest.main()
