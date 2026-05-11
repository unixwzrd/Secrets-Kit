"""Phase 6A merge ladder unit tests (tombstone, generation, replay suppression)."""

from __future__ import annotations

import unittest

from secrets_kit.importers import ImportCandidate
from secrets_kit.models.core import EntryMetadata
from secrets_kit.models.lineage import LineageSnapshot
from secrets_kit.sync.merge import merge_decision_v2, sync_lineage_eligible


def _meta(*, name: str = "K", entry_id: str = "e1", updated: str = "2026-05-01T12:00:00Z") -> EntryMetadata:
    return EntryMetadata(
        name=name,
        service="s",
        account="a",
        updated_at=updated,
        entry_id=entry_id,
    )


def _cand(
    *,
    meta: EntryMetadata,
    value: str = "v",
    disposition: str = "active",
    generation: int | None = 5,
    tombstone_generation: int | None = None,
) -> ImportCandidate:
    d = disposition  # type: ignore[arg-type]
    return ImportCandidate(
        metadata=meta,
        value=value,
        disposition=d,
        generation=generation,
        tombstone_generation=tombstone_generation,
    )


class Phase6aMergeTest(unittest.TestCase):
    def test_lineage_eligible_tombstone_requires_tgen(self) -> None:
        c = ImportCandidate(metadata=_meta(entry_id="e1"), value="", disposition="tombstone", generation=None, tombstone_generation=None)
        self.assertFalse(sync_lineage_eligible(c))
        c2 = ImportCandidate(
            metadata=_meta(entry_id="e1"),
            value="",
            disposition="tombstone",
            generation=None,
            tombstone_generation=2,
        )
        self.assertTrue(sync_lineage_eligible(c2))

    def test_tombstone_no_local_row_unchanged(self) -> None:
        inc = _cand(
            meta=_meta(entry_id="e1"),
            value="",
            disposition="tombstone",
            generation=None,
            tombstone_generation=2,
        )
        self.assertEqual(
            merge_decision_v2(
                local_meta=None,
                local_value=None,
                local_lineage=None,
                incoming=inc,
                incoming_origin_host="h2",
                local_host_id="h1",
                sqlite_lineage_merge=True,
            ),
            "unchanged",
        )

    def test_tombstone_wins_when_inc_t_ge_local_gen(self) -> None:
        loc_meta = _meta(entry_id="e1")
        loc = LineageSnapshot(
            entry_id="e1",
            service="s",
            account="a",
            name="K",
            generation=3,
            tombstone_generation=0,
            deleted=False,
        )
        inc = ImportCandidate(
            metadata=loc_meta,
            value="",
            disposition="tombstone",
            generation=None,
            tombstone_generation=3,
        )
        self.assertEqual(
            merge_decision_v2(
                local_meta=loc_meta,
                local_value="secret",
                local_lineage=loc,
                incoming=inc,
                incoming_origin_host="h2",
                local_host_id="h1",
                sqlite_lineage_merge=True,
            ),
            "import",
        )

    def test_stale_tombstone_skipped(self) -> None:
        loc_meta = _meta(entry_id="e1")
        loc = LineageSnapshot(
            entry_id="e1",
            service="s",
            account="a",
            name="K",
            generation=10,
            tombstone_generation=0,
            deleted=False,
        )
        inc = ImportCandidate(
            metadata=loc_meta,
            value="",
            disposition="tombstone",
            generation=None,
            tombstone_generation=2,
        )
        self.assertEqual(
            merge_decision_v2(
                local_meta=loc_meta,
                local_value="x",
                local_lineage=loc,
                incoming=inc,
                incoming_origin_host="h2",
                local_host_id="h1",
                sqlite_lineage_merge=True,
            ),
            "skip",
        )

    def test_tombstone_replay_deleted_unchanged(self) -> None:
        loc_meta = _meta(entry_id="e1")
        loc = LineageSnapshot(
            entry_id="e1",
            service="s",
            account="a",
            name="K",
            generation=4,
            tombstone_generation=3,
            deleted=True,
        )
        inc = ImportCandidate(
            metadata=loc_meta,
            value="",
            disposition="tombstone",
            generation=None,
            tombstone_generation=3,
        )
        self.assertEqual(
            merge_decision_v2(
                local_meta=loc_meta,
                local_value=None,
                local_lineage=loc,
                incoming=inc,
                incoming_origin_host="h2",
                local_host_id="h1",
                sqlite_lineage_merge=True,
            ),
            "unchanged",
        )

    def test_active_after_delete_replay_suppressed(self) -> None:
        loc_meta = _meta(entry_id="e1")
        loc = LineageSnapshot(
            entry_id="e1",
            service="s",
            account="a",
            name="K",
            generation=4,
            tombstone_generation=3,
            deleted=True,
        )
        inc = _cand(meta=loc_meta, value="resurrect", disposition="active", generation=99)
        self.assertEqual(
            merge_decision_v2(
                local_meta=loc_meta,
                local_value=None,
                local_lineage=loc,
                incoming=inc,
                incoming_origin_host="h2",
                local_host_id="h1",
                sqlite_lineage_merge=True,
            ),
            "replay_suppressed",
        )

    def test_generation_higher_imports(self) -> None:
        loc_meta = _meta(entry_id="e1")
        loc = LineageSnapshot(
            entry_id="e1",
            service="s",
            account="a",
            name="K",
            generation=3,
            tombstone_generation=0,
            deleted=False,
        )
        inc = _cand(meta=loc_meta, value="n", disposition="active", generation=7)
        self.assertEqual(
            merge_decision_v2(
                local_meta=loc_meta,
                local_value="old",
                local_lineage=loc,
                incoming=inc,
                incoming_origin_host="h2",
                local_host_id="h1",
                sqlite_lineage_merge=True,
            ),
            "import",
        )

    def test_equal_generation_declared_hash_mismatch_conflict(self) -> None:
        loc_meta = _meta(entry_id="e1")
        loc_meta.content_hash = "ab" * 32
        loc = LineageSnapshot(
            entry_id="e1",
            service="s",
            account="a",
            name="K",
            generation=5,
            tombstone_generation=0,
            deleted=False,
        )
        inc_meta = _meta(entry_id="e1")
        inc_meta.content_hash = "cd" * 32
        inc = _cand(meta=inc_meta, value="same", disposition="active", generation=5)
        self.assertEqual(
            merge_decision_v2(
                local_meta=loc_meta,
                local_value="same",
                local_lineage=loc,
                incoming=inc,
                incoming_origin_host="h2",
                local_host_id="h1",
                sqlite_lineage_merge=True,
            ),
            "conflict",
        )

    def test_incoming_metadata_rename_same_entry_id_higher_gen_imports(self) -> None:
        """Bundle may carry a new locator in metadata while preserving entry_id (rename continuity)."""
        loc_meta = _meta(entry_id="e1", name="K")
        loc = LineageSnapshot(
            entry_id="e1",
            service="s",
            account="a",
            name="K",
            generation=2,
            tombstone_generation=0,
            deleted=False,
        )
        inc_meta = _meta(entry_id="e1", name="K2")
        inc = _cand(meta=inc_meta, value="nv", disposition="active", generation=5)
        self.assertEqual(
            merge_decision_v2(
                local_meta=loc_meta,
                local_value="old",
                local_lineage=loc,
                incoming=inc,
                incoming_origin_host="h2",
                local_host_id="h1",
                sqlite_lineage_merge=True,
            ),
            "import",
        )

    def test_entry_id_mismatch_conflict(self) -> None:
        loc_meta = _meta(entry_id="e1")
        inc_meta = _meta(entry_id="e2")
        loc = LineageSnapshot(
            entry_id="e1",
            service="s",
            account="a",
            name="K",
            generation=3,
            tombstone_generation=0,
            deleted=False,
        )
        inc = _cand(meta=inc_meta, disposition="active", generation=5)
        self.assertEqual(
            merge_decision_v2(
                local_meta=loc_meta,
                local_value="a",
                local_lineage=loc,
                incoming=inc,
                incoming_origin_host="h2",
                local_host_id="h1",
                sqlite_lineage_merge=True,
            ),
            "conflict",
        )


if __name__ == "__main__":
    unittest.main()
