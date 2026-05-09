from __future__ import annotations

import unittest

from secrets_kit.models.core import EntryMetadata
from secrets_kit.sync.merge import merge_decision


class SyncMergeTest(unittest.TestCase):
    def _meta(self, *, name: str = "K", updated: str = "2026-05-01T12:00:00Z", origin_custom: str | None = None) -> EntryMetadata:
        custom = {}
        if origin_custom is not None:
            custom["seckit_sync_origin_host"] = origin_custom
        return EntryMetadata(
            name=name,
            service="s",
            account="a",
            updated_at=updated,
            domains=["example.com"],
            custom=custom,
        )

    def test_import_when_no_local(self) -> None:
        inc = self._meta(updated="2026-05-02T12:00:00Z", origin_custom="host-b")
        self.assertEqual(
            merge_decision(
                local_meta=None,
                local_value=None,
                incoming_meta=inc,
                incoming_value="x",
                incoming_origin_host="host-b",
                local_host_id="host-a",
            ),
            "import",
        )

    def test_skip_when_incoming_older(self) -> None:
        loc = self._meta(updated="2026-05-03T12:00:00Z", origin_custom="host-a")
        inc = self._meta(updated="2026-05-02T12:00:00Z", origin_custom="host-b")
        self.assertEqual(
            merge_decision(
                local_meta=loc,
                local_value="old",
                incoming_meta=inc,
                incoming_value="new",
                incoming_origin_host="host-b",
                local_host_id="host-a",
            ),
            "skip",
        )

    def test_import_when_incoming_newer(self) -> None:
        loc = self._meta(updated="2026-05-02T12:00:00Z", origin_custom="host-a")
        inc = self._meta(updated="2026-05-03T12:00:00Z", origin_custom="host-b")
        self.assertEqual(
            merge_decision(
                local_meta=loc,
                local_value="old",
                incoming_meta=inc,
                incoming_value="new",
                incoming_origin_host="host-b",
                local_host_id="host-a",
            ),
            "import",
        )

    def test_unchanged_same_ts_origin_and_value(self) -> None:
        ts = "2026-05-02T12:00:00Z"
        loc = self._meta(updated=ts, origin_custom="host-b")
        inc = self._meta(updated=ts, origin_custom="host-b")
        self.assertEqual(
            merge_decision(
                local_meta=loc,
                local_value="same",
                incoming_meta=inc,
                incoming_value="same",
                incoming_origin_host="host-b",
                local_host_id="host-a",
            ),
            "unchanged",
        )

    def test_conflict_same_ts_origin_diff_value(self) -> None:
        ts = "2026-05-02T12:00:00Z"
        loc = self._meta(updated=ts, origin_custom="host-b")
        inc = self._meta(updated=ts, origin_custom="host-b")
        self.assertEqual(
            merge_decision(
                local_meta=loc,
                local_value="a",
                incoming_meta=inc,
                incoming_value="b",
                incoming_origin_host="host-b",
                local_host_id="host-a",
            ),
            "conflict",
        )

    def test_tiebreak_origin_when_ts_equal(self) -> None:
        ts = "2026-05-02T12:00:00Z"
        loc = self._meta(updated=ts, origin_custom="mhost")
        inc = self._meta(updated=ts, origin_custom="zhost")
        self.assertEqual(
            merge_decision(
                local_meta=loc,
                local_value="v",
                incoming_meta=inc,
                incoming_value="w",
                incoming_origin_host="zhost",
                local_host_id="host-a",
            ),
            "import",
        )


if __name__ == "__main__":
    unittest.main()
