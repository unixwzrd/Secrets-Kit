"""Ordering / replay scenarios: canonical lineage digest must match."""

from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from typing import List, Tuple

from secrets_kit.backends.operations import set_secret
from secrets_kit.backends.registry import BACKEND_SQLITE
from secrets_kit.registry.core import ensure_registry_storage, upsert_metadata
from secrets_kit.sync.canonical_record import compute_record_content_hash
from secrets_kit.sync.merge import apply_peer_sync_import

from tests.support.ops_reconcile import assert_lineage_projection_equal, lineage_projection

if importlib.util.find_spec("nacl") is not None:
    from secrets_kit.backends.sqlite import SqliteSecretStore, clear_sqlite_crypto_cache
else:

    def clear_sqlite_crypto_cache() -> None:  # pragma: no cover
        pass


def _scenario_bundle_order(*, order_ba: bool) -> List[Tuple[object, ...]]:
    td = tempfile.TemporaryDirectory()
    home = Path(td.name) / "h"
    home.mkdir(parents=True, exist_ok=True)
    db = home / "v.db"
    os.environ["SECKIT_SQLITE_PASSPHRASE"] = "stabilization-replay-determinism-test-passphrase!!"
    clear_sqlite_crypto_cache()
    try:
        ensure_registry_storage(home=home)
        set_secret(service="s", account="a", name="A", value="a0", path=str(db), backend=BACKEND_SQLITE)
        set_secret(service="s", account="a", name="B", value="b0", path=str(db), backend=BACKEND_SQLITE)
        st = SqliteSecretStore(db_path=str(db), kek_keychain_path=None)
        ra = st.resolve_by_locator(service="s", account="a", name="A")
        rb = st.resolve_by_locator(service="s", account="a", name="B")
        lsa = st.read_lineage_snapshot(entry_id=ra.metadata.entry_id)
        lsb = st.read_lineage_snapshot(entry_id=rb.metadata.entry_id)
        upsert_metadata(metadata=ra.metadata, home=home)
        upsert_metadata(metadata=rb.metadata, home=home)
        row_a = {
            "metadata": ra.metadata.to_dict(),
            "origin_host": "p",
            "value": "a1",
            "generation": lsa.generation + 1,
            "content_hash": compute_record_content_hash(secret="a1", metadata=ra.metadata),
        }
        row_b = {
            "metadata": rb.metadata.to_dict(),
            "origin_host": "p",
            "value": "b1",
            "generation": lsb.generation + 1,
            "content_hash": compute_record_content_hash(secret="b1", metadata=rb.metadata),
        }
        entries = [row_b, row_a] if order_ba else [row_a, row_b]
        apply_peer_sync_import(
            inner_entries=entries,
            local_host_id="local",
            dry_run=False,
            path=str(db),
            backend=BACKEND_SQLITE,
            kek_keychain_path=None,
            home=home,
        )
        return lineage_projection(db)
    finally:
        clear_sqlite_crypto_cache()
        if "SECKIT_SQLITE_PASSPHRASE" in os.environ:
            del os.environ["SECKIT_SQLITE_PASSPHRASE"]
        td.cleanup()


@unittest.skipUnless(importlib.util.find_spec("nacl") is not None, "requires PyNaCl")
class StabilizationReplayDeterminismTest(unittest.TestCase):
    def test_two_entry_bundle_order_permutation_same_lineage_projection(self) -> None:
        p_ab = _scenario_bundle_order(order_ba=False)
        p_ba = _scenario_bundle_order(order_ba=True)
        assert_lineage_projection_equal(p_ab, p_ba, ignore_entry_id=True)


if __name__ == "__main__":
    unittest.main()
