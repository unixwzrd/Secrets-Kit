"""Load JSON step fixtures; assert deterministic replay + trace."""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List, Tuple

from secrets_kit.backends.operations import set_secret
from secrets_kit.backends.registry import BACKEND_SQLITE
from secrets_kit.registry.core import ensure_registry_storage, upsert_metadata
from secrets_kit.sync.canonical_record import compute_record_content_hash

from tests.support.ops_reconcile import lineage_projection, run_import_sequence

if importlib.util.find_spec("nacl") is not None:
    from secrets_kit.backends.sqlite import SqliteSecretStore, clear_sqlite_crypto_cache
else:

    def clear_sqlite_crypto_cache() -> None:  # pragma: no cover
        pass


_FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _load_fixture(name: str) -> Dict[str, Any]:
    with open(_FIXTURES / name, encoding="utf-8") as f:
        return json.load(f)


def _run_fixture_sequence(*, passphrase: str, fixture_name: str) -> Tuple[List[Tuple[object, ...]], List[Dict[str, Any]]]:
    data = _load_fixture(fixture_name)
    td = tempfile.TemporaryDirectory()
    home = Path(td.name) / "h"
    home.mkdir(parents=True, exist_ok=True)
    db = home / "v.db"
    os.environ["SECKIT_SQLITE_PASSPHRASE"] = passphrase
    clear_sqlite_crypto_cache()
    trace_all: List[Dict[str, Any]] = []
    try:
        init = data["initial_secret"]
        ensure_registry_storage(home=home)
        set_secret(
            service=str(init["service"]),
            account=str(init["account"]),
            name=str(init["name"]),
            value=str(init["value"]),
            path=str(db),
            backend=BACKEND_SQLITE,
        )
        st = SqliteSecretStore(db_path=str(db), kek_keychain_path=None)
        r = st.resolve_by_locator(
            service=str(init["service"]),
            account=str(init["account"]),
            name=str(init["name"]),
        )
        meta = r.metadata
        upsert_metadata(metadata=meta, home=home)
        local_host = str(data["local_host_id"])
        for step in data["steps"]:
            ls = st.read_lineage_snapshot(entry_id=meta.entry_id)
            assert ls is not None
            inc = int(step["generation_increment"])
            row = {
                "metadata": meta.to_dict(),
                "origin_host": str(step["origin_host"]),
                "value": str(step["value"]),
                "generation": ls.generation + inc,
                "content_hash": compute_record_content_hash(
                    secret=str(step["value"]),
                    metadata=meta,
                ),
            }
            run_import_sequence(
                inner_entries=[row],
                local_host_id=local_host,
                dry_run=False,
                path=str(db),
                backend=BACKEND_SQLITE,
                kek_keychain_path=None,
                home=home,
                trace_out=trace_all,
            )
            st = SqliteSecretStore(db_path=str(db), kek_keychain_path=None)
        proj_full = lineage_projection(db)
        proj = [(t[0], t[4], t[5], t[6]) for t in proj_full]
        return proj, trace_all
    finally:
        clear_sqlite_crypto_cache()
        if "SECKIT_SQLITE_PASSPHRASE" in os.environ:
            del os.environ["SECKIT_SQLITE_PASSPHRASE"]
        td.cleanup()


@unittest.skipUnless(importlib.util.find_spec("nacl") is not None, "requires PyNaCl")
class OperationalFixtureReplayTest(unittest.TestCase):
    def test_fixture_v1_two_identical_runs(self) -> None:
        pp = "operational-fixture-replay-v1-test-passphrase!!"
        p1, t1 = _run_fixture_sequence(passphrase=pp, fixture_name="replay_step_sequence_v1.json")
        p2, t2 = _run_fixture_sequence(passphrase=pp, fixture_name="replay_step_sequence_v1.json")
        self.assertEqual(len(p1), 1)
        self.assertEqual(len(p1), len(p2))
        self.assertEqual(p1[0][1:], p2[0][1:])
        self.assertEqual(len(t1), len(t2))
        for a, b in zip(t1, t2):
            self.assertEqual(a.get("decision"), b.get("decision"))
            self.assertEqual(a.get("reason"), b.get("reason"))
            self.assertEqual(a.get("incoming_generation"), b.get("incoming_generation"))
            self.assertEqual(a.get("local_generation"), b.get("local_generation"))
        for row in t1 + t2:
            self.assertNotIn("value", row)

    def test_fixture_v2_multi_step_two_runs(self) -> None:
        pp = "operational-fixture-replay-v2-test-passphrase!!"
        p1, t1 = _run_fixture_sequence(passphrase=pp, fixture_name="replay_step_sequence_v2.json")
        p2, t2 = _run_fixture_sequence(passphrase=pp, fixture_name="replay_step_sequence_v2.json")
        self.assertEqual(len(p1), 1)
        self.assertEqual(len(p1), len(p2))
        self.assertEqual(p1[0][1:], p2[0][1:])
        self.assertEqual(len(t1), len(t2))
        self.assertEqual(len(t1), 2)
        for a, b in zip(t1, t2):
            self.assertEqual(a.get("decision"), b.get("decision"))
            self.assertEqual(a.get("reason"), b.get("reason"))


if __name__ == "__main__":
    unittest.main()
