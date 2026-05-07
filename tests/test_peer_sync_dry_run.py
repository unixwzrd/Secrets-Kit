"""Dry-run import: no mutations, accurate merge stats, conflict reporting."""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from secrets_kit.identity import export_public_identity, init_identity, load_identity
from secrets_kit.keychain_backend import BACKEND_SQLITE, get_secret, set_secret
from secrets_kit.models import EntryMetadata
from secrets_kit.peers import add_peer_from_file, get_peer
from secrets_kit.registry import ensure_registry_storage, load_registry, upsert_metadata
from secrets_kit.sync_bundle import build_bundle, decrypt_bundle_for_recipient, parse_bundle_file
from secrets_kit.sync_merge import apply_peer_sync_import

if importlib.util.find_spec("nacl") is not None:
    from secrets_kit.sqlite_backend import SqliteSecretStore, clear_sqlite_crypto_cache
else:

    def clear_sqlite_crypto_cache() -> None:  # pragma: no cover
        pass


@unittest.skipUnless(importlib.util.find_spec("nacl") is not None, "requires PyNaCl")
class PeerSyncDryRunTest(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self.td = Path(self._td.name)
        self.home_b = self.td / "home_b"
        self.home_a = self.td / "home_a"
        self.shared = self.td / "shared"
        for p in (self.home_a, self.home_b, self.shared):
            p.mkdir(parents=True, exist_ok=True)
        self.db_b = self.home_b / "vault.db"
        os.environ["SECKIT_SQLITE_PASSPHRASE"] = "dryrun-peer-sync-passphrase-here!!!"
        clear_sqlite_crypto_cache()

    def tearDown(self) -> None:
        clear_sqlite_crypto_cache()
        if "SECKIT_SQLITE_PASSPHRASE" in os.environ:
            del os.environ["SECKIT_SQLITE_PASSPHRASE"]
        self._td.cleanup()

    def _ensure_ab_peers(self) -> None:
        init_identity(home=self.home_a)
        init_identity(home=self.home_b)
        export_public_identity(out=self.shared / "a.pub.json", home=self.home_a)
        export_public_identity(out=self.shared / "b.pub.json", home=self.home_b)
        add_peer_from_file(alias="b", path=self.shared / "b.pub.json", home=self.home_a)

    def _encrypt_entries_for_b(self, entries_payload: list[dict]) -> tuple[object, list]:
        id_a = load_identity(home=self.home_a)
        peer_b = get_peer(alias="b", home=self.home_a)
        bundle = build_bundle(
            identity=id_a,
            recipient_records=[(peer_b.fingerprint, peer_b.box_public())],
            entries=entries_payload,
        )
        payload = parse_bundle_file(json.dumps(bundle))
        id_b = load_identity(home=self.home_b)
        inner = decrypt_bundle_for_recipient(
            payload=payload,
            identity=id_b,
            trusted_signer=id_a.verify_key,
        )
        return id_b, list(inner["entries"])

    def _make_bundle_for_b(
        self,
        *,
        entries_payload: list[dict],
    ) -> tuple[object, list]:
        """Exporter A sends bundle encrypted for B only."""
        self._ensure_ab_peers()
        return self._encrypt_entries_for_b(entries_payload)

    def test_dry_run_does_not_call_set_secret_or_upsert(self) -> None:
        inner_entries, id_b = self._make_inner_for_import_new_only()
        ensure_registry_storage(home=self.home_b)

        with patch("secrets_kit.sync_merge.set_secret") as m_set, patch(
            "secrets_kit.sync_merge.upsert_metadata"
        ) as m_up:
            stats = apply_peer_sync_import(
                inner_entries=inner_entries,
                local_host_id=id_b.host_id,
                dry_run=True,
                path=str(self.db_b),
                backend=BACKEND_SQLITE,
                kek_keychain_path=None,
                domain_filter=None,
                home=self.home_b,
            )
        m_set.assert_not_called()
        m_up.assert_not_called()
        clear_sqlite_crypto_cache()

        self.assertEqual(stats["created"], 1)
        self.assertEqual(stats["updated"], 0)
        self.assertEqual(stats["conflicts"], 0)

    def _make_inner_for_import_new_only(self) -> tuple[list, object]:
        self._ensure_ab_peers()
        ensure_registry_storage(home=self.home_a)
        db_a = self.home_a / "a.db"
        set_secret(service="svc", account="ac", name="NEWKEY", value="v1", path=str(db_a), backend=BACKEND_SQLITE)
        meta = EntryMetadata(name="NEWKEY", service="svc", account="ac")
        upsert_metadata(metadata=meta, home=self.home_a)
        st = SqliteSecretStore(db_path=str(db_a), kek_keychain_path=None)
        resolved = st.resolve_by_locator(service="svc", account="ac", name="NEWKEY")
        self.assertIsNotNone(resolved)
        m = resolved.metadata
        id_a = load_identity(home=self.home_a)
        payload_rows = [{"metadata": m.to_dict(), "origin_host": id_a.host_id, "value": "v1"}]
        id_b, inner_list = self._encrypt_entries_for_b(payload_rows)
        return inner_list, id_b

    def test_dry_run_merge_summary_skip_older(self) -> None:
        inner_entries, id_b = self._make_inner_for_import_new_only()
        ensure_registry_storage(home=self.home_b)
        # B already has strictly newer row
        set_secret(service="svc", account="ac", name="NEWKEY", value="local", path=str(self.db_b), backend=BACKEND_SQLITE)
        newer = EntryMetadata(
            name="NEWKEY",
            service="svc",
            account="ac",
            updated_at="2099-01-01T00:00:00Z",
        )
        upsert_metadata(metadata=newer, home=self.home_b)

        stats = apply_peer_sync_import(
            inner_entries=inner_entries,
            local_host_id=id_b.host_id,
            dry_run=True,
            path=str(self.db_b),
            backend=BACKEND_SQLITE,
            kek_keychain_path=None,
            domain_filter=None,
            home=self.home_b,
        )
        clear_sqlite_crypto_cache()

        self.assertEqual(stats["skipped"], 1)
        self.assertEqual(stats["created"], 0)
        self.assertEqual(stats["updated"], 0)

    def test_dry_run_conflict_same_vector_and_diff_value(self) -> None:
        ts = "2026-06-01T12:00:00Z"
        origin = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        meta_in = EntryMetadata(
            name="K",
            service="svc",
            account="ac",
            updated_at=ts,
            custom={"seckit_sync_origin_host": origin},
        )
        id_b, inner_entries = self._make_bundle_for_b(
            entries_payload=[{"metadata": meta_in.to_dict(), "origin_host": origin, "value": "from-a"}],
        )
        ensure_registry_storage(home=self.home_b)
        meta_loc = EntryMetadata(
            name="K",
            service="svc",
            account="ac",
            updated_at=ts,
            custom={"seckit_sync_origin_host": origin},
        )
        # SQLite authority metadata must carry the merge vector (registry alone is not read for merges).
        set_secret(
            service="svc",
            account="ac",
            name="K",
            value="from-b",
            comment=meta_loc.to_keychain_comment(),
            path=str(self.db_b),
            backend=BACKEND_SQLITE,
        )
        upsert_metadata(metadata=meta_loc, home=self.home_b)

        stats = apply_peer_sync_import(
            inner_entries=inner_entries,
            local_host_id=id_b.host_id,
            dry_run=True,
            path=str(self.db_b),
            backend=BACKEND_SQLITE,
            kek_keychain_path=None,
            domain_filter=None,
            home=self.home_b,
        )
        clear_sqlite_crypto_cache()

        self.assertEqual(stats["conflicts"], 1)
        self.assertEqual(stats["created"], 0)
        self.assertEqual(stats["updated"], 0)
        # Value unchanged after dry-run
        self.assertEqual(
            get_secret(service="svc", account="ac", name="K", path=str(self.db_b), backend=BACKEND_SQLITE),
            "from-b",
        )


if __name__ == "__main__":
    unittest.main()
