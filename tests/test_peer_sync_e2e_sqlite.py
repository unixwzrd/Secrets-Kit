"""End-to-end peer sync using two isolated HOME trees and SQLite vaults (no Keychain)."""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from secrets_kit.identity.core import export_public_identity, init_identity, load_identity
from secrets_kit.backends.security import BACKEND_SQLITE, get_secret, set_secret
from secrets_kit.models.core import EntryMetadata
from secrets_kit.identity.peers import add_peer_from_file, get_peer
from secrets_kit.registry.core import ensure_registry_storage, load_registry, upsert_metadata
from secrets_kit.sync.bundle import (
    SyncBundleError,
    build_bundle,
    decrypt_bundle_for_recipient,
    parse_bundle_file,
    verify_bundle_structure,
)
from secrets_kit.sync.merge import apply_peer_sync_import

if importlib.util.find_spec("nacl") is not None:
    from secrets_kit.backends.sqlite import SqliteSecretStore, clear_sqlite_crypto_cache
else:

    def clear_sqlite_crypto_cache() -> None:  # pragma: no cover
        pass


@unittest.skipUnless(importlib.util.find_spec("nacl") is not None, "requires PyNaCl")
class PeerSyncE2ESqliteTest(unittest.TestCase):
    """Two logical hosts: distinct HOME dirs, SQLite DBs, exchange pub keys and peer bundle."""

    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self.td = Path(self._td.name)
        self.home_a = self.td / "home_a"
        self.home_b = self.td / "home_b"
        self.home_c = self.td / "home_c"
        self.shared = self.td / "shared"
        for p in (self.home_a, self.home_b, self.home_c, self.shared):
            p.mkdir(parents=True, exist_ok=True)
        self.db_a = self.home_a / "vault.db"
        self.db_b = self.home_b / "vault.db"
        os.environ["SECKIT_SQLITE_PASSPHRASE"] = "e2e-test-passphrase-for-peer-sync!!"
        clear_sqlite_crypto_cache()

    def tearDown(self) -> None:
        clear_sqlite_crypto_cache()
        if "SECKIT_SQLITE_PASSPHRASE" in os.environ:
            del os.environ["SECKIT_SQLITE_PASSPHRASE"]
        self._td.cleanup()

    def test_full_export_verify_import_sqlite_two_homes(self) -> None:
        init_identity(home=self.home_a)
        init_identity(home=self.home_b)
        pub_a = self.shared / "a.pub.json"
        pub_b = self.shared / "b.pub.json"
        export_public_identity(out=pub_a, home=self.home_a)
        export_public_identity(out=pub_b, home=self.home_b)

        add_peer_from_file(alias="b", path=pub_b, home=self.home_a)
        add_peer_from_file(alias="a", path=pub_a, home=self.home_b)

        ensure_registry_storage(home=self.home_a)
        secret_value = "super-secret-e2e-api-token"
        set_secret(
            service="e2esvc",
            account="dev",
            name="API_TOKEN",
            value=secret_value,
            path=str(self.db_a),
            backend=BACKEND_SQLITE,
        )
        meta = EntryMetadata(
            name="API_TOKEN",
            service="e2esvc",
            account="dev",
            entry_type="secret",
            entry_kind="api_key",
        )
        upsert_metadata(metadata=meta, home=self.home_a)

        id_a = load_identity(home=self.home_a)
        id_b = load_identity(home=self.home_b)
        peer_b = get_peer(alias="b", home=self.home_a)
        reg_a = load_registry(home=self.home_a)
        self.assertIn("e2esvc::dev::API_TOKEN", reg_a)
        st_a = SqliteSecretStore(db_path=str(self.db_a), kek_keychain_path=None)
        res_a = st_a.resolve_by_locator(service="e2esvc", account="dev", name="API_TOKEN")
        self.assertIsNotNone(res_a)
        meta_a = res_a.metadata
        value_a = get_secret(
            service="e2esvc",
            account="dev",
            name="API_TOKEN",
            path=str(self.db_a),
            backend=BACKEND_SQLITE,
        )
        bundle = build_bundle(
            identity=id_a,
            recipient_records=[(peer_b.fingerprint, peer_b.box_public())],
            entries=[
                {
                    "metadata": meta_a.to_dict(),
                    "origin_host": id_a.host_id,
                    "value": value_a,
                }
            ],
        )
        bundle_path = self.shared / "bundle.json"
        bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

        payload = parse_bundle_file(bundle_path.read_text(encoding="utf-8"))
        wrapped = payload["wrapped_cek"]
        self.assertIsInstance(wrapped, dict)
        self.assertEqual(set(wrapped.keys()), {id_b.signing_fingerprint_hex()})
        self.assertNotIn(id_a.signing_fingerprint_hex(), wrapped)

        vr = verify_bundle_structure(payload=payload)
        self.assertTrue(vr.ok)

        inner = decrypt_bundle_for_recipient(
            payload=payload,
            identity=id_b,
            trusted_signer=id_a.verify_key,
        )
        self.assertEqual(len(inner["entries"]), 1)
        self.assertEqual(inner["entries"][0]["value"], secret_value)

        ensure_registry_storage(home=self.home_b)
        clear_sqlite_crypto_cache()
        try:
            stats = apply_peer_sync_import(
                inner_entries=list(inner["entries"]),
                local_host_id=id_b.host_id,
                dry_run=False,
                path=str(self.db_b),
                backend=BACKEND_SQLITE,
                kek_keychain_path=None,
                domain_filter=None,
                home=self.home_b,
            )
        finally:
            clear_sqlite_crypto_cache()

        self.assertGreaterEqual(stats["created"], 1)
        self.assertEqual(stats.get("conflicts", 0), 0)

        val_b = get_secret(
            service="e2esvc",
            account="dev",
            name="API_TOKEN",
            path=str(self.db_b),
            backend=BACKEND_SQLITE,
        )
        self.assertEqual(val_b, secret_value)

        reg_b = load_registry(home=self.home_b)
        self.assertIn("e2esvc::dev::API_TOKEN", reg_b)
        self.assertEqual(reg_b["e2esvc::dev::API_TOKEN"].service, "e2esvc")
        self.assertEqual(reg_b["e2esvc::dev::API_TOKEN"].name, "API_TOKEN")

    def test_import_bundle_carries_sqlite_lineage_fields(self) -> None:
        """E2E: inner entry includes Phase 6A lineage; import still succeeds on SQLite."""
        init_identity(home=self.home_a)
        init_identity(home=self.home_b)
        pub_a = self.shared / "a_lin.pub.json"
        pub_b = self.shared / "b_lin.pub.json"
        export_public_identity(out=pub_a, home=self.home_a)
        export_public_identity(out=pub_b, home=self.home_b)
        add_peer_from_file(alias="b", path=pub_b, home=self.home_a)
        add_peer_from_file(alias="a", path=pub_a, home=self.home_b)

        ensure_registry_storage(home=self.home_a)
        secret_value = "token-with-lineage-on-wire"
        set_secret(
            service="e2esvc",
            account="dev",
            name="LINEAGE_KEY",
            value=secret_value,
            path=str(self.db_a),
            backend=BACKEND_SQLITE,
        )
        meta = EntryMetadata(
            name="LINEAGE_KEY",
            service="e2esvc",
            account="dev",
            entry_type="secret",
            entry_kind="generic",
        )
        upsert_metadata(metadata=meta, home=self.home_a)

        id_a = load_identity(home=self.home_a)
        id_b = load_identity(home=self.home_b)
        peer_b = get_peer(alias="b", home=self.home_a)
        st_a = SqliteSecretStore(db_path=str(self.db_a), kek_keychain_path=None)
        res_a = st_a.resolve_by_locator(service="e2esvc", account="dev", name="LINEAGE_KEY")
        self.assertIsNotNone(res_a)
        meta_a = res_a.metadata
        value_a = get_secret(
            service="e2esvc",
            account="dev",
            name="LINEAGE_KEY",
            path=str(self.db_a),
            backend=BACKEND_SQLITE,
        )
        ls = st_a.read_lineage_snapshot(
            entry_id=(meta_a.entry_id or "").strip() or None,
            service="e2esvc",
            account="dev",
            name="LINEAGE_KEY",
        )
        self.assertIsNotNone(ls)
        self.assertFalse(ls.deleted)
        entry: dict = {
            "metadata": meta_a.to_dict(),
            "origin_host": id_a.host_id,
            "value": value_a,
            "disposition": "active",
            "generation": ls.generation,
            "tombstone_generation": ls.tombstone_generation,
        }
        bundle = build_bundle(
            identity=id_a,
            recipient_records=[(peer_b.fingerprint, peer_b.box_public())],
            entries=[entry],
        )
        payload = parse_bundle_file(json.dumps(bundle))
        inner = decrypt_bundle_for_recipient(
            payload=payload,
            identity=id_b,
            trusted_signer=id_a.verify_key,
        )
        ensure_registry_storage(home=self.home_b)
        clear_sqlite_crypto_cache()
        try:
            stats = apply_peer_sync_import(
                inner_entries=list(inner["entries"]),
                local_host_id=id_b.host_id,
                dry_run=False,
                path=str(self.db_b),
                backend=BACKEND_SQLITE,
                kek_keychain_path=None,
                domain_filter=None,
                home=self.home_b,
            )
        finally:
            clear_sqlite_crypto_cache()
        self.assertGreaterEqual(stats["created"], 1)
        self.assertEqual(stats.get("conflicts", 0), 0)
        val_b = get_secret(
            service="e2esvc",
            account="dev",
            name="LINEAGE_KEY",
            path=str(self.db_b),
            backend=BACKEND_SQLITE,
        )
        self.assertEqual(val_b, secret_value)

    def test_wrong_recipient_cannot_decrypt(self) -> None:
        init_identity(home=self.home_a)
        init_identity(home=self.home_b)
        init_identity(home=self.home_c)
        pub_a = self.shared / "a2.pub.json"
        pub_b = self.shared / "b2.pub.json"
        export_public_identity(out=pub_a, home=self.home_a)
        export_public_identity(out=pub_b, home=self.home_b)

        add_peer_from_file(alias="b", path=pub_b, home=self.home_a)

        ensure_registry_storage(home=self.home_a)
        set_secret(
            service="s",
            account="a",
            name="K",
            value="v",
            path=str(self.home_a / "v.db"),
            backend=BACKEND_SQLITE,
        )
        upsert_metadata(
            metadata=EntryMetadata(name="K", service="s", account="a"),
            home=self.home_a,
        )
        id_a = load_identity(home=self.home_a)
        id_b = load_identity(home=self.home_b)
        id_c = load_identity(home=self.home_c)
        peer_b = get_peer(alias="b", home=self.home_a)
        st_a = SqliteSecretStore(db_path=str(self.home_a / "v.db"), kek_keychain_path=None)
        res_row = st_a.resolve_by_locator(service="s", account="a", name="K")
        self.assertIsNotNone(res_row)
        m = res_row.metadata
        bundle = build_bundle(
            identity=id_a,
            recipient_records=[(peer_b.fingerprint, peer_b.box_public())],
            entries=[{"metadata": m.to_dict(), "origin_host": id_a.host_id, "value": "v"}],
        )
        payload = parse_bundle_file(json.dumps(bundle))
        with self.assertRaises(SyncBundleError):
            decrypt_bundle_for_recipient(
                payload=payload,
                identity=id_c,
                trusted_signer=id_a.verify_key,
            )


if __name__ == "__main__":
    unittest.main()
