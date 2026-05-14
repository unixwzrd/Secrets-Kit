"""Tests for SQLite unlock providers (passphrase KDF vs keychain-wrapped DEK)."""

from __future__ import annotations

import importlib.util
import os
import shutil
import sys
import tempfile
import unittest

from secrets_kit.backends.security import BackendError, check_security_cli, delete_keychain, make_temp_keychain
from secrets_kit.backends.sqlite.unlock import (
    KeychainUnlockProvider,
    PassphraseUnlockProvider,
    build_sqlite_unlock_provider,
    clear_sqlite_unlock_cache,
    derive_legacy_master_key,
)

if importlib.util.find_spec("nacl") is None:

    class SqliteUnlockTest(unittest.TestCase):
        def test_pynacl_required(self) -> None:
            self.skipTest("Install project dependencies (PyNaCl) to run sqlite unlock tests")

else:
    from secrets_kit.backends.sqlite import SqliteSecretStore, clear_sqlite_crypto_cache

    class SqliteUnlockTest(unittest.TestCase):
        def setUp(self) -> None:
            clear_sqlite_crypto_cache()
            clear_sqlite_unlock_cache()
            self._dir = tempfile.TemporaryDirectory()
            self.db = os.path.join(self._dir.name, "vault.db")

        def tearDown(self) -> None:
            clear_sqlite_crypto_cache()
            clear_sqlite_unlock_cache()
            for key in ("SECKIT_SQLITE_PASSPHRASE", "SECKIT_SQLITE_UNLOCK", "SECKIT_SQLITE_KEK_KEYCHAIN"):
                if key in os.environ:
                    del os.environ[key]
            self._dir.cleanup()

        def test_derive_legacy_master_key_deterministic(self) -> None:
            import nacl.pwhash.argon2id as argon2

            salt = b"\x00" * argon2.SALTBYTES
            k1 = derive_legacy_master_key(
                passphrase="pw",
                salt=salt,
                opslimit=argon2.OPSLIMIT_MIN,
                memlimit=argon2.MEMLIMIT_MIN,
            )
            k2 = derive_legacy_master_key(
                passphrase="pw",
                salt=salt,
                opslimit=argon2.OPSLIMIT_MIN,
                memlimit=argon2.MEMLIMIT_MIN,
            )
            self.assertEqual(k1, k2)
            self.assertEqual(len(k1), 32)

        def test_build_provider_default_passphrase(self) -> None:
            if "SECKIT_SQLITE_UNLOCK" in os.environ:
                del os.environ["SECKIT_SQLITE_UNLOCK"]
            p = build_sqlite_unlock_provider()
            self.assertIsInstance(p, PassphraseUnlockProvider)

        def test_passphrase_store_rejects_keychain_vault(self) -> None:
            """Opening a keychain-wrapped vault with PassphraseUnlockProvider must error."""
            if sys.platform != "darwin" or not check_security_cli():
                self.skipTest("requires macOS security CLI")
            fixture = make_temp_keychain(password="kc-pass")
            try:
                os.environ["SECKIT_SQLITE_UNLOCK"] = "keychain"
                os.environ["SECKIT_SQLITE_KEK_KEYCHAIN"] = fixture["path"]
                kc_store = SqliteSecretStore(db_path=self.db, kek_keychain_path=fixture["path"])
                kc_store.set(service="s", account="a", name="K", value="sekrit")
                clear_sqlite_crypto_cache()
                clear_sqlite_unlock_cache()
                os.environ["SECKIT_SQLITE_UNLOCK"] = "passphrase"
                os.environ["SECKIT_SQLITE_PASSPHRASE"] = "some-passphrase-not-used-for-wrapped!!"
                bad = SqliteSecretStore(db_path=self.db)
                with self.assertRaisesRegex(BackendError, "keychain-wrapped DEK"):
                    bad.get(service="s", account="a", name="K")
            finally:
                delete_keychain(path=fixture["path"])
                shutil.rmtree(fixture["directory"], ignore_errors=True)

        def test_keychain_store_rejects_passphrase_vault(self) -> None:
            """Opening a legacy passphrase vault with KeychainUnlockProvider must error."""
            if sys.platform != "darwin" or not check_security_cli():
                self.skipTest("requires macOS security CLI")
            fixture = make_temp_keychain(password="kc-pass")
            try:
                os.environ["SECKIT_SQLITE_PASSPHRASE"] = "legacy-passphrase-here!!!!"
                leg = SqliteSecretStore(db_path=self.db)
                leg.set(service="s", account="a", name="K", value="v")
                clear_sqlite_crypto_cache()
                clear_sqlite_unlock_cache()
                os.environ.pop("SECKIT_SQLITE_PASSPHRASE", None)
                os.environ["SECKIT_SQLITE_UNLOCK"] = "keychain"
                bad = SqliteSecretStore(db_path=self.db, kek_keychain_path=fixture["path"])
                with self.assertRaisesRegex(BackendError, "passphrase KDF"):
                    bad.get(service="s", account="a", name="K")
            finally:
                delete_keychain(path=fixture["path"])
                shutil.rmtree(fixture["directory"], ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
