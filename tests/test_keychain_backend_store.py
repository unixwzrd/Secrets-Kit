"""Keychain BackendStore adapter: authority-shaped comments."""

from __future__ import annotations

import json
import os
import shutil
import sys
import unittest

from secrets_kit.backends.security import check_security_cli, delete_keychain, make_temp_keychain
from secrets_kit.backends.keychain import KeychainBackendStore
from secrets_kit.models.core import EntryMetadata


_MACOS_KEYCHAIN_INTEGRATION = os.environ.get("SECKIT_RUN_KEYCHAIN_INTEGRATION_TESTS") == "1"


@unittest.skipUnless(sys.platform == "darwin", "macOS-only Keychain test")
@unittest.skipUnless(check_security_cli(), "security CLI not available")
@unittest.skipUnless(_MACOS_KEYCHAIN_INTEGRATION, "set SECKIT_RUN_KEYCHAIN_INTEGRATION_TESTS=1 to run live Keychain tests")
class KeychainBackendStoreAuthorityTest(unittest.TestCase):
    def test_set_entry_stores_authority_comment_without_sync_fields(self) -> None:
        fixture = make_temp_keychain(password="")
        path = fixture["path"]
        try:
            st = KeychainBackendStore(path=path)
            meta = EntryMetadata(
                name="STORE_T",
                service="store-svc",
                account="store-acct",
                entry_kind="token",
                content_hash="a" * 64,
                custom={"owner": "t", "seckit_sync_origin_host": "peer-1"},
                entry_id="550e8400-e29b-41d4-a716-446655440000",
            )
            st.set_entry(
                service="store-svc",
                account="store-acct",
                name="STORE_T",
                secret="secret-val",
                metadata=meta,
            )
            resolved = st.resolve_by_locator(service="store-svc", account="store-acct", name="STORE_T")
            self.assertIsNotNone(resolved)
            assert resolved is not None
            self.assertEqual(resolved.secret, "secret-val")
            raw_comment = st._cli.metadata(service="store-svc", account="store-acct", name="STORE_T")["comment"]
            self.assertNotIn("content_hash", raw_comment)
            self.assertNotIn("seckit_sync_origin_host", raw_comment)
            blob = json.loads(raw_comment)
            self.assertEqual(blob.get("name"), "STORE_T")
            self.assertEqual(blob["custom"]["owner"], "t")
        finally:
            try:
                delete_keychain(path=path)
            finally:
                shutil.rmtree(fixture["directory"], ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
