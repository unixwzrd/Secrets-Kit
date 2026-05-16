from __future__ import annotations

import shutil
import sys
import unittest

from platform_guards import SKIP_MACOS_ONLY
from secrets_kit.backends.keychain.security_cli import check_security_cli, delete_keychain, make_temp_keychain
from secrets_kit.backends.operations import delete_secret, get_secret, get_secret_metadata, secret_exists, set_secret


@unittest.skipUnless(sys.platform == "darwin", SKIP_MACOS_ONLY)
@unittest.skipUnless(check_security_cli(), "security CLI not available")
class KeychainBackendRealTest(unittest.TestCase):
    def test_temp_keychain_crud_and_metadata(self) -> None:
        fixture = make_temp_keychain(password="")
        path = fixture["path"]
        try:
            set_secret(
                service="seckit-test",
                account="tester",
                name="OPENAI_API_KEY",
                value="sk-test",
                label="OPENAI_API_KEY",
                comment='{"name":"OPENAI_API_KEY","service":"seckit-test","account":"tester"}',
                path=path,
            )
            self.assertTrue(secret_exists(service="seckit-test", account="tester", name="OPENAI_API_KEY", path=path))
            self.assertEqual(
                get_secret(service="seckit-test", account="tester", name="OPENAI_API_KEY", path=path),
                "sk-test",
            )
            metadata = get_secret_metadata(service="seckit-test", account="tester", name="OPENAI_API_KEY", path=path)
            self.assertEqual(metadata["account"], "tester")
            self.assertEqual(metadata["label"], "OPENAI_API_KEY")
            self.assertIn('"service":"seckit-test"', metadata["comment"])
            delete_secret(service="seckit-test", account="tester", name="OPENAI_API_KEY", path=path)
            self.assertFalse(secret_exists(service="seckit-test", account="tester", name="OPENAI_API_KEY", path=path))
        finally:
            try:
                delete_keychain(path=path)
            finally:
                shutil.rmtree(fixture["directory"], ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
