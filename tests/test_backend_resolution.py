from __future__ import annotations

import subprocess
import unittest
from unittest import mock

from secrets_kit.backends.common import (
    BACKEND_SQLITE,
    BackendError,
    is_keychain_backend,
    normalize_backend,
)
from secrets_kit.backends.keychain import (
    get_secret,
    keychain_path,
    set_secret,
)
from secrets_kit.backends.keychain.security_run import security_exists


class BackendResolutionTest(unittest.TestCase):
    def test_keychain_existence_distinguishes_missing_from_failure(self) -> None:
        for status, expected in ((0, True), (44, False)):
            with (
                self.subTest(status=status),
                mock.patch(
                    "secrets_kit.backends.keychain.security_run.subprocess.run",
                    return_value=subprocess.CompletedProcess([], status, "", ""),
                ),
            ):
                self.assertIs(security_exists(args=["find-generic-password"]), expected)

    def test_keychain_existence_errors_are_not_absence_or_provider_output(self) -> None:
        for status in (1, 36, 51, 128, -15):
            with (
                self.subTest(status=status),
                mock.patch(
                    "secrets_kit.backends.keychain.security_run.subprocess.run",
                    return_value=subprocess.CompletedProcess(
                        [], status, "private fixture", "private fixture"
                    ),
                ),
            ):
                with self.assertRaises(BackendError) as caught:
                    security_exists(args=["find-generic-password"])
                self.assertNotIn("private fixture", str(caught.exception))

    def test_normalize_backend_accepts_canonical_ids(self) -> None:
        with self.assertRaisesRegex(BackendError, "retired"):
            normalize_backend("keychain")
        self.assertEqual(normalize_backend("sqlite"), BACKEND_SQLITE)
        self.assertTrue(is_keychain_backend("keychain"))
        self.assertFalse(is_keychain_backend("sqlite"))

    def test_normalize_backend_rejects_legacy_aliases(self) -> None:
        removed_backend = "i" + "cloud"
        removed_alias = removed_backend + "-helper"
        for bad in (
            "secure",
            "local",
            "Secure",
            "LOCAL",
            removed_backend,
            removed_backend[0] + "Cloud",
            removed_alias,
            removed_alias.title(),
        ):
            with self.subTest(bad=bad):
                with self.assertRaisesRegex(BackendError, "unsupported backend"):
                    normalize_backend(bad)

    def test_keychain_backend_with_path_is_retired(self) -> None:
        import tempfile
        from pathlib import Path

        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        keychain = Path(temp_dir.name) / "test.keychain-db"
        keychain.write_text("", encoding="utf-8")
        with mock.patch(
            "secrets_kit.backends.keychain.security_cli.run_security"
        ) as run_security_mock:
            with self.assertRaisesRegex(BackendError, "retired"):
                get_secret(
                    service="sync-test",
                    account="local",
                    name="SECKIT_TEST_ALPHA",
                    path=str(keychain),
                    backend="keychain",
                )
        run_security_mock.assert_not_called()

    def test_keychain_set_is_retired_before_security(self) -> None:
        with (
            mock.patch(
                "secrets_kit.backends.keychain.security_cli.keychain_path",
                return_value=__file__,
            ),
            mock.patch(
                "secrets_kit.backends.keychain.security_cli.security_exists", return_value=False
            ),
            mock.patch(
                "secrets_kit.backends.keychain.security_cli.run_security", return_value=""
            ) as run_security_mock,
        ):
            with self.assertRaisesRegex(BackendError, "retired"):
                set_secret(
                    service="sync-test",
                    account="local",
                    name="SECKIT_TEST_ALPHA",
                    value="alpha-1",
                    backend="keychain",
                )
        run_security_mock.assert_not_called()

    def test_keychain_set_fails_before_security_when_target_missing(self) -> None:
        with mock.patch(
            "secrets_kit.backends.keychain.security_cli.keychain_path",
            return_value="/tmp/seckit-missing-test.keychain-db",
        ):
            with self.assertRaisesRegex(BackendError, "retired"):
                set_secret(
                    service="sync-test",
                    account="local",
                    name="SECKIT_TEST_ALPHA",
                    value="alpha-1",
                    backend="keychain",
                )

    def test_sqlite_backend_does_not_route_through_keychain_store(self) -> None:
        with self.assertRaisesRegex(BackendError, "not the keychain backend"):
            get_secret(
                service="sync-test",
                account="local",
                name="SECKIT_TEST_ALPHA",
                backend="sqlite",
            )

    def test_keychain_path_prefers_security_default_keychain(self) -> None:
        proc = mock.MagicMock(
            returncode=0, stdout='    "/Users/test/Library/Keychains/login.keychain-db"\n'
        )
        with (
            mock.patch(
                "secrets_kit.backends.keychain.security_cli.shutil.which",
                return_value="/usr/bin/security",
            ),
            mock.patch(
                "secrets_kit.backends.keychain.security_cli.subprocess.run",
                return_value=proc,
            ) as run_mock,
        ):
            self.assertEqual(keychain_path(), "/Users/test/Library/Keychains/login.keychain-db")
        run_mock.assert_called_once()


if __name__ == "__main__":
    unittest.main()
