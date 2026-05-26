"""Unit tests for secrets_kit.backends.dispatch."""

from __future__ import annotations

import unittest
from unittest import mock

from secrets_kit.backends.common import BACKEND_KEYCHAIN, BACKEND_SQLITE
from secrets_kit.backends.dispatch import (
    delete_secret_entry,
    read_secret_entry,
    read_secret_value,
    secret_exists_for_backend,
    write_secret,
)
from secrets_kit.models import EntryMetadata


class BackendDispatchTests(unittest.TestCase):
    def test_read_secret_value_sqlite(self) -> None:
        with mock.patch(
            "secrets_kit.backends.dispatch.get_sqlite_secret", return_value="secret"
        ) as get_mock:
            value = read_secret_value(
                service="svc",
                account="acct",
                name="key",
                backend=BACKEND_SQLITE,
                sqlite_dev_mode=True,
            )
        self.assertEqual(value, "secret")
        get_mock.assert_called_once_with(
            service="svc", account="acct", name="key", sqlite_dev_mode=True
        )

    def test_read_secret_value_keychain(self) -> None:
        with mock.patch(
            "secrets_kit.backends.dispatch.keychain_get_secret", return_value="kc"
        ) as get_mock:
            value = read_secret_value(
                service="svc",
                account="acct",
                name="key",
                backend=BACKEND_KEYCHAIN,
                keychain_path="/tmp/test.keychain-db",
            )
        self.assertEqual(value, "kc")
        get_mock.assert_called_once()

    def test_write_secret_sqlite(self) -> None:
        meta = EntryMetadata(name="key", service="svc", account="acct", source="test")
        with mock.patch("secrets_kit.backends.dispatch.set_sqlite_secret") as set_mock:
            write_secret(
                service="svc",
                account="acct",
                name="key",
                value="v",
                metadata=meta,
                backend=BACKEND_SQLITE,
                sqlite_dev_mode=True,
            )
        set_mock.assert_called_once()

    def test_write_secret_keychain(self) -> None:
        meta = EntryMetadata(name="key", service="svc", account="acct", source="test")
        with mock.patch("secrets_kit.backends.dispatch.keychain_set_secret") as set_mock:
            write_secret(
                service="svc",
                account="acct",
                name="key",
                value="v",
                metadata=meta,
                backend=BACKEND_KEYCHAIN,
            )
        set_mock.assert_called_once()
        self.assertIn("comment", set_mock.call_args.kwargs)

    def test_secret_exists_for_backend(self) -> None:
        with mock.patch("secrets_kit.backends.dispatch.sqlite_secret_exists", return_value=True):
            self.assertTrue(
                secret_exists_for_backend(
                    service="s",
                    account="a",
                    name="n",
                    backend=BACKEND_SQLITE,
                    sqlite_dev_mode=True,
                )
            )

    def test_read_secret_entry_sqlite(self) -> None:
        meta = EntryMetadata(name="n", service="s", account="a", source="sqlite")
        with mock.patch(
            "secrets_kit.backends.dispatch.get_sqlite_secret_entry",
            return_value=("val", meta),
        ):
            value, parsed = read_secret_entry(
                service="s",
                account="a",
                name="n",
                backend=BACKEND_SQLITE,
                sqlite_dev_mode=True,
            )
        self.assertEqual(value, "val")
        self.assertEqual(parsed.name, "n")

    def test_delete_secret_entry_keychain(self) -> None:
        meta = EntryMetadata(name="n", service="s", account="a", source="del")
        with mock.patch("secrets_kit.backends.dispatch.keychain_delete_secret") as delete_mock:
            delete_secret_entry(
                service="s",
                account="a",
                name="n",
                metadata=meta,
                backend=BACKEND_KEYCHAIN,
            )
        delete_mock.assert_called_once()


if __name__ == "__main__":
    unittest.main()
