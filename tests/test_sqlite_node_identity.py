"""Tests for standalone SQLite node identity lifecycle."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

from secrets_kit.backends.sqlite import SQLITE_PATH_ENV, open_sqlite_backend
from secrets_kit.backends.sqlite.node_identity import (
    SQLITE_NODE_IDENTITY_KEY_ENV,
    load_sqlite_node_identity_summary,
    sqlite_node_identity_key_path,
)
from secrets_kit.cli.commands.info import build_info_dict, cmd_info
from secrets_kit.cli.commands.init_cmd import cmd_init_operator
from secrets_kit.crypto.storage.sqlite import SQLITE_STORAGE_KEY_ENV, sqlite_storage_key_path
from secrets_kit.registry import registry_path


class SQLiteNodeIdentityLifecycleTest(unittest.TestCase):
    """Standalone identity lifecycle regressions for SQLite nodes."""

    def _init_store(self, *, home: Path) -> None:
        args = argparse.Namespace(
            yes=True,
            home=str(home),
            init_target=None,
            backend="sqlite",
        )
        with (
            mock.patch.dict(os.environ, {}, clear=False),
            redirect_stdout(StringIO()),
            redirect_stderr(StringIO()),
        ):
            os.environ.pop(SQLITE_PATH_ENV, None)
            os.environ.pop(SQLITE_STORAGE_KEY_ENV, None)
            os.environ.pop(SQLITE_NODE_IDENTITY_KEY_ENV, None)
            self.assertEqual(cmd_init_operator(args=args), 0)

    def _summary(self, *, home: Path):
        conn = open_sqlite_backend(home=home)
        try:
            return load_sqlite_node_identity_summary(conn=conn, home=home)
        finally:
            conn.close()

    def test_fresh_sqlite_init_creates_distinct_signing_and_encryption_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            self._init_store(home=home)

            summary = self._summary(home=home)

            self.assertIsNotNone(summary)
            if summary is None:
                self.fail("identity summary should be present")
            self.assertTrue(summary.node_id.startswith("node:"))
            self.assertEqual(summary.signing_algorithm, "ed25519")
            self.assertEqual(summary.encryption_algorithm, "x25519")
            self.assertNotEqual(
                summary.signing_public_key_fingerprint,
                summary.encryption_public_key_fingerprint,
            )

    def test_identity_persists_across_process_style_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            self._init_store(home=home)
            first = self._summary(home=home)

            second = self._summary(home=home)

            self.assertEqual(first, second)

    def test_two_isolated_sqlite_nodes_receive_different_identities(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home_a = Path(tmp) / "node-a"
            home_b = Path(tmp) / "node-b"
            self._init_store(home=home_a)
            self._init_store(home=home_b)

            identity_a = self._summary(home=home_a)
            identity_b = self._summary(home=home_b)

            self.assertIsNotNone(identity_a)
            self.assertIsNotNone(identity_b)
            if identity_a is None or identity_b is None:
                self.fail("both identities should be present")
            self.assertNotEqual(identity_a.node_id, identity_b.node_id)
            self.assertNotEqual(
                identity_a.signing_public_key_fingerprint,
                identity_b.signing_public_key_fingerprint,
            )
            self.assertNotEqual(
                identity_a.encryption_public_key_fingerprint,
                identity_b.encryption_public_key_fingerprint,
            )

    def test_sqlite_storage_key_is_distinct_from_node_identity_material(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            self._init_store(home=home)

            storage_key_payload = json.loads(sqlite_storage_key_path(home=home).read_text())
            identity_payload = json.loads(sqlite_node_identity_key_path(home=home).read_text())

            self.assertNotEqual(
                storage_key_payload["key_b64"],
                identity_payload["signing"]["payload"]["private_key"]["key"],
            )
            self.assertNotEqual(
                storage_key_payload["key_b64"],
                identity_payload["encryption"]["payload"]["private_key"]["key"],
            )

    def test_private_material_is_not_in_registry_transactions_envelopes_or_info(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            self._init_store(home=home)
            identity_payload = json.loads(sqlite_node_identity_key_path(home=home).read_text())
            private_values = {
                identity_payload["signing"]["payload"]["private_key"]["key"],
                identity_payload["encryption"]["payload"]["private_key"]["key"],
            }

            db_path = home / ".config" / "seckit" / "seckit.sqlite"
            conn = sqlite3.connect(db_path)
            try:
                rows = conn.execute(
                    "SELECT payload FROM transactions UNION ALL SELECT encrypted_payload FROM envelopes"
                ).fetchall()
            finally:
                conn.close()
            stdout = StringIO()
            with (
                mock.patch.object(Path, "home", return_value=home),
                redirect_stdout(stdout),
                redirect_stderr(StringIO()),
            ):
                public_info = build_info_dict(args=argparse.Namespace(backend="sqlite"))
                self.assertEqual(cmd_info(args=argparse.Namespace(backend="sqlite")), 0)

            registry_text = registry_path(home=home).read_text(encoding="utf-8")
            row_text = "\n".join(bytes(row[0]).decode("utf-8", errors="ignore") for row in rows)
            public_text = json.dumps(public_info, sort_keys=True) + stdout.getvalue()
            for private_value in private_values:
                self.assertNotIn(private_value, registry_text)
                self.assertNotIn(private_value, row_text)
                self.assertNotIn(private_value, public_text)

    def test_no_networking_required_for_identity_load(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            self._init_store(home=home)

            with mock.patch("socket.create_connection", side_effect=AssertionError("network used")):
                summary = self._summary(home=home)

            self.assertIsNotNone(summary)


if __name__ == "__main__":
    unittest.main()
