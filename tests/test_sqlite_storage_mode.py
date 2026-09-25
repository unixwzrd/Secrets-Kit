"""Tests for immutable SQLite storage mode."""

from __future__ import annotations

import argparse
import base64
import io
import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any
from unittest import mock

from secrets_kit.backends.sqlite import SQLITE_PATH_ENV, SQLiteBackendError, open_sqlite_backend
from secrets_kit.backends.sqlite.node_identity import SQLITE_NODE_IDENTITY_KEY_ENV
from secrets_kit.backends.sqlite.replay import rebuild_secret_projections
from secrets_kit.backends.sqlite.storage_mode import (
    SQLITE_STORAGE_MODE_ENCRYPTED,
    SQLITE_STORAGE_MODE_PLAINTEXT,
    read_sqlite_storage_mode,
)
from secrets_kit.backends.sqlite.transactions import (
    create_transaction,
    insert_transaction,
    inspect_transaction,
)
from secrets_kit.backends.sqlite.validation import validate_sqlite_datastore
from secrets_kit.cli.commands.delete import cmd_delete
from secrets_kit.cli.commands.get import cmd_get
from secrets_kit.cli.commands.info import build_info_dict, cmd_info
from secrets_kit.cli.commands.init_cmd import cmd_init_operator
from secrets_kit.cli.commands.set import cmd_set
from secrets_kit.crypto.storage.sqlite import SQLITE_STORAGE_KEY_ENV
from secrets_kit.registry import load_defaults
from tests.canonical_id_helpers import tid

TXN_ENCRYPTED_IN_PLAINTEXT = tid("transaction", "txn-encrypted-in-plaintext")


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


class SQLiteStorageModeTest(unittest.TestCase):
    def _init_args(self, *, home: Path, storage_mode: str | None = None) -> argparse.Namespace:
        return argparse.Namespace(
            yes=True,
            home=str(home),
            init_target=None,
            backend="sqlite",
            storage_mode=storage_mode,
            unsafe_plaintext_storage=storage_mode == "plaintext",
        )

    def _clean_env(self) -> Any:
        return mock.patch.dict(os.environ, {}, clear=False)

    def _init_home(self, *, home: Path, storage_mode: str | None = None) -> None:
        with self._clean_env(), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            os.environ.pop(SQLITE_PATH_ENV, None)
            os.environ.pop(SQLITE_STORAGE_KEY_ENV, None)
            os.environ.pop(SQLITE_NODE_IDENTITY_KEY_ENV, None)
            os.environ.pop("SECKIT_SQLITE_STORAGE_MODE", None)
            self.assertEqual(cmd_init_operator(args=self._init_args(home=home, storage_mode=storage_mode)), 0)

    def _db_path(self, *, home: Path) -> Path:
        return home / ".config" / "seckit" / "seckit.sqlite"

    def _key_path(self, *, home: Path) -> Path:
        return home / ".config" / "seckit" / "sqlite-storage.key"

    def _read_mode(self, *, home: Path) -> str:
        conn = sqlite3.connect(self._db_path(home=home))
        conn.row_factory = sqlite3.Row
        try:
            return read_sqlite_storage_mode(conn=conn) or ""
        finally:
            conn.close()

    def _stat_snapshot(self, *, home: Path) -> dict[str, tuple[int, int, int, int]]:
        config_dir = home / ".config" / "seckit"
        paths = [path for path in config_dir.iterdir() if path.is_file()]
        return {
            path.name: (
                path.stat().st_ino,
                path.stat().st_size,
                path.stat().st_mtime_ns,
                path.stat().st_mode,
            )
            for path in sorted(paths)
        }

    def _set_secret(self, *, home: Path, name: str = "ST01_SECRET", value: str = "value") -> None:
        args = argparse.Namespace(
            backend="sqlite",
            keychain=None,
            service="st01",
            account="local",
            name=name,
            value=value,
            stdin=False,
            allow_empty=False,
            type="secret",
            kind="api_key",
            tags=None,
            comment=None,
            source_url=None,
            source_label=None,
            rotation_days=None,
            rotation_warn_days=None,
            expires_at=None,
            schema=None,
            custom=[],
        )
        with mock.patch.dict(os.environ, {"HOME": str(home)}, clear=False):
            self.assertEqual(cmd_set(args=args), 0)

    def _get_secret(self, *, home: Path, name: str = "ST01_SECRET") -> str:
        args = argparse.Namespace(
            backend="sqlite",
            keychain=None,
            service="st01",
            account="local",
            name=name,
            raw=True,
        )
        stdout = io.StringIO()
        with mock.patch.dict(os.environ, {"HOME": str(home)}, clear=False), redirect_stdout(stdout):
            self.assertEqual(cmd_get(args=args), 0)
        return stdout.getvalue().strip()

    def _delete_secret(self, *, home: Path, name: str = "ST01_SECRET") -> None:
        args = argparse.Namespace(
            backend="sqlite",
            keychain=None,
            service="st01",
            account="local",
            name=name,
            yes=True,
        )
        with mock.patch.dict(os.environ, {"HOME": str(home)}, clear=False):
            self.assertEqual(cmd_delete(args=args), 0)

    def test_encrypted_mode_is_default_and_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            self._init_home(home=home)

            self.assertEqual(self._read_mode(home=home), SQLITE_STORAGE_MODE_ENCRYPTED)
            self.assertEqual(load_defaults(home=home)["sqlite_storage_mode"], "encrypted")
            self.assertTrue(self._key_path(home=home).is_file())

    def test_explicit_encrypted_initialization(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            self._init_home(home=home, storage_mode="encrypted")

            self.assertEqual(self._read_mode(home=home), SQLITE_STORAGE_MODE_ENCRYPTED)
            conn = open_sqlite_backend(home=home)
            conn.close()

    def test_explicit_plaintext_initialization_without_storage_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            self._init_home(home=home, storage_mode="plaintext")

            self.assertEqual(self._read_mode(home=home), SQLITE_STORAGE_MODE_PLAINTEXT)
            self.assertFalse(self._key_path(home=home).exists())
            conn = open_sqlite_backend(home=home)
            conn.close()

    def test_repeated_open_retains_original_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            self._init_home(home=home, storage_mode="plaintext")

            for _ in range(2):
                conn = open_sqlite_backend(home=home)
                try:
                    self.assertEqual(read_sqlite_storage_mode(conn=conn), "plaintext")
                finally:
                    conn.close()

    def test_opening_existing_datastore_does_not_modify_persistent_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            self._init_home(home=home, storage_mode="encrypted")
            before = self._stat_snapshot(home=home)

            conn = open_sqlite_backend(home=home)
            conn.close()

            self.assertEqual(self._stat_snapshot(home=home), before)

    def test_repeated_validation_does_not_modify_persistent_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            self._init_home(home=home, storage_mode="encrypted")
            before = self._stat_snapshot(home=home)
            db_path = self._db_path(home=home)

            for _ in range(2):
                conn = sqlite3.connect(db_path)
                conn.row_factory = sqlite3.Row
                try:
                    validate_sqlite_datastore(
                        conn=conn,
                        home=home,
                        sqlite_db_path=db_path,
                        configured_storage_mode="encrypted",
                    )
                finally:
                    conn.close()

            self.assertEqual(self._stat_snapshot(home=home), before)

    def test_opening_plaintext_datastore_does_not_create_storage_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            self._init_home(home=home, storage_mode="plaintext")
            before = self._stat_snapshot(home=home)

            conn = open_sqlite_backend(home=home)
            conn.close()

            self.assertFalse(self._key_path(home=home).exists())
            self.assertEqual(self._stat_snapshot(home=home), before)

    def test_defaults_database_mismatch_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            self._init_home(home=home, storage_mode="plaintext")
            defaults = load_defaults(home=home)
            defaults["sqlite_storage_mode"] = "encrypted"
            from secrets_kit.registry import save_defaults

            save_defaults(payload=defaults, home=home)

            with self.assertRaisesRegex(SQLiteBackendError, "storage mode mismatch"):
                open_sqlite_backend(home=home)

    def test_obsolete_environment_cannot_switch_persisted_storage_format(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            self._init_home(home=home, storage_mode="encrypted")

            with (
                mock.patch.dict(os.environ, {"SECKIT_SQLITE_STORAGE_MODE": "plaintext"}, clear=False),
            ):
                conn = open_sqlite_backend(home=home)
                try:
                    self.assertEqual(read_sqlite_storage_mode(conn=conn), "encrypted")
                finally:
                    conn.close()

    def test_missing_mode_metadata_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            self._init_home(home=home)
            conn = sqlite3.connect(self._db_path(home=home))
            try:
                conn.execute("DELETE FROM datastore_metadata WHERE metadata_key = 'storage_mode'")
                conn.commit()
            finally:
                conn.close()

            with self.assertRaisesRegex(SQLiteBackendError, "storage mode metadata is missing"):
                open_sqlite_backend(home=home)

    def test_encrypted_mode_requires_storage_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            self._init_home(home=home, storage_mode="encrypted")
            self._key_path(home=home).unlink()

            with self.assertRaisesRegex(SQLiteBackendError, "sqlite-storage.key"):
                open_sqlite_backend(home=home)

    def test_plaintext_mode_crud_and_replay_without_storage_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            self._init_home(home=home, storage_mode="plaintext")
            self.assertFalse(self._key_path(home=home).exists())

            self._set_secret(home=home, value="plaintext-value")
            self.assertEqual(self._get_secret(home=home), "plaintext-value")

            conn = sqlite3.connect(self._db_path(home=home))
            conn.row_factory = sqlite3.Row
            try:
                row = conn.execute(
                    "SELECT encrypted_name, encrypted_payload FROM secrets WHERE name = ?",
                    ("ST01_SECRET",),
                ).fetchone()
                self.assertEqual(row["encrypted_name"], b"ST01_SECRET")
                self.assertEqual(row["encrypted_payload"], b"plaintext-value")
                conn.execute("DELETE FROM secrets")
                rebuild_secret_projections(conn=conn)
                rebuilt = conn.execute(
                    "SELECT encrypted_payload FROM secrets WHERE name = ?",
                    ("ST01_SECRET",),
                ).fetchone()
                self.assertEqual(rebuilt["encrypted_payload"], b"plaintext-value")
            finally:
                conn.close()

            self.assertEqual(self._get_secret(home=home), "plaintext-value")
            self._delete_secret(home=home)
            conn = sqlite3.connect(self._db_path(home=home))
            conn.row_factory = sqlite3.Row
            try:
                row = conn.execute("SELECT state FROM secrets WHERE name = ?", ("ST01_SECRET",)).fetchone()
                self.assertEqual(row["state"], "deleted")
            finally:
                conn.close()

    def test_encrypted_mode_crud_does_not_store_plaintext(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            self._init_home(home=home, storage_mode="encrypted")
            self._set_secret(home=home, value="encrypted-value")

            conn = sqlite3.connect(self._db_path(home=home))
            conn.row_factory = sqlite3.Row
            try:
                row = conn.execute(
                    "SELECT encrypted_name, encrypted_payload FROM secrets WHERE name = ?",
                    ("ST01_SECRET",),
                ).fetchone()
                self.assertNotIn(b"ST01_SECRET", row["encrypted_name"])
                self.assertNotIn(b"encrypted-value", row["encrypted_payload"])
            finally:
                conn.close()
            self.assertEqual(self._get_secret(home=home), "encrypted-value")

    def test_info_reports_storage_mode_and_plaintext_warning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            self._init_home(home=home, storage_mode="plaintext")

            with mock.patch.dict(os.environ, {"HOME": str(home)}, clear=False):
                data = build_info_dict(args=argparse.Namespace(backend="sqlite"))
                self.assertEqual(data["sqlite"]["storage_mode"], "plaintext")
                self.assertFalse(data["sqlite"]["encryption"]["enabled"])
                stderr = io.StringIO()
                with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                    self.assertEqual(cmd_info(args=argparse.Namespace(backend="sqlite", info_json=False)), 0)
                self.assertIn("stored unencrypted", stderr.getvalue())

    def test_plaintext_database_rejects_encrypted_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            self._init_home(home=home, storage_mode="plaintext")
            self._set_secret(home=home)
            conn = sqlite3.connect(self._db_path(home=home))
            conn.row_factory = sqlite3.Row
            try:
                payload = {
                    "ciphertext": "abc",
                    "header": {
                        "algorithm": "chacha20-poly1305",
                        "context": "sqlite-storage:encrypted_payload",
                        "key_id": "sqlite-storage.key",
                        "version": 1,
                    },
                    "nonce": "abc",
                }
                encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
                row = conn.execute(
                    """
                    SELECT transaction_id
                    FROM transactions
                    WHERE transaction_type = 'secret.set'
                    ORDER BY rowid DESC
                    LIMIT 1
                    """
                ).fetchone()
                tx = inspect_transaction(
                    path=self._db_path(home=home),
                    transaction_id=str(row["transaction_id"]),
                )
                tx_payload = dict(tx.payload)
                tx_payload["encrypted_payload_b64"] = _b64(encoded)
                conn.execute("DELETE FROM transactions WHERE transaction_id = ?", (tx.transaction_id,))
                insert_transaction(
                    conn=conn,
                    transaction=create_transaction(
                        transaction_id=TXN_ENCRYPTED_IN_PLAINTEXT,
                        transaction_type="secret.set",
                        origin_node_id=tx.origin_node_id,
                        created_at=tx.created_at,
                        payload=tx_payload,
                    ),
                )
                with self.assertRaisesRegex(SQLiteBackendError, "storage mode"):
                    rebuild_secret_projections(conn=conn)
            finally:
                conn.close()


if __name__ == "__main__":
    unittest.main()
