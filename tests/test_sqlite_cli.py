from __future__ import annotations

import argparse
import io
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from secrets_kit.backends.base import SecretStore
from secrets_kit.backends.keychain import SecurityCliStore
from secrets_kit.backends.sqlite import (
    SQLITE_PATH_ENV,
    SqliteSecretStore,
    SQLiteValidationError,
    create_transaction,
    delete_sqlite_secret,
    get_sqlite_metadata,
    get_sqlite_secret,
    get_transaction,
    insert_transaction,
    open_sqlite_backend,
    set_sqlite_secret,
)
from secrets_kit.backends.sqlite.node_identity import ensure_sqlite_node_identity
from secrets_kit.backends.sqlite.provisioning import provision_sqlite_datastore
from secrets_kit.cli import (
    build_parser,
    cmd_doctor,
    cmd_export,
    cmd_get,
    cmd_import_env,
    cmd_run,
    cmd_service_copy,
    cmd_set,
)
from secrets_kit.crypto.storage.sqlite import SQLITE_STORAGE_KEY_ENV
from secrets_kit.models import EntryMetadata, now_utc_iso
from secrets_kit.registry import ensure_registry_storage, registry_path
from secrets_kit.schemas.identifiers import schema_id_for_name
from tests.canonical_id_helpers import tid

RECORDED_ONLY_PEER_GROUP_ID = tid("peer_group", "recorded-only-peer-group")
RECORDED_ONLY_NODE_ID = tid("node", "recorded-only-node")
RECORDED_ONLY_TXN_ID = tid("transaction", "txn-recorded-only")
MISSING_SECRET_ID = tid("secret", "missing-projection")
MISSING_OWNER_ID = tid("owner", "missing")
MISSING_SERVICE_GROUP_ID = tid("service_group", "missing")
API_KEY_SCHEMA_ID = schema_id_for_name(name="builtin.secret.api_key")


def _init_storage_mode(*, path: Path) -> None:
    conn = provision_sqlite_datastore(path=path, storage_mode="encrypted")
    try:
        ensure_sqlite_node_identity(conn=conn)
    finally:
        conn.close()


class SQLiteCliTest(unittest.TestCase):
    def test_service_copy_uses_sqlite_backend_dispatch(self) -> None:
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.dict(
                os.environ,
                {SQLITE_PATH_ENV: str(Path(tmp) / "seckit.sqlite")},
                clear=False,
            ),
        ):
            _init_storage_mode(path=Path(os.environ[SQLITE_PATH_ENV]))
            set_sqlite_secret(
                service="source",
                account="acct",
                name="COPY_KEY",
                value="secret",
                metadata=EntryMetadata(
                    name="COPY_KEY",
                    service="source",
                    account="acct",
                    entry_kind="api_key",
                ),
            )
            code = cmd_service_copy(
                args=argparse.Namespace(
                    from_service="source",
                    from_account="acct",
                    to_service="destination",
                    to_account="acct",
                    names=None,
                    tag=None,
                    type=None,
                    kind=None,
                    overwrite=False,
                    dry_run=False,
                    keychain=None,
                    backend="sqlite",
                )
            )
            copied = get_sqlite_secret(
                service="destination",
                account="acct",
                name="COPY_KEY",
            )

        self.assertEqual(code, 0)
        self.assertEqual(copied, "secret")

    def test_sqlite_runtime_commands_do_not_write_registry_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            db_path = Path(tmp) / "seckit.sqlite"
            dotenv = Path(tmp) / "import.env"
            dotenv.write_text("IMPORTED_KEY=imported-value\n", encoding="utf-8")
            ensure_registry_storage(home=home)
            catalog_path = registry_path(home=home)
            original_catalog = catalog_path.read_bytes()

            set_args = argparse.Namespace(
                name="RUNTIME_KEY",
                value="runtime-value",
                stdin=False,
                allow_empty=False,
                type="secret",
                kind="generic",
                tags=None,
                comment="",
                service="svc",
                account="acct",
                source_url="",
                source_label="",
                rotation_days=None,
                rotation_warn_days=None,
                expires_at="",
                domain=None,
                domains=None,
                meta=None,
                keychain=None,
                backend="sqlite",
            )
            get_args = argparse.Namespace(
                name="RUNTIME_KEY",
                raw=True,
                service="svc",
                account="acct",
                keychain=None,
                backend="sqlite",
            )
            run_args = argparse.Namespace(
                service="svc",
                account="acct",
                names="RUNTIME_KEY",
                tag=None,
                type=None,
                kind=None,
                all=False,
                keychain=None,
                backend="sqlite",
                child_command=["--", sys.executable, "-c", "pass"],
            )
            import_args = argparse.Namespace(
                dotenv=str(dotenv),
                from_env=None,
                account="acct",
                service="svc",
                keychain=None,
                backend="sqlite",
                type="secret",
                kind="generic",
                tags=None,
                dry_run=False,
                allow_overwrite=False,
                upsert=False,
                allow_empty=False,
                yes=True,
            )

            with (
                mock.patch.object(Path, "home", return_value=home),
                mock.patch.dict(os.environ, {SQLITE_PATH_ENV: str(db_path)}, clear=False),
                mock.patch(
                    "secrets_kit.registry.storage._atomic_write_json",
                    side_effect=AssertionError("runtime command attempted registry write"),
                ),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                _init_storage_mode(path=Path(os.environ[SQLITE_PATH_ENV]))
                self.assertEqual(cmd_set(args=set_args), 0)
                self.assertEqual(catalog_path.read_bytes(), original_catalog)

                self.assertEqual(cmd_get(args=get_args), 0)
                self.assertEqual(catalog_path.read_bytes(), original_catalog)

                with mock.patch("secrets_kit.cli.commands.run._exec_child", return_value=0):
                    self.assertEqual(cmd_run(args=run_args), 0)
                self.assertEqual(catalog_path.read_bytes(), original_catalog)

                self.assertEqual(cmd_import_env(args=import_args), 0)
                self.assertEqual(catalog_path.read_bytes(), original_catalog)

    def test_parser_accepts_sqlite_backend_without_runtime_mode(self) -> None:
        parser = build_parser()
        for command in ("set", "get", "list", "delete", "explain", "export", "run", "doctor"):
            with self.subTest(command=command):
                argv = [command, "--backend", "sqlite"]
                if command in {"set", "get", "delete", "explain"}:
                    argv.extend(["--name", "OPENAI_API_KEY"])
                if command == "set":
                    argv.extend(["--value", "secret"])
                if command == "run":
                    argv.extend(["--all", "--", sys.executable, "-c", "print('ok')"])
                args = parser.parse_args(argv)
                self.assertEqual(args.backend, "sqlite")
        import_args = parser.parse_args(
            ["import", "env", "--backend", "sqlite", "--dotenv", "x.env"]
        )
        self.assertEqual(import_args.backend, "sqlite")

    def test_sqlite_set_get_roundtrip(self) -> None:
        set_args = argparse.Namespace(
            name="OPENAI_API_KEY",
            value="secret",
            stdin=False,
            allow_empty=False,
            type="secret",
            kind="api_key",
            tags=None,
            comment="",
            service="svc",
            account="acct",
            source_url="",
            source_label="",
            rotation_days=None,
            rotation_warn_days=None,
            expires_at="",
            domain=None,
            domains=None,
            meta=None,
            keychain=None,
            backend="sqlite",
        )
        get_args = argparse.Namespace(
            name="OPENAI_API_KEY",
            raw=True,
            service="svc",
            account="acct",
            keychain=None,
            backend="sqlite",
        )
        out = io.StringIO()
        err = io.StringIO()
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.object(Path, "home", return_value=Path(tmp)),
            mock.patch.dict(
                os.environ, {SQLITE_PATH_ENV: str(Path(tmp) / "seckit.sqlite")}, clear=False
            ),
            redirect_stdout(out),
            redirect_stderr(err),
        ):
            _init_storage_mode(path=Path(os.environ[SQLITE_PATH_ENV]))
            ensure_registry_storage(home=Path(tmp))
            self.assertEqual(cmd_set(args=set_args), 0)
            self.assertEqual(cmd_get(args=get_args), 0)

        self.assertIn("secret\n", out.getvalue())

    def test_sqlite_storage_encrypts_projection_and_transaction_secret_bytes(self) -> None:
        name = "RB01_UNIQUE_SECRET_NAME"
        value = "rb01-super-plaintext-value"
        set_args = argparse.Namespace(
            name=name,
            value=value,
            stdin=False,
            allow_empty=False,
            type="secret",
            kind="api_key",
            tags=None,
            comment="",
            service="rb01-service",
            account="rb01-account",
            source_url="",
            source_label="",
            rotation_days=None,
            rotation_warn_days=None,
            expires_at="",
            domain=None,
            domains=None,
            meta=None,
            keychain=None,
            backend="sqlite",
        )
        get_args = argparse.Namespace(
            name=name,
            raw=True,
            service="rb01-service",
            account="rb01-account",
            keychain=None,
            backend="sqlite",
        )
        export_args = argparse.Namespace(
            service="rb01-service",
            account="rb01-account",
            keychain=None,
            backend="sqlite",
            format="shell",
            out=None,
            password=None,
            password_stdin=False,
            names=name,
            tag=None,
            type=None,
            kind=None,
            all=False,
        )
        run_args = argparse.Namespace(
            service="rb01-service",
            account="rb01-account",
            names=name,
            tag=None,
            type=None,
            kind=None,
            all=False,
            keychain=None,
            backend="sqlite",
            child_command=["--", sys.executable, "-c", "pass"],
        )
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            db_path = Path(tmp) / "seckit.sqlite"
            key_path = home / ".config" / "seckit" / "sqlite-storage.key"
            env = {
                SQLITE_PATH_ENV: str(db_path),
                SQLITE_STORAGE_KEY_ENV: str(key_path),
            }
            with (
                mock.patch.object(Path, "home", return_value=home),
                mock.patch.dict(os.environ, env, clear=False),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                _init_storage_mode(path=Path(os.environ[SQLITE_PATH_ENV]))
                ensure_registry_storage(home=home)
                self.assertEqual(cmd_set(args=set_args), 0)

            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            try:
                row = conn.execute(
                    """
                    SELECT encrypted_name, encrypted_payload
                    FROM secrets
                    WHERE service = ? AND account = ? AND name = ?
                    """,
                    ("rb01-service", "rb01-account", name),
                ).fetchone()
                tx_row = conn.execute(
                    """
                    SELECT payload
                    FROM transactions
                    WHERE transaction_type = 'secret.set'
                    ORDER BY rowid DESC
                    LIMIT 1
                    """
                ).fetchone()
            finally:
                conn.close()

            self.assertIsNotNone(row)
            self.assertIsNotNone(tx_row)
            if row is None or tx_row is None:
                self.fail("SQLite rows should be present")
            tx_payload = bytes(tx_row["payload"])
            name_bytes = name.encode("utf-8")
            value_bytes = value.encode("utf-8")
            self.assertNotIn(name_bytes, bytes(row["encrypted_name"]))
            self.assertNotIn(value_bytes, bytes(row["encrypted_payload"]))
            self.assertNotIn(name_bytes, tx_payload)
            self.assertNotIn(value_bytes, tx_payload)
            self.assertNotIn(b"cmIwMS1zdXBlci1wbGFpbnRleHQtdmFsdWU=", tx_payload)
            self.assertTrue(key_path.exists())

            get_out = io.StringIO()
            with (
                mock.patch.object(Path, "home", return_value=home),
                mock.patch.dict(os.environ, env, clear=False),
                redirect_stdout(get_out),
                redirect_stderr(io.StringIO()),
            ):
                _init_storage_mode(path=Path(os.environ[SQLITE_PATH_ENV]))
                self.assertEqual(cmd_get(args=get_args), 0)
            self.assertEqual(get_out.getvalue(), value + "\n")

            export_out = io.StringIO()
            with (
                mock.patch.object(Path, "home", return_value=home),
                mock.patch.dict(os.environ, env, clear=False),
                redirect_stdout(export_out),
                redirect_stderr(io.StringIO()),
            ):
                _init_storage_mode(path=Path(os.environ[SQLITE_PATH_ENV]))
                self.assertEqual(cmd_export(args=export_args), 0)
            self.assertIn(f"export {name}={value}", export_out.getvalue())

            with (
                mock.patch.object(Path, "home", return_value=home),
                mock.patch.dict(os.environ, env, clear=False),
                mock.patch("secrets_kit.cli.commands.run._exec_child", return_value=0) as exec_mock,
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                _init_storage_mode(path=Path(os.environ[SQLITE_PATH_ENV]))
                self.assertEqual(cmd_run(args=run_args), 0)
            self.assertEqual(exec_mock.call_args.kwargs["env"][name], value)

    def test_sqlite_sync_fields_roundtrip_outside_user_custom_metadata(self) -> None:
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.object(Path, "home", return_value=Path(tmp)),
            mock.patch.dict(
                os.environ,
                {SQLITE_PATH_ENV: str(Path(tmp) / "seckit.sqlite")},
                clear=False,
            ),
        ):
            _init_storage_mode(path=Path(os.environ[SQLITE_PATH_ENV]))
            set_sqlite_secret(
                service="svc",
                account="acct",
                name="SYNC_KEY",
                value="secret",
                metadata=EntryMetadata(
                    name="SYNC_KEY",
                    service="svc",
                    account="acct",
                    entry_id="11111111-1111-4111-8111-111111111111",
                    sync_origin_host="host-a",
                    custom={"owner": "ops"},
                ),
            )

            metadata = get_sqlite_metadata(service="svc", account="acct", name="SYNC_KEY")

        self.assertEqual(metadata.entry_id, "11111111-1111-4111-8111-111111111111")
        self.assertEqual(metadata.sync_origin_host, "host-a")
        self.assertEqual(metadata.custom, {"owner": "ops"})

    def test_sqlite_set_without_ack_env_allows_operation(self) -> None:
        args = argparse.Namespace(
            name="OPENAI_API_KEY",
            value="secret",
            stdin=False,
            allow_empty=False,
            type="secret",
            kind="api_key",
            tags=None,
            comment="",
            service="svc",
            account="acct",
            source_url="",
            source_label="",
            rotation_days=None,
            rotation_warn_days=None,
            expires_at="",
            domain=None,
            domains=None,
            meta=None,
            keychain=None,
            backend="sqlite",
        )
        err = io.StringIO()
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.object(Path, "home", return_value=Path(tmp)),
            mock.patch.dict(
                os.environ,
                {SQLITE_PATH_ENV: str(Path(tmp) / "seckit.sqlite")},
                clear=False,
            ),
            redirect_stdout(io.StringIO()),
            redirect_stderr(err),
        ):
            _init_storage_mode(path=Path(os.environ[SQLITE_PATH_ENV]))
            ensure_registry_storage(home=Path(tmp))
            code = cmd_set(args=args)

        self.assertEqual(code, 0)

    def test_sqlite_store_roundtrip(self) -> None:
        store = SqliteSecretStore()
        meta = EntryMetadata(
            name="OPENAI_API_KEY",
            service="svc",
            account="acct",
            entry_kind="api_key",
            tags=["prod", "token"],
            rotation_days=30,
            rotation_warn_days=7,
            domains=["example.com"],
            custom={"owner": "ops"},
            source="unit-test",
        )
        err = io.StringIO()
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.dict(
                os.environ,
                {SQLITE_PATH_ENV: str(Path(tmp) / "seckit.sqlite")},
                clear=False,
            ),
            redirect_stderr(err),
        ):
            _init_storage_mode(path=Path(os.environ[SQLITE_PATH_ENV]))
            self.assertIsInstance(store, SecretStore)
            self.assertIsInstance(SecurityCliStore(), SecretStore)
            store.set(
                service="svc", account="acct", name="OPENAI_API_KEY", value="secret", metadata=meta
            )
            self.assertTrue(store.exists(service="svc", account="acct", name="OPENAI_API_KEY"))
            self.assertEqual(
                store.get(service="svc", account="acct", name="OPENAI_API_KEY"), "secret"
            )
            stored_meta = store.metadata(service="svc", account="acct", name="OPENAI_API_KEY")
            listed = store.list(service="svc", account="acct")
            store.doctor_roundtrip(service="svc", account="acct")

        self.assertEqual(stored_meta.entry_type, "secret")
        self.assertEqual(stored_meta.entry_kind, "api_key")
        self.assertEqual(stored_meta.tags, ["prod", "token"])
        self.assertEqual(stored_meta.rotation_days, 30)
        self.assertEqual(stored_meta.rotation_warn_days, 7)
        self.assertEqual(stored_meta.domains, ["example.com"])
        self.assertEqual(stored_meta.custom, {"owner": "ops"})
        self.assertEqual(stored_meta.source, "unit-test")
        self.assertEqual([item.name for item in listed], ["OPENAI_API_KEY"])

    def test_sqlite_store_delete_hides_active_projection(self) -> None:
        store = SqliteSecretStore()
        meta = EntryMetadata(
            name="OPENAI_API_KEY", service="svc", account="acct", entry_kind="api_key"
        )
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.dict(
                os.environ,
                {
                    SQLITE_PATH_ENV: str(Path(tmp) / "seckit.sqlite"),
                },
                clear=False,
            ),
            redirect_stderr(io.StringIO()),
        ):
            _init_storage_mode(path=Path(os.environ[SQLITE_PATH_ENV]))
            store.set(
                service="svc", account="acct", name="OPENAI_API_KEY", value="secret", metadata=meta
            )
            store.delete(service="svc", account="acct", name="OPENAI_API_KEY")
            self.assertFalse(store.exists(service="svc", account="acct", name="OPENAI_API_KEY"))
            self.assertEqual(store.list(service="svc", account="acct"), [])

    def test_sqlite_delete_preserves_active_projection_metadata_in_tombstone(self) -> None:
        stored_meta = EntryMetadata(
            name="OPENAI_API_KEY",
            service="svc",
            account="acct",
            entry_kind="api_key",
            tags=["prod", "token"],
            schema_id="builtin.secret.api_key",
            schema_version=7,
        )
        caller_meta = EntryMetadata(
            name="OPENAI_API_KEY",
            service="svc",
            account="acct",
            entry_kind="generic",
            tags=[],
        )
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.dict(
                os.environ,
                {
                    SQLITE_PATH_ENV: str(Path(tmp) / "seckit.sqlite"),
                },
                clear=False,
            ),
            redirect_stderr(io.StringIO()),
        ):
            _init_storage_mode(path=Path(os.environ[SQLITE_PATH_ENV]))
            set_sqlite_secret(
                service="svc",
                account="acct",
                name="OPENAI_API_KEY",
                value="secret",
                metadata=stored_meta,
            )
            delete_sqlite_secret(
                service="svc",
                account="acct",
                name="OPENAI_API_KEY",
                metadata=caller_meta,
            )
            conn = open_sqlite_backend()
            try:
                delete_row = conn.execute(
                    """
                    SELECT transaction_id
                    FROM transactions
                    WHERE transaction_type = 'secret.delete'
                    ORDER BY rowid DESC
                    LIMIT 1
                    """
                ).fetchone()
                self.assertIsNotNone(delete_row)
                tx = get_transaction(conn=conn, transaction_id=delete_row["transaction_id"])
                kind_row = conn.execute(
                    """
                    SELECT ek.name AS entry_kind, s.schema_id, s.schema_version
                    FROM secrets s
                    JOIN entry_kinds ek ON ek.entry_kind_id = s.entry_kind_id
                    WHERE s.state = 'deleted'
                    """
                ).fetchone()
            finally:
                conn.close()

        self.assertEqual(tx.payload["entry_kind"], "api_key")
        self.assertEqual(tx.payload["tags"], ["prod", "token"])
        self.assertEqual(tx.payload["schema_id"], API_KEY_SCHEMA_ID)
        self.assertEqual(tx.payload["schema_version"], 7)
        self.assertEqual(kind_row["entry_kind"], "api_key")
        self.assertEqual(kind_row["schema_id"], API_KEY_SCHEMA_ID)
        self.assertEqual(kind_row["schema_version"], 7)

    def test_failed_projection_apply_rolls_back_transaction_insert(self) -> None:
        meta = EntryMetadata(
            name="OPENAI_API_KEY", service="svc", account="acct", entry_kind="api_key"
        )
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.dict(
                os.environ,
                {
                    SQLITE_PATH_ENV: str(Path(tmp) / "seckit.sqlite"),
                },
                clear=False,
            ),
            mock.patch(
                "secrets_kit.backends.sqlite.transaction_engine.apply_transaction",
                side_effect=SQLiteValidationError("boom"),
            ),
            redirect_stderr(io.StringIO()),
        ):
            _init_storage_mode(path=Path(os.environ[SQLITE_PATH_ENV]))
            with self.assertRaisesRegex(Exception, "boom"):
                set_sqlite_secret(
                    service="svc",
                    account="acct",
                    name="OPENAI_API_KEY",
                    value="secret",
                    metadata=meta,
                )
            conn = open_sqlite_backend()
            try:
                count = conn.execute("SELECT count(*) AS n FROM transactions").fetchone()["n"]
            finally:
                conn.close()
        self.assertEqual(count, 0)

    def test_successful_projection_marks_transactions_applied(self) -> None:
        meta = EntryMetadata(
            name="OPENAI_API_KEY", service="svc", account="acct", entry_kind="api_key"
        )
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.dict(
                os.environ,
                {SQLITE_PATH_ENV: str(Path(tmp) / "seckit.sqlite")},
                clear=False,
            ),
            redirect_stderr(io.StringIO()),
        ):
            _init_storage_mode(path=Path(os.environ[SQLITE_PATH_ENV]))
            set_sqlite_secret(
                service="svc",
                account="acct",
                name="OPENAI_API_KEY",
                value="secret",
                metadata=meta,
            )
            conn = open_sqlite_backend()
            try:
                rows = conn.execute(
                    "SELECT state, applied_at FROM transactions ORDER BY rowid"
                ).fetchall()
            finally:
                conn.close()

        self.assertEqual(len(rows), 3)
        self.assertTrue(all(row["state"] == "applied" for row in rows))
        self.assertTrue(all(row["applied_at"] for row in rows))

    def test_failed_applied_transition_rolls_back_projection_and_transactions(self) -> None:
        meta = EntryMetadata(
            name="OPENAI_API_KEY", service="svc", account="acct", entry_kind="api_key"
        )
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.dict(
                os.environ,
                {SQLITE_PATH_ENV: str(Path(tmp) / "seckit.sqlite")},
                clear=False,
            ),
            mock.patch(
                "secrets_kit.backends.sqlite.transaction_engine.mark_transaction_applied",
                side_effect=SQLiteValidationError("lifecycle transition failed"),
            ),
            redirect_stderr(io.StringIO()),
        ):
            _init_storage_mode(path=Path(os.environ[SQLITE_PATH_ENV]))
            with self.assertRaisesRegex(Exception, "lifecycle transition failed"):
                set_sqlite_secret(
                    service="svc",
                    account="acct",
                    name="OPENAI_API_KEY",
                    value="secret",
                    metadata=meta,
                )
            conn = open_sqlite_backend()
            try:
                transaction_count = conn.execute(
                    "SELECT count(*) AS n FROM transactions"
                ).fetchone()["n"]
                projection_count = conn.execute(
                    "SELECT count(*) AS n FROM secrets"
                ).fetchone()["n"]
            finally:
                conn.close()

        self.assertEqual(transaction_count, 0)
        self.assertEqual(projection_count, 0)

    def test_get_does_not_rebuild_missing_projection(self) -> None:
        get_args = argparse.Namespace(
            name="OPENAI_API_KEY",
            raw=True,
            service="svc",
            account="acct",
            keychain=None,
            backend="sqlite",
        )
        err = io.StringIO()
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.object(Path, "home", return_value=Path(tmp)),
            mock.patch.dict(
                os.environ, {SQLITE_PATH_ENV: str(Path(tmp) / "seckit.sqlite")}, clear=False
            ),
            redirect_stderr(err),
        ):
            _init_storage_mode(path=Path(os.environ[SQLITE_PATH_ENV]))
            conn = open_sqlite_backend()
            try:
                conn.execute(
                    "INSERT INTO peer_groups (peer_group_id) VALUES (?)",
                    (RECORDED_ONLY_PEER_GROUP_ID,),
                )
                conn.execute(
                    "INSERT INTO nodes (node_id, peer_group_id) VALUES (?, ?)",
                    (RECORDED_ONLY_NODE_ID, RECORDED_ONLY_PEER_GROUP_ID),
                )
                tx = create_transaction(
                    transaction_id=RECORDED_ONLY_TXN_ID,
                    transaction_type="secret.set",
                    origin_node_id=RECORDED_ONLY_NODE_ID,
                    created_at=now_utc_iso(),
                    payload={
                        "secret_id": MISSING_SECRET_ID,
                        "owner_id": MISSING_OWNER_ID,
                        "service_group_id": MISSING_SERVICE_GROUP_ID,
                        "entry_type": "secret",
                        "entry_kind": "api_key",
                        "locator_hash_b64": "bG9jYXRvcg==",
                        "encrypted_name_b64": "T1BFTkFJX0FQSV9LRVk=",
                        "encrypted_payload_b64": "c2VjcmV0",
                        "content_hash_b64": "Y29udGVudA==",
                    },
                )
                insert_transaction(conn=conn, transaction=tx)
            finally:
                conn.close()
            code = cmd_get(args=get_args)

        self.assertEqual(code, 1)
        self.assertIn("entry not found", err.getvalue())

    def test_public_cli_sqlite_acceptance_workflow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["PYTHONPATH"] = "src"
            env["HOME"] = tmp
            env.pop(SQLITE_PATH_ENV, None)
            env["SECKIT_DAEMON_RUNTIME_DIR"] = str(
                Path(tmp) / ".local" / "share" / "seckit" / "runtime"
            )
            env.pop("OPENAI_API_KEY", None)
            env.pop("ANTHROPIC_API_KEY", None)
            env.pop("IMPORTED_TOKEN", None)

            def run_cli(*argv: str) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    [sys.executable, "-m", "secrets_kit.cli", *argv],
                    cwd=Path(__file__).resolve().parents[1],
                    env=env,
                    text=True,
                    capture_output=True,
                    check=False,
                )

            def assert_success(
                process: subprocess.CompletedProcess[str], *, stdout_contains: str
            ) -> None:
                self.assertEqual(process.returncode, 0, process.stderr)
                self.assertIn(stdout_contains, process.stdout)
                self.assertEqual(process.stderr, "")

            try:
                init_proc = run_cli("init", "--yes")
                assert_success(init_proc, stdout_contains="initialized sqlite backend")
                registry = Path(tmp) / ".config" / "seckit" / "registry.json"
                database = Path(tmp) / ".config" / "seckit" / "seckit.sqlite"
                self.assertTrue(registry.is_file())
                self.assertTrue(database.is_file())
                registry_bytes = registry.read_bytes()
                registry_mtime_ns = registry.stat().st_mtime_ns

                for name, value in (
                    ("OPENAI_API_KEY", "dummy-openai"),
                    ("ANTHROPIC_API_KEY", "dummy-anthropic"),
                ):
                    set_proc = run_cli(
                        "set",
                        "--service",
                        "ai",
                        "--account",
                        "local",
                        "--backend",
                        "sqlite",
                        "--name",
                        name,
                        "--value",
                        value,
                    )
                    assert_success(set_proc, stdout_contains=f"stored: name={name}")

                get_proc = run_cli(
                    "get",
                    "--service",
                    "ai",
                    "--account",
                    "local",
                    "--backend",
                    "sqlite",
                    "--name",
                    "OPENAI_API_KEY",
                    "--raw",
                )
                self.assertEqual(get_proc.returncode, 0, get_proc.stderr)
                self.assertEqual(get_proc.stdout, "dummy-openai\n")
                self.assertEqual(get_proc.stderr, "")

                list_proc = run_cli(
                    "list",
                    "--service",
                    "ai",
                    "--account",
                    "local",
                    "--backend",
                    "sqlite",
                )
                assert_success(list_proc, stdout_contains="OPENAI_API_KEY")
                self.assertIn("OPENAI_API_KEY", list_proc.stdout)
                self.assertIn("ANTHROPIC_API_KEY", list_proc.stdout)
                self.assertNotIn("dummy-openai", list_proc.stdout)
                self.assertNotIn("dummy-anthropic", list_proc.stdout)

                explain_proc = run_cli(
                    "explain",
                    "--service",
                    "ai",
                    "--account",
                    "local",
                    "--backend",
                    "sqlite",
                    "--name",
                    "OPENAI_API_KEY",
                )
                assert_success(explain_proc, stdout_contains='"name": "OPENAI_API_KEY"')
                self.assertIn('"name": "OPENAI_API_KEY"', explain_proc.stdout)
                self.assertNotIn("dummy-openai", explain_proc.stdout)

                export_proc = run_cli(
                    "export",
                    "--service",
                    "ai",
                    "--account",
                    "local",
                    "--backend",
                    "sqlite",
                    "--all",
                    "--format",
                    "shell",
                )
                assert_success(export_proc, stdout_contains="export OPENAI_API_KEY=dummy-openai")
                self.assertIn("export ANTHROPIC_API_KEY=dummy-anthropic", export_proc.stdout)
                self.assertNotIn("IMPORTED_TOKEN", export_proc.stdout)

                child = Path(tmp) / "assert_run_environment.py"
                child.write_text(
                    "\n".join(
                        (
                            "import os",
                            "import sys",
                            'assert os.environ["OPENAI_API_KEY"] == "dummy-openai"',
                            'assert os.environ["ANTHROPIC_API_KEY"] == "dummy-anthropic"',
                            'assert "dummy-openai" not in sys.argv',
                            'assert "dummy-anthropic" not in sys.argv',
                            'print("run-ok")',
                        )
                    ),
                    encoding="utf-8",
                )
                run_proc = run_cli(
                    "run",
                    "--service",
                    "ai",
                    "--account",
                    "local",
                    "--backend",
                    "sqlite",
                    "--names",
                    "OPENAI_API_KEY,ANTHROPIC_API_KEY",
                    "--",
                    sys.executable,
                    str(child),
                )
                self.assertEqual(run_proc.returncode, 0, run_proc.stderr)
                self.assertEqual(run_proc.stdout, "run-ok\n")
                self.assertEqual(run_proc.stderr, "")
                run_command = " ".join(str(part) for part in run_proc.args)
                self.assertNotIn("dummy-openai", run_command)
                self.assertNotIn("dummy-anthropic", run_command)

                dotenv = Path(tmp) / "import.env"
                dotenv.write_text("IMPORTED_TOKEN=dummy-imported\n", encoding="utf-8")
                import_proc = run_cli(
                    "import",
                    "env",
                    "--service",
                    "ai",
                    "--account",
                    "local",
                    "--backend",
                    "sqlite",
                    "--dotenv",
                    str(dotenv),
                    "--type",
                    "secret",
                    "--kind",
                    "generic",
                    "--yes",
                )
                assert_success(import_proc, stdout_contains='"created": 1')

                delete_proc = run_cli(
                    "delete",
                    "--service",
                    "ai",
                    "--account",
                    "local",
                    "--backend",
                    "sqlite",
                    "--name",
                    "OPENAI_API_KEY",
                    "--yes",
                )
                assert_success(delete_proc, stdout_contains="deleted: name=OPENAI_API_KEY")

                doctor_proc = run_cli("doctor", "--backend", "sqlite")
                assert_success(doctor_proc, stdout_contains='"sqlite_roundtrip": true')

                transaction_proc = run_cli("transaction", "list")
                assert_success(transaction_proc, stdout_contains="TRANSACTION_ID")
                self.assertIn("secret.set", transaction_proc.stdout)
                self.assertIn("secret.delete", transaction_proc.stdout)

                envelope_proc = run_cli("envelope", "list")
                assert_success(envelope_proc, stdout_contains="ENVELOPE_ID")
                self.assertEqual(len(envelope_proc.stdout.strip().splitlines()), 1)

                self.assertEqual(registry.read_bytes(), registry_bytes)
                self.assertEqual(registry.stat().st_mtime_ns, registry_mtime_ns)

                with sqlite3.connect(database) as conn:
                    transaction_counts = dict(
                        conn.execute(
                            "SELECT transaction_type, count(*) FROM transactions "
                            "GROUP BY transaction_type"
                        ).fetchall()
                    )
                    secret_states = dict(
                        conn.execute("SELECT name, state FROM secrets ORDER BY name").fetchall()
                    )
                    envelope_count = conn.execute("SELECT count(*) FROM envelopes").fetchone()[0]

                self.assertEqual(
                    transaction_counts,
                    {
                        "secret.delete": 2,
                        "secret.set": 4,
                        "vocabulary.entry_kind.upsert": 4,
                        "vocabulary.entry_type.upsert": 4,
                    },
                )
                self.assertEqual(
                    secret_states,
                    {
                        "ANTHROPIC_API_KEY": "active",
                        "DOCTOR_TEST_KEY": "deleted",
                        "IMPORTED_TOKEN": "active",
                        "OPENAI_API_KEY": "deleted",
                    },
                )
                self.assertEqual(envelope_count, 0)
            finally:
                run_cli("daemon", "stop")

    def test_sqlite_direct_transfer_matches_keychain_cli_flow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            home.mkdir()
            src_db = Path(tmp) / "source.sqlite"
            dst_db = Path(tmp) / "dest.sqlite"
            source_env = {SQLITE_PATH_ENV: str(src_db)}
            dest_env = {SQLITE_PATH_ENV: str(dst_db)}
            ensure_registry_storage(home=home)

            set_args = argparse.Namespace(
                name="SECKIT_TEST_ALPHA",
                value="alpha-1",
                stdin=False,
                allow_empty=False,
                type="secret",
                kind="generic",
                tags=None,
                comment="source alpha",
                service="sync-test",
                account="local",
                source_url="",
                source_label="",
                rotation_days=None,
                rotation_warn_days=None,
                expires_at="",
                domain=None,
                domains=None,
                meta=None,
                keychain=None,
                backend="sqlite",
            )
            export_args = argparse.Namespace(
                service="sync-test",
                account="local",
                keychain=None,
                backend="sqlite",
                format="shell",
                out=None,
                password=None,
                password_stdin=False,
                names=None,
                tag=None,
                type=None,
                kind=None,
                all=True,
            )
            import_args = argparse.Namespace(
                dotenv="",
                from_env=None,
                account="local",
                service="sync-test",
                keychain=None,
                backend="sqlite",
                type="secret",
                kind="auto",
                tags=None,
                dry_run=False,
                allow_overwrite=True,
                upsert=False,
                allow_empty=False,
                yes=True,
            )
            get_args = argparse.Namespace(
                name="SECKIT_TEST_ALPHA",
                raw=True,
                service="sync-test",
                account="local",
                keychain=None,
                backend="sqlite",
            )

            with (
                mock.patch.object(Path, "home", return_value=home),
                mock.patch.dict(os.environ, source_env, clear=False),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                _init_storage_mode(path=Path(os.environ[SQLITE_PATH_ENV]))
                self.assertEqual(cmd_set(args=set_args), 0)

            shell_out = io.StringIO()
            with (
                mock.patch.object(Path, "home", return_value=home),
                mock.patch.dict(os.environ, source_env, clear=False),
                redirect_stdout(shell_out),
                redirect_stderr(io.StringIO()),
            ):
                _init_storage_mode(path=Path(os.environ[SQLITE_PATH_ENV]))
                self.assertEqual(cmd_export(args=export_args), 0)

            dotenv = Path(tmp) / "import.env"
            dotenv.write_text(shell_out.getvalue() + "\n", encoding="utf-8")
            import_args.dotenv = str(dotenv)

            with (
                mock.patch.object(Path, "home", return_value=home),
                mock.patch.dict(os.environ, dest_env, clear=False),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                _init_storage_mode(path=Path(os.environ[SQLITE_PATH_ENV]))
                self.assertEqual(cmd_import_env(args=import_args), 0)

            out = io.StringIO()
            with (
                mock.patch.object(Path, "home", return_value=home),
                mock.patch.dict(os.environ, dest_env, clear=False),
                redirect_stdout(out),
                redirect_stderr(io.StringIO()),
            ):
                _init_storage_mode(path=Path(os.environ[SQLITE_PATH_ENV]))
                self.assertEqual(cmd_get(args=get_args), 0)
            self.assertEqual(out.getvalue().strip(), "alpha-1")

            run_args = argparse.Namespace(
                service="sync-test",
                account="local",
                names="SECKIT_TEST_ALPHA",
                tag=None,
                type=None,
                kind=None,
                all=False,
                keychain=None,
                backend="sqlite",
                child_command=[
                    "--",
                    sys.executable,
                    "-c",
                    "import os; print(os.environ['SECKIT_TEST_ALPHA'])",
                ],
            )
            with (
                mock.patch.object(Path, "home", return_value=home),
                mock.patch.dict(os.environ, dest_env, clear=False),
                mock.patch(
                    "secrets_kit.cli.commands.run._exec_child", return_value=0
                ) as exec_child_mock,
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                _init_storage_mode(path=Path(os.environ[SQLITE_PATH_ENV]))
                self.assertEqual(cmd_run(args=run_args), 0)
            self.assertEqual(
                exec_child_mock.call_args.kwargs["env"]["SECKIT_TEST_ALPHA"], "alpha-1"
            )

            doctor_out = io.StringIO()
            with (
                mock.patch.object(Path, "home", return_value=home),
                mock.patch.dict(os.environ, dest_env, clear=False),
                redirect_stdout(doctor_out),
                redirect_stderr(io.StringIO()),
            ):
                _init_storage_mode(path=Path(os.environ[SQLITE_PATH_ENV]))
                self.assertEqual(
                    cmd_doctor(
                        args=argparse.Namespace(
                            keychain=None,
                            backend="sqlite",
                        )
                    ),
                    0,
                )
            self.assertIn('"sqlite_roundtrip": true', doctor_out.getvalue())


if __name__ == "__main__":
    unittest.main()
