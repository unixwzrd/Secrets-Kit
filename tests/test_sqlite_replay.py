"""
tests.test_sqlite_replay

Unit tests for SQLite replay and projection materialization.
"""

from __future__ import annotations

import base64
import sqlite3
import tempfile
import unittest
from pathlib import Path

from secrets_kit.backends.sqlite import (
    SQLiteValidationError,
    bootstrap_schema,
    connect_sqlite,
    create_transaction,
    insert_transaction,
    rebuild_secret_projections,
)
from secrets_kit.backends.sqlite.taxonomy import entry_kind_id_for_name, entry_type_id_for_name


def _b64(value: bytes) -> str:
    """
    Encode bytes for Phase 4 test payloads.

    Args:
        value:
            Bytes to encode.

    Returns:
        ASCII base64 text.

    Side Effects:
        None.
    """
    return base64.b64encode(value).decode("ascii")


class SQLiteReplayTest(unittest.TestCase):
    def _connect(self, tmpdir: str) -> sqlite3.Connection:
        """
        Open a bootstrapped SQLite test connection.

        Args:
            tmpdir:
                Temporary directory path.

        Returns:
            Configured SQLite connection.

        Side Effects:
            Creates a SQLite database and bootstraps schema.
        """
        conn = connect_sqlite(path=Path(tmpdir) / "seckit.sqlite")
        bootstrap_schema(conn=conn)
        return conn

    def _insert_projection_parents(self, conn: sqlite3.Connection) -> None:
        """
        Insert parent rows required by the secrets projection FKs.

        Args:
            conn:
                SQLite connection.

        Returns:
            None.

        Side Effects:
            Inserts organization, client, owner, and service-group rows.
        """
        conn.execute("INSERT INTO organization (organization_id) VALUES (?)", ("org-1",))
        conn.execute(
            "INSERT INTO clients (client_id, organization_id) VALUES (?, ?)", ("client-1", "org-1")
        )
        conn.execute(
            "INSERT INTO owners (owner_id, client_id) VALUES (?, ?)", ("owner-1", "client-1")
        )
        conn.execute(
            "INSERT INTO service_groups (service_group_id, owner_id) VALUES (?, ?)",
            ("service-group-1", "owner-1"),
        )

    def _set_payload(self, *, encrypted_payload: bytes = b"payload-1") -> dict[str, object]:
        """
        Build a minimal secret.set payload.

        Args:
            encrypted_payload:
                Placeholder encrypted payload bytes.

        Returns:
            Canonical JSON payload mapping.

        Side Effects:
            None.
        """
        return {
            "secret_id": "secret-1",
            "owner_id": "owner-1",
            "service_group_id": "service-group-1",
            "entry_type": "secret",
            "entry_kind": "api_key",
            "schema_id": "builtin.secret",
            "schema_version": 1,
            "locator_hash_b64": _b64(b"locator-1"),
            "encrypted_name_b64": _b64(b"name-1"),
            "encrypted_metadata_b64": _b64(b"metadata-1"),
            "encrypted_payload_b64": _b64(encrypted_payload),
            "content_hash_b64": _b64(b"content-1"),
            "projection_created_at": "2026-05-25T00:00:00Z",
            "projection_updated_at": "2026-05-25T00:00:00Z",
        }

    def _delete_payload(self) -> dict[str, object]:
        """
        Build a minimal secret.delete tombstone payload.

        Returns:
            Canonical JSON payload mapping.

        Side Effects:
            None.
        """
        return {
            "secret_id": "secret-1",
            "owner_id": "owner-1",
            "service_group_id": "service-group-1",
            "entry_type": "secret",
            "entry_kind": "api_key",
            "locator_hash_b64": _b64(b"locator-1"),
            "encrypted_name_b64": _b64(b"name-1"),
            "content_hash_b64": _b64(b"content-delete"),
            "projection_updated_at": "2026-05-25T00:01:00Z",
        }

    def _insert_transaction(
        self,
        conn: sqlite3.Connection,
        *,
        transaction_id: str,
        transaction_type: str,
        payload: dict[str, object],
        created_at: str = "2026-05-25T00:00:00Z",
    ) -> None:
        """
        Insert a canonical replay test transaction.

        Args:
            conn:
                SQLite connection.
            transaction_id:
                Transaction identifier.
            transaction_type:
                Transaction type.
            payload:
                Transaction payload.
            created_at:
                Creation timestamp.

        Returns:
            None.

        Side Effects:
            Inserts one transaction row.
        """
        insert_transaction(
            conn=conn,
            transaction=create_transaction(
                transaction_id=transaction_id,
                transaction_type=transaction_type,
                origin_node_id="node-1",
                created_at=created_at,
                payload=payload,
            ),
        )

    def _secret_row(self, conn: sqlite3.Connection) -> sqlite3.Row:
        """
        Return the test secret projection row.

        Args:
            conn:
                SQLite connection.

        Returns:
            SQLite row.

        Side Effects:
            Reads one projection row.
        """
        row = conn.execute("SELECT * FROM secrets WHERE secret_id = ?", ("secret-1",)).fetchone()
        self.assertIsNotNone(row)
        return row

    def test_secret_set_materializes_active_projection(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                self._insert_projection_parents(conn)
                self._insert_transaction(
                    conn,
                    transaction_id="txn-set-1",
                    transaction_type="secret.set",
                    payload=self._set_payload(),
                )

                rebuild_secret_projections(conn=conn)

                row = self._secret_row(conn)
                self.assertEqual(row["state"], "active")
                self.assertEqual(row["locator_hash"], b"locator-1")
                self.assertEqual(row["encrypted_name"], b"name-1")
                self.assertEqual(row["encrypted_metadata"], b"metadata-1")
                self.assertEqual(row["encrypted_payload"], b"payload-1")
                self.assertEqual(row["content_hash"], b"content-1")
            finally:
                conn.close()

    def test_newer_secret_set_replaces_projection(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                self._insert_projection_parents(conn)
                self._insert_transaction(
                    conn,
                    transaction_id="txn-set-1",
                    transaction_type="secret.set",
                    payload=self._set_payload(encrypted_payload=b"payload-1"),
                    created_at="2026-05-25T00:00:00Z",
                )
                self._insert_transaction(
                    conn,
                    transaction_id="txn-set-2",
                    transaction_type="secret.set",
                    payload={
                        **self._set_payload(encrypted_payload=b"payload-2"),
                        "content_hash_b64": _b64(b"content-2"),
                        "projection_created_at": "2026-05-25T00:02:00Z",
                        "projection_updated_at": "2026-05-25T00:02:00Z",
                    },
                    created_at="2026-05-25T00:02:00Z",
                )

                rebuild_secret_projections(conn=conn)

                row = self._secret_row(conn)
                self.assertEqual(row["state"], "active")
                self.assertEqual(row["encrypted_payload"], b"payload-2")
                self.assertEqual(row["content_hash"], b"content-2")
                self.assertEqual(conn.execute("SELECT count(*) FROM secrets").fetchone()[0], 1)
            finally:
                conn.close()

    def test_secret_delete_materializes_deleted_tombstone(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                self._insert_projection_parents(conn)
                self._insert_transaction(
                    conn,
                    transaction_id="txn-set-1",
                    transaction_type="secret.set",
                    payload=self._set_payload(),
                    created_at="2026-05-25T00:00:00Z",
                )
                self._insert_transaction(
                    conn,
                    transaction_id="txn-delete-1",
                    transaction_type="secret.delete",
                    payload=self._delete_payload(),
                    created_at="2026-05-25T00:01:00Z",
                )

                rebuild_secret_projections(conn=conn)

                row = self._secret_row(conn)
                self.assertEqual(row["state"], "deleted")
                self.assertEqual(row["encrypted_payload"], b"")
                self.assertEqual(row["content_hash"], b"content-delete")
                self.assertEqual(row["updated_at"], "2026-05-25T00:01:00Z")
            finally:
                conn.close()

    def test_secret_delete_does_not_require_plaintext_or_previous_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                self._insert_projection_parents(conn)
                delete_payload = self._delete_payload()
                self.assertNotIn("name", delete_payload)
                self.assertNotIn("value", delete_payload)
                self.assertNotIn("encrypted_payload_b64", delete_payload)
                self._insert_transaction(
                    conn,
                    transaction_id="txn-delete-1",
                    transaction_type="secret.delete",
                    payload=delete_payload,
                )

                rebuild_secret_projections(conn=conn)

                row = self._secret_row(conn)
                self.assertEqual(row["state"], "deleted")
                self.assertEqual(row["encrypted_payload"], b"")
            finally:
                conn.close()

    def test_invalid_base64_fails_before_projection_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                self._insert_projection_parents(conn)
                self._insert_transaction(
                    conn,
                    transaction_id="txn-set-bad",
                    transaction_type="secret.set",
                    payload={**self._set_payload(), "encrypted_payload_b64": "***not-base64***"},
                )

                with self.assertRaisesRegex(SQLiteValidationError, "encrypted_payload_b64"):
                    rebuild_secret_projections(conn=conn)

                self.assertEqual(conn.execute("SELECT count(*) FROM secrets").fetchone()[0], 0)
            finally:
                conn.close()

    def test_unsupported_transaction_type_fails_explicitly(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                self._insert_projection_parents(conn)
                self._insert_transaction(
                    conn,
                    transaction_id="txn-unknown",
                    transaction_type="secret.rename",
                    payload=self._set_payload(),
                )

                with self.assertRaisesRegex(
                    SQLiteValidationError, "unsupported replay transaction type"
                ):
                    rebuild_secret_projections(conn=conn)
            finally:
                conn.close()

    def test_rebuild_clears_stale_projection_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                self._insert_projection_parents(conn)
                conn.execute(
                    """
                    INSERT INTO secrets (
                        secret_id,
                        owner_id,
                        service_group_id,
                        entry_type_id,
                        entry_kind_id,
                        locator_hash,
                        encrypted_name,
                        encrypted_payload,
                        content_hash,
                        state,
                        created_at,
                        updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "stale-secret",
                        "owner-1",
                        "service-group-1",
                        entry_type_id_for_name(name="secret"),
                        entry_kind_id_for_name(name="api_key"),
                        b"stale-locator",
                        b"stale-name",
                        b"stale-payload",
                        b"stale-content",
                        "active",
                        "2026-05-25T00:00:00Z",
                        "2026-05-25T00:00:00Z",
                    ),
                )
                self._insert_transaction(
                    conn,
                    transaction_id="txn-set-1",
                    transaction_type="secret.set",
                    payload=self._set_payload(),
                )

                rebuild_secret_projections(conn=conn)

                self.assertIsNone(
                    conn.execute(
                        "SELECT * FROM secrets WHERE secret_id = ?", ("stale-secret",)
                    ).fetchone()
                )
                self.assertIsNotNone(
                    conn.execute(
                        "SELECT * FROM secrets WHERE secret_id = ?", ("secret-1",)
                    ).fetchone()
                )
            finally:
                conn.close()

    def test_rebuild_is_idempotent_with_same_local_transactions(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                self._insert_projection_parents(conn)
                self._insert_transaction(
                    conn,
                    transaction_id="txn-set-1",
                    transaction_type="secret.set",
                    payload=self._set_payload(),
                )

                rebuild_secret_projections(conn=conn)
                first_rows = [
                    tuple(row)
                    for row in conn.execute("SELECT * FROM secrets ORDER BY secret_id").fetchall()
                ]
                rebuild_secret_projections(conn=conn)
                second_rows = [
                    tuple(row)
                    for row in conn.execute("SELECT * FROM secrets ORDER BY secret_id").fetchall()
                ]

                self.assertEqual(first_rows, second_rows)
            finally:
                conn.close()

    def test_envelopes_do_not_affect_replay_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                self._insert_projection_parents(conn)
                self._insert_transaction(
                    conn,
                    transaction_id="txn-set-1",
                    transaction_type="secret.set",
                    payload=self._set_payload(),
                )
                conn.execute(
                    """
                    INSERT INTO envelopes (
                        envelope_id,
                        transaction_id,
                        encrypted_payload,
                        envelope_hash,
                        state
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    ("env-1", "txn-set-1", b"envelope-payload", b"envelope-hash", "pending"),
                )

                rebuild_secret_projections(conn=conn)
                row = self._secret_row(conn)

                self.assertEqual(row["encrypted_payload"], b"payload-1")
                self.assertEqual(conn.execute("SELECT count(*) FROM envelopes").fetchone()[0], 1)
            finally:
                conn.close()


if __name__ == "__main__":
    unittest.main()
