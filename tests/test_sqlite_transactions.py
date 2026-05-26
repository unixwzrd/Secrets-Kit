"""
tests.test_sqlite_transactions

Unit tests for the SQLite transaction foundation.
"""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from secrets_kit.backends.sqlite import (
    DuplicateTransactionError,
    SQLiteValidationError,
    Transaction,
    bootstrap_schema,
    canonical_json_bytes,
    connect_sqlite,
    create_transaction,
    get_transaction,
    hash_payload,
    insert_transaction,
    payload_hash_bytes_to_hex,
    payload_hash_hex_to_bytes,
    transaction_exists,
)
from secrets_kit.backends.sqlite.taxonomy import entry_kind_id_for_name, entry_type_id_for_name


class SQLiteTransactionTest(unittest.TestCase):
    def _connect(self, tmpdir: str) -> sqlite3.Connection:
        """
        Open a SQLite test connection and explicitly bootstrap schema.

        Args:
            tmpdir:
                Temporary directory path.

        Returns:
            Configured SQLite connection.

        Side Effects:
            Creates a SQLite database under the temporary directory and calls
            ``bootstrap_schema`` before persistence operations.
        """
        path = Path(tmpdir) / "seckit.sqlite"
        conn = connect_sqlite(path=path)
        bootstrap_schema(conn=conn)
        return conn

    def _transaction(self, transaction_id: str = "txn-1") -> Transaction:
        """
        Build a representative test transaction.

        Args:
            transaction_id:
                Transaction identifier.

        Returns:
            Transaction with computed payload hash.

        Side Effects:
            None.
        """
        return create_transaction(
            transaction_id=transaction_id,
            transaction_type="secret.set",
            origin_node_id="node-1",
            created_at="2026-05-25T00:00:00Z",
            payload={
                "name": "API_TOKEN",
                "metadata": {"service": "svc"},
                "value_ref": "future-encrypted-body",
            },
        )

    def test_bootstrap_creates_phase2_schema_tables_and_user_version(self) -> None:
        expected_tables = {
            "clients",
            "entry_kinds",
            "entry_types",
            "envelopes",
            "local_node_state",
            "nodes",
            "organization",
            "owners",
            "peer_groups",
            "secret_tag_assignments",
            "secret_tags",
            "secrets",
            "service_groups",
            "transactions",
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                rows = conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                ).fetchall()
                table_names = {row["name"] for row in rows}

                self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 2)
                self.assertTrue(expected_tables.issubset(table_names))
            finally:
                conn.close()

    def test_phase2_parent_chain_foreign_keys_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                with self.assertRaises(sqlite3.IntegrityError):
                    conn.execute(
                        "INSERT INTO clients (client_id, organization_id) VALUES (?, ?)",
                        ("client-missing-org", "missing-org"),
                    )

                conn.execute("INSERT INTO organization (organization_id) VALUES (?)", ("org-1",))
                conn.execute(
                    "INSERT INTO clients (client_id, organization_id) VALUES (?, ?)",
                    ("client-1", "org-1"),
                )
                conn.execute(
                    "INSERT INTO owners (owner_id, client_id) VALUES (?, ?)",
                    ("owner-1", "client-1"),
                )
                conn.execute(
                    "INSERT INTO service_groups (service_group_id, owner_id) VALUES (?, ?)",
                    ("service-group-1", "owner-1"),
                )

                type_id = entry_type_id_for_name(name="secret")
                kind_id = entry_kind_id_for_name(name="api_key")
                with self.assertRaises(sqlite3.IntegrityError):
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
                            "secret-bad-owner",
                            "missing-owner",
                            "service-group-1",
                            type_id,
                            kind_id,
                            b"locator",
                            b"name",
                            b"payload",
                            b"content",
                            "active",
                            "2026-05-25T00:00:00Z",
                            "2026-05-25T00:00:00Z",
                        ),
                    )
            finally:
                conn.close()

    def test_secrets_projection_preserves_blob_fields_and_nullable_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                conn.execute("INSERT INTO organization (organization_id) VALUES (?)", ("org-1",))
                conn.execute(
                    "INSERT INTO clients (client_id, organization_id) VALUES (?, ?)",
                    ("client-1", "org-1"),
                )
                conn.execute(
                    "INSERT INTO owners (owner_id, client_id) VALUES (?, ?)",
                    ("owner-1", "client-1"),
                )
                conn.execute(
                    "INSERT INTO service_groups (service_group_id, owner_id) VALUES (?, ?)",
                    ("service-group-1", "owner-1"),
                )
                type_id = entry_type_id_for_name(name="secret")
                kind_id = entry_kind_id_for_name(name="api_key")
                conn.execute(
                    """
                    INSERT INTO secrets (
                        secret_id,
                        owner_id,
                        service_group_id,
                        entry_type_id,
                        entry_kind_id,
                        schema_id,
                        schema_version,
                        locator_hash,
                        encrypted_name,
                        encrypted_metadata,
                        encrypted_payload,
                        content_hash,
                        state,
                        created_at,
                        updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "secret-1",
                        "owner-1",
                        "service-group-1",
                        type_id,
                        kind_id,
                        None,
                        None,
                        b"locator-hash",
                        b"encrypted-name",
                        None,
                        b"encrypted-payload",
                        b"content-hash",
                        "active",
                        "2026-05-25T00:00:00Z",
                        "2026-05-25T00:00:00Z",
                    ),
                )

                row = conn.execute(
                    "SELECT * FROM secrets WHERE secret_id = ?", ("secret-1",)
                ).fetchone()

                self.assertEqual(row["locator_hash"], b"locator-hash")
                self.assertEqual(row["encrypted_name"], b"encrypted-name")
                self.assertIsNone(row["encrypted_metadata"])
                self.assertEqual(row["encrypted_payload"], b"encrypted-payload")
                self.assertEqual(row["content_hash"], b"content-hash")
                self.assertIsNone(row["schema_id"])
                self.assertIsNone(row["schema_version"])

                with self.assertRaisesRegex(sqlite3.IntegrityError, "state"):
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
                            "secret-bad-state",
                            "owner-1",
                            "service-group-1",
                            type_id,
                            kind_id,
                            b"locator-hash",
                            b"encrypted-name",
                            b"encrypted-payload",
                            b"content-hash",
                            "pending",
                            "2026-05-25T00:00:00Z",
                            "2026-05-25T00:00:00Z",
                        ),
                    )
            finally:
                conn.close()

    def test_secrets_schema_has_no_plaintext_name_or_value_columns(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                columns = {
                    row["name"] for row in conn.execute("PRAGMA table_info(secrets)").fetchall()
                }

                self.assertNotIn("name", columns)
                self.assertNotIn("value", columns)
                self.assertIn("encrypted_name", columns)
                self.assertIn("encrypted_payload", columns)
            finally:
                conn.close()

    def test_envelopes_are_inert_reserved_schema_with_nullable_destinations(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                transaction = self._transaction()
                insert_transaction(conn=conn, transaction=transaction)

                conn.execute(
                    """
                    INSERT INTO envelopes (
                        envelope_id,
                        transaction_id,
                        destination_node_id,
                        destination_peer_group_id,
                        encrypted_payload,
                        envelope_hash,
                        state
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "envelope-1",
                        transaction.transaction_id,
                        None,
                        None,
                        b"payload",
                        b"hash",
                        "recorded",
                    ),
                )
                row = conn.execute(
                    "SELECT * FROM envelopes WHERE envelope_id = ?", ("envelope-1",)
                ).fetchone()

                self.assertIsNone(row["destination_node_id"])
                self.assertIsNone(row["destination_peer_group_id"])

                with self.assertRaises(sqlite3.IntegrityError):
                    conn.execute(
                        """
                        INSERT INTO envelopes (
                            envelope_id,
                            transaction_id,
                            destination_node_id,
                            encrypted_payload,
                            envelope_hash,
                            state
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            "envelope-bad-node",
                            transaction.transaction_id,
                            "missing-node",
                            b"payload",
                            b"hash",
                            "recorded",
                        ),
                    )

                with self.assertRaises(sqlite3.IntegrityError):
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
                        (
                            "envelope-bad-txn",
                            "missing-transaction",
                            b"payload",
                            b"hash",
                            "recorded",
                        ),
                    )

                with self.assertRaisesRegex(sqlite3.IntegrityError, "state"):
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
                        (
                            "envelope-bad-state",
                            transaction.transaction_id,
                            b"payload",
                            b"hash",
                            "active",
                        ),
                    )
            finally:
                conn.close()

    def test_canonical_json_does_not_depend_on_insertion_order(self) -> None:
        left = {"b": 2, "a": {"z": 1, "m": 2}}
        right = {"a": {"m": 2, "z": 1}, "b": 2}

        self.assertEqual(canonical_json_bytes(payload=left), canonical_json_bytes(payload=right))
        self.assertEqual(canonical_json_bytes(payload=left), b'{"a":{"m":2,"z":1},"b":2}')

    def test_hash_payload_is_stable_for_identical_payload_data(self) -> None:
        left = {"b": 2, "a": 1}
        right = {"a": 1, "b": 2}

        self.assertEqual(hash_payload(payload=left), hash_payload(payload=right))

    def test_hash_conversion_helpers_preserve_api_boundary(self) -> None:
        hash_hex = hash_payload(payload={"a": 1})
        hash_bytes = payload_hash_hex_to_bytes(hash_hex=hash_hex)

        self.assertEqual(len(hash_bytes), 32)
        self.assertEqual(payload_hash_bytes_to_hex(hash_bytes=hash_bytes), hash_hex)

    def test_connection_enables_wal_synchronous_normal_and_foreign_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                self.assertEqual(conn.execute("PRAGMA foreign_keys").fetchone()[0], 1)
                self.assertEqual(conn.execute("PRAGMA journal_mode").fetchone()[0].lower(), "wal")
                self.assertEqual(conn.execute("PRAGMA synchronous").fetchone()[0], 1)
            finally:
                conn.close()

    def test_connection_does_not_bootstrap_schema_implicitly(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = connect_sqlite(path=Path(tmpdir) / "seckit.sqlite")
            try:
                transaction = self._transaction()

                with self.assertRaisesRegex(
                    sqlite3.OperationalError, "no such table: transactions"
                ):
                    insert_transaction(conn=conn, transaction=transaction)
            finally:
                conn.close()

    def test_round_trip_transaction_persistence(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                transaction = self._transaction()
                insert_transaction(conn=conn, transaction=transaction)

                stored = get_transaction(conn=conn, transaction_id=transaction.transaction_id)

                self.assertEqual(stored, transaction)
            finally:
                conn.close()

    def test_version_routing_source_fields_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                transaction = create_transaction(
                    transaction_id="txn-routing",
                    transaction_version=2,
                    payload_version=3,
                    protocol_version=4,
                    transaction_type="secret.delete",
                    origin_node_id="node-9",
                    origin_owner_id="owner-1",
                    origin_peer_group_id="peer-group-1",
                    origin_organization_id="org-1",
                    target_peer_group_id="peer-group-2",
                    target_service_group_id="svc-group-1",
                    target_owner_id="owner-2",
                    target_object_id="object-1",
                    source_class="operator",
                    replication_policy="local-only",
                    payload_encoding="json",
                    idempotency_key="idem-1",
                    previous_transaction_id="txn-prev",
                    signature=b"future-signature",
                    created_at="2026-05-25T01:00:00Z",
                    payload={"name": "API_TOKEN"},
                )
                insert_transaction(conn=conn, transaction=transaction)

                stored = get_transaction(conn=conn, transaction_id="txn-routing")

                self.assertEqual(stored.transaction_version, 2)
                self.assertEqual(stored.payload_version, 3)
                self.assertEqual(stored.protocol_version, 4)
                self.assertEqual(stored.origin_peer_group_id, "peer-group-1")
                self.assertEqual(stored.origin_organization_id, "org-1")
                self.assertEqual(stored.target_peer_group_id, "peer-group-2")
                self.assertEqual(stored.target_service_group_id, "svc-group-1")
                self.assertEqual(stored.target_owner_id, "owner-2")
                self.assertEqual(stored.target_object_id, "object-1")
                self.assertEqual(stored.source_class, "operator")
                self.assertEqual(stored.replication_policy, "local-only")
                self.assertEqual(stored.payload_encoding, "json")
                self.assertEqual(stored.idempotency_key, "idem-1")
                self.assertEqual(stored.previous_transaction_id, "txn-prev")
                self.assertEqual(stored.signature, b"future-signature")
                self.assertIsInstance(stored.signature, bytes)
            finally:
                conn.close()

    def test_optional_routing_reference_fields_round_trip_as_null(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                transaction = self._transaction()
                insert_transaction(conn=conn, transaction=transaction)

                stored = get_transaction(conn=conn, transaction_id=transaction.transaction_id)

                self.assertIsNone(stored.origin_owner_id)
                self.assertIsNone(stored.origin_peer_group_id)
                self.assertIsNone(stored.origin_organization_id)
                self.assertIsNone(stored.target_peer_group_id)
                self.assertIsNone(stored.target_service_group_id)
                self.assertIsNone(stored.target_owner_id)
                self.assertIsNone(stored.target_object_id)
                self.assertIsNone(stored.replication_policy)
                self.assertIsNone(stored.idempotency_key)
                self.assertIsNone(stored.previous_transaction_id)
                self.assertIsNone(stored.signature)
                self.assertIsNone(stored.received_at)
                self.assertIsNone(stored.applied_at)
                self.assertIsNone(stored.acknowledged_at)
                self.assertIsNone(stored.cleared_at)
            finally:
                conn.close()

    def test_signature_round_trip_type_is_bytes_or_none(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                unsigned = self._transaction("txn-unsigned")
                signed = create_transaction(
                    transaction_id="txn-signed",
                    transaction_type="secret.set",
                    origin_node_id="node-1",
                    created_at="2026-05-25T00:00:00Z",
                    payload={"name": "API_TOKEN"},
                    signature=b"\x00signature\xff",
                )
                insert_transaction(conn=conn, transaction=unsigned)
                insert_transaction(conn=conn, transaction=signed)

                stored_unsigned = get_transaction(conn=conn, transaction_id="txn-unsigned")
                stored_signed = get_transaction(conn=conn, transaction_id="txn-signed")

                self.assertIsNone(stored_unsigned.signature)
                self.assertEqual(stored_signed.signature, b"\x00signature\xff")
                self.assertIsInstance(stored_signed.signature, bytes)
                self.assertNotIsInstance(stored_signed.signature, memoryview)
            finally:
                conn.close()

    def test_default_state_is_recorded_without_apply_timestamp(self) -> None:
        transaction = self._transaction()

        self.assertEqual(transaction.state, "recorded")
        self.assertIsNone(transaction.applied_at)
        self.assertEqual(transaction.payload_encoding, "json")

    def test_duplicate_transaction_id_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                transaction = self._transaction()
                insert_transaction(conn=conn, transaction=transaction)

                with self.assertRaises(DuplicateTransactionError):
                    insert_transaction(conn=conn, transaction=transaction)
            finally:
                conn.close()

    def test_transaction_exists_returns_boolean(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                transaction = self._transaction()

                self.assertFalse(
                    transaction_exists(conn=conn, transaction_id=transaction.transaction_id)
                )

                insert_transaction(conn=conn, transaction=transaction)

                self.assertTrue(
                    transaction_exists(conn=conn, transaction_id=transaction.transaction_id)
                )
                self.assertFalse(transaction_exists(conn=conn, transaction_id="missing"))
            finally:
                conn.close()

    def test_hash_mismatch_is_rejected(self) -> None:
        transaction = Transaction(
            transaction_id="txn-bad-hash",
            transaction_type="secret.set",
            origin_node_id="node-1",
            created_at="2026-05-25T00:00:00Z",
            payload={"name": "API_TOKEN"},
            payload_hash="0" * 64,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                with self.assertRaises(SQLiteValidationError):
                    insert_transaction(conn=conn, transaction=transaction)
            finally:
                conn.close()

    def test_unsupported_payload_encoding_is_rejected_before_sqlite(self) -> None:
        transaction = replace(self._transaction(), payload_encoding="encrypted-json")

        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                with self.assertRaisesRegex(SQLiteValidationError, "payload_encoding must be json"):
                    insert_transaction(conn=conn, transaction=transaction)
            finally:
                conn.close()

    def test_invalid_state_is_rejected_before_sqlite(self) -> None:
        transaction = replace(self._transaction(), state="pending_apply")

        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                with self.assertRaisesRegex(SQLiteValidationError, "state must be recorded"):
                    insert_transaction(conn=conn, transaction=transaction)
            finally:
                conn.close()

    def test_schema_rejects_invalid_payload_hash_length(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                with self.assertRaisesRegex(sqlite3.IntegrityError, "payload_hash"):
                    conn.execute(
                        """
                        INSERT INTO transactions (
                            transaction_id,
                            transaction_version,
                            payload_version,
                            protocol_version,
                            transaction_type,
                            origin_node_id,
                            payload_json_or_blob,
                            payload_hash,
                            state,
                            created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            "txn-short-hash",
                            1,
                            1,
                            1,
                            "secret.set",
                            "node-1",
                            b"{}",
                            b"short",
                            "recorded",
                            "now",
                        ),
                    )
            finally:
                conn.close()

    def test_schema_rejects_invalid_payload_encoding_and_state(self) -> None:
        valid_hash = payload_hash_hex_to_bytes(hash_hex=hash_payload(payload={}))
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                with self.assertRaisesRegex(sqlite3.IntegrityError, "payload_encoding"):
                    conn.execute(
                        """
                        INSERT INTO transactions (
                            transaction_id,
                            transaction_version,
                            payload_version,
                            protocol_version,
                            payload_encoding,
                            transaction_type,
                            origin_node_id,
                            payload_json_or_blob,
                            payload_hash,
                            state,
                            created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            "txn-bad-encoding",
                            1,
                            1,
                            1,
                            "encrypted-json",
                            "secret.set",
                            "node-1",
                            b"{}",
                            valid_hash,
                            "recorded",
                            "now",
                        ),
                    )

                with self.assertRaisesRegex(sqlite3.IntegrityError, "state"):
                    conn.execute(
                        """
                        INSERT INTO transactions (
                            transaction_id,
                            transaction_version,
                            payload_version,
                            protocol_version,
                            payload_encoding,
                            transaction_type,
                            origin_node_id,
                            payload_json_or_blob,
                            payload_hash,
                            state,
                            created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            "txn-bad-state",
                            1,
                            1,
                            1,
                            "json",
                            "secret.set",
                            "node-1",
                            b"{}",
                            valid_hash,
                            "pending_apply",
                            "now",
                        ),
                    )
            finally:
                conn.close()

    def test_transactions_are_append_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                transaction = self._transaction()
                insert_transaction(conn=conn, transaction=transaction)

                with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                    conn.execute(
                        "UPDATE transactions SET state = 'pending_apply' WHERE transaction_id = ?",
                        ("txn-1",),
                    )

                with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                    conn.execute("DELETE FROM transactions WHERE transaction_id = ?", ("txn-1",))
            finally:
                conn.close()


if __name__ == "__main__":
    unittest.main()
