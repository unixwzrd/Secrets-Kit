from __future__ import annotations

import sqlite3
import unittest

from secrets_kit.backends.sqlite import (
    DuplicateTransactionError,
    SQLiteBackendError,
    SQLiteValidationError,
    TransactionNotFoundError,
    bootstrap_schema,
    create_transaction,
    get_transaction,
    insert_transaction,
    transaction_exists,
)
from tests.canonical_id_helpers import tid

ORG_ID = tid("organization", "org-1")
CLIENT_ID = tid("client", "client-1")
OWNER_ID = tid("owner", "owner-1")
PEER_GROUP_ID = tid("peer_group", "peer-group-1")
NODE_ID = tid("node", "node-1")
SECRET_ID = tid("secret", "secret-1")
SECRET_ID_2 = tid("secret", "secret-2")
TXN_ID = tid("transaction", "txn-1")
TXN_ID_2 = tid("transaction", "txn-2")


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    bootstrap_schema(conn=conn)
    _seed_transaction_parents(conn=conn)
    return conn


def _seed_transaction_parents(*, conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        INSERT INTO business_organizations (
            organization_id, name, state, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (ORG_ID, "Org", "active", "2026-06-18T00:00:00Z", "2026-06-18T00:00:00Z"),
    )
    conn.execute(
        """
        INSERT INTO business_clients (
            client_id, organization_id, name, state, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            CLIENT_ID,
            ORG_ID,
            "Client",
            "active",
            "2026-06-18T00:00:00Z",
            "2026-06-18T00:00:00Z",
        ),
    )
    conn.execute(
        """
        INSERT INTO owners (owner_id, client_id, name, state, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            OWNER_ID,
            CLIENT_ID,
            "Owner",
            "active",
            "2026-06-18T00:00:00Z",
            "2026-06-18T00:00:00Z",
        ),
    )
    conn.execute(
        """
        INSERT INTO peer_groups (
            peer_group_id, owner_id, name, state, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            PEER_GROUP_ID,
            OWNER_ID,
            "Peer Group",
            "active",
            "2026-06-18T00:00:00Z",
            "2026-06-18T00:00:00Z",
        ),
    )
    conn.execute(
        """
        INSERT INTO nodes (
            node_id,
            peer_group_id,
            signing_public_key,
            signing_algorithm,
            encryption_public_key,
            encryption_algorithm,
            state,
            created_at,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            NODE_ID,
            PEER_GROUP_ID,
            b"s" * 32,
            "ed25519",
            b"e" * 32,
            "x25519",
            "active",
            "2026-06-18T00:00:00Z",
            "2026-06-18T00:00:00Z",
        ),
    )


def _transaction(*, transaction_id: str = TXN_ID):
    return create_transaction(
        transaction_id=transaction_id,
        transaction_type="secret.set",
        organization_id=ORG_ID,
        client_id=CLIENT_ID,
        owner_id=OWNER_ID,
        origin_node_id=NODE_ID,
        payload={"secret_id": SECRET_ID, "value": "token"},
        created_at="2026-06-18T00:01:00Z",
    )


class SQLiteTransactionTest(unittest.TestCase):
    def test_round_trip_transaction_persistence(self) -> None:
        conn = _connect()
        try:
            tx = _transaction()
            insert_transaction(conn=conn, transaction=tx)

            loaded = get_transaction(conn=conn, transaction_id=TXN_ID)

            self.assertEqual(loaded.transaction_id, TXN_ID)
            self.assertEqual(loaded.transaction_type, "secret.set")
            self.assertEqual(loaded.organization_id, ORG_ID)
            self.assertEqual(loaded.client_id, CLIENT_ID)
            self.assertEqual(loaded.owner_id, OWNER_ID)
            self.assertEqual(loaded.origin_node_id, NODE_ID)
            self.assertEqual(loaded.payload, {"secret_id": SECRET_ID, "value": "token"})
            self.assertEqual(loaded.payload_hash, tx.payload_hash)
            self.assertEqual(loaded.state, "pending")
        finally:
            conn.close()

    def test_schema_uses_erd_transaction_columns(self) -> None:
        conn = _connect()
        try:
            columns = {
                str(row["name"])
                for row in conn.execute("PRAGMA table_info(transactions)").fetchall()
            }

            self.assertIn("payload", columns)
            self.assertIn("organization_id", columns)
            self.assertIn("client_id", columns)
            self.assertIn("owner_id", columns)
            self.assertIn("previous_transaction_id", columns)
            self.assertNotIn("payload_json_or_blob", columns)
            self.assertNotIn("payload_encoding", columns)
            self.assertNotIn("target_peer_group_id", columns)
            self.assertNotIn("target_service_group_id", columns)
        finally:
            conn.close()

    def test_transaction_exists_returns_boolean(self) -> None:
        conn = _connect()
        try:
            self.assertFalse(transaction_exists(conn=conn, transaction_id=TXN_ID))

            insert_transaction(conn=conn, transaction=_transaction())

            self.assertTrue(transaction_exists(conn=conn, transaction_id=TXN_ID))
        finally:
            conn.close()

    def test_duplicate_transaction_id_is_rejected(self) -> None:
        conn = _connect()
        try:
            insert_transaction(conn=conn, transaction=_transaction())

            with self.assertRaises(DuplicateTransactionError):
                insert_transaction(conn=conn, transaction=_transaction())
        finally:
            conn.close()

    def test_previous_transaction_foreign_key_is_enforced(self) -> None:
        conn = _connect()
        try:
            tx = create_transaction(
                transaction_id=TXN_ID_2,
                transaction_type="secret.set",
                organization_id=ORG_ID,
                client_id=CLIENT_ID,
                owner_id=OWNER_ID,
                origin_node_id=NODE_ID,
                previous_transaction_id=tid("transaction", "missing"),
                payload={"secret_id": SECRET_ID_2, "value": "token"},
                created_at="2026-06-18T00:02:00Z",
            )

            with self.assertRaises(SQLiteBackendError):
                insert_transaction(conn=conn, transaction=tx)
        finally:
            conn.close()

    def test_invalid_payload_hash_is_rejected_before_sqlite(self) -> None:
        tx = _transaction()
        bad = tx.__class__(**{**tx.__dict__, "payload_hash": "0" * 64})

        with self.assertRaises(SQLiteValidationError):
            insert_transaction(conn=_connect(), transaction=bad)

    def test_invalid_state_is_rejected_before_sqlite(self) -> None:
        tx = _transaction()
        bad = tx.__class__(**{**tx.__dict__, "state": "recorded"})

        with self.assertRaises(SQLiteValidationError):
            insert_transaction(conn=_connect(), transaction=bad)

    def test_missing_transaction_raises(self) -> None:
        conn = _connect()
        try:
            with self.assertRaises(TransactionNotFoundError):
                get_transaction(conn=conn, transaction_id="missing")
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
