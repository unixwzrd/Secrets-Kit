from __future__ import annotations

import sqlite3
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from secrets_kit.backends.sqlite import (
    bootstrap_schema,
    create_transaction,
    insert_transaction,
    inspect_transaction,
    list_transactions_for_inspection,
)
from tests.canonical_id_helpers import tid

ORG_ID = tid("organization", "org-1")
CLIENT_ID = tid("client", "client-1")
OWNER_ID = tid("owner", "owner-1")
PEER_GROUP_ID = tid("peer_group", "peer-group-1")
NODE_ID = tid("node", "node-1")
SECRET_ID = tid("secret", "secret-1")
TXN_ID = tid("transaction", "txn-1")


def _seed(conn: sqlite3.Connection) -> None:
    conn.execute(
        "INSERT INTO business_organizations (organization_id) VALUES (?)",
        (ORG_ID,),
    )
    conn.execute(
        "INSERT INTO business_clients (client_id, organization_id) VALUES (?, ?)",
        (CLIENT_ID, ORG_ID),
    )
    conn.execute(
        "INSERT INTO owners (owner_id, client_id) VALUES (?, ?)",
        (OWNER_ID, CLIENT_ID),
    )
    conn.execute(
        "INSERT INTO peer_groups (peer_group_id, owner_id) VALUES (?, ?)",
        (PEER_GROUP_ID, OWNER_ID),
    )
    conn.execute(
        """
        INSERT INTO nodes (
            node_id,
            peer_group_id,
            signing_public_key,
            signing_algorithm,
            encryption_public_key,
            encryption_algorithm
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (NODE_ID, PEER_GROUP_ID, b"s" * 32, "ed25519", b"e" * 32, "x25519"),
    )


class SQLiteTransactionInspectionTest(unittest.TestCase):
    def test_transaction_inspection_uses_erd_fields(self) -> None:
        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "seckit.sqlite"
            conn = sqlite3.connect(path)
            conn.row_factory = sqlite3.Row
            bootstrap_schema(conn=conn)
            _seed(conn)
            tx = create_transaction(
                transaction_id=TXN_ID,
                transaction_type="secret.set",
                organization_id=ORG_ID,
                client_id=CLIENT_ID,
                owner_id=OWNER_ID,
                origin_node_id=NODE_ID,
                payload={"secret_id": SECRET_ID},
                created_at="2026-06-18T00:00:00Z",
                applied_at="2026-06-18T00:01:00Z",
            )
            insert_transaction(conn=conn, transaction=tx)
            conn.commit()
            conn.close()

            inspected = inspect_transaction(path=path, transaction_id=TXN_ID)
            listed = list_transactions_for_inspection(path=path)

            self.assertEqual(inspected.transaction_id, TXN_ID)
            self.assertEqual(inspected.organization_id, ORG_ID)
            self.assertEqual(inspected.client_id, CLIENT_ID)
            self.assertEqual(inspected.owner_id, OWNER_ID)
            self.assertEqual(inspected.origin_node_id, NODE_ID)
            self.assertEqual(inspected.transaction_type, "secret.set")
            self.assertEqual(inspected.state, "pending")
            self.assertEqual(len(listed), 1)
            self.assertEqual(listed[0].transaction_id, TXN_ID)
            self.assertEqual(listed[0].received_at, "")
            self.assertEqual(listed[0].applied_at, "2026-06-18T00:01:00Z")
            self.assertEqual(listed[0].acknowledged_at, "")
            self.assertEqual(listed[0].cleared_at, "")


if __name__ == "__main__":
    unittest.main()
