from __future__ import annotations

import sqlite3
import unittest
from unittest import mock

from secrets_kit.backends.sqlite.schema import bootstrap_schema
from secrets_kit.backends.sqlite.transaction_engine import (
    LOCAL_TRANSACTION_POLICY,
    REMOTE_TRANSACTION_POLICY,
    REPLAY_TRANSACTION_POLICY,
    TransactionSubmissionMode,
    submit_transaction,
)
from secrets_kit.backends.sqlite.transactions import create_transaction
from tests.canonical_id_helpers import tid

ORG_ID = tid("organization", "org-1")
CLIENT_ID = tid("client", "client-1")
OWNER_ID = tid("owner", "owner-1")
PEER_GROUP_ID = tid("peer_group", "peer-group-1")
NODE_ID = tid("node", "node-1")
REMOTE_NODE_ID = tid("node", "remote-node")
TX_TAG = tid("transaction", "tx-tag")


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    bootstrap_schema(conn=conn)
    return conn


def _seed_local_origin_node(*, conn: sqlite3.Connection) -> None:
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


def _tag_transaction(*, transaction_id: str = TX_TAG, origin_node_id: str = NODE_ID):
    return create_transaction(
        transaction_id=transaction_id,
        transaction_type="vocabulary.tag.upsert",
        origin_node_id=origin_node_id,
        created_at="2026-07-11T00:00:00+00:00",
        payload={"tag_id": "tag-prod", "name": "prod"},
    )


class SQLiteTransactionEngineTest(unittest.TestCase):
    def test_local_policy_persists_applies_marks_and_requests_outbound(self) -> None:
        conn = _connect()
        try:
            _seed_local_origin_node(conn=conn)
            with mock.patch(
                "secrets_kit.backends.sqlite.transaction_engine."
                "persist_outbound_envelopes_for_configured_peers"
            ) as persist_outbound:
                result = submit_transaction(
                    conn=conn,
                    transaction=_tag_transaction(),
                    policy=LOCAL_TRANSACTION_POLICY,
                )

            self.assertEqual(result.mode, TransactionSubmissionMode.LOCAL)
            self.assertTrue(result.persisted)
            self.assertTrue(result.applied)
            self.assertFalse(result.duplicate)
            self.assertTrue(result.outbound_envelopes_requested)
            persist_outbound.assert_called_once()
            tx_row = conn.execute(
                "SELECT state, applied_at FROM transactions WHERE transaction_id = ?",
                (TX_TAG,),
            ).fetchone()
            self.assertEqual(tx_row["state"], "applied")
            self.assertIsNotNone(tx_row["applied_at"])
            tag_row = conn.execute(
                "SELECT name FROM secret_tags WHERE tag_id = ?",
                ("tag-prod",),
            ).fetchone()
            self.assertEqual(tag_row["name"], "prod")
        finally:
            conn.close()

    def test_remote_policy_bootstraps_support_rows_and_ignores_duplicate(self) -> None:
        conn = _connect()
        try:
            transaction = _tag_transaction(origin_node_id=REMOTE_NODE_ID)
            with mock.patch(
                "secrets_kit.backends.sqlite.transaction_engine."
                "persist_outbound_envelopes_for_configured_peers"
            ):
                first = submit_transaction(
                    conn=conn,
                    transaction=transaction,
                    policy=REMOTE_TRANSACTION_POLICY,
                )
                second = submit_transaction(
                    conn=conn,
                    transaction=transaction,
                    policy=REMOTE_TRANSACTION_POLICY,
                )

            self.assertEqual(first.mode, TransactionSubmissionMode.REMOTE)
            self.assertTrue(first.persisted)
            self.assertTrue(first.applied)
            self.assertFalse(first.duplicate)
            self.assertFalse(second.persisted)
            self.assertFalse(second.applied)
            self.assertTrue(second.duplicate)
            self.assertEqual(
                conn.execute("SELECT count(*) FROM transactions").fetchone()[0],
                1,
            )
            self.assertIsNotNone(
                conn.execute("SELECT 1 FROM nodes WHERE node_id = ?", (REMOTE_NODE_ID,)).fetchone()
            )
        finally:
            conn.close()

    def test_replay_policy_applies_without_persisting_or_outbound(self) -> None:
        conn = _connect()
        try:
            with mock.patch(
                "secrets_kit.backends.sqlite.transaction_engine."
                "persist_outbound_envelopes_for_configured_peers"
            ) as persist_outbound:
                result = submit_transaction(
                    conn=conn,
                    transaction=_tag_transaction(),
                    policy=REPLAY_TRANSACTION_POLICY,
                )

            self.assertEqual(result.mode, TransactionSubmissionMode.REPLAY)
            self.assertFalse(result.persisted)
            self.assertTrue(result.applied)
            self.assertFalse(result.outbound_envelopes_requested)
            persist_outbound.assert_not_called()
            self.assertEqual(
                conn.execute("SELECT count(*) FROM transactions").fetchone()[0],
                0,
            )
            self.assertEqual(
                conn.execute("SELECT name FROM secret_tags WHERE tag_id = ?", ("tag-prod",)).fetchone()[
                    "name"
                ],
                "prod",
            )
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
