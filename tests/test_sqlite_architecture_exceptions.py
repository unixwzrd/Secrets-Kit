"""Tests for bounded SQLite architecture exception paths."""

from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from secrets_kit.backends.sqlite.connection import connect_sqlite, transaction
from secrets_kit.backends.sqlite.envelopes import persist_outbound_envelopes
from secrets_kit.backends.sqlite.gate import SQLITE_PATH_ENV
from secrets_kit.backends.sqlite.local_node import load_local_node_projection
from secrets_kit.backends.sqlite.node_identity import (
    SQLITE_NODE_IDENTITY_KEY_ENV,
    ensure_sqlite_node_identity,
)
from secrets_kit.backends.sqlite.schema import bootstrap_schema
from secrets_kit.backends.sqlite.secrets_api import set_sqlite_secret
from secrets_kit.backends.sqlite.taxonomy import resolve_entry_type_and_kind_ids
from secrets_kit.backends.sqlite.transactions import create_transaction, insert_transaction
from secrets_kit.identifiers import deterministic_identifier
from secrets_kit.models import EntryMetadata, now_utc_iso
from secrets_kit.taxonomy.uuid import entry_kind_id_for_name, entry_type_id_for_name
from tests.canonical_id_helpers import tid

ORG_ID = tid("organization", "architecture-org")
CLIENT_ID = tid("client", "architecture-client")
OWNER_ID = tid("owner", "architecture-owner")
PEER_GROUP_ID = tid("peer_group", "architecture-peer-group")
NODE_ID = tid("node", "architecture-node")
PEER_NODE_ID = tid("node", "architecture-peer-cache")
TXN_DELIVERY_CACHE = tid("transaction", "txn-delivery-cache")
LOCAL_STANDALONE_NODE_ID = deterministic_identifier(
    identifier_type="node",
    namespace="sqlite.bootstrap",
    name="local-standalone-cli",
)


class SQLiteArchitectureExceptionsTest(unittest.TestCase):
    def _connect(self, tmpdir: str) -> sqlite3.Connection:
        conn = connect_sqlite(path=Path(tmpdir) / "seckit.sqlite")
        bootstrap_schema(conn=conn)
        return conn

    def test_local_projection_parent_bootstrap_does_not_create_parent_transactions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "seckit.sqlite")
            metadata = EntryMetadata(
                name="API_TOKEN",
                service="svc",
                account="acct",
                entry_type="secret",
                entry_kind="api_key",
                updated_at=now_utc_iso(),
            )
            with mock.patch.dict(
                os.environ,
                {SQLITE_PATH_ENV: db_path, "SECKIT_DAEMON_PEERS": ""},
                clear=False,
            ):
                set_sqlite_secret(
                    service="svc",
                    account="acct",
                    name="API_TOKEN",
                    value="value",
                    metadata=metadata,
                )

            conn = connect_sqlite(path=db_path)
            try:
                self.assertEqual(
                    conn.execute("SELECT count(*) FROM business_organizations").fetchone()[0],
                    1,
                )
                self.assertEqual(conn.execute("SELECT count(*) FROM business_clients").fetchone()[0], 1)
                self.assertEqual(conn.execute("SELECT count(*) FROM owners").fetchone()[0], 1)
                self.assertEqual(
                    conn.execute("SELECT count(*) FROM service_groups").fetchone()[0],
                    1,
                )
                transaction_types = {
                    row["transaction_type"]
                    for row in conn.execute("SELECT transaction_type FROM transactions")
                }
                self.assertEqual(
                    transaction_types,
                    {
                        "secret.set",
                        "vocabulary.entry_kind.upsert",
                        "vocabulary.entry_type.upsert",
                    },
                )
                self.assertFalse(any(value.startswith("owner.") for value in transaction_types))
                self.assertFalse(
                    any(value.startswith("service_group.") for value in transaction_types)
                )
                transaction_rows = conn.execute(
                    """
                    SELECT organization_id, client_id, owner_id, origin_node_id
                    FROM transactions
                    """
                ).fetchall()
                self.assertTrue(transaction_rows)
                self.assertTrue(
                    all(
                        row["organization_id"] is None
                        and row["client_id"] is None
                        and row["owner_id"] is None
                        and row["origin_node_id"] == LOCAL_STANDALONE_NODE_ID
                        for row in transaction_rows
                    )
                )
                self.assertIsNotNone(
                    conn.execute(
                        "SELECT 1 FROM nodes WHERE node_id = ?",
                        (LOCAL_STANDALONE_NODE_ID,),
                    ).fetchone()
                )
            finally:
                conn.close()

    def test_envelope_node_delivery_cache_does_not_create_transactions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            conn = self._connect(tmp)
            try:
                conn.execute(
                    "INSERT OR IGNORE INTO business_organizations (organization_id, name) VALUES (?, ?)",
                    (ORG_ID, "test organization"),
                )
                conn.execute(
                    """
                    INSERT OR IGNORE INTO business_clients (client_id, organization_id, name)
                    VALUES (?, ?, ?)
                    """,
                    (CLIENT_ID, ORG_ID, "test client"),
                )
                conn.execute(
                    "INSERT OR IGNORE INTO owners (owner_id, client_id, name) VALUES (?, ?, ?)",
                    (OWNER_ID, CLIENT_ID, "test owner"),
                )
                conn.execute(
                    "INSERT OR IGNORE INTO peer_groups (peer_group_id, owner_id, name) VALUES (?, ?, ?)",
                    (PEER_GROUP_ID, OWNER_ID, "test peer group"),
                )
                identity_env = {SQLITE_NODE_IDENTITY_KEY_ENV: str(Path(tmp) / "node-identity.key")}
                with mock.patch.dict(os.environ, identity_env, clear=False):
                    ensure_sqlite_node_identity(conn=conn)
                    local_node = load_local_node_projection(conn=conn)
                    self.assertIsNotNone(local_node)
                conn.execute(
                    """
                    INSERT OR IGNORE INTO nodes (
                        node_id,
                        peer_group_id,
                        signing_public_key,
                        signing_algorithm,
                        encryption_public_key,
                        encryption_algorithm,
                        state
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        NODE_ID,
                        PEER_GROUP_ID,
                        bytes(32),
                        "ed25519",
                        bytes(32),
                        "x25519",
                        "active",
                    ),
                )
                conn.execute(
                    """
                    INSERT OR IGNORE INTO nodes (
                        node_id,
                        peer_group_id,
                        signing_public_key,
                        signing_algorithm,
                        encryption_public_key,
                        encryption_algorithm,
                        state
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        PEER_NODE_ID,
                        PEER_GROUP_ID,
                        bytes(32),
                        "ed25519",
                        bytes(32),
                        "x25519",
                        "active",
                    ),
                )
                tx = create_transaction(
                    transaction_id=TXN_DELIVERY_CACHE,
                    transaction_type="vocabulary.tag.upsert",
                    origin_node_id=local_node.node_id,
                    created_at=now_utc_iso(),
                    payload={"tag_id": "tag-delivery-cache", "name": "delivery-cache"},
                )
                peer = PEER_NODE_ID
                with mock.patch.dict(os.environ, identity_env, clear=False):
                    with transaction(conn=conn):
                        insert_transaction(conn=conn, transaction=tx)
                        before_count = conn.execute("SELECT count(*) FROM transactions").fetchone()[0]
                        before_peer_group_count = conn.execute(
                            "SELECT count(*) FROM peer_groups"
                        ).fetchone()[0]
                        persist_outbound_envelopes(conn=conn, transaction=tx, peers=[peer])
                        after_count = conn.execute("SELECT count(*) FROM transactions").fetchone()[0]

                self.assertEqual(before_count, 1)
                self.assertEqual(after_count, 1)
                self.assertEqual(conn.execute("SELECT count(*) FROM envelopes").fetchone()[0], 1)
                self.assertIsNotNone(
                    conn.execute(
                        "SELECT 1 FROM nodes WHERE node_id = ?",
                        (PEER_NODE_ID,),
                    ).fetchone()
                )
                self.assertEqual(
                    conn.execute("SELECT count(*) FROM peer_groups").fetchone()[0],
                    before_peer_group_count,
                )
            finally:
                conn.close()

    def test_vocabulary_resolution_fallback_is_projection_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            conn = self._connect(tmp)
            try:
                entry_type = "audit_custom_type"
                entry_kind = "audit_custom_kind"
                type_id, kind_id = resolve_entry_type_and_kind_ids(
                    conn=conn,
                    entry_type=entry_type,
                    entry_kind=entry_kind,
                )

                self.assertEqual(type_id, entry_type_id_for_name(name=entry_type))
                self.assertEqual(kind_id, entry_kind_id_for_name(name=entry_kind))
                self.assertIsNotNone(
                    conn.execute(
                        "SELECT 1 FROM entry_types WHERE entry_type_id = ?",
                        (type_id,),
                    ).fetchone()
                )
                self.assertIsNotNone(
                    conn.execute(
                        "SELECT 1 FROM entry_kinds WHERE entry_kind_id = ?",
                        (kind_id,),
                    ).fetchone()
                )
                self.assertEqual(conn.execute("SELECT count(*) FROM transactions").fetchone()[0], 0)
            finally:
                conn.close()


if __name__ == "__main__":
    unittest.main()
