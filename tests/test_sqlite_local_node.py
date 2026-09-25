"""
tests.test_sqlite_local_node

Tests for SQLite local-node projections.
"""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from secrets_kit.backends.sqlite.connection import connect_sqlite
from secrets_kit.backends.sqlite.local_hierarchy import (
    local_peer_group_display_name,
    local_peer_group_id_for_node,
)
from secrets_kit.backends.sqlite.local_node import (
    load_local_node_projection,
    save_local_node_projection,
)
from secrets_kit.backends.sqlite.schema import bootstrap_schema
from secrets_kit.crypto.models import (
    ALGORITHM_ED25519,
    ALGORITHM_X25519,
    EncryptionKeypair,
    KeyMetadata,
    NodeIdentity,
    SigningKeypair,
    key_id_for_public_key,
)
from tests.canonical_id_helpers import tid

LOCAL_NODE_ID = tid("node", "local-node")
LOCAL_REPLACEMENT_NODE_ID = tid("node", "local-replacement")


class SQLiteLocalNodeTest(unittest.TestCase):
    def _connect(self, tmpdir: str) -> sqlite3.Connection:
        """
        Open a bootstrapped SQLite test connection.

        The connection uses a temporary database and does not touch the
        operator's configured SQLite path.
        """
        conn = connect_sqlite(path=Path(tmpdir) / "seckit.sqlite")
        bootstrap_schema(conn=conn)
        return conn

    def _identity(
        self,
        *,
        node_id: str = LOCAL_NODE_ID,
        signing_public_key: bytes = b"s" * 32,
        encryption_public_key: bytes = b"e" * 32,
        signing_private_key: bytes = b"S" * 32,
        encryption_private_key: bytes = b"E" * 32,
    ) -> NodeIdentity:
        """
        Build deterministic local node key material.

        Private keys intentionally differ from public keys so tests can verify
        raw private key bytes are not persisted in SQLite.
        """
        signing = SigningKeypair(
            metadata=KeyMetadata(
                key_id=key_id_for_public_key(
                    algorithm=ALGORITHM_ED25519,
                    public_key=signing_public_key,
                ),
                algorithm=ALGORITHM_ED25519,
                created_at="2026-06-15T00:00:00Z",
                active=True,
            ),
            private_key=signing_private_key,
            public_key=signing_public_key,
        )
        encryption = EncryptionKeypair(
            metadata=KeyMetadata(
                key_id=key_id_for_public_key(
                    algorithm=ALGORITHM_X25519,
                    public_key=encryption_public_key,
                ),
                algorithm=ALGORITHM_X25519,
                created_at="2026-06-15T00:00:01Z",
                active=True,
            ),
            private_key=encryption_private_key,
            public_key=encryption_public_key,
        )
        return NodeIdentity(node_id=node_id, signing=signing, encryption=encryption)

    def test_schema_creates_nodes_and_node_private_without_local_node_tables(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                tables = {
                    row["name"]
                    for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    ).fetchall()
                }

                self.assertIn("nodes", tables)
                self.assertIn("node_private", tables)
                self.assertIn("datastore_metadata", tables)
                self.assertNotIn("local_node", tables)
                self.assertNotIn("local_node_identity", tables)
                self.assertNotIn("local_node_keys", tables)
            finally:
                conn.close()

    def test_save_and_load_singleton_local_node_projection(self) -> None:
        identity = self._identity()
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                save_local_node_projection(
                    conn=conn,
                    identity=identity,
                    signing_private_key_reference="keychain:signing",
                    encryption_private_key_reference="keychain:encryption",
                )

                projection = load_local_node_projection(conn=conn)

                self.assertIsNotNone(projection)
                if projection is None:
                    self.fail("local node projection should be present")
                self.assertEqual(projection.node_id, identity.node_id)
                self.assertEqual(
                    projection.peer_group_id,
                    local_peer_group_id_for_node(node_id=identity.node_id),
                )
                self.assertEqual(projection.signing_public_key, identity.signing.public_key)
                self.assertEqual(projection.signing_private_key_reference, "keychain:signing")
                self.assertEqual(projection.encryption_public_key, identity.encryption.public_key)
                self.assertEqual(
                    projection.encryption_private_key_reference,
                    "keychain:encryption",
                )
            finally:
                conn.close()

    def test_singleton_local_node_save_replaces_existing_row(self) -> None:
        first = self._identity()
        replacement = self._identity(
            node_id=LOCAL_REPLACEMENT_NODE_ID,
            signing_public_key=b"t" * 32,
            encryption_public_key=b"f" * 32,
            signing_private_key=b"T" * 32,
            encryption_private_key=b"F" * 32,
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                save_local_node_projection(
                    conn=conn,
                    identity=first,
                    signing_private_key_reference="keychain:signing:first",
                    encryption_private_key_reference="keychain:encryption:first",
                )
                save_local_node_projection(
                    conn=conn,
                    identity=replacement,
                    signing_private_key_reference="keychain:signing:replacement",
                    encryption_private_key_reference="keychain:encryption:replacement",
                )

                projection = load_local_node_projection(conn=conn)
                row_count = conn.execute("SELECT count(*) FROM node_private").fetchone()[0]

                self.assertEqual(row_count, 1)
                self.assertIsNotNone(projection)
                if projection is None:
                    self.fail("local node projection should be present")
                self.assertEqual(projection.node_id, replacement.node_id)
                self.assertEqual(
                    projection.peer_group_id,
                    local_peer_group_id_for_node(node_id=replacement.node_id),
                )
                self.assertEqual(
                    projection.signing_private_key_reference,
                    "keychain:signing:replacement",
                )
            finally:
                conn.close()

    def test_distinct_local_nodes_get_distinct_peer_group_ids(self) -> None:
        first = self._identity()
        second = self._identity(node_id=LOCAL_REPLACEMENT_NODE_ID)
        first_peer_group_id = local_peer_group_id_for_node(node_id=first.node_id)
        second_peer_group_id = local_peer_group_id_for_node(node_id=second.node_id)

        self.assertNotEqual(first.node_id, second.node_id)
        self.assertNotEqual(first_peer_group_id, second_peer_group_id)
        self.assertEqual(
            local_peer_group_display_name(peer_group_id=first_peer_group_id),
            local_peer_group_display_name(peer_group_id=first_peer_group_id),
        )

    def test_duplicate_peer_group_display_names_are_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                first_peer_group_id = local_peer_group_id_for_node(node_id=LOCAL_NODE_ID)
                second_peer_group_id = local_peer_group_id_for_node(
                    node_id=LOCAL_REPLACEMENT_NODE_ID
                )
                conn.execute(
                    "INSERT INTO peer_groups (peer_group_id, name) VALUES (?, ?)",
                    (first_peer_group_id, "duplicate-display"),
                )
                conn.execute(
                    "INSERT INTO peer_groups (peer_group_id, name) VALUES (?, ?)",
                    (second_peer_group_id, "duplicate-display"),
                )
                rows = conn.execute(
                    "SELECT peer_group_id FROM peer_groups WHERE name = ? ORDER BY peer_group_id",
                    ("duplicate-display",),
                ).fetchall()

                self.assertEqual(
                    [str(row["peer_group_id"]) for row in rows],
                    sorted([first_peer_group_id, second_peer_group_id]),
                )
            finally:
                conn.close()

    def test_local_hierarchy_helpers_reject_malformed_ids(self) -> None:
        with self.assertRaises(ValueError):
            local_peer_group_id_for_node(node_id="not-a-node-id")
        with self.assertRaises(ValueError):
            local_peer_group_id_for_node(node_id=local_peer_group_id_for_node(node_id=LOCAL_NODE_ID))
        with self.assertRaises(ValueError):
            local_peer_group_display_name(peer_group_id=LOCAL_NODE_ID)

    def test_raw_private_key_bytes_are_not_stored(self) -> None:
        identity = self._identity()
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                save_local_node_projection(
                    conn=conn,
                    identity=identity,
                    signing_private_key_reference="keychain:signing",
                    encryption_private_key_reference="keychain:encryption",
                )

                row = conn.execute(
                    """
                    SELECT
                        nodes.signing_public_key,
                        node_private.signing_private_key_reference,
                        nodes.encryption_public_key,
                        node_private.encryption_private_key_reference
                    FROM node_private
                    INNER JOIN nodes ON nodes.node_id = node_private.node_id
                    WHERE nodes.node_id = ?
                    """,
                    (identity.node_id,),
                ).fetchone()
                stored_values = {
                    bytes(row["signing_public_key"]),
                    str(row["signing_private_key_reference"]).encode("utf-8"),
                    bytes(row["encryption_public_key"]),
                    str(row["encryption_private_key_reference"]).encode("utf-8"),
                }

                self.assertNotIn(identity.signing.private_key, stored_values)
                self.assertNotIn(identity.encryption.private_key, stored_values)
            finally:
                conn.close()

    def test_nodes_and_node_private_have_no_json_metadata_or_version_columns(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                node_columns = {
                    str(row["name"]) for row in conn.execute("PRAGMA table_info(nodes)").fetchall()
                }
                private_columns = {
                    str(row["name"])
                    for row in conn.execute("PRAGMA table_info(node_private)").fetchall()
                }

                self.assertNotIn("runtime_metadata_json", node_columns)
                self.assertNotIn("key_rotation_metadata_json", node_columns)
                self.assertNotIn("record_version", node_columns)
                self.assertNotIn("runtime_metadata_json", private_columns)
                self.assertNotIn("key_rotation_metadata_json", private_columns)
                self.assertNotIn("record_version", private_columns)
            finally:
                conn.close()


if __name__ == "__main__":
    unittest.main()
