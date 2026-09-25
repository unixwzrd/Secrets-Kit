"""
tests.test_sqlite_peer_nodes

Tests for SQLite remote peer-node endpoint projections.
"""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from secrets_kit.backends.sqlite.connection import connect_sqlite
from secrets_kit.backends.sqlite.peer_nodes import (
    load_peer_node_projection,
    save_peer_node_projection,
)
from secrets_kit.backends.sqlite.schema import bootstrap_schema
from secrets_kit.crypto.models import ALGORITHM_ED25519, ALGORITHM_X25519
from secrets_kit.crypto.peer_models import PeerIdentity, PeerPublicKeys
from tests.canonical_id_helpers import tid

ORG_ID = tid("organization", "peer-node-org")
CLIENT_ID = tid("client", "peer-node-client")
OWNER_ID = tid("owner", "peer-node-owner")
PEER_NODE_ID = tid("node", "peer-node")
PEER_GROUP_ID = tid("peer_group", "peer-node-routing")
SERVICE_GROUP_PRIMARY_ID = tid("service_group", "peer-node-primary")
SERVICE_GROUP_AUDIT_ID = tid("service_group", "peer-node-audit")
SERVICE_GROUP_SECONDARY_ID = tid("service_group", "peer-node-secondary")
SERVICE_GROUP_FIRST_ID = tid("service_group", "peer-node-first")
SERVICE_GROUP_REPLACEMENT_ID = tid("service_group", "peer-node-replacement")
PEER_GROUP_FIRST_ID = tid("peer_group", "peer-node-first")
PEER_GROUP_REPLACEMENT_ID = tid("peer_group", "peer-node-replacement")


class SQLitePeerNodesTest(unittest.TestCase):
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
        node_id: str = PEER_NODE_ID,
        signing_public_key: bytes = b"s" * 32,
        encryption_public_key: bytes = b"e" * 32,
    ) -> PeerIdentity:
        """
        Build deterministic remote peer public identity data.

        Peer nodes store public communication metadata only; no private key
        material or key references exist in this fixture.
        """
        return PeerIdentity(
            node_id=node_id,
            public_keys=PeerPublicKeys(
                signing_public_key=signing_public_key,
                encryption_public_key=encryption_public_key,
                signing_algorithm=ALGORITHM_ED25519,
                encryption_algorithm=ALGORITHM_X25519,
            ),
        )

    def _seed_service_groups(
        self,
        *,
        conn: sqlite3.Connection,
        service_group_ids: tuple[str, ...],
    ) -> None:
        """
        Seed parent organization/client/owner rows for service-group FKs.

        Peer-node service-group relationships are the behavior under test; the
        parent rows are ordinary taxonomy scaffolding.
        """
        conn.execute(
            "INSERT OR IGNORE INTO business_organizations (organization_id) VALUES (?)",
            (ORG_ID,),
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO business_clients (client_id, organization_id)
            VALUES (?, ?)
            """,
            (CLIENT_ID, ORG_ID),
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO owners (owner_id, client_id)
            VALUES (?, ?)
            """,
            (OWNER_ID, CLIENT_ID),
        )
        for service_group_id in service_group_ids:
            conn.execute(
                """
                INSERT OR IGNORE INTO service_groups (service_group_id, owner_id)
                VALUES (?, ?)
                """,
                (service_group_id, OWNER_ID),
            )

    def test_schema_creates_peer_node_tables_without_object_decomposition_tables(self) -> None:
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
                self.assertNotIn("peer_node_peer_groups", tables)
                self.assertIn("service_group_nodes", tables)
                self.assertNotIn("peer_nodes", tables)
                self.assertNotIn("peer_identities", tables)
                self.assertNotIn("peer_public_keys", tables)
                self.assertNotIn("peer_addresses", tables)
                self.assertNotIn("peer_group_memberships", tables)
                self.assertNotIn("peer_descriptive_metadata", tables)
            finally:
                conn.close()

    def test_save_and_load_peer_node_endpoint_projection(self) -> None:
        identity = self._identity()
        service_groups = (SERVICE_GROUP_PRIMARY_ID, SERVICE_GROUP_AUDIT_ID)
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                self._seed_service_groups(conn=conn, service_group_ids=service_groups)

                save_peer_node_projection(
                    conn=conn,
                    identity=identity,
                    peer_group_id=PEER_GROUP_ID,
                    service_address="tcp://peer.example.invalid:9443",
                    service_group_ids=service_groups,
                    operator_description="Remote operator endpoint",
                    last_seen_at="2026-06-15T00:00:00Z",
                )

                projection = load_peer_node_projection(conn=conn, node_id=identity.node_id)

                self.assertIsNotNone(projection)
                if projection is None:
                    self.fail("peer node projection should be present")
                self.assertEqual(projection.node_id, identity.node_id)
                self.assertEqual(projection.service_address, "tcp://peer.example.invalid:9443")
                self.assertEqual(
                    projection.signing_public_key,
                    identity.public_keys.signing_public_key,
                )
                self.assertEqual(projection.signing_algorithm, ALGORITHM_ED25519)
                self.assertEqual(
                    projection.encryption_public_key,
                    identity.public_keys.encryption_public_key,
                )
                self.assertEqual(projection.encryption_algorithm, ALGORITHM_X25519)
                self.assertEqual(projection.operator_description, "Remote operator endpoint")
                self.assertEqual(projection.last_seen_at, "2026-06-15T00:00:00Z")
                self.assertEqual(projection.peer_group_id, PEER_GROUP_ID)
                self.assertEqual(projection.service_group_ids, tuple(sorted(service_groups)))
            finally:
                conn.close()

    def test_peer_group_and_service_group_relationships_are_separate(self) -> None:
        identity = self._identity()
        service_groups = (SERVICE_GROUP_PRIMARY_ID, SERVICE_GROUP_SECONDARY_ID)
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                self._seed_service_groups(conn=conn, service_group_ids=service_groups)

                save_peer_node_projection(
                    conn=conn,
                    identity=identity,
                    peer_group_id=PEER_GROUP_ID,
                    service_address="tcp://peer.example.invalid:9443",
                    service_group_ids=service_groups,
                )

                peer_group_row = conn.execute(
                    """
                    SELECT peer_group_id
                    FROM nodes
                    WHERE node_id = ?
                    """,
                    (identity.node_id,),
                ).fetchone()
                service_group_rows = conn.execute(
                    """
                    SELECT service_group_id
                    FROM service_group_nodes
                    WHERE node_id = ?
                    ORDER BY service_group_id
                    """,
                    (identity.node_id,),
                ).fetchall()

                self.assertIsNotNone(peer_group_row)
                if peer_group_row is None:
                    self.fail("peer node row should be present")
                self.assertEqual(peer_group_row["peer_group_id"], PEER_GROUP_ID)
                self.assertEqual(
                    [row["service_group_id"] for row in service_group_rows],
                    sorted(service_groups),
                )
            finally:
                conn.close()

    def test_idempotent_save_replaces_endpoint_and_relationships(self) -> None:
        identity = self._identity()
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                self._seed_service_groups(
                    conn=conn,
                    service_group_ids=(SERVICE_GROUP_FIRST_ID, SERVICE_GROUP_REPLACEMENT_ID),
                )
                save_peer_node_projection(
                    conn=conn,
                    identity=identity,
                    peer_group_id=PEER_GROUP_FIRST_ID,
                    service_address="tcp://first.example.invalid:9443",
                    service_group_ids=(SERVICE_GROUP_FIRST_ID,),
                    operator_description="first",
                )
                save_peer_node_projection(
                    conn=conn,
                    identity=identity,
                    peer_group_id=PEER_GROUP_REPLACEMENT_ID,
                    service_address="tcp://replacement.example.invalid:9443",
                    service_group_ids=(SERVICE_GROUP_REPLACEMENT_ID,),
                    operator_description="replacement",
                    last_seen_at="2026-06-15T00:00:02Z",
                )

                projection = load_peer_node_projection(conn=conn, node_id=identity.node_id)
                node_count = conn.execute("SELECT count(*) FROM nodes").fetchone()[0]
                peer_group_row = conn.execute(
                    """
                    SELECT peer_group_id
                    FROM nodes
                    WHERE node_id = ?
                    """,
                    (identity.node_id,),
                ).fetchone()
                service_group_count = conn.execute(
                    """
                    SELECT count(*)
                    FROM service_group_nodes
                    WHERE node_id = ?
                    """,
                    (identity.node_id,),
                ).fetchone()[0]

                self.assertEqual(node_count, 1)
                self.assertIsNotNone(peer_group_row)
                if peer_group_row is None:
                    self.fail("peer node row should be present")
                self.assertEqual(peer_group_row["peer_group_id"], PEER_GROUP_REPLACEMENT_ID)
                self.assertEqual(service_group_count, 1)
                self.assertIsNotNone(projection)
                if projection is None:
                    self.fail("peer node projection should be present")
                self.assertEqual(
                    projection.service_address,
                    "tcp://replacement.example.invalid:9443",
                )
                self.assertEqual(projection.peer_group_id, PEER_GROUP_REPLACEMENT_ID)
                self.assertEqual(projection.service_group_ids, (SERVICE_GROUP_REPLACEMENT_ID,))
                self.assertEqual(projection.operator_description, "replacement")
            finally:
                conn.close()

    def test_save_and_load_do_not_require_peer_node_peer_groups_table(self) -> None:
        identity = self._identity()
        service_groups = (SERVICE_GROUP_PRIMARY_ID,)
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                self._seed_service_groups(conn=conn, service_group_ids=service_groups)
                conn.execute("DROP TABLE IF EXISTS peer_node_peer_groups")

                save_peer_node_projection(
                    conn=conn,
                    identity=identity,
                    peer_group_id=PEER_GROUP_ID,
                    service_address="tcp://peer.example.invalid:9443",
                    service_group_ids=service_groups,
                )
                projection = load_peer_node_projection(conn=conn, node_id=identity.node_id)

                self.assertIsNotNone(projection)
                if projection is None:
                    self.fail("peer node projection should be present")
                self.assertEqual(projection.peer_group_id, PEER_GROUP_ID)
                self.assertEqual(projection.service_group_ids, service_groups)
            finally:
                conn.close()

    def test_peer_node_projection_has_no_private_key_or_custody_columns(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                rows = conn.execute("PRAGMA table_info(nodes)").fetchall()
                columns = {str(row["name"]) for row in rows}

                self.assertNotIn("private_key", columns)
                self.assertNotIn("private_key_reference", columns)
                self.assertNotIn("encrypted_private_key_blob", columns)
                self.assertNotIn("key_custody", columns)
                self.assertNotIn("runtime_metadata_json", columns)
                self.assertNotIn("key_rotation_metadata_json", columns)
                self.assertNotIn("record_version", columns)
            finally:
                conn.close()

    def test_peer_node_algorithm_constraints_reject_invalid_values(self) -> None:
        identity = self._identity()
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                save_peer_node_projection(
                    conn=conn,
                    identity=identity,
                    peer_group_id=PEER_GROUP_ID,
                    service_address="tcp://peer.example.invalid:9443",
                )

                with self.assertRaises(sqlite3.IntegrityError):
                    conn.execute(
                        """
                        UPDATE nodes
                        SET signing_algorithm = ?
                        WHERE node_id = ?
                        """,
                        ("x25519", identity.node_id),
                    )
                with self.assertRaises(sqlite3.IntegrityError):
                    conn.execute(
                        """
                        UPDATE nodes
                        SET encryption_algorithm = ?
                        WHERE node_id = ?
                        """,
                        ("ed25519", identity.node_id),
                    )
            finally:
                conn.close()
