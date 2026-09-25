"""
tests.security.test_peer_authorization

Security regressions for explicit peer synchronization authorization.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tests.canonical_id_helpers import tid

from secrets_kit.backends.sqlite.connection import connect_sqlite
from secrets_kit.backends.sqlite.exceptions import SQLiteValidationError
from secrets_kit.backends.sqlite.peer_registry import (
    is_peer_synchronization_eligible,
    require_peer_synchronization_eligible,
)
from secrets_kit.backends.sqlite.schema import bootstrap_schema

PEER_GROUP_ID = tid("peer_group", "security-peer-authorization-peer-group")
PEER_NODE_ID = tid("node", "security-peer-authorization-peer")
AUTHORIZED_SERVICE_GROUP_ID = tid("service_group", "security-peer-authorization-allowed")
DENIED_SERVICE_GROUP_ID = tid("service_group", "security-peer-authorization-denied")


class PeerAuthorizationSecurityTest(unittest.TestCase):
    def test_active_peer_with_no_authorization_mode_fails_closed_for_service_groups(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            conn = connect_sqlite(path=Path(tmp) / "seckit.sqlite")
            try:
                bootstrap_schema(conn=conn)
                _seed_active_peer(conn=conn, authorization_mode="none")
                self.assertTrue(is_peer_synchronization_eligible(conn=conn, node_id=PEER_NODE_ID))
                self.assertFalse(
                    is_peer_synchronization_eligible(
                        conn=conn,
                        node_id=PEER_NODE_ID,
                        service_group_id=AUTHORIZED_SERVICE_GROUP_ID,
                    )
                )
                with self.assertRaisesRegex(SQLiteValidationError, "no service-group"):
                    require_peer_synchronization_eligible(
                        conn=conn,
                        node_id=PEER_NODE_ID,
                        service_group_id=AUTHORIZED_SERVICE_GROUP_ID,
                    )
            finally:
                conn.close()

    def test_allow_list_authorizes_only_listed_service_groups(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            conn = connect_sqlite(path=Path(tmp) / "seckit.sqlite")
            try:
                bootstrap_schema(conn=conn)
                _seed_active_peer(conn=conn, authorization_mode="allow_list")
                conn.execute(
                    "INSERT INTO service_groups (service_group_id) VALUES (?)",
                    (AUTHORIZED_SERVICE_GROUP_ID,),
                )
                conn.execute(
                    """
                    INSERT INTO service_group_nodes (
                        service_group_id, node_id, state, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        AUTHORIZED_SERVICE_GROUP_ID,
                        PEER_NODE_ID,
                        "active",
                        "2026-07-14T00:00:00Z",
                        "2026-07-14T00:00:00Z",
                    ),
                )
                self.assertTrue(
                    is_peer_synchronization_eligible(
                        conn=conn,
                        node_id=PEER_NODE_ID,
                        service_group_id=AUTHORIZED_SERVICE_GROUP_ID,
                    )
                )
                self.assertFalse(
                    is_peer_synchronization_eligible(
                        conn=conn,
                        node_id=PEER_NODE_ID,
                        service_group_id=DENIED_SERVICE_GROUP_ID,
                    )
                )
            finally:
                conn.close()

    def test_all_authorization_is_explicit_wildcard(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            conn = connect_sqlite(path=Path(tmp) / "seckit.sqlite")
            try:
                bootstrap_schema(conn=conn)
                _seed_active_peer(conn=conn, authorization_mode="all")
                self.assertTrue(
                    is_peer_synchronization_eligible(
                        conn=conn,
                        node_id=PEER_NODE_ID,
                        service_group_id=DENIED_SERVICE_GROUP_ID,
                    )
                )
            finally:
                conn.close()


def _seed_active_peer(*, conn, authorization_mode: str) -> None:
    conn.execute(
        "INSERT INTO peer_groups (peer_group_id) VALUES (?)",
        (PEER_GROUP_ID,),
    )
    conn.execute(
        """
        INSERT INTO nodes (
            node_id,
            peer_group_id,
            signing_algorithm,
            signing_public_key,
            encryption_algorithm,
            encryption_public_key,
            authorization_mode,
            state
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            PEER_NODE_ID,
            PEER_GROUP_ID,
            "ed25519",
            bytes(32),
            "x25519",
            bytes(32),
            authorization_mode,
            "active",
        ),
    )


if __name__ == "__main__":
    unittest.main()
