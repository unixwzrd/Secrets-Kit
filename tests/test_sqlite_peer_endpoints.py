"""
tests.test_sqlite_peer_endpoints

Focused endpoint lifecycle projection and replay coverage.
"""

from __future__ import annotations

import argparse
import sqlite3
import unittest
from unittest import mock

from secrets_kit.backends.sqlite.exceptions import SQLiteValidationError
from secrets_kit.backends.sqlite.peer_endpoint_auth import (
    PEER_ENDPOINT_EXPIRE,
    PEER_ENDPOINT_REGISTER,
    PEER_ENDPOINT_REMOVE,
    PEER_ENDPOINT_REPLACE,
    PEER_ENDPOINT_UPDATE,
    validate_endpoint,
    verify_peer_endpoint_transaction,
)
from secrets_kit.backends.sqlite.peer_endpoint_projection import apply_peer_endpoint_transaction
from secrets_kit.backends.sqlite.peer_endpoints import (
    create_peer_endpoint_transaction,
    list_peer_endpoint_records,
    reregister_local_endpoint,
)
from secrets_kit.backends.sqlite.peer_registry import get_peer_registry_entry
from secrets_kit.backends.sqlite.replay import rebuild_secret_projections
from secrets_kit.backends.sqlite.schema import bootstrap_schema
from secrets_kit.backends.sqlite.transaction_apply import apply_transaction
from secrets_kit.backends.sqlite.transactions import insert_transaction
from secrets_kit.cli.commands.internal import cmd_internal_register_endpoint

LOCAL_NODE = "node:00000000-0000-4000-8000-000000000001"
REMOTE_NODE = "node:00000000-0000-4000-8000-000000000002"
PEER_GROUP = "pg:00000000-0000-4000-8000-000000000001"


class SQLitePeerEndpointTest(unittest.TestCase):
    def setUp(self) -> None:
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        bootstrap_schema(conn=self.conn)
        self.conn.execute("INSERT INTO peer_groups (peer_group_id) VALUES (?)", (PEER_GROUP,))
        for node_id, state in ((LOCAL_NODE, "active"), (REMOTE_NODE, "active")):
            self.conn.execute(
                """
                INSERT INTO nodes (
                    node_id, peer_group_id, signing_public_key, signing_algorithm,
                    encryption_public_key, encryption_algorithm, authorization_mode,
                    state, created_at, updated_at
                ) VALUES (?, ?, ?, 'ed25519', ?, 'x25519', 'all', ?, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')
                """,
                (node_id, PEER_GROUP, b"a" * 32, b"b" * 32, state),
            )

    def tearDown(self) -> None:
        self.conn.close()

    def test_register_update_expire_remove_lifecycle(self) -> None:
        register = create_peer_endpoint_transaction(
            transaction_type=PEER_ENDPOINT_REGISTER,
            node_id=REMOTE_NODE,
            endpoint="tcp://127.0.0.1:41001",
        )
        apply_peer_endpoint_transaction(conn=self.conn, transaction=register)
        entry = get_peer_registry_entry(conn=self.conn, node_id=REMOTE_NODE)
        self.assertIsNotNone(entry)
        assert entry is not None
        self.assertEqual(entry.endpoint, "tcp://127.0.0.1:41001")
        self.assertEqual(entry.endpoint_state, "active")

        update = create_peer_endpoint_transaction(
            transaction_type=PEER_ENDPOINT_UPDATE,
            node_id=REMOTE_NODE,
            endpoint="tcp://127.0.0.1:41002",
            previous_endpoint="tcp://127.0.0.1:41001",
        )
        apply_peer_endpoint_transaction(conn=self.conn, transaction=update)
        records = list_peer_endpoint_records(conn=self.conn, node_id=REMOTE_NODE)
        self.assertEqual([record.state for record in records], ["removed", "active"])
        self.assertEqual(records[-1].endpoint, "tcp://127.0.0.1:41002")

        expire = create_peer_endpoint_transaction(
            transaction_type=PEER_ENDPOINT_EXPIRE,
            node_id=REMOTE_NODE,
            endpoint="tcp://127.0.0.1:41002",
        )
        apply_peer_endpoint_transaction(conn=self.conn, transaction=expire)
        self.assertEqual(get_peer_registry_entry(conn=self.conn, node_id=REMOTE_NODE).endpoint_state, "expired")  # type: ignore[union-attr]

        remove = create_peer_endpoint_transaction(
            transaction_type=PEER_ENDPOINT_REMOVE,
            node_id=REMOTE_NODE,
            endpoint="tcp://127.0.0.1:41002",
        )
        apply_peer_endpoint_transaction(conn=self.conn, transaction=remove)
        self.assertEqual(get_peer_registry_entry(conn=self.conn, node_id=REMOTE_NODE).endpoint_state, "removed")  # type: ignore[union-attr]

    def test_replay_reconstructs_endpoint_projection(self) -> None:
        transaction = create_peer_endpoint_transaction(
            transaction_type=PEER_ENDPOINT_REGISTER,
            node_id=REMOTE_NODE,
            endpoint="tcp://example.test:41003",
        )
        insert_transaction(conn=self.conn, transaction=transaction)
        apply_transaction(conn=self.conn, transaction=transaction)
        self.conn.execute("DELETE FROM peer_endpoints")
        rebuild_secret_projections(conn=self.conn)
        entry = get_peer_registry_entry(conn=self.conn, node_id=REMOTE_NODE)
        self.assertIsNotNone(entry)
        assert entry is not None
        self.assertEqual(entry.endpoint, "tcp://example.test:41003")
        self.assertEqual(entry.endpoint_state, "active")

    def test_replacement_requires_previous_endpoint(self) -> None:
        with self.assertRaisesRegex(SQLiteValidationError, "previous_endpoint"):
            create_peer_endpoint_transaction(
                transaction_type=PEER_ENDPOINT_UPDATE,
                node_id=REMOTE_NODE,
                endpoint="tcp://127.0.0.1:41004",
            )

    def test_explicit_replacement_transaction_retires_previous_endpoint(self) -> None:
        register = create_peer_endpoint_transaction(
            transaction_type=PEER_ENDPOINT_REGISTER,
            node_id=REMOTE_NODE,
            endpoint="tcp://127.0.0.1:41006",
        )
        apply_peer_endpoint_transaction(conn=self.conn, transaction=register)
        replacement = create_peer_endpoint_transaction(
            transaction_type=PEER_ENDPOINT_REPLACE,
            node_id=REMOTE_NODE,
            endpoint="tcp://127.0.0.1:41007",
            previous_endpoint="tcp://127.0.0.1:41006",
        )
        apply_peer_endpoint_transaction(conn=self.conn, transaction=replacement)
        records = list_peer_endpoint_records(conn=self.conn, node_id=REMOTE_NODE)
        self.assertEqual([(record.endpoint, record.state) for record in records], [
            ("tcp://127.0.0.1:41006", "removed"),
            ("tcp://127.0.0.1:41007", "active"),
        ])

    def test_remote_endpoint_transaction_requires_admitted_origin(self) -> None:
        transaction = create_peer_endpoint_transaction(
            transaction_type=PEER_ENDPOINT_REGISTER,
            node_id=REMOTE_NODE,
            endpoint="tcp://example.test:41005",
        )
        verify_peer_endpoint_transaction(conn=self.conn, transaction=transaction)
        insert_transaction(conn=self.conn, transaction=transaction)
        apply_transaction(conn=self.conn, transaction=transaction)
        self.assertEqual(
            get_peer_registry_entry(conn=self.conn, node_id=REMOTE_NODE).endpoint,
            "tcp://example.test:41005",  # type: ignore[union-attr]
        )

    def test_reregister_replaces_existing_active_endpoint(self) -> None:
        replacement = mock.Mock()
        with (
            mock.patch(
                "secrets_kit.backends.sqlite.peer_endpoints._local_node_id",
                return_value=LOCAL_NODE,
            ),
            mock.patch(
                "secrets_kit.backends.sqlite.peer_endpoints.open_sqlite_backend",
                return_value=mock.Mock(),
            ),
            mock.patch(
                "secrets_kit.backends.sqlite.peer_endpoints.list_active_peer_endpoints",
                return_value=[(LOCAL_NODE, "tcp://127.0.0.1:41000")],
            ),
            mock.patch(
                "secrets_kit.backends.sqlite.peer_endpoints.update_local_endpoint",
                return_value=replacement,
            ) as update,
        ):
            result = reregister_local_endpoint(endpoint="tcp://127.0.0.1:41001")

        self.assertIs(result, replacement)
        update.assert_called_once_with(
            endpoint="tcp://127.0.0.1:41001",
            previous_endpoint="tcp://127.0.0.1:41000",
            expires_at=None,
            operator_comment="",
            propagate=False,
        )

    def test_internal_endpoint_registration_propagates_lifecycle_transaction(self) -> None:
        args = argparse.Namespace(endpoint="tcp://127.0.0.1:41009")
        with mock.patch(
            "secrets_kit.cli.commands.internal.reregister_local_endpoint"
        ) as reregister:
            self.assertEqual(cmd_internal_register_endpoint(args=args), 0)
        reregister.assert_called_once_with(
            endpoint="tcp://127.0.0.1:41009",
            propagate=True,
        )

    def test_endpoint_authority_keeps_future_transport_descriptors_opaque(self) -> None:
        self.assertEqual(validate_endpoint(value="quic://peer.example.invalid"), "quic://peer.example.invalid")


if __name__ == "__main__":
    unittest.main()
