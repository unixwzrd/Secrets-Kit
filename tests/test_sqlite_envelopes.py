"""
tests.test_sqlite_envelopes

Tests for outbound envelope persistence.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import socket
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from pathlib import Path
from unittest import mock

from secrets_kit.backends.sqlite.connection import connect_sqlite, transaction
from secrets_kit.backends.sqlite.envelopes import (
    get_persisted_envelope,
    list_persisted_envelopes,
    persist_outbound_envelopes,
)
from secrets_kit.backends.sqlite.gate import SQLITE_PATH_ENV, open_sqlite_backend
from secrets_kit.backends.sqlite.local_node import load_local_node_projection
from secrets_kit.backends.sqlite.node_identity import (
    SQLITE_NODE_IDENTITY_KEY_ENV,
    ensure_sqlite_node_identity,
)
from secrets_kit.backends.sqlite.schema import bootstrap_schema
from secrets_kit.backends.sqlite.secrets_api import set_sqlite_secret
from secrets_kit.backends.sqlite.transactions import create_transaction, insert_transaction
from secrets_kit.cli.commands.envelope import cmd_envelope_list, cmd_envelope_show
from secrets_kit.daemon.client import TCP_HOST
from secrets_kit.models import EntryMetadata
from secrets_kit.protocol.envelope import canonical_envelope_bytes, parse_envelope_bytes
from secrets_kit.protocol.payload_codec import (
    decode_envelope_payload,
    plaintext_envelope_payload_codec,
)
from secrets_kit.runtime.outbound_delivery import (
    CLAIM_LEASE_SECONDS,
    MAX_DELIVERY_ATTEMPTS,
    _queue_endpoint_prerequisites,
    next_outbound_attempt_at,
    process_pending_outbound_envelopes,
    resume_peer_delivery,
)
from tests.canonical_id_helpers import tid

ORG_ID = tid("organization", "envelope-org")
CLIENT_ID = tid("client", "envelope-client")
OWNER_ID = tid("owner", "envelope-owner")
PEER_GROUP_ID = tid("peer_group", "envelope-peer-group")
LOCAL_NODE_ID = tid("node", "envelope-local-node")
PEER_NODE_ID_1 = tid("node", "envelope-peer-1")
PEER_NODE_ID_2 = tid("node", "envelope-peer-2")
TXN_ID = tid("transaction", "txn-1")


def _free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((TCP_HOST, 0))
        return int(sock.getsockname()[1])


class SQLiteEnvelopeTest(unittest.TestCase):
    def setUp(self) -> None:
        # Queue/transaction fixtures use placeholder public keys, not real peers.
        # Keep their plaintext codec explicit; encrypted delivery is tested separately.
        patcher = mock.patch.dict("os.environ", {"SECKIT_ENVELOPE_PAYLOAD_CODEC": "plaintext", "SECKIT_UNSAFE_PLAINTEXT_ENVELOPES": "1"})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_missing_endpoint_prerequisite_is_queued_once_for_selected_peer(self) -> None:
        from secrets_kit.backends.sqlite.peer_endpoints import create_peer_endpoint_transaction

        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            self.addCleanup(conn.close)
            first = replace(create_peer_endpoint_transaction(
                transaction_type="peer.endpoint.register", node_id=self.local_node_id,
                endpoint="tcp://127.0.0.1:41001",
            ), state="applied", applied_at="2026-09-05T00:00:00+00:00")
            update = replace(create_peer_endpoint_transaction(
                transaction_type="peer.endpoint.update", node_id=self.local_node_id,
                endpoint="tcp://127.0.0.1:41002", previous_endpoint="tcp://127.0.0.1:41001",
            ), state="applied")
            receiver = sqlite3.connect(":memory:", isolation_level=None)
            receiver.row_factory = sqlite3.Row
            self.addCleanup(receiver.close)
            conn.backup(receiver)
            with transaction(conn=conn):
                insert_transaction(conn=conn, transaction=first)
                insert_transaction(conn=conn, transaction=update)
            _queue_endpoint_prerequisites(conn=conn, selected_peer_ids=None)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM envelopes").fetchone()[0], 0)
            with transaction(conn=conn):
                persist_outbound_envelopes(conn=conn, transaction=replace(update, state="pending"), peers=[PEER_NODE_ID_1])
            before = [tuple(r) for r in conn.execute("SELECT * FROM transactions ORDER BY rowid")]
            _queue_endpoint_prerequisites(conn=conn, selected_peer_ids={PEER_NODE_ID_2})
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM envelopes").fetchone()[0], 1)
            _queue_endpoint_prerequisites(conn=conn, selected_peer_ids=None)
            after = [tuple(r) for r in conn.execute("SELECT * FROM envelopes ORDER BY rowid")]
            self.assertEqual(len(after), 2)
            _queue_endpoint_prerequisites(conn=conn, selected_peer_ids=None)
            self.assertEqual(after, [tuple(r) for r in conn.execute("SELECT * FROM envelopes ORDER BY rowid")])
            self.assertEqual(before, [tuple(r) for r in conn.execute("SELECT * FROM transactions ORDER BY rowid")])
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM peer_endpoints").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM envelopes WHERE destination_node_id = ?", (PEER_NODE_ID_2,)).fetchone()[0], 0)
            from secrets_kit.backends.sqlite.transaction_engine import (
                REMOTE_TRANSACTION_POLICY,
                submit_transaction,
            )
            from secrets_kit.runtime.inbound_envelopes import transaction_from_envelope_payload
            # Exercise the real receiver submission lifecycle, not projection alone.
            for original in (first, update):
                row = conn.execute("SELECT encrypted_payload FROM envelopes WHERE transaction_id = ?", (original.transaction_id,)).fetchone()
                envelope = json.loads(bytes(row[0]))
                received = transaction_from_envelope_payload(payload=json.loads(
                    decode_envelope_payload(payload=envelope["payload"])
                ))
                self.assertEqual(received.state, "pending")
                for field in ("received_at", "applied_at", "acknowledged_at", "cleared_at"):
                    self.assertIsNone(getattr(received, field))
                self.assertEqual(received.payload_hash, original.payload_hash)
                self.assertEqual(received.payload, original.payload)
                with transaction(conn=receiver):
                    result = submit_transaction(conn=receiver, transaction=received, policy=REMOTE_TRANSACTION_POLICY)
                self.assertTrue(result.applied)
                with transaction(conn=receiver):
                    repeated = submit_transaction(conn=receiver, transaction=received, policy=REMOTE_TRANSACTION_POLICY)
                self.assertTrue(repeated.duplicate)
            self.assertEqual(receiver.execute("SELECT endpoint FROM peer_endpoints WHERE state = 'active'").fetchone()[0], "tcp://127.0.0.1:41002")
            from secrets_kit.backends.sqlite.exceptions import SQLiteValidationError
            from secrets_kit.backends.sqlite.peer_endpoint_projection import (
                apply_peer_endpoint_transaction,
            )
            with self.assertRaises(SQLiteValidationError):
                with transaction(conn=conn):
                    apply_peer_endpoint_transaction(conn=conn, transaction=update)
            with transaction(conn=conn):
                apply_peer_endpoint_transaction(conn=conn, transaction=first)
                apply_peer_endpoint_transaction(conn=conn, transaction=update)
            self.assertEqual(conn.execute("SELECT endpoint FROM peer_endpoints WHERE state = 'active'").fetchone()[0], "tcp://127.0.0.1:41002")

    def test_endpoint_prerequisite_missing_or_unauthorized_fails_closed(self) -> None:
        from secrets_kit.backends.sqlite.peer_endpoints import create_peer_endpoint_transaction

        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            self.addCleanup(conn.close)
            update = replace(create_peer_endpoint_transaction(
                transaction_type="peer.endpoint.update", node_id=self.local_node_id,
                endpoint="tcp://127.0.0.1:41002", previous_endpoint="tcp://127.0.0.1:41001",
            ), state="applied")
            with transaction(conn=conn):
                insert_transaction(conn=conn, transaction=update)
                persist_outbound_envelopes(conn=conn, transaction=update, peers=[PEER_NODE_ID_1])
            original = [tuple(r) for r in conn.execute("SELECT * FROM envelopes")]
            with self.assertLogs("secrets_kit.runtime.outbound_delivery", level="WARNING"):
                _queue_endpoint_prerequisites(conn=conn, selected_peer_ids=None)
            self.assertEqual(original, [tuple(r) for r in conn.execute("SELECT * FROM envelopes")])
            with mock.patch("secrets_kit.runtime.outbound_delivery.is_peer_synchronization_eligible", return_value=False), mock.patch("secrets_kit.runtime.outbound_delivery.persist_outbound_envelopes") as persist:
                _queue_endpoint_prerequisites(conn=conn, selected_peer_ids=None)
                persist.assert_not_called()

    def _connect(self, tmpdir: str) -> sqlite3.Connection:
        old_identity_key_path = os.environ.get(SQLITE_NODE_IDENTITY_KEY_ENV)
        os.environ[SQLITE_NODE_IDENTITY_KEY_ENV] = str(Path(tmpdir) / "node-identity.key")
        self.addCleanup(self._restore_identity_key_env, old_identity_key_path)
        conn = connect_sqlite(path=Path(tmpdir) / "seckit.sqlite")
        bootstrap_schema(conn=conn)
        ensure_sqlite_node_identity(conn=conn)
        projection = load_local_node_projection(conn=conn)
        assert projection is not None
        self.local_node_id = projection.node_id
        self._seed_transaction_parents(conn=conn)
        return conn

    def _restore_identity_key_env(self, value: str | None) -> None:
        if value is None:
            os.environ.pop(SQLITE_NODE_IDENTITY_KEY_ENV, None)
        else:
            os.environ[SQLITE_NODE_IDENTITY_KEY_ENV] = value

    def _seed_transaction_parents(self, *, conn: sqlite3.Connection) -> None:
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
                self.local_node_id,
                PEER_GROUP_ID,
                bytes(32),
                "ed25519",
                bytes(32),
                "x25519",
                "active",
            ),
        )
        for peer_node_id in (PEER_NODE_ID_1, PEER_NODE_ID_2):
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
                    peer_node_id,
                    PEER_GROUP_ID,
                    bytes(32),
                    "ed25519",
                    bytes(32),
                    "x25519",
                    "active",
                ),
            )

    def _transaction(self, *, transaction_id: str = TXN_ID):
        return create_transaction(
            transaction_id=transaction_id,
            transaction_type="vocabulary.tag.upsert",
            origin_node_id=self.local_node_id,
            created_at="2026-06-05T00:00:00+00:00",
            payload={"tag_id": "tag-1", "name": "prod"},
        )

    def _peers(self) -> list[str]:
        return [PEER_NODE_ID_1, PEER_NODE_ID_2]

    def test_one_transaction_creates_one_envelope_per_peer(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                tx = self._transaction()
                with transaction(conn=conn):
                    insert_transaction(conn=conn, transaction=tx)
                    persist_outbound_envelopes(conn=conn, transaction=tx, peers=self._peers())

                rows = conn.execute(
                    """
                    SELECT transaction_id, destination_node_id, state, sent_at, encrypted_payload
                    FROM envelopes
                    ORDER BY destination_node_id
                    """
                ).fetchall()
                self.assertEqual(len(rows), 2)
                self.assertEqual([row["transaction_id"] for row in rows], [TXN_ID, TXN_ID])
                self.assertEqual(
                    [row["destination_node_id"] for row in rows],
                    sorted([PEER_NODE_ID_1, PEER_NODE_ID_2]),
                )
                self.assertEqual([row["state"] for row in rows], ["pending", "pending"])
                self.assertEqual([row["sent_at"] for row in rows], [None, None])
                payload = json.loads(rows[0]["encrypted_payload"].decode("utf-8"))
                self.assertEqual(payload["message_type"], "transaction")
                self.assertEqual(payload["envelope_id"], payload["message_id"])
                self.assertEqual(payload["source_node_id"], self.local_node_id)
                self.assertEqual(payload["destination_node_id"], rows[0]["destination_node_id"])
                decoded_payload = json.loads(
                    decode_envelope_payload(payload=payload["payload"]).decode("utf-8")
                )
                self.assertEqual(decoded_payload["transaction_id"], TXN_ID)
            finally:
                conn.close()

    def test_persisted_envelope_reconstructs_identical_protocol_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                tx = self._transaction()
                with transaction(conn=conn):
                    insert_transaction(conn=conn, transaction=tx)
                    persist_outbound_envelopes(conn=conn, transaction=tx, peers=[self._peers()[0]])

                row = conn.execute("SELECT encrypted_payload FROM envelopes").fetchone()
                stored_bytes = bytes(row["encrypted_payload"])
                reconstructed = parse_envelope_bytes(data=stored_bytes)
                self.assertEqual(canonical_envelope_bytes(envelope=reconstructed), stored_bytes)
            finally:
                conn.close()

    def test_outbound_persistence_invokes_payload_codec(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                tx = self._transaction()
                with mock.patch(
                    "secrets_kit.backends.sqlite.envelopes.plaintext_envelope_payload_codec",
                    wraps=plaintext_envelope_payload_codec,
                ) as codec_factory:
                    with transaction(conn=conn):
                        insert_transaction(conn=conn, transaction=tx)
                        persist_outbound_envelopes(
                            conn=conn,
                            transaction=tx,
                            peers=[self._peers()[0]],
                        )
                self.assertGreaterEqual(codec_factory.call_count, 1)
            finally:
                conn.close()

    def test_local_retry_metadata_does_not_change_protocol_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                tx = self._transaction()
                with transaction(conn=conn):
                    insert_transaction(conn=conn, transaction=tx)
                    persist_outbound_envelopes(conn=conn, transaction=tx, peers=[self._peers()[0]])

                before = bytes(conn.execute("SELECT encrypted_payload FROM envelopes").fetchone()[0])
                conn.execute(
                    """
                    UPDATE envelopes
                    SET attempt_count = ?, claimed_at = ?, next_attempt_at = ?, last_error = ?
                    """,
                    (
                        7,
                        "2026-07-12T00:02:00Z",
                        "2026-07-12T00:03:00Z",
                        "connection refused",
                    ),
                )
                after = bytes(conn.execute("SELECT encrypted_payload FROM envelopes").fetchone()[0])
                self.assertEqual(after, before)
                self.assertEqual(
                    canonical_envelope_bytes(envelope=parse_envelope_bytes(data=after)),
                    before,
                )
            finally:
                conn.close()

    def test_failed_network_delivery_does_not_remove_envelope_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                tx = self._transaction()
                with transaction(conn=conn):
                    insert_transaction(conn=conn, transaction=tx)
                    persist_outbound_envelopes(
                        conn=conn,
                        transaction=tx,
                        peers=[PEER_NODE_ID_1],
                    )

                sent = process_pending_outbound_envelopes(
                    conn=conn,
                    peer_ids=[PEER_NODE_ID_1],
                )
                self.assertEqual(sent, 0)
                self.assertEqual(
                    conn.execute("SELECT count(*) FROM envelopes").fetchone()[0],
                    1,
                )
            finally:
                conn.close()

    def test_duplicate_transaction_processing_does_not_create_duplicate_envelopes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                tx = self._transaction()
                peers = self._peers()
                with transaction(conn=conn):
                    insert_transaction(conn=conn, transaction=tx)
                    persist_outbound_envelopes(conn=conn, transaction=tx, peers=peers)
                    persist_outbound_envelopes(conn=conn, transaction=tx, peers=peers)

                self.assertEqual(
                    conn.execute("SELECT count(*) FROM envelopes").fetchone()[0],
                    2,
                )
            finally:
                conn.close()

    def test_local_transaction_creation_does_not_trust_configured_peer_without_registry(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "seckit.sqlite"
            with mock.patch.dict(
                "os.environ",
                {
                    SQLITE_PATH_ENV: str(db_path),
                    "HOME": tmpdir,
                    SQLITE_NODE_IDENTITY_KEY_ENV: str(Path(tmpdir) / "node-identity.key"),
                    "SECKIT_DAEMON_PEERS": f"{PEER_NODE_ID_1}@{TCP_HOST}:19001",
                },
            ):
                from secrets_kit.cli.commands.init_cmd import cmd_init_operator

                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    self.assertEqual(cmd_init_operator(args=argparse.Namespace(home=tmpdir, yes=True, unsafe_plaintext_storage=True)), 0)
                set_sqlite_secret(
                    service="svc",
                    account="acct",
                    name="NAME",
                    value="value",
                    metadata=EntryMetadata(
                        name="NAME",
                        service="svc",
                        account="acct",
                        source="unit-test",
                    ),
                )
                conn = open_sqlite_backend()
                try:
                    rows = conn.execute(
                        """
                        SELECT e.transaction_id, e.destination_node_id
                        FROM envelopes e
                        JOIN transactions t ON t.transaction_id = e.transaction_id
                        WHERE t.transaction_type = 'secret.set'
                        """
                    ).fetchall()
                    self.assertEqual(len(rows), 0)
                finally:
                    conn.close()

    def test_pending_envelope_successfully_transitions_to_sent(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                tx = self._transaction()
                with transaction(conn=conn):
                    insert_transaction(conn=conn, transaction=tx)
                    persist_outbound_envelopes(
                        conn=conn,
                        transaction=tx,
                        peers=[self._peers()[0]],
                    )
                stored_bytes = bytes(
                    conn.execute("SELECT encrypted_payload FROM envelopes").fetchone()[0]
                )
                with mock.patch(
                    "secrets_kit.runtime.outbound_delivery.request_opaque_route",
                    return_value={"version": 1, "status": "ok", "response": "delivered"},
                ) as route:
                    sent = process_pending_outbound_envelopes(
                        conn=conn,
                        peers=[self._peers()[0]],
                    )
                self.assertEqual(sent, 1)
                row = conn.execute(
                    "SELECT state, sent_at, acknowledged_at FROM envelopes"
                ).fetchone()
                self.assertEqual(row["state"], "sent")
                self.assertIsInstance(row["sent_at"], str)
                self.assertIsNone(row["acknowledged_at"])
                self.assertEqual(route.call_args.kwargs["payload"], stored_bytes)
            finally:
                conn.close()

    def test_failed_peer_leaves_envelope_pending(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                tx = self._transaction()
                with transaction(conn=conn):
                    insert_transaction(conn=conn, transaction=tx)
                    persist_outbound_envelopes(
                        conn=conn,
                        transaction=tx,
                        peers=[self._peers()[0]],
                    )
                with mock.patch(
                    "secrets_kit.runtime.outbound_delivery.request_opaque_route",
                    side_effect=OSError("connection refused"),
                ):
                    with self.assertLogs(
                        "secrets_kit.runtime.outbound_delivery",
                        level="WARNING",
                    ) as logs:
                        sent = process_pending_outbound_envelopes(
                            conn=conn,
                            peers=[self._peers()[0]],
                        )
                self.assertEqual(sent, 0)
                self.assertIn("transport delivery failed", "\n".join(logs.output))
                row = conn.execute(
                    "SELECT state, sent_at, attempt_count, last_error FROM envelopes"
                ).fetchone()
                self.assertEqual(row["state"], "retry_pending")
                self.assertIsNone(row["sent_at"])
                self.assertEqual(row["attempt_count"], 1)
                self.assertIn("connection refused", row["last_error"])
            finally:
                conn.close()

    def test_retry_pending_envelope_is_retried_and_marked_sent(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                tx = self._transaction()
                with transaction(conn=conn):
                    insert_transaction(conn=conn, transaction=tx)
                    persist_outbound_envelopes(
                        conn=conn,
                        transaction=tx,
                        peers=[self._peers()[0]],
                    )
                with mock.patch(
                    "secrets_kit.runtime.outbound_delivery.request_opaque_route",
                    side_effect=[
                        OSError("connection refused"),
                        {"version": 1, "status": "ok", "response": "delivered"},
                    ],
                ):
                    first = process_pending_outbound_envelopes(
                        conn=conn,
                        peers=[self._peers()[0]],
                    )
                    conn.execute(
                        "UPDATE envelopes SET next_attempt_at = '2000-01-01T00:00:00Z'"
                    )
                    second = process_pending_outbound_envelopes(
                        conn=conn,
                        peers=[self._peers()[0]],
                    )
                self.assertEqual((first, second), (0, 1))
                row = conn.execute(
                    """
                    SELECT state, attempt_count, sent_at, last_error, next_attempt_at
                    FROM envelopes
                    """
                ).fetchone()
                self.assertEqual(row["state"], "sent")
                self.assertEqual(row["attempt_count"], 2)
                self.assertIsInstance(row["sent_at"], str)
                self.assertIsNone(row["last_error"])
                self.assertIsNone(row["next_attempt_at"])
            finally:
                conn.close()

    def test_stale_delivery_claim_is_recovered_and_retried(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                tx = self._transaction()
                with transaction(conn=conn):
                    insert_transaction(conn=conn, transaction=tx)
                    persist_outbound_envelopes(
                        conn=conn,
                        transaction=tx,
                        peers=[self._peers()[0]],
                    )
                    conn.execute(
                        """
                        UPDATE envelopes
                        SET state = 'sending', claimed_at = '2000-01-01T00:00:00Z'
                        """
                    )
                stored_bytes = bytes(
                    conn.execute("SELECT encrypted_payload FROM envelopes").fetchone()[0]
                )
                with mock.patch(
                    "secrets_kit.runtime.outbound_delivery.request_opaque_route",
                    return_value={"version": 1, "status": "ok", "response": "delivered"},
                ) as route:
                    sent = process_pending_outbound_envelopes(
                        conn=conn,
                        peers=[self._peers()[0]],
                    )
                    repeated = process_pending_outbound_envelopes(
                        conn=conn,
                        peers=[self._peers()[0]],
                    )
                self.assertEqual(sent, 1)
                self.assertEqual(repeated, 0)
                self.assertEqual(route.call_count, 1)
                self.assertEqual(route.call_args.kwargs["payload"], stored_bytes)
                row = conn.execute(
                    "SELECT state, attempt_count, sent_at FROM envelopes"
                ).fetchone()
                self.assertEqual(row["state"], "sent")
                self.assertEqual(row["attempt_count"], 1)
                self.assertIsInstance(row["sent_at"], str)
            finally:
                conn.close()

    def test_active_delivery_claim_schedules_exact_lease_expiry(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            self.addCleanup(conn.close)
            tx = self._transaction()
            with transaction(conn=conn):
                insert_transaction(conn=conn, transaction=tx)
                persist_outbound_envelopes(
                    conn=conn,
                    transaction=tx,
                    peers=[PEER_NODE_ID_1],
                )
                conn.execute(
                    """
                    UPDATE envelopes
                    SET state = 'sending', claimed_at = '2099-01-01T00:00:00Z'
                    """
                )
            with mock.patch(
                "secrets_kit.runtime.outbound_delivery.request_opaque_route"
            ) as route:
                self.assertEqual(process_pending_outbound_envelopes(conn=conn), 0)
            route.assert_not_called()
            self.assertEqual(CLAIM_LEASE_SECONDS, 60)
            self.assertEqual(
                next_outbound_attempt_at(conn=conn),
                "2099-01-01T00:01:00Z",
            )

    def test_next_delivery_deadline_is_earliest_retry_or_claim_expiry(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            self.addCleanup(conn.close)
            tx = self._transaction()
            with transaction(conn=conn):
                insert_transaction(conn=conn, transaction=tx)
                persist_outbound_envelopes(
                    conn=conn,
                    transaction=tx,
                    peers=self._peers(),
                )
                conn.execute(
                    """
                    UPDATE envelopes
                    SET state = 'retry_pending',
                        next_attempt_at = '2099-01-01T00:02:00Z'
                    WHERE destination_node_id = ?
                    """,
                    (PEER_NODE_ID_1,),
                )
                conn.execute(
                    """
                    UPDATE envelopes
                    SET state = 'claimed', claimed_at = '2099-01-01T00:00:00Z'
                    WHERE destination_node_id = ?
                    """,
                    (PEER_NODE_ID_2,),
                )
            self.assertEqual(
                next_outbound_attempt_at(conn=conn),
                "2099-01-01T00:01:00Z",
            )
            conn.execute(
                """
                UPDATE envelopes
                SET next_attempt_at = '2099-01-01T00:00:30Z'
                WHERE destination_node_id = ?
                """,
                (PEER_NODE_ID_1,),
            )
            self.assertEqual(
                next_outbound_attempt_at(conn=conn),
                "2099-01-01T00:00:30Z",
            )

    def test_parked_peer_claim_does_not_restart_delivery_schedule(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            self.addCleanup(conn.close)
            first = self._transaction()
            second = self._transaction(
                transaction_id=tid("transaction", "parked-peer-claim")
            )
            with transaction(conn=conn):
                insert_transaction(conn=conn, transaction=first)
                insert_transaction(conn=conn, transaction=second)
                persist_outbound_envelopes(
                    conn=conn,
                    transaction=first,
                    peers=self._peers(),
                )
                persist_outbound_envelopes(
                    conn=conn,
                    transaction=second,
                    peers=[PEER_NODE_ID_1],
                )
                peer_one_rows = conn.execute(
                    """
                    SELECT envelope_id FROM envelopes
                    WHERE destination_node_id = ?
                    ORDER BY envelope_id
                    """,
                    (PEER_NODE_ID_1,),
                ).fetchall()
                conn.execute(
                    """
                    UPDATE envelopes
                    SET state = 'retry_pending', next_attempt_at = NULL
                    WHERE envelope_id = ?
                    """,
                    (peer_one_rows[0]["envelope_id"],),
                )
                conn.execute(
                    """
                    UPDATE envelopes
                    SET state = 'sending', claimed_at = '2099-01-01T00:00:00Z'
                    WHERE envelope_id = ?
                    """,
                    (peer_one_rows[1]["envelope_id"],),
                )
                conn.execute(
                    """
                    UPDATE envelopes
                    SET state = 'retry_pending',
                        next_attempt_at = '2099-01-01T00:02:00Z'
                    WHERE destination_node_id = ?
                    """,
                    (PEER_NODE_ID_2,),
                )
            self.assertEqual(
                next_outbound_attempt_at(conn=conn),
                "2099-01-01T00:02:00Z",
            )

    def test_expired_final_attempt_claim_is_parked_without_retry(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            self.addCleanup(conn.close)
            tx = self._transaction()
            with transaction(conn=conn):
                insert_transaction(conn=conn, transaction=tx)
                persist_outbound_envelopes(
                    conn=conn,
                    transaction=tx,
                    peers=[PEER_NODE_ID_1],
                )
                conn.execute(
                    """
                    UPDATE envelopes
                    SET state = 'sending', attempt_count = ?,
                        claimed_at = '2000-01-01T00:00:00Z'
                    """,
                    (MAX_DELIVERY_ATTEMPTS,),
                )
            with mock.patch(
                "secrets_kit.runtime.outbound_delivery.request_opaque_route"
            ) as route:
                self.assertEqual(process_pending_outbound_envelopes(conn=conn), 0)
                self.assertEqual(process_pending_outbound_envelopes(conn=conn), 0)
            route.assert_not_called()
            row = conn.execute(
                "SELECT state, attempt_count, next_attempt_at FROM envelopes"
            ).fetchone()
            self.assertEqual(row["state"], "retry_pending")
            self.assertEqual(row["attempt_count"], MAX_DELIVERY_ATTEMPTS)
            self.assertIsNone(row["next_attempt_at"])
            self.assertIsNone(next_outbound_attempt_at(conn=conn))

    def test_transport_delivery_does_not_hold_sqlite_write_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "seckit.sqlite"
            conn = self._connect(tmpdir)
            try:
                tx = self._transaction()
                with transaction(conn=conn):
                    insert_transaction(conn=conn, transaction=tx)
                    persist_outbound_envelopes(
                        conn=conn,
                        transaction=tx,
                        peers=[self._peers()[0]],
                    )

                def write_during_delivery(*args: object, **kwargs: object) -> dict[str, object]:
                    other = connect_sqlite(path=db_path)
                    try:
                        other.execute(
                            "UPDATE envelopes SET last_error = ?",
                            ("write during delivery succeeded",),
                        )
                        other.commit()
                    finally:
                        other.close()
                    return {"version": 1, "status": "ok", "response": "delivered"}

                with mock.patch(
                    "secrets_kit.runtime.outbound_delivery.request_opaque_route",
                    side_effect=write_during_delivery,
                ):
                    sent = process_pending_outbound_envelopes(
                        conn=conn,
                        peers=[self._peers()[0]],
                    )
                self.assertEqual(sent, 1)
                row = conn.execute("SELECT state FROM envelopes").fetchone()
                self.assertEqual(row["state"], "sent")
            finally:
                conn.close()

    def test_multiple_pending_envelopes_are_processed(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                tx = self._transaction()
                with transaction(conn=conn):
                    insert_transaction(conn=conn, transaction=tx)
                    persist_outbound_envelopes(conn=conn, transaction=tx, peers=self._peers())
                with mock.patch(
                    "secrets_kit.runtime.outbound_delivery.request_opaque_route",
                    return_value={"version": 1, "status": "ok", "response": "delivered"},
                ):
                    sent = process_pending_outbound_envelopes(conn=conn, peers=self._peers())
                self.assertEqual(sent, 2)
                states = [
                    row["state"]
                    for row in conn.execute("SELECT state FROM envelopes ORDER BY envelope_id")
                ]
                self.assertEqual(states, ["sent", "sent"])
            finally:
                conn.close()

    def test_failed_peer_uses_one_bounded_budget_without_starving_healthy_peer(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            self.addCleanup(conn.close)
            first = self._transaction()
            second = self._transaction(
                transaction_id=tid("transaction", "envelope-retry-second")
            )
            with transaction(conn=conn):
                insert_transaction(conn=conn, transaction=first)
                insert_transaction(conn=conn, transaction=second)
                persist_outbound_envelopes(
                    conn=conn,
                    transaction=first,
                    peers=self._peers(),
                )
                persist_outbound_envelopes(
                    conn=conn,
                    transaction=second,
                    peers=[PEER_NODE_ID_1],
                )
            retained = {
                row["envelope_id"]: (
                    row["destination_node_id"],
                    bytes(row["encrypted_payload"]),
                )
                for row in conn.execute(
                    "SELECT envelope_id, destination_node_id, encrypted_payload FROM envelopes"
                )
            }
            attempts: list[str] = []

            def deliver(*, peer_id: str, payload: bytes) -> dict[str, object]:
                self.assertEqual(payload, retained[next(
                    envelope_id
                    for envelope_id, (_peer_id, canonical) in retained.items()
                    if canonical == payload
                )][1])
                attempts.append(peer_id)
                if peer_id == PEER_NODE_ID_1:
                    raise OSError("peer unavailable")
                return {"version": 1, "status": "ok", "response": "delivered"}

            with mock.patch(
                "secrets_kit.runtime.outbound_delivery.request_opaque_route",
                side_effect=deliver,
            ):
                self.assertEqual(process_pending_outbound_envelopes(conn=conn), 1)
                self.assertEqual(
                    attempts.count(PEER_NODE_ID_1),
                    1,
                )
                self.assertEqual(attempts.count(PEER_NODE_ID_2), 1)
                for _ in range(MAX_DELIVERY_ATTEMPTS - 1):
                    conn.execute(
                        """
                        UPDATE envelopes
                        SET next_attempt_at = '2000-01-01T00:00:00Z'
                        WHERE destination_node_id = ? AND state = 'retry_pending'
                        """,
                        (PEER_NODE_ID_1,),
                    )
                    process_pending_outbound_envelopes(conn=conn)
                calls_at_exhaustion = len(attempts)
                process_pending_outbound_envelopes(conn=conn)
                self.assertEqual(len(attempts), calls_at_exhaustion)
                self.assertEqual(
                    attempts.count(PEER_NODE_ID_1),
                    MAX_DELIVERY_ATTEMPTS,
                )

            parked = conn.execute(
                """
                SELECT envelope_id, destination_node_id, encrypted_payload,
                       state, next_attempt_at
                FROM envelopes
                WHERE destination_node_id = ?
                ORDER BY envelope_id
                """,
                (PEER_NODE_ID_1,),
            ).fetchall()
            self.assertEqual(len(parked), 2)
            self.assertTrue(
                all(
                    row["state"] == "retry_pending"
                    and row["next_attempt_at"] is None
                    and retained[row["envelope_id"]]
                    == (row["destination_node_id"], bytes(row["encrypted_payload"]))
                    for row in parked
                )
            )
            self.assertEqual(
                resume_peer_delivery(conn=conn, peer_id=PEER_NODE_ID_1),
                2,
            )
            with mock.patch(
                "secrets_kit.runtime.outbound_delivery.request_opaque_route",
                return_value={"version": 1, "status": "ok", "response": "delivered"},
            ) as recovered:
                self.assertEqual(process_pending_outbound_envelopes(conn=conn), 2)
            self.assertEqual(recovered.call_count, 2)

    def test_recovered_peer_receives_fresh_bounded_delivery_episodes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            self.addCleanup(conn.close)
            tx = self._transaction()
            with transaction(conn=conn):
                insert_transaction(conn=conn, transaction=tx)
                persist_outbound_envelopes(
                    conn=conn,
                    transaction=tx,
                    peers=[PEER_NODE_ID_1],
                )
            retained_envelope = tuple(
                conn.execute(
                    """
                    SELECT envelope_id, transaction_id, source_node_id,
                           destination_node_id, encrypted_payload, envelope_hash
                    FROM envelopes
                    """
                ).fetchone()
            )
            retained_transaction = tuple(
                conn.execute(
                    "SELECT * FROM transactions WHERE transaction_id = ?",
                    (tx.transaction_id,),
                ).fetchone()
            )

            def exhaust_episode() -> None:
                for _ in range(MAX_DELIVERY_ATTEMPTS):
                    process_pending_outbound_envelopes(conn=conn)
                    conn.execute(
                        """
                        UPDATE envelopes
                        SET next_attempt_at = '2000-01-01T00:00:00Z'
                        WHERE state = 'retry_pending' AND next_attempt_at IS NOT NULL
                        """
                    )

            with mock.patch(
                "secrets_kit.runtime.outbound_delivery.request_opaque_route",
                side_effect=OSError("peer unavailable"),
            ) as route:
                exhaust_episode()
                self.assertEqual(route.call_count, MAX_DELIVERY_ATTEMPTS)
                self.assertEqual(
                    resume_peer_delivery(conn=conn, peer_id=PEER_NODE_ID_1),
                    1,
                )
                process_pending_outbound_envelopes(conn=conn)
                recovered = conn.execute(
                    "SELECT attempt_count, next_attempt_at FROM envelopes"
                ).fetchone()
                self.assertEqual(recovered["attempt_count"], 1)
                self.assertIsNotNone(recovered["next_attempt_at"])

                self.assertEqual(
                    resume_peer_delivery(conn=conn, peer_id=PEER_NODE_ID_1),
                    0,
                )
                for _ in range(MAX_DELIVERY_ATTEMPTS - 1):
                    conn.execute(
                        "UPDATE envelopes SET next_attempt_at = '2000-01-01T00:00:00Z'"
                    )
                    process_pending_outbound_envelopes(conn=conn)
                parked = conn.execute(
                    "SELECT attempt_count, next_attempt_at FROM envelopes"
                ).fetchone()
                self.assertEqual(parked["attempt_count"], MAX_DELIVERY_ATTEMPTS)
                self.assertIsNone(parked["next_attempt_at"])

                self.assertEqual(
                    resume_peer_delivery(conn=conn, peer_id=PEER_NODE_ID_1),
                    1,
                )
                self.assertEqual(
                    resume_peer_delivery(conn=conn, peer_id=PEER_NODE_ID_1),
                    0,
                )
                process_pending_outbound_envelopes(conn=conn)
                repeated = conn.execute(
                    "SELECT attempt_count, next_attempt_at FROM envelopes"
                ).fetchone()
                self.assertEqual(repeated["attempt_count"], 1)
                self.assertIsNotNone(repeated["next_attempt_at"])

            self.assertEqual(
                retained_envelope,
                tuple(
                    conn.execute(
                        """
                        SELECT envelope_id, transaction_id, source_node_id,
                               destination_node_id, encrypted_payload, envelope_hash
                        FROM envelopes
                        """
                    ).fetchone()
                ),
            )
            self.assertEqual(
                retained_transaction,
                tuple(
                    conn.execute(
                        "SELECT * FROM transactions WHERE transaction_id = ?",
                        (tx.transaction_id,),
                    ).fetchone()
                ),
            )

    def test_already_sent_envelopes_are_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                tx = self._transaction()
                with transaction(conn=conn):
                    insert_transaction(conn=conn, transaction=tx)
                    persist_outbound_envelopes(
                        conn=conn,
                        transaction=tx,
                        peers=[self._peers()[0]],
                    )
                    conn.execute(
                        "UPDATE envelopes SET state = 'sent', sent_at = ?",
                        ("2026-06-05T00:01:00+00:00",),
                    )
                with mock.patch(
                    "secrets_kit.runtime.outbound_delivery.request_opaque_route"
                ) as request:
                    sent = process_pending_outbound_envelopes(
                        conn=conn,
                        peers=[self._peers()[0]],
                    )
                self.assertEqual(sent, 0)
                request.assert_not_called()
                row = conn.execute("SELECT state, sent_at FROM envelopes").fetchone()
                self.assertEqual(row["state"], "sent")
                self.assertEqual(row["sent_at"], "2026-06-05T00:01:00+00:00")
            finally:
                conn.close()

    def test_envelope_sent_by_another_worker_before_mark_is_not_counted(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                tx = self._transaction()
                with transaction(conn=conn):
                    insert_transaction(conn=conn, transaction=tx)
                    persist_outbound_envelopes(
                        conn=conn,
                        transaction=tx,
                        peers=[self._peers()[0]],
                    )
                envelope_id = conn.execute("SELECT envelope_id FROM envelopes").fetchone()[
                    "envelope_id"
                ]

                def mark_sent_before_ack(*args: object, **kwargs: object) -> dict[str, object]:
                    conn.execute(
                        """
                        UPDATE envelopes
                        SET state = 'sent', sent_at = ?
                        WHERE envelope_id = ?
                        """,
                        ("2026-06-05T00:02:00+00:00", envelope_id),
                    )
                    return {"version": 1, "status": "ok", "response": "delivered"}

                with mock.patch(
                    "secrets_kit.runtime.outbound_delivery.request_opaque_route",
                    side_effect=mark_sent_before_ack,
                ):
                    sent = process_pending_outbound_envelopes(
                        conn=conn,
                        peers=[self._peers()[0]],
                    )
                self.assertEqual(sent, 0)
                row = conn.execute("SELECT state, sent_at FROM envelopes").fetchone()
                self.assertEqual(row["state"], "sent")
                self.assertEqual(row["sent_at"], "2026-06-05T00:02:00+00:00")
            finally:
                conn.close()

    def test_repeated_worker_passes_are_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = self._connect(tmpdir)
            try:
                tx = self._transaction()
                with transaction(conn=conn):
                    insert_transaction(conn=conn, transaction=tx)
                    persist_outbound_envelopes(
                        conn=conn,
                        transaction=tx,
                        peers=[self._peers()[0]],
                    )
                with mock.patch(
                    "secrets_kit.runtime.outbound_delivery.request_opaque_route",
                    return_value={"version": 1, "status": "ok", "response": "delivered"},
                ) as request:
                    first = process_pending_outbound_envelopes(
                        conn=conn,
                        peers=[self._peers()[0]],
                    )
                    second = process_pending_outbound_envelopes(
                        conn=conn,
                        peers=[self._peers()[0]],
                    )
                self.assertEqual((first, second), (1, 0))
                self.assertEqual(request.call_count, 1)
                self.assertEqual(
                    conn.execute("SELECT count(*) FROM envelopes WHERE state = 'sent'").fetchone()[
                        0
                    ],
                    1,
                )
            finally:
                conn.close()

    def test_list_persisted_envelopes_reads_inspection_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "seckit.sqlite"
            conn = self._connect(tmpdir)
            try:
                tx = self._transaction()
                with transaction(conn=conn):
                    insert_transaction(conn=conn, transaction=tx)
                    persist_outbound_envelopes(conn=conn, transaction=tx, peers=[self._peers()[0]])
                with mock.patch.dict("os.environ", {SQLITE_PATH_ENV: str(db_path)}):
                    rows = list_persisted_envelopes()
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0].transaction_id, TXN_ID)
                self.assertEqual(rows[0].destination_node_id, PEER_NODE_ID_1)
                self.assertEqual(rows[0].state, "pending")
                self.assertEqual(rows[0].attempt_count, 0)
                self.assertEqual(rows[0].retry_state, "none")
                self.assertEqual(rows[0].failure_reason, "")
                self.assertIsInstance(rows[0].created_at, str)
                self.assertTrue(rows[0].created_at)
                self.assertEqual(rows[0].sent_at, "")
            finally:
                conn.close()

    def test_envelope_list_command_prints_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "seckit.sqlite"
            conn = self._connect(tmpdir)
            try:
                tx = self._transaction()
                with transaction(conn=conn):
                    insert_transaction(conn=conn, transaction=tx)
                    persist_outbound_envelopes(conn=conn, transaction=tx, peers=[self._peers()[0]])
                stdout = io.StringIO()
                with mock.patch.dict("os.environ", {SQLITE_PATH_ENV: str(db_path)}), redirect_stdout(
                    stdout
                ):
                    code = cmd_envelope_list(args=argparse.Namespace())
                self.assertEqual(code, 0)
                text = stdout.getvalue()
                self.assertIn("ENVELOPE_ID", text)
                self.assertIn("TRANSACTION_ID", text)
                self.assertIn(PEER_NODE_ID_1, text)
                self.assertIn("pending", text)
            finally:
                conn.close()

    def test_envelope_show_command_prints_one_row(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "seckit.sqlite"
            conn = self._connect(tmpdir)
            try:
                tx = self._transaction()
                with transaction(conn=conn):
                    insert_transaction(conn=conn, transaction=tx)
                    persist_outbound_envelopes(conn=conn, transaction=tx, peers=[self._peers()[0]])
                with mock.patch.dict("os.environ", {SQLITE_PATH_ENV: str(db_path)}):
                    envelope = list_persisted_envelopes()[0]
                    stdout = io.StringIO()
                    with redirect_stdout(stdout):
                        code = cmd_envelope_show(
                            args=argparse.Namespace(envelope_id=envelope.envelope_id)
                        )
                self.assertEqual(code, 0)
                self.assertIn(f"envelope_id: {envelope.envelope_id}", stdout.getvalue())
                self.assertIn(f"transaction_id: {TXN_ID}", stdout.getvalue())
                self.assertIn(f"destination_node_id: {PEER_NODE_ID_1}", stdout.getvalue())
            finally:
                conn.close()

    def test_envelope_show_missing_returns_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "seckit.sqlite"
            conn = self._connect(tmpdir)
            conn.close()
            stderr = io.StringIO()
            with mock.patch.dict("os.environ", {SQLITE_PATH_ENV: str(db_path)}), redirect_stderr(
                stderr
            ):
                code = cmd_envelope_show(args=argparse.Namespace(envelope_id="missing"))
            self.assertEqual(code, 1)
            self.assertIn("envelope not found: missing", stderr.getvalue())

    def test_get_persisted_envelope_missing_database_is_read_only_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "missing.sqlite"
            with mock.patch.dict("os.environ", {SQLITE_PATH_ENV: str(db_path)}):
                self.assertEqual(list_persisted_envelopes(), [])
                self.assertIsNone(get_persisted_envelope(envelope_id="missing"))
            self.assertFalse(db_path.exists())


if __name__ == "__main__":
    unittest.main()
