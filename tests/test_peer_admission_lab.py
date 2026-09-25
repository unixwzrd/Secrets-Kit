from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from secrets_kit.backends.sqlite import (
    SQLiteValidationError,
    accept_peer_admission,
    bootstrap_replay_support_rows,
    bootstrap_schema,
    connect_sqlite,
    get_transaction,
    insert_transaction,
    open_sqlite_backend,
    rebuild_secret_projections,
)
from secrets_kit.backends.sqlite.peer_admission import (
    PEER_ADMISSION_ACCEPT,
    PEER_ADMISSION_REQUEST,
    create_peer_admission_transaction,
    create_signed_peer_admission_decision,
)
from secrets_kit.backends.sqlite.peer_registry import (
    AUTHORIZATION_MODE_ALL,
    AUTHORIZATION_MODE_NONE,
    get_peer_registry_entry,
    is_peer_synchronization_eligible,
)
from secrets_kit.backends.sqlite.storage_mode import (
    SQLITE_STORAGE_MODE_PLAINTEXT,
    initialize_sqlite_storage_mode,
)
from secrets_kit.daemon.client import send_opaque_tcp
from tests.canonical_id_helpers import tid
from tests.local_peer_lab import (
    inject_transaction,
    make_node,
    node_environment,
    peer_acceptance_response_transactions,
    peer_request_transaction,
    peer_state,
    provision_node,
    public_identity,
    run_cli_json,
    start_daemon,
    stop_daemon,
    transaction_count,
    transaction_envelope,
)

UNKNOWN_NODE_ID = tid("node", "unknown-admission-node")
UNKNOWN_REQUEST_ID = tid("transaction", "unknown-admission-request")
SERVICE_GROUP_ID = tid("service_group", "peer-registry-service-group")


class PeerAdmissionLocalLabTest(unittest.TestCase):
    def test_direct_injection_admits_two_isolated_nodes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            node_a = make_node(root=root, name="node-a")
            node_b = make_node(root=root, name="node-b")
            provision_node(node=node_a)
            provision_node(node=node_b)

            identity_a = public_identity(node=node_a)
            identity_b = public_identity(node=node_b)
            self.assertNotEqual(identity_a.node_id, identity_b.node_id)
            self.assertNotEqual(identity_a.signing_public_key, identity_b.signing_public_key)
            self.assertNotEqual(identity_a.encryption_public_key, identity_b.encryption_public_key)
            self.assertFalse((node_a.operator_store / "sqlite-storage.key").exists())
            self.assertFalse((node_b.operator_store / "sqlite-storage.key").exists())

            request_a_to_b = peer_request_transaction(source=node_a)
            self.assertNotIn("private", repr(request_a_to_b.payload).lower())
            inject_transaction(node=node_b, transaction=request_a_to_b)
            self.assertEqual(
                peer_state(node=node_b, peer_node_id=identity_a.node_id), "admission_requested"
            )

            with node_environment(node=node_b):
                accept_peer_admission(node_id=identity_a.node_id)
            self.assertEqual(peer_state(node=node_b, peer_node_id=identity_a.node_id), "active")

            request_b_to_a, accept_b_to_a = peer_acceptance_response_transactions(source=node_b)
            inject_transaction(node=node_a, transaction=request_b_to_a)
            inject_transaction(node=node_a, transaction=accept_b_to_a)
            self.assertEqual(peer_state(node=node_a, peer_node_id=identity_b.node_id), "active")

            peer_a_view = run_cli_json(
                node=node_a,
                args=["peer", "show", "--backend", "sqlite", "--json", identity_b.node_id],
            )
            peer_b_view = run_cli_json(
                node=node_b,
                args=["peer", "list", "--backend", "sqlite", "--json"],
            )
            self.assertEqual(peer_a_view["state"], "active")
            self.assertEqual(peer_a_view["authorization_mode"], "none")
            self.assertEqual(peer_b_view[0]["node_id"], identity_a.node_id)
            self.assertEqual(peer_b_view[0]["state"], "active")
            self.assertEqual(peer_b_view[0]["authorization_mode"], "none")

    def test_direct_injection_rejects_duplicate_unknown_and_malformed_transitions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            node_a = make_node(root=root, name="node-a")
            node_b = make_node(root=root, name="node-b")
            provision_node(node=node_a)
            provision_node(node=node_b)

            identity_a = public_identity(node=node_a)
            request_a_to_b = peer_request_transaction(source=node_a)
            inject_transaction(node=node_b, transaction=request_a_to_b)
            before = transaction_count(node=node_b)
            inject_transaction(node=node_b, transaction=request_a_to_b)
            self.assertEqual(transaction_count(node=node_b), before)

            duplicate_request = peer_request_transaction(source=node_a)
            with self.assertRaisesRegex(SQLiteValidationError, "duplicate peer admission"):
                inject_transaction(node=node_b, transaction=duplicate_request)

            with node_environment(node=node_a):
                unknown_accept = create_signed_peer_admission_decision(
                    proof_type=PEER_ADMISSION_ACCEPT,
                    node_id=UNKNOWN_NODE_ID,
                    request_id=UNKNOWN_REQUEST_ID,
                )
            with self.assertRaisesRegex(SQLiteValidationError, "unknown request"):
                inject_transaction(node=node_b, transaction=unknown_accept)

            malformed_payload = dict(peer_request_transaction(source=node_a).payload)
            malformed_payload["encryption_public_key"] = malformed_payload["signing_public_key"]
            malformed_request = create_peer_admission_transaction(
                transaction_type=PEER_ADMISSION_REQUEST,
                origin_node_id=identity_a.node_id,
                payload=malformed_payload,
            )
            with self.assertRaisesRegex(SQLiteValidationError, "must differ"):
                inject_transaction(node=node_b, transaction=malformed_request)

    def test_rejected_peer_does_not_become_active_and_restart_preserves_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            node_a = make_node(root=root, name="node-a")
            node_b = make_node(root=root, name="node-b")
            provision_node(node=node_a)
            provision_node(node=node_b)
            identity_a = public_identity(node=node_a)

            inject_transaction(node=node_b, transaction=peer_request_transaction(source=node_a))
            with node_environment(node=node_b):
                from secrets_kit.backends.sqlite import reject_peer_admission

                reject_peer_admission(node_id=identity_a.node_id)
            self.assertEqual(peer_state(node=node_b, peer_node_id=identity_a.node_id), "rejected")

            proc = start_daemon(node=node_b)
            stop_daemon(proc=proc, node=node_b)
            self.assertEqual(peer_state(node=node_b, peer_node_id=identity_a.node_id), "rejected")

    def test_replay_reconstructs_admission_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            node_a = make_node(root=root, name="node-a")
            node_b = make_node(root=root, name="node-b")
            provision_node(node=node_a)
            provision_node(node=node_b)

            identity_a = public_identity(node=node_a)
            inject_transaction(node=node_b, transaction=peer_request_transaction(source=node_a))
            with node_environment(node=node_b):
                accept_peer_admission(node_id=identity_a.node_id)
                source = connect_sqlite(path=node_b.sqlite_path)
                try:
                    source.row_factory = sqlite3.Row
                    transactions = [
                        get_transaction(conn=source, transaction_id=row["transaction_id"])
                        for row in source.execute(
                            "SELECT transaction_id FROM transactions ORDER BY rowid"
                        ).fetchall()
                    ]
                finally:
                    source.close()

            target = connect_sqlite(path=root / "replay-target.sqlite")
            try:
                bootstrap_schema(conn=target)
                initialize_sqlite_storage_mode(conn=target, mode=SQLITE_STORAGE_MODE_PLAINTEXT)
                bootstrap_replay_support_rows(conn=target, transactions=transactions)
                for transaction in transactions:
                    insert_transaction(conn=target, transaction=transaction)
                rebuild_secret_projections(conn=target)
                row = target.execute(
                    "SELECT state FROM nodes WHERE node_id = ?",
                    (identity_a.node_id,),
                ).fetchone()
                self.assertEqual(row["state"], "active")
            finally:
                target.close()

    def test_daemon_transport_rejects_unknown_signed_admission_request(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            node_a = make_node(root=root, name="node-a")
            node_b = make_node(root=root, name="node-b")
            provision_node(node=node_a)
            provision_node(node=node_b)
            identity_a = public_identity(node=node_a)
            node_b.env["SECKIT_DAEMON_TRANSPORT"] = "direct_tcp"
            node_b.env["SECKIT_UNSAFE_TEST_DIRECT_TCP"] = "1"

            proc_b = start_daemon(node=node_b)
            try:
                envelope = transaction_envelope(
                    transaction=peer_request_transaction(source=node_a),
                    signer_node=node_a,
                    recipient_node=node_b,
                )
                response = send_opaque_tcp(
                    payload=json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode(
                        "utf-8"
                    ),
                    port=node_b.port,
                )
                self.assertEqual(response.get("status"), "error")
                self.assertEqual(response.get("error"), "runtime_handoff_failed")
            finally:
                stop_daemon(proc=proc_b, node=node_b)
            self.assertEqual(peer_state(node=node_b, peer_node_id=identity_a.node_id), "")

    def test_peer_registry_projects_admission_authorization_metadata_and_service_groups(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            node_a = make_node(root=root, name="node-a")
            node_b = make_node(root=root, name="node-b")
            provision_node(node=node_a)
            provision_node(node=node_b)

            identity_a = public_identity(node=node_a)
            inject_transaction(node=node_b, transaction=peer_request_transaction(source=node_a))
            with node_environment(node=node_b):
                conn = open_sqlite_backend()
                try:
                    requested = get_peer_registry_entry(conn=conn, node_id=identity_a.node_id)
                    self.assertIsNotNone(requested)
                    assert requested is not None
                    self.assertEqual(requested.admission_state, "admission_requested")
                    self.assertEqual(requested.authorization_state, "unauthorized")
                    self.assertEqual(requested.authorization_mode, "none")
                    self.assertFalse(requested.synchronization_eligible)
                    self.assertFalse(
                        is_peer_synchronization_eligible(
                            conn=conn,
                            node_id=identity_a.node_id,
                            service_group_id=SERVICE_GROUP_ID,
                        )
                    )
                finally:
                    conn.close()

                accept_peer_admission(
                    node_id=identity_a.node_id,
                    display_name="Node A display",
                    service_group_ids=(SERVICE_GROUP_ID,),
                )
                conn = open_sqlite_backend()
                try:
                    accepted = get_peer_registry_entry(conn=conn, node_id=identity_a.node_id)
                    self.assertIsNotNone(accepted)
                    assert accepted is not None
                    self.assertEqual(accepted.admission_state, "active")
                    self.assertEqual(accepted.authorization_state, "authorized")
                    self.assertEqual(accepted.authorization_mode, "allow_list")
                    self.assertTrue(accepted.synchronization_eligible)
                    self.assertEqual(accepted.display_name, "Node A display")
                    self.assertEqual(accepted.local_alias, "")
                    self.assertEqual(accepted.service_group_ids, (SERVICE_GROUP_ID,))
                    self.assertTrue(
                        is_peer_synchronization_eligible(
                            conn=conn,
                            node_id=identity_a.node_id,
                            service_group_id=SERVICE_GROUP_ID,
                        )
                    )
                    self.assertFalse(
                        is_peer_synchronization_eligible(
                            conn=conn,
                            node_id=identity_a.node_id,
                            service_group_id=tid("service_group", "unauthorized"),
                        )
                    )
                    self.assertTrue(accepted.signing_fingerprint)
                    self.assertTrue(accepted.encryption_fingerprint)
                finally:
                    conn.close()

    def test_peer_accept_authorization_modes_are_explicit_and_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            node_a = make_node(root=root, name="node-a")
            node_b = make_node(root=root, name="node-b")
            node_c = make_node(root=root, name="node-c")
            provision_node(node=node_a)
            provision_node(node=node_b)
            provision_node(node=node_c)

            identity_a = public_identity(node=node_a)
            identity_c = public_identity(node=node_c)
            inject_transaction(node=node_b, transaction=peer_request_transaction(source=node_a))
            inject_transaction(node=node_b, transaction=peer_request_transaction(source=node_c))

            with node_environment(node=node_b):
                accept_peer_admission(node_id=identity_a.node_id)
                conn = open_sqlite_backend()
                try:
                    accepted_none = get_peer_registry_entry(conn=conn, node_id=identity_a.node_id)
                    self.assertIsNotNone(accepted_none)
                    assert accepted_none is not None
                    self.assertEqual(accepted_none.authorization_mode, AUTHORIZATION_MODE_NONE)
                    self.assertTrue(
                        is_peer_synchronization_eligible(conn=conn, node_id=identity_a.node_id)
                    )
                    self.assertFalse(
                        is_peer_synchronization_eligible(
                            conn=conn,
                            node_id=identity_a.node_id,
                            service_group_id=SERVICE_GROUP_ID,
                        )
                    )
                finally:
                    conn.close()

                accept_peer_admission(
                    node_id=identity_c.node_id,
                    authorization_mode=AUTHORIZATION_MODE_ALL,
                )
                conn = open_sqlite_backend()
                try:
                    accepted_all = get_peer_registry_entry(conn=conn, node_id=identity_c.node_id)
                    self.assertIsNotNone(accepted_all)
                    assert accepted_all is not None
                    self.assertEqual(accepted_all.authorization_mode, AUTHORIZATION_MODE_ALL)
                    self.assertTrue(
                        is_peer_synchronization_eligible(
                            conn=conn,
                            node_id=identity_c.node_id,
                            service_group_id=SERVICE_GROUP_ID,
                        )
                    )
                finally:
                    conn.close()

                with self.assertRaisesRegex(SQLiteValidationError, "all cannot include"):
                    create_signed_peer_admission_decision(
                        proof_type=PEER_ADMISSION_ACCEPT,
                        node_id=identity_a.node_id,
                        request_id=UNKNOWN_REQUEST_ID,
                        authorization_mode=AUTHORIZATION_MODE_ALL,
                        service_group_ids=(SERVICE_GROUP_ID,),
                    )


if __name__ == "__main__":
    unittest.main()
