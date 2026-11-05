"""tests.test_peer_revocation

Synthetic regression coverage for local peer revocation and its send boundary.
"""

from __future__ import annotations

import hashlib
import io
import json
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from secrets_kit.backends.sqlite import (
    accept_peer_admission,
    bootstrap_replay_support_rows,
    connect_sqlite,
    get_transaction,
    insert_transaction,
    open_sqlite_backend,
    rebuild_secret_projections,
    reject_peer_admission,
    request_peer_admission,
)
from secrets_kit.backends.sqlite.exceptions import SQLiteBackendError, SQLiteValidationError
from secrets_kit.backends.sqlite.gate import sqlite_path
from secrets_kit.backends.sqlite.node_identity import ensure_sqlite_node_identity
from secrets_kit.backends.sqlite.peer_admission import (
    PEER_ADMISSION_LOCAL_POLICY,
    create_peer_admission_transaction,
    local_peer_public_identity,
    revoke_peer_admission,
)
from secrets_kit.backends.sqlite.peer_admission_auth import signed_admission_revocation_payload
from secrets_kit.backends.sqlite.peer_delivery_lock import peer_delivery_lock
from secrets_kit.backends.sqlite.peer_registry import is_peer_synchronization_eligible
from secrets_kit.backends.sqlite.schema import bootstrap_schema
from secrets_kit.backends.sqlite.secrets_api import set_sqlite_secret
from secrets_kit.backends.sqlite.storage_mode import (
    SQLITE_STORAGE_MODE_PLAINTEXT,
    initialize_sqlite_storage_mode,
)
from secrets_kit.cli import build_parser
from secrets_kit.cli.commands.peer import cmd_peer_revoke
from secrets_kit.models import EntryMetadata
from secrets_kit.runtime.inbound_envelopes import apply_inbound_transaction
from secrets_kit.runtime.outbound_delivery import (
    DeliveryOutcome,
    process_pending_outbound_envelopes,
)
from secrets_kit.runtime.transport_identity import (
    TransportIdentityError,
    sign_transport_binding,
    verify_transport_binding,
)
from tests.local_peer_lab import (
    make_node,
    node_environment,
    peer_request_transaction,
    provision_node,
)


class PeerRevocationTest(unittest.TestCase):
    def _nodes(self, root: Path):
        nodes = [make_node(root=root, name=name) for name in ("peer-a", "owner-b", "peer-c")]
        for node in nodes:
            provision_node(node=node)
        a, b, c = nodes
        requests = [peer_request_transaction(source=node) for node in (a, c)]
        with node_environment(node=b):
            for request in requests:
                request_peer_admission(signed_request=request.payload)
                accept_peer_admission(
                    node_id=str(request.payload["node_id"]), authorization_mode="all"
                )
        return a, b, c, str(requests[0].payload["node_id"]), str(requests[1].payload["node_id"])

    @staticmethod
    def _set_secret(name: str) -> None:
        set_sqlite_secret(
            service="synthetic-revocation",
            account="test",
            name=name,
            value="synthetic-value",
            metadata=EntryMetadata(name=name),
        )

    def test_revoke_denies_queued_new_inbound_and_reconnection_but_preserves_other_peer(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            a, b, _c, a_id, c_id = self._nodes(Path(tmp))
            with node_environment(node=a):
                claim = sign_transport_binding(
                    challenge="a" * 64, transport_identity="synthetic-route"
                )
                self._set_secret("INBOUND_PROBE")
                conn = open_sqlite_backend()
                try:
                    row = conn.execute(
                        "SELECT transaction_id FROM transactions WHERE transaction_type = 'secret.set' ORDER BY rowid DESC LIMIT 1"
                    ).fetchone()
                    inbound = get_transaction(conn=conn, transaction_id=row["transaction_id"])
                finally:
                    conn.close()
            with node_environment(node=b):
                self.assertEqual(
                    verify_transport_binding(
                        claim=claim,
                        expected_challenge="a" * 64,
                        expected_transport_identity="synthetic-route",
                    ),
                    a_id,
                )
                self._set_secret("BEFORE_REVOKE")
                conn = open_sqlite_backend()
                try:
                    before_ids = [
                        row["transaction_id"]
                        for row in conn.execute(
                            "SELECT transaction_id FROM transactions ORDER BY rowid"
                        )
                    ]
                    self.assertGreater(
                        conn.execute(
                            "SELECT COUNT(*) FROM envelopes WHERE destination_node_id = ? AND state = 'pending'",
                            (a_id,),
                        ).fetchone()[0],
                        0,
                    )
                finally:
                    conn.close()
                result = revoke_peer_admission(node_id=a_id)
                self.assertEqual(result.transaction_type, "peer.admission.revoke")
                self.assertIsNone(result.proof_payload)
                conn = open_sqlite_backend()
                try:
                    self.assertFalse(is_peer_synchronization_eligible(conn=conn, node_id=a_id))
                    self.assertTrue(is_peer_synchronization_eligible(conn=conn, node_id=c_id))
                    self.assertEqual(
                        conn.execute(
                            "SELECT COUNT(*) FROM envelopes WHERE destination_node_id = ? AND state IN ('pending','retry_pending','claimed','sending')",
                            (a_id,),
                        ).fetchone()[0],
                        0,
                    )
                    self.assertGreater(
                        conn.execute(
                            "SELECT COUNT(*) FROM envelopes WHERE destination_node_id = ? AND state = 'authorization_denied'",
                            (a_id,),
                        ).fetchone()[0],
                        0,
                    )
                    self.assertTrue(
                        set(before_ids).issubset(
                            {
                                row[0]
                                for row in conn.execute("SELECT transaction_id FROM transactions")
                            }
                        )
                    )
                    a_envelopes = conn.execute(
                        "SELECT COUNT(*) FROM envelopes WHERE destination_node_id = ?", (a_id,)
                    ).fetchone()[0]
                    c_envelopes = conn.execute(
                        "SELECT COUNT(*) FROM envelopes WHERE destination_node_id = ?", (c_id,)
                    ).fetchone()[0]
                finally:
                    conn.close()
                self._set_secret("AFTER_REVOKE")
                conn = open_sqlite_backend()
                try:
                    self.assertEqual(
                        conn.execute(
                            "SELECT COUNT(*) FROM envelopes WHERE destination_node_id = ?", (a_id,)
                        ).fetchone()[0],
                        a_envelopes,
                    )
                    self.assertGreater(
                        conn.execute(
                            "SELECT COUNT(*) FROM envelopes WHERE destination_node_id = ?", (c_id,)
                        ).fetchone()[0],
                        c_envelopes,
                    )
                finally:
                    conn.close()
                with self.assertRaisesRegex(SQLiteValidationError, "not permitted"):
                    apply_inbound_transaction(transaction=inbound)
                with self.assertRaisesRegex(TransportIdentityError, "not admitted"):
                    verify_transport_binding(
                        claim=claim,
                        expected_challenge="a" * 64,
                        expected_transport_identity="synthetic-route",
                    )
                with self.assertRaisesRegex(SQLiteBackendError, "not pending"):
                    reject_peer_admission(node_id=a_id)
                with self.assertRaisesRegex(SQLiteBackendError, "not actively admitted"):
                    revoke_peer_admission(node_id=a_id)

    def test_cli_revoke_reports_only_after_canonical_transaction_commits(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            _a, b, _c, a_id, _c_id = self._nodes(Path(tmp))
            with node_environment(node=b), redirect_stdout(io.StringIO()) as output:
                args = build_parser().parse_args(
                    ["peer", "revoke", a_id, "--json"]
                )
                self.assertEqual(cmd_peer_revoke(args=args), 0)
                result = json.loads(output.getvalue())
                self.assertEqual(result["state"], "revoked")
                conn = open_sqlite_backend()
                try:
                    self.assertEqual(
                        get_transaction(
                            conn=conn, transaction_id=result["transaction_id"]
                        ).transaction_type,
                        "peer.admission.revoke",
                    )
                finally:
                    conn.close()

    def test_local_node_cannot_be_revoked_as_a_peer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            _a, b, _c, _a_id, _c_id = self._nodes(Path(tmp))
            with node_environment(node=b):
                local_id = local_peer_public_identity().node_id
                with self.assertRaisesRegex(SQLiteBackendError, "unknown or local peer"):
                    revoke_peer_admission(node_id=local_id)
                conn = open_sqlite_backend()
                try:
                    self.assertEqual(
                        conn.execute(
                            "SELECT state FROM nodes WHERE node_id = ?", (local_id,)
                        ).fetchone()[0],
                        "active",
                    )
                    self.assertEqual(
                        conn.execute(
                            "SELECT COUNT(*) FROM transactions WHERE transaction_type = 'peer.admission.revoke'"
                        ).fetchone()[0],
                        0,
                    )
                finally:
                    conn.close()

    def test_unsafe_peer_lock_fails_before_revocation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            _a, b, _c, a_id, _c_id = self._nodes(Path(tmp))
            with node_environment(node=b):
                digest = hashlib.sha256(a_id.encode("utf-8")).hexdigest()
                path = sqlite_path().with_name(f".seckit-peer-delivery-{digest}.lock")
                path.symlink_to(Path(tmp) / "unrelated")
                with self.assertRaisesRegex(SQLiteBackendError, "lock is unavailable"):
                    revoke_peer_admission(node_id=a_id)
                conn = open_sqlite_backend()
                try:
                    self.assertTrue(is_peer_synchronization_eligible(conn=conn, node_id=a_id))
                    self.assertEqual(
                        conn.execute(
                            "SELECT COUNT(*) FROM transactions WHERE transaction_type = 'peer.admission.revoke'"
                        ).fetchone()[0],
                        0,
                    )
                finally:
                    conn.close()

    def test_revoked_peer_remains_denied_after_projection_rebuild(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _a, b, _c, a_id, c_id = self._nodes(root)
            with node_environment(node=b):
                revoke_peer_admission(node_id=a_id)
                source = open_sqlite_backend()
                try:
                    history = [
                        get_transaction(conn=source, transaction_id=row[0])
                        for row in source.execute(
                            "SELECT transaction_id FROM transactions WHERE transaction_type LIKE 'peer.admission.%' ORDER BY rowid"
                        )
                    ]
                finally:
                    source.close()
                target = connect_sqlite(path=root / "replay-target.sqlite")
                try:
                    bootstrap_schema(conn=target)
                    initialize_sqlite_storage_mode(conn=target, mode=SQLITE_STORAGE_MODE_PLAINTEXT)
                    ensure_sqlite_node_identity(conn=target)
                    bootstrap_replay_support_rows(conn=target, transactions=history)
                    for tx in history:
                        insert_transaction(conn=target, transaction=tx)
                    rebuild_secret_projections(conn=target)
                    self.assertFalse(is_peer_synchronization_eligible(conn=target, node_id=a_id))
                    self.assertTrue(is_peer_synchronization_eligible(conn=target, node_id=c_id))
                    row = target.execute(
                        "SELECT state, authorization_mode FROM nodes WHERE node_id = ?", (a_id,)
                    ).fetchone()
                    self.assertEqual((row["state"], row["authorization_mode"]), ("revoked", "none"))
                finally:
                    target.close()

    def test_revocation_waits_for_inflight_send_and_stops_remaining_queued_work(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            _a, b, _c, a_id, _c_id = self._nodes(Path(tmp))
            with node_environment(node=b):
                self._set_secret("QUEUE_PROBE")
                entered = threading.Event()
                release = threading.Event()
                revoked = threading.Event()
                deliveries: list[str] = []
                failures: list[BaseException] = []

                def deliver(*, row):
                    deliveries.append(str(row["envelope_id"]))
                    entered.set()
                    if not release.wait(timeout=5):
                        raise AssertionError("test send was not released")
                    return DeliveryOutcome(delivered=True)

                def send_worker() -> None:
                    try:
                        conn = open_sqlite_backend()
                        try:
                            process_pending_outbound_envelopes(conn=conn, peer_ids=[a_id])
                        finally:
                            conn.close()
                    except BaseException as exc:
                        failures.append(exc)

                def revoke_worker() -> None:
                    try:
                        revoke_peer_admission(node_id=a_id)
                    except BaseException as exc:
                        failures.append(exc)
                    finally:
                        revoked.set()

                with mock.patch(
                    "secrets_kit.runtime.outbound_delivery.deliver_outbound_envelope",
                    side_effect=deliver,
                ):
                    sender = threading.Thread(target=send_worker)
                    sender.start()
                    self.assertTrue(entered.wait(timeout=5))
                    revoker = threading.Thread(target=revoke_worker)
                    revoker.start()
                    self.assertFalse(revoked.wait(timeout=0.1))
                    release.set()
                    sender.join(timeout=10)
                    revoker.join(timeout=10)
                    self.assertFalse(sender.is_alive() or revoker.is_alive())
                    self.assertFalse(failures, failures)
                    self.assertTrue(revoked.is_set())
                    completed_before_return = len(deliveries)
                    conn = open_sqlite_backend()
                    try:
                        process_pending_outbound_envelopes(conn=conn, peer_ids=[a_id])
                        self.assertEqual(
                            conn.execute(
                                "SELECT COUNT(*) FROM envelopes WHERE destination_node_id = ? AND state IN ('pending','retry_pending','claimed','sending')",
                                (a_id,),
                            ).fetchone()[0],
                            0,
                        )
                    finally:
                        conn.close()
                    self.assertEqual(len(deliveries), completed_before_return)

    def test_failed_lock_boundary_does_not_claim_revocation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            _a, b, _c, a_id, _c_id = self._nodes(Path(tmp))
            with node_environment(node=b), peer_delivery_lock(node_id=a_id):

                def short_lock(*, node_id, timeout_seconds):
                    return peer_delivery_lock(node_id=node_id, timeout_seconds=0.02)

                with mock.patch(
                    "secrets_kit.backends.sqlite.peer_admission.peer_delivery_lock",
                    side_effect=short_lock,
                ):
                    with self.assertRaisesRegex(SQLiteBackendError, "revocation was not applied"):
                        revoke_peer_admission(node_id=a_id)
                conn = open_sqlite_backend()
                try:
                    self.assertTrue(is_peer_synchronization_eligible(conn=conn, node_id=a_id))
                    self.assertEqual(
                        conn.execute(
                            "SELECT COUNT(*) FROM transactions WHERE transaction_type = 'peer.admission.revoke'"
                        ).fetchone()[0],
                        0,
                    )
                finally:
                    conn.close()

    def test_tampered_local_revocation_proof_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            _a, b, _c, a_id, _c_id = self._nodes(Path(tmp))
            with node_environment(node=b):
                payload = signed_admission_revocation_payload(node_id=a_id)
                payload["node_id"] = str(peer_request_transaction(source=b).payload["node_id"])
                from secrets_kit.backends.sqlite.connection import transaction
                from secrets_kit.backends.sqlite.transaction_engine import submit_transaction

                tx = create_peer_admission_transaction(
                    transaction_type="peer.admission.revoke",
                    payload=payload,
                    origin_node_id=str(payload["signer_node_id"]),
                )
                conn = open_sqlite_backend()
                try:
                    with self.assertRaisesRegex(
                        SQLiteValidationError, "signature verification failed"
                    ):
                        with transaction(conn=conn):
                            submit_transaction(
                                conn=conn, transaction=tx, policy=PEER_ADMISSION_LOCAL_POLICY
                            )
                    self.assertTrue(is_peer_synchronization_eligible(conn=conn, node_id=a_id))
                finally:
                    conn.close()

    def test_admitted_remote_peer_cannot_revoke_another_local_peer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            a, b, _c, _a_id, c_id = self._nodes(Path(tmp))
            with node_environment(node=a):
                payload = signed_admission_revocation_payload(node_id=c_id)
                forged = create_peer_admission_transaction(
                    transaction_type="peer.admission.revoke",
                    payload=payload,
                    origin_node_id=str(payload["signer_node_id"]),
                )
            with node_environment(node=b):
                with self.assertRaisesRegex(SQLiteValidationError, "signed by the local node"):
                    apply_inbound_transaction(transaction=forged)
                conn = open_sqlite_backend()
                try:
                    self.assertTrue(is_peer_synchronization_eligible(conn=conn, node_id=c_id))
                    self.assertEqual(
                        conn.execute(
                            "SELECT COUNT(*) FROM transactions WHERE transaction_id = ?",
                            (forged.transaction_id,),
                        ).fetchone()[0],
                        0,
                    )
                finally:
                    conn.close()


if __name__ == "__main__":
    unittest.main()
