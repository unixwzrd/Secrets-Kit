from __future__ import annotations

import argparse
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from secrets_kit.backends.sqlite import (
    SQLiteBackendError,
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
from secrets_kit.backends.sqlite.peer_admission import PEER_ADMISSION_REQUEST
from secrets_kit.backends.sqlite.storage_mode import (
    SQLITE_STORAGE_MODE_PLAINTEXT,
    initialize_sqlite_storage_mode,
)
from secrets_kit.backends.sqlite.transactions import inspect_transaction
from secrets_kit.cli import build_parser
from secrets_kit.cli.commands.peer import (
    cmd_peer_accept,
    cmd_peer_import_acceptance,
    cmd_peer_import_request,
    cmd_peer_request,
)
from tests.canonical_id_helpers import tid
from tests.local_peer_lab import (
    make_node,
    node_environment,
    peer_request_transaction,
    peer_state,
    provision_node,
)

TAMPERED_NODE_ID = tid("node", "tampered-peer-admission")
SERVICE_GROUP_ID = tid("service_group", "peer-admission-cli-service-group")


class NamedPeerScopeTest(unittest.TestCase):
    """Named customer scopes must map exactly to the existing allow-list path."""

    def test_named_scope_is_retained_in_signed_admission(self) -> None:
        from secrets_kit.backends.sqlite.peer_admission import get_peer_admission
        from secrets_kit.backends.sqlite.secrets_api import _service_group_id

        with tempfile.TemporaryDirectory() as directory:
            a = make_node(root=Path(directory), name="a")
            b = make_node(root=Path(directory), name="b")
            provision_node(node=a)
            provision_node(node=b)
            request = peer_request_transaction(source=a)
            with node_environment(node=b), redirect_stdout(io.StringIO()) as output:
                imported = request_peer_admission(signed_request=request.payload)
                args = build_parser().parse_args([
                    "peer", "accept", imported.node_id, "--backend", "sqlite",
                    "--service", "beta-test", "--account", "external", "--json",
                ])
                self.assertEqual(cmd_peer_accept(args=args), 0)
                row = get_peer_admission(node_id=imported.node_id)
                self.assertIsNotNone(row)
                assert row is not None
                self.assertEqual(row.authorization_mode, "allow_list")
                self.assertEqual(tuple(row.service_group_ids), (_service_group_id(account="external", service="beta-test"),))
                self.assertEqual(json.loads(output.getvalue())["proof_type"], "peer.admission.accept")

            # A new signed request cannot reset an already active admission or
            # silently replace its customer's existing scope authorization.
            repeated_request = peer_request_transaction(source=a)
            with node_environment(node=b):
                before = get_peer_admission(node_id=imported.node_id)
                with self.assertRaisesRegex(SQLiteBackendError, "duplicate peer admission"):
                    request_peer_admission(signed_request=repeated_request.payload)
                self.assertEqual(get_peer_admission(node_id=imported.node_id), before)

    def test_named_scope_uses_existing_identifier_without_wildcard(self) -> None:
        from secrets_kit.backends.sqlite.secrets_api import _service_group_id

        args = build_parser().parse_args([
            "peer", "accept", TAMPERED_NODE_ID, "--backend", "sqlite",
            "--service", "beta-test", "--account", "external", "--json",
        ])
        with mock.patch("secrets_kit.cli.commands.peer.accept_peer_admission") as accept, redirect_stdout(io.StringIO()):
            accept.return_value.proof_payload = {}
            self.assertEqual(cmd_peer_accept(args=args), 0)
        accept.assert_called_once_with(
            node_id=TAMPERED_NODE_ID, operator_comment="",
            service_group_ids=(_service_group_id(account="external", service="beta-test"),),
            authorization_mode=None,
        )

    def test_partial_empty_or_mixed_scopes_fail_before_admission(self) -> None:
        cases = [
            ["--service", "beta-test"], ["--account", "external"],
            ["--service", "", "--account", "external"],
            ["--service", "beta-test", "--account", " "],
            ["--service", "beta\0test", "--account", "external"],
            ["--service", "beta-test", "--account", "external", "--all-service-groups"],
            ["--service", "beta-test", "--account", "external", "--service-group-id", SERVICE_GROUP_ID],
        ]
        for options in cases:
            with self.subTest(options=options), mock.patch("secrets_kit.cli.commands.peer.accept_peer_admission") as accept, redirect_stderr(io.StringIO()):
                args = build_parser().parse_args(["peer", "accept", TAMPERED_NODE_ID, "--backend", "sqlite", *options])
                self.assertEqual(cmd_peer_accept(args=args), 1)
                accept.assert_not_called()


class SQLitePeerAdmissionTest(unittest.TestCase):
    def test_request_accept_and_reject_project_authenticated_admission_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            node_a = make_node(root=root, name="node-a")
            node_b = make_node(root=root, name="node-b")
            node_c = make_node(root=root, name="node-c")
            provision_node(node=node_a)
            provision_node(node=node_b)
            provision_node(node=node_c)

            request_a = peer_request_transaction(source=node_a)
            with node_environment(node=node_b):
                request = request_peer_admission(signed_request=request_a.payload)
                self.assertEqual(request.transaction_type, "peer.admission.request")
                self.assertEqual(peer_state(node=node_b, peer_node_id=request.node_id), "admission_requested")

                accept = accept_peer_admission(node_id=request.node_id)
                self.assertEqual(accept.transaction_type, "peer.admission.accept")
                self.assertEqual(peer_state(node=node_b, peer_node_id=request.node_id), "active")
                self.assertIsNotNone(accept.proof_payload)

            request_c = peer_request_transaction(source=node_c)
            with node_environment(node=node_b):
                request_peer_admission(signed_request=request_c.payload)
                reject = reject_peer_admission(node_id=str(request_c.payload["node_id"]))
                self.assertEqual(reject.transaction_type, "peer.admission.reject")
                self.assertEqual(
                    peer_state(node=node_b, peer_node_id=str(request_c.payload["node_id"])),
                    "rejected",
                )

    def test_invalid_transitions_and_unsigned_payloads_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            node_a = make_node(root=root, name="node-a")
            node_b = make_node(root=root, name="node-b")
            provision_node(node=node_a)
            provision_node(node=node_b)

            with node_environment(node=node_b):
                with self.assertRaisesRegex(SQLiteBackendError, "cannot accept unknown"):
                    accept_peer_admission(node_id="node:missing")
                with self.assertRaisesRegex(SQLiteBackendError, "unknown"):
                    reject_peer_admission(node_id="node:missing")
                with self.assertRaisesRegex(SQLiteBackendError, "signature is required"):
                    request_peer_admission(
                        signed_request={
                            "node_id": "node:unsigned",
                            "signing_public_key": "not-used",
                            "signing_algorithm": "ed25519",
                            "encryption_public_key": "not-used",
                            "encryption_algorithm": "x25519",
                            "created_at": "2026-07-11T00:00:00Z",
                            "nonce": "nonce",
                            "proof_type": "peer.admission.request",
                            "proof_version": 1,
                            "request_id": "admission-request:unsigned",
                        }
                    )

            request_a = peer_request_transaction(source=node_a)
            with node_environment(node=node_b):
                request_peer_admission(signed_request=request_a.payload)
                with self.assertRaisesRegex(SQLiteBackendError, "duplicate peer admission"):
                    request_peer_admission(signed_request=peer_request_transaction(source=node_a).payload)
                accept_peer_admission(node_id=str(request_a.payload["node_id"]))
                with self.assertRaisesRegex(SQLiteBackendError, "not pending"):
                    accept_peer_admission(node_id=str(request_a.payload["node_id"]))

    def test_tampered_authenticated_request_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            node_a = make_node(root=root, name="node-a")
            node_b = make_node(root=root, name="node-b")
            provision_node(node=node_a)
            provision_node(node=node_b)
            tampered = dict(peer_request_transaction(source=node_a).payload)
            tampered["node_id"] = TAMPERED_NODE_ID
            with node_environment(node=node_b):
                with self.assertRaisesRegex(SQLiteBackendError, "signature verification failed"):
                    request_peer_admission(signed_request=tampered)

    def test_replay_rebuilds_peer_admission_state_from_transactions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            node_a = make_node(root=root, name="node-a")
            node_b = make_node(root=root, name="node-b")
            provision_node(node=node_a)
            provision_node(node=node_b)
            request_a = peer_request_transaction(source=node_a)
            peer_node_id = str(request_a.payload["node_id"])

            with node_environment(node=node_b):
                request_peer_admission(signed_request=request_a.payload)
                accept_peer_admission(node_id=peer_node_id)
                source = open_sqlite_backend()
                try:
                    transactions = [
                        get_transaction(conn=source, transaction_id=row["transaction_id"])
                        for row in source.execute(
                            "SELECT transaction_id FROM transactions ORDER BY rowid"
                        ).fetchall()
                    ]
                finally:
                    source.close()

            target = connect_sqlite(path=root / "target.sqlite")
            try:
                from secrets_kit.backends.sqlite import bootstrap_schema

                bootstrap_schema(conn=target)
                initialize_sqlite_storage_mode(conn=target, mode=SQLITE_STORAGE_MODE_PLAINTEXT)
                bootstrap_replay_support_rows(conn=target, transactions=transactions)
                for transaction in transactions:
                    insert_transaction(conn=target, transaction=transaction)
                rebuild_secret_projections(conn=target)
                row = target.execute(
                    "SELECT state FROM nodes WHERE node_id = ?",
                    (peer_node_id,),
                ).fetchone()
                self.assertEqual(row["state"], "active")
            finally:
                target.close()

    def test_transaction_inspection_includes_public_authentication_proof_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            node_a = make_node(root=root, name="node-a")
            node_b = make_node(root=root, name="node-b")
            provision_node(node=node_a)
            provision_node(node=node_b)
            request_a = peer_request_transaction(source=node_a)
            with node_environment(node=node_b):
                result = request_peer_admission(signed_request=request_a.payload)
            inspected = inspect_transaction(
                path=node_b.sqlite_path,
                transaction_id=result.transaction_id,
            )
            self.assertEqual(inspected.transaction_type, PEER_ADMISSION_REQUEST)
            self.assertEqual(inspected.payload["node_id"], request_a.payload["node_id"])
            self.assertIn("signature", inspected.payload)
            self.assertNotIn("private", json.dumps(inspected.payload).lower())

    def test_peer_cli_commands_use_signed_request_import_flow(self) -> None:
        parser = build_parser()
        self.assertEqual(
            parser.parse_args(["peer", "request", "--backend", "sqlite"]).peer_command,
            "request",
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            node_a = make_node(root=root, name="node-a")
            node_b = make_node(root=root, name="node-b")
            provision_node(node=node_a)
            provision_node(node=node_b)

            with node_environment(node=node_a), redirect_stdout(io.StringIO()) as stdout:
                self.assertEqual(
                    cmd_peer_request(
                        args=argparse.Namespace(
                            backend="sqlite",
                            service_address="",
                            comment="",
                            json=True,
                        )
                    ),
                    0,
                )
                request_payload = json.loads(stdout.getvalue())

            with node_environment(node=node_b), mock.patch(
                "sys.stdin",
                io.StringIO(json.dumps(request_payload)),
            ), redirect_stdout(io.StringIO()) as stdout:
                self.assertEqual(
                    cmd_peer_import_request(
                        args=argparse.Namespace(backend="sqlite", file=None),
                    ),
                    0,
                )
                self.assertIn("transaction_type: peer.admission.request", stdout.getvalue())

            with node_environment(node=node_b), redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(
                    cmd_peer_accept(
                        args=argparse.Namespace(
                            backend="sqlite",
                            node_id=request_payload["node_id"],
                            comment="",
                            service_group_id=[SERVICE_GROUP_ID],
                            all_service_groups=True,
                            json=False,
                        )
                    ),
                    1,
                )
                self.assertIn("cannot be combined", stderr.getvalue())

            with node_environment(node=node_b), redirect_stdout(io.StringIO()) as stdout:
                self.assertEqual(
                    cmd_peer_accept(
                        args=argparse.Namespace(
                            backend="sqlite",
                            node_id=request_payload["node_id"],
                            comment="",
                            json=True,
                        )
                    ),
                    0,
                )
                acceptance_payload = json.loads(stdout.getvalue())
            self.assertEqual(acceptance_payload["proof_type"], "peer.admission.accept")

            with node_environment(node=node_a), mock.patch(
                "sys.stdin",
                io.StringIO(json.dumps(acceptance_payload)),
            ), redirect_stdout(io.StringIO()):
                self.assertEqual(
                    cmd_peer_import_acceptance(
                        args=argparse.Namespace(backend="sqlite", file=None),
                    ),
                    0,
                )

            with node_environment(node=node_b), redirect_stdout(io.StringIO()) as stdout:
                self.assertEqual(
                    cmd_peer_request(
                        args=argparse.Namespace(
                            backend="sqlite",
                            service_address="",
                            comment="",
                            json=True,
                        )
                    ),
                    0,
                )
                request_b_payload = json.loads(stdout.getvalue())
            with node_environment(node=node_a), mock.patch(
                "sys.stdin",
                io.StringIO(json.dumps(request_b_payload)),
            ), redirect_stdout(io.StringIO()):
                self.assertEqual(
                    cmd_peer_import_request(
                        args=argparse.Namespace(backend="sqlite", file=None),
                    ),
                    0,
                )
            with node_environment(node=node_a), redirect_stdout(io.StringIO()) as stdout:
                self.assertEqual(
                    cmd_peer_accept(
                        args=argparse.Namespace(
                            backend="sqlite",
                            node_id=request_b_payload["node_id"],
                            comment="",
                            service_group_id=(),
                            all_service_groups=True,
                            json=True,
                        )
                    ),
                    0,
                )
                acceptance_b_payload = json.loads(stdout.getvalue())
            with node_environment(node=node_b), mock.patch(
                "sys.stdin",
                io.StringIO(json.dumps(acceptance_b_payload)),
            ), redirect_stdout(io.StringIO()):
                self.assertEqual(
                    cmd_peer_import_acceptance(
                        args=argparse.Namespace(backend="sqlite", file=None),
                    ),
                    0,
                )
            self.assertEqual(
                peer_state(node=node_a, peer_node_id=str(request_b_payload["node_id"])),
                "active",
            )

            with node_environment(node=node_b), redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(
                    cmd_peer_accept(
                        args=argparse.Namespace(
                            backend="sqlite",
                            node_id=request_payload["node_id"],
                            comment="",
                            json=False,
                        )
                    ),
                    1,
                )
                self.assertIn("not pending", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
