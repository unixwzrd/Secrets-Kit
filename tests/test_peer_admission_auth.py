from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from secrets_kit.backends.sqlite.exceptions import SQLiteValidationError
from secrets_kit.backends.sqlite.gate import open_sqlite_backend
from secrets_kit.backends.sqlite.node_identity import load_sqlite_node_identity_material
from secrets_kit.backends.sqlite.peer_admission import (
    PEER_ADMISSION_ACCEPT,
    create_signed_peer_admission_decision,
)
from secrets_kit.backends.sqlite.peer_admission_auth import (
    admission_decision_signing_bytes,
    admission_request_signing_bytes,
    verify_admission_decision_payload,
    verify_admission_request_payload,
)
from secrets_kit.crypto.codecs import encode_b64url
from secrets_kit.crypto.signatures import sign_ed25519
from tests.canonical_id_helpers import tid
from tests.local_peer_lab import (
    inject_transaction,
    make_node,
    node_environment,
    peer_request_transaction,
    provision_node,
)

TAMPERED_NODE_ID = tid("node", "tampered-auth-node")
TAMPERED_REQUEST_ID = tid("transaction", "tampered-auth-request")


class PeerAdmissionAuthTest(unittest.TestCase):
    def test_valid_request_and_acceptance_signatures_verify(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            node_a = make_node(root=root, name="node-a")
            node_b = make_node(root=root, name="node-b")
            provision_node(node=node_a)
            provision_node(node=node_b)
            request = peer_request_transaction(source=node_a)
            verify_admission_request_payload(payload=request.payload)
            inject_transaction(node=node_b, transaction=request)
            with node_environment(node=node_b):
                decision = create_signed_peer_admission_decision(
                    proof_type=PEER_ADMISSION_ACCEPT,
                    node_id=str(request.payload["node_id"]),
                    request_id=str(request.payload["request_id"]),
                )
                conn = open_sqlite_backend()
                try:
                    verify_admission_decision_payload(conn=conn, payload=decision.payload)
                finally:
                    conn.close()

    def test_request_signed_fields_are_bound_to_signature(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            node_a = make_node(root=root, name="node-a")
            node_b = make_node(root=root, name="node-b")
            provision_node(node=node_a)
            provision_node(node=node_b)
            payload = peer_request_transaction(source=node_a).payload
            tamper_cases = {
                "node_id": TAMPERED_NODE_ID,
                "signing_public_key": peer_request_transaction(source=node_b).payload[
                    "signing_public_key"
                ],
                "encryption_public_key": peer_request_transaction(source=node_b).payload[
                    "encryption_public_key"
                ],
                "signing_algorithm": "ed448",
                "encryption_algorithm": "x448",
                "request_id": TAMPERED_REQUEST_ID,
                "nonce": "changed",
                "created_at": "2026-07-11T00:00:00Z",
            }
            for field_name, value in tamper_cases.items():
                with self.subTest(field_name=field_name):
                    tampered = dict(payload)
                    tampered[field_name] = value
                    with self.assertRaises(SQLiteValidationError):
                        verify_admission_request_payload(payload=tampered)

    def test_wrong_private_key_and_malformed_signature_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            node_a = make_node(root=root, name="node-a")
            node_b = make_node(root=root, name="node-b")
            provision_node(node=node_a)
            provision_node(node=node_b)
            payload = dict(peer_request_transaction(source=node_a).payload)
            with node_environment(node=node_b):
                conn = open_sqlite_backend()
                try:
                    wrong_identity = load_sqlite_node_identity_material(conn=conn)
                finally:
                    conn.close()
            payload["signature"] = encode_b64url(
                sign_ed25519(
                    private_key=wrong_identity.signing.private_key,
                    message=admission_request_signing_bytes(payload=payload),
                )
            )
            with self.assertRaisesRegex(SQLiteValidationError, "signature verification failed"):
                verify_admission_request_payload(payload=payload)

            malformed = dict(peer_request_transaction(source=node_a).payload)
            malformed["signature"] = "not-base64"
            with self.assertRaises(SQLiteValidationError):
                verify_admission_request_payload(payload=malformed)

    def test_acceptance_signed_fields_are_bound_to_signature(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            node_a = make_node(root=root, name="node-a")
            node_b = make_node(root=root, name="node-b")
            provision_node(node=node_a)
            provision_node(node=node_b)
            request = peer_request_transaction(source=node_a)
            inject_transaction(node=node_b, transaction=request)
            with node_environment(node=node_b):
                decision = create_signed_peer_admission_decision(
                    proof_type=PEER_ADMISSION_ACCEPT,
                    node_id=str(request.payload["node_id"]),
                    request_id=str(request.payload["request_id"]),
                )
                conn = open_sqlite_backend()
                try:
                    for field_name, value in {
                        "node_id": "node:changed",
                        "request_id": "admission-request:changed",
                        "nonce": "changed",
                        "decided_at": "2026-07-11T00:00:00Z",
                    }.items():
                        with self.subTest(field_name=field_name):
                            tampered = dict(decision.payload)
                            tampered[field_name] = value
                            with self.assertRaises(SQLiteValidationError):
                                verify_admission_decision_payload(conn=conn, payload=tampered)

                finally:
                    conn.close()
            wrong_key = dict(decision.payload)
            with node_environment(node=node_a):
                conn = open_sqlite_backend()
                try:
                    wrong_identity = load_sqlite_node_identity_material(conn=conn)
                finally:
                    conn.close()
            wrong_key["signature"] = encode_b64url(
                sign_ed25519(
                    private_key=wrong_identity.signing.private_key,
                    message=admission_decision_signing_bytes(payload=wrong_key),
                )
            )
            with node_environment(node=node_b):
                conn = open_sqlite_backend()
                try:
                    with self.assertRaisesRegex(
                        SQLiteValidationError,
                        "signature verification failed",
                    ):
                        verify_admission_decision_payload(conn=conn, payload=wrong_key)
                finally:
                    conn.close()


if __name__ == "__main__":
    unittest.main()
