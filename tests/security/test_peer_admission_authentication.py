"""
tests.security.test_peer_admission_authentication

Security regressions for authenticated peer admission.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tests.local_peer_lab import (
    inject_transaction,
    make_node,
    node_environment,
    peer_request_transaction,
    provision_node,
    transaction_envelope,
)

from secrets_kit.backends.sqlite import get_transaction, open_sqlite_backend
from secrets_kit.backends.sqlite.node_identity import load_sqlite_node_identity_material
from secrets_kit.crypto.codecs import encode_b64url


class PeerAdmissionAuthenticationSecurityTest(unittest.TestCase):
    def test_private_identity_material_is_not_serialized_in_admission_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            node_a = make_node(root=root, name="node-a")
            node_b = make_node(root=root, name="node-b")
            provision_node(node=node_a)
            provision_node(node=node_b)
            request = peer_request_transaction(source=node_a)
            inject_transaction(node=node_b, transaction=request)

            with node_environment(node=node_a):
                conn = open_sqlite_backend()
                try:
                    identity = load_sqlite_node_identity_material(conn=conn)
                finally:
                    conn.close()

            serialized_request = json.dumps(request.payload, sort_keys=True)
            serialized_envelope = json.dumps(transaction_envelope(transaction=request), sort_keys=True)
            with node_environment(node=node_b):
                conn = open_sqlite_backend()
                try:
                    persisted = get_transaction(conn=conn, transaction_id=request.transaction_id)
                finally:
                    conn.close()
            serialized_persisted = json.dumps(persisted.payload, sort_keys=True)

            private_fragments = [
                identity.signing.private_key.hex(),
                identity.encryption.private_key.hex(),
                encode_b64url(identity.signing.private_key),
                encode_b64url(identity.encryption.private_key),
            ]
            for fragment in private_fragments:
                self.assertNotIn(fragment, serialized_request)
                self.assertNotIn(fragment, serialized_envelope)
                self.assertNotIn(fragment, serialized_persisted)

    def test_nodes_do_not_share_storage_or_identity_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            node_a = make_node(root=root, name="node-a")
            node_b = make_node(root=root, name="node-b")
            provision_node(node=node_a)
            provision_node(node=node_b)

            self.assertNotEqual(node_a.sqlite_path, node_b.sqlite_path)
            self.assertNotEqual(node_a.identity_key_path, node_b.identity_key_path)
            self.assertNotIn("SECKIT_SQLITE_STORAGE_KEY_PATH", node_a.env)
            self.assertNotIn("SECKIT_SQLITE_STORAGE_KEY_PATH", node_b.env)


if __name__ == "__main__":
    unittest.main()
