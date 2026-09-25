"""
tests.test_runtime_transport_identity

Verify runtime ownership of signed ephemeral transport identity bindings.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from secrets_kit.backends.sqlite import accept_peer_admission, request_peer_admission
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


class RuntimeTransportIdentityTests(unittest.TestCase):
    """Exercise binding signatures without exposing transport types to runtime code."""

    def test_admitted_peer_binding_verifies_and_preserves_opaque_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            left, right = self._nodes(root=Path(tmp))
            self._admit(source=left, destination=right)
            challenge = "a" * 64
            with node_environment(node=left):
                claim = sign_transport_binding(
                    challenge=challenge,
                    transport_identity="12D3KooWAuthenticatedConnection",
                )
            with node_environment(node=right):
                verified = verify_transport_binding(
                    claim=claim,
                    expected_challenge=challenge,
                    expected_transport_identity="12D3KooWAuthenticatedConnection",
                )
            self.assertEqual(verified, claim["node_id"])

    def test_forged_mismatched_replayed_and_unknown_bindings_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            left, right = self._nodes(root=Path(tmp))
            challenge = "b" * 64
            with node_environment(node=left):
                claim = sign_transport_binding(
                    challenge=challenge,
                    transport_identity="transport-peer-left",
                )
            with node_environment(node=right):
                with self.assertRaisesRegex(TransportIdentityError, "not admitted"):
                    verify_transport_binding(
                        claim=claim,
                        expected_challenge=challenge,
                        expected_transport_identity="transport-peer-left",
                    )

            self._admit(source=left, destination=right)
            with node_environment(node=right):
                with self.assertRaisesRegex(TransportIdentityError, "challenge"):
                    verify_transport_binding(
                        claim=claim,
                        expected_challenge="c" * 64,
                        expected_transport_identity="transport-peer-left",
                    )
                with self.assertRaisesRegex(TransportIdentityError, "identity"):
                    verify_transport_binding(
                        claim=claim,
                        expected_challenge=challenge,
                        expected_transport_identity="transport-peer-other",
                    )
                forged = dict(claim)
                forged["signature"] = "A" * 86
                with self.assertRaises(TransportIdentityError):
                    verify_transport_binding(
                        claim=forged,
                        expected_challenge=challenge,
                        expected_transport_identity="transport-peer-left",
                    )

    def _nodes(self, *, root: Path):
        left = make_node(root=root, name="left")
        right = make_node(root=root, name="right")
        provision_node(node=left)
        provision_node(node=right)
        return left, right

    def _admit(self, *, source, destination) -> None:
        request = peer_request_transaction(source=source)
        with node_environment(node=destination):
            request_peer_admission(signed_request=request.payload)
            accept_peer_admission(node_id=str(request.payload["node_id"]))


if __name__ == "__main__":
    unittest.main()
