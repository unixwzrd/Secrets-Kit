from __future__ import annotations

import unittest
from dataclasses import FrozenInstanceError

from secrets_kit.crypto.peer_models import (
    PEER_MODEL_VERSION,
    PeerAddress,
    PeerGroupMembership,
    PeerIdentity,
    PeerPublicKeys,
    peer_address_from_dict,
    peer_address_to_dict,
    peer_group_membership_from_dict,
    peer_group_membership_to_dict,
    peer_identity_from_dict,
    peer_identity_to_dict,
    peer_public_keys_from_dict,
    peer_public_keys_to_dict,
)
from secrets_kit.identifiers import deterministic_identifier

PEER_NODE_ID = deterministic_identifier(
    identifier_type="node", namespace="tests.crypto", name="peer-node-1"
)
PEER_GROUP_ID = deterministic_identifier(
    identifier_type="peer_group", namespace="tests.crypto", name="group-1"
)


class CryptoPeerModelsTest(unittest.TestCase):
    def test_peer_public_keys_round_trip(self) -> None:
        keys = PeerPublicKeys(
            signing_public_key=b"s" * 32,
            encryption_public_key=b"e" * 32,
        )

        payload = peer_public_keys_to_dict(keys=keys)

        self.assertEqual(payload["version"], PEER_MODEL_VERSION)
        self.assertEqual(peer_public_keys_from_dict(value=payload), keys)
        self.assertEqual(PeerPublicKeys.from_dict(keys.to_dict()), keys)

    def test_peer_public_keys_validation(self) -> None:
        with self.assertRaises(ValueError):
            PeerPublicKeys(signing_public_key=b"short", encryption_public_key=b"e" * 32)
        with self.assertRaises(ValueError):
            PeerPublicKeys(
                signing_public_key=b"s" * 32,
                encryption_public_key=b"short",
            )
        with self.assertRaises(ValueError):
            PeerPublicKeys(
                signing_public_key=b"s" * 32,
                encryption_public_key=b"e" * 32,
                signing_algorithm="rsa",
            )

    def test_peer_address_round_trip(self) -> None:
        address = PeerAddress(
            address_type="tcp",
            value="seckit.example:9443",
            label="primary",
            priority=10,
        )

        payload = peer_address_to_dict(address=address)

        self.assertEqual(peer_address_from_dict(value=payload), address)
        self.assertEqual(PeerAddress.from_dict(address.to_dict()), address)

    def test_peer_address_validation(self) -> None:
        with self.assertRaises(ValueError):
            PeerAddress(address_type="", value="endpoint")
        with self.assertRaises(ValueError):
            PeerAddress(address_type="tcp", value="")
        with self.assertRaises(ValueError):
            PeerAddress(address_type="tcp", value="endpoint", priority=-1)

    def test_peer_group_membership_round_trip(self) -> None:
        membership = PeerGroupMembership(
            group_id=PEER_GROUP_ID,
            role="member",
            joined_at="2026-06-13T00:00:00Z",
            active=True,
        )

        payload = peer_group_membership_to_dict(membership=membership)

        self.assertEqual(peer_group_membership_from_dict(value=payload), membership)
        self.assertEqual(PeerGroupMembership.from_dict(membership.to_dict()), membership)

    def test_peer_group_membership_validation(self) -> None:
        with self.assertRaises(ValueError):
            PeerGroupMembership(group_id="")
        with self.assertRaises(TypeError):
            PeerGroupMembership(group_id=PEER_GROUP_ID, active="yes")  # type: ignore[arg-type]

    def test_peer_identity_round_trip(self) -> None:
        identity = PeerIdentity(
            node_id=PEER_NODE_ID,
            public_keys=PeerPublicKeys(
                signing_public_key=b"s" * 32,
                encryption_public_key=b"e" * 32,
            ),
            addresses=(PeerAddress(address_type="uds", value="/tmp/seckit.sock"),),
            group_memberships=(PeerGroupMembership(group_id=PEER_GROUP_ID, role="member"),),
            descriptive_metadata={"display_name": "Peer One", "owner": "ops"},
        )

        payload = peer_identity_to_dict(identity=identity)

        self.assertEqual(payload["version"], PEER_MODEL_VERSION)
        self.assertEqual(peer_identity_from_dict(value=payload), identity)
        self.assertEqual(PeerIdentity.from_dict(identity.to_dict()), identity)
        self.assertEqual(
            identity.descriptive_metadata,
            (("display_name", "Peer One"), ("owner", "ops")),
        )

    def test_peer_identity_validation(self) -> None:
        keys = PeerPublicKeys(signing_public_key=b"s" * 32, encryption_public_key=b"e" * 32)

        with self.assertRaises(ValueError):
            PeerIdentity(node_id="", public_keys=keys)
        with self.assertRaises(TypeError):
            PeerIdentity(node_id=PEER_NODE_ID, public_keys="keys")  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            PeerIdentity(node_id=PEER_NODE_ID, public_keys=keys, addresses=("bad",))  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            PeerIdentity(
                node_id=PEER_NODE_ID,
                public_keys=keys,
                descriptive_metadata={"": "bad"},
            )

    def test_unsupported_version_rejected(self) -> None:
        keys = PeerPublicKeys(signing_public_key=b"s" * 32, encryption_public_key=b"e" * 32)
        payload = keys.to_dict()
        payload["version"] = 999

        with self.assertRaises(ValueError):
            PeerPublicKeys.from_dict(payload)

    def test_peer_models_are_immutable(self) -> None:
        identity = PeerIdentity(
            node_id=PEER_NODE_ID,
            public_keys=PeerPublicKeys(
                signing_public_key=b"s" * 32,
                encryption_public_key=b"e" * 32,
            ),
        )

        with self.assertRaises(FrozenInstanceError):
            identity.node_id = "other"  # type: ignore[misc]

    def test_peer_models_do_not_expose_runtime_behaviors(self) -> None:
        identity = PeerIdentity(
            node_id=PEER_NODE_ID,
            public_keys=PeerPublicKeys(
                signing_public_key=b"s" * 32,
                encryption_public_key=b"e" * 32,
            ),
        )

        for forbidden in ("connect", "discover", "trust", "sync", "route"):
            self.assertFalse(hasattr(identity, forbidden))


if __name__ == "__main__":
    unittest.main()
