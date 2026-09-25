from __future__ import annotations

import unittest

from secrets_kit.crypto.peer_models import (
    PeerAddress,
    PeerGroupMembership,
    PeerIdentity,
    PeerPublicKeys,
)
from secrets_kit.crypto.peer_registry import PeerRegistry
from tests.canonical_id_helpers import tid

PEER_1_ID = tid("node", "peer-registry-peer-1")
PEER_2_ID = tid("node", "peer-registry-peer-2")
PEER_3_ID = tid("node", "peer-registry-peer-3")
MISSING_PEER_ID = tid("node", "peer-registry-missing")
GROUP_A_ID = tid("peer_group", "peer-registry-group-a")
GROUP_B_ID = tid("peer_group", "peer-registry-group-b")
OTHER_GROUP_ID = tid("peer_group", "peer-registry-other")


class CryptoPeerRegistryTest(unittest.TestCase):
    def test_add_peer(self) -> None:
        registry = PeerRegistry()
        peer = _peer(node_id=PEER_1_ID)

        registry.add_peer(peer=peer)

        self.assertEqual(registry.get_peer(node_id=PEER_1_ID), peer)

    def test_add_peer_rejects_duplicate_node_id(self) -> None:
        registry = PeerRegistry()
        registry.add_peer(peer=_peer(node_id=PEER_1_ID))

        with self.assertRaises(ValueError):
            registry.add_peer(peer=_peer(node_id=PEER_1_ID, group_id=OTHER_GROUP_ID))

    def test_update_peer(self) -> None:
        registry = PeerRegistry()
        original = _peer(node_id=PEER_1_ID, group_id=GROUP_A_ID)
        updated = _peer(node_id=PEER_1_ID, group_id=GROUP_B_ID, label="updated")
        registry.add_peer(peer=original)

        registry.update_peer(peer=updated)

        self.assertEqual(registry.get_peer(node_id=PEER_1_ID), updated)
        self.assertNotEqual(registry.get_peer(node_id=PEER_1_ID), original)

    def test_update_missing_peer_rejected(self) -> None:
        registry = PeerRegistry()

        with self.assertRaises(KeyError) as context:
            registry.update_peer(peer=_peer(node_id=MISSING_PEER_ID))
        self.assertEqual(context.exception.args, (MISSING_PEER_ID,))

    def test_remove_peer(self) -> None:
        registry = PeerRegistry()
        registry.add_peer(peer=_peer(node_id=PEER_1_ID))

        registry.remove_peer(node_id=PEER_1_ID)

        self.assertIsNone(registry.get_peer(node_id=PEER_1_ID))
        self.assertEqual(registry.list_peers(), ())

    def test_remove_missing_peer_rejected(self) -> None:
        registry = PeerRegistry()

        with self.assertRaises(KeyError) as context:
            registry.remove_peer(node_id=MISSING_PEER_ID)
        self.assertEqual(context.exception.args, (MISSING_PEER_ID,))

    def test_lookup_existing_peer(self) -> None:
        registry = PeerRegistry()
        peer = _peer(node_id=PEER_1_ID)
        registry.add_peer(peer=peer)

        self.assertIs(registry.get_peer(node_id=PEER_1_ID), peer)

    def test_lookup_missing_peer(self) -> None:
        registry = PeerRegistry()

        self.assertIsNone(registry.get_peer(node_id=MISSING_PEER_ID))

    def test_list_peers_returns_tuple_in_insertion_order(self) -> None:
        registry = PeerRegistry()
        peer_1 = _peer(node_id=PEER_1_ID)
        peer_2 = _peer(node_id=PEER_2_ID)
        registry.add_peer(peer=peer_1)
        registry.add_peer(peer=peer_2)

        peers = registry.list_peers()

        self.assertIsInstance(peers, tuple)
        self.assertEqual(peers, (peer_1, peer_2))

    def test_list_peers_by_group(self) -> None:
        registry = PeerRegistry()
        peer_1 = _peer(node_id=PEER_1_ID, group_id=GROUP_A_ID)
        peer_2 = _peer(node_id=PEER_2_ID, group_id=GROUP_B_ID)
        peer_3 = _peer(node_id=PEER_3_ID, group_id=GROUP_A_ID)
        registry.add_peer(peer=peer_1)
        registry.add_peer(peer=peer_2)
        registry.add_peer(peer=peer_3)

        peers = registry.list_peers_by_group(group_name=GROUP_A_ID)

        self.assertIsInstance(peers, tuple)
        self.assertEqual(peers, (peer_1, peer_3))

    def test_list_peers_by_group_returns_empty_tuple_when_no_match(self) -> None:
        registry = PeerRegistry()
        registry.add_peer(peer=_peer(node_id=PEER_1_ID, group_id=GROUP_A_ID))

        self.assertEqual(registry.list_peers_by_group(group_name=GROUP_B_ID), ())

    def test_empty_registry_behavior(self) -> None:
        registry = PeerRegistry()

        self.assertEqual(registry.list_peers(), ())
        self.assertEqual(registry.list_peers_by_group(group_name=GROUP_A_ID), ())
        self.assertIsNone(registry.get_peer(node_id=PEER_1_ID))

    def test_registry_rejects_invalid_inputs(self) -> None:
        registry = PeerRegistry()

        with self.assertRaises(TypeError):
            registry.add_peer(peer="not-a-peer")  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            registry.get_peer(node_id="")
        with self.assertRaises(ValueError):
            registry.list_peers_by_group(group_name="")


def _peer(
    *,
    node_id: str,
    group_id: str = GROUP_A_ID,
    label: str = "primary",
) -> PeerIdentity:
    return PeerIdentity(
        node_id=node_id,
        public_keys=PeerPublicKeys(
            signing_public_key=b"s" * 32,
            encryption_public_key=b"e" * 32,
        ),
        addresses=(PeerAddress(address_type="tcp", value=f"{node_id}.example:9443", label=label),),
        group_memberships=(PeerGroupMembership(group_id=group_id, role="member"),),
    )


if __name__ == "__main__":
    unittest.main()
