from __future__ import annotations

import unittest
from collections.abc import Mapping, Sequence

from secrets_kit.crypto.models import (
    generate_encryption_keypair,
    generate_node_identity,
    generate_signing_keypair,
)
from secrets_kit.crypto.peer_models import (
    PeerAddress,
    PeerGroupMembership,
    PeerIdentity,
    PeerPublicKeys,
)
from secrets_kit.crypto.persistence import (
    PERSISTENCE_RECORD_VERSION,
    RECORD_TYPE_NODE_IDENTITY,
    RECORD_TYPE_PEER_IDENTITY,
    encryption_keypair_from_record,
    encryption_keypair_to_record,
    identity_from_record,
    identity_to_record,
    peer_identity_from_record,
    peer_identity_to_record,
    signing_keypair_from_record,
    signing_keypair_to_record,
)
from secrets_kit.identifiers import deterministic_identifier

LOCAL_NODE_ID = deterministic_identifier(
    identifier_type="node", namespace="tests.crypto", name="local-node-1"
)
PEER_NODE_ID = deterministic_identifier(
    identifier_type="node", namespace="tests.crypto", name="peer-node-1"
)
PEER_GROUP_ID = deterministic_identifier(
    identifier_type="peer_group", namespace="tests.crypto", name="group-1"
)


class CryptoPersistenceTest(unittest.TestCase):
    def test_node_identity_record_round_trip(self) -> None:
        identity = generate_node_identity(node_id=LOCAL_NODE_ID)

        record = identity_to_record(identity=identity)

        self.assertEqual(record["version"], PERSISTENCE_RECORD_VERSION)
        self.assertEqual(record["record_type"], RECORD_TYPE_NODE_IDENTITY)
        _assert_storage_safe(record)
        self.assertEqual(identity_from_record(record=record), identity)

    def test_signing_keypair_record_round_trip(self) -> None:
        keypair = generate_signing_keypair()

        record = signing_keypair_to_record(keypair=keypair)

        _assert_storage_safe(record)
        self.assertEqual(signing_keypair_from_record(record=record), keypair)

    def test_encryption_keypair_record_round_trip(self) -> None:
        keypair = generate_encryption_keypair()

        record = encryption_keypair_to_record(keypair=keypair)

        _assert_storage_safe(record)
        self.assertEqual(encryption_keypair_from_record(record=record), keypair)

    def test_peer_identity_record_round_trip_includes_nested_peer_models(self) -> None:
        identity = PeerIdentity(
            node_id=PEER_NODE_ID,
            public_keys=PeerPublicKeys(
                signing_public_key=b"s" * 32,
                encryption_public_key=b"e" * 32,
            ),
            addresses=(
                PeerAddress(
                    address_type="tcp",
                    value="peer.example:9443",
                    label="primary",
                    priority=10,
                ),
            ),
            group_memberships=(
                PeerGroupMembership(
                    group_id=PEER_GROUP_ID,
                    role="member",
                    joined_at="2026-06-13T00:00:00Z",
                    active=True,
                ),
            ),
            descriptive_metadata={"display_name": "Peer One"},
        )

        record = peer_identity_to_record(identity=identity)

        self.assertEqual(record["version"], PERSISTENCE_RECORD_VERSION)
        self.assertEqual(record["record_type"], RECORD_TYPE_PEER_IDENTITY)
        _assert_storage_safe(record)
        self.assertEqual(peer_identity_from_record(record=record), identity)

    def test_to_record_rejects_wrong_model_type(self) -> None:
        with self.assertRaises(TypeError):
            identity_to_record(identity="not-an-identity")  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            signing_keypair_to_record(keypair="not-a-keypair")  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            encryption_keypair_to_record(keypair="not-a-keypair")  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            peer_identity_to_record(identity="not-a-peer")  # type: ignore[arg-type]

    def test_from_record_rejects_missing_payload(self) -> None:
        record: dict[str, object] = {
            "record_type": RECORD_TYPE_NODE_IDENTITY,
            "version": PERSISTENCE_RECORD_VERSION,
        }

        with self.assertRaises(ValueError):
            identity_from_record(record=record)

    def test_from_record_rejects_wrong_record_type(self) -> None:
        identity = generate_node_identity(node_id=LOCAL_NODE_ID)
        record = identity_to_record(identity=identity)
        record["record_type"] = "other"

        with self.assertRaises(ValueError):
            identity_from_record(record=record)

    def test_from_record_rejects_unsupported_version(self) -> None:
        identity = generate_node_identity(node_id=LOCAL_NODE_ID)
        record = identity_to_record(identity=identity)
        record["version"] = 999

        with self.assertRaises(ValueError):
            identity_from_record(record=record)

    def test_from_record_rejects_bool_version(self) -> None:
        identity = generate_node_identity(node_id=LOCAL_NODE_ID)
        record = identity_to_record(identity=identity)
        record["version"] = True

        with self.assertRaises(ValueError):
            identity_from_record(record=record)

    def test_invalid_keypair_payload_is_rejected(self) -> None:
        keypair = generate_signing_keypair()
        record = signing_keypair_to_record(keypair=keypair)
        payload = record["payload"]
        if not isinstance(payload, dict):
            self.fail("payload must be a dictionary")
        metadata = payload["metadata"]
        if not isinstance(metadata, dict):
            self.fail("metadata must be a dictionary")
        metadata["algorithm"] = "x25519"

        with self.assertRaises(ValueError):
            signing_keypair_from_record(record=record)


def _assert_storage_safe(value: object) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise AssertionError(f"storage record key is not str: {key!r}")
            _assert_storage_safe(item)
        return
    if isinstance(value, list):
        for item in value:
            _assert_storage_safe(item)
        return
    if isinstance(value, tuple):
        raise AssertionError(f"storage record contains tuple: {value!r}")
    if isinstance(value, Sequence) and not isinstance(value, str):
        raise AssertionError(f"storage record contains unsupported sequence: {value!r}")
    if not isinstance(value, (str, int, bool)):
        raise AssertionError(f"storage record contains unsupported value: {value!r}")


if __name__ == "__main__":
    unittest.main()
