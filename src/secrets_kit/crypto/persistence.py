"""
secrets_kit.crypto.persistence

Pure-Python persistence records for crypto model materialization.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

from secrets_kit.crypto.models import (
    EncryptionKeypair,
    KeyMetadata,
    NodeIdentity,
    SigningKeypair,
    deserialize_private_key,
    deserialize_public_key,
    node_identity_from_dict,
    node_identity_to_dict,
    serialize_private_key,
    serialize_public_key,
)
from secrets_kit.crypto.peer_models import (
    PeerIdentity,
    peer_identity_from_dict,
    peer_identity_to_dict,
)

PERSISTENCE_RECORD_VERSION: Final = 1
RECORD_TYPE_NODE_IDENTITY: Final = "node_identity"
RECORD_TYPE_SIGNING_KEYPAIR: Final = "signing_keypair"
RECORD_TYPE_ENCRYPTION_KEYPAIR: Final = "encryption_keypair"
RECORD_TYPE_PEER_IDENTITY: Final = "peer_identity"


def identity_to_record(*, identity: NodeIdentity) -> dict[str, object]:
    """Materialize a local node identity into a versioned persistence record."""
    if not isinstance(identity, NodeIdentity):
        raise TypeError("identity must be a NodeIdentity")
    return _build_record(
        record_type=RECORD_TYPE_NODE_IDENTITY,
        payload=node_identity_to_dict(identity=identity),
    )


def identity_from_record(*, record: Mapping[str, object]) -> NodeIdentity:
    """Rehydrate a local node identity from a versioned persistence record."""
    payload = _payload_from_record(record=record, expected_type=RECORD_TYPE_NODE_IDENTITY)
    return node_identity_from_dict(value=payload)


def signing_keypair_to_record(*, keypair: SigningKeypair) -> dict[str, object]:
    """Materialize an Ed25519 signing keypair into a persistence record."""
    if not isinstance(keypair, SigningKeypair):
        raise TypeError("keypair must be a SigningKeypair")
    return _build_record(
        record_type=RECORD_TYPE_SIGNING_KEYPAIR,
        payload=_keypair_to_payload(keypair=keypair),
    )


def signing_keypair_from_record(*, record: Mapping[str, object]) -> SigningKeypair:
    """Rehydrate an Ed25519 signing keypair from a persistence record."""
    payload = _payload_from_record(record=record, expected_type=RECORD_TYPE_SIGNING_KEYPAIR)
    metadata = _metadata_from_payload(payload=payload)
    private_algorithm, private_key = deserialize_private_key(
        _required_mapping(value=payload, field_name="private_key")
    )
    public_algorithm, public_key = deserialize_public_key(
        _required_mapping(value=payload, field_name="public_key")
    )
    if private_algorithm != metadata.algorithm or public_algorithm != metadata.algorithm:
        raise ValueError("keypair algorithms must match metadata")
    return SigningKeypair(metadata=metadata, private_key=private_key, public_key=public_key)


def encryption_keypair_to_record(*, keypair: EncryptionKeypair) -> dict[str, object]:
    """Materialize an X25519 encryption keypair into a persistence record."""
    if not isinstance(keypair, EncryptionKeypair):
        raise TypeError("keypair must be an EncryptionKeypair")
    return _build_record(
        record_type=RECORD_TYPE_ENCRYPTION_KEYPAIR,
        payload=_keypair_to_payload(keypair=keypair),
    )


def encryption_keypair_from_record(*, record: Mapping[str, object]) -> EncryptionKeypair:
    """Rehydrate an X25519 encryption keypair from a persistence record."""
    payload = _payload_from_record(record=record, expected_type=RECORD_TYPE_ENCRYPTION_KEYPAIR)
    metadata = _metadata_from_payload(payload=payload)
    private_algorithm, private_key = deserialize_private_key(
        _required_mapping(value=payload, field_name="private_key")
    )
    public_algorithm, public_key = deserialize_public_key(
        _required_mapping(value=payload, field_name="public_key")
    )
    if private_algorithm != metadata.algorithm or public_algorithm != metadata.algorithm:
        raise ValueError("keypair algorithms must match metadata")
    return EncryptionKeypair(metadata=metadata, private_key=private_key, public_key=public_key)


def peer_identity_to_record(*, identity: PeerIdentity) -> dict[str, object]:
    """Materialize remote peer identity metadata into a persistence record."""
    if not isinstance(identity, PeerIdentity):
        raise TypeError("identity must be a PeerIdentity")
    return _build_record(
        record_type=RECORD_TYPE_PEER_IDENTITY,
        payload=peer_identity_to_dict(identity=identity),
    )


def peer_identity_from_record(*, record: Mapping[str, object]) -> PeerIdentity:
    """Rehydrate remote peer identity metadata from a persistence record."""
    payload = _payload_from_record(record=record, expected_type=RECORD_TYPE_PEER_IDENTITY)
    return peer_identity_from_dict(value=payload)


def _build_record(*, record_type: str, payload: Mapping[str, object]) -> dict[str, object]:
    return {
        "payload": dict(payload),
        "record_type": record_type,
        "version": PERSISTENCE_RECORD_VERSION,
    }


def _keypair_to_payload(*, keypair: SigningKeypair | EncryptionKeypair) -> dict[str, object]:
    return {
        "metadata": {
            "active": keypair.metadata.active,
            "algorithm": keypair.metadata.algorithm,
            "created_at": keypair.metadata.created_at,
            "key_id": keypair.metadata.key_id,
        },
        "private_key": serialize_private_key(
            algorithm=keypair.metadata.algorithm,
            key=keypair.private_key,
        ),
        "public_key": serialize_public_key(
            algorithm=keypair.metadata.algorithm,
            key=keypair.public_key,
        ),
    }


def _payload_from_record(
    *,
    record: Mapping[str, object],
    expected_type: str,
) -> Mapping[str, object]:
    if not isinstance(record, Mapping):
        raise TypeError("record must be a mapping")
    version = record.get("version")
    if not isinstance(version, int) or isinstance(version, bool):
        raise ValueError("record version must be an integer")
    if version != PERSISTENCE_RECORD_VERSION:
        raise ValueError(f"unsupported persistence record version: {version}")
    record_type = record.get("record_type")
    if record_type != expected_type:
        raise ValueError(f"record_type must be {expected_type}")
    payload = record.get("payload")
    if not isinstance(payload, Mapping):
        raise ValueError("payload must be an object")
    return payload


def _metadata_from_payload(*, payload: Mapping[str, object]) -> KeyMetadata:
    metadata = _required_mapping(value=payload, field_name="metadata")
    active = metadata.get("active")
    if not isinstance(active, bool):
        raise ValueError("metadata active must be bool")
    return KeyMetadata(
        key_id=_required_string(value=metadata, field_name="key_id"),
        algorithm=_required_string(value=metadata, field_name="algorithm"),
        created_at=_required_string(value=metadata, field_name="created_at"),
        active=active,
    )


def _required_mapping(*, value: Mapping[str, object], field_name: str) -> Mapping[str, object]:
    field_value = value.get(field_name)
    if not isinstance(field_value, Mapping):
        raise ValueError(f"{field_name} is required")
    return field_value


def _required_string(*, value: Mapping[str, object], field_name: str) -> str:
    field_value = value.get(field_name)
    if not isinstance(field_value, str) or not field_value:
        raise ValueError(f"{field_name} is required")
    return field_value


__all__ = [
    "PERSISTENCE_RECORD_VERSION",
    "RECORD_TYPE_ENCRYPTION_KEYPAIR",
    "RECORD_TYPE_NODE_IDENTITY",
    "RECORD_TYPE_PEER_IDENTITY",
    "RECORD_TYPE_SIGNING_KEYPAIR",
    "encryption_keypair_from_record",
    "encryption_keypair_to_record",
    "identity_from_record",
    "identity_to_record",
    "peer_identity_from_record",
    "peer_identity_to_record",
    "signing_keypair_from_record",
    "signing_keypair_to_record",
]
