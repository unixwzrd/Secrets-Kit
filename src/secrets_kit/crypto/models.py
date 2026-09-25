"""
secrets_kit.crypto.models

Standalone identity and key-material models.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Mapping

from secrets_kit.crypto.canonical import canonical_json_bytes
from secrets_kit.crypto.codecs import decode_b64url, encode_b64url
from secrets_kit.crypto.hashing import sha256_hex
from secrets_kit.crypto.keys import generate_x25519_keypair
from secrets_kit.crypto.signatures import generate_ed25519_keypair
from secrets_kit.identifiers import validate_identifier

KEY_SERIALIZATION_VERSION = 1
ALGORITHM_ED25519 = "ed25519"
ALGORITHM_X25519 = "x25519"
SUPPORTED_KEY_ALGORITHMS = frozenset({ALGORITHM_ED25519, ALGORITHM_X25519})
_RAW_KEY_SIZE_BY_ALGORITHM = {
    ALGORITHM_ED25519: 32,
    ALGORITHM_X25519: 32,
}

KeyAlgorithm = Literal["ed25519", "x25519"]


@dataclass(frozen=True)
class KeyMetadata:
    key_id: str
    algorithm: str
    created_at: str
    active: bool

    def __post_init__(self) -> None:
        if not isinstance(self.key_id, str) or not self.key_id:
            raise ValueError("key_id is required")
        _validate_algorithm(algorithm=self.algorithm)
        if not isinstance(self.created_at, str) or not self.created_at:
            raise ValueError("created_at is required")
        if not isinstance(self.active, bool):
            raise TypeError("active must be bool")


@dataclass(frozen=True)
class SigningKeypair:
    metadata: KeyMetadata
    private_key: bytes
    public_key: bytes

    def __post_init__(self) -> None:
        if self.metadata.algorithm != ALGORITHM_ED25519:
            raise ValueError("signing keypair algorithm must be ed25519")
        _validate_key_bytes(algorithm=ALGORITHM_ED25519, key=self.private_key, field_name="private_key")
        _validate_key_bytes(algorithm=ALGORITHM_ED25519, key=self.public_key, field_name="public_key")
        _validate_key_id(metadata=self.metadata, public_key=self.public_key)


@dataclass(frozen=True)
class EncryptionKeypair:
    metadata: KeyMetadata
    private_key: bytes
    public_key: bytes

    def __post_init__(self) -> None:
        if self.metadata.algorithm != ALGORITHM_X25519:
            raise ValueError("encryption keypair algorithm must be x25519")
        _validate_key_bytes(algorithm=ALGORITHM_X25519, key=self.private_key, field_name="private_key")
        _validate_key_bytes(algorithm=ALGORITHM_X25519, key=self.public_key, field_name="public_key")
        _validate_key_id(metadata=self.metadata, public_key=self.public_key)


@dataclass(frozen=True)
class NodeIdentity:
    node_id: str
    signing: SigningKeypair
    encryption: EncryptionKeypair

    def __post_init__(self) -> None:
        if not isinstance(self.node_id, str) or not self.node_id:
            raise ValueError("node_id is required")
        if not isinstance(self.signing, SigningKeypair):
            raise TypeError("signing must be a SigningKeypair")
        if not isinstance(self.encryption, EncryptionKeypair):
            raise TypeError("encryption must be an EncryptionKeypair")

    def to_dict(self) -> dict[str, object]:
        """
        Serialize node identity key material into a pure-Python dictionary.

        The payload is versioned and generic. It has no SQLite, daemon, keyring,
        keychain, or network assumptions.
        """
        return node_identity_to_dict(identity=self)

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> NodeIdentity:
        """
        Deserialize node identity key material from a pure-Python dictionary.

        The returned object is the authoritative crypto model ``NodeIdentity``.
        """
        return node_identity_from_dict(value=value)


def generate_signing_keypair() -> SigningKeypair:
    """Generate Ed25519 signing key material."""
    private_key, public_key = generate_ed25519_keypair()
    return SigningKeypair(
        metadata=_metadata_for_public_key(algorithm=ALGORITHM_ED25519, public_key=public_key),
        private_key=private_key,
        public_key=public_key,
    )


def generate_encryption_keypair() -> EncryptionKeypair:
    """Generate X25519 encryption key-agreement material."""
    private_key, public_key = generate_x25519_keypair()
    return EncryptionKeypair(
        metadata=_metadata_for_public_key(algorithm=ALGORITHM_X25519, public_key=public_key),
        private_key=private_key,
        public_key=public_key,
    )


def generate_node_identity(node_id: str) -> NodeIdentity:
    """Generate standalone node identity key material."""
    validate_identifier(value=node_id, expected_type="node", field="node_id")
    return NodeIdentity(
        node_id=node_id,
        signing=generate_signing_keypair(),
        encryption=generate_encryption_keypair(),
    )


def node_identity_to_dict(*, identity: NodeIdentity) -> dict[str, object]:
    """Serialize authoritative node identity key material."""
    if not isinstance(identity, NodeIdentity):
        raise TypeError("identity must be a NodeIdentity")
    return {
        "encryption": _keypair_to_dict(keypair=identity.encryption),
        "node_id": identity.node_id,
        "signing": _keypair_to_dict(keypair=identity.signing),
        "version": KEY_SERIALIZATION_VERSION,
    }


def node_identity_from_dict(*, value: Mapping[str, object]) -> NodeIdentity:
    """Deserialize authoritative node identity key material."""
    version = value.get("version")
    if not isinstance(version, int) or isinstance(version, bool):
        raise ValueError("node identity version must be an integer")
    if version != KEY_SERIALIZATION_VERSION:
        raise ValueError(f"unsupported node identity version: {version}")
    node_id = _required_string(value=value, field_name="node_id")
    signing_payload = _required_mapping(value=value, field_name="signing")
    encryption_payload = _required_mapping(value=value, field_name="encryption")
    return NodeIdentity(
        node_id=node_id,
        signing=_signing_keypair_from_dict(value=signing_payload),
        encryption=_encryption_keypair_from_dict(value=encryption_payload),
    )


def serialize_public_key(*, algorithm: str, key: bytes) -> dict[str, object]:
    """Serialize a raw public key into a versioned pure-Python payload."""
    return _serialize_key(algorithm=algorithm, key=key)


def deserialize_public_key(value: Mapping[str, object]) -> tuple[str, bytes]:
    """Deserialize a versioned public-key payload into ``(algorithm, key)``."""
    return _deserialize_key(value=value)


def serialize_private_key(*, algorithm: str, key: bytes) -> dict[str, object]:
    """Serialize a raw private key into a versioned pure-Python payload."""
    return _serialize_key(algorithm=algorithm, key=key)


def deserialize_private_key(value: Mapping[str, object]) -> tuple[str, bytes]:
    """Deserialize a versioned private-key payload into ``(algorithm, key)``."""
    return _deserialize_key(value=value)


def key_id_for_public_key(*, algorithm: str, public_key: bytes) -> str:
    """Return the deterministic key id for an algorithm/public-key pair."""
    _validate_key_bytes(algorithm=algorithm, key=public_key, field_name="public_key")
    return sha256_hex(
        canonical_json_bytes(
            {
                "algorithm": algorithm,
                "public_key": encode_b64url(public_key),
                "version": KEY_SERIALIZATION_VERSION,
            }
        )
    )


def _metadata_for_public_key(*, algorithm: KeyAlgorithm, public_key: bytes) -> KeyMetadata:
    return KeyMetadata(
        key_id=key_id_for_public_key(algorithm=algorithm, public_key=public_key),
        algorithm=algorithm,
        created_at=_now_utc_iso(),
        active=True,
    )


def _serialize_key(*, algorithm: str, key: bytes) -> dict[str, object]:
    _validate_key_bytes(algorithm=algorithm, key=key, field_name="key")
    return {
        "algorithm": algorithm,
        "key": encode_b64url(key),
        "version": KEY_SERIALIZATION_VERSION,
    }


def _deserialize_key(*, value: Mapping[str, object]) -> tuple[str, bytes]:
    version = value.get("version")
    if not isinstance(version, int) or isinstance(version, bool):
        raise ValueError("key serialization version must be an integer")
    if version != KEY_SERIALIZATION_VERSION:
        raise ValueError(f"unsupported key serialization version: {version}")
    algorithm = value.get("algorithm")
    if not isinstance(algorithm, str):
        raise ValueError("algorithm is required")
    encoded_key = value.get("key")
    if not isinstance(encoded_key, str) or not encoded_key:
        raise ValueError("key is required")
    key = decode_b64url(encoded_key)
    _validate_key_bytes(algorithm=algorithm, key=key, field_name="key")
    return algorithm, key


def _keypair_to_dict(*, keypair: SigningKeypair | EncryptionKeypair) -> dict[str, object]:
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


def _signing_keypair_from_dict(*, value: Mapping[str, object]) -> SigningKeypair:
    metadata = _metadata_from_dict(value=_required_mapping(value=value, field_name="metadata"))
    algorithm, private_key = deserialize_private_key(
        _required_mapping(value=value, field_name="private_key")
    )
    public_algorithm, public_key = deserialize_public_key(
        _required_mapping(value=value, field_name="public_key")
    )
    if algorithm != ALGORITHM_ED25519 or public_algorithm != ALGORITHM_ED25519:
        raise ValueError("signing identity keys must use ed25519")
    return SigningKeypair(metadata=metadata, private_key=private_key, public_key=public_key)


def _encryption_keypair_from_dict(*, value: Mapping[str, object]) -> EncryptionKeypair:
    metadata = _metadata_from_dict(value=_required_mapping(value=value, field_name="metadata"))
    algorithm, private_key = deserialize_private_key(
        _required_mapping(value=value, field_name="private_key")
    )
    public_algorithm, public_key = deserialize_public_key(
        _required_mapping(value=value, field_name="public_key")
    )
    if algorithm != ALGORITHM_X25519 or public_algorithm != ALGORITHM_X25519:
        raise ValueError("encryption identity keys must use x25519")
    return EncryptionKeypair(metadata=metadata, private_key=private_key, public_key=public_key)


def _metadata_from_dict(*, value: Mapping[str, object]) -> KeyMetadata:
    active = value.get("active")
    if not isinstance(active, bool):
        raise ValueError("metadata active must be bool")
    return KeyMetadata(
        key_id=_required_string(value=value, field_name="key_id"),
        algorithm=_required_string(value=value, field_name="algorithm"),
        created_at=_required_string(value=value, field_name="created_at"),
        active=active,
    )


def _validate_algorithm(*, algorithm: str) -> None:
    if algorithm not in SUPPORTED_KEY_ALGORITHMS:
        raise ValueError(f"unsupported key algorithm: {algorithm}")


def _validate_key_bytes(*, algorithm: str, key: bytes, field_name: str) -> None:
    _validate_algorithm(algorithm=algorithm)
    expected_size = _RAW_KEY_SIZE_BY_ALGORITHM[algorithm]
    if not isinstance(key, bytes) or len(key) != expected_size:
        raise ValueError(f"{field_name} must be {expected_size} raw bytes for {algorithm}")


def _validate_key_id(*, metadata: KeyMetadata, public_key: bytes) -> None:
    expected_key_id = key_id_for_public_key(
        algorithm=metadata.algorithm,
        public_key=public_key,
    )
    if metadata.key_id != expected_key_id:
        raise ValueError("metadata key_id does not match public key")


def _now_utc_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _required_string(*, value: Mapping[str, object], field_name: str) -> str:
    field_value = value.get(field_name)
    if not isinstance(field_value, str) or not field_value:
        raise ValueError(f"{field_name} is required")
    return field_value


def _required_mapping(*, value: Mapping[str, object], field_name: str) -> Mapping[str, object]:
    field_value = value.get(field_name)
    if not isinstance(field_value, Mapping):
        raise ValueError(f"{field_name} is required")
    return field_value


__all__ = [
    "ALGORITHM_ED25519",
    "ALGORITHM_X25519",
    "KEY_SERIALIZATION_VERSION",
    "SUPPORTED_KEY_ALGORITHMS",
    "EncryptionKeypair",
    "KeyMetadata",
    "NodeIdentity",
    "SigningKeypair",
    "node_identity_from_dict",
    "node_identity_to_dict",
    "deserialize_private_key",
    "deserialize_public_key",
    "generate_encryption_keypair",
    "generate_node_identity",
    "generate_signing_keypair",
    "key_id_for_public_key",
    "serialize_private_key",
    "serialize_public_key",
]
