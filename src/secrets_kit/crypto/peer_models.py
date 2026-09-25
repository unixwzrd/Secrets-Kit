"""
secrets_kit.crypto.peer_models

Standalone metadata models for remote peer identities.

These dataclasses only represent information known about remote peers. They do
not perform trust decisions, discovery, networking, daemon coordination,
runtime state management, or persistence.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from secrets_kit.crypto.codecs import decode_b64url, encode_b64url
from secrets_kit.crypto.models import ALGORITHM_ED25519, ALGORITHM_X25519
from secrets_kit.identifiers import IdentifierValidationError, validate_identifier

PEER_MODEL_VERSION = 1
_PUBLIC_KEY_SIZE = 32


@dataclass(frozen=True)
class PeerPublicKeys:
    signing_public_key: bytes
    encryption_public_key: bytes
    signing_algorithm: str = ALGORITHM_ED25519
    encryption_algorithm: str = ALGORITHM_X25519

    def __post_init__(self) -> None:
        _validate_algorithm(
            algorithm=self.signing_algorithm,
            expected=ALGORITHM_ED25519,
            field_name="signing_algorithm",
        )
        _validate_algorithm(
            algorithm=self.encryption_algorithm,
            expected=ALGORITHM_X25519,
            field_name="encryption_algorithm",
        )
        _validate_public_key(value=self.signing_public_key, field_name="signing_public_key")
        _validate_public_key(value=self.encryption_public_key, field_name="encryption_public_key")

    def to_dict(self) -> dict[str, object]:
        """Serialize peer public keys into a versioned pure-Python payload."""
        return peer_public_keys_to_dict(keys=self)

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> PeerPublicKeys:
        """Deserialize peer public keys from a versioned pure-Python payload."""
        return peer_public_keys_from_dict(value=value)


@dataclass(frozen=True)
class PeerAddress:
    address_type: str
    value: str
    label: str = ""
    priority: int = 0

    def __post_init__(self) -> None:
        _validate_required_text(value=self.address_type, field_name="address_type")
        _validate_required_text(value=self.value, field_name="value")
        _validate_optional_text(value=self.label, field_name="label")
        if not isinstance(self.priority, int) or isinstance(self.priority, bool) or self.priority < 0:
            raise ValueError("priority must be a non-negative integer")

    def to_dict(self) -> dict[str, object]:
        """Serialize peer address metadata into a versioned pure-Python payload."""
        return peer_address_to_dict(address=self)

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> PeerAddress:
        """Deserialize peer address metadata from a versioned pure-Python payload."""
        return peer_address_from_dict(value=value)


@dataclass(frozen=True)
class PeerGroupMembership:
    group_id: str
    role: str = ""
    joined_at: str = ""
    active: bool = True

    def __post_init__(self) -> None:
        _validate_canonical_identifier(
            value=self.group_id,
            expected_type="peer_group",
            field_name="group_id",
        )
        _validate_optional_text(value=self.role, field_name="role")
        _validate_optional_text(value=self.joined_at, field_name="joined_at")
        if not isinstance(self.active, bool):
            raise TypeError("active must be bool")

    def to_dict(self) -> dict[str, object]:
        """Serialize peer group membership into a versioned pure-Python payload."""
        return peer_group_membership_to_dict(membership=self)

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> PeerGroupMembership:
        """Deserialize peer group membership from a versioned pure-Python payload."""
        return peer_group_membership_from_dict(value=value)


@dataclass(frozen=True)
class PeerIdentity:
    node_id: str
    public_keys: PeerPublicKeys
    addresses: tuple[PeerAddress, ...] = ()
    group_memberships: tuple[PeerGroupMembership, ...] = ()
    descriptive_metadata: tuple[tuple[str, str], ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        _validate_canonical_identifier(
            value=self.node_id,
            expected_type="node",
            field_name="node_id",
        )
        if not isinstance(self.public_keys, PeerPublicKeys):
            raise TypeError("public_keys must be PeerPublicKeys")
        object.__setattr__(
            self,
            "addresses",
            _coerce_tuple(
                values=self.addresses,
                expected_type=PeerAddress,
                field_name="addresses",
            ),
        )
        object.__setattr__(
            self,
            "group_memberships",
            _coerce_tuple(
                values=self.group_memberships,
                expected_type=PeerGroupMembership,
                field_name="group_memberships",
            ),
        )
        object.__setattr__(
            self,
            "descriptive_metadata",
            _coerce_metadata(metadata=self.descriptive_metadata),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialize peer identity metadata into a versioned pure-Python payload."""
        return peer_identity_to_dict(identity=self)

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> PeerIdentity:
        """Deserialize peer identity metadata from a versioned pure-Python payload."""
        return peer_identity_from_dict(value=value)


def peer_public_keys_to_dict(*, keys: PeerPublicKeys) -> dict[str, object]:
    """Serialize peer public keys."""
    if not isinstance(keys, PeerPublicKeys):
        raise TypeError("keys must be PeerPublicKeys")
    return {
        "encryption_algorithm": keys.encryption_algorithm,
        "encryption_public_key": encode_b64url(keys.encryption_public_key),
        "signing_algorithm": keys.signing_algorithm,
        "signing_public_key": encode_b64url(keys.signing_public_key),
        "version": PEER_MODEL_VERSION,
    }


def peer_public_keys_from_dict(*, value: Mapping[str, object]) -> PeerPublicKeys:
    """Deserialize peer public keys."""
    _validate_version(value=value)
    return PeerPublicKeys(
        signing_public_key=decode_b64url(
            _required_string(value=value, field_name="signing_public_key")
        ),
        encryption_public_key=decode_b64url(
            _required_string(value=value, field_name="encryption_public_key")
        ),
        signing_algorithm=_required_string(value=value, field_name="signing_algorithm"),
        encryption_algorithm=_required_string(value=value, field_name="encryption_algorithm"),
    )


def peer_address_to_dict(*, address: PeerAddress) -> dict[str, object]:
    """Serialize peer address metadata."""
    if not isinstance(address, PeerAddress):
        raise TypeError("address must be PeerAddress")
    return {
        "address_type": address.address_type,
        "label": address.label,
        "priority": address.priority,
        "value": address.value,
        "version": PEER_MODEL_VERSION,
    }


def peer_address_from_dict(*, value: Mapping[str, object]) -> PeerAddress:
    """Deserialize peer address metadata."""
    _validate_version(value=value)
    priority = value.get("priority")
    if not isinstance(priority, int) or isinstance(priority, bool):
        raise ValueError("priority must be an integer")
    return PeerAddress(
        address_type=_required_string(value=value, field_name="address_type"),
        value=_required_string(value=value, field_name="value"),
        label=_optional_string(value=value, field_name="label"),
        priority=priority,
    )


def peer_group_membership_to_dict(*, membership: PeerGroupMembership) -> dict[str, object]:
    """Serialize peer group membership metadata."""
    if not isinstance(membership, PeerGroupMembership):
        raise TypeError("membership must be PeerGroupMembership")
    return {
        "active": membership.active,
        "group_id": membership.group_id,
        "joined_at": membership.joined_at,
        "role": membership.role,
        "version": PEER_MODEL_VERSION,
    }


def peer_group_membership_from_dict(*, value: Mapping[str, object]) -> PeerGroupMembership:
    """Deserialize peer group membership metadata."""
    _validate_version(value=value)
    active = value.get("active")
    if not isinstance(active, bool):
        raise ValueError("active must be bool")
    return PeerGroupMembership(
        group_id=_required_string(value=value, field_name="group_id"),
        role=_optional_string(value=value, field_name="role"),
        joined_at=_optional_string(value=value, field_name="joined_at"),
        active=active,
    )


def peer_identity_to_dict(*, identity: PeerIdentity) -> dict[str, object]:
    """Serialize remote peer identity metadata."""
    if not isinstance(identity, PeerIdentity):
        raise TypeError("identity must be PeerIdentity")
    return {
        "addresses": [address.to_dict() for address in identity.addresses],
        "descriptive_metadata": dict(identity.descriptive_metadata),
        "group_memberships": [
            membership.to_dict() for membership in identity.group_memberships
        ],
        "node_id": identity.node_id,
        "public_keys": identity.public_keys.to_dict(),
        "version": PEER_MODEL_VERSION,
    }


def peer_identity_from_dict(*, value: Mapping[str, object]) -> PeerIdentity:
    """Deserialize remote peer identity metadata."""
    _validate_version(value=value)
    addresses = _required_sequence(value=value, field_name="addresses")
    memberships = _required_sequence(value=value, field_name="group_memberships")
    metadata = value.get("descriptive_metadata", {})
    if not isinstance(metadata, Mapping):
        raise ValueError("descriptive_metadata must be an object")
    return PeerIdentity(
        node_id=_required_string(value=value, field_name="node_id"),
        public_keys=PeerPublicKeys.from_dict(_required_mapping(value=value, field_name="public_keys")),
        addresses=tuple(
            PeerAddress.from_dict(_require_mapping_item(item=item, field_name="addresses"))
            for item in addresses
        ),
        group_memberships=tuple(
            PeerGroupMembership.from_dict(
                _require_mapping_item(item=item, field_name="group_memberships")
            )
            for item in memberships
        ),
        descriptive_metadata=_coerce_metadata(metadata=metadata),
    )


def _validate_version(*, value: Mapping[str, object]) -> None:
    version = value.get("version")
    if not isinstance(version, int) or isinstance(version, bool):
        raise ValueError("version must be an integer")
    if version != PEER_MODEL_VERSION:
        raise ValueError(f"unsupported peer model version: {version}")


def _validate_algorithm(*, algorithm: str, expected: str, field_name: str) -> None:
    if algorithm != expected:
        raise ValueError(f"{field_name} must be {expected}")


def _validate_public_key(*, value: bytes, field_name: str) -> None:
    if not isinstance(value, bytes) or len(value) != _PUBLIC_KEY_SIZE:
        raise ValueError(f"{field_name} must be 32 raw bytes")


def _validate_required_text(*, value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} is required")


def _validate_canonical_identifier(
    *, value: str, expected_type: str, field_name: str
) -> None:
    try:
        validate_identifier(
            value=value,
            expected_type=expected_type,  # type: ignore[arg-type]
            field=field_name,
        )
    except IdentifierValidationError as exc:
        raise ValueError(str(exc)) from exc


def _validate_optional_text(*, value: str, field_name: str) -> None:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")


def _required_string(*, value: Mapping[str, object], field_name: str) -> str:
    field_value = value.get(field_name)
    if not isinstance(field_value, str) or not field_value:
        raise ValueError(f"{field_name} is required")
    return field_value


def _optional_string(*, value: Mapping[str, object], field_name: str) -> str:
    field_value = value.get(field_name, "")
    if not isinstance(field_value, str):
        raise ValueError(f"{field_name} must be a string")
    return field_value


def _required_mapping(*, value: Mapping[str, object], field_name: str) -> Mapping[str, object]:
    field_value = value.get(field_name)
    if not isinstance(field_value, Mapping):
        raise ValueError(f"{field_name} is required")
    return field_value


def _required_sequence(*, value: Mapping[str, object], field_name: str) -> Sequence[object]:
    field_value = value.get(field_name)
    if not isinstance(field_value, Sequence) or isinstance(field_value, (str, bytes)):
        raise ValueError(f"{field_name} must be a sequence")
    return field_value


def _require_mapping_item(*, item: object, field_name: str) -> Mapping[str, object]:
    if not isinstance(item, Mapping):
        raise ValueError(f"{field_name} items must be objects")
    return item


def _coerce_tuple(*, values: object, expected_type: type, field_name: str) -> tuple:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
        raise TypeError(f"{field_name} must be a sequence")
    for value in values:
        if not isinstance(value, expected_type):
            raise TypeError(f"{field_name} items must be {expected_type.__name__}")
    return tuple(values)


def _coerce_metadata(*, metadata: object) -> tuple[tuple[str, str], ...]:
    if isinstance(metadata, Mapping):
        items = tuple(sorted(metadata.items()))
    elif isinstance(metadata, Sequence) and not isinstance(metadata, (str, bytes)):
        items = tuple(metadata)
    else:
        raise TypeError("descriptive_metadata must be a mapping or sequence")
    for key, value in items:
        if not isinstance(key, str) or not key:
            raise ValueError("descriptive_metadata keys must be non-empty strings")
        if not isinstance(value, str):
            raise ValueError("descriptive_metadata values must be strings")
    return items


__all__ = [
    "PEER_MODEL_VERSION",
    "PeerAddress",
    "PeerGroupMembership",
    "PeerIdentity",
    "PeerPublicKeys",
    "peer_address_from_dict",
    "peer_address_to_dict",
    "peer_group_membership_from_dict",
    "peer_group_membership_to_dict",
    "peer_identity_from_dict",
    "peer_identity_to_dict",
    "peer_public_keys_from_dict",
    "peer_public_keys_to_dict",
]
