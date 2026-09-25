"""
secrets_kit.crypto.records

Generic crypto record models and serialization helpers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from secrets_kit.crypto.codecs import decode_b64url, encode_b64url

CRYPTO_RECORD_VERSION = 1
ALGORITHM_CHACHA20POLY1305 = "chacha20poly1305"
ALGORITHM_ED25519 = "ed25519"
ALGORITHM_X25519_HKDF_SHA256_CHACHA20POLY1305 = "x25519-hkdf-sha256-chacha20poly1305"
SUPPORTED_CIPHERTEXT_RECORD_ALGORITHMS = frozenset({ALGORITHM_CHACHA20POLY1305})
SUPPORTED_SIGNATURE_RECORD_ALGORITHMS = frozenset({ALGORITHM_ED25519})
SUPPORTED_WRAPPED_KEY_RECORD_ALGORITHMS = frozenset(
    {ALGORITHM_X25519_HKDF_SHA256_CHACHA20POLY1305}
)


@dataclass(frozen=True)
class CiphertextRecord:
    version: int
    algorithm: str
    key_id: str
    nonce: bytes
    ciphertext: bytes
    context: str = ""

    def __post_init__(self) -> None:
        _validate_record_version(version=self.version)
        _validate_record_algorithm(
            algorithm=self.algorithm,
            supported=SUPPORTED_CIPHERTEXT_RECORD_ALGORITHMS,
            record_name="ciphertext",
        )
        _validate_required_text(value=self.key_id, field_name="key_id")
        _validate_optional_text(value=self.context, field_name="context")
        _validate_non_empty_bytes(value=self.nonce, field_name="nonce")
        _validate_non_empty_bytes(value=self.ciphertext, field_name="ciphertext")


@dataclass(frozen=True)
class SignatureRecord:
    version: int
    algorithm: str
    key_id: str
    signature: bytes
    context: str = ""

    def __post_init__(self) -> None:
        _validate_record_version(version=self.version)
        _validate_record_algorithm(
            algorithm=self.algorithm,
            supported=SUPPORTED_SIGNATURE_RECORD_ALGORITHMS,
            record_name="signature",
        )
        _validate_required_text(value=self.key_id, field_name="key_id")
        _validate_optional_text(value=self.context, field_name="context")
        _validate_non_empty_bytes(value=self.signature, field_name="signature")


@dataclass(frozen=True)
class WrappedKeyRecord:
    version: int
    algorithm: str
    key_id: str
    nonce: bytes
    wrapped_key: bytes
    context: str = ""

    def __post_init__(self) -> None:
        _validate_record_version(version=self.version)
        _validate_record_algorithm(
            algorithm=self.algorithm,
            supported=SUPPORTED_WRAPPED_KEY_RECORD_ALGORITHMS,
            record_name="wrapped key",
        )
        _validate_required_text(value=self.key_id, field_name="key_id")
        _validate_optional_text(value=self.context, field_name="context")
        _validate_non_empty_bytes(value=self.nonce, field_name="nonce")
        _validate_non_empty_bytes(value=self.wrapped_key, field_name="wrapped_key")


def serialize_ciphertext_record(record: CiphertextRecord) -> dict[str, object]:
    """Serialize a generic ciphertext record into a versioned payload."""
    if not isinstance(record, CiphertextRecord):
        raise TypeError("record must be a CiphertextRecord")
    return {
        "algorithm": record.algorithm,
        "ciphertext": encode_b64url(record.ciphertext),
        "context": record.context,
        "key_id": record.key_id,
        "nonce": encode_b64url(record.nonce),
        "version": record.version,
    }


def deserialize_ciphertext_record(value: Mapping[str, object]) -> CiphertextRecord:
    """Deserialize a generic ciphertext record."""
    return CiphertextRecord(
        version=_required_record_version(value=value),
        algorithm=_required_string(value=value, field_name="algorithm"),
        key_id=_required_string(value=value, field_name="key_id"),
        nonce=decode_b64url(_required_string(value=value, field_name="nonce")),
        ciphertext=decode_b64url(_required_string(value=value, field_name="ciphertext")),
        context=_optional_string(value=value, field_name="context"),
    )


def serialize_signature_record(record: SignatureRecord) -> dict[str, object]:
    """Serialize a generic signature record into a versioned payload."""
    if not isinstance(record, SignatureRecord):
        raise TypeError("record must be a SignatureRecord")
    return {
        "algorithm": record.algorithm,
        "context": record.context,
        "key_id": record.key_id,
        "signature": encode_b64url(record.signature),
        "version": record.version,
    }


def deserialize_signature_record(value: Mapping[str, object]) -> SignatureRecord:
    """Deserialize a generic signature record."""
    return SignatureRecord(
        version=_required_record_version(value=value),
        algorithm=_required_string(value=value, field_name="algorithm"),
        key_id=_required_string(value=value, field_name="key_id"),
        signature=decode_b64url(_required_string(value=value, field_name="signature")),
        context=_optional_string(value=value, field_name="context"),
    )


def serialize_wrapped_key_record(record: WrappedKeyRecord) -> dict[str, object]:
    """Serialize a generic wrapped-key record into a versioned payload."""
    if not isinstance(record, WrappedKeyRecord):
        raise TypeError("record must be a WrappedKeyRecord")
    return {
        "algorithm": record.algorithm,
        "context": record.context,
        "key_id": record.key_id,
        "nonce": encode_b64url(record.nonce),
        "version": record.version,
        "wrapped_key": encode_b64url(record.wrapped_key),
    }


def deserialize_wrapped_key_record(value: Mapping[str, object]) -> WrappedKeyRecord:
    """Deserialize a generic wrapped-key record."""
    return WrappedKeyRecord(
        version=_required_record_version(value=value),
        algorithm=_required_string(value=value, field_name="algorithm"),
        key_id=_required_string(value=value, field_name="key_id"),
        nonce=decode_b64url(_required_string(value=value, field_name="nonce")),
        wrapped_key=decode_b64url(_required_string(value=value, field_name="wrapped_key")),
        context=_optional_string(value=value, field_name="context"),
    )


def _validate_record_version(*, version: int) -> None:
    if not isinstance(version, int) or isinstance(version, bool):
        raise ValueError("record version must be an integer")
    if version != CRYPTO_RECORD_VERSION:
        raise ValueError(f"unsupported crypto record version: {version}")


def _validate_record_algorithm(
    *,
    algorithm: str,
    supported: frozenset[str],
    record_name: str,
) -> None:
    if algorithm not in supported:
        raise ValueError(f"unsupported {record_name} record algorithm: {algorithm}")


def _validate_required_text(*, value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} is required")


def _validate_optional_text(*, value: str, field_name: str) -> None:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")


def _validate_non_empty_bytes(*, value: bytes, field_name: str) -> None:
    if not isinstance(value, bytes) or not value:
        raise ValueError(f"{field_name} must be non-empty bytes")


def _required_record_version(*, value: Mapping[str, object]) -> int:
    version = value.get("version")
    if not isinstance(version, int) or isinstance(version, bool):
        raise ValueError("record version must be an integer")
    return version


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


__all__ = [
    "ALGORITHM_CHACHA20POLY1305",
    "ALGORITHM_ED25519",
    "ALGORITHM_X25519_HKDF_SHA256_CHACHA20POLY1305",
    "CRYPTO_RECORD_VERSION",
    "SUPPORTED_CIPHERTEXT_RECORD_ALGORITHMS",
    "SUPPORTED_SIGNATURE_RECORD_ALGORITHMS",
    "SUPPORTED_WRAPPED_KEY_RECORD_ALGORITHMS",
    "CiphertextRecord",
    "SignatureRecord",
    "WrappedKeyRecord",
    "deserialize_ciphertext_record",
    "deserialize_signature_record",
    "deserialize_wrapped_key_record",
    "serialize_ciphertext_record",
    "serialize_signature_record",
    "serialize_wrapped_key_record",
]
