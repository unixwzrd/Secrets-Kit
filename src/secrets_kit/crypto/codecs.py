"""
secrets_kit.crypto.codecs

Deterministic codecs for crypto data structures.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from typing import Any

SUPPORTED_CRYPTO_BLOB_VERSIONS = frozenset({1})


@dataclass(frozen=True)
class CryptoHeader:
    version: int
    algorithm: str
    key_id: str = ""
    context: str = ""


@dataclass(frozen=True)
class EncryptedBlob:
    header: CryptoHeader
    nonce: bytes
    ciphertext: bytes


def encode_b64url(data: bytes) -> str:
    """Encode bytes as unpadded URL-safe base64 text."""
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def decode_b64url(value: str) -> bytes:
    """Decode unpadded URL-safe base64 text."""
    if not isinstance(value, str):
        raise TypeError("value must be a string")
    padding = "=" * (-len(value) % 4)
    try:
        return base64.b64decode(
            (value + padding).encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, UnicodeEncodeError) as exc:
        raise ValueError("invalid base64url value") from exc


def encode_encrypted_blob(blob: EncryptedBlob) -> bytes:
    """Encode an encrypted blob as deterministic canonical JSON bytes."""
    _validate_blob(blob=blob)
    payload = {
        "ciphertext": encode_b64url(blob.ciphertext),
        "header": {
            "algorithm": blob.header.algorithm,
            "context": blob.header.context,
            "key_id": blob.header.key_id,
            "version": blob.header.version,
        },
        "nonce": encode_b64url(blob.nonce),
    }
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def decode_encrypted_blob(data: bytes) -> EncryptedBlob:
    """Decode deterministic encrypted blob JSON bytes."""
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("encrypted blob must be valid JSON bytes") from exc
    if not isinstance(payload, dict):
        raise ValueError("encrypted blob must be a JSON object")
    header_payload = payload.get("header")
    if not isinstance(header_payload, dict):
        raise ValueError("encrypted blob header is required")
    header = _decode_header(payload=header_payload)
    nonce = decode_b64url(_required_text(payload=payload, field_name="nonce"))
    ciphertext = decode_b64url(_required_text(payload=payload, field_name="ciphertext"))
    blob = EncryptedBlob(header=header, nonce=nonce, ciphertext=ciphertext)
    _validate_blob(blob=blob)
    return blob


def _decode_header(*, payload: dict[str, Any]) -> CryptoHeader:
    version = payload.get("version")
    if not isinstance(version, int) or isinstance(version, bool):
        raise ValueError("encrypted blob header version must be an integer")
    if version not in SUPPORTED_CRYPTO_BLOB_VERSIONS:
        raise ValueError(f"unsupported encrypted blob version: {version}")
    return CryptoHeader(
        version=version,
        algorithm=_required_text(payload=payload, field_name="algorithm"),
        key_id=_optional_text(payload=payload, field_name="key_id"),
        context=_optional_text(payload=payload, field_name="context"),
    )


def _validate_blob(*, blob: EncryptedBlob) -> None:
    if not isinstance(blob, EncryptedBlob):
        raise TypeError("blob must be an EncryptedBlob")
    if blob.header.version not in SUPPORTED_CRYPTO_BLOB_VERSIONS:
        raise ValueError(f"unsupported encrypted blob version: {blob.header.version}")
    if not blob.header.algorithm:
        raise ValueError("encrypted blob algorithm is required")
    if not isinstance(blob.nonce, bytes) or not blob.nonce:
        raise ValueError("encrypted blob nonce must be non-empty bytes")
    if not isinstance(blob.ciphertext, bytes) or not blob.ciphertext:
        raise ValueError("encrypted blob ciphertext must be non-empty bytes")


def _required_text(*, payload: dict[str, Any], field_name: str) -> str:
    value = payload.get(field_name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} is required")
    return value


def _optional_text(*, payload: dict[str, Any], field_name: str) -> str:
    value = payload.get(field_name, "")
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    return value


__all__ = [
    "CryptoHeader",
    "EncryptedBlob",
    "decode_b64url",
    "decode_encrypted_blob",
    "encode_b64url",
    "encode_encrypted_blob",
]
