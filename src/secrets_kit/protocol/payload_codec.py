"""
secrets_kit.protocol.payload_codec

Envelope payload codec boundary.
"""

from __future__ import annotations

import base64
import hashlib
import os
from collections.abc import Mapping
from dataclasses import dataclass, replace

from secrets_kit.crypto.canonical import canonical_json_bytes
from secrets_kit.crypto.codecs import CryptoHeader, EncryptedBlob, decode_b64url, encode_b64url
from secrets_kit.crypto.encryption import decrypt_aead, encrypt_aead
from secrets_kit.crypto.keys import derive_x25519_shared_key, generate_x25519_keypair
from secrets_kit.crypto.records import ALGORITHM_X25519_HKDF_SHA256_CHACHA20POLY1305

PLAINTEXT_CODEC_MODE = "plaintext"
ENCRYPTED_CODEC_MODE = "encrypted"
PLAINTEXT_CODEC_ALGORITHM = "identity"
ENCRYPTED_CODEC_ALGORITHM = ALGORITHM_X25519_HKDF_SHA256_CHACHA20POLY1305
ENVELOPE_PAYLOAD_CODEC_ENV = "SECKIT_ENVELOPE_PAYLOAD_CODEC"
ENVELOPE_ENCRYPTION_METADATA_VERSION = 1
ENVELOPE_ENCRYPTION_AAD_PROFILE = "envelope-payload-v1"


class EnvelopePayloadCodecError(ValueError):
    """Raised when envelope payload codec processing fails."""


@dataclass(frozen=True)
class EnvelopePayloadRecord:
    """Encoded envelope payload plus protocol-visible codec metadata."""

    payload: dict[str, object]
    encoded_payload_bytes: bytes
    metadata: dict[str, object]
    encryption_metadata: dict[str, object] | None = None


@dataclass(frozen=True)
class EnvelopePayloadContext:
    """Protocol fields bound into encrypted envelope payload authentication."""

    envelope_id: str
    source_node_id: str
    destination_node_id: str
    transaction_id: str
    envelope_version: int
    protocol_version: int


@dataclass(frozen=True)
class EnvelopePayloadCodec:
    """Small immutable envelope payload codec API."""

    mode: str
    algorithm: str
    implemented: bool = True
    context: EnvelopePayloadContext | None = None
    recipient_node_id: str = ""
    recipient_public_key: bytes = b""
    recipient_key_fingerprint: str = ""
    local_private_key: bytes = b""
    local_public_key: bytes = b""
    encryption_metadata: dict[str, object] | None = None

    def with_context(self, context: EnvelopePayloadContext) -> EnvelopePayloadCodec:
        """Return this codec with protocol envelope context bound."""
        return replace(self, context=context)

    def encode(self, *, canonical_payload_bytes: bytes) -> EnvelopePayloadRecord:
        """Encode outbound canonical payload bytes for envelope transport."""
        if not self.implemented:
            raise EnvelopePayloadCodecError(
                f"{self.mode} envelope payload codec is not implemented; EL-03 required"
            )
        if not isinstance(canonical_payload_bytes, bytes):
            raise EnvelopePayloadCodecError("canonical_payload_bytes must be bytes")
        if self.mode == ENCRYPTED_CODEC_MODE:
            return self._encode_encrypted(canonical_payload_bytes=canonical_payload_bytes)
        encoded = bytes(canonical_payload_bytes)
        metadata = self.metadata()
        return EnvelopePayloadRecord(
            payload={
                "codec": metadata,
                "encoding": "base64url",
                "data_b64": _b64url_encode(encoded),
            },
            encoded_payload_bytes=encoded,
            metadata=metadata,
        )

    def decode(self, *, payload: object) -> bytes:
        """Decode inbound envelope payload bytes through the selected codec."""
        metadata = payload_codec_metadata(payload=payload)
        validate_payload_codec_metadata(metadata=metadata, expected_mode=self.mode)
        if not self.implemented:
            raise EnvelopePayloadCodecError(
                f"{self.mode} envelope payload codec is not implemented; EL-03 required"
            )
        if not isinstance(payload, dict):
            raise EnvelopePayloadCodecError("envelope payload must be an object")
        encoded = _payload_data_bytes(payload=payload)
        if self.mode == ENCRYPTED_CODEC_MODE:
            return self._decode_encrypted(encoded_payload_bytes=encoded)
        return bytes(encoded)

    def metadata(self) -> dict[str, object]:
        """Return protocol-visible codec metadata."""
        return {
            "version": 1,
            "mode": self.mode,
            "algorithm": self.algorithm,
        }

    def _encode_encrypted(self, *, canonical_payload_bytes: bytes) -> EnvelopePayloadRecord:
        context = _required_context(context=self.context)
        _validate_raw_public_key(value=self.recipient_public_key, field_name="recipient_public_key")
        if self.recipient_node_id != context.destination_node_id:
            raise EnvelopePayloadCodecError("recipient_node_id must match destination_node_id")
        fingerprint = _key_fingerprint(public_key=self.recipient_public_key)
        if self.recipient_key_fingerprint and self.recipient_key_fingerprint != fingerprint:
            raise EnvelopePayloadCodecError("recipient key fingerprint mismatch")
        ephemeral_private_key, ephemeral_public_key = generate_x25519_keypair()
        metadata = self.metadata()
        encryption_metadata = _encryption_metadata(
            context=context,
            recipient_key_fingerprint=fingerprint,
            ephemeral_public_key=ephemeral_public_key,
        )
        shared_key = derive_x25519_shared_key(
            private_key=ephemeral_private_key,
            peer_public_key=self.recipient_public_key,
            context=_kdf_context(
                context=context,
                codec_metadata=metadata,
                encryption_metadata=encryption_metadata,
            ),
        )
        encrypted_blob = encrypt_aead(
            key=shared_key,
            plaintext=canonical_payload_bytes,
            aad=_aad(
                context=context,
                codec_metadata=metadata,
                encryption_metadata=encryption_metadata,
            ),
            key_id=fingerprint,
            context=ENVELOPE_ENCRYPTION_AAD_PROFILE,
        )
        encryption_metadata = {
            **encryption_metadata,
            "nonce": encode_b64url(encrypted_blob.nonce),
        }
        encoded = encrypted_blob.ciphertext
        return EnvelopePayloadRecord(
            payload={
                "codec": metadata,
                "encoding": "base64url",
                "data_b64": _b64url_encode(encoded),
            },
            encoded_payload_bytes=encoded,
            metadata=metadata,
            encryption_metadata=encryption_metadata,
        )

    def _decode_encrypted(self, *, encoded_payload_bytes: bytes) -> bytes:
        context = _required_context(context=self.context)
        metadata = self.metadata()
        encryption_metadata = validate_encryption_metadata(
            metadata=self.encryption_metadata,
            expected_recipient_node_id=context.destination_node_id,
        )
        expected_fingerprint = _key_fingerprint(public_key=self._local_public_key())
        if encryption_metadata["recipient_key_fingerprint"] != expected_fingerprint:
            raise EnvelopePayloadCodecError("recipient key fingerprint mismatch")
        try:
            ephemeral_public_key = decode_b64url(str(encryption_metadata["ephemeral_public_key"]))
            nonce = decode_b64url(str(encryption_metadata["nonce"]))
        except (TypeError, ValueError) as exc:
            raise EnvelopePayloadCodecError("encryption_metadata contains invalid base64url") from exc
        _validate_raw_public_key(value=ephemeral_public_key, field_name="ephemeral_public_key")
        if len(nonce) != 12:
            raise EnvelopePayloadCodecError("encryption nonce must be 12 bytes")
        shared_key = derive_x25519_shared_key(
            private_key=self.local_private_key,
            peer_public_key=ephemeral_public_key,
            context=_kdf_context(
                context=context,
                codec_metadata=metadata,
                encryption_metadata=_metadata_without_nonce(metadata=encryption_metadata),
            ),
        )
        blob = EncryptedBlob(
            header=CryptoHeader(
                version=1,
                algorithm="chacha20poly1305",
                key_id=str(encryption_metadata["recipient_key_fingerprint"]),
                context=ENVELOPE_ENCRYPTION_AAD_PROFILE,
            ),
            nonce=nonce,
            ciphertext=encoded_payload_bytes,
        )
        try:
            return decrypt_aead(
                key=shared_key,
                blob=blob,
                aad=_aad(
                    context=context,
                    codec_metadata=metadata,
                    encryption_metadata=_metadata_without_nonce(metadata=encryption_metadata),
                ),
            )
        except Exception as exc:
            raise EnvelopePayloadCodecError("encrypted envelope payload authentication failed") from exc

    def _local_public_key(self) -> bytes:
        """Return local public key supplied for recipient fingerprint checks."""
        _validate_raw_public_key(value=self.local_public_key, field_name="local_public_key")
        return self.local_public_key


PLAINTEXT_ENVELOPE_PAYLOAD_CODEC = EnvelopePayloadCodec(
    mode=PLAINTEXT_CODEC_MODE,
    algorithm=PLAINTEXT_CODEC_ALGORITHM,
)
ENCRYPTED_ENVELOPE_PAYLOAD_CODEC = EnvelopePayloadCodec(
    mode=ENCRYPTED_CODEC_MODE,
    algorithm=ENCRYPTED_CODEC_ALGORITHM,
)


def plaintext_envelope_payload_codec() -> EnvelopePayloadCodec:
    """Return the plaintext identity-transform envelope payload codec."""
    return PLAINTEXT_ENVELOPE_PAYLOAD_CODEC


def encrypted_envelope_payload_codec(
    *,
    context: EnvelopePayloadContext | None = None,
    recipient_node_id: str = "",
    recipient_public_key: bytes = b"",
    recipient_key_fingerprint: str = "",
    local_private_key: bytes = b"",
    local_public_key: bytes = b"",
    encryption_metadata: dict[str, object] | None = None,
) -> EnvelopePayloadCodec:
    """Return the X25519/HKDF/ChaCha20-Poly1305 envelope payload codec."""
    return EnvelopePayloadCodec(
        mode=ENCRYPTED_CODEC_MODE,
        algorithm=ENCRYPTED_CODEC_ALGORITHM,
        context=context,
        recipient_node_id=recipient_node_id,
        recipient_public_key=recipient_public_key,
        recipient_key_fingerprint=recipient_key_fingerprint,
        local_private_key=local_private_key,
        local_public_key=local_public_key,
        encryption_metadata=encryption_metadata,
    )


def envelope_payload_codec_for_metadata(*, metadata: object) -> EnvelopePayloadCodec:
    """Resolve a codec from protocol payload metadata."""
    if not isinstance(metadata, dict):
        raise EnvelopePayloadCodecError("payload codec metadata must be an object")
    mode = metadata.get("mode")
    if mode == PLAINTEXT_CODEC_MODE:
        return plaintext_envelope_payload_codec()
    if mode == ENCRYPTED_CODEC_MODE:
        return encrypted_envelope_payload_codec()
    raise EnvelopePayloadCodecError(f"unsupported envelope payload codec mode: {mode!r}")


def payload_codec_metadata(*, payload: object) -> dict[str, object]:
    """Read codec metadata from an envelope payload record."""
    if not isinstance(payload, dict):
        raise EnvelopePayloadCodecError("envelope payload must be an object")
    metadata = payload.get("codec")
    if not isinstance(metadata, dict):
        raise EnvelopePayloadCodecError("envelope payload codec metadata must be an object")
    return dict(metadata)


def validate_payload_codec_metadata(
    *, metadata: object, expected_mode: str | None = None
) -> dict[str, object]:
    """Validate protocol-visible payload codec metadata."""
    if not isinstance(metadata, dict):
        raise EnvelopePayloadCodecError("payload codec metadata must be an object")
    version = metadata.get("version")
    mode = metadata.get("mode")
    algorithm = metadata.get("algorithm")
    if version != 1:
        raise EnvelopePayloadCodecError("payload codec metadata version is unsupported")
    if mode not in {PLAINTEXT_CODEC_MODE, ENCRYPTED_CODEC_MODE}:
        raise EnvelopePayloadCodecError(f"unsupported envelope payload codec mode: {mode!r}")
    if expected_mode is not None and mode != expected_mode:
        raise EnvelopePayloadCodecError(
            f"payload codec mode mismatch: expected {expected_mode}, got {mode}"
        )
    if mode == PLAINTEXT_CODEC_MODE and algorithm != PLAINTEXT_CODEC_ALGORITHM:
        raise EnvelopePayloadCodecError("plaintext payload codec algorithm must be identity")
    if mode == ENCRYPTED_CODEC_MODE and algorithm != ENCRYPTED_CODEC_ALGORITHM:
        raise EnvelopePayloadCodecError("encrypted payload codec algorithm is unsupported")
    return dict(metadata)


def configured_envelope_payload_codec_mode() -> str:
    """Encrypt normal P2P payloads independently of RSS and local storage mode.

    The explicit environment override is reserved for development/test fixtures;
    it is not a customer encryption setting. Invalid overrides fail closed.
    """
    mode = os.getenv(ENVELOPE_PAYLOAD_CODEC_ENV, ENCRYPTED_CODEC_MODE)
    if mode not in {PLAINTEXT_CODEC_MODE, ENCRYPTED_CODEC_MODE}:
        raise EnvelopePayloadCodecError(f"unsupported envelope payload codec mode: {mode!r}")
    if mode == PLAINTEXT_CODEC_MODE and os.getenv("SECKIT_UNSAFE_PLAINTEXT_ENVELOPES") != "1":
        raise EnvelopePayloadCodecError("UNSAFE plaintext envelopes require SECKIT_UNSAFE_PLAINTEXT_ENVELOPES=1")
    return mode


def validate_encryption_metadata(
    *,
    metadata: object,
    expected_recipient_node_id: str | None = None,
) -> dict[str, object]:
    """Validate protocol-visible encrypted envelope metadata."""
    if not isinstance(metadata, Mapping):
        raise EnvelopePayloadCodecError("encryption_metadata must be an object")
    version = metadata.get("version")
    algorithm = metadata.get("algorithm")
    recipient_node_id = metadata.get("recipient_node_id")
    recipient_key_fingerprint = metadata.get("recipient_key_fingerprint")
    ephemeral_public_key = metadata.get("ephemeral_public_key")
    nonce = metadata.get("nonce")
    aad_profile = metadata.get("aad_profile")
    if version != ENVELOPE_ENCRYPTION_METADATA_VERSION:
        raise EnvelopePayloadCodecError("encryption_metadata version is unsupported")
    if algorithm != ENCRYPTED_CODEC_ALGORITHM:
        raise EnvelopePayloadCodecError("encryption_metadata algorithm is unsupported")
    if not isinstance(recipient_node_id, str) or not recipient_node_id:
        raise EnvelopePayloadCodecError("encryption_metadata recipient_node_id is required")
    if expected_recipient_node_id is not None and recipient_node_id != expected_recipient_node_id:
        raise EnvelopePayloadCodecError("encryption_metadata recipient_node_id mismatch")
    if not isinstance(recipient_key_fingerprint, str) or len(recipient_key_fingerprint) != 64:
        raise EnvelopePayloadCodecError("encryption_metadata recipient_key_fingerprint must be sha256 hex")
    try:
        int(recipient_key_fingerprint, 16)
    except ValueError as exc:
        raise EnvelopePayloadCodecError(
            "encryption_metadata recipient_key_fingerprint must be sha256 hex"
        ) from exc
    if recipient_key_fingerprint.lower() != recipient_key_fingerprint:
        raise EnvelopePayloadCodecError(
            "encryption_metadata recipient_key_fingerprint must be lowercase"
        )
    if not isinstance(ephemeral_public_key, str) or not ephemeral_public_key:
        raise EnvelopePayloadCodecError("encryption_metadata ephemeral_public_key is required")
    if not isinstance(nonce, str) or not nonce:
        raise EnvelopePayloadCodecError("encryption_metadata nonce is required")
    if aad_profile != ENVELOPE_ENCRYPTION_AAD_PROFILE:
        raise EnvelopePayloadCodecError("encryption_metadata aad_profile is unsupported")
    try:
        _validate_raw_public_key(
            value=decode_b64url(ephemeral_public_key),
            field_name="ephemeral_public_key",
        )
        decoded_nonce = decode_b64url(nonce)
    except (TypeError, ValueError) as exc:
        raise EnvelopePayloadCodecError("encryption_metadata contains invalid base64url") from exc
    if len(decoded_nonce) != 12:
        raise EnvelopePayloadCodecError("encryption_metadata nonce must be 12 bytes")
    return {
        "version": version,
        "algorithm": algorithm,
        "recipient_node_id": recipient_node_id,
        "recipient_key_fingerprint": recipient_key_fingerprint,
        "ephemeral_public_key": ephemeral_public_key,
        "nonce": nonce,
        "aad_profile": aad_profile,
    }


def decode_envelope_payload(*, payload: object) -> bytes:
    """Decode an envelope payload through the codec declared by its metadata."""
    metadata = payload_codec_metadata(payload=payload)
    codec = envelope_payload_codec_for_metadata(metadata=metadata)
    return codec.decode(payload=payload)


def encoded_payload_bytes(*, payload: object) -> bytes:
    """Return the encoded payload bytes committed by the canonical envelope."""
    if not isinstance(payload, dict):
        raise EnvelopePayloadCodecError("envelope payload must be an object")
    validate_payload_codec_metadata(metadata=payload_codec_metadata(payload=payload))
    return _payload_data_bytes(payload=payload)


def _payload_data_bytes(*, payload: dict[str, object]) -> bytes:
    encoding = payload.get("encoding")
    if encoding != "base64url":
        raise EnvelopePayloadCodecError("envelope payload encoding must be base64url")
    data_b64 = payload.get("data_b64")
    if not isinstance(data_b64, str) or not data_b64:
        raise EnvelopePayloadCodecError("envelope payload data_b64 must be a non-empty string")
    return _b64url_decode(data_b64)


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode((value + padding).encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise EnvelopePayloadCodecError("envelope payload data_b64 is invalid") from exc


def _required_context(*, context: EnvelopePayloadContext | None) -> EnvelopePayloadContext:
    if not isinstance(context, EnvelopePayloadContext):
        raise EnvelopePayloadCodecError("encrypted envelope payload context is required")
    return context


def _key_fingerprint(*, public_key: bytes) -> str:
    _validate_raw_public_key(value=public_key, field_name="public_key")
    return hashlib.sha256(public_key).hexdigest()


def _validate_raw_public_key(*, value: bytes, field_name: str) -> None:
    if not isinstance(value, bytes) or len(value) != 32:
        raise EnvelopePayloadCodecError(f"{field_name} must be 32 raw bytes")


def _encryption_metadata(
    *,
    context: EnvelopePayloadContext,
    recipient_key_fingerprint: str,
    ephemeral_public_key: bytes,
) -> dict[str, object]:
    return {
        "version": ENVELOPE_ENCRYPTION_METADATA_VERSION,
        "algorithm": ENCRYPTED_CODEC_ALGORITHM,
        "recipient_node_id": context.destination_node_id,
        "recipient_key_fingerprint": recipient_key_fingerprint,
        "ephemeral_public_key": encode_b64url(ephemeral_public_key),
        "aad_profile": ENVELOPE_ENCRYPTION_AAD_PROFILE,
    }


def _aad(
    *,
    context: EnvelopePayloadContext,
    codec_metadata: dict[str, object],
    encryption_metadata: dict[str, object],
) -> bytes:
    return canonical_json_bytes(
        {
            "aad_profile": ENVELOPE_ENCRYPTION_AAD_PROFILE,
            "codec": codec_metadata,
            "encryption_metadata": encryption_metadata,
            "envelope_id": context.envelope_id,
            "envelope_version": context.envelope_version,
            "protocol_version": context.protocol_version,
            "source_node_id": context.source_node_id,
            "destination_node_id": context.destination_node_id,
            "transaction_id": context.transaction_id,
        }
    )


def _kdf_context(
    *,
    context: EnvelopePayloadContext,
    codec_metadata: dict[str, object],
    encryption_metadata: dict[str, object],
) -> bytes:
    return canonical_json_bytes(
        {
            "purpose": "secrets-kit.envelope-payload-key",
            "codec": codec_metadata,
            "encryption_metadata": encryption_metadata,
            "envelope_id": context.envelope_id,
            "source_node_id": context.source_node_id,
            "destination_node_id": context.destination_node_id,
            "transaction_id": context.transaction_id,
        }
    )


def _metadata_without_nonce(*, metadata: dict[str, object]) -> dict[str, object]:
    allowed_keys = {
        "version",
        "algorithm",
        "recipient_node_id",
        "recipient_key_fingerprint",
        "ephemeral_public_key",
        "aad_profile",
    }
    return {
        key: value
        for key, value in metadata.items()
        if key in allowed_keys
    }


__all__ = [
    "ENCRYPTED_CODEC_ALGORITHM",
    "ENCRYPTED_CODEC_MODE",
    "PLAINTEXT_CODEC_ALGORITHM",
    "PLAINTEXT_CODEC_MODE",
    "ENCRYPTED_ENVELOPE_PAYLOAD_CODEC",
    "ENVELOPE_PAYLOAD_CODEC_ENV",
    "ENVELOPE_ENCRYPTION_AAD_PROFILE",
    "ENVELOPE_ENCRYPTION_METADATA_VERSION",
    "PLAINTEXT_ENVELOPE_PAYLOAD_CODEC",
    "EnvelopePayloadCodec",
    "EnvelopePayloadCodecError",
    "EnvelopePayloadContext",
    "EnvelopePayloadRecord",
    "configured_envelope_payload_codec_mode",
    "decode_envelope_payload",
    "encoded_payload_bytes",
    "encrypted_envelope_payload_codec",
    "envelope_payload_codec_for_metadata",
    "payload_codec_metadata",
    "plaintext_envelope_payload_codec",
    "validate_encryption_metadata",
    "validate_payload_codec_metadata",
]
