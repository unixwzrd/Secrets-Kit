"""
secrets_kit.protocol.envelope_signing

Canonical protocol envelope signing and verification.
"""

from __future__ import annotations

import hashlib
from dataclasses import replace
from typing import Any

from secrets_kit.crypto.codecs import decode_b64url, encode_b64url
from secrets_kit.crypto.signatures import sign_ed25519, verify_ed25519
from secrets_kit.identifiers import IdentifierValidationError, validate_identifier
from secrets_kit.protocol.envelope import (
    CanonicalEnvelope,
    canonical_envelope_bytes,
)

ENVELOPE_SIGNATURE_VERSION = 1
ENVELOPE_SIGNATURE_ALGORITHM = "ed25519"


class EnvelopeSignatureError(ValueError):
    """Raised when a signed protocol envelope is missing or invalid."""


def signing_public_key_fingerprint(*, public_key: bytes) -> str:
    """Return the canonical fingerprint for an Ed25519 signing public key."""
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise EnvelopeSignatureError("signing public key must be 32 raw bytes")
    return hashlib.sha256(public_key).hexdigest()


def sign_envelope(
    *,
    envelope: CanonicalEnvelope,
    signer_node_id: str,
    signing_private_key: bytes,
    signing_public_key: bytes,
) -> CanonicalEnvelope:
    """
    Return ``envelope`` with canonical Ed25519 signature metadata.

    The signed object is the canonical envelope bytes with identical signature
    metadata except ``signature`` is ``null``. This keeps the signature
    transport- and persistence-independent while avoiding a second envelope
    representation.
    """
    _validate_node_id(value=signer_node_id, field="signer_node_id")
    if envelope.source_node_id != signer_node_id:
        raise EnvelopeSignatureError("signer_node_id must match envelope source_node_id")
    if envelope.signature_metadata is not None:
        raise EnvelopeSignatureError("envelope is already signed")
    metadata = _unsigned_signature_metadata(
        signer_node_id=signer_node_id,
        signing_public_key=signing_public_key,
    )
    signed_bytes = canonical_envelope_bytes(
        envelope=replace(envelope, signature_metadata=metadata)
    )
    signature = sign_ed25519(private_key=signing_private_key, message=signed_bytes)
    return replace(
        envelope,
        signature_metadata={
            **metadata,
            "signature": encode_b64url(signature),
        },
    )


def verify_envelope_signature(
    *,
    envelope: CanonicalEnvelope,
    expected_signer_node_id: str,
    signing_public_key: bytes,
    expected_key_fingerprint: str | None = None,
) -> None:
    """Verify the canonical Ed25519 envelope signature."""
    _validate_node_id(value=expected_signer_node_id, field="expected_signer_node_id")
    if envelope.source_node_id != expected_signer_node_id:
        raise EnvelopeSignatureError("envelope source_node_id does not match expected signer")
    metadata = _validated_signature_metadata(metadata=envelope.signature_metadata)
    if metadata["signer_node_id"] != expected_signer_node_id:
        raise EnvelopeSignatureError("signature signer_node_id does not match expected signer")
    actual_fingerprint = signing_public_key_fingerprint(public_key=signing_public_key)
    if metadata["key_fingerprint"] != actual_fingerprint:
        raise EnvelopeSignatureError("signature key fingerprint does not match signing public key")
    if expected_key_fingerprint is not None and metadata["key_fingerprint"] != expected_key_fingerprint:
        raise EnvelopeSignatureError("signature key fingerprint does not match admitted identity")
    signature = _decode_signature(value=metadata["signature"])
    unsigned_metadata = {**metadata, "signature": None}
    signed_bytes = canonical_envelope_bytes(
        envelope=replace(envelope, signature_metadata=unsigned_metadata)
    )
    try:
        valid = verify_ed25519(
            public_key=signing_public_key,
            message=signed_bytes,
            signature=signature,
        )
    except (TypeError, ValueError) as exc:
        raise EnvelopeSignatureError(str(exc)) from exc
    if not valid:
        raise EnvelopeSignatureError("envelope signature is invalid")


def envelope_signing_bytes(*, envelope: CanonicalEnvelope) -> bytes:
    """
    Return the canonical bytes that are signed for an already signed envelope.

    This is exposed for tests and diagnostics. It does not verify the signature.
    """
    metadata = _validated_signature_metadata(metadata=envelope.signature_metadata)
    return canonical_envelope_bytes(
        envelope=replace(envelope, signature_metadata={**metadata, "signature": None})
    )


def validate_signature_metadata(*, metadata: object) -> dict[str, Any]:
    """Validate protocol-visible signature metadata shape."""
    return _validated_signature_metadata(metadata=metadata)


def _unsigned_signature_metadata(
    *, signer_node_id: str, signing_public_key: bytes
) -> dict[str, Any]:
    return {
        "version": ENVELOPE_SIGNATURE_VERSION,
        "algorithm": ENVELOPE_SIGNATURE_ALGORITHM,
        "signer_node_id": signer_node_id,
        "key_fingerprint": signing_public_key_fingerprint(public_key=signing_public_key),
        "signature": None,
    }


def _validated_signature_metadata(*, metadata: object) -> dict[str, Any]:
    if not isinstance(metadata, dict):
        raise EnvelopeSignatureError("signature_metadata must be an object")
    version = metadata.get("version")
    algorithm = metadata.get("algorithm")
    signer_node_id = metadata.get("signer_node_id")
    key_fingerprint = metadata.get("key_fingerprint")
    signature = metadata.get("signature")
    if version != ENVELOPE_SIGNATURE_VERSION:
        raise EnvelopeSignatureError("signature_metadata version is unsupported")
    if algorithm != ENVELOPE_SIGNATURE_ALGORITHM:
        raise EnvelopeSignatureError("signature_metadata algorithm is unsupported")
    if not isinstance(signer_node_id, str):
        raise EnvelopeSignatureError("signature_metadata signer_node_id must be a string")
    _validate_node_id(value=signer_node_id, field="signature_metadata.signer_node_id")
    if not isinstance(key_fingerprint, str) or len(key_fingerprint) != 64:
        raise EnvelopeSignatureError("signature_metadata key_fingerprint must be sha256 hex")
    try:
        int(key_fingerprint, 16)
    except ValueError as exc:
        raise EnvelopeSignatureError("signature_metadata key_fingerprint must be sha256 hex") from exc
    if key_fingerprint.lower() != key_fingerprint:
        raise EnvelopeSignatureError("signature_metadata key_fingerprint must be lowercase")
    if signature is not None and not isinstance(signature, str):
        raise EnvelopeSignatureError("signature_metadata signature must be a string or null")
    if isinstance(signature, str) and not signature:
        raise EnvelopeSignatureError("signature_metadata signature must be non-empty")
    return {
        "version": version,
        "algorithm": algorithm,
        "signer_node_id": signer_node_id,
        "key_fingerprint": key_fingerprint,
        "signature": signature,
    }


def _decode_signature(*, value: object) -> bytes:
    if not isinstance(value, str) or not value:
        raise EnvelopeSignatureError("signature_metadata signature is required")
    try:
        signature = decode_b64url(value)
    except (TypeError, ValueError) as exc:
        raise EnvelopeSignatureError("signature_metadata signature is invalid") from exc
    if len(signature) != 64:
        raise EnvelopeSignatureError("signature_metadata signature must be 64 raw bytes")
    return signature


def _validate_node_id(*, value: str, field: str) -> None:
    try:
        validate_identifier(value=value, expected_type="node", field=field)
    except IdentifierValidationError as exc:
        raise EnvelopeSignatureError(str(exc)) from exc


__all__ = [
    "ENVELOPE_SIGNATURE_ALGORITHM",
    "ENVELOPE_SIGNATURE_VERSION",
    "EnvelopeSignatureError",
    "envelope_signing_bytes",
    "sign_envelope",
    "signing_public_key_fingerprint",
    "validate_signature_metadata",
    "verify_envelope_signature",
]
