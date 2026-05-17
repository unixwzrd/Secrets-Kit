"""Ed25519 envelope signing with deterministic canonical serialization."""

from __future__ import annotations

import base64
import json
from dataclasses import replace
from typing import Any, Mapping

import nacl.exceptions
import nacl.signing

from secrets_kit.protocol.envelope import MessageEnvelope, SignatureMetadata


class SignatureError(ValueError):
    """Envelope signature verification failed."""


def canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    """Return deterministic canonical JSON bytes for signing."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def signing_bytes(envelope: MessageEnvelope) -> bytes:
    """Return canonical bytes for envelope fields covered by the signature."""
    return canonical_json_bytes(envelope.to_dict(include_signature_value=False))


def sign_envelope(
    envelope: MessageEnvelope,
    *,
    signing_key: nacl.signing.SigningKey,
    key_id: str,
) -> MessageEnvelope:
    """Return ``envelope`` with Ed25519 signature metadata attached."""
    meta = SignatureMetadata(
        alg="ed25519",
        key_id=key_id,
        signed_fields=envelope.signature.signed_fields,
        value=None,
    )
    unsigned = replace(envelope, signature=meta)
    sig = signing_key.sign(signing_bytes(unsigned)).signature
    return replace(unsigned, signature=replace(meta, value=base64.standard_b64encode(sig).decode("ascii")))


def verify_envelope(
    envelope: MessageEnvelope,
    *,
    verify_key: nacl.signing.VerifyKey,
) -> None:
    """Verify an Ed25519 envelope signature."""
    if envelope.signature.alg != "ed25519":
        raise SignatureError(f"unsupported signature algorithm: {envelope.signature.alg!r}")
    if not envelope.signature.value:
        raise SignatureError("missing signature value")
    try:
        sig = base64.standard_b64decode(envelope.signature.value.encode("ascii"))
        verify_key.verify(signing_bytes(envelope), sig)
    except (ValueError, nacl.exceptions.BadSignatureError) as exc:
        raise SignatureError("envelope signature verification failed") from exc
