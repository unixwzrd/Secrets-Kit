"""
secrets_kit.crypto.transaction_signing

Standalone payload signing helpers for future transaction boundaries.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Mapping

from secrets_kit.crypto.canonical import canonical_json_bytes
from secrets_kit.crypto.keyring import InMemoryKeyring
from secrets_kit.crypto.models import ALGORITHM_ED25519, SigningKeypair
from secrets_kit.crypto.signatures import sign_ed25519, verify_ed25519


@dataclass(frozen=True)
class TransactionSignature:
    key_id: str
    signature: bytes
    algorithm: str
    created_at: str

    def __post_init__(self) -> None:
        if not isinstance(self.key_id, str) or not self.key_id:
            raise ValueError("key_id is required")
        if not isinstance(self.signature, bytes) or not self.signature:
            raise ValueError("signature is required")
        if self.algorithm != ALGORITHM_ED25519:
            raise ValueError("algorithm must be ed25519")
        if not isinstance(self.created_at, str) or not self.created_at:
            raise ValueError("created_at is required")


def sign_payload(
    *,
    keypair: SigningKeypair,
    payload: Mapping[str, object],
) -> TransactionSignature:
    """Sign a mapping payload using deterministic canonical JSON bytes."""
    if not isinstance(keypair, SigningKeypair):
        raise TypeError("keypair must be a SigningKeypair")
    if keypair.metadata.algorithm != ALGORITHM_ED25519:
        raise ValueError("keypair algorithm must be ed25519")
    canonical_payload = canonical_json_bytes(payload)
    return TransactionSignature(
        key_id=keypair.metadata.key_id,
        signature=sign_ed25519(keypair.private_key, canonical_payload),
        algorithm=keypair.metadata.algorithm,
        created_at=_now_utc_iso(),
    )


def verify_payload(
    *,
    public_key: bytes,
    payload: Mapping[str, object],
    signature: TransactionSignature,
) -> bool:
    """Verify a payload signature using deterministic canonical JSON bytes."""
    if not isinstance(signature, TransactionSignature):
        raise TypeError("signature must be a TransactionSignature")
    if signature.algorithm != ALGORITHM_ED25519:
        raise ValueError("signature algorithm must be ed25519")
    canonical_payload = canonical_json_bytes(payload)
    return verify_ed25519(public_key, canonical_payload, signature.signature)


def sign_payload_with_keyring(
    *,
    keyring: InMemoryKeyring,
    payload: Mapping[str, object],
) -> TransactionSignature:
    """Sign a payload with the active signing key from an in-memory keyring."""
    if not isinstance(keyring, InMemoryKeyring):
        raise TypeError("keyring must be an InMemoryKeyring")
    keypair = keyring.get_active_signing_key()
    if keypair is None:
        raise ValueError("no active signing key")
    return sign_payload(keypair=keypair, payload=payload)


def _now_utc_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


__all__ = [
    "TransactionSignature",
    "sign_payload",
    "sign_payload_with_keyring",
    "verify_payload",
]
