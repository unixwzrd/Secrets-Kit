"""
secrets_kit.crypto.encryption

Generic AEAD helpers.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from secrets_kit.crypto.codecs import CryptoHeader, EncryptedBlob
from secrets_kit.crypto.random import random_bytes

AEAD_ALGORITHM = "chacha20poly1305"
AEAD_VERSION = 1
CHACHA20POLY1305_KEY_BYTES = 32
CHACHA20POLY1305_NONCE_BYTES = 12


def encrypt_aead(
    *,
    key: bytes,
    plaintext: bytes,
    aad: bytes = b"",
    key_id: str = "",
    context: str = "",
) -> EncryptedBlob:
    """Encrypt plaintext with ChaCha20-Poly1305 and return an encrypted blob."""
    _validate_key(key=key)
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")
    if not isinstance(aad, bytes):
        raise TypeError("aad must be bytes")
    if not isinstance(key_id, str):
        raise TypeError("key_id must be a string")
    if not isinstance(context, str):
        raise TypeError("context must be a string")

    nonce = random_bytes(CHACHA20POLY1305_NONCE_BYTES)
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
    return EncryptedBlob(
        header=CryptoHeader(
            version=AEAD_VERSION,
            algorithm=AEAD_ALGORITHM,
            key_id=key_id,
            context=context,
        ),
        nonce=nonce,
        ciphertext=ciphertext,
    )


def decrypt_aead(*, key: bytes, blob: EncryptedBlob, aad: bytes = b"") -> bytes:
    """Decrypt a ChaCha20-Poly1305 encrypted blob."""
    _validate_key(key=key)
    if not isinstance(blob, EncryptedBlob):
        raise TypeError("blob must be an EncryptedBlob")
    if not isinstance(aad, bytes):
        raise TypeError("aad must be bytes")
    if blob.header.version != AEAD_VERSION:
        raise ValueError(f"unsupported encrypted blob version: {blob.header.version}")
    if blob.header.algorithm != AEAD_ALGORITHM:
        raise ValueError(f"unsupported AEAD algorithm: {blob.header.algorithm}")
    if not isinstance(blob.nonce, bytes) or len(blob.nonce) != CHACHA20POLY1305_NONCE_BYTES:
        raise ValueError("nonce must be 12 bytes")
    if not isinstance(blob.ciphertext, bytes) or not blob.ciphertext:
        raise ValueError("ciphertext must be non-empty bytes")
    return ChaCha20Poly1305(key).decrypt(blob.nonce, blob.ciphertext, aad)


def _validate_key(*, key: bytes) -> None:
    if not isinstance(key, bytes) or len(key) != CHACHA20POLY1305_KEY_BYTES:
        raise ValueError("key must be exactly 32 bytes")


__all__ = ["decrypt_aead", "encrypt_aead"]
