"""
secrets_kit.crypto.keys

Symmetric key generation, X25519 key agreement, and HKDF helpers.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from secrets_kit.crypto.random import random_bytes


def generate_symmetric_key() -> bytes:
    """Generate a 256-bit symmetric key."""
    return random_bytes(32)


def generate_x25519_keypair() -> tuple[bytes, bytes]:
    """Generate an X25519 keypair as ``(private_key, public_key)`` raw bytes."""
    private_key = X25519PrivateKey.generate()
    return (
        private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ),
    )


def derive_hkdf_sha256(root_key: bytes, context: bytes, length: int = 32) -> bytes:
    """Derive key material from ``root_key`` using HKDF-SHA-256."""
    if not isinstance(root_key, bytes) or not root_key:
        raise ValueError("root_key must be non-empty bytes")
    if not isinstance(context, bytes) or not context:
        raise ValueError("context must be non-empty bytes")
    if not isinstance(length, int) or length < 1:
        raise ValueError("length must be a positive integer")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=context,
    ).derive(root_key)


def derive_x25519_shared_key(private_key: bytes, peer_public_key: bytes, context: bytes) -> bytes:
    """Derive a 256-bit shared key from X25519 raw key bytes and HKDF context."""
    if not isinstance(private_key, bytes) or len(private_key) != 32:
        raise ValueError("private_key must be 32 raw bytes")
    if not isinstance(peer_public_key, bytes) or len(peer_public_key) != 32:
        raise ValueError("peer_public_key must be 32 raw bytes")
    shared_secret = X25519PrivateKey.from_private_bytes(private_key).exchange(
        X25519PublicKey.from_public_bytes(peer_public_key)
    )
    return derive_hkdf_sha256(root_key=shared_secret, context=context, length=32)


__all__ = [
    "derive_hkdf_sha256",
    "derive_x25519_shared_key",
    "generate_symmetric_key",
    "generate_x25519_keypair",
]
