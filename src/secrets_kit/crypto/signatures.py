"""
secrets_kit.crypto.signatures

Ed25519 signing helpers.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def generate_ed25519_keypair() -> tuple[bytes, bytes]:
    """Generate an Ed25519 keypair as ``(private_key, public_key)`` raw bytes."""
    private_key = Ed25519PrivateKey.generate()
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


def sign_ed25519(private_key: bytes, message: bytes) -> bytes:
    """Sign ``message`` with a raw Ed25519 private key."""
    if not isinstance(private_key, bytes) or len(private_key) != 32:
        raise ValueError("private_key must be 32 raw bytes")
    if not isinstance(message, bytes):
        raise TypeError("message must be bytes")
    return Ed25519PrivateKey.from_private_bytes(private_key).sign(message)


def verify_ed25519(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Return whether ``signature`` is valid for ``message`` and ``public_key``."""
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise ValueError("public_key must be 32 raw bytes")
    if not isinstance(message, bytes):
        raise TypeError("message must be bytes")
    if not isinstance(signature, bytes):
        raise TypeError("signature must be bytes")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except InvalidSignature:
        return False
    return True


__all__ = ["generate_ed25519_keypair", "sign_ed25519", "verify_ed25519"]
