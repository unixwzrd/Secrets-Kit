"""Payload encryption policy hooks.

The protocol layer records encryption metadata but does not choose a storage
backend and does not require plaintext access for routing.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PayloadEncryptionPolicy:
    """Payload encryption policy marker."""

    mode: str = "none"
    required: bool = False


DEBUG_PLAINTEXT_POLICY = PayloadEncryptionPolicy(mode="none", required=False)
PRODUCTION_ENCRYPTED_POLICY = PayloadEncryptionPolicy(mode="x25519-box", required=True)

