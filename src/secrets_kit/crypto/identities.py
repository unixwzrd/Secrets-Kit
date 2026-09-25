"""
secrets_kit.crypto.identities

Compatibility exports for authoritative identity models.

Identity construction and serialization live in ``secrets_kit.crypto.models``.
This module preserves the older import location without maintaining a second
``NodeIdentity`` implementation.
"""

from __future__ import annotations

from secrets_kit.crypto.models import (
    NodeIdentity,
    generate_node_identity,
    node_identity_from_dict,
    node_identity_to_dict,
)

__all__ = [
    "NodeIdentity",
    "generate_node_identity",
    "node_identity_from_dict",
    "node_identity_to_dict",
]
