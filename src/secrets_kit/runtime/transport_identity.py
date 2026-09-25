"""
secrets_kit.runtime.transport_identity

Sign and verify ephemeral transport-identity bindings.

The runtime treats ``transport_identity`` as an opaque string. It performs
node-key cryptography and Peer Registry admission checks, but it does not
import transport implementations, resolve endpoints, or persist routes.
"""

from __future__ import annotations

import re
from typing import Any

from secrets_kit.backends.sqlite.gate import open_sqlite_backend
from secrets_kit.backends.sqlite.node_identity import load_sqlite_node_identity_material
from secrets_kit.backends.sqlite.peer_registry import (
    ADMISSION_STATE_ACTIVE,
    get_peer_registry_entry,
)
from secrets_kit.crypto.canonical import canonical_json_bytes
from secrets_kit.crypto.codecs import decode_b64url, encode_b64url
from secrets_kit.crypto.signatures import sign_ed25519, verify_ed25519
from secrets_kit.identifiers import validate_identifier

TRANSPORT_BINDING_VERSION = 1
TRANSPORT_BINDING_ALGORITHM = "ed25519"
_CHALLENGE_RE = re.compile(r"^[0-9a-f]{64}$")


class TransportIdentityError(ValueError):
    """Raised when an ephemeral transport binding is malformed or invalid."""


def sign_transport_binding(*, challenge: str, transport_identity: str) -> dict[str, Any]:
    """
    Sign one ephemeral transport binding with the local node identity.

    The returned claim contains no endpoint and changes no durable state.
    ``transport_identity`` is opaque to the runtime.
    """
    challenge = _validate_challenge(challenge)
    transport_identity = _validate_transport_identity(transport_identity)
    conn = open_sqlite_backend()
    try:
        identity = load_sqlite_node_identity_material(conn=conn)
    finally:
        conn.close()
    unsigned = _unsigned_claim(
        node_id=identity.node_id,
        challenge=challenge,
        transport_identity=transport_identity,
    )
    signature = sign_ed25519(
        private_key=identity.signing.private_key,
        message=canonical_json_bytes(unsigned),
    )
    return {**unsigned, "signature": encode_b64url(signature)}


def verify_transport_binding(
    *,
    claim: object,
    expected_challenge: str,
    expected_transport_identity: str,
) -> str:
    """
    Verify a remote binding and return its admitted Secrets Kit node ID.

    Verification requires an active Peer Registry admission and the admitted
    Ed25519 public key. Application synchronization authorization remains a
    separate runtime decision at envelope delivery and inbound processing.
    """
    expected_challenge = _validate_challenge(expected_challenge)
    expected_transport_identity = _validate_transport_identity(expected_transport_identity)
    value = _validate_claim(claim)
    if value["challenge"] != expected_challenge:
        raise TransportIdentityError("transport binding challenge does not match")
    if value["transport_identity"] != expected_transport_identity:
        raise TransportIdentityError("transport binding identity does not match connection")

    conn = open_sqlite_backend()
    try:
        entry = get_peer_registry_entry(conn=conn, node_id=value["node_id"])
    finally:
        conn.close()
    if entry is None or entry.admission_state != ADMISSION_STATE_ACTIVE:
        raise TransportIdentityError(
            f"transport binding peer is not admitted: peer_id={value['node_id']}"
        )
    if entry.signing_algorithm != TRANSPORT_BINDING_ALGORITHM or not entry.signing_public_key:
        raise TransportIdentityError("transport binding peer signing key is unavailable")
    try:
        public_key = decode_b64url(entry.signing_public_key)
        signature = decode_b64url(value["signature"])
        valid = verify_ed25519(
            public_key=public_key,
            message=canonical_json_bytes({**value, "signature": None}),
            signature=signature,
        )
    except (TypeError, ValueError) as exc:
        raise TransportIdentityError(f"transport binding signature is invalid: {exc}") from exc
    if not valid:
        raise TransportIdentityError("transport binding signature is invalid")
    return value["node_id"]


def _unsigned_claim(*, node_id: str, challenge: str, transport_identity: str) -> dict[str, Any]:
    validate_identifier(value=node_id, expected_type="node", field="node_id")
    return {
        "version": TRANSPORT_BINDING_VERSION,
        "algorithm": TRANSPORT_BINDING_ALGORITHM,
        "node_id": node_id,
        "challenge": challenge,
        "transport_identity": transport_identity,
        "signature": None,
    }


def _validate_claim(claim: object) -> dict[str, Any]:
    if not isinstance(claim, dict):
        raise TransportIdentityError("transport binding claim must be an object")
    allowed = {
        "version",
        "algorithm",
        "node_id",
        "challenge",
        "transport_identity",
        "signature",
    }
    if set(claim) != allowed:
        raise TransportIdentityError("transport binding claim fields are invalid")
    if claim.get("version") != TRANSPORT_BINDING_VERSION:
        raise TransportIdentityError("transport binding version is unsupported")
    if claim.get("algorithm") != TRANSPORT_BINDING_ALGORITHM:
        raise TransportIdentityError("transport binding algorithm is unsupported")
    node_id = claim.get("node_id")
    if not isinstance(node_id, str):
        raise TransportIdentityError("transport binding node_id is required")
    try:
        node_id = validate_identifier(value=node_id, expected_type="node", field="node_id")
    except ValueError as exc:
        raise TransportIdentityError(str(exc)) from exc
    challenge = _validate_challenge(claim.get("challenge"))
    transport_identity = _validate_transport_identity(claim.get("transport_identity"))
    signature = claim.get("signature")
    if not isinstance(signature, str) or not signature:
        raise TransportIdentityError("transport binding signature is required")
    try:
        decoded = decode_b64url(signature)
    except (TypeError, ValueError) as exc:
        raise TransportIdentityError("transport binding signature is invalid") from exc
    if len(decoded) != 64:
        raise TransportIdentityError("transport binding signature must be 64 raw bytes")
    return {
        "version": TRANSPORT_BINDING_VERSION,
        "algorithm": TRANSPORT_BINDING_ALGORITHM,
        "node_id": node_id,
        "challenge": challenge,
        "transport_identity": transport_identity,
        "signature": signature,
    }


def _validate_challenge(value: object) -> str:
    if not isinstance(value, str) or _CHALLENGE_RE.fullmatch(value) is None:
        raise TransportIdentityError("transport binding challenge must be 32-byte lowercase hex")
    return value


def _validate_transport_identity(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise TransportIdentityError("transport identity must be a non-empty bounded string")
    return value


__all__ = [
    "TRANSPORT_BINDING_ALGORITHM",
    "TRANSPORT_BINDING_VERSION",
    "TransportIdentityError",
    "sign_transport_binding",
    "verify_transport_binding",
]
