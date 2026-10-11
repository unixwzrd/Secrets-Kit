"""secrets_kit.protocol.peer_invitation

Bounded encrypted invitation framing, separate from peer admission and billing.
Existing AEAD, HKDF and Ed25519 helpers own cryptographic primitives. A code
anchors the issuer key; possessing it never creates a signed peer acceptance.
Orchestration must enforce consent, original expiry and single-use state.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidTag

from secrets_kit.crypto.canonical import canonical_json_bytes
from secrets_kit.crypto.codecs import (
    decode_b64url,
    decode_encrypted_blob,
    encode_b64url,
    encode_encrypted_blob,
)
from secrets_kit.crypto.encryption import decrypt_aead, encrypt_aead
from secrets_kit.crypto.keys import derive_hkdf_sha256, generate_symmetric_key
from secrets_kit.crypto.signatures import sign_ed25519, verify_ed25519

INVITATION_PROTOCOL = "peer_invitation/v1"
MAX_INVITATION_BYTES = 32768
MAX_INVITATION_LIFETIME = 900
_STAGES = {"offer": "source", "join": "target", "approve": "source", "complete": "target"}


class InvitationError(ValueError):
    """Safe invitation failure; never include codes or decrypted contents."""


def _key_bytes(value: object) -> bytes:
    if not isinstance(value, str) or len(value) != 43:
        raise InvitationError("invitation key is invalid")
    raw = decode_b64url(value)
    if len(raw) != 32 or encode_b64url(raw) != value:
        raise InvitationError("invitation key is invalid")
    return raw


@dataclass(frozen=True)
class InvitationSecret:
    """Client-only code material; secret bytes never appear in repr/logs."""

    root_key: bytes = field(repr=False)
    issuer_key_hash: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if len(self.root_key) != 32 or len(self.issuer_key_hash) != 32:
            raise InvitationError("invitation key is invalid")

    @classmethod
    def create(cls, *, issuer_public_key: bytes) -> InvitationSecret:
        if len(issuer_public_key) != 32:
            raise InvitationError("invitation issuer is invalid")
        return cls(generate_symmetric_key(), hashlib.sha256(issuer_public_key).digest())

    @classmethod
    def from_code(cls, code: str) -> InvitationSecret:
        try:
            if not isinstance(code, str) or len(code) != 92:
                raise InvitationError("invitation code is invalid")
            prefix, root, issuer = code.split(".")
            if prefix != "skp1":
                raise InvitationError("invitation code is invalid")
            return cls(_key_bytes(root), _key_bytes(issuer))
        except (ValueError, TypeError):
            raise InvitationError("invitation code is invalid") from None

    def code(self) -> str:
        """Return only for intentional private handoff, never command arguments."""
        return f"skp1.{encode_b64url(self.root_key)}.{encode_b64url(self.issuer_key_hash)}"

    @property
    def session_id(self) -> str:
        return encode_b64url(self.derive("session"))

    def derive(self, purpose: str) -> bytes:
        if purpose not in {"session", "read", "join", *[f"encrypt:{stage}" for stage in _STAGES]}:
            raise InvitationError("invitation key purpose is invalid")
        return derive_hkdf_sha256(self.root_key, f"{INVITATION_PROTOCOL}:{purpose}".encode("ascii"))


def _context(secret: InvitationSecret, stage: str) -> dict[str, str]:
    if stage not in _STAGES:
        raise InvitationError("invitation stage is invalid")
    return {"protocol": INVITATION_PROTOCOL, "session_id": secret.session_id,
            "role": _STAGES[stage], "stage": stage}


def seal_invitation_message(
    *, secret: InvitationSecret, stage: str, body: dict[str, Any],
    signing_private_key: bytes, signing_public_key: bytes, expires_at: int,
    now: int | None = None,
) -> bytes:
    """Sign and encrypt one bounded phase; neither operation grants admission."""
    current = int(time.time()) if now is None else now
    if type(expires_at) is not int or not current < expires_at <= current + MAX_INVITATION_LIFETIME:
        raise InvitationError("invitation lifetime is invalid")
    context = _context(secret, stage)
    payload = {**context, "issued_at": current, "expires_at": expires_at, "body": body}
    signed = {"payload": payload, "signing_public_key": encode_b64url(signing_public_key),
              "signature": encode_b64url(sign_ed25519(signing_private_key, canonical_json_bytes(payload)))}
    raw = canonical_json_bytes(signed)
    if len(raw) > MAX_INVITATION_BYTES // 2:
        raise InvitationError("invitation message is too large")
    blob = encrypt_aead(key=secret.derive(f"encrypt:{stage}"), plaintext=raw,
                        aad=canonical_json_bytes(context), context=INVITATION_PROTOCOL)
    return encode_encrypted_blob(blob)


def open_invitation_message(
    *, secret: InvitationSecret, stage: str, data: bytes, now: int | None = None,
    expected_signer: bytes | None = None, expected_expires_at: int | None = None,
) -> tuple[dict[str, Any], bytes, int]:
    """Verify phase, issuer/target key and signed deadline without applying state.

    Only a first join may supply a previously unknown signer. Completion must
    use the explicitly approved target key; subsequent phases retain expiry.
    """
    try:
        if not isinstance(data, bytes) or len(data) > MAX_INVITATION_BYTES:
            raise InvitationError("invitation message is invalid")
        context = _context(secret, stage)
        blob = decode_encrypted_blob(data)
        if blob.header.context != INVITATION_PROTOCOL:
            raise InvitationError("invitation context is invalid")
        raw = decrypt_aead(key=secret.derive(f"encrypt:{stage}"), blob=blob, aad=canonical_json_bytes(context))
        value = json.loads(raw)
        if not isinstance(value, dict) or set(value) != {"payload", "signing_public_key", "signature"}:
            raise InvitationError("invitation message is invalid")
        payload = value["payload"]
        if not isinstance(payload, dict) or set(payload) != {*context, "issued_at", "expires_at", "body"}:
            raise InvitationError("invitation message is invalid")
        if any(payload[key] != item for key, item in context.items()) or not isinstance(payload["body"], dict):
            raise InvitationError("invitation message is invalid")
        current = int(time.time()) if now is None else now
        issued, expiry = payload["issued_at"], payload["expires_at"]
        if (type(issued) is not int or type(expiry) is not int or issued > current + 30
                or not 0 < expiry - issued <= MAX_INVITATION_LIFETIME or expiry <= current
                or (expected_expires_at is not None and expiry != expected_expires_at)):
            raise InvitationError("invitation expired or deadline changed")
        if stage != "offer" and expected_expires_at is None:
            raise InvitationError("original invitation deadline is required")
        signer = _key_bytes(value["signing_public_key"])
        if stage in {"offer", "approve"} and hashlib.sha256(signer).digest() != secret.issuer_key_hash:
            raise InvitationError("invitation issuer changed")
        if expected_signer is not None and signer != expected_signer:
            raise InvitationError("invitation signer changed")
        if stage == "complete" and expected_signer is None:
            raise InvitationError("approved target signer is required")
        signature = decode_b64url(value["signature"])
        if len(signature) != 64 or not verify_ed25519(signer, canonical_json_bytes(payload), signature):
            raise InvitationError("invitation signature is invalid")
        return payload["body"], signer, expiry
    except (ValueError, TypeError, KeyError, InvalidTag, UnicodeError):
        raise InvitationError("invitation verification failed") from None
