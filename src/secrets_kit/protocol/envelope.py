"""Signed routing envelope structures."""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from secrets_kit.protocol.routing import RouteMetadata

PROTOCOL_MAJOR = 1
PROTOCOL_MINOR = 0


class ProtocolVersionError(ValueError):
    """Unsupported protocol version."""


@dataclass(frozen=True)
class Principal:
    """Symbolic protocol identity, independent of transport address."""

    node_id: str
    agent_id: Optional[str] = None
    instance_id: Optional[str] = None
    signing_fingerprint: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Principal":
        node_id = str(raw.get("node_id", "")).strip()
        if not node_id:
            raise ValueError("principal.node_id is required")
        return cls(
            node_id=node_id,
            agent_id=_optional_str(raw.get("agent_id")),
            instance_id=_optional_str(raw.get("instance_id")),
            signing_fingerprint=_optional_str(raw.get("signing_fingerprint")),
        )


@dataclass(frozen=True)
class PayloadMetadata:
    """Payload codec and encryption metadata. Payload bytes remain opaque here."""

    codec: str = "json"
    content_type: str = "application/octet-stream"
    encryption: str = "none"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "PayloadMetadata":
        return cls(
            codec=str(raw.get("codec", "json")),
            content_type=str(raw.get("content_type", "application/octet-stream")),
            encryption=str(raw.get("encryption", "none")),
        )


@dataclass(frozen=True)
class ReplayMetadata:
    """Replay protection metadata."""

    nonce: str = field(default_factory=lambda: str(uuid.uuid4()))
    sequence: Optional[int] = None
    previous_message_id: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ReplayMetadata":
        seq = raw.get("sequence")
        return cls(
            nonce=str(raw.get("nonce", "")).strip() or str(uuid.uuid4()),
            sequence=int(seq) if seq is not None else None,
            previous_message_id=_optional_str(raw.get("previous_message_id")),
        )


@dataclass(frozen=True)
class SignatureMetadata:
    """Signature algorithm, key id, and signature value."""

    alg: str = "ed25519"
    key_id: str = ""
    signed_fields: tuple[str, ...] = ("protocol_version", "message_id", "sender", "recipient", "created_at", "expires_at", "route", "payload", "replay")
    value: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["signed_fields"] = list(self.signed_fields)
        if self.value is None:
            out.pop("value", None)
        return out

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "SignatureMetadata":
        fields = raw.get("signed_fields") or ()
        return cls(
            alg=str(raw.get("alg", "ed25519")),
            key_id=str(raw.get("key_id", "")),
            signed_fields=tuple(str(v) for v in fields),
            value=_optional_str(raw.get("value")),
        )


@dataclass(frozen=True)
class MessageEnvelope:
    """Protocol routing envelope around an opaque payload string."""

    protocol_version: str
    message_id: str
    sender: Principal
    recipient: Principal
    route: RouteMetadata
    payload: PayloadMetadata
    payload_body: str
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    correlation_id: Optional[str] = None
    expires_at: Optional[str] = None
    ttl_seconds: Optional[int] = None
    replay: ReplayMetadata = field(default_factory=ReplayMetadata)
    signature: SignatureMetadata = field(default_factory=SignatureMetadata)

    def to_dict(self, *, include_signature_value: bool = True) -> dict[str, Any]:
        sig = self.signature.to_dict()
        if not include_signature_value:
            sig.pop("value", None)
        out: dict[str, Any] = {
            "protocol_version": self.protocol_version,
            "message_id": self.message_id,
            "sender": self.sender.to_dict(),
            "recipient": self.recipient.to_dict(),
            "source_instance_id": self.sender.instance_id,
            "destination_instance_id": self.recipient.instance_id,
            "created_at": self.created_at,
            "route": self.route.to_dict(),
            "payload": self.payload.to_dict(),
            "payload_body": self.payload_body,
            "replay": self.replay.to_dict(),
            "signature": sig,
        }
        if self.correlation_id is not None:
            out["correlation_id"] = self.correlation_id
        if self.expires_at is not None:
            out["expires_at"] = self.expires_at
        if self.ttl_seconds is not None:
            out["ttl_seconds"] = int(self.ttl_seconds)
        return {k: v for k, v in out.items() if v is not None}

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "MessageEnvelope":
        reject_unsupported_major(raw.get("protocol_version"))
        return cls(
            protocol_version=str(raw["protocol_version"]),
            message_id=str(raw["message_id"]),
            correlation_id=_optional_str(raw.get("correlation_id")),
            sender=Principal.from_dict(dict(raw["sender"])),
            recipient=Principal.from_dict(dict(raw["recipient"])),
            created_at=str(raw["created_at"]),
            expires_at=_optional_str(raw.get("expires_at")),
            ttl_seconds=int(raw["ttl_seconds"]) if raw.get("ttl_seconds") is not None else None,
            route=RouteMetadata.from_dict(dict(raw["route"])),
            payload=PayloadMetadata.from_dict(dict(raw.get("payload") or {})),
            payload_body=str(raw.get("payload_body", "")),
            replay=ReplayMetadata.from_dict(dict(raw.get("replay") or {})),
            signature=SignatureMetadata.from_dict(dict(raw.get("signature") or {})),
        )


def protocol_version() -> str:
    return f"{PROTOCOL_MAJOR}.{PROTOCOL_MINOR}"


def reject_unsupported_major(version: Any) -> None:
    """Reject unsupported major protocol versions with a diagnostic error."""
    raw = str(version or "").strip()
    try:
        major = int(raw.split(".", 1)[0])
    except (ValueError, IndexError) as exc:
        raise ProtocolVersionError(f"invalid protocol_version: {raw!r}") from exc
    if major != PROTOCOL_MAJOR:
        raise ProtocolVersionError(f"unsupported protocol major version {major}; expected {PROTOCOL_MAJOR}")


def build_message_envelope(
    *,
    sender: Principal,
    recipient: Principal,
    route: RouteMetadata,
    payload_body: str,
    payload: Optional[PayloadMetadata] = None,
    correlation_id: Optional[str] = None,
    ttl_seconds: Optional[int] = None,
) -> MessageEnvelope:
    """Build an unsigned message envelope with generated ids."""
    return MessageEnvelope(
        protocol_version=protocol_version(),
        message_id=str(uuid.uuid4()),
        correlation_id=correlation_id,
        sender=sender,
        recipient=recipient,
        route=route,
        payload=payload or PayloadMetadata(),
        payload_body=payload_body,
        ttl_seconds=ttl_seconds,
    )


def _optional_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    out = str(value).strip()
    return out or None

