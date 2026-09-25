"""
secrets_kit.protocol.envelope

Canonical protocol envelope representation and serialization.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from secrets_kit.crypto.canonical import canonical_json_bytes
from secrets_kit.identifiers import (
    IdentifierValidationError,
    deterministic_identifier,
    validate_identifier,
)
from secrets_kit.models import now_utc_iso
from secrets_kit.protocol.payload_codec import (
    ENCRYPTED_CODEC_MODE,
    EnvelopePayloadCodec,
    EnvelopePayloadCodecError,
    EnvelopePayloadContext,
    encoded_payload_bytes,
    payload_codec_metadata,
    validate_encryption_metadata,
    validate_payload_codec_metadata,
)

CANONICAL_ENVELOPE_VERSION = 1
ENVELOPE_TYPE_TRANSACTION = "transaction"

_REQUIRED_FIELDS = frozenset(
    {
        "version",
        "envelope_version",
        "envelope_id",
        "message_type",
        "message_id",
        "source_node_id",
        "destination_node_id",
        "transaction_id",
        "protocol_version",
        "created_at",
        "expires_at",
        "routing",
        "payload",
        "payload_hash",
        "signature_metadata",
        "encryption_metadata",
    }
)
_ALLOWED_FIELDS = _REQUIRED_FIELDS | {"expires_at"}


class EnvelopeValidationError(ValueError):
    """Raised when a protocol envelope is malformed."""


@dataclass(frozen=True)
class CanonicalEnvelope:
    """
    Immutable protocol envelope.

    Local transport metadata such as retry counters, claim timestamps, delivery
    timestamps, and failure diagnostics intentionally live outside this object.
    """

    envelope_id: str
    source_node_id: str
    destination_node_id: str
    transaction_id: str
    payload: dict[str, Any]
    created_at: str
    payload_hash: str
    version: int = 1
    envelope_version: int = CANONICAL_ENVELOPE_VERSION
    message_type: str = ENVELOPE_TYPE_TRANSACTION
    protocol_version: int = 1
    routing: dict[str, Any] = field(default_factory=dict)
    expires_at: str | None = None
    signature_metadata: dict[str, Any] | None = None
    encryption_metadata: dict[str, Any] | None = None

    @property
    def message_id(self) -> str:
        return self.envelope_id


def build_transaction_envelope(
    *,
    transaction: Any,
    destination_node_id: str,
    envelope_id: str | None = None,
    created_at: str | None = None,
    routing: Mapping[str, Any] | None = None,
    expires_at: str | None = None,
    payload_codec: EnvelopePayloadCodec,
) -> CanonicalEnvelope:
    """
    Build a canonical transaction envelope from a transaction model.

    The transaction object is intentionally accepted structurally so the
    protocol layer does not import SQLite backend models.
    """
    source_node_id = _required_string(transaction.origin_node_id, field_name="origin_node_id")
    transaction_id = _required_string(transaction.transaction_id, field_name="transaction_id")
    validate_identifier(value=source_node_id, expected_type="node", field="source_node_id")
    validate_identifier(value=destination_node_id, expected_type="node", field="destination_node_id")
    validate_identifier(value=transaction_id, expected_type="transaction", field="transaction_id")
    resolved_envelope_id = envelope_id or deterministic_identifier(
        identifier_type="envelope",
        namespace="protocol.envelope",
        name=f"{transaction_id}\0{destination_node_id}",
    )
    payload = transaction_payload(transaction=transaction)
    canonical_payload_bytes = canonical_json_bytes(payload)
    payload_record = payload_codec.with_context(
        EnvelopePayloadContext(
            envelope_id=resolved_envelope_id,
            source_node_id=source_node_id,
            destination_node_id=destination_node_id,
            transaction_id=transaction_id,
            envelope_version=CANONICAL_ENVELOPE_VERSION,
            protocol_version=int(transaction.protocol_version),
        )
    ).encode(canonical_payload_bytes=canonical_payload_bytes)
    return CanonicalEnvelope(
        envelope_id=resolved_envelope_id,
        source_node_id=source_node_id,
        destination_node_id=destination_node_id,
        transaction_id=transaction_id,
        payload=payload_record.payload,
        payload_hash=payload_commitment(encoded_payload_bytes=payload_record.encoded_payload_bytes),
        created_at=created_at or now_utc_iso(),
        protocol_version=int(transaction.protocol_version),
        routing=dict(routing or {}),
        expires_at=expires_at,
        encryption_metadata=payload_record.encryption_metadata,
    )


def transaction_payload(*, transaction: Any) -> dict[str, Any]:
    return {
        "transaction_id": transaction.transaction_id,
        "transaction_type": transaction.transaction_type,
        "transaction_version": transaction.transaction_version,
        "payload_version": transaction.payload_version,
        "protocol_version": transaction.protocol_version,
        "organization_id": transaction.organization_id,
        "client_id": transaction.client_id,
        "owner_id": transaction.owner_id,
        "origin_node_id": transaction.origin_node_id,
        "previous_transaction_id": transaction.previous_transaction_id,
        "payload": transaction.payload,
        "payload_hash": transaction.payload_hash,
        "signature": transaction.signature,
        "state": transaction.state,
        "created_at": transaction.created_at,
        "received_at": transaction.received_at,
        "applied_at": transaction.applied_at,
        "acknowledged_at": transaction.acknowledged_at,
        "cleared_at": transaction.cleared_at,
    }


def payload_commitment(*, encoded_payload_bytes: bytes) -> str:
    return hashlib.sha256(bytes(encoded_payload_bytes)).hexdigest()


def canonical_envelope_dict(*, envelope: CanonicalEnvelope) -> dict[str, Any]:
    return {
        "created_at": envelope.created_at,
        "destination_node_id": envelope.destination_node_id,
        "encryption_metadata": envelope.encryption_metadata,
        "envelope_id": envelope.envelope_id,
        "envelope_version": envelope.envelope_version,
        "expires_at": envelope.expires_at,
        "message_id": envelope.message_id,
        "message_type": envelope.message_type,
        "payload": envelope.payload,
        "payload_hash": envelope.payload_hash,
        "protocol_version": envelope.protocol_version,
        "routing": envelope.routing,
        "signature_metadata": envelope.signature_metadata,
        "source_node_id": envelope.source_node_id,
        "transaction_id": envelope.transaction_id,
        "version": envelope.version,
    }


def canonical_envelope_bytes(*, envelope: CanonicalEnvelope) -> bytes:
    return canonical_json_bytes(canonical_envelope_dict(envelope=envelope))


def parse_envelope_bytes(*, data: bytes) -> CanonicalEnvelope:
    try:
        payload = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_object_pairs,
        )
    except UnicodeDecodeError as exc:
        raise EnvelopeValidationError("envelope json must be UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise EnvelopeValidationError(f"envelope json is invalid: {exc}") from exc
    return parse_envelope_mapping(payload=payload)


def parse_envelope_mapping(*, payload: object) -> CanonicalEnvelope:
    if not isinstance(payload, Mapping):
        raise EnvelopeValidationError("envelope must be a JSON object")
    unknown = sorted(set(payload).difference(_ALLOWED_FIELDS))
    if unknown:
        raise EnvelopeValidationError(f"unknown envelope field: {unknown[0]}")
    missing = sorted(_REQUIRED_FIELDS.difference(payload))
    if missing:
        raise EnvelopeValidationError(f"missing required field: {missing[0]}")

    version = _required_int(payload["version"], field_name="version")
    envelope_version = _required_int(payload["envelope_version"], field_name="envelope_version")
    protocol_version = _required_int(payload["protocol_version"], field_name="protocol_version")
    if version != 1:
        raise EnvelopeValidationError("version is unsupported")
    if envelope_version != CANONICAL_ENVELOPE_VERSION:
        raise EnvelopeValidationError("envelope_version is unsupported")
    if protocol_version < 1:
        raise EnvelopeValidationError("protocol_version must be positive")

    envelope_id = _required_string(payload["envelope_id"], field_name="envelope_id")
    message_id = _required_string(payload["message_id"], field_name="message_id")
    if message_id != envelope_id:
        raise EnvelopeValidationError("message_id must match envelope_id")
    message_type = _required_string(payload["message_type"], field_name="message_type")
    if message_type != ENVELOPE_TYPE_TRANSACTION:
        raise EnvelopeValidationError("message_type is unsupported")

    source_node_id = _required_string(payload["source_node_id"], field_name="source_node_id")
    destination_node_id = _required_string(
        payload["destination_node_id"], field_name="destination_node_id"
    )
    transaction_id = _required_string(payload["transaction_id"], field_name="transaction_id")
    try:
        validate_identifier(value=envelope_id, expected_type="envelope", field="envelope_id")
        validate_identifier(value=source_node_id, expected_type="node", field="source_node_id")
        validate_identifier(
            value=destination_node_id,
            expected_type="node",
            field="destination_node_id",
        )
        validate_identifier(value=transaction_id, expected_type="transaction", field="transaction_id")
    except IdentifierValidationError as exc:
        raise EnvelopeValidationError(str(exc)) from exc

    created_at = _required_string(payload["created_at"], field_name="created_at")
    expires_at = payload.get("expires_at")
    if expires_at is not None:
        expires_at = _required_string(expires_at, field_name="expires_at")

    routing = payload["routing"]
    if not isinstance(routing, Mapping):
        raise EnvelopeValidationError("routing must be an object")
    payload_body = payload["payload"]
    if not isinstance(payload_body, Mapping):
        raise EnvelopeValidationError("payload must be an object")
    try:
        validate_payload_codec_metadata(metadata=payload_body.get("codec"))
        committed_payload_bytes = encoded_payload_bytes(payload=payload_body)
    except EnvelopePayloadCodecError as exc:
        raise EnvelopeValidationError(str(exc)) from exc

    payload_hash = _required_string(payload["payload_hash"], field_name="payload_hash")
    if len(payload_hash) != 64:
        raise EnvelopeValidationError("payload_hash must be a lowercase sha256 hex string")
    try:
        int(payload_hash, 16)
    except ValueError as exc:
        raise EnvelopeValidationError("payload_hash must be a lowercase sha256 hex string") from exc
    if payload_hash.lower() != payload_hash:
        raise EnvelopeValidationError("payload_hash must be a lowercase sha256 hex string")
    expected_hash = payload_commitment(encoded_payload_bytes=committed_payload_bytes)
    if payload_hash != expected_hash:
        raise EnvelopeValidationError("payload_hash does not match payload")

    signature_metadata = _optional_signature_metadata(
        payload["signature_metadata"],
        field_name="signature_metadata",
    )
    encryption_metadata = _optional_encryption_metadata(
        value=payload["encryption_metadata"],
        field_name="encryption_metadata",
        payload_body=payload_body,
        destination_node_id=destination_node_id,
    )
    envelope = CanonicalEnvelope(
        version=version,
        envelope_version=envelope_version,
        envelope_id=envelope_id,
        message_type=message_type,
        source_node_id=source_node_id,
        destination_node_id=destination_node_id,
        transaction_id=transaction_id,
        protocol_version=protocol_version,
        created_at=created_at,
        expires_at=expires_at,
        routing=dict(routing),
        payload=dict(payload_body),
        payload_hash=payload_hash,
        signature_metadata=signature_metadata,
        encryption_metadata=encryption_metadata,
    )
    if canonical_envelope_dict(envelope=envelope) != dict(payload):
        raise EnvelopeValidationError("envelope is not in canonical protocol shape")
    return envelope


def _required_string(value: object, *, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise EnvelopeValidationError(f"{field_name} must be a non-empty string")
    return value


def _required_int(value: object, *, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise EnvelopeValidationError(f"{field_name} must be an integer")
    return value


def _optional_metadata(value: object, *, field_name: str) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise EnvelopeValidationError(f"{field_name} must be null or an object")
    return dict(value)


def _optional_encryption_metadata(
    *,
    value: object,
    field_name: str,
    payload_body: Mapping[str, Any],
    destination_node_id: str,
) -> dict[str, Any] | None:
    metadata = _optional_metadata(value, field_name=field_name)
    codec_metadata = payload_codec_metadata(payload=payload_body)
    if codec_metadata.get("mode") == ENCRYPTED_CODEC_MODE:
        if metadata is None:
            raise EnvelopeValidationError("encryption_metadata is required for encrypted payloads")
        try:
            return validate_encryption_metadata(
                metadata=metadata,
                expected_recipient_node_id=destination_node_id,
            )
        except EnvelopePayloadCodecError as exc:
            raise EnvelopeValidationError(str(exc)) from exc
    if metadata is not None:
        raise EnvelopeValidationError("encryption_metadata is only supported for encrypted payloads")
    return None


def _optional_signature_metadata(value: object, *, field_name: str) -> dict[str, Any] | None:
    metadata = _optional_metadata(value, field_name=field_name)
    if metadata is None:
        return None
    from secrets_kit.protocol.envelope_signing import (  # noqa: PLC0415
        EnvelopeSignatureError,
        validate_signature_metadata,
    )

    try:
        return validate_signature_metadata(metadata=metadata)
    except EnvelopeSignatureError as exc:
        raise EnvelopeValidationError(str(exc)) from exc


def _reject_duplicate_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: set[str] = set()
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise EnvelopeValidationError(f"duplicate envelope field: {key}")
        seen.add(key)
        result[key] = value
    return result


__all__ = [
    "CANONICAL_ENVELOPE_VERSION",
    "ENVELOPE_TYPE_TRANSACTION",
    "CanonicalEnvelope",
    "EnvelopeValidationError",
    "build_transaction_envelope",
    "canonical_envelope_bytes",
    "canonical_envelope_dict",
    "parse_envelope_bytes",
    "parse_envelope_mapping",
    "payload_commitment",
    "transaction_payload",
]
