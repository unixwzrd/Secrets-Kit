"""
secrets_kit.runtime.inbound_envelopes

Validate and apply inbound protocol envelopes through the runtime boundary.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from secrets_kit.backends.sqlite.connection import transaction as sqlite_transaction
from secrets_kit.backends.sqlite.exceptions import SQLiteValidationError
from secrets_kit.backends.sqlite.gate import open_sqlite_backend
from secrets_kit.backends.sqlite.local_node import load_local_node_projection
from secrets_kit.backends.sqlite.models import Transaction
from secrets_kit.backends.sqlite.node_identity import load_sqlite_node_identity_material
from secrets_kit.backends.sqlite.peer_registry import (
    get_peer_registry_entry,
    require_peer_synchronization_eligible,
)
from secrets_kit.backends.sqlite.sync_storage import localize_inbound_storage_payload
from secrets_kit.backends.sqlite.transaction_engine import (
    REMOTE_TRANSACTION_POLICY,
    submit_transaction,
)
from secrets_kit.backends.sqlite.transaction_scope import service_group_scope_id
from secrets_kit.backends.sqlite.transactions import (
    create_transaction,
    transaction_exists,
)
from secrets_kit.crypto.codecs import decode_b64url
from secrets_kit.protocol.envelope import (
    ENVELOPE_TYPE_TRANSACTION,
    CanonicalEnvelope,
    EnvelopeValidationError,
    canonical_envelope_dict,
    parse_envelope_bytes,
    parse_envelope_mapping,
)
from secrets_kit.protocol.envelope_signing import EnvelopeSignatureError, verify_envelope_signature
from secrets_kit.protocol.payload_codec import (
    ENCRYPTED_CODEC_MODE,
    EnvelopePayloadCodecError,
    EnvelopePayloadContext,
    encrypted_envelope_payload_codec,
    payload_codec_metadata,
)

_TRANSACTION_REQUIRED_FIELDS = frozenset(
    {"transaction_id", "transaction_type", "origin_node_id", "created_at", "payload"}
)
_TRANSACTION_OPTIONAL_FIELDS = frozenset(
    {
        "transaction_version",
        "payload_version",
        "protocol_version",
        "organization_id",
        "client_id",
        "owner_id",
        "previous_transaction_id",
        "state",
        "received_at",
        "applied_at",
        "acknowledged_at",
        "cleared_at",
    }
)
_ADMISSION_TRANSACTION_TYPES = frozenset(
    {
        "peer.admission.request",
        "peer.admission.accept",
        "peer.admission.reject",
    }
)


def transaction_from_envelope_payload(*, payload: object) -> Transaction:
    """
    Build a Transaction from one inbound transaction-envelope payload.

    Args:
        payload:
            Envelope payload object.

    Returns:
        Transaction model.

    Raises:
        SQLiteValidationError:
            Payload is malformed or unsupported.

    Side Effects:
        None.
    """
    if not isinstance(payload, Mapping):
        raise SQLiteValidationError("transaction payload must be an object")
    for field_name in sorted(_TRANSACTION_REQUIRED_FIELDS):
        if field_name not in payload:
            raise SQLiteValidationError(f"transaction.{field_name} is required")
    if not isinstance(payload["payload"], Mapping):
        raise SQLiteValidationError("transaction.payload must be an object")
    if payload.get("signature") is not None:
        raise SQLiteValidationError("transaction.signature is not supported over JSON envelope")

    kwargs: dict[str, Any] = {
        "transaction_id": payload["transaction_id"],
        "transaction_type": payload["transaction_type"],
        "origin_node_id": payload["origin_node_id"],
        "created_at": payload["created_at"],
        "payload": payload["payload"],
    }
    for field_name in _TRANSACTION_OPTIONAL_FIELDS:
        if field_name in payload:
            kwargs[field_name] = payload[field_name]
    return create_transaction(**kwargs)


def apply_inbound_transaction(*, transaction: Transaction) -> None:
    """
    Insert and apply one inbound transaction through the local SQLite boundary.

    Args:
        transaction:
            Inbound transaction.

    Returns:
        None.

    Raises:
        SQLiteValidationError:
            Origin node is unknown or transaction/projection validation fails.
        sqlite3.Error:
            SQLite persistence failure.

    Side Effects:
        Inserts transaction rows and applies projections atomically.
    """
    conn = open_sqlite_backend()
    try:
        with sqlite_transaction(conn=conn):
            if transaction.transaction_type not in _ADMISSION_TRANSACTION_TYPES:
                local_node = load_local_node_projection(conn=conn)
                if local_node is not None and transaction.origin_node_id == local_node.node_id:
                    if not transaction_exists(
                        conn=conn,
                        transaction_id=transaction.transaction_id,
                    ):
                        raise SQLiteValidationError(
                            "remote transaction cannot claim local origin: "
                            f"transaction_id={transaction.transaction_id} "
                            f"origin_node_id={transaction.origin_node_id}"
                        )
                else:
                    require_peer_synchronization_eligible(
                        conn=conn,
                        node_id=transaction.origin_node_id,
                        service_group_id=service_group_scope_id(transaction=transaction),
                    )
            submit_transaction(conn=conn, transaction=transaction, policy=REMOTE_TRANSACTION_POLICY)
    finally:
        conn.close()


def apply_inbound_transaction_envelope(*, envelope: Mapping[str, Any]) -> None:
    """
    Apply one validated transaction envelope.

    Args:
        envelope:
            Daemon envelope mapping.

    Returns:
        None.

    Raises:
        SQLiteValidationError:
            Envelope or transaction payload is invalid.

    Side Effects:
        Applies the transaction to local SQLite state.
    """
    try:
        canonical_envelope = parse_envelope_mapping(payload=envelope)
    except EnvelopeValidationError as exc:
        raise SQLiteValidationError(f"invalid envelope: {exc}") from exc
    _verify_inbound_envelope_signature(envelope=canonical_envelope)
    envelope = canonical_envelope_dict(envelope=canonical_envelope)
    if envelope.get("message_type") != ENVELOPE_TYPE_TRANSACTION:
        raise SQLiteValidationError("invalid envelope: message_type must be transaction")
    try:
        decoded_payload = json.loads(
            _decode_inbound_envelope_payload(envelope=canonical_envelope).decode("utf-8")
        )
    except (EnvelopePayloadCodecError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SQLiteValidationError(f"invalid envelope payload codec: {exc}") from exc
    if not isinstance(decoded_payload, dict):
        raise SQLiteValidationError("transaction payload must be an object")
    raw_transaction_payload = decoded_payload.get("payload")
    if not isinstance(raw_transaction_payload, Mapping):
        raise SQLiteValidationError("transaction.payload must be an object")
    conn = open_sqlite_backend()
    try:
        localized_payload = localize_inbound_storage_payload(
            conn=conn,
            transaction_id=str(decoded_payload.get("transaction_id", "")),
            transaction_type=str(decoded_payload.get("transaction_type", "")),
            payload=raw_transaction_payload,
        )
    finally:
        conn.close()
    transaction = transaction_from_envelope_payload(
        payload={**decoded_payload, "payload": localized_payload}
    )
    if transaction.transaction_id != envelope.get("transaction_id"):
        raise SQLiteValidationError("transaction_id must match envelope transaction_id")
    if transaction.origin_node_id != envelope.get("source_node_id"):
        raise SQLiteValidationError("origin_node_id must match envelope source_node_id")
    apply_inbound_transaction(transaction=transaction)


def apply_inbound_transaction_envelope_bytes(*, data: bytes) -> None:
    """
    Decode, validate, and apply one inbound transaction envelope.

    Args:
        data:
            Raw JSON envelope bytes.

    Returns:
        None.

    Raises:
        SQLiteValidationError:
            Envelope JSON, envelope shape, or transaction payload is invalid.

    Side Effects:
        Applies the transaction to local SQLite state.
    """
    try:
        envelope = parse_envelope_bytes(data=data)
    except EnvelopeValidationError as exc:
        raise SQLiteValidationError(f"invalid envelope: {exc}") from exc
    apply_inbound_transaction_envelope(envelope=canonical_envelope_dict(envelope=envelope))


def _verify_inbound_envelope_signature(*, envelope: CanonicalEnvelope) -> None:
    conn = open_sqlite_backend()
    try:
        try:
            metadata = payload_codec_metadata(payload=envelope.payload)
        except EnvelopePayloadCodecError as exc:
            raise SQLiteValidationError(f"invalid envelope payload codec: {exc}") from exc
        if metadata.get("mode") != ENCRYPTED_CODEC_MODE:
            raise SQLiteValidationError("live synchronization requires encrypted envelopes")
        local_node = load_local_node_projection(conn=conn)
        if local_node is None:
            raise SQLiteValidationError("local node identity projection is missing")
        if envelope.destination_node_id != local_node.node_id:
            raise SQLiteValidationError(
                "envelope destination does not match local node: "
                f"destination_node_id={envelope.destination_node_id} local_node_id={local_node.node_id}"
            )
        entry = get_peer_registry_entry(conn=conn, node_id=envelope.source_node_id)
        if entry is None:
            raise SQLiteValidationError(f"unknown peer: peer_id={envelope.source_node_id}")
        if not entry.synchronization_eligible:
            raise SQLiteValidationError(
                "peer synchronization not permitted: "
                f"peer_id={envelope.source_node_id} admission_state={entry.admission_state} "
                f"authorization_state={entry.authorization_state}"
            )
        if entry.signing_algorithm != "ed25519":
            raise SQLiteValidationError(
                "peer signing algorithm is unsupported: "
                f"peer_id={envelope.source_node_id} algorithm={entry.signing_algorithm}"
            )
        if not entry.signing_public_key:
            raise SQLiteValidationError(
                f"peer signing public key is missing: peer_id={envelope.source_node_id}"
            )
        try:
            signing_public_key = decode_b64url(entry.signing_public_key)
        except ValueError as exc:
            raise SQLiteValidationError(
                f"peer signing public key is invalid: peer_id={envelope.source_node_id}"
            ) from exc
        try:
            verify_envelope_signature(
                envelope=envelope,
                expected_signer_node_id=envelope.source_node_id,
                signing_public_key=signing_public_key,
                expected_key_fingerprint=entry.signing_fingerprint,
            )
        except EnvelopeSignatureError as exc:
            raise SQLiteValidationError(
                f"invalid envelope signature: peer_id={envelope.source_node_id}: {exc}"
            ) from exc
    finally:
        conn.close()


def _decode_inbound_envelope_payload(*, envelope: CanonicalEnvelope) -> bytes:
    try:
        metadata = payload_codec_metadata(payload=envelope.payload)
    except EnvelopePayloadCodecError as exc:
        raise SQLiteValidationError(f"invalid envelope payload codec: {exc}") from exc
    if metadata.get("mode") != ENCRYPTED_CODEC_MODE:
        raise SQLiteValidationError("live synchronization requires encrypted envelopes")
    conn = open_sqlite_backend()
    try:
        identity = load_sqlite_node_identity_material(conn=conn)
    finally:
        conn.close()
    try:
        return encrypted_envelope_payload_codec(
            context=EnvelopePayloadContext(
                envelope_id=envelope.envelope_id,
                source_node_id=envelope.source_node_id,
                destination_node_id=envelope.destination_node_id,
                transaction_id=envelope.transaction_id,
                envelope_version=envelope.envelope_version,
                protocol_version=envelope.protocol_version,
            ),
            local_private_key=identity.encryption.private_key,
            local_public_key=identity.encryption.public_key,
            encryption_metadata=envelope.encryption_metadata,
        ).decode(payload=envelope.payload)
    except EnvelopePayloadCodecError as exc:
        raise SQLiteValidationError(f"invalid encrypted envelope payload: {exc}") from exc


__all__ = [
    "apply_inbound_transaction",
    "apply_inbound_transaction_envelope",
    "apply_inbound_transaction_envelope_bytes",
    "transaction_from_envelope_payload",
]


def main() -> int:
    """Apply daemon-supplied stdin bytes using the unchanged runtime boundary.

    Internal subprocess entrypoint only. Preserve exit-zero success and reject
    every application failure without emitting payloads or exception details.
    Avoid importing unrelated customer CLI commands for each received envelope.
    """
    import sys

    if sys.argv[1:] != ["--stdin"]:
        return 2
    try:
        apply_inbound_transaction_envelope_bytes(data=sys.stdin.buffer.read())
    except Exception:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
