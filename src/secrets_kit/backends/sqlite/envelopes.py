"""
secrets_kit.backends.sqlite.envelopes

Persist and inspect canonical outbound envelopes without performing transport.
"""

from __future__ import annotations

import hashlib
import logging
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from secrets_kit.backends.sqlite.gate import sqlite_path
from secrets_kit.backends.sqlite.local_hierarchy import local_peer_group_id_for_node
from secrets_kit.backends.sqlite.models import Transaction
from secrets_kit.backends.sqlite.node_identity import load_sqlite_node_identity_material
from secrets_kit.backends.sqlite.peer_registry import (
    PeerRegistryEntry,
    get_peer_registry_entry,
    is_peer_synchronization_eligible,
    list_peer_registry_entries,
)
from secrets_kit.backends.sqlite.sync_storage import prepare_outbound_storage_payload
from secrets_kit.backends.sqlite.transaction_scope import service_group_scope_id
from secrets_kit.crypto.codecs import decode_b64url
from secrets_kit.identifiers import validate_identifier
from secrets_kit.protocol.envelope import (
    CanonicalEnvelope,
    build_transaction_envelope,
    canonical_envelope_bytes,
    parse_envelope_bytes,
)
from secrets_kit.protocol.envelope_signing import sign_envelope
from secrets_kit.protocol.payload_codec import (
    ENCRYPTED_CODEC_MODE,
    EnvelopePayloadCodec,
    configured_envelope_payload_codec_mode,
    encrypted_envelope_payload_codec,
    plaintext_envelope_payload_codec,
)

LOGGER = logging.getLogger(__name__)
AUTHORIZATION_DENIED_STATE = "authorization_denied"
RETRY_PENDING_STATE = "retry_pending"


@dataclass(frozen=True)
class EnvelopeInspection:
    """Operator-facing projection of one persisted envelope row."""

    envelope_id: str
    transaction_id: str
    destination_node_id: str
    state: str
    created_at: str
    sent_at: str
    attempt_count: int
    retry_state: str
    failure_reason: str


def persist_outbound_envelopes_for_configured_peers(
    *, conn: sqlite3.Connection, transaction: Transaction
) -> None:
    """Persist envelopes for every eligible peer in the Peer Registry.

    Endpoint/bootstrap configuration is daemon-owned and is deliberately not
    consulted while creating durable protocol envelopes.
    """
    persist_outbound_envelopes(
        conn=conn,
        transaction=transaction,
        peers=[
            entry.node_id
            for entry in list_peer_registry_entries(conn=conn)
            if entry.node_id != transaction.origin_node_id
        ],
    )


def persist_outbound_envelopes(
    *,
    conn: sqlite3.Connection,
    transaction: Transaction,
    peers: Iterable[str],
) -> None:
    """Persist one canonical delivery row per authorized destination peer."""
    service_group_id = service_group_scope_id(transaction=transaction)
    eligible_peers = _eligible_peer_entries(
        conn=conn,
        peers=peers,
        service_group_id=service_group_id,
    )
    if not eligible_peers:
        return
    identity = load_sqlite_node_identity_material(conn=conn)
    if transaction.origin_node_id != identity.node_id:
        LOGGER.info(
            "skipping outbound envelope generation for remote-origin transaction transaction_id=%s origin_node_id=%s local_node_id=%s",
            transaction.transaction_id,
            transaction.origin_node_id,
            identity.node_id,
        )
        return
    for peer_id, entry in eligible_peers:
        _ensure_node(
            conn=conn,
            node_id=transaction.origin_node_id,
            peer_group_id=local_peer_group_id_for_node(node_id=transaction.origin_node_id),
        )
        payload_codec = _outbound_payload_codec_for_peer(entry=entry)
        envelope_transaction = prepare_outbound_storage_payload(
            conn=conn,
            transaction=transaction,
            envelope_encrypted=payload_codec.mode == ENCRYPTED_CODEC_MODE,
        )
        envelope = sign_envelope(
            envelope=build_transaction_envelope(
                transaction=envelope_transaction,
                destination_node_id=peer_id,
                payload_codec=payload_codec,
            ),
            signer_node_id=identity.node_id,
            signing_private_key=identity.signing.private_key,
            signing_public_key=identity.signing.public_key,
        )
        envelope_bytes = canonical_envelope_bytes(envelope=envelope)
        conn.execute(
            """
            INSERT OR IGNORE INTO envelopes (
                envelope_id, transaction_id, source_node_id, destination_node_id,
                encrypted_payload, envelope_hash, state, attempt_count, sent_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                envelope.envelope_id,
                transaction.transaction_id,
                transaction.origin_node_id,
                peer_id,
                envelope_bytes,
                hashlib.sha256(envelope_bytes).digest(),
                "pending",
                0,
                None,
            ),
        )


def _eligible_peer_entries(
    *,
    conn: sqlite3.Connection,
    peers: Iterable[str],
    service_group_id: str | None,
) -> list[tuple[str, PeerRegistryEntry]]:
    result: list[tuple[str, PeerRegistryEntry]] = []
    for peer_id in peers:
        if not is_peer_synchronization_eligible(
            conn=conn,
            node_id=peer_id,
            service_group_id=service_group_id,
        ):
            continue
        entry = get_peer_registry_entry(conn=conn, node_id=peer_id)
        if entry is not None:
            result.append((peer_id, entry))
    return result


def _outbound_payload_codec_for_peer(*, entry: PeerRegistryEntry) -> EnvelopePayloadCodec:
    mode = configured_envelope_payload_codec_mode()
    if mode != ENCRYPTED_CODEC_MODE:
        return plaintext_envelope_payload_codec()
    if entry.encryption_algorithm != "x25519":
        raise ValueError(
            "peer encryption algorithm is unsupported: "
            f"peer_id={entry.node_id} algorithm={entry.encryption_algorithm}"
        )
    if not entry.encryption_public_key:
        raise ValueError(f"peer encryption public key is missing: peer_id={entry.node_id}")
    try:
        recipient_public_key = decode_b64url(entry.encryption_public_key)
    except ValueError as exc:
        raise ValueError(f"peer encryption public key is invalid: peer_id={entry.node_id}") from exc
    return encrypted_envelope_payload_codec(
        recipient_node_id=entry.node_id,
        recipient_public_key=recipient_public_key,
        recipient_key_fingerprint=entry.encryption_fingerprint,
    )


def list_persisted_envelopes() -> list[EnvelopeInspection]:
    """List persisted envelope diagnostics without mutating runtime state."""
    path = sqlite_path()
    if not path.is_file():
        return []
    conn = _open_readonly_sqlite(path=path)
    try:
        rows = conn.execute(
            """
            SELECT envelope_id, transaction_id, destination_node_id, state,
                   sent_at, attempt_count, next_attempt_at, last_error,
                   encrypted_payload
            FROM envelopes
            ORDER BY envelope_id
            """
        ).fetchall()
        return [_inspection_from_row(row=row) for row in rows]
    finally:
        conn.close()


def get_persisted_envelope(*, envelope_id: str) -> EnvelopeInspection | None:
    """Return one persisted envelope diagnostic projection."""
    path = sqlite_path()
    if not path.is_file():
        return None
    conn = _open_readonly_sqlite(path=path)
    try:
        row = conn.execute(
            """
            SELECT envelope_id, transaction_id, destination_node_id, state,
                   sent_at, attempt_count, next_attempt_at, last_error,
                   encrypted_payload
            FROM envelopes
            WHERE envelope_id = ?
            """,
            (envelope_id,),
        ).fetchone()
        return None if row is None else _inspection_from_row(row=row)
    finally:
        conn.close()


def _open_readonly_sqlite(*, path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _inspection_from_row(*, row: sqlite3.Row) -> EnvelopeInspection:
    return EnvelopeInspection(
        envelope_id=row["envelope_id"],
        transaction_id=row["transaction_id"],
        destination_node_id=row["destination_node_id"] or "",
        state=row["state"],
        created_at=_created_at_from_payload(value=row["encrypted_payload"]),
        sent_at=row["sent_at"] or "",
        attempt_count=int(row["attempt_count"] or 0),
        retry_state=_retry_state(row=row),
        failure_reason=str(row["last_error"] or ""),
    )


def _retry_state(*, row: sqlite3.Row) -> str:
    if row["state"] == RETRY_PENDING_STATE:
        return f"retry_pending next_attempt_at={row['next_attempt_at'] or ''}"
    if row["state"] == AUTHORIZATION_DENIED_STATE:
        return AUTHORIZATION_DENIED_STATE
    return "none"


def _created_at_from_payload(*, value: bytes) -> str:
    try:
        envelope = parse_envelope_bytes(data=bytes(value))
    except Exception:
        return ""
    return envelope.created_at


def _ensure_node(*, conn: sqlite3.Connection, node_id: str, peer_group_id: str) -> None:
    """Ensure local parent rows required by envelope foreign keys."""
    validate_identifier(value=node_id, expected_type="node", field="node_id")
    validate_identifier(value=peer_group_id, expected_type="peer_group", field="peer_group_id")
    conn.execute(
        "INSERT OR IGNORE INTO peer_groups (peer_group_id) VALUES (?)",
        (peer_group_id,),
    )
    conn.execute(
        "INSERT OR IGNORE INTO nodes (node_id, peer_group_id) VALUES (?, ?)",
        (node_id, peer_group_id),
    )


__all__ = [
    "CanonicalEnvelope",
    "EnvelopeInspection",
    "get_persisted_envelope",
    "list_persisted_envelopes",
    "persist_outbound_envelopes",
    "persist_outbound_envelopes_for_configured_peers",
]
