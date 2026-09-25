"""
secrets_kit.backends.sqlite.peer_admission

Canonical peer admission transaction producers.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass

from secrets_kit.backends.sqlite.connection import transaction as sqlite_transaction
from secrets_kit.backends.sqlite.exceptions import SQLiteBackendError, SQLiteValidationError
from secrets_kit.backends.sqlite.gate import open_sqlite_backend
from secrets_kit.backends.sqlite.local_node import load_local_node_projection
from secrets_kit.backends.sqlite.models import Transaction
from secrets_kit.backends.sqlite.peer_admission_auth import (
    PROOF_TYPE_ACCEPT,
    PROOF_TYPE_REJECT,
    PROOF_TYPE_REQUEST,
    deterministic_admission_transaction_id,
    signed_admission_decision_payload,
    signed_admission_request_payload,
    verify_admission_decision_payload,
    verify_admission_request_payload,
)
from secrets_kit.backends.sqlite.peer_registry import (
    AUTHORIZATION_MODE_ALL,
    AUTHORIZATION_MODE_ALLOW_LIST,
    AUTHORIZATION_MODE_NONE,
    get_peer_registry_entry,
    list_peer_registry_entries,
)
from secrets_kit.backends.sqlite.serialization import load_canonical_json
from secrets_kit.backends.sqlite.transaction_engine import (
    TransactionSubmissionMode,
    TransactionSubmissionPolicy,
    submit_transaction,
)
from secrets_kit.backends.sqlite.transactions import create_transaction
from secrets_kit.crypto.codecs import encode_b64url
from secrets_kit.models import now_utc_iso

PEER_ADMISSION_REQUEST = PROOF_TYPE_REQUEST
PEER_ADMISSION_ACCEPT = PROOF_TYPE_ACCEPT
PEER_ADMISSION_REJECT = PROOF_TYPE_REJECT

PEER_ADMISSION_LOCAL_POLICY = TransactionSubmissionPolicy(
    mode=TransactionSubmissionMode.LOCAL,
    persist_transaction=True,
    apply_projection=True,
    mark_applied=True,
    generate_outbound_envelopes=False,
    bootstrap_support_rows=True,
    ignore_duplicate=False,
)

PEER_ADMISSION_OUTBOUND_REQUEST_POLICY = TransactionSubmissionPolicy(
    mode=TransactionSubmissionMode.LOCAL,
    persist_transaction=True,
    apply_projection=False,
    mark_applied=True,
    generate_outbound_envelopes=False,
    bootstrap_support_rows=True,
    ignore_duplicate=False,
)

PEER_ADMISSION_INBOUND_DECISION_POLICY = TransactionSubmissionPolicy(
    mode=TransactionSubmissionMode.LOCAL,
    persist_transaction=True,
    apply_projection=False,
    mark_applied=True,
    generate_outbound_envelopes=False,
    bootstrap_support_rows=True,
    ignore_duplicate=False,
)


@dataclass(frozen=True)
class PeerAdmissionResult:
    transaction_id: str
    transaction_type: str
    node_id: str
    state: str
    proof_payload: dict[str, object] | None = None


@dataclass(frozen=True)
class PeerPublicIdentity:
    node_id: str
    signing_public_key: str
    signing_algorithm: str
    encryption_public_key: str
    encryption_algorithm: str


@dataclass(frozen=True)
class PeerInspection:
    node_id: str
    state: str
    authorization_state: str
    authorization_mode: str
    synchronization_eligible: bool
    signing_algorithm: str
    signing_public_key: str
    signing_fingerprint: str
    encryption_algorithm: str
    encryption_public_key: str
    encryption_fingerprint: str
    service_address: str
    endpoint: str
    endpoint_state: str
    endpoint_expires_at: str
    operator_description: str
    service_group_ids: tuple[str, ...]
    created_at: str
    updated_at: str


def create_signed_peer_admission_request(
    *,
    service_address: str = "",
    operator_comment: str = "",
) -> Transaction:
    payload = signed_admission_request_payload(
        service_address=service_address,
        operator_comment=operator_comment,
    )
    return create_peer_admission_transaction(
        transaction_type=PEER_ADMISSION_REQUEST,
        payload=payload,
        origin_node_id=str(payload["node_id"]),
    )


def request_peer_admission(*, signed_request: Mapping[str, object]) -> PeerAdmissionResult:
    payload = dict(signed_request)
    verify_admission_request_payload(payload=payload)
    tx = create_peer_admission_transaction(
        transaction_type=PEER_ADMISSION_REQUEST,
        payload=payload,
        origin_node_id=str(payload["node_id"]),
    )
    _submit_peer_admission_transaction(transaction=tx)
    return PeerAdmissionResult(
        transaction_id=tx.transaction_id,
        transaction_type=tx.transaction_type,
        node_id=str(payload["node_id"]),
        state="admission_requested",
        proof_payload=payload,
    )


def retain_local_peer_admission_request(*, transaction: Transaction) -> None:
    """Retain an emitted request so a returned decision can be verified."""
    if transaction.transaction_type != PEER_ADMISSION_REQUEST:
        raise SQLiteBackendError("local peer admission request has an invalid type")
    conn = open_sqlite_backend()
    try:
        with sqlite_transaction(conn=conn):
            submit_transaction(
                conn=conn,
                transaction=transaction,
                policy=PEER_ADMISSION_OUTBOUND_REQUEST_POLICY,
            )
    except (sqlite3.Error, SQLiteValidationError) as exc:
        raise SQLiteBackendError(str(exc)) from exc
    finally:
        conn.close()


def accept_peer_admission(
    *,
    node_id: str,
    operator_comment: str = "",
    display_name: str = "",
    service_group_ids: tuple[str, ...] = (),
    authorization_mode: str | None = None,
) -> PeerAdmissionResult:
    request_id = _pending_request_id_for_peer(node_id=node_id)
    resolved_authorization_mode = _resolve_authorization_mode(
        service_group_ids=service_group_ids,
        authorization_mode=authorization_mode,
    )
    payload = signed_admission_decision_payload(
        proof_type=PEER_ADMISSION_ACCEPT,
        node_id=node_id,
        request_id=request_id,
        operator_comment=operator_comment,
        display_name=display_name,
        service_group_ids=service_group_ids,
        authorization_mode=resolved_authorization_mode,
    )
    tx = create_peer_admission_transaction(
        transaction_type=PEER_ADMISSION_ACCEPT,
        payload=payload,
        origin_node_id=str(payload["signer_node_id"]),
    )
    _submit_peer_admission_transaction(transaction=tx)
    return PeerAdmissionResult(
        transaction_id=tx.transaction_id,
        transaction_type=tx.transaction_type,
        node_id=node_id,
        state="active",
        proof_payload=payload,
    )


def reject_peer_admission(*, node_id: str, operator_comment: str = "") -> PeerAdmissionResult:
    request_id = _pending_request_id_for_peer(node_id=node_id)
    payload = signed_admission_decision_payload(
        proof_type=PEER_ADMISSION_REJECT,
        node_id=node_id,
        request_id=request_id,
        operator_comment=operator_comment,
    )
    tx = create_peer_admission_transaction(
        transaction_type=PEER_ADMISSION_REJECT,
        payload=payload,
        origin_node_id=str(payload["signer_node_id"]),
    )
    _submit_peer_admission_transaction(transaction=tx)
    return PeerAdmissionResult(
        transaction_id=tx.transaction_id,
        transaction_type=tx.transaction_type,
        node_id=node_id,
        state="rejected",
        proof_payload=payload,
    )


def create_signed_peer_admission_decision(
    *,
    proof_type: str,
    node_id: str,
    request_id: str,
    operator_comment: str = "",
    display_name: str = "",
    service_group_ids: tuple[str, ...] = (),
    authorization_mode: str | None = None,
) -> Transaction:
    resolved_authorization_mode = _resolve_authorization_mode(
        service_group_ids=service_group_ids,
        authorization_mode=authorization_mode,
    )
    payload = signed_admission_decision_payload(
        proof_type=proof_type,
        node_id=node_id,
        request_id=request_id,
        operator_comment=operator_comment,
        display_name=display_name,
        service_group_ids=service_group_ids,
        authorization_mode=resolved_authorization_mode,
    )
    return create_peer_admission_transaction(
        transaction_type=proof_type,
        payload=payload,
        origin_node_id=str(payload["signer_node_id"]),
    )


def import_peer_admission_decision(*, signed_decision: Mapping[str, object]) -> PeerAdmissionResult:
    payload = dict(signed_decision)
    transaction_type = str(payload.get("proof_type") or "")
    if transaction_type not in {PEER_ADMISSION_ACCEPT, PEER_ADMISSION_REJECT}:
        raise SQLiteBackendError("peer admission decision proof_type is unsupported")
    conn = open_sqlite_backend()
    try:
        verify_admission_decision_payload(conn=conn, payload=payload)
    except SQLiteValidationError as exc:
        raise SQLiteBackendError(str(exc)) from exc
    finally:
        conn.close()
    tx = create_peer_admission_transaction(
        transaction_type=transaction_type,
        payload=payload,
        origin_node_id=str(payload["signer_node_id"]),
    )
    conn = open_sqlite_backend()
    try:
        with sqlite_transaction(conn=conn):
            submit_transaction(
                conn=conn,
                transaction=tx,
                policy=PEER_ADMISSION_INBOUND_DECISION_POLICY,
            )
    except (sqlite3.Error, SQLiteValidationError) as exc:
        raise SQLiteBackendError(str(exc)) from exc
    finally:
        conn.close()
    return PeerAdmissionResult(
        transaction_id=tx.transaction_id,
        transaction_type=tx.transaction_type,
        node_id=str(payload["node_id"]),
        state="active" if transaction_type == PEER_ADMISSION_ACCEPT else "rejected",
        proof_payload=payload,
    )


def local_peer_public_identity() -> PeerPublicIdentity:
    conn = open_sqlite_backend()
    try:
        projection = load_local_node_projection(conn=conn)
        if projection is None:
            raise SQLiteValidationError("local node identity is required before peer admission")
        return PeerPublicIdentity(
            node_id=projection.node_id,
            signing_public_key=encode_b64url(projection.signing_public_key),
            signing_algorithm="ed25519",
            encryption_public_key=encode_b64url(projection.encryption_public_key),
            encryption_algorithm="x25519",
        )
    except SQLiteValidationError as exc:
        raise SQLiteBackendError(str(exc)) from exc
    finally:
        conn.close()


def list_peer_admissions() -> list[PeerInspection]:
    conn = open_sqlite_backend()
    try:
        return [_inspection_from_registry_entry(entry=entry) for entry in list_peer_registry_entries(conn=conn)]
    finally:
        conn.close()


def get_peer_admission(*, node_id: str) -> PeerInspection | None:
    conn = open_sqlite_backend()
    try:
        entry = get_peer_registry_entry(conn=conn, node_id=node_id)
        if entry is None:
            return None
        return _inspection_from_registry_entry(entry=entry)
    finally:
        conn.close()


def create_peer_admission_transaction(
    *,
    transaction_type: str,
    payload: dict[str, object],
    origin_node_id: str | None = None,
) -> Transaction:
    if origin_node_id is None:
        conn = open_sqlite_backend()
        try:
            origin_node_id = _local_origin_node_id(conn=conn)
        finally:
            conn.close()
    return create_transaction(
        transaction_id=deterministic_admission_transaction_id(
            proof_type=transaction_type,
            payload=payload,
        ),
        transaction_type=transaction_type,
        origin_node_id=origin_node_id,
        created_at=now_utc_iso(),
        payload=payload,
    )


def _pending_request_id_for_peer(*, node_id: str) -> str:
    conn = open_sqlite_backend()
    try:
        row = conn.execute("SELECT state FROM nodes WHERE node_id = ?", (node_id,)).fetchone()
        if row is None:
            raise SQLiteValidationError(f"cannot accept unknown peer admission request: {node_id}")
        if str(row["state"] or "") != "admission_requested":
            raise SQLiteValidationError(
                f"peer admission request is not pending: {node_id} state={row['state']}"
            )
        for tx_row in conn.execute(
            """
            SELECT payload
            FROM transactions
            WHERE transaction_type = ?
            ORDER BY rowid DESC
            """,
            (PEER_ADMISSION_REQUEST,),
        ).fetchall():
            payload = load_canonical_json(payload_bytes=tx_row["payload"])
            if payload.get("node_id") == node_id:
                request_id = payload.get("request_id")
                if isinstance(request_id, str) and request_id:
                    return request_id
        raise SQLiteValidationError(f"peer admission request_id not found for peer: {node_id}")
    except (sqlite3.Error, SQLiteValidationError) as exc:
        raise SQLiteBackendError(str(exc)) from exc
    finally:
        conn.close()


def _submit_peer_admission_transaction(*, transaction: Transaction) -> None:
    conn = open_sqlite_backend()
    try:
        with sqlite_transaction(conn=conn):
            submit_transaction(
                conn=conn,
                transaction=transaction,
                policy=PEER_ADMISSION_LOCAL_POLICY,
            )
    except (sqlite3.Error, SQLiteValidationError) as exc:
        raise SQLiteBackendError(str(exc)) from exc
    finally:
        conn.close()


def _local_origin_node_id(*, conn: sqlite3.Connection) -> str:
    projection = load_local_node_projection(conn=conn)
    if projection is None:
        raise SQLiteValidationError("local node identity is required before peer admission")
    return projection.node_id


def _resolve_authorization_mode(
    *,
    service_group_ids: tuple[str, ...],
    authorization_mode: str | None,
) -> str:
    if authorization_mode is None:
        return AUTHORIZATION_MODE_ALLOW_LIST if service_group_ids else AUTHORIZATION_MODE_NONE
    if authorization_mode == AUTHORIZATION_MODE_ALL and service_group_ids:
        raise SQLiteValidationError("authorization_mode all cannot include service_group_ids")
    if authorization_mode == AUTHORIZATION_MODE_NONE and service_group_ids:
        raise SQLiteValidationError("authorization_mode none cannot include service_group_ids")
    return authorization_mode


def _inspection_from_registry_entry(*, entry) -> PeerInspection:
    return PeerInspection(
        node_id=entry.node_id,
        state=entry.admission_state,
        authorization_state=entry.authorization_state,
        authorization_mode=entry.authorization_mode,
        synchronization_eligible=entry.synchronization_eligible,
        signing_algorithm=entry.signing_algorithm,
        signing_public_key=entry.signing_public_key,
        signing_fingerprint=entry.signing_fingerprint,
        encryption_algorithm=entry.encryption_algorithm,
        encryption_public_key=entry.encryption_public_key,
        encryption_fingerprint=entry.encryption_fingerprint,
        service_address=entry.service_address,
        endpoint=entry.endpoint,
        endpoint_state=entry.endpoint_state,
        endpoint_expires_at=entry.endpoint_expires_at,
        operator_description=entry.display_name,
        service_group_ids=entry.service_group_ids,
        created_at=entry.created_at,
        updated_at=entry.updated_at,
    )


__all__ = [
    "PEER_ADMISSION_ACCEPT",
    "PEER_ADMISSION_LOCAL_POLICY",
    "PEER_ADMISSION_REJECT",
    "PEER_ADMISSION_REQUEST",
    "AUTHORIZATION_MODE_ALL",
    "AUTHORIZATION_MODE_ALLOW_LIST",
    "AUTHORIZATION_MODE_NONE",
    "PeerAdmissionResult",
    "PeerInspection",
    "PeerPublicIdentity",
    "accept_peer_admission",
    "create_signed_peer_admission_decision",
    "create_signed_peer_admission_request",
    "create_peer_admission_transaction",
    "get_peer_admission",
    "list_peer_admissions",
    "local_peer_public_identity",
    "retain_local_peer_admission_request",
    "reject_peer_admission",
    "request_peer_admission",
    "import_peer_admission_decision",
]
