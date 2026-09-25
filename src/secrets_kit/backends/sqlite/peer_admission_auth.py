"""
secrets_kit.backends.sqlite.peer_admission_auth

Signed peer-admission artifacts and verification.
"""

from __future__ import annotations

import secrets
import sqlite3
from collections.abc import Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from secrets_kit.backends.sqlite.exceptions import SQLiteValidationError
from secrets_kit.backends.sqlite.gate import open_sqlite_backend
from secrets_kit.backends.sqlite.models import Transaction
from secrets_kit.backends.sqlite.node_identity import load_sqlite_node_identity_material
from secrets_kit.backends.sqlite.peer_registry import (
    AUTHORIZATION_MODE_ALL,
    AUTHORIZATION_MODE_ALLOW_LIST,
    AUTHORIZATION_MODE_NONE,
    AUTHORIZATION_MODES,
)
from secrets_kit.backends.sqlite.serialization import load_canonical_json
from secrets_kit.crypto.canonical import canonical_json_bytes
from secrets_kit.crypto.codecs import decode_b64url, encode_b64url
from secrets_kit.crypto.signatures import sign_ed25519, verify_ed25519
from secrets_kit.identifiers import (
    IdentifierType,
    deterministic_identifier,
    random_identifier,
    validate_identifier,
)
from secrets_kit.models import now_utc_iso

ADMISSION_PROOF_VERSION = 1
PROOF_TYPE_REQUEST = "peer.admission.request"
PROOF_TYPE_ACCEPT = "peer.admission.accept"
PROOF_TYPE_REJECT = "peer.admission.reject"

_REQUEST_REQUIRED = frozenset(
    {
        "proof_version",
        "proof_type",
        "request_id",
        "node_id",
        "signing_algorithm",
        "signing_public_key",
        "encryption_algorithm",
        "encryption_public_key",
        "created_at",
        "nonce",
        "signature",
    }
)
_DECISION_REQUIRED = frozenset(
    {
        "proof_version",
        "proof_type",
        "request_id",
        "decision_id",
        "node_id",
        "signer_node_id",
        "signer_signing_algorithm",
        "signer_signing_public_key",
        "signer_encryption_algorithm",
        "signer_encryption_public_key",
        "decided_at",
        "nonce",
        "signature",
    }
)


def signed_admission_request_payload(
    *,
    service_address: str = "",
    operator_comment: str = "",
) -> dict[str, object]:
    conn = open_sqlite_backend()
    try:
        identity = load_sqlite_node_identity_material(conn=conn)
    finally:
        conn.close()
    payload: dict[str, object] = {
        "proof_version": ADMISSION_PROOF_VERSION,
        "proof_type": PROOF_TYPE_REQUEST,
        "request_id": random_identifier(identifier_type="transaction"),
        "node_id": identity.node_id,
        "signing_algorithm": identity.signing.metadata.algorithm,
        "signing_public_key": encode_b64url(identity.signing.public_key),
        "encryption_algorithm": identity.encryption.metadata.algorithm,
        "encryption_public_key": encode_b64url(identity.encryption.public_key),
        "created_at": now_utc_iso(),
        "nonce": _nonce(),
    }
    if service_address:
        payload["service_address"] = service_address
    if operator_comment:
        payload["operator_comment"] = operator_comment
    payload["signature"] = encode_b64url(
        sign_ed25519(
            private_key=identity.signing.private_key,
            message=admission_request_signing_bytes(payload=payload),
        )
    )
    return payload


def signed_admission_decision_payload(
    *,
    proof_type: str,
    node_id: str,
    request_id: str,
    operator_comment: str = "",
    display_name: str = "",
    service_group_ids: tuple[str, ...] = (),
    authorization_mode: str = AUTHORIZATION_MODE_NONE,
) -> dict[str, object]:
    if proof_type not in {PROOF_TYPE_ACCEPT, PROOF_TYPE_REJECT}:
        raise SQLiteValidationError("admission decision proof_type is unsupported")
    if authorization_mode not in AUTHORIZATION_MODES:
        raise SQLiteValidationError(f"authorization_mode is unsupported: {authorization_mode}")
    if proof_type == PROOF_TYPE_REJECT:
        authorization_mode = AUTHORIZATION_MODE_NONE
    if authorization_mode == AUTHORIZATION_MODE_ALL and service_group_ids:
        raise SQLiteValidationError("authorization_mode all cannot include service_group_ids")
    if authorization_mode == AUTHORIZATION_MODE_NONE and service_group_ids:
        raise SQLiteValidationError("authorization_mode none cannot include service_group_ids")
    if authorization_mode == AUTHORIZATION_MODE_ALLOW_LIST:
        _validate_service_group_ids(service_group_ids=service_group_ids)
    conn = open_sqlite_backend()
    try:
        identity = load_sqlite_node_identity_material(conn=conn)
    finally:
        conn.close()
    payload: dict[str, object] = {
        "proof_version": ADMISSION_PROOF_VERSION,
        "proof_type": proof_type,
        "request_id": request_id,
        "decision_id": random_identifier(identifier_type="transaction"),
        "node_id": node_id,
        "signer_node_id": identity.node_id,
        "signer_signing_algorithm": identity.signing.metadata.algorithm,
        "signer_signing_public_key": encode_b64url(identity.signing.public_key),
        "signer_encryption_algorithm": identity.encryption.metadata.algorithm,
        "signer_encryption_public_key": encode_b64url(identity.encryption.public_key),
        "decided_at": now_utc_iso(),
        "nonce": _nonce(),
    }
    if proof_type == PROOF_TYPE_ACCEPT:
        payload["accepted_at"] = payload["decided_at"]
        payload["authorization_mode"] = authorization_mode
    else:
        payload["rejected_at"] = payload["decided_at"]
    if display_name:
        payload["display_name"] = display_name
    if service_group_ids:
        payload["service_group_ids"] = list(service_group_ids)
    if operator_comment:
        payload["operator_comment"] = operator_comment
    payload["signature"] = encode_b64url(
        sign_ed25519(
            private_key=identity.signing.private_key,
            message=admission_decision_signing_bytes(payload=payload),
        )
    )
    return payload


def admission_request_signing_bytes(*, payload: Mapping[str, object]) -> bytes:
    return canonical_json_bytes(_without_signature(payload=payload))


def admission_decision_signing_bytes(*, payload: Mapping[str, object]) -> bytes:
    return canonical_json_bytes(_without_signature(payload=payload))


def verify_admission_request_payload(*, payload: Mapping[str, object]) -> None:
    _require_fields(payload=payload, fields=_REQUEST_REQUIRED)
    _require_int(payload=payload, field_name="proof_version", expected=ADMISSION_PROOF_VERSION)
    _require_text(payload=payload, field_name="proof_type", expected=PROOF_TYPE_REQUEST)
    _require_identifier(payload=payload, field_name="request_id", expected_type="transaction")
    _require_identifier(payload=payload, field_name="node_id", expected_type="node")
    _require_text(payload=payload, field_name="created_at")
    _require_text(payload=payload, field_name="nonce")
    signing_public_key = _public_key(
        payload=payload,
        key_field="signing_public_key",
        algorithm_field="signing_algorithm",
        expected_algorithm="ed25519",
        key_kind="signing",
    )
    encryption_public_key = _public_key(
        payload=payload,
        key_field="encryption_public_key",
        algorithm_field="encryption_algorithm",
        expected_algorithm="x25519",
        key_kind="encryption",
    )
    if signing_public_key == encryption_public_key:
        raise SQLiteValidationError("signing_public_key and encryption_public_key must differ")
    signature = _signature(payload=payload)
    if not verify_ed25519(
        public_key=signing_public_key,
        message=admission_request_signing_bytes(payload=payload),
        signature=signature,
    ):
        raise SQLiteValidationError("peer admission request signature verification failed")


def verify_admission_decision_payload(
    *,
    conn: sqlite3.Connection,
    payload: Mapping[str, object],
) -> None:
    _require_fields(payload=payload, fields=_DECISION_REQUIRED)
    _require_int(payload=payload, field_name="proof_version", expected=ADMISSION_PROOF_VERSION)
    proof_type = _require_text(payload=payload, field_name="proof_type")
    if proof_type not in {PROOF_TYPE_ACCEPT, PROOF_TYPE_REJECT}:
        raise SQLiteValidationError("peer admission decision proof_type is unsupported")
    request_id = _require_identifier(
        payload=payload, field_name="request_id", expected_type="transaction"
    )
    node_id = _require_identifier(payload=payload, field_name="node_id", expected_type="node")
    _require_identifier(payload=payload, field_name="decision_id", expected_type="transaction")
    _require_identifier(
        payload=payload, field_name="signer_node_id", expected_type="node"
    )
    _require_text(payload=payload, field_name="decided_at")
    _require_text(payload=payload, field_name="nonce")
    authorization_mode = _optional_text(payload=payload, field_name="authorization_mode")
    service_group_ids = _optional_text_list(payload=payload, field_name="service_group_ids")
    if proof_type == PROOF_TYPE_ACCEPT:
        if authorization_mode is None:
            authorization_mode = AUTHORIZATION_MODE_NONE
        if authorization_mode not in AUTHORIZATION_MODES:
            raise SQLiteValidationError(
                f"peer admission authorization_mode is unsupported: {authorization_mode}"
            )
        if authorization_mode == AUTHORIZATION_MODE_ALL and service_group_ids:
            raise SQLiteValidationError(
                "peer admission authorization_mode all cannot include service_group_ids"
            )
        if authorization_mode == AUTHORIZATION_MODE_NONE and service_group_ids:
            raise SQLiteValidationError(
                "peer admission authorization_mode none cannot include service_group_ids"
            )
        if authorization_mode == AUTHORIZATION_MODE_ALLOW_LIST:
            _validate_service_group_ids(service_group_ids=service_group_ids)
    elif authorization_mode is not None or service_group_ids:
        raise SQLiteValidationError(
            "peer admission rejection cannot include synchronization authorization"
        )
    signer_signing_public_key = _public_key(
        payload=payload,
        key_field="signer_signing_public_key",
        algorithm_field="signer_signing_algorithm",
        expected_algorithm="ed25519",
        key_kind="signing",
    )
    signer_encryption_public_key = _public_key(
        payload=payload,
        key_field="signer_encryption_public_key",
        algorithm_field="signer_encryption_algorithm",
        expected_algorithm="x25519",
        key_kind="encryption",
    )
    if signer_signing_public_key == signer_encryption_public_key:
        raise SQLiteValidationError(
            "signer_signing_public_key and signer_encryption_public_key must differ"
        )
    if not verify_ed25519(
        public_key=signer_signing_public_key,
        message=admission_decision_signing_bytes(payload=payload),
        signature=_signature(payload=payload),
    ):
        raise SQLiteValidationError("peer admission decision signature verification failed")
    _require_matching_request(conn=conn, node_id=node_id, request_id=request_id)


def verify_peer_admission_transaction(
    *,
    conn: sqlite3.Connection,
    transaction: Transaction,
) -> None:
    if transaction.transaction_type == PROOF_TYPE_REQUEST:
        verify_admission_request_payload(payload=transaction.payload)
        node_id = _require_text(payload=transaction.payload, field_name="node_id")
        if transaction.origin_node_id != node_id:
            raise SQLiteValidationError("peer admission request origin_node_id must match node_id")
        _reject_reused_request_id(conn=conn, transaction=transaction)
        return
    if transaction.transaction_type in {PROOF_TYPE_ACCEPT, PROOF_TYPE_REJECT}:
        verify_admission_decision_payload(conn=conn, payload=transaction.payload)
        signer_node_id = _require_text(payload=transaction.payload, field_name="signer_node_id")
        if transaction.origin_node_id != signer_node_id:
            raise SQLiteValidationError(
                "peer admission decision origin_node_id must match signer_node_id"
            )


def deterministic_admission_transaction_id(*, proof_type: str, payload: Mapping[str, object]) -> str:
    if proof_type == PROOF_TYPE_REQUEST:
        stable_id = _require_identifier(
            payload=payload, field_name="request_id", expected_type="transaction"
        )
    elif proof_type in {PROOF_TYPE_ACCEPT, PROOF_TYPE_REJECT}:
        stable_id = _require_identifier(
            payload=payload, field_name="decision_id", expected_type="transaction"
        )
    else:
        raise SQLiteValidationError("peer admission proof_type is unsupported")
    return deterministic_identifier(
        identifier_type="transaction",
        namespace="peer.admission",
        name=f"{proof_type}\0{stable_id}",
    )


def _require_matching_request(
    *,
    conn: sqlite3.Connection,
    node_id: str,
    request_id: str,
) -> None:
    for row in conn.execute(
        """
        SELECT payload
        FROM transactions
        WHERE transaction_type = ?
        ORDER BY rowid
        """,
        (PROOF_TYPE_REQUEST,),
    ).fetchall():
        payload = load_canonical_json(payload_bytes=row["payload"])
        if payload.get("node_id") == node_id and payload.get("request_id") == request_id:
            return
    raise SQLiteValidationError(f"peer admission acceptance references unknown request: {request_id}")


def _reject_reused_request_id(*, conn: sqlite3.Connection, transaction: Transaction) -> None:
    request_id = _require_text(payload=transaction.payload, field_name="request_id")
    for row in conn.execute(
        """
        SELECT transaction_id, payload
        FROM transactions
        WHERE transaction_type = ?
        ORDER BY rowid
        """,
        (PROOF_TYPE_REQUEST,),
    ).fetchall():
        if str(row["transaction_id"]) == transaction.transaction_id:
            continue
        payload = load_canonical_json(payload_bytes=row["payload"])
        if payload.get("request_id") == request_id:
            raise SQLiteValidationError(f"peer admission request_id already used: {request_id}")


def _without_signature(*, payload: Mapping[str, object]) -> dict[str, object]:
    result = dict(payload)
    result.pop("signature", None)
    return result


def _require_fields(*, payload: Mapping[str, object], fields: frozenset[str]) -> None:
    for field_name in sorted(fields):
        if field_name not in payload:
            raise SQLiteValidationError(f"{field_name} is required")


def _require_int(*, payload: Mapping[str, object], field_name: str, expected: int) -> None:
    value = payload.get(field_name)
    if not isinstance(value, int) or isinstance(value, bool):
        raise SQLiteValidationError(f"{field_name} must be an integer")
    if value != expected:
        raise SQLiteValidationError(f"{field_name} must be {expected}")


def _require_text(
    *,
    payload: Mapping[str, object],
    field_name: str,
    expected: str | None = None,
) -> str:
    value = payload.get(field_name)
    if not isinstance(value, str) or not value:
        raise SQLiteValidationError(f"{field_name} is required")
    if expected is not None and value != expected:
        raise SQLiteValidationError(f"{field_name} must be {expected}")
    return value


def _optional_text(*, payload: Mapping[str, object], field_name: str) -> str | None:
    value = payload.get(field_name)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise SQLiteValidationError(f"{field_name} must be a non-empty string")
    return value


def _optional_text_list(
    *, payload: Mapping[str, object], field_name: str
) -> tuple[str, ...]:
    value = payload.get(field_name)
    if value is None:
        return ()
    if not isinstance(value, list):
        raise SQLiteValidationError(f"{field_name} must be a list")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item:
            raise SQLiteValidationError(f"{field_name} entries must be non-empty strings")
        result.append(item)
    return tuple(result)


def _validate_service_group_ids(*, service_group_ids: tuple[str, ...]) -> None:
    for service_group_id in service_group_ids:
        try:
            validate_identifier(
                value=service_group_id,
                expected_type="service_group",
                field="service_group_ids",
            )
        except ValueError as exc:
            raise SQLiteValidationError(str(exc)) from exc


def _require_identifier(
    *,
    payload: Mapping[str, object],
    field_name: str,
    expected_type: IdentifierType,
) -> str:
    value = _require_text(payload=payload, field_name=field_name)
    try:
        return validate_identifier(
            value=value,
            expected_type=expected_type,
            field=field_name,
        )
    except ValueError as exc:
        raise SQLiteValidationError(str(exc)) from exc


def _public_key(
    *,
    payload: Mapping[str, object],
    key_field: str,
    algorithm_field: str,
    expected_algorithm: str,
    key_kind: str,
) -> bytes:
    _require_text(payload=payload, field_name=algorithm_field, expected=expected_algorithm)
    encoded = _require_text(payload=payload, field_name=key_field)
    try:
        value = decode_b64url(encoded)
    except ValueError as exc:
        raise SQLiteValidationError(f"{key_field} must be base64url public key bytes") from exc
    if len(value) != 32:
        raise SQLiteValidationError(f"{key_field} must decode to 32 bytes")
    try:
        if key_kind == "signing":
            Ed25519PublicKey.from_public_bytes(value)
        else:
            X25519PublicKey.from_public_bytes(value)
    except ValueError as exc:
        raise SQLiteValidationError(f"{key_field} is not a valid {expected_algorithm} public key") from exc
    return value


def _signature(*, payload: Mapping[str, object]) -> bytes:
    encoded = _require_text(payload=payload, field_name="signature")
    try:
        return decode_b64url(encoded)
    except ValueError as exc:
        raise SQLiteValidationError("signature must be base64url bytes") from exc


def _nonce() -> str:
    return secrets.token_urlsafe(32)


__all__ = [
    "ADMISSION_PROOF_VERSION",
    "PROOF_TYPE_ACCEPT",
    "PROOF_TYPE_REJECT",
    "PROOF_TYPE_REQUEST",
    "admission_decision_signing_bytes",
    "admission_request_signing_bytes",
    "deterministic_admission_transaction_id",
    "signed_admission_decision_payload",
    "signed_admission_request_payload",
    "verify_admission_decision_payload",
    "verify_admission_request_payload",
    "verify_peer_admission_transaction",
]
