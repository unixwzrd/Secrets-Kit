"""
secrets_kit.backends.sqlite.secrets_api

SQLite secret CRUD, listing, and SqliteSecretStore.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
from typing import Any

from secrets_kit.backends.base import SecretStore
from secrets_kit.backends.sqlite.connection import transaction
from secrets_kit.backends.sqlite.exceptions import SQLiteBackendError, SQLiteValidationError
from secrets_kit.backends.sqlite.gate import open_sqlite_backend
from secrets_kit.backends.sqlite.local_hierarchy import (
    LOCAL_CLIENT_ID,
    LOCAL_FALLBACK_NODE_ID,
    LOCAL_ORGANIZATION_ID,
    local_peer_group_display_name,
    local_peer_group_id_for_node,
)
from secrets_kit.backends.sqlite.local_node import load_local_node_projection
from secrets_kit.backends.sqlite.storage_mode import read_sqlite_storage_mode
from secrets_kit.backends.sqlite.transaction_engine import (
    LOCAL_TRANSACTION_POLICY,
    submit_transaction,
)
from secrets_kit.backends.sqlite.transactions import (
    create_transaction,
)
from secrets_kit.backends.sqlite.vocabulary_projections import (
    vocabulary_entry_kind_payload,
    vocabulary_entry_type_payload,
)
from secrets_kit.crypto.storage.sqlite import decrypt_payload as decrypt_storage_payload
from secrets_kit.crypto.storage.sqlite import encrypt_payload as encrypt_storage_payload
from secrets_kit.identifiers import (
    IdentifierValidationError,
    deterministic_identifier,
    random_identifier,
    validate_identifier,
)
from secrets_kit.internal_metadata import ENTRY_ID_CUSTOM_KEY, SYNC_ORIGIN_CUSTOM_KEY
from secrets_kit.models import METADATA_SCHEMA_VERSION, EntryMetadata, now_utc_iso
from secrets_kit.schemas.identifiers import schema_id_for_name
from secrets_kit.system_objects import is_operator_metadata
from secrets_kit.taxonomy.uuid import entry_kind_id_for_name, entry_type_id_for_name


def set_sqlite_secret(
    *,
    service: str,
    account: str,
    name: str,
    value: str,
    metadata: EntryMetadata,
) -> None:
    """
    Store one secret through canonical SQLite transaction and projection paths.

    Args:
        service:
            Service scope.
        account:
            Account scope.
        name:
            Secret name.
        value:
            Secret value.
        metadata:
            CLI metadata.
    Raises:
        SQLiteBackendError:
            SQLite operation failure.

    Side Effects:
        Inserts one canonical transaction and applies its projection atomically.
    """
    conn = open_sqlite_backend()
    try:
        storage_mode = read_sqlite_storage_mode(conn=conn)
        with transaction(conn=conn):
            _ensure_local_projection_parents(conn=conn, account=account, service=service)
            origin_node_id = _local_origin_node_id(conn=conn)
            _emit_vocabulary_transactions_for_metadata(conn=conn, metadata=metadata)
            tx = create_transaction(
                transaction_id=_new_transaction_id(),
                transaction_type="secret.set",
                origin_node_id=origin_node_id,
                created_at=now_utc_iso(),
                payload=_set_payload(
                    service=service,
                    account=account,
                    name=name,
                    value=value,
                    metadata=metadata,
                    storage_mode=storage_mode,
                ),
            )
            submit_transaction(conn=conn, transaction=tx, policy=LOCAL_TRANSACTION_POLICY)
    except (sqlite3.Error, SQLiteValidationError) as exc:
        raise SQLiteBackendError(str(exc)) from exc
    finally:
        conn.close()


def get_sqlite_secret(
    *,
    service: str,
    account: str,
    name: str,
) -> str:
    """
    Read one active SQLite projection value.

    Args:
        service:
            Service scope.
        account:
            Account scope.
        name:
            Secret name.
    Returns:
        Decoded local payload value, using the datastore's immutable format.

    Raises:
        SQLiteBackendError:
            Active projection is missing or cannot be decoded.

    Side Effects:
        Reads projections only; never replays or repairs.
    """
    conn = open_sqlite_backend()
    try:
        storage_mode = read_sqlite_storage_mode(conn=conn)
        row = _active_secret_row(conn=conn, service=service, account=account, name=name)
        return _decode_text_payload(
            value=row["encrypted_payload"],
            field_name="encrypted_payload",
            storage_mode=storage_mode,
        )
    finally:
        conn.close()


def get_sqlite_secret_entry(
    *,
    service: str,
    account: str,
    name: str,
) -> tuple[str, EntryMetadata]:
    """
    Read one active SQLite projection value and metadata.

    Args:
        service:
            Service scope.
        account:
            Account scope.
        name:
            Secret name.
    Returns:
        Decoded value and metadata.

    Raises:
        SQLiteBackendError:
            Active projection is missing or cannot be decoded.

    Side Effects:
        Reads projections only; never replays or repairs.
    """
    conn = open_sqlite_backend()
    try:
        storage_mode = read_sqlite_storage_mode(conn=conn)
        row = _active_secret_row(conn=conn, service=service, account=account, name=name)
        value = _decode_text_payload(
            value=row["encrypted_payload"],
            field_name="encrypted_payload",
            storage_mode=storage_mode,
        )
        metadata = _metadata_from_row(conn=conn, row=row)
        return value, metadata
    finally:
        conn.close()


def sqlite_secret_exists(
    *,
    service: str,
    account: str,
    name: str,
) -> bool:
    """
    Return whether an active SQLite projection exists.

    Args:
        service:
            Service scope.
        account:
            Account scope.
        name:
            Secret name.
    Returns:
        True when an active projection exists.

    Side Effects:
        Reads projections only; never replays or repairs.
    """
    conn = open_sqlite_backend()
    try:
        return (
            _active_secret_row(
                conn=conn, service=service, account=account, name=name, missing_ok=True
            )
            is not None
        )
    finally:
        conn.close()


def get_sqlite_metadata(
    *,
    service: str,
    account: str,
    name: str,
) -> EntryMetadata:
    """
    Read metadata from one active SQLite projection.

    Args:
        service:
            Service scope.
        account:
            Account scope.
        name:
            Secret name.
    Returns:
        Decoded metadata from the active projection.

    Raises:
        SQLiteBackendError:
            Active projection is missing or metadata cannot be decoded.

    Side Effects:
        Reads projections only; never replays or repairs.
    """
    conn = open_sqlite_backend()
    try:
        row = _active_secret_row(conn=conn, service=service, account=account, name=name)
        return _metadata_from_row(conn=conn, row=row)
    finally:
        conn.close()


def delete_sqlite_secret(
    *,
    service: str,
    account: str,
    name: str,
    metadata: EntryMetadata,
) -> None:
    """
    Tombstone one secret through canonical SQLite transaction and projection paths.

    Args:
        service:
            Service scope.
        account:
            Account scope.
        name:
            Secret name.
        metadata:
            CLI metadata.
    Raises:
        SQLiteBackendError:
            SQLite operation failure.

    Side Effects:
        Inserts one canonical transaction and applies its tombstone projection atomically.
    """
    conn = open_sqlite_backend()
    try:
        storage_mode = read_sqlite_storage_mode(conn=conn)
        with transaction(conn=conn):
            _ensure_local_projection_parents(conn=conn, account=account, service=service)
            origin_node_id = _local_origin_node_id(conn=conn)
            active_row = _active_secret_row(
                conn=conn,
                service=service,
                account=account,
                name=name,
            )
            tombstone_metadata = _metadata_from_row(conn=conn, row=active_row)
            tx = create_transaction(
                transaction_id=_new_transaction_id(),
                transaction_type="secret.delete",
                origin_node_id=origin_node_id,
                created_at=now_utc_iso(),
                payload=_delete_payload(
                    service=service,
                    account=account,
                    name=name,
                    metadata=tombstone_metadata,
                    storage_mode=storage_mode,
                ),
            )
            submit_transaction(conn=conn, transaction=tx, policy=LOCAL_TRANSACTION_POLICY)
    except (sqlite3.Error, SQLiteValidationError) as exc:
        raise SQLiteBackendError(str(exc)) from exc
    finally:
        conn.close()


def list_active_sqlite_metadata(
    *,
    service: str | None = None,
    account: str | None = None,
) -> list[EntryMetadata]:
    """
    List metadata from active SQLite projection rows.

    Args:
        service:
            Optional service filter.
        account:
            Optional account filter.
    Returns:
        Active projection metadata entries.

    Raises:
        SQLiteBackendError:
            Stored metadata cannot be decoded.

    Side Effects:
        Reads projections only; never replays or repairs.
    """
    conn = open_sqlite_backend()
    try:
        where = ["s.state = 'active'"]
        params: list[str] = []
        if service:
            where.append("s.service = ?")
            params.append(service)
        if account:
            where.append("s.account = ?")
            params.append(account)
        rows = conn.execute(
            f"""
            SELECT s.*, et.name AS entry_type, ek.name AS entry_kind
            FROM secrets s
            JOIN entry_types et ON et.entry_type_id = s.entry_type_id
            JOIN entry_kinds ek ON ek.entry_kind_id = s.entry_kind_id
            WHERE {' AND '.join(where)}
            ORDER BY s.service, s.account, s.name
            """,
            tuple(params),
        ).fetchall()
        entries: list[EntryMetadata] = []
        for row in rows:
            meta = _metadata_from_row(conn=conn, row=row)
            if not is_operator_metadata(metadata=meta):
                continue
            entries.append(meta)
        return sorted(entries, key=lambda item: (item.service, item.account, item.name))
    finally:
        conn.close()


class SqliteSecretStore(SecretStore):
    """Logical standalone SQLite SecretStore over transaction/projection storage."""

    def set(
        self,
        *,
        service: str,
        account: str,
        name: str,
        value: str,
        metadata: EntryMetadata | None = None,
        comment: str = "",
        label: str | None = None,
    ) -> None:
        _ = comment, label
        meta = metadata or EntryMetadata(
            name=name, service=service, account=account, source="sqlite"
        )
        set_sqlite_secret(
            service=service,
            account=account,
            name=name,
            value=value,
            metadata=meta,
        )

    def get(self, *, service: str, account: str, name: str) -> str:
        return get_sqlite_secret(
            service=service,
            account=account,
            name=name,
        )

    def metadata(self, *, service: str, account: str, name: str) -> EntryMetadata:
        return get_sqlite_metadata(
            service=service,
            account=account,
            name=name,
        )

    def exists(self, *, service: str, account: str, name: str) -> bool:
        return sqlite_secret_exists(
            service=service,
            account=account,
            name=name,
        )

    def delete(self, *, service: str, account: str, name: str) -> None:
        metadata = self.metadata(service=service, account=account, name=name)
        delete_sqlite_secret(
            service=service,
            account=account,
            name=name,
            metadata=metadata,
        )

    def list(
        self, *, service: str | None = None, account: str | None = None
    ) -> list[EntryMetadata]:
        return list_active_sqlite_metadata(
            service=service,
            account=account,
        )

    def doctor_roundtrip(self, *, service: str = "seckit-doctor", account: str = "doctor") -> None:
        test_name = "DOCTOR_TEST_KEY"
        value = "doctor_ok"
        metadata = EntryMetadata(
            name=test_name, service=service, account=account, source="sqlite-doctor"
        )
        self.set(service=service, account=account, name=test_name, value=value, metadata=metadata)
        fetched = self.get(service=service, account=account, name=test_name)
        if fetched != value:
            raise SQLiteBackendError("doctor roundtrip mismatch")
        self.delete(service=service, account=account, name=test_name)


def _ensure_local_projection_parents(
    *, conn: sqlite3.Connection, account: str, service: str
) -> None:
    """
    Ensure standalone local parent rows required by secret projections.

    This is a bounded local bootstrap exception, not synchronization authority:
    it creates deterministic support rows so secret projections can satisfy
    foreign keys while the canonical mutation history remains in transactions.
    Do not use this helper to model peer-ingested owner or service-group state.
    """
    local_node_id = _local_origin_node_id(conn=conn)
    peer_group_id = local_peer_group_id_for_node(node_id=local_node_id)
    conn.execute(
        "INSERT OR IGNORE INTO business_organizations (organization_id, operator_comment) VALUES (?, ?)",
        (LOCAL_ORGANIZATION_ID, "local standalone SQLite"),
    )
    conn.execute(
        "INSERT OR IGNORE INTO business_clients (client_id, organization_id, operator_comment) VALUES (?, ?, ?)",
        (LOCAL_CLIENT_ID, LOCAL_ORGANIZATION_ID, "local standalone SQLite"),
    )
    conn.execute(
        "INSERT OR IGNORE INTO owners (owner_id, client_id, operator_comment) VALUES (?, ?, ?)",
        (_owner_id(account=account), LOCAL_CLIENT_ID, f"local account {account}"),
    )
    conn.execute(
        "INSERT OR IGNORE INTO peer_groups (peer_group_id, owner_id, name) VALUES (?, ?, ?)",
        (
            peer_group_id,
            _owner_id(account=account),
            local_peer_group_display_name(peer_group_id=peer_group_id),
        ),
    )
    conn.execute(
        """
        INSERT OR IGNORE INTO nodes (
            node_id,
            peer_group_id,
            signing_public_key,
            signing_algorithm,
            encryption_public_key,
            encryption_algorithm,
            state
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            local_node_id,
            peer_group_id,
            bytes(32),
            "ed25519",
            bytes(32),
            "x25519",
            "active",
        ),
    )
    conn.execute(
        "INSERT OR IGNORE INTO service_groups (service_group_id, owner_id, operator_comment) VALUES (?, ?, ?)",
        (
            _service_group_id(account=account, service=service),
            _owner_id(account=account),
            f"local service {service}",
        ),
    )


def _active_secret_row(
    *,
    conn: sqlite3.Connection,
    service: str,
    account: str,
    name: str,
    missing_ok: bool = False,
) -> sqlite3.Row | None:
    row = conn.execute(
        """
        SELECT s.*, et.name AS entry_type, ek.name AS entry_kind
        FROM secrets s
        JOIN entry_types et ON et.entry_type_id = s.entry_type_id
        JOIN entry_kinds ek ON ek.entry_kind_id = s.entry_kind_id
        WHERE s.secret_id = ? AND s.state = 'active'
        """,
        (_secret_id(service=service, account=account, name=name),),
    ).fetchone()
    if row is None and not missing_ok:
        raise SQLiteBackendError(f"entry not found: {service}::{account}::{name}")
    return row


def _emit_vocabulary_transactions_for_metadata(
    *,
    conn: sqlite3.Connection,
    metadata: EntryMetadata,
) -> None:
    """Emit vocabulary upserts for entry_type and entry_kind before secret.set."""
    origin_node_id = _local_origin_node_id(conn=conn)
    specs = (
        (
            "vocabulary.entry_type.upsert",
            vocabulary_entry_type_payload(
                entry_type_id=entry_type_id_for_name(name=metadata.entry_type),
                name=metadata.entry_type,
            ),
        ),
        (
            "vocabulary.entry_kind.upsert",
            vocabulary_entry_kind_payload(
                entry_kind_id=entry_kind_id_for_name(name=metadata.entry_kind),
                name=metadata.entry_kind,
            ),
        ),
    )
    for transaction_type, payload in specs:
        tx = create_transaction(
            transaction_id=_new_transaction_id(),
            transaction_type=transaction_type,
            origin_node_id=origin_node_id,
            created_at=now_utc_iso(),
            payload=payload,
        )
        submit_transaction(conn=conn, transaction=tx, policy=LOCAL_TRANSACTION_POLICY)


def _local_origin_node_id(*, conn: sqlite3.Connection) -> str:
    projection = load_local_node_projection(conn=conn)
    if projection is None:
        return LOCAL_FALLBACK_NODE_ID
    return projection.node_id


def _set_payload(
    *,
    service: str,
    account: str,
    name: str,
    value: str,
    metadata: EntryMetadata,
    storage_mode: str,
) -> dict[str, Any]:
    value_bytes = value.encode("utf-8")
    payload = {
        "secret_id": _secret_id(service=service, account=account, name=name),
        "owner_id": _owner_id(account=account),
        "service_group_id": _service_group_id(account=account, service=service),
        "entry_type": metadata.entry_type,
        "entry_kind": metadata.entry_kind,
        "schema_id": _payload_schema_id(schema_id=metadata.schema_id),
        "schema_version": metadata.schema_version,
        "service": service,
        "account": account,
        **_metadata_payload_fields(metadata=metadata),
        "locator_hash_b64": _b64(_digest_bytes("locator", service, account, name)),
        "encrypted_name_b64": _b64(
            encrypt_storage_payload(
                plaintext=name.encode("utf-8"),
                field_name="encrypted_name",
                storage_mode=storage_mode,
            )
        ),
        "encrypted_payload_b64": _b64(
            encrypt_storage_payload(
                plaintext=value_bytes,
                field_name="encrypted_payload",
                storage_mode=storage_mode,
            )
        ),
        "content_hash_b64": _b64(hashlib.sha256(value_bytes).digest()),
        "projection_created_at": metadata.created_at,
        "projection_updated_at": metadata.updated_at,
    }
    return payload


def _delete_payload(
    *, service: str, account: str, name: str, metadata: EntryMetadata, storage_mode: str
) -> dict[str, Any]:
    payload = {
        "secret_id": _secret_id(service=service, account=account, name=name),
        "owner_id": _owner_id(account=account),
        "service_group_id": _service_group_id(account=account, service=service),
        "entry_type": metadata.entry_type,
        "entry_kind": metadata.entry_kind,
        "schema_id": _payload_schema_id(schema_id=metadata.schema_id),
        "schema_version": metadata.schema_version,
        "service": service,
        "account": account,
        **_metadata_payload_fields(metadata=metadata),
        "locator_hash_b64": _b64(_digest_bytes("locator", service, account, name)),
        "encrypted_name_b64": _b64(
            encrypt_storage_payload(
                plaintext=name.encode("utf-8"),
                field_name="encrypted_name",
                storage_mode=storage_mode,
            )
        ),
        "content_hash_b64": _b64(_digest_bytes("deleted", service, account, name)),
        "projection_updated_at": now_utc_iso(),
    }
    return payload


def _metadata_payload_fields(*, metadata: EntryMetadata) -> dict[str, Any]:
    custom = dict(metadata.custom)
    custom.pop(ENTRY_ID_CUSTOM_KEY, None)
    custom.pop(SYNC_ORIGIN_CUSTOM_KEY, None)
    if metadata.entry_id:
        custom[ENTRY_ID_CUSTOM_KEY] = metadata.entry_id
    if metadata.sync_origin_host:
        custom[SYNC_ORIGIN_CUSTOM_KEY] = metadata.sync_origin_host
    return {
        "tags": list(metadata.tags),
        "source": metadata.source,
        "comment": metadata.comment,
        "source_url": metadata.source_url,
        "source_label": metadata.source_label,
        "rotation_days": metadata.rotation_days,
        "rotation_warn_days": metadata.rotation_warn_days,
        "last_rotated_at": metadata.last_rotated_at,
        "expires_at": metadata.expires_at,
        "domains": list(metadata.domains),
        "custom": custom,
    }


def _payload_schema_id(*, schema_id: str) -> str | None:
    if not schema_id:
        return None
    try:
        return validate_identifier(value=schema_id, expected_type="schema", field="schema_id")
    except IdentifierValidationError:
        return schema_id_for_name(name=schema_id)


def _metadata_from_row(*, conn: sqlite3.Connection, row: sqlite3.Row) -> EntryMetadata:
    secret_id = str(row["secret_id"])
    custom = _custom_for_secret(conn=conn, secret_id=secret_id)
    entry_id = str(custom.pop(ENTRY_ID_CUSTOM_KEY, ""))
    sync_origin_host = str(custom.pop(SYNC_ORIGIN_CUSTOM_KEY, ""))
    return EntryMetadata(
        name=str(row["name"]),
        entry_type=str(row["entry_type"]),
        entry_kind=str(row["entry_kind"]),
        tags=_tags_for_secret(conn=conn, secret_id=secret_id),
        comment=str(row["comment"] or ""),
        service=str(row["service"]),
        account=str(row["account"]),
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
        source=str(row["source"] or "manual"),
        schema_id=str(row["schema_id"] or ""),
        schema_version=(
            int(row["schema_version"])
            if row["schema_version"] is not None
            else METADATA_SCHEMA_VERSION
        ),
        source_url=str(row["source_url"] or ""),
        source_label=str(row["source_label"] or ""),
        rotation_days=int(row["rotation_days"]) if row["rotation_days"] is not None else None,
        rotation_warn_days=(
            int(row["rotation_warn_days"]) if row["rotation_warn_days"] is not None else None
        ),
        last_rotated_at=str(row["last_rotated_at"] or ""),
        expires_at=str(row["expires_at"] or ""),
        domains=_domains_for_secret(conn=conn, secret_id=secret_id),
        entry_id=entry_id,
        sync_origin_host=sync_origin_host,
        custom=custom,
    )


def _tags_for_secret(*, conn: sqlite3.Connection, secret_id: str) -> list[str]:
    rows = conn.execute(
        """
        SELECT st.name
        FROM secret_tag_assignments sta
        JOIN secret_tags st ON st.tag_id = sta.tag_id
        WHERE sta.secret_id = ?
        ORDER BY st.name COLLATE NOCASE
        """,
        (secret_id,),
    ).fetchall()
    return [str(row["name"]) for row in rows]


def _domains_for_secret(*, conn: sqlite3.Connection, secret_id: str) -> list[str]:
    rows = conn.execute(
        """
        SELECT domain
        FROM secret_domains
        WHERE secret_id = ?
        ORDER BY domain COLLATE NOCASE
        """,
        (secret_id,),
    ).fetchall()
    return [str(row["domain"]) for row in rows]


def _custom_for_secret(*, conn: sqlite3.Connection, secret_id: str) -> dict[str, Any]:
    rows = conn.execute(
        """
        SELECT metadata_key, metadata_value
        FROM secret_custom_metadata
        WHERE secret_id = ?
        ORDER BY metadata_key COLLATE NOCASE
        """,
        (secret_id,),
    ).fetchall()
    custom: dict[str, Any] = {}
    for row in rows:
        try:
            custom[str(row["metadata_key"])] = json.loads(str(row["metadata_value"]))
        except json.JSONDecodeError as exc:
            raise SQLiteBackendError("SQLite projection custom metadata is invalid JSON") from exc
    return custom


def _decode_text_payload(*, value: bytes, field_name: str, storage_mode: str) -> str:
    try:
        return decrypt_storage_payload(
            stored=bytes(value),
            field_name=field_name,
            storage_mode=storage_mode,
        ).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SQLiteBackendError(f"SQLite projection {field_name} is not UTF-8 text") from exc
    except ValueError as exc:
        raise SQLiteBackendError(f"SQLite projection {field_name} cannot be decrypted") from exc


def _secret_id(*, service: str, account: str, name: str) -> str:
    return deterministic_identifier(
        identifier_type="secret",
        namespace="sqlite.secret",
        name=_deterministic_name(service, account, name),
    )


def _owner_id(*, account: str) -> str:
    return deterministic_identifier(
        identifier_type="owner",
        namespace="sqlite.owner",
        name=_deterministic_name(account),
    )


def _service_group_id(*, account: str, service: str) -> str:
    return deterministic_identifier(
        identifier_type="service_group",
        namespace="sqlite.service_group",
        name=_deterministic_name(account, service),
    )


def _new_transaction_id() -> str:
    return random_identifier(identifier_type="transaction")


def _deterministic_name(*parts: str) -> str:
    return "\0".join(parts)


def _digest_hex(*parts: str) -> str:
    return _digest_bytes(*parts).hex()


def _digest_bytes(*parts: str) -> bytes:
    joined = "\0".join(parts).encode("utf-8")
    return hashlib.sha256(joined).digest()


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


__all__ = [
    "SqliteSecretStore",
    "delete_sqlite_secret",
    "get_sqlite_metadata",
    "get_sqlite_secret",
    "get_sqlite_secret_entry",
    "list_active_sqlite_metadata",
    "set_sqlite_secret",
    "sqlite_secret_exists",
]
