"""
secrets_kit.backends.sqlite.secrets_api

SQLite secret CRUD, listing, and SqliteSecretStore.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import uuid
from typing import Any

from secrets_kit.backends.base import SecretStore
from secrets_kit.backends.sqlite.connection import transaction
from secrets_kit.backends.sqlite.exceptions import SQLiteBackendError, SQLiteValidationError
from secrets_kit.backends.sqlite.gate import (
    open_sqlite_backend,
    require_sqlite_developer_mode,
)
from secrets_kit.backends.sqlite.replay import apply_transaction
from secrets_kit.backends.sqlite.transactions import create_transaction, insert_transaction
from secrets_kit.backends.sqlite.vocabulary_projections import (
    vocabulary_entry_kind_payload,
    vocabulary_entry_type_payload,
)
from secrets_kit.crypto.storage.sqlite import decrypt_payload as decrypt_storage_payload
from secrets_kit.crypto.storage.sqlite import encrypt_payload as encrypt_storage_payload
from secrets_kit.models import EntryMetadata, now_utc_iso
from secrets_kit.system_objects import is_operator_metadata
from secrets_kit.taxonomy.uuid import entry_kind_id_for_name, entry_type_id_for_name

_LOCAL_ORGANIZATION_ID = "local-standalone"
_LOCAL_CLIENT_ID = "local-standalone-client"
_LOCAL_NODE_ID = "local-standalone-cli"


def set_sqlite_secret(
    *,
    service: str,
    account: str,
    name: str,
    value: str,
    metadata: EntryMetadata,
    sqlite_dev_mode: bool = False,
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
        sqlite_dev_mode:
            Command-line acknowledgement flag.

    Raises:
        SQLiteBackendError:
            SQLite operation failure.

    Side Effects:
        Inserts one canonical transaction and applies its projection atomically.
    """
    require_sqlite_developer_mode(sqlite_dev_mode=sqlite_dev_mode)
    conn = open_sqlite_backend()
    try:
        with transaction(conn=conn):
            _ensure_local_projection_parents(conn=conn, account=account, service=service)
            _emit_vocabulary_transactions_for_metadata(conn=conn, metadata=metadata)
            tx = create_transaction(
                transaction_id=_new_transaction_id(),
                transaction_type="secret.set",
                origin_node_id=_LOCAL_NODE_ID,
                created_at=now_utc_iso(),
                payload=_set_payload(
                    service=service, account=account, name=name, value=value, metadata=metadata
                ),
                target_owner_id=_owner_id(account=account),
                target_service_group_id=_service_group_id(account=account, service=service),
                target_object_id=_secret_id(service=service, account=account, name=name),
                source_class="local-cli",
                idempotency_key=_new_transaction_id(),
            )
            insert_transaction(conn=conn, transaction=tx)
            apply_transaction(conn=conn, transaction=tx)
    except (sqlite3.Error, SQLiteValidationError) as exc:
        raise SQLiteBackendError(str(exc)) from exc
    finally:
        conn.close()


def get_sqlite_secret(
    *,
    service: str,
    account: str,
    name: str,
    sqlite_dev_mode: bool = False,
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
        sqlite_dev_mode:
            Command-line acknowledgement flag.

    Returns:
        Decoded Phase 5A development payload value.

    Raises:
        SQLiteBackendError:
            Active projection is missing or cannot be decoded.

    Side Effects:
        Reads projections only; never replays or repairs.
    """
    require_sqlite_developer_mode(sqlite_dev_mode=sqlite_dev_mode)
    conn = open_sqlite_backend()
    try:
        row = _active_secret_row(conn=conn, service=service, account=account, name=name)
        return _decode_text_payload(value=row["encrypted_payload"], field_name="encrypted_payload")
    finally:
        conn.close()


def get_sqlite_secret_entry(
    *,
    service: str,
    account: str,
    name: str,
    sqlite_dev_mode: bool = False,
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
        sqlite_dev_mode:
            Command-line acknowledgement flag.

    Returns:
        Decoded value and metadata.

    Raises:
        SQLiteBackendError:
            Active projection is missing or cannot be decoded.

    Side Effects:
        Reads projections only; never replays or repairs.
    """
    require_sqlite_developer_mode(sqlite_dev_mode=sqlite_dev_mode)
    conn = open_sqlite_backend()
    try:
        row = _active_secret_row(conn=conn, service=service, account=account, name=name)
        value = _decode_text_payload(value=row["encrypted_payload"], field_name="encrypted_payload")
        metadata = _metadata_from_blob(blob=row["encrypted_metadata"])
        return value, metadata
    finally:
        conn.close()


def sqlite_secret_exists(
    *,
    service: str,
    account: str,
    name: str,
    sqlite_dev_mode: bool = False,
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
        sqlite_dev_mode:
            Command-line acknowledgement flag.

    Returns:
        True when an active projection exists.

    Side Effects:
        Reads projections only; never replays or repairs.
    """
    require_sqlite_developer_mode(sqlite_dev_mode=sqlite_dev_mode)
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
    sqlite_dev_mode: bool = False,
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
        sqlite_dev_mode:
            Command-line acknowledgement flag.

    Returns:
        Decoded metadata from the active projection.

    Raises:
        SQLiteBackendError:
            Active projection is missing or metadata cannot be decoded.

    Side Effects:
        Reads projections only; never replays or repairs.
    """
    require_sqlite_developer_mode(sqlite_dev_mode=sqlite_dev_mode)
    conn = open_sqlite_backend()
    try:
        row = _active_secret_row(conn=conn, service=service, account=account, name=name)
        return _metadata_from_blob(blob=row["encrypted_metadata"])
    finally:
        conn.close()


def delete_sqlite_secret(
    *,
    service: str,
    account: str,
    name: str,
    metadata: EntryMetadata,
    sqlite_dev_mode: bool = False,
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
        sqlite_dev_mode:
            Command-line acknowledgement flag.

    Raises:
        SQLiteBackendError:
            SQLite operation failure.

    Side Effects:
        Inserts one canonical transaction and applies its tombstone projection atomically.
    """
    require_sqlite_developer_mode(sqlite_dev_mode=sqlite_dev_mode)
    conn = open_sqlite_backend()
    try:
        with transaction(conn=conn):
            _ensure_local_projection_parents(conn=conn, account=account, service=service)
            tx = create_transaction(
                transaction_id=_new_transaction_id(),
                transaction_type="secret.delete",
                origin_node_id=_LOCAL_NODE_ID,
                created_at=now_utc_iso(),
                payload=_delete_payload(
                    service=service, account=account, name=name, metadata=metadata
                ),
                target_owner_id=_owner_id(account=account),
                target_service_group_id=_service_group_id(account=account, service=service),
                target_object_id=_secret_id(service=service, account=account, name=name),
                source_class="local-cli",
                idempotency_key=_new_transaction_id(),
            )
            insert_transaction(conn=conn, transaction=tx)
            apply_transaction(conn=conn, transaction=tx)
    except (sqlite3.Error, SQLiteValidationError) as exc:
        raise SQLiteBackendError(str(exc)) from exc
    finally:
        conn.close()


def list_active_sqlite_metadata(
    *,
    service: str | None = None,
    account: str | None = None,
    sqlite_dev_mode: bool = False,
) -> list[EntryMetadata]:
    """
    List metadata from active SQLite projection rows.

    Args:
        service:
            Optional service filter.
        account:
            Optional account filter.
        sqlite_dev_mode:
            Command-line acknowledgement flag.

    Returns:
        Active projection metadata entries.

    Raises:
        SQLiteBackendError:
            Stored metadata cannot be decoded.

    Side Effects:
        Reads projections only; never replays or repairs.
    """
    require_sqlite_developer_mode(sqlite_dev_mode=sqlite_dev_mode)
    conn = open_sqlite_backend()
    try:
        rows = conn.execute(
            """
            SELECT encrypted_metadata
            FROM secrets
            WHERE state = 'active'
            ORDER BY updated_at, secret_id
            """
        ).fetchall()
        entries: list[EntryMetadata] = []
        for row in rows:
            meta = _metadata_from_blob(blob=row["encrypted_metadata"])
            if not is_operator_metadata(metadata=meta):
                continue
            if service and meta.service != service:
                continue
            if account and meta.account != account:
                continue
            entries.append(meta)
        return sorted(entries, key=lambda item: (item.service, item.account, item.name))
    finally:
        conn.close()


class SqliteSecretStore(SecretStore):
    """Logical standalone SQLite SecretStore over transaction/projection storage."""

    def __init__(self, *, sqlite_dev_mode: bool = False) -> None:
        self.sqlite_dev_mode = sqlite_dev_mode

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
            sqlite_dev_mode=self.sqlite_dev_mode,
        )

    def get(self, *, service: str, account: str, name: str) -> str:
        return get_sqlite_secret(
            service=service,
            account=account,
            name=name,
            sqlite_dev_mode=self.sqlite_dev_mode,
        )

    def metadata(self, *, service: str, account: str, name: str) -> EntryMetadata:
        return get_sqlite_metadata(
            service=service,
            account=account,
            name=name,
            sqlite_dev_mode=self.sqlite_dev_mode,
        )

    def exists(self, *, service: str, account: str, name: str) -> bool:
        return sqlite_secret_exists(
            service=service,
            account=account,
            name=name,
            sqlite_dev_mode=self.sqlite_dev_mode,
        )

    def delete(self, *, service: str, account: str, name: str) -> None:
        metadata = self.metadata(service=service, account=account, name=name)
        delete_sqlite_secret(
            service=service,
            account=account,
            name=name,
            metadata=metadata,
            sqlite_dev_mode=self.sqlite_dev_mode,
        )

    def list(
        self, *, service: str | None = None, account: str | None = None
    ) -> list[EntryMetadata]:
        return list_active_sqlite_metadata(
            service=service,
            account=account,
            sqlite_dev_mode=self.sqlite_dev_mode,
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
    conn.execute(
        "INSERT OR IGNORE INTO organization (organization_id, operator_comment) VALUES (?, ?)",
        (_LOCAL_ORGANIZATION_ID, "local standalone SQLite"),
    )
    conn.execute(
        "INSERT OR IGNORE INTO clients (client_id, organization_id, operator_comment) VALUES (?, ?, ?)",
        (_LOCAL_CLIENT_ID, _LOCAL_ORGANIZATION_ID, "local standalone SQLite"),
    )
    conn.execute(
        "INSERT OR IGNORE INTO owners (owner_id, client_id, operator_comment) VALUES (?, ?, ?)",
        (_owner_id(account=account), _LOCAL_CLIENT_ID, f"local account {account}"),
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
        SELECT *
        FROM secrets
        WHERE secret_id = ? AND state = 'active'
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
            origin_node_id=_LOCAL_NODE_ID,
            created_at=now_utc_iso(),
            payload=payload,
            source_class="local-cli",
            idempotency_key=_new_transaction_id(),
        )
        insert_transaction(conn=conn, transaction=tx)
        apply_transaction(conn=conn, transaction=tx)


def _set_payload(
    *, service: str, account: str, name: str, value: str, metadata: EntryMetadata
) -> dict[str, Any]:
    value_bytes = value.encode("utf-8")
    return {
        "secret_id": _secret_id(service=service, account=account, name=name),
        "owner_id": _owner_id(account=account),
        "service_group_id": _service_group_id(account=account, service=service),
        "entry_type": metadata.entry_type,
        "entry_kind": metadata.entry_kind,
        "schema_id": metadata.schema_id or None,
        "schema_version": metadata.schema_version,
        "tags": list(metadata.tags),
        "locator_hash_b64": _b64(_digest_bytes("locator", service, account, name)),
        "encrypted_name_b64": _b64(
            encrypt_storage_payload(plaintext=name.encode("utf-8"), field_name="encrypted_name")
        ),
        "encrypted_metadata_b64": _b64(
            encrypt_storage_payload(
                plaintext=metadata.to_keychain_comment().encode("utf-8"),
                field_name="encrypted_metadata",
            )
        ),
        "encrypted_payload_b64": _b64(
            encrypt_storage_payload(plaintext=value_bytes, field_name="encrypted_payload")
        ),
        "content_hash_b64": _b64(hashlib.sha256(value_bytes).digest()),
        "projection_created_at": metadata.created_at,
        "projection_updated_at": metadata.updated_at,
    }


def _delete_payload(
    *, service: str, account: str, name: str, metadata: EntryMetadata
) -> dict[str, Any]:
    return {
        "secret_id": _secret_id(service=service, account=account, name=name),
        "owner_id": _owner_id(account=account),
        "service_group_id": _service_group_id(account=account, service=service),
        "entry_type": metadata.entry_type,
        "entry_kind": metadata.entry_kind,
        "schema_id": metadata.schema_id or None,
        "schema_version": metadata.schema_version,
        "tags": list(metadata.tags),
        "locator_hash_b64": _b64(_digest_bytes("locator", service, account, name)),
        "encrypted_name_b64": _b64(
            encrypt_storage_payload(plaintext=name.encode("utf-8"), field_name="encrypted_name")
        ),
        "encrypted_metadata_b64": _b64(
            encrypt_storage_payload(
                plaintext=metadata.to_keychain_comment().encode("utf-8"),
                field_name="encrypted_metadata",
            )
        ),
        "content_hash_b64": _b64(_digest_bytes("deleted", service, account, name)),
        "projection_updated_at": now_utc_iso(),
    }


def _metadata_from_blob(*, blob: bytes | None) -> EntryMetadata:
    if blob is None:
        raise SQLiteBackendError("SQLite projection metadata is missing")
    payload = _decode_text_payload(value=blob, field_name="encrypted_metadata")
    try:
        parsed = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise SQLiteBackendError("SQLite projection metadata is invalid JSON") from exc
    if not isinstance(parsed, dict):
        raise SQLiteBackendError("SQLite projection metadata must be a JSON object")
    return EntryMetadata.from_dict(parsed)


def _decode_text_payload(*, value: bytes, field_name: str) -> str:
    try:
        return decrypt_storage_payload(stored=bytes(value), field_name=field_name).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SQLiteBackendError(f"SQLite projection {field_name} is not UTF-8 text") from exc


def _secret_id(*, service: str, account: str, name: str) -> str:
    return "secret:" + _digest_hex("secret", service, account, name)


def _owner_id(*, account: str) -> str:
    return "owner:" + _digest_hex("owner", account)


def _service_group_id(*, account: str, service: str) -> str:
    return "service-group:" + _digest_hex("service-group", account, service)


def _new_transaction_id() -> str:
    return "txn:" + uuid.uuid4().hex


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
