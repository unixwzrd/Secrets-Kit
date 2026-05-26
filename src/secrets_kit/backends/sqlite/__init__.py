"""
secrets_kit.backends.sqlite

SQLite transaction foundation exports.
"""

from __future__ import annotations

from secrets_kit.backends.sqlite.backend import (
    SQLITE_DEVELOPER_MODE_ENV,
    SQLITE_DEVELOPER_MODE_WARNING,
    SQLITE_PATH_ENV,
    SQLITE_PLAINTEXT_DEBUG_ENV,
    SQLITE_SUPPRESS_DEVELOPER_MODE_WARNING_ENV,
    SQLITE_UNSAFE_WARNING,
    SqliteSecretStore,
    delete_sqlite_secret,
    get_sqlite_metadata,
    get_sqlite_secret,
    get_sqlite_secret_entry,
    is_sqlite_backend,
    list_active_sqlite_metadata,
    open_sqlite_backend,
    require_sqlite_developer_mode,
    set_sqlite_secret,
    sqlite_path,
    sqlite_secret_exists,
)
from secrets_kit.backends.sqlite.connection import connect_sqlite, transaction
from secrets_kit.backends.sqlite.exceptions import (
    DuplicateTransactionError,
    SQLiteBackendError,
    SQLiteValidationError,
    TransactionNotFoundError,
)
from secrets_kit.backends.sqlite.hashing import (
    hash_payload,
    payload_hash_bytes_to_hex,
    payload_hash_hex_to_bytes,
    sha256_hex,
)
from secrets_kit.backends.sqlite.models import Transaction
from secrets_kit.backends.sqlite.projections import (
    apply_secret_delete_projection,
    apply_secret_set_projection,
)
from secrets_kit.backends.sqlite.replay import (
    SUPPORTED_REPLAY_TRANSACTION_TYPES,
    apply_transaction,
    rebuild_secret_projections,
    replay_transactions,
)
from secrets_kit.backends.sqlite.schema import SCHEMA_VERSION, bootstrap_schema
from secrets_kit.backends.sqlite.serialization import canonical_json_bytes, load_canonical_json
from secrets_kit.backends.sqlite.transactions import (
    create_transaction,
    get_transaction,
    insert_transaction,
    transaction_exists,
    validate_transaction,
)
from secrets_kit.crypto.storage.sqlite import decrypt_payload, encrypt_payload

__all__ = [
    "DuplicateTransactionError",
    "SCHEMA_VERSION",
    "SQLiteBackendError",
    "SQLiteValidationError",
    "SUPPORTED_REPLAY_TRANSACTION_TYPES",
    "SQLITE_DEVELOPER_MODE_ENV",
    "SQLITE_DEVELOPER_MODE_WARNING",
    "SQLITE_PLAINTEXT_DEBUG_ENV",
    "SQLITE_PATH_ENV",
    "SQLITE_SUPPRESS_DEVELOPER_MODE_WARNING_ENV",
    "SQLITE_UNSAFE_WARNING",
    "SqliteSecretStore",
    "Transaction",
    "TransactionNotFoundError",
    "apply_secret_delete_projection",
    "apply_secret_set_projection",
    "apply_transaction",
    "bootstrap_schema",
    "canonical_json_bytes",
    "connect_sqlite",
    "create_transaction",
    "delete_sqlite_secret",
    "decrypt_payload",
    "encrypt_payload",
    "get_sqlite_metadata",
    "get_sqlite_secret",
    "get_sqlite_secret_entry",
    "get_transaction",
    "hash_payload",
    "insert_transaction",
    "is_sqlite_backend",
    "list_active_sqlite_metadata",
    "load_canonical_json",
    "open_sqlite_backend",
    "payload_hash_bytes_to_hex",
    "payload_hash_hex_to_bytes",
    "rebuild_secret_projections",
    "require_sqlite_developer_mode",
    "replay_transactions",
    "set_sqlite_secret",
    "sha256_hex",
    "sqlite_path",
    "sqlite_secret_exists",
    "transaction",
    "transaction_exists",
    "validate_transaction",
]
