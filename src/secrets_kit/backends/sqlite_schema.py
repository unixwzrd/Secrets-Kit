"""SQLite DDL and schema version constants only (no migration branching or crypto).

Operational code stays in :mod:`secrets_kit.backends.sqlite`; migrations in
:mod:`secrets_kit.backends.sqlite_migrations`.
"""

from __future__ import annotations

import sqlite3

# Connection / pragma constants (data only)
SQLITE_CONNECT_TIMEOUT_S = 30.0
PRAGMA_FOREIGN_KEYS_ON = "PRAGMA foreign_keys = ON"

# PRAGMA user_version values
SQLITE_USER_VERSION_V2 = 2
SQLITE_USER_VERSION_V3 = 3

VAULT_META_SQL = """
CREATE TABLE IF NOT EXISTS vault_meta (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    kdf_salt BLOB NOT NULL,
    opslimit INTEGER NOT NULL,
    memlimit INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    wrapped_dek BLOB,
    unlock_provider TEXT
);
"""

# Canonical v2 ``secrets`` table (single source; used for new DB and post-rename create).
SECRETS_TABLE_V2_SQL = """
CREATE TABLE secrets (
    entry_id TEXT NOT NULL PRIMARY KEY,
    service TEXT NOT NULL,
    account TEXT NOT NULL,
    name TEXT NOT NULL,
    locator_hash TEXT NOT NULL,
    locator_hint TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    origin_host TEXT NOT NULL,
    deleted INTEGER NOT NULL DEFAULT 0,
    deleted_at TEXT NOT NULL DEFAULT '',
    generation INTEGER NOT NULL DEFAULT 1,
    tombstone_generation INTEGER NOT NULL DEFAULT 0,
    backend_version INTEGER NOT NULL DEFAULT 1,
    corrupt INTEGER NOT NULL DEFAULT 0,
    corrupt_reason TEXT NOT NULL DEFAULT '',
    last_validation_at TEXT NOT NULL DEFAULT '',
    content_hash TEXT NOT NULL DEFAULT '',
    ciphertext BLOB NOT NULL,
    nonce BLOB NOT NULL,
    crypto_version INTEGER NOT NULL,
    UNIQUE(service, account, name)
);
"""

# Append-only audit log (no plaintext secrets; index/locator/generation metadata only).
SECRETS_AUDIT_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS secrets_audit (
    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
    operation TEXT NOT NULL,
    changed_at TEXT NOT NULL,
    entry_id TEXT,
    service TEXT,
    account TEXT,
    name TEXT,
    generation INTEGER,
    tombstone_generation INTEGER,
    deleted INTEGER,
    content_hash TEXT NOT NULL DEFAULT ''
);
"""

# AFTER INSERT / UPDATE / DELETE on secrets — capture non-secret columns only.
AUDIT_TRIGGERS_SQL = """
CREATE TRIGGER IF NOT EXISTS secrets_audit_ai
AFTER INSERT ON secrets
BEGIN
  INSERT INTO secrets_audit (
    operation, changed_at, entry_id, service, account, name,
    generation, tombstone_generation, deleted, content_hash
  ) VALUES (
    'insert', strftime('%Y-%m-%dT%H:%M:%SZ','now'),
    NEW.entry_id, NEW.service, NEW.account, NEW.name,
    NEW.generation, NEW.tombstone_generation, NEW.deleted, NEW.content_hash
  );
END;

CREATE TRIGGER IF NOT EXISTS secrets_audit_au
AFTER UPDATE ON secrets
BEGIN
  INSERT INTO secrets_audit (
    operation, changed_at, entry_id, service, account, name,
    generation, tombstone_generation, deleted, content_hash
  ) VALUES (
    'update', strftime('%Y-%m-%dT%H:%M:%SZ','now'),
    NEW.entry_id, NEW.service, NEW.account, NEW.name,
    NEW.generation, NEW.tombstone_generation, NEW.deleted, NEW.content_hash
  );
END;

CREATE TRIGGER IF NOT EXISTS secrets_audit_ad
AFTER DELETE ON secrets
BEGIN
  INSERT INTO secrets_audit (
    operation, changed_at, entry_id, service, account, name,
    generation, tombstone_generation, deleted, content_hash
  ) VALUES (
    'delete', strftime('%Y-%m-%dT%H:%M:%SZ','now'),
    OLD.entry_id, OLD.service, OLD.account, OLD.name,
    OLD.generation, OLD.tombstone_generation, OLD.deleted, OLD.content_hash
  );
END;
"""


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Apply base DDL that must exist before migrations (vault_meta)."""
    conn.executescript(VAULT_META_SQL)


def create_schema(conn: sqlite3.Connection) -> None:
    """Alias for :func:`ensure_schema` (base vault table creation)."""
    ensure_schema(conn)


def create_indexes(conn: sqlite3.Connection) -> None:
    """Reserved for future index DDL (currently none)."""
    _ = conn  # API stability for callers that pass a connection


def create_triggers(conn: sqlite3.Connection) -> None:
    """Create audit triggers (expects ``secrets`` and ``secrets_audit`` tables)."""
    if AUDIT_TRIGGERS_SQL.strip():
        conn.executescript(AUDIT_TRIGGERS_SQL)


def apply_secrets_v2_table(conn: sqlite3.Connection) -> None:
    """Create empty v2 ``secrets`` table (new database or after legacy rename)."""
    conn.executescript(SECRETS_TABLE_V2_SQL)


def install_audit_schema(conn: sqlite3.Connection) -> None:
    """Create ``secrets_audit`` table + attach triggers (idempotent)."""
    conn.executescript(SECRETS_AUDIT_TABLE_SQL)
    create_triggers(conn)
