"""
secrets_kit.backends.sqlite.schema

**DDL-only** surface for the encrypted SQLite store: canonical SQL strings plus
tiny helpers that execute them.

Migration branching, unlock, and crypto live elsewhere—see
:mod:`secrets_kit.backends.sqlite.migrations` and :mod:`secrets_kit.backends.sqlite.store`.
"""

from __future__ import annotations

import sqlite3

# Connection / pragma constants (data only)
SQLITE_CONNECT_TIMEOUT_S: float = 30.0
PRAGMA_FOREIGN_KEYS_ON: str = "PRAGMA foreign_keys = ON"

# PRAGMA user_version values
SQLITE_USER_VERSION_V2: int = 2
SQLITE_USER_VERSION_V3: int = 3

VAULT_META_SQL: str = """
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
SECRETS_TABLE_V2_SQL: str = """
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
SECRETS_AUDIT_TABLE_SQL: str = """
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
AUDIT_TRIGGERS_SQL: str = """
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


def ensure_schema(*, conn: sqlite3.Connection) -> None:
    """
    **Base DDL:** ensure ``vault_meta`` exists (idempotent ``CREATE IF NOT EXISTS``).

    ``conn`` must be an open :class:`sqlite3.Connection`; the caller owns
    transactions and commits. This runs a single ``executescript``; it does
    **not** read passphrases or ciphertext.
    """
    conn.executescript(VAULT_META_SQL)


def create_schema(*, conn: sqlite3.Connection) -> None:
    """
    **Alias** for :func:`ensure_schema` (creates base vault metadata table only).

    Use ``conn=...``; identical behavior to :func:`ensure_schema`.
    """
    ensure_schema(conn=conn)


def create_indexes(*, conn: sqlite3.Connection) -> None:
    """
    **Reserved** hook for future index DDL—currently a no-op.

    ``conn`` is accepted so callers can keep a stable keyword API; no SQL is run
    until indexes are defined here.
    """
    _ = conn


def create_triggers(*, conn: sqlite3.Connection) -> None:
    """
    **Audit triggers:** install AFTER INSERT/UPDATE/DELETE triggers on ``secrets``.

    Expects ``secrets`` and ``secrets_audit`` to exist. Runs idempotent
    ``CREATE TRIGGER IF NOT EXISTS`` SQL; logs **no** secret bytes—only
    locator/generation/hash columns defined in :data:`AUDIT_TRIGGERS_SQL`.
    """
    if AUDIT_TRIGGERS_SQL.strip():
        conn.executescript(AUDIT_TRIGGERS_SQL)


def apply_secrets_v2_table(*, conn: sqlite3.Connection) -> None:
    """
    **v2 table:** create the canonical ``secrets`` table (empty or after legacy rename).

    Executes :data:`SECRETS_TABLE_V2_SQL`; caller decides when this runs (new DB
    or post-``ALTER … RENAME``). Does not migrate row data.
    """
    conn.executescript(SECRETS_TABLE_V2_SQL)


def install_audit_schema(*, conn: sqlite3.Connection) -> None:
    """
    **Audit schema:** append-only ``secrets_audit`` plus AFTER INSERT/UPDATE/DELETE triggers.

    Runs idempotent ``IF NOT EXISTS`` DDL for the table, then :func:`create_triggers`.
    Suitable for forward-only upgrades; **no** plaintext secret material in audit rows.
    """
    conn.executescript(SECRETS_AUDIT_TABLE_SQL)
    create_triggers(conn=conn)
