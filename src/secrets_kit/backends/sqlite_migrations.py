"""SQLite schema migration and ALTER-table patching (no CRUD/crypto)."""

from __future__ import annotations

import sqlite3

import nacl.exceptions
import nacl.secret
from dataclasses import replace

from secrets_kit.backends.base import BACKEND_IMPL_VERSION, build_joint_payload_bytes, parse_joint_payload_or_legacy
from secrets_kit.backends.sqlite_schema import (
    SQLITE_USER_VERSION_V2,
    SQLITE_USER_VERSION_V3,
    apply_secrets_v2_table,
    ensure_schema,
    install_audit_schema,
)
from secrets_kit.backends.sqlite_unlock import UnlockProvider, _migrate_vault_meta_columns
from secrets_kit.models.core import ensure_entry_id
from secrets_kit.models.locator import locator_hash_hex, opaque_locator_hint
from secrets_kit.sync.canonical_record import attach_content_hash


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    cur = conn.execute(f"PRAGMA table_info({table})")
    return {str(row[1]) for row in cur.fetchall()}


def _migrate_legacy_to_v2(conn: sqlite3.Connection, db_path: str, unlock_provider: UnlockProvider) -> None:
    """Rename legacy ``secrets`` to ``secrets_legacy`` and repopulate v2 ``secrets``."""
    conn.execute("ALTER TABLE secrets RENAME TO secrets_legacy")
    apply_secrets_v2_table(conn)
    key = unlock_provider.materialize_master_key(conn, db_path)
    box = nacl.secret.SecretBox(key)
    rows = conn.execute(
        "SELECT service, account, name, ciphertext, nonce, updated_at, origin_host, crypto_version, metadata_json FROM secrets_legacy"
    ).fetchall()
    for svc, acct, nm, ciphertext, nonce, updated_at, origin_host, crypto_v, meta_json in rows:
        try:
            plain = box.decrypt(ciphertext, nonce)
        except nacl.exceptions.CryptoError:
            continue
        meta_json_str = meta_json if isinstance(meta_json, str) else ""
        secret_val, meta = parse_joint_payload_or_legacy(
            plain=plain,
            legacy_metadata_json=meta_json_str or None,
            service=str(svc),
            account=str(acct),
            name=str(nm),
        )
        meta = ensure_entry_id(meta)
        meta = replace(meta, name=str(nm), service=str(svc), account=str(acct))
        meta_h = attach_content_hash(secret=secret_val, metadata=replace(meta, content_hash=""))
        body = build_joint_payload_bytes(secret=secret_val, metadata=meta_h)
        enc = box.encrypt(body)
        n_nonce, ct = enc[:24], enc[24:]
        lh = opaque_locator_hint(entry_id=meta_h.entry_id)
        lhash = locator_hash_hex(service=str(svc), account=str(acct), name=str(nm))
        ch = str(meta_h.content_hash or "")
        conn.execute(
            """
            INSERT INTO secrets (entry_id, service, account, name, locator_hash, locator_hint,
                updated_at, origin_host, deleted, deleted_at, generation, tombstone_generation,
                backend_version, corrupt, corrupt_reason, last_validation_at,
                content_hash, ciphertext, nonce, crypto_version)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, '', 1, 0, ?, 0, '', '', ?, ?, ?, ?)
            """,
            (
                meta_h.entry_id,
                str(svc),
                str(acct),
                str(nm),
                lhash,
                lh,
                str(updated_at),
                str(origin_host),
                BACKEND_IMPL_VERSION,
                ch,
                ct,
                n_nonce,
                int(crypto_v),
            ),
        )
    conn.execute("DROP TABLE secrets_legacy")
    conn.commit()


def _ensure_content_hash_column(conn: sqlite3.Connection) -> None:
    cols = _table_columns(conn, "secrets")
    if "content_hash" not in cols:
        conn.execute("ALTER TABLE secrets ADD COLUMN content_hash TEXT NOT NULL DEFAULT ''")


def _ensure_corruption_columns(conn: sqlite3.Connection) -> None:
    cols = _table_columns(conn, "secrets")
    if "corrupt" not in cols:
        conn.execute("ALTER TABLE secrets ADD COLUMN corrupt INTEGER NOT NULL DEFAULT 0")
    if "corrupt_reason" not in cols:
        conn.execute("ALTER TABLE secrets ADD COLUMN corrupt_reason TEXT NOT NULL DEFAULT ''")
    if "last_validation_at" not in cols:
        conn.execute("ALTER TABLE secrets ADD COLUMN last_validation_at TEXT NOT NULL DEFAULT ''")


def _apply_audit_migration(conn: sqlite3.Connection) -> None:
    """Idempotent: ensure audit table + triggers; bump user_version to v3."""
    install_audit_schema(conn)
    cur_ver = int(conn.execute("PRAGMA user_version").fetchone()[0])
    if cur_ver < SQLITE_USER_VERSION_V3:
        conn.execute(f"PRAGMA user_version = {SQLITE_USER_VERSION_V3}")


def migrate_if_needed(conn: sqlite3.Connection, db_path: str, unlock_provider: UnlockProvider) -> None:
    """Open-time migration: base DDL, legacy → v2, column patches, audit v3.

    Preserves prior behavior for existing databases; adds ``secrets_audit`` + triggers
    and sets ``user_version`` to 3 when audit is installed.
    """
    ensure_schema(conn)
    _migrate_vault_meta_columns(conn)
    cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='secrets'")
    has_secrets = cur.fetchone() is not None
    if not has_secrets:
        apply_secrets_v2_table(conn)
        conn.commit()
        _apply_audit_migration(conn)
        conn.commit()
        return
    cols = _table_columns(conn, "secrets")
    if "entry_id" not in cols:
        _migrate_legacy_to_v2(conn, db_path=db_path, unlock_provider=unlock_provider)
        conn.execute(f"PRAGMA user_version = {SQLITE_USER_VERSION_V2}")
    _ensure_corruption_columns(conn)
    _ensure_content_hash_column(conn)
    conn.commit()
    _apply_audit_migration(conn)
    conn.commit()
