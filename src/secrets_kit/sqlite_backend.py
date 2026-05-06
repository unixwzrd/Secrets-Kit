"""Portable encrypted SQLite secret store (PyNaCl SecretBox + unlock providers)."""

from __future__ import annotations

import os
import socket
import sqlite3
from pathlib import Path
from typing import Any, Dict, Optional

import nacl.exceptions
import nacl.secret

from secrets_kit.keychain_backend import BackendError, backend_service_name
from secrets_kit.models import now_utc_iso
from secrets_kit.registry import registry_dir
from secrets_kit.sqlite_unlock import (
    UnlockProvider,
    _migrate_vault_meta_columns,
    build_sqlite_unlock_provider,
    clear_sqlite_unlock_cache,
    passphrase_for_store,
    set_sqlite_passphrase_provider,
)

CRYPTO_VERSION = 1

# Process-local cache: (abs_db_path, provider_kind, keychain_tag) -> DEK bytes
_master_key_by_db: Dict[tuple[str, str, str], bytes] = {}


def clear_sqlite_crypto_cache() -> None:
    """Clear passphrase, KEK, and master-key caches (for tests)."""
    clear_sqlite_unlock_cache()
    _master_key_by_db.clear()


def default_sqlite_db_path(*, home: Optional[Path] = None) -> str:
    """Default path for the SQLite store: ~/.config/seckit/secrets.db"""
    return str(registry_dir(home=home) / "secrets.db")


def _origin_host() -> str:
    override = os.environ.get("SECKIT_ORIGIN_HOST", "").strip()
    if override:
        return override
    try:
        return socket.gethostname() or "unknown"
    except OSError:
        return "unknown"


def _abs_db_path(db_path: str) -> str:
    return str(Path(db_path).expanduser().resolve())


def _connect(db_path: str) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=30.0)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS vault_meta (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            kdf_salt BLOB NOT NULL,
            opslimit INTEGER NOT NULL,
            memlimit INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            wrapped_dek BLOB,
            unlock_provider TEXT
        );
        CREATE TABLE IF NOT EXISTS secrets (
            service TEXT NOT NULL,
            account TEXT NOT NULL,
            name TEXT NOT NULL,
            ciphertext BLOB NOT NULL,
            nonce BLOB NOT NULL,
            updated_at TEXT NOT NULL,
            origin_host TEXT NOT NULL,
            crypto_version INTEGER NOT NULL,
            metadata_json TEXT,
            PRIMARY KEY (service, account, name)
        );
        """
    )
    conn.execute("PRAGMA user_version = 1")
    _migrate_vault_meta_columns(conn)


class SqliteSecretStore:
    """Encrypted SQLite-backed store implementing :class:`SecretStore`."""

    def __init__(
        self,
        *,
        db_path: str,
        unlock_provider: Optional[UnlockProvider] = None,
        kek_keychain_path: Optional[str] = None,
    ) -> None:
        self.db_path = os.path.expanduser(db_path)
        self._unlock_provider = unlock_provider or build_sqlite_unlock_provider(
            kek_keychain_path=kek_keychain_path,
        )

    def _master_cache_key(self) -> tuple[str, str, str]:
        prov = self._unlock_provider
        kc = getattr(prov, "keychain_path", None) or ""
        return (_abs_db_path(self.db_path), type(prov).__name__, str(kc))

    def _conn(self) -> sqlite3.Connection:
        conn = _connect(self.db_path)
        _init_schema(conn)
        return conn

    def _unlock_key(self, conn: sqlite3.Connection) -> bytes:
        ck = self._master_cache_key()
        if ck in _master_key_by_db:
            return _master_key_by_db[ck]
        key = self._unlock_provider.materialize_master_key(conn, self.db_path)
        _master_key_by_db[ck] = key
        return key

    def set(
        self,
        *,
        service: str,
        account: str,
        name: str,
        value: str,
        comment: str = "",
        label: Optional[str] = None,
    ) -> None:
        key = self._unlock_key(conn := self._conn())
        try:
            box = nacl.secret.SecretBox(key)
            encrypted = box.encrypt(value.encode("utf-8"))
            nonce, ciphertext = encrypted[:24], encrypted[24:]
            updated_at = now_utc_iso()
            origin = _origin_host()
            meta_json = comment if comment else None
            conn.execute(
                """
                INSERT INTO secrets (service, account, name, ciphertext, nonce, updated_at, origin_host, crypto_version, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(service, account, name) DO UPDATE SET
                    ciphertext = excluded.ciphertext,
                    nonce = excluded.nonce,
                    updated_at = excluded.updated_at,
                    origin_host = excluded.origin_host,
                    crypto_version = excluded.crypto_version,
                    metadata_json = excluded.metadata_json
                """,
                (service, account, name, ciphertext, nonce, updated_at, origin, CRYPTO_VERSION, meta_json),
            )
            conn.commit()
        finally:
            conn.close()

    def get(self, *, service: str, account: str, name: str) -> str:
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT ciphertext, nonce FROM secrets WHERE service = ? AND account = ? AND name = ?",
                (service, account, name),
            ).fetchone()
            if row is None:
                raise BackendError("secret not found")
            key = self._unlock_key(conn)
            ciphertext, nonce = row[0], row[1]
            box = nacl.secret.SecretBox(key)
            try:
                plain = box.decrypt(ciphertext, nonce)
            except nacl.exceptions.CryptoError as exc:
                raise BackendError("decryption failed (wrong passphrase or corrupted data)") from exc
            return plain.decode("utf-8")
        finally:
            conn.close()

    def metadata(self, *, service: str, account: str, name: str) -> Dict[str, Any]:
        """Return row metadata (stored in plaintext columns; no passphrase required)."""
        conn = self._conn()
        try:
            row = conn.execute(
                """
                SELECT metadata_json, updated_at, origin_host, crypto_version
                FROM secrets WHERE service = ? AND account = ? AND name = ?
                """,
                (service, account, name),
            ).fetchone()
            if row is None:
                raise BackendError("secret not found")
            metadata_json, updated_at, origin_host, crypto_version = row
            comment = metadata_json or ""
            svc = backend_service_name(service=service, name=name)
            return {
                "account": account,
                "service_name": svc,
                "label": name,
                "comment": comment,
                "created_at_raw": "",
                "modified_at_raw": "",
                "sqlite_updated_at": updated_at,
                "origin_host": origin_host,
                "crypto_version": int(crypto_version),
                "raw": "",
            }
        finally:
            conn.close()

    def exists(self, *, service: str, account: str, name: str) -> bool:
        conn = self._conn()
        try:
            _init_schema(conn)
            row = conn.execute(
                "SELECT 1 FROM secrets WHERE service = ? AND account = ? AND name = ? LIMIT 1",
                (service, account, name),
            ).fetchone()
            return row is not None
        finally:
            conn.close()

    def delete(self, *, service: str, account: str, name: str) -> None:
        conn = self._conn()
        try:
            conn.execute("DELETE FROM secrets WHERE service = ? AND account = ? AND name = ?", (service, account, name))
            conn.commit()
        finally:
            conn.close()
