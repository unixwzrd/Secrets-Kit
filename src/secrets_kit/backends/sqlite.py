"""Portable encrypted SQLite secret store (PyNaCl SecretBox + unlock providers).

v2 schema: decrypt-free index columns + single encrypted joint payload (secret + metadata).
Legacy v1 rows (plaintext metadata_json + ciphertext = secret only) are migrated on open.
"""

from __future__ import annotations

import os
import socket
import sqlite3
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, Optional, Tuple

import nacl.exceptions
import nacl.secret

from secrets_kit.backends.base import (
    BACKEND_IMPL_VERSION,
    INDEX_SCHEMA_VERSION,
    PAYLOAD_SCHEMA_VERSION,
    BackendCapabilities,
    BackendSecurityPosture,
    BackendStore,
    IndexRow,
    ResolvedEntry,
    build_joint_payload_bytes,
    normalize_store_locator,
    parse_joint_payload_or_legacy,
)
from secrets_kit.backends.security import BackendError, backend_service_name
from secrets_kit.backends.inventory import GenpCandidate
from secrets_kit.models.locator import locator_hash_hex, opaque_locator_hint
from secrets_kit.models.core import EntryMetadata, Locator, ensure_entry_id, now_utc_iso
from secrets_kit.models.lineage import LineageSnapshot
from secrets_kit.registry.core import registry_dir
from secrets_kit.sync.canonical_record import attach_content_hash
from secrets_kit.backends.sqlite_unlock import (
    UnlockProvider,
    _migrate_vault_meta_columns,
    build_sqlite_unlock_provider,
    clear_sqlite_unlock_cache,
)

CRYPTO_VERSION = 1
PLAINTEXT_DEBUG_CRYPTO_VERSION = 0
SQLITE_USER_VERSION_V2 = 2
_SQLITE_PLAINTEXT_DEBUG_WARNED = False

# Process-local cache: (abs_db_path, provider_kind, keychain_tag) -> DEK bytes
_master_key_by_db: Dict[tuple[str, str, str], bytes] = {}


def _sqlite_plaintext_debug_enabled() -> bool:
    """Opt-in **non-production** mode: store joint payload bytes without SecretBox."""
    return os.environ.get("SECKIT_SQLITE_PLAINTEXT_DEBUG", "").strip().lower() in ("1", "true", "yes")


def _warn_sqlite_plaintext_debug_once() -> None:
    global _SQLITE_PLAINTEXT_DEBUG_WARNED
    if not _sqlite_plaintext_debug_enabled() or _SQLITE_PLAINTEXT_DEBUG_WARNED:
        return
    _SQLITE_PLAINTEXT_DEBUG_WARNED = True
    print(
        "WARNING: SECKIT_SQLITE_PLAINTEXT_DEBUG is set — joint payloads stored WITHOUT encryption. "
        "Development/testing/forensics only; not for production secrets.",
        file=sys.stderr,
    )


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


_SCHEMA_V2_SECRETS = """
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


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    cur = conn.execute(f"PRAGMA table_info({table})")
    return {str(row[1]) for row in cur.fetchall()}


def _migrate_legacy_to_v2(conn: sqlite3.Connection, db_path: str, unlock_provider: UnlockProvider) -> None:
    """Rename legacy ``secrets`` to ``secrets_legacy`` and repopulate v2 ``secrets``."""
    conn.execute("ALTER TABLE secrets RENAME TO secrets_legacy")
    conn.executescript(
        """
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
    )
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


def _init_schema(conn: sqlite3.Connection, db_path: str, unlock_provider: UnlockProvider) -> None:
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
        """
    )
    _migrate_vault_meta_columns(conn)
    cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='secrets'")
    has_secrets = cur.fetchone() is not None
    if not has_secrets:
        conn.executescript(_SCHEMA_V2_SECRETS)
        conn.execute(f"PRAGMA user_version = {SQLITE_USER_VERSION_V2}")
        conn.commit()
        return
    cols = _table_columns(conn, "secrets")
    if "entry_id" not in cols:
        _migrate_legacy_to_v2(conn, db_path=db_path, unlock_provider=unlock_provider)
        conn.execute(f"PRAGMA user_version = {SQLITE_USER_VERSION_V2}")
    _ensure_corruption_columns(conn)
    _ensure_content_hash_column(conn)
    conn.commit()


def iter_secrets_plaintext_index(
    *, db_path: str, service_filter: Optional[str] = None
) -> Iterator[GenpCandidate]:
    """Yield recover candidates for SQLite.

    v2 stores metadata inside the encrypted payload; this iterator **decrypts** each row to
    rebuild comment JSON for :func:`recover_sources.iter_recover_candidates` (unlock required).
    """
    store = SqliteSecretStore(db_path=str(Path(db_path).expanduser()))
    yield from store.iter_recover_genp_candidates(service_filter=service_filter)


class SqliteSecretStore(BackendStore):
    """Encrypted SQLite-backed store implementing :class:`SecretStore` and :class:`BackendStore`."""

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
        _warn_sqlite_plaintext_debug_once()

    def _master_cache_key(self) -> tuple[str, str, str]:
        prov = self._unlock_provider
        kc = getattr(prov, "keychain_path", None) or ""
        return (_abs_db_path(self.db_path), type(prov).__name__, str(kc))

    def _conn(self) -> sqlite3.Connection:
        conn = _connect(self.db_path)
        _init_schema(conn, db_path=self.db_path, unlock_provider=self._unlock_provider)
        return conn

    def _unlock_key(self, conn: sqlite3.Connection) -> bytes:
        ck = self._master_cache_key()
        if ck in _master_key_by_db:
            return _master_key_by_db[ck]
        key = self._unlock_provider.materialize_master_key(conn, self.db_path)
        _master_key_by_db[ck] = key
        return key

    # --- BackendStore ---
    def security_posture(self) -> BackendSecurityPosture:
        if _sqlite_plaintext_debug_enabled():
            return BackendSecurityPosture(
                metadata_encrypted=False,
                safe_index_supported=True,
                requires_unlock_for_metadata=True,
                supports_secure_delete=False,
            )
        return BackendSecurityPosture(
            metadata_encrypted=True,
            safe_index_supported=True,
            requires_unlock_for_metadata=True,
            supports_secure_delete=False,
        )

    def capabilities(self) -> BackendCapabilities:
        return BackendCapabilities(
            supports_safe_index=True,
            supports_unlock_enumeration=True,
            supports_atomic_rename=True,
            supports_tombstones=True,
            supports_backend_migrate=True,
            supports_transactional_set=True,
            supports_selective_resolve=True,
            set_atomicity="atomic",
            supports_peer_lineage_merge=True,
            supports_reconcile_transaction=True,
        )

    def _row_to_index_safe(self, row: Tuple[Any, ...]) -> IndexRow:
        (
            entry_id,
            locator_hash,
            locator_hint,
            updated_at,
            deleted,
            deleted_at,
            generation,
            tombstone_generation,
            backend_impl,
            corrupt,
            corrupt_reason,
            last_validation_at,
        ) = row
        return IndexRow(
            entry_id=str(entry_id),
            locator_hash=str(locator_hash),
            locator_hint=str(locator_hint),
            updated_at=str(updated_at),
            deleted=bool(deleted),
            deleted_at=str(deleted_at or ""),
            generation=int(generation),
            tombstone_generation=int(tombstone_generation),
            index_schema_version=INDEX_SCHEMA_VERSION,
            payload_schema_version=PAYLOAD_SCHEMA_VERSION,
            backend_impl_version=int(backend_impl),
            payload_ref=str(entry_id),
            corrupt=bool(corrupt),
            corrupt_reason=str(corrupt_reason or ""),
            last_validation_at=str(last_validation_at or ""),
        )

    def _row_to_index_from_full_prefix(self, meta_slice: Tuple[Any, ...]) -> IndexRow:
        (
            entry_id,
            locator_hash,
            locator_hint,
            _service,
            _account,
            _name,
            updated_at,
            deleted,
            deleted_at,
            generation,
            tombstone_generation,
            backend_impl,
            corrupt,
            corrupt_reason,
            last_validation_at,
        ) = meta_slice
        return IndexRow(
            entry_id=str(entry_id),
            locator_hash=str(locator_hash),
            locator_hint=str(locator_hint),
            updated_at=str(updated_at),
            deleted=bool(deleted),
            deleted_at=str(deleted_at or ""),
            generation=int(generation),
            tombstone_generation=int(tombstone_generation),
            index_schema_version=INDEX_SCHEMA_VERSION,
            payload_schema_version=PAYLOAD_SCHEMA_VERSION,
            backend_impl_version=int(backend_impl),
            payload_ref=str(entry_id),
            corrupt=bool(corrupt),
            corrupt_reason=str(corrupt_reason or ""),
            last_validation_at=str(last_validation_at or ""),
        )

    def iter_index(self) -> Iterator[IndexRow]:
        conn = self._conn()
        try:
            cur = conn.execute(
                """
                SELECT entry_id, locator_hash, locator_hint,
                       updated_at, deleted, deleted_at, generation, tombstone_generation, backend_version,
                       corrupt, corrupt_reason, last_validation_at
                FROM secrets ORDER BY entry_id
                """
            )
            for row in cur.fetchall():
                yield self._row_to_index_safe(row)
        finally:
            conn.close()

    def rebuild_index(self) -> None:
        conn = self._conn()
        try:
            cur = conn.execute(
                """
                SELECT entry_id, locator_hash, locator_hint, service, account, name, updated_at,
                       deleted, deleted_at, generation, tombstone_generation, backend_version,
                       corrupt, corrupt_reason, last_validation_at,
                       ciphertext, nonce, crypto_version
                FROM secrets
                """
            )
            for row in cur.fetchall():
                if row[7]:
                    continue
                try:
                    resolved = self._decrypt_resolved(conn, row)
                except BackendError:
                    conn.execute(
                        """
                        UPDATE secrets SET corrupt = 1, corrupt_reason = ?, last_validation_at = ?
                        WHERE entry_id = ?
                        """,
                        ("decrypt_failed", now_utc_iso(), row[0]),
                    )
                    continue
                meta = resolved.metadata
                lh = opaque_locator_hint(entry_id=str(row[0]))
                lhash = locator_hash_hex(service=meta.service, account=meta.account, name=meta.name)
                conn.execute(
                    """
                    UPDATE secrets SET locator_hash = ?, locator_hint = ?,
                        corrupt = 0, corrupt_reason = '', last_validation_at = ?
                    WHERE entry_id = ? AND deleted = 0
                    """,
                    (lhash, lh, now_utc_iso(), row[0]),
                )
            conn.commit()
        finally:
            conn.close()

    def _metadata_from_comment(self, *, comment: str, service: str, account: str, name: str) -> EntryMetadata:
        if comment.strip():
            parsed = EntryMetadata.from_keychain_comment(comment)
            if parsed is not None:
                return ensure_entry_id(parsed)
        ts = now_utc_iso()
        return ensure_entry_id(
            EntryMetadata(name=name, service=service, account=account, created_at=ts, updated_at=ts, source="manual")
        )

    def read_lineage_snapshot(
        self,
        *,
        entry_id: Optional[str] = None,
        service: str = "",
        account: str = "",
        name: str = "",
    ) -> Optional[LineageSnapshot]:
        """Return index lineage for one row (no payload decrypt)."""
        conn = self._conn()
        try:
            eid = (entry_id or "").strip()
            if eid:
                row = conn.execute(
                    """
                    SELECT entry_id, service, account, name, generation, tombstone_generation, deleted
                    FROM secrets WHERE entry_id = ?
                    """,
                    (eid,),
                ).fetchone()
            else:
                loc = normalize_store_locator(service=service, account=account, name=name)
                row = conn.execute(
                    """
                    SELECT entry_id, service, account, name, generation, tombstone_generation, deleted
                    FROM secrets WHERE service = ? AND account = ? AND name = ?
                    """,
                    (loc.service, loc.account, loc.name),
                ).fetchone()
            if row is None:
                return None
            return LineageSnapshot(
                entry_id=str(row[0]),
                service=str(row[1]),
                account=str(row[2]),
                name=str(row[3]),
                generation=int(row[4]),
                tombstone_generation=int(row[5]),
                deleted=bool(row[6]),
            )
        finally:
            conn.close()

    def run_reconcile_transaction(self, fn: Callable[[sqlite3.Connection], None]) -> None:
        """One ``BEGIN IMMEDIATE`` … ``COMMIT`` scope for Phase 6A reconcile (pair mutations deterministically)."""
        conn = self._conn()
        try:
            conn.execute("BEGIN IMMEDIATE")
            fn(conn)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _bump_tombstone_lineage_conn(
        self,
        conn: sqlite3.Connection,
        *,
        entry_id: str,
        tombstone_generation: int,
    ) -> None:
        """Advance tombstone generation when local row is already deleted and *incoming* is strictly newer."""
        row = conn.execute(
            "SELECT tombstone_generation, deleted FROM secrets WHERE entry_id = ?",
            (entry_id,),
        ).fetchone()
        if row is None or not bool(row[1]):
            return
        cur_t = int(row[0])
        if tombstone_generation <= cur_t:
            return
        conn.execute(
            """
            UPDATE secrets SET tombstone_generation = ?, updated_at = ?, origin_host = ?
            WHERE entry_id = ? AND deleted = 1
            """,
            (tombstone_generation, now_utc_iso(), _origin_host(), entry_id),
        )

    def bump_tombstone_lineage(
        self,
        *,
        entry_id: str,
        tombstone_generation: int,
    ) -> None:
        """Advance tombstone generation when local row is already deleted and *incoming* is strictly newer."""

        def _go(conn: sqlite3.Connection) -> None:
            self._bump_tombstone_lineage_conn(conn, entry_id=entry_id, tombstone_generation=tombstone_generation)

        self.run_reconcile_transaction(_go)

    def _delete_entry_locator_conn(
        self, conn: sqlite3.Connection, *, service: str, account: str, name: str
    ) -> None:
        """Tombstone one row by locator; caller owns the transaction."""
        loc = normalize_store_locator(service=service, account=account, name=name)
        row = self._read_row_full(conn, loc.service, loc.account, loc.name)
        if row is None:
            return
        gen = int(row[9]) + 1
        tgen = int(row[10]) + 1
        conn.execute(
            """
            UPDATE secrets SET deleted = 1, deleted_at = ?, generation = ?, tombstone_generation = ?, updated_at = ?
            WHERE service = ? AND account = ? AND name = ?
            """,
            (now_utc_iso(), gen, tgen, now_utc_iso(), loc.service, loc.account, loc.name),
        )

    def _read_row_full(self, conn: sqlite3.Connection, service: str, account: str, name: str) -> Optional[Any]:
        loc = normalize_store_locator(service=service, account=account, name=name)
        return conn.execute(
            """
            SELECT entry_id, locator_hash, locator_hint, service, account, name, updated_at,
                   deleted, deleted_at, generation, tombstone_generation, backend_version,
                   corrupt, corrupt_reason, last_validation_at,
                   ciphertext, nonce, crypto_version
            FROM secrets WHERE service = ? AND account = ? AND name = ?
            """,
            (loc.service, loc.account, loc.name),
        ).fetchone()

    def _decrypt_resolved(self, conn: sqlite3.Connection, row: Tuple[Any, ...]) -> ResolvedEntry:
        meta_slice = row[:-3]
        ciphertext, nonce, crypto_ver = row[-3], row[-2], row[-1]
        if int(crypto_ver) == PLAINTEXT_DEBUG_CRYPTO_VERSION:
            plain = bytes(ciphertext)
        else:
            key = self._unlock_key(conn)
            box = nacl.secret.SecretBox(key)
            try:
                plain = box.decrypt(ciphertext, nonce)
            except nacl.exceptions.CryptoError as exc:
                raise BackendError("decryption failed (wrong passphrase or corrupted data)") from exc
        (
            _entry_id,
            _locator_hash,
            _locator_hint,
            service,
            account,
            name,
            _updated_at,
            _deleted,
            _deleted_at,
            _generation,
            _tombstone_generation,
            _backend_impl,
            _corrupt,
            _corrupt_reason,
            _last_validation_at,
        ) = meta_slice
        secret_val, meta = parse_joint_payload_or_legacy(
            plain=plain,
            legacy_metadata_json=None,
            service=str(service),
            account=str(account),
            name=str(name),
        )
        return ResolvedEntry(secret=secret_val, metadata=meta)

    def _materialize_payload_storage(
        self, conn: sqlite3.Connection, body: bytes
    ) -> Tuple[bytes, bytes, int]:
        """Return (ciphertext, nonce, crypto_version) for the joint payload bytes."""
        if _sqlite_plaintext_debug_enabled():
            return body, b"\x00" * 24, PLAINTEXT_DEBUG_CRYPTO_VERSION
        key = self._unlock_key(conn)
        box = nacl.secret.SecretBox(key)
        enc = box.encrypt(body)
        nonce_b, ciphertext_b = enc[:24], enc[24:]
        return ciphertext_b, nonce_b, CRYPTO_VERSION

    def set_entry(
        self,
        *,
        service: str,
        account: str,
        name: str,
        secret: str,
        metadata: EntryMetadata,
    ) -> None:
        meta = ensure_entry_id(metadata)
        loc = normalize_store_locator(service=service, account=account, name=name)
        meta = replace(meta, name=loc.name, service=loc.service, account=loc.account)
        if not (meta.updated_at or "").strip():
            meta = replace(meta, updated_at=now_utc_iso())
        conn = self._conn()
        try:
            self._set_entry_conn(conn, loc=loc, secret=secret, meta=meta)
            conn.commit()
        finally:
            conn.close()

    def _set_entry_conn(
        self,
        conn: sqlite3.Connection,
        *,
        loc: Locator,
        secret: str,
        meta: EntryMetadata,
    ) -> None:
        """Persist payload; caller owns transaction/commits when used inside ``BEGIN``."""
        meta = ensure_entry_id(meta)
        meta = replace(meta, name=loc.name, service=loc.service, account=loc.account)
        if not (meta.updated_at or "").strip():
            meta = replace(meta, updated_at=now_utc_iso())
        updated_at = meta.updated_at
        origin = _origin_host()
        existing = self._read_row_full(conn, loc.service, loc.account, loc.name)
        if existing:
            _eid = str(existing[0])
            gen = int(existing[9]) + 1
            entry_id = meta.entry_id or _eid
            if entry_id != _eid:
                entry_id = _eid
            meta = replace(meta, entry_id=entry_id)
            meta_h = attach_content_hash(secret=secret, metadata=replace(meta, content_hash=""))
            body = build_joint_payload_bytes(secret=secret, metadata=meta_h)
            ciphertext2, nonce2, crypto_v2 = self._materialize_payload_storage(conn, body)
            lh = opaque_locator_hint(entry_id=meta_h.entry_id)
            lhash = locator_hash_hex(service=loc.service, account=loc.account, name=loc.name)
            ch = str(meta_h.content_hash or "")
            conn.execute(
                """
                UPDATE secrets SET
                    locator_hash = ?, locator_hint = ?, updated_at = ?, origin_host = ?,
                    generation = ?, tombstone_generation = ?, backend_version = ?,
                    content_hash = ?,
                    ciphertext = ?, nonce = ?, crypto_version = ?,
                    corrupt = 0, corrupt_reason = '', last_validation_at = ?
                WHERE service = ? AND account = ? AND name = ? AND deleted = 0
                """,
                (
                    lhash,
                    lh,
                    updated_at,
                    origin,
                    gen,
                    int(existing[10]),
                    BACKEND_IMPL_VERSION,
                    ch,
                    ciphertext2,
                    nonce2,
                    crypto_v2,
                    now_utc_iso(),
                    loc.service,
                    loc.account,
                    loc.name,
                ),
            )
        else:
            meta_h = attach_content_hash(secret=secret, metadata=replace(meta, content_hash=""))
            body = build_joint_payload_bytes(secret=secret, metadata=meta_h)
            ciphertext, nonce, crypto_v = self._materialize_payload_storage(conn, body)
            lh = opaque_locator_hint(entry_id=meta_h.entry_id)
            lhash = locator_hash_hex(service=loc.service, account=loc.account, name=loc.name)
            ch = str(meta_h.content_hash or "")
            conn.execute(
                """
                INSERT INTO secrets (
                    entry_id, service, account, name, locator_hash, locator_hint,
                    updated_at, origin_host, deleted, deleted_at, generation, tombstone_generation,
                    backend_version, corrupt, corrupt_reason, last_validation_at,
                    content_hash, ciphertext, nonce, crypto_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, '', 1, 0, ?, 0, '', '', ?, ?, ?, ?)
                """,
                (
                    meta_h.entry_id,
                    loc.service,
                    loc.account,
                    loc.name,
                    lhash,
                    lh,
                    updated_at,
                    origin,
                    BACKEND_IMPL_VERSION,
                    ch,
                    ciphertext,
                    nonce,
                    crypto_v,
                ),
            )

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
        meta = self._metadata_from_comment(comment=comment, service=service, account=account, name=name)
        self.set_entry(service=service, account=account, name=name, secret=value, metadata=meta)

    def get_secret(self, *, service: str, account: str, name: str) -> str:
        return self.get(service=service, account=account, name=name)

    def get(self, *, service: str, account: str, name: str) -> str:
        conn = self._conn()
        try:
            row = self._read_row_full(conn, service, account, name)
            if row is None or row[7]:
                raise BackendError("secret not found")
            resolved = self._decrypt_resolved(conn, row)
            return resolved.secret
        finally:
            conn.close()

    def resolve_by_entry_id(self, *, entry_id: str) -> Optional[ResolvedEntry]:
        conn = self._conn()
        try:
            row = conn.execute(
                """
                SELECT entry_id, locator_hash, locator_hint, service, account, name, updated_at,
                       deleted, deleted_at, generation, tombstone_generation, backend_version,
                       corrupt, corrupt_reason, last_validation_at,
                       ciphertext, nonce, crypto_version
                FROM secrets WHERE entry_id = ?
                """,
                (entry_id,),
            ).fetchone()
            if row is None or row[7]:
                return None
            return self._decrypt_resolved(conn, row)
        finally:
            conn.close()

    def resolve_by_locator(self, *, service: str, account: str, name: str) -> Optional[ResolvedEntry]:
        conn = self._conn()
        try:
            row = self._read_row_full(conn, service, account, name)
            if row is None or row[7]:
                return None
            return self._decrypt_resolved(conn, row)
        finally:
            conn.close()

    def metadata(self, *, service: str, account: str, name: str) -> Dict[str, Any]:
        conn = self._conn()
        try:
            row = self._read_row_full(conn, service, account, name)
            if row is None:
                raise BackendError("secret not found")
            resolved = self._decrypt_resolved(conn, row)
            comment = resolved.metadata.to_keychain_comment()
            svc = backend_service_name(service=service, name=name)
            return {
                "account": account,
                "service_name": svc,
                "label": name,
                "comment": comment,
                "created_at_raw": "",
                "modified_at_raw": "",
                "sqlite_updated_at": str(row[6]),
                "origin_host": _origin_host(),
                "crypto_version": int(row[-1]),
                "raw": "",
            }
        finally:
            conn.close()

    def exists(self, *, service: str, account: str, name: str) -> bool:
        loc = normalize_store_locator(service=service, account=account, name=name)
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT deleted FROM secrets WHERE service = ? AND account = ? AND name = ?",
                (loc.service, loc.account, loc.name),
            ).fetchone()
            return row is not None and not bool(row[0])
        finally:
            conn.close()

    def delete_entry(self, *, service: str, account: str, name: str) -> None:
        loc = normalize_store_locator(service=service, account=account, name=name)
        conn = self._conn()
        try:
            self._delete_entry_locator_conn(conn, service=loc.service, account=loc.account, name=loc.name)
            conn.commit()
        finally:
            conn.close()

    def delete(self, *, service: str, account: str, name: str) -> None:
        self.delete_entry(service=service, account=account, name=name)

    def iter_unlocked(
        self, *, filter_fn: Optional[Callable[[IndexRow, EntryMetadata], bool]] = None
    ) -> Iterator[tuple[IndexRow, ResolvedEntry]]:
        conn = self._conn()
        try:
            cur = conn.execute(
                """
                SELECT entry_id, locator_hash, locator_hint, service, account, name,
                       updated_at, deleted, deleted_at, generation, tombstone_generation, backend_version,
                       corrupt, corrupt_reason, last_validation_at,
                       ciphertext, nonce, crypto_version
                FROM secrets WHERE deleted = 0
                """
            )
            for row in cur.fetchall():
                idx = self._row_to_index_from_full_prefix(row[:-3])
                try:
                    resolved = self._decrypt_resolved(conn, row)
                except BackendError:
                    continue
                if filter_fn is None or filter_fn(idx, resolved.metadata):
                    yield idx, resolved
        finally:
            conn.close()

    def _rename_entry_conn(
        self,
        conn: sqlite3.Connection,
        *,
        entry_id: str,
        new_service: str,
        new_account: str,
        new_name: str,
    ) -> None:
        """Move locator for ``entry_id``; caller owns the transaction."""
        nloc = normalize_store_locator(service=new_service, account=new_account, name=new_name)
        row = conn.execute(
            """
            SELECT entry_id, locator_hash, locator_hint, service, account, name, updated_at,
                   deleted, deleted_at, generation, tombstone_generation, backend_version,
                   corrupt, corrupt_reason, last_validation_at,
                   ciphertext, nonce, crypto_version
            FROM secrets WHERE entry_id = ?
            """,
            (entry_id,),
        ).fetchone()
        if row is None or row[7]:
            raise BackendError("secret not found")
        resolved = self._decrypt_resolved(conn, row)
        gen = int(row[9]) + 1
        new_hash = locator_hash_hex(service=nloc.service, account=nloc.account, name=nloc.name)
        new_hint = opaque_locator_hint(entry_id=entry_id)
        meta = replace(
            resolved.metadata,
            name=nloc.name,
            service=nloc.service,
            account=nloc.account,
            updated_at=now_utc_iso(),
        )
        meta_h = attach_content_hash(secret=resolved.secret, metadata=replace(meta, content_hash=""))
        body = build_joint_payload_bytes(secret=resolved.secret, metadata=meta_h)
        ciphertext, nonce, crypto_v = self._materialize_payload_storage(conn, body)
        ch = str(meta_h.content_hash or "")
        conn.execute("DELETE FROM secrets WHERE entry_id = ?", (entry_id,))
        conn.execute(
            """
            INSERT INTO secrets (
                entry_id, service, account, name, locator_hash, locator_hint,
                updated_at, origin_host, deleted, deleted_at, generation, tombstone_generation,
                backend_version, corrupt, corrupt_reason, last_validation_at,
                content_hash, ciphertext, nonce, crypto_version
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, '', ?, 0, ?, 0, '', '', ?, ?, ?, ?)
            """,
            (
                entry_id,
                nloc.service,
                nloc.account,
                nloc.name,
                new_hash,
                new_hint,
                now_utc_iso(),
                _origin_host(),
                gen,
                BACKEND_IMPL_VERSION,
                ch,
                ciphertext,
                nonce,
                crypto_v,
            ),
        )

    def rename_entry(self, *, entry_id: str, new_service: str, new_account: str, new_name: str) -> None:
        conn = self._conn()
        try:
            self._rename_entry_conn(
                conn,
                entry_id=entry_id,
                new_service=new_service,
                new_account=new_account,
                new_name=new_name,
            )
            conn.commit()
        finally:
            conn.close()

    def iter_recover_genp_candidates(self, *, service_filter: Optional[str] = None) -> Iterator[GenpCandidate]:
        for _idx, resolved in self.iter_unlocked():
            if service_filter and resolved.metadata.service != service_filter:
                continue
            yield GenpCandidate(
                account=resolved.metadata.account,
                service=resolved.metadata.service,
                name=resolved.metadata.name,
                comment=resolved.metadata.to_keychain_comment(),
            )




