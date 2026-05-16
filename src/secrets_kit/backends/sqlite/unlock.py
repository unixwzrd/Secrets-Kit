"""
secrets_kit.backends.sqlite.unlock

SQLite vault unlock: passphrase KDF (legacy) or macOS Keychain-wrapped DEK.
"""

from __future__ import annotations

import base64
import getpass
import hashlib
import os
import sqlite3
import sys
from typing import Callable, Protocol

import nacl.pwhash
import nacl.secret
from secrets_kit.backends.security import BackendError, _run_security
from secrets_kit.models.core import now_utc_iso

UNLOCK_PASSPHRASE = "passphrase"
UNLOCK_KEYCHAIN = "keychain"

WRAPPED_DEK_VERSION = 1

_sqlite_passphrase_provider: Callable[[], str] | None = None

# Process-local cache: resolved passphrase bytes per absolute db path (UTF-8 phrase).
_passphrase_by_db: dict[str, str] = {}

# Process-local cache: base64 KEK per (abs_db_path, keychain_path key).
_kek_b64_by_db: dict[tuple[str, str], str] = {}


def clear_sqlite_unlock_cache() -> None:
    """Clear passphrase and KEK resolution caches (for tests)."""
    _passphrase_by_db.clear()
    _kek_b64_by_db.clear()


def set_sqlite_passphrase_provider(fn: Callable[[], str] | None) -> None:
    """Override passphrase resolution (used by tests). Pass None to restore default behavior."""
    global _sqlite_passphrase_provider
    _sqlite_passphrase_provider = fn


def _resolve_passphrase() -> str:
    """Resolve the SQLite passphrase from provider, env, or interactive prompt."""
    if _sqlite_passphrase_provider is not None:
        return _sqlite_passphrase_provider()
    env = os.environ.get("SECKIT_SQLITE_PASSPHRASE", "")
    if env:
        return env
    if sys.stdin.isatty():
        p1 = getpass.getpass("SQLite store passphrase: ")
        p2 = getpass.getpass("Confirm passphrase: ")
        if p1 != p2:
            raise BackendError("passphrases do not match")
        if not p1:
            raise BackendError("passphrase cannot be empty")
        return p1
    raise BackendError(
        "SQLite backend needs a passphrase: set SECKIT_SQLITE_PASSPHRASE or run interactively."
    )


def abs_db_path(db_path: str) -> str:
    """Normalized absolute path string for cache keys."""
    from pathlib import Path

    return str(Path(db_path).expanduser().resolve())


def passphrase_for_store(db_path: str) -> str:
    """Return passphrase for this DB, caching per absolute path."""
    ap = abs_db_path(db_path)
    if ap in _passphrase_by_db:
        return _passphrase_by_db[ap]
    phrase = _resolve_passphrase()
    _passphrase_by_db[ap] = phrase
    return phrase


def derive_legacy_master_key(*, passphrase: str, salt: bytes, opslimit: int, memlimit: int) -> bytes:
    """Argon2id KDF for legacy vaults (salt + params stored in vault_meta). Public for tests."""
    return nacl.pwhash.argon2id.kdf(
        nacl.secret.SecretBox.KEY_SIZE,
        passphrase.encode("utf-8"),
        salt,
        opslimit=opslimit,
        memlimit=memlimit,
    )


def _migrate_vault_meta_columns(conn: sqlite3.Connection) -> None:
    """Add wrapped_dek / unlock_provider if missing (idempotent)."""
    cur = conn.execute("PRAGMA table_info(vault_meta)")
    names = {str(row[1]) for row in cur.fetchall()}
    if "wrapped_dek" not in names:
        conn.execute("ALTER TABLE vault_meta ADD COLUMN wrapped_dek BLOB")
    if "unlock_provider" not in names:
        conn.execute("ALTER TABLE vault_meta ADD COLUMN unlock_provider TEXT")


def _kek_service_account(*, db_path: str) -> tuple[str, str]:
    """Return deterministic (service, account) tuple for the KEK keychain entry."""
    h = hashlib.sha256(abs_db_path(db_path).encode("utf-8")).hexdigest()
    return "ai.unixwzrd.seckit.sqlite-vault-kek", h[:32]


def _wrap_dek(*, dek: bytes, kek: bytes) -> bytes:
    """Wrap a DEK with a KEK using SecretBox; prefix with version byte."""
    box = nacl.secret.SecretBox(kek)
    return bytes([WRAPPED_DEK_VERSION]) + box.encrypt(dek)


def _unwrap_dek(*, wrapped: bytes, kek: bytes) -> bytes:
    """Unwrap a DEK using a KEK; validate version byte."""
    if not wrapped or wrapped[0] != WRAPPED_DEK_VERSION:
        raise BackendError("invalid wrapped DEK payload in vault_meta")
    box = nacl.secret.SecretBox(kek)
    return box.decrypt(wrapped[1:])


def _security_append_keychain(args: list[str], keychain_path: str | None) -> list[str]:
    """Append keychain target arguments to a ``security`` CLI argument list."""
    out = list(args)
    if keychain_path:
        out.extend(["-T", "/usr/bin/security"])
        out.append(os.path.expanduser(keychain_path))
    return out


def _read_kek_b64(*, db_path: str, keychain_path: str | None) -> str:
    """Read the base64-encoded KEK from the macOS Keychain."""
    service, account = _kek_service_account(db_path=db_path)
    args = _security_append_keychain(
        ["find-generic-password", "-a", account, "-s", service, "-w"],
        keychain_path,
    )
    return _run_security(args=args)


def _write_kek_b64(*, db_path: str, keychain_path: str | None, kek_b64: str) -> None:
    """Write the base64-encoded KEK to the macOS Keychain."""
    service, account = _kek_service_account(db_path=db_path)
    args = _security_append_keychain(
        [
            "add-generic-password",
            "-a",
            account,
            "-s",
            service,
            "-l",
            "seckit-sqlite-kek",
            "-j",
            "",
            "-U",
            "-w",
            kek_b64,
        ],
        keychain_path,
    )
    _run_security(args=args)


def _read_kek_bytes_required(*, db_path: str, keychain_path: str | None) -> bytes:
    """Load KEK from Keychain; used when opening an existing wrapped vault."""
    cache_key = (abs_db_path(db_path), keychain_path or "")
    if cache_key in _kek_b64_by_db:
        return base64.standard_b64decode(_kek_b64_by_db[cache_key].encode("ascii"))
    b64 = _read_kek_b64(db_path=db_path, keychain_path=keychain_path)
    kek = base64.standard_b64decode(b64.encode("ascii"))
    _kek_b64_by_db[cache_key] = b64
    return kek


def _get_or_create_kek_bytes(*, db_path: str, keychain_path: str | None) -> bytes:
    """Create KEK item if missing — only when provisioning a new keychain-wrapped vault."""
    cache_key = (abs_db_path(db_path), keychain_path or "")
    if cache_key in _kek_b64_by_db:
        return base64.standard_b64decode(_kek_b64_by_db[cache_key].encode("ascii"))
    try:
        b64 = _read_kek_b64(db_path=db_path, keychain_path=keychain_path)
        kek = base64.standard_b64decode(b64.encode("ascii"))
    except BackendError:
        kek = os.urandom(nacl.secret.SecretBox.KEY_SIZE)
        b64 = base64.standard_b64encode(kek).decode("ascii")
        _write_kek_b64(db_path=db_path, keychain_path=keychain_path, kek_b64=b64)
    _kek_b64_by_db[cache_key] = b64
    return kek


class UnlockProvider(Protocol):
    """Supplies the master encryption key (DEK) for SQLite SecretBox."""

    @property
    def provider_name(self) -> str:
        """Identifier persisted in vault_meta.unlock_provider for wrapped vaults."""

    def materialize_master_key(self, conn: sqlite3.Connection, db_path: str) -> bytes:
        """Ensure vault_meta exists when creating a new vault; return 32-byte DEK."""


class PassphraseUnlockProvider:
    """Legacy passphrase + Argon2id KDF, or error if vault is keychain-wrapped."""

    @property
    def provider_name(self) -> str:
        return UNLOCK_PASSPHRASE

    def materialize_master_key(self, conn: sqlite3.Connection, db_path: str) -> bytes:
        """Derive or return the master key for a passphrase-backed vault.

        Creates a new vault_meta row when the vault is first opened.
        Raises ``BackendError`` when the vault is keychain-wrapped.
        """
        _migrate_vault_meta_columns(conn)
        row = conn.execute(
            """
            SELECT kdf_salt, opslimit, memlimit, wrapped_dek, unlock_provider
            FROM vault_meta WHERE id = 1
            """
        ).fetchone()
        phrase = passphrase_for_store(db_path)
        if row is None:
            salt = os.urandom(nacl.pwhash.argon2id.SALTBYTES)
            opslimit = nacl.pwhash.argon2id.OPSLIMIT_MODERATE
            memlimit = nacl.pwhash.argon2id.MEMLIMIT_MODERATE
            created = now_utc_iso()
            key = derive_legacy_master_key(passphrase=phrase, salt=salt, opslimit=opslimit, memlimit=memlimit)
            conn.execute(
                """
                INSERT INTO vault_meta (id, kdf_salt, opslimit, memlimit, created_at, wrapped_dek, unlock_provider)
                VALUES (1, ?, ?, ?, ?, NULL, NULL)
                """,
                (salt, opslimit, memlimit, created),
            )
            conn.commit()
            return key
        salt, opslimit, memlimit, wrapped_dek, _unlock_provider = row[0], int(row[1]), int(row[2]), row[3], row[4]
        if wrapped_dek is not None:
            raise BackendError(
                "This SQLite vault stores a keychain-wrapped DEK. Set SECKIT_SQLITE_UNLOCK=keychain "
                "(and ensure the KEK item is readable in the keychain)."
            )
        return derive_legacy_master_key(passphrase=phrase, salt=salt, opslimit=opslimit, memlimit=memlimit)


class KeychainUnlockProvider:
    """DEK wrapped with a KEK stored as a generic password in the macOS keychain (security CLI)."""

    def __init__(self, *, keychain_path: str | None = None) -> None:
        """Initialise a Keychain unlock provider bound to an optional custom keychain file."""
        self.keychain_path = os.path.expanduser(keychain_path) if keychain_path else None

    @property
    def provider_name(self) -> str:
        return UNLOCK_KEYCHAIN

    def materialize_master_key(self, conn: sqlite3.Connection, db_path: str) -> bytes:
        """Unwrap or create the DEK for a keychain-backed vault.

        Creates a new vault_meta row and KEK item when the vault is first opened.
        Raises ``BackendError`` on non-macOS or when the vault uses passphrase KDF.
        """
        if sys.platform != "darwin":
            raise BackendError("SQLite keychain unlock requires macOS")
        _migrate_vault_meta_columns(conn)
        row = conn.execute(
            """
            SELECT kdf_salt, opslimit, memlimit, created_at, wrapped_dek, unlock_provider
            FROM vault_meta WHERE id = 1
            """
        ).fetchone()
        if row is None:
            dek = os.urandom(nacl.secret.SecretBox.KEY_SIZE)
            kek = _get_or_create_kek_bytes(db_path=db_path, keychain_path=self.keychain_path)
            wrapped = _wrap_dek(dek=dek, kek=kek)
            salt = os.urandom(nacl.pwhash.argon2id.SALTBYTES)
            opslimit = nacl.pwhash.argon2id.OPSLIMIT_MODERATE
            memlimit = nacl.pwhash.argon2id.MEMLIMIT_MODERATE
            created = now_utc_iso()
            conn.execute(
                """
                INSERT INTO vault_meta (id, kdf_salt, opslimit, memlimit, created_at, wrapped_dek, unlock_provider)
                VALUES (1, ?, ?, ?, ?, ?, ?)
                """,
                (salt, opslimit, memlimit, created, wrapped, UNLOCK_KEYCHAIN),
            )
            conn.commit()
            return dek
        _salt, _ops, _mem, _created, wrapped_dek, _unlock_provider = (
            row[0],
            row[1],
            row[2],
            row[3],
            row[4],
            row[5],
        )
        if wrapped_dek is None:
            raise BackendError(
                "This SQLite vault uses passphrase KDF. Set SECKIT_SQLITE_UNLOCK=passphrase and SECKIT_SQLITE_PASSPHRASE."
            )
        kek = _read_kek_bytes_required(db_path=db_path, keychain_path=self.keychain_path)
        try:
            return _unwrap_dek(wrapped=wrapped_dek, kek=kek)
        except Exception as exc:  # noqa: BLE001
            if isinstance(exc, BackendError):
                raise
            raise BackendError("failed to unwrap SQLite DEK (wrong keychain or corrupt vault_meta)") from exc


def build_sqlite_unlock_provider(
    *,
    mode: str | None = None,
    kek_keychain_path: str | None = None,
) -> UnlockProvider:
    """Build provider from ``mode`` or :envvar:`SECKIT_SQLITE_UNLOCK`.

    * ``passphrase`` (default): Argon2id KDF from :envvar:`SECKIT_SQLITE_PASSPHRASE` (legacy layout).
    * ``keychain``: KEK in Keychain; requires macOS. Optional :envvar:`SECKIT_SQLITE_KEK_KEYCHAIN` or
      ``kek_keychain_path`` selects the keychain file (default: login keychain via ``security`` defaults).
    """
    raw = (mode or os.environ.get("SECKIT_SQLITE_UNLOCK", UNLOCK_PASSPHRASE)).strip().lower()
    kc_path = kek_keychain_path
    if not kc_path:
        env_kc = os.environ.get("SECKIT_SQLITE_KEK_KEYCHAIN", "").strip()
        if env_kc:
            kc_path = env_kc
    if raw in ("passphrase", "password", "pwd"):
        return PassphraseUnlockProvider()
    if raw in ("keychain", "kc"):
        return KeychainUnlockProvider(keychain_path=kc_path)
    raise BackendError(
        f"unsupported SECKIT_SQLITE_UNLOCK={raw!r} (use {UNLOCK_PASSPHRASE!r} or {UNLOCK_KEYCHAIN!r})"
    )
