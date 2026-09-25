"""
secrets_kit.crypto.storage.sqlite

Storage codec for SQLite backend payload columns.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import stat
from pathlib import Path
from typing import Any

from secrets_kit.crypto.codecs import decode_encrypted_blob, encode_b64url, encode_encrypted_blob
from secrets_kit.crypto.encryption import decrypt_aead, encrypt_aead
from secrets_kit.crypto.keys import generate_symmetric_key
from secrets_kit.models import now_utc_iso

SQLITE_STORAGE_KEY_ENV = "SECKIT_SQLITE_STORAGE_KEY_PATH"
SQLITE_PATH_ENV = "SECKIT_SQLITE_PATH"
SQLITE_STORAGE_KEY_VERSION = 1
SQLITE_STORAGE_KEY_ALGORITHM = "chacha20-poly1305"
SQLITE_STORAGE_KEY_BYTES = 32
SQLITE_STORAGE_CODEC_CONTEXT = "sqlite-storage"
SQLITE_STORAGE_MODE_ENCRYPTED = "encrypted"
SQLITE_STORAGE_MODE_PLAINTEXT = "plaintext"


def sqlite_storage_key_path(*, home: Path | None = None) -> Path:
    """
    Return the local SQLite storage key path.

    The default operator path is ``~/.config/seckit/sqlite-storage.key``. The
    environment override exists for isolated tests and scripted sandboxes.
    """
    configured = os.getenv(SQLITE_STORAGE_KEY_ENV)
    if configured:
        return Path(configured).expanduser()
    sqlite_path = os.getenv(SQLITE_PATH_ENV)
    if sqlite_path:
        return Path(sqlite_path).expanduser().parent / "sqlite-storage.key"
    operator_home = home or Path.home()
    return operator_home / ".config" / "seckit" / "sqlite-storage.key"


def ensure_sqlite_storage_key(*, home: Path | None = None) -> Path:
    """
    Ensure the local SQLite storage key exists and has expected permissions.

    Returns:
        Path to the local SQLite storage key file.

    Side Effects:
        Creates the local storage key and parent directory when absent.
        Existing objects are validated, not silently repaired.
    """
    path = sqlite_storage_key_path(home=home)
    _ = _load_or_create_storage_key_at(path=path)
    return path


def encrypt_payload(
    *, plaintext: bytes, field_name: str, storage_mode: str = SQLITE_STORAGE_MODE_ENCRYPTED
) -> bytes:
    """
    Encrypt plaintext for SQLite storage.

    The returned bytes are a versioned encoded encrypted blob suitable for
    storage in transaction payloads and projection BLOB columns.
    """
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")
    _validate_field_name(field_name=field_name)
    mode = _validate_storage_mode(storage_mode=storage_mode)
    if mode == SQLITE_STORAGE_MODE_PLAINTEXT:
        return plaintext
    blob = encrypt_aead(
        key=_load_or_create_storage_key(),
        plaintext=plaintext,
        aad=_aad(field_name=field_name),
        key_id="sqlite-storage.key",
        context=f"{SQLITE_STORAGE_CODEC_CONTEXT}:{field_name}",
    )
    return encode_encrypted_blob(blob)


def decrypt_payload(
    *, stored: bytes, field_name: str, storage_mode: str = SQLITE_STORAGE_MODE_ENCRYPTED
) -> bytes:
    """Decrypt bytes from SQLite storage."""
    if not isinstance(stored, bytes):
        raise TypeError("stored must be bytes")
    _validate_field_name(field_name=field_name)
    mode = _validate_storage_mode(storage_mode=storage_mode)
    if mode == SQLITE_STORAGE_MODE_PLAINTEXT:
        if _looks_like_encrypted_blob(stored=stored):
            raise ValueError("encrypted SQLite storage record found in plaintext datastore")
        return stored
    blob = decode_encrypted_blob(stored)
    return decrypt_aead(
        key=_load_or_create_storage_key(),
        blob=blob,
        aad=_aad(field_name=field_name),
    )


def _load_or_create_storage_key() -> bytes:
    path = sqlite_storage_key_path()
    return _load_or_create_storage_key_at(path=path)


def _load_or_create_storage_key_at(*, path: Path) -> bytes:
    if path.is_symlink():
        raise ValueError(f"SQLite storage key must not be a symbolic link: {path}")
    if path.exists():
        _validate_storage_key_path(path=path)
        key = _load_storage_key(path=path)
        return key
    return _create_storage_key(path=path)


def _load_storage_key(*, path: Path) -> bytes:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid SQLite storage key: {path}") from exc
    if not isinstance(payload, dict):
        raise ValueError("SQLite storage key must be a JSON object")
    _validate_key_metadata(payload=payload)
    key = _decode_key(value=str(payload["key_b64"]))
    if len(key) != SQLITE_STORAGE_KEY_BYTES:
        raise ValueError("SQLite storage key must decode to 32 bytes")
    return key


def _create_storage_key(*, path: Path) -> bytes:
    key = generate_symmetric_key()
    _ensure_new_parent_directory(path=path)
    payload = {
        "algorithm": SQLITE_STORAGE_KEY_ALGORITHM,
        "created_at": now_utc_iso(),
        "key_b64": encode_b64url(key),
        "version": SQLITE_STORAGE_KEY_VERSION,
    }
    encoded = json.dumps(
        payload,
        sort_keys=True,
        indent=2,
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    tmp_path = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(tmp_path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
            handle.write(b"\n")
        os.replace(tmp_path, path)
        os.chmod(path, 0o600)
    except BaseException:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass
        raise
    return key


def _ensure_new_parent_directory(*, path: Path) -> None:
    parent = path.parent
    if parent.exists():
        metadata = parent.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError(f"SQLite storage key directory must not be a symbolic link: {parent}")
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError(f"SQLite storage key parent is not a directory: {parent}")
        return
    parent.mkdir(parents=True, mode=0o700, exist_ok=False)
    os.chmod(parent, 0o700)


def _validate_storage_key_path(*, path: Path) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise ValueError(f"SQLite storage key is missing: {path}") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise ValueError(f"SQLite storage key must not be a symbolic link: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"SQLite storage key is not a regular file: {path}")
    mode = stat.S_IMODE(metadata.st_mode)
    if metadata.st_uid != os.getuid():
        raise ValueError(
            "SQLite storage key owner validation failed: "
            f"path={path}; expected_owner_uid={os.getuid()}; actual_owner_uid={metadata.st_uid}"
        )
    if mode != 0o600:
        raise ValueError(
            "SQLite storage key permission validation failed: "
            f"path={path}; expected=0600; actual=0{mode:o}"
        )


def _validate_key_metadata(*, payload: dict[str, Any]) -> None:
    if payload.get("version") != SQLITE_STORAGE_KEY_VERSION:
        raise ValueError("unsupported SQLite storage key version")
    if payload.get("algorithm") != SQLITE_STORAGE_KEY_ALGORITHM:
        raise ValueError("unsupported SQLite storage key algorithm")
    if not isinstance(payload.get("created_at"), str) or not payload["created_at"]:
        raise ValueError("SQLite storage key created_at is required")
    if not isinstance(payload.get("key_b64"), str) or not payload["key_b64"]:
        raise ValueError("SQLite storage key key_b64 is required")


def _decode_key(*, value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode((value + padding).encode("ascii"))
    except (binascii.Error, UnicodeEncodeError):
        try:
            return base64.b64decode(value.encode("ascii"), validate=True)
        except (binascii.Error, UnicodeEncodeError) as exc:
            raise ValueError("SQLite storage key key_b64 is invalid") from exc


def _validate_field_name(*, field_name: str) -> None:
    if field_name not in {"encrypted_name", "encrypted_payload"}:
        raise ValueError("unsupported SQLite storage field")


def _validate_storage_mode(*, storage_mode: str) -> str:
    if storage_mode not in {SQLITE_STORAGE_MODE_ENCRYPTED, SQLITE_STORAGE_MODE_PLAINTEXT}:
        raise ValueError("unsupported SQLite storage mode")
    return storage_mode


def _looks_like_encrypted_blob(*, stored: bytes) -> bool:
    try:
        payload = json.loads(stored.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    return (
        isinstance(payload, dict)
        and isinstance(payload.get("header"), dict)
        and "ciphertext" in payload
        and "nonce" in payload
    )


def _aad(*, field_name: str) -> bytes:
    return f"secrets-kit.sqlite-storage.v1:{field_name}".encode("utf-8")


__all__ = [
    "SQLITE_STORAGE_KEY_ENV",
    "decrypt_payload",
    "ensure_sqlite_storage_key",
    "encrypt_payload",
    "sqlite_storage_key_path",
]
