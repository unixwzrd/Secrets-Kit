"""Read-only legacy Keychain inventory and explicit SQLite migration helpers."""

from __future__ import annotations

import ctypes
import json
import os
import selectors
import subprocess
import sys
import time
from dataclasses import dataclass
from dataclasses import fields as dataclass_fields
from pathlib import Path

from secrets_kit.backends.keychain.comment_codec import parse_keychain_comment
from secrets_kit.backends.keychain.security_cli import backend_service_name, keychain_path
from secrets_kit.backends.keychain.security_run import parse_dump_keychain_output
from secrets_kit.backends.sqlite.gate import open_sqlite_backend
from secrets_kit.backends.sqlite.storage_mode import (
    SQLITE_STORAGE_MODE_ENCRYPTED,
    read_sqlite_storage_mode,
)
from secrets_kit.models import EntryMetadata, ValidationError, validate_key_name

MAX_INVENTORY_BYTES = 8 * 1024 * 1024
MAX_INVENTORY_ITEMS = 10_000
MAX_SECRET_BYTES = 1024 * 1024
_METADATA_FIELDS = frozenset(field.name for field in dataclass_fields(EntryMetadata)) | {
    "type",
    "kind",
}


class MigrationError(ValueError):
    """Value-free error for a failed legacy migration preflight or read."""


@dataclass(frozen=True)
class LegacyItem:
    """One selected Keychain item identified only by non-secret metadata."""

    metadata: EntryMetadata
    structured_comment: bool = False


@dataclass(frozen=True)
class LegacyInventory:
    """Selected items and redacted reasons for unsupported source records."""

    path: Path
    items: tuple[LegacyItem, ...]
    unsupported: tuple[str, ...]


def inventory_keychain(*, path: str | None, service: str, account: str) -> LegacyInventory:
    """Inventory one explicit scope without requesting Keychain password values."""
    if sys.platform != "darwin":
        raise MigrationError("Keychain migration requires macOS")
    if not service or not account:
        raise MigrationError("migration requires a service and account scope")
    target = Path(keychain_path(path=path)).expanduser()
    if not target.is_file() or target.is_symlink():
        raise MigrationError("source Keychain must be an existing regular file")
    stdout, stderr = _bounded_inventory_output(target=target)
    try:
        raw = (stdout + b"\n" + stderr).decode("utf-8")
    except UnicodeDecodeError:
        raise MigrationError("Keychain inventory encoding is unsupported") from None
    parsed = parse_dump_keychain_output(raw=raw)
    if len(parsed) > MAX_INVENTORY_ITEMS:
        raise MigrationError("Keychain inventory exceeds maximum item count")

    prefix = f"{service}:"
    items: list[LegacyItem] = []
    unsupported: list[str] = []
    seen: set[str] = set()
    for ordinal, fields in enumerate(parsed, start=1):
        raw_service = str(fields.get("service_name", ""))
        raw_account = str(fields.get("account", ""))
        raw_comment = str(fields.get("comment", ""))
        comment = "" if raw_comment == "<NULL>" else raw_comment
        selected = raw_account == account and raw_service.startswith(prefix)
        if not selected:
            continue
        name = raw_service[len(prefix) :]
        try:
            if validate_key_name(name=name) != name:
                raise ValidationError("noncanonical name")
        except ValidationError:
            unsupported.append(f"item {ordinal}: invalid name")
            continue
        if name in seen:
            unsupported.append(f"item {ordinal}: duplicate identity")
            continue
        seen.add(name)
        if comment:
            try:
                payload = json.loads(comment)
                if not isinstance(payload, dict) or not set(payload) <= _METADATA_FIELDS:
                    raise ValueError("unsupported fields")
                if not all(
                    isinstance(payload.get(key), str) for key in ("name", "service", "account")
                ):
                    raise ValueError("invalid identity")
                for key in ("tags", "domains"):
                    if key in payload and (
                        not isinstance(payload[key], list)
                        or not all(isinstance(value, str) for value in payload[key])
                    ):
                        raise ValueError("invalid metadata list")
                if "custom" in payload and not isinstance(payload["custom"], dict):
                    raise ValueError("invalid custom metadata")
                for key in ("schema_version", "rotation_days", "rotation_warn_days"):
                    if (
                        key in payload
                        and payload[key] is not None
                        and type(payload[key]) is not int
                    ):
                        raise ValueError("invalid numeric metadata")
                metadata = parse_keychain_comment(comment=comment)
            except (KeyError, TypeError, ValueError, OverflowError):
                metadata = None
            if metadata is None:
                unsupported.append(f"item {ordinal}: unsupported comment metadata")
                continue
            if (metadata.service, metadata.account, metadata.name) != (service, account, name):
                unsupported.append(f"item {ordinal}: comment identity mismatch")
                continue
        else:
            metadata = EntryMetadata(
                name=name, service=service, account=account, source="keychain-migration"
            )
        items.append(LegacyItem(metadata=metadata, structured_comment=bool(comment)))
    return LegacyInventory(path=target, items=tuple(items), unsupported=tuple(unsupported))


def read_legacy_value(*, inventory: LegacyInventory, item: LegacyItem) -> str:
    """Read exact UTF-8 password bytes through macOS Security.framework."""
    metadata = item.metadata
    if sys.platform != "darwin":
        raise MigrationError("Keychain value read requires macOS")
    service = backend_service_name(service=metadata.service, name=metadata.name).encode("utf-8")
    account = metadata.account.encode("utf-8")
    security = ctypes.CDLL("/System/Library/Frameworks/Security.framework/Security")
    core_foundation = ctypes.CDLL(
        "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
    )
    security.SecKeychainOpen.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)]
    security.SecKeychainOpen.restype = ctypes.c_int32
    security.SecKeychainFindGenericPassword.argtypes = [
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_char_p, ctypes.c_uint32,
        ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
    ]
    security.SecKeychainFindGenericPassword.restype = ctypes.c_int32
    security.SecKeychainItemFreeContent.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    security.SecKeychainItemFreeContent.restype = ctypes.c_int32
    core_foundation.CFRelease.argtypes = [ctypes.c_void_p]
    keychain = ctypes.c_void_p()
    password = ctypes.c_void_p()
    length = ctypes.c_uint32()
    try:
        if security.SecKeychainOpen(os.fsencode(inventory.path), ctypes.byref(keychain)) != 0:
            raise MigrationError("Keychain value read failed")
        if security.SecKeychainFindGenericPassword(
            keychain, len(service), service, len(account), account,
            ctypes.byref(length), ctypes.byref(password), None,
        ) != 0:
            raise MigrationError("Keychain value read failed")
        if length.value > MAX_SECRET_BYTES:
            raise MigrationError("Keychain value exceeds maximum size")
        try:
            return ctypes.string_at(password, length.value).decode("utf-8")
        except UnicodeDecodeError:
            raise MigrationError("Keychain value encoding is unsupported") from None
    finally:
        if password.value:
            security.SecKeychainItemFreeContent(None, password)
        if keychain.value:
            core_foundation.CFRelease(keychain)


def _bounded_inventory_output(*, target: Path) -> tuple[bytes, bytes]:
    """Capture metadata-only dump output with a hard in-memory byte ceiling."""
    try:
        process = subprocess.Popen(
            ["security", "dump-keychain", str(target)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        stdout = bytearray()
        stderr = bytearray()
        deadline = time.monotonic() + 30
        with selectors.DefaultSelector() as selector:
            assert process.stdout is not None and process.stderr is not None
            selector.register(process.stdout, selectors.EVENT_READ, stdout)
            selector.register(process.stderr, selectors.EVENT_READ, stderr)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise MigrationError("Keychain inventory timed out")
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fd, min(65536, MAX_INVENTORY_BYTES + 1 - len(stdout) - len(stderr)))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    key.data.extend(chunk)
                    if len(stdout) + len(stderr) > MAX_INVENTORY_BYTES:
                        raise MigrationError("Keychain inventory exceeds maximum size")
        if process.wait(timeout=max(0, deadline - time.monotonic())) != 0:
            raise MigrationError("Keychain inventory failed")
        return bytes(stdout), bytes(stderr)
    except (OSError, subprocess.TimeoutExpired):
        raise MigrationError("Keychain inventory failed") from None
    finally:
        if "process" in locals() and process.poll() is None:
            process.kill()
            process.wait()
        if "process" in locals():
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()


def require_encrypted_sqlite_target() -> None:
    """Require an already initialized, valid encrypted SQLite operator store."""
    try:
        conn = open_sqlite_backend()
        try:
            if read_sqlite_storage_mode(conn=conn) != SQLITE_STORAGE_MODE_ENCRYPTED:
                raise MigrationError("migration requires encrypted SQLite storage")
        finally:
            conn.close()
    except MigrationError:
        raise
    except Exception:
        raise MigrationError(
            "SQLite target is unavailable or invalid; initialize a fresh encrypted target without replacing an existing database"
        ) from None


def target_state(*, item: LegacyItem) -> str:
    """Return absent, active, or deleted for a matching SQLite identity."""
    metadata = item.metadata
    conn = open_sqlite_backend()
    try:
        row = conn.execute(
            "SELECT state FROM secrets WHERE service = ? AND account = ? AND name = ?",
            (metadata.service, metadata.account, metadata.name),
        ).fetchone()
    finally:
        conn.close()
    return "absent" if row is None else str(row["state"])


def metadata_matches(
    *, source: EntryMetadata, target: EntryMetadata, structured_comment: bool
) -> bool:
    """Compare preserved structured metadata, excluding generated minimal timestamps."""
    ignored = set() if structured_comment else {"created_at", "updated_at"}
    left = {key: value for key, value in source.to_dict().items() if key not in ignored}
    right = {key: value for key, value in target.to_dict().items() if key not in ignored}
    for key in ("tags", "domains"):
        left[key] = sorted(left[key])
        right[key] = sorted(right[key])
    return left == right


__all__ = [
    "LegacyInventory",
    "LegacyItem",
    "MigrationError",
    "inventory_keychain",
    "metadata_matches",
    "read_legacy_value",
    "require_encrypted_sqlite_target",
    "target_state",
]
