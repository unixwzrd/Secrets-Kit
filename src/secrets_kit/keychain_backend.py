"""Keychain and secret-store backends for seckit.

``resolve_secret_store`` returns either :class:`SecurityCliStore` (macOS ``security`` CLI against
the login keychain or ``--keychain`` path) or :class:`SqliteSecretStore` (encrypted SQLite via
PyNaCl). Canonical backend ids: ``secure`` (alias: ``local``) and ``sqlite``.

The former synchronizable / iCloud Keychain helper (``icloud``, ``icloud-helper``) was **removed** —
macOS kills that helper at launch in typical configurations. Use **export/import** for cross-host transfer.

Additional backends (PGP, vault, broker) should implement :class:`SecretStore`,
extend :func:`normalize_backend` / validation, and register in :func:`resolve_secret_store`
and ``secrets_kit.cli``.
"""

from __future__ import annotations

import ast
import os
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Any, Dict, FrozenSet, Optional, Protocol


class BackendError(RuntimeError):
    """Keychain backend error."""


BACKEND_SECURE = "secure"
"""Local Keychain only: ``security`` CLI (alias: ``local``)."""

BACKEND_SQLITE = "sqlite"
"""Portable encrypted SQLite store (PyNaCl)."""

ICLOUD_BACKEND_REMOVED_MESSAGE = (
    "The icloud / icloud-helper backend was removed: the synchronizable Keychain helper is killed by "
    "macOS (SIGKILL / entitlements) and is not usable. Use --backend secure (or local) and "
    "seckit export / import for cross-host transfer. See docs/ICLOUD_SYNC_VALIDATION.md."
)

_BACKEND_ALIASES: Dict[str, str] = {
    "local": BACKEND_SECURE,
}

# Accepted on CLI / env / defaults.json (``local`` is an alias for ``secure``).
BACKEND_CHOICES: tuple[str, ...] = (
    BACKEND_SECURE,
    BACKEND_SQLITE,
    "local",
)

_KNOWN_NORMALIZED: FrozenSet[str] = frozenset({BACKEND_SECURE, BACKEND_SQLITE})


def normalize_backend(backend: str) -> str:
    """Return canonical backend id (``secure``, ``sqlite``; ``local`` aliases ``secure``)."""
    raw = backend.strip().lower()
    if raw in {"icloud", "icloud-helper"}:
        raise BackendError(ICLOUD_BACKEND_REMOVED_MESSAGE)
    normalized = _BACKEND_ALIASES.get(raw, raw)
    if normalized not in _KNOWN_NORMALIZED:
        raise BackendError(
            f"unsupported backend: {backend!r} (expected {BACKEND_SECURE}, {BACKEND_SQLITE}, or alias local)"
        )
    return normalized


def is_secure_backend(backend: str) -> bool:
    return normalize_backend(backend) == BACKEND_SECURE


def is_sqlite_backend(backend: str) -> bool:
    return normalize_backend(backend) == BACKEND_SQLITE


DEFAULT_KEYCHAIN_PATH = os.path.expanduser("~/Library/Keychains/login.keychain-db")
ATTRIBUTE_PATTERN = re.compile(r'^\s+(?:"(?P<qkey>[^"]+)"|(?P<hkey>0x[0-9A-Fa-f]+))\s*<[^>]+>=(?P<value>.*)$')


def backend_service_name(*, service: str, name: str) -> str:
    """Compose keychain service name including logical secret key."""
    return f"{service}:{name}"


def _validate_backend(*, backend: str, path: Optional[str]) -> str:
    normalized = normalize_backend(backend)
    if path is not None:
        # Custom keychain files are only used with the security CLI (secure backend).
        pass
    return normalized


class SecretStore(Protocol):
    """Contract for any secret backend (Keychain, vault, PGP, etc.) used by the CLI."""

    def set(self, *, service: str, account: str, name: str, value: str, comment: str = "", label: Optional[str] = None) -> None:
        ...

    def get(self, *, service: str, account: str, name: str) -> str:
        ...

    def metadata(self, *, service: str, account: str, name: str) -> Dict[str, Any]:
        ...

    def exists(self, *, service: str, account: str, name: str) -> bool:
        ...

    def delete(self, *, service: str, account: str, name: str) -> None:
        ...


class SecurityCliStore:
    """Local macOS Keychain backend implemented through the `security` CLI."""

    def __init__(self, *, path: Optional[str] = None) -> None:
        self.path = path

    def _target(self) -> Optional[str]:
        return keychain_path(path=self.path) if self.path else None

    def _append_target(self, args: list[str]) -> list[str]:
        target = self._target()
        if target:
            args.append(target)
        return args

    def set(self, *, service: str, account: str, name: str, value: str, comment: str = "", label: Optional[str] = None) -> None:
        svc = backend_service_name(service=service, name=name)
        args = ["add-generic-password", "-a", account, "-s", svc, "-l", label or name, "-j", comment, "-U", "-w", value]
        if self.path:
            args.extend(["-T", "/usr/bin/security"])
        _run_security(args=self._append_target(args))

    def get(self, *, service: str, account: str, name: str) -> str:
        svc = backend_service_name(service=service, name=name)
        args = ["find-generic-password", "-a", account, "-s", svc, "-w"]
        return _run_security(args=self._append_target(args))

    def metadata(self, *, service: str, account: str, name: str) -> Dict[str, Any]:
        svc = backend_service_name(service=service, name=name)
        args = ["find-generic-password", "-a", account, "-s", svc, "-g"]
        proc = _run_security_capture(args=self._append_target(args))
        merged = "\n".join(part for part in ((proc.stdout or "").strip(), (proc.stderr or "").strip()) if part)
        return _parse_find_generic_password_output(raw=merged)

    def exists(self, *, service: str, account: str, name: str) -> bool:
        svc = backend_service_name(service=service, name=name)
        args = ["find-generic-password", "-a", account, "-s", svc]
        return _security_exists(args=self._append_target(args))

    def delete(self, *, service: str, account: str, name: str) -> None:
        svc = backend_service_name(service=service, name=name)
        args = ["delete-generic-password", "-a", account, "-s", svc]
        _run_security(args=self._append_target(args))


def resolve_secret_store(
    *,
    backend: str = "secure",
    path: Optional[str] = None,
    kek_keychain_path: Optional[str] = None,
) -> SecretStore:
    """Resolve the concrete :class:`SecretStore` for ``backend``.

    * ``secure``: macOS ``security`` CLI; ``path`` is an optional keychain file.
    * ``sqlite``: encrypted SQLite file; ``path`` is the database path (default ``~/.config/seckit/secrets.db``).
      When :envvar:`SECKIT_SQLITE_UNLOCK` is ``keychain``, ``kek_keychain_path`` (or
      :envvar:`SECKIT_SQLITE_KEK_KEYCHAIN`) selects the keychain file that holds the KEK.
    """
    normalized = _validate_backend(backend=backend, path=path)
    if normalized == BACKEND_SQLITE:
        from secrets_kit.sqlite_backend import SqliteSecretStore, default_sqlite_db_path

        db_path = path or default_sqlite_db_path()
        kc = kek_keychain_path
        if not kc:
            env_kc = os.environ.get("SECKIT_SQLITE_KEK_KEYCHAIN", "").strip()
            kc = os.path.expanduser(env_kc) if env_kc else None
        else:
            kc = os.path.expanduser(kc)
        return SqliteSecretStore(db_path=os.path.expanduser(db_path), kek_keychain_path=kc)
    return SecurityCliStore(path=path)


def _run_security(*, args: list[str], stdin: Optional[str] = None) -> str:
    cmd = ["security", *args]
    proc = subprocess.run(
        cmd,
        input=stdin,
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        raise BackendError(stderr or f"security command failed: {' '.join(cmd)}")
    return (proc.stdout or "").strip()


def _run_security_capture(*, args: list[str], stdin: Optional[str] = None) -> subprocess.CompletedProcess[str]:
    cmd = ["security", *args]
    proc = subprocess.run(
        cmd,
        input=stdin,
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        raise BackendError(stderr or f"security command failed: {' '.join(cmd)}")
    return proc


def _security_exists(*, args: list[str]) -> bool:
    cmd = ["security", *args]
    proc = subprocess.run(
        cmd,
        text=True,
        capture_output=True,
        check=False,
    )
    return proc.returncode == 0


def keychain_path(*, path: Optional[str] = None) -> str:
    return os.path.expanduser(path or DEFAULT_KEYCHAIN_PATH)


def keychain_accessible(*, path: Optional[str] = None) -> bool:
    target = keychain_path(path=path)
    return _security_exists(args=["show-keychain-info", target])


def keychain_info(*, path: Optional[str] = None) -> str:
    target = keychain_path(path=path)
    return _run_security(args=["show-keychain-info", target])


def keychain_policy(*, path: Optional[str] = None) -> dict[str, Any]:
    target = keychain_path(path=path)
    info = keychain_info(path=target)
    normalized = info.lower()
    timeout_seconds: Optional[int] = None
    if "timeout=" in normalized:
        try:
            timeout_seconds = int(normalized.split("timeout=", 1)[1].split()[0].rstrip("s"))
        except Exception:  # noqa: BLE001
            timeout_seconds = None
    return {
        "path": target,
        "raw": info,
        "no_timeout": "no-timeout" in normalized,
        "lock_on_sleep": "lock-on-sleep" in normalized,
        "timeout_seconds": timeout_seconds,
    }


def unlock_keychain(*, path: Optional[str] = None) -> str:
    target = keychain_path(path=path)
    cmd = ["security", "unlock-keychain", target]
    proc = subprocess.run(cmd, check=False)
    if proc.returncode != 0:
        raise BackendError(f"failed to unlock keychain: {target}")
    return target


def lock_keychain(*, path: Optional[str] = None) -> str:
    target = keychain_path(path=path)
    cmd = ["security", "lock-keychain", target]
    proc = subprocess.run(cmd, check=False)
    if proc.returncode != 0:
        raise BackendError(f"failed to lock keychain: {target}")
    return target


def harden_keychain(*, path: Optional[str] = None, timeout_seconds: int = 3600) -> str:
    target = keychain_path(path=path)
    _run_security(args=["set-keychain-settings", "-l", "-u", "-t", str(timeout_seconds), target])
    return target


def set_secret(
    *,
    service: str,
    account: str,
    name: str,
    value: str,
    comment: str = "",
    label: Optional[str] = None,
    path: Optional[str] = None,
    backend: str = "secure",
    kek_keychain_path: Optional[str] = None,
) -> None:
    """Create or update a keychain secret entry."""
    store = resolve_secret_store(backend=backend, path=path, kek_keychain_path=kek_keychain_path)
    store.set(service=service, account=account, name=name, value=value, comment=comment, label=label)


def get_secret(
    *,
    service: str,
    account: str,
    name: str,
    path: Optional[str] = None,
    backend: str = "secure",
    kek_keychain_path: Optional[str] = None,
) -> str:
    """Read secret value from keychain."""
    store = resolve_secret_store(backend=backend, path=path, kek_keychain_path=kek_keychain_path)
    return store.get(service=service, account=account, name=name)


def get_secret_metadata(
    *,
    service: str,
    account: str,
    name: str,
    path: Optional[str] = None,
    backend: str = "secure",
    kek_keychain_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Read keychain metadata attributes for one secret."""
    store = resolve_secret_store(backend=backend, path=path, kek_keychain_path=kek_keychain_path)
    return store.metadata(service=service, account=account, name=name)


def secret_exists(
    *,
    service: str,
    account: str,
    name: str,
    path: Optional[str] = None,
    backend: str = "secure",
    kek_keychain_path: Optional[str] = None,
) -> bool:
    """Return whether a keychain item exists for one logical secret."""
    store = resolve_secret_store(backend=backend, path=path, kek_keychain_path=kek_keychain_path)
    return store.exists(service=service, account=account, name=name)


def delete_secret(
    *,
    service: str,
    account: str,
    name: str,
    path: Optional[str] = None,
    backend: str = "secure",
    kek_keychain_path: Optional[str] = None,
) -> None:
    """Delete secret from keychain."""
    store = resolve_secret_store(backend=backend, path=path, kek_keychain_path=kek_keychain_path)
    store.delete(service=service, account=account, name=name)


def check_security_cli() -> bool:
    """Return whether macOS security tool is available."""
    proc = subprocess.run(["which", "security"], capture_output=True, text=True, check=False)
    return proc.returncode == 0


def doctor_roundtrip(
    *,
    service: str = "seckit-doctor",
    account: str = "doctor",
    path: Optional[str] = None,
    backend: str = "secure",
    kek_keychain_path: Optional[str] = None,
) -> None:
    """Run a backend write/read/delete smoke test."""
    test_name = "DOCTOR_TEST_KEY"
    value = "doctor_ok"
    set_secret(
        service=service,
        account=account,
        name=test_name,
        value=value,
        path=path,
        backend=backend,
        kek_keychain_path=kek_keychain_path,
    )
    fetched = get_secret(
        service=service, account=account, name=test_name, path=path, backend=backend, kek_keychain_path=kek_keychain_path
    )
    if fetched != value:
        raise BackendError("doctor roundtrip mismatch")
    delete_secret(
        service=service,
        account=account,
        name=test_name,
        path=path,
        backend=backend,
        kek_keychain_path=kek_keychain_path,
    )


def create_keychain(*, path: str, password: str) -> str:
    """Create a dedicated test keychain file."""
    target = keychain_path(path=path)
    Path(target).parent.mkdir(parents=True, exist_ok=True)
    _run_security(args=["create-keychain", "-p", password, target])
    return target


def delete_keychain(*, path: str) -> None:
    """Delete a dedicated keychain file."""
    target = keychain_path(path=path)
    _run_security(args=["delete-keychain", target])


def unlock_keychain_with_password(*, path: str, password: str) -> str:
    """Unlock a keychain using a supplied password, intended for isolated tests."""
    target = keychain_path(path=path)
    _run_security(args=["unlock-keychain", "-p", password, target])
    return target


def make_temp_keychain(*, password: str = "seckit-test-password") -> Dict[str, str]:
    """Create and unlock a temporary keychain for regression tests."""
    temp_dir = tempfile.mkdtemp(prefix="seckit-keychain-")
    path = os.path.join(temp_dir, "test.keychain-db")
    create_keychain(path=path, password=password)
    unlock_keychain_with_password(path=path, password=password)
    return {"directory": temp_dir, "path": path, "password": password}


def _parse_find_generic_password_output(*, raw: str) -> Dict[str, Any]:
    metadata: Dict[str, Any] = {
        "account": "",
        "service_name": "",
        "label": "",
        "comment": "",
        "created_at_raw": "",
        "modified_at_raw": "",
        "raw": raw,
    }
    for line in raw.splitlines():
        match = ATTRIBUTE_PATTERN.match(line)
        if not match:
            continue
        key = match.group("qkey") or match.group("hkey") or ""
        value = _decode_attribute_value(match.group("value").strip())
        if key == "acct":
            metadata["account"] = value
        elif key == "svce":
            metadata["service_name"] = value
        elif key in {"labl", "0x00000007"}:
            metadata["label"] = value
        elif key == "icmt":
            metadata["comment"] = value
        elif key == "cdat":
            metadata["created_at_raw"] = value
        elif key == "mdat":
            metadata["modified_at_raw"] = value
    return metadata


def _decode_attribute_value(raw: str) -> str:
    if raw.startswith('"') and raw.endswith('"'):
        try:
            return str(ast.literal_eval(raw))
        except (SyntaxError, ValueError):
            return raw.strip('"')
    return raw
