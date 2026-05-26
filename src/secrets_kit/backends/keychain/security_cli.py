"""
secrets_kit.backends.keychain.security_cli

Keychain backend implemented with the macOS security command.

``resolve_secret_store`` returns :class:`SecurityCliStore`: the macOS ``security`` CLI
against the login keychain (or ``--keychain`` path). Canonical backend id is
``keychain``.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

from secrets_kit.backends.base import SecretStore
from secrets_kit.backends.common import (
    BACKEND_KEYCHAIN,
    BackendError,
    is_keychain_backend,
    normalize_backend,
)
from secrets_kit.backends.keychain.comment_codec import (
    format_keychain_comment,
    parse_keychain_comment,
)
from secrets_kit.backends.keychain.security_run import (
    parse_find_generic_password_output,
    run_security,
    run_security_capture,
    security_exists,
)
from secrets_kit.models import EntryMetadata

__all__ = [
    "DEFAULT_KEYCHAIN_PATH",
    "SecretStore",
    "SecurityCliStore",
    "backend_service_name",
    "check_security_cli",
    "create_keychain",
    "delete_keychain",
    "delete_secret",
    "doctor_roundtrip",
    "get_secret",
    "get_secret_metadata",
    "harden_keychain",
    "keychain_accessible",
    "keychain_info",
    "keychain_path",
    "keychain_policy",
    "lock_keychain",
    "make_temp_keychain",
    "resolve_secret_store",
    "secret_exists",
    "set_secret",
    "unlock_keychain",
    "unlock_keychain_with_password",
]

DEFAULT_KEYCHAIN_PATH = os.path.expanduser("~/Library/Keychains/login.keychain-db")


def backend_service_name(*, service: str, name: str) -> str:
    """Compose keychain service name including logical secret key."""
    return f"{service}:{name}"


def _validate_backend(*, backend: str, path: Optional[str]) -> str:
    normalized = normalize_backend(backend)
    if not is_keychain_backend(normalized):
        raise BackendError(f"backend {backend!r} is not the {BACKEND_KEYCHAIN} backend")
    if path is not None:
        # Custom keychain files are only used with the Keychain backend.
        pass
    return normalized


class SecurityCliStore(SecretStore):
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

    def set(
        self,
        *,
        service: str,
        account: str,
        name: str,
        value: str,
        metadata: Optional[EntryMetadata] = None,
        comment: str = "",
        label: Optional[str] = None,
    ) -> None:
        if metadata is not None and not comment:
            comment = format_keychain_comment(metadata=metadata)
        if self.exists(service=service, account=account, name=name):
            self.delete(service=service, account=account, name=name)
        svc = backend_service_name(service=service, name=name)
        args = [
            "add-generic-password",
            "-a",
            account,
            "-s",
            svc,
            "-l",
            label or name,
            "-j",
            comment,
            "-w",
            value,
        ]
        if self.path:
            args.extend(["-T", "/usr/bin/security"])
        run_security(args=self._append_target(args))

    def get(self, *, service: str, account: str, name: str) -> str:
        svc = backend_service_name(service=service, name=name)
        args = ["find-generic-password", "-a", account, "-s", svc, "-w"]
        return run_security(args=self._append_target(args))

    def raw_metadata(self, *, service: str, account: str, name: str) -> Dict[str, Any]:
        """Read raw fields from the macOS security command."""
        svc = backend_service_name(service=service, name=name)
        args = ["find-generic-password", "-a", account, "-s", svc, "-g"]
        proc = run_security_capture(args=self._append_target(args))
        merged = "\n".join(
            part for part in ((proc.stdout or "").strip(), (proc.stderr or "").strip()) if part
        )
        return parse_find_generic_password_output(raw=merged)

    def metadata(self, *, service: str, account: str, name: str) -> EntryMetadata:
        raw = self.raw_metadata(service=service, account=account, name=name)
        parsed = parse_keychain_comment(comment=str(raw.get("comment", "")))
        if parsed is not None:
            return parsed
        return EntryMetadata(name=name, service=service, account=account, source="keychain-minimal")

    def exists(self, *, service: str, account: str, name: str) -> bool:
        svc = backend_service_name(service=service, name=name)
        args = ["find-generic-password", "-a", account, "-s", svc]
        return security_exists(args=self._append_target(args))

    def delete(self, *, service: str, account: str, name: str) -> None:
        svc = backend_service_name(service=service, name=name)
        args = ["delete-generic-password", "-a", account, "-s", svc]
        run_security(args=self._append_target(args))

    def list(
        self, *, service: str | None = None, account: str | None = None
    ) -> list[EntryMetadata]:
        _ = service, account
        raise BackendError(
            "Keychain listing is provided by registry/index helpers, not raw security scans"
        )

    def doctor_roundtrip(self, *, service: str = "seckit-doctor", account: str = "doctor") -> None:
        test_name = "DOCTOR_TEST_KEY"
        value = "doctor_ok"
        self.set(service=service, account=account, name=test_name, value=value)
        fetched = self.get(service=service, account=account, name=test_name)
        if fetched != value:
            raise BackendError("doctor roundtrip mismatch")
        self.delete(service=service, account=account, name=test_name)


def resolve_secret_store(
    *, backend: str = BACKEND_KEYCHAIN, path: Optional[str] = None
) -> SecretStore:
    """Resolve the concrete :class:`SecretStore` for ``backend`` (and optional keychain ``path``).

    Only the Keychain backend (``keychain``) is supported by this module.
    """
    _validate_backend(backend=backend, path=path)
    return SecurityCliStore(path=path)


def keychain_path(*, path: Optional[str] = None) -> str:
    return os.path.expanduser(path or DEFAULT_KEYCHAIN_PATH)


def keychain_accessible(*, path: Optional[str] = None) -> bool:
    target = keychain_path(path=path)
    return security_exists(args=["show-keychain-info", target])


def keychain_info(*, path: Optional[str] = None) -> str:
    target = keychain_path(path=path)
    return run_security(args=["show-keychain-info", target])


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
    run_security(args=["set-keychain-settings", "-l", "-u", "-t", str(timeout_seconds), target])
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
    backend: str = BACKEND_KEYCHAIN,
) -> None:
    """Create or update a keychain secret entry."""
    store = resolve_secret_store(backend=backend, path=path)
    store.set(
        service=service, account=account, name=name, value=value, comment=comment, label=label
    )


def get_secret(
    *,
    service: str,
    account: str,
    name: str,
    path: Optional[str] = None,
    backend: str = BACKEND_KEYCHAIN,
) -> str:
    """Read secret value from keychain."""
    store = resolve_secret_store(backend=backend, path=path)
    return store.get(service=service, account=account, name=name)


def get_secret_metadata(
    *,
    service: str,
    account: str,
    name: str,
    path: Optional[str] = None,
    backend: str = BACKEND_KEYCHAIN,
) -> Dict[str, Any]:
    """Read keychain metadata attributes for one secret."""
    store = resolve_secret_store(backend=backend, path=path)
    if not isinstance(store, SecurityCliStore):
        raise BackendError("raw Keychain metadata is available only from SecurityCliStore")
    return store.raw_metadata(service=service, account=account, name=name)


def secret_exists(
    *,
    service: str,
    account: str,
    name: str,
    path: Optional[str] = None,
    backend: str = BACKEND_KEYCHAIN,
) -> bool:
    """Return whether a keychain item exists for one logical secret."""
    store = resolve_secret_store(backend=backend, path=path)
    return store.exists(service=service, account=account, name=name)


def delete_secret(
    *,
    service: str,
    account: str,
    name: str,
    path: Optional[str] = None,
    backend: str = BACKEND_KEYCHAIN,
) -> None:
    """Delete secret from keychain."""
    store = resolve_secret_store(backend=backend, path=path)
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
    backend: str = BACKEND_KEYCHAIN,
) -> None:
    """Run a backend write/read/delete smoke test."""
    store = resolve_secret_store(backend=backend, path=path)
    store.doctor_roundtrip(service=service, account=account)


def create_keychain(*, path: str, password: str) -> str:
    """Create a dedicated test keychain file."""
    target = keychain_path(path=path)
    Path(target).parent.mkdir(parents=True, exist_ok=True)
    run_security(args=["create-keychain", "-p", password, target])
    return target


def delete_keychain(*, path: str) -> None:
    """Delete a dedicated keychain file."""
    target = keychain_path(path=path)
    run_security(args=["delete-keychain", target])


def unlock_keychain_with_password(*, path: str, password: str) -> str:
    """Unlock a keychain using a supplied password, intended for isolated tests."""
    target = keychain_path(path=path)
    run_security(args=["unlock-keychain", "-p", password, target])
    return target


def make_temp_keychain(*, password: str = "seckit-test-password") -> Dict[str, str]:
    """Create and unlock a temporary keychain for regression tests."""
    temp_dir = tempfile.mkdtemp(prefix="seckit-keychain-")
    path = os.path.join(temp_dir, "test.keychain-db")
    create_keychain(path=path, password=password)
    unlock_keychain_with_password(path=path, password=password)
    return {"directory": temp_dir, "path": path, "password": password}
