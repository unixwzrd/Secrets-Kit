"""macOS Keychain backend for seckit."""

from __future__ import annotations

import os
import subprocess
from typing import Any, Optional


class BackendError(RuntimeError):
    """Keychain backend error."""


DEFAULT_KEYCHAIN_PATH = os.path.expanduser("~/Library/Keychains/login.keychain-db")


def backend_service_name(*, service: str, name: str) -> str:
    """Compose keychain service name including logical secret key."""
    return f"{service}:{name}"


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


def harden_keychain(*, path: Optional[str] = None, timeout_seconds: int = 3600) -> str:
    target = keychain_path(path=path)
    _run_security(args=["set-keychain-settings", "-l", "-u", "-t", str(timeout_seconds), target])
    return target


def set_secret(*, service: str, account: str, name: str, value: str) -> None:
    """Create or update a keychain secret entry."""
    svc = backend_service_name(service=service, name=name)
    _run_security(args=["add-generic-password", "-a", account, "-s", svc, "-w", value, "-U"])


def get_secret(*, service: str, account: str, name: str) -> str:
    """Read secret value from keychain."""
    svc = backend_service_name(service=service, name=name)
    return _run_security(args=["find-generic-password", "-a", account, "-s", svc, "-w"])


def secret_exists(*, service: str, account: str, name: str) -> bool:
    """Return whether a keychain item exists for one logical secret."""
    svc = backend_service_name(service=service, name=name)
    return _security_exists(args=["find-generic-password", "-a", account, "-s", svc])


def delete_secret(*, service: str, account: str, name: str) -> None:
    """Delete secret from keychain."""
    svc = backend_service_name(service=service, name=name)
    _run_security(args=["delete-generic-password", "-a", account, "-s", svc])


def check_security_cli() -> bool:
    """Return whether macOS security tool is available."""
    proc = subprocess.run(["which", "security"], capture_output=True, text=True, check=False)
    return proc.returncode == 0


def doctor_roundtrip(*, service: str = "seckit-doctor", account: str = "doctor") -> None:
    """Run a backend write/read/delete smoke test."""
    test_name = "DOCTOR_TEST_KEY"
    value = "doctor_ok"
    set_secret(service=service, account=account, name=test_name, value=value)
    fetched = get_secret(service=service, account=account, name=test_name)
    if fetched != value:
        raise BackendError("doctor roundtrip mismatch")
    delete_secret(service=service, account=account, name=test_name)
