"""macOS Keychain backend for secrets-kit."""

from __future__ import annotations

import subprocess
from typing import Optional


class BackendError(RuntimeError):
    """Keychain backend error."""


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


def set_secret(*, service: str, account: str, name: str, value: str) -> None:
    """Create or update a keychain secret entry."""
    svc = backend_service_name(service=service, name=name)
    _run_security(args=["add-generic-password", "-a", account, "-s", svc, "-w", value, "-U"])


def get_secret(*, service: str, account: str, name: str) -> str:
    """Read secret value from keychain."""
    svc = backend_service_name(service=service, name=name)
    return _run_security(args=["find-generic-password", "-a", account, "-s", svc, "-w"])


def delete_secret(*, service: str, account: str, name: str) -> None:
    """Delete secret from keychain."""
    svc = backend_service_name(service=service, name=name)
    _run_security(args=["delete-generic-password", "-a", account, "-s", svc])


def check_security_cli() -> bool:
    """Return whether macOS security tool is available."""
    proc = subprocess.run(["which", "security"], capture_output=True, text=True, check=False)
    return proc.returncode == 0


def doctor_roundtrip(*, service: str = "secrets-kit-doctor", account: str = "doctor") -> None:
    """Run a backend write/read/delete smoke test."""
    test_name = "DOCTOR_TEST_KEY"
    value = "doctor_ok"
    set_secret(service=service, account=account, name=test_name, value=value)
    fetched = get_secret(service=service, account=account, name=test_name)
    if fetched != value:
        raise BackendError("doctor roundtrip mismatch")
    delete_secret(service=service, account=account, name=test_name)
