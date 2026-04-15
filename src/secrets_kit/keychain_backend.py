"""macOS Keychain backend for seckit."""

from __future__ import annotations

import ast
import os
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Any, Dict, Optional


class BackendError(RuntimeError):
    """Keychain backend error."""


DEFAULT_KEYCHAIN_PATH = os.path.expanduser("~/Library/Keychains/login.keychain-db")
ATTRIBUTE_PATTERN = re.compile(r'^\s+(?:"(?P<qkey>[^"]+)"|(?P<hkey>0x[0-9A-Fa-f]+))\s*<[^>]+>=(?P<value>.*)$')


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
) -> None:
    """Create or update a keychain secret entry."""
    svc = backend_service_name(service=service, name=name)
    args = ["add-generic-password", "-a", account, "-s", svc, "-l", label or name, "-j", comment, "-U", "-w", value]
    target = keychain_path(path=path) if path else None
    if target:
        args.append(target)
    _run_security(args=args)


def get_secret(*, service: str, account: str, name: str, path: Optional[str] = None) -> str:
    """Read secret value from keychain."""
    svc = backend_service_name(service=service, name=name)
    args = ["find-generic-password", "-a", account, "-s", svc, "-w"]
    target = keychain_path(path=path) if path else None
    if target:
        args.append(target)
    return _run_security(args=args)


def get_secret_metadata(*, service: str, account: str, name: str, path: Optional[str] = None) -> Dict[str, Any]:
    """Read keychain metadata attributes for one secret."""
    svc = backend_service_name(service=service, name=name)
    args = ["find-generic-password", "-a", account, "-s", svc, "-g"]
    target = keychain_path(path=path) if path else None
    if target:
        args.append(target)
    proc = _run_security_capture(args=args)
    merged = "\n".join(part for part in ((proc.stdout or "").strip(), (proc.stderr or "").strip()) if part)
    return _parse_find_generic_password_output(raw=merged)


def secret_exists(*, service: str, account: str, name: str, path: Optional[str] = None) -> bool:
    """Return whether a keychain item exists for one logical secret."""
    svc = backend_service_name(service=service, name=name)
    args = ["find-generic-password", "-a", account, "-s", svc]
    target = keychain_path(path=path) if path else None
    if target:
        args.append(target)
    return _security_exists(args=args)


def delete_secret(*, service: str, account: str, name: str, path: Optional[str] = None) -> None:
    """Delete secret from keychain."""
    svc = backend_service_name(service=service, name=name)
    args = ["delete-generic-password", "-a", account, "-s", svc]
    target = keychain_path(path=path) if path else None
    if target:
        args.append(target)
    _run_security(args=args)


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
