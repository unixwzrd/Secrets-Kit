"""macOS ``/usr/bin/security`` adapter and Keychain utilities."""

from __future__ import annotations

import ast
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

from secrets_kit.backends.errors import BackendError

DEFAULT_KEYCHAIN_PATH = os.path.expanduser("~/Library/Keychains/login.keychain-db")
ATTRIBUTE_PATTERN = re.compile(r'^\s+(?:"(?P<qkey>[^"]+)"|(?P<hkey>0x[0-9A-Fa-f]+))\s*<[^>]+>=(?P<value>.*)$')


def keychain_service_name(*, service: str, name: str) -> str:
    """Compose the Keychain ``svce`` attribute for a logical secret."""
    return f"{service}:{name}"


def run_security(*, args: list[str], stdin: Optional[str] = None) -> str:
    """Run ``security`` and return stdout. Raise ``BackendError`` on non-zero exit."""
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


def run_security_capture(*, args: list[str], stdin: Optional[str] = None) -> subprocess.CompletedProcess[str]:
    """Run ``security`` and return the full ``CompletedProcess``."""
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


def security_exists(*, args: list[str]) -> bool:
    """Run ``security`` and return ``True`` only when the exit code is zero."""
    cmd = ["security", *args]
    proc = subprocess.run(
        cmd,
        text=True,
        capture_output=True,
        check=False,
    )
    return proc.returncode == 0


def check_security_cli() -> bool:
    """Return whether macOS security tool is available."""
    proc = subprocess.run(["which", "security"], capture_output=True, text=True, check=False)
    return proc.returncode == 0


def keychain_path(*, path: Optional[str] = None) -> str:
    """Resolve a keychain path, defaulting to the login keychain."""
    return os.path.expanduser(path or DEFAULT_KEYCHAIN_PATH)


def keychain_accessible(*, path: Optional[str] = None) -> bool:
    """Return ``True`` when ``show-keychain-info`` succeeds for the given path."""
    target = keychain_path(path=path)
    return security_exists(args=["show-keychain-info", target])


def keychain_info(*, path: Optional[str] = None) -> str:
    """Run ``security show-keychain-info`` and return the raw text output."""
    target = keychain_path(path=path)
    return run_security(args=["show-keychain-info", target])


def keychain_policy(*, path: Optional[str] = None) -> dict[str, Any]:
    """Parse keychain policy flags from ``show-keychain-info`` output."""
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
    """Unlock the keychain via ``security unlock-keychain``."""
    target = keychain_path(path=path)
    cmd = ["security", "unlock-keychain", target]
    proc = subprocess.run(cmd, check=False)
    if proc.returncode != 0:
        raise BackendError(f"failed to unlock keychain: {target}")
    return target


def lock_keychain(*, path: Optional[str] = None) -> str:
    """Lock the keychain via ``security lock-keychain``."""
    target = keychain_path(path=path)
    cmd = ["security", "lock-keychain", target]
    proc = subprocess.run(cmd, check=False)
    if proc.returncode != 0:
        raise BackendError(f"failed to lock keychain: {target}")
    return target


def harden_keychain(*, path: Optional[str] = None, timeout_seconds: int = 3600) -> str:
    """Apply ``lock-on-sleep`` and ``lock-after-timeout`` to the keychain."""
    target = keychain_path(path=path)
    run_security(args=["set-keychain-settings", "-l", "-u", "-t", str(timeout_seconds), target])
    return target


def create_keychain(*, path: str, password: Optional[str] = None) -> str:
    """Create a dedicated keychain file."""
    target = keychain_path(path=path)
    Path(target).parent.mkdir(parents=True, exist_ok=True)
    if password:
        run_security(args=["create-keychain", "-p", password, target])
    else:
        run_security(args=["create-keychain", "-p", "", target])
    return target


def delete_keychain(*, path: str) -> None:
    """Delete a dedicated keychain file."""
    target = keychain_path(path=path)
    run_security(args=["delete-keychain", target])


def unlock_keychain_with_password(*, path: str, password: Optional[str] = None) -> str:
    """Unlock a keychain using a password, or ``-p ''`` for a no-password keychain."""
    target = keychain_path(path=path)
    if password:
        run_security(args=["unlock-keychain", "-p", password, target])
    else:
        run_security(args=["unlock-keychain", "-p", "", target])
    return target


def make_temp_keychain(*, password: str = "seckit-test-password") -> Dict[str, str]:
    """Create and unlock a temporary keychain for regression tests."""
    temp_dir = tempfile.mkdtemp(prefix="seckit-keychain-")
    path = os.path.join(temp_dir, "test.keychain-db")
    pwd_opt: Optional[str] = None if password == "" else password
    create_keychain(path=path, password=pwd_opt)
    unlock_keychain_with_password(path=path, password=pwd_opt)
    return {"directory": temp_dir, "path": path, "password": password}


class SecurityCliStore:
    """Local macOS Keychain store implemented through the ``security`` CLI."""

    def __init__(self, *, path: Optional[str] = None) -> None:
        """Initialise a Keychain store bound to an optional custom keychain file."""
        self.path = path

    def _target(self) -> Optional[str]:
        """Return the expanded keychain path, or ``None`` for the default login keychain."""
        return keychain_path(path=self.path) if self.path else None

    def _append_target(self, args: list[str]) -> list[str]:
        """Append the keychain path to a ``security`` argument list when set."""
        target = self._target()
        if target:
            args.append(target)
        return args

    def set(self, *, service: str, account: str, name: str, value: str, comment: str = "", label: Optional[str] = None) -> None:
        """Write a secret to the macOS Keychain via ``security add-generic-password``."""
        svc = keychain_service_name(service=service, name=name)
        args = ["add-generic-password", "-a", account, "-s", svc, "-l", label or name, "-j", comment, "-U", "-w", value]
        if self.path:
            args.extend(["-T", "/usr/bin/security"])
        run_security(args=self._append_target(args))

    def get(self, *, service: str, account: str, name: str) -> str:
        """Read a secret from the macOS Keychain via ``security find-generic-password``."""
        svc = keychain_service_name(service=service, name=name)
        args = ["find-generic-password", "-a", account, "-s", svc, "-w"]
        return run_security(args=self._append_target(args))

    def metadata(self, *, service: str, account: str, name: str) -> Dict[str, Any]:
        """Read keychain metadata attributes as a dict."""
        svc = keychain_service_name(service=service, name=name)
        args = ["find-generic-password", "-a", account, "-s", svc, "-g"]
        proc = run_security_capture(args=self._append_target(args))
        merged = "\n".join(part for part in ((proc.stdout or "").strip(), (proc.stderr or "").strip()) if part)
        return parse_find_generic_password_output(raw=merged)

    def exists(self, *, service: str, account: str, name: str) -> bool:
        """Return ``True`` when a keychain entry exists for the logical secret."""
        svc = keychain_service_name(service=service, name=name)
        args = ["find-generic-password", "-a", account, "-s", svc]
        return security_exists(args=self._append_target(args))

    def delete(self, *, service: str, account: str, name: str) -> None:
        """Delete a keychain entry via ``security delete-generic-password``."""
        svc = keychain_service_name(service=service, name=name)
        args = ["delete-generic-password", "-a", account, "-s", svc]
        run_security(args=self._append_target(args))


def parse_find_generic_password_output(*, raw: str) -> Dict[str, Any]:
    """Parse ``security find-generic-password -g`` output into a flat metadata dict."""
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
    """Strip outer quotes and decode escaped strings from ``security`` output."""
    if raw.startswith('"') and raw.endswith('"'):
        try:
            return str(ast.literal_eval(raw))
        except (SyntaxError, ValueError):
            return raw.strip('"')
    return raw

