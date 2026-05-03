"""Native helper discovery and request plumbing for Secrets-Kit.

**Fully local Keychain** (``--backend secure``, alias ``local``) uses the macOS ``security`` CLI only.

The bundled **``seckit-keychain-helper``** is for **`--backend icloud-helper`** (alias ``icloud``):
synchronizable Keychain items use Security.framework from the entitled binary.
It is **not** used for the secure/local CLI path.

The helper Mach-O is **built in release automation** (``scripts/build_bundled_helper_for_wheel.sh``,
``docs/GITHUB_RELEASE_BUILD.md``). Wheels ship it; this module does not compile Swift on end-user machines.
"""

from __future__ import annotations

import json
import os
import plistlib
from pathlib import Path
import shutil
import signal
import subprocess
import sys
from typing import Any, Dict, List


class NativeHelperError(RuntimeError):
    """Native helper operation failed."""


HELPER_NAME = "seckit-keychain-helper"


def _returncode_message(*, returncode: int) -> str:
    if returncode < 0:
        signum = -returncode
        try:
            signal_name = signal.Signals(signum).name
        except ValueError:
            signal_name = f"signal {signum}"
        return f"helper was terminated by {signal_name} ({returncode})"
    return f"helper failed with exit code {returncode}"


def helper_install_dir() -> Path:
    return Path(sys.executable).resolve().parent


def helper_install_path() -> Path:
    return helper_install_dir() / HELPER_NAME


def bundled_helper_path() -> Path | None:
    """Path to the wheel-shipped helper next to this package, if present (macOS only)."""
    if sys.platform != "darwin":
        return None
    candidate = Path(__file__).resolve().parent / "native_helper_bundled" / HELPER_NAME
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return candidate
    return None


def _ordered_helper_candidates() -> List[Path]:
    """Search order: ``SECKIT_HELPER_PATH``, wheel bundle, venv ``bin``, ``PATH``."""
    candidates: List[Path] = []
    env_raw = os.environ.get("SECKIT_HELPER_PATH")
    if env_raw:
        candidates.append(Path(env_raw).expanduser())

    bundled = bundled_helper_path()
    install = helper_install_path()
    path_candidate = shutil.which(HELPER_NAME)
    path_path = Path(path_candidate) if path_candidate else None

    for p in (bundled, install, path_path):
        if p is not None and p not in candidates:
            candidates.append(p)
    return candidates


def icloud_helper_binary_path() -> Path | None:
    """First helper executable in search order that carries iCloud Keychain entitlements."""
    for candidate in _ordered_helper_candidates():
        if candidate.exists() and os.access(candidate, os.X_OK):
            if helper_has_icloud_entitlements(path=candidate):
                return candidate
    return None


def icloud_backend_available() -> bool:
    return icloud_helper_binary_path() is not None


def icloud_backend_error() -> str:
    return (
        "iCloud backend requires the native helper signed with synchronizable Keychain entitlements. "
        "Install a macOS wheel that bundles seckit-keychain-helper, or set SECKIT_HELPER_PATH to a "
        "suitably entitled binary (see docs/ICLOUD_SYNC_VALIDATION.md)."
    )


def helper_status() -> Dict[str, Any]:
    """Summarize iCloud helper resolution for ``seckit helper status``.

    ``helper.installed`` / ``helper.path`` refer to the entitled Mach-O used for
    ``--backend icloud-helper`` only. ``--backend secure`` does not use this binary.
    """
    bundled = bundled_helper_path()
    path = icloud_helper_binary_path()
    icloud_ready = path is not None
    helper_block: Dict[str, Any] = {
        "installed": icloud_ready,
        "path": str(path) if path else None,
        "bundled_path": str(bundled) if bundled else None,
    }
    return {
        "backend_availability": {
            "secure": True,
            "icloud-helper": icloud_ready,
            "local": True,
            "icloud": icloud_ready,
        },
        "helper": helper_block,
    }


def run_helper_request(*, payload: Dict[str, Any]) -> Dict[str, Any]:
    backend = str(payload.get("backend", "local"))
    if backend not in {"icloud", "icloud-helper"}:
        raise NativeHelperError(
            "internal error: native helper expects synchronizable-backend payload (wire backend icloud); "
            "secure/local uses the security CLI only"
        )
    helper = icloud_helper_binary_path()
    if helper is None:
        raise NativeHelperError(icloud_backend_error())
    proc = subprocess.run(
        [str(helper)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        check=False,
    )
    raw = (proc.stdout or "").strip()
    if not raw:
        if proc.returncode != 0:
            stderr = (proc.stderr or "").strip()
            raise NativeHelperError(stderr or _returncode_message(returncode=proc.returncode))
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        stderr = (proc.stderr or "").strip()
        detail = f"helper returned invalid json: {exc}"
        if proc.returncode != 0:
            detail = f"{_returncode_message(returncode=proc.returncode)}; {detail}"
        if stderr:
            detail = f"{detail}; stderr: {stderr}"
        raise NativeHelperError(detail) from exc
    if not isinstance(data, dict):
        raise NativeHelperError("helper returned non-object json")
    if data.get("ok") is False:
        raise NativeHelperError(str(data.get("error", "helper request failed")))
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        raise NativeHelperError(stderr or _returncode_message(returncode=proc.returncode))
    return data


def helper_entitlements(*, path: Path) -> Dict[str, Any]:
    codesign = shutil.which("codesign")
    if not codesign:
        return {}
    proc = subprocess.run(
        [codesign, "-d", "--entitlements", "-", str(path)],
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0 or not proc.stdout:
        return {}
    try:
        data = plistlib.loads(proc.stdout)
    except Exception:
        return _parse_codesign_entitlements_text(raw=proc.stdout)
    return data if isinstance(data, dict) else {}


def _parse_codesign_entitlements_text(*, raw: bytes) -> Dict[str, Any]:
    text = raw.decode("utf-8", errors="replace")
    result: Dict[str, Any] = {}
    current_key: str | None = None
    collecting_array = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[Key] "):
            current_key = stripped.split("] ", 1)[1]
            collecting_array = False
            continue
        if current_key is None:
            continue
        if stripped == "[Array]":
            result[current_key] = []
            collecting_array = True
            continue
        if stripped.startswith("[String] "):
            value = stripped.split("] ", 1)[1]
            if collecting_array:
                values = result.setdefault(current_key, [])
                if isinstance(values, list):
                    values.append(value)
            else:
                result[current_key] = value
    return result


def helper_has_icloud_entitlements(*, path: Path) -> bool:
    entitlements = helper_entitlements(path=path)
    access_groups = entitlements.get("keychain-access-groups")
    return bool(
        entitlements.get("com.apple.application-identifier")
        and entitlements.get("com.apple.developer.team-identifier")
        and isinstance(access_groups, list)
        and access_groups
    )
