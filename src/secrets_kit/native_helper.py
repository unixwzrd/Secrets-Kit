"""Native helper discovery and request plumbing for Secrets-Kit.

The helper is optional. The normal local backend can use the macOS ``security``
CLI, while iCloud/synchronizable Keychain access requires a native Security
framework path.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any, Dict


class NativeHelperError(RuntimeError):
    """Native helper operation failed."""


HELPER_NAME = "seckit-keychain-helper"


def helper_source_dir() -> Path:
    return Path(__file__).resolve().parent / "native_helper_src"


def helper_install_dir() -> Path:
    return Path(sys.executable).resolve().parent


def helper_install_path() -> Path:
    return helper_install_dir() / HELPER_NAME


def swift_binary_path() -> str | None:
    return shutil.which("swift")


def lipo_binary_path() -> str | None:
    return shutil.which("lipo")


def local_helper_binary_path() -> Path | None:
    candidates = [
        Path(os.environ["SECKIT_HELPER_PATH"]).expanduser()
        for key in ("SECKIT_HELPER_PATH",)
        if os.environ.get(key)
    ]
    candidates.append(helper_install_path())
    path_candidate = shutil.which(HELPER_NAME)
    if path_candidate:
        candidates.append(Path(path_candidate))
    for candidate in candidates:
        if candidate.exists() and os.access(candidate, os.X_OK):
            return candidate
    return None


def helper_installed() -> bool:
    return local_helper_binary_path() is not None


def icloud_backend_available() -> bool:
    return helper_installed()


def icloud_backend_error() -> str:
    return (
        "iCloud backend requires the native helper. "
        "Run `seckit helper install-local` first."
    )


def helper_status() -> Dict[str, Any]:
    helper_path = local_helper_binary_path()
    source_dir = helper_source_dir()
    swift_path = swift_binary_path()
    lipo_path = lipo_binary_path()
    return {
        "backend_availability": {
            "local": True,
            "icloud": helper_path is not None,
        },
        "helper": {
            "helper_installed": helper_path is not None,
            "path": str(helper_path) if helper_path else None,
            "source_dir": str(source_dir),
            "source_available": source_dir.exists(),
        },
        "swift_available": swift_path is not None,
        "swift_path": swift_path,
        "lipo_available": lipo_path is not None,
        "lipo_path": lipo_path,
    }


def run_helper_request(*, payload: Dict[str, Any]) -> Dict[str, Any]:
    helper = local_helper_binary_path()
    if helper is None:
        raise NativeHelperError(icloud_backend_error())
    proc = subprocess.run(
        [str(helper)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        raise NativeHelperError(stderr or f"helper failed with exit code {proc.returncode}")
    raw = (proc.stdout or "").strip()
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise NativeHelperError(f"helper returned invalid json: {exc}") from exc
    if not isinstance(data, dict):
        raise NativeHelperError("helper returned non-object json")
    if data.get("ok") is False:
        raise NativeHelperError(str(data.get("error", "helper request failed")))
    return data


def _run_checked(cmd: list[str]) -> None:
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        raise NativeHelperError(stderr or f"command failed: {' '.join(cmd)}")


def build_and_install_helper() -> Path:
    if sys.platform != "darwin":
        raise NativeHelperError("native helper can only be built on macOS")
    source_dir = helper_source_dir()
    if not source_dir.exists():
        raise NativeHelperError(f"native helper source not found: {source_dir}")
    swift = swift_binary_path()
    if not swift:
        raise NativeHelperError("Swift toolchain not found")
    lipo = lipo_binary_path()
    if not lipo:
        raise NativeHelperError("lipo tool not found")

    _run_checked([swift, "build", "--package-path", str(source_dir), "-c", "release", "--arch", "arm64"])
    _run_checked([swift, "build", "--package-path", str(source_dir), "-c", "release", "--arch", "x86_64"])

    arm64_binary = source_dir / ".build" / "arm64-apple-macosx" / "release" / HELPER_NAME
    x86_binary = source_dir / ".build" / "x86_64-apple-macosx" / "release" / HELPER_NAME
    universal_binary = source_dir / ".build" / f"{HELPER_NAME}-universal"
    _run_checked([lipo, "-create", str(arm64_binary), str(x86_binary), "-output", str(universal_binary)])

    target = helper_install_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(universal_binary, target)
    target.chmod(0o755)
    return target


def build_and_install_local_helper() -> Path:
    return build_and_install_helper()
