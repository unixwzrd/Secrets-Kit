"""Native helper support for local and iCloud backends."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import sysconfig
from pathlib import Path
from typing import Dict, Optional


HELPER_NAME = "seckit-keychain-helper"
HELPER_SUPPORTED_BACKENDS = {"local", "icloud"}


class NativeHelperError(RuntimeError):
    """Native helper operation failed."""


def _build_status(message: str) -> None:
    print(f"[seckit helper] {message}", flush=True)


def helper_source_dir() -> Path:
    return Path(__file__).resolve().parent / "native_helper_src"


def helper_install_path() -> Path:
    scripts_dir = Path(sysconfig.get_path("scripts"))
    return scripts_dir / HELPER_NAME


def local_helper_binary_path() -> Optional[Path]:
    preferred = helper_install_path()
    if preferred.exists():
        return preferred
    found = shutil.which(HELPER_NAME)
    return Path(found) if found else None


def helper_binary_path() -> Optional[Path]:
    return local_helper_binary_path()


def helper_installed() -> bool:
    return local_helper_binary_path() is not None


def swift_binary_path() -> Optional[str]:
    for cmd in (["xcrun", "--find", "swift"], ["swift", "--version"]):
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode == 0:
            if cmd[:2] == ["xcrun", "--find"]:
                path = (proc.stdout or "").strip()
                return path or None
            found = shutil.which("swift")
            if found:
                return found
    return None


def swift_available() -> bool:
    return swift_binary_path() is not None


def lipo_binary_path() -> Optional[str]:
    for cmd in (["xcrun", "--find", "lipo"],):
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode == 0:
            path = (proc.stdout or "").strip()
            return path or None
    return shutil.which("lipo")


def _run_version(target: Path) -> Optional[str]:
    proc = subprocess.run([str(target), "--version"], capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        return None
    return (proc.stdout or "").strip() or None


def helper_version(*, path: Optional[Path] = None) -> Optional[str]:
    target = path or local_helper_binary_path()
    if not target:
        return None
    return _run_version(target)


def icloud_backend_available() -> bool:
    return helper_installed()


def icloud_backend_error() -> str:
    return (
        "backend=icloud requires the native helper. "
        "Run `seckit helper install-local` to build and install it."
    )


def helper_status() -> Dict[str, object]:
    helper = local_helper_binary_path()
    swift_path = swift_binary_path()
    available_backends = sorted(HELPER_SUPPORTED_BACKENDS if helper else {"local"})
    return {
        "backend_availability": {
            "local": True,
            "icloud": helper is not None,
        },
        "helper": {
            "helper_name": HELPER_NAME,
            "helper_installed": helper is not None,
            "helper_path": str(helper) if helper else None,
            "helper_version": helper_version(path=helper) if helper else None,
            "install_target": str(helper_install_path()),
            "supported_backends": available_backends,
        },
        "swift_available": swift_path is not None,
        "swift_path": swift_path,
        "source_dir": str(helper_source_dir()),
        "python_executable": sys.executable,
        "scripts_dir": sysconfig.get_path("scripts"),
    }


def build_and_install_local_helper() -> Path:
    if sys.platform != "darwin":
        raise NativeHelperError("native helper install is only supported on macOS")
    source_dir = helper_source_dir()
    if not source_dir.exists():
        raise NativeHelperError(f"native helper source not found: {source_dir}")
    _build_status(f"using helper source: {source_dir}")
    swift_path = swift_binary_path()
    if not swift_path:
        raise NativeHelperError(
            "Swift toolchain not found. Install Xcode Command Line Tools and retry."
        )
    _build_status(f"using swift: {swift_path}")
    lipo_path = lipo_binary_path()
    if not lipo_path:
        raise NativeHelperError("lipo not found. Install full Xcode and retry.")
    _build_status(f"using lipo: {lipo_path}")

    built_binaries: list[Path] = []
    for arch in ("arm64", "x86_64"):
        _build_status(f"building helper for {arch}")
        build_cmd = [swift_path, "build", "-c", "release", "--arch", arch, "--package-path", str(source_dir)]
        proc = subprocess.run(build_cmd, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            stderr = (proc.stderr or "").strip()
            raise NativeHelperError(stderr or f"swift build failed for arch={arch}")
        built_binary = source_dir / ".build" / f"{arch}-apple-macosx" / "release" / HELPER_NAME
        if not built_binary.exists():
            raise NativeHelperError(f"built helper not found for arch={arch}: {built_binary}")
        built_binaries.append(built_binary)
        _build_status(f"built {arch} slice: {built_binary}")

    target = helper_install_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    universal_tmp = source_dir / ".build" / f"{HELPER_NAME}-universal"
    _build_status("combining slices into universal binary")
    lipo_cmd = [lipo_path, "-create", *(str(path) for path in built_binaries), "-output", str(universal_tmp)]
    proc = subprocess.run(lipo_cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        raise NativeHelperError(stderr or "lipo create failed")
    if not universal_tmp.exists():
        raise NativeHelperError(f"universal helper not found: {universal_tmp}")
    _build_status(f"copying universal helper to: {target}")
    shutil.copy2(universal_tmp, target)
    current_mode = stat.S_IMODE(target.stat().st_mode)
    target.chmod(current_mode | 0o755)
    _build_status("helper install complete")
    return target


def build_and_install_helper() -> Path:
    return build_and_install_local_helper()


def run_helper_request(*, payload: Dict[str, object]) -> Dict[str, object]:
    helper = local_helper_binary_path()
    if not helper:
        raise NativeHelperError(
            "local native helper not installed. Run `seckit helper install-local` to build it."
        )
    proc = subprocess.run(
        [str(helper)],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        raise NativeHelperError(stderr or "native helper request failed")
    try:
        data = json.loads((proc.stdout or "").strip() or "{}")
    except json.JSONDecodeError as exc:
        raise NativeHelperError(f"invalid helper response: {exc}") from exc
    if not isinstance(data, dict):
        raise NativeHelperError("invalid helper response: top-level must be object")
    if data.get("ok") is False:
        raise NativeHelperError(str(data.get("error") or "native helper request failed"))
    return data
