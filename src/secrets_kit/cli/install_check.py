"""
secrets_kit.cli.install_check

Fast post-install verification (no backend roundtrips, no registry scan).
"""

from __future__ import annotations

import os
import platform
import sys
from importlib.resources import files
from pathlib import Path
from typing import Any

from secrets_kit import __version__
from secrets_kit.registry.storage import registry_dir

_SCHEMA_SEEDS = (
    "builtin.secret.generic.json",
    "builtin.secret.api_key.json",
)

_TAXONOMY_SEEDS = (
    "entry_types.json",
    "entry_kinds.json",
)

_SECKIT_SHARE_DIR = Path(os.environ.get("SECKIT_SHARE_DIR", Path.home() / ".local" / "share" / "seckit"))
_SECKIT_STATE_DIR = Path(os.environ.get("SECKIT_STATE_DIR", _SECKIT_SHARE_DIR / "state"))
_SECKIT_RUNTIME_PATH_FILE = Path(
    os.environ.get("SECKIT_RUNTIME_PATH_FILE", _SECKIT_STATE_DIR / "runtime-path")
)
_SECKIT_LAUNCHER_PATH = Path(
    os.environ.get("SECKIT_LAUNCHER_PATH", Path.home() / ".local" / "bin" / "seckit")
)


def _check_python_version(*, issues: list[str]) -> bool:
    major, minor = sys.version_info[:2]
    if (major, minor) < (3, 9):
        issues.append(f"python version {major}.{minor} < 3.9")
        return False
    return True


def _check_package_seeds(*, issues: list[str]) -> bool:
    ok = True
    for name in _SCHEMA_SEEDS:
        path = files("secrets_kit.schemas") / "builtin" / name
        if not path.is_file():
            issues.append(f"missing schema seed: {name}")
            ok = False
    for name in _TAXONOMY_SEEDS:
        path = files("secrets_kit.taxonomy") / "builtin" / name
        if not path.is_file():
            issues.append(f"missing taxonomy seed: {name}")
            ok = False
    return ok


def _check_cryptography(*, issues: list[str]) -> bool:
    try:
        import cryptography  # noqa: F401
    except ImportError:
        issues.append("cryptography package not installed")
        return False
    return True


def _check_config_writable(*, issues: list[str]) -> bool:
    config_dir = registry_dir()
    try:
        config_dir.mkdir(parents=True, exist_ok=True)
        probe = config_dir / ".install_check_probe"
        probe.write_text("", encoding="utf-8")
        probe.unlink(missing_ok=True)
    except OSError as exc:
        issues.append(f"config dir not writable: {config_dir} ({exc})")
        return False
    return True


def _check_launcher_runtime(*, issues: list[str]) -> bool:
    ok = True
    if not _SECKIT_LAUNCHER_PATH.is_file():
        issues.append(f"launcher not found: {_SECKIT_LAUNCHER_PATH}")
        ok = False
    if not _SECKIT_RUNTIME_PATH_FILE.is_file():
        issues.append(f"runtime path file not found: {_SECKIT_RUNTIME_PATH_FILE}")
        return False
    runtime_root = _SECKIT_RUNTIME_PATH_FILE.read_text(encoding="utf-8").strip()
    if not runtime_root:
        issues.append(f"runtime path file is empty: {_SECKIT_RUNTIME_PATH_FILE}")
        return False
    runtime_bin = Path(runtime_root) / "bin" / "seckit"
    if not runtime_bin.is_file():
        issues.append(f"runtime seckit binary not found: {runtime_bin}")
        ok = False
    return ok


def _backend_hints() -> dict[str, Any]:
    system = platform.system().lower()
    machine = platform.machine()
    hints: dict[str, Any] = {
        "platform": system,
        "machine": machine,
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
    }
    if system == "darwin":
        from secrets_kit.backends.keychain import check_security_cli

        hints["keychain_cli"] = check_security_cli()
        if not hints["keychain_cli"]:
            hints["note"] = "macOS keychain backend requires the security CLI"
    elif system == "linux":
        hints["default_backend"] = "sqlite"
        hints["note"] = "Linux installs use SQLite backend by default (sqlite_dev_mode)"
    return hints


def run_install_check() -> dict[str, Any]:
    """
    Run fast install verification checks.

    Returns:
        Dict with ok, version, issues, and backend_hints.
    """
    issues: list[str] = []
    checks = [
        _check_python_version(issues=issues),
        _check_cryptography(issues=issues),
        _check_package_seeds(issues=issues),
        _check_config_writable(issues=issues),
        _check_launcher_runtime(issues=issues),
    ]
    result: dict[str, Any] = {
        "ok": all(checks) and not issues,
        "version": __version__,
        "issues": issues,
        "backend_hints": _backend_hints(),
        "config_dir": str(registry_dir()),
        "interpreter": sys.executable,
        "launcher": str(_SECKIT_LAUNCHER_PATH),
        "runtime_path_file": str(_SECKIT_RUNTIME_PATH_FILE),
    }
    return result


def install_state_path(*, home: Path | None = None) -> Path:
    """Path to install.json state file."""
    return registry_dir(home=home) / "install.json"


__all__ = ["run_install_check", "install_state_path"]
