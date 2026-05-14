"""Version and diagnostic JSON for ``seckit version``."""

from __future__ import annotations

import sys
from typing import Dict

from secrets_kit.utils.helper_status import helper_status
from secrets_kit.version_meta import package_version_string

from secrets_kit.cli.support.defaults import CONFIG_STORABLE_KEYS, _load_defaults
from secrets_kit.registry.core import RegistryError, defaults_path, ensure_defaults_storage


def _cli_version() -> str:
    """User-visible version string (installed metadata or :data:`UNKNOWN_VERSION` fallback)."""
    return package_version_string()


def _version_info_dict() -> Dict[str, object]:
    """Build a JSON-safe dict for `seckit version --json` / `--info` (no secret values)."""
    status = helper_status()
    info: Dict[str, object] = {
        "version": _cli_version(),
        "platform": sys.platform,
        "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "backend_availability": status["backend_availability"],
        "keychain_access": status["keychain_access"],
        "helper": status["helper"],
    }
    try:
        ensure_defaults_storage()
        dpath = defaults_path()
        info["defaults_path"] = str(dpath)
        merged = _load_defaults()
        safe = {k: merged[k] for k in CONFIG_STORABLE_KEYS if k in merged}
        info["defaults"] = {str(k): safe[k] for k in sorted(safe.keys(), key=str)}
    except (RegistryError, OSError, TypeError, ValueError):
        info["defaults_path"] = None
        info["defaults"] = {}
    return info
