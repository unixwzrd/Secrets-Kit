"""Compatibility JSON for ``seckit helper status`` / ``seckit version --json``.

No separate native binary is shipped; macOS Keychain access uses the ``security`` CLI
(``--backend secure``). This module reports ``backend_availability`` and whether **sqlite**
is available (PyNaCl import). Portable cross-host transfer uses export/import or peer bundles.
"""

from __future__ import annotations

from typing import Any, Dict


def helper_status() -> Dict[str, Any]:
    """JSON for ``seckit helper status`` and ``seckit version --json`` (no secrets)."""
    sqlite_ok = False
    try:
        import nacl.secret  # noqa: F401

        sqlite_ok = True
    except ImportError:
        sqlite_ok = False
    return {
        "backend_availability": {
            "secure": True,
            "local": True,
            "sqlite": sqlite_ok,
        },
        "helper": {
            "installed": False,
            "path": None,
            "bundled_path": None,
            "note": "No bundled native helper binary; use --backend secure and export/import.",
        },
    }
