"""Stub status for the removed Swift Keychain helper.

The **``seckit-keychain-helper``** synchronizable Keychain backend was removed: macOS routinely
**SIGKILL**s that binary at launch. **`--backend secure`** (``security`` CLI) and **export/import**
are the only supported storage paths.

``seckit helper status`` still emits JSON so older automation keeps parsing; **icloud** entries
are always **false**.
"""

from __future__ import annotations

from typing import Any, Dict


def helper_status() -> Dict[str, Any]:
    """JSON for ``seckit helper status`` and ``seckit version --json`` (no secrets)."""
    return {
        "backend_availability": {
            "secure": True,
            "local": True,
            "icloud-helper": False,
            "icloud": False,
        },
        "helper": {
            "installed": False,
            "path": None,
            "bundled_path": None,
            "removed": True,
            "note": "Swift seckit-keychain-helper was removed; use --backend secure and export/import.",
        },
    }
