"""
secrets_kit.cli.operator_defaults

Canonical operator defaults written by ``seckit init``.
"""

from __future__ import annotations

import getpass
import sys
from typing import Dict, Optional

from secrets_kit.backends.common import BACKEND_KEYCHAIN, BACKEND_SQLITE


def initial_operator_defaults(*, account: Optional[str] = None) -> Dict[str, object]:
    """Return the standard defaults.json payload for a fresh install."""
    resolved_account = account or getpass.getuser() or "default"
    backend = BACKEND_KEYCHAIN if sys.platform == "darwin" else BACKEND_SQLITE
    return {
        "backend": backend,
        "type": "secret",
        "kind": "api_key",
        "account": resolved_account,
        "default_rotation_days": 90,
        "rotation_warn_days": 14,
    }


__all__ = ["initial_operator_defaults"]
