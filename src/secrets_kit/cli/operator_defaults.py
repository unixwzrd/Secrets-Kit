"""
secrets_kit.cli.operator_defaults

Canonical operator defaults written by ``seckit init``.
"""

from __future__ import annotations

import getpass
import os
import pwd
import sys
from typing import Dict, Optional

from secrets_kit.backends.common import BACKEND_KEYCHAIN, BACKEND_SQLITE, normalize_backend


def resolve_operator_account() -> str:
    """
    Resolve the operator account label for defaults.json.

    Prefer the login identity over inherited ``USER=root`` from sudo/pipes.
    """
    for key in ("LOGNAME", "USER", "LNAME"):
        value = os.environ.get(key, "").strip()
        if value and value != "root":
            return value

    home = os.environ.get("HOME", "").strip()
    if home.startswith("/Users/"):
        account = os.path.basename(home.rstrip("/"))
        if account and account != "root":
            return account

    try:
        name = pwd.getpwuid(os.getuid()).pw_name
        if name and name != "root":
            return name
    except KeyError:
        pass

    return getpass.getuser() or "default"


def initial_operator_defaults(
    *, account: Optional[str] = None, backend: Optional[str] = None
) -> Dict[str, object]:
    """Return the standard defaults.json payload for a fresh install."""
    resolved_account = account or resolve_operator_account()
    selected_backend = (
        normalize_backend(backend)
        if backend is not None
        else BACKEND_KEYCHAIN
        if sys.platform == "darwin"
        else BACKEND_SQLITE
    )
    return {
        "backend": selected_backend,
        "type": "secret",
        "kind": "api_key",
        "account": resolved_account,
        "default_rotation_days": 90,
        "rotation_warn_days": 14,
    }


__all__ = ["initial_operator_defaults", "resolve_operator_account"]
