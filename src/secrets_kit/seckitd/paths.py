"""
secrets_kit.seckitd.paths

User-private runtime paths for ``seckitd`` Unix sockets.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def default_runtime_dir() -> Path:
    """Directory for the Unix socket (0700 at bind time).

    - Linux: ``$XDG_RUNTIME_DIR/seckit`` when set (typical: /run/user/<uid>).
    - macOS: ``~/Library/Caches/seckit/run`` (user-local cache).
    - Fallback: ``~/.cache/seckit/run``.
    """
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Caches" / "seckit" / "run"
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    if xdg:
        return Path(xdg) / "seckit"
    return Path.home() / ".cache" / "seckit" / "run"


def default_socket_path() -> Path:
    """Default socket: ``<runtime_dir>/seckitd.sock``."""
    return default_runtime_dir() / "seckitd.sock"
