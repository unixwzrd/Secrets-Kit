"""Defaults for operator install URLs (baked per release)."""

from __future__ import annotations

DEFAULT_REF = "v1.2.3"
DEFAULT_REPO_URL = "https://github.com/unixwzrd/Secrets-Kit.git"
DEFAULT_INSTALL_URL = (
    f"https://raw.githubusercontent.com/unixwzrd/Secrets-Kit/{DEFAULT_REF}/install.sh"
)

__all__ = ["DEFAULT_REF", "DEFAULT_REPO_URL", "DEFAULT_INSTALL_URL"]
