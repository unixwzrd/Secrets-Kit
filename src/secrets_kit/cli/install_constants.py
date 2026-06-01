"""Defaults for operator install URLs (branch-based; version resolved at install time)."""

from __future__ import annotations

DEFAULT_REPO = "unixwzrd/Secrets-Kit"
DEFAULT_INSTALL_BRANCH = "dev"
DEFAULT_REPO_URL = f"https://github.com/{DEFAULT_REPO}.git"
DEFAULT_INSTALL_URL = (
    f"https://raw.githubusercontent.com/{DEFAULT_REPO}/{DEFAULT_INSTALL_BRANCH}/install.sh"
)

__all__ = [
    "DEFAULT_INSTALL_BRANCH",
    "DEFAULT_INSTALL_URL",
    "DEFAULT_REPO",
    "DEFAULT_REPO_URL",
]
