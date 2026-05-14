"""Single source for the user-visible package version string.

When the distribution is not installed (no package metadata), returns
:const:`UNKNOWN_VERSION`. This is intentional for ``PYTHONPATH=src`` and raw
checkouts; see ``docs/PACKAGE_VERSION.md``.
"""

from __future__ import annotations

import importlib.metadata

PACKAGE_NAME = "seckit"
"""PyPI / distribution name passed to :func:`importlib.metadata.version`."""

UNKNOWN_VERSION = "0.0.0+unknown"
"""Explicit sentinel when ``seckit`` is not installed as a distribution."""


def package_version_string() -> str:
    """Return the installed ``seckit`` version, or :const:`UNKNOWN_VERSION`.

    Returns:
        Version string from metadata, or :const:`UNKNOWN_VERSION` if the package
        is not discoverable (typical for bare source trees).

    Note:
        Does not read ``pyproject.toml`` directly; installers must publish metadata.
    """
    try:
        return importlib.metadata.version(PACKAGE_NAME)
    except importlib.metadata.PackageNotFoundError:
        return UNKNOWN_VERSION
