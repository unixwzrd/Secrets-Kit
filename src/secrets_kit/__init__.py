"""
secrets_kit
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

import tomli


def _source_tree_version() -> str | None:
    for parent in Path(__file__).resolve().parents:
        pyproject = parent / "pyproject.toml"
        if pyproject.exists():
            with pyproject.open("rb") as fh:
                data = tomli.load(fh)
            project = data.get("project", {})
            value = project.get("version")
            if isinstance(value, str):
                return value
    return None


try:
    __version__ = _source_tree_version() or version("seckit")
except PackageNotFoundError:
    __version__ = "0+unknown"

__all__ = ["__version__"]
