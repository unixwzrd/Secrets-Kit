#!/usr/bin/env python3
"""Emit an allowlisted Secrets Kit scope for Hermes startup resolution."""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _names(path: Path) -> list[str]:
    """Read and validate the bounded environment-name allowlist."""
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ValueError("names file must be an absolute regular file")
    names = [line.strip() for line in path.read_text(encoding="utf-8").splitlines()]
    names = [name for name in names if name and not name.startswith("#")]
    if not names or len(names) > 128 or len(set(names)) != len(names):
        raise ValueError("names file must contain 1-128 unique names")
    if any(not _NAME.fullmatch(name) for name in names):
        raise ValueError("names file contains an invalid environment name")
    return names


def _emit(names: list[str]) -> int:
    """Emit only selected, single-line values from the inherited environment."""
    for name in names:
        value = os.environ.get(name)
        if value is None or not value or any(mark in value for mark in ("\n", "\r", "\0")):
            return 78
        print(f"{name}={value}")
    return 0


def main() -> int:
    """Resolve the allowlist through `seckit run` or emit its child environment."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--seckit", type=Path, required=True)
    parser.add_argument("--names-file", type=Path, required=True)
    parser.add_argument("--account", required=True)
    parser.add_argument("--service", required=True)
    parser.add_argument("--backend", choices=("keychain", "sqlite"), default="sqlite")
    parser.add_argument("--emit", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    names = _names(args.names_file)
    if args.emit:
        return _emit(names)
    seckit = args.seckit.expanduser().resolve(strict=True)
    if not seckit.is_file() or os.access(seckit, os.X_OK) is False:
        return 69
    child = [
        str(seckit),
        "run",
        "--account", args.account,
        "--service", args.service,
        "--backend", args.backend,
        "--names", ",".join(names),
        "--",
        sys.executable,
        str(Path(__file__).resolve()),
        "--seckit", str(seckit),
        "--names-file", str(args.names_file),
        "--account", args.account,
        "--service", args.service,
        "--backend", args.backend,
        "--emit",
    ]
    os.execv(str(seckit), child)
    return 70


if __name__ == "__main__":
    raise SystemExit(main())
