#!/usr/bin/env python3
"""Run basedpyright for pre-commit (same paths as ``make lint-types``)."""

from __future__ import annotations

import subprocess
import sys


def main() -> int:
    try:
        import basedpyright  # noqa: F401
    except ImportError:
        print(
            "pre-commit: basedpyright is not installed for this Python.\n"
            '  Install dev deps: pip install -e ".[dev]"',
            file=sys.stderr,
        )
        return 1
    cmd = [sys.executable, "-m", "basedpyright", "src", "tests"]
    return subprocess.call(cmd)


if __name__ == "__main__":
    raise SystemExit(main())
