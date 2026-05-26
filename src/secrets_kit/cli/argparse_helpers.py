"""
secrets_kit.cli.argparse_helpers

Shared argparse subclasses for seckit CLI ergonomics.
"""

from __future__ import annotations

import argparse
import sys
from typing import NoReturn


class SeckitArgumentParser(argparse.ArgumentParser):
    """
    ArgumentParser that prints full command help before exit on parse errors.

    Root invocations like ``seckit --jelp`` otherwise show only a one-line usage
    summary because required subparsers fail before unknown-option checks run.
    """

    def error(self, message: str) -> NoReturn:
        self.print_help(file=sys.stdout)
        self.exit(2, f"\n{self.prog}: error: {message}\n")


__all__ = ["SeckitArgumentParser"]
