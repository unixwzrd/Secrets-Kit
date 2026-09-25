"""
secrets_kit.cli.argparse_helpers

Shared argparse subclasses for seckit CLI ergonomics.
"""

from __future__ import annotations

import argparse
import sys
from typing import NoReturn

from secrets_kit.locale import msg


class LocalizedHelpFormatter(argparse.HelpFormatter):
    """Translate the usage heading without changing arguments or parsing."""

    def add_usage(self, usage, actions, groups, prefix=None) -> None:
        super().add_usage(usage, actions, groups, prefix=prefix or msg("cli.help.usage"))


class SeckitArgumentParser(argparse.ArgumentParser):
    """
    ArgumentParser that prints full command help before exit on parse errors.

    Root invocations like ``seckit --jelp`` otherwise show only a one-line usage
    summary because required subparsers fail before unknown-option checks run.
    """

    def __init__(self, *args, **kwargs) -> None:
        """Use bundled help labels without changing process-wide gettext state."""
        add_help = kwargs.pop("add_help", True)
        kwargs.setdefault("formatter_class", LocalizedHelpFormatter)
        super().__init__(*args, add_help=False, **kwargs)
        self._positionals.title = msg("cli.help.positionals")
        self._optionals.title = msg("cli.help.options")
        if add_help:
            self.add_argument("-h", "--help", action="help", help=msg("cli.help.help"))

    def error(self, message: str) -> NoReturn:
        self.print_help(file=sys.stdout)
        self.exit(2, f"\n{self.prog}: {msg('cli.help.error', message=message)}\n")


__all__ = ["SeckitArgumentParser"]
