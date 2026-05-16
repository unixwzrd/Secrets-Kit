"""
secrets_kit.cli.parser.formatter

Argparse help rendering for ``seckit`` CLI.

This module is **not** for user-facing copy. All strings live in
:mod:`secrets_kit.cli.strings.en` (``STRINGS``). Here we only choose how
``argparse`` **lays out** ``--help`` output.

Why a custom formatter:

- :class:`argparse.RawDescriptionHelpFormatter` — Keeps newlines in
  ``description`` and ``epilog``. Without it, multi-line blocks from
  ``STRINGS`` (examples, sections) would be word-wrapped into one paragraph.
- :class:`argparse.ArgumentDefaultsHelpFormatter` — Appends ``(default: …)``
  to each argument's help text when a default is set, so operators see
  defaults without digging the code.

Together, ``--help`` stays readable for long epilogs and shows defaults
consistently. Collapsing this into ``strings`` would be the wrong layer
(strings are data; this is argparse presentation).

"""

from __future__ import annotations

import argparse

__all__ = ("SeckitHelpFormatter",)


class SeckitHelpFormatter(argparse.RawDescriptionHelpFormatter, argparse.ArgumentDefaultsHelpFormatter):
    """Help formatter combining raw multi-line text and visible argument defaults.

    Pass as ``formatter_class=`` on any :class:`argparse.ArgumentParser` that
    uses multi-line ``description`` / ``epilog`` from ``STRINGS`` and should
    show per-flag defaults.

    Behavior is entirely inherited from the two stdlib mix-in classes above;
    this class exists as a single named type for imports and typing.
    """
