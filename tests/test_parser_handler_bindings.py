"""Introspection: every leaf CLI subparser must bind a handler (``func``)."""

from __future__ import annotations

import argparse
import unittest

from secrets_kit.cli.parser.base import build_parser


def _walk_parsers(parser: argparse.ArgumentParser) -> None:
    sub_actions = [a for a in parser._actions if isinstance(a, argparse._SubParsersAction)]
    if not sub_actions:
        defaults = getattr(parser, "_defaults", None) or {}
        assert defaults.get("func") is not None, f"missing handler on parser prog={parser.prog!r}"
        return
    for action in sub_actions:
        for _, sub in action.choices.items():
            _walk_parsers(sub)


class ParserHandlerBindingTest(unittest.TestCase):
    def test_all_leaf_subcommands_have_func(self) -> None:
        p = build_parser()
        subs = [a for a in p._actions if isinstance(a, argparse._SubParsersAction)]
        self.assertTrue(subs, "expected root subparsers")
        for _, subparser in subs[0].choices.items():
            _walk_parsers(subparser)
