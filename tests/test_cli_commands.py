from __future__ import annotations

import unittest

from secrets_kit.cli import build_parser


class CliCommandsTest(unittest.TestCase):
    def test_parser_has_expected_commands(self) -> None:
        parser = build_parser()
        commands = parser._subparsers._group_actions[0].choices.keys()  # type: ignore[attr-defined]
        for expected in {"set", "get", "list", "delete", "import", "export", "doctor", "migrate"}:
            self.assertIn(expected, commands)

    def test_kind_flags_parse(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["set", "--name", "OPENAI_API_KEY", "--value", "x", "--kind", "token"])
        self.assertEqual(args.kind, "token")

        args = parser.parse_args(["import", "file", "--file", "secrets.json", "--kind", "auto"])
        self.assertEqual(args.kind, "auto")


if __name__ == "__main__":
    unittest.main()
