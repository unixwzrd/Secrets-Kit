"""Tests for seckit install command."""

from __future__ import annotations

import argparse
import io
import unittest
from contextlib import redirect_stdout

from secrets_kit.cli import build_parser
from secrets_kit.cli.commands.install_cmd import (
    _build_install_sh_argv,
    _remote_ssh_command,
    cmd_install,
)
from secrets_kit.cli.install_constants import DEFAULT_INSTALL_URL


class CliInstallTest(unittest.TestCase):
    def test_parser_has_install_command(self) -> None:
        parser = build_parser()
        commands = parser._subparsers._group_actions[0].choices.keys()  # type: ignore[attr-defined]
        self.assertIn("install", commands)

    def test_remote_ssh_command_uses_batch_mode_and_curl(self) -> None:
        args = argparse.Namespace(
            remote_host="user@host.example",
            ref="v2.0.0a3",
            repo_url=None,
            install_url=None,
            upgrade=False,
            dev=False,
            yes=True,
            no_init=False,
            no_verify=False,
            dry_run=False,
            json=False,
        )
        argv = _remote_ssh_command(host=args.remote_host, args=args)
        self.assertEqual(argv[0], "ssh")
        self.assertIn("BatchMode=yes", argv)
        self.assertIn("ConnectTimeout=10", argv)
        joined = " ".join(argv)
        self.assertIn("curl -fsSL", joined)
        self.assertIn(DEFAULT_INSTALL_URL, joined)
        self.assertIn("--yes", joined)

    def test_build_install_sh_argv_upgrade(self) -> None:
        args = argparse.Namespace(
            remote_host=None,
            ref="v2.0.0a3",
            repo_url=None,
            install_url=None,
            upgrade=True,
            dev=False,
            yes=False,
            no_init=False,
            no_verify=False,
            dry_run=False,
            json=False,
        )
        argv = _build_install_sh_argv(args=args)
        self.assertTrue(any(part.endswith("install.sh") for part in argv))
        self.assertIn("--upgrade", argv)
        self.assertIn("--ref", argv)

    def test_install_no_args_prints_curl_hint(self) -> None:
        args = argparse.Namespace(
            remote_host=None,
            ref=None,
            repo_url=None,
            install_url=None,
            upgrade=False,
            dev=False,
            yes=False,
            no_init=False,
            no_verify=False,
            dry_run=False,
            json=False,
        )
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = cmd_install(args=args)
        text = stdout.getvalue()
        self.assertIn("curl -fsSL", text)
        self.assertIn(code, (0, 1))

    def test_install_upgrade_delegates_to_install_sh(self) -> None:
        args = argparse.Namespace(
            remote_host=None,
            ref=None,
            repo_url=None,
            install_url=None,
            upgrade=True,
            dev=False,
            yes=False,
            no_init=False,
            no_verify=False,
            dry_run=True,
            json=False,
        )
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = cmd_install(args=args)
        self.assertEqual(code, 0)
        self.assertIn("install.sh", stdout.getvalue())
        self.assertIn("--upgrade", stdout.getvalue())

    def test_install_remote_dry_run(self) -> None:
        args = argparse.Namespace(
            remote_host="user@host",
            ref=None,
            repo_url=None,
            install_url=None,
            upgrade=False,
            dev=False,
            yes=False,
            no_init=False,
            no_verify=False,
            dry_run=True,
            json=False,
        )
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = cmd_install(args=args)
        self.assertEqual(code, 0)
        self.assertIn("ssh", stdout.getvalue())
        self.assertIn("curl -fsSL", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
