"""Tests for seckit install command."""

from __future__ import annotations

import argparse
import io
import unittest
from contextlib import redirect_stdout
from unittest import mock

from secrets_kit.cli import build_parser
from secrets_kit.cli.commands.install_cmd import (
    _build_install_sh_argv,
    _current_ref,
    _normalize_ssh_target,
    _prepare_remote_install,
    _remote_ssh_command,
    cmd_install,
)


class CliInstallTest(unittest.TestCase):
    def test_parser_has_install_command(self) -> None:
        parser = build_parser()
        commands = parser._subparsers._group_actions[0].choices.keys()  # type: ignore[attr-defined]
        self.assertIn("install", commands)

    def test_remote_ssh_command_explicit_ref_uses_cli_flag(self) -> None:
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
            skip_verify_if_unchanged=False,
            dry_run=False,
            json=False,
        )
        argv = _remote_ssh_command(host=args.remote_host, args=args)
        self.assertEqual(argv[0], "ssh")
        self.assertIn("BatchMode=yes", argv)
        self.assertIn("ConnectTimeout=10", argv)
        joined = " ".join(argv)
        self.assertIn("bash -s --", joined)
        self.assertIn("--yes", joined)
        self.assertIn("--ref", joined)
        self.assertIn("v2.0.0a3", joined)

    def test_normalize_ssh_target_at_host_defaults_user(self) -> None:
        with mock.patch.dict("os.environ", {"USER": "alice"}, clear=False):
            self.assertEqual(_normalize_ssh_target("@rocky"), "alice@rocky")
        self.assertEqual(_normalize_ssh_target("bob@rocky"), "bob@rocky")

    def test_normalize_ssh_target_rejects_bare_host(self) -> None:
        from secrets_kit.cli.commands.install_cmd import InstallTargetError

        with self.assertRaises(InstallTargetError):
            _normalize_ssh_target("rocky")

    def test_prepare_remote_install_sets_yes(self) -> None:
        args = argparse.Namespace(remote_host="@host", yes=False)
        host = _prepare_remote_install(args=args)
        self.assertTrue(args.yes)
        self.assertTrue(host and host.endswith("@host"))

    def test_remote_ssh_command_default_pin_uses_env_not_ref_flag(self) -> None:
        args = argparse.Namespace(
            remote_host="user@host.example",
            ref=None,
            repo_url=None,
            install_url=None,
            upgrade=False,
            dev=False,
            yes=False,
            no_init=False,
            no_verify=False,
            skip_verify_if_unchanged=False,
            dry_run=False,
            json=False,
        )
        _prepare_remote_install(args=args)
        argv = _remote_ssh_command(host=args.remote_host, args=args)
        joined = " ".join(argv)
        self.assertIn(f"SECKIT_REF={_current_ref()}", joined)
        self.assertNotIn("--ref", joined)
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
            skip_verify_if_unchanged=False,
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
            skip_verify_if_unchanged=False,
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
            skip_verify_if_unchanged=False,
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
            remote_host="@host",
            ref=None,
            repo_url=None,
            install_url=None,
            upgrade=False,
            dev=False,
            yes=False,
            no_init=False,
            no_verify=False,
            skip_verify_if_unchanged=False,
            dry_run=True,
            json=False,
        )
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = cmd_install(args=args)
        self.assertEqual(code, 0)
        out = stdout.getvalue()
        self.assertIn("ssh", out)
        self.assertIn("bash -s --", out)
        self.assertIn(f"@{args.remote_host.split('@', 1)[-1]}", out)
        self.assertIn(f"SECKIT_REF={_current_ref()}", out)
        self.assertNotIn("--ref", out)
        self.assertIn("--yes", out)


if __name__ == "__main__":
    unittest.main()
