"""
secrets_kit.cli.parsers.install

Parser registration for seckit install.
"""

from __future__ import annotations

import argparse

from secrets_kit.cli.commands.install_cmd import cmd_install
from secrets_kit.cli.install_constants import DEFAULT_INSTALL_URL, DEFAULT_REF
from secrets_kit.locale import msg


def register_install_commands(
    *, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    """Register install / upgrade / remote SSH wrapper."""
    p_install = subparsers.add_parser("install", help=msg("cli.install.help"))
    p_install.add_argument(
        "remote_host",
        nargs="?",
        metavar="user@host",
        help=msg("cli.install.remote_help"),
    )
    p_install.add_argument(
        "--ref",
        default=None,
        help=msg("cli.install.ref_help", default_ref=DEFAULT_REF),
    )
    p_install.add_argument("--repo-url", help=msg("cli.install.repo_url_help"))
    p_install.add_argument(
        "--install-url",
        default=None,
        help=msg("cli.install.install_url_help", default_url=DEFAULT_INSTALL_URL),
    )
    p_install.add_argument("--upgrade", action="store_true", help=msg("cli.install.upgrade_help"))
    p_install.add_argument("--repair", action="store_true", help=msg("cli.install.repair_help"))
    p_install.add_argument("--dev", action="store_true", help=msg("cli.install.dev_help"))
    p_install.add_argument("--yes", action="store_true", help=msg("cli.common.yes_help"))
    p_install.add_argument("--no-init", action="store_true", help=msg("cli.install.no_init_help"))
    p_install.add_argument(
        "--no-verify",
        action="store_true",
        help=msg("cli.install.no_verify_help"),
    )
    p_install.add_argument("--dry-run", action="store_true", help=msg("cli.common.dry_run_help"))
    p_install.add_argument("--json", action="store_true", help=msg("cli.install.json_help"))
    p_install.add_argument("--verbose", action="store_true", help=msg("cli.install.verbose_help"))
    p_install.add_argument(
        "--safe",
        action="store_true",
        help=msg("cli.install.safe_help"),
    )
    p_install.add_argument(
        "--no-shell-profile",
        action="store_true",
        help=msg("cli.install.no_shell_profile_help"),
    )
    p_install.add_argument(
        "--shell-profile-force",
        action="store_true",
        help=msg("cli.install.shell_profile_force_help"),
    )
    p_install.add_argument(
        "--no-uv-download",
        action="store_true",
        help=msg("cli.install.no_uv_download_help"),
    )
    p_install.set_defaults(func=cmd_install)


__all__ = ["register_install_commands"]
