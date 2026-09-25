"""secrets_kit.cli.parsers.upgrade: parser registration for explicit upgrades."""

from __future__ import annotations

import argparse

from secrets_kit.cli.commands.upgrade import cmd_upgrade
from secrets_kit.locale import msg


def register_upgrade_command(
    *, subparsers: argparse._SubParsersAction[argparse.ArgumentParser]
) -> None:
    """Register the thin wrapper around the existing preserving installer."""
    parser = subparsers.add_parser("upgrade", help=msg("cli.upgrade.help"))
    parser.set_defaults(remote_host=None)
    parser.add_argument("--check", action="store_true", help=msg("cli.upgrade.check_help"))
    parser.add_argument("--refresh", action="store_true", help=msg("cli.upgrade.refresh_help"))
    parser.add_argument("--ref", default=None, help=msg("cli.install.ref_help"))
    parser.add_argument("--repo-url", help=msg("cli.install.repo_url_help"))
    parser.set_defaults(install_url=None)
    parser.add_argument("--yes", action="store_true", help=msg("cli.common.yes_help"))
    parser.add_argument("--no-verify", action="store_true", help=msg("cli.install.no_verify_help"))
    parser.add_argument("--skip-verify-if-unchanged", action="store_true", help=msg("cli.install.skip_verify_if_unchanged_help"))
    parser.add_argument("--dry-run", action="store_true", help=msg("cli.common.dry_run_help"))
    parser.add_argument("--json", action="store_true", help=msg("cli.install.json_help"))
    parser.add_argument("--verbose", action="store_true", help=msg("cli.install.verbose_help"))
    parser.add_argument("--safe", action="store_true", help=msg("cli.install.safe_help"))
    parser.add_argument("--no-shell-profile", action="store_true", help=msg("cli.install.no_shell_profile_help"))
    parser.add_argument("--shell-profile-force", action="store_true", help=msg("cli.install.shell_profile_force_help"))
    parser.add_argument("--no-uv-download", action="store_true", help=msg("cli.install.no_uv_download_help"))
    commands = parser.add_subparsers(dest="upgrade_command")
    service = commands.add_parser("service", help=msg("cli.upgrade.service_help"))
    service.add_argument("service_action", choices=("install", "status", "uninstall"))
    parser.set_defaults(func=cmd_upgrade)


__all__ = ["register_upgrade_command"]
