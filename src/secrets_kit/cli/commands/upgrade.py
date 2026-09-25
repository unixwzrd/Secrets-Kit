"""secrets_kit.cli.commands.upgrade: explicit update checks and installer delegation."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

from secrets_kit import __version__
from secrets_kit.cli.commands.install_cmd import cmd_install
from secrets_kit.cli.update_check import (
    check_for_update,
    download_release_installer,
    release_installer_asset,
    update_context,
)
from secrets_kit.cli.update_service import manage_update_service
from secrets_kit.locale import msg

_VERSION_REF = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:(a|b|rc)(\d+))?$")


def _version_key(value: str) -> tuple[int, int, int, int, int]:
    match = _VERSION_REF.fullmatch(value)
    if not match:
        raise ValueError("release_tag_required")
    major, minor, patch, stage, serial = match.groups()
    rank = {"a": 0, "b": 1, "rc": 2, None: 3}[stage]
    return int(major), int(minor), int(patch), rank, int(serial or 0)


def cmd_upgrade(*, args: argparse.Namespace) -> int:
    """Check for an update or invoke the existing preserving upgrade path."""
    if getattr(args, "upgrade_command", None) == "service":
        return manage_update_service(action=args.service_action)
    if getattr(args, "check", False):
        result = check_for_update(refresh=bool(getattr(args, "refresh", False)))
        if getattr(args, "json", False):
            print(json.dumps(result, sort_keys=True))
        else:
            status = str(result["status"])
            print(msg(f"cli.upgrade.status_{status}", **result))
        return 2 if result["status"] == "unavailable" else 0
    reference = getattr(args, "ref", None)
    installer_url: str | None = None
    installer_digest: str | None = None
    if reference:
        try:
            if _version_key(reference) < _version_key(__version__):
                raise ValueError("downgrade_not_supported")
        except ValueError as exc:
            print(msg(f"cli.upgrade.{exc}"))
            return 2
    else:
        result = check_for_update(refresh=True)
        if result["status"] == "unavailable":
            print(msg("cli.upgrade.status_unavailable", **result))
            return 2
        if result["status"] == "current":
            print(msg("cli.upgrade.status_current", **result))
            return 0
        reference = str(result["latest"])
        args.ref = reference
        installer_url = str(result["installer_url"])
        installer_digest = str(result["installer_digest"])
    try:
        repository, channel = update_context()
    except ValueError:
        print(msg("cli.upgrade.status_unavailable"))
        return 2
    if not getattr(args, "yes", False) and not getattr(args, "dry_run", False):
        if not sys.stdin.isatty():
            print(msg("cli.upgrade.confirm_required", current=f"v{__version__}", target=reference))
            return 64
        answer = input(msg("cli.upgrade.confirm_prompt", current=f"v{__version__}", target=reference))
        if answer.strip().lower() not in {"y", "yes"}:
            print(msg("cli.common.aborted"))
            return 64
    try:
        if installer_url is None or installer_digest is None:
            installer_url, installer_digest = release_installer_asset(
                repository=repository, reference=reference
            )
        installer = download_release_installer(url=installer_url, digest=installer_digest)
    except (OSError, ValueError):
        print(msg("cli.upgrade.status_unavailable"))
        return 2
    args.upgrade = True
    args.repair = False
    args.dev = False
    args.no_init = True
    previous = {name: os.environ.get(name) for name in ("SECKIT_GITHUB_REPO", "SECKIT_RELEASE_CHANNEL")}
    os.environ.update(SECKIT_GITHUB_REPO=repository, SECKIT_RELEASE_CHANNEL=channel)
    try:
        args.install_script = str(installer)
        return cmd_install(args=args)
    finally:
        installer.unlink(missing_ok=True)
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


__all__ = ["cmd_upgrade"]
