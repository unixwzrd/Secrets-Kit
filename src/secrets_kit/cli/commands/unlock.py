"""
secrets_kit.cli.commands.unlock

Unlock command implementation.
"""

from __future__ import annotations

import argparse

from secrets_kit.backends.keychain import (
    BackendError,
    check_security_cli,
    harden_keychain,
    keychain_accessible,
    keychain_path,
    keychain_policy,
    unlock_keychain,
)
from secrets_kit.cli.io import _confirm, _fatal
from secrets_kit.locale import msg


def cmd_unlock(*, args: argparse.Namespace) -> int:
    if not check_security_cli():
        return _fatal(message=msg("errors.security_cli_not_found"), code=1)

    target = keychain_path(path=args.keychain)
    command = f"security unlock-keychain {target}"
    harden_command = f"security set-keychain-settings -l -u -t {args.timeout} {target}"
    policy = None
    try:
        policy = keychain_policy(path=target)
    except BackendError:
        policy = None

    print("")
    print("********************************************************************************")
    print("")
    print(msg("cli.unlock.notice.about_to_run"))
    print("")
    print(f"  {command}")
    print("")
    print(msg("cli.unlock.notice.password_prompt"))
    print(msg("cli.unlock.notice.password_safety"))
    if policy and policy.get("no_timeout"):
        print("")
        print(msg("cli.unlock.warning.relaxed_policy"))
        print(msg("cli.unlock.warning.hardening_command"))
        print("")
        print(f"  {harden_command}")
        print("")
        print(msg("cli.unlock.warning.recommended_policy"))
    print("********************************************************************************")
    print("")

    if args.dry_run:
        return 0

    if keychain_accessible(path=target):
        print(msg("cli.unlock.status.accessible", target=target))
        return 0

    if not args.yes and not _confirm(prompt=msg("prompts.unlock_keychain", target=target)):
        print(msg("cli.common.aborted"))
        return 1

    try:
        unlock_keychain(path=target)
        print(msg("cli.unlock.status.unlocked", target=target))
        if args.harden:
            print("")
            print(
                "********************************************************************************"
            )
            print("")
            print(msg("cli.unlock.notice.about_to_run"))
            print("")
            print(f"  {harden_command}")
            print("")
            print(msg("cli.unlock.notice.enable_timeout"))
            print(
                "********************************************************************************"
            )
            print("")
            harden_keychain(path=target, timeout_seconds=args.timeout)
            print(msg("cli.unlock.hardened", target=target, timeout=args.timeout))
        return 0
    except BackendError as exc:
        return _fatal(message=str(exc), code=1)


__all__ = ["cmd_unlock"]
