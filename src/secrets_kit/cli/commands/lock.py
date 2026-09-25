"""
secrets_kit.cli.commands.lock

Lock command implementation.
"""

from __future__ import annotations

import argparse

from secrets_kit.backends.keychain import (
    BackendError,
    check_security_cli,
    keychain_path,
    lock_keychain,
)
from secrets_kit.cli.io import _fatal
from secrets_kit.locale import msg


def cmd_lock(*, args: argparse.Namespace) -> int:
    if not check_security_cli():
        return _fatal(message=msg("errors.security_cli_not_found"), code=1)

    target = keychain_path(path=args.keychain)

    if args.dry_run:
        print(f"security lock-keychain {target}")
        return 0

    try:
        print(msg("cli.lock.locking", target=target))
        lock_keychain(path=target)
        print(msg("cli.lock.locked", target=target))
        return 0
    except BackendError as exc:
        return _fatal(message=str(exc), code=1)


__all__ = ["cmd_lock"]
