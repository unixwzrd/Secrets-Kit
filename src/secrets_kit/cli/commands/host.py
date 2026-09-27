"""secrets_kit.cli.commands.host: opt-in host identity management.

Host IDs are descriptive scope; billing and peer access still require their
separate operator and peer-admission authorization paths.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path

from secrets_kit.cli.io import _fatal
from secrets_kit.host_context import (
    create_host_context,
    join_host_context,
    joined_host_membership,
    load_host_context,
)
from secrets_kit.shared_runtime import (
    SharedRuntimeError,
    activate_shared_generation,
    register_shared_user,
)


def cmd_host_configure(*, args: argparse.Namespace) -> int:
    """Create one administrator-owned context outside runtime generations."""
    try:
        context = create_host_context(
            prefix=Path(args.prefix), environment=args.environment,
            organization_name=args.organization, client_name=args.client,
            organization_id=args.organization_id, client_id=args.client_id,
        )
    except (OSError, ValueError, PermissionError) as exc:
        return _fatal(message=str(exc), code=1)
    print(json.dumps(context.as_dict(), sort_keys=True))
    return 0


def cmd_host_show(*, args: argparse.Namespace) -> int:
    """Show identifiers only; no billing credential is stored here."""
    try:
        if getattr(args, "joined", False):
            result = joined_host_membership(prefix=Path(args.prefix))
        else:
            result = load_host_context(Path(args.prefix)).as_dict()
    except (OSError, ValueError, PermissionError, sqlite3.Error) as exc:
        return _fatal(message=str(exc), code=1)
    print(json.dumps(result, sort_keys=True))
    return 0


def cmd_host_join(*, args: argparse.Namespace) -> int:
    """Associate an initialized same-user SQLite store with a host context."""
    try:
        result = join_host_context(prefix=Path(args.prefix), environment=args.environment)
    except (OSError, ValueError, PermissionError) as exc:
        return _fatal(message=str(exc), code=1)
    print(json.dumps(result, sort_keys=True))
    return 0


def cmd_host_register(*, args: argparse.Namespace) -> int:
    """Register one explicitly joined user for shared rolling upgrades."""
    try:
        users = register_shared_user(prefix=Path(args.prefix), username=args.user)
    except (OSError, ValueError, PermissionError, SharedRuntimeError) as exc:
        return _fatal(message=str(exc), code=1)
    print(json.dumps({"users": users}, sort_keys=True))
    return 0


def cmd_host_activate(*, args: argparse.Namespace) -> int:
    """Atomically activate a generation with per-user service checks."""
    try:
        result = activate_shared_generation(prefix=Path(args.prefix), generation_name=args.generation)
    except (OSError, ValueError, PermissionError, SharedRuntimeError) as exc:
        return _fatal(message=str(exc), code=1)
    print(json.dumps(result, sort_keys=True))
    return 0


__all__ = ["cmd_host_activate", "cmd_host_configure", "cmd_host_join", "cmd_host_register", "cmd_host_show"]
