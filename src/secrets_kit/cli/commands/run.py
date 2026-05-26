"""
secrets_kit.cli.commands.run

Run command implementation.
"""

from __future__ import annotations

import argparse
import os

from secrets_kit.backends.keychain import BackendError
from secrets_kit.cli.exec import _child_command_args, _exec_child
from secrets_kit.cli.io import _fatal
from secrets_kit.cli.selection import _build_env_map, _select_entries
from secrets_kit.errors import EXIT_COMMAND_CANNOT_EXECUTE, EXIT_COMMAND_NOT_FOUND
from secrets_kit.locale import msg
from secrets_kit.models import ValidationError
from secrets_kit.registry import RegistryError


def cmd_run(*, args: argparse.Namespace) -> int:
    command = _child_command_args(args.child_command)
    try:
        if not command:
            return _fatal(message=msg("errors.run.requires_command"), code=2)

        selected = _select_entries(args=args, require_explicit_selection=False)
        if not selected:
            return _fatal(message=msg("errors.no_matching_entries.run"), code=1)

        env = os.environ.copy()
        env.update(_build_env_map(entries=selected, args=args))
        return _exec_child(argv=command, env=env)
    except (ValidationError, RegistryError, BackendError) as exc:
        return _fatal(message=str(exc), code=1)
    except FileNotFoundError:
        return _fatal(
            message=msg("errors.command_not_found", command=command[0]), code=EXIT_COMMAND_NOT_FOUND
        )
    except OSError as exc:
        return _fatal(
            message=msg("errors.command_launch_failed", command=command[0], error=exc),
            code=EXIT_COMMAND_CANNOT_EXECUTE,
        )


__all__ = ["cmd_run"]
