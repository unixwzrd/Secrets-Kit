"""
secrets_kit.cli.support.env_exec

Child process env injection for ``seckit run``.
"""

from __future__ import annotations

import argparse
import os

from secrets_kit.backends.security import BackendError, get_secret
from secrets_kit.cli.support.args import _backend_access_kwargs
from secrets_kit.models.core import EntryMetadata


def _build_env_map(*, entries: list[EntryMetadata], args: argparse.Namespace) -> dict[str, str]:
    env_map: dict[str, str] = {}
    for meta in entries:
        try:
            env_map[meta.name] = get_secret(
                service=meta.service,
                account=meta.account,
                name=meta.name,
                **_backend_access_kwargs(args),
            )
        except BackendError as exc:
            raise BackendError(
                f"failed to read secret for run: service={meta.service} account={meta.account} "
                f"name={meta.name}. Use --names/--tag to narrow the injected set if this command "
                f"does not need every entry in the scope. Underlying error: {exc}"
            ) from exc
    return env_map


def _child_command_args(raw_args: list[str]) -> list[str]:
    args = list(raw_args)
    if args and args[0] == "--":
        args = args[1:]
    return args


def _exec_child(*, argv: list[str], env: dict[str, str]) -> int:
    os.execvpe(argv[0], argv, env)
    return 0
