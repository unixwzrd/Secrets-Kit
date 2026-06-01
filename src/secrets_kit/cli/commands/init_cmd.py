"""
secrets_kit.cli.commands.init_cmd

Initialize operator config and optional SQLite developer storage.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from secrets_kit.backends.common import (
    BACKEND_KEYCHAIN,
    BACKEND_SQLITE,
    BackendError,
    normalize_backend,
)
from secrets_kit.backends.sqlite import (
    SQLiteBackendError,
    open_sqlite_backend,
    require_sqlite_developer_mode,
    sqlite_path,
)
from secrets_kit.backends.sqlite.schema import SCHEMA_VERSION
from secrets_kit.cli.io import _confirm, _fatal
from secrets_kit.cli.operator_defaults import initial_operator_defaults
from secrets_kit.locale import msg
from secrets_kit.models import ValidationError
from secrets_kit.registry import (
    RegistryError,
    defaults_path,
    load_registry,
    registry_path,
    save_defaults,
    save_registry,
)
from secrets_kit.schemas.registry_store import merge_seed_files_into_store
from secrets_kit.taxonomy.registry_store import merge_seed_files_into_taxonomy_store


def _home_path(args: argparse.Namespace) -> Optional[Path]:
    raw = getattr(args, "home", None)
    return Path(raw).expanduser() if raw else None


def _existing_init_targets(*, home: Optional[Path]) -> List[str]:
    lines: List[str] = []
    dpath = defaults_path(home=home)
    if dpath.exists() and dpath.read_text(encoding="utf-8").strip() not in ("", "{}"):
        lines.append(str(dpath))
    rpath = registry_path(home=home)
    if rpath.exists():
        try:
            entries = load_registry(home=home)
            if entries:
                lines.append(f"{rpath} ({len(entries)} entries)")
            else:
                lines.append(str(rpath))
        except RegistryError:
            lines.append(str(rpath))
    spath = sqlite_path()
    if home is not None:
        return lines
    if spath.exists():
        lines.append(str(spath))
    return lines


def _existing_sqlite_target() -> Optional[str]:
    spath = sqlite_path()
    if spath.exists():
        return str(spath)
    return None


def _require_init_confirmation(*, args: argparse.Namespace, targets: List[str], scope: str) -> bool:
    if getattr(args, "yes", False):
        return True
    if not targets:
        return True
    print(msg("cli.init.warning.header", scope=scope), file=sys.stderr)
    for target in targets:
        print(f"  - {target}", file=sys.stderr)
    print(msg("cli.init.warning.footer"), file=sys.stderr)
    return _confirm(prompt=msg("prompts.init_confirm", scope=scope))


def cmd_init_operator(*, args: argparse.Namespace) -> int:
    """Reset defaults.json and registry.json to a fresh operator layout."""
    home = _home_path(args)
    try:
        targets = _existing_init_targets(home=home)
        if not _require_init_confirmation(args=args, targets=targets, scope="operator"):
            print(msg("cli.common.aborted"))
            return 1
        payload = initial_operator_defaults(backend=getattr(args, "backend", None))
        backend = normalize_backend(str(payload.get("backend", BACKEND_KEYCHAIN)))
        sqlite_dev_mode = bool(getattr(args, "sqlite_dev_mode", False))
        if backend == BACKEND_SQLITE:
            require_sqlite_developer_mode(sqlite_dev_mode=sqlite_dev_mode)
            conn = open_sqlite_backend()
            conn.close()
        save_defaults(payload=payload, home=home)
        save_registry(entries={}, home=home)
        try:
            merge_seed_files_into_store(
                backend=backend,
                allow_replace=False,
                sqlite_dev_mode=sqlite_dev_mode,
            )
        except (BackendError, OSError) as exc:
            print(f"warning: metadata schema registry seed skipped ({exc})", file=sys.stderr)
        try:
            merge_seed_files_into_taxonomy_store(
                backend=backend,
                sqlite_dev_mode=sqlite_dev_mode,
            )
        except (BackendError, OSError, ValidationError) as exc:
            print(f"warning: taxonomy registry seed skipped ({exc})", file=sys.stderr)
        print(
            msg(
                "cli.init.operator.done",
                defaults_path=str(defaults_path(home=home)),
                registry_path=str(registry_path(home=home)),
            )
        )
        return 0
    except (BackendError, SQLiteBackendError, RegistryError, ValidationError, OSError) as exc:
        return _fatal(message=str(exc), code=1)


def cmd_init_sqlite(*, args: argparse.Namespace) -> int:
    """Delete and recreate the standalone SQLite developer database file."""
    try:
        require_sqlite_developer_mode(sqlite_dev_mode=getattr(args, "sqlite_dev_mode", False))
        target = _existing_sqlite_target()
        targets = [target] if target else []
        if not _require_init_confirmation(args=args, targets=targets, scope="sqlite"):
            print(msg("cli.common.aborted"))
            return 1
        spath = sqlite_path()
        if spath.exists():
            spath.unlink()
        conn = open_sqlite_backend()
        user_version = conn.execute("PRAGMA user_version").fetchone()[0]
        conn.close()
        try:
            merge_seed_files_into_store(backend="sqlite", allow_replace=False, sqlite_dev_mode=True)
            merge_seed_files_into_taxonomy_store(backend="sqlite", sqlite_dev_mode=True)
        except (BackendError, SQLiteBackendError, ValidationError) as exc:
            return _fatal(message=str(exc), code=1)
        print(
            msg(
                "cli.init.sqlite.done",
                path=str(spath),
                schema_version=SCHEMA_VERSION,
                user_version=user_version,
            )
        )
        return 0
    except (SQLiteBackendError, RegistryError, OSError) as exc:
        return _fatal(message=str(exc), code=1)


def cmd_init(*, args: argparse.Namespace) -> int:
    """Dispatch init subcommands (operator layout or sqlite)."""
    target = getattr(args, "init_target", None)
    if target == "sqlite":
        return cmd_init_sqlite(args=args)
    return cmd_init_operator(args=args)


__all__ = ["cmd_init", "cmd_init_operator", "cmd_init_sqlite"]
