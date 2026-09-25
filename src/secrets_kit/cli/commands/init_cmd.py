"""
secrets_kit.cli.commands.init_cmd

Initialize customer configuration and encrypted SQLite storage by default.
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path
from typing import List, Optional

from secrets_kit.backends.common import (
    BACKEND_KEYCHAIN,
    BACKEND_SQLITE,
    BackendError,
    normalize_backend,
)
from secrets_kit.backends.sqlite import SQLiteBackendError, sqlite_path
from secrets_kit.backends.sqlite.node_identity import ensure_sqlite_node_identity
from secrets_kit.backends.sqlite.provisioning import provision_sqlite_datastore
from secrets_kit.backends.sqlite.schema import SCHEMA_VERSION
from secrets_kit.backends.sqlite.storage_mode import (
    SQLITE_STORAGE_MODE_ENCRYPTED,
    read_sqlite_storage_mode,
)
from secrets_kit.backends.sqlite.validation import validate_sqlite_datastore
from secrets_kit.cli.io import _confirm, _fatal
from secrets_kit.cli.operator_defaults import initial_operator_defaults
from secrets_kit.crypto.storage.sqlite import ensure_sqlite_storage_key
from secrets_kit.locale import msg
from secrets_kit.models import ValidationError
from secrets_kit.registry import (
    RegistryError,
    defaults_path,
    ensure_defaults_storage,
    ensure_registry_storage,
    load_catalog,
    load_defaults,
    registry_path,
    save_defaults,
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
            catalog = load_catalog(home=home)
            if catalog.schemas:
                lines.append(f"{rpath} ({len(catalog.schemas)} schemas)")
            else:
                lines.append(str(rpath))
        except RegistryError:
            lines.append(str(rpath))
    spath = sqlite_path(home=home)
    if spath.exists():
        lines.append(str(spath))
    return lines


def _existing_sqlite_target(*, home: Path | None = None) -> Optional[str]:
    spath = sqlite_path(home=home)
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


def _storage_mode_arg(*, args: argparse.Namespace) -> str:
    """Select storage only for initialization, never as an application mode."""
    if getattr(args, "unsafe_plaintext_storage", False):
        print(msg("errors.init.plaintext_development_only"), file=sys.stderr)
        return "plaintext"
    if getattr(args, "storage_mode", None) not in (None, SQLITE_STORAGE_MODE_ENCRYPTED):
        raise SQLiteBackendError(msg("errors.init.plaintext_development_only"))
    return SQLITE_STORAGE_MODE_ENCRYPTED


def _existing_sqlite_storage_mode(*, home: Optional[Path]) -> str | None:
    path = sqlite_path(home=home)
    if not path.exists():
        return None
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        return read_sqlite_storage_mode(conn=conn)
    finally:
        conn.close()


def _operator_init_storage_mode(*, args: argparse.Namespace, home: Optional[Path]) -> str:
    mode = _storage_mode_arg(args=args)
    existing = _existing_sqlite_storage_mode(home=home)
    if existing is not None and existing != mode:
        raise SQLiteBackendError(
            "SQLite storage mode mismatch: "
            f"database={existing}; requested={mode}; "
            "storage mode is immutable for the lifetime of the datastore"
        )
    return mode


def _provision_operator_store(
    *,
    payload: dict[str, object],
    home: Optional[Path],
) -> None:
    """Provision defaults and registry files."""
    save_defaults(payload=payload, home=home)
    ensure_registry_storage(home=home)


def _seed_operator_store(*, backend: str, home: Optional[Path], strict: bool = False) -> None:
    """Seed schema and taxonomy catalog data after required backends exist."""
    try:
        merge_seed_files_into_store(
            backend=backend,
            allow_replace=False,
            home=home,
        )
    except (BackendError, OSError) as exc:
        if strict:
            raise
        print(f"warning: metadata schema registry seed skipped ({exc})", file=sys.stderr)
    try:
        merge_seed_files_into_taxonomy_store(
            backend=backend,
            home=home,
        )
    except (BackendError, OSError, ValidationError) as exc:
        if strict:
            raise
        print(f"warning: taxonomy registry seed skipped ({exc})", file=sys.stderr)


def _provision_sqlite_storage_key(*, home: Optional[Path], storage_mode: str) -> None:
    """Provision the local SQLite storage key."""
    if storage_mode != SQLITE_STORAGE_MODE_ENCRYPTED:
        return
    ensure_sqlite_storage_key(home=home)


def _provision_sqlite_datastore(
    *, home: Optional[Path], storage_mode: str
) -> tuple[sqlite3.Connection, int]:
    """Provision the SQLite datastore schema and return the open connection."""
    conn = provision_sqlite_datastore(
        path=sqlite_path(home=home),
        storage_mode=storage_mode,
    )
    user_version = conn.execute("PRAGMA user_version").fetchone()[0]
    return conn, int(user_version)


def _provision_sqlite_node_identity(
    *,
    conn: sqlite3.Connection,
    home: Optional[Path],
    replace: bool = False,
) -> None:
    """Provision the local node identity material and SQLite public projection."""
    ensure_sqlite_node_identity(conn=conn, home=home, replace=replace)


def _validate_sqlite_installation(*, home: Optional[Path]) -> None:
    """Validate the complete SQLite operator-store installation."""
    conn = sqlite3.connect(sqlite_path(home=home))
    conn.row_factory = sqlite3.Row
    configured_mode = load_defaults(home=home).get("sqlite_storage_mode")
    try:
        validate_sqlite_datastore(
            conn=conn,
            home=home,
            sqlite_db_path=sqlite_path(home=home),
            configured_storage_mode=configured_mode,
        )
    finally:
        conn.close()


def cmd_init_operator(*, args: argparse.Namespace) -> int:
    """Reset defaults.json and registry.json to a fresh operator layout."""
    home = _home_path(args)
    try:
        targets = _existing_init_targets(home=home)
        if not _require_init_confirmation(args=args, targets=targets, scope="operator"):
            print(msg("cli.common.aborted"))
            return 1
        backend_arg = getattr(args, "backend", None)
        selected_backend = normalize_backend(backend_arg) if backend_arg else None
        storage_mode = (
            _operator_init_storage_mode(args=args, home=home)
            if selected_backend == BACKEND_SQLITE
            else None
        )
        payload = initial_operator_defaults(
            backend=backend_arg,
            sqlite_storage_mode=storage_mode,
        )
        backend = normalize_backend(str(payload.get("backend", BACKEND_KEYCHAIN)))
        if backend == BACKEND_SQLITE and storage_mode is None:
            storage_mode = _operator_init_storage_mode(args=args, home=home)
            payload["sqlite_storage_mode"] = storage_mode
        _provision_operator_store(payload=payload, home=home)
        if backend == BACKEND_SQLITE:
            _provision_sqlite_storage_key(home=home, storage_mode=storage_mode)
            conn, _user_version = _provision_sqlite_datastore(
                home=home,
                storage_mode=storage_mode,
            )
            try:
                _provision_sqlite_node_identity(conn=conn, home=home)
            finally:
                conn.close()
        _seed_operator_store(backend=backend, home=home)
        if backend == BACKEND_SQLITE:
            _validate_sqlite_installation(home=home)
        print(
            msg(
                "cli.init.operator.done",
                backend=backend,
                defaults_path=str(defaults_path(home=home)),
                registry_path=str(registry_path(home=home)),
            )
        )
        if backend == BACKEND_SQLITE:
            print(msg("cli.init.storage_mode.selected", storage_mode=storage_mode))
        return 0
    except (BackendError, SQLiteBackendError, RegistryError, ValidationError, OSError) as exc:
        return _fatal(message=str(exc), code=1)


def cmd_init_sqlite(*, args: argparse.Namespace) -> int:
    """Recreate SQLite with encrypted storage unless explicitly unsafe."""
    try:
        home = _home_path(args)
        storage_mode = _storage_mode_arg(args=args)
        target = _existing_sqlite_target(home=home)
        targets = [target] if target else []
        if not _require_init_confirmation(args=args, targets=targets, scope="sqlite"):
            print(msg("cli.common.aborted"))
            return 1
        spath = sqlite_path(home=home)
        replace_identity = spath.exists()
        if spath.exists():
            spath.unlink()
        ensure_defaults_storage(home=home)
        ensure_registry_storage(home=home)
        defaults = load_defaults(home=home)
        defaults["backend"] = BACKEND_SQLITE
        defaults["sqlite_storage_mode"] = storage_mode
        save_defaults(payload=defaults, home=home)
        _provision_sqlite_storage_key(home=home, storage_mode=storage_mode)
        conn, user_version = _provision_sqlite_datastore(
            home=home,
            storage_mode=storage_mode,
        )
        try:
            _provision_sqlite_node_identity(
                conn=conn,
                home=home,
                replace=replace_identity,
            )
        finally:
            conn.close()
        try:
            _seed_operator_store(backend="sqlite", home=home, strict=True)
        except (BackendError, SQLiteBackendError, ValidationError, OSError) as exc:
            return _fatal(message=str(exc), code=1)
        _validate_sqlite_installation(home=home)
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
