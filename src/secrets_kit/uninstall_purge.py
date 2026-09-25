"""secrets_kit.uninstall_purge: explicitly selected, same-user exit deletion.

Never infer ownership from an inventory or recursively delete customer state.
Only exact standard filenames and individually named Keychain items are accepted.
The caller must stop writers and finish any requested backup before execution.
Each retry is a new explicit authorization; missing selected files are harmless.
"""

from __future__ import annotations

import os
import stat
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from secrets_kit.uninstall import UninstallError, _check_path
from secrets_kit.uninstall_state import STANDARD_STATE


@contextmanager
def _parent(*, home: Path, path: Path) -> Iterator[int]:
    """Open a verified directory chain without following substituted symlinks."""
    descriptor = os.open(home, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in path.parent.relative_to(home).parts:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            info = os.fstat(descriptor)
            if info.st_uid != os.getuid() or info.st_mode & 0o022:
                raise UninstallError("purge_unsafe_directory")
        yield descriptor
    finally:
        os.close(descriptor)


def _identity(info: os.stat_result) -> tuple[int, ...]:
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_mode & 0o022:
        raise UninstallError("purge_unsafe_file")
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_mode)


def prepare_purge(*, home: Path, files: list[str], keychain: list[list[str]]) -> dict:
    """Validate exact selections, without reading values or deleting anything.

    SQLite sidecars must be selected with their database when they exist. Custom
    files, directory selection, wildcards, and whole-Keychain deletion are refused.
    """
    if not files and not keychain:
        raise UninstallError("purge_requires_named_selection")
    allowed = {home / root / name for root, names in STANDARD_STATE.items() for name in names}
    allowed.add(home / ".local/share/seckit/runtime/libp2p-identity.key")
    paths = sorted({Path(value).expanduser().absolute() for value in files})
    snapshots = {}
    for path in paths:
        if path not in allowed or ".." in path.parts:
            raise UninstallError("purge_unknown_or_custom_path")
        try:
            with _parent(home=home, path=path) as descriptor:
                snapshots[path] = _identity(os.stat(path.name, dir_fd=descriptor, follow_symlinks=False))
        except FileNotFoundError:
            snapshots[path] = None
    database = home / ".config/seckit/seckit.sqlite"
    family = {database, Path(str(database) + "-wal"), Path(str(database) + "-shm")}
    if family.intersection(paths):
        for path in family.difference(paths):
            if path.exists() or path.is_symlink():
                raise UninstallError("purge_select_complete_sqlite_family")
    selections = []
    for item in keychain:
        if sys.platform != "darwin" or len(item) != 4 or any(not value or "\x00" in value for value in item):
            raise UninstallError("purge_invalid_keychain_selection")
        target = Path(item[0]).expanduser().absolute()
        _check_path(path=target, home=home)
        _identity(target.lstat())
        selection = (str(target), *item[1:])
        if selection not in selections:
            selections.append(selection)
    return {"files": snapshots, "keychain": selections}


def execute_purge(*, home: Path, plan: dict) -> None:
    """Delete only preflighted selections; fail before runtime removal on error.

    No erase guarantee is made for SSDs or backups. Keychain provider output is
    never returned. Partial deletion is possible; a retry needs a fresh dry-run.
    """
    from secrets_kit.backends.keychain.security_cli import SecurityCliStore

    # Check every file again before the first deletion, including absent targets.
    refreshed = prepare_purge(home=home, files=[str(path) for path in plan["files"]], keychain=plan["keychain"])
    if refreshed != plan:
        raise UninstallError("purge_state_changed")
    for target, service, account, name in plan["keychain"]:
        try:
            store = SecurityCliStore(path=target)
            if store.exists(service=service, account=account, name=name):
                store.delete(service=service, account=account, name=name)
                if store.exists(service=service, account=account, name=name):
                    raise UninstallError("purge_keychain_delete_unverified")
        except (OSError, RuntimeError, ValueError):
            raise UninstallError("purge_keychain_operation_failed") from None
    for path, expected in plan["files"].items():
        if expected is None:
            continue
        with _parent(home=home, path=path) as descriptor:
            if _identity(os.stat(path.name, dir_fd=descriptor, follow_symlinks=False)) != expected:
                raise UninstallError("purge_state_changed")
            os.unlink(path.name, dir_fd=descriptor)
            os.fsync(descriptor)
