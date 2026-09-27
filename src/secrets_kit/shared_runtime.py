"""Administrator-owned shared runtime activation and user registration.

Only executable code is shared. Every registered account keeps its own store,
keys, node identity, daemon, and RSS device credential in its home directory.
"""

from __future__ import annotations

import fcntl
import json
import os
import plistlib
import pwd
import shlex
import sqlite3
import stat
import subprocess
import sys
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from secrets_kit.host_context import HOST_MEMBERSHIP_KEY, host_context_path, load_host_context

USERS_RELATIVE_PATH = Path("config/users.json")


class SharedRuntimeError(RuntimeError):
    """A shared activation or registered user check failed closed."""


def _require_admin_prefix(prefix: Path) -> None:
    if os.geteuid() != 0:
        raise PermissionError("shared runtime management requires root")
    host_context_path(prefix)
    current = Path("/")
    for part in prefix.parts[1:]:
        current = current / part
        info = current.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise PermissionError(f"unsafe shared runtime path component: {current}")
    load_host_context(prefix)


@contextmanager
def _locked_config(prefix: Path) -> Iterator[None]:
    lock_path = prefix / "config/.users.lock"
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise PermissionError("unsafe shared user-registry lock")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _registered_users(prefix: Path) -> list[str]:
    path = prefix / USERS_RELATIVE_PATH
    if not path.exists() and not path.is_symlink():
        return []
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise PermissionError("unsafe shared user registry")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise SharedRuntimeError("unsupported shared user registry")
    users = payload.get("users")
    if not isinstance(users, list) or any(not isinstance(user, str) for user in users):
        raise SharedRuntimeError("invalid shared user registry")
    if users != sorted(set(users)):
        raise SharedRuntimeError("shared user registry must be unique and sorted")
    return users


def _write_users(prefix: Path, users: list[str]) -> None:
    path = prefix / USERS_RELATIVE_PATH
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump({"version": 1, "users": sorted(users)}, output, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _user_membership(prefix: Path, username: str) -> dict[str, object]:
    account = pwd.getpwnam(username)
    if account.pw_uid == 0:
        raise SharedRuntimeError("root may not join a shared Secrets Kit installation")
    home = Path(account.pw_dir)
    config = home / ".config/seckit"
    database = config / "seckit.sqlite"
    for path, directory in ((config, True), (database, False)):
        info = path.lstat()
        kind_ok = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
        if not kind_ok or info.st_uid != account.pw_uid or info.st_mode & 0o077:
            raise PermissionError(f"unsafe per-user Secrets Kit path for {username}")
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    try:
        connection.execute("PRAGMA query_only=ON")
        row = connection.execute(
            "SELECT metadata_value FROM datastore_metadata WHERE metadata_key=?",
            (HOST_MEMBERSHIP_KEY,),
        ).fetchone()
    finally:
        connection.close()
    if row is None:
        raise SharedRuntimeError(f"{username} has not explicitly joined the shared host")
    membership = json.loads(row[0])
    context = load_host_context(prefix)
    if (
        not isinstance(membership, dict)
        or membership.get("installation_id") != context.installation_id
        or membership.get("environment") != context.environment
        or membership.get("unix_username") != username
        or membership.get("organization_id") != context.organization_id
        or membership.get("client_id") != context.client_id
    ):
        raise SharedRuntimeError(f"{username} is bound to another host context")
    return membership


def _service_uses_shared_launcher(prefix: Path, username: str) -> None:
    home = Path(pwd.getpwnam(username).pw_dir)
    launcher = str(prefix / "bin/seckit")
    if sys.platform == "darwin":
        definition = home / "Library/LaunchAgents/net.unixwzrd.secrets-kit.daemon.plist"
        info = definition.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != pwd.getpwnam(username).pw_uid or info.st_mode & 0o022:
            raise SharedRuntimeError(f"{username} has no safe managed daemon definition")
        arguments = plistlib.loads(definition.read_bytes()).get("ProgramArguments")
    else:
        definition = home / ".config/systemd/user/secrets-kit-daemon.service"
        info = definition.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != pwd.getpwnam(username).pw_uid or info.st_mode & 0o022:
            raise SharedRuntimeError(f"{username} has no safe managed daemon definition")
        lines = definition.read_text(encoding="utf-8").splitlines()
        commands = [line.partition("=")[2] for line in lines if line.startswith("ExecStart=")]
        arguments = shlex.split(commands[0]) if len(commands) == 1 else None
    if arguments != [launcher, "daemon", "run"]:
        raise SharedRuntimeError(f"{username}'s daemon does not use the shared launcher")


def register_shared_user(*, prefix: Path, username: str) -> list[str]:
    """Register a user only after explicit join and managed service install."""
    _require_admin_prefix(prefix)
    with _locked_config(prefix):
        _user_membership(prefix, username)
        _service_uses_shared_launcher(prefix, username)
        users = _registered_users(prefix)
        if username not in users:
            users.append(username)
            users.sort()
            _write_users(prefix, users)
        return users


def _generation_path(prefix: Path, name: str) -> Path:
    if not name.startswith("runtime-") or Path(name).name != name:
        raise ValueError("generation must be one runtime-* directory name")
    generation = prefix / "runtime" / name
    info = generation.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise PermissionError("generation must be a root-owned, non-writable directory")
    executable = generation / "bin/seckit"
    if not executable.is_file() or executable.is_symlink() or not os.access(executable, os.X_OK):
        raise SharedRuntimeError("generation has no executable Secrets Kit CLI")
    marker = generation / "seckit-environment"
    marker_info = marker.lstat()
    if not stat.S_ISREG(marker_info.st_mode) or marker_info.st_uid != 0 or marker_info.st_mode & 0o022:
        raise SharedRuntimeError("generation has no safe environment marker")
    if marker.read_text(encoding="utf-8").strip() != load_host_context(prefix).environment:
        raise SharedRuntimeError("generation environment does not match host context")
    return generation


def _user_command(username: str, command: list[str]) -> str:
    account = pwd.getpwnam(username)
    variables: list[str] = []
    if sys.platform == "linux":
        variables = [
            f"XDG_RUNTIME_DIR=/run/user/{account.pw_uid}",
            f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{account.pw_uid}/bus",
        ]
    shell_command = " ".join(shlex.quote(item) for item in ["/usr/bin/env", *variables, *command])
    result = subprocess.run(
        ["/usr/bin/su", "-l", username, "-c", shell_command],
        capture_output=True, text=True, timeout=60, check=False,
    )
    if result.returncode != 0:
        raise SharedRuntimeError(f"{username}: {command[-2:]} failed (exit {result.returncode})")
    return result.stdout.strip()


def _switch_current(prefix: Path, generation: Path | None) -> None:
    runtime = prefix / "runtime"
    current = runtime / "current"
    temporary = runtime / f".current.{uuid.uuid4().hex}.tmp"
    if generation is None:
        current.unlink(missing_ok=True)
        return
    os.symlink(str(generation), temporary)
    try:
        os.replace(temporary, current)
    finally:
        temporary.unlink(missing_ok=True)


def activate_shared_generation(*, prefix: Path, generation_name: str) -> dict[str, object]:
    """Switch once, restart registered daemons in order, and roll back on failure."""
    _require_admin_prefix(prefix)
    with _locked_config(prefix):
        generation = _generation_path(prefix, generation_name)
        current = prefix / "runtime/current"
        if current.exists() and not current.is_symlink():
            raise SharedRuntimeError("current runtime must be a managed symbolic link")
        previous = current.resolve(strict=True) if current.is_symlink() else None
        if previous is not None:
            if previous != _generation_path(prefix, previous.name).resolve(strict=True):
                raise SharedRuntimeError("current runtime points outside the managed generation directory")
        users = _registered_users(prefix)
        for username in users:
            _user_membership(prefix, username)
            _service_uses_shared_launcher(prefix, username)
        expected = subprocess.run(
            [str(generation / "bin/seckit"), "--version"],
            capture_output=True, text=True, timeout=15, check=False,
        )
        if expected.returncode != 0 or not expected.stdout.strip():
            raise SharedRuntimeError("candidate generation version check failed")
        if previous == generation:
            return {"generation": generation.name, "version": expected.stdout.strip(), "users": users, "changed": False}
        _switch_current(prefix, generation)
        completed: list[str] = []
        try:
            for username in users:
                _user_command(username, [str(prefix / "bin/seckit"), "daemon", "restart"])
                _user_command(username, [str(prefix / "bin/seckit"), "daemon", "service", "status"])
                observed = _user_command(username, [str(prefix / "bin/seckit"), "--version"])
                if observed != expected.stdout.strip():
                    raise SharedRuntimeError(f"{username}: installed version does not match the candidate")
                completed.append(username)
        except (OSError, subprocess.TimeoutExpired, SharedRuntimeError) as exc:
            _switch_current(prefix, previous)
            failures: list[str] = []
            for rollback_user in [*completed, username]:
                try:
                    _user_command(rollback_user, [str(prefix / "bin/seckit"), "daemon", "restart"])
                except (OSError, subprocess.TimeoutExpired, SharedRuntimeError):
                    failures.append(rollback_user)
            raise SharedRuntimeError(
                f"shared activation failed at {username}; previous code restored; rollback restart failures: {failures}"
            ) from exc
        return {"generation": generation.name, "version": expected.stdout.strip(), "users": users, "changed": True}


__all__ = ["SharedRuntimeError", "activate_shared_generation", "register_shared_user"]
