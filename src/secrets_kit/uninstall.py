"""
secrets_kit.uninstall

Remove receipt-verified dedicated client runtimes while preserving all user data.

Only the standard per-user installer layout is supported. Unknown installations,
changed files, unsafe ownership and permissions fail closed before service removal.
Receipts are local ownership records, not signatures or a defense against the owner.

Bash and Zsh startup files are not deleted. When a profile contains the exact
three-line block ``install.sh`` writes for ``HOME/.local/bin``, that block alone
is removed after the dry-run plan is checked again. Unrelated lines stay, and
the file mode stays. Symlinks, foreign owners, and edited, duplicate, or
malformed marker blocks fail closed with no profile write.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import plistlib
import re
import shutil
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any

RECEIPT = ".seckit-install-receipt.json"
REMOVAL_RECEIPT = ".seckit-removal-receipt.json"
GENERATION = re.compile(r"runtime-[0-9]+-[0-9]+\Z")
# install.sh detect_shell_profile writes one of these; uninstall scans each
# because the uninstalling shell may differ from the installing shell.
_SHELL_PROFILES = (".bashrc", ".bash_profile", ".zshrc")
_PROFILE_BEGIN = "# >>> seckit path >>>"
_PROFILE_END = "# <<< seckit path <<<"


class UninstallError(ValueError):
    """Reject an unsafe or unsupported removal without printing file contents."""


def _check_path(*, path: Path, home: Path) -> None:
    """Reject linked, non-owner or writable ancestors below the explicit home."""
    if not path.is_relative_to(home) or path == home:
        raise UninstallError("unsupported_path")
    for parent in reversed((path, *path.parents)):
        if parent == home or not parent.is_relative_to(home):
            continue
        if parent.is_symlink():
            raise UninstallError("symlink_path")
        if parent.exists():
            info = parent.stat()
            if info.st_uid != os.getuid() or info.st_mode & 0o022:
                raise UninstallError("unsafe_ownership_or_permissions")


def _snapshot(*, root: Path) -> dict[str, Any]:
    """Inventory types, permissions, links and hashes without following links."""
    entries: dict[str, Any] = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in sorted(dirs + files):
            path = Path(directory) / name
            relative = str(path.relative_to(root))
            if relative in {RECEIPT, REMOVAL_RECEIPT}:
                continue
            info = path.lstat()
            if info.st_uid != os.getuid():
                raise UninstallError("foreign_owned_runtime_entry")
            mode = stat.S_IMODE(info.st_mode)
            if stat.S_ISLNK(info.st_mode):
                entries[relative] = ["link", os.readlink(path)]
            elif mode & 0o022:
                raise UninstallError("writable_runtime_entry")
            elif stat.S_ISDIR(info.st_mode):
                entries[relative] = ["directory", mode]
            elif stat.S_ISREG(info.st_mode):
                with path.open("rb") as stream:
                    digest = hashlib.file_digest(stream, "sha256").hexdigest()
                entries[relative] = ["file", mode, digest]
            else:
                raise UninstallError("unexpected_runtime_entry")
    return entries


def record_installation(*, runtime: Path) -> None:
    """Seal a newly installed standard runtime; never adopt a legacy runtime."""
    home = Path.home().absolute()
    if (runtime / REMOVAL_RECEIPT).exists() or (runtime / REMOVAL_RECEIPT).is_symlink():
        raise UninstallError("removal_in_progress")
    root = home / ".local/share/seckit/runtime"
    _check_path(path=runtime, home=home)
    if runtime.parent != root or not GENERATION.fullmatch(runtime.name):
        raise UninstallError("unsupported_runtime_layout")
    if not (runtime / "pyvenv.cfg").is_file():
        raise UninstallError("not_dedicated_venv")
    # uv creates a writable advisory lock even under a restrictive umask.
    # Harden only this known freshly created regular file, never linked targets.
    lock = runtime / ".lock"
    if lock.exists() or lock.is_symlink():
        info = lock.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise UninstallError("unsafe_uv_lock")
        lock.chmod(0o600, follow_symlinks=False)
    payload = {"schema": 1, "entries": _snapshot(root=runtime), "launchers": {}}
    for name in ("seckit", "seckit-mcp"):
        path = home / ".local/bin" / name
        _check_path(path=path, home=home)
        payload["launchers"][name] = hashlib.sha256(path.read_bytes()).hexdigest()
    destination = runtime / RECEIPT
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(payload, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())


def removal_plan() -> dict[str, Any]:
    """Validate the complete runtime inventory before returning a value-free plan."""
    if os.getuid() == 0:
        raise UninstallError("run_as_installing_user_not_root")
    # An overridden daemon namespace could stop a different client; do not infer it.
    overrides = [name for name in os.environ if name.startswith("SECKIT_") and name != "SECKIT_LANGUAGE"]
    if overrides:
        raise UninstallError("unset_seckit_overrides_before_uninstall")
    home = Path.home().absolute()
    root = home / ".local/share/seckit/runtime"
    _check_path(path=root, home=home)
    generations: list[Path] = []
    links: list[Path] = []
    launcher_hashes: dict[str, set[str]] = {"seckit": set(), "seckit-mcp": set()}
    for path in sorted(root.iterdir()) if root.exists() else []:
        # The daemon shares this parent with installed venv generations. These
        # are state/IPC, not packages: preserve identities and never rmtree them.
        if path.name in {"seckitd.json", "seckitd.sock", "seckitd.start.lock", "libp2p-identity.key"}:
            _check_path(path=path, home=home)
            info = path.lstat()
            expected_type = stat.S_ISSOCK if path.name == "seckitd.sock" else stat.S_ISREG
            if not expected_type(info.st_mode):
                raise UninstallError("unexpected_daemon_state_type")
            continue
        if path.name in {"current", "previous"} and path.is_symlink():
            target = path.resolve(strict=True)
            if target.parent != root or not GENERATION.fullmatch(target.name):
                raise UninstallError("runtime_link_outside_installation")
            links.append(path)
            continue
        if not GENERATION.fullmatch(path.name) or not path.is_dir():
            raise UninstallError("unknown_runtime_layout")
        _check_path(path=path, home=home)
        # A crash after removing the final receipt can leave only an empty
        # directory. No recursive adoption is allowed in this narrow case.
        if not any(path.iterdir()):
            generations.append(path)
            continue
        receipt = path / RECEIPT
        resuming = (path / REMOVAL_RECEIPT).exists() or (path / REMOVAL_RECEIPT).is_symlink()
        if resuming:
            if receipt.exists():
                raise UninstallError("ambiguous_removal_receipt")
            receipt = path / REMOVAL_RECEIPT
        _check_path(path=receipt, home=home)
        if not receipt.is_file() or stat.S_IMODE(receipt.stat().st_mode) != 0o600:
            raise UninstallError("missing_or_unsafe_install_receipt")
        data = json.loads(receipt.read_text())
        current = _snapshot(root=path)
        expected = data.get("entries", {})
        valid = current == expected
        if resuming and isinstance(expected, dict):
            valid = all(name in expected and entry == expected[name] for name, entry in current.items())
        if data.get("schema") != 1 or not valid:
            raise UninstallError("runtime_changed_since_installation")
        for name in launcher_hashes:
            launcher_hashes[name].add(data["launchers"][name])
        generations.append(path)
    launchers: list[Path] = []
    for name, accepted in launcher_hashes.items():
        path = home / ".local/bin" / name
        _check_path(path=path, home=home)
        if path.exists():
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() not in accepted:
                raise UninstallError("unknown_or_modified_launcher")
            launchers.append(path)
    from secrets_kit.daemon.service import service_definition_path

    definition = service_definition_path()
    _check_path(path=definition, home=home)
    if definition.exists():
        if not generations:
            raise UninstallError("service_without_verified_runtime")
        launcher = str(home / ".local/bin/seckit")
        if sys.platform == "darwin":
            from secrets_kit.daemon.service import _launchd_payload

            data = plistlib.loads(definition.read_bytes())
            expected = plistlib.loads(_launchd_payload(Path(launcher), home=home))
            if data != expected:
                raise UninstallError("unexpected_service_definition")
        else:
            from secrets_kit.daemon.service import _systemd_payload

            if definition.read_bytes() != _systemd_payload(Path(launcher)):
                raise UninstallError("unexpected_service_definition")
    return {
        "remove": [str(path) for path in (*links, *launchers, *generations)],
        "service": str(definition),
        "preserve": [str(home / ".config/seckit"), str(home / ".local/share/seckit/state"), str(root)],
        "preserve_other": ["datastores", "keychain", "identities", "exports", "uv", "shared_python", "shell_profiles"],
        "shell_profile_edits": _shell_profile_edits(home=home),
    }


def _profile_path_line(home: Path) -> str:
    """Return the export install.sh writes for the standard launcher directory."""
    return f'export PATH="{home / ".local/bin"}:$PATH"'


def _line_text(line: str) -> str:
    """Drop one trailing newline without treating other whitespace as disposable."""
    if line.endswith("\r\n"):
        return line[:-2]
    if line.endswith(("\n", "\r")):
        return line[:-1]
    return line


def _exact_block_start(lines: list[str], *, home: Path) -> int | None:
    """Return the single exact installer block, or None when no markers exist.

    Any other use of the marker text is rejected so unknown lines are not removed.
    """
    begins: list[int] = []
    ends: list[int] = []
    for index, line in enumerate(lines):
        text = _line_text(line)
        if _PROFILE_BEGIN not in text and _PROFILE_END not in text:
            continue
        if text == _PROFILE_BEGIN:
            begins.append(index)
        elif text == _PROFILE_END:
            ends.append(index)
        else:
            raise UninstallError("edited_shell_profile_block")
    if not begins and not ends:
        return None
    if len(begins) > 1 or len(ends) > 1:
        raise UninstallError("duplicate_shell_profile_block")
    if len(begins) != 1 or len(ends) != 1 or ends[0] != begins[0] + 2:
        raise UninstallError("malformed_shell_profile_block")
    if _line_text(lines[begins[0] + 1]) != _profile_path_line(home):
        raise UninstallError("edited_shell_profile_block")
    return begins[0]


def _read_regular_profile(path: Path) -> tuple[bytes, os.stat_result]:
    """Read a same-user regular profile without following a substituted link."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise UninstallError("symlink_shell_profile") from None
        raise UninstallError("unsafe_shell_profile") from None
    try:
        info = os.fstat(descriptor)
        if stat.S_ISLNK(info.st_mode):
            raise UninstallError("symlink_shell_profile")
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise UninstallError("unsafe_shell_profile")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks), info
    finally:
        os.close(descriptor)


def _inspect_shell_profile(path: Path, *, home: Path) -> bool:
    """Report whether this startup file still has the exact managed PATH block."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(info.st_mode):
        raise UninstallError("symlink_shell_profile")
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
        raise UninstallError("unsafe_shell_profile")
    raw, _ = _read_regular_profile(path)
    if _PROFILE_BEGIN.encode() not in raw and _PROFILE_END.encode() not in raw:
        return False
    try:
        lines = raw.decode("utf-8").splitlines(keepends=True)
    except UnicodeDecodeError:
        raise UninstallError("malformed_shell_profile_block") from None
    return _exact_block_start(lines, home=home) is not None


def _shell_profile_edits(*, home: Path) -> list[dict[str, str]]:
    """List standard profiles whose exact installer PATH block would be removed.

    The plan names files and the action only. Profile text is not copied into it.
    """
    edits: list[dict[str, str]] = []
    for name in _SHELL_PROFILES:
        path = home / name
        if _inspect_shell_profile(path, home=home):
            edits.append({"path": str(path), "action": "remove_managed_path_block"})
    return edits


def _profile_without_block(path: Path, *, home: Path) -> tuple[bytes, bytes, int]:
    """Return the original bytes, block-removed bytes, and mode for one profile."""
    raw, info = _read_regular_profile(path)
    try:
        lines = raw.decode("utf-8").splitlines(keepends=True)
    except UnicodeDecodeError:
        raise UninstallError("malformed_shell_profile_block") from None
    start = _exact_block_start(lines, home=home)
    if start is None:
        raise UninstallError("installation_changed_during_uninstall")
    del lines[start:start + 3]
    return raw, "".join(lines).encode("utf-8"), stat.S_IMODE(info.st_mode)


def _write_all(descriptor: int, payload: bytes) -> None:
    """Write every byte of a profile replacement."""
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise UninstallError("unsafe_shell_profile")
        view = view[written:]


def _atomic_replace(path: Path, payload: bytes, *, mode: int, previous: bytes) -> None:
    """Replace profile bytes if the file is still the checked regular file.

    A same-directory rename keeps the write off the live name until it is complete.
    The previous mode is restored on the replacement. Links are not followed.
    """
    current, info = _read_regular_profile(path)
    if current != previous or stat.S_IMODE(info.st_mode) != mode or info.st_uid != os.getuid():
        raise UninstallError("installation_changed_during_uninstall")
    temporary: Path | None = None
    descriptor = -1
    try:
        descriptor, name = tempfile.mkstemp(prefix=".seckit-profile.", dir=path.parent)
        temporary = Path(name)
        _write_all(descriptor, payload)
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.rename(temporary, path)
        temporary = None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _apply_shell_profile_edits(edits: list[dict[str, str]]) -> None:
    """Recheck every planned profile, then remove only its exact three-line block."""
    if not edits:
        return
    home = Path.home().absolute()
    if _shell_profile_edits(home=home) != edits:
        raise UninstallError("installation_changed_during_uninstall")
    prepared: list[tuple[Path, bytes, bytes, int]] = []
    for edit in edits:
        path = Path(edit["path"])
        if edit.get("action") != "remove_managed_path_block":
            raise UninstallError("installation_changed_during_uninstall")
        if path.parent != home or path.name not in _SHELL_PROFILES:
            raise UninstallError("unsafe_shell_profile")
        previous, payload, mode = _profile_without_block(path, home=home)
        prepared.append((path, previous, payload, mode))
    for path, previous, payload, mode in prepared:
        _atomic_replace(path, payload, mode=mode, previous=previous)


def _stop_runtime() -> None:
    """Stop same-user supervision and detached IPC before touching the runtime."""
    from secrets_kit.daemon.client import ping_daemon, stop_daemon
    from secrets_kit.daemon.service import service_status, uninstall_service

    uninstall_service()
    stop_daemon(timeout=30)
    if ping_daemon(timeout=0.5):
        raise UninstallError("daemon_still_running")
    if service_status()["active"]:
        raise UninstallError("service_still_active")


def uninstall(*, dry_run: bool = True, archive: Path | None = None,
              purge: bool = False, purge_files: list[str] | None = None,
              purge_keychain: list[list[str]] | None = None) -> dict[str, Any]:
    """Remove a verified runtime and the exact installer PATH block.

    State is deleted only with explicit purge selections. Dry-run performs no writes.
    Profile text is checked again immediately before the block is removed.
    """
    plan = removal_plan()
    selections = {"files": purge_files or [], "keychain": purge_keychain or []}
    if not purge and any(selections.values()):
        raise UninstallError("purge_selection_requires_purge")
    if purge:
        from secrets_kit.uninstall_purge import prepare_purge

        prepared = prepare_purge(home=Path.home().absolute(), **selections)
        plan["purge_files"] = [str(path) for path in prepared["files"]]
        plan["purge_keychain_count"] = len(prepared["keychain"])
    if archive is not None:
        plan["archive"] = str(archive.expanduser().absolute())
    if dry_run:
        from secrets_kit.uninstall_state import preserved_state_inventory

        return {"status": "dry_run", **plan,
                "preserved_state": preserved_state_inventory(home=Path.home().absolute())}
    if not plan["remove"] and not purge:
        if not plan["shell_profile_edits"]:
            return {"status": "already_removed", **plan}
        _apply_shell_profile_edits(plan["shell_profile_edits"])
        return {"status": "removed", **plan}
    if not shutil.rmtree.avoids_symlink_attacks:
        raise UninstallError("safe_recursive_removal_unavailable")
    from secrets_kit.cli.update_service import manage_update_service

    if manage_update_service(action="uninstall") not in {0}:
        raise UninstallError("update_check_service_unsafe")
    _stop_runtime()
    # Recheck after daemon shutdown; never delete a changed runtime or profile.
    if removal_plan() != {key: value for key, value in plan.items() if key not in {"archive", "purge_files", "purge_keychain_count"}}:
        raise UninstallError("installation_changed_during_uninstall")
    if purge:
        # Daemon shutdown may legitimately flush SQLite; snapshot only once quiet.
        prepared = prepare_purge(home=Path.home().absolute(), **selections)
    if archive is not None:
        from secrets_kit.uninstall_archive import create_state_archive

        create_state_archive(home=Path.home().absolute(), destination=archive)
    if purge:
        from secrets_kit.uninstall_purge import execute_purge

        execute_purge(home=Path.home().absolute(), plan=prepared)
    _apply_shell_profile_edits(plan["shell_profile_edits"])
    for value in plan["remove"]:
        path = Path(value)
        if path.is_symlink() or path.is_file():
            path.unlink()
        else:
            _remove_generation(path)
    return {"status": "removed", **plan}


def _remove_generation(path: Path) -> None:
    """Remove a verified inventory with a resumable receipt retained until last.

    Atomic receipt renaming records intent before any package entry is removed.
    A resumed plan allows missing entries, but rejects added or changed entries.
    Persistent data is outside this runtime generation and is never touched.
    """
    original = path / RECEIPT
    receipt = path / REMOVAL_RECEIPT
    if original.exists():
        original.rename(receipt)
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    entries = _snapshot(root=path)
    # Descend through the platform's fd-based, symlink-attack-resistant rmtree,
    # not pathname walks that could traverse a substituted intermediate link.
    for name in sorted(name for name in entries if "/" not in name):
        target = path / name
        if entries[name][0] == "directory":
            shutil.rmtree(target)
        else:
            target.unlink()
    if receipt.exists():
        receipt.unlink()
    path.rmdir()


def cmd_uninstall(*, args: argparse.Namespace) -> int:
    """Render a sanitized plan and require explicit confirmation for removal."""
    from secrets_kit.locale import msg

    if not args.dry_run and not args.yes:
        print(msg("cli.uninstall.confirm"), file=sys.stderr)
        return 64
    try:
        archive = getattr(args, "archive", None)
        if archive and not args.dry_run:
            print(msg("cli.uninstall.archive_warning"), file=sys.stderr)
        result = uninstall(dry_run=args.dry_run, archive=Path(archive) if archive else None,
                           purge=getattr(args, "purge", False),
                           purge_files=getattr(args, "purge_file", None),
                           purge_keychain=getattr(args, "purge_keychain", None))
    except UninstallError as exc:
        print(json.dumps({"status": "rejected", "reason": str(exc)}), file=sys.stderr)
        return 78
    except (OSError, ValueError, KeyError, TypeError, RuntimeError):
        # File contents, secret paths and service-manager output must not escape.
        print(msg("cli.uninstall.operation_failed"), file=sys.stderr)
        return 78
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    record_installation(runtime=Path(sys.argv[1]).absolute())
