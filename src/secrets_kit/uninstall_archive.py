"""secrets_kit.uninstall_archive: explicit, sensitive standard-path exit backups.

Archive only regular same-user files under enumerated client state paths. Refuse
symbolic links, hard-linked files and concurrent content changes. This is not an encrypted or sanitized export.
The caller stops the client before calling; other writers must also be stopped.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import tarfile
from pathlib import Path

from secrets_kit.exporters import write_protected_export

MAX_ARCHIVE_BYTES = 128 * 1024 * 1024


def create_state_archive(*, home: Path, destination: Path) -> None:
    """Write a new 0600 tar.gz with checksums; never delete or alter input files.

    Standard configuration, state, and transport identity are included. Custom
    datastore paths, Keychain items and external logs are deliberately excluded.
    Refuse inputs above 128 MiB rather than allocate unbounded process memory.
    """
    from secrets_kit.uninstall import _check_path

    roots = [home / ".config/seckit", home / ".local/share/seckit/state",
             home / ".local/share/seckit/runtime/libp2p-identity.key"]
    destination = destination.expanduser().absolute()
    protected_roots = [*roots, home / ".local/share/seckit/runtime"]
    if any(destination == root or destination.is_relative_to(root) for root in protected_roots):
        raise ValueError("archive_destination_inside_state")
    files: list[Path] = []
    for root in roots:
        _check_path(path=root, home=home)
        if not root.exists():
            continue
        candidates = [root]
        if root.is_dir():
            for directory, dirs, names in os.walk(root, followlinks=False):
                for name in dirs + names:
                    path = Path(directory) / name
                    _check_path(path=path, home=home)
                    if path.is_file():
                        candidates.append(path)
                    elif not path.is_dir():
                        raise ValueError("archive_unsupported_file")
        for path in candidates:
            if path.is_file():
                files.append(path)
    manifest = {}
    payload = io.BytesIO()
    total = 0
    with tarfile.open(fileobj=payload, mode="w:gz") as archive:
        for path in sorted(files):
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(descriptor, "rb") as stream:
                before = os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_nlink != 1:
                    raise ValueError("archive_unsafe_file")
                total += before.st_size
                if total > MAX_ARCHIVE_BYTES:
                    raise ValueError("archive_size_limit")
                data = stream.read(MAX_ARCHIVE_BYTES - total + before.st_size + 1)
                after = os.fstat(stream.fileno())
                if len(data) != before.st_size or before.st_mtime_ns != after.st_mtime_ns or before.st_ctime_ns != after.st_ctime_ns:
                    raise ValueError("archive_input_changed")
            name = str(path.relative_to(home))
            manifest[name] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o600
            archive.addfile(info, io.BytesIO(data))
        data = json.dumps({"schema": 1, "files": manifest}, sort_keys=True).encode()
        info = tarfile.TarInfo("manifest.json")
        info.size = len(data)
        info.mode = 0o600
        archive.addfile(info, io.BytesIO(data))
    write_protected_export(destination=destination, payload=payload.getvalue())
