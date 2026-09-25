"""secrets_kit.uninstall_state: read-only inventory of preserved client state.

Names identify standard locations, not exclusive ownership or deletion authority.
Never read file contents, enumerate Keychain, descend into custom directories, or
follow links. The uninstaller uses this inventory for its explicit dry-run report.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

STANDARD_STATE = {
    ".config/seckit": frozenset({
        "seckit.sqlite", "seckit.sqlite-wal", "seckit.sqlite-shm",
        "sqlite-storage.key", "node-identity.key", "config.json", "defaults.json",
        "registry.json", "install.json", "rss-client.json", "rss-auth-key.json",
        "rss-checkout.json", "rss-provisioning.json", "rss-enrollment-token",
    }),
    ".local/share/seckit/state": frozenset({"runtime-path", "runtime.json", "install.log"}),
}


def preserved_state_inventory(*, home: Path) -> list[dict[str, str]]:
    """Report standard and unknown paths without acquiring deletion authority.

    Open each directory component relative to its already-open parent, refusing
    symlinks and unsafe ownership/permissions. Uninspectable roots are reported
    as preserved, never silently interpreted as empty. Results contain no values.
    """
    result: list[dict[str, str]] = []
    for relative, names in STANDARD_STATE.items():
        descriptor = None
        try:
            descriptor = os.open(home, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            for component in Path(relative).parts:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
                info = os.fstat(descriptor)
                if info.st_uid != os.getuid() or info.st_mode & 0o022:
                    raise PermissionError
            for name in sorted(os.listdir(descriptor)):
                info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                classification = "unknown"
                if name in names:
                    classification = "standard"
                    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                            or info.st_uid != os.getuid() or info.st_mode & 0o022):
                        classification = "unsafe_standard"
                result.append({"path": str(home / relative / name), "classification": classification})
        except FileNotFoundError:
            # A disappearing entry is not proof the entire directory is empty.
            result.append({"path": str(home / relative), "classification": "absent_or_changed"})
        except OSError:
            result.append({"path": str(home / relative), "classification": "uninspectable"})
        finally:
            if descriptor is not None:
                os.close(descriptor)
    return result
