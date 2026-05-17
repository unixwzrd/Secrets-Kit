"""Fail-fast ephemeral runtime namespace paths.

Runtime artifacts are sockets, pid files, locks, transient registries, and
coordination state. They must not silently fall back to persistent config or
application-data directories.
"""

from __future__ import annotations

import os
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


class RuntimePathError(RuntimeError):
    """Runtime namespace allocation or validation failed."""


RUNTIME_ENV = "SECKIT_RUNTIME_DIR"
INSTANCE_ENV = "SECKIT_RUNTIME_INSTANCE"
ALLOW_TMP_ENV = "SECKIT_RUNTIME_ALLOW_TMP"
DEFAULT_INSTANCE = "default"


@dataclass(frozen=True)
class RuntimeLayout:
    """Resolved per-user, per-instance runtime namespace."""

    root: Path
    instance: str

    @property
    def registry_path(self) -> Path:
        return self.root / "registry.json"

    @property
    def sockets_dir(self) -> Path:
        return self.root / "sockets"

    @property
    def pids_dir(self) -> Path:
        return self.root / "pids"

    @property
    def locks_dir(self) -> Path:
        return self.root / "locks"

    @property
    def logs_dir(self) -> Path:
        return self.root / "logs"

    def agent_socket_path(self, agent_id: str) -> Path:
        return self.sockets_dir / f"{_safe_component(agent_id)}.sock"

    def agent_pid_path(self, agent_id: str) -> Path:
        return self.pids_dir / f"{_safe_component(agent_id)}.pid"

    def agent_lock_path(self, agent_id: str) -> Path:
        return self.locks_dir / f"{_safe_component(agent_id)}.lock"


def runtime_instance(raw: str | None = None) -> str:
    """Return a safe runtime instance id."""
    val = (raw if raw is not None else os.environ.get(INSTANCE_ENV, DEFAULT_INSTANCE)).strip()
    return _safe_component(val or DEFAULT_INSTANCE)


def default_runtime_root(*, instance: str | None = None) -> Path:
    """Return the preferred ephemeral runtime root without creating it."""
    inst = runtime_instance(instance)
    override = os.environ.get(RUNTIME_ENV)
    if override and override.strip():
        base = Path(override).expanduser()
        if base.exists() and base.is_symlink():
            raise RuntimePathError(f"runtime override is a symlink: {base}")
        return base / inst
    if sys.platform == "darwin":
        base = Path(tempfile.gettempdir()).expanduser()
        if base.resolve() in (Path("/tmp"), Path("/private/tmp")) and os.environ.get(ALLOW_TMP_ENV) != "1":
            raise RuntimePathError(
                "macOS runtime directory resolved to /tmp; set SECKIT_RUNTIME_DIR or "
                "SECKIT_RUNTIME_ALLOW_TMP=1 for an explicit /tmp runtime namespace"
            )
        return base / "seckit" / str(os.geteuid()) / inst
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    if xdg and xdg.strip():
        return Path(xdg).expanduser() / "seckit" / inst
    run_user = Path("/run/user") / str(os.geteuid())
    if run_user.exists():
        return run_user / "seckit" / inst
    raise RuntimePathError(
        "no ephemeral runtime directory available; set SECKIT_RUNTIME_DIR or XDG_RUNTIME_DIR "
        f"for uid {os.geteuid()}"
    )


def runtime_layout(*, instance: str | None = None, create: bool = True) -> RuntimeLayout:
    """Resolve and optionally create a validated runtime layout."""
    root = default_runtime_root(instance=instance)
    layout = RuntimeLayout(root=root, instance=runtime_instance(instance))
    if create:
        ensure_runtime_layout(layout)
    return layout


def ensure_runtime_layout(layout: RuntimeLayout) -> None:
    """Create runtime directories and validate ownership/permissions."""
    for path in (layout.root, layout.sockets_dir, layout.pids_dir, layout.locks_dir, layout.logs_dir):
        ensure_runtime_dir(path)


def ensure_runtime_dir(path: Path) -> None:
    """Create ``path`` as an owner-only runtime directory and validate it."""
    _validate_parent_chain(path.parent)
    if path.exists() and path.is_symlink():
        raise RuntimePathError(f"runtime path is a symlink: {path}")
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    validate_runtime_dir(path)
    mode = path.stat().st_mode & 0o777
    if mode != 0o700:
        try:
            path.chmod(0o700)
        except OSError as exc:
            raise RuntimePathError(f"cannot chmod runtime directory {path} to 0700: {exc}") from exc
    validate_runtime_dir(path)


def validate_runtime_dir(path: Path) -> None:
    """Validate owner, symlink, directory, and unsafe parent semantics."""
    if path.is_symlink():
        raise RuntimePathError(f"runtime directory is a symlink: {path}")
    try:
        st = path.stat()
    except OSError as exc:
        raise RuntimePathError(f"cannot stat runtime directory {path}: {exc}") from exc
    if not stat.S_ISDIR(st.st_mode):
        raise RuntimePathError(f"runtime path is not a directory: {path}")
    if st.st_uid != os.geteuid():
        raise RuntimePathError(f"runtime directory {path} owner uid {st.st_uid} != effective uid {os.geteuid()}")
    if st.st_mode & 0o077:
        raise RuntimePathError(f"runtime directory {path} has unsafe mode {oct(st.st_mode & 0o777)}")
    _validate_parent_chain(path.parent)


def _validate_parent_chain(path: Path) -> None:
    """Reject unsafe world-writable parents after resolving platform symlinks."""
    try:
        cur = path.expanduser().resolve(strict=False)
    except OSError as exc:
        raise RuntimePathError(f"cannot resolve runtime parent {path}: {exc}") from exc
    seen: set[Path] = set()
    while True:
        if cur in seen:
            raise RuntimePathError(f"runtime parent loop while validating {path}")
        seen.add(cur)
        if cur.exists():
            st = cur.stat()
            if st.st_mode & stat.S_IWOTH:
                sticky = bool(st.st_mode & stat.S_ISVTX)
                owner_ok = st.st_uid in (0, os.geteuid())
                if not (sticky and owner_ok):
                    raise RuntimePathError(f"runtime parent is unsafe world-writable path: {cur}")
        parent = cur.parent
        if parent == cur:
            break
        cur = parent


def _safe_component(raw: str) -> str:
    """Normalize a path component used in runtime filenames."""
    val = str(raw).strip()
    if not val or val in {".", ".."} or "/" in val or "\x00" in val:
        raise RuntimePathError(f"invalid runtime path component: {raw!r}")
    return val
