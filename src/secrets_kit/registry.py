"""Registry handling for non-secret metadata."""

from __future__ import annotations

from dataclasses import asdict
import json
import os
from pathlib import Path
import tempfile
from typing import Dict, List, Optional

from secrets_kit.models import EntryMetadata, now_utc_iso


class RegistryError(RuntimeError):
    """Registry operation failed."""


def registry_dir(*, home: Optional[Path] = None) -> Path:
    """Return metadata directory path."""
    base = home or Path.home()
    return base / ".config" / "secrets-kit"


def registry_path(*, home: Optional[Path] = None) -> Path:
    """Return metadata file path."""
    return registry_dir(home=home) / "registry.json"


def _mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def _check_secure_perms(*, path: Path, max_mode: int) -> None:
    if not path.exists():
        return
    mode = _mode(path)
    if mode > max_mode:
        raise RegistryError(f"unsafe permissions on {path}: {oct(mode)} (expected <= {oct(max_mode)})")


def ensure_registry_storage(*, home: Optional[Path] = None) -> Path:
    """Create registry directory/file with secure permissions."""
    rdir = registry_dir(home=home)
    rdir.mkdir(parents=True, exist_ok=True)
    os.chmod(rdir, 0o700)
    _check_secure_perms(path=rdir, max_mode=0o700)

    rpath = registry_path(home=home)
    if not rpath.exists():
        payload = {"version": 1, "entries": []}
        _atomic_write_json(path=rpath, payload=payload)
    os.chmod(rpath, 0o600)
    _check_secure_perms(path=rpath, max_mode=0o600)
    return rpath


def _atomic_write_json(*, path: Path, payload: Dict) -> None:
    """Write JSON atomically with secure file mode."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix="registry-", suffix=".json", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(tmp_path, path)
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


def load_registry(*, home: Optional[Path] = None) -> Dict[str, EntryMetadata]:
    """Load metadata registry into keyed mapping."""
    rpath = ensure_registry_storage(home=home)
    _check_secure_perms(path=rpath, max_mode=0o600)
    payload = json.loads(rpath.read_text(encoding="utf-8"))
    entries = payload.get("entries", [])
    mapping: Dict[str, EntryMetadata] = {}
    for item in entries:
        meta = EntryMetadata.from_dict(item)
        mapping[meta.key()] = meta
    return mapping


def save_registry(*, entries: Dict[str, EntryMetadata], home: Optional[Path] = None) -> None:
    """Persist metadata registry mapping."""
    rpath = ensure_registry_storage(home=home)
    _check_secure_perms(path=rpath, max_mode=0o600)
    serialized: List[Dict] = [asdict(item) for item in sorted(entries.values(), key=lambda m: (m.service, m.account, m.name))]
    _atomic_write_json(path=rpath, payload={"version": 1, "entries": serialized})
    os.chmod(rpath, 0o600)


def upsert_metadata(*, metadata: EntryMetadata, home: Optional[Path] = None) -> None:
    """Insert or update one metadata record."""
    entries = load_registry(home=home)
    key = metadata.key()
    existing = entries.get(key)
    if existing:
        metadata.created_at = existing.created_at
        metadata.updated_at = now_utc_iso()
    entries[key] = metadata
    save_registry(entries=entries, home=home)


def delete_metadata(*, service: str, account: str, name: str, home: Optional[Path] = None) -> bool:
    """Delete one metadata record. Return True when removed."""
    entries = load_registry(home=home)
    key = f"{service}::{account}::{name}"
    existed = key in entries
    if existed:
        del entries[key]
        save_registry(entries=entries, home=home)
    return existed
