"""Transient runtime endpoint registry."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List

from secrets_kit.runtime.paths import RuntimeLayout, RuntimePathError
from secrets_kit.transport.unix import probe_unix_socket

REGISTRY_VERSION = 1


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class EndpointRecord:
    """One transient runtime endpoint registration."""

    instance_id: str
    agent_id: str
    endpoint_id: str
    socket_path: str
    pid: int
    uid: int
    protocol_version: int
    capabilities: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=now_utc_iso)
    last_seen: str = field(default_factory=now_utc_iso)

    @property
    def key(self) -> str:
        return f"{self.instance_id}/{self.agent_id}/{self.endpoint_id}"


def load_registry(layout: RuntimeLayout) -> dict[str, EndpointRecord]:
    """Load transient registry entries from disk if present."""
    path = layout.registry_path
    if not path.exists():
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or int(raw.get("version", 0)) != REGISTRY_VERSION:
        raise RuntimePathError(f"unsupported runtime registry: {path}")
    out: dict[str, EndpointRecord] = {}
    for item in raw.get("endpoints", []):
        if not isinstance(item, dict):
            continue
        rec = EndpointRecord(**item)
        out[rec.key] = rec
    return out


def save_registry(layout: RuntimeLayout, records: Iterable[EndpointRecord]) -> None:
    """Atomically write transient registry state."""
    payload = {"version": REGISTRY_VERSION, "endpoints": [asdict(r) for r in records]}
    layout.root.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix="registry-", suffix=".json", dir=str(layout.root))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(tmp, layout.registry_path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def register_endpoint(layout: RuntimeLayout, record: EndpointRecord) -> None:
    """Register or replace one endpoint in the transient registry."""
    records = load_registry(layout)
    records[record.key] = record
    save_registry(layout, records.values())


def unregister_endpoint(layout: RuntimeLayout, *, instance_id: str, agent_id: str, endpoint_id: str) -> None:
    """Remove one endpoint from the transient registry."""
    records = load_registry(layout)
    records.pop(f"{instance_id}/{agent_id}/{endpoint_id}", None)
    save_registry(layout, records.values())


def reconstruct_registry(layout: RuntimeLayout) -> dict[str, EndpointRecord]:
    """Reconstruct registry from active socket/pid artifacts.

    The registry is not durable authority. Records without live pids or accepting
    sockets are discarded.
    """
    records = load_registry(layout)
    live: dict[str, EndpointRecord] = {}
    for key, rec in records.items():
        if endpoint_is_live(rec):
            live[key] = rec
    save_registry(layout, live.values())
    return live


def cleanup_stale_endpoints(layout: RuntimeLayout) -> dict[str, EndpointRecord]:
    """Remove stale socket files and registry entries."""
    records = load_registry(layout)
    live: dict[str, EndpointRecord] = {}
    for key, rec in records.items():
        if endpoint_is_live(rec):
            live[key] = rec
            continue
        _unlink_if_runtime_child(Path(rec.socket_path), layout.sockets_dir)
        pid_path = layout.agent_pid_path(rec.agent_id)
        lock_path = layout.agent_lock_path(rec.agent_id)
        _unlink_if_runtime_child(pid_path, layout.pids_dir)
        _unlink_if_runtime_child(lock_path, layout.locks_dir)
    save_registry(layout, live.values())
    return live


def endpoint_is_live(record: EndpointRecord) -> bool:
    """Return True when pid exists and socket accepts connections."""
    if int(record.uid) != os.geteuid():
        return False
    if not _pid_alive(int(record.pid)):
        return False
    return probe_unix_socket(Path(record.socket_path), timeout_s=0.1)


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _unlink_if_runtime_child(path: Path, parent: Path) -> None:
    try:
        resolved_parent = parent.resolve()
        resolved_path = path.resolve(strict=False)
    except OSError:
        return
    if resolved_parent not in resolved_path.parents and resolved_path != resolved_parent:
        return
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    except OSError:
        pass
