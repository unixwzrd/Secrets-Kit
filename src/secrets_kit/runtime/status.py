"""Runtime-owned read-only status collector and JSON subprocess entry point.

The daemon invokes this module without loading the customer CLI. Datastore
validation and access remain in this runtime-owned subprocess.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from secrets_kit import __version__
from secrets_kit.backends.common import BACKEND_SQLITE, normalize_backend
from secrets_kit.backends.sqlite.exceptions import SQLiteBackendError, SQLiteValidationError
from secrets_kit.backends.sqlite.gate import open_sqlite_backend, sqlite_path
from secrets_kit.backends.sqlite.local_node import load_local_node_projection
from secrets_kit.backends.sqlite.peer_endpoints import list_active_peer_endpoints
from secrets_kit.backends.sqlite.peer_registry import list_peer_registry_entries
from secrets_kit.backends.sqlite.schema import SCHEMA_VERSION
from secrets_kit.backends.sqlite.storage_mode import read_sqlite_storage_mode
from secrets_kit.registry import RegistryError, read_defaults

TRANSACTION_STATES = ("pending", "applied", "replayed", "failed")
ENVELOPE_STATES = (
    "pending",
    "claimed",
    "sending",
    "sent",
    "received",
    "acknowledged",
    "failed",
    "retry_pending",
    "authorization_denied",
    "purged",
)


def build_runtime_status() -> dict[str, Any]:
    """Return runtime state without daemon or transport dependencies."""
    backend = _configured_backend()
    data: dict[str, Any] = {
        "version": __version__,
        "available": True,
        "backend": backend,
        "database": {
            "backend": backend,
        },
        "identity": None,
        "peers": [],
        "transactions": _empty_counts(TRANSACTION_STATES),
        "envelopes": _empty_counts(ENVELOPE_STATES),
        "synchronization": {
            "last_successful_outbound": None,
            "last_received_transaction": None,
        },
    }
    if backend != BACKEND_SQLITE:
        data["database"]["reason"] = "runtime status details are backend-specific"
        return data
    data["database"].update(
        {
            "path": str(sqlite_path()),
            "schema_version_expected": SCHEMA_VERSION,
        }
    )
    try:
        conn = open_sqlite_backend()
    except (SQLiteBackendError, SQLiteValidationError, sqlite3.Error, OSError, ValueError) as exc:
        data["available"] = False
        data["error"] = str(exc)
        return data
    try:
        data["database"].update(
            {
                "exists": True,
                "user_version": _scalar(conn, "PRAGMA user_version"),
                "storage_mode": read_sqlite_storage_mode(conn=conn),
            }
        )
        data["identity"] = _identity_status(conn=conn)
        data["peers"] = _peer_status(conn=conn)
        data["transactions"] = _lifecycle_status(conn=conn, table="transactions", states=TRANSACTION_STATES)
        data["envelopes"] = _lifecycle_status(conn=conn, table="envelopes", states=ENVELOPE_STATES)
        data["synchronization"] = _synchronization_status(conn=conn)
        # Share the runtime-owned route read with the status IPC request. The
        # daemon must not open the datastore or repeat the CLI startup for it.
        data["transport_routes"] = [
            {"peer_id": node_id, "endpoint": endpoint}
            for node_id, endpoint in list_active_peer_endpoints(conn=conn)
        ]
    except (sqlite3.Error, SQLiteBackendError, SQLiteValidationError, OSError, ValueError) as exc:
        data["available"] = False
        data["error"] = str(exc)
    finally:
        conn.close()
    return data


def _configured_backend() -> str:
    try:
        configured = read_defaults().get("backend")
        if configured is not None:
            return normalize_backend(str(configured))
    except (RegistryError, OSError, TypeError, ValueError):
        pass
    return BACKEND_SQLITE


def _identity_status(*, conn: sqlite3.Connection) -> dict[str, Any] | None:
    projection = load_local_node_projection(conn=conn)
    if projection is None:
        return None
    return {
        "peer_id": projection.node_id,
        "peer_name": projection.node_id,
        "runtime_mode": "local",
        "state": projection.state,
        "created_at": projection.created_at,
        "updated_at": projection.updated_at,
    }


def _peer_status(*, conn: sqlite3.Connection) -> list[dict[str, Any]]:
    peers: list[dict[str, Any]] = []
    for entry in list_peer_registry_entries(conn=conn):
        peers.append(
            {
                "name": entry.display_name or entry.local_alias or entry.node_id,
                "peer_id": entry.node_id,
                "authorized": entry.authorization_state == "authorized",
                "synchronization_eligible": entry.synchronization_eligible,
                "connected": None,
                "reachable": None,
                "known_endpoint": entry.endpoint or entry.service_address or None,
                "endpoint_state": entry.endpoint_state,
                "endpoint_expires_at": entry.endpoint_expires_at or None,
                "last_contact_at": entry.updated_at or None,
            }
        )
    return peers


def _lifecycle_status(
    *, conn: sqlite3.Connection, table: str, states: tuple[str, ...]
) -> dict[str, Any]:
    counts = _empty_counts(states)
    for row in conn.execute(f'SELECT state, COUNT(*) AS count FROM "{table}" GROUP BY state'):
        state = str(row["state"])
        if state in counts:
            counts[state] = int(row["count"])
    counts["total"] = int(conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])
    if table == "transactions":
        counts["applied"] = counts.get("applied", 0) + counts.get("replayed", 0)
        counts["incomplete"] = counts.get("pending", 0)
        counts["latest_success"] = _latest_transaction(conn=conn, state_clause="state IN ('applied', 'replayed')")
        counts["latest_failed"] = _latest_transaction(conn=conn, state_clause="state = 'failed'")
    else:
        counts["incomplete"] = sum(counts.get(state, 0) for state in ("pending", "claimed", "sending", "retry_pending"))
        counts["retry_queue"] = counts.get("retry_pending", 0)
        counts["currently_sending"] = counts.get("sending", 0)
    return counts


def _latest_transaction(*, conn: sqlite3.Connection, state_clause: str) -> dict[str, Any] | None:
    row = conn.execute(
        f"""
        SELECT transaction_id, transaction_type, state,
               COALESCE(applied_at, created_at) AS timestamp
        FROM transactions
        WHERE {state_clause}
        ORDER BY COALESCE(applied_at, created_at) DESC, rowid DESC
        LIMIT 1
        """
    ).fetchone()
    return None if row is None else {key: row[key] for key in row.keys()}


def _synchronization_status(*, conn: sqlite3.Connection) -> dict[str, Any]:
    outbound = conn.execute("SELECT MAX(sent_at) FROM envelopes WHERE sent_at IS NOT NULL").fetchone()[0]
    inbound = conn.execute("SELECT MAX(received_at) FROM transactions WHERE received_at IS NOT NULL").fetchone()[0]
    return {
        "last_successful_outbound": outbound,
        "last_received_transaction": inbound,
    }


def _empty_counts(states: tuple[str, ...]) -> dict[str, Any]:
    return {state: 0 for state in states} | {"total": 0}


def _scalar(conn: sqlite3.Connection, query: str) -> Any:
    row = conn.execute(query).fetchone()
    return row[0] if row else None


__all__ = ["build_runtime_status"]


def main() -> int:
    """Emit the existing status contract; do not initialize or repair state."""
    print(json.dumps(build_runtime_status(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
