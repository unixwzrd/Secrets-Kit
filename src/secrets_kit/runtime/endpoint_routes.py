"""secrets_kit.runtime.endpoint_routes: validated route-query subprocess.

Read existing runtime-owned endpoint records through the normal datastore gate.
No caching, initialization bypass, or transport ownership moves into the daemon.
"""

from __future__ import annotations

import json
from typing import Any

from secrets_kit.backends.sqlite.gate import open_sqlite_backend
from secrets_kit.backends.sqlite.peer_endpoints import list_active_peer_endpoints


def build_endpoint_routes() -> dict[str, Any]:
    """Return the existing internal route contract; always close the connection."""
    conn = open_sqlite_backend()
    try:
        return {"version": 1, "routes": [
            {"peer_id": node_id, "endpoint": endpoint}
            for node_id, endpoint in list_active_peer_endpoints(conn=conn)
        ]}
    finally:
        conn.close()


def main() -> int:
    """Emit route JSON on success, otherwise fail without exception details."""
    try:
        result = build_endpoint_routes()
    except Exception:
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
