"""
secrets_kit.seckitd.main

Console entrypoint for ``seckitd`` (``python -m secrets_kit.seckitd``).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from secrets_kit.seckitd.paths import default_socket_path
from secrets_kit.seckitd.server import serve_forever


def main(argv: list[str] | None = None) -> int:
    """Entry point for the ``seckitd`` daemon."""
    ap = argparse.ArgumentParser(
        prog="seckitd",
        description="Local Secrets Kit daemon (Unix socket; Phase 5A).",
    )
    ap.add_argument(
        "--socket",
        type=Path,
        default=None,
        help="Unix socket path (default: ephemeral runtime namespace)",
    )
    ap.add_argument("--instance", default=None, help="Runtime instance name")
    ap.add_argument("--agent-id", default=None, help="Runtime agent id")
    ns = ap.parse_args(argv)
    path = ns.socket or default_socket_path(instance=ns.instance, agent_id=ns.agent_id)
    serve_forever(socket_path=path if ns.socket else None, instance=ns.instance, agent_id=ns.agent_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
