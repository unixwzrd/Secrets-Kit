"""
secrets_kit.daemon

Minimal UDS daemon skeleton for seckitd.
"""

from __future__ import annotations

from secrets_kit.daemon.client import (
    daemon_status,
    ping_daemon,
    request_daemon_status,
    start_daemon,
    stop_daemon,
)

__all__ = [
    "daemon_status",
    "ping_daemon",
    "request_daemon_status",
    "start_daemon",
    "stop_daemon",
]
