"""
secrets_kit.cli.commands.daemon

Daemon command implementations.
"""

from __future__ import annotations

import argparse
import getpass

from secrets_kit.cli.io import _fatal
from secrets_kit.daemon.client import (
    DaemonError,
    daemon_status,
    ping_daemon,
    start_daemon,
    stop_daemon,
)
from secrets_kit.daemon.server import serve_forever
from secrets_kit.daemon.service import (
    DaemonServiceError,
    install_service,
    restart_service,
    service_installed,
    service_status,
    start_service,
    stop_service,
    uninstall_service,
)
from secrets_kit.locale import msg


def _print_status() -> None:
    status = daemon_status()
    print(msg("cli.daemon.running", value=str(bool(status["running"])).lower()))
    print(msg("cli.daemon.pid", value=status.get("pid") or ""))
    print(msg("cli.daemon.uds_path", value=status.get("uds_path") or ""))
    print(msg("cli.daemon.tcp_port", value=status.get("tcp_port") or ""))
    print(msg("cli.daemon.startup_timestamp", value=status.get("startup_timestamp") or ""))


def cmd_daemon_start(*, args: argparse.Namespace) -> int:
    try:
        if service_installed():
            start_service()
        else:
            start_daemon()
    except (DaemonError, DaemonServiceError) as exc:
        return _fatal(message=str(exc), code=1)
    _print_status()
    return 0


def cmd_daemon_stop(*, args: argparse.Namespace) -> int:
    try:
        if service_installed():
            stop_service()
        else:
            stop_daemon()
    except (DaemonError, DaemonServiceError) as exc:
        return _fatal(message=str(exc), code=1)
    print(msg("cli.daemon.stopped"))
    return 0


def cmd_daemon_status(*, args: argparse.Namespace) -> int:
    status = daemon_status()
    _print_status()
    return 0 if status["running"] else 1


def cmd_daemon_ping(*, args: argparse.Namespace) -> int:
    if ping_daemon():
        print("pong")
        return 0
    return _fatal(message=msg("cli.daemon.unreachable"), code=1)


def cmd_daemon_restart(*, args: argparse.Namespace) -> int:
    """Restart a managed or detached same-user daemon."""

    try:
        if service_installed():
            restart_service()
        else:
            stop_daemon()
            start_daemon()
    except (DaemonError, DaemonServiceError) as exc:
        return _fatal(message=str(exc), code=1)
    _print_status()
    return 0


def cmd_daemon_run(*, args: argparse.Namespace) -> int:
    """Run ``seckitd`` in the foreground for a service manager."""

    _ = args
    return serve_forever()


def cmd_daemon_service_install(*, args: argparse.Namespace) -> int:
    """Install and start the same-user managed daemon service."""

    try:
        created = install_service()
        data = service_status()
    except (DaemonError, DaemonServiceError) as exc:
        return _fatal(message=str(exc), code=1)
    print(msg("cli.daemon.service.installed", value=str(bool(data['installed'])).lower()))
    print(msg("cli.daemon.service.created", value=str(created).lower()))
    print(msg("cli.daemon.service.manager", value=data['manager']))
    print(msg("cli.daemon.service.active", value=str(bool(data['active'])).lower()))
    if data.get("linger") is False:
        print(
            msg("cli.daemon.service.linger_hint", user=getpass.getuser())
        )
    return 0


def cmd_daemon_service_uninstall(*, args: argparse.Namespace) -> int:
    """Stop and remove the same-user daemon service."""

    try:
        removed = uninstall_service()
    except DaemonServiceError as exc:
        return _fatal(message=str(exc), code=1)
    print(msg("cli.daemon.service.removed", value=str(removed).lower()))
    return 0


def cmd_daemon_service_status(*, args: argparse.Namespace) -> int:
    """Show same-user service-manager and daemon reachability state."""

    _ = args
    try:
        data = service_status()
    except DaemonServiceError as exc:
        return _fatal(message=str(exc), code=1)
    for key in ("manager", "installed", "active", "daemon_reachable", "definition", "linger"):
        if key in data:
            value = data[key]
            print(msg(f"cli.daemon.service.{key}", value=str(value).lower() if isinstance(value, bool) else value))
    return 0 if data["installed"] and data["active"] and data["daemon_reachable"] else 1


__all__ = [
    "cmd_daemon_ping",
    "cmd_daemon_start",
    "cmd_daemon_status",
    "cmd_daemon_stop",
    "cmd_daemon_restart",
    "cmd_daemon_run",
    "cmd_daemon_service_install",
    "cmd_daemon_service_status",
    "cmd_daemon_service_uninstall",
]
