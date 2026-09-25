"""
secrets_kit.cli.main

Process entrypoint for the seckit CLI.
"""

from __future__ import annotations

from secrets_kit.cli.defaults import _apply_defaults
from secrets_kit.cli.io import _fatal
from secrets_kit.cli.parser import build_parser
from secrets_kit.models import ValidationError

_DELIVERY_MUTATION_COMMANDS = {
    "delete",
    "import",
    "migrate",
    "schema",
    "service",
    "set",
    "taxonomy",
}
_PEER_MUTATION_COMMANDS = {
    "accept",
    "import-acceptance",
    "import-request",
    "reject",
    "request",
}
_PEER_ADMISSION_CHANGE_COMMANDS = {"accept", "import-acceptance"}


def _daemon_events_after_success(*, args: object) -> tuple[str, ...]:
    """Return local daemon events justified by the completed CLI mutation."""
    command = getattr(args, "command", None)
    if command == "peer":
        peer_command = getattr(args, "peer_command", None)
        events: list[str] = []
        if peer_command in _PEER_ADMISSION_CHANGE_COMMANDS:
            events.append("admission-changed")
        if peer_command in _PEER_MUTATION_COMMANDS:
            events.append("delivery-wake")
        return tuple(events)
    if command in _DELIVERY_MUTATION_COMMANDS:
        return ("delivery-wake",)
    return ()


def main() -> int:
    """CLI main entry."""
    parser = build_parser()
    args = parser.parse_args()
    try:
        if getattr(args, "command", None) not in {
            "config",
            "daemon",
            "envelope",
            "init",
            "info",
            "internal",
            "rss",
            "status",
            "transaction",
            "uninstall",
        }:
            _apply_defaults(args=args)
    except ValidationError as exc:
        return _fatal(message=str(exc), code=1)
    result = args.func(args=args)
    if result == 0:
        for event in _daemon_events_after_success(args=args):
            try:
                from secrets_kit.daemon.client import request_daemon

                request_daemon(command=event, timeout=0.2)
            except Exception:
                # Durable state remains authoritative across daemon downtime.
                pass
    return result


__all__ = ["main"]
