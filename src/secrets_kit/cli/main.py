"""
secrets_kit.cli.main

Process entrypoint for the seckit CLI.
"""

from __future__ import annotations

from secrets_kit.cli.defaults import _apply_defaults
from secrets_kit.cli.io import _fatal
from secrets_kit.cli.parser import build_parser
from secrets_kit.models import ValidationError


def main() -> int:
    """CLI main entry."""
    parser = build_parser()
    args = parser.parse_args()
    try:
        if getattr(args, "command", None) not in {"config", "init", "info"}:
            _apply_defaults(args=args)
    except ValidationError as exc:
        return _fatal(message=str(exc), code=1)
    return args.func(args=args)


__all__ = ["main"]
