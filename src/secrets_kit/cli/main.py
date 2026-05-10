"""CLI entrypoint for seckit."""

from secrets_kit.models.core import ValidationError

from secrets_kit.cli.parser.base import build_parser
from secrets_kit.cli.support.defaults import _apply_defaults
from secrets_kit.cli.support.interaction import _fatal


def main() -> int:
    """CLI main entry."""
    parser = build_parser()
    args = parser.parse_args()
    try:
        if getattr(args, "command", None) not in ("config", "defaults"):
            _apply_defaults(args=args)
    except ValidationError as exc:
        return _fatal(message=str(exc), code=1)
    return args.func(args=args)


if __name__ == "__main__":
    raise SystemExit(main())
