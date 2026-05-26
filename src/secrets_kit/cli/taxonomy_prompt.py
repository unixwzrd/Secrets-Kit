"""
secrets_kit.cli.taxonomy_prompt

Interactive and flag-driven taxonomy name normalization prompts.
"""

from __future__ import annotations

import argparse
import sys
from typing import Optional

from secrets_kit.models import ValidationError
from secrets_kit.taxonomy.normalize import canonical_taxonomy_name, resolve_stored_taxonomy_name
from secrets_kit.taxonomy.validate import policy_mode_active


def _prompt_force_raw(*, label: str, raw: str) -> bool:
    print(
        f"warning: {label} {raw!r} is not canonical; force-raw keeps the literal spelling "
        "(separate UUID — discouraged)",
        file=sys.stderr,
    )
    answer = input("  use canonical name? [Y/n/force-raw]: ").strip().lower()
    if answer in {"", "y", "yes"}:
        return False
    if answer in {"force-raw", "force", "raw"}:
        return True
    if answer in {"n", "no"}:
        raise ValidationError(f"aborted normalization for {label}")
    raise ValidationError(f"invalid choice for {label} normalization")


def resolve_name_for_cli(
    *,
    label: str,
    raw: str,
    args: argparse.Namespace,
    sqlite_dev_mode: bool = False,
) -> str:
    """
    Resolve one vocabulary name for CLI writes.

    Honors --accept-normalized / -y and --force-raw-name on args when present.
    """
    force_raw = bool(getattr(args, "force_raw_name", False))
    accept = bool(getattr(args, "accept_normalized", False)) or bool(getattr(args, "yes", False))

    if policy_mode_active(sqlite_dev_mode=sqlite_dev_mode) and force_raw:
        raise ValidationError("--force-raw-name is not allowed in policy mode")

    if force_raw:
        return resolve_stored_taxonomy_name(raw=raw, force_raw=True)

    canonical = canonical_taxonomy_name(raw=raw)
    if raw.strip() == canonical:
        return canonical

    if accept:
        print(f"note: {label} {raw!r} -> {canonical!r}", file=sys.stderr)
        return canonical

    if sys.stdin.isatty():
        if _prompt_force_raw(label=label, raw=raw):
            if not sqlite_dev_mode and policy_mode_active(sqlite_dev_mode=False):
                raise ValidationError("--force-raw-name is only allowed in developer mode")
            return resolve_stored_taxonomy_name(raw=raw, force_raw=True)
        return canonical

    raise ValidationError(
        f"{label} {raw!r} normalizes to {canonical!r}; "
        "re-run with --accept-normalized or fix the spelling"
    )


def resolve_optional_name_for_cli(
    *,
    label: str,
    raw: Optional[str],
    args: argparse.Namespace,
    sqlite_dev_mode: bool = False,
) -> Optional[str]:
    if raw is None or str(raw).strip() == "":
        return None
    return resolve_name_for_cli(label=label, raw=str(raw), args=args, sqlite_dev_mode=sqlite_dev_mode)


__all__ = ["resolve_name_for_cli", "resolve_optional_name_for_cli"]
