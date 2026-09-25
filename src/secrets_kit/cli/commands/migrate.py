"""
secrets_kit.cli.commands.migrate

Migrate command implementations.
"""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import List

from secrets_kit.cli.commands.import_cmd import cmd_import_env
from secrets_kit.cli.io import _fatal
from secrets_kit.importers import read_dotenv
from secrets_kit.locale import msg


def cmd_migrate_dotenv(*, args: argparse.Namespace) -> int:
    dotenv = Path(args.dotenv)
    if not dotenv.exists():
        return _fatal(message=msg("errors.migrate.dotenv_not_found", path=dotenv), code=1)

    if args.archive:
        archive_path = Path(args.archive)
        archive_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(dotenv, archive_path)
        print(msg("cli.migrate.archived", path=archive_path))

    tmp = argparse.Namespace(
        dotenv=str(dotenv),
        from_env=None,
        account=args.account,
        service=args.service,
        keychain=args.keychain,
        backend=args.backend,
        type=args.type,
        kind=args.kind,
        tags=args.tags,
        dry_run=args.dry_run,
        allow_overwrite=args.allow_overwrite,
        upsert=False,
        allow_empty=args.allow_empty,
        yes=args.yes,
    )
    code = cmd_import_env(args=tmp)
    if code != 0 or args.dry_run or not args.replace_with_placeholders:
        return code

    parsed = read_dotenv(dotenv_path=dotenv)
    original = dotenv.read_text(encoding="utf-8").splitlines()
    rewritten: List[str] = []
    for line in original:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            rewritten.append(line)
            continue
        left = stripped.split("=", 1)[0].strip()
        if left.startswith("export "):
            left = left[len("export ") :].strip()
        if left in parsed:
            prefix = "export " if stripped.startswith("export ") else ""
            rewritten.append(f"{prefix}{left}=${{{left}}}")
        else:
            rewritten.append(line)

    dotenv.write_text("\n".join(rewritten) + "\n", encoding="utf-8")
    print(msg("cli.migrate.rewrote", path=dotenv))
    return 0


def cmd_migrate_metadata(*, args: argparse.Namespace) -> int:
    _ = args, json
    return _fatal(
        message="metadata registry inventory migration is no longer supported; backend metadata is authoritative",
        code=1,
    )


__all__ = ["cmd_migrate_dotenv", "cmd_migrate_metadata"]
