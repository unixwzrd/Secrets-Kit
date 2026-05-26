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

from secrets_kit.backends.keychain import get_secret, secret_exists, set_secret
from secrets_kit.cli.commands.import_cmd import cmd_import_env
from secrets_kit.cli.io import _fatal
from secrets_kit.cli.selection import _backend_arg, _keychain_arg
from secrets_kit.importers import read_dotenv
from secrets_kit.locale import msg
from secrets_kit.models import EntryMetadata, now_utc_iso
from secrets_kit.registry import RegistryError, load_registry, upsert_metadata
from secrets_kit.registry.resolve import read_metadata


def cmd_migrate_dotenv(*, args: argparse.Namespace) -> int:
    dotenv = Path(args.dotenv)
    if not dotenv.exists():
        return _fatal(message=msg("errors.migrate.dotenv_not_found", path=dotenv), code=1)

    if args.archive:
        archive_path = Path(args.archive)
        archive_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(dotenv, archive_path)
        print(f"archived: {archive_path}")

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
    print(f"rewrote placeholders in {dotenv}")
    return 0


def cmd_migrate_metadata(*, args: argparse.Namespace) -> int:
    try:
        registry = load_registry()
    except RegistryError as exc:
        return _fatal(message=str(exc), code=1)

    selected: List[EntryMetadata] = []
    for meta in registry.values():
        if args.service and meta.service != args.service:
            continue
        if args.account and meta.account != args.account:
            continue
        selected.append(meta)

    stats = {"migrated": 0, "skipped": 0, "missing_keychain": 0}
    for meta in sorted(selected, key=lambda item: (item.service, item.account, item.name)):
        if not secret_exists(
            service=meta.service,
            account=meta.account,
            name=meta.name,
            path=_keychain_arg(args),
            backend=_backend_arg(args),
        ):
            stats["missing_keychain"] += 1
            continue
        resolved = read_metadata(
            service=meta.service,
            account=meta.account,
            name=meta.name,
            registry=registry,
            path=_keychain_arg(args),
            backend=_backend_arg(args),
        )
        if resolved and resolved["metadata_source"] == "keychain" and not args.force:
            stats["skipped"] += 1
            continue
        if args.dry_run:
            stats["migrated"] += 1
            continue
        value = get_secret(
            service=meta.service,
            account=meta.account,
            name=meta.name,
            path=_keychain_arg(args),
            backend=_backend_arg(args),
        )
        meta.updated_at = now_utc_iso()
        set_secret(
            service=meta.service,
            account=meta.account,
            name=meta.name,
            value=value,
            label=meta.name,
            comment=meta.to_keychain_comment(),
            path=_keychain_arg(args),
            backend=_backend_arg(args),
        )
        verify = read_metadata(
            service=meta.service,
            account=meta.account,
            name=meta.name,
            registry=registry,
            path=_keychain_arg(args),
            backend=_backend_arg(args),
        )
        if not verify or verify["metadata_source"] != "keychain":
            return _fatal(
                message=msg("errors.migrate.metadata_verify_failed", key=meta.key()), code=1
            )
        upsert_metadata(metadata=meta)
        stats["migrated"] += 1

    print(json.dumps(stats, indent=2, sort_keys=True))
    return 0


__all__ = ["cmd_migrate_dotenv", "cmd_migrate_metadata"]
