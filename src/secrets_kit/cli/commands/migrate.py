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

from secrets_kit.backends.sqlite import get_sqlite_secret_entry
from secrets_kit.backends.sqlite.secrets_api import (
    authorize_existing_sqlite_secret_for_sync,
    import_sqlite_secret_local,
)
from secrets_kit.cli.commands.import_cmd import cmd_import_env
from secrets_kit.cli.io import _fatal
from secrets_kit.cli.keychain_migration import (
    MigrationError,
    inventory_keychain,
    metadata_matches,
    read_legacy_value,
    require_encrypted_sqlite_target,
    target_state,
)
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
        keychain=getattr(args, "keychain", None),
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


def cmd_migrate_keychain(*, args: argparse.Namespace) -> int:
    """Inventory or explicitly copy a selected Keychain scope into encrypted SQLite."""
    if args.authorize_sync and not args.apply:
        return _fatal(message="--authorize-sync requires --apply", code=1)
    try:
        inventory = inventory_keychain(
            path=args.keychain, service=args.service, account=args.account
        )
        try:
            require_encrypted_sqlite_target()
        except MigrationError:
            if args.apply:
                raise
            target_ready = False
            states = [(item, "unavailable") for item in inventory.items]
        else:
            target_ready = True
            states = [(item, target_state(item=item)) for item in inventory.items]
    except MigrationError as exc:
        return _fatal(message=str(exc), code=1)
    except Exception:
        return _fatal(message="Keychain migration preflight failed", code=1)

    summary = {
        "dry_run": not args.apply,
        "source_keychain": str(inventory.path),
        "service": args.service,
        "account": args.account,
        "items": [{"name": item.metadata.name, "target": state} for item, state in states],
        "unsupported": list(inventory.unsupported),
        "sync_authorized": bool(args.authorize_sync),
        "target_ready": target_ready,
    }
    if not args.apply:
        print(json.dumps(summary, sort_keys=True))
        return 0 if not inventory.unsupported else 1
    if inventory.unsupported or not states:
        return _fatal(
            message="Keychain inventory is incomplete or empty; no credentials copied", code=1
        )

    # Resolve every existing target before the first write. A conflicting or
    # tombstoned identity always stops the entire selected scope.
    try:
        for item, state in states:
            if state == "absent":
                continue
            if state != "active":
                raise MigrationError("SQLite target contains a deleted or unsupported identity")
            source_value = read_legacy_value(inventory=inventory, item=item)
            target_value, target_metadata = get_sqlite_secret_entry(
                service=args.service, account=args.account, name=item.metadata.name
            )
            if source_value != target_value or not metadata_matches(
                source=item.metadata,
                target=target_metadata,
                structured_comment=item.structured_comment,
            ):
                raise MigrationError("SQLite target conflicts with a Keychain credential")
    except MigrationError as exc:
        return _fatal(message=str(exc), code=1)
    except Exception:
        return _fatal(message="SQLite migration comparison failed", code=1)

    copied = 0
    skipped = 0
    for item, state in states:
        if state == "active":
            skipped += 1
            continue
        try:
            value = read_legacy_value(inventory=inventory, item=item)
            import_sqlite_secret_local(
                service=args.service,
                account=args.account,
                name=item.metadata.name,
                value=value,
                metadata=item.metadata,
            )
            verified_value, verified_metadata = get_sqlite_secret_entry(
                service=args.service, account=args.account, name=item.metadata.name
            )
            if value != verified_value or not metadata_matches(
                source=item.metadata,
                target=verified_metadata,
                structured_comment=item.structured_comment,
            ):
                raise MigrationError("SQLite migration verification failed")
        except Exception:
            print(
                json.dumps(
                    {"copied": copied, "skipped": skipped, "verified": False}, sort_keys=True
                )
            )
            return _fatal(
                message="Keychain migration stopped; originals remain and rerun is safe", code=1
            )
        copied += 1
    if args.authorize_sync:
        try:
            for item, _ in states:
                authorize_existing_sqlite_secret_for_sync(
                    service=args.service, account=args.account, name=item.metadata.name
                )
        except Exception:
            return _fatal(
                message="migration values were verified, but sync authorization stopped; rerun --apply --authorize-sync",
                code=1,
            )
    print(
        json.dumps(
            {
                "copied": copied,
                "skipped": skipped,
                "verified": True,
                "sync_authorized": bool(args.authorize_sync),
                "source_preserved": True,
            },
            sort_keys=True,
        )
    )
    return 0


__all__ = ["cmd_migrate_dotenv", "cmd_migrate_keychain", "cmd_migrate_metadata"]
