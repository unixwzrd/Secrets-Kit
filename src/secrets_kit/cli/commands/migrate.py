"""
secrets_kit.cli.commands.migrate

Migration and registry recovery subcommands.
"""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

from secrets_kit.backends.security import (
    BackendError,
    check_security_cli,
    get_secret,
    secret_exists,
    set_secret,
)
from secrets_kit.cli.commands.import_export import cmd_import_env
from secrets_kit.cli.constants.exit_codes import EXIT_CODES
from secrets_kit.cli.support.args import (
    _backend_access_kwargs,
    _backend_arg,
    _keychain_arg,
    _store_path,
)
from secrets_kit.cli.support.interaction import _fatal, _format_tags, _print_table
from secrets_kit.importers import read_dotenv
from secrets_kit.models.core import (
    EntryMetadata,
    ValidationError,
    infer_entry_kind_from_name,
    make_registry_key,
    now_utc_iso,
    validate_key_name,
)
from secrets_kit.recovery.recover_sources import iter_recover_candidates
from secrets_kit.registry.core import RegistryError, load_registry, upsert_metadata
from secrets_kit.registry.resolve import _read_metadata


def cmd_migrate_dotenv(*, args: argparse.Namespace) -> int:
    """Import a dotenv file into seckit and optionally rewrite it to placeholders.

    Archives the original file when ``--archive`` is set, imports the entries
    via ``cmd_import_env``, and then replaces values with ``${NAME}``
    placeholders in the original file.
    """
    dotenv = Path(args.dotenv)
    if not dotenv.exists():
        return _fatal(message=f"dotenv file not found: {dotenv}", code=EXIT_CODES["ENOENT"])

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
    rewritten: list[str] = []
    for line in original:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            rewritten.append(line)
            continue
        left = stripped.split("=", 1)[0].strip()
        if left.startswith("export "):
            left = left[len("export "):].strip()
        if left in parsed:
            prefix = "export " if stripped.startswith("export ") else ""
            rewritten.append(f"{prefix}{left}=${{{left}}}")
        else:
            rewritten.append(line)

    dotenv.write_text("\n".join(rewritten) + "\n", encoding="utf-8")
    print(f"rewrote placeholders in {dotenv}")
    return 0


def cmd_migrate_metadata(*, args: argparse.Namespace) -> int:
    """Write registry metadata into the backend comment / payload field.

    For each registry entry that exists in the backend, re-encodes the
    current ``EntryMetadata`` as a keychain comment (secure) or SQLite
    payload (sqlite). Skips entries whose metadata source is already
    ``keychain`` or ``sqlite`` unless ``--force`` is passed.
    """
    try:
        registry = load_registry()
    except RegistryError as exc:
        return _fatal(message=str(exc), code=EXIT_CODES["EPERM"])

    selected: list[EntryMetadata] = []
    for meta in registry.values():
        if args.service and meta.service != args.service:
            continue
        if args.account and meta.account != args.account:
            continue
        selected.append(meta)

    stats = {"migrated": 0, "skipped": 0, "missing_keychain": 0}
    for meta in sorted(selected, key=lambda item: (item.service, item.account, item.name)):
        if not secret_exists(service=meta.service, account=meta.account, name=meta.name, **_backend_access_kwargs(args)):
            stats["missing_keychain"] += 1
            continue
        resolved = _read_metadata(
            service=meta.service,
            account=meta.account,
            name=meta.name,
            registry=registry,
            **_backend_access_kwargs(args),
        )
        if resolved and resolved["metadata_source"] in {"keychain", "sqlite"} and not args.force:
            stats["skipped"] += 1
            continue
        if args.dry_run:
            stats["migrated"] += 1
            continue
        value = get_secret(service=meta.service, account=meta.account, name=meta.name, **_backend_access_kwargs(args))
        meta.updated_at = now_utc_iso()
        set_secret(
            service=meta.service,
            account=meta.account,
            name=meta.name,
            value=value,
            label=meta.name,
            comment=meta.to_keychain_comment(),
            **_backend_access_kwargs(args),
        )
        verify = _read_metadata(
            service=meta.service,
            account=meta.account,
            name=meta.name,
            registry=registry,
            **_backend_access_kwargs(args),
        )
        if not verify or verify["metadata_source"] not in {"keychain", "sqlite"}:
            return _fatal(message=f"failed to verify migrated metadata for {meta.key()}", code=EXIT_CODES["EIO"])
        upsert_metadata(metadata=meta)
        stats["migrated"] += 1

    print(json.dumps(stats, indent=2, sort_keys=True))
    return 0


def cmd_recover_registry(*, args: argparse.Namespace) -> int:
    """Rebuild registry/index metadata from the live store.

    Scans the backend (Keychain or SQLite) for entries that are not yet
    indexed in ``registry.json``, validates their names, deduplicates by
    registry key, and writes new metadata records. Entries whose
    keychain comments contain valid metadata are preserved; others get
    auto-inferred ``entry_kind`` and fresh timestamps.
    """
    from secrets_kit.backends.security import is_secure_backend, is_sqlite_backend

    backend = _backend_arg(args)
    if is_secure_backend(backend):
        if not check_security_cli():
            return _fatal(message="security CLI not found", code=EXIT_CODES["EAPP_SECURITY_CLI_MISSING"])
    elif not is_sqlite_backend(backend):
        return _fatal(message="recover requires --backend secure or sqlite", code=EXIT_CODES["EINVAL"])

    filt = getattr(args, "service", None)
    filt = filt.strip() if filt else None
    service_filter = filt or None

    sqlite_db: str | None = None
    if is_sqlite_backend(backend):
        sqlite_db = _store_path(args)
        if not sqlite_db:
            return _fatal(message="SQLite recover requires --db or SECKIT_SQLITE_DB / defaults", code=EXIT_CODES["EINVAL"])

    try:
        candidate_iter = iter_recover_candidates(
            backend=backend,
            service_filter=service_filter,
            keychain_file=_keychain_arg(args),
            sqlite_db=sqlite_db,
        )
    except BackendError as exc:
        return _fatal(message=str(exc), code=EXIT_CODES["EPERM"])

    stats: dict[str, object] = {
        "candidates": 0,
        "recovered": 0,
        "skipped_bad_name": 0,
        "skipped_bad_names": [],
        "skipped_duplicate": 0,
        "skipped_duplicate_keys": [],
        "skipped_no_secret": 0,
        "skipped_no_secret_keys": [],
    }
    seen: set[str] = set()
    dry = bool(getattr(args, "dry_run", False))
    json_only = bool(getattr(args, "json", False))
    recovered_metas: list[EntryMetadata] = []
    recovered_rows: list[list[str]] = []

    for cand in candidate_iter:
        stats["candidates"] += 1
        try:
            validate_key_name(name=cand.name)
        except ValidationError as exc:
            stats["skipped_bad_name"] += 1
            stats["skipped_bad_names"].append(
                {
                    "service": cand.service,
                    "account": cand.account,
                    "name": cand.name,
                    "reason": str(exc),
                }
            )
            continue
        rkey = make_registry_key(service=cand.service, account=cand.account, name=cand.name)
        if rkey in seen:
            stats["skipped_duplicate"] += 1
            stats["skipped_duplicate_keys"].append(rkey)
            continue
        if not secret_exists(
            service=cand.service,
            account=cand.account,
            name=cand.name,
            **_backend_access_kwargs(args),
        ):
            stats["skipped_no_secret"] += 1
            stats["skipped_no_secret_keys"].append(rkey)
            continue

        parsed = EntryMetadata.from_keychain_comment(cand.comment)
        if parsed is not None and (
            parsed.name != cand.name
            or parsed.service != cand.service
            or parsed.account != cand.account
        ):
            parsed = None

        if parsed is not None:
            meta = parsed
            meta.updated_at = now_utc_iso()
        else:
            ts = now_utc_iso()
            meta = EntryMetadata(
                name=cand.name,
                service=cand.service,
                account=cand.account,
                entry_kind=infer_entry_kind_from_name(name=cand.name),
                source="recovered-keychain" if is_secure_backend(backend) else "recovered-sqlite",
                created_at=ts,
                updated_at=ts,
            )

        seen.add(rkey)
        recovered_metas.append(meta)
        recovered_rows.append(
            [
                meta.name,
                meta.entry_type,
                meta.entry_kind,
                meta.service,
                meta.account,
                _format_tags(tags=meta.tags),
                "dry-run" if dry else "written",
                meta.updated_at,
            ]
        )
        if dry:
            stats["recovered"] += 1
            continue
        upsert_metadata(metadata=meta)
        stats["recovered"] += 1

    report: dict[str, object] = {**stats, "recovered_entries": [m.to_dict() for m in recovered_metas]}
    if json_only:
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0

    if dry and recovered_rows:
        headers = ["NAME", "TYPE", "KIND", "SERVICE", "ACCOUNT", "TAGS", "STATUS", "UPDATED_AT"]
        _print_table(headers=headers, rows=recovered_rows)
        print()

    print(json.dumps({k: v for k, v in report.items() if k != "recovered_entries"}, indent=2, sort_keys=True))
    return 0
