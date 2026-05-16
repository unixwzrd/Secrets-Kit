"""
secrets_kit.cli.commands.import_export

Import, export, and candidate merge helpers.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Iterable

from secrets_kit.backends.security import (
    BackendError,
    get_secret,
    secret_exists,
    set_secret,
)
from secrets_kit.cli.constants.exit_codes import EXIT_CODES
from secrets_kit.cli.support.args import (
    _backend_access_kwargs,
    _backend_arg,
    _kek_keychain_arg,
    _store_path,
)
from secrets_kit.cli.support.env_exec import _build_env_map
from secrets_kit.cli.support.interaction import (
    _confirm,
    _fatal,
    _format_tags,
    _print_table,
    _read_password,
)
from secrets_kit.cli.support.metadata_selection import _select_entries
from secrets_kit.importers import (
    ImportCandidate,
    candidates_from_dotenv,
    candidates_from_env,
    candidates_from_file,
)
from secrets_kit.models.core import EntryMetadata, ValidationError, now_utc_iso
from secrets_kit.registry.core import RegistryError, upsert_metadata
from secrets_kit.registry.resolve import _read_metadata
from secrets_kit.utils.crypto import (
    CryptoUnavailable,
    build_plain_export,
    decrypt_payload,
    encrypt_payload,
    ensure_crypto_available,
)


def _merge_candidates(*, groups: Iterable[list[ImportCandidate]]) -> dict[str, ImportCandidate]:
    merged: dict[str, ImportCandidate] = {}
    for group in groups:
        for candidate in group:
            merged[candidate.metadata.key()] = candidate
    return merged


def _apply_candidates(
    *,
    candidates: dict[str, ImportCandidate],
    allow_overwrite: bool,
    dry_run: bool,
    allow_empty: bool,
    path: str | None = None,
    backend: str = "secure",
    kek_keychain_path: str | None = None,
) -> dict[str, int]:
    from secrets_kit.registry.core import load_registry

    registry = load_registry()
    stats = {"created": 0, "updated": 0, "skipped": 0, "unchanged": 0}
    for key in sorted(candidates):
        candidate = candidates[key]
        resolved = _read_metadata(
            service=candidate.metadata.service,
            account=candidate.metadata.account,
            name=candidate.metadata.name,
            registry=registry,
            path=path,
            backend=backend,
            kek_keychain_path=kek_keychain_path,
        )
        exists = resolved is not None and secret_exists(
            service=candidate.metadata.service,
            account=candidate.metadata.account,
            name=candidate.metadata.name,
            path=path,
            backend=backend,
            kek_keychain_path=kek_keychain_path,
        )
        if exists and not allow_overwrite:
            stats["skipped"] += 1
            continue
        if not allow_empty and not candidate.value:
            stats["skipped"] += 1
            continue
        if resolved:
            existing_meta = resolved["metadata"]
            if isinstance(existing_meta, EntryMetadata):
                candidate.metadata = _merge_import_metadata(existing=existing_meta, incoming=candidate.metadata)
                candidate.metadata.created_at = existing_meta.created_at
            if exists and not dry_run:
                current_value = get_secret(
                    service=candidate.metadata.service,
                    account=candidate.metadata.account,
                    name=candidate.metadata.name,
                    path=path,
                    backend=backend,
                    kek_keychain_path=kek_keychain_path,
                )
                if current_value == candidate.value:
                    stats["unchanged"] += 1
                    continue
        candidate.metadata.updated_at = now_utc_iso()
        if dry_run:
            stats["updated" if exists else "created"] += 1
            continue
        set_secret(
            service=candidate.metadata.service,
            account=candidate.metadata.account,
            name=candidate.metadata.name,
            value=candidate.value,
            label=candidate.metadata.name,
            comment=candidate.metadata.to_keychain_comment(),
            path=path,
            backend=backend,
            kek_keychain_path=kek_keychain_path,
        )
        upsert_metadata(metadata=candidate.metadata)
        stats["updated" if exists else "created"] += 1
    return stats


def _merge_import_metadata(*, existing: EntryMetadata, incoming: EntryMetadata) -> EntryMetadata:
    merged = EntryMetadata.from_dict(existing.to_dict())
    merged.source = incoming.source
    merged.updated_at = now_utc_iso()
    # Keep existing classification/tags/comment unless the destination did not have them.
    if not merged.entry_type:
        merged.entry_type = incoming.entry_type
    if merged.entry_kind == "generic" and incoming.entry_kind != "generic":
        merged.entry_kind = incoming.entry_kind
    if not merged.tags and incoming.tags:
        merged.tags = incoming.tags
    if not merged.comment and incoming.comment:
        merged.comment = incoming.comment
    return merged


def _preview_candidates(*, merged: Dict[str, ImportCandidate]) -> None:
    print("plan:")
    headers = ["NAME", "TYPE", "KIND", "SERVICE", "ACCOUNT", "TAGS", "SOURCE", "VALUE"]
    table_rows: list[list[str]] = []
    for key in sorted(merged):
        candidate = merged[key]
        meta = candidate.metadata
        table_rows.append(
            [
                meta.name,
                meta.entry_type,
                meta.entry_kind,
                meta.service,
                meta.account,
                _format_tags(tags=meta.tags),
                meta.source,
                "<redacted>",
            ]
        )
    _print_table(headers=headers, rows=table_rows)


def cmd_import_env(*, args: argparse.Namespace) -> int:
    if not args.dotenv and not args.from_env:
        return _fatal(message="import env requires --dotenv and/or --from-env")
    try:
        groups: list[list[ImportCandidate]] = []
        if args.dotenv:
            groups.append(
                candidates_from_dotenv(
                    dotenv_path=Path(args.dotenv),
                    account=args.account,
                    service=args.service,
                    entry_type=args.type,
                    entry_kind=args.kind,
                    tags_csv=args.tags,
                )
            )
        if args.from_env:
            groups.append(
                candidates_from_env(
                    prefix=args.from_env,
                    account=args.account,
                    service=args.service,
                    entry_type=args.type,
                    entry_kind=args.kind,
                    tags_csv=args.tags,
                )
            )
        merged = _merge_candidates(groups=groups)
        _preview_candidates(merged=merged)
        if not merged:
            print("nothing to import")
            return 0
        if not args.dry_run and not args.yes and not _confirm(prompt=f"Import {len(merged)} entries?"):
            print("aborted")
            return EXIT_CODES["ECANCELED"]
        stats = _apply_candidates(
            candidates=merged,
            allow_overwrite=args.allow_overwrite or getattr(args, "upsert", False),
            dry_run=args.dry_run,
            allow_empty=args.allow_empty,
            path=_store_path(args),
            backend=_backend_arg(args),
            kek_keychain_path=_kek_keychain_arg(args),
        )
        print(json.dumps(stats, indent=2, sort_keys=True))
        return 0
    except (ValidationError, ValueError, RegistryError, BackendError, FileNotFoundError) as exc:
        return _fatal(message=str(exc), code=EXIT_CODES["EPERM"])


def cmd_import_file(*, args: argparse.Namespace) -> int:
    try:
        rows = candidates_from_file(
            file_path=Path(args.file),
            fmt=args.format,
            default_type=args.type,
            default_kind=args.kind,
        )
        merged = {row.metadata.key(): row for row in rows}
        _preview_candidates(merged=merged)
        if not merged:
            print("nothing to import")
            return 0
        if not args.dry_run and not args.yes and not _confirm(prompt=f"Import {len(merged)} entries?"):
            print("aborted")
            return EXIT_CODES["ECANCELED"]
        stats = _apply_candidates(
            candidates=merged,
            allow_overwrite=args.allow_overwrite,
            dry_run=args.dry_run,
            allow_empty=args.allow_empty,
            path=_store_path(args),
            backend=_backend_arg(args),
            kek_keychain_path=_kek_keychain_arg(args),
        )
        print(json.dumps(stats, indent=2, sort_keys=True))
        return 0
    except (ValidationError, ValueError, RegistryError, BackendError, FileNotFoundError) as exc:
        return _fatal(message=str(exc), code=EXIT_CODES["EPERM"])


def cmd_import_encrypted(*, args: argparse.Namespace) -> int:
    try:
        ensure_crypto_available()
        password = _read_password(
            value=args.password,
            use_stdin=args.password_stdin,
            prompt="backup file password for encrypted import: ",
        )
        payload = json.loads(Path(args.file).read_text(encoding="utf-8"))
        decrypted = decrypt_payload(payload=payload, password=password)
        if decrypted.get("format") != "seckit.export":
            return _fatal(message="unsupported decrypted payload format", code=EXIT_CODES["ENOTSUP"])
        entries = decrypted.get("entries", [])
        rows: list[ImportCandidate] = []
        for row in entries:
            if not isinstance(row, dict):
                continue
            meta = EntryMetadata.from_dict(row.get("metadata", {}))
            rows.append(ImportCandidate(metadata=meta, value=str(row.get("value", "")).strip()))
        merged = {row.metadata.key(): row for row in rows}
        _preview_candidates(merged=merged)
        if not merged:
            print("nothing to import")
            return 0
        if not args.dry_run and not args.yes and not _confirm(prompt=f"Import {len(merged)} entries?"):
            print("aborted")
            return EXIT_CODES["ECANCELED"]
        stats = _apply_candidates(
            candidates=merged,
            allow_overwrite=args.allow_overwrite,
            dry_run=args.dry_run,
            allow_empty=args.allow_empty,
            path=_store_path(args),
            backend=_backend_arg(args),
            kek_keychain_path=_kek_keychain_arg(args),
        )
        print(json.dumps(stats, indent=2, sort_keys=True))
        return 0
    except (ValidationError, ValueError, RegistryError, BackendError, FileNotFoundError, CryptoUnavailable) as exc:
        return _fatal(message=str(exc), code=EXIT_CODES["EPERM"])


def cmd_export(*, args: argparse.Namespace) -> int:
    from secrets_kit.utils.exporters import (
        export_dotenv_placeholders,
        export_shell_lines,
    )

    try:
        selected = _select_entries(args=args, require_explicit_selection=True)
        if not selected:
            return _fatal(message="no matching entries selected for export", code=EXIT_CODES["ENOENT"])

        if args.format == "shell":
            print(export_shell_lines(env_map=_build_env_map(entries=selected, args=args)))
            return 0

        if args.format == "dotenv":
            keys = [meta.name for meta in selected]
            print(export_dotenv_placeholders(keys=keys))
            return 0

        if args.format == "encrypted-json":
            ensure_crypto_available()
            password = _read_password(
                value=args.password,
                use_stdin=args.password_stdin,
                prompt="new password to encrypt the backup file: ",
            )
            items: list[dict[str, str]] = []
            for meta in sorted(selected, key=lambda item: item.name):
                items.append(
                    {
                        "metadata": meta.to_dict(),
                        "value": get_secret(
                            service=meta.service,
                            account=meta.account,
                            name=meta.name,
                            **_backend_access_kwargs(args),
                        ),
                    }
                )
            plain = build_plain_export(entries=items)
            encrypted = encrypt_payload(payload=plain, password=password)
            output = json.dumps(encrypted.__dict__, indent=2, sort_keys=True)
            if args.out:
                Path(args.out).write_text(output + "\n", encoding="utf-8")
            else:
                print(output)
            return 0

        return _fatal(message=f"unsupported format: {args.format}", code=EXIT_CODES["ENOTSUP"])
    except (ValidationError, RegistryError, BackendError, CryptoUnavailable) as exc:
        return _fatal(message=str(exc), code=EXIT_CODES["EPERM"])

