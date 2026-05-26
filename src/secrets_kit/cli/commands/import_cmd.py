"""
secrets_kit.cli.commands.import_cmd

Import command implementations.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional

from secrets_kit.backends.common import BackendError
from secrets_kit.backends.dispatch import read_secret_value, secret_exists_for_backend, write_secret
from secrets_kit.backends.sqlite import SQLiteBackendError
from secrets_kit.cli.io import _confirm, _fatal, _read_password
from secrets_kit.cli.selection import _backend_arg, _keychain_arg
from secrets_kit.cli.tables import _format_tags, _print_table
from secrets_kit.cli.taxonomy_prompt import resolve_name_for_cli
from secrets_kit.crypto.cli import decrypt_payload, ensure_crypto_available
from secrets_kit.crypto.errors import CryptoUnavailable
from secrets_kit.importers import (
    ImportCandidate,
    candidates_from_dotenv,
    candidates_from_env,
    candidates_from_file,
)
from secrets_kit.locale import msg
from secrets_kit.models import EntryMetadata, ValidationError, now_utc_iso
from secrets_kit.registry import RegistryError, load_registry, upsert_metadata
from secrets_kit.registry.resolve import merge_import_metadata, read_metadata
from secrets_kit.taxonomy.register import sync_vocabulary_on_write


def _merge_candidates(*, groups: Iterable[List[ImportCandidate]]) -> Dict[str, ImportCandidate]:
    merged: Dict[str, ImportCandidate] = {}
    for group in groups:
        for candidate in group:
            merged[candidate.metadata.key()] = candidate
    return merged


def _apply_candidates(
    *,
    candidates: Dict[str, ImportCandidate],
    allow_overwrite: bool,
    dry_run: bool,
    allow_empty: bool,
    path: Optional[str] = None,
    backend: str = "keychain",
    sqlite_dev_mode: bool = False,
    args: Optional[argparse.Namespace] = None,
) -> Dict[str, int]:
    registry = load_registry()
    stats = {"created": 0, "updated": 0, "skipped": 0, "unchanged": 0}
    for key in sorted(candidates):
        candidate = candidates[key]
        resolved = read_metadata(
            service=candidate.metadata.service,
            account=candidate.metadata.account,
            name=candidate.metadata.name,
            registry=registry,
            path=path,
            backend=backend,
            sqlite_dev_mode=sqlite_dev_mode,
        )
        exists = secret_exists_for_backend(
            service=candidate.metadata.service,
            account=candidate.metadata.account,
            name=candidate.metadata.name,
            backend=backend,
            keychain_path=path,
            sqlite_dev_mode=sqlite_dev_mode,
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
                candidate.metadata = merge_import_metadata(
                    existing=existing_meta,
                    incoming=candidate.metadata,
                    backend=backend,
                    keychain_path=path,
                    sqlite_dev_mode=sqlite_dev_mode,
                )
                candidate.metadata.created_at = existing_meta.created_at
            if exists and not dry_run:
                current_value = read_secret_value(
                    service=candidate.metadata.service,
                    account=candidate.metadata.account,
                    name=candidate.metadata.name,
                    backend=backend,
                    keychain_path=path,
                    sqlite_dev_mode=sqlite_dev_mode,
                )
                if current_value == candidate.value:
                    stats["unchanged"] += 1
                    continue
        candidate.metadata.updated_at = now_utc_iso()
        if dry_run:
            stats["updated" if exists else "created"] += 1
            continue
        if args is not None:
            meta = candidate.metadata
            entry_type = resolve_name_for_cli(
                label="entry_type",
                raw=meta.entry_type,
                args=args,
                sqlite_dev_mode=sqlite_dev_mode,
            )
            entry_kind = resolve_name_for_cli(
                label="entry_kind",
                raw=meta.entry_kind,
                args=args,
                sqlite_dev_mode=sqlite_dev_mode,
            )
            resolved_tags = [
                resolve_name_for_cli(
                    label="tag", raw=tag, args=args, sqlite_dev_mode=sqlite_dev_mode
                )
                for tag in meta.tags
            ]
            vocab = sync_vocabulary_on_write(
                entry_type=entry_type,
                entry_kind=entry_kind,
                tags=resolved_tags,
                backend=backend,
                keychain_path=path,
                sqlite_dev_mode=sqlite_dev_mode,
            )
            meta.entry_type = vocab.entry_type  # type: ignore[assignment]
            meta.entry_kind = vocab.entry_kind  # type: ignore[assignment]
            meta.tags = vocab.tags
        write_secret(
            service=candidate.metadata.service,
            account=candidate.metadata.account,
            name=candidate.metadata.name,
            value=candidate.value,
            metadata=candidate.metadata,
            backend=backend,
            keychain_path=path,
            sqlite_dev_mode=sqlite_dev_mode,
            label=candidate.metadata.name,
        )
        upsert_metadata(metadata=candidate.metadata)
        stats["updated" if exists else "created"] += 1
    return stats


def _preview_candidates(*, merged: Dict[str, ImportCandidate]) -> None:
    print("plan:")
    rows: List[List[str]] = []
    for key in sorted(merged):
        candidate = merged[key]
        meta = candidate.metadata
        rows.append(
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
    _print_table(
        headers=["NAME", "TYPE", "KIND", "SERVICE", "ACCOUNT", "TAGS", "SOURCE", "VALUE"], rows=rows
    )


def _run_import(
    *,
    args: argparse.Namespace,
    load_candidates: Callable[[], Dict[str, ImportCandidate]],
) -> int:
    try:
        merged = load_candidates()
        _preview_candidates(merged=merged)
        if not merged:
            print(msg("cli.common.nothing_to_import"))
            return 0
        if (
            not args.dry_run
            and not args.yes
            and not _confirm(prompt=msg("prompts.import_entries", count=len(merged)))
        ):
            print(msg("cli.common.aborted"))
            return 1
        stats = _apply_candidates(
            candidates=merged,
            allow_overwrite=args.allow_overwrite or getattr(args, "upsert", False),
            dry_run=args.dry_run,
            allow_empty=args.allow_empty,
            path=_keychain_arg(args),
            backend=_backend_arg(args),
            sqlite_dev_mode=getattr(args, "sqlite_dev_mode", False),
            args=args,
        )
        print(json.dumps(stats, indent=2, sort_keys=True))
        return 0
    except (
        ValidationError,
        ValueError,
        RegistryError,
        BackendError,
        SQLiteBackendError,
        FileNotFoundError,
    ) as exc:
        return _fatal(message=str(exc), code=1)


def cmd_import_env(*, args: argparse.Namespace) -> int:
    if not args.dotenv and not args.from_env:
        return _fatal(message=msg("errors.import.requires_source"))

    def load_candidates() -> Dict[str, ImportCandidate]:
        groups: List[List[ImportCandidate]] = []
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
        return _merge_candidates(groups=groups)

    return _run_import(args=args, load_candidates=load_candidates)


def cmd_import_file(*, args: argparse.Namespace) -> int:
    def load_candidates() -> Dict[str, ImportCandidate]:
        rows = candidates_from_file(
            file_path=Path(args.file),
            fmt=args.format,
            default_type=args.type,
            default_kind=args.kind,
        )
        return {row.metadata.key(): row for row in rows}

    return _run_import(args=args, load_candidates=load_candidates)


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
            return _fatal(message=msg("errors.import.unsupported_payload"), code=1)
        entries = decrypted.get("entries", [])

        def load_candidates() -> Dict[str, ImportCandidate]:
            rows: List[ImportCandidate] = []
            for row in entries:
                if not isinstance(row, dict):
                    continue
                meta = EntryMetadata.from_dict(row.get("metadata", {}))
                rows.append(ImportCandidate(metadata=meta, value=str(row.get("value", "")).strip()))
            return {row.metadata.key(): row for row in rows}

        return _run_import(args=args, load_candidates=load_candidates)
    except (
        ValidationError,
        ValueError,
        RegistryError,
        BackendError,
        SQLiteBackendError,
        FileNotFoundError,
        CryptoUnavailable,
    ) as exc:
        return _fatal(message=str(exc), code=1)


__all__ = [
    "_apply_candidates",
    "_merge_candidates",
    "_preview_candidates",
    "_run_import",
    "cmd_import_encrypted",
    "cmd_import_env",
    "cmd_import_file",
]
