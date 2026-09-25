"""
secrets_kit.cli.selection

Entry selection and environment-map helpers shared by export and run commands.
"""

from __future__ import annotations

import argparse
from typing import Dict, List, Optional

from secrets_kit.backends.common import BACKEND_KEYCHAIN
from secrets_kit.backends.dispatch import build_env_map, list_secret_metadata
from secrets_kit.models import EntryMetadata, validate_key_name
from secrets_kit.registry.resolve import read_metadata


def _keychain_arg(args: argparse.Namespace) -> Optional[str]:
    return getattr(args, "keychain", None)


def _backend_arg(args: argparse.Namespace) -> str:
    return getattr(args, "backend", BACKEND_KEYCHAIN)


def _select_entries(
    *,
    args: argparse.Namespace,
    require_explicit_selection: bool,
) -> List[EntryMetadata]:
    selected: Dict[str, EntryMetadata] = {}
    names = (
        {validate_key_name(name=item) for item in args.names.split(",")}
        if getattr(args, "names", None)
        else set()
    )

    if names:
        for name in sorted(names):
            resolved = read_metadata(
                service=args.service,
                account=args.account,
                name=name,
                path=_keychain_arg(args),
                backend=_backend_arg(args),
            )
            if not resolved:
                continue
            meta = resolved["metadata"]
            if isinstance(meta, EntryMetadata):
                selected[meta.key()] = meta
        return sorted(selected.values(), key=lambda item: item.name)

    explicit_filter = bool(
        getattr(args, "tag", None)
        or getattr(args, "type", None)
        or getattr(args, "kind", None)
        or getattr(args, "all", False)
    )
    if require_explicit_selection and not explicit_filter:
        return []

    for meta in list_secret_metadata(
        backend=_backend_arg(args),
        service=args.service,
        account=args.account,
        keychain_path=_keychain_arg(args),
    ):
        if getattr(args, "type", None) and meta.entry_type != args.type:
            continue
        if getattr(args, "kind", None) and meta.entry_kind != args.kind:
            continue
        if getattr(args, "tag", None) and args.tag not in meta.tags:
            continue
        selected[meta.key()] = meta

    return sorted(selected.values(), key=lambda item: item.name)


def _build_env_map(*, entries: List[EntryMetadata], args: argparse.Namespace) -> Dict[str, str]:
    return build_env_map(
        entries=entries,
        backend=_backend_arg(args),
        keychain_path=_keychain_arg(args),
    )


__all__ = ["_backend_arg", "_build_env_map", "_keychain_arg", "_select_entries"]
