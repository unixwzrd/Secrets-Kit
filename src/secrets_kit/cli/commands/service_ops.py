"""Copy secrets between service scopes."""

from __future__ import annotations

import argparse
import json

from secrets_kit.backends.security import BackendError, get_secret, secret_exists, set_secret
from secrets_kit.models.core import EntryMetadata, ValidationError, now_utc_iso
from secrets_kit.registry.core import RegistryError, upsert_metadata
from secrets_kit.registry.resolve import _read_metadata

from secrets_kit.cli.support.args import _backend_access_kwargs, _backend_arg, _kek_keychain_arg, _store_path
from secrets_kit.cli.support.defaults import _current_os_account
from secrets_kit.cli.support.interaction import _fatal
from secrets_kit.cli.support.metadata_selection import _select_entries


def cmd_service_copy(*, args: argparse.Namespace) -> int:
    try:
        from_account = args.from_account or _current_os_account()
        to_account = args.to_account or from_account
        selector_args = argparse.Namespace(
            service=args.from_service,
            account=from_account,
            names=args.names,
            tag=args.tag,
            type=args.type,
            kind=args.kind,
            all=True,
            keychain=args.keychain,
            db=getattr(args, "db", None),
            backend=_backend_arg(args),
        )
        selected = _select_entries(args=selector_args, require_explicit_selection=False)
        if not selected:
            return _fatal(
                message=f"no matching entries selected for service copy: {args.from_service}/{from_account}",
                code=1,
            )

        stats = {"created": 0, "updated": 0, "skipped": 0}
        for source_meta in selected:
            dest_exists = secret_exists(
                service=args.to_service,
                account=to_account,
                name=source_meta.name,
                **_backend_access_kwargs(args),
            )
            if dest_exists and not args.overwrite:
                stats["skipped"] += 1
                continue

            value = get_secret(
                service=source_meta.service,
                account=source_meta.account,
                name=source_meta.name,
                **_backend_access_kwargs(args),
            )
            dest_meta = EntryMetadata.from_dict(source_meta.to_dict())
            dest_meta.service = args.to_service
            dest_meta.account = to_account
            dest_meta.source = f"copy:{source_meta.service}/{source_meta.account}"
            dest_meta.updated_at = now_utc_iso()
            if not dest_exists:
                dest_meta.created_at = now_utc_iso()
            else:
                existing = _read_metadata(
                    service=args.to_service,
                    account=to_account,
                    name=source_meta.name,
                    path=_store_path(args),
                    backend=_backend_arg(args),
                    kek_keychain_path=_kek_keychain_arg(args),
                )
                if existing and isinstance(existing.get("metadata"), EntryMetadata):
                    dest_meta.created_at = existing["metadata"].created_at

            if not args.dry_run:
                set_secret(
                    service=args.to_service,
                    account=to_account,
                    name=source_meta.name,
                    value=value,
                    label=source_meta.name,
                    comment=dest_meta.to_keychain_comment(),
                    **_backend_access_kwargs(args),
                )
                upsert_metadata(metadata=dest_meta)
            stats["updated" if dest_exists else "created"] += 1

        print(json.dumps(stats, indent=2, sort_keys=True))
        return 0
    except (ValidationError, RegistryError, BackendError) as exc:
        return _fatal(message=str(exc), code=1)
