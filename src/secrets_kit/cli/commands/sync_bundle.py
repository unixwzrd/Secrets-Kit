"""Signed encrypted peer bundle subcommands."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List

from secrets_kit.backends.security import BackendError, get_secret
from secrets_kit.identity.core import IdentityError, load_identity
from secrets_kit.identity.peers import get_peer
from secrets_kit.models.core import ValidationError
from secrets_kit.registry.core import RegistryError
from secrets_kit.sync.bundle import SyncBundleError, build_bundle, decrypt_bundle_for_recipient, inspect_bundle, parse_bundle_file, verify_bundle_structure
from secrets_kit.sync.merge import apply_peer_sync_import, effective_origin_host

from secrets_kit.cli.support.args import _backend_access_kwargs
from secrets_kit.cli.support.interaction import _confirm, _fatal
from secrets_kit.cli.support.metadata_selection import _entries_match_domain_filter, _resolve_domains, _select_entries
from secrets_kit.cli.support.peer_sync_errors import _peer_sync_cli_error


def cmd_sync_export(*, args: argparse.Namespace) -> int:
    try:
        ident = load_identity()
        selected = _select_entries(args=args, require_explicit_selection=True)
        dfilter = _resolve_domains(domain=getattr(args, "domain", None), domains_csv=getattr(args, "domains", None))
        selected = _entries_match_domain_filter(entries=selected, domains=dfilter)
        if not selected:
            return _fatal(message="no matching entries selected for sync export", code=1)
        recipients = [(get_peer(alias=a).fingerprint, get_peer(alias=a).box_public()) for a in args.peer]
        entries: List[Dict[str, object]] = []
        for meta in sorted(selected, key=lambda item: item.name):
            value = get_secret(
                service=meta.service,
                account=meta.account,
                name=meta.name,
                **_backend_access_kwargs(args),
            )
            oh = effective_origin_host(meta=meta, default_host_id=ident.host_id)
            entries.append({"metadata": meta.to_dict(), "origin_host": oh, "value": value})
        bundle = build_bundle(
            identity=ident,
            recipient_records=recipients,
            entries=entries,
            domain_filter=dfilter or None,
        )
        out_path = Path(args.out).expanduser()
        out_path.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        summary = {
            "domain_filter": dfilter,
            "entry_count": len(entries),
            "out": str(out_path),
            "peers": list(args.peer),
            "signer_fingerprint": ident.signing_fingerprint_hex(),
        }
        if getattr(args, "json", False):
            print(json.dumps(summary, indent=2, sort_keys=True))
        else:
            print(json.dumps(summary, indent=2, sort_keys=True))
        return 0
    except ValidationError as exc:
        return _fatal(message=str(exc), code=1)
    except (BackendError, IdentityError, RegistryError, SyncBundleError) as exc:
        return _fatal(message=_peer_sync_cli_error(exc), code=1)


def cmd_sync_import(*, args: argparse.Namespace) -> int:
    try:
        ident = load_identity()
        text = Path(args.file).expanduser().read_text(encoding="utf-8")
        payload = parse_bundle_file(text)
        signer = get_peer(alias=args.signer)
        inner = decrypt_bundle_for_recipient(
            payload=payload,
            identity=ident,
            trusted_signer=signer.verify_key(),
        )
        raw_entries = inner.get("entries", [])
        if not isinstance(raw_entries, list):
            return _fatal(message="bundle inner entries must be an array", code=1)
        dfilter = _resolve_domains(domain=getattr(args, "domain", None), domains_csv=getattr(args, "domains", None))
        conv_entries = [e for e in raw_entries if isinstance(e, dict)]
        if len(conv_entries) != len(raw_entries):
            return _fatal(message="bundle inner entries must be objects", code=1)
        if not args.dry_run and not args.yes and not _confirm(
            prompt=f"Import {len(conv_entries)} entries from peer bundle (merge rules apply)?",
        ):
            print("aborted")
            return 1
        stats = apply_peer_sync_import(
            inner_entries=conv_entries,
            local_host_id=ident.host_id,
            dry_run=args.dry_run,
            **_backend_access_kwargs(args),
            domain_filter=dfilter or None,
        )
        out = dict(stats)
        out["bundle_export_id"] = inner.get("export_id", "")
        out["bundle_origin_host"] = inner.get("origin_host", "")
        print(json.dumps(out, indent=2, sort_keys=True))
        return 0
    except FileNotFoundError as exc:
        return _fatal(message=f"Peer sync: bundle file not found ({exc})", code=1)
    except OSError as exc:
        return _fatal(message=f"Peer sync: cannot read bundle file ({exc})", code=1)
    except ValidationError as exc:
        return _fatal(message=str(exc), code=1)
    except (BackendError, IdentityError, RegistryError, SyncBundleError) as exc:
        return _fatal(message=_peer_sync_cli_error(exc), code=1)


def cmd_sync_verify(*, args: argparse.Namespace) -> int:
    try:
        text = Path(args.file).expanduser().read_text(encoding="utf-8")
        payload = parse_bundle_file(text)
        vr = verify_bundle_structure(payload=payload)
        result: Dict[str, object] = {
            "entry_count": vr.entry_count,
            "message": vr.message,
            "ok": vr.ok,
            "signer_fingerprint": vr.signer_fingerprint,
            "signer_host_id": vr.signer_host_id,
        }
        if getattr(args, "try_decrypt", False):
            ident = load_identity()
            signer_peer = get_peer(alias=args.signer) if getattr(args, "signer", None) else None
            if signer_peer is None:
                result["decrypt_error"] = "sync verify --try-decrypt requires --signer"
            else:
                try:
                    inner = decrypt_bundle_for_recipient(
                        payload=payload,
                        identity=ident,
                        trusted_signer=signer_peer.verify_key(),
                    )
                    entries = inner.get("entries", [])
                    result["decrypt_ok"] = True
                    result["inner_entry_count"] = len(entries) if isinstance(entries, list) else 0
                except SyncBundleError as exc:
                    result["decrypt_ok"] = False
                    result["decrypt_error"] = _peer_sync_cli_error(exc)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if vr.ok else 1
    except FileNotFoundError as exc:
        return _fatal(message=f"Peer sync: bundle file not found ({exc})", code=1)
    except OSError as exc:
        return _fatal(message=f"Peer sync: cannot read bundle file ({exc})", code=1)
    except (SyncBundleError, IdentityError, RegistryError) as exc:
        return _fatal(message=_peer_sync_cli_error(exc), code=1)


def cmd_sync_inspect(*, args: argparse.Namespace) -> int:
    try:
        text = Path(args.file).expanduser().read_text(encoding="utf-8")
        payload = parse_bundle_file(text)
        info = inspect_bundle(payload=payload)
        print(json.dumps(info, indent=2, sort_keys=True))
        return 0
    except FileNotFoundError as exc:
        return _fatal(message=f"Peer sync: bundle file not found ({exc})", code=1)
    except OSError as exc:
        return _fatal(message=f"Peer sync: cannot read bundle file ({exc})", code=1)
    except SyncBundleError as exc:
        return _fatal(message=_peer_sync_cli_error(exc), code=1)
