"""
secrets_kit.cli.commands.peers

Trusted peer subcommands.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from secrets_kit.cli.constants.exit_codes import EXIT_CODES
from secrets_kit.cli.support.interaction import _fatal, _print_table
from secrets_kit.cli.support.peer_sync_errors import _peer_sync_cli_error
from secrets_kit.identity.core import IdentityError
from secrets_kit.identity.peers import (
    add_peer_from_file,
    get_peer,
    list_peers,
    remove_peer,
)
from secrets_kit.registry.core import RegistryError


def cmd_peer_add(*, args: argparse.Namespace) -> int:
    try:
        rec = add_peer_from_file(alias=args.alias, path=Path(args.export_path).expanduser())
        payload = {
            "alias": rec.alias,
            "fingerprint": rec.fingerprint,
            "host_id": rec.host_id,
            "trusted_at": rec.trusted_at,
        }
        if getattr(args, "json", False):
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(f"added peer {rec.alias} host_id={rec.host_id} fingerprint={rec.fingerprint[:16]}…")
        return 0
    except IdentityError as exc:
        return _fatal(message=f"Peer registry: invalid peer identity export file — {exc}", code=EXIT_CODES["EINVAL"])
    except RegistryError as exc:
        return _fatal(message=_peer_sync_cli_error(exc), code=EXIT_CODES["EAPP_PEER_NOT_FOUND"])


def cmd_peer_remove(*, args: argparse.Namespace) -> int:
    try:
        ok = remove_peer(alias=args.alias)
        if not ok:
            return _fatal(message=f"no peer named {args.alias!r}", code=EXIT_CODES["ENOENT"])
        if getattr(args, "json", False):
            print(json.dumps({"removed": args.alias}, indent=2, sort_keys=True))
        else:
            print(f"removed peer {args.alias}")
        return 0
    except RegistryError as exc:
        return _fatal(message=_peer_sync_cli_error(exc), code=EXIT_CODES["EAPP_PEER_NOT_FOUND"])


def cmd_peer_list(*, args: argparse.Namespace) -> int:
    try:
        rows = list_peers()
        if getattr(args, "json", False):
            payload = [
                {
                    "alias": p.alias,
                    "fingerprint": p.fingerprint,
                    "host_id": p.host_id,
                    "trusted_at": p.trusted_at,
                }
                for p in rows
            ]
            print(json.dumps(payload, indent=2, sort_keys=True))
            return 0
        if not rows:
            print("no peers")
            return 0
        _print_table(
            headers=["alias", "fingerprint", "host_id", "trusted_at"],
            rows=[
                [p.alias, p.fingerprint[:16] + "…", p.host_id, p.trusted_at]
                for p in rows
            ],
        )
        return 0
    except RegistryError as exc:
        return _fatal(message=str(exc), code=EXIT_CODES["EPERM"])


def cmd_peer_show(*, args: argparse.Namespace) -> int:
    try:
        p = get_peer(alias=args.alias)
        payload = {
            "alias": p.alias,
            "box_public": p.box_public_b64,
            "fingerprint": p.fingerprint,
            "host_id": p.host_id,
            "signing_public": p.signing_public_b64,
            "trusted_at": p.trusted_at,
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    except RegistryError as exc:
        return _fatal(message=_peer_sync_cli_error(exc), code=EXIT_CODES["EAPP_PEER_NOT_FOUND"])
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    except RegistryError as exc:
        return _fatal(message=_peer_sync_cli_error(exc), code=EXIT_CODES["EAPP_PEER_NOT_FOUND"])
