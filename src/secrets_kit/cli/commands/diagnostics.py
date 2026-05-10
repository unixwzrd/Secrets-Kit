"""Diagnostics, keychain UX, and version/helper subcommands."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict

from secrets_kit.backends.security import (
    BackendError,
    check_security_cli,
    doctor_roundtrip,
    harden_keychain,
    keychain_accessible,
    keychain_path,
    keychain_policy,
    lock_keychain,
    unlock_keychain,
)
from secrets_kit.models.core import EntryMetadata, ValidationError
from secrets_kit.recovery.recover_sources import iter_recover_candidates
from secrets_kit.registry.core import RegistryError, ensure_defaults_storage, ensure_registry_storage, load_registry
from secrets_kit.registry.resolve import _read_metadata
from secrets_kit.utils.helper_status import helper_status

from secrets_kit.cli.support.args import _backend_access_kwargs, _backend_arg, _doctor_skip_missing_secret_scan, _keychain_arg, _kek_keychain_arg, _store_path
from secrets_kit.cli.support.interaction import _confirm, _fatal, _format_tags, _print_table
from secrets_kit.cli.support.metadata_selection import _resolve_status
from secrets_kit.cli.support.version_info import _cli_version, _version_info_dict


def cmd_doctor(*, args: argparse.Namespace) -> int:
    from secrets_kit.backends.security import is_secure_backend, is_sqlite_backend, secret_exists

    backend = _backend_arg(args)
    status: dict = {
        "security_cli": False,
        "registry": False,
        "defaults": False,
        "keychain_roundtrip": False,
        "registry_path": None,
        "defaults_path": None,
        "metadata_keychain_drift": [],
        "entries_using_registry_fallback": [],
        "rotation_warnings": [],
    }
    if is_secure_backend(backend):
        if check_security_cli():
            status["security_cli"] = True
        else:
            print(json.dumps(status, indent=2, sort_keys=True))
            return _fatal(message="security CLI not found", code=1)
    else:
        status["security_cli"] = check_security_cli()

    try:
        path = ensure_registry_storage()
        status["registry"] = True
        status["registry_path"] = str(path)
    except RegistryError as exc:
        print(json.dumps(status, indent=2, sort_keys=True))
        return _fatal(message=str(exc), code=1)

    try:
        dpath = ensure_defaults_storage()
        status["defaults"] = True
        status["defaults_path"] = str(dpath)
    except RegistryError as exc:
        print(json.dumps(status, indent=2, sort_keys=True))
        return _fatal(message=str(exc), code=1)

    try:
        doctor_roundtrip(**_backend_access_kwargs(args))
        status["keychain_roundtrip"] = True
    except BackendError as exc:
        print(json.dumps(status, indent=2, sort_keys=True))
        return _fatal(message=str(exc), code=1)

    try:
        entries = load_registry()
        drift = []
        fallback = []
        warnings = []
        for meta in sorted(entries.values(), key=lambda item: (item.service, item.account, item.name)):
            if not secret_exists(service=meta.service, account=meta.account, name=meta.name, **_backend_access_kwargs(args)):
                if _doctor_skip_missing_secret_scan(args):
                    continue
                drift.append(
                    {
                        "name": meta.name,
                        "service": meta.service,
                        "account": meta.account,
                    }
                )
                continue
            resolved = _read_metadata(
                service=meta.service,
                account=meta.account,
                name=meta.name,
                registry=entries,
                **_backend_access_kwargs(args),
            )
            if resolved and resolved["metadata_source"] == "registry-fallback":
                fallback.append(
                    {
                        "name": meta.name,
                        "service": meta.service,
                        "account": meta.account,
                    }
                )
            if resolved and isinstance(resolved["metadata"], EntryMetadata):
                entry_status = _resolve_status(metadata=resolved["metadata"])
                if entry_status:
                    warnings.append(
                        {
                            "name": meta.name,
                            "service": meta.service,
                            "account": meta.account,
                            "status": entry_status,
                        }
                    )
        status["metadata_keychain_drift"] = drift
        status["entries_using_registry_fallback"] = fallback
        status["rotation_warnings"] = warnings
        if is_sqlite_backend(backend):
            from secrets_kit.backends.sqlite import SqliteSecretStore

            spath = _store_path(args)
            if spath:
                st = SqliteSecretStore(db_path=spath, kek_keychain_path=_kek_keychain_arg(args))
                status["backend_security_posture"] = asdict(st.security_posture())
                status["backend_capabilities"] = {**asdict(st.capabilities())}
        elif is_secure_backend(backend):
            from secrets_kit.backends.security_store import KeychainBackendStore

            st = KeychainBackendStore(path=_keychain_arg(args))
            status["backend_security_posture"] = asdict(st.security_posture())
            status["backend_capabilities"] = {**asdict(st.capabilities())}
    except (RegistryError, BackendError) as exc:
        print(json.dumps(status, indent=2, sort_keys=True))
        return _fatal(message=str(exc), code=1)

    print(json.dumps(status, indent=2, sort_keys=True))
    if status["metadata_keychain_drift"] or status["entries_using_registry_fallback"]:
        return _fatal(message="metadata/keychain drift detected", code=1)
    return 0


def cmd_backend_index(*, args: argparse.Namespace) -> int:
    try:
        from secrets_kit.backends.base import resolve_backend_store

        store = resolve_backend_store(
            backend=_backend_arg(args),
            path=_store_path(args),
            kek_keychain_path=_kek_keychain_arg(args),
        )
        for row in store.iter_index():
            print(json.dumps(row.to_safe_dict(), sort_keys=True))
        return 0
    except (BackendError, ValidationError, RegistryError, OSError) as exc:
        return _fatal(message=str(exc), code=1)


def cmd_rebuild_index(*, args: argparse.Namespace) -> int:
    try:
        from secrets_kit.backends.base import resolve_backend_store

        store = resolve_backend_store(
            backend=_backend_arg(args),
            path=_store_path(args),
            kek_keychain_path=_kek_keychain_arg(args),
        )
        store.rebuild_index()
        print(json.dumps({"rebuilt": True, "backend": _backend_arg(args)}, indent=2, sort_keys=True))
        return 0
    except (BackendError, ValidationError, RegistryError, OSError) as exc:
        return _fatal(message=str(exc), code=1)


def cmd_journal_append(*, args: argparse.Namespace) -> int:
    try:
        from secrets_kit.registry.journal import append_journal_event

        raw = getattr(args, "event_json", "") or ""
        evt = json.loads(raw)
        if not isinstance(evt, dict):
            return _fatal(message="journal event must be a JSON object", code=1)
        path = append_journal_event(home=None, event=evt)
        print(json.dumps({"written": True, "path": str(path)}, sort_keys=True))
        return 0
    except json.JSONDecodeError as exc:
        return _fatal(message=str(exc), code=1)
    except (RegistryError, OSError) as exc:
        return _fatal(message=str(exc), code=1)


def cmd_unlock(*, args: argparse.Namespace) -> int:
    if not check_security_cli():
        return _fatal(message="security CLI not found", code=1)

    target = keychain_path(path=args.keychain)
    command = f"security unlock-keychain {target}"
    harden_command = f"security set-keychain-settings -l -u -t {args.timeout} {target}"
    policy = None
    try:
        policy = keychain_policy(path=target)
    except BackendError:
        policy = None

    print("")
    print("********************************************************************************")
    print("")
    print("About to run:")
    print("")
    print(f"  {command}")
    print("")
    print("This will prompt macOS for the keychain password if needed.")
    print("Secrets-Kit does not read, capture, or store that password.")
    if policy and policy.get("no_timeout"):
        print("")
        print("WARNING: relaxed keychain policy detected: no timeout is configured.")
        print("Suggested hardening command:")
        print("")
        print(f"  {harden_command}")
        print("")
        print("Recommended policy: lock on sleep and lock after timeout.")
    print("********************************************************************************")
    print("")

    if args.dry_run:
        return 0

    if keychain_accessible(path=target):
        print(f"keychain already accessible: {target}")
        return 0

    if not args.yes and not _confirm(prompt=f"Proceed with unlocking {target}?"):
        print("aborted")
        return 1

    try:
        unlock_keychain(path=target)
        print(f"unlocked: {target}")
        if args.harden:
            print("")
            print("********************************************************************************")
            print("")
            print("About to run:")
            print("")
            print(f"  {harden_command}")
            print("")
            print("This will enable lock-on-sleep and lock-after-timeout for the keychain.")
            print("********************************************************************************")
            print("")
            harden_keychain(path=target, timeout_seconds=args.timeout)
            print(f"hardened: {target} timeout={args.timeout}s")
        return 0
    except BackendError as exc:
        return _fatal(message=str(exc), code=1)


def cmd_lock(*, args: argparse.Namespace) -> int:
    if not check_security_cli():
        return _fatal(message="security CLI not found", code=1)

    target = keychain_path(path=args.keychain)

    if args.dry_run:
        print(f"security lock-keychain {target}")
        return 0

    try:
        print(f"locking keychain: {target}")
        lock_keychain(path=target)
        print(f"locked: {target}")
        return 0
    except BackendError as exc:
        return _fatal(message=str(exc), code=1)


def cmd_keychain_status(*, args: argparse.Namespace) -> int:
    if not check_security_cli():
        return _fatal(message="security CLI not found", code=1)

    target = keychain_path(path=args.keychain)
    try:
        policy = keychain_policy(path=target)
    except BackendError as exc:
        return _fatal(message=str(exc), code=1)

    output = {
        "path": target,
        "accessible": keychain_accessible(path=target),
        "no_timeout": policy["no_timeout"],
        "lock_on_sleep": policy["lock_on_sleep"],
        "timeout_seconds": policy["timeout_seconds"],
        "raw": policy["raw"],
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    if output["no_timeout"]:
        print(
            f"WARNING: relaxed keychain policy detected. Suggested command:\n"
            f"  security set-keychain-settings -l -u -t 3600 {target}",
            file=sys.stderr,
        )
    return 0


def cmd_version(*, args: argparse.Namespace) -> int:
    if getattr(args, "version_json", False):
        print(json.dumps(_version_info_dict(), indent=2, sort_keys=True))
        return 0
    if getattr(args, "version_info", False):
        data = _version_info_dict()
        lines = [
            f"version: {data['version']}",
            f"platform: {data['platform']}",
            f"python: {data['python']}",
        ]
        dp = data.get("defaults_path")
        lines.append(f"defaults_path: {dp if dp else '(unknown)'}")
        defaults = data.get("defaults") or {}
        if defaults:
            lines.append("defaults:")
            for k in sorted(defaults.keys(), key=str):
                lines.append(f"  {k}: {defaults[k]!r}")
        else:
            lines.append("defaults: (none)")
        ba = data.get("backend_availability") or {}
        lines.append(
            "backend_availability: "
            + ", ".join(f"{k}={ba[k]}" for k in sorted(ba.keys(), key=str))
        )
        hb = data.get("helper") or {}
        lines.append(f"helper.installed: {hb.get('installed')}")
        lines.append(f"helper.path: {hb.get('path') or '(none)'}")
        lines.append(f"helper.bundled_path: {hb.get('bundled_path') or '(none)'}")
        print("\n".join(lines))
        return 0
    print(_cli_version())
    return 0


def cmd_helper_status(*, args: argparse.Namespace) -> int:
    del args
    print(json.dumps(helper_status(), indent=2, sort_keys=True))
    return 0
