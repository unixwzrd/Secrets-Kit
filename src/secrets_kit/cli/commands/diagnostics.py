"""
secrets_kit.cli.commands.diagnostics

Diagnostics, keychain UX, and version/helper subcommands.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict

from secrets_kit.backends.security import (
    BACKEND_SQLITE,
    BackendError,
    check_security_cli,
    doctor_roundtrip,
    harden_keychain,
    keychain_accessible,
    keychain_path,
    keychain_policy,
    lock_keychain,
    normalize_backend,
    unlock_keychain,
)
from secrets_kit.cli.constants.exit_codes import EXIT_CODES
from secrets_kit.cli.support.args import (
    _backend_access_kwargs,
    _backend_arg,
    _doctor_skip_missing_secret_scan,
    _kek_keychain_arg,
    _keychain_arg,
    _store_path,
)
from secrets_kit.cli.support.interaction import (
    _confirm,
    _fatal,
    _format_tags,
    _print_table,
)
from secrets_kit.cli.support.metadata_selection import _resolve_status
from secrets_kit.cli.support.version_info import _cli_version, _version_info_dict
from secrets_kit.models.core import EntryMetadata, ValidationError
from secrets_kit.recovery.recover_sources import iter_recover_candidates
from secrets_kit.registry.core import (
    RegistryError,
    defaults_path,
    ensure_defaults_storage,
    ensure_registry_storage,
    load_registry,
    registry_dir,
    save_defaults,
)
from secrets_kit.registry.resolve import _read_metadata
from secrets_kit.utils.helper_status import helper_status


def _scan_invalid_backend_references() -> list[dict]:
    """Return configs/env whose ``backend`` value does not :func:`normalize_backend`."""
    refs: list[dict] = []
    env_b = os.environ.get("SECKIT_DEFAULT_BACKEND", "").strip()
    if env_b:
        try:
            normalize_backend(env_b)
        except BackendError:
            refs.append({"source": "env", "var": "SECKIT_DEFAULT_BACKEND", "value": env_b})
    try:
        dpath = defaults_path()
        if dpath.exists():
            raw = json.loads(dpath.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                b = raw.get("backend")
                if b is not None:
                    try:
                        normalize_backend(str(b))
                    except BackendError:
                        refs.append({"source": "defaults.json", "path": str(dpath), "value": b})
    except (json.JSONDecodeError, OSError, TypeError):
        pass
    try:
        cpath = registry_dir() / "config.json"
        if cpath.exists():
            raw = json.loads(cpath.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                b = raw.get("backend")
                if b is not None:
                    try:
                        normalize_backend(str(b))
                    except BackendError:
                        refs.append({"source": "config.json", "path": str(cpath), "value": b})
    except (json.JSONDecodeError, OSError, TypeError):
        pass
    return refs


def cmd_doctor(*, args: argparse.Namespace) -> int:
    """Run JSON diagnostics: security CLI, roundtrip, registry drift, backend posture.

    Checks:
    - ``security`` CLI availability and keychain roundtrip
    - Registry file health and metadata consistency
    - Default configuration validity (with ``--fix-defaults``)
    - Rotation warnings for entries with ``rotation_days``
    - Invalid backend references in the registry
    Emits a single JSON object to stdout.
    """
    from secrets_kit.backends.security import (
        is_secure_backend,
        is_sqlite_backend,
        secret_exists,
    )

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
        "invalid_backend_references": [],
        "reconcile_read_only_tools": (
            "seckit reconcile inspect|lineage|explain|verify — SQLite lineage diagnostics; "
            "report-only (no auto-repair)"
        ),
    }

    if getattr(args, "fix_defaults", False):
        try:
            dfix = defaults_path()
            if dfix.exists():
                payload_fix = json.loads(dfix.read_text(encoding="utf-8"))
                if isinstance(payload_fix, dict) and "backend" in payload_fix:
                    try:
                        normalize_backend(str(payload_fix["backend"]))
                    except BackendError:
                        cleaned = {k: v for k, v in payload_fix.items() if k != "backend"}
                        save_defaults(payload=cleaned)
        except (json.JSONDecodeError, OSError, TypeError, ValueError, RegistryError):
            pass

    status["invalid_backend_references"] = _scan_invalid_backend_references()

    if is_secure_backend(backend):
        if check_security_cli():
            status["security_cli"] = True
        else:
            print(json.dumps(status, indent=2, sort_keys=True))
            return _fatal(message="security CLI not found", code=EXIT_CODES["EAPP_SECURITY_CLI_MISSING"])
    else:
        status["security_cli"] = check_security_cli()

    try:
        path = ensure_registry_storage()
        status["registry"] = True
        status["registry_path"] = str(path)
    except RegistryError as exc:
        print(json.dumps(status, indent=2, sort_keys=True))
        return _fatal(message=str(exc), code=EXIT_CODES["EPERM"])

    try:
        dpath = ensure_defaults_storage()
        status["defaults"] = True
        status["defaults_path"] = str(dpath)
    except RegistryError as exc:
        print(json.dumps(status, indent=2, sort_keys=True))
        return _fatal(message=str(exc), code=EXIT_CODES["EPERM"])

    try:
        doctor_roundtrip(**_backend_access_kwargs(args))
        status["keychain_roundtrip"] = True
    except BackendError as exc:
        print(json.dumps(status, indent=2, sort_keys=True))
        return _fatal(message=str(exc), code=EXIT_CODES["EPERM"])

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
            from secrets_kit.backends.keychain import KeychainBackendStore

            st = KeychainBackendStore(path=_keychain_arg(args))
            status["backend_security_posture"] = asdict(st.security_posture())
            status["backend_capabilities"] = {**asdict(st.capabilities())}
    except (RegistryError, BackendError) as exc:
        print(json.dumps(status, indent=2, sort_keys=True))
        return _fatal(message=str(exc), code=EXIT_CODES["EPERM"])

    print(json.dumps(status, indent=2, sort_keys=True))
    if status["metadata_keychain_drift"] or status["entries_using_registry_fallback"]:
        return _fatal(message="metadata/keychain drift detected", code=EXIT_CODES["EAPP_METADATA_DRIFT"])
    return 0


def cmd_sqlite_inspect(*, args: argparse.Namespace) -> int:
    """Dump SQLite index rows and optional unlock summaries (no secret values).

    With ``--summaries``, also decrypts each row to report the secret byte
    length and lineage fields. Requires a valid KEK when the database is
    passphrase- or keychain-protected.
    """
    if _backend_arg(args) != BACKEND_SQLITE:
        return _fatal(message="sqlite-inspect requires --backend sqlite", code=EXIT_CODES["EINVAL"])
    spath = _store_path(args)
    if not spath:
        return _fatal(message="sqlite-inspect requires --db PATH", code=EXIT_CODES["EINVAL"])
    try:
        from secrets_kit.backends.sqlite import SqliteSecretStore

        store = SqliteSecretStore(db_path=spath, kek_keychain_path=_kek_keychain_arg(args))
        payload: dict = {
            "index_rows": [r.to_safe_dict() for r in store.iter_index()],
            "backend_security_posture": asdict(store.security_posture()),
        }
        if getattr(args, "summaries", False):
            summaries = []
            for idx, resolved in store.iter_unlocked():
                summaries.append(
                    {
                        "entry_id": idx.entry_id,
                        "deleted": idx.deleted,
                        "locator_hash": idx.locator_hash,
                        "secret_byte_len": len(resolved.secret.encode("utf-8")),
                        "service": resolved.metadata.service,
                        "account": resolved.metadata.account,
                        "name": resolved.metadata.name,
                        "generation": idx.generation,
                        "tombstone_generation": idx.tombstone_generation,
                    }
                )
            payload["unlock_summaries"] = summaries
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    except (BackendError, ValidationError, RegistryError, OSError) as exc:
        return _fatal(message=str(exc), code=EXIT_CODES["EPERM"])


def cmd_backend_index(*, args: argparse.Namespace) -> int:
    """Emit decrypt-safe backend index rows as JSON lines (one per line).

    Uses ``BackendStore.iter_index``; no secret values are materialised.
    """
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
        return _fatal(message=str(exc), code=EXIT_CODES["EPERM"])


def cmd_rebuild_index(*, args: argparse.Namespace) -> int:
    """Rebuild the backend decrypt-free index from authority payloads.

    For SQLite this repairs ``locator_hash`` and ``content_hash`` columns
    by re-scanning the encrypted payloads without materialising plaintext.
    """
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
        return _fatal(message=str(exc), code=EXIT_CODES["EPERM"])


def cmd_journal_append(*, args: argparse.Namespace) -> int:
    """Append one JSON object line to ``registry_events.jsonl``.

    The event must be a JSON object (not an array or scalar). This is an
    operational / sync aid; advanced usage only.
    """
    try:
        from secrets_kit.registry.journal import append_journal_event

        raw = getattr(args, "event_json", "") or ""
        evt = json.loads(raw)
        if not isinstance(evt, dict):
            return _fatal(message="journal event must be a JSON object", code=EXIT_CODES["EINVAL"])
        path = append_journal_event(home=None, event=evt)
        print(json.dumps({"written": True, "path": str(path)}, sort_keys=True))
        return 0
    except json.JSONDecodeError as exc:
        return _fatal(message=str(exc), code=EXIT_CODES["EPERM"])
    except (RegistryError, OSError) as exc:
        return _fatal(message=str(exc), code=EXIT_CODES["EPERM"])


def cmd_unlock(*, args: argparse.Namespace) -> int:
    """Unlock the configured macOS Keychain backend.

    Detects relaxed keychain policies (no timeout) and suggests a hardening
    command. With ``--harden``, applies ``lock-on-sleep`` and ``lock-after-timeout``
    settings immediately after unlock. Secrets-Kit never reads or stores the
    keychain password.
    """
    if not check_security_cli():
        return _fatal(message="security CLI not found", code=EXIT_CODES["EAPP_SECURITY_CLI_MISSING"])

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
        return EXIT_CODES["ECANCELED"]

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
        return _fatal(message=str(exc), code=EXIT_CODES["EPERM"])


def cmd_lock(*, args: argparse.Namespace) -> int:
    """Lock the configured macOS Keychain backend."""
    if not check_security_cli():
        return _fatal(message="security CLI not found", code=EXIT_CODES["EAPP_SECURITY_CLI_MISSING"])

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
        return _fatal(message=str(exc), code=EXIT_CODES["EPERM"])


def cmd_keychain_status(*, args: argparse.Namespace) -> int:
    """Report macOS Keychain accessibility and lock policy as JSON.

    Emits a warning to stderr when a relaxed (no-timeout) policy is detected.
    """
    if not check_security_cli():
        return _fatal(message="security CLI not found", code=EXIT_CODES["EAPP_SECURITY_CLI_MISSING"])

    target = keychain_path(path=args.keychain)
    try:
        policy = keychain_policy(path=target)
    except BackendError as exc:
        return _fatal(message=str(exc), code=EXIT_CODES["EPERM"])

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
    """Print the installed seckit version.

    ``--json`` emits a structured JSON object. ``--info`` adds platform,
    Python version, defaults summary, and helper status.
    """
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
        kc = data.get("keychain_access") or {}
        lines.append(
            "keychain_access: "
            + ", ".join(f"{k}={kc[k]!r}" for k in sorted(kc.keys(), key=str))
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
    """Print backend availability and helper metadata as JSON (no secrets)."""
    del args
    print(json.dumps(helper_status(), indent=2, sort_keys=True))
    return 0
