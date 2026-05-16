"""
secrets_kit.cli.commands.secrets

Core secret CRUD, list, explain, and run.
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone

from secrets_kit.backends.errors import BackendError
from secrets_kit.backends.operations import delete_secret, get_secret, set_secret
from secrets_kit.cli.constants.exit_codes import EXIT_CODES
from secrets_kit.cli.support.args import (
    _backend_access_kwargs,
    _backend_arg,
    _kek_keychain_arg,
    _store_path,
)
from secrets_kit.cli.support.env_exec import (
    _build_env_map,
    _child_command_args,
    _exec_child,
)
from secrets_kit.cli.support.interaction import (
    _confirm,
    _fatal,
    _format_tags,
    _parse_timestamp,
    _print_table,
    _read_value,
)
from secrets_kit.cli.support.metadata_selection import (
    _build_metadata,
    _resolve_status,
    _select_entries,
)
from secrets_kit.models.core import EntryMetadata, ValidationError, validate_key_name
from secrets_kit.registry.core import (
    RegistryError,
    delete_metadata,
    load_registry,
    upsert_metadata,
)
from secrets_kit.registry.resolve import _read_metadata


def cmd_set(*, args: argparse.Namespace) -> int:
    """Store a secret in the backend and update registry metadata.

    Validates the key name, reads the value (from args or stdin), builds
    metadata from CLI arguments, stores the secret via the backend, and
    upserts the registry index.

    Parameters
    ----------
    args : argparse.Namespace
        Parsed CLI arguments including name, value, service, account,
        backend, keychain, and metadata flags.

    Returns
    -------
    int
        EXIT_SUCCESS (0) on success, or a POSIX error code on failure.

    Raises
    ------
    No exceptions are raised; errors are returned as integer exit codes.

    Error Conditions
    ---------------
    - ValidationError → EINVAL (22): invalid key name or metadata.
    - RegistryError → EPERM (1): registry update failure.
    - BackendError → EPERM (1): backend store failure.
    """
    try:
        name = validate_key_name(name=args.name)
        value = _read_value(value=args.value, use_stdin=args.stdin, allow_empty=args.allow_empty)
        meta = _build_metadata(args=args, name=name, source="manual")
        set_secret(
            service=args.service,
            account=args.account,
            name=name,
            value=value,
            label=name,
            comment=meta.to_keychain_comment(),
            **_backend_access_kwargs(args),
        )
        upsert_metadata(metadata=meta)
        print(f"stored: name={name} type={meta.entry_type} kind={meta.entry_kind} service={args.service} account={args.account}")
        return 0
    except (ValidationError, RegistryError, BackendError) as exc:
        return _fatal(message=str(exc))


def cmd_get(*, args: argparse.Namespace) -> int:
    """Retrieve a secret from the backend and print its metadata.

    Fetches the secret value and associated metadata, then prints either
    the raw value or a redacted summary depending on --raw.

    Parameters
    ----------
    args : argparse.Namespace
        Parsed CLI arguments including name, service, account, raw flag,
        and backend selection.

    Returns
    -------
    int
        EXIT_SUCCESS (0) on success, or a POSIX error code on failure.

    Error Conditions
    ---------------
    - ValidationError → EINVAL (22): invalid key name.
    - BackendError → EPERM (1): backend read failure.
    - RegistryError → EPERM (1): registry access failure.
    """
    try:
        name = validate_key_name(name=args.name)
        value = get_secret(service=args.service, account=args.account, name=name, **_backend_access_kwargs(args))
        resolved = _read_metadata(
            service=args.service,
            account=args.account,
            name=name,
            **_backend_access_kwargs(args),
        )
        metadata = resolved["metadata"] if resolved else None
        kind = metadata.entry_kind if isinstance(metadata, EntryMetadata) else "unknown"
        entry_type = metadata.entry_type if isinstance(metadata, EntryMetadata) else "unknown"
        if args.raw:
            print(value)
        else:
            print(f"name={name} type={entry_type} kind={kind} service={args.service} account={args.account} value=<redacted>")
        return 0
    except (ValidationError, BackendError, RegistryError) as exc:
        return _fatal(message=str(exc), code=EXIT_CODES["EPERM"])


def cmd_list(*, args: argparse.Namespace) -> int:
    """List secrets from the registry with optional filtering.

    Loads the registry index, filters by service, account, type, kind,
    tag, and staleness, then prints results as JSON or a formatted table.

    Parameters
    ----------
    args : argparse.Namespace
        Parsed CLI arguments including service, account, type, kind, tag,
        stale days, and format.

    Returns
    -------
    int
        EXIT_SUCCESS (0) on success, or a POSIX error code on failure.

    Error Conditions
    ---------------
    - RegistryError → EPERM (1): registry load failure.
    """
    try:
        entries = load_registry()
    except RegistryError as exc:
        return _fatal(message=str(exc), code=EXIT_CODES["EPERM"])

    rows = []
    cutoff = None
    if args.stale is not None:
        cutoff = datetime.now(timezone.utc).timestamp() - (args.stale * 86400)
    for indexed in entries.values():
        if args.service and indexed.service != args.service:
            continue
        if args.account and indexed.account != args.account:
            continue
        resolved = _read_metadata(
            service=indexed.service,
            account=indexed.account,
            name=indexed.name,
            registry=entries,
            path=_store_path(args),
            backend=_backend_arg(args),
            kek_keychain_path=_kek_keychain_arg(args),
        )
        if not resolved:
            continue
        meta = resolved["metadata"]
        if not isinstance(meta, EntryMetadata):
            continue
        if args.type and meta.entry_type != args.type:
            continue
        if args.kind and meta.entry_kind != args.kind:
            continue
        if args.tag and args.tag not in meta.tags:
            continue
        if cutoff is not None:
            updated = _parse_timestamp(meta.updated_at)
            if not updated:
                continue
            if updated.timestamp() > cutoff:
                continue
        rows.append((meta, resolved))

    rows.sort(key=lambda item: (item[0].service, item[0].account, item[0].name))

    if args.format == "json":
        output = []
        for item, resolved in rows:
            payload = item.to_dict()
            payload["status"] = _resolve_status(metadata=item)
            payload["metadata_source"] = resolved["metadata_source"]
            payload["registry_fallback_used"] = resolved["registry_fallback_used"]
            output.append(payload)
        print(json.dumps(output, indent=2))
        return 0

    if not rows:
        print("no entries")
        return 0

    headers = ["NAME", "TYPE", "KIND", "SERVICE", "ACCOUNT", "TAGS", "STATUS", "UPDATED_AT"]
    table_rows: list[list[str]] = []
    for item, resolved in rows:
        table_rows.append(
            [
                item.name,
                item.entry_type,
                item.entry_kind,
                item.service,
                item.account,
                _format_tags(tags=item.tags),
                ",".join(_resolve_status(metadata=item) or ["ok"]),
                item.updated_at,
            ]
        )
    _print_table(headers=headers, rows=table_rows)
    return 0


def cmd_delete(*, args: argparse.Namespace) -> int:
    """Delete a secret from the backend and registry.

    Prompts for confirmation (unless --yes), then removes the secret from
    the backend and deletes its metadata from the registry.

    Parameters
    ----------
    args : argparse.Namespace
        Parsed CLI arguments including name, service, account, yes flag,
        and backend selection.

    Returns
    -------
    int
        EXIT_SUCCESS (0) on success, EPERM (1) if aborted, or another
        POSIX error code on failure.

    Error Conditions
    ---------------
    - ValidationError → EINVAL (22): invalid key name.
    - BackendError → EPERM (1): backend delete failure.
    - RegistryError → EPERM (1): registry delete failure.
    - User abort → EPERM (1): confirmation declined.
    """
    try:
        name = validate_key_name(name=args.name)
        if not args.yes and not _confirm(prompt=f"Delete {name} from service={args.service} account={args.account}?"):
            print("aborted")
            return EXIT_CODES["EPERM"]
        delete_secret(service=args.service, account=args.account, name=name, **_backend_access_kwargs(args))
        delete_metadata(service=args.service, account=args.account, name=name)
        print(f"deleted: name={name} service={args.service} account={args.account}")
        return 0
    except (ValidationError, BackendError, RegistryError) as exc:
        return _fatal(message=str(exc), code=EXIT_CODES["EPERM"])


def cmd_explain(*, args: argparse.Namespace) -> int:
    """Print detailed metadata for a secret in JSON format.

    Resolves metadata from the backend or registry, decodes it, and
    prints a JSON payload including status, source, and keychain fields.

    Parameters
    ----------
    args : argparse.Namespace
        Parsed CLI arguments including name, service, account, and
        backend selection.

    Returns
    -------
    int
        EXIT_SUCCESS (0) on success, or a POSIX error code on failure.

    Error Conditions
    ---------------
    - Entry not found → ENOENT (2): no matching registry or backend entry.
    - Metadata decode failed → EIO (5): corrupt metadata.
    - ValidationError → EINVAL (22): invalid key name.
    - RegistryError → EPERM (1): registry access failure.
    """
    try:
        name = validate_key_name(name=args.name)
        resolved = _read_metadata(service=args.service, account=args.account, name=name, **_backend_access_kwargs(args))
        if not resolved:
            return _fatal(message=f"entry not found: {args.service}::{args.account}::{name}", code=EXIT_CODES["ENOENT"])
        entry = resolved["metadata"]
        if not isinstance(entry, EntryMetadata):
            return _fatal(message="metadata decode failed", code=EXIT_CODES["EIO"])
        payload = entry.to_dict()
        payload["status"] = _resolve_status(metadata=entry)
        payload["metadata_source"] = resolved["metadata_source"]
        payload["registry_fallback_used"] = resolved["registry_fallback_used"]
        payload["keychain_fields"] = resolved["keychain_fields"]
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    except (ValidationError, RegistryError) as exc:
        return _fatal(message=str(exc), code=EXIT_CODES["EPERM"])


def cmd_run(*, args: argparse.Namespace) -> int:
    """Run a child command with selected secrets injected as environment variables.

    Selects secrets matching CLI filters, builds an environment map from
    their values, and execs the child command with the augmented environment.

    Parameters
    ----------
    args : argparse.Namespace
        Parsed CLI arguments including child_command, service, account,
        names, tag, and backend selection.

    Returns
    -------
    int
        Child process exit status on success, or a POSIX error code on failure.

    Error Conditions
    ---------------
    - Missing command → EINVAL (22): no command after --.
    - No matching entries → ENOENT (2): filter produced empty selection.
    - ValidationError → EPERM (1): invalid input.
    - RegistryError → EPERM (1): registry access failure.
    - BackendError → EPERM (1): backend read failure.
    - Command not found → ENOENT (2): executable does not exist.
    - Launch failure → ENOEXEC (8): OS error starting the command.
    """
    command = _child_command_args(args.child_command)
    try:
        if not command:
            return _fatal(message="run requires a target command after --", code=EXIT_CODES["EINVAL"])

        selected = _select_entries(args=args, require_explicit_selection=False)
        if not selected:
            return _fatal(message="no matching entries selected for run", code=EXIT_CODES["ENOENT"])

        env = os.environ.copy()
        env.update(_build_env_map(entries=selected, args=args))
        return _exec_child(argv=command, env=env)
    except (ValidationError, RegistryError, BackendError) as exc:
        return _fatal(message=str(exc), code=EXIT_CODES["EPERM"])
    except FileNotFoundError:
        return _fatal(message=f"command not found: {command[0]}", code=EXIT_CODES["ENOENT"])
    except OSError as exc:
        return _fatal(message=f"failed to launch {command[0]}: {exc}", code=EXIT_CODES["ENOEXEC"])
