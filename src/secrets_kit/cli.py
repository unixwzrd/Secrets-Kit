"""CLI entrypoint for seckit."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from dataclasses import asdict
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as package_version
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from secrets_kit.exporters import export_shell_lines
from secrets_kit.importers import (
    ImportCandidate,
    candidates_from_dotenv,
    candidates_from_env,
    candidates_from_file,
    read_dotenv,
)
from secrets_kit.keychain_backend import (
    BackendError,
    check_security_cli,
    delete_secret,
    doctor_roundtrip,
    get_secret,
    harden_keychain,
    keychain_accessible,
    keychain_policy,
    keychain_path,
    lock_keychain,
    secret_exists,
    set_secret,
    unlock_keychain,
)
from secrets_kit.models import (
    ENTRY_KIND_VALUES,
    EntryMetadata,
    ValidationError,
    normalize_tags,
    validate_entry_kind,
    validate_entry_type,
    validate_key_name,
)
from secrets_kit.registry import (
    RegistryError,
    delete_metadata,
    ensure_registry_storage,
    load_registry,
    upsert_metadata,
)


def _fatal(*, message: str, code: int = 2) -> int:
    print(f"ERROR: {message}", file=sys.stderr)
    return code


def _cli_version() -> str:
    try:
        return package_version("seckit")
    except PackageNotFoundError:
        return "0.1.0"


def _confirm(*, prompt: str) -> bool:
    try:
        answer = input(f"{prompt} [y/N]: ").strip().lower()
    except EOFError:
        return False
    return answer in {"y", "yes"}


def _read_value(*, value: Optional[str], use_stdin: bool, allow_empty: bool) -> str:
    if use_stdin:
        data = sys.stdin.read()
    else:
        data = value or ""
    if not allow_empty and not data.strip():
        raise ValidationError("value cannot be empty unless --allow-empty is set")
    return data.strip()


def _format_tags(*, tags: List[str]) -> str:
    return ",".join(tags) if tags else "-"


def _merge_candidates(*, groups: Iterable[List[ImportCandidate]]) -> Dict[str, ImportCandidate]:
    merged: Dict[str, ImportCandidate] = {}
    for group in groups:
        for candidate in group:
            merged[candidate.metadata.key()] = candidate
    return merged


def _apply_candidates(*, candidates: Dict[str, ImportCandidate], allow_overwrite: bool, dry_run: bool, allow_empty: bool) -> Dict[str, int]:
    registry = load_registry()
    stats = {"created": 0, "updated": 0, "skipped": 0}
    for key in sorted(candidates):
        candidate = candidates[key]
        exists = key in registry
        if exists and not allow_overwrite:
            stats["skipped"] += 1
            continue
        if not allow_empty and not candidate.value:
            stats["skipped"] += 1
            continue
        if dry_run:
            stats["updated" if exists else "created"] += 1
            continue
        set_secret(
            service=candidate.metadata.service,
            account=candidate.metadata.account,
            name=candidate.metadata.name,
            value=candidate.value,
        )
        upsert_metadata(metadata=candidate.metadata)
        stats["updated" if exists else "created"] += 1
    return stats


def cmd_set(*, args: argparse.Namespace) -> int:
    try:
        name = validate_key_name(name=args.name)
        entry_type = validate_entry_type(entry_type=args.type)
        entry_kind = validate_entry_kind(entry_kind=args.kind)
        value = _read_value(value=args.value, use_stdin=args.stdin, allow_empty=args.allow_empty)
        tags = normalize_tags(tags_csv=args.tags)
        meta = EntryMetadata(
            name=name,
            entry_type=entry_type,
            entry_kind=entry_kind,
            tags=tags,
            service=args.service,
            account=args.account,
            source="manual",
        )
        set_secret(service=args.service, account=args.account, name=name, value=value)
        upsert_metadata(metadata=meta)
        print(f"stored: name={name} type={entry_type} kind={entry_kind} service={args.service} account={args.account}")
        return 0
    except (ValidationError, RegistryError, BackendError) as exc:
        return _fatal(message=str(exc))


def cmd_get(*, args: argparse.Namespace) -> int:
    try:
        name = validate_key_name(name=args.name)
        value = get_secret(service=args.service, account=args.account, name=name)
        metadata = load_registry().get(f"{args.service}::{args.account}::{name}")
        kind = metadata.entry_kind if metadata else "unknown"
        entry_type = metadata.entry_type if metadata else "unknown"
        if args.raw:
            print(value)
        else:
            print(f"name={name} type={entry_type} kind={kind} service={args.service} account={args.account} value=<redacted>")
        return 0
    except (ValidationError, BackendError, RegistryError) as exc:
        return _fatal(message=str(exc), code=1)


def cmd_list(*, args: argparse.Namespace) -> int:
    try:
        entries = load_registry()
    except RegistryError as exc:
        return _fatal(message=str(exc), code=1)

    rows = []
    for meta in entries.values():
        if args.service and meta.service != args.service:
            continue
        if args.account and meta.account != args.account:
            continue
        if args.type and meta.entry_type != args.type:
            continue
        if args.kind and meta.entry_kind != args.kind:
            continue
        if args.tag and args.tag not in meta.tags:
            continue
        rows.append(meta)

    rows.sort(key=lambda item: (item.service, item.account, item.name))

    if args.format == "json":
        print(json.dumps([asdict(item) for item in rows], indent=2))
        return 0

    if not rows:
        print("no entries")
        return 0

    print("NAME\tTYPE\tKIND\tSERVICE\tACCOUNT\tTAGS\tUPDATED_AT")
    for item in rows:
        print(
            f"{item.name}\t{item.entry_type}\t{item.entry_kind}\t{item.service}\t{item.account}\t{_format_tags(tags=item.tags)}\t{item.updated_at}"
        )
    return 0


def cmd_delete(*, args: argparse.Namespace) -> int:
    try:
        name = validate_key_name(name=args.name)
        if not args.yes and not _confirm(prompt=f"Delete {name} from service={args.service} account={args.account}?"):
            print("aborted")
            return 1
        delete_secret(service=args.service, account=args.account, name=name)
        delete_metadata(service=args.service, account=args.account, name=name)
        print(f"deleted: name={name} service={args.service} account={args.account}")
        return 0
    except (ValidationError, BackendError, RegistryError) as exc:
        return _fatal(message=str(exc), code=1)


def _preview_candidates(*, merged: Dict[str, ImportCandidate]) -> None:
    print("plan:")
    print("NAME\tTYPE\tKIND\tSERVICE\tACCOUNT\tTAGS\tSOURCE\tVALUE")
    for key in sorted(merged):
        candidate = merged[key]
        meta = candidate.metadata
        print(
            f"{meta.name}\t{meta.entry_type}\t{meta.entry_kind}\t{meta.service}\t{meta.account}\t{_format_tags(tags=meta.tags)}\t{meta.source}\t<redacted>"
        )


def cmd_import_env(*, args: argparse.Namespace) -> int:
    if not args.dotenv and not args.from_env:
        return _fatal(message="import env requires --dotenv and/or --from-env")
    try:
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
        merged = _merge_candidates(groups=groups)
        _preview_candidates(merged=merged)
        if not merged:
            print("nothing to import")
            return 0
        if not args.dry_run and not args.yes and not _confirm(prompt=f"Import {len(merged)} entries?"):
            print("aborted")
            return 1
        stats = _apply_candidates(
            candidates=merged,
            allow_overwrite=args.allow_overwrite,
            dry_run=args.dry_run,
            allow_empty=args.allow_empty,
        )
        print(json.dumps(stats, indent=2, sort_keys=True))
        return 0
    except (ValidationError, ValueError, RegistryError, BackendError, FileNotFoundError) as exc:
        return _fatal(message=str(exc), code=1)


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
            return 1
        stats = _apply_candidates(
            candidates=merged,
            allow_overwrite=args.allow_overwrite,
            dry_run=args.dry_run,
            allow_empty=args.allow_empty,
        )
        print(json.dumps(stats, indent=2, sort_keys=True))
        return 0
    except (ValidationError, ValueError, RegistryError, BackendError, FileNotFoundError) as exc:
        return _fatal(message=str(exc), code=1)


def cmd_export(*, args: argparse.Namespace) -> int:
    if args.format != "shell":
        return _fatal(message="only --format shell is supported in v1")

    try:
        entries = load_registry()
        selected: List[EntryMetadata] = []
        names = {validate_key_name(name=item) for item in args.names.split(",")} if args.names else set()
        for meta in entries.values():
            if args.service and meta.service != args.service:
                continue
            if args.account and meta.account != args.account:
                continue
            if args.type and meta.entry_type != args.type:
                continue
            if args.kind and meta.entry_kind != args.kind:
                continue
            if args.tag and args.tag not in meta.tags:
                continue
            if names and meta.name not in names:
                continue
            if not (args.names or args.tag or args.type or args.all):
                continue
            selected.append(meta)

        if not selected:
            return _fatal(message="no matching entries selected for export", code=1)

        env_map: Dict[str, str] = {}
        for meta in sorted(selected, key=lambda item: item.name):
            env_map[meta.name] = get_secret(service=meta.service, account=meta.account, name=meta.name)
        print(export_shell_lines(env_map=env_map))
        return 0
    except (ValidationError, RegistryError, BackendError) as exc:
        return _fatal(message=str(exc), code=1)


def cmd_doctor(*, args: argparse.Namespace) -> int:
    del args
    status = {
        "security_cli": False,
        "registry": False,
        "keychain_roundtrip": False,
        "registry_path": None,
        "metadata_keychain_drift": [],
    }
    if check_security_cli():
        status["security_cli"] = True
    else:
        print(json.dumps(status, indent=2, sort_keys=True))
        return _fatal(message="security CLI not found", code=1)

    try:
        path = ensure_registry_storage()
        status["registry"] = True
        status["registry_path"] = str(path)
    except RegistryError as exc:
        print(json.dumps(status, indent=2, sort_keys=True))
        return _fatal(message=str(exc), code=1)

    try:
        doctor_roundtrip()
        status["keychain_roundtrip"] = True
    except BackendError as exc:
        print(json.dumps(status, indent=2, sort_keys=True))
        return _fatal(message=str(exc), code=1)

    try:
        entries = load_registry()
        drift = []
        for meta in sorted(entries.values(), key=lambda item: (item.service, item.account, item.name)):
            if not secret_exists(service=meta.service, account=meta.account, name=meta.name):
                drift.append(
                    {
                        "name": meta.name,
                        "service": meta.service,
                        "account": meta.account,
                    }
                )
        status["metadata_keychain_drift"] = drift
    except (RegistryError, BackendError) as exc:
        print(json.dumps(status, indent=2, sort_keys=True))
        return _fatal(message=str(exc), code=1)

    print(json.dumps(status, indent=2, sort_keys=True))
    if status["metadata_keychain_drift"]:
        return _fatal(message="metadata/keychain drift detected", code=1)
    return 0


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
    del args
    print(_cli_version())
    return 0


def cmd_migrate_dotenv(*, args: argparse.Namespace) -> int:
    dotenv = Path(args.dotenv)
    if not dotenv.exists():
        return _fatal(message=f"dotenv file not found: {dotenv}", code=1)

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
        type=args.type,
        kind=args.kind,
        tags=args.tags,
        dry_run=args.dry_run,
        allow_overwrite=args.allow_overwrite,
        allow_empty=args.allow_empty,
        yes=args.yes,
    )
    code = cmd_import_env(args=tmp)
    if code != 0 or args.dry_run or not args.replace_with_placeholders:
        return code

    parsed = read_dotenv(dotenv_path=dotenv)
    original = dotenv.read_text(encoding="utf-8").splitlines()
    rewritten: List[str] = []
    for line in original:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            rewritten.append(line)
            continue
        left = stripped.split("=", 1)[0].strip()
        if left.startswith("export "):
            left = left[len("export ") :].strip()
        if left in parsed:
            prefix = "export " if stripped.startswith("export ") else ""
            rewritten.append(f"{prefix}{left}=${{{left}}}")
        else:
            rewritten.append(line)

    dotenv.write_text("\n".join(rewritten) + "\n", encoding="utf-8")
    print(f"rewrote placeholders in {dotenv}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Construct CLI parser."""
    parser = argparse.ArgumentParser(prog="seckit", description="Secure secrets and PII CLI for local ops")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {_cli_version()}")
    sub = parser.add_subparsers(
        dest="command",
        required=True,
        title="commands",
        metavar="COMMAND",
        description="Available commands",
    )

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--account", default="default")
    common.add_argument("--service", default="seckit")

    p_set = sub.add_parser("set", parents=[common], help="Store or update one secret value")
    p_set.add_argument("--name", required=True)
    p_set.add_argument("--value")
    p_set.add_argument("--stdin", action="store_true")
    p_set.add_argument("--type", default="secret", choices=["secret", "pii"])
    p_set.add_argument("--kind", default="generic", choices=ENTRY_KIND_VALUES)
    p_set.add_argument("--tags")
    p_set.add_argument("--allow-empty", action="store_true")
    p_set.set_defaults(func=cmd_set)

    p_get = sub.add_parser("get", parents=[common], help="Read one stored secret value")
    p_get.add_argument("--name", required=True)
    p_get.add_argument("--raw", action="store_true")
    p_get.set_defaults(func=cmd_get)

    p_list = sub.add_parser("list", help="List stored metadata entries, redacted by default")
    p_list.add_argument("--account")
    p_list.add_argument("--service")
    p_list.add_argument("--type", choices=["secret", "pii"])
    p_list.add_argument("--kind", choices=ENTRY_KIND_VALUES)
    p_list.add_argument("--tag")
    p_list.add_argument("--format", choices=["table", "json"], default="table")
    p_list.set_defaults(func=cmd_list)

    p_delete = sub.add_parser("delete", parents=[common], help="Delete one stored secret and its metadata")
    p_delete.add_argument("--name", required=True)
    p_delete.add_argument("--yes", action="store_true")
    p_delete.set_defaults(func=cmd_delete)

    p_import = sub.add_parser("import", help="Import secrets from env or file sources")
    import_sub = p_import.add_subparsers(dest="import_command", required=True)

    p_import_env = import_sub.add_parser("env", parents=[common], help="Import secrets from dotenv and/or live environment")
    p_import_env.add_argument("--dotenv")
    p_import_env.add_argument("--from-env")
    p_import_env.add_argument("--type", default="secret", choices=["secret", "pii"])
    p_import_env.add_argument("--kind", default="auto", choices=[*ENTRY_KIND_VALUES, "auto"])
    p_import_env.add_argument("--tags")
    p_import_env.add_argument("--dry-run", action="store_true")
    p_import_env.add_argument("--allow-overwrite", action="store_true")
    p_import_env.add_argument("--allow-empty", action="store_true")
    p_import_env.add_argument("--yes", action="store_true")
    p_import_env.set_defaults(func=cmd_import_env)

    p_import_file = import_sub.add_parser("file", help="Import secrets from JSON or YAML files")
    p_import_file.add_argument("--file", required=True)
    p_import_file.add_argument("--format", choices=["json", "yaml", "yml"])
    p_import_file.add_argument("--type", default="secret", choices=["secret", "pii"])
    p_import_file.add_argument("--kind", default="auto", choices=[*ENTRY_KIND_VALUES, "auto"])
    p_import_file.add_argument("--dry-run", action="store_true")
    p_import_file.add_argument("--allow-overwrite", action="store_true")
    p_import_file.add_argument("--allow-empty", action="store_true")
    p_import_file.add_argument("--yes", action="store_true")
    p_import_file.set_defaults(func=cmd_import_file)

    p_export = sub.add_parser("export", parents=[common], help="Export selected secrets for runtime use")
    p_export.add_argument("--format", default="shell")
    p_export.add_argument("--names")
    p_export.add_argument("--tag")
    p_export.add_argument("--type", choices=["secret", "pii"])
    p_export.add_argument("--kind", choices=ENTRY_KIND_VALUES)
    p_export.add_argument("--all", action="store_true")
    p_export.set_defaults(func=cmd_export)

    p_doctor = sub.add_parser("doctor", help="Run backend, registry, and drift diagnostics")
    p_doctor.set_defaults(func=cmd_doctor)

    p_unlock = sub.add_parser("unlock", help="Unlock the configured macOS keychain backend")
    p_unlock.add_argument("--keychain", help="Override keychain path (default: login.keychain-db)")
    p_unlock.add_argument("--dry-run", action="store_true", help="Show the backend command without running it")
    p_unlock.add_argument("--yes", action="store_true", help="Run without confirmation prompt")
    p_unlock.add_argument("--harden", action="store_true", help="Also apply a safer keychain timeout policy after unlock")
    p_unlock.add_argument("--timeout", type=int, default=3600, help="Timeout in seconds used with --harden (default: 3600)")
    p_unlock.set_defaults(func=cmd_unlock)

    p_lock = sub.add_parser("lock", help="Lock the configured macOS keychain backend")
    p_lock.add_argument("--keychain", help="Override keychain path (default: login.keychain-db)")
    p_lock.add_argument("--dry-run", action="store_true", help="Show the backend command without running it")
    p_lock.add_argument("--yes", action="store_true", help="Run without confirmation prompt")
    p_lock.set_defaults(func=cmd_lock)

    p_keychain = sub.add_parser("keychain-status", help="Report macOS keychain accessibility and lock policy")
    p_keychain.add_argument("--keychain", help="Override keychain path (default: login.keychain-db)")
    p_keychain.set_defaults(func=cmd_keychain_status)

    p_version = sub.add_parser("version", help="Print the installed seckit version")
    p_version.set_defaults(func=cmd_version)

    p_migrate = sub.add_parser("migrate", help="Migrate existing secret files into seckit")
    migrate_sub = p_migrate.add_subparsers(dest="migrate_command", required=True)
    p_migrate_dotenv = migrate_sub.add_parser("dotenv", parents=[common], help="Import a dotenv file and optionally rewrite it to placeholders")
    p_migrate_dotenv.add_argument("--dotenv", required=True)
    p_migrate_dotenv.add_argument("--archive")
    p_migrate_dotenv.add_argument("--type", default="secret", choices=["secret", "pii"])
    p_migrate_dotenv.add_argument("--kind", default="auto", choices=[*ENTRY_KIND_VALUES, "auto"])
    p_migrate_dotenv.add_argument("--tags")
    p_migrate_dotenv.add_argument("--dry-run", action="store_true")
    p_migrate_dotenv.add_argument("--allow-overwrite", action="store_true")
    p_migrate_dotenv.add_argument("--allow-empty", action="store_true")
    p_migrate_dotenv.add_argument("--yes", action="store_true")
    p_migrate_dotenv.add_argument("--replace-with-placeholders", dest="replace_with_placeholders", action="store_true", default=True)
    p_migrate_dotenv.add_argument("--no-replace-with-placeholders", dest="replace_with_placeholders", action="store_false")
    p_migrate_dotenv.set_defaults(func=cmd_migrate_dotenv)

    return parser


def main() -> int:
    """CLI main entry."""
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args=args)


if __name__ == "__main__":
    raise SystemExit(main())
