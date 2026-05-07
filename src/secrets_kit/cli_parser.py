"""argparse construction for seckit (build_parser)."""

from __future__ import annotations

import argparse

from secrets_kit.cli_groups import HELP_DB, HELP_KEYCHAIN_OVERRIDE, make_common_parent
from secrets_kit.cli_help import CONFIG_COMMAND_DESCRIPTION, MAIN_HELP_EPILOG, SeckitHelpFormatter
from secrets_kit.keychain_backend import BACKEND_CHOICES
from secrets_kit.models import ENTRY_KIND_VALUES


def build_parser() -> argparse.ArgumentParser:
    """Construct CLI parser. Lazy-imports cli handlers to avoid import cycles."""
    import secrets_kit.cli as cli

    parser = argparse.ArgumentParser(
        prog="seckit",
        description=(
            "Local secrets and PII: store values in a configured backend "
            "(Keychain when using --backend secure on macOS, or encrypted SQLite); "
            "manage operator defaults under ~/.config/seckit/."
        ),
        epilog=MAIN_HELP_EPILOG,
        formatter_class=SeckitHelpFormatter,
    )
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {cli._cli_version()}")
    sub = parser.add_subparsers(
        dest="command",
        required=True,
        title="commands",
        metavar="COMMAND",
        description=(
            "Run seckit COMMAND --help for options. "
            "Typical flags: --backend, --service, --account, --keychain, --db."
        ),
    )

    backend_choices = list(BACKEND_CHOICES)
    common = make_common_parent(backend_choices)
    cfg_keys = sorted(cli._CONFIG_STORABLE_KEYS)

    p_set = sub.add_parser(
        "set",
        parents=[common],
        help="Store or update one secret value",
        epilog=(
            "Examples:\n"
            "  echo 'sk-example' | seckit set --name OPENAI_API_KEY --stdin --kind api_key \\\n"
            "    --service my-stack --account local-dev\n"
            "  seckit set --name DEMO --value hello --kind generic --service my-stack --account local-dev"
        ),
        formatter_class=SeckitHelpFormatter,
    )
    p_set.add_argument("--name", required=True)
    p_set.add_argument("--value")
    p_set.add_argument("--stdin", action="store_true")
    p_set.add_argument("--type", choices=["secret", "pii"])
    p_set.add_argument("--kind", choices=ENTRY_KIND_VALUES)
    p_set.add_argument("--tags")
    p_set.add_argument("--comment")
    p_set.add_argument("--source-url")
    p_set.add_argument("--source-label")
    p_set.add_argument("--rotation-days", type=int)
    p_set.add_argument("--rotation-warn-days", type=int)
    p_set.add_argument("--expires-at")
    p_set.add_argument("--domain", action="append")
    p_set.add_argument("--domains")
    p_set.add_argument("--meta", action="append")
    p_set.add_argument("--allow-empty", action="store_true")
    p_set.set_defaults(func=cli.cmd_set)

    p_get = sub.add_parser(
        "get",
        parents=[common],
        help="Read one stored secret value (redacted by default; --raw materializes plaintext)",
        epilog=(
            "Examples:\n"
            "  seckit get --name OPENAI_API_KEY --service my-stack --account local-dev\n"
            "  seckit get --name OPENAI_API_KEY --service my-stack --account local-dev --raw\n"
            "The second form exposes the secret (--raw is elevated disclosure)."
        ),
        formatter_class=SeckitHelpFormatter,
    )
    p_get.add_argument("--name", required=True)
    p_get.add_argument(
        "--raw",
        action="store_true",
        help="Materialize plaintext secret to stdout (elevated disclosure)",
    )
    p_get.set_defaults(func=cli.cmd_get)

    p_list = sub.add_parser(
        "list",
        parents=[common],
        help=(
            "Inventory: list seckit-managed entries using safe enumeration; "
            "selective backend resolve only when filters need it (values redacted)"
        ),
        epilog=(
            "Examples:\n"
            "  seckit list --service my-stack --account local-dev\n"
            "  seckit list --service my-stack --account local-dev --tag prod --format json\n"
            "Use --format json for stable automation; table layout may change between releases."
        ),
        formatter_class=SeckitHelpFormatter,
    )
    p_list.add_argument("--type", choices=["secret", "pii"])
    p_list.add_argument("--kind", choices=ENTRY_KIND_VALUES)
    p_list.add_argument("--tag")
    p_list.add_argument("--stale", type=int, help="Filter entries older than N days")
    p_list.add_argument("--format", choices=["table", "json"], default="table")
    p_list.set_defaults(func=cli.cmd_list)

    p_explain = sub.add_parser(
        "explain",
        parents=[common],
        help="Inspect one entry: resolve authoritative metadata; secret stays redacted in normal output",
        epilog=(
            "Examples:\n"
            "  seckit explain --name OPENAI_API_KEY --service my-stack --account local-dev\n"
            "Resolves internally without materializing the secret to the terminal by default."
        ),
        formatter_class=SeckitHelpFormatter,
    )
    p_explain.add_argument("--name", required=True)
    p_explain.set_defaults(func=cli.cmd_explain)

    p_config = sub.add_parser(
        "config",
        aliases=["defaults"],
        help="View or edit defaults.json (compatibility alias: defaults)",
        description=CONFIG_COMMAND_DESCRIPTION,
        epilog=(
            "Examples:\n"
            "  seckit config show\n"
            "  seckit config set service my-stack\n"
            "  seckit defaults show --effective"
        ),
        formatter_class=SeckitHelpFormatter,
    )
    config_sub = p_config.add_subparsers(dest="config_command", required=True)
    p_config_show = config_sub.add_parser(
        "show",
        help="Print defaults from defaults.json; add --effective for merged file + legacy config + env",
    )
    p_config_show.add_argument(
        "--effective",
        action="store_true",
        help="Merge defaults.json, legacy ~/.config/seckit/config.json, and SECKIT_* env overrides",
    )
    p_config_show.set_defaults(func=cli.cmd_config_show)
    p_config_set = config_sub.add_parser("set", help="Set one key in defaults.json")
    p_config_set.add_argument("key", choices=cfg_keys, metavar="KEY")
    p_config_set.add_argument("value", help="Value (use quotes if it contains spaces)")
    p_config_set.set_defaults(func=cli.cmd_config_set)
    p_config_unset = config_sub.add_parser("unset", help="Remove one key from defaults.json")
    p_config_unset.add_argument("key", choices=cfg_keys, metavar="KEY")
    p_config_unset.set_defaults(func=cli.cmd_config_unset)
    p_config_path = config_sub.add_parser("path", help="Print path to defaults.json")
    p_config_path.set_defaults(func=cli.cmd_config_path)

    p_delete = sub.add_parser(
        "delete",
        parents=[common],
        help="Delete one stored secret and its metadata",
        epilog=(
            "Examples:\n"
            "  seckit delete --name OLD_KEY --service my-stack --account local-dev\n"
            "  seckit delete --name OLD_KEY --service my-stack --account local-dev --yes"
        ),
        formatter_class=SeckitHelpFormatter,
    )
    p_delete.add_argument("--name", required=True)
    p_delete.add_argument("--yes", action="store_true")
    p_delete.set_defaults(func=cli.cmd_delete)

    p_import = sub.add_parser(
        "import",
        help="Import secrets from dotenv, live env, JSON/YAML, or encrypted export",
        description="Bulk-create or update entries. Subcommands: env, file, encrypted-json.",
        formatter_class=SeckitHelpFormatter,
    )
    import_sub = p_import.add_subparsers(dest="import_command", required=True)

    p_import_env = import_sub.add_parser(
        "env",
        parents=[common],
        help="Import secrets from dotenv and/or live environment",
    )
    p_import_env.add_argument("--dotenv")
    p_import_env.add_argument("--from-env")
    p_import_env.add_argument("--type", choices=["secret", "pii"])
    p_import_env.add_argument("--kind", choices=[*ENTRY_KIND_VALUES, "auto"])
    p_import_env.add_argument("--tags")
    p_import_env.add_argument("--dry-run", action="store_true")
    p_import_env.add_argument("--allow-overwrite", action="store_true")
    p_import_env.add_argument("--upsert", action="store_true", help="Create new names and update existing values")
    p_import_env.add_argument("--allow-empty", action="store_true")
    p_import_env.add_argument("--yes", action="store_true")
    p_import_env.set_defaults(func=cli.cmd_import_env)

    p_import_file = import_sub.add_parser("file", help="Import secrets from JSON or YAML files")
    p_import_file.add_argument("--file", required=True)
    p_import_file.add_argument("--format", choices=["json", "yaml", "yml"])
    p_import_file.add_argument("--type", choices=["secret", "pii"])
    p_import_file.add_argument("--kind", choices=[*ENTRY_KIND_VALUES, "auto"])
    p_import_file.add_argument("--backend", choices=backend_choices)
    p_import_file.add_argument("--keychain", help=HELP_KEYCHAIN_OVERRIDE)
    p_import_file.add_argument("--db", help=HELP_DB)
    p_import_file.add_argument("--dry-run", action="store_true")
    p_import_file.add_argument("--allow-overwrite", action="store_true")
    p_import_file.add_argument("--allow-empty", action="store_true")
    p_import_file.add_argument("--yes", action="store_true")
    p_import_file.set_defaults(func=cli.cmd_import_file)

    p_import_encrypted = import_sub.add_parser("encrypted-json", help="Import secrets from encrypted JSON export")
    p_import_encrypted.add_argument("--file", required=True)
    p_import_encrypted.add_argument("--backend", choices=backend_choices)
    p_import_encrypted.add_argument("--keychain", help=HELP_KEYCHAIN_OVERRIDE)
    p_import_encrypted.add_argument("--db", help=HELP_DB)
    p_import_encrypted.add_argument("--password")
    p_import_encrypted.add_argument("--password-stdin", action="store_true")
    p_import_encrypted.add_argument("--dry-run", action="store_true")
    p_import_encrypted.add_argument("--allow-overwrite", action="store_true")
    p_import_encrypted.add_argument("--allow-empty", action="store_true")
    p_import_encrypted.add_argument("--yes", action="store_true")
    p_import_encrypted.set_defaults(func=cli.cmd_import_encrypted)

    p_export = sub.add_parser(
        "export",
        parents=[common],
        help="Materialize selected secrets for runtime (shell, dotenv, or encrypted-json backup)",
        epilog=(
            "Examples:\n"
            "  seckit export --service my-stack --account local-dev --format shell --names OPENAI_API_KEY\n"
            "  seckit export --service my-stack --account local-dev --format encrypted-json --out backup.json\n"
            "Export paths perform bulk materialization; scope with --names, --tag, or explicit --all as documented."
        ),
        formatter_class=SeckitHelpFormatter,
    )
    p_export.add_argument("--format", default="shell", choices=["shell", "dotenv", "encrypted-json"])
    p_export.add_argument("--out")
    p_export.add_argument("--password")
    p_export.add_argument("--password-stdin", action="store_true")
    p_export.add_argument("--names")
    p_export.add_argument("--tag")
    p_export.add_argument("--type", choices=["secret", "pii"])
    p_export.add_argument("--kind", choices=ENTRY_KIND_VALUES)
    p_export.add_argument("--all", action="store_true", help="Export all matching entries (elevated scope)")
    p_export.set_defaults(func=cli.cmd_export)

    p_run = sub.add_parser(
        "run",
        parents=[common],
        help="Resolve secrets and exec a child with env injection (runtime-scoped materialization)",
        epilog=(
            "Examples:\n"
            "  seckit run --service my-stack --account local-dev -- python3 app.py\n"
            "  seckit run --service my-stack --account local-dev --names OPENAI_API_KEY -- python3 -c 'import os; ...'\n"
            "Child processes receive plaintext in environment variables."
        ),
        formatter_class=SeckitHelpFormatter,
    )
    p_run.add_argument("--names")
    p_run.add_argument("--tag")
    p_run.add_argument("--type", choices=["secret", "pii"])
    p_run.add_argument("--kind", choices=ENTRY_KIND_VALUES)
    p_run.add_argument("--all", action="store_true", help="Inject all matching entries (elevated scope)")
    p_run.add_argument("child_command", nargs=argparse.REMAINDER)
    p_run.set_defaults(func=cli.cmd_run)

    p_service = sub.add_parser("service", help="Manage service-scoped secret groups")
    service_sub = p_service.add_subparsers(dest="service_command", required=True)
    p_service_copy = service_sub.add_parser("copy", help="Copy secrets from one service scope to another")
    p_service_copy.add_argument("--from-service", required=True)
    p_service_copy.add_argument("--to-service", required=True)
    p_service_copy.add_argument("--from-account")
    p_service_copy.add_argument("--to-account")
    p_service_copy.add_argument("--backend", choices=backend_choices)
    p_service_copy.add_argument("--keychain", help=HELP_KEYCHAIN_OVERRIDE)
    p_service_copy.add_argument("--db", help=HELP_DB)
    p_service_copy.add_argument("--names")
    p_service_copy.add_argument("--tag")
    p_service_copy.add_argument("--type", choices=["secret", "pii"])
    p_service_copy.add_argument("--kind", choices=ENTRY_KIND_VALUES)
    p_service_copy.add_argument("--overwrite", action="store_true")
    p_service_copy.add_argument("--dry-run", action="store_true")
    p_service_copy.set_defaults(func=cli.cmd_service_copy)

    p_doctor = sub.add_parser(
        "doctor",
        help="JSON diagnostics: security CLI, roundtrip, registry drift, backend capabilities/posture",
        epilog=(
            "Examples:\n"
            "  seckit doctor\n"
            "  seckit doctor --backend sqlite --db /path/to/secrets.db"
        ),
        formatter_class=SeckitHelpFormatter,
    )
    p_doctor.add_argument("--backend", choices=backend_choices)
    p_doctor.add_argument("--keychain", help=HELP_KEYCHAIN_OVERRIDE)
    p_doctor.add_argument("--db", help=HELP_DB)
    p_doctor.set_defaults(func=cli.cmd_doctor)

    p_backend_index = sub.add_parser(
        "backend-index",
        parents=[common],
        help="Diagnostics: decrypt-safe backend index rows (BackendStore.iter_index); not authority, not secrets",
        epilog=(
            "Examples:\n"
            "  seckit backend-index --service my-stack --account local-dev\n"
            "Emits JSON lines; not a materialization path—see docs/CLI_ARCHITECTURE.md."
        ),
        formatter_class=SeckitHelpFormatter,
    )
    p_backend_index.set_defaults(func=cli.cmd_backend_index)

    p_rebuild_index = sub.add_parser(
        "rebuild-index",
        parents=[common],
        help="Rebuild backend decrypt-free index from authority payloads (SQLite); repair hashes/hints",
    )
    p_rebuild_index.set_defaults(func=cli.cmd_rebuild_index)

    p_journal = sub.add_parser(
        "journal",
        help="Append-only local registry event log (operational / sync aid; advanced)",
    )
    journal_sub = p_journal.add_subparsers(dest="journal_command", required=True)
    p_journal_append = journal_sub.add_parser("append", help="Append one JSON object line to registry_events.jsonl")
    p_journal_append.add_argument("event_json", metavar="JSON", help="Single JSON object (shell-quoted)")
    p_journal_append.set_defaults(func=cli.cmd_journal_append)

    p_unlock = sub.add_parser(
        "unlock",
        help="Unlock the configured macOS Keychain backend (Keychain-specific)",
    )
    p_unlock.add_argument("--keychain", help=HELP_KEYCHAIN_OVERRIDE)
    p_unlock.add_argument("--dry-run", action="store_true", help="Show the backend command without running it")
    p_unlock.add_argument("--yes", action="store_true", help="Run without confirmation prompt")
    p_unlock.add_argument("--harden", action="store_true", help="Also apply a safer keychain timeout policy after unlock")
    p_unlock.add_argument("--timeout", type=int, default=3600, help="Timeout in seconds used with --harden (default: 3600)")
    p_unlock.set_defaults(func=cli.cmd_unlock)

    p_lock = sub.add_parser(
        "lock",
        help="Lock the configured macOS Keychain backend (Keychain-specific)",
    )
    p_lock.add_argument("--keychain", help=HELP_KEYCHAIN_OVERRIDE)
    p_lock.add_argument("--dry-run", action="store_true", help="Show the backend command without running it")
    p_lock.add_argument("--yes", action="store_true", help="Run without confirmation prompt")
    p_lock.set_defaults(func=cli.cmd_lock)

    p_keychain = sub.add_parser(
        "keychain-status",
        help="Report macOS Keychain accessibility and lock policy (Keychain-specific)",
    )
    p_keychain.add_argument("--keychain", help=HELP_KEYCHAIN_OVERRIDE)
    p_keychain.set_defaults(func=cli.cmd_keychain_status)

    p_recover = sub.add_parser(
        "recover",
        parents=[common],
        help="Rebuild registry/index metadata from the live store (same as migrate recover-registry)",
        description=(
            "When registry.json is missing or stale but secrets still exist in the store, scan the backend "
            "and rewrite a slim registry index. Does not read secret values from SQLite ciphertext; "
            "uses index/comment metadata where available."
        ),
        epilog=(
            "Examples:\n"
            "  seckit recover --dry-run\n"
            "  seckit recover --json\n"
            "See docs/WORKFLOWS.md for recovery flows."
        ),
        formatter_class=SeckitHelpFormatter,
    )
    p_recover.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview: print a list-style table and skip writing registry.json",
    )
    p_recover.add_argument(
        "--json",
        action="store_true",
        help="Emit a single JSON object (includes recovered_entries and skip details); no table",
    )
    p_recover.set_defaults(func=cli.cmd_recover_registry)

    p_version = sub.add_parser("version", help="Print the installed seckit version")
    vgrp = p_version.add_mutually_exclusive_group()
    vgrp.add_argument(
        "--info",
        action="store_true",
        dest="version_info",
        help="Print version, platform, defaults summary, and helper status stub (no secret values)",
    )
    vgrp.add_argument(
        "--json",
        action="store_true",
        dest="version_json",
        help="Same as --info as JSON (sorted keys)",
    )
    p_version.set_defaults(func=cli.cmd_version, version_info=False, version_json=False)

    p_helper = sub.add_parser(
        "helper",
        help="Show backend availability and helper metadata (JSON, no secrets; advanced / diagnostics)",
    )
    helper_sub = p_helper.add_subparsers(dest="helper_command", required=True)
    p_helper_status = helper_sub.add_parser(
        "status",
        help="Print JSON: backend_availability and helper fields (no bundled Mach-O)",
    )
    p_helper_status.set_defaults(func=cli.cmd_helper_status)

    p_migrate = sub.add_parser("migrate", help="Migrate existing secret files into seckit")

    p_identity = sub.add_parser("identity", help="Host Ed25519/X25519 identity for peer sync")
    id_sub = p_identity.add_subparsers(dest="identity_command", required=True)
    p_id_init = id_sub.add_parser("init", help="Create or replace host signing/box key material")
    p_id_init.add_argument("--force", action="store_true")
    p_id_init.add_argument("--json", action="store_true")
    p_id_init.set_defaults(func=cli.cmd_identity_init)
    p_id_show = id_sub.add_parser("show", help="Show local host id and fingerprints")
    p_id_show.add_argument("--json", action="store_true")
    p_id_show.set_defaults(func=cli.cmd_identity_show)
    p_id_exp = id_sub.add_parser("export", help="Write public identity JSON for peer add")
    p_id_exp.add_argument("-o", "--out")
    p_id_exp.add_argument("--json", action="store_true")
    p_id_exp.set_defaults(func=cli.cmd_identity_export)

    p_peer = sub.add_parser("peer", help="Trusted peers for peer sync bundles")
    peer_sub = p_peer.add_subparsers(dest="peer_command", required=True)
    p_peer_add = peer_sub.add_parser("add", help="Add peer from `seckit identity export` file")
    p_peer_add.add_argument("alias")
    p_peer_add.add_argument("export_path", metavar="PATH")
    p_peer_add.add_argument("--json", action="store_true")
    p_peer_add.set_defaults(func=cli.cmd_peer_add)
    p_peer_rm = peer_sub.add_parser("remove", help="Remove a peer alias")
    p_peer_rm.add_argument("alias")
    p_peer_rm.add_argument("--json", action="store_true")
    p_peer_rm.set_defaults(func=cli.cmd_peer_remove)
    p_peer_ls = peer_sub.add_parser("list", help="List trusted peers")
    p_peer_ls.add_argument("--json", action="store_true")
    p_peer_ls.set_defaults(func=cli.cmd_peer_list)
    p_peer_sh = peer_sub.add_parser("show", help="Show one peer (JSON)")
    p_peer_sh.add_argument("alias")
    p_peer_sh.set_defaults(func=cli.cmd_peer_show)

    p_sync = sub.add_parser("sync", help="Signed encrypted peer bundle export/import")
    sync_sub = p_sync.add_subparsers(dest="sync_command", required=True)
    p_sync_ex = sync_sub.add_parser("export", parents=[common], help="Export registry secrets to a peer bundle")
    p_sync_ex.add_argument("-o", "--out", required=True)
    p_sync_ex.add_argument("--peer", action="append", required=True, metavar="ALIAS", help="Recipient alias (repeatable)")
    p_sync_ex.add_argument("--domain", action="append")
    p_sync_ex.add_argument("--domains")
    p_sync_ex.add_argument("--names")
    p_sync_ex.add_argument("--tag")
    p_sync_ex.add_argument("--type", choices=["secret", "pii"])
    p_sync_ex.add_argument("--kind", choices=ENTRY_KIND_VALUES)
    p_sync_ex.add_argument("--all", action="store_true")
    p_sync_ex.add_argument("--json", action="store_true")
    p_sync_ex.set_defaults(func=cli.cmd_sync_export)
    p_sync_im = sync_sub.add_parser("import", parents=[common], help="Import and merge a peer bundle")
    p_sync_im.add_argument("file")
    p_sync_im.add_argument(
        "--signer",
        required=True,
        metavar="ALIAS",
        help="Local peer alias for the exporter who signed this bundle",
    )
    p_sync_im.add_argument("--domain", action="append")
    p_sync_im.add_argument("--domains")
    p_sync_im.add_argument("--dry-run", action="store_true")
    p_sync_im.add_argument("--yes", action="store_true")
    p_sync_im.set_defaults(func=cli.cmd_sync_import)
    p_sync_vf = sync_sub.add_parser("verify", help="Verify bundle JSON signature and structure")
    p_sync_vf.add_argument("file")
    p_sync_vf.add_argument("--try-decrypt", action="store_true", help="Decrypt inner (requires local identity + --signer)")
    p_sync_vf.add_argument("--signer", metavar="ALIAS", help="Exporter peer alias (required with --try-decrypt)")
    p_sync_vf.set_defaults(func=cli.cmd_sync_verify, try_decrypt=False)
    p_sync_insp = sync_sub.add_parser("inspect", help="Inspect bundle (manifest; no decryption)")
    p_sync_insp.add_argument("file")
    p_sync_insp.set_defaults(func=cli.cmd_sync_inspect)

    migrate_sub = p_migrate.add_subparsers(dest="migrate_command", required=True)
    p_migrate_dotenv = migrate_sub.add_parser(
        "dotenv",
        parents=[common],
        help="Import a dotenv file and optionally rewrite it to placeholders",
    )
    p_migrate_dotenv.add_argument("--dotenv", required=True)
    p_migrate_dotenv.add_argument("--archive")
    p_migrate_dotenv.add_argument("--type", choices=["secret", "pii"])
    p_migrate_dotenv.add_argument("--kind", choices=[*ENTRY_KIND_VALUES, "auto"])
    p_migrate_dotenv.add_argument("--tags")
    p_migrate_dotenv.add_argument("--dry-run", action="store_true")
    p_migrate_dotenv.add_argument("--allow-overwrite", action="store_true")
    p_migrate_dotenv.add_argument("--allow-empty", action="store_true")
    p_migrate_dotenv.add_argument("--yes", action="store_true")
    p_migrate_dotenv.add_argument("--replace-with-placeholders", dest="replace_with_placeholders", action="store_true", default=True)
    p_migrate_dotenv.add_argument("--no-replace-with-placeholders", dest="replace_with_placeholders", action="store_false")
    p_migrate_dotenv.set_defaults(func=cli.cmd_migrate_dotenv)

    p_migrate_metadata = migrate_sub.add_parser(
        "metadata",
        parents=[common],
        help="Write registry metadata into keychain comment JSON",
    )
    p_migrate_metadata.add_argument("--dry-run", action="store_true")
    p_migrate_metadata.add_argument("--force", action="store_true")
    p_migrate_metadata.set_defaults(func=cli.cmd_migrate_metadata)

    p_migrate_recover = migrate_sub.add_parser(
        "recover-registry",
        parents=[common],
        help="Compatibility alias for `seckit recover` (rebuild registry from the store)",
    )
    p_migrate_recover.add_argument("--dry-run", action="store_true")
    p_migrate_recover.add_argument(
        "--json",
        action="store_true",
        help="Emit a single JSON object (includes recovered_entries and skip details); no table",
    )
    p_migrate_recover.set_defaults(func=cli.cmd_recover_registry)

    return parser
