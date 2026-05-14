"""English human-facing CLI strings.

Operator-visible ``help=``, ``description=``, and ``epilog=`` text for argparse only.
Does **not** hold JSON output key names or wire identifiers—those stay in parser/commands code.

Lookup: ``STRINGS["KEY"]``. Stub locales (``es``, ``it``) re-export this dict until translated.
"""

from __future__ import annotations

__all__ = ("STRINGS",)

STRINGS: dict[str, str] = {
    "MAIN_HELP_EPILOG": """\
Typical paths (under ~/.config/seckit/, dir mode 0700, files 0600 unless noted):
  defaults.json     Operator defaults: backend, service, account, sqlite_db, tags, rotation hints
  registry.json     Slim index of seckit-managed entries (locator + entry_id + timestamps; not secrets)
  secrets.db        Default SQLite vault for --backend sqlite (override with SECKIT_SQLITE_DB / --db)
  identity/         Host signing/box keys for peer sync (seckit sync / seckit peer)

Command taxonomy (see docs/CLI_REFERENCE.md):
  Everyday operations     set, get, list, explain, run, export, import, delete
  Configuration           config (compatibility alias: defaults), unlock, lock, keychain-status, version
  Inventory / diagnostics doctor, backend-index, sqlite-inspect, rebuild-index, recover
  Migration / maintenance migrate, service
  Peer / sync             identity, peer, sync, daemon (local seckitd)
  Advanced / internal     helper, journal, migrate recover-registry, and other compatibility aliases

Command compatibility:
  Existing commands and aliases stay script-safe unless explicitly deprecated. Root help lists canonical
  names first; aliases name their replacement. See docs/CLI_STYLE_GUIDE.md.

Automation: prefer --json and structured output; human-readable tables and help text may change between
  releases. See docs/CLI_STYLE_GUIDE.md (JSON output stability).

Further reading: docs/CONCEPTS.md, docs/WORKFLOWS.md, docs/CLI_ARCHITECTURE.md, docs/DEFAULTS.md,
  docs/METADATA_REGISTRY.md, docs/METADATA_SEMANTICS_ADR.md, docs/RUNTIME_AUTHORITY_ADR.md
""",
    "CONFIG_COMMAND_DESCRIPTION": """\
Manage operator defaults stored in defaults.json (not secret values).

Subcommands:
  show              Print defaults.json. Use --effective to merge legacy config.json + SECKIT_* env.
  set KEY VALUE     Write one key (choices shown in usage). Values are validated (e.g. backend).
  unset KEY         Remove one key from defaults.json.
  path              Print the absolute path to defaults.json.

Secrets and rich metadata live in the backend and in registry.json as a slim index;
defaults.json only fills omitted CLI flags like --service and --backend.""",
    "HELP_KEYCHAIN_COMMON": (
        "Secure: keychain file for secret items. SQLite+keychain unlock: keychain file holding "
        "the KEK (see SECKIT_SQLITE_UNLOCK). Default: login.keychain-db"
    ),
    "HELP_KEYCHAIN_OVERRIDE": "Override keychain path (default: login.keychain-db)",
    "HELP_DB": (
        "SQLite database path (--backend sqlite only; default ~/.config/seckit/secrets.db or SECKIT_SQLITE_DB)"
    ),
    "ROOT_DESCRIPTION": (
        "Local secrets and PII: store values in a configured backend "
        "(Keychain when using --backend secure on macOS, or encrypted SQLite); "
        "manage operator defaults under ~/.config/seckit/."
    ),
    "SUBPARSERS_DESCRIPTION": (
        "Run seckit COMMAND --help for options. "
        "Typical flags: --backend, --service, --account, --keychain, --db."
    ),
    "DAEMON_HELP": "Control local seckitd (Unix socket; Phase 5)",
    "DAEMON_EPILOG": (
        "Run the daemon: ``seckitd`` or ``seckit daemon serve`` (same socket defaults).\n"
        "Examples:\n"
        "  seckitd --socket /tmp/seckitd.sock\n"
        "  seckit daemon ping --socket /tmp/seckitd.sock\n"
        "  seckit daemon submit-outbound --socket /tmp/seckitd.sock --payload-file ./blob.bin\n"
    ),
    "DAEMON_PING_HELP": "Ping local seckitd",
    "DAEMON_SOCKET_HELP": "Unix socket path (default: user runtime dir)",
    "DAEMON_TIMEOUT_HELP": "Socket timeout seconds",
    "DAEMON_STATUS_HELP": "Daemon status JSON",
    "DAEMON_SYNC_STATUS_HELP": (
        "Loopback runtime / coordinator snapshot (Phase 5D; requires SECKITD_RUNTIME_LOOPBACK on daemon)"
    ),
    "DAEMON_SUBMIT_OUTBOUND_HELP": "Submit an opaque outbound payload (local receipt only)",
    "DAEMON_PAYLOAD_FILE_HELP": "File whose raw bytes are sent as base64",
    "DAEMON_PAYLOAD_TYPE_HELP": "Advisory label only",
    "DAEMON_CLIENT_REF_HELP": "Optional client reference string",
    "DAEMON_ROUTE_KEY_HELP": (
        "Optional route key for loopback coordinator (default route when empty); "
        "only used when daemon runs with SECKITD_RUNTIME_LOOPBACK=1"
    ),
    "DAEMON_SERVE_HELP": "Run seckitd in the foreground (Unix socket listener)",
    "DAEMON_SERVE_EPILOG": (
        "Environment (Phase 5B):\n"
        "  SECKITD_INSECURE_SKIP_PEER_CRED=1 — skip same-user socket peer checks (**unsafe**; containers only).\n"
        "  SECKITD_VERBOSE_IPC=1 — include subprocess stdout/stderr tails in ``relay_inbound`` responses on success (**sensitive**).\n"
        "Environment (Phase 5D):\n"
        "  SECKITD_RUNTIME_LOOPBACK=1 — enable in-process loopback transport + coordinator ticker (testing; **non-authoritative**).\n"
        "See docs/IPC_SEMANTICS_ADR.md (local peer IPC) and docs/SECURITY_MODEL.md (sensitive debug env vars)."
    ),
    "SET_HELP": "Store or update one secret value",
    "SET_EPILOG": (
        "Examples:\n"
        "  echo 'sk-example' | seckit set --name OPENAI_API_KEY --stdin --kind api_key \\\n"
        "    --service my-stack --account local-dev\n"
        "  seckit set --name DEMO --value hello --kind generic --service my-stack --account local-dev"
    ),
    "GET_HELP": (
        "Read one stored secret value (redacted by default; --raw materializes plaintext to stdout)"
    ),
    "GET_EPILOG": (
        "Examples:\n"
        "  seckit get --name OPENAI_API_KEY --service my-stack --account local-dev\n"
        "  seckit get --name OPENAI_API_KEY --service my-stack --account local-dev --raw\n"
        "Without --raw, output stays redacted. With --raw, plaintext is materialized to stdout. "
        "Child env injection uses `seckit run` (see `seckit run --help`). docs/RUNTIME_AUTHORITY_ADR.md"
    ),
    "GET_RAW_HELP": "Materialize plaintext secret to stdout (elevated disclosure)",
    "LIST_HELP": (
        "Inventory: list seckit-managed entries using safe enumeration; "
        "selective backend resolve only when filters need it (values redacted)"
    ),
    "LIST_EPILOG": (
        "Examples:\n"
        "  seckit list --service my-stack --account local-dev\n"
        "  seckit list --service my-stack --account local-dev --tag prod --format json\n"
        "Use --format json for stable automation; table layout may change between releases."
    ),
    "LIST_STALE_HELP": "Filter entries older than N days",
    "EXPLAIN_HELP": (
        "Inspect one entry: authoritative metadata JSON; secret plaintext is not written to stdout by default"
    ),
    "EXPLAIN_EPILOG": (
        "Examples:\n"
        "  seckit explain --name OPENAI_API_KEY --service my-stack --account local-dev\n"
        "Resolves internally without materializing the secret to the terminal by default. "
        "See docs/RUNTIME_AUTHORITY_ADR.md (resolve vs materialize)."
    ),
    "CONFIG_HELP": "View or edit defaults.json (compatibility alias: defaults)",
    "CONFIG_EPILOG": (
        "Examples:\n"
        "  seckit config show\n"
        "  seckit config set service my-stack\n"
        "  seckit defaults show --effective"
    ),
    "CONFIG_SHOW_HELP": (
        "Print defaults from defaults.json; add --effective for merged file + legacy config + env"
    ),
    "CONFIG_EFFECTIVE_HELP": (
        "Merge defaults.json, legacy ~/.config/seckit/config.json, and SECKIT_* env overrides"
    ),
    "CONFIG_SET_HELP": "Set one key in defaults.json",
    "CONFIG_VALUE_HELP": "Value (use quotes if it contains spaces)",
    "CONFIG_UNSET_HELP": "Remove one key from defaults.json",
    "CONFIG_PATH_HELP": "Print path to defaults.json",
    "DELETE_HELP": "Delete one stored secret and its metadata",
    "DELETE_EPILOG": (
        "Examples:\n"
        "  seckit delete --name OLD_KEY --service my-stack --account local-dev\n"
        "  seckit delete --name OLD_KEY --service my-stack --account local-dev --yes"
    ),
    "IMPORT_HELP": "Import secrets from dotenv, live env, JSON/YAML, or encrypted export",
    "IMPORT_DESCRIPTION": "Bulk-create or update entries. Subcommands: env, file, encrypted-json.",
    "IMPORT_ENV_HELP": "Import secrets from dotenv and/or live environment",
    "IMPORT_UPSERT_HELP": "Create new names and update existing values",
    "IMPORT_FILE_HELP": "Import secrets from JSON or YAML files",
    "IMPORT_ENCRYPTED_JSON_HELP": "Import secrets from encrypted JSON export",
    "EXPORT_HELP": (
        "Exported materialization: shell, dotenv, or encrypted-json file (bulk plaintext or backup artifact)"
    ),
    "EXPORT_EPILOG": (
        "Exports are materialization paths that produce operator-visible text or an externalized artifact "
        "(transient or persistent depending on transport/storage). Prefer narrow scope (--names, --tag) or "
        "explicit --all.\n\n"
        "Examples:\n"
        "  seckit export --service my-stack --account local-dev --format shell --names OPENAI_API_KEY\n"
        "  seckit export --service my-stack --account local-dev --format encrypted-json --out backup.json\n"
    ),
    "EXPORT_ALL_HELP": "Export all matching entries (elevated scope)",
    "RUN_HELP": (
        "Exec a child after resolve/inject: injection transfers plaintext into another execution context"
    ),
    "RUN_EPILOG": (
        "Injection is a runtime-scoped materialization path that transfers plaintext into another execution context.\n"
        "Environment inheritance: injection into child execution contexts may further propagate through environment "
        "inheritance unless explicitly constrained by the caller/runtime.\n\n"
        "Examples:\n"
        "  seckit run --service my-stack --account local-dev -- python3 app.py\n"
        "  seckit run --service my-stack --account local-dev --names OPENAI_API_KEY -- python3 -c 'import os; ...'\n"
    ),
    "RUN_ALL_HELP": "Inject all matching entries (elevated scope)",
    "SERVICE_HELP": "Manage service-scoped secret groups",
    "SERVICE_COPY_HELP": "Copy secrets from one service scope to another",
    "DOCTOR_HELP": (
        "JSON diagnostics: security CLI, roundtrip, registry drift, backend capabilities/posture"
    ),
    "DOCTOR_EPILOG": (
        "Examples:\n"
        "  seckit doctor\n"
        "  seckit doctor --backend sqlite --db /path/to/secrets.db\n"
        "  seckit doctor --fix-defaults  # rewrite defaults.json if backend is a legacy id"
    ),
    "DOCTOR_FIX_DEFAULTS_HELP": (
        "Rewrite ~/.config/seckit/defaults.json when 'backend' is icloud / icloud-helper (does not change env vars)"
    ),
    "BACKEND_INDEX_HELP": (
        "Diagnostics: decrypt-safe backend index rows (BackendStore.iter_index); not authority, not secrets"
    ),
    "BACKEND_INDEX_EPILOG": (
        "Examples:\n"
        "  seckit backend-index --service my-stack --account local-dev\n"
        "Emits JSON lines; not a materialization path—see docs/CLI_ARCHITECTURE.md."
    ),
    "SQLITE_INSPECT_HELP": (
        "SQLite debug: JSON index dump; optional unlock summaries (secret lengths only, no values)"
    ),
    "SQLITE_INSPECT_EPILOG": (
        "Requires ``--backend sqlite`` and ``--db``. For ``--summaries``, the store must be unlockable.\n"
        "See SECKIT_SQLITE_PLAINTEXT_DEBUG in docs/SECURITY_MODEL.md (disposable SQLite debug)."
    ),
    "SQLITE_INSPECT_SUMMARIES_HELP": (
        "Include per-row unlock summaries (secret byte length, locator fields); requires decrypt"
    ),
    "REBUILD_INDEX_HELP": (
        "Rebuild backend decrypt-free index from authority payloads (SQLite); repair hashes/hints"
    ),
    "JOURNAL_HELP": "Append-only local registry event log (operational / sync aid; advanced)",
    "JOURNAL_APPEND_HELP": "Append one JSON object line to registry_events.jsonl",
    "JOURNAL_EVENT_JSON_HELP": "Single JSON object (shell-quoted)",
    "UNLOCK_HELP": "Unlock the configured macOS Keychain backend (Keychain-specific)",
    "KEYCHAIN_CMD_DRY_RUN_HELP": "Show the backend command without running it",
    "KEYCHAIN_CMD_YES_HELP": "Run without confirmation prompt",
    "UNLOCK_HARDEN_HELP": "Also apply a safer keychain timeout policy after unlock",
    "UNLOCK_TIMEOUT_HELP": "Timeout in seconds used with --harden (default: 3600)",
    "LOCK_HELP": "Lock the configured macOS Keychain backend (Keychain-specific)",
    "KEYCHAIN_STATUS_HELP": (
        "Report macOS Keychain accessibility and lock policy (Keychain-specific)"
    ),
    "RECOVER_HELP": (
        "Rebuild registry/index metadata from the live store (same as migrate recover-registry)"
    ),
    "RECOVER_DESCRIPTION": (
        "When registry.json is missing or stale but secrets still exist in the store, scan the backend "
        "and rewrite a slim registry index. Does not read secret values from SQLite ciphertext; "
        "uses index/comment metadata where available."
    ),
    "RECOVER_EPILOG": (
        "Examples:\n"
        "  seckit recover --dry-run\n"
        "  seckit recover --json\n"
        "See docs/WORKFLOWS.md for recovery flows."
    ),
    "RECOVER_DRY_RUN_HELP": (
        "Preview: print a list-style table and skip writing registry.json"
    ),
    "RECOVER_JSON_OUTPUT_HELP": (
        "Emit a single JSON object (includes recovered_entries and skip details); no table"
    ),
    "VERSION_HELP": "Print the installed seckit version",
    "VERSION_INFO_HELP": (
        "Print version, platform, defaults summary, and helper status stub (no secret values)"
    ),
    "VERSION_JSON_HELP": "Same as --info as JSON (sorted keys)",
    "HELPER_HELP": (
        "Show backend availability and helper metadata (JSON, no secrets; advanced / diagnostics)"
    ),
    "HELPER_STATUS_HELP": "Print JSON: backend_availability and helper fields (no bundled Mach-O)",
    "MIGRATE_HELP": "Migrate existing secret files into seckit",
    "IDENTITY_HELP": "Host Ed25519/X25519 identity for peer sync",
    "IDENTITY_INIT_HELP": "Create or replace host signing/box key material",
    "IDENTITY_SHOW_HELP": "Show local host id and fingerprints",
    "IDENTITY_EXPORT_HELP": "Write public identity JSON for peer add",
    "PEER_HELP": "Trusted peers for peer sync bundles",
    "PEER_ADD_HELP": "Add peer from `seckit identity export` file",
    "PEER_REMOVE_HELP": "Remove a peer alias",
    "PEER_LIST_HELP": "List trusted peers",
    "PEER_SHOW_HELP": "Show one peer (JSON)",
    "RECONCILE_HELP": (
        "Read-only Phase 6A reconciliation diagnostics (SQLite lineage; no repair)"
    ),
    "RECONCILE_INSPECT_HELP": (
        "Dump SQLite index row + capability flags for an entry_id (no secret values)"
    ),
    "RECONCILE_LINEAGE_HELP": "Lineage-oriented view of SQLite index fields for an entry_id",
    "RECONCILE_EXPLAIN_HELP": (
        "Classify one bundle row JSON against local state (stdin, '-', or --bundle-row PATH)"
    ),
    "RECONCILE_BUNDLE_ROW_HELP": (
        "JSON file with one inner entries[] object; omit or '-' to read stdin"
    ),
    "RECONCILE_LOCAL_HOST_ID_HELP": (
        "Host id used as default_origin for the synthetic ImportCandidate (default: explain-local)"
    ),
    "RECONCILE_VERIFY_HELP": (
        "Read-only PRAGMA + lineage-shaped invariant report (report-only; no auto-fix)"
    ),
    "RECONCILE_STRICT_CONTENT_HASH_HELP": (
        "Also report active rows with empty content_hash (informational)"
    ),
    "SYNC_HELP": "Signed encrypted peer bundle export/import",
    "SYNC_EXPORT_HELP": "Export registry secrets to a peer bundle",
    "SYNC_EXPORT_PEER_HELP": "Recipient alias (repeatable)",
    "SYNC_IMPORT_HELP": "Import and merge a peer bundle",
    "SYNC_IMPORT_EPILOG": (
        "Use ``-`` as FILE to read bundle JSON from stdin (also used by ``seckitd`` relay inbound).\n"
        "Examples:\n"
        "  seckit sync import ./bundle.json --signer alice --yes\n"
        "  cat bundle.json | seckit sync import - --signer alice --yes --backend sqlite --db ./vault.db"
    ),
    "SYNC_IMPORT_FILE_HELP": "Path to bundle JSON, or '-' for stdin",
    "SYNC_IMPORT_SIGNER_HELP": "Local peer alias for the exporter who signed this bundle",
    "SYNC_IMPORT_RECONCILE_TRACE_HELP": (
        "Emit secret-safe JSONL classification rows to stderr (decision, reason, lineage fields)"
    ),
    "SYNC_VERIFY_HELP": "Verify bundle JSON signature and structure",
    "SYNC_TRY_DECRYPT_HELP": "Decrypt inner (requires local identity + --signer)",
    "SYNC_VERIFY_SIGNER_HELP": "Exporter peer alias (required with --try-decrypt)",
    "SYNC_INSPECT_HELP": "Inspect bundle (manifest; no decryption)",
    "MIGRATE_DOTENV_HELP": "Import a dotenv file and optionally rewrite it to placeholders",
    "MIGRATE_METADATA_HELP": "Write registry metadata into keychain comment JSON",
    "MIGRATE_RECOVER_REGISTRY_HELP": (
        "Compatibility alias for `seckit recover` (rebuild registry from the store)"
    ),
}
