"""Shared CLI help text, formatters, and epilog fragments for seckit."""

from __future__ import annotations

import argparse


class SeckitHelpFormatter(argparse.RawDescriptionHelpFormatter, argparse.ArgumentDefaultsHelpFormatter):
    """Preserve description/epilog newlines; show defaults where useful."""


MAIN_HELP_EPILOG = """\
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
"""

# Backward-compatible alias for internal imports
_MAIN_HELP_EPILOG = MAIN_HELP_EPILOG


CONFIG_COMMAND_DESCRIPTION = """\
Manage operator defaults stored in defaults.json (not secret values).

Subcommands:
  show              Print defaults.json. Use --effective to merge legacy config.json + SECKIT_* env.
  set KEY VALUE     Write one key (choices shown in usage). Values are validated (e.g. backend).
  unset KEY         Remove a key from defaults.json.
  path              Print the absolute path to defaults.json.

Secrets and rich metadata live in the backend and in registry.json as a slim index;
defaults.json only fills omitted CLI flags like --service and --backend.\
"""