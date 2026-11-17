# Credential migration, recovery, and uninstall

Use this reference only for approved local source files and the selected Unix account. Keep existing working data authoritative during upgrades. Do not reset stores or overwrite newer values merely because old dotenv files remain on disk.

## Inventory and precedence

1. Identify the selected application's actual loading paths, including dotenv files, profiles, service configuration, and file-based credentials. Inventory approved files and variable names without printing values. Do not recursively harvest the home directory or dump the process environment.
2. Separate credentials from ordinary configuration. A file can contain both. Migrate only selected names, preserve required non-secret settings, and identify all consumers before moving a shared file.
3. Record the exact service/account scope and the precedence of multiple sources. A filename such as `.env.local` does not establish precedence or even prove that the application loads it. Compare conflicting values internally and obtain a decision; report conflicts by name only.
4. Use the product's dotenv parser. Do not source dotenv as shell code or write a replacement parser with different quoting, interpolation, or duplicate-key behavior. Read installed help before handling non-dotenv formats, multiline values, or empty values. The Hermes startup helper supports only nonempty single-line values; do not silently flatten or discard unsupported data.
5. Use separate per-file allowlists: requesting a name absent from that file must fail. The final application allowlist is the approved union, not every variable inherited by the installer.

Set `SECKIT_SOURCE`, `SECKIT_NAMES`, `SECKIT_SERVICE`, and `SECKIT_ACCOUNT` to the approved non-secret path, comma-separated names, and scope. Use `seckit_local` from the installation skill:

```bash
: "${SECKIT_SOURCE:?set the approved dotenv path}"
: "${SECKIT_NAMES:?set the exact names present in this file}"
: "${SECKIT_SERVICE:?set the approved service}"
: "${SECKIT_ACCOUNT:?set the approved account}"
seckit_local import env --dotenv "$SECKIT_SOURCE" --names "$SECKIT_NAMES" --service "$SECKIT_SERVICE" --account "$SECKIT_ACCOUNT" --backend sqlite --dry-run
seckit_local import env --dotenv "$SECKIT_SOURCE" --names "$SECKIT_NAMES" --service "$SECKIT_SERVICE" --account "$SECKIT_ACCOUNT" --backend sqlite --yes
```

Execute the apply command only after the redacted dry-run matches the approved plan. For a reviewed intentional replacement, add `--allow-overwrite` to both commands after approving the exact affected scope/names. Do not use a blanket upsert to resolve unknown precedence. Keep the original files unchanged until cutover passes.

Import from other credential formats only through a documented local import path supported by the installed release. Do not pass a credential's value in command arguments, a model-visible MCP call, or chat. SSH private keys, storage keys, and OAuth credential bundles are not automatically convertible into environment secrets.

## Verify before cutover

- Require a healthy managed daemon and readable existing metadata. Installation checks do not count as value or application verification.
- Compare every selected imported value against the approved effective source inside a local, value-suppressing verifier. CLI materialization requires `get --raw`; the default display is not the stored value. Do not run a raw retrieval directly into an agent-visible terminal result. Retain counts/pass/fail, not values, lengths, per-secret hashes, or tool payloads.
- Test a synthetic canary through the actual application startup path and update it to prove refresh after the relevant restart. Keep failures separate from parser/verifier failures; do not change the store merely to make a comparison pass.
- Keep startup injection distinct from model-visible MCP retrieval. Verify only separately approved retrieval names; a successful test does not authorize every name.
- Preserve the existing cutover requirement for a successful credential-rotation test. Provider-side rotation needs its own authorization. A synthetic refresh test is useful but is not a substitute for that requirement unless the owner explicitly approves a different gate.
- Check actual application functionality and fresh startup evidence. With dotenv fallback still active, successful startup does not prove Secrets Kit supplied the values.

## Archive and cut over

Moving source files and restarting the application are separate authorized actions. Arrange rollback before either. Follow the host's service manager, inspect active workloads, and affect only the selected application stack. If the agent's own session will be stopped, leave a value-free checkpoint and use a supported out-of-process restart or ask the operator; do not repeatedly restart unrelated services to recover the session.

Choose the archive protection with the owner:

| Option | What it provides |
| --- | --- |
| Owner-private directory or tar outside all application loading paths | Prevents automatic dotenv fallback; remains readable by the same Unix user and its agents. |
| Encrypted archive with its key held outside the agent's access, or operator-controlled/off-host storage | Can remove the agent's ability to recover the plaintext, subject to that separate access boundary. |

A tar file is not encryption. Modes `0700`/`0600` do not isolate two processes running as the same Unix account. Do not label an archive inaccessible merely because it is hidden or outside the application home.

For an owner-approved private tar, the example below copies two already inventoried regular files. Set `APP_HOME` and `ARCHIVE_PARENT` to validated absolute directories, with the destination outside every application/repository loading path. Change the explicit file list to the approved existing sources; do not add globs or archive the whole home directory.

```bash
(
  set -eu
  umask 077
  : "${APP_HOME:?set the validated application home}"
  : "${ARCHIVE_PARENT:?set the approved private archive parent}"
  test -d "$ARCHIVE_PARENT"
  test -f "$APP_HOME/.env" && test ! -L "$APP_HOME/.env"
  test -f "$APP_HOME/.env.local" && test ! -L "$APP_HOME/.env.local"
  ARCHIVE_DIR=$(mktemp -d "$ARCHIVE_PARENT/seckit-sources.XXXXXXXX")
  tar -cf "$ARCHIVE_DIR/dotenv-recovery.tar" -C "$APP_HOME" .env .env.local
  chmod 600 "$ARCHIVE_DIR/dotenv-recovery.tar"
  tar -tf "$ARCHIVE_DIR/dotenv-recovery.tar"
  printf 'Recovery archive: %s\n' "$ARCHIVE_DIR/dotenv-recovery.tar"
)
```

This creates a plaintext recovery copy; it neither removes the originals nor proves content equality. Verify the archive's contents against the selected sources privately before moving originals. Review backup copies, profile variants and remaining credential assignments so fallback is actually disabled. Retain ordinary non-secret settings required by the application.

After explicit cutover approval, relocate only the inventoried originals to the approved recovery destination or otherwise remove them from their loading paths. Start a fresh application process without those sources or inherited fallback credentials, then verify startup injection, an approved functional request, and intended MCP policy. If a gate fails, restore the agreed source/configuration fallback and report failure; do not call import success a cutover success.

Leave the recoverable archive and a value-free path/restore inventory for the user to remove later. Do not automatically delete archives, wipe backups, or claim SSD snapshots and old copies have been securely erased.

## Export credentials and uninstall

Use this reverse path when the owner wants to stop using Secrets Kit. Export selected access credentials while the store is readable, move the application back to its approved credential source, verify a fresh start, and only then remove the software. Do not uninstall first and assume the old dotenv files contain current values.

### Choose the output format and scope

`export --format dotenv` writes references such as `NAME=${NAME}`, not stored values. For current credentials, `export --format dotenv-values --out PATH` writes a new protected plaintext dotenv file; `export --format shell --out PATH` writes protected POSIX-shell assignments. The value-bearing dotenv format requires `--out` and refuses values whose interpolation or control characters would prevent faithful loading. Never redirect a value-bearing stdout export into an agent tool result or use MCP retrieval to assemble a dotenv file.

Export one approved service/account scope per file with an explicit name list. Preserve the mapping of scope, selected names and intended consumer without recording values. Do not merge scopes that use the same variable name: an environment file cannot distinguish two different accounts' `API_TOKEN` values. `dotenv-values` refuses a partial explicit name selection; still check expected names and counts before cutover.

Set `EXIT_PARENT` to an approved existing owner-controlled absolute directory with no symlink components, outside repositories and automatic application loading paths. Set the source scope/name variables to the approved non-secret selectors. Define `seckit_local` in this shell as described in the installation skill, then run:

```bash
: "${EXIT_PARENT:?set the approved private export parent}"
: "${SECKIT_SERVICE:?set the source service}"
: "${SECKIT_ACCOUNT:?set the source account}"
: "${SECKIT_NAMES:?set the exact comma-separated export names}"
umask 077
EXIT_DIR=$(mktemp -d "$EXIT_PARENT/seckit-exit.XXXXXXXX")
seckit_local export --backend sqlite --service "$SECKIT_SERVICE" --account "$SECKIT_ACCOUNT" --names "$SECKIT_NAMES" --format shell --out "$EXIT_DIR/credentials.sh"
```

This new file is plaintext, mode `0600`, and owner-private; it remains readable by the same Unix user. Existing destinations, symlinks, and unsafe output directories are refused. Keep the path for subsequent steps if the agent's next tool call uses a new shell. Do not print, attach, or send the exported contents to the model.

### Create application dotenv files only after compatibility checks

Create a candidate `.env` with the explicit value-bearing format:

```bash
seckit_local export --backend sqlite --service "$SECKIT_SERVICE" --account "$SECKIT_ACCOUNT" --names "$SECKIT_NAMES" --format dotenv-values --out "$EXIT_DIR/.env"
```

This file contains stored credential values. Verify every selected value with the target application's actual dotenv loader in a value-suppressing local check before installing it at an active loading path. Quoting, escape sequences and multiline support differ among loaders. The exporter rejects literal `${` interpolation and unsupported controls rather than writing a changed value; if it rejects a credential, keep the protected shell export and use a reviewed application-specific recovery path. Do not assume the product's older dotenv importer can round-trip shell-exported apostrophes or multiline values.

If comparison fails, retain `credentials.sh` as a shell recovery artifact and stop the dotenv cutover. Use an approved application-specific format; do not invent a converter, strip quotes/prefixes with sed, or silently alter a credential to make the loader accept it. A shell-capable startup can instead consume the reviewed shell export; that is a different application configuration, not a generic dotenv file.

Repeat the scoped export into separate new files/directories for additional approved consumers. Exports reconstruct selected values, not the original files' comments, ordering, configuration-only entries, or file-based credential formats. Restore required non-secret configuration separately and preserve the agreed `.env`/`.env.local` precedence.

### Reverse application integration before removing software

1. Back up current application configuration and retain a verified recovery artifact. Do not restore an old full configuration snapshot over unrelated newer edits.
2. With explicit cutover approval, put the verified dotenv file at its selected path with owner-only permissions, or configure the approved shell-based credential source. Refuse to overwrite an existing source until the owner has reviewed it.
3. Disable only this application's Secrets Kit startup source and MCP registration using the application's supported configuration interface. Preserve unrelated MCP servers. Keep the old wiring available for rollback until the replacement source is verified.
4. Restart only the approved application processes through their actual manager, and verify an approved functional request with the replacement source. Confirm a fresh process no longer invokes the Secrets Kit helper, MCP server, or `seckit run`. Do not infer success from a still-running process that inherited old credentials.
5. If a gate fails, restore the reviewed application wiring and report failure. Keep Secrets Kit and its datastore intact; do not continue to uninstall.

For Hermes, identify the actual `secrets.command` source and MCP registration key rather than assuming it is named `secrets_kit` or `seckit`. Disable those exact entries, preserve other integrations, and check fresh gateway/desktop startup separately. No code edits are part of this procedure.

### Preview removal, preserve state, then confirm

Use the installing Unix account and the supported standard per-user installation. A shared/system installation requires its administrator's separate procedure. Do not manufacture receipts or manually remove a runtime that the uninstaller rejects.

```bash
: "${EXIT_DIR:?set the existing validated recovery directory}"
seckit_local uninstall --dry-run --archive "$EXIT_DIR/seckit-state.tar.gz"
```

Review the removal plan before proceeding. The dry-run does not stop services or create the archive. It should select only verified Secrets Kit runtime/launcher/service/profile changes and preserve the datastore, keys, configuration, and unrelated files. An unknown or modified installation is a failed gate, not permission for recursive deletion.

After the owner approves that exact plan and the application replacement-source check has passed, an unattended agent may use `--yes` to bypass the interactive prompt. It does not bypass ownership, receipt, path, or service safety checks:

```bash
seckit_local uninstall --yes --archive "$EXIT_DIR/seckit-state.tar.gz"
```

If removal reports `service_still_active`, stop before retrying. Check the selected account's managed daemon state and whether an application still uses it. After those consumers are stopped, run `seckit_local daemon service uninstall`, verify the service is inactive, then rerun the reviewed uninstall command. Do not remove a runtime or service file by hand, and do not treat this failure as permission to purge customer state.

The archive contains sensitive standard state, including keys needed to recover the encrypted store; it is not itself an encrypted credential export. Keep it outside application loading paths and protect it like plaintext credentials. Archive failure may leave the service stopped while the runtime remains installed: retain the failure and inspect state before retrying. Custom datastore paths are not automatically covered by this standard-state archive.

Confirm the selected launchers/runtime and managed daemon/update checker were removed, the application still works after a fresh start without Secrets Kit, and recovery files and preserved datastore/key files remain intact. The uninstaller does not own arbitrary application configuration, copied skills, or custom helper files; clean those up only after exact ownership/callers are reviewed and their removal is approved.

Default uninstall is not purge, RSS revocation, subscription cancellation, provider-key revocation, or secure erasure. Do not add `--purge` to this exit path. The user may separately decide what preserved state and archives to remove later. To return to Secrets Kit, reinstall from a verified artifact under the same Unix account and original state paths, verify preserved credentials/identity, and re-enable the reviewed application integration without initialization or automatic stale-source reimport.

## Recover an empty failed installation

Reinitialization is allowed only when the selected state is verified empty and disposable, or the owner explicitly designates it disposable with full knowledge that identity/history may be replaced. No readable secrets is not enough if peer identity, transactions, enrollment, or billing-owner credentials must survive. If the release cannot establish emptiness, stop rather than infer it.

1. Record software version, selected backend/path, daemon state, and evidence supporting the recovery classification. A schema mismatch or corrupt database remains uncertain data until assessed; do not automatically reset it.
2. Stop only the selected account's managed daemon after checking its consumers. Back up the database consistently together with its matching storage/identity keys and necessary configuration. Account for SQLite WAL/journal state: do not copy only a live database file or separate it from its key. Use a supported consistent backup or quiesce all writers before copying the complete state.
3. Keep code and state distinct. Preserve `~/.local/bin/`, `~/.local/share/seckit/runtime/`, its `current` link, installation receipts, and unrelated application files. Do not move the whole runtime directory to remove a stale daemon PID/socket.
4. Retain a dated owner-private recovery copy and exact restore inventory. Do not put storage keys, RSS credentials, or recovery codes into diagnostic output. Never fabricate a valid installation receipt.
5. Relocate only the reviewed failed datastore/state targets. Then use the verified installed CLI's `init` once. Do not try multiple initialization commands after one succeeds; initialization is not a retry probe.
6. Import from the approved sources and requalify the application path above. Do not silently reuse an old RSS credential with a new identity or claim that historical peer authorization survived a reset.

For populated or uncertain stores, repair/upgrade the software without initialization and obtain a datastore recovery plan. Configuration rollback, code-generation rollback, and customer-data restoration are different operations; none automatically undoes an import or restores peer authority.
