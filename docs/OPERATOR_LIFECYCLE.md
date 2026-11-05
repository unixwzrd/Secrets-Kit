> Source of truth: Secrets Kit documentation master. This public copy is a reviewed derivative.

# Operator lifecycle — export, resilience, uninstall

**Created:** 2026-05-05  
**Updated:** 2026-11-04

This document is **policy and procedure**, not a feature spec. It complements [SECURITY_MODEL.md](SECURITY_MODEL.md).

- [Operator lifecycle — export, resilience, uninstall](#operator-lifecycle--export-resilience-uninstall)
  - [Resilience model](#resilience-model)
  - [Plaintext / broad export (allowed, bounded)](#plaintext--broad-export-allowed-bounded)
  - [Uninstall](#uninstall)
    - [Current release behavior](#current-release-behavior)
    - [Preserved state and permanent removal](#preserved-state-and-permanent-removal)
  - [Rollback](#rollback)
  - [Related](#related)

## Resilience model

- **Current operator resilience:** use explicit export/import flows and protect any generated artifacts. Encrypted JSON export is the current built-in artifact format.
- **Full / plaintext export** (where the product exposes it) is for **audit**, **migration**, **exit**, **severe divergence**, or **DR** only. It must stay **explicit**, **noisy** (warnings / confirmations), and **high-friction** (`--yes` with documented risk, typed confirms where applicable—not “one click backup”).
- **Daemon/envelope synchronization** requires explicit peer admission and authorization. Transport availability depends on the selected route and network conditions.

See also [CLI_REFERENCE.md](CLI_REFERENCE.md) and [WORKFLOWS.md](WORKFLOWS.md).

## Plaintext / broad export (allowed, bounded)

Export paths that can surface **materialized** or **structured sensitive** data must:

1. Require an **obvious** command or flag (no hidden side channels).
2. Emit **clear stderr / operator messaging** that data is sensitive and where it is written.
3. Avoid encouraging **scheduled** or **routine** full-plaintext export as “backup”; prefer encrypted export artifacts when operator-managed export is required.

No tooling should imply that export is **mandatory** for day-to-day safety.

## Uninstall

Secrets Kit does **not** use **dark patterns**: no encryption ransom, no undisclosed background retention, no “phone home” during uninstall. Subscription cancellation and application removal are separate actions. Removing a peer never silently cancels billing, and cancelling billing never silently deletes local customer data.

### Current release behavior

The `seckit uninstall` command provides a data-preserving removal path for supported managed installations. Older or unrecognized runtime layouts require manual review; do not manufacture ownership records or remove files based on guessed paths.

For a standard same-user installation:

```bash
seckit uninstall --dry-run
seckit uninstall --yes
```

Run as the installing user, never root. Dry-run inventories removal targets and managed shell-profile edits without stopping services. The confirmed command stops same-user daemon supervision and the detached daemon before removing verified dedicated runtime generations and the `seckit`/`seckit-mcp` launchers. It removes only the exact standard installer PATH block from Bash/Zsh profiles, preserving unrelated content and file permissions. Edited, duplicate, malformed, linked or foreign-owned profiles cause rejection instead of silent rewriting; inspect the reported issue before retrying. Configuration, databases, identities, Keychain items, exported files, installer state/logs, UV, managed Python, and unrelated environments remain intact. Reinstall from the verified artifact to reuse preserved state. Removal does not cancel a subscription or revoke an enrollment.

The updated installer records an owner-only content/type/mode/link inventory for each newly created standard runtime. Modified or added files, missing receipts, unknown/shared layouts, unsafe parents, namespace overrides, and failed shutdown cause refusal rather than guessed deletion. Runtime launchers disable bytecode writes so ordinary commands do not mutate the sealed package tree. The inventory is an ownership record, not a cryptographic trust signature against the same OS user. Do not concurrently upgrade, modify, or run other clients against a runtime being removed.

The daemon's metadata, socket, startup lock, and local transport identity share the runtime parent with the installed venv generations. They are not package directories. The preserving uninstaller recognizes these bounded state paths without deleting the identity; the daemon removes its own IPC state during shutdown. It rejects substituted symlinks and unexpected types. On Linux, reinstalling managed supervision waits for systemd to stop the previous client unit before enabling it again, rather than racing an IPC-only shutdown.

The installer sets `umask 077` for newly created paths. Existing writable or foreign-owned ancestors are not silently adopted by the uninstaller; inspect and correct them under the owning account. A failed installation without a receipt must not be treated as a successfully managed installation.

Older runtime generations without ownership receipts are not eligible for automatic removal; upgrading does not authorize deletion of unreceipted generations. Do not manufacture receipts to bypass this check. The uninstaller can be retried after an interrupted verified removal: it permits missing entries, rejects added or changed entries, and preserves persistent state. Once launchers are removed, repeat invocation requires a retained installer or reinstall. An already-empty runtime is treated as a no-op.

**Typical steps (adjust for your install method):**

1. **Remove managed daemon supervision first:** run `seckit daemon service uninstall`. The command is idempotent and stops the same-user LaunchAgent or systemd user service before deleting its definition. If no managed service is installed, run `seckit daemon stop` for the detached daemon.
2. **Remove runtime directories only after daemon supervision is gone** so the service manager cannot restart a partially removed runtime. Published-artifact installs normally use `~/.local/share/seckit/runtime/` and `~/.local/bin/seckit*`.
3. **Remove the Python package** if installed via pip (`pip uninstall …`) or delete the venv that contained it.
4. **SQLite data (you must choose):** SQLite is the operational backend. Keep or archive the database at the configured path (including `SECKIT_SQLITE_PATH`) for reinstall, or select it explicitly for permanent removal. Legacy Keychain records are migration inputs only; migration and ordinary uninstall do not delete them.
5. **Configuration and registry:** Remove or archive `~/.config/seckit/` (`defaults.json`, `registry.json`, and related paths you used).
6. **Verify:** Ensure no remaining scheduled jobs, agents, or wrappers still call `seckit` or `seckitd`.

Operators are responsible for **their** copies of exports, bundles on disk, and shell history—nothing in the product should imply those vanish automatically on uninstall.

### Preserved state and permanent removal

Managed-service installation creates missing intermediate service directories with mode `0700`, independent of the login umask. Daemon metadata is replaced atomically with mode `0600`; reinstall must not leave group-writable lifecycle state. Existing unsafe directories are not silently adopted by uninstall.

The dry-run inventories the selected removal scope before changes. The default uninstaller stops and removes managed daemon supervision first, removes only the dedicated Secrets Kit runtime and launchers, and preserves customer data, configuration, transport identity, and protected datastore state for later reinstall. It does not remove `uv`, a shared Python environment, unrelated Keychain entries, user-created exports, or files whose ownership cannot be proven.

Permanent data removal requires a separate explicit purge option and confirmation. Purge is bounded to selected known paths and identifiers, rejects unknown layouts, and reports preserved state. Symlinks, hard-linked state files, unexpected ownership, unsafe permissions, unknown runtime layouts, and ambiguous shared environments fail closed. A requested archive must complete before purge deletion. Hard-linked state files are rejected because they may alias files outside the client state directories.

An installation receipt covers runtime entries and launcher hashes only; it is not authority to delete configuration, datastore, or Keychain contents. Keychain resolution can include unmanaged/adopted entries, and metadata source labels do not prove exclusive product ownership. Whole-Keychain deletion or automatic deletion of every visible entry is outside the safe purge boundary. Purge requires explicit selection for each file and Keychain entry; unknown/custom files are preserved and reported rather than recursively removed. Ordinary uninstall preserves customer state.

The dry-run's `preserved_state` inventory is read-only and covers immediate entries in standard configuration and installer-state directories. `standard` identifies a recognized filename, not proof of exclusive ownership. `unknown` entries are preserved without traversing custom directories or following links. `unsafe_standard`, `uninspectable`, and `absent_or_changed` are not deletion approval or proof of an empty state. The inventory does not read file contents or Keychain entries. Runtime identity preservation is reported separately. Keychain lookup errors other than item-not-found are reported as errors rather than absence.

### Explicit permanent removal

For permanent removal, add `--purge` and repeat `--purge-file /absolute/standard/file` for each selected file. `--purge` alone refuses to guess. Inspect the complete command with `--dry-run`, then replace `--dry-run` with `--yes`. Only recognized standard client filenames and the runtime transport identity are eligible; custom paths and directory deletion are refused. Select existing SQLite `-wal` and `-shm` files together with the database. All unselected files and directories remain intact, including keys unless explicitly selected. Stop other writers first. Deleting a selected key can make retained data unreadable; verify an independent backup before selecting keys.

On macOS, repeat `--purge-keychain /absolute/keychain SERVICE ACCOUNT NAME` for individual entries. No automatic enumeration or whole-Keychain deletion occurs. The report gives the selected item count without printing those identifiers or values. Keychain entries and custom datastore locations are not covered by `--archive`; export them separately before confirming deletion.

An optional `--archive /absolute/new-backup.tar.gz` must finish before any purge deletion. Deletion failure leaves the runtime installed, but selected items already deleted are not restored automatically and supervision may be stopped. Inspect a fresh dry-run before retrying the same explicit selections; missing selected files/items are tolerated. Each confirmed retry authorizes the currently selected paths anew, not unknown files or a silently expanded inventory. Purge is not transactional across files and Keychain, and does not promise secure erasure from SSDs, snapshots or backups.

Before removal, the user may choose one of these independent exit paths:

- an explicit plaintext dotenv export, defaulting to `.env` only when plaintext export was specifically requested;
- a portable encrypted export using an already-installed external `age` implementation and a user-selected recipient;
- a protected state archive containing product-owned state, a manifest, and checksums for recovery or support.

Plaintext export must warn before materialization, create a mode-`0600` regular file atomically, refuse symlinks, and refuse an existing destination unless the user explicitly authorizes replacement. Portable encryption must fail closed when `age` or a valid recipient is unavailable; Secrets Kit must not install it automatically or fall back to plaintext. A protected state archive is highly sensitive and must never be described as sanitized support evidence.

## Rollback

### State archive

Recovery of product state must use the original canonical home/key paths: node identity projections contain absolute key references, and a moved home fails identity validation. Do not rewrite the database or weaken validation to relocate it. Preserve existing configuration and state separately before restoring verified archive members; do not overwrite surviving files or restore into a running client. Portable shell/age secret export is a different exit path and does not preserve enrollment identity.

`seckit uninstall --dry-run --archive /absolute/new-backup.tar.gz` previews the backup destination without writing or stopping services. `seckit uninstall --yes --archive /absolute/new-backup.tar.gz` stops the client, archives standard configuration/state and transport identity, and only then removes the verified runtime. Archive failure leaves runtime files installed but the service stopped; correct the failure before retrying or explicitly restart the client.

The archive is mode 0600, contains a SHA256 manifest, and refuses existing destinations and linked inputs. It is sensitive and unencrypted, not sanitized support evidence. Standard paths are `~/.config/seckit`, `~/.local/share/seckit/state`, and the runtime transport identity. Custom datastore paths, Keychain, and external logs are excluded. Stop all other writers before archival; the snapshot rejects observed changes but is not a transaction across independent processes. Inputs above 128 MiB fail rather than create a partial archive. Explicit purge is described above.

The macOS managed client uses the same user's background launchd domain (`user/<uid>`) and a Background-session LaunchAgent. An SSH login can install and operate this service without switching desktop accounts or using root. Existing GUI-domain client jobs are located for shutdown or migration. Desktop login is not required to operate the service through SSH.

Use the supported `seckit daemon service` commands to manage the client. These commands do not install a system-wide macOS service or run the daemon as root.

The installer refuses to change a runtime while a per-account system LaunchDaemon definition or loaded boot job exists. This check runs before installer directory creation, downloads or runtime replacement, including `--upgrade` and `--repair`. Do not bypass it with path overrides or by deleting the plist manually. System-level supervision requires administrator-assisted removal and restoration; the customer runtime must still be installed and operated as the customer, never as root. Use the documented same-user service commands rather than optional boot-service helpers.

The job uses Standard process scheduling so interactive CLI and MCP requests are not subject to background resource throttling. This does not change its Background-session placement, same-user permissions, or headless lifecycle.

Install/start does not forcibly restart a process launched by RunAtLoad. The explicit restart command requests replacement. MCP status retains fail-closed error behavior with a five-second response timeout, consistent with other MCP operations.

The installer preserves older runtime generations during installation and upgrade. Removing generations requires explicit cleanup with verified ownership; successful activation alone does not authorize deleting recovery material. Retained runtimes consume disk space until cleanup. Before relocating an existing standard installation, stop the client and verify a protected recovery archive. A failed archive must prevent all subsequent relocation and installation steps.

Local daemon and IPC changes should remain reversible with normal source control rollback. Public peer-side daemon behavior must not require remote synchronization transport state or daemon-side secret persistence.

## Related

- [SECURITY_MODEL.md](SECURITY_MODEL.md) — exposure and redaction contract.
- [CLI_REFERENCE.md](CLI_REFERENCE.md) — current daemon and inspection commands.

## Portable exit export

### Recovery after interrupted removal

If uninstall fails after removing the launcher, rerun the supported installer using the same trusted artifact and installing user, then run `seckit uninstall --dry-run` and review the plan before retrying `seckit uninstall --yes`. Do not delete or reseal a partial runtime by hand. A retained removal receipt permits missing original files but rejects added or changed files. Keep preserved configuration and datastore state in their original paths.

Before uninstall, explicitly export the required scope while the SQLite backend is accessible. `seckit export --all --format shell --out PATH` creates plaintext shell assignments; `seckit export --all --format age --recipient RECIPIENT --out PATH` creates portable encryption. Include the existing service/account selection options for the intended scope. An installed external `age` executable is required; Secrets Kit does not install it or fall back to plaintext. Recover the encrypted shell file independently with `age --decrypt --identity IDENTITY_FILE BACKUP.age`; protect redirected plaintext output and review its contents before sourcing it. This is shell syntax, not a universal dotenv interchange format.

File output uses a new mode-`0600` file and refuses existing destinations, including symlinks. The parent directory must be owner-controlled, not group/world writable, and have no symlink components. Use a different destination rather than overwriting a backup. Shell export without `--out` retains its explicit stdout behavior. The existing `dotenv` format still exports placeholders, not secret values. The encrypted-json file path now uses the same protected writer.

These exports do not trigger uninstall or purge. Verify the backup before removal. Age export fails without an installed external executable and does not create plaintext as a fallback.
