# Operator lifecycle — export, resilience, uninstall

**Created:** 2026-05-05  
**Updated:** 2026-09-15

This document is **policy and procedure**, not a feature spec. It complements [SECURITY_MODEL.md](SECURITY_MODEL.md).

- [Operator lifecycle — export, resilience, uninstall](#operator-lifecycle--export-resilience-uninstall)
  - [Resilience model](#resilience-model)
  - [Plaintext / broad export (allowed, bounded)](#plaintext--broad-export-allowed-bounded)
  - [Uninstall](#uninstall)
    - [Current release behavior](#current-release-behavior)
    - [Required next-RC behavior](#required-next-rc-behavior)
  - [Rollback](#rollback)
  - [Related](#related)

## Resilience model

- **Current operator resilience:** use explicit export/import flows and protect any generated artifacts. Encrypted JSON export is the current built-in artifact format.
- **Full / plaintext export** (where the product exposes it) is for **audit**, **migration**, **exit**, **severe divergence**, or **DR** only. It must stay **explicit**, **noisy** (warnings / confirmations), and **high-friction** (`--yes` with documented risk, typed confirms where applicable—not “one click backup”).
- **Daemon/envelope synchronization** exists in the current source for local and configured localhost peer delivery paths, including local lab orchestration, but the daemon implementation is under architectural boundary review. Cross-host P2P, peer discovery, RSS synchronization, and peer-bundle operator commands are not current CLI workflows.

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

Previously installed releases require the transparent manual procedure below. The unpublished candidate now implements the data-preserving subset of `seckit uninstall`; the full exit-export, archive, purge, legacy-installation, and platform qualification gate is not yet complete.

For a newly installed, receipt-aware candidate in the standard same-user layout:

```bash
seckit uninstall --dry-run
seckit uninstall --yes
```

Run as the installing user, never root. Dry-run inventories removal targets and managed shell-profile edits without stopping services. The confirmed command stops same-user daemon supervision and the detached daemon before removing verified dedicated runtime generations and the `seckit`/`seckit-mcp` launchers. It removes only the exact standard installer PATH block from Bash/Zsh profiles, preserving unrelated content and file permissions. Edited, duplicate, malformed, linked or foreign-owned profiles cause rejection instead of silent rewriting; inspect the reported issue before retrying. Configuration, databases, identities, Keychain items, exported files, installer state/logs, UV, managed Python, and unrelated environments remain intact. Reinstall from the verified artifact to reuse preserved state. Removal does not cancel a subscription or revoke an enrollment.

The updated installer records an owner-only content/type/mode/link inventory for each newly created standard runtime. Modified or added files, missing receipts, unknown/shared layouts, unsafe parents, namespace overrides, and failed shutdown cause refusal rather than guessed deletion. Runtime launchers disable bytecode writes so ordinary commands do not mutate the sealed package tree. The inventory is an ownership record, not a cryptographic trust signature against the same OS user. Do not concurrently upgrade, modify, or run other clients against a runtime being removed.

The daemon's metadata, socket, startup lock, and local transport identity share the runtime parent with the installed venv generations. They are not package directories. The preserving uninstaller recognizes these bounded state paths without deleting the identity; the daemon removes its own IPC state during shutdown. It rejects substituted symlinks and unexpected types. On Linux, reinstalling managed supervision waits for systemd to stop the previous client unit before enabling it again, rather than racing an IPC-only shutdown.

The installer sets `umask 077` for newly created paths. Existing writable or foreign-owned ancestors are not silently adopted by the uninstaller; inspect and correct them under the owning account before qualification. A failed installation without a receipt remains unqualified and must not be treated as a successful removable release.

Older generations without receipts are deliberately unsupported by this candidate; upgrading does not authorize deletion of unreceipted generations. Do not manufacture receipts for an existing environment merely to bypass this check. Inventory and qualify legacy migration/removal before fleet cleanup. The candidate supports explicitly selected `--purge` as described below; installed qualification is in progress. A bounded standard-state archive is available as described below. Separate protected shell/age export is described below and requires installed qualification. Do not describe a data-preserving removal as a clean empty-state install. Interrupted verified removal can be retried: an atomically renamed removal receipt is retained until the generation is empty. Retry permits missing entries only, rejects added or changed entries, and preserves persistent state. A crash after receipt deletion permits removal of only the empty generation directory. Unreceipted nonempty runtimes remain unsupported. Once launchers are removed, repeat invocation requires a retained installation or reinstall; the removal routine itself treats an already-empty runtime as a no-op.

**Typical steps (adjust for your install method):**

1. **Remove managed daemon supervision first:** run `seckit daemon service uninstall`. The command is idempotent and stops the same-user LaunchAgent or systemd user service before deleting its definition. If no managed service is installed, run `seckit daemon stop` for the detached daemon.
2. **Remove runtime directories only after daemon supervision is gone** so the service manager cannot restart a partially removed runtime. Published-artifact installs normally use `~/.local/share/seckit/runtime/` and `~/.local/bin/seckit*`.
3. **Remove the Python package** if installed via pip (`pip uninstall …`) or delete the venv that contained it.
4. **Backend data (you must choose):**
   - **Keychain:** Remove generic-password items the tool created (service/account/name patterns depend on your usage); the app does not silently delete other entries.
   - **SQLite:** Delete the database file if you used `--backend sqlite` (path from operator config or `SECKIT_SQLITE_PATH`).
5. **Configuration and registry:** Remove or archive `~/.config/seckit/` (`defaults.json`, `registry.json`, and related paths you used).
6. **Verify:** Ensure no remaining scheduled jobs, agents, or wrappers still call `seckit` or `seckitd`.

Operators are responsible for **their** copies of exports, bundles on disk, and shell history—nothing in the product should imply those vanish automatically on uninstall.

### Required next-RC behavior

Managed-service installation creates missing intermediate service directories with mode `0700`, independent of the login umask. Daemon metadata is replaced atomically with mode `0600`; reinstall must not leave group-writable lifecycle state. Existing unsafe directories are not silently adopted by uninstall.

The next RC must provide an idempotent `seckit uninstall` workflow with a dry-run. It must inventory exactly which installer-owned paths, managed-service definitions, runtime generations, launchers, configuration, datastore files, identity files, and known product-owned Keychain items it would affect before changing state.

The default uninstaller stops and removes managed daemon supervision first, removes only the dedicated Secrets Kit runtime and launchers, and preserves customer data, configuration, RSS identity, and protected datastore state for later reinstall. It must not remove `uv`, a shared Python environment, unrelated Keychain entries, user-created exports, or files whose ownership cannot be proven.

Permanent data removal requires a separate explicit purge option and confirmation. The purge must remain bounded to known product-owned paths and identifiers, reject unknown layouts, and report what was preserved. Symlinks, hard-linked state files, unexpected ownership, unsafe permissions, unknown runtime layouts, and ambiguous shared environments fail closed. A failed exit backup must prevent removal. The candidate exit archive rejects hard-linked state files because they may alias files outside the client state directories; both names and the installed runtime are retained on rejection. This archive check does not implement purge.

Purge ownership review: the current installation receipt covers runtime entries and launcher hashes only; it is not authority to delete configuration, datastore or Keychain contents. Keychain resolution intentionally includes unmanaged/adopted entries, and metadata source labels do not prove exclusive product ownership. A whole-Keychain deletion or automatic deletion of every visible entry is therefore outside the safe purge boundary. Candidate purge requires explicit named selection for every file and Keychain entry, with unknown/custom files always preserved and reported rather than recursively removed. Ordinary uninstall continues to preserve all customer state.

The candidate dry-run now includes `preserved_state`, a read-only inventory of immediate entries in the standard configuration and installer-state directories. `standard` identifies a recognized filename, not proof of exclusive ownership. `unknown` entries are preserved without traversing custom directories or following links. `unsafe_standard`, `uninspectable`, and `absent_or_changed` must not be treated as deletion approval or a successful empty-state check. No file contents or Keychain entries are read for this inventory. Runtime identity preservation remains reported separately by the existing preservation roots. A Keychain lookup failure other than item-not-found now raises a localized error rather than being mistaken for absence; this safeguard also protects explicit Keychain purge.

### Explicit permanent removal

For permanent removal, add `--purge` and repeat `--purge-file /absolute/standard/file` for each selected file. `--purge` alone refuses to guess. Inspect the complete command with `--dry-run`, then replace `--dry-run` with `--yes`. Only recognized standard client filenames and the runtime transport identity are eligible; custom paths and directory deletion are refused. Select existing SQLite `-wal` and `-shm` files together with the database. All unselected files and directories remain intact, including keys unless explicitly selected. Stop other writers first. Deleting a selected key can make retained data unreadable; verify an independent backup before selecting keys.

On macOS, repeat `--purge-keychain /absolute/keychain SERVICE ACCOUNT NAME` for individual entries. No automatic enumeration or whole-Keychain deletion occurs. The report gives the selected item count without printing those identifiers or values. Keychain entries and custom datastore locations are not covered by `--archive`; export them separately before confirming deletion.

An optional `--archive /absolute/new-backup.tar.gz` must finish before any purge deletion. Deletion failure leaves the runtime installed, but selected items already deleted are not restored automatically and supervision may be stopped. Inspect a fresh dry-run before retrying the same explicit selections; missing selected files/items are tolerated. Each confirmed retry authorizes the currently selected paths anew, not unknown files or a silently expanded inventory. Purge is not transactional across files and Keychain, and does not promise secure erasure from SSDs, snapshots or backups.

Before removal, the user may choose one of these independent exit paths:

- an explicit plaintext dotenv export, defaulting to `.env` only when plaintext export was specifically requested;
- a portable encrypted export using an already-installed external `age` implementation and a user-selected recipient;
- a protected state archive containing product-owned state, a manifest, and checksums for recovery or support.

Plaintext export must warn before materialization, create a mode-`0600` regular file atomically, refuse symlinks, and refuse an existing destination unless the user explicitly authorizes replacement. Portable encryption must fail closed when `age` or a valid recipient is unavailable; Secrets Kit must not install it automatically or fall back to plaintext. A protected state archive is highly sensitive and must never be described as sanitized support evidence.

Qualification must cover artifact install, managed and detached daemon modes, upgrade generations, preserved-state uninstall/reinstall, explicit purge, Keychain and SQLite backends, interrupted removal, repeat execution, and verification that no product-owned service or process survives removal. The uninstaller is a release gate for the next external tester RC.

## Rollback

### Candidate state archive

Recovery of product state must use the original canonical home/key paths: node identity projections contain absolute key references, and a moved home fails identity validation. Do not rewrite the database or weaken validation to relocate it. Same-path encrypted-store recovery has passed a CLI regression and a local macOS ARM64 installed audit-wheel cycle; relocation and the complete supported-platform matrix remain unqualified. Preserve existing configuration and state separately before restoring verified archive members; do not overwrite surviving files or restore into a running client. Portable shell/age secret export is a different exit path and does not preserve enrollment identity.

`seckit uninstall --dry-run --archive /absolute/new-backup.tar.gz` previews the backup destination without writing or stopping services. `seckit uninstall --yes --archive /absolute/new-backup.tar.gz` stops the client, archives standard configuration/state and transport identity, and only then removes the verified runtime. Archive failure leaves runtime files installed but the service stopped; correct the failure before retrying or explicitly restart the client.

The new archive is mode 0600, contains a SHA256 manifest, and refuses existing destinations and linked inputs. It is sensitive and unencrypted, not sanitized support evidence. Standard paths are `~/.config/seckit`, `~/.local/share/seckit/state`, and the runtime transport identity. Custom datastore paths, Keychain, and external logs are excluded. Stop all other writers before archival; the snapshot rejects observed changes but is not a transaction across independent processes. Inputs above 128 MiB fail rather than create a partial archive. Final-RC supported-platform backup/restore qualification remains open. Explicit purge is described above; complete installed-platform qualification remains open.

The macOS managed client uses the same user's background launchd domain (`user/<uid>`) and a Background-session LaunchAgent. An SSH login can install and operate this service without switching desktop accounts or using root. Existing GUI-domain client jobs are located for shutdown or migration. Desktop login is not required to operate the service through SSH.

Use the supported `seckit daemon service` commands to manage the client. These commands do not install a system-wide macOS service or run the daemon as root.

The installer refuses to change a runtime while a per-account system LaunchDaemon definition or loaded boot job exists. This check runs before installer directory creation, downloads or runtime replacement, including `--upgrade` and `--repair`. Do not bypass it with path overrides or by deleting the plist manually. System-level supervision requires administrator-assisted removal and restoration; the customer runtime must still be installed and operated as the customer, never as root. The optional boot-service helper is not yet part of the supported released installation procedure.

The job uses Standard process scheduling so interactive CLI and MCP requests are not subject to background resource throttling. This does not change its Background-session placement, same-user permissions, or headless lifecycle.

Install/start does not forcibly restart a process launched by RunAtLoad. The explicit restart command requests replacement. MCP status retains fail-closed error behavior with a five-second response timeout, consistent with other MCP operations.

The installer preserves older runtime generations during installation and upgrade. Removing generations requires explicit cleanup with verified ownership; successful activation alone does not authorize deleting recovery material. Retained runtimes consume disk space until cleanup. Legacy qualification first stops the client, verifies a protected recovery archive, and only then relocates the existing standard installation. A failed archive must prevent all subsequent relocation and installation steps.

Local daemon and IPC changes should remain reversible with normal source control rollback. Public peer-side daemon behavior must not require remote synchronization transport state or daemon-side secret persistence.

## Related

- [SECURITY_MODEL.md](SECURITY_MODEL.md) — exposure and redaction contract.
- [CLI_REFERENCE.md](CLI_REFERENCE.md) — current daemon and inspection commands.

## Portable exit export — candidate implementation

### Recovery after interrupted removal

If uninstall fails after removing the launcher, rerun the supported installer using the same trusted artifact and installing user, then run `seckit uninstall --dry-run` and review the plan before retrying `seckit uninstall --yes`. Do not delete or reseal a partial runtime by hand. A retained removal receipt permits missing original files but rejects added or changed files. Keep preserved configuration and datastore state in their original paths.

An isolated installed macOS ARM64 pilot verified this sequence after an injected filesystem failure removing `pyvenv.cfg`, with the launcher and runtime binaries already removed. Reinstallation recovered the encrypted value; the next uninstall removed the partial and replacement generations. This covers one deterministic filesystem-error point, not arbitrary power loss, every interruption window, managed-service failure or all support targets.

Before uninstall, explicitly export the required scope while the backend is accessible. The candidate supports `seckit export --all --format shell --out PATH` for plaintext shell assignments and `seckit export --all --format age --recipient RECIPIENT --out PATH` for portable encryption. Include the existing service/account/backend selection options for the intended scope. An installed external `age` executable is required; Secrets Kit does not install it or fall back to plaintext. Recover the encrypted shell file independently with `age --decrypt --identity IDENTITY_FILE BACKUP.age`; protect redirected plaintext output and review its contents before sourcing it. This is shell syntax, not a universal dotenv interchange format.

File output uses a new mode-`0600` file and refuses existing destinations, including symlinks. The parent directory must be owner-controlled, not group/world writable, and have no symlink components. Use a different destination rather than overwriting a backup. Shell export without `--out` retains its explicit stdout behavior. The existing `dotenv` format still exports placeholders, not secret values. The encrypted-json file path now uses the same protected writer.

These exports do not trigger uninstall or purge. Verify the backup before removal. An isolated macOS ARM64 installed-artifact pilot passed shell export, uninstall and independent Bash recovery, including protected-file mode verification and refusal of existing files, symlinks and writable destination directories. Missing external `age` refused without creating an output file. This does not qualify real age encryption/decryption, dependency-free installation, managed-service recovery or the complete supported-platform matrix. State archives, purge and interrupted-removal recovery are not completed by the portable export checks.
