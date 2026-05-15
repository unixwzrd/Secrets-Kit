# Peer sync bundles (Phase 1B)

**Created**: 2026-05-05  
**Updated**: 2026-05-12

Manual, **offline** exchange of selected secrets between hosts: **signed** (Ed25519) **and encrypted** (X25519 Box for per-recipient CEK wrap, NaCl SecretBox for the payload). **No network, daemon, or sync engine** is part of this phase—only files you copy yourself (`scp`, USB, Syncthing folder, etc.).

## Trust model

1. Each host runs **`seckit identity init`** once. This creates a stable **`host_id`** (UUID) and two key roles: **signing** (Ed25519) and **Box** (Curve25519).
2. Operators exchange **public** material only: **`seckit identity export -o peer.pub.json`**. Peers file lives next to registry under `~/.config/seckit/identity/secret.json` (mode `0600`); **never** ship the secret file.
3. You **register** a peer with **`seckit peer add <alias> peer.pub.json`**. The registry stores both public keys and a **fingerprint** (SHA-256 over the raw Ed25519 verify key, hex). File: `~/.config/seckit/peers.json` (`0600`).
4. **Export:** `seckit sync export --peer alice --peer bob -o bundle.json …` selects secrets like **`seckit export`**, optionally narrows with **`--domain` / `--domains`**, and builds one bundle with **one wrapped CEK slot per recipient** (fingerprint → Box ciphertext).
5. **Import:** On the recipient, the signer must already be trusted: **`seckit sync import bundle.json --signer carol …`**. The CLI verifies the detached signature, unwraps the CEK with your Box key, decrypts the inner JSON, then **merges** entries deterministically (see below).

If you add a peer alias pointing at the wrong public file, you can decrypt bundles meant for another principal **only if** you are in `wrapped_cek`. Wrong trust is an operator error; the tool does not “phone home.”

## Bundle format (`seckit.peer_bundle` v1)

- **Top-level:** `format`, `version`, `manifest`, `wrapped_cek`, `inner_ciphertext`, `signature`.
- **Signed payload** (canonical JSON, `sort_keys=True`, `separators=(',', ':')`): exactly  
  `{"inner_ciphertext": "...", "manifest": {...}, "wrapped_cek": {...}}`.
- **Inner plaintext** (UTF-8 JSON, encrypted with SecretBox): `export_id`, `created_at`, `origin_host`, optional `domain_filter`, and **`entries`**: `[{ "metadata": {...}, "value": "...", "origin_host": "..." }]`.

### Forward-compatible manifest

New **`manifest`** keys **must not** be ignored if they could change algorithms, signing scope, recipient wrapping, or trust binding. **V1** allows extra keys **only** if their names begin with **`x_`** (experimental / informational). Those keys are included in the signed object. Producers **must not** use `x_*` to smuggle security-critical behavior without a format bump.

## Merge rules (import)

For each entry, compare `(updated_at, origin_host)` lexicographically. **Origin** is the exporting host’s id for that row (stored in metadata custom key `seckit_sync_origin_host` after import). **Ties** with the same value → **unchanged**; ties with different values → **conflict** (skipped, counted in stats). **Strictly newer** incoming row → **import**; **older** → **skip**.

**SQLite lineage merge:** When bundle rows carry **`generation`**, **`tombstone_generation`**, or **`disposition: tombstone`**, and the backend is SQLite with durable index lineage, merge uses **tombstone authority**, **generation ordering**, **replay suppression**, optional **`content_hash`** verification, and **`entry_id`-stable rename**. Import JSON may include **`hash_conflict_details`** when a declared row hash does not verify. Read-only reconciliation tooling reports stable decision and reason strings without exposing secret values.

`export_id` is **not** a replay cache—re-import policy is **only** per-entry merge.

## Domain filters

- **Export:** after normal selection, keep entries whose **`domains`** overlap any **`--domain` / `--domains`** value (any exact string match).
- **Import:** same rule: only entries matching the filter are applied.

## Commands (summary)

| Command | Purpose |
|--------|---------|
| `seckit identity init [--force]` | Create host secrets |
| `seckit identity show` | Host id + fingerprints |
| `seckit identity export [-o PATH]` | Public JSON for peers |
| `seckit peer add ALIAS PATH` | Trust exported public identity |
| `seckit peer remove / list / show` | Manage registry |
| `seckit sync export -o FILE --peer ALIAS …` | Build bundle |
| `seckit sync import FILE --signer ALIAS …` | Verify, decrypt, merge |
| `seckit sync verify FILE` | Signature + structure |
| `seckit sync inspect FILE` | Manifest + recipient fingerprints |
| `seckit sync import … --reconcile-trace` | Optional **stderr JSONL** trace: per-row `decision`, stable **`reason`**, lineage fields (no secret values) |
| `seckit reconcile inspect --entry-id …` | Read-only SQLite index row + backend capabilities |
| `seckit reconcile lineage --entry-id …` | Lineage fields for one `entry_id` |
| `seckit reconcile explain --bundle-row PATH` (or stdin) | Classify one inner entry JSON against the local store (no writes) |
| `seckit reconcile verify` | Read-only `PRAGMA` checks + lineage-shaped invariants (report-only) |

Backend flags (`--backend`, `--db`, `--keychain`) on **`sync import`** match other secret commands.

## What this stack does not do (transport)

Peer sync in Phase 1B is **file-in / file-out** only. The implementation does **not** use:

- sockets or HTTP clients  
- background daemons or auto-sync  
- discovery or push notifications
- hosted relay operations

You copy the bundle and public JSON yourself (**scp**, **rsync**, USB, AirDrop, a Syncthing folder, etc.). Those tools are just transports for files; **seckit** does not connect to them.

Treat a `.peer_bundle` JSON like an **encrypted backup**: ciphertext + wrapped keys—not safe to publish, even though plaintext secrets are not stored in the file in the clear.

## Two physical Macs / Linux hosts (SSH, no hard-coded peers)

The repo does **not** define a production hostname or IP. In **your** shell, set a destination once (examples: `user@10.x.x.x`, `user@lan-name`, or an **SSH config** `Host` alias such as `my-vault-mac`):

```bash
export SECKIT_PEER_SYNC_SSH='user@other-host'   # operator-only; do not commit
```

Use **`${SECKIT_PEER_SYNC_SSH}`** with **`scp`** and **`rsync`** the same way you would a literal `user@host`:

```bash
scp ./peer-bundle.json "${SECKIT_PEER_SYNC_SSH}:~/"
rsync -av ./alice.pub.json "${SECKIT_PEER_SYNC_SSH}:~/sync-inbox/"
```

**No TTY required** for a quick connectivity check (good for automation or agents):

```bash
ssh -o BatchMode=yes -o ConnectTimeout=10 "${SECKIT_PEER_SYNC_SSH}" date
```

On the **remote** side, **`seckit`** must resolve on **`PATH`** for the command SSH runs. Many operators configure non-interactive sessions (profile/`ssh`/`sshd` behavior) so **`PATH`** matches an interactive shell; then remote one-shots work without `-t` and without a “login shell” wrapper, for example:

```bash
ssh -o BatchMode=yes "${SECKIT_PEER_SYNC_SSH}" 'seckit --help'
ssh -o BatchMode=yes "${SECKIT_PEER_SYNC_SSH}" 'seckit sync verify ~/Downloads/peer-bundle.json'
```

If a host still gives a minimal **`PATH`** for non-interactive commands, use **`bash -lc '…'`** or call the **absolute path** to the **`seckit`** entry point from your **pip** / **conda** environment.

**Replicating the project** without pushing to GitHub: copying a checkout (e.g. **`tar`**) to the peer and **`pip install`** there is enough for validation; you do not need a public remote for manual bundle sync testing. For a one-shot checklist on the peer (no agent SSH required), run [`scripts/peer_sync_remote_smoke.sh`](../scripts/peer_sync_remote_smoke.sh) from that checkout.

Public identity exchange uses the same pattern—copy only **`*.pub.json`** (or whatever you named the export). Never **`scp`** `~/.config/seckit/identity/secret.json`.

### Launchd checks on the other host

Launchd coverage is documented in [LAUNCHD_VALIDATION.md](LAUNCHD_VALIDATION.md). On **macOS** with a normal **console login**, **`make test`** already runs the temp-keychain and SQLite launchd unittests when **`launchctl print gui/$UID`** succeeds (use **`SECKIT_RUN_LAUNCHD_TESTS=0`** to skip, or **`=1`** to force from SSH). Run heavier checks **on that machine** (not only an SSH session without a GUI domain): **`SECKIT_RUN_LAUNCHD_LOGIN_KEYCHAIN_TESTS=1`**, **`SECKIT_RUN_LAUNCHD_SERVICE_KEYCHAIN_TESTS=1`**, **`SECKIT_RUN_LAUNCHD_SQLITE_TESTS=1`** / **`=0`**, etc. A user who is already logged in at the console often has an easier time with login-keychain–backed flows than a headless SSH session alone.

## Two-machine walkthrough (SQLite example)

Use the **same** pattern with **`--backend secure`** and your Keychain path if you prefer; below uses portable SQLite.

### Machine 1 (Alice, exporter)

```bash
export SECKIT_SQLITE_PASSPHRASE='your-strong-passphrase'
seckit identity init
seckit identity export -o ~/alice.pub.json
# After you have Bob's public file from him:
seckit peer add bob ~/Downloads/bob.pub.json
seckit set --backend sqlite --db ~/.config/seckit/alice-secrets.db \
  --service myapp --account prod --name API_KEY --value "$SECRET" --kind api_key
seckit sync export --backend sqlite --db ~/.config/seckit/alice-secrets.db \
  --service myapp --account prod --peer bob --all -o ~/peer-bundle.json
seckit sync verify ~/peer-bundle.json
```

Copy **`alice.pub.json`** to Bob (email/USB) and **`bob.pub.json`** from Bob the same way.

### Machine 2 (Bob, importer)

```bash
export SECKIT_SQLITE_PASSPHRASE='bobs-vault-passphrase'
seckit identity init
seckit identity export -o ~/bob.pub.json
seckit peer add alice ~/Downloads/alice.pub.json
# Copy peer-bundle from exporter, e.g.:
# scp "${SECKIT_PEER_SYNC_SSH}:peer-bundle.json" ~/Downloads/peer-bundle.json
seckit sync verify ~/Downloads/peer-bundle.json
seckit sync import ~/Downloads/peer-bundle.json --signer alice \
  --backend sqlite --db ~/.config/seckit/bob-secrets.db --dry-run
seckit sync import ~/Downloads/peer-bundle.json --signer alice \
  --backend sqlite --db ~/.config/seckit/bob-secrets.db --yes
seckit get --backend sqlite --db ~/.config/seckit/bob-secrets.db \
  --service myapp --account prod --name API_KEY --raw
```

**Dry-run** prints JSON merge stats (`created`, `updated`, `skipped`, `unchanged`, `conflicts`) and performs **no** writes. Use **`--yes`** after you accept the dry-run summary.

### macOS Keychain (secure backend)

On each machine, use **`--backend secure`** (default on macOS), drop **`--db`**, and set **`--service` / `--account`** as you normally would. The **bundle file** is still moved manually; only the **secret store** backend changes.

## Automated tests and registry `home`

The unit tests under `tests/test_peer_sync_*.py` use distinct temp directories as logical “homes” for SQLite vaults and **`apply_peer_sync_import(..., home=...)`** so metadata merge targets the right **`registry.json`** without changing the process **`HOME`**. For full **`seckit`** integration (Keychain, launchd), run the suite on macOS with **`security`** available; optional launchd coverage uses **`SECKIT_RUN_LAUNCHD_TESTS=1`** and **`SECKIT_RUN_LAUNCHD_SQLITE_TESTS=1`** as documented in [LAUNCHD_VALIDATION.md](LAUNCHD_VALIDATION.md). A GUI login session helps when tests need an unlocked login keychain.

## See also

- [SECURITY_MODEL.md](SECURITY_MODEL.md) — overall posture  
- [CROSS_HOST_VALIDATION.md](CROSS_HOST_VALIDATION.md) — encrypted export/import
