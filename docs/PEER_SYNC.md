# Peer sync bundles (Phase 1B)

**Created**: 2026-05-05  
**Updated**: 2026-05-06

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

For each entry, compare `(updated_at, origin_host)` lexicographically. **Origin** is the exporting host’s id for that row (stored in metadata custom key `seckit_sync_origin_host` after import). Ties with the same value → **unchanged**; ties with different values → **conflict** (skipped, counted in stats). **Strictly newer** incoming row → **import**; **older** → **skip**.

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

Backend flags (`--backend`, `--db`, `--keychain`) on **`sync import`** match other secret commands.

## What this stack does not do (transport)

Peer sync in Phase 1B is **file-in / file-out** only. The implementation does **not** use:

- sockets or HTTP clients  
- background daemons or auto-sync  
- relays, discovery, or push notifications  

You copy the bundle and public JSON yourself (**scp**, **rsync**, USB, AirDrop, a Syncthing folder, etc.). Those tools are just transports for files; **seckit** does not connect to them.

Treat a `.peer_bundle` JSON like an **encrypted backup**: ciphertext + wrapped keys—not safe to publish, even though plaintext secrets are not stored in the file in the clear.

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
# Copy peer-bundle.json from Alice (scp example):
# scp alice@host:peer-bundle.json ~/Downloads/peer-bundle.json
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

## See also

- [SECURITY_MODEL.md](SECURITY_MODEL.md) — overall posture  
- [CROSS_HOST_VALIDATION.md](CROSS_HOST_VALIDATION.md) — encrypted export/import
