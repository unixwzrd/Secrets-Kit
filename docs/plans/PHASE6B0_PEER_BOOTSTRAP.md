# Phase 6B0 — Disposable peer bootstrap

**Created**: 2026-05-12  
**Updated**: 2026-05-12

Operational bootstrap for **secrets-kit** disposable peers: thin `install.sh`, full `bootstrap_peer.sh`, `env.sh` contract, reset/smoke helpers. This is **not** production deployment or orchestration.

## Two operational layers

1. **Administrator / developer machine** — operator-controlled checkout or install; may author or serve installer scripts. Not an orchestrator.
2. **Disposable peers** — macOS or Linux hosts used for replay, VM validation, and ugly-condition testing. The **peer-root directory** is the portable artifact.

## Layout (peer-root)

```text
peer-A/
  .venv/           # Operational Python runtime (only contract after bootstrap)
  repo/            # Git clone or symlink to editable checkout (provenance, git status)
  runtime/         # Peer-local scratch (see env.sh)
  state/
    vault.db       # SQLite path via SECKIT_SQLITE_DB
    public/        # bootstrap writes host-identity.json (public export)
  .config/seckit/  # Created under HOME=peer-root: registry, identity, peers
  logs/
  bundles/
  snapshots/
  env.sh           # Source this before reset/smoke/runbooks
```

Identity **secret** material lives under `$HOME/.config/seckit/identity` when `HOME` is the peer root. A **public** export for manual trust is copied to `state/public/host-identity.json`.

## Installer layering

| Script | Role |
| --- | --- |
| [`scripts/install.sh`](../../scripts/install.sh) | Resolves `bootstrap_peer.sh` next to itself (or `SECKIT_BOOTSTRAP_SCRIPT`) and **exec**s it. Does not fetch sources. |
| [`scripts/bootstrap_peer.sh`](../../scripts/bootstrap_peer.sh) | Creates layout, selects Python, creates `.venv`, `pip install -e`, writes `env.sh`, runs `identity init`, exports public identity. |

Do not merge these into one unmaintainable script.

### curl \| sh note

There is **no** automatic download in `install.sh`. For reproducible installs: **clone** the repository at a pinned **branch**, **tag**, or **commit SHA**, then run `scripts/install.sh` or `scripts/bootstrap_peer.sh` from that tree.

## Python runtime policy

Bootstrap **does not** treat mutable system Python as operational truth and **does not** modify `/usr/bin/python*`.

**Selection order:**

1. First `python3.13` … `python3` on `PATH` with version **≥ 3.9** (matches `pyproject.toml` `requires-python`).
2. Else `CONDA_PREFIX/bin/python` if `CONDA_PREFIX` is set and version is sufficient.

The script prints the interpreter path and version, then runs `"$PY" -m venv "$PEER_ROOT/.venv"`. **uv-managed Python** may be documented later; it is not required for 6B0.

**Avoid:** Homebrew-only assumptions, pyenv requirements, hidden interpreter swaps.

## Source modes and pinned refs

**Editable:**

```bash
./scripts/bootstrap_peer.sh --peer-root /path/to/peer-A --editable /path/to/secrets-kit
```

Creates `repo/` as a **symlink** to the editable checkout and `pip install -e` that path.

**Git:**

```bash
./scripts/bootstrap_peer.sh --peer-root /path/to/peer-A \
  --git https://github.com/<org>/secrets-kit.git \
  --branch experimental-bootstrap
```

```bash
./scripts/bootstrap_peer.sh --peer-root /path/to/peer-A \
  --git https://github.com/<org>/secrets-kit.git \
  --ref v1.2.3
```

```bash
./scripts/bootstrap_peer.sh --peer-root /path/to/peer-A \
  --git https://github.com/<org>/secrets-kit.git \
  --ref <commit-sha>
```

`--branch` and `--ref` are mutually exclusive. Clone target is always `$SECKIT_PEER_ROOT/repo/`, then `pip install -e "$SECKIT_PEER_ROOT/repo"`.

## env.sh contract

Every operational helper should begin with `source env.sh` (from the peer root, or `--env-file`).

Generated variables include:

- `SECKIT_PEER_NAME`, `SECKIT_PEER_ROOT`
- `HOME` — set to `SECKIT_PEER_ROOT` so `~/.config/seckit` is **inside** the peer
- `SECKIT_STATE_DIR`, `SECKIT_SQLITE_DB`, `SECKIT_RUNTIME_DIR`, `SECKIT_LOG_DIR`, `SECKIT_BUNDLE_DIR`, `SECKIT_SNAPSHOT_DIR`
- `SECKIT_CONFIG_DIR` — convenience alias for `$HOME/.config/seckit`
- `PATH` — peer `.venv/bin` prepended
- Either `SECKIT_SQLITE_PASSPHRASE` (random hex, **disposable peers**) or `SECKIT_SQLITE_PLAINTEXT_DEBUG=1` with `--no-passphrase` (development only)

**Passphrase in `env.sh` is for disposable/testing layout.** Do not reuse for production without a deliberate threat model.

## Trust boundary

- Bootstrap may run `seckit identity init` and write **`state/public/host-identity.json`**.
- Operators **manually** distribute public material and run `seckit peer add` on other peers.
- **No** silent cross-peer trust, auto-enrollment, or coordinated identity.

## Companion scripts

| Script | Purpose |
| --- | --- |
| [`scripts/reset_peer.sh`](../../scripts/reset_peer.sh) | Source `env.sh`; optionally stop daemon; reset vault / config / runtime; preserve `bundles/` and `snapshots/` unless `--purge-artifacts`. |
| [`scripts/bootstrap_vm_smoke.sh`](../../scripts/bootstrap_vm_smoke.sh) | After `env.sh`: `doctor`, `reconcile verify`, optional `daemon ping`. |

## Host targets (validation)

Primary: **macOS Sequoia** (Intel + Apple Silicon), **Rocky Linux 9 (aarch64)**, **Debian 13 (arm64)**. Install **git**, Python **3.9+**, and **openssl** (for passphrase generation) where applicable.

## Bootstrap non-goals

- No auto-update, background update checks, or self-updating peers.
- No automatic dependency upgrades during bootstrap.
- No Ansible/agents/orchestration.

## Future CI/CD (out of 6B0 scope)

Possible later direction: versioned installer artifacts, staging `install.sh` / bootstrap assets per branch or tag, reproducible bootstrap URLs, optional tarballs, optional signed manifests. **Not** in scope here: automatic deployment, fleet orchestration, remote fleet management.

## References

- [`PHASE6B_OPERATIONAL_VALIDATION.md`](PHASE6B_OPERATIONAL_VALIDATION.md) — topology and ugly-condition runbooks (Phase 6B).
- [`../PEER_SYNC.md`](../PEER_SYNC.md) — bundle workflows.
- [`scripts/peer_sync_remote_smoke.sh`](../../scripts/peer_sync_remote_smoke.sh) — additional remote smoke hooks.
