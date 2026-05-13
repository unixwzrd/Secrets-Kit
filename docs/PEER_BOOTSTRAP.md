# Disposable peer bootstrap (operator)

**Created**: 2026-05-13  
**Updated**: 2026-05-13

Thin layered scripts under `scripts/` build a **relocatable peer-root**: `.venv`, `repo/` (editable install or git clone), generated `env.sh`, and local layout for disposable testing. This is **not** hosted relay infrastructure; see repository separation notes in maintainer docs.

## Scripts

| Script | Role |
|--------|------|
| [`install.sh`](../scripts/install.sh) | Resolves `bootstrap_peer.sh` by absolute path and `exec`s it (any cwd). |
| [`bootstrap_peer.sh`](../scripts/bootstrap_peer.sh) | Creates peer layout, venv, `pip install -e`, `env.sh`, optional `identity init`. |
| [`reset_peer.sh`](../scripts/reset_peer.sh) | Tear down / reset pieces of a peer-root (see `--help`). |
| [`bootstrap_vm_smoke.sh`](../scripts/bootstrap_vm_smoke.sh) | Post-bootstrap smoke checks. |

Requires **bash**. Clone or copy the repository before running; installers do not download sources.

## `env.sh` contract

After bootstrap, **`env.sh`** exports at least:

- **`SECKIT_ENV_FILE`** — absolute path to this `env.sh`
- **`SECKIT_REPO_ROOT`** — absolute path to `peer-root/repo`
- **`SECKIT_PEER_ROOT`**, **`HOME`** (peer isolation), SQLite and artifact paths, **`PATH`** with `peer-root/.venv/bin` first

**Do not** rely on changing into the repo directory for day-to-day commands.

## Verify (from any cwd)

```bash
source /absolute/path/to/peer-root/env.sh
command -v seckit
seckit --help
"$SECKIT_REPO_ROOT/scripts/bootstrap_vm_smoke.sh" --env-file "$SECKIT_ENV_FILE"
```

Peer trust and bundle semantics: [PEER_SYNC.md](PEER_SYNC.md).
