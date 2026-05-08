# Secrets Kit - "stop painting API keys on argv" release

![Secrets Kit](./docs/images/Secrets-Kit-Banner.png)

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue)](#requirements) [![Platform](https://img.shields.io/badge/Platform-macOS%20%28Keychain%29%20%7C%20cross--platform%20%28SQLite%29-informational)](#requirements) [![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Repository:** `Secrets-Kit` · **CLI:** `seckit` · **Current release target:** `v1.2.5`

Secrets Kit is a Python CLI that stores secret values in one of two backends:

- **`--backend secure`** (default on macOS): **login Keychain** via the `security` CLI; metadata lives in the keychain item comment JSON; **`~/.config/seckit/registry.json`** is an index/recovery aid.
- **`--backend sqlite`**: **encrypted SQLite file** (PyNaCl SecretBox + Argon2id); portable across OSes that run Python 3.9+; same registry-driven **`list`** / metadata flow as Keychain.

It can **inject** selected secrets into child processes via `seckit run` and **export** shell/dotenv or encrypted backups.

## Scope and limits (read first)

| In scope | Out of scope |
|----------|----------------|
| Python 3.9+; **Keychain** on macOS (`security`) | Hosted vault, HSM, zero-knowledge guarantees |
| **`--backend sqlite`**: local encrypted DB file (no sync, no daemon) | Live multi-master sync; **SQLite store** is **not** replicated by this tool |
| **Primary cross-host:** `seckit export` / **`import`** (e.g. **encrypted JSON**) + you move the file | Phone home; your Keychain password is never read by the tool |
| `seckit run`, import/export, encrypted cross-host backup | Live multi-master Keychain sync; protection on an already-compromised machine/session |

If that trust model is unclear, use something else until it is.

## Install

```bash
pip install "git+https://github.com/unixwzrd/Secrets-Kit.git@v1.2.0#egg=seckit"
```

Development checkout: `pip install -e .` in a venv. **Dependencies** include **cryptography**, **PyYAML**, and **PyNaCl** (libsodium bindings) for the SQLite backend and encrypted export.

**Keychain (macOS):** `--backend secure` (alias `local`) uses the macOS `security` CLI. **Reliable host-to-host transfer:** [Cross-Host Validation](docs/CROSS_HOST_VALIDATION.md) (encrypted export).

**SQLite (portable):** default unlock is **passphrase + Argon2id** (`SECKIT_SQLITE_PASSPHRASE`, or interactive). On macOS you can set **`SECKIT_SQLITE_UNLOCK=keychain`** so new vaults store a **DEK wrapped with a KEK** in the Keychain (`security` CLI); use **`SECKIT_SQLITE_KEK_KEYCHAIN`** or **`--keychain`** (with `--backend sqlite`) to choose the keychain file. Existing passphrase-only vaults stay readable with **`SECKIT_SQLITE_UNLOCK=passphrase`**. Also: **`SECKIT_SQLITE_DB`** / **`--db`** / `sqlite_db` in defaults; default DB `~/.config/seckit/secrets.db`. **No** sync/daemon—back up the file yourself.

```bash
seckit version
```

## Portable SQLite quick example

```bash
export SECKIT_SQLITE_PASSPHRASE='use-a-strong-passphrase'
seckit set --backend sqlite --service myapp --account dev --name API_KEY --value s3cr3t --kind api_key
seckit get --backend sqlite --service myapp --account dev --name API_KEY
```

See [Defaults](docs/DEFAULTS.md) for `sqlite_db`, `SECKIT_SQLITE_DB`, and `SECKIT_ORIGIN_HOST`.

## First commands

```bash
seckit keychain-status
seckit unlock
echo 'example' | seckit set --name DEMO_KEY --stdin --kind generic --service my-stack --account local-dev
seckit list --service my-stack --account local-dev
seckit run --service my-stack --account local-dev -- python3 -c 'import os; print("DEMO" in os.environ)'
```

**Longer walkthrough:** [Quickstart](docs/QUICKSTART.md)

## Defaults and config file

Avoid repeating `--service` / `--account` via `~/.config/seckit/defaults.json` or `SECKIT_DEFAULT_*`. Edit from the CLI: `seckit config set …`, `seckit config show` ([Defaults](docs/DEFAULTS.md)). **`registry.json` is metadata only**, not CLI defaults. **`seckit list`** shows **registry entries** (secrets seckit knows about), not everything visible in Keychain Access.

## Documentation

| Audience | Start here |
|----------|------------|
| Everyone | [Documentation index](docs/README.md) |
| Day-to-day use | [Quickstart](docs/QUICKSTART.md) · [CLI reference](docs/CLI_REFERENCE.md) · [Workflows](docs/WORKFLOWS.md) · [Defaults](docs/DEFAULTS.md) · [Usage entry](docs/USAGE.md) |
| CLI concepts | [Concepts](docs/CONCEPTS.md) · [CLI architecture](docs/CLI_ARCHITECTURE.md) · [CLI style guide](docs/CLI_STYLE_GUIDE.md) |
| Security posture | [Security model](docs/SECURITY_MODEL.md) |
| Agents / apps | [Integrations](docs/INTEGRATIONS.md) · [Examples](docs/EXAMPLES.md) |
| Release signing / wheels | [GitHub release build](docs/GITHUB_RELEASE_BUILD.md) |
| Deep dives | [Metadata registry](docs/METADATA_REGISTRY.md) · [Cross-host validation](docs/CROSS_HOST_VALIDATION.md) · [Peer sync bundles](docs/PEER_SYNC.md) |

## Contributing

Issues and PRs welcome (CLI UX, backends, docs, import/export edge cases). Local checks:

```bash
bash ./scripts/run_local_validation.sh
```

**Updated:** 2026-05-07

---

## Support / license

- [Patreon](https://patreon.com/unixwzrd) · [Ko-Fi](https://ko-fi.com/unixwzrd) · [Buy Me a Coffee](https://buymeacoffee.com/unixwzrd)

Copyright 2026 [unixwzrd@unixwzrd.ai](mailto:unixwzrd@unixwzrd.ai) — [MIT License](LICENSE)
