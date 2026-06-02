# Secrets Kit - "stop painting API keys on argv" release

![Secrets Kit](./docs/images/Secrets-Kit-Banner.png)

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue)](#requirements) [![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux-informational)](#requirements) [![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Repository:** `Secrets-Kit` · **CLI:** `seckit` · **Development target:** `v2.0.0a3` (unreleased)

Secrets Kit is a **macOS** CLI that stores secret values in the **login Keychain**, keeps **metadata on the keychain item** (comment JSON), and uses **`~/.config/seckit/registry.json`** only as an index/recovery aid—not the source of truth. It can **inject** selected secrets into child processes via `seckit run` and **export** shell/dotenv or encrypted backups.

## Safety warning

Secrets Kit handles secrets, passwords, API tokens, and other sensitive material. Read this before installing it or storing anything valuable.

- This is a local operator tool, not a hosted vault, HSM, compliance system, legal guarantee, or substitute for your own security review.
- If your host account, shell session, Python environment, clipboard, terminal, backups, or exported files are compromised, Secrets Kit cannot protect the data exposed through them.
- Test install, backup, export/import, and recovery flows with disposable data before using real credentials.
- Keep encrypted exports, SQLite developer databases, shell history, logs, and copied files out of public repositories and shared folders.
- Do not use this for regulated, production, customer, or third-party secrets unless you understand the trust boundaries and accept responsibility for operating it safely.

If that trust model is unclear, stop and use a managed secret store you already trust.

## Scope and limits (read first)

| In scope | Out of scope |
|----------|----------------|
| macOS or Linux, Python 3.11+, `security` + login Keychain on macOS | Hosted vault, HSM, zero-knowledge guarantees |
| **Primary cross-host:** `seckit export` / **`import`** (e.g. **encrypted JSON**) + you move the file | Phone home; your Keychain password is never read by the tool |
| `seckit run`, import/export, encrypted cross-host backup | Live multi-master “sync” guarantees; protection on an already-compromised machine/session |

If any row above is unclear, do not use this tool for real secrets yet.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/unixwzrd/Secrets-Kit/dev/install.sh | bash
# or
wget -qO- https://raw.githubusercontent.com/unixwzrd/Secrets-Kit/dev/install.sh | bash
```

Full install/upgrade docs: [INSTALL.md](docs/INSTALL.md). Development checkout: `make install-dev`. Lint: `make lint`. For day-to-day use, the supported backend is **Keychain** (`--backend keychain`). SQLite standalone CLI use is available for development with `--backend sqlite --sqlite-dev-mode` while encryption-at-rest is still pending. **Reliable host-to-host transfer:** use the integration scripts or explicit export/import flows.

```bash
seckit --version
```

## First commands

```bash
seckit info
seckit unlock
echo 'example' | seckit set --name DEMO_KEY --stdin --kind generic --service my-stack --account local-dev
seckit list --service my-stack --account local-dev
seckit run --service my-stack --account local-dev -- python3 -c 'import os; print("DEMO" in os.environ)'
```

**Longer walkthrough:** [Quickstart](docs/QUICKSTART.md)

## Defaults and config file

Avoid repeating `--service` / `--account` via `~/.config/seckit/defaults.json` or `SECKIT_DEFAULT_*`. Edit from the CLI: `seckit config set …`, `seckit config show` ([Defaults](docs/DEFAULTS.md)). **`registry.json` is metadata only**, not CLI defaults.

## Documentation

| Audience | Start here |
|----------|------------|
| Everyone | [Documentation index](docs/README.md) |
| Day-to-day use | [Install](docs/INSTALL.md) · [Quickstart](docs/QUICKSTART.md) · [Usage](docs/USAGE.md) · [Defaults](docs/DEFAULTS.md) |
| Security posture | [Security model](docs/SECURITY_MODEL.md) |
| Agents / apps | [Integrations](docs/INTEGRATIONS.md) · [Examples](docs/EXAMPLES.md) |
| Cross-host transfer | Encrypted export/import and [peer bundles](docs/PEER_SYNC.md) |
| Wheels / release | [GitHub release build](docs/GITHUB_RELEASE_BUILD.md) |
| Deep dives | [Metadata registry](docs/METADATA_REGISTRY.md) · [Peer sync](docs/PEER_SYNC.md) |

## Contributing

Issues and PRs welcome (CLI UX, backends, docs, import/export edge cases). Local checks:

```bash
pip install -e ".[dev]"
pre-commit install
make lint
make test-fast
make test-sqlite-unit
make help
make validate-fast
bash ./scripts/run_local_validation.sh
```

Use `make validate-full` or `make make-all` for the full local validation layer, including integration and launchd test targets.

**Updated:** 2026-05-05

---

## Support / license

- [Patreon](https://patreon.com/unixwzrd) · [Ko-Fi](https://ko-fi.com/unixwzrd) · [Buy Me a Coffee](https://buymeacoffee.com/unixwzrd)

Copyright 2026 [unixwzrd@unixwzrd.ai](mailto:unixwzrd@unixwzrd.ai) — [MIT License](LICENSE)
