# Secrets Kit

![Secrets Kit](./docs/images/Secrets-Kit-Banner.png)

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue)](#user-installation) [![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux-informational)](#user-installation) [![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

- [Secrets Kit](#secrets-kit)
  - [Beyond AI agents](#beyond-ai-agents)
  - [Safety warning](#safety-warning)
  - [Scope and limits (read first)](#scope-and-limits-read-first)
  - [User installation](#user-installation)
  - [User installation vs developer installation](#user-installation-vs-developer-installation)
  - [Release channels](#release-channels)
  - [Install](#install)
  - [Upgrade](#upgrade)
  - [First commands](#first-commands)
  - [Defaults and config file](#defaults-and-config-file)
  - [Documentation](#documentation)
  - [Contributing](#contributing)
  - [Support / license](#support--license)

**Repository:** `Secrets-Kit` · **CLI:** `seckit` · **Candidate:** `v2.0.1b12` (unqualified prerelease; not a public stable release)

Secrets Kit is a local-first secrets CLI for macOS and Linux. It supports macOS Keychain and encrypted SQLite storage, authenticated encrypted peer synchronization, optional RSS forwarding, selected environment injection through `seckit run`, and policy-scoped read-only stdio MCP access.

## Beyond AI agents

Use Secrets Kit for database clients, scheduled jobs, deployment scripts, web applications and other programs that read credentials from environment variables. Start with local storage and encrypted P2P sharing on your LAN; optionally add RSS for peers across home, office and VPS networks. MCP is an optional interface, not a requirement.

With the selected credentials already stored:

```bash
seckit run --service postgres --account development --names PGPASSWORD -- psql -h localhost -U app -d appdb
seckit run --service redis --account development --names REDISCLI_AUTH -- redis-cli -h localhost PING
seckit run --service batch --account development --names API_TOKEN -- ./nightly-job.sh
```

The PostgreSQL command is `psql`, not `pgsql`. Secrets stay out of these command arguments, but child processes receive them in their environment; this does not protect against a compromised account, environment dumps or application logging. Programs requiring password files need their documented file interface; `seckit run` does not rewrite hard-coded configuration or create password files automatically. See [application examples](docs/EXAMPLES.md) for setup and PostgreSQL's password-file alternative.

## Safety warning

Secrets Kit handles secrets, passwords, API tokens, and other sensitive material. Read this before installing it or storing anything valuable.

- This is a local operator tool, not a hosted vault, HSM, compliance system, legal guarantee, or substitute for your own security review.
- If your host account, shell session, Python environment, clipboard, terminal, backups, or exported files are compromised, Secrets Kit cannot protect the data exposed through them.
- Test install, backup, export/import, and recovery flows with disposable data before using real credentials.
- Keep encrypted exports, SQLite databases, shell history, logs, and copied files out of public repositories and shared folders.
- Do not use this for regulated, production, customer, or third-party secrets unless you understand the trust boundaries and accept responsibility for operating it safely.

If that trust model is unclear, stop and use a managed secret store you already trust.

## Scope and limits (read first)

| In scope | Out of scope |
| --- | --- |
| macOS or Linux; installer-managed runtime; `security` + login Keychain on macOS | Hosted vault, HSM, zero-knowledge guarantees |
| Encrypted peer synchronization and explicit export/import | Automatic trust in unknown peers or hosted custody of customer secrets |
| `seckit run`, import/export, encrypted cross-host backup | Availability guarantees; protection on an already-compromised machine/session |

If any row above is unclear, do not use this tool for real secrets yet.

## User installation

End users do not need to install Python, uv, virtual environments, or Git. The installer provisions the runtime automatically.

Download **`install.sh`** from the selected release or the maintainer's supplied link and open Terminal in its folder. Do not download GitHub's **Source code** archives.

```bash
bash ./install.sh
```

CI supplies the repository and exact release identity; the user does not edit repository names, tags or package locations. The single-file installer handles application verification and managed-runtime setup automatically. No archive extraction, individual package downloads, manual checksum commands, Python installation or GitHub CLI are required. Internet access is needed for runtime dependencies. The script also supports `curl … | bash` and `wget … | bash` when given an accessible direct download URL. See [INSTALL.md](docs/INSTALL.md) for streaming and optional checksum verification.

Remote installation is performed from an installed `seckit` command:

```bash
seckit install user@host
```

For first-time SSH setup, see [QUICK_SSH_SETUP.md](docs/QUICK_SSH_SETUP.md).

## User installation vs developer installation

User installation uses the release installer and does not require a source checkout. Developer installation is only for people working on Secrets-Kit itself; it uses a Git checkout and development tools such as `make install-dev`, `make lint`, and `make test`.

## Release channels

Operators install published release artifacts only. Maintainers validate a public release candidate before promoting it to the production branch; local feature branches and development checkouts are not production release sources.

## Install

Follow [User installation](#user-installation) above for the pinned verified artifact command.

Full installation and upgrade instructions: [INSTALL.md](docs/INSTALL.md). Keychain is macOS-specific; encrypted SQLite supports peer synchronization on macOS and Linux. Development checkout: `make install-dev`. Lint: `make lint`.

```bash
seckit --version
```

## Upgrade

```bash
seckit upgrade --check
seckit upgrade
# Optional same-user daily availability checks; never automatic installation:
seckit upgrade service install
```

The installer records the release repository, channel, and RSS operator origin. Public beta updates need no GitHub authentication. Upgrades preserve customer state; intentional downgrades are not supported. `seckit install user@host --upgrade --ref v2.0.1b12` remains available for remote installation after that release is published.

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
| --- | --- |
| Everyone | [Documentation index](docs/README.md) |
| Day-to-day use | [Install](docs/INSTALL.md) · [Quickstart](docs/QUICKSTART.md) · [Usage](docs/USAGE.md) · [Defaults](docs/DEFAULTS.md) |
| Security posture | [Security model](docs/SECURITY_MODEL.md) |
| Agents / apps | [Integrations](docs/INTEGRATIONS.md) · [Examples](docs/EXAMPLES.md) |
| Cross-host transfer | Encrypted peer synchronization or explicit export/import |
| Metadata | [Taxonomy](docs/TAXONOMY.md) · [Metadata schemas](docs/METADATA_SCHEMAS.md) |

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

**Updated:** 2026-09-16

---

## Support / license

- [Patreon](https://patreon.com/unixwzrd) · [Ko-Fi](https://ko-fi.com/unixwzrd) · [Buy Me a Coffee](https://buymeacoffee.com/unixwzrd)

Copyright 2026 [unixwzrd@unixwzrd.ai](mailto:unixwzrd@unixwzrd.ai) — [MIT License](LICENSE)
