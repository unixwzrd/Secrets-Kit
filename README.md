# Secrets Kit

![Secrets Kit](./docs/images/Secrets-Kit-Banner.png)

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue)](#requirements) [![Platform](https://img.shields.io/badge/Platform-macOS-informational)](#requirements) [![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

- [Secrets Kit](#secrets-kit)
  - [**IMPORTANT: Read This First**](#important-read-this-first)
  - [Why It Exists](#why-it-exists)
  - [What It Does](#what-it-does)
  - [Requirements](#requirements)
  - [Installation](#installation)
  - [Quick Start](#quick-start)
  - [Defaults](#defaults)
  - [Command Surface](#command-surface)
  - [Security Notes](#security-notes)
  - [Documentation](#documentation)
  - [Contributing](#contributing)
  - [Support This and Other Projects](#support-this-and-other-projects)
  - [License](#license)

Secrets Kit is a local macOS command-line tool for handling API keys, access tokens, passwords, and other sensitive values without leaving them scattered across `.env` files, shell startup files, random notes, or project directories.

It stores secret values in the macOS login Keychain, keeps non-secret metadata in a local registry, and can export environment variables into the current shell when a runtime actually needs them. The goal is not to promise perfect security. The goal is to give operators and developers a cleaner, safer workflow than plain-text secrets spread around the filesystem.

Repository name: `Secrets-Kit`  
CLI command: `seckit`  
Current release target: `v0.9.0`

## **IMPORTANT: Read This First**

Secrets Kit is intentionally narrow in scope:

- macOS only in `v0.9.0`
- stores secret values in the user's login Keychain
- keeps metadata in `~/.config/seckit/registry.json`
- supports command defaults in `~/.config/seckit/config.json`
- exports values into the current shell for local runtime use

That makes it useful, but it also means it has limits.

Secrets Kit is **not**:

- a hosted secret manager
- a zero-knowledge vault
- an HSM
- a guarantee against compromise on an already compromised machine or user session

It also does **not**:

- collect secrets for its own service
- transmit secrets to a backend
- store your Keychain password

Under the hood, it is a thin wrapper around the macOS `security` command plus local metadata and workflow helpers.

If you do not understand or accept that trust model, do not use it yet.

## Why It Exists

For many local development and AI workflows, secrets end up everywhere. They show up in `.env` files, `~/.bashrc`, `~/.bash_profile`, copied shell commands, README snippets, archived config folders, and test scripts that were only meant to be temporary. That is how access tokens end up committed to GitHub, left behind in backups, or exposed to whatever script happens to read the wrong directory.

It also reduces the chance of accidentally exposing secrets to GitHub, GitLab, or any other code hosting system by leaving them in plain-text project files.

Secrets Kit gives you a more disciplined local pattern:

- keep secret values in Keychain
- keep descriptive metadata in a local registry
- export values only when the current shell or runtime needs them
- migrate `.env` files into placeholders instead of leaving raw values behind

It is not magic. It just gives you a much better default workflow than loose plain-text files.

## What It Does

Secrets Kit focuses on a few practical jobs:

- store, retrieve, list, explain, and delete secrets
- classify entries with `type` and `kind`
- import from existing environment files
- export environment variables for local runtimes
- help migrate `.env` files away from embedded secret values
- check for drift between local metadata and Keychain entries

## Requirements

- Python 3.9+
- macOS
- access to the `security` CLI and the login Keychain

## Installation

For a local checkout, the shortest path is:

```bash
cd ~/projects/Secrets-Kit
python -m venv .venv
source .venv/bin/activate
python -m pip install .
```

In most cases, `python -m pip install .` is enough. The extra `pip/setuptools/wheel` upgrade step is optional and only useful if you are working in an older or inconsistent Python environment and want to normalize the packaging toolchain first.

Install directly from GitHub:

```bash
python -m pip install "git+https://github.com/unixwzrd/Secrets-Kit.git"
```

Editable install for active development:

```bash
python -m pip install -e "git+https://github.com/unixwzrd/Secrets-Kit.git#egg=seckit"
```

Optional YAML file-import support for `seckit import file`:

```bash
python -m pip install '.[yaml]'
```

If you are not importing secrets from YAML files, you do not need that extra.

## Quick Start

Start by checking whether the login Keychain is available from your current shell:

```bash
seckit keychain-status
seckit unlock
```

The unlock flow is intentionally explicit. A sanitized example looks like this:

```bash
$ seckit unlock

********************************************************************************

About to run:

  security unlock-keychain /Users/example/Library/Keychains/login.keychain-db

This will prompt macOS for the keychain password if needed.
Secrets Kit does not read, capture, or store that password.
********************************************************************************

Proceed with unlocking /Users/example/Library/Keychains/login.keychain-db? [y/N]: y
password to unlock /Users/example/Library/Keychains/login.keychain-db:
unlocked: /Users/example/Library/Keychains/login.keychain-db
```

Store a couple of values into a neutral local scope:

```bash
echo 'sk-example' | seckit set --name OPENAI_API_KEY --stdin --kind api_key --service my-stack --account local-dev
echo 'hunter2' | seckit set --name ADMIN_PASSWORD --stdin --kind password --service my-stack --account local-dev
```

List the entries without exposing the values:

```bash
seckit list --service my-stack --account local-dev
```

Real output looks more like an inventory report than a value dump:

```text
NAME                     TYPE    KIND      SERVICE   ACCOUNT    TAGS  UPDATED_AT
OPENAI_API_KEY           secret  api_key   my-stack  local-dev  -     2026-04-12T01:04:34Z
ADMIN_PASSWORD           secret  password  my-stack  local-dev  -     2026-04-12T01:04:34Z
GATEWAY_TOKEN            secret  token     my-stack  local-dev  -     2026-04-12T01:04:34Z
```

Export them into the current shell only when your runtime needs them:

```bash
eval "$(seckit export --format shell --service my-stack --account local-dev --all)"
```

When the session is finished, you can relock the Keychain explicitly:

```bash
seckit lock
```

If `seckit keychain-status` warns that the login Keychain never times out, you can apply a safer policy:

```bash
seckit unlock --harden
```

## Defaults

If you work with the same service and account often, defaults make the tool much easier to live with. Instead of repeating `--service` and `--account` on every command, you can set them once in environment variables or `~/.config/seckit/config.json`.

Example:

```bash
export SECKIT_DEFAULT_SERVICE=my-stack
export SECKIT_DEFAULT_ACCOUNT=local-dev
```

Then shorter commands become practical:

```bash
seckit list
seckit export --format shell --all
```

That is especially useful when you are launching the same local stack repeatedly from one shell session.

## Command Surface

```bash
seckit set
seckit get
seckit list
seckit explain
seckit delete
seckit import env
seckit import file
seckit export
seckit doctor
seckit unlock
seckit lock
seckit keychain-status
seckit migrate dotenv
```

## Security Notes

Secrets Kit improves local secret hygiene, but it does not make sensitive material risk-free.

- secret values live in the login Keychain, not in the registry
- the registry contains metadata only
- normal output stays redacted unless you explicitly ask for raw values
- exported variables still exist in the current process environment once you export them
- a compromised local session can still expose what that session can already access

If you need a remote secret service, cross-host policy enforcement, or stronger isolation guarantees, use a tool designed for that problem.

## Documentation

- [Quickstart](docs/QUICKSTART.md)
- [Usage & Workflows](docs/USAGE.md)
- [Integrations](docs/INTEGRATIONS.md)
- [Examples](docs/EXAMPLES.md)
- [Security Model](docs/SECURITY_MODEL.md)
- [Defaults](docs/DEFAULTS.md)
- [Metadata Registry](docs/METADATA_REGISTRY.md)
- [OpenClaw Integration (Legacy Example)](docs/INTEGRATION_OPENCLAW.md)

## Contributing

Issues and PRs are welcome.
Useful contributions:

- backend hardening
- cross-platform backend support
- CLI UX improvements
- import/export edge-case handling
- docs and operator workflows

Local checks:

```bash
cd ~/projects/Secrets-Kit
python -m unittest discover -s tests -v
```

Pre-commit (optional):

```bash
python -m pip install pre-commit
pre-commit install
pre-commit run --all-files
```

Run tests locally:

```bash
cd ~/projects/Secrets-Kit
PYTHONPATH=src python -m unittest discover -s tests -v
```

## Support This and Other Projects

- [Patreon](https://patreon.com/unixwzrd)
- [Ko-Fi](https://ko-fi.com/unixwzrd)
- [Buy Me a Coffee](https://buymeacoffee.com/unixwzrd)

## License

Copyright 2026  
[unixwzrd@unixwzrd.ai](mailto:unixwzrd@unixwzrd.ai)

[MIT License](LICENSE)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

*Last updated: 2026-04-12*
