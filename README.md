# Secrets Kit

*Last updated: 2026-03-02*

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue)](#requirements) [![Platform](https://img.shields.io/badge/Platform-macOS-informational)](#requirements) [![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

- [Secrets Kit](#seckit)
  - [Why Secrets Kit](#why-seckit)
  - [Features](#features)
  - [Requirements](#requirements)
  - [Recommended Environment Setup](#recommended-environment-setup)
  - [Installation](#installation)
    - [From local source](#from-local-source)
    - [Direct from GitHub](#direct-from-github)
    - [Direct from GitHub (editable/dev)](#direct-from-github-editabledev)
    - [Optional YAML import support](#optional-yaml-import-support)
  - [Quick Start](#quick-start)
  - [Command Surface](#command-surface)
  - [Security Notes](#security-notes)
  - [Docs](#docs)
  - [Contributing](#contributing)
  - [Support This and Other Projects](#support-this-and-other-projects)
  - [License](#license)

Simple, secure CLI for secrets and PII. Store values in Keychain, keep metadata in a local registry, and export runtime env values without putting secrets in git.

## Why Secrets Kit

If you manage local AI stacks, scripts, and service credentials, secrets spread quickly across `.env` files, shell history, and random docs.
Secrets Kit gives you one clean operator workflow:

- store secrets in Keychain
- classify entries (`type` + `kind`)
- import from env/files
- export only what runtime needs
- migrate dotenv files to `${VAR}` placeholders

## Features

- `set/get/list/delete` lifecycle commands
- strict redaction by default (`get --raw` is explicit)
- semantic `kind` classification:
  - `token`, `password`, `user_id`, `api_key`, `email`, `phone`, `address`, `credit_card`, `wallet`, `pii_other`, `generic`
- `import env` from dotenv and/or live process env
- `import file` from JSON (YAML with optional dependency)
- `export --format shell` for runtime `eval`
- `doctor` backend and storage checks
- `migrate dotenv` flow with archive + placeholder rewrite

## Requirements

- Python 3.9+
- macOS (v1 backend)
- `security` CLI (Keychain access)

## Recommended Environment Setup

```bash
cd ~/projects/seckit
python -m venv .venv
source .venv/bin/activate
python -m pip install -U pip setuptools wheel
```

## Installation

### From local source

```bash
cd ~/projects/seckit
pip install -e .
```

### Direct from GitHub

```bash
pip install "git+https://github.com/unixwzrd/seckit.git"
```

### Direct from GitHub (editable/dev)

```bash
pip install -e "git+https://github.com/unixwzrd/seckit.git#egg=seckit"
```

### Optional YAML import support

```bash
pip install -e '.[yaml]'
```

Deactivate when done:

```bash
deactivate
```

## Quick Start

Store two entries:

```bash
echo 'sk-live' | seckit set --name OPENAI_API_KEY --stdin --type secret --kind api_key --service openclaw --account miafour
echo 'hunter2' | seckit set --name ADMIN_PASSWORD --stdin --type secret --kind password --service openclaw --account miafour
```

List (redacted):

```bash
seckit list --service openclaw --account miafour
```

Export into current shell for runtime:

```bash
eval "$(seckit export --format shell --service openclaw --account miafour --all)"
```

## Command Surface

```bash
seckit set
seckit get
seckit list
seckit delete
seckit import env
seckit import file
seckit export
seckit doctor
seckit migrate dotenv
```

Short alias (same command set):

```bash
seckit set
seckit list
seckit export --format shell --all
```

## Security Notes

- Secret values are stored in Keychain only.
- Registry metadata lives at `~/.config/seckit/registry.json`.
- Registry contains no secret values.
- Default output is redacted.
- File permissions are enforced (`0700` dir, `0600` file).

## Docs

- [Quickstart](docs/QUICKSTART.md)
- [Security Model](docs/SECURITY_MODEL.md)
- [OpenClaw Integration](docs/INTEGRATION_OPENCLAW.md)
- [Metadata Registry](docs/METADATA_REGISTRY.md)
- [TODO](docs/TODO.md)

## Contributing

Issues and PRs are welcome.
Useful contributions:

- backend hardening
- cross-platform backend support
- CLI UX improvements
- import/export edge-case handling
- docs and operator workflows

Run tests locally:

```bash
cd ~/projects/seckit
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
