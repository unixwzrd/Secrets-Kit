# Install Secrets-Kit

**Updated**: 2026-05-27

## Prerequisites

- macOS or Linux
- Python 3.9+

Installer does not install Python. If no suitable Python is found, install stops with a clear error.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/unixwzrd/Secrets-Kit/v2.0.0a1/install.sh | bash
```

Default install runs package install, `seckit init`, and a post-install doctor check.

## Upgrade

```bash
curl -fsSL https://raw.githubusercontent.com/unixwzrd/Secrets-Kit/v2.0.0a1/install.sh | bash -s -- --upgrade
```

Upgrade updates the package in the existing install environment and skips `seckit init`.

## Verify

```bash
seckit --version
seckit doctor --install-check
```

## Troubleshooting

- `no Python 3.9+ interpreter found`: install Python 3.9+, activate conda/venv, or set `SECKIT_PYTHON=/path/to/python3`
- `seckit: command not found`: add managed venv bin to PATH (installer prints the line)
- Upgrade used unexpected Python: check `~/.config/seckit/install.json` and rerun with intended env active

## Python Resolution

Resolution order:

1. Active conda
2. Active venv
3. Existing managed venv
4. `SECKIT_PYTHON`
5. `python3` / `python` on `PATH` (used to create managed venv)

## Advanced Flags (Appendix)

Use only when needed:

- `--upgrade` update package in-place; skip `seckit init`
- `--dev` editable install from a local checkout (`SECKIT_INSTALL_ROOT`, default `PWD`)
- `--yes` non-interactive mode when init would prompt
- `--no-init` install package only; skip `seckit init`
- `--no-verify` skip post-install `seckit doctor --install-check`
- `--ref TAG` install from a different git ref (for testing pins)
- `--repo-url URL` install from a fork or alternate git remote
- `--dry-run` print planned actions; make no changes
- `--json` emit machine-readable installer result

Optional environment overrides:

- `SECKIT_PYTHON=/path/to/python3` force a specific Python 3.9+ interpreter
- `SECKIT_MANAGED_VENV=/path/to/venv` change managed venv location
- `SECKIT_INSTALL_STATE=/path/to/install.json` change install state file location

For exhaustive command/reference details: [CLI_REFERENCE.md](CLI_REFERENCE.md). For runtime defaults: [DEFAULTS.md](DEFAULTS.md).
