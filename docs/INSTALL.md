# Install Secrets-Kit

**Updated**: 2026-05-27

## Prerequisites

- macOS or Linux
- Python 3.9+

Installer does not install Python. If no suitable Python is found, install stops with a clear error.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/unixwzrd/Secrets-Kit/v2.0.0a2/install.sh | bash
```

Default install provisions an isolated runtime, installs Secrets-Kit, runs `seckit init`, and runs a post-install doctor check.
Output is concise progress/status only.

## Upgrade

```bash
curl -fsSL https://raw.githubusercontent.com/unixwzrd/Secrets-Kit/v2.0.0a2/install.sh | bash -s -- --upgrade
```

Upgrade refreshes runtime/package in the existing install environment and skips `seckit init`.

## Verify

```bash
seckit --version
seckit doctor --install-check
```

## Execution Modes

- Default: concise progress output, quiet dependency chatter.
- `--verbose`: environment resolution details, selected interpreter, subprocess detail.
- Debug: `bash -x install.sh` (or `SECKIT_DEBUG=1`) for shell-level tracing.

## Troubleshooting

- `no Python 3.9+ interpreter found`: install Python 3.9+, activate conda/venv, or set `SECKIT_PYTHON=/path/to/python3`
- `runtime bootstrap unavailable` with `--safe` or `--no-uv-download`: remove those flags for a normal install, or preinstall runtime tooling on locked-down hosts
- `seckit: command not found`: add `~/.local/bin` to PATH (installer prints the line)
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
- `--verbose` show installer decision and subprocess detail
- `--repair` rebuild runtime/launcher while preserving operator config/state
- `--safe` CI/SSH: no shell profile edits, no automatic runtime bootstrap download
- `--no-uv-download` do not download runtime tooling; fail if unavailable
- `--no-shell-profile` never modify shell startup files
- `--shell-profile-force` allow startup file updates in non-interactive mode

Optional environment overrides:

- `SECKIT_PYTHON=/path/to/python3` force a specific Python 3.9+ interpreter
- `SECKIT_MANAGED_VENV=/path/to/venv` change managed venv location
- `SECKIT_INSTALL_STATE=/path/to/install.json` change install state file location

For exhaustive command/reference details: [CLI_REFERENCE.md](CLI_REFERENCE.md). For runtime defaults: [DEFAULTS.md](DEFAULTS.md).
