# Install Secrets-Kit

**Created**: 2026-05-26  
**Updated**: 2026-05-26

Canonical operator install for macOS and Linux. Phase 1 is **curl | bash** plus pip-from-GitHub — no Homebrew, Docker, daemons, or repo mirroring.

## First install

```bash
curl -fsSL https://raw.githubusercontent.com/unixwzrd/Secrets-Kit/v1.2.3/install.sh | bash
```

Each release `install.sh` bakes in its tag (`v1.2.3` today). Override when needed:

```bash
curl -fsSL https://raw.githubusercontent.com/unixwzrd/Secrets-Kit/v1.2.3/install.sh | bash -s -- --ref v1.2.3 --yes
```

## Upgrade

Preserves your Python environment, `~/.config/seckit` config, registry, and backend data. Only upgrades the package and dependencies, then reruns a fast install check.

```bash
curl -fsSL https://raw.githubusercontent.com/unixwzrd/Secrets-Kit/v1.2.3/install.sh | bash -s -- --upgrade
```

Or, after install:

```bash
seckit install --upgrade
```

## Python environment

The installer never uses arbitrary system `pip`. It always runs `"$PYTHON" -m pip` on a selected interpreter.

**Resolution order (first install):**

1. Active **conda** environment (`CONDA_PREFIX`)
2. Active **venv** (`VIRTUAL_ENV`)
3. **Managed venv** at `$HOME/.local/share/seckit/venv` (created if needed)

**Upgrade:** reads `~/.config/seckit/install.json` and reuses the recorded interpreter when it still exists and is executable. If missing, the installer warns and falls back to the resolution order above.

**Requirements:** Python 3.9+, `python -m pip` on that interpreter.

## Install state

`~/.config/seckit/install.json` records:

- `interpreter` — Python used for install/upgrade
- `venv_path` — venv path or `null`
- `install_method` — `conda`, `venv`, or `managed`
- `version` — installed seckit version
- `ref` — git ref used for pip

## Verify

```bash
seckit doctor --install-check
```

Fast check only (no keychain roundtrip, no registry drift scan). Target: under one second on a warm machine.

## Remote install

```bash
ssh -o BatchMode=yes -o ConnectTimeout=10 user@host \
  'curl -fsSL https://raw.githubusercontent.com/unixwzrd/Secrets-Kit/v1.2.3/install.sh | bash -s -- --yes'
```

Convenience wrapper:

```bash
seckit install user@host --yes
```

## Local development (checkout only)

From a git clone — not for operator `curl | bash`:

```bash
make install-dev
# or
./install.sh --dev
```

Uses editable `pip install -e ".[dev]"` and `main` (or `--ref`) — not the baked release tag.

## Makefile targets (clone only)

| Target | Action |
|--------|--------|
| `make install` | Run `./install.sh` |
| `make install-dev` | Run `./install.sh --dev` |
| `make install-upgrade` | Run `./install.sh --upgrade` |
| `make install-check` | `seckit doctor --install-check` |

## Non-goals (phase 1)

- rsync / repo mirroring / deployment orchestration
- systemd / launchd service install
- Homebrew, Docker, PyInstaller
- Custom install root directories

See also: [QUICKSTART.md](QUICKSTART.md), [CLI_REFERENCE.md](CLI_REFERENCE.md).
