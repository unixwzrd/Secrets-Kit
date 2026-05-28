# Install Secrets-Kit

**Created**: 2026-05-26  
**Updated**: 2026-05-27

**Pre-release (`dev` line):** version `2.0.0a0` · git tag `v2.0.0a0`

---

## Default install (recommended)

No command-line switches are required for a normal first install.

```bash
curl -fsSL https://raw.githubusercontent.com/unixwzrd/Secrets-Kit/v2.0.0a0/install.sh | bash
```

That single command:

1. **Installs** the `seckit` CLI with pip (from the release tag baked into `install.sh`).
2. **Chooses Python** — active conda env → active venv → existing managed venv → new managed venv at `~/.local/share/seckit/venv`.
3. **Runs** `seckit init` to create operator defaults and an empty registry (skipped on upgrade).
4. **Verifies** with `seckit doctor --install-check`.

If the installer created a **managed venv**, add its `bin` directory to your `PATH` (the installer prints the exact line). Then:

```bash
seckit --version
seckit info
seckit doctor --install-check
```

### What gets configured automatically

| Platform | Default backend | Config files |
|----------|-----------------|--------------|
| **macOS** | Login **Keychain** (`backend: keychain`) | `~/.config/seckit/defaults.json`, `registry.json` |
| **Linux** | **SQLite** (`backend: sqlite`) | Same paths; SQLite DB under `~/.config/seckit/` |

Defaults include your OS username as `account`, `kind: api_key`, and rotation hints. Change them anytime with `seckit config` — see [DEFAULTS.md](DEFAULTS.md).

**macOS Keychain** is the supported production backend. **SQLite** on macOS is for developer workflows only (`--sqlite-dev-mode` on commands); see [QUICKSTART.md](QUICKSTART.md) and [DEFAULTS.md](DEFAULTS.md).

You do **not** pass backend or config paths to `install.sh`. Set backends and paths **after** install with `seckit config` or environment variables documented in [DEFAULTS.md](DEFAULTS.md).

---

## Upgrade

```bash
curl -fsSL https://raw.githubusercontent.com/unixwzrd/Secrets-Kit/v2.0.0a0/install.sh | bash -s -- --upgrade
```

Or from an existing install: `seckit install --upgrade`

Upgrade **only** updates the Python package. It **preserves** `~/.config/seckit/`, secrets, and registry data. It does **not** run `seckit init` again.

---

## Install from a git clone (developers)

```bash
git clone https://github.com/unixwzrd/Secrets-Kit.git
cd Secrets-Kit
./install.sh --dev
```

`--dev` installs an **editable** copy from your checkout (not the release tag). Use `make install-dev` as a shortcut. For lint/test dependencies, run `bash ./scripts/install_dev_deps.sh` once.

---

## `install.sh` options (non-standard only)

Use these only when the default flow does not fit. Typical operators never need them.

| Option | When to use |
|--------|-------------|
| *(none)* | First install, most upgrades via full installer without `--upgrade` on a fresh machine |
| `--upgrade` | Refresh the package on a machine that already has Secrets-Kit installed |
| `--dev` | Editable install from a local clone (not for `curl \| bash`) |
| `--yes` | Overwrite existing `defaults.json` / `registry.json` without a prompt (auto-enabled when stdin is not a terminal, e.g. `curl \| bash`) |
| `--no-init` | Install CLI only; you will run `seckit init` yourself |
| `--no-verify` | Skip `seckit doctor --install-check` at the end |
| `--ref TAG` | Install a different git ref (e.g. `dev`, `v2.0.0a0`) instead of the baked release tag |
| `--repo-url URL` | Fork or mirror of the Git repository |
| `--dry-run` | Show what would happen; make no changes |
| `--json` | Machine-readable result on stdout |
| `-h`, `--help` | Print installer help |

**Examples (advanced):**

```bash
# Upgrade only
curl -fsSL …/install.sh | bash -s -- --upgrade

# Install CLI but defer init
./install.sh --no-init

# Pin a branch (testing)
curl -fsSL …/install.sh | bash -s -- --ref dev
```

### Environment variables (advanced)

| Variable | Default | Purpose |
|----------|---------|---------|
| `SECKIT_MANAGED_VENV` | `~/.local/share/seckit/venv` | Where the installer creates a standalone venv |
| `SECKIT_INSTALL_STATE` | `~/.config/seckit/install.json` | Records which Python was used (for upgrades) |

Config and secret **storage paths** (SQLite file, alternate config home) are **not** installer flags. Use `seckit init --home PATH`, `SECKIT_SQLITE_PATH`, or `seckit config` — see [DEFAULTS.md](DEFAULTS.md).

---

## Python environment

The installer always uses `"$PYTHON" -m pip` (never bare `pip`).

Resolution order:

1. Active **conda** (`$CONDA_PREFIX/bin/python`)
2. Active **venv** (`$VIRTUAL_ENV/bin/python`)
3. Existing **managed venv** at `SECKIT_MANAGED_VENV`
4. **Create** a new managed venv (needs `python3` 3.9+ on `PATH`)

Upgrade reuses the interpreter stored in `install.json` when it still exists.

---

## Remote install

```bash
ssh user@host 'curl -fsSL https://raw.githubusercontent.com/unixwzrd/Secrets-Kit/v2.0.0a0/install.sh | bash'
```

No extra flags are required unless you are upgrading (`bash -s -- --upgrade`) or testing a non-release ref.

---

## After install: changing backend or paths

| Goal | What to run |
|------|-------------|
| View defaults | `seckit config show` |
| Set default service/account | `seckit config set service my-stack` |
| Use SQLite on macOS (dev) | `seckit config set backend sqlite` and use `--sqlite-dev-mode` on commands |
| Alternate SQLite DB file | `export SECKIT_SQLITE_PATH=…` or set in `defaults.json` — [DEFAULTS.md](DEFAULTS.md) |
| Separate config directory | `seckit init --home /path/to/config-home` (destructive; confirms unless `--yes`) |

---

## Publish a release (maintainers)

`project.version` must be [PEP 440](https://peps.python.org/pep-0440/) (e.g. `2.0.0a0` — not `2.0.0-pre-0a`).

These must match **exactly**:

| Item | Value (example) |
|------|-----------------|
| `pyproject.toml` → `version` | `2.0.0a0` |
| Git tag | `v2.0.0a0` (`v` + version string) |
| `install.sh` → `SECKIT_REF_BAKED` | `v2.0.0a0` |
| `install.sh` → `SECKIT_INSTALL_URL` | `…/v2.0.0a0/install.sh` |
| `install_constants.py` → `DEFAULT_REF` | same as `SECKIT_REF_BAKED` |

**Steps:**

1. Commit and push branch `dev`.
2. Tag the commit you are shipping:

   ```bash
   git tag -a v2.0.0a0 -m "Pre-release 2.0.0a0"
   git push origin v2.0.0a0
   ```

3. Confirm tag points at that commit: `git rev-parse v2.0.0a0 origin/dev`
4. Create GitHub prerelease on tag `v2.0.0a0`.
5. Optional: `SECKIT_RELEASE_TAG=v2.0.0a0 bash ./scripts/release_preflight.sh`

Pushing to branch **`dev`** does **not** move a tag.

---

## Non-goals (phase 1)

No rsync deploy, Homebrew/Docker, daemons, or custom install roots via `install.sh`.

See also: [QUICKSTART.md](QUICKSTART.md), [CLI_REFERENCE.md](CLI_REFERENCE.md), [DEFAULTS.md](DEFAULTS.md).
