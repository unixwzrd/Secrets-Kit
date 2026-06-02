# Install Secrets-Kit

**Updated**: 2026-06-02

Canonical operator install for macOS and Linux.

## Prerequisites

- macOS or Linux
- Network access for first install (runtime bootstrap and release artifacts)

The installer provisions **Python 3.12** via uv and installs the **latest GitHub release** for the active channel.

## Install

Development channel (default):

```bash
curl -fsSL https://raw.githubusercontent.com/unixwzrd/Secrets-Kit/dev/install.sh | bash
# or
wget -qO- https://raw.githubusercontent.com/unixwzrd/Secrets-Kit/dev/install.sh | bash
```

Stable channel:

```bash
SECKIT_RELEASE_CHANNEL=release \
  curl -fsSL https://raw.githubusercontent.com/unixwzrd/Secrets-Kit/main/install.sh | bash
# or
SECKIT_RELEASE_CHANNEL=release \
  wget -qO- https://raw.githubusercontent.com/unixwzrd/Secrets-Kit/main/install.sh | bash
```

Default install:

1. Bootstraps uv when needed
2. Provisions Python 3.12 and creates an isolated runtime
3. Resolves the latest GitHub release and installs the universal wheel (`py3-none-any`) when available, falling back to sdist
4. Runs `seckit init` (Linux: with `--sqlite-dev-mode`), then `seckit doctor --install-check` and `seckit doctor --acceptance-test`

## Upgrade

```bash
curl -fsSL https://raw.githubusercontent.com/unixwzrd/Secrets-Kit/dev/install.sh | bash -s -- --upgrade
# or
wget -qO- https://raw.githubusercontent.com/unixwzrd/Secrets-Kit/dev/install.sh | bash -s -- --upgrade
```

Or, after install:

```bash
seckit install --upgrade
```

Upgrade refreshes runtime/package, keeps the previous runtime generation as fallback, removes older generations, and skips `seckit init`. When the running `seckit` was installed from a release wheel (no local `install.sh` in the package), `seckit install --upgrade` falls back to the same `curl | bash` flow as the operator installer.

## Runtime layout

| Path | Purpose |
|------|---------|
| `~/.local/bin/seckit` | Launcher shim |
| `~/.local/share/seckit/runtime/` | Isolated uv venv generations |
| `~/.local/share/seckit/runtime/current` | Canonical runtime symlink (launcher target) |
| `~/.local/share/seckit/state/runtime-path` | Legacy pointer kept for older `doctor --install-check` builds |
| `~/.local/share/seckit/state/runtime.json` | Python version, release ref, package source |
| `~/.config/seckit/install.json` | Installed version, release ref, package source, and `verified` flag (set after successful post-install checks) |
| `~/.config/seckit/defaults.json` | Operator defaults |

## Verify

```bash
seckit --version
seckit info
seckit doctor --install-check
seckit doctor --acceptance-test
```

`--install-check` is fast (launcher, seeds, writable config; no backend roundtrip).

`--acceptance-test` runs ephemeral CRUD in the `__seckit_test__` namespace and always cleans up:

| Platform | Backends exercised |
|----------|-------------------|
| macOS | `keychain`, then `sqlite` |
| Linux | `sqlite` only |

Each backend runs three inline test fixtures (`ACCEPTANCE_PROBE`, `ACCEPTANCE_TOKEN`, `ACCEPTANCE_CONFIG`) through create, read, update, list, delete, and verify-delete. On macOS, if the login keychain file is missing, acceptance creates a **temporary keychain** and removes it afterward. Acceptance does not modify operator secrets outside `__seckit_test__`.

Helper scripts (from a clone):

```bash
bash scripts/install-validation.sh      # post-install checks only
bash scripts/upgrade-validation.sh      # upgrade + secret survival + checks
```

See [RELEASE_VALIDATION.md](RELEASE_VALIDATION.md) for the full cross-platform matrix.

## Remote install

```bash
ssh -o BatchMode=yes -o ConnectTimeout=10 user@host \
  'curl -fsSL https://raw.githubusercontent.com/unixwzrd/Secrets-Kit/dev/install.sh | bash -s -- --yes'
```

Equivalent with `wget`:

```bash
ssh -o BatchMode=yes -o ConnectTimeout=10 user@host \
  'wget -qO- https://raw.githubusercontent.com/unixwzrd/Secrets-Kit/dev/install.sh | bash -s -- --yes'
```

Convenience wrapper:

```bash
seckit install @seckit-rocky
seckit install seckit@other-host
```

Remote targets must include `@` (`@host` uses your local `$USER`; `user@host` sets the SSH user). Remote install implies `--yes` (non-interactive).

Remote install pins the **release wheel** for the caller’s version (`v` + `seckit --version`) via `SECKIT_REF` on the remote host (no `git` required). Override with `--ref TAG` (wheel for released tags; git only if the wheel is missing).

## Local development (checkout only)

From a git clone — not for operator `curl|bash`/`wget|bash`:

```bash
make install-dev
# or
./install.sh --dev
```

Uses editable install from the local checkout. Pin a git ref with `./install.sh --ref TAG` when testing non-release builds.

## Makefile targets (clone only)

| Target | Action |
|--------|--------|
| `make install` | Run `./install.sh` |
| `make install-dev` | Run `./install.sh --dev` |
| `make install-upgrade` | Run `./install.sh --upgrade` |
| `make install-check` | `seckit doctor --install-check` |

## Execution modes

- Default: concise progress output, quiet dependency chatter.
- `--verbose`: interpreter resolution, release selection, subprocess detail.
- Debug: pipe to `SECKIT_DEBUG=1 bash` for shell-level tracing.

## Troubleshooting

- `no GitHub release found`: no prerelease exists for the dev channel, or no stable release for the release channel.
- `no compatible release artifact found`: release assets missing; maintainer must publish the universal wheel and sdist.
- `runtime bootstrap unavailable` with `--safe` or `--no-uv-download`: remove those flags, or preinstall uv and `uv python install 3.12`.
- `need 'tar' (command not found)` during runtime bootstrap on minimal Linux: current installer falls back to a direct GitHub `uv` release when `tar` is missing (uses `python3` to unpack if needed). If both fail, install `tar` (`dnf install -y tar` on Rocky) or ensure `python3` is on `PATH`.
- Remote install over SSH with a bare `PATH`: the installer prepends standard system bin directories; you can also `export PATH="/usr/local/bin:/usr/bin:/bin:${PATH}"` before running.
- `git` / `git clone` errors on minimal Debian: default install uses the **release wheel** (no git). Git is only needed for non-tag refs (e.g. `--ref dev`) when no wheel exists. `seckit install user@host` pins the remote version via `SECKIT_REF` and the wheel, not `git+https://…`.
- `seckit: command not found`: add `~/.local/bin` to PATH (installer prints the line when it cannot edit your shell profile).
- `defaults.account` shows `root` after a sudo install: rerun `seckit init --yes` as the operator user.
- `acceptance test failed` on macOS with a service account: login keychain may be absent; current builds use a temp keychain for acceptance only.
- Linux `seckit set` fails after install: export `SECKIT_SQLITE_DEVELOPER_MODE=1` or pass `--sqlite-dev-mode` (acceptance enables this internally; normal CLI does not).
- Large `~/.cache/uv` after install: expected; the installer does not use a separate Secrets-Kit cache directory.

## Advanced flags (appendix)

- `--upgrade` update package/runtime; skip `seckit init`
- `--dev` editable install from a local checkout (`SECKIT_INSTALL_ROOT`, default `PWD`)
- `--ref TAG` install from **git** at TAG instead of release wheel
- `--yes` non-interactive mode when init would prompt
- `--no-init` install package only; skip `seckit init`
- `--no-verify` skip post-install `seckit doctor --install-check` and `--acceptance-test`
- `--skip-verify-if-unchanged` skip verification when `install.json` already records this ref and package source as verified (speeds repeat installs of the same wheel)
- `--verbose`, `--repair`, `--safe`, `--no-uv-download`, `--no-shell-profile`, `--shell-profile-force`

Environment overrides:

- `SECKIT_RELEASE_CHANNEL=prerelease|release` choose latest prerelease vs stable release
- `SECKIT_INSTALL_BRANCH=dev|main` branch used by docs/examples for `install.sh` URL
- `SECKIT_RUNTIME_PYTHON=3.12` pin uv-managed Python series
- `SECKIT_REF=vX.Y.Z` pin a specific release tag
- `SECKIT_WHEEL_URL=URL` force a specific wheel or sdist URL (testing)
- `SECKIT_UV_RELEASE_BASE=URL` base URL for direct `uv` tarball bootstrap (default: Astral GitHub latest)
- `SECKIT_UV_RELEASE_URL=URL` full tarball URL override (skips arch detection)

See also: [QUICKSTART.md](QUICKSTART.md) (operator workflow), [CLI_REFERENCE.md](CLI_REFERENCE.md), [MAINTAINER_RELEASE.md](MAINTAINER_RELEASE.md).
