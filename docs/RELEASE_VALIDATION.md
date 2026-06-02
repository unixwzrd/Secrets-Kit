# Release validation checklist

**Created**: 2026-06-01  
**Updated**: 2026-06-02

Executable operator checklist for cross-platform release candidate validation.  
Architecture, installer layout, and backend behavior are frozen for this pass — only validate and report.

## Prerequisites (all platforms)

| Requirement | Notes |
|-------------|--------|
| Network | GitHub API, release assets, `raw.githubusercontent.com`, optional `astral.sh` (uv bootstrap) |
| User install | Non-root operator account recommended |
| `curl` or `wget` or `python3` | Installer downloader fallback chain |
| `bash` | 4.x+ |
| `~/.local/bin` on `PATH` | Or use full path `~/.local/bin/seckit` in commands below |

**Linux (SQLite backend):** `install.sh` passes `--sqlite-dev-mode` to `seckit init`. For manual `seckit set` / `get` after install, use `--sqlite-dev-mode` or `export SECKIT_SQLITE_DEVELOPER_MODE=1` (acceptance test enables dev mode internally).

**Channels:**

| Channel | Install URL branch | Env |
|---------|-------------------|-----|
| Prerelease (default installer) | `dev` | `SECKIT_RELEASE_CHANNEL=prerelease` (default) |
| Stable release | `main` | `SECKIT_RELEASE_CHANNEL=release` |

Replace `vX.Y.Z` / `2.0.0a3` with the version under test.

---

## Maintainer: build and publish (before platform matrix)

### 1. Version alignment

```bash
grep '^version' pyproject.toml
# Expect: version = "X.Y.Z"

git tag -l 'v*' | sort -V | tail -3
# Next tag must be vX.Y.Z matching pyproject.toml
```

### 2. Local artifacts (optional pre-push)

```bash
python3 -m pip install -U build
python3 -m build -w -s -n
bash ./scripts/verify-release-artifacts.sh --local
```

**Expected:** `verify-release-artifacts: artifact naming verification passed`  
**Expected files in `dist/`:**

- `seckit-X.Y.Z-py3-none-any.whl`
- `seckit-X.Y.Z.tar.gz`

Installer wheel URL pattern (must match asset name):

`https://github.com/unixwzrd/Secrets-Kit/releases/download/vX.Y.Z/seckit-X.Y.Z-py3-none-any.whl`

### 3. Tag and CI release

```bash
# From sterile public repo after sync:
bash ./scripts/release
# Or manual tag push; CI .github/workflows/release.yml runs on v*
```

**Expected GitHub release layout:**

| Asset | Required for default install |
|-------|------------------------------|
| `seckit-X.Y.Z-py3-none-any.whl` | Yes (installer primary) |
| `seckit-X.Y.Z.tar.gz` | No (fallback only if wheel missing) |

### 4. Post-upload artifact check

```bash
bash ./scripts/verify-release-artifacts.sh --github-tag vX.Y.Z
```

---

## Shared cleanup (destructive — fresh install only)

Run only when intentionally removing Secrets-Kit from the test host.

```bash
# Launcher and runtime
rm -f "${HOME}/.local/bin/seckit"
rm -rf "${HOME}/.local/share/seckit"

# Operator config (includes secrets metadata; macOS keychain items are NOT removed)
rm -rf "${HOME}/.config/seckit"

# Optional: remove installer PATH block from shell profile
# Edit ~/.zshrc or ~/.bashrc — delete lines between:
#   # >>> seckit path >>>
#   # <<< seckit path <<<
```

**macOS:** Keychain entries created during tests may remain until deleted manually (`seckit delete` or Keychain Access).

**Linux:** SQLite file default: `~/.config/seckit/seckit.sqlite` (removed with `rm -rf ~/.config/seckit` above).

---

## Shared validation commands (after every install / upgrade)

```bash
export PATH="${HOME}/.local/bin:${PATH}"

bash /path/to/secrets-kit/scripts/install-validation.sh --verbose
```

Or manually:

```bash
seckit --version
# Expected: seckit X.Y.Z  (PEP 440 version matching release)

seckit info
# Expected: human-readable backend/paths summary (exit 0)

seckit doctor --install-check | python3 -m json.tool
# Expected: "ok": true

seckit doctor --acceptance-test | python3 -m json.tool
# Expected: "ok": true
# macOS: backends ["keychain","sqlite"]; steps include keychain:ACCEPTANCE_PROBE:verify_delete and sqlite:ACCEPTANCE_CONFIG:verify_delete
# Linux: backends ["sqlite"]; steps include sqlite:ACCEPTANCE_PROBE:verify_delete
# Fixtures exercised: ACCEPTANCE_PROBE, ACCEPTANCE_TOKEN, ACCEPTANCE_CONFIG (namespace __seckit_test__)
```

---

## macOS — fresh install

### Cleanup

Run [shared cleanup](#shared-cleanup-destructive--fresh-install-only).

### Install

```bash
curl -fsSL https://raw.githubusercontent.com/unixwzrd/Secrets-Kit/dev/install.sh | bash -s -- --yes
```

Stable channel example:

```bash
SECKIT_RELEASE_CHANNEL=release \
  curl -fsSL https://raw.githubusercontent.com/unixwzrd/Secrets-Kit/main/install.sh | bash -s -- --yes
```

**Expected installer output (summary):**

- Steps `[1/5]` … `[5/5]` complete
- `Secrets-Kit installed successfully.`
- `Install verification passed.`
- `Acceptance test passed.`
- No `seckit-install: error:` lines

### Validation

```bash
bash ./scripts/install-validation.sh --verbose
```

**Expected:** `install-validation: all checks passed`

---

## macOS — upgrade

### Preconditions

- Completed [macOS fresh install](#macos--fresh-install) (or existing install)
- Published release **newer** than installed version on channel under test

### Install (upgrade)

```bash
curl -fsSL https://raw.githubusercontent.com/unixwzrd/Secrets-Kit/dev/install.sh | bash -s -- --upgrade --yes
```

**Expected:** upgrade path skips `seckit init`; verification and acceptance still run unless `--no-verify`.

### Validation

```bash
bash ./scripts/upgrade-validation.sh \
  --install-url 'https://raw.githubusercontent.com/unixwzrd/Secrets-Kit/dev/install.sh' \
  --verbose
```

**Expected:** `upgrade-validation: upgrade validation passed`

---

## Rocky Linux — fresh install

Test on Rocky 8/9 or RHEL-equivalent with `curl`, `python3`, and user-writable `$HOME`.

### Cleanup

[Shared cleanup](#shared-cleanup-destructive--fresh-install-only).

### Install

```bash
curl -fsSL https://raw.githubusercontent.com/unixwzrd/Secrets-Kit/dev/install.sh | bash -s -- --yes
```

**Expected:** same success criteria as macOS; `seckit info` should show `backend: sqlite`; acceptance runs **sqlite only**.

### Validation

```bash
export SECKIT_SQLITE_DEVELOPER_MODE=1
bash ./scripts/install-validation.sh --verbose
```

---

## Rocky Linux — upgrade

### Upgrade

```bash
export SECKIT_SQLITE_DEVELOPER_MODE=1

curl -fsSL https://raw.githubusercontent.com/unixwzrd/Secrets-Kit/dev/install.sh | bash -s -- --upgrade --yes
```

### Validation

```bash
export SECKIT_SQLITE_DEVELOPER_MODE=1
bash ./scripts/upgrade-validation.sh \
  --install-url 'https://raw.githubusercontent.com/unixwzrd/Secrets-Kit/dev/install.sh' \
  --verbose
```

---

## Debian — fresh install

Use Debian 11+ or Ubuntu 22.04+ (installer targets Debian-family the same as Ubuntu).

### Cleanup

[Shared cleanup](#shared-cleanup-destructive--fresh-install-only).

### Install

```bash
sudo apt-get update -qq
sudo apt-get install -y curl ca-certificates python3

export SECKIT_SQLITE_DEVELOPER_MODE=1

curl -fsSL https://raw.githubusercontent.com/unixwzrd/Secrets-Kit/dev/install.sh | bash -s -- --yes
```

### Validation

```bash
export SECKIT_SQLITE_DEVELOPER_MODE=1
bash ./scripts/install-validation.sh --verbose
```

---

## Debian — upgrade

### Upgrade

```bash
export SECKIT_SQLITE_DEVELOPER_MODE=1

curl -fsSL https://raw.githubusercontent.com/unixwzrd/Secrets-Kit/dev/install.sh | bash -s -- --upgrade --yes
```

### Validation

```bash
export SECKIT_SQLITE_DEVELOPER_MODE=1
bash ./scripts/upgrade-validation.sh \
  --install-url 'https://raw.githubusercontent.com/unixwzrd/Secrets-Kit/dev/install.sh' \
  --verbose
```

---

## Repair smoke (optional, macOS or Linux)

```bash
curl -fsSL https://raw.githubusercontent.com/unixwzrd/Secrets-Kit/dev/install.sh | bash -s -- --repair --yes
bash ./scripts/install-validation.sh
```

**Expected:** launcher/runtime rebuilt; `~/.config/seckit` preserved; validation passes.

---

## Automation scripts (reference)

| Script | Purpose |
|--------|---------|
| `scripts/install-validation.sh` | Post-install checks only |
| `scripts/upgrade-validation.sh` | Upgrade + secret survival + install-validation |
| `scripts/verify-release-artifacts.sh` | Wheel name vs `pyproject.toml` / installer |
| `scripts/release_preflight.sh` | Tag ↔ `pyproject.toml` (CI) |

---

## Remaining release blockers

Track before declaring RC:

| ID | Blocker | Impact |
|----|---------|--------|
| B2 | Normal Linux CLI requires `SECKIT_SQLITE_DEVELOPER_MODE=1` or `--sqlite-dev-mode` for ad-hoc commands | Operator docs must be explicit |
| B3 | Cross-platform matrix not yet executed on physical Rocky/Debian/macOS hosts | RC requires human sign-off per table above |
| B4 | `docs/GITHUB_RELEASE_BUILD.md` mentions macOS release validate job; current `release.yml` validate job is Ubuntu-only | Doc drift only |
| B5 | Acceptance test leaves SQLite transaction history (tombstones); not a functional leak | Documented behavior |

---

## Release candidate declaration

RC is ready when:

1. `scripts/release` (or tag push) published `vX.Y.Z` with both wheel and sdist.
2. `scripts/verify-release-artifacts.sh --github-tag vX.Y.Z` passes.
3. All six platform scenarios in this document pass on real hosts (or documented waivers with bugs filed).
4. No open P0/P1 blockers in the table above.
