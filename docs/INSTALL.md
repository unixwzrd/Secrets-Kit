# Install Secrets-Kit

**Created**: 2026-05-26  
**Updated**: 2026-05-26

**Pre-release (`dev` line):** version `2.0.0a0` · git tag `v2.0.0a0`

`project.version` must be [PEP 440](https://peps.python.org/pep-0440/) (e.g. `2.0.0a0` for alpha 0 — not `2.0.0-pre-0a`).

Operator install: **curl | bash** + pip from GitHub. See [Publish a release](#publish-a-release) before tagging.

---

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/unixwzrd/Secrets-Kit/v2.0.0a0/install.sh | bash -s -- --yes
```

Verify:

```bash
seckit doctor --install-check
seckit version
```

## Upgrade

```bash
curl -fsSL https://raw.githubusercontent.com/unixwzrd/Secrets-Kit/v2.0.0a0/install.sh | bash -s -- --upgrade
```

Or: `seckit install --upgrade`

## Python environment

Installer uses `"$PYTHON" -m pip` only. Resolution order: active **conda** → active **venv** → `$HOME/.local/share/seckit/venv`.

Upgrade reuses the interpreter in `~/.config/seckit/install.json` when it still exists.

## Remote

```bash
ssh -o BatchMode=yes -o ConnectTimeout=10 user@host \
  'curl -fsSL https://raw.githubusercontent.com/unixwzrd/Secrets-Kit/v2.0.0a0/install.sh | bash -s -- --yes'
```

## Local clone (not curl)

```bash
./install.sh --dev --yes
# or: make install-dev
```

---

## Publish a release

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
2. Tag the commit you are shipping (tip of `dev` after push):

   ```bash
   git tag -a v2.0.0a0 -m "Pre-release 2.0.0a0"
   git push origin v2.0.0a0
   ```

3. Confirm tag points at that commit (not an older `main` commit):

   ```bash
   git rev-parse v2.0.0a0 origin/dev
   git show v2.0.0a0:pyproject.toml | grep '^version'
   ```

4. Create GitHub prerelease on tag `v2.0.0a0`.

5. Preflight (optional):

   ```bash
   SECKIT_RELEASE_TAG=v2.0.0a0 bash ./scripts/release_preflight.sh
   ```

Pushing to branch **`dev`** does **not** move a tag. The tag must be created on the commit **after** push.

---

## Non-goals (phase 1)

No rsync deploy, Homebrew/Docker, daemons, or custom install roots.

See also: [QUICKSTART.md](QUICKSTART.md), [CLI_REFERENCE.md](CLI_REFERENCE.md).
