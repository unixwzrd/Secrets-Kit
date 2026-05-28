# Maintainer release guide

**Created**: 2026-05-27  
**Updated**: 2026-05-27

Operator install docs: [INSTALL.md](INSTALL.md). CI wheel/sdist detail: [GITHUB_RELEASE_BUILD.md](GITHUB_RELEASE_BUILD.md).

---

## Version and tag alignment

`project.version` in `pyproject.toml` must be valid [PEP 440](https://peps.python.org/pep-0440/) (e.g. `2.0.0a1` for alpha 1 — not `2.0.0-pre-0a`).

These must match **exactly** for a tagged release:

| Item | Example |
|------|---------|
| `pyproject.toml` → `version` | `2.0.0a1` |
| Git tag | `v2.0.0a1` (`v` + version string) |
| `install.sh` → `SECKIT_REF_BAKED` | `v2.0.0a1` |
| `install.sh` → `SECKIT_INSTALL_URL` | `…/v2.0.0a1/install.sh` |
| `install_constants.py` → `DEFAULT_REF` | same as `SECKIT_REF_BAKED` |

---

## Publish a pre-release (sterile `dev` line)

1. Commit and push branch `dev`.
2. Tag the commit you are shipping (tip of `dev` after push):

   ```bash
   git tag -a v2.0.0a1 -m "Pre-release 2.0.0a1"
   git push origin v2.0.0a1
   ```

3. Confirm tag points at that commit (not an old `main` tip):

   ```bash
   git rev-parse v2.0.0a1 origin/dev
   git show v2.0.0a1:pyproject.toml | grep '^version'
   ```

4. Wait for the **release** GitHub Actions workflow on the tag push.
5. Create a GitHub **pre-release** on tag `v2.0.0a1`.

Preflight (optional, local):

```bash
SECKIT_RELEASE_TAG=v2.0.0a1 bash ./scripts/release_preflight.sh
```

Pushing to branch **`dev`** does **not** move an existing tag. Create or move the tag on the commit you intend to ship.

---

## CI / release workflow

Tag push runs `.github/workflows/release.yml`:

1. **validate** — `release_preflight.sh` (tag vs `pyproject.toml`), then `run_local_validation.sh` on macOS.
2. **wheel** — matrix Python 3.9–3.13; smoke: `seckit --version`, `seckit info --json`, `seckit doctor --install-check`.
3. **sdist** — source tarball on Ubuntu.
4. **collect-dist** — artifact bundle for release upload.

See [GITHUB_RELEASE_BUILD.md](GITHUB_RELEASE_BUILD.md) for wheel platform tags and local packaging scripts.

---

## Bumping the pre-release version

For a **new** pre-release (e.g. `2.0.0a0` → `2.0.0a1`):

1. Bump `pyproject.toml` `version`.
2. Align `install.sh`, `install_constants.py`, and operator doc curl URLs.
3. Front-post `CHANGELOG.md`.
4. Push `dev`, tag `v` + new version, push tag.

Do not re-use the same tag name for a different commit unless intentionally force-moving a broken tag (avoid for normal releases).
