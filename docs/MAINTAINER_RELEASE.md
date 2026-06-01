# Maintainer release guide

**Created**: 2026-05-27  
**Updated**: 2026-05-31

Operator install docs: [INSTALL.md](INSTALL.md). CI artifact detail: [GITHUB_RELEASE_BUILD.md](GITHUB_RELEASE_BUILD.md).

---

## Version and tag alignment

`project.version` in `pyproject.toml` must be valid [PEP 440](https://peps.python.org/pep-0440/).

These must match for a tagged release:

| Item | Example |
|------|---------|
| `pyproject.toml` → `version` | `2.0.0a3` |
| Git tag | `v2.0.0a3` (`v` + version string) |
| `install.sh` | branch-based (`dev` or `main`); no baked version |
| `install_constants.py` → `DEFAULT_INSTALL_BRANCH` | `dev` or `main` |

---

## Publish a pre-release from sterile `dev`

1. Regenerate the sterile public `dev` branch from the curated `dev-local` tree.
2. Validate the sterile tree.
3. Push branch `dev`.
4. Tag the exact commit being shipped:

   ```bash
   git tag -a v2.0.0a3 -m "Pre-release v2.0.0a3"
   git push origin v2.0.0a3
   ```

5. Confirm tag and package version agree:

   ```bash
   git rev-parse v2.0.0a3 origin/dev
   git show v2.0.0a3:pyproject.toml | grep '^version'
   ```

6. Wait for the release GitHub Actions workflow on the tag push.
7. Confirm the GitHub pre-release has:
   - `seckit-2.0.0a3-py3-none-any.whl`
   - `seckit-2.0.0a3.tar.gz`

Preflight:

```bash
SECKIT_RELEASE_TAG=v2.0.0a3 bash ./scripts/release_preflight.sh
```

Pushing branch `dev` does not move an existing tag. Create or move tags deliberately only on the commit being shipped.

---

## CI / release workflow

Tag push runs `.github/workflows/release.yml`:

1. **validate** — `release_preflight.sh` and `run_local_validation.sh` on macOS and Ubuntu.
2. **wheel** — one universal `py3-none-any` wheel using Python 3.12.
3. **sdist** — one source tarball on Ubuntu.
4. **collect-dist** — artifact bundle for release upload.
5. **publish-github-release** — uploads wheel and sdist to the GitHub release for the tag.

Release flow from the sterile repo:

```bash
bash scripts/release
```

That script rsyncs from `../secrets-kit/`, commits, tags from `pyproject.toml`, pushes, and creates/updates the GitHub release. CI on tag push builds and uploads artifacts.

---

## Bumping the pre-release version

For a new pre-release:

1. Bump `pyproject.toml` `version`.
2. Front-post `CHANGELOG.md`.
3. Regenerate sterile `dev` from `dev-local`.
4. From the sterile repo, run `bash scripts/release` or tag/push manually.

Avoid reusing the same tag name for a different commit unless intentionally replacing a broken pre-release tag.
