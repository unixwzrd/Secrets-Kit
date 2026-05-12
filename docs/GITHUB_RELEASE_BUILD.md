# GitHub Actions release: macOS wheels (Python only)

**Created**: 2026-05-02  
**Updated**: 2026-05-12

Secrets-Kit **wheels and sdist** ship **Python + package data** only (no bundled native app or helper). For **`--backend secure`**, the CLI uses the macOS **`security`** binary.

## Universal2 vs many macOS runners

- **Use** a **single wheel platform tag** per Python: `macosx_13_0_universal2` (see [setup.cfg](../setup.cfg)). Match your lowest supported macOS for the interpreter wheels you publish.
- **Do** build **one wheel per Python version** you support (e.g. 3.9–3.13) so each wheel’s `cp*` tag matches the installer’s interpreter.

## What runs in CI

The [release workflow](../.github/workflows/release.yml):

1. **validate** — **release preflight** (on tag `v*`, tag vs `pyproject.toml` `version`; optional `CHANGELOG.md` warning), then tests on **Python 3.12**. **Branch/PR CI** (`.github/workflows/ci.yml`) runs **3.9–3.13** × several macOS images.
2. **wheel** — matrix **3.9–3.13**; `python -m build -w`; per Python, venv smoke: `seckit version`, `seckit version --json`, `seckit helper status`.
3. **sdist** — source distribution on Ubuntu.
4. **collect-dist** — merges wheels + sdist into **`seckit-dist`**.

### Preflight (tag releases)

`scripts/release_preflight.sh` runs at the start of **validate** when `GITHUB_REF` is `refs/tags/v*`. Manual `workflow_dispatch` uses a branch ref, so the tag check is skipped.

## Local release (your Mac)

\```bash
bash scripts/package_release_wheels.sh
# optional: PY_VERSIONS='3.9,3.10,3.11,3.12,3.13'
\```

Then tag `vX.Y.Z`, push, or upload `dist/*` to PyPI / GitHub Release.

## References

- [Security model](SECURITY_MODEL.md)
