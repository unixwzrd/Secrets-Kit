# GitHub Actions release: universal wheel and sdist

**Updated**: 2026-06-02

Secrets-Kit ships Python package code and JSON package data only. It does not bundle native extensions or platform binaries. For `--backend keychain`, the CLI uses the host macOS `security` binary at runtime.

## Release artifacts

The release workflow publishes:

- `seckit-<version>-py3-none-any.whl`
- `seckit-<version>.tar.gz`

The installer prefers the universal wheel on macOS and Linux, and falls back to the sdist only when no wheel asset is available.

## What runs in CI

Branch CI (`.github/workflows/ci.yml`) runs local validation on:

- macOS 15
- Ubuntu
- Python 3.11
- Python 3.12

The [release workflow](../.github/workflows/release.yml) on tag push `v*`:

1. **validate** — `release_preflight.sh`, lint, and fast unit tests on Ubuntu.
2. **wheel** — build one universal wheel with Python 3.12; `verify-release-artifacts.sh --local` checks naming against `install.sh`.
3. **smoke** — install the wheel and run:
   - `seckit --version`
   - `seckit info --json`
   - `seckit doctor --install-check`
4. **sdist** — build one source distribution.
5. **collect-dist** — merge wheel and sdist artifacts.
6. **publish-github-release** — upload `dist/*` to the GitHub release.

Post-install acceptance (`doctor --acceptance-test`) is exercised by the operator installer on target hosts; see [RELEASE_VALIDATION.md](RELEASE_VALIDATION.md).

## Maintainer release script

From the sterile public repo:

```bash
bash scripts/release
```

Bump `pyproject.toml` in the dev repo first. The script rsyncs, commits, tags, pushes, and creates the GitHub release. CI attaches the wheel and sdist when the tag lands.

## Local artifact check

```bash
python -m pip install -U build
python -m build -w -s -n
python - <<'PY'
from pathlib import Path
from zipfile import ZipFile

wheel = next(Path("dist").glob("seckit-*-py3-none-any.whl"))
with ZipFile(wheel) as zf:
    wheel_meta = next(name for name in zf.namelist() if name.endswith("/WHEEL"))
    print(zf.read(wheel_meta).decode())
PY
```

Expected metadata:

```text
Root-Is-Purelib: true
Tag: py3-none-any
```

## References

- [Security model](SECURITY_MODEL.md)
- [Maintainer release guide](MAINTAINER_RELEASE.md)
