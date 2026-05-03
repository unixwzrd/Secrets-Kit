#!/usr/bin/env bash
# Verify release tag matches pyproject.toml project.version (tag pushes only).
# Optional: warn if CHANGELOG.md does not mention the version.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

REF="${GITHUB_REF:-}"
if [[ -n "${SECKIT_RELEASE_TAG:-}" ]]; then
  REF="refs/tags/${SECKIT_RELEASE_TAG#refs/tags/}"
fi

if [[ "$REF" =~ ^refs/tags/v.+ ]]; then
  TAG="${REF#refs/tags/}"
  VER="${TAG#v}"
  PYVER="$(
    python3 -c "
import pathlib, re
text = pathlib.Path('pyproject.toml').read_text(encoding='utf-8')
# [project] version = \"x.y.z\"
m = re.search(r'^version\\s*=\\s*\"([^\"]+)\"', text, re.MULTILINE)
if not m:
    raise SystemExit('could not parse version from pyproject.toml')
print(m.group(1))
"
  )"
  if [[ "$VER" != "$PYVER" ]]; then
    echo "ERROR: git tag '$TAG' (version $VER) does not match pyproject.toml project.version '$PYVER'" >&2
    exit 1
  fi
  echo "OK: tag $TAG matches pyproject.toml version $PYVER"
  if [[ -f CHANGELOG.md ]] && ! grep -qF "$VER" CHANGELOG.md; then
    echo "WARNING: CHANGELOG.md has no line containing '$VER' — update before release if intentional" >&2
  fi
else
  echo "release_preflight: not a version tag ref (${REF:-local}); skipping tag/pyproject check."
fi
