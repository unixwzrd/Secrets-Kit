#!/usr/bin/env bash
# Sync source trees between the working repo (secrets-kit) and the sterile push repo
# (secrets-kit-public). Does not touch .git, build artifacts, or caches.
#
# Usage (from either repo root):
#   bash scripts/sync_repos.sh dev-to-sterile    # copy secrets-kit → secrets-kit-public
#   bash scripts/sync_repos.sh sterile-to-dev    # copy secrets-kit-public → secrets-kit
#
# After dev-to-sterile: commit and push from secrets-kit-public (origin dev + tags).
# After sterile-to-dev: continue feature work in secrets-kit; re-sync before the next push.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV="${SECKIT_DEV_REPO:-$(cd "${ROOT}/.." && pwd)/secrets-kit}"
STERILE="${SECKIT_STERILE_REPO:-$(cd "${ROOT}/.." && pwd)/secrets-kit-public}"

direction="${1:-}"
if [[ "${direction}" != "dev-to-sterile" && "${direction}" != "sterile-to-dev" ]]; then
  echo "usage: $0 dev-to-sterile | sterile-to-dev" >&2
  exit 2
fi

if [[ "${direction}" == "dev-to-sterile" ]]; then
  SRC="${DEV}"
  DST="${STERILE}"
else
  SRC="${STERILE}"
  DST="${DEV}"
fi

for d in "${SRC}" "${DST}"; do
  if [[ ! -d "${d}" ]]; then
    echo "ERROR: missing directory: ${d}" >&2
    exit 1
  fi
done

RSYNC_EXCLUDES=(
  --exclude .git
  --exclude __pycache__
  --exclude '*.pyc'
  --exclude .ruff_cache
  --exclude build
  --exclude dist
  --exclude .wheel-smoke
  --exclude test-reports
  --exclude '*.egg-info'
  --exclude .pytest_cache
  --exclude .mypy_cache
)

echo "sync ${direction}"
echo "  from: ${SRC}"
echo "  to:   ${DST}"
rsync -a "${RSYNC_EXCLUDES[@]}" "${SRC}/" "${DST}/"
echo "OK"
