#!/usr/bin/env bash
# Build Python wheels + sdist for release (local maintainer Mac). Wheels are Python-only.
#
# Prereqs: macOS, Python 3.9+ with pip.
#
# Optional: build several interpreters on your machine (comma-separated; must exist on PATH):
#    export PY_VERSIONS='3.9,3.10,3.11,3.12,3.13'
#
# Wheel platform tag is fixed in repo setup.cfg (macosx_13_0_universal2). To change it, edit setup.cfg.
#
# Then:
#    bash scripts/package_release_wheels.sh
#
# Output: dist/*.whl and dist/*.tar.gz (sdist once at end).
#
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "Release wheels must be built on macOS (platform tag in setup.cfg)." >&2
  exit 1
fi

export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-13.0}"

if [[ ! -f "$ROOT/setup.cfg" ]] || ! grep -q 'plat_name' "$ROOT/setup.cfg"; then
  echo "Expected setup.cfg with [bdist_wheel] plat_name (macOS universal2)." >&2
  exit 1
fi

echo "==> Building Python-only wheels (security CLI / sqlite backends; no bundled Mach-O)"

python3 -m pip install -U pip setuptools wheel build

rm -rf dist
mkdir -p dist

build_one() {
  local label="$1"
  shift
  local py=( "$@" )
  if ! command -v "${py[0]}" >/dev/null 2>&1; then
    echo "skip: ${py[0]} not found"
    return 0
  fi
  echo "==> Wheel: ${label} ($("${py[0]}" -c 'import sys; print(sys.version)'))"
  "${py[@]}" -m pip install -q -U build setuptools wheel
  "${py[@]}" -m build -w -n --outdir "$ROOT/dist"
}

if [[ -n "${PY_VERSIONS:-}" ]]; then
  IFS=',' read -ra RAW <<< "$PY_VERSIONS"
  for raw in "${RAW[@]}"; do
    ver="$(echo "$raw" | tr -d '[:space:]')"
    [[ -z "$ver" ]] && continue
    # Prefer python3.12 style, then python3 on PATH if version matches
    if command -v "python${ver}" >/dev/null 2>&1; then
      build_one "python${ver}" "python${ver}"
    elif command -v python3 >/dev/null 2>&1 && [[ "$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")" == "$ver" ]]; then
      build_one "python3" python3
    else
      echo "skip Python ${ver}: no python${ver} on PATH" >&2
    fi
  done
else
  build_one "default python3" python3
fi

echo "==> sdist (source; no bundled binary in tarball beyond README under native_helper_bundled/)"
python3 -m build -s -n --outdir "$ROOT/dist"

echo
echo "Done. Contents of dist/:"
ls -la "$ROOT/dist"
echo
echo "Next: twine upload dist/*   or   attach dist/* to a GitHub Release"
