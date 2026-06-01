#!/usr/bin/env bash
# Verify wheel/sdist names match installer expectations and pyproject.toml version.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

MODE=""
TAG=""
DIST_DIR="${DIST_DIR:-dist}"
GITHUB_REPO="${SECKIT_GITHUB_REPO:-unixwzrd/Secrets-Kit}"

usage() {
  cat <<'EOF'
Usage: verify-release-artifacts.sh [options]

Fail loudly when release artifact names do not match install.sh expectations.

Installer expects (for tag vX.Y.Z):
  seckit-X.Y.Z-py3-none-any.whl

Options:
  --local              Verify files under dist/ (default if dist/ has artifacts)
  --github-tag TAG     Verify GitHub release assets (requires gh + network)
  --dist-dir DIR       Local dist directory (default: dist)
  -h, --help           Show help

Environment:
  SECKIT_GITHUB_REPO   GitHub repo for --github-tag (default: unixwzrd/Secrets-Kit)
EOF
}

log() { printf 'verify-release-artifacts: %s\n' "$*" >&2; }
die() { printf 'verify-release-artifacts: ERROR: %s\n' "$*" >&2; exit 1; }

get_pyproject_version() {
  python3 <<'PY'
import pathlib
import re

text = pathlib.Path("pyproject.toml").read_text(encoding="utf-8")
match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
if not match:
    raise SystemExit("could not parse version from pyproject.toml")
print(match.group(1))
PY
}

ref_to_version() {
  local ref="${1:?}"
  ref="${ref#v}"
  printf '%s' "${ref}"
}

expected_wheel_name() {
  local version="${1:?}"
  printf 'seckit-%s-py3-none-any.whl' "${version}"
}

expected_sdist_name() {
  local version="${1:?}"
  printf 'seckit-%s.tar.gz' "${version}"
}

verify_installer_url_pattern() {
  local tag="${1:?}"
  local version wheel_name url
  version="$(ref_to_version "${tag}")"
  wheel_name="$(expected_wheel_name "${version}")"
  url="https://github.com/${GITHUB_REPO}/releases/download/${tag}/${wheel_name}"
  log "installer wheel URL pattern: ${url}"
  if [[ "${wheel_name}" != "seckit-${version}-py3-none-any.whl" ]]; then
    die "internal naming mismatch for tag ${tag}"
  fi
}

verify_local_dist() {
  local version="${1:?}"
  local wheel_name sdist_name
  wheel_name="$(expected_wheel_name "${version}")"
  sdist_name="$(expected_sdist_name "${version}")"

  [[ -d "${DIST_DIR}" ]] || die "dist directory not found: ${DIST_DIR}"

  local -a wheels=()
  shopt -s nullglob
  wheels=("${DIST_DIR}"/seckit-*-py3-none-any.whl)
  shopt -u nullglob

  if [[ "${#wheels[@]}" -eq 0 ]]; then
    die "no universal wheel in ${DIST_DIR}/ (expected ${wheel_name})"
  fi
  if [[ "${#wheels[@]}" -gt 1 ]]; then
    die "multiple universal wheels in ${DIST_DIR}/: ${wheels[*]}"
  fi
  if [[ "$(basename "${wheels[0]}")" != "${wheel_name}" ]]; then
    die "wheel name mismatch: got $(basename "${wheels[0]}"), expected ${wheel_name}"
  fi
  log "OK: local wheel ${wheel_name}"

  if [[ -f "${DIST_DIR}/${sdist_name}" ]]; then
    log "OK: local sdist ${sdist_name}"
  else
    log "note: sdist not found (${sdist_name}); installer prefers wheel"
  fi
}

verify_github_release() {
  local tag="${1:?}"
  local version wheel_name
  version="$(ref_to_version "${tag}")"
  wheel_name="$(expected_wheel_name "${version}")"

  command -v gh >/dev/null 2>&1 || die "gh CLI required for --github-tag"
  verify_installer_url_pattern "${tag}"

  local assets
  assets="$(gh release view "${tag}" --repo "${GITHUB_REPO}" --json assets -q '.assets[].name')" \
    || die "GitHub release not found: ${GITHUB_REPO} ${tag}"

  if ! printf '%s\n' "${assets}" | grep -qxF "${wheel_name}"; then
    die "release ${tag} missing asset ${wheel_name}; assets:\n${assets}"
  fi
  log "OK: GitHub release ${tag} includes ${wheel_name}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --local) MODE="local"; shift ;;
    --github-tag) TAG="${2:?}"; MODE="github"; shift 2 ;;
    --dist-dir) DIST_DIR="${2:?}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

VERSION="$(get_pyproject_version)"
log "pyproject.toml version: ${VERSION}"

if [[ -z "${MODE}" ]]; then
  if [[ -d "${DIST_DIR}" ]] && compgen -G "${DIST_DIR}/seckit-*-py3-none-any.whl" >/dev/null; then
    MODE="local"
  elif [[ -n "${TAG}" ]]; then
    MODE="github"
  else
    MODE="local"
  fi
fi

if [[ "${MODE}" == "local" ]]; then
  verify_local_dist "${VERSION}"
  if [[ -z "${TAG}" ]]; then
    TAG="v${VERSION}"
  fi
  verify_installer_url_pattern "${TAG}"
elif [[ "${MODE}" == "github" ]]; then
  [[ -n "${TAG}" ]] || TAG="v${VERSION}"
  if [[ "$(ref_to_version "${TAG}")" != "${VERSION}" ]]; then
    die "tag ${TAG} version ($(ref_to_version "${TAG}")) != pyproject.toml (${VERSION})"
  fi
  verify_github_release "${TAG}"
else
  die "unknown mode: ${MODE}"
fi

log "artifact naming verification passed"
exit 0
