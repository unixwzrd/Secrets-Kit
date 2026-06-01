#!/usr/bin/env bash
# Upgrade safety validation — requires an existing install; runs install.sh --upgrade.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SECKIT="${SECKIT:-seckit}"
INSTALL_URL="${SECKIT_INSTALL_URL:-https://raw.githubusercontent.com/unixwzrd/Secrets-Kit/dev/install.sh}"
INSTALL_SCRIPT="${SECKIT_INSTALL_SCRIPT:-}"
VERBOSE="${VERBOSE:-0}"

TEST_SERVICE="${SECKIT_UPGRADE_TEST_SERVICE:-__seckit_upgrade_test__}"
TEST_ACCOUNT="${SECKIT_UPGRADE_TEST_ACCOUNT:-__seckit_upgrade_test__}"
TEST_NAME="${SECKIT_UPGRADE_TEST_NAME:-UPGRADE_VALIDATION_PROBE}"
TEST_VALUE="${SECKIT_UPGRADE_TEST_VALUE:-seckit_upgrade_validation_v1}"

usage() {
  cat <<'EOF'
Usage: upgrade-validation.sh [options]

Validate upgrade safety on a machine with Secrets-Kit already installed.

Flow:
  1. Record defaults backend
  2. Create a temporary test secret
  3. Run install.sh --upgrade --yes (curl URL or local script)
  4. Verify secret value and backend unchanged
  5. Run scripts/install-validation.sh
  6. Remove test secret and registry metadata

Options:
  --install-url URL     curl | bash install URL (default: dev channel install.sh)
  --install-script PATH Use local install.sh instead of curl
  --seckit PATH         seckit command (default: seckit)
  --verbose             Verbose output
  -h, --help            Show help

Environment:
  SECKIT_SQLITE_DEVELOPER_MODE=1   Required on Linux when backend=sqlite for set/get
EOF
}

log() { printf 'upgrade-validation: %s\n' "$*" >&2; }
die() { printf 'upgrade-validation: ERROR: %s\n' "$*" >&2; exit 1; }

cleanup_secret() {
  log "cleanup: removing test secret (best effort)"
  "${SECKIT}" delete \
    --service "${TEST_SERVICE}" \
    --account "${TEST_ACCOUNT}" \
    --name "${TEST_NAME}" \
    --yes \
    ${SQLITE_DEV_FLAG} \
    >/dev/null 2>&1 || true
}

read_defaults_backend() {
  python3 <<'PY'
import json
import os
from pathlib import Path

config = Path(os.environ["HOME"]) / ".config" / "seckit" / "defaults.json"
if not config.is_file():
    raise SystemExit("defaults.json not found; run seckit init first")
data = json.loads(config.read_text(encoding="utf-8"))
backend = data.get("backend")
if not backend:
    raise SystemExit("defaults.json missing backend key")
print(backend)
PY
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --install-url) INSTALL_URL="${2:?}"; INSTALL_SCRIPT=""; shift 2 ;;
    --install-script) INSTALL_SCRIPT="${2:?}"; shift 2 ;;
    --seckit) SECKIT="${2:?}"; shift 2 ;;
    --verbose) VERBOSE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

if ! command -v "${SECKIT}" >/dev/null 2>&1 && [[ ! -x "${SECKIT}" ]]; then
  die "seckit not found: ${SECKIT}"
fi

SQLITE_DEV_FLAG=""
if [[ "$(uname -s)" == "Linux" ]]; then
  export SECKIT_SQLITE_DEVELOPER_MODE="${SECKIT_SQLITE_DEVELOPER_MODE:-1}"
  SQLITE_DEV_FLAG="--sqlite-dev-mode"
fi

trap cleanup_secret EXIT

BACKEND_BEFORE="$(read_defaults_backend)"
log "backend before upgrade: ${BACKEND_BEFORE}"

log "creating test secret ${TEST_SERVICE}/${TEST_ACCOUNT}/${TEST_NAME}"
"${SECKIT}" set \
  --service "${TEST_SERVICE}" \
  --account "${TEST_ACCOUNT}" \
  --name "${TEST_NAME}" \
  --value "${TEST_VALUE}" \
  ${SQLITE_DEV_FLAG} \
  || die "failed to create test secret (on Linux sqlite, ensure SECKIT_SQLITE_DEVELOPER_MODE=1)"

VALUE_BEFORE="$("${SECKIT}" get \
  --service "${TEST_SERVICE}" \
  --account "${TEST_ACCOUNT}" \
  --name "${TEST_NAME}" \
  --raw \
  ${SQLITE_DEV_FLAG})"
VALUE_BEFORE="${VALUE_BEFORE%%$'\n'}"
[[ "${VALUE_BEFORE}" == "${TEST_VALUE}" ]] || die "pre-upgrade secret value mismatch"

log "running upgrade"
if [[ -n "${INSTALL_SCRIPT}" ]]; then
  [[ -f "${INSTALL_SCRIPT}" ]] || die "install script not found: ${INSTALL_SCRIPT}"
  if [[ "${VERBOSE}" -eq 1 ]]; then
    bash "${INSTALL_SCRIPT}" --upgrade --yes
  else
    bash "${INSTALL_SCRIPT}" --upgrade --yes >/dev/null
  fi
else
  if [[ "${VERBOSE}" -eq 1 ]]; then
    curl -fsSL "${INSTALL_URL}" | bash -s -- --upgrade --yes
  else
    curl -fsSL "${INSTALL_URL}" | bash -s -- --upgrade --yes >/dev/null
  fi
fi

BACKEND_AFTER="$(read_defaults_backend)"
[[ "${BACKEND_AFTER}" == "${BACKEND_BEFORE}" ]] \
  || die "backend changed: ${BACKEND_BEFORE} -> ${BACKEND_AFTER}"

VALUE_AFTER="$("${SECKIT}" get \
  --service "${TEST_SERVICE}" \
  --account "${TEST_ACCOUNT}" \
  --name "${TEST_NAME}" \
  --raw \
  ${SQLITE_DEV_FLAG})"
VALUE_AFTER="${VALUE_AFTER%%$'\n'}"
[[ "${VALUE_AFTER}" == "${TEST_VALUE}" ]] \
  || die "post-upgrade secret value mismatch (expected ${TEST_VALUE}, got ${VALUE_AFTER})"

log "post-upgrade install validation"
VALIDATION_ARGS=()
[[ "${VERBOSE}" -eq 1 ]] && VALIDATION_ARGS+=(--verbose)
bash "${SCRIPT_DIR}/install-validation.sh" "${VALIDATION_ARGS[@]}"

cleanup_secret
trap - EXIT

log "upgrade validation passed"
exit 0
