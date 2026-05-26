#!/usr/bin/env bash
# Secrets-Kit operator installer (curl | bash).
set -euo pipefail

# Baked in per release tag (override with --ref or SECKIT_REF env).
SECKIT_REF_BAKED="v1.2.3"
SECKIT_INSTALL_URL="${SECKIT_INSTALL_URL:-https://raw.githubusercontent.com/unixwzrd/Secrets-Kit/v1.2.3/install.sh}"
SECKIT_REF="${SECKIT_REF:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/install_lib.sh
source "${SCRIPT_DIR}/scripts/lib/install_lib.sh"

UPGRADE=0
DEV_MODE=0
YES=0
NO_INIT=0
NO_VERIFY=0
DRY_RUN=0
JSON_OUT=0

usage() {
  cat <<EOF
Usage: install.sh [options]

Options:
  --ref TAG           Git ref for pip install (default: ${SECKIT_REF_BAKED}, or main with --dev)
  --repo-url URL      Git repository URL (default: ${SECKIT_REPO_URL})
  --upgrade           Upgrade package only; preserve config and data
  --dev               Editable install from local repo (developer checkout)
  --yes               Non-interactive init
  --no-init           Skip seckit init on first install
  --no-verify         Skip seckit doctor --install-check
  --dry-run           Print planned actions only
  --json              Machine-readable status on stdout
  -h, --help          Show this help

Operator install:
  curl -fsSL ${SECKIT_INSTALL_URL} | bash

Upgrade:
  curl -fsSL ${SECKIT_INSTALL_URL} | bash -s -- --upgrade
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ref)
      SECKIT_REF="${2:?--ref requires a value}"
      shift 2
      ;;
    --repo-url)
      SECKIT_REPO_URL="${2:?--repo-url requires a value}"
      shift 2
      ;;
    --upgrade) UPGRADE=1; shift ;;
    --dev) DEV_MODE=1; shift ;;
    --yes) YES=1; shift ;;
    --no-init) NO_INIT=1; shift ;;
    --no-verify) NO_VERIFY=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --json) JSON_OUT=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) install_die "unknown option: $1" ;;
  esac
done

if [[ -z "${SECKIT_REF}" ]]; then
  if [[ "${DEV_MODE}" -eq 1 ]]; then
    SECKIT_REF="main"
  else
    SECKIT_REF="${SECKIT_REF_BAKED}"
  fi
fi

emit_json() {
  printf '%s\n' "$1"
}

main() {
  preflight_install

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    install_log "dry-run: ref=${SECKIT_REF} upgrade=${UPGRADE} dev=${DEV_MODE}"
    if [[ "${JSON_OUT}" -eq 1 ]]; then
      emit_json "{\"dry_run\":true,\"ref\":\"${SECKIT_REF}\",\"upgrade\":${UPGRADE},\"dev\":${DEV_MODE}}"
    fi
    exit 0
  fi

  if [[ "${UPGRADE}" -eq 1 ]]; then
    SECKIT_PYTHON_FOR_STATE="$(command -v python3 2>/dev/null || command -v python 2>/dev/null || true)"
    resolve_python_for_upgrade
  else
    resolve_python
  fi

  validate_python
  install_log "using ${PYTHON} (method=${SECKIT_INSTALL_METHOD})"

  if [[ "${DEV_MODE}" -eq 1 ]]; then
    pip_install_dev "${SCRIPT_DIR}"
  elif [[ "${UPGRADE}" -eq 1 ]]; then
    pip_upgrade_seckit
  else
    pip_install_seckit
  fi

  write_install_state

  if [[ "${UPGRADE}" -eq 0 && "${NO_INIT}" -eq 0 ]]; then
    init_args=()
    if [[ "${YES}" -eq 1 ]]; then
      init_args+=(--yes)
    fi
    run_seckit init "${init_args[@]}"
  fi

  if [[ "${NO_VERIFY}" -eq 0 ]]; then
    run_seckit doctor --install-check
  fi

  if [[ "${JSON_OUT}" -eq 1 ]]; then
    emit_json "{\"ok\":true,\"ref\":\"${SECKIT_REF}\",\"interpreter\":\"${PYTHON}\",\"install_method\":\"${SECKIT_INSTALL_METHOD}\"}"
  else
    install_log "done (ref=${SECKIT_REF})"
  fi
}

main "$@"
