#!/usr/bin/env bash
# Secrets-Kit operator installer (curl | bash).
set -euo pipefail

# Baked in per release (must match pyproject.toml version with a leading v).
SECKIT_REF_BAKED="v2.0.0a0"
SECKIT_INSTALL_URL="${SECKIT_INSTALL_URL:-https://raw.githubusercontent.com/unixwzrd/Secrets-Kit/v2.0.0a0/install.sh}"
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
Secrets-Kit installer

Typical install (no options required):
  curl -fsSL ${SECKIT_INSTALL_URL} | bash

  Installs the seckit CLI, runs first-time setup (seckit init), and verifies the install.
  macOS: defaults to the login Keychain backend. Linux: defaults to SQLite.
  Uses your active conda/venv if set; otherwise creates ~/.local/share/seckit/venv.

Upgrade an existing install:
  curl -fsSL ${SECKIT_INSTALL_URL} | bash -s -- --upgrade

Advanced options (non-standard installs only):
  --ref TAG           Pin a different git tag or branch for pip (default: ${SECKIT_REF_BAKED})
  --repo-url URL      Alternate Git repository (default: ${SECKIT_REPO_URL})
  --dev               Editable install from this checkout (developer clone only)
  --yes               Skip confirmation when overwriting existing config (auto-enabled when stdin is not a TTY)
  --no-init           Install the package but skip seckit init
  --no-verify         Skip seckit doctor --install-check after install
  --dry-run           Print planned actions only
  --json              Machine-readable status on stdout
  -h, --help          Show this help

Environment (advanced):
  SECKIT_MANAGED_VENV   Alternate managed venv path (default: ~/.local/share/seckit/venv)
  SECKIT_INSTALL_STATE  Alternate install state file (default: ~/.config/seckit/install.json)

Backend and config paths are set by seckit init / seckit config after install, not by install.sh.
See docs/INSTALL.md for details.
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

# curl | bash and other non-interactive installs cannot answer init prompts.
if [[ "${YES}" -eq 0 && ! -t 0 ]]; then
  YES=1
fi

if [[ -z "${SECKIT_REF}" ]]; then
  if [[ "${DEV_MODE}" -eq 1 ]]; then
    SECKIT_REF="dev"
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
    install_print_finish
  fi
}

main "$@"
