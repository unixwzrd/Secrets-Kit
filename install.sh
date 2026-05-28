#!/usr/bin/env bash
# Secrets-Kit operator installer (curl | bash).
set -euo pipefail

# Baked in per release (must match pyproject.toml version with a leading v).
SECKIT_REF_BAKED="v2.0.0a1"
SECKIT_INSTALL_URL="${SECKIT_INSTALL_URL:-https://raw.githubusercontent.com/unixwzrd/Secrets-Kit/v2.0.0a1/install.sh}"
SECKIT_REF="${SECKIT_REF:-}"
SECKIT_MANAGED_VENV="${SECKIT_MANAGED_VENV:-$HOME/.local/share/seckit/venv}"
SECKIT_INSTALL_STATE="${SECKIT_INSTALL_STATE:-$HOME/.config/seckit/install.json}"
SECKIT_REPO_URL="${SECKIT_REPO_URL:-https://github.com/unixwzrd/Secrets-Kit.git}"
SECKIT_INSTALL_ROOT="${SECKIT_INSTALL_ROOT:-$PWD}"

UPGRADE=0
DEV_MODE=0
YES=0
NO_INIT=0
NO_VERIFY=0
DRY_RUN=0
JSON_OUT=0

install_log() {
  printf 'seckit-install: %s\n' "$*" >&2
}

install_warn() {
  printf 'seckit-install: warning: %s\n' "$*" >&2
}

install_die() {
  printf 'seckit-install: error: %s\n' "$*" >&2
  exit 1
}

install_supported_os() {
  case "$(uname -s)" in
    Darwin | Linux) return 0 ;;
    *) return 1 ;;
  esac
}

install_python_missing_help() {
  cat >&2 <<'EOF'
seckit-install: Python 3.9+ is required before running this installer.
This script does not download, bundle, or install Python for you.

Options:
  1. Install Python 3.9+ on this machine, then re-run install.sh.
  2. Point at an existing interpreter:
       SECKIT_PYTHON=/path/to/python3 install.sh
  3. Re-use a previous managed install if ~/.local/share/seckit/venv still exists.

macOS: https://www.python.org/downloads/macos/  or  brew install python3
Linux: install python3.9+ from your distribution (package manager).
EOF
}

_json_escape() {
  local s="${1-}"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/\\r}"
  s="${s//$'\t'/\\t}"
  printf '%s' "$s"
}

install_state_field() {
  local key="${1:?key required}"
  local file="${SECKIT_INSTALL_STATE}"
  local line=""

  [[ -f "$file" ]] || return 1
  line="$(grep -E "^[[:space:]]*\"${key}\"" "$file" 2>/dev/null | head -1)" || return 1
  if [[ "$line" =~ \"${key}\"[[:space:]]*:[[:space:]]*\"([^\"]*)\" ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
    return 0
  fi
  return 1
}

python_bin_dir() {
  dirname "${PYTHON}"
}

python_version_ok() {
  local py="${1:?python path required}"
  local ver="" major="" minor=""

  [[ -x "${py}" ]] || return 1
  ver="$("${py}" --version 2>&1)" || return 1
  if [[ "${ver}" =~ [Pp]ython[[:space:]]+([0-9]+)\.([0-9]+) ]]; then
    major="${BASH_REMATCH[1]}"
    minor="${BASH_REMATCH[2]}"
    if (( major > 3 || (major == 3 && minor >= 9) )); then
      return 0
    fi
  fi
  return 1
}

resolve_seckit_python() {
  if [[ -z "${SECKIT_PYTHON:-}" ]]; then
    return 1
  fi
  if python_version_ok "${SECKIT_PYTHON}"; then
    printf '%s' "${SECKIT_PYTHON}"
    return 0
  fi
  install_die "SECKIT_PYTHON is not executable or is older than 3.9: ${SECKIT_PYTHON}"
}

discover_python_on_path() {
  local candidate=""
  for candidate in "$(command -v python3 2>/dev/null || true)" "$(command -v python 2>/dev/null || true)"; do
    [[ -n "${candidate}" && -x "${candidate}" ]] || continue
    if python_version_ok "${candidate}"; then
      printf '%s' "${candidate}"
      return 0
    fi
  done
  return 1
}

create_managed_venv() {
  local bootstrap_py="${1:?bootstrap interpreter required}"
  if ! python_version_ok "${bootstrap_py}"; then
    install_die "cannot create managed venv: ${bootstrap_py} is not Python 3.9+"
  fi
  install_log "creating managed venv at ${SECKIT_MANAGED_VENV} using ${bootstrap_py}"
  mkdir -p "$(dirname "${SECKIT_MANAGED_VENV}")"
  "${bootstrap_py}" -m venv "${SECKIT_MANAGED_VENV}"
  PYTHON="${SECKIT_MANAGED_VENV}/bin/python"
  if ! python_version_ok "${PYTHON}"; then
    install_die "managed venv was created but ${PYTHON} is not usable"
  fi
  SECKIT_INSTALL_METHOD="managed"
  SECKIT_VENV_PATH="${SECKIT_MANAGED_VENV}"
}

_use_interpreter() {
  local py="${1:?}" method="${2:?}" venv_path="${3:-}"
  if ! python_version_ok "${py}"; then
    install_die "interpreter is not Python 3.9+: ${py}"
  fi
  PYTHON="${py}"
  SECKIT_INSTALL_METHOD="${method}"
  SECKIT_VENV_PATH="${venv_path}"
}

resolve_python() {
  PYTHON=""
  SECKIT_INSTALL_METHOD=""
  SECKIT_VENV_PATH=""

  if [[ -n "${CONDA_PREFIX:-}" && -x "${CONDA_PREFIX}/bin/python" ]]; then
    _use_interpreter "${CONDA_PREFIX}/bin/python" "conda" ""
    return 0
  fi
  if [[ -n "${VIRTUAL_ENV:-}" && -x "${VIRTUAL_ENV}/bin/python" ]]; then
    _use_interpreter "${VIRTUAL_ENV}/bin/python" "venv" "${VIRTUAL_ENV}"
    return 0
  fi
  if [[ -x "${SECKIT_MANAGED_VENV}/bin/python" ]]; then
    _use_interpreter "${SECKIT_MANAGED_VENV}/bin/python" "managed" "${SECKIT_MANAGED_VENV}"
    return 0
  fi

  local explicit=""
  explicit="$(resolve_seckit_python || true)"
  if [[ -n "${explicit}" ]]; then
    _use_interpreter "${explicit}" "explicit" ""
    return 0
  fi

  local discovered=""
  discovered="$(discover_python_on_path || true)"
  if [[ -n "${discovered}" ]]; then
    create_managed_venv "${discovered}"
    return 0
  fi

  install_python_missing_help
  install_die "no Python 3.9+ interpreter found"
}

resolve_python_for_upgrade() {
  PYTHON=""
  SECKIT_INSTALL_METHOD=""
  SECKIT_VENV_PATH=""

  if [[ -f "${SECKIT_INSTALL_STATE}" ]]; then
    local recorded="" method="" venv_path=""
    recorded="$(install_state_field interpreter || true)"
    if [[ -n "${recorded}" && -x "${recorded}" ]]; then
      if ! python_version_ok "${recorded}"; then
        install_warn "recorded interpreter is not Python 3.9+: ${recorded}"
      else
        PYTHON="${recorded}"
        method="$(install_state_field install_method || true)"
        SECKIT_INSTALL_METHOD="${method:-unknown}"
        venv_path="$(install_state_field venv_path || true)"
        SECKIT_VENV_PATH="${venv_path}"
        install_log "upgrade: reusing interpreter ${PYTHON}"
        return 0
      fi
    elif [[ -n "${recorded}" ]]; then
      install_warn "recorded interpreter missing or not executable: ${recorded}"
    fi
  else
    install_warn "no install state at ${SECKIT_INSTALL_STATE}; resolving environment"
  fi

  resolve_python
}

validate_python() {
  local ver=""
  if [[ -z "${PYTHON:-}" || ! -x "${PYTHON}" ]]; then
    install_die "no Python interpreter selected"
  fi
  if ! python_version_ok "${PYTHON}"; then
    install_die "selected interpreter is not Python 3.9+: ${PYTHON}"
  fi
  ver="$("${PYTHON}" --version 2>&1)" || install_die "could not read Python version from ${PYTHON}"
  install_log "${ver} ($(uname -s) $(uname -m))"

  if ! "${PYTHON}" -m pip --version >/dev/null 2>&1; then
    install_die "pip not available for ${PYTHON}; run: ${PYTHON} -m ensurepip --upgrade"
  fi

  case "$(uname -s)" in
    Darwin)
      if ! command -v security >/dev/null 2>&1; then
        install_warn "security CLI not found; macOS keychain backend may not work"
      fi
      ;;
    Linux)
      install_log "Linux default backend is sqlite (use sqlite_dev_mode for developer workflows)"
      ;;
  esac
}

pip_vcs_url() {
  printf '%s' "git+${SECKIT_REPO_URL}@${SECKIT_REF}"
}

pip_install_seckit() {
  local spec=""
  spec="$(pip_vcs_url)"
  install_log "installing ${spec}"
  "${PYTHON}" -m pip install "${spec}"
}

pip_upgrade_seckit() {
  local spec=""
  spec="$(pip_vcs_url)"
  install_log "upgrading ${spec}"
  "${PYTHON}" -m pip install --upgrade "${spec}"
}

pip_install_dev() {
  local repo_root="${1:?repo root required}"
  if [[ ! -f "${repo_root}/pyproject.toml" ]]; then
    install_die "--dev requires a local checkout containing pyproject.toml (set SECKIT_INSTALL_ROOT)"
  fi
  install_log "editable dev install from ${repo_root}"
  (cd "${repo_root}" && "${PYTHON}" -m pip install -e '.[dev]')
}

seckit_installed_version() {
  local bin="" version=""
  bin="$(python_bin_dir)/seckit"
  if [[ ! -x "${bin}" ]]; then
    printf '%s' "unknown"
    return 0
  fi
  version="$("${bin}" --version 2>/dev/null | awk 'NF { print $2; exit }')"
  if [[ -z "${version}" ]]; then
    printf '%s' "unknown"
  else
    printf '%s' "${version}"
  fi
}

write_install_state() {
  local version="" interpreter_escaped="" method_escaped="" venv_escaped="" version_escaped="" ref_escaped=""
  version="$(seckit_installed_version)"
  interpreter_escaped="$(_json_escape "${PYTHON}")"
  method_escaped="$(_json_escape "${SECKIT_INSTALL_METHOD}")"
  version_escaped="$(_json_escape "${version}")"
  ref_escaped="$(_json_escape "${SECKIT_REF}")"
  if [[ -n "${SECKIT_VENV_PATH:-}" ]]; then
    venv_escaped="$(_json_escape "${SECKIT_VENV_PATH}")"
  fi

  mkdir -p "$(dirname "${SECKIT_INSTALL_STATE}")"
  if [[ -n "${venv_escaped:-}" ]]; then
    cat >"${SECKIT_INSTALL_STATE}" <<EOF
{
  "interpreter": "${interpreter_escaped}",
  "venv_path": "${venv_escaped}",
  "install_method": "${method_escaped}",
  "version": "${version_escaped}",
  "ref": "${ref_escaped}"
}
EOF
  else
    cat >"${SECKIT_INSTALL_STATE}" <<EOF
{
  "interpreter": "${interpreter_escaped}",
  "venv_path": null,
  "install_method": "${method_escaped}",
  "version": "${version_escaped}",
  "ref": "${ref_escaped}"
}
EOF
  fi
}

run_seckit() {
  local bin_dir=""
  bin_dir="$(python_bin_dir)"
  if [[ -x "${bin_dir}/seckit" ]]; then
    "${bin_dir}/seckit" "$@"
    return $?
  fi
  if command -v seckit >/dev/null 2>&1; then
    seckit "$@"
    return $?
  fi
  install_die "seckit not found on PATH after install"
}

preflight_install() {
  if ! install_supported_os; then
    install_die "unsupported OS; macOS and Linux only"
  fi
  mkdir -p "$(dirname "${SECKIT_INSTALL_STATE}")"
  if ! touch "$(dirname "${SECKIT_INSTALL_STATE}")/.write_test" 2>/dev/null; then
    install_die "~/.config/seckit is not writable"
  fi
  rm -f "$(dirname "${SECKIT_INSTALL_STATE}")/.write_test"
}

install_print_finish() {
  local bin_dir=""
  bin_dir="$(python_bin_dir)"
  install_log "done (ref=${SECKIT_REF}, method=${SECKIT_INSTALL_METHOD})"
  if [[ "${SECKIT_INSTALL_METHOD}" == "managed" && -d "${bin_dir}" ]]; then
    install_log "add seckit to your shell PATH:"
    printf '  export PATH="%s:$PATH"\n' "${bin_dir}" >&2
  fi
  install_log "next: seckit --version && seckit info"
}

usage() {
  cat <<EOF
Secrets-Kit installer

Typical install (no options required):
  curl -fsSL ${SECKIT_INSTALL_URL} | bash

  Requires Python 3.9+ already installed (this script does not install Python).
  Installs the seckit CLI, runs first-time setup (seckit init), and verifies the install.
  Python order: active conda, active venv, managed venv, SECKIT_PYTHON, then python3 on PATH.

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
  SECKIT_PYTHON         Explicit Python 3.9+ interpreter (required if python3 is not on PATH)
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
    resolve_python_for_upgrade
  else
    resolve_python
  fi

  validate_python
  install_log "using ${PYTHON} (method=${SECKIT_INSTALL_METHOD})"

  if [[ "${DEV_MODE}" -eq 1 ]]; then
    pip_install_dev "${SECKIT_INSTALL_ROOT}"
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
