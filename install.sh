#!/usr/bin/env bash
# Secrets-Kit operator installer (curl | bash compatible, standalone).
set -euo pipefail

SECKIT_REF_BAKED="v2.0.0a2"
SECKIT_INSTALL_URL="${SECKIT_INSTALL_URL:-https://raw.githubusercontent.com/unixwzrd/Secrets-Kit/v2.0.0a2/install.sh}"
SECKIT_REF="${SECKIT_REF:-}"
SECKIT_REPO_URL="${SECKIT_REPO_URL:-https://github.com/unixwzrd/Secrets-Kit.git}"
SECKIT_INSTALL_ROOT="${SECKIT_INSTALL_ROOT:-$PWD}"

SECKIT_SHARE_DIR="${SECKIT_SHARE_DIR:-$HOME/.local/share/seckit}"
SECKIT_RUNTIME_DIR="${SECKIT_RUNTIME_DIR:-$SECKIT_SHARE_DIR/runtime}"
SECKIT_STATE_DIR="${SECKIT_STATE_DIR:-$SECKIT_SHARE_DIR/state}"
SECKIT_CACHE_DIR="${SECKIT_CACHE_DIR:-$SECKIT_SHARE_DIR/cache}"
SECKIT_RUNTIME_PATH_FILE="${SECKIT_RUNTIME_PATH_FILE:-$SECKIT_STATE_DIR/runtime-path}"
SECKIT_RUNTIME_JSON="${SECKIT_RUNTIME_JSON:-$SECKIT_STATE_DIR/runtime.json}"
SECKIT_INSTALL_LOG="${SECKIT_INSTALL_LOG:-$SECKIT_STATE_DIR/install.log}"
SECKIT_LAUNCHER_BIN_DIR="${SECKIT_LAUNCHER_BIN_DIR:-$HOME/.local/bin}"
SECKIT_LAUNCHER_PATH="${SECKIT_LAUNCHER_PATH:-$SECKIT_LAUNCHER_BIN_DIR/seckit}"

SECKIT_CONFIG_DIR="${SECKIT_CONFIG_DIR:-$HOME/.config/seckit}"
SECKIT_INSTALL_STATE="${SECKIT_INSTALL_STATE:-$SECKIT_CONFIG_DIR/install.json}"

UPGRADE=0
REPAIR=0
DEV_MODE=0
YES=0
NO_INIT=0
NO_VERIFY=0
DRY_RUN=0
JSON_OUT=0
VERBOSE=0
SAFE_MODE=0
NO_UV_DOWNLOAD=0
NO_SHELL_PROFILE=0
SHELL_PROFILE_FORCE=0
SECKIT_DEBUG="${SECKIT_DEBUG:-0}"

PYTHON=""
UV_BIN=""
INSTALL_METHOD=""
TARGET_RUNTIME=""
CURRENT_RUNTIME=""
IS_INTERACTIVE=0
PROFILE_CHANGED=0
PROFILE_CHANGED_FILE=""
PROFILE_BACKUP_FILE=""

if [[ -t 0 && -t 1 ]]; then
  IS_INTERACTIVE=1
fi
if [[ "${SECKIT_DEBUG}" == "1" ]]; then
  VERBOSE=1
fi

install_log() { printf 'seckit-install: %s\n' "$*" >&2; }
install_warn() { printf 'seckit-install: warning: %s\n' "$*" >&2; }
install_die() { printf 'seckit-install: error: %s\n' "$*" >&2; exit 1; }
verbose_log() { [[ "${VERBOSE}" -eq 1 ]] && install_log "$*"; }
step() { printf '[%s/5] %s\n' "$1" "$2" >&2; }

append_log() {
  mkdir -p "$(dirname "${SECKIT_INSTALL_LOG}")"
  printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >>"${SECKIT_INSTALL_LOG}"
}

install_supported_os() {
  case "$(uname -s)" in
    Darwin|Linux) return 0 ;;
    *) return 1 ;;
  esac
}

python_version_ok() {
  local py="${1:?}" ver major minor
  [[ -x "${py}" ]] || return 1
  ver="$(${py} --version 2>&1)" || return 1
  if [[ "${ver}" =~ [Pp]ython[[:space:]]+([0-9]+)\.([0-9]+) ]]; then
    major="${BASH_REMATCH[1]}"
    minor="${BASH_REMATCH[2]}"
    (( major > 3 || (major == 3 && minor >= 9) ))
    return $?
  fi
  return 1
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

run_capture() {
  local out_file err_file rc
  out_file="$(mktemp -t seckit-install-out.XXXXXX)"
  err_file="$(mktemp -t seckit-install-err.XXXXXX)"
  if [[ "${VERBOSE}" -eq 1 ]]; then
    append_log "RUN $*"
    "$@"
    return $?
  fi
  append_log "RUN $*"
  "$@" >"${out_file}" 2>"${err_file}" || rc=$?
  rc="${rc:-0}"
  if [[ "${rc}" -ne 0 ]]; then
    [[ -s "${out_file}" ]] && sed 's/^/  /' "${out_file}" >&2
    [[ -s "${err_file}" ]] && sed 's/^/  /' "${err_file}" >&2
    [[ -s "${out_file}" ]] && cat "${out_file}" >>"${SECKIT_INSTALL_LOG}"
    [[ -s "${err_file}" ]] && cat "${err_file}" >>"${SECKIT_INSTALL_LOG}"
  fi
  rm -f "${out_file}" "${err_file}"
  return "${rc}"
}

atomic_write_text() {
  local target="${1:?}" content="${2:-}" tmp
  tmp="${target}.tmp.$$"
  printf '%s' "${content}" >"${tmp}"
  sync "${tmp}" 2>/dev/null || true
  mv -f "${tmp}" "${target}"
}

atomic_write_file_from() {
  local target="${1:?}" src="${2:?}" tmp
  tmp="${target}.tmp.$$"
  cp "${src}" "${tmp}"
  sync "${tmp}" 2>/dev/null || true
  mv -f "${tmp}" "${target}"
}

read_runtime_path() {
  [[ -f "${SECKIT_RUNTIME_PATH_FILE}" ]] || return 1
  local p
  p="$(tr -d '\r' <"${SECKIT_RUNTIME_PATH_FILE}" | head -1)"
  [[ -n "${p}" ]] || return 1
  printf '%s' "${p}"
}

find_python_candidate() {
  local candidate=""

  if [[ -n "${CONDA_PREFIX:-}" && -x "${CONDA_PREFIX}/bin/python" ]] && python_version_ok "${CONDA_PREFIX}/bin/python"; then
    INSTALL_METHOD="conda"
    printf '%s' "${CONDA_PREFIX}/bin/python"
    return 0
  fi
  if [[ -n "${VIRTUAL_ENV:-}" && -x "${VIRTUAL_ENV}/bin/python" ]] && python_version_ok "${VIRTUAL_ENV}/bin/python"; then
    INSTALL_METHOD="venv"
    printf '%s' "${VIRTUAL_ENV}/bin/python"
    return 0
  fi

  CURRENT_RUNTIME="$(read_runtime_path || true)"
  if [[ -n "${CURRENT_RUNTIME}" && -x "${CURRENT_RUNTIME}/bin/python" ]] && python_version_ok "${CURRENT_RUNTIME}/bin/python"; then
    INSTALL_METHOD="managed"
    printf '%s' "${CURRENT_RUNTIME}/bin/python"
    return 0
  fi

  if [[ -n "${SECKIT_PYTHON:-}" ]]; then
    if python_version_ok "${SECKIT_PYTHON}"; then
      INSTALL_METHOD="explicit"
      printf '%s' "${SECKIT_PYTHON}"
      return 0
    fi
    install_die "SECKIT_PYTHON is not executable or is older than 3.9: ${SECKIT_PYTHON}"
  fi

  for candidate in "$(command -v python3 2>/dev/null || true)" "$(command -v python 2>/dev/null || true)"; do
    [[ -n "${candidate}" && -x "${candidate}" ]] || continue
    if python_version_ok "${candidate}"; then
      INSTALL_METHOD="path"
      printf '%s' "${candidate}"
      return 0
    fi
  done
  return 1
}

uv_bootstrap_blocked() {
  [[ "${NO_UV_DOWNLOAD}" -eq 1 || "${SAFE_MODE}" -eq 1 ]]
}

resolve_uv() {
  if command -v uv >/dev/null 2>&1; then
    UV_BIN="$(command -v uv)"
    verbose_log "using existing runtime tool: ${UV_BIN}"
    return 0
  fi
  if [[ -x "${HOME}/.local/bin/uv" ]]; then
    UV_BIN="${HOME}/.local/bin/uv"
    verbose_log "using existing runtime tool: ${UV_BIN}"
    return 0
  fi

  if uv_bootstrap_blocked; then
    install_die "runtime bootstrap unavailable (--safe or --no-uv-download). Install Python 3.9+ and retry without those flags, or use a host with runtime tooling already present."
  fi

  install_log "Preparing isolated runtime environment..."
  verbose_log "runtime tool not found; bootstrapping via network"

  if [[ "${IS_INTERACTIVE}" -eq 1 && "${YES}" -eq 0 && -t 1 ]]; then
    local reply=""
    printf 'Download and install runtime components? [Y/n] ' >&2
    read -r reply </dev/tty || reply=""
    case "${reply}" in
      [nN]|[nN][oO]) install_die "install cancelled" ;;
    esac
  fi

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    return 0
  fi
  run_capture sh -c "curl -LsSf https://astral.sh/uv/install.sh | sh" \
    || install_die "failed preparing isolated runtime environment"
  if command -v uv >/dev/null 2>&1; then
    UV_BIN="$(command -v uv)"
    verbose_log "bootstrapped runtime tool: ${UV_BIN}"
    return 0
  fi
  if [[ -x "${HOME}/.local/bin/uv" ]]; then
    UV_BIN="${HOME}/.local/bin/uv"
    verbose_log "bootstrapped runtime tool: ${UV_BIN}"
    return 0
  fi
  install_die "runtime bootstrap reported success but the environment is still unavailable"
}

ensure_dirs() {
  mkdir -p "${SECKIT_RUNTIME_DIR}" "${SECKIT_STATE_DIR}" "${SECKIT_CACHE_DIR}" "${SECKIT_CONFIG_DIR}" "${SECKIT_LAUNCHER_BIN_DIR}"
}

next_runtime_generation() {
  local stamp idx candidate
  stamp="$(date +%Y%m%d)"
  idx=1
  while :; do
    candidate="${SECKIT_RUNTIME_DIR}/runtime-${stamp}-$(printf '%03d' "${idx}")"
    if [[ ! -e "${candidate}" ]]; then
      printf '%s' "${candidate}"
      return 0
    fi
    idx=$((idx + 1))
  done
}

create_runtime() {
  TARGET_RUNTIME="$(next_runtime_generation)"
  verbose_log "creating runtime: ${TARGET_RUNTIME}"

  local -a cmd=("${UV_BIN}" venv "${TARGET_RUNTIME}" --python "${PYTHON}")
  [[ "${VERBOSE}" -eq 1 ]] || cmd+=(--quiet)
  UV_CACHE_DIR="${SECKIT_CACHE_DIR}" run_capture "${cmd[@]}" || install_die "failed creating uv runtime"
}

uv_install_secrets_kit() {
  local spec="" mode="${1:?}"
  if [[ "${DEV_MODE}" -eq 1 ]]; then
    [[ -f "${SECKIT_INSTALL_ROOT}/pyproject.toml" ]] || install_die "--dev requires local checkout containing pyproject.toml"
    spec="-e .[dev]"
  else
    spec="git+${SECKIT_REPO_URL}@${SECKIT_REF}"
  fi

  local -a cmd=("${UV_BIN}" pip install --python "${TARGET_RUNTIME}/bin/python")
  [[ "${mode}" == "upgrade" ]] && cmd+=(--upgrade)
  [[ "${VERBOSE}" -eq 1 ]] || cmd+=(--quiet)

  if [[ "${DEV_MODE}" -eq 1 ]]; then
    append_log "RUN (cd ${SECKIT_INSTALL_ROOT} && ${cmd[*]} ${spec})"
    (cd "${SECKIT_INSTALL_ROOT}" && UV_CACHE_DIR="${SECKIT_CACHE_DIR}" run_capture "${cmd[@]}" "${spec}") || install_die "failed installing editable seckit"
  else
    UV_CACHE_DIR="${SECKIT_CACHE_DIR}" run_capture "${cmd[@]}" "${spec}" || install_die "failed installing seckit"
  fi
}

write_runtime_state() {
  local runtime_json current_link_tmp
  runtime_json="$(mktemp -t seckit-runtime-json.XXXXXX)"
  cat >"${runtime_json}" <<EOF_JSON
{
  "runtime": "$(_json_escape "${TARGET_RUNTIME}")",
  "method": "$(_json_escape "${INSTALL_METHOD}")",
  "python": "$(_json_escape "${PYTHON}")",
  "uv": "$(_json_escape "${UV_BIN}")",
  "ref": "$(_json_escape "${SECKIT_REF}")"
}
EOF_JSON
  atomic_write_file_from "${SECKIT_RUNTIME_JSON}" "${runtime_json}"
  rm -f "${runtime_json}"

  atomic_write_text "${SECKIT_RUNTIME_PATH_FILE}" "${TARGET_RUNTIME}\n"

  current_link_tmp="${SECKIT_RUNTIME_DIR}/current.tmp.$$"
  ln -sfn "${TARGET_RUNTIME}" "${current_link_tmp}"
  mv -f "${current_link_tmp}" "${SECKIT_RUNTIME_DIR}/current"
}

write_install_state() {
  local version install_json
  version="$(${TARGET_RUNTIME}/bin/seckit --version 2>/dev/null | awk 'NF {print $2; exit}')"
  install_json="$(mktemp -t seckit-install-json.XXXXXX)"
  cat >"${install_json}" <<EOF_JSON
{
  "version": "$(_json_escape "${version:-unknown}")",
  "ref": "$(_json_escape "${SECKIT_REF}")",
  "method": "uv",
  "updated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF_JSON
  atomic_write_file_from "${SECKIT_INSTALL_STATE}" "${install_json}"
  rm -f "${install_json}"
}

write_launcher() {
  local launcher
  launcher="$(mktemp -t seckit-launcher.XXXXXX)"
  cat >"${launcher}" <<'EOF_LAUNCH'
#!/usr/bin/env bash
set -euo pipefail
STATE_DIR="${SECKIT_STATE_DIR_OVERRIDE:-$HOME/.local/share/seckit/state}"
RUNTIME_PATH_FILE="${STATE_DIR}/runtime-path"
if [[ ! -f "${RUNTIME_PATH_FILE}" ]]; then
  echo "seckit launcher: runtime path missing (${RUNTIME_PATH_FILE})" >&2
  exit 1
fi
RUNTIME_DIR="$(head -1 "${RUNTIME_PATH_FILE}" | tr -d '\r')"
if [[ -z "${RUNTIME_DIR}" || ! -x "${RUNTIME_DIR}/bin/seckit" ]]; then
  echo "seckit launcher: invalid runtime path (${RUNTIME_DIR})" >&2
  exit 1
fi
exec "${RUNTIME_DIR}/bin/seckit" "$@"
EOF_LAUNCH
  chmod 755 "${launcher}"
  atomic_write_file_from "${SECKIT_LAUNCHER_PATH}" "${launcher}"
  rm -f "${launcher}"
}

detect_shell_profile() {
  local shell_name
  shell_name="$(basename "${SHELL:-}")"
  case "${shell_name}" in
    zsh) printf '%s' "${HOME}/.zshrc" ;;
    bash)
      if [[ -f "${HOME}/.bashrc" ]]; then
        printf '%s' "${HOME}/.bashrc"
      else
        printf '%s' "${HOME}/.bash_profile"
      fi
      ;;
    *) printf '' ;;
  esac
}

apply_shell_profile_block() {
  local profile tmp begin end line
  begin="# >>> seckit path >>>"
  end="# <<< seckit path <<<"
  line="export PATH=\"${SECKIT_LAUNCHER_BIN_DIR}:\$PATH\""

  if [[ "${NO_SHELL_PROFILE}" -eq 1 || "${SAFE_MODE}" -eq 1 ]]; then
    install_log "PATH hint: export PATH=\"${SECKIT_LAUNCHER_BIN_DIR}:\$PATH\""
    return 0
  fi
  if [[ "${IS_INTERACTIVE}" -ne 1 && "${SHELL_PROFILE_FORCE}" -ne 1 ]]; then
    install_log "PATH hint: export PATH=\"${SECKIT_LAUNCHER_BIN_DIR}:\$PATH\""
    return 0
  fi

  profile="$(detect_shell_profile)"
  if [[ -z "${profile}" ]]; then
    install_log "PATH hint: export PATH=\"${SECKIT_LAUNCHER_BIN_DIR}:\$PATH\""
    return 0
  fi

  mkdir -p "$(dirname "${profile}")"
  touch "${profile}"

  tmp="$(mktemp -t seckit-profile.XXXXXX)"
  awk -v b="${begin}" -v e="${end}" '
    BEGIN { skip=0 }
    {
      if ($0 == b) { skip=1; next }
      if (skip == 1 && $0 == e) { skip=0; next }
      if (skip == 0) print
    }
  ' "${profile}" >"${tmp}"

  PROFILE_BACKUP_FILE="${profile}.seckit.bak.$$"
  cp "${profile}" "${PROFILE_BACKUP_FILE}"
  {
    cat "${tmp}"
    printf '\n%s\n%s\n%s\n' "${begin}" "${line}" "${end}"
  } >"${profile}"
  rm -f "${tmp}"

  PROFILE_CHANGED=1
  PROFILE_CHANGED_FILE="${profile}"
  install_log "updated shell profile: ${profile}"
}

rollback_shell_profile_if_needed() {
  if [[ "${PROFILE_CHANGED}" -eq 1 && -n "${PROFILE_CHANGED_FILE}" && -n "${PROFILE_BACKUP_FILE}" && -f "${PROFILE_BACKUP_FILE}" ]]; then
    cp "${PROFILE_BACKUP_FILE}" "${PROFILE_CHANGED_FILE}" || true
    rm -f "${PROFILE_BACKUP_FILE}" || true
  fi
}

clear_shell_profile_backup() {
  if [[ -n "${PROFILE_BACKUP_FILE}" && -f "${PROFILE_BACKUP_FILE}" ]]; then
    rm -f "${PROFILE_BACKUP_FILE}"
  fi
}

run_install_check() {
  local -a args=(doctor --install-check)
  run_capture "${TARGET_RUNTIME}/bin/seckit" "${args[@]}"
}

usage() {
  cat <<EOF
Secrets-Kit installer

Typical install:
  curl -fsSL ${SECKIT_INSTALL_URL} | bash

Upgrade:
  curl -fsSL ${SECKIT_INSTALL_URL} | bash -s -- --upgrade

Options:
  --upgrade              Upgrade runtime/package only
  --repair               Rebuild runtime/launcher while preserving config/state
  --dev                  Editable install from local checkout
  --yes                  Non-interactive init overwrite confirmations
  --no-init              Skip seckit init
  --no-verify            Skip doctor --install-check
  --ref TAG              Install from different git ref
  --repo-url URL         Install from different git repository
  --dry-run              Print planned actions only
  --json                 Emit machine-readable result
  --verbose              Verbose decision + subprocess output
  --safe                 CI/SSH: no shell profile edits, no runtime bootstrap download
  --no-uv-download       Do not download runtime tooling; fail if unavailable
  --no-shell-profile     Never modify shell startup files
  --shell-profile-force  Allow profile edits in non-interactive mode
  -h, --help             Show this help
EOF
}

preflight_install() {
  install_supported_os || install_die "unsupported OS (macOS and Linux only)"
  ensure_dirs
  append_log "--- installer start pid=$$ ---"
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --ref) SECKIT_REF="${2:?--ref requires a value}"; shift 2 ;;
      --repo-url) SECKIT_REPO_URL="${2:?--repo-url requires a value}"; shift 2 ;;
      --upgrade) UPGRADE=1; shift ;;
      --repair) REPAIR=1; UPGRADE=1; NO_INIT=1; shift ;;
      --dev) DEV_MODE=1; shift ;;
      --yes) YES=1; shift ;;
      --no-init) NO_INIT=1; shift ;;
      --no-verify) NO_VERIFY=1; shift ;;
      --dry-run) DRY_RUN=1; shift ;;
      --json) JSON_OUT=1; shift ;;
      --verbose) VERBOSE=1; shift ;;
      --safe) SAFE_MODE=1; NO_UV_DOWNLOAD=1; shift ;;
      --no-uv-download) NO_UV_DOWNLOAD=1; shift ;;
      --no-shell-profile) NO_SHELL_PROFILE=1; shift ;;
      --shell-profile-force) SHELL_PROFILE_FORCE=1; shift ;;
      --allow-uv-download)
        install_warn "--allow-uv-download is deprecated (default install bootstraps automatically)"
        shift
        ;;
      -h|--help) usage; exit 0 ;;
      *) install_die "unknown option: $1" ;;
    esac
  done
}

emit_json() { printf '%s\n' "$1"; }

main() {
  trap rollback_shell_profile_if_needed ERR

  parse_args "$@"
  preflight_install

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

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    install_log "dry-run: ref=${SECKIT_REF} upgrade=${UPGRADE} repair=${REPAIR} dev=${DEV_MODE}"
    install_log "dry-run: runtime root ${SECKIT_RUNTIME_DIR}"
    if [[ "${JSON_OUT}" -eq 1 ]]; then
      emit_json "{\"dry_run\":true,\"ref\":\"${SECKIT_REF}\",\"upgrade\":${UPGRADE},\"repair\":${REPAIR},\"dev\":${DEV_MODE}}"
    fi
    exit 0
  fi

  step 1 "Preparing runtime..."
  resolve_uv

  step 2 "Creating isolated runtime..."
  PYTHON="$(find_python_candidate || true)"
  [[ -n "${PYTHON}" ]] || install_die "no Python 3.9+ interpreter found"
  verbose_log "selected interpreter: ${PYTHON} (${INSTALL_METHOD})"
  create_runtime

  step 3 "Installing Secrets-Kit..."
  if [[ "${UPGRADE}" -eq 1 ]]; then
    uv_install_secrets_kit "upgrade"
  else
    uv_install_secrets_kit "install"
  fi
  write_runtime_state
  write_launcher
  write_install_state

  step 4 "Running first-time setup..."
  if [[ "${UPGRADE}" -eq 0 && "${NO_INIT}" -eq 0 ]]; then
    local -a init_args=(init)
    [[ "${YES}" -eq 1 ]] && init_args+=(--yes)
    run_capture "${TARGET_RUNTIME}/bin/seckit" "${init_args[@]}" || install_die "seckit init failed"
  else
    verbose_log "init skipped"
  fi
  apply_shell_profile_block

  step 5 "Verifying install..."
  if [[ "${NO_VERIFY}" -eq 0 ]]; then
    run_install_check || install_die "install verification failed"
  else
    verbose_log "verification skipped"
  fi

  clear_shell_profile_backup

  if [[ "${JSON_OUT}" -eq 1 ]]; then
    emit_json "{\"ok\":true,\"ref\":\"${SECKIT_REF}\",\"runtime\":\"${TARGET_RUNTIME}\",\"uv\":\"${UV_BIN}\"}"
  else
    printf '\nSecrets-Kit installed successfully.\n' >&2
    if [[ "${IS_INTERACTIVE}" -eq 0 || "${NO_SHELL_PROFILE}" -eq 1 || "${SAFE_MODE}" -eq 1 ]]; then
      install_log "PATH hint: export PATH=\"${SECKIT_LAUNCHER_BIN_DIR}:\$PATH\""
    fi
  fi
}

main "$@"
