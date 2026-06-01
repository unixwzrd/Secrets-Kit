#!/usr/bin/env bash
# Secrets-Kit operator installer (curl | bash compatible, standalone).
set -euo pipefail

SECKIT_GITHUB_REPO="${SECKIT_GITHUB_REPO:-unixwzrd/Secrets-Kit}"
SECKIT_INSTALL_BRANCH="${SECKIT_INSTALL_BRANCH:-dev}"
SECKIT_RELEASE_CHANNEL="${SECKIT_RELEASE_CHANNEL:-prerelease}"
SECKIT_INSTALL_URL="${SECKIT_INSTALL_URL:-https://raw.githubusercontent.com/${SECKIT_GITHUB_REPO}/${SECKIT_INSTALL_BRANCH}/install.sh}"
SECKIT_REF="${SECKIT_REF:-}"
SECKIT_REPO_URL="${SECKIT_REPO_URL:-https://github.com/${SECKIT_GITHUB_REPO}.git}"
SECKIT_RELEASE_BASE="${SECKIT_RELEASE_BASE:-}"
SECKIT_RUNTIME_PYTHON="${SECKIT_RUNTIME_PYTHON:-3.12}"
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
PREVIOUS_RUNTIME=""
PACKAGE_SOURCE=""
PACKAGE_SPEC=""
RUNTIME_PYTHON_VERSION=""
SECKIT_REF_EXPLICIT=0
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
verbose_log() {
  if [[ "${VERBOSE}" -eq 1 ]]; then
    install_log "$*"
  fi
}
step() { printf '[%s/5] %s\n' "$1" "$2" >&2; }
step_done() { install_log "[${1}/5] complete."; }

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
  p="$(head -1 "${SECKIT_RUNTIME_PATH_FILE}" | tr -d '\r' | sed -e 's/[[:space:]]*$//' -e 's/\\n$//')"
  [[ -n "${p}" ]] || return 1
  printf '%s' "${p}"
}

write_runtime_path_file() {
  local target="${1:?}" runtime_path="${2:?}" tmp
  tmp="${target}.tmp.$$"
  printf '%s\n' "${runtime_path}" >"${tmp}"
  sync "${tmp}" 2>/dev/null || true
  mv -f "${tmp}" "${target}"
}

ref_to_version() {
  local ref="${1:?}"
  ref="${ref#v}"
  printf '%s' "${ref}"
}

github_api_get() {
  local path="${1:?}"
  curl -fsSL --connect-timeout 15 --max-time 60 \
    -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/${SECKIT_GITHUB_REPO}/${path}"
}

resolve_latest_release_tag() {
  [[ -n "${SECKIT_REF}" ]] && return 0
  local json tag="" candidate_tag="" candidate_draft="" candidate_prerelease=""
  json="$(github_api_get "releases?per_page=30")" \
    || install_die "unable to query GitHub releases for ${SECKIT_GITHUB_REPO}"
  case "${SECKIT_RELEASE_CHANNEL}" in
    release|prerelease) ;;
    *) install_die "unsupported release channel: ${SECKIT_RELEASE_CHANNEL} (expected release or prerelease)" ;;
  esac

  while IFS= read -r line; do
    if [[ "${line}" =~ ^[[:space:]]{2}\{ ]]; then
      candidate_tag=""
      candidate_draft=""
      candidate_prerelease=""
    fi
    if [[ "${line}" =~ \"tag_name\"[[:space:]]*:[[:space:]]*\"([^\"]+)\" ]]; then
      candidate_tag="${BASH_REMATCH[1]}"
    elif [[ "${line}" =~ \"draft\"[[:space:]]*:[[:space:]]*(true|false) ]]; then
      candidate_draft="${BASH_REMATCH[1]}"
    elif [[ "${line}" =~ \"prerelease\"[[:space:]]*:[[:space:]]*(true|false) ]]; then
      candidate_prerelease="${BASH_REMATCH[1]}"
      [[ -n "${candidate_tag}" && "${candidate_draft}" != "true" ]] || continue
      if [[ "${SECKIT_RELEASE_CHANNEL}" == "release" && "${candidate_prerelease}" == "true" ]]; then
        continue
      fi
      if [[ "${SECKIT_RELEASE_CHANNEL}" == "prerelease" && "${candidate_prerelease}" != "true" ]]; then
        continue
      fi
      tag="${candidate_tag}"
      break
    fi
  done <<<"${json}"
  [[ -n "${tag}" ]] || install_die "no GitHub release found (channel=${SECKIT_RELEASE_CHANNEL})"
  SECKIT_REF="${tag}"
  install_log "Using release: ${SECKIT_REF}"
  verbose_log "release channel: ${SECKIT_RELEASE_CHANNEL}"
}

release_download_base() {
  if [[ -n "${SECKIT_RELEASE_BASE}" ]]; then
    printf '%s' "${SECKIT_RELEASE_BASE}"
    return 0
  fi
  printf '%s' "https://github.com/${SECKIT_GITHUB_REPO}/releases/download/${SECKIT_REF}"
}

artifact_url_exists() {
  local url="${1:?}"
  curl -fsSIL --connect-timeout 15 --max-time 60 "${url}" >/dev/null 2>&1
}

pick_release_asset_url() {
  local base version wheel_url sdist_url source_url
  base="$(release_download_base)"
  version="$(ref_to_version "${SECKIT_REF}")"
  wheel_url="${base}/seckit-${version}-py3-none-any.whl"
  sdist_url="${base}/seckit-${version}.tar.gz"
  source_url="https://github.com/${SECKIT_GITHUB_REPO}/archive/refs/tags/${SECKIT_REF}.tar.gz"
  if artifact_url_exists "${wheel_url}"; then
    printf '%s' "${wheel_url}"
    return 0
  fi
  if artifact_url_exists "${sdist_url}"; then
    printf '%s' "${sdist_url}"
    return 0
  fi
  if artifact_url_exists "${source_url}"; then
    install_warn "release assets missing for ${SECKIT_REF}; installing tagged source archive"
    printf '%s' "${source_url}"
    return 0
  fi
  install_die "no compatible release artifact found in ${SECKIT_REF} (expected seckit-${version}-py3-none-any.whl, seckit-${version}.tar.gz, or tag source archive)"
}

resolve_release_artifact_url() {
  if [[ -n "${SECKIT_WHEEL_URL:-}" ]]; then
    printf '%s' "${SECKIT_WHEEL_URL}"
    return 0
  fi
  pick_release_asset_url
}

resolve_package_spec() {
  if [[ "${DEV_MODE}" -eq 1 ]]; then
    [[ -f "${SECKIT_INSTALL_ROOT}/pyproject.toml" ]] || install_die "--dev requires local checkout containing pyproject.toml"
    PACKAGE_SOURCE="editable"
    PACKAGE_SPEC="-e .[dev]"
    return 0
  fi
  if [[ "${SECKIT_REF_EXPLICIT}" -eq 1 ]]; then
    PACKAGE_SOURCE="git"
    PACKAGE_SPEC="git+${SECKIT_REPO_URL}@${SECKIT_REF}"
    return 0
  fi
  PACKAGE_SOURCE="release"
  PACKAGE_SPEC="$(resolve_release_artifact_url)"
  if [[ "${PACKAGE_SPEC}" == file://* ]]; then
    [[ -f "${PACKAGE_SPEC#file://}" ]] || install_die "local release artifact not found: ${PACKAGE_SPEC#file://}"
    return 0
  fi
  if ! artifact_url_exists "${PACKAGE_SPEC}"; then
    install_die "release artifact not found: ${PACKAGE_SPEC} (publish GitHub release assets for ${SECKIT_REF}, or use --ref for git install)"
  fi
}

ensure_uv_runtime_python() {
  local py_spec="${SECKIT_RUNTIME_PYTHON}"
  INSTALL_METHOD="uv-managed"

  if ! uv_bootstrap_blocked; then
    install_log "Provisioning Python ${py_spec} (may take a minute)..."
    local -a install_cmd=("${UV_BIN}" python install "${py_spec}")
    if [[ "${VERBOSE}" -ne 1 ]]; then
      install_cmd+=(--quiet)
    fi
    UV_CACHE_DIR="${SECKIT_CACHE_DIR}" run_capture "${install_cmd[@]}" \
      || install_die "failed provisioning Python ${py_spec}"
  fi

  PYTHON="$("${UV_BIN}" python find "${py_spec}" 2>/dev/null || true)"
  [[ -n "${PYTHON}" && -x "${PYTHON}" ]] \
    || install_die "Python ${py_spec} unavailable. Remove --safe/--no-uv-download or preinstall: uv python install ${py_spec}"

  RUNTIME_PYTHON_VERSION="$("${PYTHON}" --version 2>&1 | sed -E 's/^[Pp]ython[[:space:]]+//')"
  install_log "Runtime Python: ${RUNTIME_PYTHON_VERSION}"
  verbose_log "runtime interpreter: ${PYTHON}"
}

uv_bootstrap_blocked() {
  [[ "${NO_UV_DOWNLOAD}" -eq 1 || "${SAFE_MODE}" -eq 1 ]]
}

resolve_uv() {
  if command -v uv >/dev/null 2>&1; then
    UV_BIN="$(command -v uv)"
    verbose_log "using existing runtime tool: ${UV_BIN}"
    install_log "Runtime tools ready."
    return 0
  fi
  if [[ -x "${HOME}/.local/bin/uv" ]]; then
    UV_BIN="${HOME}/.local/bin/uv"
    verbose_log "using existing runtime tool: ${UV_BIN}"
    install_log "Runtime tools ready."
    return 0
  fi

  if uv_bootstrap_blocked; then
    install_die "runtime bootstrap unavailable (--safe or --no-uv-download). Install uv and preinstall runtime Python with: uv python install ${SECKIT_RUNTIME_PYTHON}"
  fi

  install_log "Preparing isolated runtime environment..."
  verbose_log "runtime tool not found; bootstrapping via network"

  if [[ "${IS_INTERACTIVE}" -eq 1 && "${YES}" -eq 0 ]]; then
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

  install_log "Downloading runtime components (may take a few minutes)..."
  local bootstrap_sh='curl -LsSf --connect-timeout 30 --max-time 600 https://astral.sh/uv/install.sh | sh'
  if [[ "${VERBOSE}" -eq 1 ]]; then
    append_log "RUN ${bootstrap_sh}"
    sh -c "${bootstrap_sh}" || install_die "failed preparing isolated runtime environment"
  else
    run_capture sh -c "${bootstrap_sh}" \
      || install_die "failed preparing isolated runtime environment (see ${SECKIT_INSTALL_LOG})"
  fi
  install_log "Runtime components ready."
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

  local -a cmd=("${UV_BIN}" venv "${TARGET_RUNTIME}" --python "${SECKIT_RUNTIME_PYTHON}")
  if [[ "${VERBOSE}" -ne 1 ]]; then
    cmd+=(--quiet)
  fi
  UV_CACHE_DIR="${SECKIT_CACHE_DIR}" run_capture "${cmd[@]}" || install_die "failed creating uv runtime"
}

uv_install_secrets_kit() {
  local mode="${1:?}"
  [[ -n "${PACKAGE_SPEC}" ]] || install_die "internal error: package spec not resolved"

  local -a cmd=("${UV_BIN}" pip install --python "${TARGET_RUNTIME}/bin/python")
  if [[ "${mode}" == "upgrade" ]]; then
    cmd+=(--upgrade)
  fi
  if [[ "${VERBOSE}" -ne 1 ]]; then
    cmd+=(--quiet)
  fi

  case "${PACKAGE_SOURCE}" in
    editable)
      append_log "RUN (cd ${SECKIT_INSTALL_ROOT} && ${cmd[*]} ${PACKAGE_SPEC})"
      (cd "${SECKIT_INSTALL_ROOT}" && UV_CACHE_DIR="${SECKIT_CACHE_DIR}" run_capture "${cmd[@]}" "${PACKAGE_SPEC}") \
        || install_die "failed installing editable seckit"
      ;;
    *)
      verbose_log "package source: ${PACKAGE_SOURCE} (${PACKAGE_SPEC})"
      UV_CACHE_DIR="${SECKIT_CACHE_DIR}" run_capture "${cmd[@]}" "${PACKAGE_SPEC}" \
        || install_die "failed installing seckit (${PACKAGE_SOURCE})"
      ;;
  esac
}

prune_old_runtimes() {
  local keep_a keep_b path
  keep_a="${TARGET_RUNTIME}"
  keep_b="${PREVIOUS_RUNTIME:-}"
  [[ -d "${SECKIT_RUNTIME_DIR}" ]] || return 0

  shopt -s nullglob
  for path in "${SECKIT_RUNTIME_DIR}"/runtime-*; do
    [[ -d "${path}" ]] || continue
    if [[ "${path}" == "${keep_a}" || ( -n "${keep_b}" && "${path}" == "${keep_b}" ) ]]; then
      continue
    fi
    verbose_log "removing old runtime: ${path}"
    rm -rf "${path}"
  done
  shopt -u nullglob
}

cleanup_install_cache() {
  [[ -d "${SECKIT_CACHE_DIR}" ]] || return 0
  shopt -s dotglob nullglob
  local entries=("${SECKIT_CACHE_DIR}"/*)
  if [[ "${#entries[@]}" -gt 0 ]]; then
    verbose_log "cleaning installer cache: ${SECKIT_CACHE_DIR}"
    rm -rf "${entries[@]}"
  fi
  shopt -u dotglob nullglob
}

write_runtime_state() {
  local runtime_json current_link_tmp previous_link_tmp
  runtime_json="$(mktemp -t seckit-runtime-json.XXXXXX)"
  cat >"${runtime_json}" <<EOF_JSON
{
  "runtime": "$(_json_escape "${TARGET_RUNTIME}")",
  "method": "$(_json_escape "${INSTALL_METHOD}")",
  "python": "$(_json_escape "${PYTHON}")",
  "python_version": "$(_json_escape "${RUNTIME_PYTHON_VERSION}")",
  "python_source": "uv-managed",
  "runtime_python": "$(_json_escape "${SECKIT_RUNTIME_PYTHON}")",
  "package_source": "$(_json_escape "${PACKAGE_SOURCE}")",
  "package_spec": "$(_json_escape "${PACKAGE_SPEC}")",
  "uv": "$(_json_escape "${UV_BIN}")",
  "ref": "$(_json_escape "${SECKIT_REF}")"
}
EOF_JSON
  atomic_write_file_from "${SECKIT_RUNTIME_JSON}" "${runtime_json}"
  rm -f "${runtime_json}"

  write_runtime_path_file "${SECKIT_RUNTIME_PATH_FILE}" "${TARGET_RUNTIME}"

  current_link_tmp="${SECKIT_RUNTIME_DIR}/current.tmp.$$"
  ln -sfn "${TARGET_RUNTIME}" "${current_link_tmp}"
  mv -f "${current_link_tmp}" "${SECKIT_RUNTIME_DIR}/current"

  if [[ -n "${PREVIOUS_RUNTIME:-}" && "${PREVIOUS_RUNTIME}" != "${TARGET_RUNTIME}" && -d "${PREVIOUS_RUNTIME}" ]]; then
    previous_link_tmp="${SECKIT_RUNTIME_DIR}/previous.tmp.$$"
    ln -sfn "${PREVIOUS_RUNTIME}" "${previous_link_tmp}"
    mv -f "${previous_link_tmp}" "${SECKIT_RUNTIME_DIR}/previous"
  else
    rm -f "${SECKIT_RUNTIME_DIR}/previous"
  fi
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
  "package_source": "$(_json_escape "${PACKAGE_SOURCE}")",
  "runtime_python": "$(_json_escape "${SECKIT_RUNTIME_PYTHON}")",
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
RUNTIME_DIR="$(head -1 "${RUNTIME_PATH_FILE}" | tr -d '\r' | sed -e 's/[[:space:]]*$//' -e 's/\\n$//')"
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
  if [[ "${VERBOSE}" -eq 1 ]]; then
    run_capture "${TARGET_RUNTIME}/bin/seckit" "${args[@]}"
    return $?
  fi
  local out_file err_file rc
  out_file="$(mktemp -t seckit-install-check-out.XXXXXX)"
  err_file="$(mktemp -t seckit-install-check-err.XXXXXX)"
  append_log "RUN ${TARGET_RUNTIME}/bin/seckit ${args[*]}"
  "${TARGET_RUNTIME}/bin/seckit" "${args[@]}" >"${out_file}" 2>"${err_file}" || rc=$?
  rc="${rc:-0}"
  if [[ "${rc}" -ne 0 ]]; then
    [[ -s "${out_file}" ]] && sed 's/^/  /' "${out_file}" >&2
    [[ -s "${err_file}" ]] && sed 's/^/  /' "${err_file}" >&2
    [[ -s "${out_file}" ]] && cat "${out_file}" >>"${SECKIT_INSTALL_LOG}"
    [[ -s "${err_file}" ]] && cat "${err_file}" >>"${SECKIT_INSTALL_LOG}"
    rm -f "${out_file}" "${err_file}"
    return "${rc}"
  fi
  if grep -q '"ok"[[:space:]]*:[[:space:]]*false' "${out_file}" 2>/dev/null; then
    sed 's/^/  /' "${out_file}" >&2
    cat "${out_file}" >>"${SECKIT_INSTALL_LOG}" 2>/dev/null || true
    rm -f "${out_file}" "${err_file}"
    return 1
  fi
  install_log "Install verification passed."
  rm -f "${out_file}" "${err_file}"
  return 0
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
  --ref TAG              Install from git at TAG (not release wheel)
  --repo-url URL         Git remote when using --ref
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
      --ref) SECKIT_REF="${2:?--ref requires a value}"; SECKIT_REF_EXPLICIT=1; shift 2 ;;
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
      resolve_latest_release_tag
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
  step_done 1

  PREVIOUS_RUNTIME="$(read_runtime_path || true)"
  resolve_package_spec

  step 2 "Creating isolated runtime..."
  ensure_uv_runtime_python
  install_log "Creating isolated environment (may take a minute)..."
  create_runtime
  install_log "Isolated environment ready."
  step_done 2

  step 3 "Installing Secrets-Kit..."
  if [[ "${UPGRADE}" -eq 1 ]]; then
    install_log "Upgrading package (may take a few minutes)..."
    uv_install_secrets_kit "upgrade"
  else
    install_log "Installing package (may take a few minutes)..."
    uv_install_secrets_kit "install"
  fi
  write_runtime_state
  write_launcher
  write_install_state
  prune_old_runtimes
  install_log "Package installed."
  step_done 3

  step 4 "Running first-time setup..."
  if [[ "${UPGRADE}" -eq 0 && "${NO_INIT}" -eq 0 ]]; then
    install_log "Initializing configuration..."
    local -a init_args=(init)
    if [[ "${YES}" -eq 1 ]]; then
      init_args+=(--yes)
    fi
    run_capture "${TARGET_RUNTIME}/bin/seckit" "${init_args[@]}" || install_die "seckit init failed"
    install_log "Configuration initialized."
  else
    install_log "First-time setup skipped."
    verbose_log "init skipped"
  fi
  apply_shell_profile_block
  step_done 4

  step 5 "Verifying install..."
  if [[ "${NO_VERIFY}" -eq 0 ]]; then
    install_log "Running install verification..."
    run_install_check || install_die "install verification failed"
  else
    install_log "Install verification skipped."
    verbose_log "verification skipped"
  fi
  step_done 5
  cleanup_install_cache

  clear_shell_profile_backup

  if [[ "${JSON_OUT}" -eq 1 ]]; then
    emit_json "{\"ok\":true,\"ref\":\"${SECKIT_REF}\",\"runtime\":\"${TARGET_RUNTIME}\",\"python\":\"${RUNTIME_PYTHON_VERSION}\",\"package_source\":\"${PACKAGE_SOURCE}\",\"uv\":\"${UV_BIN}\"}"
  else
    printf '\nSecrets-Kit installed successfully.\n' >&2
    install_log "Version: $(${TARGET_RUNTIME}/bin/seckit --version 2>/dev/null | awk 'NF {print $2; exit}')"
    install_log "Command: ${SECKIT_LAUNCHER_PATH}"
    if [[ "${IS_INTERACTIVE}" -eq 0 || "${NO_SHELL_PROFILE}" -eq 1 || "${SAFE_MODE}" -eq 1 ]]; then
      install_log "PATH hint: export PATH=\"${SECKIT_LAUNCHER_BIN_DIR}:\$PATH\""
    fi
  fi
}

main "$@"
