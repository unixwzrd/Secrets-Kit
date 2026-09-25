#!/usr/bin/env bash
# Secrets-Kit operator installer (curl | bash compatible, standalone).
set -euo pipefail
umask 077

SECKIT_GITHUB_REPO="${SECKIT_GITHUB_REPO:-}"
SECKIT_INSTALL_BRANCH="${SECKIT_INSTALL_BRANCH:-}"
SECKIT_RELEASE_CHANNEL="${SECKIT_RELEASE_CHANNEL:-}"
SECKIT_RSS_OPERATOR_URL="${SECKIT_RSS_OPERATOR_URL:-}"
SECKIT_INSTALL_URL="${SECKIT_INSTALL_URL:-https://raw.githubusercontent.com/${SECKIT_GITHUB_REPO}/${SECKIT_INSTALL_BRANCH}/install.sh}"
SECKIT_REF="${SECKIT_REF:-}"
SECKIT_SOURCE_COMMIT="${SECKIT_SOURCE_COMMIT:-}"
SECKIT_SOURCE_REF="${SECKIT_SOURCE_REF:-}"
SECKIT_VERIFIED_BUNDLE_VERSION="${SECKIT_VERIFIED_BUNDLE_VERSION:-}"
SECKIT_REPO_URL="${SECKIT_REPO_URL:-https://github.com/${SECKIT_GITHUB_REPO}.git}"
SECKIT_RELEASE_BASE="${SECKIT_RELEASE_BASE:-}"
SECKIT_RUNTIME_PYTHON="${SECKIT_RUNTIME_PYTHON:-3.12}"
SECKIT_INSTALL_ROOT="${SECKIT_INSTALL_ROOT:-$PWD}"

SECKIT_SHARE_DIR="${SECKIT_SHARE_DIR:-$HOME/.local/share/seckit}"
SECKIT_RUNTIME_DIR="${SECKIT_RUNTIME_DIR:-$SECKIT_SHARE_DIR/runtime}"
SECKIT_STATE_DIR="${SECKIT_STATE_DIR:-$SECKIT_SHARE_DIR/state}"
SECKIT_RUNTIME_PATH_FILE="${SECKIT_RUNTIME_PATH_FILE:-$SECKIT_STATE_DIR/runtime-path}"
SECKIT_RUNTIME_JSON="${SECKIT_RUNTIME_JSON:-$SECKIT_STATE_DIR/runtime.json}"
SECKIT_INSTALL_LOG="${SECKIT_INSTALL_LOG:-$SECKIT_STATE_DIR/install.log}"
SECKIT_LAUNCHER_BIN_DIR="${SECKIT_LAUNCHER_BIN_DIR:-$HOME/.local/bin}"
SECKIT_LAUNCHER_PATH="${SECKIT_LAUNCHER_PATH:-$SECKIT_LAUNCHER_BIN_DIR/seckit}"
SECKIT_MCP_LAUNCHER_PATH="${SECKIT_MCP_LAUNCHER_PATH:-$SECKIT_LAUNCHER_BIN_DIR/seckit-mcp}"
SECKIT_UV_INSTALL_URL="${SECKIT_UV_INSTALL_URL:-https://astral.sh/uv/install.sh}"
SECKIT_UV_RELEASE_BASE="${SECKIT_UV_RELEASE_BASE:-https://github.com/astral-sh/uv/releases/latest/download}"
SECKIT_UV_RELEASE_URL="${SECKIT_UV_RELEASE_URL:-}"
SECKIT_CONNECT_TIMEOUT="${SECKIT_CONNECT_TIMEOUT:-15}"
SECKIT_TRANSFER_TIMEOUT="${SECKIT_TRANSFER_TIMEOUT:-60}"
SECKIT_UV_TRANSFER_TIMEOUT="${SECKIT_UV_TRANSFER_TIMEOUT:-600}"
SECKIT_NETWORK_RETRIES="${SECKIT_NETWORK_RETRIES:-3}"

SECKIT_CONFIG_DIR="${SECKIT_CONFIG_DIR:-$HOME/.config/seckit}"
SECKIT_INSTALL_STATE="${SECKIT_INSTALL_STATE:-$SECKIT_CONFIG_DIR/install.json}"

UPGRADE=0
REPAIR=0
DEV_MODE=0
YES=0
NO_INIT=0
INIT_STATE=""
NO_VERIFY=0
SKIP_VERIFY_IF_UNCHANGED=0
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
TARGET_RUNTIME_CREATED=0
TARGET_RUNTIME_ACTIVATING=0
PREVIOUS_RUNTIME=""
PACKAGE_SOURCE=""
PACKAGE_SPEC=""
PACKAGE_DISPLAY_SPEC=""
PACKAGE_CACHE_FILE=""
PACKAGE_CACHE_DIR=""
DEPENDENCY_OVERRIDE_FILE=""
DEPENDENCY_CACHE_DIR=""
BACKPORT_WHEEL=""
BACKPORT_SHA256=""
MDNS_WHEEL=""
MDNS_SHA256=""
FASTECDSA_WHEEL=""
FASTECDSA_SHA256=""
FASTECDSA_VERSION=""
RUNTIME_PYTHON_VERSION=""
SECKIT_REF_EXPLICIT=0
IS_INTERACTIVE=0
PROFILE_CHANGED=0
PROFILE_CHANGED_FILE=""
PROFILE_BACKUP_FILE=""
PREVIOUS_INSTALL_REF=""
PREVIOUS_INSTALL_PACKAGE_SOURCE=""
PREVIOUS_INSTALL_VERIFIED="false"

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

# Non-login SSH often ships a minimal PATH; standard sbin/bin dirs hold tar, etc.
ensure_operator_path() {
  local std="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  local dir merged="${PATH}"
  local IFS=':'
  for dir in ${std}; do
    case ":${merged}:" in
      *":${dir}:"*) ;;
      *) merged="${dir}:${merged}" ;;
    esac
  done
  PATH="${merged}"
  export PATH
}

has_command() {
  local name="$1"
  command -v "${name}" >/dev/null 2>&1 && return 0
  local d
  for d in /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin; do
    [[ -x "${d}/${name}" ]] && return 0
  done
  return 1
}

github_auth_header() {
  local token="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
  if [[ -z "${token}" ]] && has_command gh; then
    token="$(gh auth token 2>/dev/null || true)"
  fi
  [[ -n "${token}" ]] || return 1
  printf 'Authorization: Bearer %s' "${token}"
}

uv_release_triple() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"
  case "${os}" in
    Darwin)
      case "${arch}" in
        arm64|aarch64) printf '%s' 'aarch64-apple-darwin' ;;
        x86_64|amd64) printf '%s' 'x86_64-apple-darwin' ;;
      esac
      ;;
    Linux)
      case "${arch}" in
        x86_64|amd64) printf '%s' 'x86_64-unknown-linux-gnu' ;;
        aarch64|arm64) printf '%s' 'aarch64-unknown-linux-gnu' ;;
        armv7l) printf '%s' 'armv7-unknown-linux-gnueabihf' ;;
      esac
      ;;
  esac
}

extract_archive_gz() {
  local archive="$1" dest="$2"
  if has_command tar; then
    tar -xzf "${archive}" -C "${dest}"
    return 0
  fi
  if has_command python3; then
    python3 -c 'import sys, tarfile; tarfile.open(sys.argv[1], "r:gz").extractall(sys.argv[2])' \
      "${archive}" "${dest}"
    return 0
  fi
  install_die "need tar or python3 to unpack uv release (install tar, or ensure python3 is on PATH)"
}

find_uv_bin() {
  ensure_operator_path
  if command -v uv >/dev/null 2>&1; then
    command -v uv
    return 0
  fi
  if [[ -x "${SECKIT_LAUNCHER_BIN_DIR}/uv" ]]; then
    printf '%s' "${SECKIT_LAUNCHER_BIN_DIR}/uv"
    return 0
  fi
  if [[ -x "${HOME}/.local/bin/uv" ]]; then
    printf '%s' "${HOME}/.local/bin/uv"
    return 0
  fi
  return 1
}

bootstrap_uv_via_install_script() {
  local bootstrap_file rc=0
  bootstrap_file="$(mktemp -t seckit-uv-install.XXXXXX)"
  download_file "${SECKIT_UV_INSTALL_URL}" "${bootstrap_file}" "" "${SECKIT_UV_TRANSFER_TIMEOUT}" \
    || { rm -f "${bootstrap_file}"; return 1; }
  if [[ "${VERBOSE}" -eq 1 ]]; then
    append_log "RUN sh ${bootstrap_file}"
    sh "${bootstrap_file}" || rc=1
  else
    run_capture sh "${bootstrap_file}" || rc=1
  fi
  rm -f "${bootstrap_file}"
  return "${rc}"
}

bootstrap_uv_via_release() {
  local triple archive tmpdir url uv_path uvx_path
  triple="$(uv_release_triple)" || {
    install_die "unsupported platform for uv bootstrap: $(uname -s)/$(uname -m)"
  }
  if [[ -n "${SECKIT_UV_RELEASE_URL}" ]]; then
    url="${SECKIT_UV_RELEASE_URL}"
  else
    url="${SECKIT_UV_RELEASE_BASE}/uv-${triple}.tar.gz"
  fi
  archive="$(mktemp -t seckit-uv-archive.XXXXXX)"
  rm -f "${archive}"
  archive="${archive}.tar.gz"
  tmpdir="$(mktemp -d -t seckit-uv-extract.XXXXXX)"
  verbose_log "uv release archive: ${url}"
  download_file "${url}" "${archive}" "" "${SECKIT_UV_TRANSFER_TIMEOUT}" \
    || { rm -rf "${tmpdir}"; rm -f "${archive}"; return 1; }
  extract_archive_gz "${archive}" "${tmpdir}" \
    || { rm -rf "${tmpdir}"; rm -f "${archive}"; return 1; }
  rm -f "${archive}"
  uv_path="$(find "${tmpdir}" -type f -name uv -perm -111 2>/dev/null | head -1)"
  [[ -n "${uv_path}" && -f "${uv_path}" ]] \
    || { rm -rf "${tmpdir}"; install_die "uv binary not found in release archive"; }
  mkdir -p "${SECKIT_LAUNCHER_BIN_DIR}"
  install -m 755 "${uv_path}" "${SECKIT_LAUNCHER_BIN_DIR}/uv"
  uvx_path="$(find "${tmpdir}" -type f -name uvx -perm -111 2>/dev/null | head -1)"
  if [[ -n "${uvx_path}" && -f "${uvx_path}" ]]; then
    install -m 755 "${uvx_path}" "${SECKIT_LAUNCHER_BIN_DIR}/uvx"
  fi
  rm -rf "${tmpdir}"
  export PATH="${SECKIT_LAUNCHER_BIN_DIR}:${PATH}"
  return 0
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

ref_to_version() {
  local ref="${1:?}"
  ref="${ref#v}"
  printf '%s' "${ref}"
}

resolve_downloader() {
  if command -v curl >/dev/null 2>&1; then
    printf 'curl'
    return 0
  fi
  if command -v wget >/dev/null 2>&1; then
    printf 'wget'
    return 0
  fi
  if command -v python3 >/dev/null 2>&1; then
    printf 'python3'
    return 0
  fi
  install_die "network downloader unavailable (install curl, wget, or python3)"
}

download_text() {
  local url="${1:?}" header="${2:-}" tool
  tool="$(resolve_downloader)"
  case "${tool}" in
    curl)
      local -a args=(curl -fsSL --retry "${SECKIT_NETWORK_RETRIES}" --connect-timeout "${SECKIT_CONNECT_TIMEOUT}" --max-time "${SECKIT_TRANSFER_TIMEOUT}")
      # Keep private authorization headers out of downloader process arguments.
      printf '%s\n' "${header}" | "${args[@]}" -H @- "${url}"
      ;;
    wget)
      local -a args=(wget -qO- --tries "$((SECKIT_NETWORK_RETRIES + 1))" --connect-timeout "${SECKIT_CONNECT_TIMEOUT}" --read-timeout "${SECKIT_TRANSFER_TIMEOUT}" --timeout "${SECKIT_TRANSFER_TIMEOUT}")
      wget_with_private_headers "${header}" "${args[@]:1}" "${url}"
      ;;
    python3)
      SECKIT_URL="${url}" SECKIT_TIMEOUT="${SECKIT_TRANSFER_TIMEOUT}" SECKIT_RETRIES="${SECKIT_NETWORK_RETRIES}" python3 3<<< "${header}" <<'PY'
import os
import sys
import time
import urllib.request

req = urllib.request.Request(os.environ["SECKIT_URL"])
for line in os.fdopen(3).read().splitlines():
    if ":" in line:
        key, value = line.split(":", 1)
        req.add_header(key.strip(), value.strip())
last_exc = None
for attempt in range(int(os.environ["SECKIT_RETRIES"]) + 1):
    try:
        with urllib.request.urlopen(req, timeout=float(os.environ["SECKIT_TIMEOUT"])) as response:
            sys.stdout.buffer.write(response.read())
            sys.exit(0)
    except Exception as exc:
        last_exc = exc
        if attempt < int(os.environ["SECKIT_RETRIES"]):
            time.sleep(min(2 ** attempt, 5))
print(f"download failed: {last_exc}", file=sys.stderr)
sys.exit(1)
PY
      ;;
  esac
}

wget_with_private_headers() (
  # Wget requires a regular startup file, not /dev/stdin. Remove this private
  # transient file on success, failure, or termination of this subshell.
  local header="${1:-}" header_file line
  shift
  if [[ -z "${header}" ]]; then
    wget "$@"
    exit $?
  fi
  header_file="$(mktemp -t seckit-download-headers.XXXXXX)" || exit 1
  trap 'rm -f -- "${header_file}"' EXIT
  chmod 600 "${header_file}" || exit 1
  while IFS= read -r line; do
    [[ -z "${line}" ]] || printf 'header = %s\n' "${line}"
  done <<< "${header}" > "${header_file}"
  wget --config="${header_file}" "$@"
)

download_file() {
  local url="${1:?}" dest="${2:?}" header="${3:-}" max_time="${4:-$SECKIT_TRANSFER_TIMEOUT}" tool tmp
  local download_status=0
  tmp="${dest}.tmp.$$"
  rm -f "${tmp}"
  tool="$(resolve_downloader)"
  case "${tool}" in
    curl)
      local -a args=(curl -fsSL --retry "${SECKIT_NETWORK_RETRIES}" --connect-timeout "${SECKIT_CONNECT_TIMEOUT}" --max-time "${max_time}")
      printf '%s\n' "${header}" | "${args[@]}" -H @- -o "${tmp}" "${url}" \
        || download_status=$?
      ;;
    wget)
      local -a args=(wget -qO "${tmp}" --tries "$((SECKIT_NETWORK_RETRIES + 1))" --connect-timeout "${SECKIT_CONNECT_TIMEOUT}" --read-timeout "${max_time}" --timeout "${max_time}")
      wget_with_private_headers "${header}" "${args[@]:1}" "${url}" || download_status=$?
      ;;
    python3)
      SECKIT_URL="${url}" SECKIT_DEST="${tmp}" SECKIT_TIMEOUT="${max_time}" SECKIT_RETRIES="${SECKIT_NETWORK_RETRIES}" python3 3<<< "${header}" <<'PY' || download_status=$?
import os
import sys
import time
import urllib.request

req = urllib.request.Request(os.environ["SECKIT_URL"])
for line in os.fdopen(3).read().splitlines():
    if ":" in line:
        key, value = line.split(":", 1)
        req.add_header(key.strip(), value.strip())
last_exc = None
for attempt in range(int(os.environ["SECKIT_RETRIES"]) + 1):
    try:
        with urllib.request.urlopen(req, timeout=float(os.environ["SECKIT_TIMEOUT"])) as response:
            with open(os.environ["SECKIT_DEST"], "wb") as fh:
                fh.write(response.read())
            sys.exit(0)
    except Exception as exc:
        last_exc = exc
        if attempt < int(os.environ["SECKIT_RETRIES"]):
            time.sleep(min(2 ** attempt, 5))
print(f"download failed: {last_exc}", file=sys.stderr)
sys.exit(1)
PY
      ;;
  esac
  if [[ "${download_status}" -ne 0 ]]; then
    rm -f "${tmp}"
    return "${download_status}"
  fi
  mv -f "${tmp}" "${dest}"
}

url_exists() {
  local url="${1:?}" header="${2:-}" tool
  if [[ "${url}" == file://* ]]; then
    [[ -f "${url#file://}" ]]
    return $?
  fi
  tool="$(resolve_downloader)"
  case "${tool}" in
    curl)
      local -a args=(curl -fsSIL --retry "${SECKIT_NETWORK_RETRIES}" --connect-timeout "${SECKIT_CONNECT_TIMEOUT}" --max-time "${SECKIT_TRANSFER_TIMEOUT}")
      printf '%s\n' "${header}" | "${args[@]}" -H @- "${url}" >/dev/null 2>&1
      ;;
    wget)
      local -a args=(wget --spider -q --tries "$((SECKIT_NETWORK_RETRIES + 1))" --connect-timeout "${SECKIT_CONNECT_TIMEOUT}" --read-timeout "${SECKIT_TRANSFER_TIMEOUT}" --timeout "${SECKIT_TRANSFER_TIMEOUT}")
      wget_with_private_headers "${header}" "${args[@]:1}" "${url}" >/dev/null 2>&1
      ;;
    python3)
      SECKIT_URL="${url}" SECKIT_TIMEOUT="${SECKIT_TRANSFER_TIMEOUT}" SECKIT_RETRIES="${SECKIT_NETWORK_RETRIES}" python3 3<<< "${header}" <<'PY'
import os
import sys
import time
import urllib.error
import urllib.request

url = os.environ["SECKIT_URL"]
header = os.fdopen(3).read()
timeout = float(os.environ["SECKIT_TIMEOUT"])
retries = int(os.environ["SECKIT_RETRIES"])
for attempt in range(retries + 1):
    try:
        for method in ("HEAD", "GET"):
            req = urllib.request.Request(url, method=method)
            for line in header.splitlines():
                if ":" in line:
                    key, value = line.split(":", 1)
                    req.add_header(key.strip(), value.strip())
            try:
                with urllib.request.urlopen(req, timeout=timeout) as response:
                    if 200 <= response.status < 400:
                        sys.exit(0)
            except urllib.error.HTTPError as exc:
                if method == "HEAD" and exc.code in (405, 501):
                    continue
                raise
    except Exception:
        if attempt < retries:
            time.sleep(min(2 ** attempt, 5))
sys.exit(1)
PY
      ;;
  esac
}

json_python() {
  if [[ -n "${PYTHON}" && -x "${PYTHON}" ]]; then
    printf '%s' "${PYTHON}"
    return 0
  fi
  install_die "managed runtime must be provisioned before parsing installation metadata"
}

github_api_get() {
  local path="${1:?}" header=""
  header="$(github_auth_header || true)"
  if [[ -n "${header}" ]]; then
    header=$'Accept: application/vnd.github+json\n'"${header}"
  else
    header="Accept: application/vnd.github+json"
  fi
  download_text "https://api.github.com/repos/${SECKIT_GITHUB_REPO}/${path}" "${header}"
}

resolve_latest_release_tag() {
  [[ -n "${SECKIT_REF}" ]] && return 0
  local json tag json_py
  json="$(github_api_get "releases?per_page=30")" \
    || install_die "unable to query GitHub releases for ${SECKIT_GITHUB_REPO}"
  case "${SECKIT_RELEASE_CHANNEL}" in
    release|prerelease) ;;
    *) install_die "unsupported release channel: ${SECKIT_RELEASE_CHANNEL} (expected release or prerelease)" ;;
  esac
  json_py="$(json_python)"
  tag="$(printf '%s' "${json}" | "${json_py}" -c '
import json
import sys

channel = sys.argv[1]
try:
    releases = json.load(sys.stdin)
except json.JSONDecodeError as exc:
    print(f"invalid GitHub release JSON: {exc}", file=sys.stderr)
    sys.exit(2)

for release in releases:
    if release.get("draft"):
        continue
    prerelease = bool(release.get("prerelease"))
    if channel == "release" and prerelease:
        continue
    if channel == "prerelease" and not prerelease:
        continue
    tag = release.get("tag_name")
    if tag:
        print(tag)
        sys.exit(0)
sys.exit(1)
' "${SECKIT_RELEASE_CHANNEL}")" || tag=""
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

try_release_wheel_url() {
  local base version wheel_url header="" json json_py api_url
  [[ -n "${SECKIT_REF}" ]] || return 1
  header="$(github_auth_header || true)"
  if [[ -n "${header}" ]]; then
    json="$(github_api_get "releases/tags/${SECKIT_REF}" || true)"
    [[ -n "${json}" ]] || return 1
    json_py="$(json_python)"
    api_url="$(printf '%s' "${json}" | "${json_py}" -c '
import json
import sys
for asset in json.load(sys.stdin).get("assets", []):
    if asset.get("name") == "seckit-" + sys.argv[1].lstrip("v") + "-py3-none-any.whl":
        print(asset.get("url", ""))
        break
' "${SECKIT_REF}")"
    [[ -n "${api_url}" ]] || return 1
    printf '%s' "${api_url}"
    return 0
  fi
  base="$(release_download_base)"
  version="$(ref_to_version "${SECKIT_REF}")"
  wheel_url="${base}/seckit-${version}-py3-none-any.whl"
  if url_exists "${wheel_url}"; then
    printf '%s' "${wheel_url}"
    return 0
  fi
  return 1
}

cache_release_wheel() {
  local wheel_url="${1:?}" header="" cache_dir cache_file
  header="$(github_auth_header || true)"
  [[ -n "${header}" ]] || return 1
  if [[ "${wheel_url}" == https://api.github.com/* ]]; then
    header=$'Accept: application/octet-stream\n'"${header}"
  fi
  cache_dir="$(mktemp -d -t seckit-release-wheel.XXXXXX)"
  cache_file="${cache_dir}/seckit-$(ref_to_version "${SECKIT_REF}")-py3-none-any.whl"
  if ! download_file "${wheel_url}" "${cache_file}" "${header}"; then
    rm -f "${cache_file}"
    rmdir "${cache_dir}" 2>/dev/null || true
    return 1
  fi
  printf 'file://%s' "${cache_file}"
}

pick_release_asset_url() {
  local wheel_url
  wheel_url="$(try_release_wheel_url || true)"
  if [[ -n "${wheel_url}" ]]; then
    printf '%s' "${wheel_url}"
    return 0
  fi
  install_die "release wheel not found for ${SECKIT_REF} (expected seckit-$(ref_to_version "${SECKIT_REF}")-py3-none-any.whl; publish the release asset or use the maintainer-only Git fallback)"
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
    PACKAGE_SPEC="-e ."
    return 0
  fi
  if [[ "${SECKIT_REF_EXPLICIT}" -eq 1 ]]; then
    local wheel_url=""
    if [[ -n "${SECKIT_WHEEL_URL:-}" ]]; then
      wheel_url="${SECKIT_WHEEL_URL}"
    else
      wheel_url="$(try_release_wheel_url || true)"
    fi
    if [[ -n "${wheel_url}" ]]; then
      PACKAGE_SOURCE="release"
      PACKAGE_DISPLAY_SPEC="${wheel_url}"
      if [[ "${wheel_url}" == file://* ]]; then
        PACKAGE_SPEC="${wheel_url}"
      elif [[ -n "$(github_auth_header || true)" ]]; then
        PACKAGE_SPEC="$(cache_release_wheel "${wheel_url}")" || install_die "unable to download private release wheel"
      else
        PACKAGE_SPEC="${wheel_url}"
      fi
      verbose_log "explicit --ref resolved to release wheel (no git required)"
      return 0
    fi
    if [[ "${SECKIT_REPO_URL}" == "https://github.com/${SECKIT_GITHUB_REPO}.git" ]]; then
      # Fetch a GitHub source archive without requiring Git or GitHub CLI.
      # Authentication stays in the downloader, never in the package URL.
      local header
      [[ "${SECKIT_REF}" =~ ^[a-zA-Z0-9_./-]+$ ]] || install_die "unsupported source reference"
      header="$(github_auth_header || true)"
      PACKAGE_CACHE_DIR="$(mktemp -d -t seckit-source.XXXXXX)"
      PACKAGE_CACHE_FILE="${PACKAGE_CACHE_DIR}/source.tar.gz"
      download_file "https://api.github.com/repos/${SECKIT_GITHUB_REPO}/tarball/${SECKIT_REF}" "${PACKAGE_CACHE_FILE}" "${header}" \
        || install_die "unable to download source reference; private repositories require authorized GH_TOKEN, GITHUB_TOKEN, or an existing gh login"
      PACKAGE_SOURCE="archive"
      PACKAGE_SPEC="file://${PACKAGE_CACHE_FILE}"
      PACKAGE_DISPLAY_SPEC="https://github.com/${SECKIT_GITHUB_REPO}/tree/${SECKIT_REF}"
      return 0
    fi
    has_command git || install_die "custom Git repository requires Git; use a release wheel or the GitHub archive installation path instead"
    PACKAGE_SOURCE="git"
    PACKAGE_SPEC="git+${SECKIT_REPO_URL}@${SECKIT_REF}"
    return 0
  fi
  PACKAGE_SOURCE="release"
  PACKAGE_DISPLAY_SPEC="$(resolve_release_artifact_url)"
  if [[ "${PACKAGE_DISPLAY_SPEC}" == file://* ]]; then
    PACKAGE_SPEC="${PACKAGE_DISPLAY_SPEC}"
  elif [[ -n "$(github_auth_header || true)" ]]; then
    PACKAGE_SPEC="$(cache_release_wheel "${PACKAGE_DISPLAY_SPEC}")" || install_die "unable to download private release wheel"
  else
    PACKAGE_SPEC="${PACKAGE_DISPLAY_SPEC}"
  fi
  if [[ "${PACKAGE_SPEC}" == file://* ]]; then
    [[ -f "${PACKAGE_SPEC#file://}" ]] || install_die "local release artifact not found: ${PACKAGE_SPEC#file://}"
    return 0
  fi
  if ! url_exists "${PACKAGE_SPEC}"; then
    install_die "release artifact not found: ${PACKAGE_SPEC} (publish GitHub release assets for ${SECKIT_REF}, or use --ref for git install)"
  fi
}

validate_local_release_artifact() {
  [[ "${PACKAGE_SOURCE}" == release ]] || return 0
  [[ "${PACKAGE_SPEC}" == file://* ]] || return 0
  local package_file="${PACKAGE_SPEC#file://}"
  local artifact_version expected
  artifact_version="$(ref_to_version "${SECKIT_REF}")"
  if [[ -n "${SECKIT_VERIFIED_BUNDLE_VERSION}" ]]; then
    [[ "${SECKIT_VERIFIED_BUNDLE_VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+((a|b|rc)[0-9]+)?$ ]] \
      || install_die "verified bundle version is invalid"
    case "${SECKIT_SOURCE_REF}" in
      refs/heads/*)
        [[ "${SECKIT_SOURCE_COMMIT}" =~ ^[a-f0-9]{40}$ \
          && "${SECKIT_REF}" == "${SECKIT_SOURCE_COMMIT}" \
          && "${SECKIT_INSTALL_BRANCH}" == "${SECKIT_SOURCE_COMMIT}" ]] \
          || install_die "verified branch bundle source identity is inconsistent"
        artifact_version="${SECKIT_VERIFIED_BUNDLE_VERSION}"
        ;;
      refs/tags/*)
        [[ "${SECKIT_REF}" == "${SECKIT_SOURCE_REF#refs/tags/}" \
          && "${SECKIT_VERIFIED_BUNDLE_VERSION}" == "${artifact_version}" ]] \
          || install_die "verified tag bundle source identity is inconsistent"
        ;;
      *)
        install_die "verified bundle source ref is invalid"
        ;;
    esac
  fi
  expected="seckit-${artifact_version}-py3-none-any.whl"
  [[ -f "${package_file}" && ! -L "${package_file}" ]] \
    || install_die "local release artifact not found or is a symlink: ${package_file}"
  [[ "$(basename "${package_file}")" == "${expected}" ]] \
    || install_die "local release artifact does not match ${SECKIT_REF}: expected ${expected}"
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
    run_capture "${install_cmd[@]}" \
      || install_die "failed provisioning Python ${py_spec}"
  fi

  PYTHON="$("${UV_BIN}" python find --managed-python "${py_spec}" 2>/dev/null || true)"
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
  ensure_operator_path
  if UV_BIN="$(find_uv_bin)"; then
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
  local boot_ok=0
  if has_command tar; then
    if bootstrap_uv_via_install_script; then
      boot_ok=1
    else
      install_warn "astral uv install script failed; trying direct release install"
    fi
  else
    verbose_log "tar not on PATH; using direct uv release install"
  fi
  if [[ "${boot_ok}" -eq 0 ]]; then
    bootstrap_uv_via_release \
      || install_die "failed preparing isolated runtime environment (see ${SECKIT_INSTALL_LOG})"
  fi
  install_log "Runtime components ready."
  if UV_BIN="$(find_uv_bin)"; then
    verbose_log "bootstrapped runtime tool: ${UV_BIN}"
    return 0
  fi
  install_die "runtime bootstrap reported success but the environment is still unavailable"
}

ensure_dirs() {
  mkdir -p "${SECKIT_RUNTIME_DIR}" "${SECKIT_STATE_DIR}" "${SECKIT_CONFIG_DIR}" "${SECKIT_LAUNCHER_BIN_DIR}"
}

current_runtime_path() {
  local current="${SECKIT_RUNTIME_DIR}/current"
  [[ -L "${current}" || -d "${current}" ]] || return 1
  local resolved
  if [[ -L "${current}" ]]; then
    resolved="$(readlink "${current}")" || return 1
    if [[ "${resolved}" != /* ]]; then
      resolved="${SECKIT_RUNTIME_DIR}/${resolved}"
    fi
  else
    resolved="$(cd -P "${current}" 2>/dev/null && pwd)" || return 1
  fi
  [[ -n "${resolved}" && -x "${resolved}/bin/seckit" ]] || return 1
  printf '%s' "${resolved}"
}

managed_daemon_service_installed() {
  [[ -f "${HOME}/Library/LaunchAgents/net.unixwzrd.secrets-kit.daemon.plist" \
    || -f "${HOME}/.config/systemd/user/secrets-kit-daemon.service" ]]
}

# Report disabled systemd linger after a healthy Linux user-service install.
# This does not change service setup and is not an installation prerequisite.
warn_if_systemd_linger_disabled() {
  [[ "$(uname -s)" == "Linux" ]] || return 0
  local linger user
  if ! linger="$(loginctl show-user "$(id -u)" -p Linger --value 2>/dev/null)"; then
    install_warn "could not verify systemd linger; check 'seckit daemon service status' before relying on unattended operation"
    return 0
  fi
  linger="${linger//[[:space:]]/}"
  [[ "${linger}" == "yes" ]] && return 0
  if [[ "${linger}" != "no" ]]; then
    install_warn "could not verify systemd linger; check 'seckit daemon service status' before relying on unattended operation"
    return 0
  fi
  user="$(id -un 2>/dev/null || id -u)"
  install_warn "systemd linger is disabled for ${user}; unattended operation after logout requires an administrator to run: loginctl enable-linger ${user}"
}

require_user_managed_install() {
  [[ $(uname -s) == Darwin ]] || return 0
  local uid definition query_result
  uid=$(id -u)
  definition="/Library/LaunchDaemons/net.unixwzrd.secrets-kit.daemon.${uid}.plist"
  if [[ -e ${definition} || -L ${definition} ]]; then
    install_die "boot-managed daemon requires administrator-assisted upgrade: remove boot supervision with the installed helper first, run this installer as the customer, then restore boot supervision; no runtime was changed"
  fi
  if /bin/launchctl print "system/net.unixwzrd.secrets-kit.daemon.${uid}" >/dev/null 2>&1; then
    install_die "boot-managed daemon requires administrator-assisted upgrade; no runtime was changed"
  else
    query_result=$?
  fi
  [[ ${query_result} -eq 113 ]] \
    || install_die "cannot determine boot-managed daemon state; no runtime was changed"
}

restore_previous_runtime_after_daemon_failure() {
  [[ -n "${PREVIOUS_RUNTIME:-}" && -x "${PREVIOUS_RUNTIME}/bin/seckit" ]] \
    || install_die "managed daemon failed and no healthy prior runtime is available"
  local current_link_tmp
  current_link_tmp="${SECKIT_RUNTIME_DIR}/current.rollback.$$"
  ln -sfn "${PREVIOUS_RUNTIME}" "${current_link_tmp}"
  rm -f "${SECKIT_RUNTIME_DIR}/current"
  mv -f "${current_link_tmp}" "${SECKIT_RUNTIME_DIR}/current"
  atomic_write_text "${SECKIT_RUNTIME_PATH_FILE}" "${PREVIOUS_RUNTIME}"$'\n'
  if [[ -n "${RUNTIME_JSON_BACKUP:-}" && -f "${RUNTIME_JSON_BACKUP}" ]]; then
    atomic_write_file_from "${SECKIT_RUNTIME_JSON}" "${RUNTIME_JSON_BACKUP}"
  fi
  "${SECKIT_LAUNCHER_PATH}" daemon restart >/dev/null 2>&1 \
    || install_die "managed daemon rollback failed to restore service health"
}

restart_managed_daemon_after_upgrade() {
  [[ "${UPGRADE}" -eq 1 ]] || return 0
  managed_daemon_service_installed || return 0
  install_log "Restarting managed daemon through the stable launcher..."
  if "${SECKIT_LAUNCHER_PATH}" daemon restart >/dev/null 2>&1; then
    install_log "Managed daemon recovered after upgrade."
    return 0
  fi
  install_warn "Managed daemon did not recover within the bounded readiness window; rolling back runtime."
  restore_previous_runtime_after_daemon_failure
  install_die "upgrade rolled back because managed daemon health did not recover"
}

next_runtime_generation() {
  local stamp idx candidate
  stamp="$(date +%Y%m%d)"
  idx=1
  while :; do
    candidate="${SECKIT_RUNTIME_DIR}/runtime-${stamp}-$(printf '%03d' "${idx}")"
    if [[ ! -e "${candidate}" && ! -L "${candidate}" ]]; then
      printf '%s' "${candidate}"
      return 0
    fi
    idx=$((idx + 1))
  done
}

create_runtime() {
  TARGET_RUNTIME="$(next_runtime_generation)"
  # Claim only a new directory; never let UV clear an existing generation.
  mkdir -m 0700 "${TARGET_RUNTIME}" || install_die "cannot claim new runtime directory"
  TARGET_RUNTIME_CREATED=1
  verbose_log "creating runtime: ${TARGET_RUNTIME}"

  local -a cmd=("${UV_BIN}" venv "${TARGET_RUNTIME}" --python "${PYTHON}")
  if [[ "${VERBOSE}" -ne 1 ]]; then
    cmd+=(--quiet)
  fi
  run_capture "${cmd[@]}" || install_die "failed creating uv runtime"
}

preserve_failed_runtime() {
  # Only this invocation's unactivated candidate may be moved. Keep all bytes
  # outside the generation inventory; do not adopt or remove older runtimes.
  [[ "${TARGET_RUNTIME_CREATED:-0}" -eq 1 && "${TARGET_RUNTIME_ACTIVATING:-0}" -eq 0 ]] || return 0
  [[ -d "${TARGET_RUNTIME}" && ! -L "${TARGET_RUNTIME}" && -O "${TARGET_RUNTIME}" ]] || return 0
  local recovery
  recovery="$(mktemp -d "${SECKIT_RUNTIME_DIR%/*}/failed-install.XXXXXXXX")" || return 0
  if mv "${TARGET_RUNTIME}" "${recovery}/runtime"; then
    install_warn "Unactivated runtime preserved at ${recovery}; existing installation unchanged."
  else
    install_warn "Unable to preserve failed runtime separately; retained ${TARGET_RUNTIME}."
  fi
}

prepare_intel_native_runtime() {
  [[ "$(uname -s):$(uname -m)" == "Darwin:x86_64" ]] || return 0
  [[ "${TARGET_RUNTIME_CREATED:-0}" -eq 1 ]] || install_die "Intel dependencies require a new runtime"
  local package
  # Bootstrap only published wheels, then install our Python-only helper without
  # dependency resolution. Nothing runs from the customer's active generation.
  run_capture "${UV_BIN}" pip install --python "${TARGET_RUNTIME}/bin/python" \
    --only-binary :all: 'tomli>=2.0.0' 'zstandard==0.25.0' certifi \
    || install_die "failed preparing Intel dependency reader"
  (cd "${SECKIT_INSTALL_ROOT}" && run_capture "${UV_BIN}" pip install \
    --python "${TARGET_RUNTIME}/bin/python" --no-deps "${PACKAGE_SPEC}") \
    || install_die "failed preparing Intel installer helper"
  for package in openssl-3.5.8-h332eb6d_0 cryptography-50.0.1-py312h6b03e6b_0; do
    download_file "https://conda.anaconda.org/conda-forge/osx-64/${package}.conda" \
      "${DEPENDENCY_CACHE_DIR}/${package}.conda" "" \
      || install_die "failed downloading pinned Intel dependency"
  done
  run_capture "${TARGET_RUNTIME}/bin/python" -m secrets_kit.install_native_prefix "${DEPENDENCY_CACHE_DIR}" \
    || install_die "Intel dependency verification or relocation failed"
}

uv_install_secrets_kit() {
  local mode="${1:?}"
  [[ -n "${PACKAGE_SPEC}" ]] || install_die "internal error: package spec not resolved"

  [[ -f "${DEPENDENCY_OVERRIDE_FILE}" ]] \
    || install_die "internal error: dependency override was not prepared"
  prepare_intel_native_runtime

  local -a cmd=(
    "${UV_BIN}" pip install
    --python "${TARGET_RUNTIME}/bin/python"
    --overrides "${DEPENDENCY_OVERRIDE_FILE}"
    --no-cache
  )
  cmd+=(--only-binary fastecdsa,cryptography)
  if [[ "${mode}" == "upgrade" && "$(uname -s):$(uname -m)" != "Darwin:x86_64" ]]; then
    cmd+=(--upgrade)
  fi
  if [[ "${VERBOSE}" -ne 1 ]]; then
    cmd+=(--quiet)
  fi

  if [[ "$(uname -s):$(uname -m)" == "Darwin:x86_64" && "${PACKAGE_SOURCE}" != "editable" ]]; then
    # Zeroconf supports pure Python on Intel macOS. Keep optional Cython and
    # Poetry's optional Git probe away from Apple's developer-tool wrappers.
    # Scope this environment to UV; installer verification retains normal PATH.
    cmd=(/usr/bin/env "PATH=${TARGET_RUNTIME}/bin" SKIP_CYTHON=1 "${cmd[@]}")
  fi

  case "${PACKAGE_SOURCE}" in
    editable)
      append_log "RUN (cd ${SECKIT_INSTALL_ROOT} && ${cmd[*]} ${PACKAGE_SPEC})"
      (cd "${SECKIT_INSTALL_ROOT}" && run_capture "${cmd[@]}" "${PACKAGE_SPEC}") \
        || install_die "failed installing editable seckit"
      ;;
    *)
      verbose_log "package source: ${PACKAGE_SOURCE} (${PACKAGE_SPEC})"
      run_capture "${cmd[@]}" "${PACKAGE_SPEC}" \
        || install_die "failed installing seckit (${PACKAGE_SOURCE})"
      ;;
  esac
}

prepare_dependency_override() {
  DEPENDENCY_OVERRIDE_FILE="$(mktemp -t seckit-dependency-override.XXXXXX)"
  prepare_libp2p_backport
  if [[ "$(uname -s):$(uname -m)" == "Linux:aarch64" ]]; then
    prepare_pinned_dependency "fastecdsa" "${FASTECDSA_WHEEL}" "${FASTECDSA_SHA256}"
  else
    printf 'fastecdsa==%s\n' "${FASTECDSA_VERSION}" >>"${DEPENDENCY_OVERRIDE_FILE}"
  fi
}

# Resolve an immutable Python-only dependency from an adjacent release bundle
# or the same authenticated repository/ref as the client.
prepare_pinned_dependency() {
  local package="${1:?}" artifact="${2:?}" expected_sha256="${3:?}"
  local local_dir="" source="" header="" actual="" wheel
  wheel="${DEPENDENCY_CACHE_DIR}/${artifact}"
  if [[ "${PACKAGE_SPEC}" == file://* ]]; then
    local_dir="$(dirname "${PACKAGE_SPEC#file://}")"
  elif [[ "${PACKAGE_SOURCE}" == editable ]]; then
    local_dir="${SECKIT_INSTALL_ROOT}"
  fi
  if [[ -n "${local_dir}" && ( -e "${local_dir}/${artifact}" || -L "${local_dir}/${artifact}" ) ]]; then
    source="${local_dir}/${artifact}"
  elif [[ -n "${local_dir}" && ( -e "${local_dir}/dependencies/${artifact}" || -L "${local_dir}/dependencies/${artifact}" ) ]]; then
    source="${local_dir}/dependencies/${artifact}"
  fi
  if [[ -n "${source}" ]]; then
    [[ -f "${source}" && ! -L "${source}" ]] || install_die "invalid dependency artifact"
    cp "${source}" "${wheel}"
  else
    [[ -n "${SECKIT_REF}" ]] || install_die "dependency download requires a release reference"
    header="$(github_auth_header || true)"
    header=$'Accept: application/vnd.github.raw+json\n'"${header}"
    download_file "https://api.github.com/repos/${SECKIT_GITHUB_REPO}/contents/dependencies/${artifact}?ref=${SECKIT_REF}" "${wheel}" "${header}" \
      || install_die "pinned ${package} dependency unavailable; use the complete release bundle or authenticated repository access"
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "${wheel}")"
  elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "${wheel}")"
  else
    install_die "SHA256 verification tool unavailable"
  fi
  [[ "${actual%% *}" == "${expected_sha256}" ]] || install_die "${package} dependency checksum mismatch"
  printf '%s @ file://%s\n' "${package}" "${wheel}" >>"${DEPENDENCY_OVERRIDE_FILE}"
}

# Preserve the released entry-point contract while preparing both bounded
# dependencies without permitting package-index fallback.
prepare_libp2p_backport() {
  DEPENDENCY_CACHE_DIR="$(mktemp -d -t seckit-dependency.XXXXXX)"
  prepare_pinned_dependency "libp2p" "${BACKPORT_WHEEL}" "${BACKPORT_SHA256}"
  prepare_pinned_dependency "zeroconf" "${MDNS_WHEEL}" "${MDNS_SHA256}"
}

cleanup_dependency_cache() {
  if [[ -n "${DEPENDENCY_CACHE_DIR:-}" ]]; then
    rm -f "${DEPENDENCY_CACHE_DIR}/${BACKPORT_WHEEL}" \
      "${DEPENDENCY_CACHE_DIR}/${MDNS_WHEEL}" \
      "${DEPENDENCY_CACHE_DIR}/${FASTECDSA_WHEEL}"
    rm -f "${DEPENDENCY_CACHE_DIR}/openssl-3.5.8-h332eb6d_0.conda" \
      "${DEPENDENCY_CACHE_DIR}/cryptography-50.0.1-py312h6b03e6b_0.conda"
    rmdir "${DEPENDENCY_CACHE_DIR}" 2>/dev/null || true
  fi
}

validate_transport_dependencies() {
  run_capture \
    "${TARGET_RUNTIME}/bin/python" \
    -m \
    secrets_kit.install_transport_validation \
    || install_die "native transport dependency or libp2p startup validation failed"
}

prune_old_runtimes() {
  # Installation is not proof that older generations are disposable. Preserve
  # legacy and receipt-backed runtimes for explicit verified removal/recovery.
  verbose_log "preserving previous runtime generations for explicit cleanup"
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
  "github_repo": "$(_json_escape "${SECKIT_GITHUB_REPO}")",
  "source_commit": "$(_json_escape "${SECKIT_SOURCE_COMMIT}")",
  "source_ref": "$(_json_escape "${SECKIT_SOURCE_REF}")",
  "release_channel": "$(_json_escape "${SECKIT_RELEASE_CHANNEL}")",
  "rss_operator_url": "$(_json_escape "${SECKIT_RSS_OPERATOR_URL}")",
  "package_spec": "$(_json_escape "${PACKAGE_DISPLAY_SPEC:-${PACKAGE_SPEC}}")",
  "uv": "$(_json_escape "${UV_BIN}")",
  "ref": "$(_json_escape "${SECKIT_REF}")"
}
EOF_JSON
  atomic_write_file_from "${SECKIT_RUNTIME_JSON}" "${runtime_json}"
  rm -f "${runtime_json}"

  # Compatibility for released seckit doctor builds before runtime/current became
  # the canonical launcher target. The launcher no longer reads this file.
  atomic_write_text "${SECKIT_RUNTIME_PATH_FILE}" "${TARGET_RUNTIME}"$'\n'

  current_link_tmp="${SECKIT_RUNTIME_DIR}/current.tmp.$$"
  ln -sfn "${TARGET_RUNTIME}" "${current_link_tmp}"
  rm -f "${SECKIT_RUNTIME_DIR}/current"
  mv -f "${current_link_tmp}" "${SECKIT_RUNTIME_DIR}/current"

  if [[ -n "${PREVIOUS_RUNTIME:-}" && "${PREVIOUS_RUNTIME}" != "${TARGET_RUNTIME}" && -d "${PREVIOUS_RUNTIME}" ]]; then
    previous_link_tmp="${SECKIT_RUNTIME_DIR}/previous.tmp.$$"
    ln -sfn "${PREVIOUS_RUNTIME}" "${previous_link_tmp}"
    rm -f "${SECKIT_RUNTIME_DIR}/previous"
    mv -f "${previous_link_tmp}" "${SECKIT_RUNTIME_DIR}/previous"
  else
    rm -f "${SECKIT_RUNTIME_DIR}/previous"
  fi
}

write_install_state() {
  local version install_json
  version="$("${TARGET_RUNTIME}/bin/seckit" --version 2>/dev/null | awk 'NF {print $2; exit}')"
  install_json="$(mktemp -t seckit-install-json.XXXXXX)"
  cat >"${install_json}" <<EOF_JSON
{
  "version": "$(_json_escape "${version:-unknown}")",
  "ref": "$(_json_escape "${SECKIT_REF}")",
  "method": "uv",
  "package_source": "$(_json_escape "${PACKAGE_SOURCE}")",
  "github_repo": "$(_json_escape "${SECKIT_GITHUB_REPO}")",
  "source_commit": "$(_json_escape "${SECKIT_SOURCE_COMMIT}")",
  "source_ref": "$(_json_escape "${SECKIT_SOURCE_REF}")",
  "release_channel": "$(_json_escape "${SECKIT_RELEASE_CHANNEL}")",
  "rss_operator_url": "$(_json_escape "${SECKIT_RSS_OPERATOR_URL}")",
  "runtime_python": "$(_json_escape "${SECKIT_RUNTIME_PYTHON}")",
  "verified": false,
  "updated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF_JSON
  atomic_write_file_from "${SECKIT_INSTALL_STATE}" "${install_json}"
  rm -f "${install_json}"
}

load_previous_install_state() {
  [[ -f "${SECKIT_INSTALL_STATE}" ]] || return 0
  local parsed
  parsed="$("${PYTHON}" - <<'PY' "${SECKIT_INSTALL_STATE}" 2>/dev/null || true
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
try:
    payload = json.loads(path.read_text(encoding="utf-8"))
except Exception:
    print("||false")
    raise SystemExit(0)
print(
    f"{payload.get('ref','')}|{payload.get('package_source','')}|{str(bool(payload.get('verified', False))).lower()}"
)
PY
)"
  PREVIOUS_INSTALL_REF="${parsed%%|*}"
  parsed="${parsed#*|}"
  PREVIOUS_INSTALL_PACKAGE_SOURCE="${parsed%%|*}"
  PREVIOUS_INSTALL_VERIFIED="${parsed##*|}"
}

mark_install_verified() {
  [[ -f "${SECKIT_INSTALL_STATE}" ]] || return 0
  local tmp
  tmp="$(mktemp -t seckit-install-verified.XXXXXX)"
  "${PYTHON}" - <<'PY' "${SECKIT_INSTALL_STATE}" "${tmp}" >/dev/null 2>&1 || { rm -f "${tmp}"; return 0; }
import json
import sys
from pathlib import Path

src = Path(sys.argv[1])
dst = Path(sys.argv[2])
payload = json.loads(src.read_text(encoding="utf-8"))
payload["verified"] = True
dst.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
PY
  atomic_write_file_from "${SECKIT_INSTALL_STATE}" "${tmp}"
  rm -f "${tmp}"
}

should_skip_verification() {
  [[ "${NO_VERIFY}" -eq 0 ]] || return 1
  [[ "${SKIP_VERIFY_IF_UNCHANGED}" -eq 1 ]] || return 1
  [[ "${PREVIOUS_INSTALL_VERIFIED}" == "true" ]] || return 1
  [[ -n "${PREVIOUS_INSTALL_REF}" && "${PREVIOUS_INSTALL_REF}" == "${SECKIT_REF}" ]] || return 1
  [[ -n "${PREVIOUS_INSTALL_PACKAGE_SOURCE}" && "${PREVIOUS_INSTALL_PACKAGE_SOURCE}" == "${PACKAGE_SOURCE}" ]] || return 1
  return 0
}

write_launcher() {
  local launcher
  launcher="$(mktemp -t seckit-launcher.XXXXXX)"
  cat >"${launcher}" <<'EOF_LAUNCH'
#!/usr/bin/env bash
set -euo pipefail
STATE_DIR="${SECKIT_STATE_DIR_OVERRIDE:-$HOME/.local/share/seckit/state}"
RUNTIME_LINK="${SECKIT_RUNTIME_DIR_OVERRIDE:-$HOME/.local/share/seckit/runtime}/current"
COMMAND="$(basename "$0")"
case "${COMMAND}" in
  seckit|seckit-mcp) ;;
  *)
    echo "seckit launcher: unsupported command (${COMMAND})" >&2
    exit 1
    ;;
esac
if [[ ! -e "${RUNTIME_LINK}" ]]; then
  echo "seckit launcher: runtime link missing (${RUNTIME_LINK})" >&2
  exit 1
fi
RUNTIME_DIR="$(cd -P "${RUNTIME_LINK}" 2>/dev/null && pwd)"
if [[ -z "${RUNTIME_DIR}" || ! -x "${RUNTIME_DIR}/bin/${COMMAND}" ]]; then
  echo "seckit launcher: invalid runtime command (${RUNTIME_DIR}/bin/${COMMAND})" >&2
  exit 1
fi
export PYTHONDONTWRITEBYTECODE=1
exec "${RUNTIME_DIR}/bin/${COMMAND}" "$@"
EOF_LAUNCH
  chmod 755 "${launcher}"
  atomic_write_file_from "${SECKIT_LAUNCHER_PATH}" "${launcher}"
  atomic_write_file_from "${SECKIT_MCP_LAUNCHER_PATH}" "${launcher}"
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

_run_doctor_gate() {
  local label="${1:?}" success_msg="${2:?}"
  shift 2
  local -a args=("$@")
  if [[ "${VERBOSE}" -eq 1 ]]; then
    run_capture "${TARGET_RUNTIME}/bin/seckit" "${args[@]}"
    return $?
  fi
  local out_file err_file rc
  out_file="$(mktemp -t "seckit-${label}-out.XXXXXX")"
  err_file="$(mktemp -t "seckit-${label}-err.XXXXXX")"
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
  install_log "${success_msg}"
  rm -f "${out_file}" "${err_file}"
  return 0
}

run_install_check() {
  _run_doctor_gate install-check "Install verification passed." doctor --install-check
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
  --skip-verify-if-unchanged
                         Skip verification if ref/package_source already verified
  --ref TAG              Pin a published release tag (wheel preferred)
  --repo-url URL         Maintainer-only Git fallback when a wheel is absent
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
  ensure_operator_path
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
      --skip-verify-if-unchanged) SKIP_VERIFY_IF_UNCHANGED=1; shift ;;
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

load_installer_pins() {
  # Read the same pinned-artifact list verified by CI and embedded in the release.
  local script_dir pin_file digest name extra mdns_source="" count=0
  script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-./install.sh}")" && pwd)"
  if [[ -f "${script_dir}/installer-pins.sha256" && ! -L "${script_dir}/installer-pins.sha256" ]]; then
    pin_file="${script_dir}/installer-pins.sha256"
  elif [[ -f "${script_dir}/dependencies/installer-pins.sha256" && ! -L "${script_dir}/dependencies/installer-pins.sha256" ]]; then
    pin_file="${script_dir}/dependencies/installer-pins.sha256"
  else
    install_die "pinned dependency manifest is missing or unsafe"
  fi
  while read -r digest name extra; do
    [[ "${digest}" =~ ^[a-f0-9]{64}$ && "${name}" =~ ^[A-Za-z0-9_+.-]+$ && -z "${extra:-}" ]] || install_die "invalid pinned dependency entry"
    case "${name}" in
      libp2p-*-py3-none-any.whl)
        [[ -z "${BACKPORT_WHEEL}" ]] || install_die "duplicate libp2p pin"
        BACKPORT_WHEEL="${name}"; BACKPORT_SHA256="${digest}" ;;
      zeroconf-*-py3-none-any.whl)
        [[ -z "${MDNS_WHEEL}" ]] || install_die "duplicate zeroconf wheel pin"
        MDNS_WHEEL="${name}"; MDNS_SHA256="${digest}" ;;
      zeroconf-*.tar.gz)
        [[ -z "${mdns_source:-}" ]] || install_die "duplicate zeroconf source pin"
        mdns_source="${name}" ;;
      fastecdsa-*-cp312-cp312-manylinux2014_aarch64.manylinux_2_17_aarch64.whl)
        [[ -z "${FASTECDSA_WHEEL}" ]] || install_die "duplicate fastecdsa ARM wheel pin"
        FASTECDSA_WHEEL="${name}"; FASTECDSA_SHA256="${digest}"
        FASTECDSA_VERSION="${name#fastecdsa-}"
        FASTECDSA_VERSION="${FASTECDSA_VERSION%%-*}"
        [[ "${FASTECDSA_VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || install_die "invalid fastecdsa pin version" ;;
      *) install_die "unexpected pinned dependency name" ;;
    esac
    count=$((count + 1))
  done < "${pin_file}"
  [[ "${count}" -eq 4 && -n "${BACKPORT_WHEEL}" && -n "${MDNS_WHEEL}" \
    && -n "${FASTECDSA_WHEEL}" \
    && "${mdns_source:-}" == "${MDNS_WHEEL%-py3-none-any.whl}.tar.gz" ]] \
    || install_die "incomplete or inconsistent pinned dependency manifest"
}

detect_init_state() {
  # Never run `seckit init --yes` over even a partial customer store.
  local operator_home="$1"
  local defaults_file="${operator_home}/.config/seckit/defaults.json"
  local registry_file="${operator_home}/.config/seckit/registry.json"
  local database_file="${SECKIT_SQLITE_PATH:-${operator_home}/.config/seckit/seckit.sqlite}"
  local existing_count=0
  local path
  for path in "${defaults_file}" "${registry_file}" "${database_file}"; do
    if [[ -e "${path}" || -L "${path}" ]]; then
      existing_count=$((existing_count + 1))
    fi
  done
  if [[ "${existing_count}" -eq 0 ]]; then
    INIT_STATE="fresh"
  elif [[ "${existing_count}" -eq 3 ]]; then
    INIT_STATE="existing"
  else
    install_die "incomplete existing configuration; installation stopped before replacing the Secrets Kit runtime. Preserve the store and report this error."
  fi
}

main() {
  trap rollback_shell_profile_if_needed ERR
  trap 'preserve_failed_runtime; [[ -n "${PACKAGE_CACHE_FILE:-}" ]] && rm -f "${PACKAGE_CACHE_FILE}"; [[ -n "${PACKAGE_CACHE_DIR:-}" ]] && rmdir "${PACKAGE_CACHE_DIR}" 2>/dev/null || true; [[ -n "${DEPENDENCY_OVERRIDE_FILE:-}" ]] && rm -f "${DEPENDENCY_OVERRIDE_FILE}"; cleanup_dependency_cache' EXIT

  parse_args "$@"
  load_installer_pins
  require_user_managed_install
  if [[ "$DEV_MODE" -eq 0 && ( -z "$SECKIT_GITHUB_REPO" || -z "$SECKIT_RELEASE_CHANNEL" ) ]]; then
    install_die 'Use the CI-generated install.sh from the intended release; this source installer has no repository/channel identity.'
  fi
  preflight_install

  if [[ "${YES}" -eq 0 && ! -t 0 ]]; then
    YES=1
  fi
  if [[ -z "${SECKIT_REF}" && "${DEV_MODE}" -eq 1 ]]; then
    SECKIT_REF="dev"
  fi

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    install_log "dry-run: ref=${SECKIT_REF:-latest-${SECKIT_RELEASE_CHANNEL}} upgrade=${UPGRADE} repair=${REPAIR} dev=${DEV_MODE}"
    install_log "dry-run: runtime root ${SECKIT_RUNTIME_DIR}"
    if [[ "${JSON_OUT}" -eq 1 ]]; then
      emit_json "{\"dry_run\":true,\"ref\":\"${SECKIT_REF:-latest-${SECKIT_RELEASE_CHANNEL}}\",\"upgrade\":${UPGRADE},\"repair\":${REPAIR},\"dev\":${DEV_MODE}}"
    fi
    exit 0
  fi

  step 1 "Preparing runtime..."
  resolve_uv
  ensure_uv_runtime_python
  load_previous_install_state
  if [[ "${UPGRADE}" -eq 0 && "${NO_INIT}" -eq 0 ]]; then
    detect_init_state "${HOME}"
  fi
  if [[ -z "${SECKIT_REF}" ]]; then
    resolve_latest_release_tag
  fi
  step_done 1

  PREVIOUS_RUNTIME="$(current_runtime_path || true)"
  RUNTIME_JSON_BACKUP=""
  if [[ -f "${SECKIT_RUNTIME_JSON}" ]]; then
    RUNTIME_JSON_BACKUP="$(mktemp -t seckit-runtime-json-backup.XXXXXX)"
    cp -p "${SECKIT_RUNTIME_JSON}" "${RUNTIME_JSON_BACKUP}"
  fi
  resolve_package_spec
  validate_local_release_artifact
  prepare_dependency_override
  if [[ "${PACKAGE_SPEC}" == file://* ]]; then
    local package_file package_dir
    package_file="${PACKAGE_SPEC#file://}"
    package_dir="$(dirname "${package_file}")"
    if [[ "$(basename "${package_dir}")" == seckit-release-wheel.* ]]; then
      PACKAGE_CACHE_FILE="${package_file}"
      PACKAGE_CACHE_DIR="${package_dir}"
    fi
  fi

  step 2 "Creating isolated runtime..."
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
  install_log "Validating native transport dependencies..."
  validate_transport_dependencies
  TARGET_RUNTIME_ACTIVATING=1
  write_runtime_state
  write_launcher
  restart_managed_daemon_after_upgrade
  write_install_state
  prune_old_runtimes
  if [[ -n "${RUNTIME_JSON_BACKUP:-}" ]]; then
    rm -f "${RUNTIME_JSON_BACKUP}"
    RUNTIME_JSON_BACKUP=""
  fi
  install_log "Package installed."
  step_done 3

  step 4 "Running first-time setup..."
  if [[ "${INIT_STATE}" == "fresh" ]]; then
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
  if [[ "${INIT_STATE}" == "fresh" || "${INIT_STATE}" == "existing" ]]; then
    run_capture "${TARGET_RUNTIME}/bin/seckit" daemon service install || install_die "managed service setup failed"
    run_capture "${TARGET_RUNTIME}/bin/seckit" daemon service status || install_die "managed service is not healthy"
    warn_if_systemd_linger_disabled
  fi
  apply_shell_profile_block
  step_done 4

  step 5 "Verifying install..."
  if should_skip_verification; then
    install_log "Verification skipped (already verified ref=${SECKIT_REF}, source=${PACKAGE_SOURCE})."
  elif [[ "${NO_VERIFY}" -eq 0 ]]; then
    install_log "Running install verification..."
    run_install_check || install_die "install verification failed"
    mark_install_verified
  else
    install_log "Install verification skipped."
    verbose_log "verification skipped"
  fi
  step_done 5

  # Seal only freshly installed, standard-layout generations supporting removal.
  # Never manufacture receipts for pre-existing/shared runtimes.
  if [[ "${SECKIT_RUNTIME_DIR}" == "${HOME}/.local/share/seckit/runtime" \
    && "${SECKIT_LAUNCHER_PATH}" == "${HOME}/.local/bin/seckit" \
    && "${SECKIT_MCP_LAUNCHER_PATH}" == "${HOME}/.local/bin/seckit-mcp" ]] \
    && PYTHONDONTWRITEBYTECODE=1 "${TARGET_RUNTIME}/bin/seckit" uninstall --help >/dev/null 2>&1; then
    PYTHONDONTWRITEBYTECODE=1 "${TARGET_RUNTIME}/bin/python" -m secrets_kit.uninstall "${TARGET_RUNTIME}" \
      || install_die "unable to record dedicated runtime ownership; uninstall qualification is unavailable"
  fi

  clear_shell_profile_backup

  if [[ "${JSON_OUT}" -eq 1 ]]; then
    emit_json "{\"ok\":true,\"ref\":\"${SECKIT_REF}\",\"runtime\":\"${TARGET_RUNTIME}\",\"python\":\"${RUNTIME_PYTHON_VERSION}\",\"package_source\":\"${PACKAGE_SOURCE}\",\"uv\":\"${UV_BIN}\"}"
  else
    printf '\nSecrets-Kit installed successfully.\n' >&2
    install_log "Version: $("${TARGET_RUNTIME}/bin/seckit" --version 2>/dev/null | awk 'NF {print $2; exit}')"
    install_log "Command: ${SECKIT_LAUNCHER_PATH}"
    install_log "MCP command: ${SECKIT_MCP_LAUNCHER_PATH}"
    if [[ "${IS_INTERACTIVE}" -eq 0 || "${NO_SHELL_PROFILE}" -eq 1 || "${SAFE_MODE}" -eq 1 ]]; then
      install_log "PATH hint: export PATH=\"${SECKIT_LAUNCHER_BIN_DIR}:\$PATH\""
    fi
  fi
}

main "$@"
