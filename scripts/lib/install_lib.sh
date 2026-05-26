# shellcheck shell=bash
# Shared helpers for install.sh (source only).

set -euo pipefail

SECKIT_MANAGED_VENV="${SECKIT_MANAGED_VENV:-$HOME/.local/share/seckit/venv}"
SECKIT_INSTALL_STATE="${SECKIT_INSTALL_STATE:-$HOME/.config/seckit/install.json}"
SECKIT_REPO_URL="${SECKIT_REPO_URL:-https://github.com/unixwzrd/Secrets-Kit.git}"

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

resolve_python() {
  PYTHON=""
  SECKIT_INSTALL_METHOD=""
  SECKIT_VENV_PATH=""

  if [[ -n "${CONDA_PREFIX:-}" && -x "${CONDA_PREFIX}/bin/python" ]]; then
    PYTHON="${CONDA_PREFIX}/bin/python"
    SECKIT_INSTALL_METHOD="conda"
    return 0
  fi

  if [[ -n "${VIRTUAL_ENV:-}" && -x "${VIRTUAL_ENV}/bin/python" ]]; then
    PYTHON="${VIRTUAL_ENV}/bin/python"
    SECKIT_INSTALL_METHOD="venv"
    SECKIT_VENV_PATH="${VIRTUAL_ENV}"
    return 0
  fi

  if [[ -x "${SECKIT_MANAGED_VENV}/bin/python" ]]; then
    PYTHON="${SECKIT_MANAGED_VENV}/bin/python"
    SECKIT_INSTALL_METHOD="managed"
    SECKIT_VENV_PATH="${SECKIT_MANAGED_VENV}"
    return 0
  fi

  local bootstrap_py=""
  if command -v python3 >/dev/null 2>&1; then
    bootstrap_py="$(command -v python3)"
  elif command -v python >/dev/null 2>&1; then
    bootstrap_py="$(command -v python)"
  else
    install_die "python3 not found; install Python 3.9+ or activate conda/venv"
  fi

  install_log "creating managed venv at ${SECKIT_MANAGED_VENV}"
  mkdir -p "$(dirname "${SECKIT_MANAGED_VENV}")"
  "${bootstrap_py}" -m venv "${SECKIT_MANAGED_VENV}"
  PYTHON="${SECKIT_MANAGED_VENV}/bin/python"
  SECKIT_INSTALL_METHOD="managed"
  SECKIT_VENV_PATH="${SECKIT_MANAGED_VENV}"
}

resolve_python_for_upgrade() {
  PYTHON=""
  SECKIT_INSTALL_METHOD=""
  SECKIT_VENV_PATH=""

  if [[ -f "${SECKIT_INSTALL_STATE}" ]]; then
    local recorded=""
    recorded="$(
      "${SECKIT_PYTHON_FOR_STATE:-python3}" -c "
import json, sys
from pathlib import Path
p = Path(sys.argv[1])
if not p.is_file():
    sys.exit(0)
data = json.loads(p.read_text(encoding='utf-8'))
print(data.get('interpreter', ''))
" "${SECKIT_INSTALL_STATE}" 2>/dev/null || true
    )"
    if [[ -n "${recorded}" && -x "${recorded}" ]]; then
      PYTHON="${recorded}"
      SECKIT_INSTALL_METHOD="$(
        "${recorded}" -c "
import json, sys
from pathlib import Path
data = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
print(data.get('install_method', 'unknown'))
" "${SECKIT_INSTALL_STATE}" 2>/dev/null || echo unknown
      )"
      SECKIT_VENV_PATH="$(
        "${recorded}" -c "
import json, sys
from pathlib import Path
data = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
print(data.get('venv_path') or '')
" "${SECKIT_INSTALL_STATE}" 2>/dev/null || true
      )"
      install_log "upgrade: reusing interpreter ${PYTHON}"
      return 0
    fi
    if [[ -n "${recorded}" ]]; then
      install_warn "recorded interpreter missing or not executable: ${recorded}"
    fi
  else
    install_warn "no install state at ${SECKIT_INSTALL_STATE}; resolving environment"
  fi

  resolve_python
}

validate_python() {
  if [[ -z "${PYTHON:-}" || ! -x "${PYTHON}" ]]; then
    install_die "no Python interpreter selected"
  fi

  "${PYTHON}" -c '
import platform, sys
if sys.version_info < (3, 9):
    raise SystemExit(f"Python {sys.version_info[0]}.{sys.version_info[1]} < 3.9")
system = platform.system()
machine = platform.machine()
print(f"platform={system} machine={machine} python={platform.python_version()}")
unsupported = {"Windows"}
if system in unsupported:
    raise SystemExit(f"unsupported platform: {system}")
' || install_die "Python validation failed"

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
  install_log "editable dev install from ${repo_root}"
  "${PYTHON}" -m pip install -e "${repo_root}[dev]"
}

write_install_state() {
  local version=""
  version="$("${PYTHON}" -c 'from secrets_kit import __version__; print(__version__)' 2>/dev/null || echo unknown)"
  mkdir -p "$(dirname "${SECKIT_INSTALL_STATE}")"
  SECKIT_INSTALL_STATE="${SECKIT_INSTALL_STATE}" \
  SECKIT_INSTALL_METHOD="${SECKIT_INSTALL_METHOD}" \
  SECKIT_VENV_PATH="${SECKIT_VENV_PATH:-}" \
  SECKIT_REF="${SECKIT_REF}" \
  SECKIT_VERSION="${version}" \
  SECKIT_INTERPRETER="${PYTHON}" \
    "${PYTHON}" -c '
import json, os
from pathlib import Path
state = {
    "interpreter": os.environ["SECKIT_INTERPRETER"],
    "venv_path": os.environ.get("SECKIT_VENV_PATH") or None,
    "install_method": os.environ["SECKIT_INSTALL_METHOD"],
    "version": os.environ.get("SECKIT_VERSION", "unknown"),
    "ref": os.environ.get("SECKIT_REF", ""),
}
path = Path(os.environ["SECKIT_INSTALL_STATE"])
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
'
}

run_seckit() {
  local bin_dir=""
  bin_dir="$("${PYTHON}" -c 'import sys; print(sys.prefix)')/bin"
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
