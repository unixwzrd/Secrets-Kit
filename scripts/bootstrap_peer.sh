#!/usr/bin/env bash
# Disposable peer bootstrap: layout peer-root, .venv, optional git repo/, env.sh, identity.
# Does not modify system Python; does not auto-update. Safe to run from any cwd (§11).
set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"

# Minimum CPython (must match pyproject requires-python)
MIN_PY_MAJOR=3
MIN_PY_MINOR=9

usage() {
  cat <<'EOF'
Usage:
  /path/to/scripts/bootstrap_peer.sh --peer-root DIR (--editable PATH | --git URL) [options]

Required:
  --peer-root PATH          Relocatable peer directory to create/populate

Source (one required):
  --editable PATH           pip install -e PATH; symlink PATH into peer-root/repo/
  --git URL                 git clone URL into peer-root/repo/ (requires git on PATH)

Git pinning (optional; --branch and --ref are mutually exclusive):
  --branch NAME             After clone, checkout this branch
  --ref SPEC                After clone, checkout tag or commit SHA

Options:
  --name NAME               Peer label for env.sh (default: peer)
  --force-venv              Remove existing .venv before creating
  --no-identity-init        Skip `seckit identity init` after install
  --no-passphrase           Set SECKIT_SQLITE_PLAINTEXT_DEBUG=1 (disposable peers only)
  -h, --help                This help

Prerequisites (stock systems):
  - Python 3.9+ with venv (Debian/Ubuntu: apt install python3 python3-venv)
  - git when using --git
  - openssl optional (passphrase); else selected Python's secrets module

Python selection:
  1) python3 on PATH if >= 3.9
  2) python3.13, python3.12, ... as needed
  3) Optional: CONDA_PREFIX/bin/python if set

After bootstrap, from any directory:
  source "$SECKIT_ENV_FILE"   # paths printed at end of bootstrap
  command -v seckit && seckit --help
  "$SECKIT_REPO_ROOT/scripts/bootstrap_vm_smoke.sh" --env-file "$SECKIT_ENV_FILE"

See docs/plans/PHASE6B0_PEER_BOOTSTRAP.md
EOF
}

PEER_ROOT=""
PEER_NAME="peer"
EDITABLE=""
GIT_URL=""
BRANCH=""
REF=""
FORCE_VENV=0
NO_IDENTITY=0
PLAIN_DEBUG=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --peer-root)
      PEER_ROOT="${2:-}"
      shift 2
      ;;
    --editable)
      EDITABLE="${2:-}"
      shift 2
      ;;
    --git)
      GIT_URL="${2:-}"
      shift 2
      ;;
    --branch)
      BRANCH="${2:-}"
      shift 2
      ;;
    --ref)
      REF="${2:-}"
      shift 2
      ;;
    --name)
      PEER_NAME="${2:-}"
      shift 2
      ;;
    --force-venv)
      FORCE_VENV=1
      shift
      ;;
    --no-identity-init)
      NO_IDENTITY=1
      shift
      ;;
    --no-passphrase)
      PLAIN_DEBUG=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "$PEER_ROOT" ]]; then
  echo "bootstrap_peer.sh: --peer-root is required" >&2
  exit 1
fi

if [[ -n "$EDITABLE" && -n "$GIT_URL" ]]; then
  echo "bootstrap_peer.sh: use only one of --editable or --git" >&2
  exit 1
fi
if [[ -z "$EDITABLE" && -z "$GIT_URL" ]]; then
  echo "bootstrap_peer.sh: provide --editable PATH or --git URL" >&2
  exit 1
fi

if [[ -n "$BRANCH" && -n "$REF" ]]; then
  echo "bootstrap_peer.sh: use only one of --branch or --ref" >&2
  exit 1
fi

_py_version_ok() {
  local py="$1"
  "$py" -c "import sys; v=sys.version_info; raise SystemExit(0 if (v.major,v.minor)>=(${MIN_PY_MAJOR},${MIN_PY_MINOR}) else 1)" 2>/dev/null
}

_venv_module_ok() {
  local py="$1"
  "$py" -c "import venv" 2>/dev/null
}

select_python() {
  SELECTED_PY=""
  local c p
  for c in python3 python3.13 python3.12 python3.11 python3.10; do
    if command -v "$c" >/dev/null 2>&1; then
      p="$(command -v "$c")"
      if _py_version_ok "$p"; then
        SELECTED_PY="$p"
        SELECTED_PY_SOURCE="PATH:$c"
        return 0
      fi
    fi
  done
  if [[ -n "${CONDA_PREFIX:-}" && -x "${CONDA_PREFIX}/bin/python" ]]; then
    p="${CONDA_PREFIX}/bin/python"
    if _py_version_ok "$p"; then
      SELECTED_PY="$p"
      SELECTED_PY_SOURCE="CONDA_PREFIX"
      return 0
    fi
  fi
  return 1
}

if ! select_python; then
  echo "bootstrap_peer.sh: no Python >= ${MIN_PY_MAJOR}.${MIN_PY_MINOR} found on PATH." >&2
  echo "Install Python 3.9+ (e.g. python3). Debian/Ubuntu: sudo apt install python3 python3-venv" >&2
  echo "Optional: set CONDA_PREFIX to a Conda env that provides python." >&2
  exit 1
fi

if ! _venv_module_ok "$SELECTED_PY"; then
  echo "bootstrap_peer.sh: selected interpreter has no 'venv' module: $SELECTED_PY" >&2
  echo "Debian/Ubuntu: sudo apt install python3-venv" >&2
  echo "RHEL/Rocky: sudo dnf install python3" >&2
  exit 1
fi

echo "bootstrap_peer.sh: selected Python: $SELECTED_PY ($SELECTED_PY_SOURCE)"
echo "bootstrap_peer.sh: $($SELECTED_PY -c 'import sys; print(sys.version.split()[0])')"

mkdir -p "$PEER_ROOT"
PEER_ROOT="$(cd "$PEER_ROOT" && pwd)"
mkdir -p "$PEER_ROOT/repo" "$PEER_ROOT/runtime" "$PEER_ROOT/state" \
  "$PEER_ROOT/logs" "$PEER_ROOT/bundles" "$PEER_ROOT/snapshots"

if [[ "$FORCE_VENV" -eq 1 && -d "$PEER_ROOT/.venv" ]]; then
  rm -rf "$PEER_ROOT/.venv"
fi

if [[ ! -d "$PEER_ROOT/.venv" ]]; then
  if ! "$SELECTED_PY" -m venv "$PEER_ROOT/.venv"; then
    echo "bootstrap_peer.sh: 'python -m venv' failed for: $SELECTED_PY" >&2
    echo "Install the venv package for your distribution (e.g. python3-venv)." >&2
    exit 1
  fi
fi

PIP=( "$PEER_ROOT/.venv/bin/pip" )
if ! "${PIP[@]}" install -U pip setuptools wheel; then
  echo "bootstrap_peer.sh: pip upgrade (pip setuptools wheel) failed." >&2
  exit 1
fi

if [[ -n "$EDITABLE" ]]; then
  if [[ ! -d "$EDITABLE" ]]; then
    echo "bootstrap_peer.sh: --editable path is not a directory: $EDITABLE" >&2
    exit 1
  fi
  EDITABLE="$(cd "$EDITABLE" && pwd)"
  rm -rf "$PEER_ROOT/repo"
  ln -sfn "$EDITABLE" "$PEER_ROOT/repo"
  if ! "${PIP[@]}" install -e "$EDITABLE"; then
    echo "bootstrap_peer.sh: pip install -e failed for: $EDITABLE" >&2
    exit 1
  fi
elif [[ -n "$GIT_URL" ]]; then
  if ! command -v git >/dev/null 2>&1; then
    echo "bootstrap_peer.sh: 'git' not on PATH; install git or use --editable with a local checkout path." >&2
    exit 1
  fi
  if [[ -d "$PEER_ROOT/repo/.git" ]]; then
    echo "bootstrap_peer.sh: repo/ already exists; skip clone (update manually if needed)" >&2
  else
    rm -rf "$PEER_ROOT/repo"
    if ! git clone "$GIT_URL" "$PEER_ROOT/repo"; then
      echo "bootstrap_peer.sh: git clone failed." >&2
      exit 1
    fi
    if [[ -n "$REF" ]]; then
      if ! git -C "$PEER_ROOT/repo" checkout "$REF"; then
        echo "bootstrap_peer.sh: git checkout '$REF' failed." >&2
        exit 1
      fi
    elif [[ -n "$BRANCH" ]]; then
      if ! git -C "$PEER_ROOT/repo" checkout "$BRANCH"; then
        echo "bootstrap_peer.sh: git checkout '$BRANCH' failed." >&2
        exit 1
      fi
    fi
  fi
  if ! "${PIP[@]}" install -e "$PEER_ROOT/repo"; then
    echo "bootstrap_peer.sh: pip install -e failed for: $PEER_ROOT/repo" >&2
    exit 1
  fi
fi

SECKIT_REPO_ROOT_ABS="$PEER_ROOT/repo"
SECKIT_STATE_DIR="$PEER_ROOT/state"
SECKIT_SQLITE_DB="$SECKIT_STATE_DIR/vault.db"
SQLITE_PASS=""
if [[ "$PLAIN_DEBUG" -eq 1 ]]; then
  SQLITE_EXTRA_COMMENT="SECKIT_SQLITE_PLAINTEXT_DEBUG=1 (disposable / non-production)"
else
  if command -v openssl >/dev/null 2>&1; then
    SQLITE_PASS="$(openssl rand -hex 32)"
  else
    SQLITE_PASS="$("$SELECTED_PY" -c 'import secrets; print(secrets.token_hex(32))' 2>/dev/null || true)"
  fi
  if [[ -z "$SQLITE_PASS" ]]; then
    echo "bootstrap_peer.sh: could not generate passphrase; install openssl or pass --no-passphrase" >&2
    exit 1
  fi
  SQLITE_EXTRA_COMMENT="generated passphrase (store peer-root securely; disposable peers only)"
fi

_q() {
  printf '%q' "$1"
}

ENV_FILE="$PEER_ROOT/env.sh"
umask 077
{
  echo "# Generated by bootstrap_peer.sh — disposable peer environment (do not source from relative cwd without absolute path)"
  echo "export SECKIT_ENV_FILE=$(_q "$ENV_FILE")"
  echo "export SECKIT_REPO_ROOT=$(_q "$SECKIT_REPO_ROOT_ABS")"
  echo "export SECKIT_PEER_NAME=$(_q "$PEER_NAME")"
  echo "export SECKIT_PEER_ROOT=$(_q "$PEER_ROOT")"
  echo "# Isolate metadata + identity under peer (registry uses ~/.config/seckit relative to HOME)"
  echo "export HOME=$(_q "$PEER_ROOT")"
  echo "export SECKIT_STATE_DIR=$(_q "$SECKIT_STATE_DIR")"
  echo "export SECKIT_SQLITE_DB=$(_q "$SECKIT_SQLITE_DB")"
  echo "export SECKIT_RUNTIME_DIR=$(_q "$PEER_ROOT/runtime")"
  echo "export SECKIT_LOG_DIR=$(_q "$PEER_ROOT/logs")"
  echo "export SECKIT_BUNDLE_DIR=$(_q "$PEER_ROOT/bundles")"
  echo "export SECKIT_SNAPSHOT_DIR=$(_q "$PEER_ROOT/snapshots")"
  echo "# Convenience: actual identity path is \$HOME/.config/seckit/identity"
  echo "export SECKIT_CONFIG_DIR=$(_q "$PEER_ROOT/.config/seckit")"
  if [[ "$PLAIN_DEBUG" -eq 1 ]]; then
    echo "export SECKIT_SQLITE_PLAINTEXT_DEBUG=1"
    echo "# $SQLITE_EXTRA_COMMENT"
  else
    echo "export SECKIT_SQLITE_PASSPHRASE=$(_q "$SQLITE_PASS")"
    echo "# $SQLITE_EXTRA_COMMENT"
  fi
  echo "export PATH=$(_q "$PEER_ROOT/.venv/bin"):\$PATH"
} >"$ENV_FILE"
chmod 600 "$ENV_FILE"

echo "bootstrap_peer.sh: wrote $ENV_FILE"

# shellcheck disable=SC1090
set -a
# shellcheck source=/dev/null
source "$ENV_FILE"
set +a

SECKIT_BIN="$PEER_ROOT/.venv/bin/seckit"
if [[ "$NO_IDENTITY" -eq 0 ]]; then
  if ! "$SECKIT_BIN" identity show >/dev/null 2>&1; then
    echo "bootstrap_peer.sh: initializing host identity..."
    "$SECKIT_BIN" identity init
  else
    echo "bootstrap_peer.sh: identity already present; skipping init (use identity init --force manually)"
  fi
fi

echo ""
echo "=== Host identity summary (public) ==="
"$SECKIT_BIN" identity show || true
PUB_DIR="$SECKIT_STATE_DIR/public"
mkdir -p "$PUB_DIR"
if "$SECKIT_BIN" identity export -o "$PUB_DIR/host-identity.json" 2>/dev/null; then
  echo "bootstrap_peer.sh: wrote public export: $PUB_DIR/host-identity.json"
  echo "Operator: share that file with peers via seckit peer add (manual trust only)."
fi

echo ""
echo "=== Bootstrap success (from any cwd, after sourcing env.sh) ==="
echo ". $(_q "$ENV_FILE")"
echo "command -v seckit && seckit --help"
echo "$(_q "$SECKIT_REPO_ROOT_ABS/scripts/bootstrap_vm_smoke.sh") --env-file $(_q "$ENV_FILE")"
echo ""
echo "This script lives at: $SCRIPT_DIR/bootstrap_peer.sh"
echo ""
