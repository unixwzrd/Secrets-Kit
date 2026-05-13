#!/usr/bin/env bash
# Post-bootstrap smoke. After `source env.sh`, works from any cwd (§11).
set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"

usage() {
  cat <<'EOF'
Usage (canonical — after bootstrap, from any cwd):
  . /absolute/path/to/peer-root/env.sh
  command -v seckit
  seckit --help
  "$SECKIT_REPO_ROOT/scripts/bootstrap_vm_smoke.sh" --env-file "$SECKIT_ENV_FILE"

Or pass env explicitly:
  /path/to/repo/scripts/bootstrap_vm_smoke.sh --env-file /path/to/peer-root/env.sh

Discovery when --env-file omitted:
  1) SECKIT_ENV_FILE (if set and file exists)
  2) SECKIT_PEER_ROOT/env.sh
  3) ./env.sh in current working directory (last resort)

Stock systems: Python 3.9+ with venv (no Conda required). Install git only for --git bootstrap.

See docs/plans/PHASE6B0_PEER_BOOTSTRAP.md

Options:
  -h, --help
EOF
}

ENV_FILE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --env-file)
      ENV_FILE="${2:-}"
      shift 2
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

if [[ -z "$ENV_FILE" ]]; then
  if [[ -n "${SECKIT_ENV_FILE:-}" && -f "$SECKIT_ENV_FILE" ]]; then
    ENV_FILE="$SECKIT_ENV_FILE"
  elif [[ -n "${SECKIT_PEER_ROOT:-}" && -f "${SECKIT_PEER_ROOT}/env.sh" ]]; then
    ENV_FILE="${SECKIT_PEER_ROOT}/env.sh"
  elif [[ -f "$(pwd)/env.sh" ]]; then
    ENV_FILE="$(pwd)/env.sh"
  else
    echo "bootstrap_vm_smoke.sh: pass --env-file or source env.sh (sets SECKIT_ENV_FILE)" >&2
    exit 1
  fi
fi

# shellcheck source=/dev/null
set -a
source "$ENV_FILE"
set +a

if [[ -z "${SECKIT_PEER_ROOT:-}" || -z "${SECKIT_SQLITE_DB:-}" ]]; then
  echo "bootstrap_vm_smoke.sh: SECKIT_PEER_ROOT / SECKIT_SQLITE_DB not set after sourcing env" >&2
  exit 1
fi

if [[ -z "${SECKIT_REPO_ROOT:-}" ]]; then
  echo "bootstrap_vm_smoke.sh: SECKIT_REPO_ROOT not set (re-run bootstrap_peer.sh to regenerate env.sh)" >&2
  exit 1
fi

if [[ ! -d "${SECKIT_REPO_ROOT}/scripts" ]]; then
  echo "bootstrap_vm_smoke.sh: SECKIT_REPO_ROOT has no scripts/ (SECKIT_REPO_ROOT=$SECKIT_REPO_ROOT)" >&2
  exit 1
fi

echo "=== bootstrap_vm_smoke: $(hostname) @ $(date -u '+%Y-%m-%dT%H:%M:%SZ') ==="
echo "SECKIT_ENV_FILE=$SECKIT_ENV_FILE"
echo "SECKIT_PEER_ROOT=$SECKIT_PEER_ROOT"
echo "SECKIT_REPO_ROOT=$SECKIT_REPO_ROOT"
echo "HOME=$HOME (should equal peer root for isolation)"

if ! command -v seckit >/dev/null 2>&1; then
  echo "ERROR: seckit not on PATH (expected after sourcing env.sh)" >&2
  exit 1
fi
echo "seckit: $(command -v seckit)"
seckit --help >/dev/null
echo "seckit --help: ok"

echo "=== identity ==="
seckit identity show

echo "=== doctor (sqlite) ==="
seckit doctor --backend sqlite --db "$SECKIT_SQLITE_DB"

echo "=== reconcile verify ==="
seckit reconcile verify --backend sqlite --db "$SECKIT_SQLITE_DB"

echo "=== daemon ping (optional) ==="
if seckit daemon ping 2>/dev/null; then
  echo "daemon: reachable"
else
  echo "INFO: daemon not running or not reachable (expected if seckitd not started)" >&2
fi

echo "=== bootstrap_vm_smoke: PASS ==="
echo "(invoked from: $SCRIPT_DIR/bootstrap_vm_smoke.sh)"
