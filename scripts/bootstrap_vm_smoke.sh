#!/usr/bin/env bash
# Post-bootstrap smoke for a disposable peer. Requires env.sh-sourced environment.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  source /path/to/peer/env.sh
  ./scripts/bootstrap_vm_smoke.sh

Or:
  SECKIT_PEER_ROOT=/path/to/peer ./scripts/bootstrap_vm_smoke.sh

Or:
  ./scripts/bootstrap_vm_smoke.sh --env-file /path/to/peer/env.sh

Runs non-interactive checks: seckit on PATH, identity, doctor (sqlite), reconcile verify.

See docs/plans/PHASE6B0_PEER_BOOTSTRAP.md and docs/plans/PHASE6B_OPERATIONAL_VALIDATION.md

Rocky 9 / Debian notes: install git, Python 3.9+, openssl; use same bootstrap_peer.sh
Python policy (PATH python or CONDA_PREFIX).

Related:
  scripts/peer_sync_remote_smoke.sh — broader remote / optional unittest hooks
  docs/PEER_SYNC.md — bundle workflows

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
  if [[ -n "${SECKIT_PEER_ROOT:-}" && -f "${SECKIT_PEER_ROOT}/env.sh" ]]; then
    ENV_FILE="${SECKIT_PEER_ROOT}/env.sh"
  elif [[ -f "$(pwd)/env.sh" ]]; then
    ENV_FILE="$(pwd)/env.sh"
  else
    echo "bootstrap_vm_smoke.sh: source env.sh first, pass --env-file, or set SECKIT_PEER_ROOT" >&2
    exit 1
  fi
fi

# shellcheck source=/dev/null
set -a
source "$ENV_FILE"
set +a

if [[ -z "${SECKIT_PEER_ROOT:-}" || -z "${SECKIT_SQLITE_DB:-}" ]]; then
  echo "bootstrap_vm_smoke.sh: SECKIT_PEER_ROOT / SECKIT_SQLITE_DB not set" >&2
  exit 1
fi

echo "=== bootstrap_vm_smoke: $(hostname) @ $(date -u '+%Y-%m-%dT%H:%M:%SZ') ==="
echo "SECKIT_PEER_ROOT=$SECKIT_PEER_ROOT"
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
