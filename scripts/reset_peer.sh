#!/usr/bin/env bash
# Reset disposable peer state. Requires env.sh (or peer root) for paths.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  reset_peer.sh [options]

Loads peer environment, then removes selected state. Bundles/ and snapshots/ are
preserved unless --purge-artifacts is set.

Environment / discovery:
  Prefer: source env.sh (plan contract)
  Or set: SECKIT_PEER_ROOT pointing at peer directory (uses SECKIT_PEER_ROOT/env.sh)
  Or: run from peer root with ./env.sh present and pass --env-file ./env.sh

Options:
  --env-file PATH      Source this env.sh (default: auto)
  --vault-only         Remove only SECKIT_SQLITE_DB
  --full-config        Remove ~/.config/seckit under peer HOME (registry, identity, peers)
  --runtime            Clear SECKIT_RUNTIME_DIR contents (optional daemon socket area may differ)
  --venv               Remove peer .venv (re-run bootstrap_peer.sh to recreate)
  --only-venv          Only remove .venv (no vault/config/runtime reset)
  --purge-artifacts    Also remove bundles/ and snapshots/ under peer root
  --stop-daemon        Best-effort: pkill seckitd for current user (optional)
  --dry-run            Print actions only
  -h, --help           This help

Default when no mode flags: remove vault DB, full ~/.config/seckit under peer, and runtime dir.
Use --only-venv to recreate just the virtualenv without wiping identity/SQLite.

See docs/plans/PHASE6B0_PEER_BOOTSTRAP.md
EOF
}

ENV_FILE=""
VAULT_ONLY=0
FULL_CONFIG=0
RUNTIME_CLEAR=0
VENV_RM=0
PURGE_ARTIFACTS=0
STOP_DAEMON=0
DRY=0
DEFAULT_MODE=1
ONLY_VENV=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --env-file)
      ENV_FILE="${2:-}"
      shift 2
      ;;
    --vault-only)
      DEFAULT_MODE=0
      VAULT_ONLY=1
      shift
      ;;
    --full-config)
      DEFAULT_MODE=0
      FULL_CONFIG=1
      shift
      ;;
    --runtime)
      DEFAULT_MODE=0
      RUNTIME_CLEAR=1
      shift
      ;;
    --venv)
      VENV_RM=1
      shift
      ;;
    --only-venv)
      ONLY_VENV=1
      DEFAULT_MODE=0
      VAULT_ONLY=0
      FULL_CONFIG=0
      RUNTIME_CLEAR=0
      VENV_RM=1
      shift
      ;;
    --purge-artifacts)
      PURGE_ARTIFACTS=1
      shift
      ;;
    --stop-daemon)
      STOP_DAEMON=1
      shift
      ;;
    --dry-run)
      DRY=1
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

if [[ -z "$ENV_FILE" ]]; then
  if [[ -n "${SECKIT_PEER_ROOT:-}" && -f "${SECKIT_PEER_ROOT}/env.sh" ]]; then
    ENV_FILE="${SECKIT_PEER_ROOT}/env.sh"
  elif [[ -f "$(pwd)/env.sh" ]]; then
    ENV_FILE="$(pwd)/env.sh"
  else
    echo "reset_peer.sh: set --env-file or SECKIT_PEER_ROOT, or run from peer root with env.sh" >&2
    exit 1
  fi
fi

if [[ ! -f "$ENV_FILE" ]]; then
  echo "reset_peer.sh: env file not found: $ENV_FILE" >&2
  exit 1
fi

# shellcheck source=/dev/null
set -a
source "$ENV_FILE"
set +a

if [[ -z "${SECKIT_PEER_ROOT:-}" ]]; then
  echo "reset_peer.sh: SECKIT_PEER_ROOT not set after sourcing env.sh" >&2
  exit 1
fi

runrm() {
  local p="$1"
  if [[ ! -e "$p" ]]; then
    return 0
  fi
  if [[ "$DRY" -eq 1 ]]; then
    echo "DRY-RUN rm -rf $(_q "$p")"
    return 0
  fi
  rm -rf "$p"
  echo "removed: $p"
}

_q() { printf '%q' "$1"; }

if [[ "$STOP_DAEMON" -eq 1 ]]; then
  if [[ "$DRY" -eq 1 ]]; then
    echo "DRY-RUN: pkill -u \"$(whoami)\" -f seckitd  (best-effort)"
  else
    pkill -u "$(whoami)" -f seckitd 2>/dev/null || true
    echo "stop-daemon: sent best-effort pkill for seckitd (ignore if none)"
  fi
fi

if [[ "$ONLY_VENV" -eq 1 ]]; then
  :
elif [[ "$DEFAULT_MODE" -eq 1 ]]; then
  VAULT_ONLY=1
  FULL_CONFIG=1
  RUNTIME_CLEAR=1
fi

if [[ "$VAULT_ONLY" -eq 1 && -n "${SECKIT_SQLITE_DB:-}" ]]; then
  runrm "$SECKIT_SQLITE_DB"
fi

CFG="$SECKIT_PEER_ROOT/.config/seckit"
if [[ "$FULL_CONFIG" -eq 1 ]]; then
  runrm "$CFG"
fi

if [[ "$RUNTIME_CLEAR" -eq 1 ]]; then
  RD="${SECKIT_RUNTIME_DIR:-$SECKIT_PEER_ROOT/runtime}"
  if [[ -d "$RD" ]]; then
    if [[ "$DRY" -eq 1 ]]; then
      echo "DRY-RUN: clear directory $(_q "$RD")"
    else
      find "$RD" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
      echo "cleared: $RD"
    fi
  fi
fi

if [[ "$PURGE_ARTIFACTS" -eq 1 ]]; then
  runrm "$SECKIT_PEER_ROOT/bundles"
  runrm "$SECKIT_PEER_ROOT/snapshots"
  mkdir -p "$SECKIT_PEER_ROOT/bundles" "$SECKIT_PEER_ROOT/snapshots"
  echo "recreated empty bundles/ and snapshots/"
fi

if [[ "$VENV_RM" -eq 1 ]]; then
  runrm "$SECKIT_PEER_ROOT/.venv"
fi

echo "reset_peer.sh: done"
