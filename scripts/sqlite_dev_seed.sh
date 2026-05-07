#!/usr/bin/env bash
# Load fake demo secrets into a throwaway SQLite DB (safe for local testing only).
set -euo pipefail

# Fixed test passphrase — override only if you insist: SECKIT_SQLITE_PASSPHRASE=...
SYNTHETIC_PASSPHRASE="seckit-dev-synthetic-vault"

usage() {
  cat <<'EOF'
Usage: sqlite_dev_seed.sh [--force]

Reads fixtures/synthetic-sample.env (tracked in repo), imports into:
  ~/.config/seckit/secrets-dev.db
Passphrase (unless you set SECKIT_SQLITE_PASSPHRASE): seckit-dev-synthetic-vault

Optional env:
  SECKIT_SQLITE_DB           target DB path
  SECKIT_SYNTHETIC_DOTENV    alternate dotenv file path
  SECKIT_SYNTHETIC_SERVICE   default synthetic
  SECKIT_SYNTHETIC_ACCOUNT   default: your login name

  --force  --allow-overwrite
EOF
}

FORCE_FLAGS=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --force) FORCE_FLAGS="--allow-overwrite"; shift ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_SAMPLE="$REPO_ROOT/fixtures/synthetic-sample.env"

expand_sample_path() {
  local p="$1"
  case "$p" in
    ~|~/) printf '%s' "$HOME" ;;
    ~/*) printf '%s' "$HOME/${p:2}" ;;
    *) printf '%s' "$p" ;;
  esac
}

if [[ -n "${SECKIT_SYNTHETIC_DOTENV:-}" ]]; then
  SAMPLE="$(expand_sample_path "${SECKIT_SYNTHETIC_DOTENV}")"
  if [[ ! -f "$SAMPLE" ]]; then
    echo "WARN: SECKIT_SYNTHETIC_DOTENV set but not found: $SAMPLE — using $DEFAULT_SAMPLE" >&2
    echo "WARN: To clear a stale value: unset SECKIT_SYNTHETIC_DOTENV" >&2
    SAMPLE="$DEFAULT_SAMPLE"
  fi
else
  SAMPLE="$DEFAULT_SAMPLE"
fi

if [[ ! -f "$SAMPLE" ]]; then
  echo "ERROR: dotenv not found: $SAMPLE (expected $DEFAULT_SAMPLE in repo)" >&2
  exit 1
fi

export SECKIT_SQLITE_PASSPHRASE="${SECKIT_SQLITE_PASSPHRASE:-$SYNTHETIC_PASSPHRASE}"
export SECKIT_SQLITE_DB="${SECKIT_SQLITE_DB:-$HOME/.config/seckit/secrets-dev.db}"

ACCT="${SECKIT_SYNTHETIC_ACCOUNT:-$(id -un)}"
SVC="${SECKIT_SYNTHETIC_SERVICE:-synthetic}"

mkdir -p "$(dirname "$SECKIT_SQLITE_DB")"

run_seckit() {
  if command -v seckit >/dev/null 2>&1; then
    seckit "$@"
  else
    PYTHONPATH="${REPO_ROOT}/src${PYTHONPATH:+:${PYTHONPATH}}" python3 -m secrets_kit.cli "$@"
  fi
}

run_seckit import env --backend sqlite --db "$SECKIT_SQLITE_DB" \
  --service "$SVC" --account "$ACCT" --dotenv "$SAMPLE" \
  --yes $FORCE_FLAGS --kind auto

echo "Done: $SECKIT_SQLITE_DB (from $SAMPLE; passphrase: $SYNTHETIC_PASSPHRASE unless you overrode SECKIT_SQLITE_PASSPHRASE)"
echo "Keychain twin: scripts/keychain_dev_seed.sh (same dotenv, --backend secure)."
