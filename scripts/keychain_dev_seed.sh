#!/usr/bin/env bash
# Load the same fake demo secrets as sqlite_dev_seed.sh into the macOS Keychain (secure backend).
# Intended for an interactive login session (login.keychain-db unlocked). No temp keychain password.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: keychain_dev_seed.sh [--force]

Imports fixtures/synthetic-sample.env using --backend secure (default login keychain).

Optional env:
  SECKIT_SYNTHETIC_DOTENV    alternate dotenv path (default: repo fixtures/synthetic-sample.env)
  SECKIT_SYNTHETIC_SERVICE   logical service (default: synthetic)
  SECKIT_SYNTHETIC_ACCOUNT   account scope (default: your login name)
  SECKIT_PYTHON              if set, run "$SECKIT_PYTHON -m secrets_kit.cli" (use when python3 lacks PyNaCl)

Optional flag:
  --keychain PATH   passed to seckit as --keychain (otherwise login keychain)

  --force           --allow-overwrite on import
EOF
}

FORCE_FLAGS=""
KEYCHAIN_FLAGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --force) FORCE_FLAGS="--allow-overwrite"; shift ;;
    --keychain)
      KEYCHAIN_FLAGS=(--keychain "$2")
      shift 2 ;;
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
    SAMPLE="$DEFAULT_SAMPLE"
  fi
else
  SAMPLE="$DEFAULT_SAMPLE"
fi

if [[ ! -f "$SAMPLE" ]]; then
  echo "ERROR: dotenv not found: $SAMPLE" >&2
  exit 1
fi

ACCT="${SECKIT_SYNTHETIC_ACCOUNT:-$(id -un)}"
SVC="${SECKIT_SYNTHETIC_SERVICE:-synthetic}"

# Prefer an explicit interpreter when system `python3` lacks PyNaCl (common on macOS):
#   SECKIT_PYTHON=/path/to/venv/bin/python bash scripts/keychain_dev_seed.sh
# Or: conda run -n venvutil env PYTHONPATH=$PWD/src python -m secrets_kit.cli …
if [[ -n "${SECKIT_PYTHON:-}" ]]; then
  export PYTHONPATH="${REPO_ROOT}/src${PYTHONPATH:+:${PYTHONPATH}}"
  SECKIT=("$SECKIT_PYTHON" -m secrets_kit.cli)
elif command -v seckit >/dev/null 2>&1; then
  SECKIT=(seckit)
else
  export PYTHONPATH="${REPO_ROOT}/src${PYTHONPATH:+:${PYTHONPATH}}"
  SECKIT=(python3 -m secrets_kit.cli)
fi

"${SECKIT[@]}" import env --backend secure "${KEYCHAIN_FLAGS[@]}" \
  --service "$SVC" --account "$ACCT" --dotenv "$SAMPLE" \
  --yes $FORCE_FLAGS --kind auto

echo "Done: imported $(basename "$SAMPLE") into Keychain (service=$SVC account=$ACCT)."
echo "Verify: ${SECKIT[*]} list --backend secure ${KEYCHAIN_FLAGS[*]} --service \"$SVC\" --account \"$ACCT\""
