#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

usage() {
  cat <<'EOF'
Usage:
  seckit_cross_host_prepare.sh --service sync-test --account local [options]

Options:
  --source-keychain PATH   source disposable keychain path
  --dest-keychain PATH     destination disposable keychain path
  --password VALUE         disposable keychain password
  --reset                  delete and recreate the disposable keychains

Defaults:
  source keychain: /tmp/seckit-sync-source.keychain-db
  dest keychain:   /tmp/seckit-sync-dest.keychain-db
  password:        seckit-test-password

This helper:
  - creates two disposable keychain files
  - unlocks both with the disposable password
  - seeds source entries into the source keychain
  - prints the next direct and localhost-transport commands
EOF
}

service=""
account=""
source_keychain="/tmp/seckit-sync-source.keychain-db"
dest_keychain="/tmp/seckit-sync-dest.keychain-db"
password="seckit-test-password"
reset="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --service) service="$2"; shift 2 ;;
    --account) account="$2"; shift 2 ;;
    --source-keychain) source_keychain="$2"; shift 2 ;;
    --dest-keychain) dest_keychain="$2"; shift 2 ;;
    --password) password="$2"; shift 2 ;;
    --reset) reset="1"; shift 1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

[[ -n "$service" && -n "$account" ]] || { usage; exit 2; }

run_seckit() {
  if command -v seckit >/dev/null 2>&1; then
    seckit "$@"
  else
    PYTHONPATH="$REPO_ROOT/src" python3 -m secrets_kit.cli "$@"
  fi
}

delete_keychain_if_present() {
  local path="$1"
  if [[ -e "$path" ]]; then
    security delete-keychain "$path" >/dev/null 2>&1 || true
  fi
}

create_keychain_if_missing() {
  local path="$1"
  if [[ "$reset" == "1" ]]; then
    delete_keychain_if_present "$path"
  fi
  if [[ ! -e "$path" ]]; then
    security create-keychain -p "$password" "$path"
  fi
  security unlock-keychain -p "$password" "$path"
}

ensure_entry() {
  local keychain="$1"
  local name="$2"
  local value="$3"
  local comment="$4"
  if run_seckit explain --keychain "$keychain" --name "$name" --service "$service" --account "$account" >/dev/null 2>&1; then
    echo "exists: $name ($keychain)"
    return 0
  fi
  printf '%s\n' "$value" | run_seckit set \
    --keychain "$keychain" \
    --name "$name" \
    --stdin \
    --service "$service" \
    --account "$account" \
    --kind generic \
    --comment "$comment"
  echo "created: $name ($keychain)"
}

create_keychain_if_missing "$source_keychain"
create_keychain_if_missing "$dest_keychain"

ensure_entry "$source_keychain" "SECKIT_TEST_ALPHA" "alpha-1" "disposable source alpha"
ensure_entry "$source_keychain" "SECKIT_TEST_BETA" "beta-1" "disposable source beta"
ensure_entry "$source_keychain" "SECKIT_TEST_DELETE_ME" "delete-me" "disposable delete path"

echo
echo "Prepared disposable keychains:"
echo "  source: $source_keychain"
echo "  dest:   $dest_keychain"
echo "  password: $password"
echo
echo "Next commands:"
echo "  bash ./scripts/seckit_cross_host_verify.sh --service '$service' --account '$account' --source-keychain '$source_keychain' --dest-keychain '$dest_keychain' --password '$password'"
echo "  bash ./scripts/seckit_cross_host_transport_localhost.sh --service '$service' --account '$account' --source-keychain '$source_keychain' --dest-keychain '$dest_keychain'"
