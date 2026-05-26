#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/seckit_env.sh"

usage() {
  cat <<'EOF'
Usage:
  seckit_cross_host_prepare.sh --service sync-test --account local [options]

Options:
  --backend VALUE         keychain or sqlite
  --source-keychain PATH   source disposable keychain path
  --dest-keychain PATH     destination disposable keychain path
  --source-db PATH         source SQLite database path
  --dest-db PATH           destination SQLite database path
  --home PATH              isolated HOME for SQLite registry/default files
  --password VALUE         disposable keychain password
  --reset                  delete and recreate the disposable keychains

Defaults:
  source keychain: /tmp/seckit-sync-source.keychain-db
  dest keychain:   /tmp/seckit-sync-dest.keychain-db
  source db:       /tmp/seckit-sync-source.sqlite
  dest db:         /tmp/seckit-sync-dest.sqlite
  sqlite home:     /tmp/seckit-sync-sqlite-home
  password:        seckit-test-password

This helper:
  - creates two disposable Keychain files or standalone SQLite stores
  - unlocks Keychain files with the disposable password when backend=keychain
  - seeds source entries into the selected source backend
  - prints the next direct and localhost-transport commands
EOF
}

service=""
account=""
backend="keychain"
source_keychain="/tmp/seckit-sync-source.keychain-db"
dest_keychain="/tmp/seckit-sync-dest.keychain-db"
source_db="/tmp/seckit-sync-source.sqlite"
dest_db="/tmp/seckit-sync-dest.sqlite"
sqlite_home="/tmp/seckit-sync-sqlite-home"
password="seckit-test-password"
reset="0"
sqlite_warning_emitted="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --backend) backend="$2"; shift 2 ;;
    --service) service="$2"; shift 2 ;;
    --account) account="$2"; shift 2 ;;
    --source-keychain) source_keychain="$2"; shift 2 ;;
    --dest-keychain) dest_keychain="$2"; shift 2 ;;
    --source-db) source_db="$2"; shift 2 ;;
    --dest-db) dest_db="$2"; shift 2 ;;
    --home) sqlite_home="$2"; shift 2 ;;
    --password) password="$2"; shift 2 ;;
    --reset) reset="1"; shift 1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

[[ -n "$service" && -n "$account" ]] || { usage; exit 2; }
[[ "$backend" == "keychain" || "$backend" == "sqlite" ]] || { echo "unsupported backend: $backend" >&2; exit 2; }

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

run_sqlite() {
  local db="$1"
  local status=0
  shift
  if [[ "$sqlite_warning_emitted" == "0" ]]; then
    HOME="$sqlite_home" SECKIT_SQLITE_PATH="$db" run_seckit "$@" || status=$?
    sqlite_warning_emitted="1"
  else
    HOME="$sqlite_home" SECKIT_SQLITE_PATH="$db" SECKIT_SQLITE_SUPPRESS_DEV_WARNING=1 run_seckit "$@" || status=$?
  fi
  return "$status"
}

ensure_sqlite_entry() {
  local db="$1"
  local name="$2"
  local value="$3"
  local comment="$4"
  if run_sqlite "$db" explain --backend sqlite --sqlite-dev-mode --name "$name" --service "$service" --account "$account" >/dev/null 2>&1; then
    echo "exists: $name ($db)"
    return 0
  fi
  printf '%s\n' "$value" | run_sqlite "$db" set \
    --backend sqlite \
    --sqlite-dev-mode \
    --name "$name" \
    --stdin \
    --service "$service" \
    --account "$account" \
    --kind generic \
    --comment "$comment"
  echo "created: $name ($db)"
}

if [[ "$backend" == "keychain" ]]; then
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
  echo "  bash ./scripts/seckit_cross_host_verify.sh --backend keychain --service '$service' --account '$account' --source-keychain '$source_keychain' --dest-keychain '$dest_keychain' --password '$password'"
  echo "  bash ./scripts/seckit_cross_host_transport_localhost.sh --backend keychain --service '$service' --account '$account' --source-keychain '$source_keychain' --dest-keychain '$dest_keychain'"
else
  if [[ "$reset" == "1" ]]; then
    rm -f "$source_db" "$dest_db"
    rm -rf "$sqlite_home"
  fi
  mkdir -p "$(dirname "$source_db")" "$(dirname "$dest_db")" "$sqlite_home"
  ensure_sqlite_entry "$source_db" "SECKIT_TEST_ALPHA" "alpha-1" "sqlite source alpha"
  ensure_sqlite_entry "$source_db" "SECKIT_TEST_BETA" "beta-1" "sqlite source beta"
  ensure_sqlite_entry "$source_db" "SECKIT_TEST_DELETE_ME" "delete-me" "sqlite delete path"

  echo
  echo "Prepared standalone SQLite stores:"
  echo "  source: $source_db"
  echo "  dest:   $dest_db"
  echo "  home:   $sqlite_home"
  echo
  echo "Next commands:"
  echo "  bash ./scripts/seckit_cross_host_verify.sh --backend sqlite --service '$service' --account '$account' --source-db '$source_db' --dest-db '$dest_db' --home '$sqlite_home'"
  echo "  bash ./scripts/seckit_cross_host_transport_localhost.sh --backend sqlite --service '$service' --account '$account' --source-db '$source_db' --dest-db '$dest_db' --home '$sqlite_home'"
fi
