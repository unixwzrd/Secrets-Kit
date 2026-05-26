#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/seckit_env.sh"

usage() {
  cat <<'EOF'
Usage:
  seckit_cross_host_verify.sh --service sync-test --account local [options]

Options:
  --backend VALUE         keychain or sqlite
  --source-keychain PATH   source disposable keychain path
  --dest-keychain PATH     destination disposable keychain path
  --source-db PATH         source SQLite database path
  --dest-db PATH           destination SQLite database path
  --home PATH              isolated HOME for SQLite registry/default files
  --password VALUE         destination keychain password

Defaults:
  source keychain: /tmp/seckit-sync-source.keychain-db
  dest keychain:   /tmp/seckit-sync-dest.keychain-db
  source db:       /tmp/seckit-sync-source.sqlite
  dest db:         /tmp/seckit-sync-dest.sqlite
  sqlite home:     /tmp/seckit-sync-sqlite-home
  password:        seckit-test-password

This helper:
  - inspects the source backend
  - exports the standard SECKIT_TEST_* entries from source
  - imports them into the destination backend
  - verifies metadata and value reads in the destination backend
  - when backend=keychain, locks the destination keychain and confirms import fails
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
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

[[ -n "$service" && -n "$account" ]] || { usage; exit 2; }
[[ "$backend" == "keychain" || "$backend" == "sqlite" ]] || { echo "unsupported backend: $backend" >&2; exit 2; }

tmp_export="$(mktemp /tmp/seckit-cross-host.XXXXXX.env)"
cleanup() {
  rm -f "$tmp_export"
}
trap cleanup EXIT

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

if [[ "$backend" == "keychain" ]]; then
  security unlock-keychain -p "$password" "$source_keychain"
  security unlock-keychain -p "$password" "$dest_keychain"

  echo "== source keychain checks =="
  run_seckit list --keychain "$source_keychain" --service "$service" --account "$account"
  run_seckit explain --keychain "$source_keychain" --name SECKIT_TEST_ALPHA --service "$service" --account "$account"
  run_seckit doctor --keychain "$source_keychain"

  echo
  echo "== export from source =="
  run_seckit export \
    --keychain "$source_keychain" \
    --format shell \
    --service "$service" \
    --account "$account" \
    --names SECKIT_TEST_ALPHA,SECKIT_TEST_BETA,SECKIT_TEST_DELETE_ME > "$tmp_export"
  cat "$tmp_export"

  echo
  echo "== import into destination =="
  run_seckit import env \
    --keychain "$dest_keychain" \
    --dotenv "$tmp_export" \
    --service "$service" \
    --account "$account" \
    --allow-overwrite \
    --yes

  echo
  echo "== destination keychain checks =="
  run_seckit explain --keychain "$dest_keychain" --name SECKIT_TEST_ALPHA --service "$service" --account "$account"
  run_seckit get --keychain "$dest_keychain" --name SECKIT_TEST_ALPHA --service "$service" --account "$account" --raw
  run_seckit doctor --keychain "$dest_keychain"
  ls -l "$dest_keychain"

  echo
  echo "== locked destination negative test =="
  run_seckit lock --keychain "$dest_keychain" --yes >/dev/null
  if run_seckit import env \
    --keychain "$dest_keychain" \
    --dotenv "$tmp_export" \
    --service "$service" \
    --account "$account" \
    --allow-overwrite \
    --yes; then
    echo "ERROR: import unexpectedly succeeded while destination keychain was locked" >&2
    exit 1
  fi
  echo "locked destination failure observed as expected"

  echo
  echo "== unlock and retry =="
  security unlock-keychain -p "$password" "$dest_keychain"
  run_seckit import env \
    --keychain "$dest_keychain" \
    --dotenv "$tmp_export" \
    --service "$service" \
    --account "$account" \
    --allow-overwrite \
    --yes
  run_seckit explain --keychain "$dest_keychain" --name SECKIT_TEST_ALPHA --service "$service" --account "$account"

  echo
  echo "disposable-keychain verification complete"
else
  mkdir -p "$sqlite_home" "$(dirname "$source_db")" "$(dirname "$dest_db")"

  echo "== source SQLite checks =="
  run_sqlite "$source_db" list --backend sqlite --sqlite-dev-mode --service "$service" --account "$account"
  run_sqlite "$source_db" explain --backend sqlite --sqlite-dev-mode --name SECKIT_TEST_ALPHA --service "$service" --account "$account"
  run_sqlite "$source_db" doctor --backend sqlite --sqlite-dev-mode

  echo
  echo "== export from source =="
  run_sqlite "$source_db" export \
    --backend sqlite \
    --sqlite-dev-mode \
    --format shell \
    --service "$service" \
    --account "$account" \
    --names SECKIT_TEST_ALPHA,SECKIT_TEST_BETA,SECKIT_TEST_DELETE_ME > "$tmp_export"
  cat "$tmp_export"

  echo
  echo "== import into destination =="
  run_sqlite "$dest_db" import env \
    --backend sqlite \
    --sqlite-dev-mode \
    --dotenv "$tmp_export" \
    --service "$service" \
    --account "$account" \
    --allow-overwrite \
    --yes

  echo
  echo "== destination SQLite checks =="
  run_sqlite "$dest_db" explain --backend sqlite --sqlite-dev-mode --name SECKIT_TEST_ALPHA --service "$service" --account "$account"
  run_sqlite "$dest_db" get --backend sqlite --sqlite-dev-mode --name SECKIT_TEST_ALPHA --service "$service" --account "$account" --raw
  run_sqlite "$dest_db" doctor --backend sqlite --sqlite-dev-mode
  ls -l "$dest_db"

  echo
  echo "standalone SQLite verification complete"
fi
