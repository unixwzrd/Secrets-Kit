#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/seckit_env.sh"

usage() {
  cat <<'EOF'
Usage:
  seckit_cross_host_transport_localhost.sh --service sync-test --account local [options]

Options:
  --backend VALUE         keychain or sqlite
  --source-keychain PATH   source disposable keychain path
  --dest-keychain PATH     destination disposable keychain path
  --source-db PATH         source SQLite database path
  --dest-db PATH           destination SQLite database path
  --home PATH              isolated HOME for SQLite registry/default files
  --password VALUE         disposable keychain password

Defaults:
  source keychain: /tmp/seckit-sync-source.keychain-db
  dest keychain:   /tmp/seckit-sync-dest.keychain-db
  source db:       /tmp/seckit-sync-source.sqlite
  dest db:         /tmp/seckit-sync-dest.sqlite
  sqlite home:     /tmp/seckit-sync-sqlite-home
  password:        seckit-test-password

This helper:
  - exports the standard SECKIT_TEST_* entries from the source backend
  - pipes them through ssh localhost
  - imports into the destination backend on the localhost side
  - verifies the destination metadata and value read afterwards
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

if [[ "$backend" == "keychain" ]]; then
  remote_import_cmd=$(cat <<EOF
cd "$SECKIT_REPO_ROOT" && security unlock-keychain -p "$password" "$dest_keychain" && if [[ "${SECKIT_USE_PATH_CLI:-0}" == "1" ]] && command -v seckit >/dev/null 2>&1; then \
  seckit import env --keychain "$dest_keychain" --dotenv /dev/stdin --service "$service" --account "$account" --allow-overwrite --yes; \
else \
  PYTHONPATH="$SECKIT_REPO_ROOT/src" "$SECKIT_PYTHON_BIN" -m secrets_kit.cli import env --keychain "$dest_keychain" --dotenv /dev/stdin --service "$service" --account "$account" --allow-overwrite --yes; \
fi
EOF
)

  security unlock-keychain -p "$password" "$source_keychain"
  security unlock-keychain -p "$password" "$dest_keychain"

  echo "== ssh localhost transport import =="
  run_seckit export \
    --keychain "$source_keychain" \
    --format shell \
    --service "$service" \
    --account "$account" \
    --names SECKIT_TEST_ALPHA,SECKIT_TEST_BETA,SECKIT_TEST_DELETE_ME \
    | ssh localhost "$remote_import_cmd"

  echo
  echo "== localhost destination verification =="
  run_seckit explain --keychain "$dest_keychain" --name SECKIT_TEST_ALPHA --service "$service" --account "$account"
  run_seckit get --keychain "$dest_keychain" --name SECKIT_TEST_ALPHA --service "$service" --account "$account" --raw
  run_seckit doctor --keychain "$dest_keychain"
else
  mkdir -p "$sqlite_home" "$(dirname "$source_db")" "$(dirname "$dest_db")"
  remote_import_cmd=$(cat <<EOF
cd "$SECKIT_REPO_ROOT" && HOME="$sqlite_home" SECKIT_SQLITE_PATH="$dest_db" SECKIT_SQLITE_SUPPRESS_DEV_WARNING=1 PYTHONPATH="$SECKIT_REPO_ROOT/src" "$SECKIT_PYTHON_BIN" -m secrets_kit.cli import env --backend sqlite --sqlite-dev-mode --dotenv /dev/stdin --service "$service" --account "$account" --allow-overwrite --yes
EOF
)

  echo "== ssh localhost transport import =="
  run_sqlite "$source_db" export \
    --backend sqlite \
    --sqlite-dev-mode \
    --format shell \
    --service "$service" \
    --account "$account" \
    --names SECKIT_TEST_ALPHA,SECKIT_TEST_BETA,SECKIT_TEST_DELETE_ME \
    | ssh localhost "$remote_import_cmd"

  echo
  echo "== localhost destination verification =="
  run_sqlite "$dest_db" explain --backend sqlite --sqlite-dev-mode --name SECKIT_TEST_ALPHA --service "$service" --account "$account"
  run_sqlite "$dest_db" get --backend sqlite --sqlite-dev-mode --name SECKIT_TEST_ALPHA --service "$service" --account "$account" --raw
  run_sqlite "$dest_db" doctor --backend sqlite --sqlite-dev-mode
fi
