#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

usage() {
  cat <<'EOF'
Usage:
  seckit_cross_host_transport_localhost.sh --service sync-test --account local [options]

Options:
  --source-keychain PATH   source disposable keychain path
  --dest-keychain PATH     destination disposable keychain path
  --password VALUE         disposable keychain password

Defaults:
  source keychain: /tmp/seckit-sync-source.keychain-db
  dest keychain:   /tmp/seckit-sync-dest.keychain-db
  password:        seckit-test-password

This helper:
  - exports the standard SECKIT_TEST_* entries from the source keychain
  - pipes them through ssh localhost
  - imports into the destination keychain on the localhost side
  - verifies the destination metadata and value read afterwards
EOF
}

service=""
account=""
source_keychain="/tmp/seckit-sync-source.keychain-db"
dest_keychain="/tmp/seckit-sync-dest.keychain-db"
password="seckit-test-password"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --service) service="$2"; shift 2 ;;
    --account) account="$2"; shift 2 ;;
    --source-keychain) source_keychain="$2"; shift 2 ;;
    --dest-keychain) dest_keychain="$2"; shift 2 ;;
    --password) password="$2"; shift 2 ;;
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

remote_import_cmd=$(cat <<EOF
cd "$REPO_ROOT" && security unlock-keychain -p "$password" "$dest_keychain" && if command -v seckit >/dev/null 2>&1; then \
  seckit import env --keychain "$dest_keychain" --dotenv /dev/stdin --service "$service" --account "$account" --allow-overwrite --yes; \
else \
  PYTHONPATH="$REPO_ROOT/src" python3 -m secrets_kit.cli import env --keychain "$dest_keychain" --dotenv /dev/stdin --service "$service" --account "$account" --allow-overwrite --yes; \
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
