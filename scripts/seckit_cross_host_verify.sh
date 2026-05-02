#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

usage() {
  cat <<'EOF'
Usage:
  seckit_cross_host_verify.sh --service sync-test --account local [options]

Options:
  --source-keychain PATH   source disposable keychain path
  --dest-keychain PATH     destination disposable keychain path
  --password VALUE         destination keychain password

Defaults:
  source keychain: /tmp/seckit-sync-source.keychain-db
  dest keychain:   /tmp/seckit-sync-dest.keychain-db
  password:        seckit-test-password

This helper:
  - inspects the source disposable keychain
  - exports the standard SECKIT_TEST_* entries from source
  - imports them into the destination disposable keychain
  - verifies metadata and value reads in the destination keychain
  - locks the destination keychain and confirms import fails
  - unlocks the destination keychain and confirms retry succeeds
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

tmp_export="$(mktemp /tmp/seckit-cross-host.XXXXXX.env)"
cleanup() {
  rm -f "$tmp_export"
}
trap cleanup EXIT

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
