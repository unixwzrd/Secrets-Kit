#!/usr/bin/env bash
# Persistence: write secrets, then read/rebuild/recover in a minimal-env subprocess.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${SCRIPT_DIR}/runtime_report.sh"

SECKIT_BIN="${SECKIT_BIN:-$(command -v seckit || true)}"
PY_BIN="${PYTHON:-$(command -v python3 || command -v python || true)}"
have_seckit=0
if [[ -n "${SECKIT_BIN}" && -x "${SECKIT_BIN}" ]]; then
  have_seckit=1
fi

if [[ "${have_seckit}" -eq 0 ]]; then
  if [[ -z "${PY_BIN}" || ! -x "${PY_BIN}" ]] || ! "${PY_BIN}" -c "import yaml, nacl" 2>/dev/null; then
    echo "ERROR: need seckit on PATH or PYTHON / python3 with PyYAML + PyNaCl." >&2
    exit 1
  fi
else
  if [[ -z "${PY_BIN}" || ! -x "${PY_BIN}" ]] || ! "${PY_BIN}" -c "import json" 2>/dev/null; then
    PY_BIN="$(command -v python3 || command -v python || true)"
  fi
fi

if [[ "${have_seckit}" -eq 1 ]]; then
  echo "== using seckit: ${SECKIT_BIN}" >&2
else
  echo "== using python module: ${PY_BIN} -m secrets_kit.cli.main" >&2
fi

SMOKE_HOME="$(mktemp -d "${TMPDIR:-/tmp}/seckit-sqlite-restart.XXXXXX")"

__runtime_report_cleanup_hook() {
  rm -rf "${SMOKE_HOME}"
}

report_init "smoke_sqlite_restart"

if ! command -v sqlite3 >/dev/null 2>&1; then
  echo "ERROR: sqlite3 CLI not found" >&2
  exit 1
fi

DB="$SMOKE_HOME/.config/seckit/secrets.db"
PASS="${SECKIT_SQLITE_PASSPHRASE:-seckit-smoke-restart-passphrase-test!!}"
SVC=restart-smoke
ACCT=local
export PYTHONPATH="${REPO_ROOT}/src${PYTHONPATH:+:$PYTHONPATH}"

run_cli() {
  HOME="$SMOKE_HOME" \
    SECKIT_SQLITE_UNLOCK="${SECKIT_SQLITE_UNLOCK:-passphrase}" \
    SECKIT_SQLITE_PASSPHRASE="$PASS" \
    SECKIT_SQLITE_DB="$DB" \
    PYTHONPATH="${REPO_ROOT}/src${PYTHONPATH:+:$PYTHONPATH}" \
    run_cli_inner "$@"
}

run_cli_inner() {
  if [[ "${have_seckit}" -eq 1 ]]; then
      "$SECKIT_BIN" "$@"
  else
      "$PY_BIN" -m secrets_kit.cli.main "$@"
  fi
}

run_cli_minenv() {
  if [[ "${have_seckit}" -eq 1 ]]; then
    env -i \
      HOME="$SMOKE_HOME" \
      PATH="${PATH:-/usr/bin:/bin:/usr/local/bin}" \
      TMPDIR="${TMPDIR:-/tmp}" \
      SECKIT_SQLITE_UNLOCK=passphrase \
      SECKIT_SQLITE_PASSPHRASE="$PASS" \
      SECKIT_SQLITE_DB="$DB" \
      PYTHONPATH="${REPO_ROOT}/src" \
      "$SECKIT_BIN" "$@"
  else
    env -i \
      HOME="$SMOKE_HOME" \
      PATH="${PATH:-/usr/bin:/bin:/usr/local/bin}" \
      TMPDIR="${TMPDIR:-/tmp}" \
      SECKIT_SQLITE_UNLOCK=passphrase \
      SECKIT_SQLITE_PASSPHRASE="$PASS" \
      SECKIT_SQLITE_DB="$DB" \
      PYTHONPATH="${REPO_ROOT}/src" \
      "$PY_BIN" -m secrets_kit.cli.main "$@"
  fi
}

echo "== write phase (subprocess A): two secrets" >&2
run_cli set --backend sqlite --db "$DB" --service "$SVC" --account "$ACCT" --name ALPHA --value alpha-one --kind generic
run_cli set --backend sqlite --db "$DB" --service "$SVC" --account "$ACCT" --name BETA --value beta-two --kind generic
run_cli list --backend sqlite --db "$DB" --service "$SVC" --account "$ACCT"

echo "== read phase (subprocess B, env -i)" >&2
run_cli_minenv get --backend sqlite --db "$DB" --service "$SVC" --account "$ACCT" --name ALPHA --raw | grep -qx 'alpha-one'

run_cli_minenv get --backend sqlite --db "$DB" --service "$SVC" --account "$ACCT" --name BETA --raw | grep -qx 'beta-two'

echo "== rebuild-index + recover (env -i)" >&2
run_cli_minenv rebuild-index --backend sqlite --db "$DB" --service "$SVC" --account "$ACCT"

recover_out="$(run_cli_minenv recover --backend sqlite --db "$DB" --dry-run --json)"

echo "$recover_out" | "${PY_BIN}" -c "import json,sys; d=json.load(sys.stdin); assert d.get('candidates',0)>=2, d"

echo "== integrity" >&2
sqlite3 "$DB" "PRAGMA integrity_check;"

echo "smoke_sqlite_restart: OK" >&2
