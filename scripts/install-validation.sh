#!/usr/bin/env bash
# Post-install validation only — does not install or upgrade Secrets-Kit.
set -euo pipefail

SECKIT="${SECKIT:-seckit}"
VERBOSE="${VERBOSE:-0}"

usage() {
  cat <<'EOF'
Usage: install-validation.sh [options]

Verify an existing Secrets-Kit installation (launcher on PATH).

Options:
  --seckit PATH    seckit binary or launcher (default: seckit from PATH)
  --verbose        Print command output to stderr
  -h, --help       Show help

Exit codes:
  0  All checks passed
  1  One or more checks failed

Checks:
  seckit --version
  seckit info
  seckit doctor --install-check
  seckit doctor --acceptance-test
EOF
}

log() { printf 'install-validation: %s\n' "$*" >&2; }
die() { printf 'install-validation: ERROR: %s\n' "$*" >&2; exit 1; }

json_ok() {
  local payload="${1:?}"
  SECKIT_JSON_PAYLOAD="${payload}" python3 <<'PY'
import json
import os
import sys

raw = os.environ.get("SECKIT_JSON_PAYLOAD", "")
try:
    data = json.loads(raw)
except json.JSONDecodeError as exc:
    print(f"invalid JSON: {exc}", file=sys.stderr)
    sys.exit(1)
if data.get("ok") is not True:
    print(json.dumps(data, indent=2), file=sys.stderr)
    sys.exit(1)
PY
}

run_check() {
  local label="${1:?}"
  shift
  log "check: ${label}"
  local out err_file rc
  err_file="$(mktemp -t seckit-install-val-err.XXXXXX)"
  if [[ "${VERBOSE}" -eq 1 ]]; then
    if ! "$@" 2>"${err_file}"; then
      [[ -s "${err_file}" ]] && cat "${err_file}" >&2
      rm -f "${err_file}"
      die "${label} failed"
    fi
    rm -f "${err_file}"
    return 0
  fi
  out="$("$@" 2>"${err_file}")" || rc=$?
  rc="${rc:-0}"
  if [[ "${rc}" -ne 0 ]]; then
    [[ -n "${out}" ]] && printf '%s\n' "${out}" >&2
    [[ -s "${err_file}" ]] && cat "${err_file}" >&2
    rm -f "${err_file}"
    die "${label} failed (exit ${rc})"
  fi
  if [[ -n "${out}" ]]; then
    printf '%s\n' "${out}"
  fi
  rm -f "${err_file}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --seckit) SECKIT="${2:?}"; shift 2 ;;
    --verbose) VERBOSE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

if ! command -v "${SECKIT}" >/dev/null 2>&1 && [[ ! -x "${SECKIT}" ]]; then
  die "seckit not found: ${SECKIT} (add ~/.local/bin to PATH or pass --seckit)"
fi

version_out="$(run_check "seckit --version" "${SECKIT}" --version)"
[[ -n "${version_out}" ]] || die "empty --version output"
log "version: ${version_out}"

run_check "seckit info" "${SECKIT}" info >/dev/null

install_check_out="$(run_check "doctor --install-check" "${SECKIT}" doctor --install-check)"
json_ok "${install_check_out}" || die "doctor --install-check reported ok=false"

acceptance_out="$(run_check "doctor --acceptance-test" "${SECKIT}" doctor --acceptance-test)"
json_ok "${acceptance_out}" || die "doctor --acceptance-test reported ok=false"

log "all checks passed"
exit 0
