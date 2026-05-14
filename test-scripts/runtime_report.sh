#!/usr/bin/env bash
# Shared reporting helpers for test-scripts/*.sh — sourced, not executed directly.
# Creates test-reports/<test_name>/<timestamp>/ with tee-captured stdout/stderr.
#
# Optional: define __runtime_report_cleanup_hook() before report_init to run
# temp-dir cleanup (and similar) on EXIT after the report is finalized.

__runtime_report_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME_REPORT_REPO_ROOT="$(cd "${__runtime_report_script_dir}/.." && pwd)"

# log_cmd — append a timestamped, shell-quoted command line to commands.log.
log_cmd() {
  [[ -n "${REPORT_DIR:-}" ]] || return 0
  local ts parts
  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  parts=("$ts" "RUN")
  local a
  for a in "$@"; do
    parts+=("$(printf '%q' "$a")")
  done
  printf '%s\n' "${parts[*]}" >> "${REPORT_DIR}/commands.log"
}

finalize_summary() {
  [[ -n "${REPORT_DIR:-}" ]] || return 0
  local code="${1:-0}"
  local status="FAIL"
  [[ "${code}" -eq 0 ]] && status="PASS"
  local ts
  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  {
    echo "---"
    echo "finished_utc=${ts}"
    echo "exit_code=${code}"
    echo "final_status=${status}"
  } >> "${REPORT_DIR}/summary.txt"
  {
    echo "${status} exit_code=${code} finished_utc=${ts}"
  } >> "${REPORT_DIR}/test-results.txt"
  _REPORT_FINALIZED=1
}

__runtime_report_on_exit() {
  local _ec=$?
  if [[ -n "${REPORT_DIR:-}" && "${_REPORT_FINALIZED:-0}" -eq 0 ]]; then
    finalize_summary "${_ec}"
  fi
  if declare -F __runtime_report_cleanup_hook >/dev/null 2>&1; then
    __runtime_report_cleanup_hook || true
  fi
  return "${_ec}"
}

# report_init <test_name>
# Creates REPORT_DIR, seeds artifact headers, attaches tee + EXIT trap.
report_init() {
  local test_name="${1:?report_init: test name required}"
  local ts
  ts="$(date -u +"%Y%m%dT%H%M%SZ")_${RANDOM}"

  REPORT_DIR="${RUNTIME_REPORT_REPO_ROOT}/test-reports/${test_name}/${ts}"
  mkdir -p "${REPORT_DIR}"
  export REPORT_DIR

  {
    echo "test_name=${test_name}"
    echo "timestamp_utc=${ts}"
    echo "repo_root=${RUNTIME_REPORT_REPO_ROOT}"
    echo "cwd_initial=$(pwd)"
    echo "--- env (sorted) ---"
    env | sort
  } > "${REPORT_DIR}/environment.txt"

  {
    echo "commands.log — ${test_name}"
    echo "started_utc=${ts}"
  } > "${REPORT_DIR}/commands.log"

  {
    echo "summary.txt — ${test_name}"
    echo "started_utc=${ts}"
  } > "${REPORT_DIR}/summary.txt"

  {
    echo "test-results.txt — ${test_name}"
    echo "started_utc=${ts}"
  } > "${REPORT_DIR}/test-results.txt"

  _REPORT_FINALIZED=0
  trap '__runtime_report_on_exit' EXIT

  exec > >(tee -i "${REPORT_DIR}/stdout.log")
  exec 2> >(tee -i "${REPORT_DIR}/stderr.log" >&2)
}
