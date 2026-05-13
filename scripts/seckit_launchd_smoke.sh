#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

MODE="login-agent"
BACKEND="${SECKIT_LAUNCHD_BACKEND:-secure}"
CURRENT_USER="$(id -un)"
CURRENT_UID="$(id -u)"
USER_HOME="$( (dscl . -read "/Users/${CURRENT_USER}" NFSHomeDirectory 2>/dev/null || true) | awk '{print $2}' )"
USER_HOME="${USER_HOME:-$HOME}"

SERVICE="launchd-smoke"
ACCOUNT="${CURRENT_USER:-local}"
NAME="SECKIT_TEST_ENV"
VALUE="expected-${MODE}-${ACCOUNT}"
OUT_DIR="/tmp/seckit-launchd-smoke-${ACCOUNT//[^A-Za-z0-9_.-]/_}"
PYTHON_BIN="${PYTHON_BIN:-$(command -v python3 || command -v python || true)}"
SECKIT_BIN="${SECKIT_BIN:-$(command -v seckit || true)}"
KEEP=0
SETUP_ONLY=0
CLEANUP_ONLY=0
UNLOCK=0
USE_EXISTING=0
EXPECTED_VALUE=""

usage() {
  cat <<'EOF'
Usage:
  seckit_launchd_smoke.sh [--mode MODE] [--backend ID] [--setup-only] [--cleanup] [--keep] [--unlock]
                           [--use-existing] [--service SERVICE] [--account ACCOUNT]
                           [--name NAME] [--expected VALUE]

Modes:
  login-agent     LaunchAgent + current user's login keychain
  service-agent   LaunchAgent + dedicated per-user service keychain
  service-daemon  LaunchDaemon + dedicated system service keychain

Runs a launchd smoke test for Secrets-Kit and writes a proof JSON file from
the process started by launchd.

The launchd job runs the installed seckit executable:

  seckit run ... -- python scripts/seckit_launchd_agent_simulator.py

The agent simulator is a separate child process. It only reads the injected
environment variable and writes proof JSON.

Options:
  --mode MODE    login-agent, service-agent, or service-daemon (default: login-agent)
  --use-existing use an existing Secrets-Kit item instead of creating a test item
  --backend ID    secure only (alias: local); default: secure or SECKIT_LAUNCHD_BACKEND.
                  The former icloud-helper path was removed from seckit.
  --service NAME service scope for the test item (default: launchd-smoke)
  --account NAME account scope for the test item (default: current user)
  --name NAME    secret/env name to inject (default: SECKIT_TEST_ENV)
  --expected VAL expected injected value; otherwise the test only checks non-empty
  --setup-only   create the keychain item and plist, print launchctl commands, do not run
  --cleanup      remove launchd plist/logs/test item for the selected mode
  --keep         keep plist, output files, and test item after a run
  --unlock       run seckit unlock before seeding the test secret
  -h, --help     show this help

Environment overrides:
  SECKIT_BIN=/path/to/seckit
  PYTHON_BIN=/path/to/python
  SECKIT_LAUNCHD_BACKEND=secure|local

Existing login-keychain item example:
  ./scripts/seckit_launchd_smoke.sh --use-existing --service hermes --name TELEGRAM_BOT_TOKEN
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="${2:-}"; shift 2 ;;
    --setup-only) SETUP_ONLY=1; shift ;;
    --cleanup) CLEANUP_ONLY=1; shift ;;
    --keep) KEEP=1; shift ;;
    --unlock) UNLOCK=1; shift ;;
    --use-existing) USE_EXISTING=1; shift ;;
    --service) SERVICE="${2:-}"; shift 2 ;;
    --account) ACCOUNT="${2:-}"; shift 2 ;;
    --name) NAME="${2:-}"; shift 2 ;;
    --expected) EXPECTED_VALUE="${2:-}"; shift 2 ;;
    --backend) BACKEND="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

case "$BACKEND" in
  local|secure) BACKEND="secure" ;;
  icloud|icloud-helper)
    echo "ERROR: icloud-helper was removed from seckit; use --backend secure (or local)." >&2
    exit 2
    ;;
  *) echo "unsupported --backend: $BACKEND (use secure or local)" >&2; exit 2 ;;
esac

case "$MODE" in
  login-agent|service-agent|service-daemon) ;;
  *) echo "unsupported mode: $MODE" >&2; usage; exit 2 ;;
esac

VALUE="${EXPECTED_VALUE:-expected-${MODE}-${ACCOUNT}}"
OUT_DIR="/tmp/seckit-launchd-smoke-${ACCOUNT//[^A-Za-z0-9_.-]/_}"
LABEL="ai.unixwzrd.seckit.launchd-smoke.${MODE}.${ACCOUNT}.${BACKEND//[- ]/_}"
OUTPUT_FILE="${OUT_DIR}/${MODE}-result.txt"
STDOUT_FILE="${OUT_DIR}/${MODE}-stdout.log"
STDERR_FILE="${OUT_DIR}/${MODE}-stderr.log"
WRAPPER_PATH=""
PASS_FILE=""
KEYCHAIN_PASSWORD=""
CHILD_SCRIPT="${SCRIPT_DIR}/seckit_launchd_agent_simulator.py"

require_tools() {
  if [[ -z "$SECKIT_BIN" || ! -x "$SECKIT_BIN" ]]; then
    echo "ERROR: could not find installed seckit executable. Activate the venv or set SECKIT_BIN=/path/to/seckit." >&2
    exit 1
  fi
  if [[ -z "$PYTHON_BIN" || ! -x "$PYTHON_BIN" ]]; then
    echo "ERROR: could not find python executable. Activate the venv or set PYTHON_BIN=/path/to/python." >&2
    exit 1
  fi
  if [[ ! -f "$CHILD_SCRIPT" ]]; then
    echo "ERROR: missing launchd agent simulator: $CHILD_SCRIPT" >&2
    exit 1
  fi
  if ! grep -q '"agent_simulator": True' "$CHILD_SCRIPT"; then
    echo "ERROR: stale launchd agent simulator; expected agent_simulator proof field in: $CHILD_SCRIPT" >&2
    exit 1
  fi
  if ! command -v openssl >/dev/null 2>&1; then
    echo "ERROR: openssl is required to generate service-keychain passwords." >&2
    exit 1
  fi
}

file_sha256() {
  shasum -a 256 "$1" | awk '{print $1}'
}

random_password() {
  openssl rand -base64 32 | tr '/+' '_-' | tr -d '='
}

ensure_private_file() {
  local path="$1"
  chmod 600 "$path"
}

mode_paths() {
  case "$MODE" in
    login-agent)
      KEYCHAIN_PATH="${USER_HOME}/Library/Keychains/login.keychain-db"
      PLIST_DIR="${USER_HOME}/Library/LaunchAgents"
      PLIST_PATH="${PLIST_DIR}/${LABEL}.plist"
      BOOTSTRAP_DOMAIN="gui/${CURRENT_UID}"
      SERVICE_TARGET="${BOOTSTRAP_DOMAIN}/${LABEL}"
      LAUNCH_KIND="agent"
      ;;
    service-agent)
      KEYCHAIN_PATH="${USER_HOME}/Library/Keychains/seckit-service.keychain-db"
      PASS_FILE="${USER_HOME}/.config/seckit/service-keychain.pass"
      PLIST_DIR="${USER_HOME}/Library/LaunchAgents"
      PLIST_PATH="${PLIST_DIR}/${LABEL}.plist"
      BOOTSTRAP_DOMAIN="gui/${CURRENT_UID}"
      SERVICE_TARGET="${BOOTSTRAP_DOMAIN}/${LABEL}"
      LAUNCH_KIND="agent"
      ;;
    service-daemon)
      if [[ "$(id -u)" != "0" ]]; then
        echo "ERROR: service-daemon mode must be run as root, usually via sudo." >&2
        exit 1
      fi
      KEYCHAIN_PATH="/Library/Application Support/SecretsKit/seckit-service.keychain-db"
      PASS_FILE="/Library/Application Support/SecretsKit/seckit-service.keychain.pass"
      WRAPPER_PATH="/Library/Application Support/SecretsKit/seckit-launchd-smoke-wrapper.sh"
      PLIST_DIR="/Library/LaunchDaemons"
      PLIST_PATH="${PLIST_DIR}/${LABEL}.plist"
      BOOTSTRAP_DOMAIN="system"
      SERVICE_TARGET="system/${LABEL}"
      LAUNCH_KIND="daemon"
      ;;
  esac
}

load_or_create_password() {
  [[ -n "$PASS_FILE" ]] || return 0
  mkdir -p "$(dirname "$PASS_FILE")"
  if [[ ! -f "$PASS_FILE" ]]; then
    random_password > "$PASS_FILE"
  fi
  ensure_private_file "$PASS_FILE"
  KEYCHAIN_PASSWORD="$(cat "$PASS_FILE")"
}

ensure_keychain() {
  case "$MODE" in
    login-agent)
      if [[ "$UNLOCK" == "1" ]]; then
        "$SECKIT_BIN" unlock --keychain "$KEYCHAIN_PATH" --yes
      fi
      if [[ ! -f "$KEYCHAIN_PATH" ]]; then
        cat >&2 <<EOF
ERROR: the login keychain file was not found:
  $KEYCHAIN_PATH

Use this mode from the target user's login session, or pass a supported mode
that uses a dedicated service keychain.
EOF
        exit 1
      fi
      ;;
    service-agent|service-daemon)
      load_or_create_password
      mkdir -p "$(dirname "$KEYCHAIN_PATH")"
      if [[ ! -f "$KEYCHAIN_PATH" ]]; then
        security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"
      fi
      security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"
      security set-keychain-settings -u -t 2147483647 "$KEYCHAIN_PATH"
      ;;
  esac
}

delete_test_secret() {
  [[ "$USE_EXISTING" == "1" ]] && return 0
  "$SECKIT_BIN" delete \
    --keychain "$KEYCHAIN_PATH" \
    --service "$SERVICE" \
    --account "$ACCOUNT" \
    --name "$NAME" \
    --yes >/dev/null 2>&1 || true
}

cleanup() {
  launchctl bootout "$SERVICE_TARGET" >/dev/null 2>&1 || true
  rm -f "$PLIST_PATH"
  [[ -n "$WRAPPER_PATH" ]] && rm -f "$WRAPPER_PATH"
  delete_test_secret
  if [[ "$KEEP" != "1" ]]; then
    rm -rf "$OUT_DIR"
  fi
}

verify_cleanup() {
  local failed=0
  if [[ -e "$PLIST_PATH" ]]; then
    echo "cleanup verification failed: plist still exists: $PLIST_PATH" >&2
    failed=1
  fi
  if launchctl print "$SERVICE_TARGET" >/dev/null 2>&1; then
    echo "cleanup verification failed: launchd target is still registered: $SERVICE_TARGET" >&2
    failed=1
  fi
  if [[ "$failed" != "0" ]]; then
    exit 1
  fi
  echo "cleanup verified: removed plist and launchd target"
}

write_agent_plist() {
  cat > "$PLIST_PATH" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${SECKIT_BIN}</string>
    <string>run</string>
    <string>--service</string>
    <string>${SERVICE}</string>
    <string>--account</string>
    <string>${ACCOUNT}</string>
    <string>--names</string>
    <string>${NAME}</string>
    <string>--keychain</string>
    <string>${KEYCHAIN_PATH}</string>
    <string>--</string>
    <string>${PYTHON_BIN}</string>
    <string>${CHILD_SCRIPT}</string>
    <string>${OUTPUT_FILE}</string>
    <string>${OUT_DIR}</string>
    <string>${KEYCHAIN_PATH}</string>
    <string>${MODE}</string>
    <string>${SERVICE_TARGET}</string>
    <string>${NAME}</string>
    <string>${SECKIT_BIN}</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>HOME</key>
    <string>${USER_HOME}</string>
    <key>USER</key>
    <string>${ACCOUNT}</string>
    <key>LOGNAME</key>
    <string>${ACCOUNT}</string>
    <key>PATH</key>
    <string>$(dirname "$SECKIT_BIN"):$(dirname "$PYTHON_BIN"):/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
  </dict>
  <key>WorkingDirectory</key>
  <string>${REPO_ROOT}</string>
  <key>RunAtLoad</key>
  <false/>
  <key>StandardOutPath</key>
  <string>${STDOUT_FILE}</string>
  <key>StandardErrorPath</key>
  <string>${STDERR_FILE}</string>
</dict>
</plist>
EOF
}

write_daemon_wrapper_and_plist() {
  cat > "$WRAPPER_PATH" <<EOF
#!/usr/bin/env bash
set -euo pipefail
security unlock-keychain -p "\$(cat "$PASS_FILE")" "$KEYCHAIN_PATH"
export PATH="$(dirname "$SECKIT_BIN"):$(dirname "$PYTHON_BIN"):/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export HOME="/var/root"
export USER="root"
export LOGNAME="root"
exec "$SECKIT_BIN" run \\
  --service "$SERVICE" \\
  --account "$ACCOUNT" \\
  --names "$NAME" \\
  --keychain "$KEYCHAIN_PATH" \\
  -- "$PYTHON_BIN" "$CHILD_SCRIPT" "$OUTPUT_FILE" "$OUT_DIR" "$KEYCHAIN_PATH" "$MODE" "$SERVICE_TARGET" "$NAME" "$SECKIT_BIN"
EOF
  chmod 700 "$WRAPPER_PATH"
  cat > "$PLIST_PATH" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${WRAPPER_PATH}</string>
  </array>
  <key>WorkingDirectory</key>
  <string>${REPO_ROOT}</string>
  <key>RunAtLoad</key>
  <false/>
  <key>StandardOutPath</key>
  <string>${STDOUT_FILE}</string>
  <key>StandardErrorPath</key>
  <string>${STDERR_FILE}</string>
</dict>
</plist>
EOF
  chmod 644 "$PLIST_PATH"
}

seed_secret() {
  [[ "$USE_EXISTING" == "1" ]] && return 0
  "$SECKIT_BIN" set \
    --keychain "$KEYCHAIN_PATH" \
    --service "$SERVICE" \
    --account "$ACCOUNT" \
    --name "$NAME" \
    --value "$VALUE" \
    --kind generic \
    --comment "launchd ${MODE} smoke test"
}

run_launchd_job() {
  launchctl bootout "$SERVICE_TARGET" >/dev/null 2>&1 || true
  launchctl bootstrap "$BOOTSTRAP_DOMAIN" "$PLIST_PATH"
  launchctl kickstart -k "$SERVICE_TARGET"
  deadline=$((SECONDS + 20))
  while [[ ! -f "$OUTPUT_FILE" && "$SECONDS" -lt "$deadline" ]]; do
    sleep 0.2
  done
  if [[ ! -f "$OUTPUT_FILE" ]]; then
    echo "launchd smoke test failed: output file was not created" >&2
    [[ -f "$STDOUT_FILE" ]] && sed 's/^/stdout: /' "$STDOUT_FILE" >&2
    [[ -f "$STDERR_FILE" ]] && sed 's/^/stderr: /' "$STDERR_FILE" >&2
    exit 1
  fi
  cat "$OUTPUT_FILE"
  if [[ -n "$EXPECTED_VALUE" || "$USE_EXISTING" != "1" ]]; then
    if ! grep -q "\"value\": \"${VALUE}\"" "$OUTPUT_FILE"; then
      echo "launchd smoke test failed: expected ${VALUE}" >&2
      exit 1
    fi
  else
    if grep -q '"value": ""' "$OUTPUT_FILE"; then
      echo "launchd smoke test failed: ${NAME} was not injected or was empty" >&2
      exit 1
    fi
  fi
  if ! grep -q "\"mode\": \"${MODE}\"" "$OUTPUT_FILE"; then
    echo "launchd smoke test failed: expected mode ${MODE}" >&2
    exit 1
  fi
  if ! grep -q '"agent_simulator": true' "$OUTPUT_FILE"; then
    echo "launchd smoke test failed: agent simulator child did not write proof" >&2
    exit 1
  fi
  echo "launchd smoke test passed for mode=${MODE} user=${ACCOUNT}"
}

require_tools
mode_paths
mkdir -p "$PLIST_DIR" "$OUT_DIR"

if [[ "$CLEANUP_ONLY" == "1" ]]; then
  cleanup
  verify_cleanup
  echo "cleaned launchd smoke test for mode=${MODE} account=${ACCOUNT}"
  exit 0
fi

echo "mode: $MODE"
echo "backend: $BACKEND"
echo "kind: $LAUNCH_KIND"
echo "user: $ACCOUNT"
echo "uid: $CURRENT_UID"
echo "home: $USER_HOME"
echo "keychain: $KEYCHAIN_PATH"
echo "service: $SERVICE"
echo "name: $NAME"
echo "use existing: $USE_EXISTING"
echo "seckit: $SECKIT_BIN"
echo "python: $PYTHON_BIN"
echo "agent simulator: $CHILD_SCRIPT"
echo "agent simulator sha256: $(file_sha256 "$CHILD_SCRIPT")"
[[ -n "$PASS_FILE" ]] && echo "password file: $PASS_FILE"
echo "launchd target: $SERVICE_TARGET"

ensure_keychain
if ! seed_secret; then
  if [[ "$MODE" == "login-agent" && "$USE_EXISTING" != "1" ]]; then
    cat >&2 <<EOF

ERROR: macOS denied creating the temporary login-keychain test item.

This failure happened before launchd ran. If this user already has a readable
Secrets-Kit item, run the smoke test without creating anything:

  $0 --use-existing --service <service> --name <name>

Example:

  $0 --use-existing --service hermes --name TELEGRAM_BOT_TOKEN
EOF
  fi
  exit 1
fi

if [[ "$MODE" == "service-daemon" ]]; then
  write_daemon_wrapper_and_plist
else
  write_agent_plist
fi

echo "plist: $PLIST_PATH"
[[ -n "$WRAPPER_PATH" ]] && echo "wrapper: $WRAPPER_PATH"
echo "target: $SERVICE_TARGET"
echo "output: $OUTPUT_FILE"

if [[ "$SETUP_ONLY" == "1" ]]; then
  cat <<EOF

Run manually:
  launchctl bootstrap "$BOOTSTRAP_DOMAIN" "$PLIST_PATH"
  launchctl kickstart -k "$SERVICE_TARGET"
  cat "$OUTPUT_FILE"

Clean up:
  "$0" --mode "$MODE" --cleanup
EOF
  exit 0
fi

run_launchd_job

if [[ "$KEEP" != "1" ]]; then
  cleanup
  verify_cleanup
fi
