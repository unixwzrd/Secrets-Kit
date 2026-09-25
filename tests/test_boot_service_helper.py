"""Exercise boot-helper failure control flow without sudo or launchctl execution."""

import os
import subprocess
import unittest
from pathlib import Path

HELPER_PATH = Path(os.environ.get(
    "SECKIT_TEST_BOOT_HELPER",
    str(Path(__file__).resolve().parents[1] / "scripts/manage-peer-boot-service.sh"),
))


class BootHelperFailureTest(unittest.TestCase):
    def test_user_supervision_query_is_fail_closed(self):
        source = HELPER_PATH.read_text()
        function = source[source.index("user_job_loaded() {"):source.index("system_job_loaded() {")]
        function = function.replace("/bin/launchctl", "fixture_launchctl")
        cases = [
            (0, "loaded", 9),
            (113, "missing service", 0),
            (112, "Bad request.\nCould not find domain for user gui: 501", 0),
            (112, "Bad request.\nCould not find domain for user gui: 502", 78),
            (112, "unknown domain error", 78),
            (1, "operation not permitted", 78),
            (5, "input/output error", 78),
        ]
        for code, output, expected in cases:
            with self.subTest(code=code, output=output):
                result = subprocess.run(
                    ["bash", "-c", '''
set -eu
reject() { echo "$1"; exit 78; }
fixture_launchctl() { printf '%s\\n' "$query_output"; return "$query_code"; }
uid=501
user_label=net.unixwzrd.secrets-kit.daemon
query_code=$1
query_output=$2
''' + function + '\nif user_job_loaded gui/501; then exit 9; fi', "fixture", str(code), output],
                    capture_output=True, text=True, timeout=5,
                )
                self.assertEqual(result.returncode, expected, result.stderr)
                if expected == 78:
                    self.assertIn("no service changed", result.stdout)

    def run_functions(self, body):
        source = HELPER_PATH.read_text()
        functions = source[source.index("customer_ping() {"):source.index("\nloaded_before=0")]
        functions = source[source.index("system_job_loaded() {"):source.index("\n[[ ${EUID}")] + "\n" + functions
        functions = functions.replace("/bin/launchctl", "fixture_launchctl").replace("/bin/rm", "fixture_rm").replace("/bin/sleep", "fixture_sleep")
        prelude = '''
set -eu
reject() { echo "reject:$1"; exit 78; }
fixture_rm() { echo removed; }
fixture_sleep() { SECONDS=$((SECONDS + 1)); }
fixture_launchctl() {
    case "$1" in
        print) if [ "$query_error" -ne 0 ]; then return "$query_error"; fi; test "$live" = 1 || return 113 ;;
        bootout) echo stopped; test "$stop_fails" = 0 || return 1; live=0 ;;
        disable) echo disabled ;;
        *) exit 99 ;;
    esac
}
target=fixture
definition=fixture
live=1
stop_fails=0
query_error=0
loaded_before=0
disabled_before=1
definition_preexisting=0
'''
        # Override customer_ping after loading the functions: the source sudo
        # command is never invoked, even when testing the health loop.
        return subprocess.run(["bash", "-c", prelude + functions + '\ncustomer_ping() { return 1; }\n' + body], capture_output=True, text=True, timeout=5)

    def test_new_failed_job_is_stopped_and_removed(self):
        result = self.run_functions("rollback_activation")
        self.assertEqual(result.returncode, 78)
        self.assertIn("stopped\ndisabled\nremoved\n", result.stdout)

    def test_existing_unloaded_definition_is_preserved(self):
        result = self.run_functions("definition_preexisting=1; rollback_activation")
        self.assertEqual(result.returncode, 78)
        self.assertIn("stopped\ndisabled\n", result.stdout)
        self.assertNotIn("removed", result.stdout)

    def test_existing_loaded_job_is_untouched(self):
        result = self.run_functions("loaded_before=1; rollback_activation")
        self.assertEqual(result.returncode, 78)
        self.assertNotIn("stopped", result.stdout)
        self.assertNotIn("removed", result.stdout)

    def test_failed_stop_retains_definition(self):
        result = self.run_functions("stop_fails=1; rollback_activation")
        self.assertEqual(result.returncode, 78)
        self.assertNotIn("removed", result.stdout)
        self.assertNotIn("disabled", result.stdout)

    def test_unknown_job_state_never_permits_cleanup(self):
        for code in (1, 5, 112):
            with self.subTest(code=code):
                result = self.run_functions(f"query_error={code}; rollback_activation")
                self.assertEqual(result.returncode, 78)
                self.assertIn("cannot determine system job state", result.stdout)
                self.assertNotIn("removed", result.stdout)
                self.assertNotIn("stopped", result.stdout)

    def test_health_success_and_bounded_failure(self):
        success = self.run_functions('customer_ping() { echo "limit:$1"; return 0; }; wait_for_health')
        self.assertEqual(success.returncode, 0)
        failure = self.run_functions('''
SECONDS=0
customer_ping() { echo "limit:$1"; SECONDS=$((SECONDS + $1)); return 1; }
wait_for_health || { echo "elapsed:$SECONDS"; exit 1; }
''')
        self.assertEqual(failure.returncode, 1)
        self.assertIn("elapsed:30", failure.stdout)
        self.assertNotIn("limit:0", failure.stdout)
