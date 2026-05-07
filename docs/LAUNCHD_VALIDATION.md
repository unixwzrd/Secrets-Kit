# launchd Validation

**Updated:** 2026-05-06

Back: [README](../README.md)

- [launchd Validation](#launchd-validation)
  - [Decision Table](#decision-table)
  - [Mode 1: Login Keychain LaunchAgent](#mode-1-login-keychain-launchagent)
    - [`secure` backend and automated tests](#secure-backend-and-automated-tests)
    - [SQLite + launchd](#sqlite--launchd)
  - [Mode 2: Dedicated Service Keychain LaunchAgent](#mode-2-dedicated-service-keychain-launchagent)
  - [Mode 3: Dedicated Service Keychain LaunchDaemon](#mode-3-dedicated-service-keychain-launchdaemon)
  - [Proof Output](#proof-output)
  - [Gated Tests](#gated-tests)
  - [Manual Reboot Test](#manual-reboot-test)
  - [Password Prompt Notes](#password-prompt-notes)


`seckit run` must work when launchd starts the process. There are three supported launchd modes, and they have different Keychain requirements.

## Decision Table

| Use case | launchd type | Keychain | Works after logout | Works after reboot before login |
| --- | --- | --- | --- | --- |
| Interactive user app or desktop agent | LaunchAgent | user login keychain | not guaranteed | no |
| User-owned background service | LaunchAgent | dedicated user service keychain | yes, during same boot after provisioning | not guaranteed |
| Machine/service daemon | LaunchDaemon | dedicated system service keychain + root-only unlock file | yes | yes |

Unsupported model:

- An unattended daemon reading another user's login keychain after logout or reboot.
- A service storing another user's login keychain password so it can unlock that keychain later.

## Mode 1: Login Keychain LaunchAgent

Use this when a user is logged in and the process should read that user's login keychain.

The smoke script installs a per-user LaunchAgent that runs the installed `seckit` executable from the active environment:

```text
seckit run ... -- python scripts/seckit_launchd_agent_simulator.py
```

The `scripts/seckit_launchd_agent_simulator.py` child is the thing that reads the injected environment variable and writes the proof file. This tests the intended production pattern: `seckit` resolves secrets, then launches a separate agent/service process with those secrets in its environment.

If the default temporary-item setup is denied by macOS, use an existing item:

```bash
./scripts/seckit_launchd_smoke.sh --use-existing --service hermes --name APPLE_ID --keep
```

This does not create or delete any keychain item.

For a normal run that cleans itself up:

```bash
./scripts/seckit_launchd_smoke.sh --mode login-agent
```

After a normal successful run, the script unloads the launchd job, removes the plist, and verifies both cleanup steps. A `--keep` run preserves the plist and output files for inspection.

If the login keychain is locked or the session cannot prompt:

```bash
./scripts/seckit_launchd_smoke.sh --mode login-agent --unlock
```

This mode proves the LaunchAgent runs in `gui/$UID` and reads:

```text
~/Library/Keychains/login.keychain-db
```

This is not the right model for unattended post-logout or post-reboot services.

### `secure` backend and automated tests

The **`security`** CLI is the only Keychain integration for **`--backend secure`**. **`scripts/seckit_launchd_smoke.sh`** uses **`--backend secure`** (alias `local`) only.

Automated coverage (macOS, opt-in):

| Variable | What it enables |
| --- | --- |
| `SECKIT_RUN_LAUNCHD_TESTS=1` | Temp-keychain + optional login-keychain launchd tests in `tests/test_launchd_run_flow.py` |
| `SECKIT_RUN_LAUNCHD_SQLITE_TESTS=1` | Adds **`test_launch_agent_sqlite_backend_injects_env`**: disposable `HOME`, SQLite DB, **dummy** `SECKIT_SQLITE_PASSPHRASE` / `SECKIT_SQLITE_UNLOCK=passphrase` in the plist (**do not** put production passphrases in real plists). Requires PyNaCl. |

`test_launch_agent_backend_secure_explicit_uses_temp_keychain` passes **`--backend secure`** explicitly to guard the **`security`** code path.

### SQLite + launchd

Use **`--backend sqlite`** with **`--db`** and non-interactive **`SECKIT_SQLITE_PASSPHRASE`** (and **`SECKIT_SQLITE_UNLOCK=passphrase`**) in the job’s `EnvironmentVariables`, or adopt **`SECKIT_SQLITE_UNLOCK=keychain`** on macOS and supply **`SECKIT_SQLITE_KEK_KEYCHAIN`** / **`--keychain`** so the KEK is readable unattended (same Keychain provisioning discipline as **`secure`**). The repository validates the passphrase path via the test above; the smoke shell script does not implement a sqlite mode.

## Mode 2: Dedicated Service Keychain LaunchAgent

Use this when a user installs a service while logged in and the service may need to keep running after logout during the same boot.

```bash
./scripts/seckit_launchd_smoke.sh --mode service-agent
```

This provisions:

```text
~/Library/Keychains/seckit-service.keychain-db
~/.config/seckit/service-keychain.pass
```

The password file is `0600` and belongs to that user. It is sensitive service credential material. Protect it like an API token.

Cleanup the LaunchAgent/test item:

```bash
./scripts/seckit_launchd_smoke.sh --mode service-agent --cleanup
```

The service keychain and password file are intentionally not deleted by cleanup because they represent the provisioned service credential store.

## Mode 3: Dedicated Service Keychain LaunchDaemon

Use this when a machine-level service must survive logout and reboot before any user logs in.

```bash
sudo ./scripts/seckit_launchd_smoke.sh --mode service-daemon
```

This provisions:

```text
/Library/Application Support/SecretsKit/seckit-service.keychain-db
/Library/Application Support/SecretsKit/seckit-service.keychain.pass
/Library/Application Support/SecretsKit/seckit-launchd-smoke-wrapper.sh
/Library/LaunchDaemons/ai.unixwzrd.seckit.launchd-smoke.service-daemon.<user>.plist
```

The root-owned password file must be mode `0600`. The wrapper unlocks the service keychain, then runs `seckit run --keychain <service-keychain>`.

Cleanup the daemon/test item:

```bash
sudo ./scripts/seckit_launchd_smoke.sh --mode service-daemon --cleanup
```

The system service keychain and password file are intentionally retained unless an administrator removes them.

## Proof Output

Every mode writes proof JSON from the process started by launchd. The output includes:

```json
{
  "agent_simulator": true,
  "child_argv0": "/Users/example/projects/secrets-kit/scripts/seckit_launchd_agent_simulator.py",
  "euid": 1002,
  "home": "/Users/example",
  "keychain": "/Users/example/Library/Keychains/seckit-service.keychain-db",
  "launchd_target": "gui/1002/ai.unixwzrd.seckit.launchd-smoke.service-agent.example",
  "mode": "service-agent",
  "name": "SECKIT_TEST_ENV",
  "pid": 12345,
  "ppid": 1,
  "seckit_bin": "/Users/example/.venv/bin/seckit",
  "uid": 1002,
  "user": "example",
  "value": "expected-service-agent-example"
}
```

That file is the evidence that launchd started `seckit`, `seckit run` launched a separate child process, and the child process received the selected secret in its environment.

Keep artifacts for inspection:

```bash
./scripts/seckit_launchd_smoke.sh --mode service-agent --keep
cat "$TMPDIR/seckit-launchd-smoke-$(id -un)/service-agent-result.txt"
./scripts/seckit_launchd_smoke.sh --mode service-agent --cleanup
```

## Gated Tests

Normal validation does not run live launchd tests by default.

**Login keychain unittest** (`test_launch_agent_can_receive_login_keychain_secret_without_keychain_password`): provisioning calls `seckit set` against the **real** login keychain. That needs a session where Keychain allows non-prompt writes—typically **Terminal.app on the console** with the user logged in at the GUI. Over **SSH only**, macOS often returns `SecKeychainItemCreateFromContent ... User interaction is not allowed` and the test will fail; that is an environment limit, not a seckit logic error.

Run all user LaunchAgent tests:

```bash
SECKIT_RUN_LAUNCHD_TESTS=1 \
SECKIT_RUN_LAUNCHD_LOGIN_KEYCHAIN_TESTS=1 \
SECKIT_RUN_LAUNCHD_SERVICE_KEYCHAIN_TESTS=1 \
PYTHONPATH=src python3 -m unittest tests.test_launchd_run_flow -v
```

Run the LaunchDaemon test:

```bash
sudo SECKIT_RUN_LAUNCHD_TESTS=1 \
  SECKIT_RUN_LAUNCHD_DAEMON_TESTS=1 \
  PYTHONPATH=src python3 -m unittest tests.test_launchd_run_flow -v
```

## Manual Reboot Test

To prove reboot-safe behavior:

1. Run daemon setup and keep artifacts:

```bash
sudo ./scripts/seckit_launchd_smoke.sh --mode service-daemon --keep
```

2. Reboot the machine.
3. Before any user login, or immediately after boot via admin access, verify the proof file was recreated or the daemon can be kickstarted:

```bash
sudo launchctl kickstart -k system/ai.unixwzrd.seckit.launchd-smoke.service-daemon.root
cat /tmp/seckit-launchd-smoke-root/service-daemon-result.txt
```

4. Cleanup when finished:

```bash
sudo ./scripts/seckit_launchd_smoke.sh --mode service-daemon --cleanup
```

## Password Prompt Notes

The disposable launchd test keychain password used by the Python unittest is:

```text
launchd-pass
```

The service keychain modes generate their own random passwords and store them in the documented password files. Those password files are the unlock material for unattended service operation.

If `login-agent` reports `User interaction is not allowed`, the failure happened before launchd ran. Use that user's GUI Terminal session or switch to a dedicated service-keychain mode.
