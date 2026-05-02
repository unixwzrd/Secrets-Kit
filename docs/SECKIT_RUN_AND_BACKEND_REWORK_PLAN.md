# Secrets-Kit Run And Backend Rework Plan

**Created**: 2026-04-28

Back: [README](../README.md)

## Summary

Rework Secrets-Kit around a safer runtime-launch workflow:

1. resolve selected secrets in the parent `seckit` process
2. inject those values into the child process environment
3. launch the child without putting secrets on the command line
4. keep storage backends behind a clean interface so macOS `security`, native Keychain/iCloud, and future stores can be swapped without changing CLI behavior

The desired operator workflow is:

```bash
seckit run --service <service> --account <account> -- command --with --args
```

`seckit run` already exists, and the immediate runtime-launch behavior has been tightened. The remaining larger work is the storage backend refactor and deeper native iCloud implementation.

## Current Findings

- `seckit run` is already implemented as a subcommand.
- `seckit run` already resolves secrets in the parent process and launches the child with `os.execvpe`.
- Tests already cover basic env injection, missing command handling, and explicit error messages when a selected secret cannot be read.
- `src/secrets_kit/native_helper.py` has been restored so CLI/backend/helper tests import cleanly.
- The macOS `security` CLI is currently mixed directly into `keychain_backend.py`.
- iCloud Keychain support should use native Security framework APIs with synchronizable Keychain items, not the `security` CLI alone.
- Documentation still emphasizes `export` in several places where `run` should become the safer recommendation for launching a process.
- Service-level secret injection should be easy: `--names` should be optional, and by default `run` should inject the selected service/account scope.
- Operators need a way to duplicate one service scope into another, then override the values that should differ.
- Dotenv import needs explicit upsert behavior so newly added variables can update an existing service safely.
- The account can usually default to the current OS user unless explicitly set.

## Design Goals

- Keep secrets out of command-line arguments.
- Avoid requiring long-lived `eval "$(seckit export ...)"` shell sessions for process launch.
- Keep secret selection explicit and auditable.
- Make broad secret injection require an obvious `--all`.
- Make failures name the specific secret that could not be read.
- Make the CLI independent from the storage backend implementation.
- Keep automated tests isolated from the login keychain by using disposable keychains.
- Keep real iCloud sync validation manual because it depends on Apple ID, iCloud Keychain state, and multiple hosts.

## Proposed CLI Behavior

Canonical command:

```bash
seckit run --service my-stack -- python app.py
```

By default, `run` should inject all secrets for the selected service/account. This keeps the common case short while still allowing narrower selection when needed.

Supported selectors should match `export`:

```bash
seckit run --service my-stack -- python app.py
seckit run --service my-stack --account local-dev --names OPENAI_API_KEY,TELEGRAM_BOT_TOKEN -- python app.py
seckit run --service my-stack --account local-dev --tag runtime -- python app.py
seckit run --service my-stack --account local-dev --kind api_key -- python app.py
seckit run --service my-stack --account local-dev --all -- python app.py
```

Optional alias under consideration:

```bash
seckit --run --service my-stack --account local-dev --names OPENAI_API_KEY -- python app.py
```

Recommendation: keep `seckit run` as canonical and only add `--run` / `-r` if there is a strong compatibility or UX reason. A subcommand is clearer with `argparse` because everything after `--` belongs to the child command.

Account default:

```text
explicit --account
SECKIT_DEFAULT_ACCOUNT
saved defaults config
current OS user from getpass.getuser()
```

The current OS user default should be visible in `seckit defaults` / `seckit doctor` output so operators are not surprised by which account scope is active.

## Service Copy And Dotenv Update Workflow

Operators should be able to copy one service scope into another:

```bash
seckit service copy --from-service OpenClaw --to-service Hermes
seckit service copy --from-service OpenClaw --from-account mia --to-service Hermes --to-account mia
```

Expected behavior:

- copy all selected names from the source service/account to the destination service/account
- preserve metadata where it still applies
- rewrite service/account metadata to the destination scope
- skip existing destination names by default
- support `--overwrite` for intentional replacement
- support `--names`, `--tag`, `--type`, and `--kind` selectors
- support `--dry-run`

Dotenv import/update should support this workflow:

```bash
seckit import env --dotenv .env --service Hermes --account mia --upsert
```

Expected behavior:

- create new names that do not exist
- update existing names only when `--upsert` or `--allow-overwrite` is provided
- preserve existing metadata fields when values are updated unless explicit metadata flags are supplied
- report created, updated, skipped, and unchanged counts
- never print imported secret values
- keep placeholder rewrite/migration behavior separate from plain import/update

## Backend Architecture

Introduce a backend abstraction with this shape:

```text
SecretStore
  set(secret)
  get(service, account, name)
  exists(service, account, name)
  metadata(service, account, name)
  delete(service, account, name)
  doctor()
```

Initial backends:

- `SecurityCliStore`: wraps the macOS `security` command for local keychain access and disposable test keychains.
- `NativeKeychainStore`: calls the native helper for local and iCloud/synchronizable Keychain items.
- Future `PgpStore` or similar: can implement the same interface without changing `seckit run`.

Backend selection should remain:

```bash
--backend local
--backend icloud
--keychain /tmp/test.keychain-db
```

Rules:

- `--backend local` can use `security` CLI by default.
- `--backend local --keychain <path>` must continue to use disposable keychain files for tests.
- `--backend icloud` must require the native helper.
- `--backend icloud --keychain <path>` must fail clearly because custom keychain files are local-only.

## iCloud Keychain Notes

The `security` command is not the right abstraction for reliable iCloud Keychain behavior.

The native helper should use Apple Security framework APIs and synchronizable item attributes. In Apple’s Security framework this is represented through synchronizable Keychain item attributes, commonly exposed as `kSecAttrSynchronizable`.

Important constraints:

- iCloud sync is Apple-managed, not Secrets-Kit-managed.
- Sync availability depends on Apple ID, iCloud Keychain settings, local trust state, and device policy.
- Automated tests should mock the helper protocol.
- Real iCloud validation should remain a manual checklist across two Macs.

## Implementation Checklist

### Phase 1: Restore Testability

- [x] Restore or recreate `src/secrets_kit/native_helper.py`.
- [x] Confirm `PYTHONPATH=src python3 -m unittest tests.test_cli_commands tests.test_backend_resolution tests.test_native_helper` imports cleanly.
- [ ] Remove stale `__pycache__` assumptions from debugging notes and ignore generated cache files if needed.
- [x] Verify existing `seckit run` unit tests still cover parent-side env injection.
- [x] Run the full unit suite after the import repair.

### Phase 2: Storage Backend Refactor

- [x] Define a `SecretStore` protocol or abstract base class.
- [x] Move direct `security` subprocess calls into a `SecurityCliStore` implementation.
- [x] Move native helper request handling into a `NativeKeychainStore` implementation.
- [x] Keep public backend functions as compatibility wrappers during the transition.
- [x] Preserve current metadata behavior, including keychain comment JSON.
- [x] Preserve disposable keychain support through `--keychain`.
- [x] Add backend-resolution tests for local, local-with-keychain, local-helper, and iCloud-helper paths.

### Phase 3: Harden `seckit run`

- [x] Require a child command after `--`.
- [x] Keep parent-side secret resolution before child launch.
- [x] Keep child launch through `os.execvpe` or an equivalent no-shell exec path.
- [x] Preserve the existing environment and overlay selected secrets.
- [x] Make `--names` optional.
- [x] Default to injecting all secrets in the selected `service/account` scope.
- [x] Keep `--names`, `--tag`, `--type`, and `--kind` as narrowing selectors.
- [x] Treat `--all` as an explicit cross-scope or broad-selection mode, not as a requirement for normal service/account injection.
- [x] Confirm `--names`, `--tag`, `--type`, `--kind`, and `--all` selection behavior matches `export`.
- [x] Default `--account` to the current OS user when no CLI, env, or saved default is set.
- [ ] Show the resolved account default in diagnostics so implicit scope is visible.
- [x] Ensure failed reads name `service`, `account`, and `name`.
- [x] Ensure `seckit run` does not print secret values.
- [ ] Decide whether to add `--run` / `-r` as an alias or keep only the `run` subcommand.

### Phase 4: Service Copy And Dotenv Upsert

- [x] Add a `service copy` command or equivalent scope-copy command.
- [x] Support source and destination service/account arguments.
- [x] Support copying selected names only.
- [x] Support copying by tag, type, and kind.
- [x] Skip existing destination names by default.
- [x] Add `--overwrite` for intentional replacement.
- [x] Add `--dry-run` with created/updated/skipped counts.
- [x] Preserve metadata where appropriate and rewrite service/account fields for the destination.
- [x] Add tests for copying `OpenClaw` scope into `Hermes` scope.
- [ ] Confirm copied secrets can then be independently changed in the destination service.
- [x] Add explicit dotenv upsert/update behavior.
- [x] Ensure `.env` import creates newly added names.
- [x] Ensure `.env` import updates existing values only when `--upsert` or `--allow-overwrite` is present.
- [x] Ensure `.env` import reports created, updated, skipped, and unchanged counts.
- [x] Keep dotenv placeholder rewrite under migration, not plain import.

### Phase 5: Process Execution Tests

- [x] Add a unit test that mocks `_exec_child` and verifies injected env values.
- [x] Add a real child-process integration test using a disposable keychain.
- [x] Store `SECKIT_TEST_ENV=expected` in a temporary keychain.
- [x] Run a child Python command through `seckit run`.
- [x] Have the child write the env value to a temporary output file.
- [x] Assert the output file contains `expected`.
- [x] Assert secrets are not included in the child command argv.
- [x] Skip disposable-keychain integration tests outside macOS.

### Phase 6: Required launchd Support Test

- [x] Add a launchd integration test for `seckit run`.
- [x] Gate automated execution behind `SECKIT_RUN_LAUNCHD_TESTS=1` because CI/headless sessions may not have a usable per-user launchd context.
- [x] Generate a temporary LaunchAgent plist for the current user.
- [x] Use `seckit run` as the launched command wrapper.
- [x] Have the launched child write a selected env value to a temporary file.
- [x] Use the disposable test keychain path in the launched command where possible.
- [x] Load, run, unload, and remove the LaunchAgent.
- [x] Document launchd validation as a release-blocking manual check when the automated launchd test is not enabled.
- [x] Add a login-keychain LaunchAgent test that does not supply a keychain password to launchd.
- [x] Pass the login keychain path explicitly for LaunchAgent runs so they do not depend on launchd's default keychain search list.
- [x] Add dedicated service-keychain LaunchAgent smoke support for after-logout service behavior.
- [x] Add dedicated service-keychain LaunchDaemon smoke support for after-reboot service behavior.
- [x] Document that login-keychain LaunchAgent mode is user-session only.
- [x] Document that LaunchDaemon mode uses a root-owned service-keychain password file.

### Phase 7: Native iCloud Backend

- [x] Confirm or restore native helper source layout.
- [x] Define helper JSON request and response schema.
- [x] Implement helper operations for `set`, `get`, `exists`, `metadata`, and `delete`.
- [x] Use synchronizable Keychain item attributes for `--backend icloud`.
- [x] Keep `seckit helper status` reporting local helper and iCloud backend availability.
- [x] Add mocked helper tests for iCloud operations.
- [ ] Keep real iCloud sync validation manual.

### Phase 8: Documentation Cleanup

- [x] Update `README.md` to prefer `seckit run` for launching processes.
- [x] Update `docs/USAGE.md` with the canonical `seckit run ... -- command` pattern.
- [x] Update `docs/INTEGRATIONS.md` to recommend `run` for process launch and reserve `export` for shell-session workflows.
- [x] Document that `run --service <name>` defaults to all names in that service/account scope.
- [x] Document account defaulting to the current OS user.
- [x] Document service copy workflows for OpenClaw/Hermes-style service duplication.
- [x] Document dotenv update/upsert behavior.
- [x] Update `docs/SECURITY_MODEL.md` to describe process inheritance risks clearly.
- [x] Update `docs/DEFAULTS.md` to clarify backend selection and helper requirements.
- [x] Update `docs/ICLOUD_SYNC_VALIDATION.md` to distinguish helper support from actual Apple-managed sync.
- [x] Review `docs/CROSS_HOST_CHECKLIST.md` and `docs/CROSS_HOST_VALIDATION.md` for stale helper/TODO language.
- [x] Move obsolete planning notes from `docs/internal/` to `docs/archive/` or remove them.
- [x] Move or delete `tmp/Swift-helper.md` after extracting any still-useful helper design details.

### Phase 9: Final Validation

- [x] Run targeted CLI/backend tests:

```bash
PYTHONPATH=src python3 -m unittest tests.test_cli_commands tests.test_backend_resolution tests.test_native_helper
```

- [x] Run full unit suite:

```bash
PYTHONPATH=src python3 -m unittest discover
```

- [x] Run disposable-keychain integration tests on macOS.
- [x] Run launchd integration validation before release, either through `SECKIT_RUN_LAUNCHD_TESTS=1` or the documented manual release check.
- [ ] Run service-keychain LaunchAgent validation with `SECKIT_RUN_LAUNCHD_SERVICE_KEYCHAIN_TESTS=1`.
- [ ] Run LaunchDaemon service-keychain validation with `SECKIT_RUN_LAUNCHD_DAEMON_TESTS=1`.
- [ ] Run manual iCloud validation on two Apple ID/iCloud-enabled macOS hosts.
- [x] Confirm docs no longer recommend `export` where `run` is safer.
- [x] Confirm service copy and dotenv upsert tests cover OpenClaw/Hermes-style service separation.

### Phase 10: CI/CD

- [x] Keep pull request and push CI on supported macOS/Python combinations.
- [x] Ensure CI invokes the same local validation script used by maintainers.
- [x] Ensure validation builds the Swift native helper when Swift is available.
- [x] Unignore project scripts required by CI so fresh checkouts include them.
- [x] Add release workflow for tag/manual distribution builds.
- [x] Keep PyPI publishing explicit through manual workflow dispatch and trusted publishing.

## Acceptance Criteria

- `seckit run` launches a child command with selected secrets in the child environment.
- `seckit run --service <service>` injects all secrets in the selected service/account scope by default.
- `--names`, `--tag`, `--type`, and `--kind` narrow the default service/account scope.
- `--account` defaults to the current OS user when no explicit/default account is configured.
- Secrets are not passed as command-line arguments.
- Secret values are not printed during normal `run` execution.
- `seckit run` works when invoked by a per-user launchd LaunchAgent.
- `seckit run` works from a LaunchAgent using a dedicated service keychain for after-logout service operation.
- `seckit run` works from a LaunchDaemon using a dedicated service keychain and root-owned unlock file for after-reboot operation.
- A service can be copied to a new service name and then independently modified.
- Dotenv import can add new keys and update existing service values intentionally.
- The storage backend is abstracted enough to swap `security` CLI for native Keychain or future stores.
- `--backend local --keychain <path>` remains usable for isolated tests.
- `--backend icloud` uses the native helper and fails clearly when unavailable.
- Test suite imports cleanly and passes.
- Docs clearly explain the safer `run` workflow and backend limitations.
