# Secrets Kit documentation

**Created:** 2026-03-10  
**Updated:** 2026-05-12

Use this page as the map. The root [README](../README.md) stays short; detail lives here.

- [Secrets Kit documentation](#secrets-kit-documentation)
  - [Operators](#operators)
  - [CLI documentation set](#cli-documentation-set)
  - [Keychain backends and validation](#keychain-backends-and-validation)
  - [Testing and CI](#testing-and-ci)
  - [Packaging and maintainers](#packaging-and-maintainers)
  - [Internal / planning (may move or trim)](#internal--planning-may-move-or-trim)


## Operators

| Doc | Purpose |
|-----|---------|
| [QUICKSTART.md](QUICKSTART.md) | Shortest path: install, unlock keychain, set/list/run |
| [USAGE.md](USAGE.md) | Entry point + links to CLI docs (minimal examples) |
| [DEFAULTS.md](DEFAULTS.md) | `defaults.json`, env vars, `seckit config` |
| [SECURITY_MODEL.md](SECURITY_MODEL.md) | What the tool does and does not protect |
| [OPERATOR_LIFECYCLE.md](OPERATOR_LIFECYCLE.md) | Export/resilience policy, manual uninstall (no dark patterns) |
| [SYNC_HOST_PROVISIONING.md](SYNC_HOST_PROVISIONING.md) | Manual sync host provisioning; conceptual onboarding bundle |
| [INTEGRATIONS.md](INTEGRATIONS.md) | Patterns for apps, agents, Hermes, OpenClaw |
| [EXAMPLES.md](EXAMPLES.md) | Small scripts and command snippets |
| [examples/](examples/) | Runnable shell examples |

## CLI documentation set

| Doc | Purpose |
|-----|---------|
| [CONCEPTS.md](CONCEPTS.md) | Operator mental model; resolve vs **materialize**; compatibility summary |
| [RUNTIME_AUTHORITY_ADR.md](RUNTIME_AUTHORITY_ADR.md) | Protected authority handling; inject / exported wording; invariants |
| [RUNTIME_SESSION_ADR.md](RUNTIME_SESSION_ADR.md) | User-scoped session, same-host authority, ownership, cache bias |
| [IPC_SEMANTICS_ADR.md](IPC_SEMANTICS_ADR.md) | Local IPC; `seckitd` vs `relayd`; sync host vocabulary; relay appendix |
| [CLI_REFERENCE.md](CLI_REFERENCE.md) | Full command reference (taxonomy order) |
| [WORKFLOWS.md](WORKFLOWS.md) | Recipes; **common operator flows** appendix |
| [CLI_ARCHITECTURE.md](CLI_ARCHITECTURE.md) | Authority vs index; `backend-index`; safe output policy |
| [CLI_STYLE_GUIDE.md](CLI_STYLE_GUIDE.md) | Help style, **JSON output stability**, error classes |

## Keychain backends and validation

| Doc | Purpose |
|-----|---------|
| [PEER_SYNC.md](PEER_SYNC.md) | Signed encrypted **peer bundles** (`identity` / `peer` / `sync` CLI); manual transport only |
| [CROSS_HOST_VALIDATION.md](CROSS_HOST_VALIDATION.md) | Disposable-keychain transfer tests |
| [CROSS_HOST_CHECKLIST.md](CROSS_HOST_CHECKLIST.md) | Operational checklist |
| [LAUNCHD_VALIDATION.md](LAUNCHD_VALIDATION.md) | LaunchAgent/Daemon notes |

## Testing and CI

GitHub Actions runs `scripts/run_local_validation.sh` (full `unittest discover` on macOS). Some tests require **interactive Keychain** or **PyNaCl**; others use SQLite-only harnesses. On hosts where the default Keychain backend is unavailable, prefer a **narrow suite** (for example `tests.test_seckitd_phase5a`, `tests.test_sync_bundle`, `tests.test_import_layer_guards`, `tests.test_cli_help_consistency`) or follow [CROSS_HOST_VALIDATION.md](CROSS_HOST_VALIDATION.md) disposable-keychain patterns.

## Packaging and maintainers

| Doc | Purpose |
|-----|---------|
| [GITHUB_RELEASE_BUILD.md](GITHUB_RELEASE_BUILD.md) | Wheels, universal2, GitHub Actions secrets, local packaging scripts |

## Internal / planning (may move or trim)

| Doc | Purpose |
|-----|---------|
| [SECKIT_RUN_AND_BACKEND_REWORK_PLAN.md](SECKIT_RUN_AND_BACKEND_REWORK_PLAN.md) | Historical/rework notes |
| [METADATA_SEMANTICS_ADR.md](METADATA_SEMANTICS_ADR.md) | Index/tombstone/generation, safe index, authority vs registry |
| [RUNTIME_AUTHORITY_ADR.md](RUNTIME_AUTHORITY_ADR.md) | Resolve / materialize / inject / exported vocabulary (semantics-first) |
| [RUNTIME_SESSION_ADR.md](RUNTIME_SESSION_ADR.md) | Runtime session, ownership, same-host authority (pre-daemon) |
| [IPC_SEMANTICS_ADR.md](IPC_SEMANTICS_ADR.md) | Local IPC; `seckitd` vs `relayd`; sync host vocabulary; relay appendix |
| [METADATA_REGISTRY.md](METADATA_REGISTRY.md) | Registry schema |
| [plans/SYNC_HOST_PROTOCOL.md](plans/SYNC_HOST_PROTOCOL.md) | Managed sync host sketch (authority, persistence, offline, pinned keys) |
| [plans/SYNC_HOST_METRICS.md](plans/SYNC_HOST_METRICS.md) | Sync host metrics allowed vs forbidden |
| [plans/PHASE5D_RUNTIME_INTEGRATION.md](plans/PHASE5D_RUNTIME_INTEGRATION.md) | Phase 5D charter (runtime stabilization; anti–daemon-authority creep) |
| [plans/PHASE5D_DEPLOYMENT_VALIDATION.md](plans/PHASE5D_DEPLOYMENT_VALIDATION.md) | Multi-node / loopback operational checklist (no product network listener) |
| [plans/SECKITD_PHASE5.md](plans/SECKITD_PHASE5.md) | Local `seckitd` Phase 5A–5E scope, threat model, rollback reference |

Other files under **`docs/plans/`** may be gitignored local notes.
