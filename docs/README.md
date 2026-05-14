# Secrets Kit documentation

**Created:** 2026-03-10
**Updated:** 2026-05-05

Use this page as the public documentation map. The root [README](../README.md) stays short; day-to-day detail lives here.

- [Secrets Kit documentation](#secrets-kit-documentation)
  - [Operators](#operators)
  - [CLI documentation set](#cli-documentation-set)
  - [Peer sync and validation](#peer-sync-and-validation)
  - [Testing and CI](#testing-and-ci)
  - [Packaging and maintainers](#packaging-and-maintainers)
  - [Internal public references](#internal-public-references)

## Operators

| Doc | Purpose |
|-----|---------|
| [QUICKSTART.md](QUICKSTART.md) | Shortest path: install, unlock keychain, set/list/run |
| [USAGE.md](USAGE.md) | Entry point + links to CLI docs (minimal examples) |
| [DEFAULTS.md](DEFAULTS.md) | `defaults.json`, env vars, `seckit config` |
| [SECURITY_MODEL.md](SECURITY_MODEL.md) | What the tool does and does not protect |
| [OPERATOR_LIFECYCLE.md](OPERATOR_LIFECYCLE.md) | Export/resilience policy, manual uninstall |
| [INTEGRATIONS.md](INTEGRATIONS.md) | Patterns for apps, agents, and runtimes (includes legacy OpenClaw examples) |
| [EXAMPLES.md](EXAMPLES.md) | Small scripts and command snippets |
| [examples/](examples/) | Runnable shell examples |

## CLI documentation set

| Doc | Purpose |
|-----|---------|
| [CONCEPTS.md](CONCEPTS.md) | Operator mental model; resolve vs materialize; compatibility summary |
| [RUNTIME_AUTHORITY_ADR.md](RUNTIME_AUTHORITY_ADR.md) | Protected authority handling; inject/export wording; invariants |
| [ARCHITECTURE_RUNTIME_SURFACE.md](ARCHITECTURE_RUNTIME_SURFACE.md) | Classify documentary vs production surfaces; local vs hosted vocabulary |
| [PACKAGE_VERSION.md](PACKAGE_VERSION.md) | Version authority, unknown sentinel, editable/checkout behavior |
| [DOCSTRING_CONTRACT.md](DOCSTRING_CONTRACT.md) | Contributor expectations for public functions and CLI handlers (S3.5) |
| [RUNTIME_SESSION_ADR.md](RUNTIME_SESSION_ADR.md) | Local peer/runtime session semantics |
| [IPC_SEMANTICS_ADR.md](IPC_SEMANTICS_ADR.md) | Local IPC and peer-side `seckitd` semantics |
| [CLI_REFERENCE.md](CLI_REFERENCE.md) | Full command reference |
| [WORKFLOWS.md](WORKFLOWS.md) | Recipes and common operator flows |
| [CLI_ARCHITECTURE.md](CLI_ARCHITECTURE.md) | Authority vs index; `backend-index`; safe output policy |
| [CLI_STYLE_GUIDE.md](CLI_STYLE_GUIDE.md) | Help style, JSON output stability, error classes |

## Peer Sync And Validation

| Doc | Purpose |
|-----|---------|
| [PEER_SYNC.md](PEER_SYNC.md) | Signed encrypted peer bundles; manual transport only |
| [PEER_BOOTSTRAP.md](PEER_BOOTSTRAP.md) | Disposable peer-root bootstrap scripts (`scripts/install.sh`, etc.) |
| [CROSS_HOST_VALIDATION.md](CROSS_HOST_VALIDATION.md) | Disposable-keychain transfer tests |
| [CROSS_HOST_CHECKLIST.md](CROSS_HOST_CHECKLIST.md) | Operational checklist |
| [LAUNCHD_VALIDATION.md](LAUNCHD_VALIDATION.md) | LaunchAgent/Daemon notes |

## Testing And CI

GitHub Actions runs `scripts/run_local_validation.sh` on macOS. Some tests require interactive Keychain access or PyNaCl; others use SQLite-only harnesses. On hosts where the default Keychain backend is unavailable, prefer a narrow suite or follow [CROSS_HOST_VALIDATION.md](CROSS_HOST_VALIDATION.md) disposable-keychain patterns.

## Packaging And Maintainers

| Doc | Purpose |
|-----|---------|
| [GITHUB_RELEASE_BUILD.md](GITHUB_RELEASE_BUILD.md) | Wheels, universal2, GitHub Actions secrets, local packaging scripts |

## Internal Public References

| Doc | Purpose |
|-----|---------|
| [SECKIT_RUN_AND_BACKEND_REWORK_PLAN.md](SECKIT_RUN_AND_BACKEND_REWORK_PLAN.md) | Historical public rework notes |
| [METADATA_SEMANTICS_ADR.md](METADATA_SEMANTICS_ADR.md) | Index/tombstone/generation, safe index, authority vs registry |
| [METADATA_REGISTRY.md](METADATA_REGISTRY.md) | Registry schema |
| [BACKEND_STORE_CONTRACT.md](BACKEND_STORE_CONTRACT.md) | BackendStore behavior and safe index contract |
| [IMPORT_LAYER_RULES.md](IMPORT_LAYER_RULES.md) | Public import/export boundary guidance |

Hosted relay, sync-host, customer/tenant, and private operational planning documents are intentionally not part of the public documentation index.
