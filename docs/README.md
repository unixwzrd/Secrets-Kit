# Secrets Kit documentation

**Created:** 2026-03-10  
**Updated:** 2026-05-08

Use this page as the map. The root [README](../README.md) stays short; detail lives here.

- [Secrets Kit documentation](#secrets-kit-documentation)
  - [Operators](#operators)
  - [CLI documentation set](#cli-documentation-set)
  - [Keychain backends and validation](#keychain-backends-and-validation)
  - [Packaging and maintainers](#packaging-and-maintainers)
  - [Internal / planning (may move or trim)](#internal--planning-may-move-or-trim)


## Operators

| Doc | Purpose |
|-----|---------|
| [QUICKSTART.md](QUICKSTART.md) | Shortest path: install, unlock keychain, set/list/run |
| [USAGE.md](USAGE.md) | Entry point + links to CLI docs (minimal examples) |
| [DEFAULTS.md](DEFAULTS.md) | `defaults.json`, env vars, `seckit config` |
| [SECURITY_MODEL.md](SECURITY_MODEL.md) | What the tool does and does not protect |
| [INTEGRATIONS.md](INTEGRATIONS.md) | Patterns for apps, agents, Hermes, OpenClaw |
| [EXAMPLES.md](EXAMPLES.md) | Small scripts and command snippets |
| [examples/](examples/) | Runnable shell examples |

## CLI documentation set

| Doc | Purpose |
|-----|---------|
| [CONCEPTS.md](CONCEPTS.md) | Operator mental model; resolve vs **materialize**; compatibility summary |
| [RUNTIME_AUTHORITY_ADR.md](RUNTIME_AUTHORITY_ADR.md) | Protected authority handling; inject / exported wording; invariants |
| [RUNTIME_SESSION_ADR.md](RUNTIME_SESSION_ADR.md) | User-scoped session, same-host authority, ownership, cache bias |
| [IPC_SEMANTICS_ADR.md](IPC_SEMANTICS_ADR.md) | Local IPC; `seckitd` vs `relayd`; relay appendix (optional future) |
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
| [IPC_SEMANTICS_ADR.md](IPC_SEMANTICS_ADR.md) | IPC trust boundary, transport mediator, optional relay semantics |
| [METADATA_REGISTRY.md](METADATA_REGISTRY.md) | Registry schema |

Other files under **`docs/plans/`** may be gitignored local notes.
