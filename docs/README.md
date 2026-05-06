# Secrets Kit documentation

**Updated:** 2026-05-07

Use this page as the map. The root [README](../README.md) stays short; detail lives here.

## Operators

| Doc | Purpose |
|-----|---------|
| [QUICKSTART.md](QUICKSTART.md) | Shortest path: install, unlock keychain, set/list/run |
| [USAGE.md](USAGE.md) | Command reference: set, get, list, import, export, run, migrate |
| [DEFAULTS.md](DEFAULTS.md) | `defaults.json`, env vars, `seckit config` |
| [SECURITY_MODEL.md](SECURITY_MODEL.md) | What the tool does and does not protect |
| [INTEGRATIONS.md](INTEGRATIONS.md) | Patterns for apps, agents, Hermes, OpenClaw |
| [EXAMPLES.md](EXAMPLES.md) | Small scripts and command snippets |
| [examples/](examples/) | Runnable shell examples |

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
| [METADATA_REGISTRY.md](METADATA_REGISTRY.md) | Registry schema |

Other files under **`docs/plans/`** may be gitignored local notes.
