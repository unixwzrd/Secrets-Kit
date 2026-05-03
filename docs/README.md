# Secrets Kit documentation

**Updated:** 2026-05-02

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
| [ICLOUD_SYNC_VALIDATION.md](ICLOUD_SYNC_VALIDATION.md) | iCloud helper, signing, SIGKILL/troubleshooting, cross-Mac checks |
| [plans/icloud-two-host-checklist.md](plans/icloud-two-host-checklist.md) | **Manual** two-Mac iCloud sync checklist (create / read / update / add / delete) |
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

Checklists shipped with the repo: **`docs/plans/icloud-two-host-checklist.md`** (other files under **`docs/plans/`** are gitignored for local notes).
