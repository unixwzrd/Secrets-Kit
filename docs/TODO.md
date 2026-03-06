# Secrets Kit TODO

**Created**: 2026-03-05  
**Updated**: 2026-03-05

- [Secrets Kit TODO](#secrets-kit-todo)
  - [README and Positioning](#readme-and-positioning)
  - [Security/Model Clarity](#securitymodel-clarity)
  - [CLI UX Enhancements](#cli-ux-enhancements)
  - [Cross-Host Roadmap (v2+)](#cross-host-roadmap-v2)

## README and Positioning

- [ ] Tighten opening value proposition:
  - Keychain-native storage,
  - git-safe placeholders,
  - runtime export workflow.
- [ ] Promote `migrate dotenv` earlier in README feature list.
- [ ] Add “no value output by default” line near quickstart for confidence.
- [ ] Add a short “Philosophy” section (local-first, explicit config, no secret-in-git).
- [ ] Add roadmap link/section for post-v1 features.

## Security/Model Clarity

- [ ] Document exact Keychain mapping (`service`, `account`, `name`) in SECURITY docs.
- [ ] Clarify backend scope explicitly: macOS-only backend in v1.
- [ ] Add note on expected registry behavior when metadata exists but keychain value is missing.

## CLI UX Enhancements

- [ ] Add metadata-inspection command (for example `explain`) or document equivalent verbose list workflow.
- [ ] Add doctor check for “metadata present, keychain item missing” drift.
- [ ] Improve docs for composite identity collisions and how they are prevented.

## Cross-Host Roadmap (v2+)

- [ ] Design encrypted bundle export/import for cross-host replication.
- [ ] Evaluate `age` as default encryption mechanism (with optional GPG path).
- [ ] Define transport-agnostic sync guidance (rsync/syncthing/iCloud/private repo).
- [ ] Add non-committal roadmap statement in README (v2 planning, not v1 commitment).
