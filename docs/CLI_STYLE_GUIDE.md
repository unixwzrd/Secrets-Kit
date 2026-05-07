# CLI style guide — Secrets Kit

**Created**: 2026-05-07  
**Updated**: 2026-05-07

Conventions for `seckit` help text, operator messages, and automation expectations.

## Command taxonomy and compatibility

- **Canonical commands** appear first in tables and root help.
- **Compatibility aliases** stay **script-safe** until deprecated; help names the **canonical** replacement where useful.
- **Advanced / internal** commands state operational/debug intent and have **lower prominence** in root `--help`.

## JSON output stability

- **JSON outputs** (e.g. `--json`, machine-readable diagnostics) are **more stable** for automation than tables, spacing, or help wording.
- **Human-readable** output is optimized for **operators**; **JSON** is optimized for **automation**.
- Do **not** pin CI to exact **`--help`** text snapshots; prefer **parser introspection** and behavioral tests.
- Human-readable tables and help **may evolve** between releases without being treated as a breaking API.

## Help verbosity and examples

- Root **`--help`:** compact, navigational, taxonomy-driven.
- Per-command **`--help`:** short **description** + **Examples:** block; prefer **≤ ~3 examples** (safe default first, advanced second; defer long flows to [WORKFLOWS.md](WORKFLOWS.md)).
- Avoid implementation dumps (SQL tutorials, schema dumps, `Security.framework` internals) in user-facing help.

## Cross-platform wording

- Prefer **generic backend** wording (“configured backend”, “store”) in shared commands.
- Do **not** assume **macOS** unless the command is explicitly platform-specific.
- **Keychain-specific** wording belongs mainly on **`unlock`**, **`lock`**, **`keychain-status`**, and capability explanations (e.g. **`doctor`**), not scattered across every subcommand.

## Safe defaults messaging

Frame **`--raw`**, **`--all`**, and **export** clearly as **elevated disclosure / materialization**. Prefer narrow defaults; document that **implicit bulk** when scope is ambiguous should be avoided (explicit **`--all`**, confirmations for destructive multi-entry actions).

## Error wording classes

Standardize recurring failure **categories** (templates can evolve, classes should not drift):

- Configuration errors  
- Backend unavailable  
- Unlock required  
- Selective resolve unavailable  
- Materialization denied (or “plaintext output requires …”)  
- Corruption detected  
- Recovery required  

**Exit codes:** equivalent failure classes should **converge toward stable exit-code semantics** over time; document target mappings in this guide and [CLI_REFERENCE.md](CLI_REFERENCE.md). Full uniformity is a **goal**, not required for every command in every release.

## Shared argparse helpers

`cli_groups.py` centralizes repeated **flag definitions** only. **Do not** infer identical **semantics** for every command from shared helpers—each command documents its own behavior.

## Tests and dynamic help

Help consistency tests **exempt**:

- **Dynamically generated** backend capability text.
- **Platform-conditional** paragraphs (assert structure and taxonomy anchors, not byte-for-byte parity across OSes).

## Deferred

A dedicated **`SECURITY_POSTURE.md`** (disclosure levels, authority/index separation, backend posture) may be added later; today, see [SECURITY_MODEL.md](SECURITY_MODEL.md) and [CLI_ARCHITECTURE.md](CLI_ARCHITECTURE.md).
