# Secrets Kit changelog

Customer-facing changes. This file is derived from the authoritative public changelog in the documentation source.

## Unreleased

## 2.0.1b19 — public beta

- Promote the DEV a58 release-process and documentation corrections without changing the qualified a56 client runtime. Derive installer operator origin from repository/ref, compare product inputs before each promotion, and remove stale fixed release tags from channel-neutral installation and Hermes integration instructions. Installed QA qualification passed before public-beta promotion.

## 2.0.1b18 — QA qualification candidate

- Promote the DEV a56 SSH peer-verification fix: use the invoked shared-host CLI when an older per-user launcher remains, while preserving the remote peer's own launcher and signed authorization. Installed QA qualification remains pending.

## 2.0.1b17 — QA qualification candidate

- Promote the DEV a55 listener-readiness fix: local libp2p and daemon IPC become reachable before RSS authentication completes. Missing RSS credentials still fail closed before listener startup; relay authorization and reservation rules are unchanged. Installed QA qualification remains pending.

## 2.0.1b16 — QA qualification candidate

- Embed the environment-specific RSS operator origin in verified prerelease installers. Shared-host Checkout reads the active generation's origin ahead of an older per-user receipt, so DEV and QA users cannot silently fall back to the production operator. Installed QA qualification remains pending.

## 2.0.1b15 — QA qualification candidate

- Recognize two users already joined to the same active shared host when installing to localhost; use the shared launcher for peer authorization without replacing either user's runtime or store. The installed DEV a52 command passed; QA qualification remains pending.

## 2.0.1b14 — QA qualification candidate

- Bring the DEV shared-host runtime, opt-in organization/client context, sequential generation activation, and direct-route/RSS fallback work into private QA for installed qualification. Preserve distinct per-user stores, identities, and RSS credentials.
- Retain listener recovery and the bounded failure-location diagnostic. The intermittent post-bind `RuntimeError` has no confirmed root cause; QA must not be marked qualified on CI alone.
- Mixed-version qualification found that a b13 peer rejected a new organization/client-scoped write, then received it after upgrading to a51. Upgrade participating peers before opt-in and verify preservation; do not claim old/new synchronization from this result.

## 2.0.1b12 — QA beta candidate

- Promote single-use beta Checkout invitation support and verified RSS operator-origin recording from DEV. QA installation and tester-handoff qualification remain required.

## 2.0.1b11 — QA beta candidate

- Promote the a41 remote peer-install path and the a42 checksum-pinned Linux ARM64 `fastecdsa` wheel into QA. After a successful Linux same-user service install, warn when systemd linger is disabled. Unattended operation after logout still requires an administrator to run `loginctl enable-linger` for that Unix user. The warning is nonfatal; linger is not an installation prerequisite, and macOS behavior is unchanged. QA installation and tester-handoff qualification remain required.

## 2.0.1b10 — QA beta candidate

- Promote the DEV-qualified default installer PATH setup and managed PATH-block uninstall cleanup into QA. Preserve explicit profile opt-outs, unrelated shell configuration and immutable release provenance. QA installation and tester-handoff qualification remain required.

## 2.0.1a42 — alpha candidate, qualification pending

- Bundle a checksum-pinned, GMP-repaired `fastecdsa` CPython 3.12 wheel for Linux ARM64. The exact a41 installer failed on a clean Debian ARM64 account because upstream publishes no compatible binary wheel and source builds are deliberately disabled on client machines.

## 2.0.1a41 — alpha candidate, failed ARM64 installation qualification

- Prepare the customer-facing `seckit install user@host` path to deliver a verified private installer over SSH, initialize a fresh peer, set up its same-user service, and authorize the relationship through existing signed peer-admission commands. Preserve installed identities and admission on reinstall. CI selects pinned dependency artifacts from one checksum manifest and rejects drift before building the installer. Source checks do not establish installed DEV or QA qualification.

## 2.0.1a40 — alpha candidate

- Remove the installer's exact managed PATH block during confirmed uninstall, preserving shell profiles, unrelated content and permissions. Dry-run reports planned profile edits; edited or unsafe profiles are not silently rewritten. Retain the a39 default PATH setup for downloaded and piped installers.

## 2.0.1a39 — alpha candidate

- Fix generated single-file installers to configure the existing managed shell PATH block for ordinary file and piped installs, while preserving explicit `--no-shell-profile` and `--safe` opt-outs. Replace the manual PATH-export instruction with a new-terminal instruction. Existing uninstall cleanup and runtime/profile rollback behavior are unchanged.

## 2.0.1b9 — QA beta candidate

- Promote the a38 authenticated binding and pinned transport repairs into QA after DEV four-peer convergence and ARM/Rocky restart recovery qualification. QA installed qualification and tester-handoff review remain required.

## 2.0.1a38 — alpha candidate

- Allow inbound peer authentication to complete while an outbound binding is pending, instead of discarding the inbound opportunity based on transport ID ordering. Preserve authentication, admission checks, deadlines and binding-state ownership. Installed multi-peer qualification remains required.

## 2.0.1a37 — alpha candidate

- Preserve connection type and transport addresses through the pinned libp2p Noise wrapper so authenticated relay bindings can retain their relay route instead of using a peer's advertised LAN address. Existing encryption, peer authorization and retry behavior remain unchanged. Installed multi-peer recovery qualification remains required.

## 2.0.1a36 — alpha diagnostic candidate

- Include the in-flight RSS authentication stage in failure diagnostics so connection setup, control exchange and prior-stream cleanup can be distinguished. Preserve existing authentication, timeout, retry and connection-retirement behavior. This diagnostic candidate does not claim to fix the installed intermittent RSS failure.

## 2.0.1a35 — alpha candidate

- Preserve the selected relay path for authenticated relayed inbound peer bindings when Identify replaces stored dial addresses with LAN listener advertisements. Do not infer a relay from missing connection metadata or invent an unavailable reverse route. Existing authentication and retry policy remain unchanged; installed recovery qualification remains required.

## 2.0.1a34 — alpha candidate

- Continue authenticated inbound peer binding when reverse-address evidence is missing or expired, without inventing a reverse route or weakening identity, signature or admission checks. Distinguish an absent claim from a mismatched identity. Release only a cancelled outbound attempt's own binding and matching discovery notification so a later discovery event can retry; preserve newer state and duplicate suppression. Installed recovery qualification remains required.

## 2.0.1a33 — alpha candidate

- Refresh expired peer-address records before replacing them with the selected RSS circuit address. Treat missing or expired endpoint evidence as unavailable rather than failing a libp2p connection notification. Preserve runtime authentication, scoped admission and existing retry policy. Installed recovery qualification remains required.

## 2.0.1a32 — alpha candidate

- Bound inbound peer-binding I/O and stream cleanup using existing timeouts. Interrupted or stale attempts cannot overwrite a newer binding attempt's state. Preserve challenge, signature, admission checks and verified RSS circuits. Source regression checks pass; installed DEV qualification remains required before QA promotion.

## 2.0.1a31 — alpha candidate

- Authenticate incoming recovery handshakes through the existing identity and admission checks instead of silently closing them because a prior binding is cached as healthy or rejected. Preserve outbound event coalescing and the existing wire protocol. Installed DEV qualification is required before QA promotion.

## 2.0.1b8 — QA beta candidate

- Promote the a30 RSS candidate-selection and binding-coordination repair into QA. This is not installed qualification or tester-handoff approval.

## 2.0.1a30 — alpha candidate

- Preserve preferred RSS circuit selection across disconnects and serialize concurrent binding attempts for one destination. Ignore stale relay callbacks and reconsider a newly selected endpoint after the active attempt completes. Regression coverage reproduces the prior circuit-switching race; installed LAN/RSS qualification remains required.

## 2.0.1b7 — QA beta candidate

- Promote the a29 event-driven delivery and recovery repair into QA. Installed multi-user LAN/RSS, billing/provisioning workflow and private production rehearsal remain required; missing-history exchange is not implemented.

## 2.0.1a29 — alpha candidate

- Replace recurring peer identity-binding sweeps with discovery/connection event handling and coalesce duplicate candidate notifications. Bound failed envelope delivery attempts per peer, retain queued work while unavailable, and wake delivery on authenticated route recovery or local CLI mutations. Source regression checks pass; installed multi-user LAN/RSS qualification remains pending. This does not implement missing-history exchange between peers.

- Reconsider known rejected discovery candidates after successful local pairing. Bound stream I/O and cleanup, permit finite retries using retained authenticated locators, and schedule interrupted delivery recovery at claim expiry without periodic worker polling.

## 2.0.1b6 — QA beta candidate

- Promote the a28 configured RSS relay-port enrollment repair and regression coverage into QA. Installed paid provisioning and full RSS qualification remain required before tester handoff.

## 2.0.1a28 — alpha candidate

- Accept configured RSS TCP relay ports during paid enrollment and interrupted-enrollment recovery instead of requiring port 4001. Malformed relay address shapes and invalid port numbers remain rejected.

## 2.0.1b5 — QA beta candidate

- Promote the a27 multi-user LAN discovery, concrete listener binding and recovery repair into QA. Installed encrypted synchronization and release-artifact qualification remain required before tester handoff.

## 2.0.1a27 — alpha candidate

- Bind dynamic peer listeners and mDNS announcements to the selected active LAN interface, excluding point-to-point VPN interfaces. Recreate the listener when the LAN address changes while retaining peer identity; do not advertise the offline loopback listener.

- Include a pinned Python-only LAN-discovery dependency with the installer, including automatic integrity verification and corresponding dependency source. Customers do not need to download or build it separately. Installed discovery and synchronization qualification remains pending.

## 2.0.1b4 — QA beta candidate

- Promote the reviewed a26 default-interface discovery repair into QA; installed multi-user encrypted synchronization qualification remains required before tester handoff.

## 2.0.1a26 — alpha candidate

- Refresh LAN discovery candidates when peer addresses change or announcements disappear, without changing peer authorization or RSS routing. Local discovery uses the operating system's default IPv4 multicast interface and dynamically allocated listener ports, allowing independent users on one host; simultaneous discovery across secondary interfaces is not supported.

## 2.0.1b3 — QA beta candidate

- Carry the archive-free installer wrapper and CI tag-reference restoration into QA. Earlier tags remain immutable; tagged artifacts and installed qualification are required before handoff.

## 2.0.1a25 — alpha candidate

- Decode and verify embedded installer files directly, removing the wrapper's tar requirement while preserving the existing managed-runtime bootstrap.
- Restore the exact pushed tag reference after CI checkout and verify checkout HEAD against the event commit before release validation.

## 2.0.1b2 — QA beta candidate

- Carry the annotated-tag preflight and commit-pinned installer fixes into QA. The failed b1 tag remains immutable; this candidate requires new CI artifacts and installed qualification.

## 2.0.1a24 — alpha candidate

- Validate annotated release tag objects separately from their source commits while retaining repository, version and branch ancestry checks.
- Validate the versioned wheel in a verified branch installer independently of its pinned source commit; reject inconsistent bundle identity.

## 2.0.1b1 — QA beta candidate

- Promote the reviewed alpha installer and version-family update safeguards to the QA beta line. Package and installer identity are rebuilt for this beta version; earlier alpha artifacts remain immutable. Installed QA qualification is tracked separately from source tests.

## 2.0.1a23 — alpha candidate

- Keep automatic update offers within the installed alpha, beta, release-candidate or stable version family; reject obsolete cross-family cached offers. Explicit maintainer-approved version selection remains available.
- Validate CI branch/version and repository visibility before release builds, and require tags to belong to their intended source branch. Installer repository, ref and source identity continue to come from CI rather than fixed download locations.

- Report incomplete installer streams as failures on macOS Bash 3.2 as well as newer Bash; retain payload verification and temporary-file cleanup.

- Generate installer provenance in CI from repository, tag/branch, commit and project version; remove fixed repository/tag defaults. Branch artifacts pin their source commit, while only tagged builds publish releases. Preserve automated upgrade arguments and allow bounded self-contained installer downloads. Existing a22 clients need a downloaded-script upgrade for their first transition.

- Provide a single-file installer named `install.sh` across beta and production, with an optional `install.sh.sha256`, supporting downloaded-script, curl-to-Bash and wget-to-Bash execution, with automatic embedded-file verification and an optional script checksum. Simplify installation instructions; the a22 application and tagged assets are unchanged.

## 2.0.1a22 — candidate

- Retain bounded route-invalidation and circuit-switch diagnostic events without including message payloads or exception text. Routing decisions and delivery behavior are unchanged.

## 2.0.1a21 — candidate

- Reduce per-envelope route-refresh startup by querying runtime-owned endpoint records without loading the full CLI. Preserve fresh datastore validation, subprocess isolation, timeout, route output and delivery order. Candidate validation is in progress; immutable a20 is unchanged.

## 2.0.1a20 — candidate

- Reduce inbound synchronization subprocess startup by invoking the existing runtime entrypoint directly instead of loading unrelated CLI commands. Preserve encrypted-envelope validation, datastore and replay behavior, fresh-process isolation, timeout and exit-status handling. Installed-candidate qualification remains pending.

## 2.0.1a19 — candidate

- Require explicit successful RSS session authentication before retaining a control stream or accepting routes. Successful primary authentication completes pending local enrollment cleanup after an interrupted response; a later secondary response cannot restore the consumed token reference. Device credentials and synchronization semantics are unchanged. Not included in immutable a18.

## 2.0.1a18 — candidate

- Align CLI status with the existing five-second MCP status wait. Slow responses are not retried or treated as success; unavailable responses still report unknown liveness. This correction is not included in immutable a17.

## 2.0.1a17 — candidate

- Reduce daemon status subprocess startup by invoking the runtime-owned read-only collector directly. Preserve the existing response, datastore validation and two-second caller timeout. This supersedes a16 only after artifact qualification.

- Invoke the read-only runtime status collector directly in its subprocess, avoiding full customer CLI startup while preserving datastore ownership, validation and status output. This candidate latency repair is not included in immutable a16 and still requires live IPC and installed qualification.

- Preserve an already-validated peer route when one libp2p connection closes but another connection to the same peer remains open. The last connection closing still invalidates the route; open connections alone do not establish or reactivate validated routes.

- Prevent Keychain metadata inspection and `explain` from exposing password-bearing command output. Metadata lookup no longer requests the password and retains only recognized attributes. Explicit secret retrieval and export remain available. This repair is not included in immutable a15.

- Collect runtime status and active route records in one daemon-to-runtime subprocess instead of two sequential CLI startups. Preserve runtime-owned datastore access, route selection and unavailable-status handling. This bounded latency repair is not included in immutable a14 and still requires installed qualification.

- Distinguish saved RSS configuration from observed relay authentication. Pending authorization returns nonzero while retaining the running local daemon; bounded capacity-denial feedback does not expose provider responses. Not included in immutable a13.

- Keep local daemon startup available when configured RSS endpoints reject authentication or cannot reserve a circuit. Retain authenticated retry state; request reservations only after authorization, including after recovery. Invalid local configuration still fails closed. This repair is not present in the immutable a12 artifact.

- Package only the pinned libp2p security backport in source distributions; exclude superseded dependency wheels from release inputs.

- Bind RSS enrollment proofs to the device's connection ID and public key using proof version 2, and reject enrollment responses for a different device or entitlement. Requires a matching enrollment service; version-1 enrollment proofs are not accepted.

- Report unavailable daemon status as `UNKNOWN` with JSON `daemon.running: null`, retaining the error and nonzero exit status. A timeout or invalid response is not evidence that the daemon stopped.

- Make runtime status use the SQLite default on macOS and Linux when no backend is configured, while preserving an explicitly configured Keychain backend.

- Remove obsolete runtime debug-mode controls and implicit custom-store initialization. Require explicit envelope codecs and encrypted live inbound synchronization; preserve destination, identity and replay safeguards. Direct TCP is explicitly test-only; installer editable installs remain supported.

Candidate version: `2.0.1a16`. This candidate is not yet published or installed-product qualified; earlier artifacts remain immutable.

- Encrypt synchronization envelopes by default for LAN P2P and RSS alike, independently of local storage encryption and RSS enrollment. Normal initialization offers no security-mode choice; unencrypted developer tests require separate explicit UNSAFE overrides, not a general application mode.

- Report the selected backend and SQLite storage mode after initialization; exercise bare initialization and subsequent default-backend operations in a fresh-home regression test.

- Default fresh initialization and unconfigured CLI backend selection to SQLite on macOS and Linux, while preserving explicitly configured Keychain selection. No datastore migration or replay changes.

- Expand application examples beyond agents to PostgreSQL, Redis and batch jobs, with explicit environment/password-file security boundaries.

- Align the README, installation and Hermes instructions with the a9 artifact layout and supported upgrade commands. These documentation corrections do not change already tagged release artifacts.

## 2.0.1a9 — 2026-09-16 (prerelease)

- Add `seckit upgrade` as a confirmation-gated wrapper around the preserving generation installer, with bounded release checks, exact-tag validation, downgrade refusal, an owner-only cache, an optional same-user daily checker, and a human-only `seckit status` update notice. The checker never installs automatically or stores credentials.
- Verify the selected release installer digest before execution and protect download credentials from process arguments. Preserve existing files after failed partial downloads.
- Remove the optional update checker during uninstall; refuse unsafe definitions and unknown service state.

## 2.0.1 prerelease series — through 2.0.1a8

Cumulative client changes preceding a9. Qualification evidence is maintained separately from these release notes.

- Enforce prebuilt cryptographic dependencies consistently for local and remote installation; no environment override enables native crypto compilation.

- Add explicit uninstall `--purge` selections for individual standard state files and named Keychain entries. Require `--yes`, complete requested archives before deletion, preserve unselected/custom files, and refuse unsafe targets. Partial failures retain the runtime for inspection and retry.

- Include a read-only preserved-state inventory in uninstall dry-run output, distinguishing standard names, unknown/custom entries, unsafe standard entries, and uninspectable locations. This inventory does not authorize deletion or implement purge.

- Refuse to treat failed Keychain inspection as an absent secret; report a localized, value-free error for lookup failures other than item-not-found.

- Refuse exit archives containing hard-linked state files before removing the runtime; preserve the original files and aliases for explicit owner review.

- Update cryptography to 50.0.1. Intel macOS installation uses pinned prebuilt publisher packages with approved metadata-directed OpenSSL relocation inside the UV runtime, without a compiler, Conda installation or custom native wheel. Original archives and installed-file hashes are retained.

- Preserve newly created, unactivated failed installations outside the runtime-generation inventory, without deleting files or adopting unknown runtimes.

- Release connection admission after failed or cancelled handshakes, with bounded socket cleanup and protection against double release of unrelated allocations.

- Update the pinned Python-only libp2p dependency to release temporary connection allocations on cancelled dials and pre-multiplexed connections, and reuse admitted allocations during connection registration. Resource limits remain enforced.

- Refuse macOS runtime replacement when boot-service inspection fails; unknown supervision state is not treated as an absent service.

- Pin a Python-only libp2p security backport that rejects oversized Yamux DATA frames and bounds body reads. The installer verifies its fixed checksum and refuses missing or altered dependency artifacts instead of falling back to the affected upstream version.

- Accept SQLite peers for an explicitly named service/account with `peer accept --service SERVICE --account ACCOUNT`, without requiring an internal service-group identifier lookup. Existing ID-based and explicit wildcard options retain their behavior.

- Detect per-account macOS system daemon jobs and reject unsafe definitions or unprivileged lifecycle changes.
- Refuse installer runtime replacement before filesystem changes when a per-account boot daemon is installed or loaded; administrator-assisted supervision changes are required.

- Use zeroconf's supported pure-Python build path for non-editable Intel macOS installation, isolating optional Git/compiler probes from host developer tools while retaining normal post-install verification.

- Retire a timed-out RSS connection within a bounded cleanup interval so the next authentication refresh can redial. Invalidate only that relay's in-memory control stream and reservation; preserve healthy alternatives and all stored synchronization state. Installed outage qualification remains pending.

- Allow bounded RSS authentication-stream cleanup to finish when an outer operation is cancelled. This preserves the existing timeout while preventing cancellation from immediately interrupting cleanup; installed recovery qualification remains pending.

- Use an exclusively created temporary file for installer write-access verification, preserving pre-existing probe files and symlink targets instead of overwriting them.

- Reload an existing managed macOS daemon after RSS enrollment, configuration or identity import so it uses the new RSS profile immediately. Ordinary repeated service installation still preserves the healthy running job. Installed qualification of this correction is pending.

- Read the cached RSS circuit acceptance response without waiting for the circuit to close. Bound the control exchange and reset failed requests; preserve the open circuit for the authenticated encrypted peer connection.

- Resolve relay authentication outcomes before selecting fallback routes, so a fast secondary is not repeatedly discarded while a failed primary times out. Preserve preferred-primary recovery without changing authorization or replay rules. Installed outage qualification remains required.
- On a selected circuit change, retire the prior cached peer connection and replace its dial addresses so the transport actually dials the new relay. Keep repeated bindings to the same circuit intact.

- Queue missing retained endpoint prerequisites for an already authorized pending endpoint update, without changing transaction contents or replay validation. Missing history remains a failed delivery rather than being fabricated. Installed recovery qualification is pending.
- Send reconstructed endpoint prerequisites with a fresh recipient lifecycle, rather than the sender's applied state and timestamps. Receiver submission and duplicate-delivery regression checks cover this correction; canonical stored transactions remain unchanged.

- Keep transport reachability separate from remote runtime rejection: a rejected envelope remains undelivered without invalidating the responding peer's route. Network failures still invalidate routes.

- Retain the daemon transport identity across managed foreground restarts using the same runtime directory as CLI-started daemons. Preserve a verified RSS circuit when inbound discovery supplies only a direct peerstore observation. Installed restart and failover qualification remains required.

- Fix encrypted SQLite deletion synchronization by rewrapping tombstone names for the receiving peer's local storage key. Keep replay consistency and encrypted-envelope requirements. All peers require the corrected client for this path; previously queued envelopes and mixed-version rollout require separate qualification.

- Add explicit protected standard-state archival before uninstall, with a checksum manifest and refusal on backup failure. Custom datastores and Keychain require separate backups; selective purge is available through explicit named selections.

- Retain removal receipts for safe retry after interrupted verified runtime uninstall. Added or changed files still cause refusal; persistent state remains preserved.

- Protect export file creation against overwrites and symlinks; honor shell export file output and add optional external-age encrypted shell export. Installed portable-export qualification remains pending.

- Reap detached daemon children and stop failed startup children within bounded waits. Allow language selection during uninstall without allowing runtime namespace overrides.

- Added bundled French, Spanish and German CLI catalogs, deterministic language selection and localized help headings. Full message coverage and installed-language qualification remain in progress; see the localization guide.

These are prerelease changes, not a public stable-release announcement.

- Removed `doctor --acceptance-test` and synthetic fixture code from the customer package and installer; `doctor --install-check` remains available.
- Removed the development-only `seckit lab` command from the customer package; its harness and synchronization tests are maintained privately.
- Added encrypted SQLite secret storage and peer synchronization.
- Added client-side Remote Secrets Sync checkout, enrollment and connection configuration.
- Added a read-only stdio MCP server with an owner-only policy and explicit retrieval permissions.
- Added managed same-user daemon services for macOS and Linux, with bounded startup and upgrade recovery.
- Kept MCP fail-closed when the daemon is unavailable.
- Added receipt-verified uninstall with dry-run and explicit confirmation. Persistent secrets, identities, configuration and shared Python/UV installations are preserved.
- Fixed macOS headless service installation and scheduling for responsive status requests.
- Preserved CLI default precedence, explicit zero-valued rotation settings and tag aliases while simplifying assignment logic.
- Preserved metadata overlay rules for blank fields, explicit values and collection copies while consolidating repetitive assignments.

Ordinary uninstall preserves customer state. Export, archive and selected purge are explicit operations; unknown/custom state is preserved rather than silently deleted.

- Prevent inbound peer discovery from replacing usable RSS circuit routes with unspecified listener addresses. Datastore and replay behavior are unchanged by this routing fix; installed recovery qualification remains pending.

## Earlier development

Earlier work introduced Keychain storage, scoped secret operations, environment-file import/export, encrypted export and child-process environment injection through `seckit run`. Detailed engineering and qualification history is maintained privately rather than published as customer release notes.
