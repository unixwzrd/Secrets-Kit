# ADR: IPC and local transport semantics (pre-daemon)

**Created**: 2026-05-08  
**Updated**: 2026-05-11  

Normative semantics for **local IPC**, future **same-user `seckitd`** transport, and **optional future `relayd`** — **without** fixing a wire format or shipping a listener. **Materialization** terms come from [RUNTIME_AUTHORITY_ADR.md](RUNTIME_AUTHORITY_ADR.md). **Session** and ownership come from [RUNTIME_SESSION_ADR.md](RUNTIME_SESSION_ADR.md).

Plan-phase sketch for managed **sync host** (operator wording) is in [plans/SYNC_HOST_PROTOCOL.md](plans/SYNC_HOST_PROTOCOL.md); it does not override this ADR.

## Purpose / scope guard

The purpose of this ADR (with [RUNTIME_SESSION_ADR.md](RUNTIME_SESSION_ADR.md)) is to **constrain future implementation complexity** and preserve **local-first, Unix-oriented** behavior. Implementations should **emerge from** these semantics rather than **redefine** them retroactively.

**This phase does not** define HTTP/gRPC, remote authentication, relay code, sockets in `seckit`, **async** IPC frameworks, **policy engines**, **distributed consensus**, or **message-broker / durable-queue** products.

## Related documents

- [RUNTIME_AUTHORITY_ADR.md](RUNTIME_AUTHORITY_ADR.md)  
- [RUNTIME_SESSION_ADR.md](RUNTIME_SESSION_ADR.md)  
- [SECURITY_MODEL.md](SECURITY_MODEL.md)  

## Opaque relay vs local plaintext IPC (no contradiction)

- **`relayd` (future, optional)** transports **opaque encrypted payloads only**. It **never** decrypts. It is a dumb **encrypted routing / switching** layer — **not** a trust authority, **not** authoritative state, **not** an inventory or **database-of-truth**.
- **Same-user local `seckitd` IPC (future)** **may** carry **transient plaintext** for **authorized local consumers**. That is still a **materialization crossing** governed by [RUNTIME_AUTHORITY_ADR.md](RUNTIME_AUTHORITY_ADR.md) (including **implicit materialization guard** on errors and logs).
- **`seckitd`** remains **transport / plumbing**: **not** authoritative vs **`BackendStore`**; **minimal business logic**; **not** merge/import authority (**`seckit`** owns that).

## Same-host authority

See [RUNTIME_SESSION_ADR.md](RUNTIME_SESSION_ADR.md): resolution stays **same-host and same-user by default**; remote relay moves **ciphertext** (or other encrypted artifacts), not **ownership** of local secret state.

## Plumbing matrix (IPC view)

| Role | IPC / payload role |
|------|---------------------|
| **`relayd`** | **Opaque ciphertext only** on the relay hop; **minimal, preferably ephemeral** registration metadata; **no** decrypt; **not** inventory. |
| **`seckitd`** | **Transport mediator** for **same-user local** IPC; **may** pass **authorized transient plaintext** or **opaque** units per policy to be defined at implementation time; **not** session authority over `BackendStore`. |
| **`seckit`** | Import / merge / CLI; initiates operations. |
| **`BackendStore`** | Persists and resolves **local** authority. |

## Trust boundary

- **Local IPC** that delivers **secret plaintext** to a peer process is a **materialization crossing** to an **IPC consumer**.
- Errors, logs, and diagnostics on the wire or in either process **must not** **implicitly** embed secret plaintext (see authority ADR).
- Default contract: **client and server (or peers)** run under the **same OS user** for this IPC profile. **root/sudo** or cross-user use is **out of contract** unless explicitly specified in a future ADR.

## Unix / minimalist streams philosophy

- Prefer thinking in terms of **byte streams** — **stdin/stdout / subprocess** patterns where applicable — and **Unix domain sockets** for local IPC when a socket is used.
- **Transport-neutral** framing: length-prefix vs delimiters **TBD**; avoid assuming a **heavyweight RPC** stack, **service mesh**, **cluster control plane**, **distributed coordinator**, or **multi-tenant broker**.

## Fetch vs inject vs export

Definitions stay in [RUNTIME_AUTHORITY_ADR.md](RUNTIME_AUTHORITY_ADR.md).

- **Fetch (IPC):** return **plaintext** to an **authorized local consumer** — a **materialization** to **that consumer**; **does not** confer **`BackendStore`** ownership.
- **Inject:** **injection** into another execution context (e.g. child env); **same canonical sentence** as authority ADR.
- **Export:** produces an **externalized artifact** (file, bundle, etc.).

## `seckitd` and `relayd` roles (normative)

- **`seckitd`:** **user-scoped** **runtime router** / **transport mediator** — **not** an **authority server**, **not** **brokered ownership**, **not** centralized session authority over others’ secrets.
- **`relayd`:** **opaque** forwarder — **never** decrypt; optional metadata is **minimal** and **ephemeral registration-style** where possible; relay **must not** become **inventory** or **source of truth**.

**Routing language:** prefer **forwarding / switching**. Do **not** imply **durable queues**, **message brokers**, or **store-and-forward durability** as **product scope** unless a **later** ADR explicitly adds them.

## Streaming

Unary vs chunked delivery **may** be chosen later; **no wire commitment** in this ADR.

## Minimal abstraction (code)

Documentary types in `src/secrets_kit/runtime_ipc.py` sketch **operation** and **error** labels and **metadata-only** envelopes — **not** a stable on-wire codec.

## Failure and redaction

- Failures **deterministic** and **safe to log**: **no secret** payload in error text.
- **Error codes** may be documented as enums for stable **meaning**; **not** full IPC contract until implementation.

---

## Appendix: Future relay (optional, out of scope today)

When specified later:

- **Direct peer communication** is preferred **whenever reachable**.
- **Relay** supports **NAT traversal**, **asynchronous delivery**, and **disconnected timing** — **not** the default over a reachable direct path.
- Relay carries **opaque encrypted blobs only**; **never** decrypts.
- Relay metadata: **intentionally minimal**, **ephemeral registration** bias; relay **must not** evolve into **inventory** or **database-of-truth** for secrets.
- Relay is **optional** participation and **not** a **trust authority**.

### Operator vocabulary: sync host

In operator-facing documentation, **sync host** means a managed **`relayd`-class** process: **best-effort opaque forwarding transport** only. **Peers** remain authoritative for registry state, merge resolution, secret ownership, identity truth, sync history, and delivery guarantees—the sync host **never** is.

## Non-goals (explicit)

No production **`seckitd`** or **`relay`** in this repo phase; no **networking** stack here; no **remote APIs**; no **distributed consensus**; no **mini distributed systems platform**; no implied **durable message broker** unless added by a **separate** ADR.
