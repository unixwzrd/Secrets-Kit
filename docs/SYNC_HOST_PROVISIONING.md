# Sync host — provisioning (manual first pass)

**Created**: 2026-05-11  
**Updated**: 2026-05-11

Operator-facing steps for introducing a **sync host** (managed **best-effort opaque forwarding transport**). Internal implementation may be referred to as **`relayd`** in code and ADRs—see [SYNC_HOST_PROTOCOL.md](plans/SYNC_HOST_PROTOCOL.md) for the naming map and authority rules.

**Phase 5C** documents process only: **no** Stripe integration, **no** automated onboarding service, **no** wire format for onboarding artifacts.

---

## Operational philosophy (summary)

- **Local-first** and **peer-authoritative** (sync host does not own registry, merge, or secret truth).  
- **Minimal metadata**; **operator-observable** metrics without payloads ([SYNC_HOST_METRICS.md](plans/SYNC_HOST_METRICS.md)).  
- **Simple** enough for a **single operator**; **self-hostable**; **graceful degradation** when the host is down (peers retry locally).  
- **Infrastructure-assisted, not infrastructure-dependent.**

Full detail: [SYNC_HOST_PROTOCOL.md](plans/SYNC_HOST_PROTOCOL.md) § F.

---

## Manual provisioning (now)

1. **Operator provisions** a sync host (VM, container, or binary—deployment detail out of scope here).  
2. **Operator generates** a **static** keypair for the sync host identity; **publish only the public key** to subscribers (pinned trust).  
3. **User receives** sync host **endpoint** and **pinned public key** after **payment or manual approval** (your commercial process—**not** automated in Phase 5C).  
4. **Client configuration:** peers reference the sync host endpoint and pinned key. Exact `defaults.json` / config keys are **TBD** — follow patterns in [DEFAULTS.md](DEFAULTS.md) when implementation lands.

---

## Conceptual onboarding bundle

What you hand to a customer (conceptual checklist; **no** file format in Phase 5C):

- Sync host **endpoint**  
- **Pinned public key** (`relayd` / sync-host identity)  
- **`account_id` / `customer_id` / `subscription_id`** as your product uses (avoid broad **“tenant”** language unless you implement real isolation)  
- Optional opaque **bootstrap token** (future)  
- Optional **expiration** for token or assignment window  

See [SYNC_HOST_PROTOCOL.md](plans/SYNC_HOST_PROTOCOL.md) § G.

---

## Future automation (not implemented)

Documentary stub only:

- Payment event (e.g. Stripe webhook)  
- Provision or assign sync host capacity  
- Issue or rotate **relay** credential / onboarding bundle  
- Email or secure download for customer  
- **`install` / CLI** consumes short-lived onboarding token  

---

## Related

- [SYNC_HOST_PROTOCOL.md](plans/SYNC_HOST_PROTOCOL.md)  
- [SECKITD_PHASE5.md](plans/SECKITD_PHASE5.md)  
- [PEER_SYNC.md](PEER_SYNC.md)  
- [OPERATOR_LIFECYCLE.md](OPERATOR_LIFECYCLE.md)  
