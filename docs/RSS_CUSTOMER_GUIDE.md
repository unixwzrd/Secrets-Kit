# Remote Secrets Sync beta customer guide

<!-- Derived from separation-governance/Secrets-Kit-Docs/RSS_CUSTOMER_GUIDE.md. -->

**Created**: 2026-08-03
**Updated**: 2026-09-29

Remote Secrets Sync (RSS) lets two authorized Secrets Kit peers exchange encrypted synchronization envelopes when direct communication is unavailable.
RSS never receives secret plaintext, customer private keys, or datastore contents.

## Subscribe and enroll the first peer

Start Checkout from the installed product. The interactive command suggests at least two units, or the number of known authorized peers plus this machine, whichever is greater. You can enter another valid quantity or pass `--connection-units N` explicitly:

```bash
seckit rss checkout
```

Open the returned `checkout_url` and complete Stripe Checkout. Secrets Kit stores the opaque Checkout recovery identifiers in a protected local receipt; customers do not construct or copy account IDs, Checkout IDs, entitlement IDs, RET values, enrollment URLs, relay identities, or relay multiaddresses.

After the payment-success page appears, run:

```bash
seckit rss enroll
seckit rss owner claim
```

The enrollment command retrieves the provisioning bundle only after verified payment, stores the short-lived **RSS Enrollment Token** (RET) as a protected file, generates the long-lived Ed25519 customer identity locally, configures the ordered primary/secondary RSS endpoint set, and installs the same-user managed daemon service. The RET never appears in command-line arguments or normal output. The daemon redeems it through the TLS 1.3 operator endpoint and removes it after successful enrollment.

If enrollment is interrupted after provisioning, rerun `seckit rss enroll`.
Secrets Kit reuses the protected retained state instead of requesting or overwriting another RET.

The owner claim requires the protected original Checkout receipt and proof from the enrolled device. Save the displayed account ID and one-time recovery codes offline before acknowledging them. The owner key stays with this Unix user and is separate from peer and RSS device keys. Existing beta customers with the original receipt can claim after upgrading; if the receipt and recovery codes are both gone, contact support for a one-time, identity-verified legacy recovery. Ordinary peer authorization cannot manage billing or devices.

Verify supervision with:

```bash
seckit daemon service status
```

On Linux, the status reports whether user lingering is enabled. If it is disabled and the daemon must run while the user is logged out, an administrator may run `loginctl enable-linger USER`.

## Add another device

On the enrolled billing owner's machine, use the normal SSH install command:

```bash
seckit install user@host
```

This installs and authorizes the peer, then sends one short-lived enrollment token over SSH so the target creates its own RSS private key and connection ID. No identity export or private key transfer is needed. `seckit install @host` uses the current username.

If paid capacity is full, the command shows the purchased and provisioned counts and a Stripe-hosted billing-portal link. Increase the quantity on the existing subscription, complete payment, and rerun the same install command. Capacity is granted only after Ops verifies and applies the paid quantity; a browser return alone does not grant a slot.

To open the portal at any time, or inspect and permanently revoke a selected device:

```bash
seckit rss billing portal
seckit rss devices list
seckit rss devices revoke CONNECTION_ID
```

Revocation frees a device slot but does not lower the subscription quantity. The result remains `pending_enforcement` until both relays acknowledge the signed revocation. A replacement machine receives a new connection ID; the old credential cannot be restored. Lower the quantity separately in the portal if desired.

## Deterministic fallback and errors

Endpoints are tried in the provisioned order. At least one must authenticate; an unavailable later endpoint does not prevent a healthy earlier endpoint from starting. Session authentication and encrypted traffic use libp2p Noise.
Secondary access becomes available only after the operator's signed authorization projection reaches that node.

Secrets Kit fails closed for broadly readable or foreign-owned credential files, links, unknown receipt or transfer versions, invalid TLS, invalid RETs, inactive entitlements, incomplete provisioning bundles, and unrecognized RSS identities. Secret values and private authentication material must not be included in support reports.

## Revocation and recovery

Payment failure, cancellation, or revocation suspends new access and terminates active forwarding. Preserve the local customer identity during an ordinary reinstall. If the billing-owner machine is lost, install on a replacement and run `seckit rss owner recover --account-id ACCOUNT_ID`; supply one saved recovery code when prompted. This rotates the owner key and issues a new offline code set. It does not revive a revoked RSS device or bypass paid capacity.

The lower-level `seckit rss configure` and identity-transfer commands remain for explicit recovery/compatibility only. They are not the normal beta customer workflow.
