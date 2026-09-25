# Remote Secrets Sync beta customer guide

<!-- Derived from separation-governance/Secrets-Kit-Docs/RSS_CUSTOMER_GUIDE.md. -->

**Created**: 2026-08-03
**Updated**: 2026-08-18

Remote Secrets Sync (RSS) lets two authorized Secrets Kit peers exchange encrypted synchronization envelopes when direct communication is unavailable.
RSS never receives secret plaintext, customer private keys, or datastore contents.

## Subscribe and enroll the first peer

Start Checkout from the installed product:

```bash
seckit rss checkout
```

Open the returned `checkout_url` and complete Stripe Checkout. Secrets Kit stores the opaque Checkout recovery identifiers in a protected local receipt; customers do not construct or copy account IDs, Checkout IDs, entitlement IDs, RET values, enrollment URLs, relay identities, or relay multiaddresses.

After the payment-success page appears, run:

```bash
seckit rss enroll
```

The enrollment command retrieves the provisioning bundle only after verified payment, stores the short-lived **RSS Enrollment Token** (RET) as a protected file, generates the long-lived Ed25519 customer identity locally, configures the ordered primary/secondary RSS endpoint set, and installs the same-user managed daemon service. The RET never appears in command-line arguments or normal output. The daemon redeems it through the TLS 1.3 operator endpoint and removes it after successful enrollment.

If enrollment is interrupted after provisioning, rerun `seckit rss enroll`.
Secrets Kit reuses the protected retained state instead of requesting or overwriting another RET.

Verify supervision with:

```bash
seckit daemon service status
```

On Linux, the status reports whether user lingering is enabled. If it is disabled and the daemon must run while the user is logged out, an administrator may run `loginctl enable-linger USER`.

## Add the second clean peer

On the enrolled first peer:

```bash
seckit rss identity export --output /protected/path/rss-identity-transfer.json
```

Transfer that `0600` file through a trusted protected channel. On peer two:

```bash
chmod 600 /protected/path/rss-identity-transfer.json
seckit rss identity import --input /protected/path/rss-identity-transfer.json
```

The versioned transfer contains the customer authentication identity plus the non-secret entitlement and ordered endpoint configuration. Import creates a new opaque connection ID and installs the same-user managed daemon service for peer two. Delete the transfer copy after a successful import.

## Deterministic fallback and errors

Endpoints are tried in the provisioned order. At least one must authenticate; an unavailable later endpoint does not prevent a healthy earlier endpoint from starting. Session authentication and encrypted traffic use libp2p Noise.
Secondary access becomes available only after the operator's signed authorization projection reaches that node.

Secrets Kit fails closed for broadly readable or foreign-owned credential files, links, unknown receipt or transfer versions, invalid TLS, invalid RETs, inactive entitlements, incomplete provisioning bundles, and unrecognized RSS identities. Secret values and private authentication material must not be included in support reports.

## Revocation and recovery

Payment failure, cancellation, or operator revocation suspends new access and terminates active forwarding. Preserve the local customer identity during an ordinary reinstall or recovery. A replacement identity requires a newly authorized enrollment workflow.

The lower-level `seckit rss configure` command is retained for documented operator-assisted recovery. It is not the normal beta customer workflow.
