# Protocol and Transport Architecture

Status: partially implemented.

This document defines the shared peer-safe protocol substrate. Hosted relay behavior is documented separately in the private relay repository.

## Layering

```text
socket transport
  -> optional TLS wrapper
  -> length-prefixed JSON frame
  -> routing envelope
  -> signed message envelope
  -> optional encrypted payload
  -> application payload
```

Sockets are pipes. The socket layer does not know about storage backends, routing policy, or plaintext payloads.

## Transports

Implemented:

- Unix domain socket helpers for same-host local IPC
- plain TCP helper skeleton
- stdlib TLS wrapper hook
- length-prefixed JSON frame codec

Not implemented:

- websockets
- HTTP transport
- gRPC
- service mesh abstractions
- fixed singleton local ports

## Framing

Frame format:

```text
uint32_be length
utf-8 JSON object bytes
```

The JSON object can be inspected with small shell/Python tools:

```bash
python - <<'PY'
import json, struct, sys
raw = sys.stdin.buffer.read()
n = struct.unpack(">I", raw[:4])[0]
print(json.dumps(json.loads(raw[4:4+n]), indent=2, sort_keys=True))
PY
```

The frame parser rejects oversized frames, short reads, invalid UTF-8, invalid JSON, and non-object top-level JSON.

Signature verification does not depend on frame bytes or parser-specific JSON key ordering.

## Envelope

The shared envelope includes protocol version, message id, correlation id, sender and recipient identity layers, timestamp and TTL/expiry fields, route metadata, payload codec/encryption metadata, signature metadata, and replay metadata.

Protocol handlers reject unsupported major protocol versions with diagnostic errors.

## Signing

Envelope signing uses Ed25519 through the existing Secrets Kit host identity.

Signed fields are serialized through deterministic canonical JSON before signing or verifying. The signature binds symbolic identities and envelope fields, not `host:port`.

Signing defaults on. Unsigned mode is only for controlled tests or explicit debug policy.

## Payload Security

Payload encryption is a protocol hook. The routing layer does not need payload plaintext and does not depend on Keychain, SQLite, or any other storage backend.

Policy states:

- `debug`: plaintext payloads may be allowed; signing still defaults on
- `local`: Unix socket peer credentials plus optional signing
- `production-relay`: TLS and/or payload encryption required by relay policy

## Identity

Identity layers:

- node identity: existing `HostIdentity`
- runtime instance identity: selected runtime namespace
- agent identity: local process/daemon identity within the instance
- session identity: per-connection runtime or relay session id

Transport endpoints are discovered dynamically and are never stable identity.

