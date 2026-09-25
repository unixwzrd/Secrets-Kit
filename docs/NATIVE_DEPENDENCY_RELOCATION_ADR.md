# ADR: Deterministic Native-Dependency Override for Beta

**Created**: 2026-07-30  
**Updated**: 2026-09-15

## Status

Accepted for beta. The July 31 official-wheel override supersedes the July 30 local binary-relocation approach. This master was reconciled with the implemented decision on September 7; reconciliation does not change runtime behavior or certify a release.

## Context

`libp2p==0.7.0` pins `fastecdsa==2.3.2`. That release lacks several required wheels, and its macOS ARM64 wheel embeds a build-host Homebrew GMP path. Compatibility testing established that official `fastecdsa==3.0.1` works with the exercised libp2p import, key, Noise, stream and shutdown paths. Its official wheels carry usable native linkage on the declared customer platforms. Linux ARM64 has no 3.0.1 wheel.

The earlier gmpy2-based local relocation proof of concept did not require custom wheels, but is historical and no longer the installation strategy. Do not restore it merely to work around an unsupported platform.

## Decision

### Approved Intel cryptography exception — implemented, qualification in progress

The maintainer approved metadata-directed install-prefix relocation for prebuilt Intel macOS cryptography 50.0.1/OpenSSL dependencies inside an isolated UV runtime. This is a narrow exception to the no-native-rewrite rule below, not permission to restore the historical GMP approach, compile native dependencies, install Conda, or create custom native wheels. Preserve and verify original publisher package hashes; apply only declared package prefix metadata to the new runtime copy, and retain installation provenance. Unexpected metadata, unsupported versions/layouts, unsafe paths or an overlong prefix must fail before activation. Verify relocated configuration/provider paths, loading and cryptographic behavior, then installed client transport and lifecycle. Approval is not implementation or qualification evidence.

The Intel installer now prepares a new UV runtime with wheel-only archive-decoding dependencies, installs the client helper without resolving native dependencies, and downloads the two pinned publisher archives. The helper authenticates the complete archives and selected file metadata, installs cryptography and the required OpenSSL libraries/configuration, and relocates only the declared libcrypto prefix. It supplies a certificate bundle from certifi and retains original archives plus installed-file hashes under `native-provenance/`. Existing destination files are never overwritten. Normal dependency resolution and the existing pre-activation transport/install checks remain required. No Conda executable, compiler or custom native wheel is used. A failed candidate remains unactivated; validation of a disposable runtime does not by itself certify the complete RSS customer workflow.

Upstream [Conda relocation documentation](https://docs.conda.io/projects/conda-build/en/latest/resources/make-relocatable.html) defines prefix replacement as an installation step. The customer runtime remains UV-managed Python; a separate Conda environment is not introduced.

### Existing fastecdsa override

The installer supplies one exact uv override for `fastecdsa==3.0.1`. Customer installation requires a binary wheel and fails closed if one is unavailable. Before activation, validation checks approved versions, expected native-extension layout, resolved non-host-specific GMP linkage, native imports and Noise-only libp2p startup/shutdown. It does not rewrite, sign or redistribute native objects.

Linux ARM is internal qualification coverage, not a compiler-free customer support claim. The existing maintainer-only source-build switch is not a customer workaround or permission to compile; using it requires explicit authorization. No transport, datastore, replay or identity behavior changes under this decision.

## Release and Qualification Rules

- Approved dependency versions and the uv override are pinned.
- Every upgrade creates and validates a new runtime generation before the `current` link changes.
- Customer qualification must prove no native source build occurred and must verify installed linkage and libp2p operation. An existing installed native library does not prove an official wheel is available for a fresh install.
- A private native dependency fork, locally built native wheel or redistributed repaired native wheel remains prohibited. This boundary does not describe separately reviewed Python-only upstream security patches.
- An upstream py-libp2p release accepting the qualified dependency can remove the temporary override after validation.

## Consequences

The product wheel remains universal while native dependencies come from official platform wheels. No compiler, Homebrew or system GMP installation is required on the declared customer platforms. Linux ARM customer support remains deferred until an official compatible wheel exists. Dependency compatibility does not constitute security-advisory clearance; that remains a separate release gate.

## Related Documents

- [PROTOCOL_TRANSPORT_ARCHITECTURE.md](PROTOCOL_TRANSPORT_ARCHITECTURE.md)
- [SECURITY_MODEL.md](SECURITY_MODEL.md)
- [INSTALL.md](INSTALL.md)
- [QUALIFICATION_ARCHITECTURE.md](QUALIFICATION_ARCHITECTURE.md)
