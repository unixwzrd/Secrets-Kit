> Source of truth: Secrets Kit documentation master. This public copy is a reviewed derivative.

# ADR: Deterministic Native-Dependency Override for Beta

**Created**: 2026-07-30  
**Updated**: 2026-11-15

## Status

Accepted for beta. The official-wheel override supersedes the earlier local GMP relocation approach. This document describes installer behavior and platform limits; release qualification is recorded separately.

## Context

`libp2p==0.7.0` pins `fastecdsa==2.3.2`. That release lacks several required wheels, and its macOS ARM64 wheel embeds a build-host Homebrew GMP path. Compatibility testing established that `fastecdsa==3.0.1` works with the exercised libp2p import, key, Noise, stream and shutdown paths. Official platform wheels are used where available. For glibc Linux ARM64, the managed release bundle pins one repaired `manylinux2014_aarch64` wheel built from the unmodified upstream source distribution. Upstream does not publish this binary wheel; its hash is pinned in the installer manifest.

The earlier gmpy2-based local relocation proof of concept did not require custom wheels, but is historical and no longer the installation strategy. Do not restore it merely to work around an unsupported platform.

## Decision

### Intel macOS cryptography relocation

The installer applies metadata-directed install-prefix relocation for prebuilt Intel macOS cryptography 50.0.1/OpenSSL dependencies inside an isolated UV runtime. It does not restore the historical GMP approach, compile native dependencies, install Conda, or create custom native wheels. It verifies original publisher package hashes, applies only declared package prefix metadata to the new runtime copy, and retains installation provenance. Unexpected metadata, unsupported versions/layouts, unsafe paths or an overlong prefix fail before activation. Relocated configuration/provider paths, loading, cryptographic behavior, and installed client transport must pass validation.

The Intel installer now prepares a new UV runtime with wheel-only archive-decoding dependencies, installs the client helper without resolving native dependencies, and downloads the two pinned publisher archives. The helper authenticates the complete archives and selected file metadata, installs cryptography and the required OpenSSL libraries/configuration, and relocates only the declared libcrypto prefix. It supplies a certificate bundle from certifi and retains original archives plus installed-file hashes under `native-provenance/`. Existing destination files are never overwritten. Normal dependency resolution and the existing pre-activation transport/install checks remain required. No Conda executable, compiler or custom native wheel is used. A failed candidate remains unactivated; validation of a disposable runtime does not by itself certify the complete RSS customer workflow.

Upstream [Conda relocation documentation](https://docs.conda.io/projects/conda-build/en/latest/resources/make-relocatable.html) defines prefix replacement as an installation step. The customer runtime remains UV-managed Python; a separate Conda environment is not introduced.

### Existing fastecdsa override

The installer supplies one exact uv override for `fastecdsa==3.0.1`. Customer installation requires a binary wheel and fails closed if one is unavailable. Before activation, validation checks approved versions, expected native-extension layout, resolved non-host-specific GMP linkage, native imports and Noise-only libp2p startup/shutdown. It does not rewrite, sign or redistribute native objects.

Linux ARM64 customer installation uses the pinned repaired `manylinux2014_aarch64` wheel built from the unmodified upstream source distribution. Debian ARM64 and Rocky ARM64 preserving-upgrade receipts using the installed 2.0.2b1 candidate record installed-file verification, a healthy managed daemon, two authenticated RSS endpoints, and four-peer synchronization. The final 2.0.2 release carried the same checksum-pinned dependency. A fresh installation from the final public tag was not separately recorded, and minimum kernel or glibc versions were not independently qualified. Wheel presence alone is not qualification evidence. The customer installer requires the pinned wheel and fails closed if unavailable; the source-build switch remains restricted to development. No transport, datastore, replay, or identity behavior changes under this dependency decision.

## Release and Qualification Rules

- Approved dependency versions and the uv override are pinned.
- Every upgrade creates and validates a new runtime generation before the `current` link changes.
- Customer qualification must prove no native source build occurred and must verify installed linkage and libp2p operation. An existing installed native library does not prove a wheel is available for a fresh install. Linux ARM64 evidence is limited to the recorded preserving-upgrade receipts and the pinned repaired wheel; do not claim a fresh final-tag install or unrecorded OS-version coverage.
- The pinned `fastecdsa` Linux ARM64 wheel described above is the approved repaired-wheel exception. Other private native dependency forks, locally built native wheels, or redistributed repaired native wheels remain prohibited. This boundary does not describe separately reviewed Python-only upstream security patches.
- An upstream py-libp2p release accepting the qualified dependency can remove the temporary override after validation.

## Consequences

The product wheel remains universal while native dependencies come from the verified platform bundle. No compiler, Homebrew or system GMP installation is required on the declared customer platforms. Linux ARM64 uses the separately built and hash-pinned manylinux wheel. Dependency compatibility does not constitute security-advisory clearance; that remains a separate release gate.

## Related Documents

- [SECURITY_MODEL.md](SECURITY_MODEL.md)
- [INSTALL.md](INSTALL.md)
