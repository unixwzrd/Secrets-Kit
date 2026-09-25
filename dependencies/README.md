# Pinned Python dependencies

`libp2p-0.7.0+seckit.4-py3-none-any.whl` is a Python-only security, connection-cleanup and Noise connection-metadata backport of upstream libp2p 0.7.0. It requires no compiler. MIT and Apache-2.0 license texts are included in the wheel.

- Base: upstream tag `v0.7.0`, commit `7acf896e497b6c944390a54c28130c83333f12ed`.
- Patch: upstream commit `146ea87d1a20cc7dacf684ecf7c204543be04b37`, rejecting oversized Yamux DATA frames and bounding body reads.
- Patch SHA256: `1725190803506b5549173ed5e1792906ba5bfb041f7c689ac7ec424094369287`.
- Additional local patch: `connection-scope-cleanup.patch`, releasing temporary dial admissions, reusing the admitted scope during connection registration, and cleaning up failed or cancelled security handshakes without double-releasing admissions. Resource limits remain enforced.
- Additional local patch: `noise-connection-metadata.patch`, SHA256 `fde0d3ca3cbdeb04224b0b67c7f1574dc71a60154884fc0ac12e41de8072768a`, applied after the Yamux security patch and `connection-scope-cleanup.patch`. It stores the raw connection in the Noise read/writer constructor so connection type and transport addresses remain exact from `RawConnection` through `NoiseTransportReadWriter`, `SecureSession` and `Mplex`. The patch includes that constructor coverage. It does not repair Mplex.
- Wheel SHA256: `9dc4ef54521e9aa6d8c423b7ae75f026765a1f509b6fa87afd60e7fbaffb9906`.

The upstream Yamux patch applies unchanged. From the source root, apply `patch -p1 < connection-scope-cleanup.patch` and then `patch -p1 < noise-connection-metadata.patch`, then set the project version to `0.7.0+seckit.4`. A reproducible build requires a clean source tree with identical Git metadata, because setuptools includes tracked documentation in the wheel. Build once per such copy with `SOURCE_DATE_EPOCH=1783616475 python -m build --wheel --no-isolation`; exclude previous `build`, `dist`, egg metadata and cache directories. The Python implementation files differing from the official upstream wheel are `libp2p/stream_muxer/yamux/yamux.py`, `libp2p/network/swarm.py` and `libp2p/security/noise/io.py`. The only runtime module differing from `+seckit.3` is `libp2p/security/noise/io.py`. Earlier backport artifacts are not included in this beta source snapshot or selected by the release script.

Use the supported Secrets Kit installer. For contributor environments, supply `--find-links dependencies` to pip when installing this checkout. A release bundle must retain this wheel alongside the Secrets Kit wheel. Do not replace the backport with index libp2p 0.7.0 or disable integrity checks.

## Linux ARM64 native dependency

`fastecdsa-3.0.1-cp312-cp312-manylinux2014_aarch64.manylinux_2_17_aarch64.whl` is the ARM64 binary selected by the installer on Linux aarch64. Upstream `fastecdsa` 3.0.1 does not publish a Linux ARM64 wheel, while the customer installer deliberately prohibits local source builds. This wheel was built from the unmodified PyPI `fastecdsa-3.0.1.tar.gz` (SHA256 `f4b4a50fd5e346c4949aba365c061c3f6b25eee7983c973e1d31de7672ba48ea`) on Rocky Linux 9 ARM64 with CPython 3.12.13, GCC 11.5 and GMP 6.2, then repaired with auditwheel 6.5.0 and patchelf 0.17.2.4 to bundle `libgmp.so.10` and receive the manylinux2014 aarch64 tag. The repaired wheel SHA256 is `64ea6e495634757d2525b38ab5d071cb7af7bb93053828eba120b8b0866e5c1c`; the checksum manifest is the installer's authority. An isolated install successfully imported both native extensions and signed/verified a P-256 message. This build evidence does not replace release-artifact or clean-install qualification.

To reproduce the build on a compatible isolated ARM64 builder with the stated compiler/GMP headers: verify the upstream source checksum, run `uv build --wheel --python 3.12 --out-dir raw fastecdsa-3.0.1.tar.gz`, then `auditwheel repair --plat manylinux2014_aarch64 --wheel-dir repaired raw/fastecdsa-3.0.1-cp312-cp312-linux_aarch64.whl`. Do not compile it on a customer's machine or silently fall back to a source build.

## LAN discovery dependency

`zeroconf-0.150.5+seckit.1-py3-none-any.whl` contains a narrowly scoped repair for simultaneous users advertising on one explicit IPv4 LAN interface. It reuses the shared wildcard listener for responses, joins the selected interface and sets the outgoing multicast interface. Missing-listener and failed-membership behavior remain explicit; setup exceptions close the socket. Other socket-selection paths are unchanged. This does not change the mDNS protocol or peer authorization.

- Base: published PyPI `zeroconf-0.150.5.tar.gz`, SHA256 `65abac1c7c1bead9f1cea7d810f1b8669332c1305bd253ae41bedc02815135a8`.
- Wheel SHA256: `e9d024626ba299433121426c524814ff93a99a2ec28f10f663c76ec7ca7dd32a`.
- Corresponding modified source: `zeroconf-0.150.5+seckit.1.tar.gz`, SHA256 `0e164be15b43899a07e55a45dcd2f953a90d31efa3abffeefb4195c40622ae10`.
- License: LGPL-2.1-or-later; COPYING is included in the wheel and source archive. Retain the corresponding source alongside the distributed wheel.

The modified source includes socket regression tests. Its version declarations identify the local repair, and the optional Poetry Cython build hook is removed to produce a portable pure-Python wheel. There are no native binaries and no compiler requirement on customer machines. Build from the corresponding source using Poetry Core 2.5.0 and `SOURCE_DATE_EPOCH=1783616475 python -m build --wheel --no-isolation` after installing its declared build requirements in an isolated build environment. Only `zeroconf/_utils/net.py` and the version declaration in `zeroconf/__init__.py` differ among runtime Python modules from the published source.
