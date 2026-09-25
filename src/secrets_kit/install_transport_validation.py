"""
secrets_kit.install_transport_validation

Validate the pinned native dependency and py-libp2p startup contract.

The installer invokes this module before activating a new runtime generation.
It inspects and imports installed artifacts but never rewrites third-party
binaries. Unknown versions, missing linkage, or incomplete transport startup
fail closed.
"""

from __future__ import annotations

import argparse
import importlib
import importlib.metadata
import json
import platform
import subprocess
from pathlib import Path
from typing import Sequence

APPROVED_VERSIONS = {
    "cryptography": "50.0.1",
    "libp2p": "0.7.0+seckit.4",
    "fastecdsa": "3.0.1",
}
EXPECTED_EXTENSIONS = {"_ecdsa", "curvemath"}


class TransportDependencyError(RuntimeError):
    """Reject an unapproved or unusable installed transport dependency."""


def _distribution_files(name: str) -> tuple[Path, ...]:
    """Return the absolute files owned by one installed distribution."""
    try:
        distribution = importlib.metadata.distribution(name)
    except importlib.metadata.PackageNotFoundError as exc:
        raise TransportDependencyError(f"required distribution is absent: {name}") from exc
    if distribution.files is None:
        raise TransportDependencyError(f"distribution file inventory is absent: {name}")
    return tuple(Path(distribution.locate_file(item)).resolve() for item in distribution.files)


def installed_versions() -> dict[str, str]:
    """Return exact approved versions or fail before runtime activation."""
    versions: dict[str, str] = {}
    for name, approved in APPROVED_VERSIONS.items():
        try:
            actual = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError as exc:
            raise TransportDependencyError(f"required distribution is absent: {name}") from exc
        if actual != approved:
            raise TransportDependencyError(
                f"unapproved {name} version: installed={actual} approved={approved}"
            )
        versions[name] = actual
    return versions


def extension_files() -> tuple[Path, ...]:
    """Locate the two expected fastecdsa native extension modules."""
    extensions = {
        path
        for path in _distribution_files("fastecdsa")
        if path.suffix == ".so" and path.parent.name == "fastecdsa"
    }
    names = {path.name.split(".", 1)[0] for path in extensions}
    if names != EXPECTED_EXTENSIONS or len(extensions) != 2:
        raise TransportDependencyError(
            f"unapproved fastecdsa extension layout: names={sorted(names)} "
            f"count={len(extensions)}"
        )
    return tuple(sorted(extensions))


def _run(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    """Execute an inspection command and convert failures to bounded errors."""
    try:
        return subprocess.run(list(command), check=True, capture_output=True, text=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        stderr = getattr(exc, "stderr", "") or ""
        raise TransportDependencyError(
            f"dependency inspection failed: {' '.join(command)}: {stderr.strip()}"
        ) from exc


def verify_macos_linkage(*, extensions: Sequence[Path]) -> dict[str, str]:
    """Require loader-relative GMP linkage to a wheel-owned library."""
    linkage: dict[str, str] = {}
    for extension in extensions:
        output = _run(("/usr/bin/otool", "-L", str(extension))).stdout
        references = [
            line.strip().split(" ", 1)[0]
            for line in output.splitlines()[1:]
            if "libgmp" in line
        ]
        if len(references) != 1:
            raise TransportDependencyError(
                f"expected one GMP reference in {extension}, found {references}"
            )
        reference = references[0]
        prefix = "@loader_path/"
        if not reference.startswith(prefix):
            raise TransportDependencyError(
                f"fastecdsa GMP reference is not loader-relative: {extension}: {reference}"
            )
        target = (extension.parent / reference.removeprefix(prefix)).resolve()
        if not target.is_file():
            raise TransportDependencyError(
                f"fastecdsa wheel-owned GMP library is absent: {extension}: {target}"
            )
        linkage[str(extension)] = reference
    return linkage


def verify_linux_linkage(*, extensions: Sequence[Path]) -> dict[str, str]:
    """Require every installed extension to resolve exactly one GMP library."""
    linkage: dict[str, str] = {}
    for extension in extensions:
        output = _run(("/usr/bin/ldd", str(extension))).stdout
        if "not found" in output:
            raise TransportDependencyError(f"unresolved dependency in {extension}: {output}")
        lines = [line.strip() for line in output.splitlines() if "libgmp" in line]
        if len(lines) != 1:
            raise TransportDependencyError(
                f"expected one resolved GMP dependency in {extension}, found {lines}"
            )
        linkage[str(extension)] = lines[0]
    return linkage


def verify_native_dependency(*, system: str | None = None) -> dict[str, object]:
    """Import fastecdsa and verify its installed native linkage without mutation."""
    operating_system = system or platform.system()
    if operating_system not in {"Darwin", "Linux"}:
        raise TransportDependencyError(f"unsupported validation platform: {operating_system}")
    extensions = extension_files()
    importlib.import_module("fastecdsa._ecdsa")
    importlib.import_module("fastecdsa.curvemath")
    if operating_system == "Darwin":
        linkage = verify_macos_linkage(extensions=extensions)
    else:
        linkage = verify_linux_linkage(extensions=extensions)
    return {
        "platform": operating_system,
        "extensions": [str(path) for path in extensions],
        "linkage": linkage,
    }


def verify_libp2p_startup() -> dict[str, object]:
    """Start and stop the installed Noise-only adapter on a dynamic loopback port."""
    # Import on the installer thread before the adapter's bounded startup wait.
    # A clean runtime has no bytecode or dynamic-loader cache yet; that cold
    # import is dependency validation, not transport startup work.
    importlib.import_module("libp2p")

    from secrets_kit.daemon.routing import RoutingTable
    from secrets_kit.daemon.transport import PyLibP2PTransport
    from secrets_kit.daemon.transports import TransportServices

    routing_table = RoutingTable()
    transport = PyLibP2PTransport(
        host="127.0.0.1",
        requested_port=0,
        discovery=False,
        routing_table=routing_table,
    )

    def unexpected_binding(*args: object) -> object:
        raise TransportDependencyError(
            f"unexpected identity binding during install check: {args!r}"
        )

    services = TransportServices(
        frame_handler=lambda payload, kind: (b"", False),
        routing_table=routing_table,
        sign_transport_binding=unexpected_binding,
        verify_transport_binding=unexpected_binding,
    )
    try:
        try:
            transport.start(services=services)
        except Exception as exc:
            raise TransportDependencyError(f"libp2p host startup failed: {exc}") from exc
        snapshot = transport.snapshot()
        details = snapshot.as_dict()
        if not snapshot.running or not snapshot.transport_identity or not snapshot.tcp_port:
            raise TransportDependencyError(f"libp2p host startup was incomplete: {details}")
        if details.get("security_protocols") != ["/noise"]:
            raise TransportDependencyError(f"libp2p security profile is not Noise-only: {details}")
        return {
            "transport": snapshot.transport,
            "peer_id": snapshot.transport_identity,
            "tcp_port": snapshot.tcp_port,
            "security_protocols": details["security_protocols"],
        }
    finally:
        transport.stop()


def validate_installation(*, system: str | None = None) -> dict[str, object]:
    """Validate pinned versions, native imports/linkage, and libp2p startup."""
    return {
        "ok": True,
        "versions": installed_versions(),
        "native": verify_native_dependency(system=system),
        "libp2p": verify_libp2p_startup(),
    }


def main(argv: Sequence[str] | None = None) -> int:
    """Run fail-closed installer validation and emit secret-free JSON."""
    argparse.ArgumentParser(description=__doc__).parse_args(argv)
    try:
        result = validate_installation()
    except TransportDependencyError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
