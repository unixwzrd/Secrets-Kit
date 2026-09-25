"""secrets_kit.install_native_prefix: bounded Intel OpenSSL prefix relocation.

Authenticate publisher archives and relocate only declared Intel OpenSSL paths
inside a new runtime. Never compile or activate it; the shell installer must
validate the completed runtime before switching the stable launcher.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import platform
import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

OPENSSL_LIBRARY_SHA256 = "b952510256f810d37da06f1f4b17f4e3d99e47fa04b6e3cb8dce26e209c8e264"
OPENSSL_LIBRARY_SIZE = 5493992
NATIVE_PACKAGES = {
    "openssl-3.5.8-h332eb6d_0": "fbbc62a6af760f94db199c08b0833210c9f665446c504bec365963245366608c",
    "cryptography-50.0.1-py312h6b03e6b_0": "aaf52c68695aa81c68946d07f8c7e2899ca25e441ab6643e8884c715c4b91ef3",
}


def native_package_members(*, data: bytes, package: str, selected: set[str] | None) -> dict[str, tuple[bytes, dict[str, Any]]]:
    """Read selected regular payload files from a pinned publisher archive.

    Authenticate the entire .conda before decoding. Read metadata from that same
    archive, reject duplicate/linked selections, and verify each selected file's
    declared hash and size. No archive paths are extracted to the filesystem.
    zstandard is an installer bootstrap dependency, imported only after hashing.
    """
    if (package not in NATIVE_PACKAGES or len(data) > 64 * 1024 * 1024
            or hashlib.sha256(data).hexdigest() != NATIVE_PACKAGES[package]):
        raise ValueError("unapproved_native_archive")
    for name in selected or ():
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or str(path) != name:
            raise ValueError("unsafe_native_member")
    import zstandard

    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        names = archive.namelist()
        expected = {"metadata.json", f"info-{package}.tar.zst", f"pkg-{package}.tar.zst"}
        if len(names) != len(expected) or set(names) != expected:
            raise ValueError("unexpected_native_archive_layout")
        rows = None
        with archive.open(f"info-{package}.tar.zst") as compressed, zstandard.ZstdDecompressor().stream_reader(compressed) as stream, tarfile.open(fileobj=stream, mode="r|") as tar:
            for member in tar:
                if member.name == "info/paths.json":
                    if rows is not None or not member.isfile() or member.size > 4 * 1024 * 1024:
                        raise ValueError("invalid_native_metadata")
                    source = tar.extractfile(member)
                    assert source is not None
                    rows = json.load(source)["paths"]
        if not isinstance(rows, list):
            raise ValueError("missing_native_metadata")
        if selected is None:
            if package != "cryptography-50.0.1-py312h6b03e6b_0":
                raise ValueError("explicit_native_selection_required")
            selected = {row["_path"] for row in rows if row["_path"].startswith((
                "lib/python3.12/site-packages/cryptography/",
                "lib/python3.12/site-packages/cryptography-50.0.1.dist-info/"))}
            if not selected:
                raise ValueError("missing_native_payload")
        for name in selected:
            path = PurePosixPath(name)
            if path.is_absolute() or ".." in path.parts or str(path) != name:
                raise ValueError("unsafe_native_member")
        metadata = {}
        for row in rows:
            name = row.get("_path")
            if name in selected:
                if name in metadata or row.get("path_type") != "hardlink":
                    raise ValueError("invalid_native_member_metadata")
                metadata[name] = row
        if set(metadata) != selected:
            raise ValueError("missing_native_member_metadata")
        result = {}
        total = 0
        with archive.open(f"pkg-{package}.tar.zst") as compressed, zstandard.ZstdDecompressor().stream_reader(compressed) as stream, tarfile.open(fileobj=stream, mode="r|") as tar:
            for member in tar:
                if member.name not in selected:
                    continue
                total += member.size
                if member.name in result or not member.isfile() or total > 64 * 1024 * 1024:
                    raise ValueError("unsafe_native_payload")
                source = tar.extractfile(member)
                assert source is not None
                payload = source.read()
                row = metadata[member.name]
                if len(payload) != row.get("size_in_bytes") or hashlib.sha256(payload).hexdigest() != row.get("sha256"):
                    raise ValueError("native_payload_mismatch")
                result[member.name] = (payload, row)
        if set(result) != selected:
            raise ValueError("missing_native_payload")
        return result


def replace_binary_prefix(*, data: bytes, placeholder: bytes, prefix: bytes) -> bytes:
    """Replace NUL-terminated path strings, retaining suffixes and byte offsets.

    Padding belongs after the complete rewritten string, not between the prefix
    and suffix. Unsupported or absent placeholders fail instead of silently
    producing an apparently relocated library. No filesystem side effects.
    """
    if (not placeholder.startswith(b"/") or not prefix.startswith(b"/")
            or b"\0" in placeholder or b"\0" in prefix or prefix == placeholder
            or len(prefix) > len(placeholder) or b".." in prefix.split(b"/")):
        raise ValueError("invalid_native_prefix")
    if placeholder not in data:
        raise ValueError("native_prefix_not_found")
    segments = data.split(b"\0")
    if placeholder in segments[-1]:
        raise ValueError("unterminated_native_prefix")
    for index, segment in enumerate(segments[:-1]):
        if placeholder in segment:
            replacement = segment.replace(placeholder, prefix)
            segments[index] = replacement + b"\0" * (len(segment) - len(replacement))
    result = b"\0".join(segments)
    if len(result) != len(data) or placeholder in result:
        raise ValueError("native_prefix_relocation_incomplete")
    return result


def relocate_openssl_library(*, data: bytes, metadata: dict[str, Any], prefix: str) -> bytes:
    """Transform only the pinned osx-64 OpenSSL 3.5.8 library payload.

    Metadata must come from the checksum-verified publisher archive, never an
    arbitrary installed file. The returned bytes still require native loading
    and path verification in the isolated target runtime.
    """
    if (metadata.get("_path") != "lib/libcrypto.3.dylib"
            or metadata.get("file_mode") != "binary"
            or metadata.get("path_type") != "hardlink"
            or metadata.get("sha256") != OPENSSL_LIBRARY_SHA256
            or metadata.get("size_in_bytes") != OPENSSL_LIBRARY_SIZE
            or len(data) != OPENSSL_LIBRARY_SIZE
            or hashlib.sha256(data).hexdigest() != OPENSSL_LIBRARY_SHA256):
        raise ValueError("unapproved_openssl_payload")
    placeholder = metadata.get("prefix_placeholder")
    if not isinstance(placeholder, str) or not PurePosixPath(prefix).is_absolute():
        raise ValueError("invalid_native_prefix_metadata")
    return replace_binary_prefix(data=data, placeholder=placeholder.encode("utf-8"), prefix=prefix.encode("utf-8"))


def install_native_packages(archive_dir: Path) -> None:
    """Populate only a new Intel UV venv; refuse collisions and retain provenance.

    The shell installer owns generation creation and activation. This helper
    never activates a runtime, changes an existing installation, or compiles.
    Partial failures remain in the unactivated generation for diagnosis.
    """
    if (platform.system(), platform.machine(), sys.version_info[:2]) != ("Darwin", "x86_64", (3, 12)) or sys.prefix == sys.base_prefix:
        raise ValueError("unsupported_native_runtime")
    import certifi

    root = Path(sys.prefix).resolve()
    if root.stat().st_uid != os.getuid():
        raise ValueError("foreign_native_runtime")
    payloads: dict[str, bytes] = {}
    provenance = {}
    for package, digest in NATIVE_PACKAGES.items():
        archive = archive_dir / (package + ".conda")
        data = archive.read_bytes()
        selected = {"lib/libcrypto.3.dylib", "lib/libssl.3.dylib", "ssl/openssl.cnf"} if package.startswith("openssl-") else None
        members = native_package_members(data=data, package=package, selected=selected)
        for name, (payload, metadata) in members.items():
            if "prefix_placeholder" in metadata:
                payload = relocate_openssl_library(data=payload, metadata=metadata, prefix=str(root))
            if name in payloads:
                raise ValueError("duplicate_native_destination")
            payloads[name] = payload
        # Original archives retain publisher metadata, licenses and original bytes.
        payloads[f"native-provenance/{package}.conda"] = data
        provenance[package] = digest
    payloads["ssl/cert.pem"] = Path(certifi.where()).read_bytes()
    payloads["ssl/certs/.keep"] = b""
    payloads["native-provenance/manifest.json"] = json.dumps({
        "archives": provenance,
        "installed_sha256": {name: hashlib.sha256(data).hexdigest() for name, data in payloads.items() if not name.startswith("native-provenance/")},
    }, sort_keys=True).encode() + b"\n"
    # Preflight every destination before writing any payload. No archive symlinks
    # are extracted and no existing file (including a dangling link) is replaced.
    for name in payloads:
        target = root / name
        if target.exists() or target.is_symlink():
            raise ValueError("existing_native_destination")
        for parent in target.parents:
            if parent == root:
                break
            if parent.is_symlink() or (parent.exists() and (not parent.is_dir() or parent.stat().st_uid != os.getuid())):
                raise ValueError("unsafe_native_destination")
    for name, payload in payloads.items():
        target = root / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ValueError("native_archive_directory_required")
        install_native_packages(Path(sys.argv[1]))
    except Exception:
        print("native_runtime_preparation_failed", file=sys.stderr)
        sys.exit(1)
