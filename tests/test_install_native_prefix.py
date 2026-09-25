"""Tests for installer byte transformation; no native files are modified."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
import tempfile
import tomllib
import types
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from secrets_kit.install_native_prefix import (
    NATIVE_PACKAGES,
    install_native_packages,
    native_package_members,
    relocate_openssl_library,
    replace_binary_prefix,
)


class NativePrefixTest(unittest.TestCase):
    def test_installer_native_archive_selection_matches_validated_packages(self):
        root = Path(__file__).resolve().parents[1]
        installer = (root / "install.sh").read_text()
        for package in NATIVE_PACKAGES:
            self.assertIn(f"{package}.conda", installer)
        project = tomllib.loads((root / "pyproject.toml").read_text())
        self.assertIn("zstandard==0.25.0", project["project"]["optional-dependencies"]["dev"])

    def test_runtime_writer_preserves_existing_files_and_retains_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "runtime"
            root.mkdir()
            ca = Path(directory) / "ca.pem"
            ca.write_bytes(b"synthetic certificate bundle")
            for package in NATIVE_PACKAGES:
                (Path(directory) / (package + ".conda")).write_bytes(b"archive fixture")
            self.enterContext(mock.patch("secrets_kit.install_native_prefix.platform.system", return_value="Darwin"))
            self.enterContext(mock.patch("secrets_kit.install_native_prefix.platform.machine", return_value="x86_64"))
            self.enterContext(mock.patch("secrets_kit.install_native_prefix.sys.prefix", str(root)))
            self.enterContext(mock.patch("secrets_kit.install_native_prefix.sys.version_info", (3, 12)))
            self.enterContext(mock.patch.dict("sys.modules", {"certifi": types.SimpleNamespace(where=lambda: str(ca))}))
            def members(**kwargs):
                name = "lib/example" if kwargs["package"].startswith("openssl") else "lib/python3.12/site-packages/cryptography/example"
                return {name: (b"verified fixture", {})}
            self.enterContext(mock.patch("secrets_kit.install_native_prefix.native_package_members", side_effect=members))
            install_native_packages(Path(directory))
            self.assertEqual((root / "ssl/cert.pem").read_bytes(), ca.read_bytes())
            self.assertTrue((root / "native-provenance/manifest.json").is_file())
            with self.assertRaisesRegex(ValueError, "existing_native_destination"):
                install_native_packages(Path(directory))
            self.assertEqual((root / "lib/example").read_bytes(), b"verified fixture")

    def test_runtime_writer_rejects_non_intel_runtime(self):
        with mock.patch("secrets_kit.install_native_prefix.platform.system", return_value="Linux"):
            with self.assertRaisesRegex(ValueError, "unsupported_native_runtime"):
                install_native_packages(Path("/unused"))

    def _archive(self, *, linked=False, wrong_hash=False, duplicate=False):
        name = "lib/example"
        payload = b"synthetic"
        row = {"_path": name, "path_type": "hardlink", "size_in_bytes": len(payload),
               "sha256": "wrong" if wrong_hash else hashlib.sha256(payload).hexdigest()}
        buffers = []
        for names, body in ((["info/paths.json"], json.dumps({"paths": [row]}).encode()),
                            ([name, name] if duplicate else [name], payload)):
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w") as tar:
                for member_name in names:
                    member = tarfile.TarInfo(member_name)
                    member.size = len(body)
                    if linked and member_name == name:
                        member.type = tarfile.SYMTYPE
                        member.linkname = "/outside"
                        member.size = 0
                    tar.addfile(member, io.BytesIO(body))
            buffers.append(buffer.getvalue())
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("metadata.json", "{}")
            archive.writestr("info-fixture.tar.zst", buffers[0])
            archive.writestr("pkg-fixture.tar.zst", buffers[1])
        data = output.getvalue()
        self.enterContext(mock.patch.dict("secrets_kit.install_native_prefix.NATIVE_PACKAGES", {"fixture": hashlib.sha256(data).hexdigest()}))
        # Compression-independent container checks; real package decoding has a separate probe.
        decoder = types.SimpleNamespace(ZstdDecompressor=lambda: types.SimpleNamespace(stream_reader=lambda stream: io.BytesIO(stream.read())))
        self.enterContext(mock.patch.dict("sys.modules", {"zstandard": decoder}))
        return data

    def test_authenticated_selected_member(self):
        data = self._archive()
        result = native_package_members(data=data, package="fixture", selected={"lib/example"})
        self.assertEqual(result["lib/example"][0], b"synthetic")

    def test_archive_tampering_rejected_before_decoding(self):
        data = self._archive()
        with self.assertRaisesRegex(ValueError, "unapproved_native_archive"):
            native_package_members(data=data + b"tampered", package="fixture", selected={"lib/example"})

    def test_link_duplicate_and_hash_mismatch_refused(self):
        for kwargs in ({"linked": True}, {"duplicate": True}, {"wrong_hash": True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                native_package_members(data=self._archive(**kwargs), package="fixture", selected={"lib/example"})

    def test_missing_or_traversing_member_refused(self):
        data = self._archive()
        for name in ("lib/missing", "../outside", "/outside"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                native_package_members(data=data, package="fixture", selected={name})

    def test_suffix_and_following_offsets_survive(self) -> None:
        data = b"header\0/long/build/prefix/ssl/openssl.cnf\0next\0"
        result = replace_binary_prefix(data=data, placeholder=b"/long/build/prefix", prefix=b"/runtime")
        self.assertIn(b"/runtime/ssl/openssl.cnf\0", result)
        self.assertEqual(len(data), len(result))
        self.assertEqual(data.index(b"next"), result.index(b"next"))

    def test_multiple_occurrences_and_binary_bytes_survive(self) -> None:
        data = b"\xff\0/old/long/a:/old/long/b\0\x80\0"
        result = replace_binary_prefix(data=data, placeholder=b"/old/long", prefix=b"/new")
        self.assertIn(b"/new/a:/new/b\0", result)
        self.assertTrue(result.startswith(b"\xff\0"))
        self.assertTrue(result.endswith(b"\x80\0"))
        self.assertEqual(len(data), len(result))

    def test_invalid_or_incomplete_prefix_refused(self) -> None:
        for data, old, new in [
            (b"/old/path\0", b"/old", b"/too-long"),
            (b"/old/path", b"/old", b"/new"),
            (b"other\0", b"/old", b"/new"),
            (b"/old/path\0", b"", b"/new"),
            (b"/old/path\0", b"/old", b"/old"),
            (b"/long/prefix\0", b"/long/prefix", b"/../x"),
            (b"/long/prefix\0", b"/long/prefix", b"relative"),
            (b"/old/path\0", b"/old", b"/\0x"),
        ]:
            with self.subTest(data=data, old=old, new=new), self.assertRaises(ValueError):
                replace_binary_prefix(data=data, placeholder=old, prefix=new)

    def test_unknown_payload_never_transformed(self) -> None:
        with self.assertRaisesRegex(ValueError, "unapproved_openssl_payload"):
            relocate_openssl_library(data=b"unknown\0", metadata={}, prefix="/runtime")
