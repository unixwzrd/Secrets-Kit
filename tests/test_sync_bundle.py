from __future__ import annotations

import argparse
import base64
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from secrets_kit.models.core import ValidationError

from secrets_kit.identity.core import init_identity, load_identity
from secrets_kit.sync.bundle import (
    SyncBundleError,
    build_bundle,
    decrypt_bundle_for_recipient,
    inspect_bundle,
    parse_bundle_file,
    verify_bundle_structure,
)


@unittest.skipUnless(importlib.util.find_spec("nacl") is not None, "requires PyNaCl")
class SyncBundleTest(unittest.TestCase):
    def _two_hosts(self) -> tuple[Path, Path]:
        td = tempfile.TemporaryDirectory()
        base = Path(td.name)
        ha = base / "a"
        hb = base / "b"
        ha.mkdir()
        hb.mkdir()
        init_identity(home=ha)
        init_identity(home=hb)
        self.addCleanup(td.cleanup)
        return ha, hb

    def test_happy_path_encrypt_decrypt(self) -> None:
        ha, hb = self._two_hosts()
        id_a = load_identity(home=ha)
        id_b = load_identity(home=hb)
        fp_b = id_b.signing_fingerprint_hex()
        entries = [
            {
                "metadata": {
                    "name": "K",
                    "service": "s",
                    "account": "a",
                    "created_at": "2026-01-01T00:00:00Z",
                    "domains": [],
                    "tags": [],
                    "updated_at": "2026-01-02T00:00:00Z",
                },
                "origin_host": id_a.host_id,
                "value": "hunter2",
            }
        ]
        bundle = build_bundle(
            identity=id_a,
            recipient_records=[(fp_b, id_b.box_public)],
            entries=entries,
            domain_filter=["example.com"],
        )
        text = json.dumps(bundle)
        payload = parse_bundle_file(text)
        self.assertTrue(verify_bundle_structure(payload=payload).ok)
        inner = decrypt_bundle_for_recipient(
            payload=payload,
            identity=id_b,
            trusted_signer=id_a.verify_key,
        )
        self.assertEqual(len(inner["entries"]), 1)
        self.assertEqual(inner["entries"][0]["value"], "hunter2")
        info = inspect_bundle(payload=payload)
        self.assertTrue(info["signature_ok"])

    def test_extra_manifest_field_still_verifies_and_decrypts(self) -> None:
        ha, hb = self._two_hosts()
        id_a = load_identity(home=ha)
        id_b = load_identity(home=hb)
        fp_b = id_b.signing_fingerprint_hex()
        entries = [
            {
                "metadata": {
                    "name": "K",
                    "service": "s",
                    "account": "a",
                    "created_at": "2026-01-01T00:00:00Z",
                    "domains": [],
                    "tags": [],
                    "updated_at": "2026-01-02T00:00:00Z",
                },
                "origin_host": id_a.host_id,
                "value": "x",
            }
        ]
        bundle = build_bundle(
            identity=id_a,
            recipient_records=[(fp_b, id_b.box_public)],
            entries=entries,
            manifest_extras={"x_future_field": "reserved-nonsecurity-note"},
        )
        payload = parse_bundle_file(json.dumps(bundle))
        self.assertTrue(verify_bundle_structure(payload=payload).ok)
        inner = decrypt_bundle_for_recipient(
            payload=payload,
            identity=id_b,
            trusted_signer=id_a.verify_key,
        )
        self.assertEqual(inner["entries"][0]["value"], "x")

    def test_tampered_inner_fails_decrypt(self) -> None:
        ha, hb = self._two_hosts()
        id_a = load_identity(home=ha)
        id_b = load_identity(home=hb)
        fp_b = id_b.signing_fingerprint_hex()
        bundle = build_bundle(
            identity=id_a,
            recipient_records=[(fp_b, id_b.box_public)],
            entries=[
                {
                    "metadata": {
                        "name": "K",
                        "service": "s",
                        "account": "a",
                        "created_at": "2026-01-01T00:00:00Z",
                        "domains": [],
                        "tags": [],
                        "updated_at": "2026-01-02T00:00:00Z",
                    },
                    "origin_host": id_a.host_id,
                    "value": "v",
                }
            ],
        )
        raw = json.loads(json.dumps(bundle))
        bad = base64.standard_b64decode(raw["inner_ciphertext"])
        bad_mut = bytearray(bad)
        bad_mut[-1] ^= 0x01
        raw["inner_ciphertext"] = base64.standard_b64encode(bytes(bad_mut)).decode("ascii")
        payload = raw
        self.assertFalse(verify_bundle_structure(payload=payload).ok)

    def test_tampered_manifest_breaks_signature(self) -> None:
        ha, hb = self._two_hosts()
        id_a = load_identity(home=ha)
        id_b = load_identity(home=hb)
        bundle = build_bundle(
            identity=id_a,
            recipient_records=[(id_b.signing_fingerprint_hex(), id_b.box_public)],
            entries=[
                {
                    "metadata": {
                        "name": "K",
                        "service": "s",
                        "account": "a",
                        "created_at": "2026-01-01T00:00:00Z",
                        "domains": [],
                        "tags": [],
                        "updated_at": "2026-01-02T00:00:00Z",
                    },
                    "origin_host": id_a.host_id,
                    "value": "v",
                }
            ],
        )
        raw = json.loads(json.dumps(bundle))
        raw["manifest"]["entry_count"] = 999
        self.assertFalse(verify_bundle_structure(payload=raw).ok)

    def test_wrong_recipient_no_wrapped_slot(self) -> None:
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        base = Path(td.name)
        dirs = [base / "a", base / "b", base / "c"]
        for p in dirs:
            p.mkdir()
            init_identity(home=p)
        id_a = load_identity(home=dirs[0])
        id_b = load_identity(home=dirs[1])
        id_c = load_identity(home=dirs[2])
        bundle = build_bundle(
            identity=id_a,
            recipient_records=[(id_b.signing_fingerprint_hex(), id_b.box_public)],
            entries=[
                {
                    "metadata": {
                        "name": "K",
                        "service": "s",
                        "account": "a",
                        "created_at": "2026-01-01T00:00:00Z",
                        "domains": [],
                        "tags": [],
                        "updated_at": "2026-01-02T00:00:00Z",
                    },
                    "origin_host": id_a.host_id,
                    "value": "v",
                }
            ],
        )
        payload = json.loads(json.dumps(bundle))
        with self.assertRaises(SyncBundleError):
            decrypt_bundle_for_recipient(
                payload=payload,
                identity=id_c,
                trusted_signer=id_a.verify_key,
            )

    def test_corrupted_json(self) -> None:
        with self.assertRaises(SyncBundleError):
            parse_bundle_file("not json {")


class SyncImportStdinParityTests(unittest.TestCase):
    """Contract: ``-`` reads the same bytes as an on-disk file for ``parse_bundle_file``."""

    def test_stdin_and_file_pass_identical_text_to_parse_bundle_file(self) -> None:
        from secrets_kit.cli.commands import sync_bundle

        bundle_text = json.dumps({"outer": "stub"})
        ns_base = {
            "signer": "alice",
            "dry_run": False,
            "yes": True,
            "domain": None,
            "domains": None,
            "backend": "secure",
            "keychain": None,
            "db": None,
        }

        def _stop(_text: str) -> None:
            raise ValidationError("stop-after-parse")

        seen: list[str] = []

        def capture(text: str) -> None:
            seen.append(text)
            _stop("")

        fake_ident = SimpleNamespace(host_id="test-host")
        with patch.object(sync_bundle, "load_identity", return_value=fake_ident):
            with patch.object(sync_bundle, "parse_bundle_file", side_effect=capture):
                with patch.object(sys.stderr, "write"):
                    ns_stdin = argparse.Namespace(file="-", **ns_base)
                    old_stdin = sys.stdin
                    sys.stdin = io.StringIO(bundle_text)
                    try:
                        sync_bundle.cmd_sync_import(args=ns_stdin)
                    finally:
                        sys.stdin = old_stdin
                    self.assertEqual(seen[-1], bundle_text)

        seen.clear()
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", suffix=".json", delete=False) as tmp:
            tmp.write(bundle_text)
            path = tmp.name
        try:
            with patch.object(sync_bundle, "load_identity", return_value=fake_ident):
                with patch.object(sync_bundle, "parse_bundle_file", side_effect=capture):
                    with patch.object(sys.stderr, "write"):
                        ns_file = argparse.Namespace(file=path, **ns_base)
                        sync_bundle.cmd_sync_import(args=ns_file)
            self.assertEqual(seen[-1], bundle_text)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_oserror_on_stdin_message_mentions_stdin(self) -> None:
        from secrets_kit.cli.commands import sync_bundle

        class _BadStdin:
            def read(self) -> str:  # noqa: PLR6301
                raise OSError("simulated read failure")

        ns = argparse.Namespace(
            file="-",
            signer="alice",
            dry_run=False,
            yes=True,
            domain=None,
            domains=None,
            backend="secure",
            keychain=None,
            db=None,
        )
        buf = io.StringIO()
        old_stdin = sys.stdin
        sys.stdin = _BadStdin()
        fake_ident = SimpleNamespace(host_id="test-host")
        try:
            with patch.object(sync_bundle, "load_identity", return_value=fake_ident):
                with patch.object(sys.stderr, "write", buf.write):
                    sync_bundle.cmd_sync_import(args=ns)
        finally:
            sys.stdin = old_stdin
        self.assertIn("stdin", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
