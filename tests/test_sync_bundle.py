from __future__ import annotations

import base64
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from secrets_kit.identity import init_identity, load_identity
from secrets_kit.sync_bundle import (
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


if __name__ == "__main__":
    unittest.main()
