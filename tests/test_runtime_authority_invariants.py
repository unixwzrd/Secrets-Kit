"""Stdout/stderr and repr guards for runtime authority / materialization semantics."""

from __future__ import annotations

import importlib.util
import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from secrets_kit.backends.base import BackendStore, ResolvedEntry
from secrets_kit.cli.main import (
    cmd_backend_index,
    cmd_doctor,
    cmd_explain,
    cmd_get,
    cmd_list,
    cmd_recover_registry,
    _apply_defaults,
)
from secrets_kit.cli.parser.base import build_parser
from secrets_kit.backends.security import BACKEND_SQLITE, set_secret
from secrets_kit.models.core import EntryMetadata
from secrets_kit.registry.core import ensure_registry_storage, upsert_metadata
from secrets_kit.runtime.authority import BACKEND_INTERFACE_EXPOSURE, backend_interface_exposure_complete
from tests.leakage_needles import RUNTIME_INVARIANT_PLAINTEXT

if importlib.util.find_spec("nacl") is not None:
    from secrets_kit.backends.sqlite import clear_sqlite_crypto_cache
else:

    def clear_sqlite_crypto_cache() -> None:  # pragma: no cover
        pass


def _parse(*argv: str) -> object:
    return build_parser().parse_args(list(argv))


def _run_cli(*, args: object) -> tuple[int, str, str]:
    _apply_defaults(args=args)
    out = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        func = getattr(args, "func")
        code = int(func(args=args))
    return code, out.getvalue(), err.getvalue()


@unittest.skipUnless(importlib.util.find_spec("nacl") is not None, "requires PyNaCl")
class RuntimeAuthorityStdoutStderrTest(unittest.TestCase):
    """Non-materialization CLI paths must not print secret plaintext to stdout/stderr."""

    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self.home = Path(self._td.name)
        self.db = self.home / "vault.db"
        os.environ["SECKIT_SQLITE_PASSPHRASE"] = "rt-inv-test-passphrase-9fb!!"
        clear_sqlite_crypto_cache()
        self._home_patch = mock.patch.object(Path, "home", return_value=self.home)
        self._home_patch.start()

        ensure_registry_storage(home=self.home)
        set_secret(
            service="rtinv",
            account="testac",
            name="RTINVKEY",
            value=RUNTIME_INVARIANT_PLAINTEXT,
            path=str(self.db),
            backend=BACKEND_SQLITE,
        )
        meta = EntryMetadata(
            name="RTINVKEY",
            service="rtinv",
            account="testac",
            entry_type="secret",
            entry_kind="api_key",
        )
        upsert_metadata(metadata=meta, home=self.home)

    def tearDown(self) -> None:
        self._home_patch.stop()
        clear_sqlite_crypto_cache()
        if "SECKIT_SQLITE_PASSPHRASE" in os.environ:
            del os.environ["SECKIT_SQLITE_PASSPHRASE"]
        self._td.cleanup()

    def _assert_streams_clean(self, out: str, err: str) -> None:
        blob = out + err
        self.assertNotIn(RUNTIME_INVARIANT_PLAINTEXT, blob)

    def test_explain_list_backend_index_get_redacted_recover_doctor_no_plaintext(self) -> None:
        flows = [
            _parse(
                "explain",
                "--backend",
                "sqlite",
                "--db",
                str(self.db),
                "--service",
                "rtinv",
                "--account",
                "testac",
                "--name",
                "RTINVKEY",
            ),
            _parse(
                "list",
                "--backend",
                "sqlite",
                "--db",
                str(self.db),
                "--service",
                "rtinv",
                "--account",
                "testac",
                "--format",
                "json",
            ),
            _parse(
                "backend-index",
                "--backend",
                "sqlite",
                "--db",
                str(self.db),
                "--service",
                "rtinv",
                "--account",
                "testac",
            ),
            _parse(
                "get",
                "--backend",
                "sqlite",
                "--db",
                str(self.db),
                "--service",
                "rtinv",
                "--account",
                "testac",
                "--name",
                "RTINVKEY",
            ),
            _parse(
                "recover",
                "--backend",
                "sqlite",
                "--db",
                str(self.db),
                "--dry-run",
            ),
            _parse(
                "doctor",
                "--backend",
                "sqlite",
                "--db",
                str(self.db),
            ),
        ]
        for args in flows:
            with self.subTest(command=getattr(args, "command", "")):
                code, out, err = _run_cli(args=args)
                self.assertIsInstance(code, int)
                self._assert_streams_clean(out, err)

    def test_get_missing_name_emits_error_without_plaintext(self) -> None:
        args = _parse(
            "get",
            "--backend",
            "sqlite",
            "--db",
            str(self.db),
            "--service",
            "rtinv",
            "--account",
            "testac",
            "--name",
            "RTINV_NO_SUCH_KEY",
        )
        code, out, err = _run_cli(args=args)
        self.assertNotEqual(code, 0)
        self._assert_streams_clean(out, err)


class RuntimeAuthorityDriftMapTest(unittest.TestCase):
    def test_backend_interface_exposure_matches_backend_store(self) -> None:
        names = getattr(BackendStore, "__abstractmethods__", frozenset())
        self.assertTrue(names)
        self.assertEqual(frozenset(names), frozenset(BACKEND_INTERFACE_EXPOSURE.keys()))
        self.assertTrue(backend_interface_exposure_complete())


@unittest.skipUnless(importlib.util.find_spec("nacl") is not None, "requires PyNaCl")
class ResolvedEntryReprTest(unittest.TestCase):
    def test_repr_redacts_secret_value(self) -> None:
        meta = EntryMetadata(
            name="K",
            service="s",
            account="a",
            entry_type="secret",
            entry_kind="api_key",
        )
        entry = ResolvedEntry(secret=RUNTIME_INVARIANT_PLAINTEXT, metadata=meta)
        text = repr(entry)
        self.assertNotIn(RUNTIME_INVARIANT_PLAINTEXT, text)
        self.assertIn("redacted", text.lower())


if __name__ == "__main__":
    unittest.main()
