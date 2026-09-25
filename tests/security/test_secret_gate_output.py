"""Ensure developer warning output never reproduces suspected credentials."""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import precommit_secret_gate


class SecretGateOutputTest(unittest.TestCase):
    def test_suspected_value_is_not_materialized_in_output(self) -> None:
        value = "sk-" + "synthetic" * 4
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.txt"
            path.write_text(f"API_KEY={value}\n", encoding="utf-8")
            output = io.StringIO()
            with mock.patch("sys.argv", ["gate", str(path)]), contextlib.redirect_stdout(output):
                precommit_secret_gate.main()
            self.assertNotIn(value, output.getvalue())
            self.assertNotIn("API_KEY=", output.getvalue())
            self.assertIn("line 1", output.getvalue())
