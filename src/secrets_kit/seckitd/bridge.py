"""Run ``seckit`` entrypoint as a controlled subprocess (no imports from ``cli`` package)."""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from typing import Dict, List, MutableMapping, Optional, Sequence

_SECKIT_MAIN = "secrets_kit" + ".cli"  # avoid static import of the CLI package


def default_seckit_argv() -> List[str]:
    """Argv prefix to invoke the operator CLI in the current interpreter."""
    return [sys.executable, "-m", _SECKIT_MAIN]


@dataclass(frozen=True)
class SubprocessResult:
    """Structured result of a ``seckit`` child (decode only; IPC redaction is separate)."""

    returncode: int
    stdout: str
    stderr: str


def run_sync_import_stdin(
    *,
    bundle_text: str,
    signer_alias: str,
    seckit_argv: Optional[Sequence[str]] = None,
    env: Optional[MutableMapping[str, str]] = None,
    timeout_s: float = 300.0,
) -> SubprocessResult:
    """Invoke ``seckit sync import - --signer … --yes`` with bundle JSON on stdin."""
    argv = list(seckit_argv) if seckit_argv is not None else default_seckit_argv()
    cmd = [
        *argv,
        "sync",
        "import",
        "-",
        "--signer",
        signer_alias,
        "--yes",
    ]
    run_env: Dict[str, str] = dict(os.environ) if env is None else {**env}
    proc = subprocess.run(
        cmd,
        input=bundle_text.encode("utf-8"),
        capture_output=True,
        timeout=timeout_s,
        env=run_env,
        check=False,
    )
    out = proc.stdout.decode("utf-8", errors="replace")
    err = proc.stderr.decode("utf-8", errors="replace")
    return SubprocessResult(
        returncode=int(proc.returncode or 0),
        stdout=out,
        stderr=err,
    )
