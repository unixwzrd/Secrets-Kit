"""Secrets-Kit test package."""

from __future__ import annotations

import atexit
import json
import os
import signal
import subprocess
import tempfile
import time
from pathlib import Path

_TEST_DAEMON_RUNTIME = tempfile.TemporaryDirectory(prefix="seckit-test-daemon.")
_TEST_DAEMON_RUNTIME_PATH = Path(_TEST_DAEMON_RUNTIME.name)
_TEST_DAEMON_RUNTIME_OWNER = "SECKIT_DAEMON_RUNTIME_DIR" not in os.environ
if _TEST_DAEMON_RUNTIME_OWNER:
    os.environ["SECKIT_DAEMON_RUNTIME_DIR"] = str(_TEST_DAEMON_RUNTIME_PATH)


def _cleanup_test_daemon_runtime() -> None:
    if not _TEST_DAEMON_RUNTIME_OWNER:
        return
    metadata = _read_metadata(runtime_path=_TEST_DAEMON_RUNTIME_PATH)
    pid = metadata.get("pid")
    previous_runtime = os.environ.get("SECKIT_DAEMON_RUNTIME_DIR")
    os.environ["SECKIT_DAEMON_RUNTIME_DIR"] = str(_TEST_DAEMON_RUNTIME_PATH)
    try:
        from secrets_kit.daemon.client import stop_daemon

        try:
            stop_daemon(timeout=2.0)
        except Exception:
            pass
    finally:
        if previous_runtime is None:
            os.environ.pop("SECKIT_DAEMON_RUNTIME_DIR", None)
        else:
            os.environ["SECKIT_DAEMON_RUNTIME_DIR"] = previous_runtime
    if isinstance(pid, int):
        _terminate_test_daemon_pid(pid=pid)
    _TEST_DAEMON_RUNTIME.cleanup()


def _read_metadata(*, runtime_path: Path) -> dict[str, object]:
    path = runtime_path / "seckitd.json"
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    return payload


def _terminate_test_daemon_pid(*, pid: int) -> None:
    if pid <= 0 or pid == os.getpid():
        return
    if _wait_for_pid_exit(pid=pid, timeout=2.0):
        return
    if not _pid_looks_like_daemon(pid=pid):
        return
    os.kill(pid, signal.SIGTERM)
    if _wait_for_pid_exit(pid=pid, timeout=2.0):
        return
    os.kill(pid, signal.SIGKILL)
    _wait_for_pid_exit(pid=pid, timeout=2.0)


def _pid_is_running(*, pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return not _pid_is_zombie(pid=pid)


def _pid_is_zombie(*, pid: int) -> bool:
    try:
        completed = subprocess.run(
            ["ps", "-p", str(pid), "-o", "stat="],
            capture_output=True,
            check=False,
            text=True,
            timeout=2.0,
        )
    except Exception:
        return False
    if completed.returncode != 0:
        return False
    return completed.stdout.strip().startswith("Z")


def _pid_looks_like_daemon(*, pid: int) -> bool:
    try:
        completed = subprocess.run(
            ["ps", "-p", str(pid), "-o", "command="],
            capture_output=True,
            check=False,
            text=True,
            timeout=2.0,
        )
    except Exception:
        return False
    if completed.returncode != 0:
        return False
    return "secrets_kit.daemon.server" in completed.stdout


def _wait_for_pid_exit(*, pid: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _pid_is_running(pid=pid):
            return True
        time.sleep(0.05)
    return not _pid_is_running(pid=pid)


atexit.register(_cleanup_test_daemon_runtime)
