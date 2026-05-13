#!/usr/bin/env python3
"""Small child process used by the launchd smoke test.

This intentionally acts like a tiny agent/service. It receives secrets only
through its environment, then writes proof JSON so tests can verify that
`seckit run` launched a separate process with the expected variables.
"""

from __future__ import annotations

import json
import os
import pathlib
import sys


OUTPUT_DIR = pathlib.Path("/tmp/seckit-launchd-smoke")


def _output_path_for_mode(mode: str) -> pathlib.Path:
    if mode == "login-agent":
        return OUTPUT_DIR / "login-agent-result.txt"
    if mode == "service-agent":
        return OUTPUT_DIR / "service-agent-result.txt"
    if mode == "service-daemon":
        return OUTPUT_DIR / "service-daemon-result.txt"
    raise ValueError(f"unsupported mode: {mode}")


def main() -> int:
    if len(sys.argv) != 6:
        print(
            "usage: seckit_launchd_agent_simulator.py "
            "<keychain> <mode> <launchd-target> <env-name> <seckit-bin>",
            file=sys.stderr,
        )
        return 2

    keychain, mode, launchd_target, name, seckit_bin = sys.argv[1:6]
    payload = {
        "agent_simulator": True,
        "child_argv0": sys.argv[0],
        "euid": os.geteuid(),
        "home": os.environ.get("HOME", ""),
        "keychain": keychain,
        "launchd_target": launchd_target,
        "logname": os.environ.get("LOGNAME", ""),
        "mode": mode,
        "name": name,
        "pid": os.getpid(),
        "ppid": os.getppid(),
        "seckit_bin": seckit_bin,
        "uid": os.getuid(),
        "user": os.environ.get("USER", ""),
        "value": os.environ.get(name, ""),
    }
    try:
        output_path = _output_path_for_mode(mode)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    output_path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
