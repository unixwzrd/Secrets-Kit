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


SAFE_OUTPUT_ROOT = os.path.realpath("/tmp")


def _resolve_output_file(output_file: str, output_dir: str) -> pathlib.Path:
    if not os.path.basename(output_dir).startswith("seckit-launchd-smoke-"):
        raise ValueError(f"output directory must be a launchd smoke directory under /tmp: {output_dir}")
    safe_dir = os.path.realpath(output_dir)
    target = os.path.realpath(output_file)
    if os.path.commonpath([SAFE_OUTPUT_ROOT, safe_dir]) != SAFE_OUTPUT_ROOT:
        raise ValueError(f"output directory must be under /tmp: {output_dir}")
    if os.path.commonpath([safe_dir, target]) != safe_dir or os.path.dirname(target) != safe_dir:
        raise ValueError(f"output file must be directly inside output directory: {output_dir}")
    return pathlib.Path(target)


def main() -> int:
    if len(sys.argv) != 8:
        print(
            "usage: seckit_launchd_agent_simulator.py "
            "<output-file> <output-dir> <keychain> <mode> <launchd-target> <env-name> <seckit-bin>",
            file=sys.stderr,
        )
        return 2

    output_file, output_dir, keychain, mode, launchd_target, name, seckit_bin = sys.argv[1:8]
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
        output_path = _resolve_output_file(output_file, output_dir)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    output_path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
