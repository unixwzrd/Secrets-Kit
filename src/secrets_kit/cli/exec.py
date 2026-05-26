"""
secrets_kit.cli.exec

Child process execution helpers for seckit run.
"""

from __future__ import annotations

import os
from typing import Dict, List


def _child_command_args(raw_args: List[str]) -> List[str]:
    args = list(raw_args)
    if args and args[0] == "--":
        args = args[1:]
    return args


def _exec_child(*, argv: List[str], env: Dict[str, str]) -> int:
    os.execvpe(argv[0], argv, env)
    return 0
