"""
secrets_kit.cli.commands.config

Config / defaults subcommands.
"""

from __future__ import annotations

import argparse
import json
import sys

from secrets_kit.cli.constants.exit_codes import EXIT_CODES
from secrets_kit.cli.support.defaults import (
    CONFIG_STORABLE_KEYS,
    _load_defaults,
    _validate_config_entry,
)
from secrets_kit.cli.support.interaction import _fatal
from secrets_kit.models.core import ValidationError
from secrets_kit.registry.core import (
    RegistryError,
    defaults_path,
    ensure_defaults_storage,
    load_defaults,
    save_defaults,
)


def cmd_config_show(*, args: argparse.Namespace) -> int:
    """Print defaults.json or effective defaults (file + legacy + env)."""
    try:
        if getattr(args, "effective", False):
            merged = _load_defaults()
            print(
                json.dumps(
                    {
                        "source": "effective",
                        "defaults_path": str(defaults_path()),
                        "config": merged,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
        ensure_defaults_storage()
        on_disk = dict(load_defaults())
        print(
            json.dumps(
                {
                    "source": "file",
                    "defaults_path": str(defaults_path()),
                    "config": on_disk,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    except ValidationError as exc:
        return _fatal(message=str(exc), code=EXIT_CODES["EINVAL"])
    except RegistryError as exc:
        return _fatal(message=str(exc), code=EXIT_CODES["EPERM"])


def cmd_config_set(*, args: argparse.Namespace) -> int:
    """Persist one key to defaults.json."""
    try:
        key = str(args.key)
        if key not in CONFIG_STORABLE_KEYS:
            allowed = ", ".join(sorted(CONFIG_STORABLE_KEYS))
            raise ValidationError(f"unknown key {key!r}; allowed: {allowed}")
        coerced = _validate_config_entry(key=key, value=str(args.value))
        ensure_defaults_storage()
        data = dict(load_defaults())
        data[key] = coerced
        save_defaults(payload=data)
        print(
            json.dumps(
                {"saved": True, "key": key, "value": data[key], "defaults_path": str(defaults_path())},
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    except ValidationError as exc:
        return _fatal(message=str(exc), code=EXIT_CODES["EINVAL"])
    except RegistryError as exc:
        return _fatal(message=str(exc), code=EXIT_CODES["EPERM"])


def cmd_config_unset(*, args: argparse.Namespace) -> int:
    """Remove one key from defaults.json."""
    try:
        key = str(args.key)
        if key not in CONFIG_STORABLE_KEYS:
            allowed = ", ".join(sorted(CONFIG_STORABLE_KEYS))
            raise ValidationError(f"unknown key {key!r}; allowed: {allowed}")
        ensure_defaults_storage()
        data = dict(load_defaults())
        if key not in data:
            print(f"key {key!r} not present in {defaults_path()}", file=sys.stderr)
            return 0
        del data[key]
        save_defaults(payload=data)
        print(json.dumps({"saved": True, "removed": key, "defaults_path": str(defaults_path())}, indent=2, sort_keys=True))
        return 0
    except ValidationError as exc:
        return _fatal(message=str(exc), code=EXIT_CODES["EINVAL"])
    except RegistryError as exc:
        return _fatal(message=str(exc), code=EXIT_CODES["EPERM"])


def cmd_config_path(*, args: argparse.Namespace) -> int:
    """Print path to defaults.json."""
    try:
        ensure_defaults_storage()
        print(defaults_path())
        return 0
    except RegistryError as exc:
        return _fatal(message=str(exc), code=EXIT_CODES["EPERM"])
