"""
secrets_kit.cli

Public CLI package exports for tests and ``python -m secrets_kit.cli``.
"""

from __future__ import annotations

from secrets_kit.cli.commands.config import (
    cmd_config_path,
    cmd_config_set,
    cmd_config_show,
    cmd_config_unset,
)
from secrets_kit.cli.commands.delete import cmd_delete
from secrets_kit.cli.commands.doctor import cmd_doctor
from secrets_kit.cli.commands.explain import cmd_explain
from secrets_kit.cli.commands.export import cmd_export
from secrets_kit.cli.commands.get import cmd_get
from secrets_kit.cli.commands.import_cmd import (
    _apply_candidates,
    cmd_import_encrypted,
    cmd_import_env,
    cmd_import_file,
)
from secrets_kit.cli.commands.info import cmd_info
from secrets_kit.cli.commands.init_cmd import cmd_init
from secrets_kit.cli.commands.list import cmd_list
from secrets_kit.cli.commands.lock import cmd_lock
from secrets_kit.cli.commands.migrate import cmd_migrate_dotenv, cmd_migrate_metadata
from secrets_kit.cli.commands.run import cmd_run
from secrets_kit.cli.commands.service import cmd_service_copy
from secrets_kit.cli.commands.set import cmd_set
from secrets_kit.cli.commands.unlock import cmd_unlock
from secrets_kit.cli.defaults import _apply_defaults
from secrets_kit.cli.exec import _exec_child
from secrets_kit.cli.io import _read_password
from secrets_kit.cli.main import main
from secrets_kit.cli.metadata_build import build_metadata
from secrets_kit.cli.parser import build_parser
from secrets_kit.cli.selection import _select_entries
from secrets_kit.registry import (
    delete_metadata,
    ensure_defaults_storage,
    ensure_registry_storage,
    load_registry,
    upsert_metadata,
)
from secrets_kit.registry.resolve import read_metadata

__all__ = [
    "_apply_candidates",
    "_apply_defaults",
    "build_metadata",
    "_exec_child",
    "read_metadata",
    "_read_password",
    "_select_entries",
    "build_parser",
    "cmd_config_path",
    "cmd_config_set",
    "cmd_config_show",
    "cmd_config_unset",
    "cmd_delete",
    "cmd_doctor",
    "cmd_explain",
    "cmd_export",
    "cmd_get",
    "cmd_import_encrypted",
    "cmd_import_env",
    "cmd_import_file",
    "cmd_init",
    "cmd_list",
    "cmd_lock",
    "cmd_migrate_dotenv",
    "cmd_migrate_metadata",
    "cmd_run",
    "cmd_service_copy",
    "cmd_set",
    "cmd_unlock",
    "cmd_info",
    "delete_metadata",
    "ensure_defaults_storage",
    "ensure_registry_storage",
    "load_registry",
    "main",
    "upsert_metadata",
]
