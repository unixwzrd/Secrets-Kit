"""argparse wiring for migrate, identity, peer, reconcile, and sync command trees.

``migrate`` parent is registered before identity/peer/reconcile/sync for stable ``seckit --help``.
Human-facing prose is ``STRINGS[...]`` from :mod:`secrets_kit.cli.strings.en`.
"""

from __future__ import annotations

import argparse
from typing import Iterable, Type

from secrets_kit.cli.commands.identity import cmd_identity_export, cmd_identity_init, cmd_identity_show
from secrets_kit.cli.commands.migrate import cmd_migrate_dotenv, cmd_migrate_metadata, cmd_recover_registry
from secrets_kit.cli.commands.peers import cmd_peer_add, cmd_peer_list, cmd_peer_remove, cmd_peer_show
from secrets_kit.cli.commands.reconcile_tools import (
    cmd_reconcile_explain,
    cmd_reconcile_inspect,
    cmd_reconcile_lineage,
    cmd_reconcile_verify,
)
from secrets_kit.cli.commands.sync_bundle import (
    cmd_sync_export,
    cmd_sync_import,
    cmd_sync_inspect,
    cmd_sync_verify,
)
from secrets_kit.cli.parser.formatter import SeckitHelpFormatter
from secrets_kit.cli.strings.en import STRINGS
from secrets_kit.models.core import ENTRY_KIND_VALUES


def add_migrate_parent_parser(sub: argparse._SubParsersAction) -> argparse.ArgumentParser:
    """Register the ``migrate`` parent parser (leaf subcommands added separately).

    Args:
        sub: Root subparser action.

    Returns:
        The ``migrate`` :class:`argparse.ArgumentParser` instance so callers
        can attach migrate subparsers without changing help order of sibling
        top-level commands.
    """
    return sub.add_parser("migrate", help=STRINGS["MIGRATE_HELP"])


def add_identity_peer_reconcile_sync_commands(
    sub: argparse._SubParsersAction,
    *,
    common: argparse.ArgumentParser,
    backend_choices: Iterable[str],
    formatter_class: Type[argparse.HelpFormatter] = SeckitHelpFormatter,
) -> None:
    """Register ``identity``, ``peer``, ``reconcile``, and ``sync`` command trees on *sub*.

    Args:
        sub: Root subparser action.
        common: Shared parent parser where commands use ``parents=[common]``.
        backend_choices: Iterable copied to list for ``choices=`` on flags.
        formatter_class: Help formatter for parsers that set epilogs or long
            descriptions.

    Returns:
        None. Mutates *sub* in place.

    Note:
        Intended to run after :func:`add_migrate_parent_parser` and before
        :func:`add_migrate_subcommands` so top-level help order stays stable.
    """
    backend_choices = list(backend_choices)

    p_identity = sub.add_parser("identity", help=STRINGS["IDENTITY_HELP"])
    id_sub = p_identity.add_subparsers(dest="identity_command", required=True)
    p_id_init = id_sub.add_parser("init", help=STRINGS["IDENTITY_INIT_HELP"])
    p_id_init.add_argument("--force", action="store_true")
    p_id_init.add_argument("--json", action="store_true")
    p_id_init.set_defaults(func=cmd_identity_init)
    p_id_show = id_sub.add_parser("show", help=STRINGS["IDENTITY_SHOW_HELP"])
    p_id_show.add_argument("--json", action="store_true")
    p_id_show.set_defaults(func=cmd_identity_show)
    p_id_exp = id_sub.add_parser("export", help=STRINGS["IDENTITY_EXPORT_HELP"])
    p_id_exp.add_argument("-o", "--out")
    p_id_exp.add_argument("--json", action="store_true")
    p_id_exp.set_defaults(func=cmd_identity_export)

    p_peer = sub.add_parser("peer", help=STRINGS["PEER_HELP"])
    peer_sub = p_peer.add_subparsers(dest="peer_command", required=True)
    p_peer_add = peer_sub.add_parser("add", help=STRINGS["PEER_ADD_HELP"])
    p_peer_add.add_argument("alias")
    p_peer_add.add_argument("export_path", metavar="PATH")
    p_peer_add.add_argument("--json", action="store_true")
    p_peer_add.set_defaults(func=cmd_peer_add)
    p_peer_rm = peer_sub.add_parser("remove", help=STRINGS["PEER_REMOVE_HELP"])
    p_peer_rm.add_argument("alias")
    p_peer_rm.add_argument("--json", action="store_true")
    p_peer_rm.set_defaults(func=cmd_peer_remove)
    p_peer_ls = peer_sub.add_parser("list", help=STRINGS["PEER_LIST_HELP"])
    p_peer_ls.add_argument("--json", action="store_true")
    p_peer_ls.set_defaults(func=cmd_peer_list)
    p_peer_sh = peer_sub.add_parser("show", help=STRINGS["PEER_SHOW_HELP"])
    p_peer_sh.add_argument("alias")
    p_peer_sh.set_defaults(func=cmd_peer_show)

    p_rec = sub.add_parser(
        "reconcile",
        help=STRINGS["RECONCILE_HELP"],
    )
    rec_sub = p_rec.add_subparsers(dest="reconcile_command", required=True, metavar="SUBCOMMAND")
    p_rec_insp = rec_sub.add_parser(
        "inspect",
        parents=[common],
        help=STRINGS["RECONCILE_INSPECT_HELP"],
    )
    p_rec_insp.add_argument("--entry-id", required=True, dest="entry_id")
    p_rec_insp.set_defaults(func=cmd_reconcile_inspect)
    p_rec_lin = rec_sub.add_parser(
        "lineage",
        parents=[common],
        help=STRINGS["RECONCILE_LINEAGE_HELP"],
    )
    p_rec_lin.add_argument("--entry-id", required=True, dest="entry_id")
    p_rec_lin.set_defaults(func=cmd_reconcile_lineage)
    p_rec_ex = rec_sub.add_parser(
        "explain",
        parents=[common],
        help=STRINGS["RECONCILE_EXPLAIN_HELP"],
    )
    p_rec_ex.add_argument(
        "--bundle-row",
        metavar="PATH",
        help=STRINGS["RECONCILE_BUNDLE_ROW_HELP"],
    )
    p_rec_ex.add_argument(
        "--local-host-id",
        default="explain-local",
        help=STRINGS["RECONCILE_LOCAL_HOST_ID_HELP"],
    )
    p_rec_ex.set_defaults(func=cmd_reconcile_explain)
    p_rec_vf = rec_sub.add_parser(
        "verify",
        parents=[common],
        help=STRINGS["RECONCILE_VERIFY_HELP"],
    )
    p_rec_vf.add_argument(
        "--strict-content-hash",
        action="store_true",
        help=STRINGS["RECONCILE_STRICT_CONTENT_HASH_HELP"],
    )
    p_rec_vf.set_defaults(func=cmd_reconcile_verify)

    p_sync = sub.add_parser("sync", help=STRINGS["SYNC_HELP"])
    sync_sub = p_sync.add_subparsers(dest="sync_command", required=True)
    p_sync_ex = sync_sub.add_parser(
        "export",
        parents=[common],
        help=STRINGS["SYNC_EXPORT_HELP"],
    )
    p_sync_ex.add_argument("-o", "--out", required=True)
    p_sync_ex.add_argument(
        "--peer",
        action="append",
        required=True,
        metavar="ALIAS",
        help=STRINGS["SYNC_EXPORT_PEER_HELP"],
    )
    p_sync_ex.add_argument("--domain", action="append")
    p_sync_ex.add_argument("--domains")
    p_sync_ex.add_argument("--names")
    p_sync_ex.add_argument("--tag")
    p_sync_ex.add_argument("--type", choices=["secret", "pii"])
    p_sync_ex.add_argument("--kind", choices=ENTRY_KIND_VALUES)
    p_sync_ex.add_argument("--all", action="store_true")
    p_sync_ex.add_argument("--json", action="store_true")
    p_sync_ex.set_defaults(func=cmd_sync_export)
    p_sync_im = sync_sub.add_parser(
        "import",
        parents=[common],
        help=STRINGS["SYNC_IMPORT_HELP"],
        epilog=STRINGS["SYNC_IMPORT_EPILOG"],
        formatter_class=formatter_class,
    )
    p_sync_im.add_argument(
        "file",
        help=STRINGS["SYNC_IMPORT_FILE_HELP"],
    )
    p_sync_im.add_argument(
        "--signer",
        required=True,
        metavar="ALIAS",
        help=STRINGS["SYNC_IMPORT_SIGNER_HELP"],
    )
    p_sync_im.add_argument("--domain", action="append")
    p_sync_im.add_argument("--domains")
    p_sync_im.add_argument("--dry-run", action="store_true")
    p_sync_im.add_argument("--yes", action="store_true")
    p_sync_im.add_argument(
        "--reconcile-trace",
        action="store_true",
        help=STRINGS["SYNC_IMPORT_RECONCILE_TRACE_HELP"],
    )
    p_sync_im.set_defaults(func=cmd_sync_import)
    p_sync_vf = sync_sub.add_parser("verify", help=STRINGS["SYNC_VERIFY_HELP"])
    p_sync_vf.add_argument("file")
    p_sync_vf.add_argument(
        "--try-decrypt",
        action="store_true",
        help=STRINGS["SYNC_TRY_DECRYPT_HELP"],
    )
    p_sync_vf.add_argument(
        "--signer",
        metavar="ALIAS",
        help=STRINGS["SYNC_VERIFY_SIGNER_HELP"],
    )
    p_sync_vf.set_defaults(func=cmd_sync_verify, try_decrypt=False)
    p_sync_insp = sync_sub.add_parser("inspect", help=STRINGS["SYNC_INSPECT_HELP"])
    p_sync_insp.add_argument("file")
    p_sync_insp.set_defaults(func=cmd_sync_inspect)


def add_migrate_subcommands(
    p_migrate: argparse.ArgumentParser,
    *,
    common: argparse.ArgumentParser,
    backend_choices: Iterable[str],
    formatter_class: Type[argparse.HelpFormatter] = SeckitHelpFormatter,
) -> None:
    """Register ``migrate`` leaf commands on the parser from :func:`add_migrate_parent_parser`.

    Args:
        p_migrate: The ``migrate`` parent parser instance.
        common: Shared parent parser for commands that need scope/backend flags.
        backend_choices: Backends for any migrate flags that constrain backend.
        formatter_class: Help formatter for parsers with long help/epilog text.

    Returns:
        None. Mutates *p_migrate* by adding a required ``migrate_command``
        subparser group.
    """
    backend_choices = list(backend_choices)

    migrate_sub = p_migrate.add_subparsers(dest="migrate_command", required=True)
    p_migrate_dotenv = migrate_sub.add_parser(
        "dotenv",
        parents=[common],
        help=STRINGS["MIGRATE_DOTENV_HELP"],
    )
    p_migrate_dotenv.add_argument("--dotenv", required=True)
    p_migrate_dotenv.add_argument("--archive")
    p_migrate_dotenv.add_argument("--type", choices=["secret", "pii"])
    p_migrate_dotenv.add_argument("--kind", choices=[*ENTRY_KIND_VALUES, "auto"])
    p_migrate_dotenv.add_argument("--tags")
    p_migrate_dotenv.add_argument("--dry-run", action="store_true")
    p_migrate_dotenv.add_argument("--allow-overwrite", action="store_true")
    p_migrate_dotenv.add_argument("--allow-empty", action="store_true")
    p_migrate_dotenv.add_argument("--yes", action="store_true")
    p_migrate_dotenv.add_argument(
        "--replace-with-placeholders",
        dest="replace_with_placeholders",
        action="store_true",
        default=True,
    )
    p_migrate_dotenv.add_argument(
        "--no-replace-with-placeholders",
        dest="replace_with_placeholders",
        action="store_false",
    )
    p_migrate_dotenv.set_defaults(func=cmd_migrate_dotenv)

    p_migrate_metadata = migrate_sub.add_parser(
        "metadata",
        parents=[common],
        help=STRINGS["MIGRATE_METADATA_HELP"],
    )
    p_migrate_metadata.add_argument("--dry-run", action="store_true")
    p_migrate_metadata.add_argument("--force", action="store_true")
    p_migrate_metadata.set_defaults(func=cmd_migrate_metadata)

    p_migrate_recover = migrate_sub.add_parser(
        "recover-registry",
        parents=[common],
        help=STRINGS["MIGRATE_RECOVER_REGISTRY_HELP"],
    )
    p_migrate_recover.add_argument("--dry-run", action="store_true")
    p_migrate_recover.add_argument(
        "--json",
        action="store_true",
        help=STRINGS["RECOVER_JSON_OUTPUT_HELP"],
    )
    p_migrate_recover.set_defaults(func=cmd_recover_registry)


__all__ = [
    "add_identity_peer_reconcile_sync_commands",
    "add_migrate_parent_parser",
    "add_migrate_subcommands",
]
