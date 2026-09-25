"""
tests.test_daemon_architecture

Enforce the transport-only daemon boundary as an architectural regression gate.
"""

from __future__ import annotations

import ast
import io
import json
import socket
import subprocess
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from secrets_kit.cli.commands.status import build_status_dict
from secrets_kit.daemon.client import DaemonError
from secrets_kit.daemon.control import control_message_bytes, route_frame_bytes
from secrets_kit.daemon.routing import PeerRoute, RoutingTable
from secrets_kit.daemon.server import _advertised_endpoint, _handle_request, _status_response
from secrets_kit.registry import RegistryError
from secrets_kit.runtime.status import _configured_backend, build_runtime_status
from secrets_kit.transport.routes import TransportRouteError, configured_peer_destinations


class DaemonArchitectureBoundaryTest(unittest.TestCase):
    """Prove that daemon code owns movement and not application state."""

    def test_endpoint_routes_query_closes_connection_on_success_and_failure(self) -> None:
        from secrets_kit.runtime.endpoint_routes import build_endpoint_routes

        for error in (None, ValueError("sensitive detail")):
            conn = mock.Mock()
            with self.subTest(error=error), mock.patch(
                "secrets_kit.runtime.endpoint_routes.open_sqlite_backend", return_value=conn
            ), mock.patch("secrets_kit.runtime.endpoint_routes.list_active_peer_endpoints",
                          return_value=[("peer", "tcp://127.0.0.1:41000")], side_effect=error) as query:
                if error:
                    with self.assertRaises(ValueError):
                        build_endpoint_routes()
                else:
                    self.assertEqual(build_endpoint_routes(), {"version": 1, "routes": [
                        {"peer_id": "peer", "endpoint": "tcp://127.0.0.1:41000"}]})
                query.assert_called_once_with(conn=conn)
                conn.close.assert_called_once_with()

    def test_endpoint_routes_module_fails_without_exposing_details(self) -> None:
        from secrets_kit.runtime.endpoint_routes import main

        with mock.patch("secrets_kit.runtime.endpoint_routes.open_sqlite_backend",
                        side_effect=ValueError("sensitive detail")), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(), 1)
        self.assertEqual(output.getvalue(), "")

    def test_route_refresh_preserves_subprocess_boundary_and_timeout(self) -> None:
        from secrets_kit.daemon.server import (
            RUNTIME_HANDOFF_TIMEOUT_SECONDS,
            _refresh_runtime_routes,
        )

        records = [{"peer_id": "peer", "endpoint": "tcp://127.0.0.1:41000"}]
        table = mock.Mock()
        with mock.patch("secrets_kit.daemon.server.subprocess.run", return_value=subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps({"version": 1, "routes": records}).encode()
        )) as worker:
            _refresh_runtime_routes(routing_table=table, adapter="libp2p")
        self.assertEqual(worker.call_args.args[0][1:], ["-m", "secrets_kit.runtime.endpoint_routes"])
        self.assertEqual(worker.call_args.kwargs["timeout"], RUNTIME_HANDOFF_TIMEOUT_SECONDS)
        self.assertEqual(worker.call_args.kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(worker.call_args.kwargs["stderr"], subprocess.DEVNULL)
        table.replace_from_runtime.assert_called_once_with(records=records, adapter="libp2p")

    def test_route_refresh_failure_does_not_replace_routes(self) -> None:
        from secrets_kit.daemon.server import _refresh_runtime_routes

        for result in (subprocess.CompletedProcess([], 1, stdout=b""),
                       subprocess.CompletedProcess([], 0, stdout=b"invalid"),
                       subprocess.TimeoutExpired("worker", 10), OSError("unavailable")):
            table = mock.Mock()
            with self.subTest(result=result), mock.patch(
                "secrets_kit.daemon.server.subprocess.run",
                **({"side_effect": result} if isinstance(result, Exception) else {"return_value": result}),
            ):
                _refresh_runtime_routes(routing_table=table, adapter="libp2p")
            table.replace_from_runtime.assert_not_called()

    def test_route_cli_and_module_emit_identical_contract(self) -> None:
        import argparse

        from secrets_kit.cli.commands.internal import cmd_internal_transport_routes
        from secrets_kit.runtime.endpoint_routes import main

        expected = {"version": 1, "routes": [{"peer_id": "peer", "endpoint": "tcp://127.0.0.1:41000"}]}
        with mock.patch("secrets_kit.runtime.endpoint_routes.build_endpoint_routes", return_value=expected), \
             redirect_stdout(io.StringIO()) as runtime_output:
            self.assertEqual(main(), 0)
        with mock.patch("secrets_kit.cli.commands.internal.build_endpoint_routes", return_value=expected), \
             redirect_stdout(io.StringIO()) as cli_output:
            cmd_internal_transport_routes(args=argparse.Namespace())
        self.assertEqual(runtime_output.getvalue(), cli_output.getvalue())

    def test_inbound_worker_preserves_opaque_subprocess_contract(self) -> None:
        from secrets_kit.daemon.server import RUNTIME_HANDOFF_TIMEOUT_SECONDS, _invoke_runtime

        for exit_code in (0, 1):
            with self.subTest(exit_code=exit_code), mock.patch(
                "secrets_kit.daemon.server.subprocess.run",
                return_value=subprocess.CompletedProcess(args=[], returncode=exit_code),
            ) as worker:
                self.assertEqual(_invoke_runtime(data=b"opaque-test-bytes"), exit_code == 0)
            self.assertEqual(worker.call_args.args[0][1:], ["-m", "secrets_kit.runtime.inbound_envelopes", "--stdin"])
            self.assertEqual(worker.call_args.kwargs["input"], b"opaque-test-bytes")
            self.assertEqual(worker.call_args.kwargs["timeout"], RUNTIME_HANDOFF_TIMEOUT_SECONDS)
            self.assertEqual(worker.call_args.kwargs["stdout"], subprocess.DEVNULL)
            self.assertEqual(worker.call_args.kwargs["stderr"], subprocess.DEVNULL)

    def test_inbound_module_delegates_bytes_and_fails_without_output(self) -> None:
        from secrets_kit.runtime.inbound_envelopes import main

        for error in (None, ValueError("sensitive exception detail")):
            with self.subTest(error=error), mock.patch("sys.argv", ["inbound", "--stdin"]), mock.patch(
                "sys.stdin", buffer=io.BytesIO(b"opaque-test-bytes")
            ), mock.patch("secrets_kit.runtime.inbound_envelopes.apply_inbound_transaction_envelope_bytes",
                          side_effect=error) as apply, mock.patch("sys.stdout") as stdout, mock.patch("sys.stderr") as stderr:
                self.assertEqual(main(), 0 if error is None else 1)
                apply.assert_called_once_with(data=b"opaque-test-bytes")
                stdout.write.assert_not_called()
                stderr.write.assert_not_called()

    def test_inbound_module_requires_explicit_stdin(self) -> None:
        from secrets_kit.runtime.inbound_envelopes import main

        with mock.patch("sys.argv", ["inbound"]), mock.patch(
            "secrets_kit.runtime.inbound_envelopes.apply_inbound_transaction_envelope_bytes"
        ) as apply:
            self.assertEqual(main(), 2)
            apply.assert_not_called()

    def test_status_worker_uses_runtime_module_without_full_cli_startup(self) -> None:
        from secrets_kit.daemon.server import (
            RUNTIME_HANDOFF_TIMEOUT_SECONDS,
            _invoke_runtime_status,
        )

        expected = {"version": 1, "available": True, "transport_routes": []}
        with mock.patch("secrets_kit.daemon.server.subprocess.run", return_value=subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps(expected).encode()
        )) as worker:
            self.assertEqual(_invoke_runtime_status(), expected)
        self.assertEqual(worker.call_args.args[0][1:], ["-m", "secrets_kit.runtime.status"])
        self.assertEqual(worker.call_args.kwargs["timeout"], RUNTIME_HANDOFF_TIMEOUT_SECONDS)

    def test_status_module_emits_existing_collector_result_unchanged(self) -> None:
        from secrets_kit.runtime.status import main

        for expected in ({"available": True, "transport_routes": []}, {"available": False, "error": "unavailable"}):
            with self.subTest(available=expected["available"]), mock.patch(
                "secrets_kit.runtime.status.build_runtime_status", return_value=expected
            ) as collector, redirect_stdout(io.StringIO()) as output:
                self.assertEqual(main(), 0)
            self.assertEqual(json.loads(output.getvalue()), expected)
            collector.assert_called_once_with()

    def test_runtime_status_reads_routes_on_its_existing_connection(self) -> None:
        conn = mock.Mock()
        with mock.patch("secrets_kit.runtime.status._configured_backend", return_value="sqlite"), mock.patch(
            "secrets_kit.runtime.status.open_sqlite_backend", return_value=conn
        ) as opened, mock.patch.multiple(
            "secrets_kit.runtime.status",
            _scalar=mock.Mock(return_value=1),
            read_sqlite_storage_mode=mock.Mock(return_value="encrypted"),
            _identity_status=mock.Mock(return_value=None),
            _peer_status=mock.Mock(return_value=[]),
            _lifecycle_status=mock.Mock(return_value={}),
            _synchronization_status=mock.Mock(return_value={}),
        ), mock.patch(
            "secrets_kit.runtime.status.list_active_peer_endpoints",
            return_value=[("peer", "tcp://127.0.0.1:41000")],
        ) as routes:
            result = build_runtime_status()
        opened.assert_called_once_with()
        routes.assert_called_once_with(conn=conn)
        conn.close.assert_called_once_with()
        self.assertEqual(result["transport_routes"], [{"peer_id": "peer", "endpoint": "tcp://127.0.0.1:41000"}])

    def test_unavailable_status_does_not_assert_daemon_stopped(self) -> None:
        for error in (TimeoutError("timed out"), OSError("unavailable"), DaemonError("invalid response")):
            with self.subTest(error=type(error).__name__), mock.patch(
                "secrets_kit.cli.commands.status.request_daemon_status", side_effect=error
            ):
                status = build_status_dict()
                self.assertEqual(status["overall"], "UNKNOWN")
                self.assertIsNone(status["daemon"]["running"])
                self.assertFalse(status["ok"])
                self.assertIn("daemon status unavailable", status["error"])

    def test_cli_status_uses_existing_mcp_five_second_ipc_bound(self) -> None:
        expected = {"overall": "OK", "daemon": {"running": True}}
        with mock.patch("secrets_kit.cli.commands.status.request_daemon_status", return_value=expected) as request:
            self.assertEqual(build_status_dict(), expected)
        request.assert_called_once_with(timeout=5.0)

    def test_cli_status_accepts_worker_response_after_two_seconds(self) -> None:
        """A bounded real UDS response must not be mistaken for daemon loss."""
        expected = {"overall": "OK", "daemon": {"running": True}}
        with tempfile.TemporaryDirectory() as directory, socket.socket(socket.AF_UNIX) as listener:
            path = Path(directory) / "status.sock"
            listener.bind(str(path))
            listener.listen(1)
            listener.settimeout(5.0)

            def reply() -> None:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(5.0)
                    while connection.recv(4096):
                        pass
                    time.sleep(2.2)
                    connection.sendall(json.dumps({"status": "ok", "data": expected}).encode())

            with ThreadPoolExecutor(max_workers=1) as pool, mock.patch(
                "secrets_kit.daemon.client.uds_path", return_value=path
            ):
                worker = pool.submit(reply)
                self.assertEqual(build_status_dict(), expected)
                worker.result(timeout=5.0)

    def test_status_backend_default_is_sqlite_on_all_platforms(self) -> None:
        for platform in ("darwin", "linux"):
            for defaults in ({}, {"backend": "sqlite"}, {"backend": "keychain"}):
                with self.subTest(platform=platform, defaults=defaults), mock.patch(
                    "sys.platform", platform
                ), mock.patch("secrets_kit.runtime.status.read_defaults", return_value=defaults):
                    self.assertEqual(_configured_backend(), defaults.get("backend", "sqlite"))

    def test_status_backend_read_failure_does_not_select_keychain(self) -> None:
        for error in (RegistryError("invalid defaults"), OSError("unreadable defaults")):
            with self.subTest(error=type(error).__name__), mock.patch(
                "secrets_kit.runtime.status.read_defaults", side_effect=error
            ):
                self.assertEqual(_configured_backend(), "sqlite")

    def test_daemon_modules_have_no_runtime_authority_imports(self) -> None:
        daemon_dir = Path(__file__).parents[1] / "src" / "secrets_kit" / "daemon"
        forbidden = (
            "secrets_kit.backends.sqlite",
            "secrets_kit.crypto",
            "secrets_kit.protocol",
            "secrets_kit.runtime",
            "secrets_kit.transaction_engine",
        )
        allowed_transport_protocols = {"secrets_kit.protocol.rss_auth"}
        violations: list[str] = []
        for path in sorted(daemon_dir.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                names: list[str] = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module]
                for name in names:
                    if name.startswith(forbidden) and name not in allowed_transport_protocols:
                        violations.append(f"{path.name}:{node.lineno}:{name}")
        self.assertEqual(violations, [])

    def test_common_transport_contract_has_no_adapter_library_dependencies(self) -> None:
        transport_dir = (
            Path(__file__).parents[1]
            / "src"
            / "secrets_kit"
            / "daemon"
            / "transports"
        )
        violations: list[str] = []
        for path in sorted(transport_dir.rglob("*.py")):
            source = path.read_text(encoding="utf-8")
            for forbidden in ("libp2p", "multiaddr", "socket"):
                if forbidden in source:
                    violations.append(f"{path.name}:{forbidden}")
        self.assertEqual(violations, [])

    def test_shared_routing_does_not_parse_adapter_endpoint_formats(self) -> None:
        path = (
            Path(__file__).parents[1]
            / "src"
            / "secrets_kit"
            / "daemon"
            / "routing.py"
        )
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        self.assertTrue(imported.isdisjoint({"libp2p", "multiaddr", "re", "urllib.parse"}))

    def test_transport_adapters_do_not_generate_application_identity(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src"
            / "secrets_kit"
            / "daemon"
            / "transport.py"
        ).read_text(encoding="utf-8")
        for forbidden in ("uuid.uuid", "deterministic_identifier", "local_node_identity"):
            self.assertNotIn(forbidden, source)

    def test_runtime_treats_transport_identity_as_opaque(self) -> None:
        runtime_dir = Path(__file__).parents[1] / "src" / "secrets_kit" / "runtime"
        violations: list[str] = []
        for path in sorted(runtime_dir.rglob("*.py")):
            source = path.read_text(encoding="utf-8")
            for forbidden in ("PeerID", "multiaddr", "AF_INET", "/p2p/"):
                if forbidden in source:
                    violations.append(f"{path.name}:{forbidden}")
        self.assertEqual(violations, [])

    def test_runtime_delivery_boundary_exposes_peer_identity_only(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src"
            / "secrets_kit"
            / "runtime"
            / "outbound_delivery.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("secrets_kit.transport.routes", source)
        self.assertNotIn("multiaddr", source)
        self.assertNotIn("libp2p", source)
        self.assertNotIn("host=peer", source)
        self.assertNotIn("port=peer", source)
        self.assertIn("peer_id=destination_node_id", source)

    def test_tcp_application_bytes_are_opaque_to_daemon(self) -> None:
        payload = b"\x00not-json\xfftransaction? no daemon should know"
        with mock.patch("secrets_kit.daemon.server._invoke_runtime", return_value=True) as invoke:
            response, should_stop = _handle_request(payload, transport="tcp")
        self.assertFalse(should_stop)
        self.assertEqual(json.loads(response)["response"], "delivered")
        invoke.assert_called_once_with(data=payload)

    def test_libp2p_application_bytes_are_opaque_to_daemon(self) -> None:
        payload = b"opaque-libp2p-envelope"
        with mock.patch("secrets_kit.daemon.server._invoke_runtime", return_value=True) as invoke:
            response, should_stop = _handle_request(payload, transport="libp2p")
        self.assertFalse(should_stop)
        self.assertEqual(json.loads(response)["response"], "delivered")
        invoke.assert_called_once_with(data=payload)

    def test_local_route_frame_preserves_opaque_payload(self) -> None:
        payload = b"\x00opaque\xffbytes"
        adapter = mock.Mock()
        adapter.send.return_value = mock.Mock(
            delivered=True, transport="direct_tcp", endpoint="127.0.0.1:19777", error=None
        )
        peer_id = "node:00000000-0000-0000-0000-000000000001"
        with mock.patch.dict(
            "os.environ", {"SECKIT_DAEMON_PEERS": f"{peer_id}@127.0.0.1:19777"}
        ):
            response, should_stop = _handle_request(
                route_frame_bytes(peer_id=peer_id, payload=payload),
                transport="uds",
                transport_adapter=adapter,
                routing_table=RoutingTable(
                    [PeerRoute(peer_id=peer_id, host="127.0.0.1", port=19777)]
                ),
            )
        self.assertFalse(should_stop)
        self.assertEqual(json.loads(response)["response"], "delivered")
        adapter.send.assert_called_once()
        self.assertEqual(adapter.send.call_args.kwargs["peer_id"], peer_id)

    def test_tcp_shutdown_is_rejected(self) -> None:
        response, should_stop = _handle_request(
            control_message_bytes(operation="shutdown"), transport="tcp"
        )
        self.assertFalse(should_stop)
        self.assertEqual(json.loads(response)["error"], "control_forbidden")

    def test_uds_shutdown_is_accepted(self) -> None:
        response, should_stop = _handle_request(
            control_message_bytes(operation="shutdown"), transport="uds"
        )
        self.assertTrue(should_stop)
        self.assertEqual(json.loads(response)["response"], "shutting_down")

    def test_loopback_tcp_status_is_control_plane(self) -> None:
        with mock.patch(
            "secrets_kit.daemon.server._invoke_runtime_status",
            return_value={"available": True, "peers": [], "transactions": {}, "envelopes": {}},
        ):
            response, should_stop = _handle_request(
                control_message_bytes(operation="status"), transport="tcp"
            )
        self.assertFalse(should_stop)
        payload = json.loads(response)
        self.assertEqual(payload["response"], "status")
        self.assertIn("data", payload)
        self.assertIn("daemon", payload["data"])

    def test_status_aggregates_runtime_peers_and_missing_routes(self) -> None:
        peer_id = "node:00000000-0000-0000-0000-000000000003"
        adapter = mock.Mock()
        adapter.snapshot.return_value.as_dict.return_value = {
            "transport": "direct_tcp",
            "tcp_port": 41000,
            "capabilities": {"discovery": False},
        }
        with mock.patch(
            "secrets_kit.daemon.server._invoke_runtime_status",
            return_value={
                "version": "2.0.1a0",
                "available": True,
                "backend": "sqlite",
                "identity": {"peer_id": "node:00000000-0000-0000-0000-000000000004"},
                "peers": [{"peer_id": peer_id, "name": "remote", "authorized": True}],
                "transactions": {"applied": 4},
                "envelopes": {"pending": 0, "retry_queue": 0, "currently_sending": 0},
                "synchronization": {},
            },
        ):
            response = json.loads(
                _status_response(
                    transport_adapter=adapter,
                    routing_table=RoutingTable(),
                )
            )
        self.assertEqual(response["data"]["overall"], "NO ROUTES AVAILABLE")
        self.assertEqual(response["data"]["routing"]["missing"], [peer_id])
        self.assertEqual(response["data"]["synchronization"]["applied_transactions"], 4)
        self.assertEqual(
            response["data"]["daemon"]["capabilities"], {"discovery": False}
        )

    def test_status_refreshes_routes_from_single_runtime_response(self) -> None:
        """Status uses one IPC response without exposing its route handoff field."""
        records = [{"peer_id": "node:00000000-0000-0000-0000-000000000003", "endpoint": "tcp://127.0.0.1:41000"}]
        routing = mock.Mock()
        with mock.patch(
            "secrets_kit.daemon.server._invoke_runtime_status",
            return_value={"available": True, "peers": [], "transport_routes": records},
        ) as status, mock.patch("secrets_kit.daemon.server._refresh_runtime_routes") as refresh:
            response = json.loads(_status_response(transport_adapter=None, routing_table=routing))
        status.assert_called_once_with()
        refresh.assert_not_called()
        routing.replace_from_runtime.assert_called_once_with(records=records, adapter="direct_tcp")
        self.assertNotIn("transport_routes", response["data"]["runtime"])

    def test_status_missing_route_snapshot_does_not_clear_existing_routes(self) -> None:
        for records in (None, "invalid"):
            routing = mock.Mock()
            with self.subTest(records=records), mock.patch(
                "secrets_kit.daemon.server._invoke_runtime_status",
                return_value={"available": False, "peers": [], "transport_routes": records},
            ):
                response = json.loads(_status_response(transport_adapter=None, routing_table=routing))
            routing.replace_from_runtime.assert_not_called()
            self.assertEqual(response["data"]["daemon_health"], "degraded")

    def test_status_empty_route_snapshot_clears_runtime_routes(self) -> None:
        routing = mock.Mock()
        with mock.patch(
            "secrets_kit.daemon.server._invoke_runtime_status",
            return_value={"available": True, "peers": [], "transport_routes": []},
        ):
            _status_response(transport_adapter=None, routing_table=routing)
        routing.replace_from_runtime.assert_called_once_with(records=[], adapter="direct_tcp")

    def test_host_port_alone_does_not_create_peer_identity(self) -> None:
        with mock.patch.dict(
            "os.environ", {"SECKIT_DAEMON_PEERS": "127.0.0.1:19777"}, clear=False
        ):
            with self.assertRaisesRegex(TransportRouteError, "node:<uuid>@<opaque-endpoint>"):
                configured_peer_destinations()

    def test_runtime_endpoint_refresh_replaces_route_by_peer_identity(self) -> None:
        peer_id = "node:00000000-0000-0000-0000-000000000002"
        table = RoutingTable(
            [PeerRoute(peer_id=peer_id, host="127.0.0.1", port=41001)]
        )
        table.replace_from_runtime(
            records=[{"peer_id": peer_id, "endpoint": "tcp://127.0.0.1:41002"}],
            adapter="direct_tcp",
        )
        route = table.resolve(peer_id=peer_id, adapter="direct_tcp")
        self.assertEqual(route.endpoint, "tcp://127.0.0.1:41002")

    def test_runtime_wildcard_endpoint_does_not_replace_bootstrap_route(self) -> None:
        peer_id = "node:00000000-0000-0000-0000-000000000002"
        bootstrap = PeerRoute(
            peer_id=peer_id,
            endpoint="/dns4/rss.example/tcp/4001/p2p/relay/p2p-circuit/p2p/peer",
            adapter="libp2p",
        )
        table = RoutingTable([bootstrap])
        table.replace_from_runtime(
            records=[
                {
                    "peer_id": peer_id,
                    "endpoint": "/ip4/0.0.0.0/tcp/41002/p2p/ephemeral",
                }
            ],
            adapter="libp2p",
        )
        route = table.resolve(peer_id=peer_id, adapter="libp2p")
        self.assertEqual(route.endpoint, bootstrap.endpoint)
        self.assertEqual(route.source, "bootstrap")

    def test_runtime_refresh_does_not_erase_validated_discovery_route(self) -> None:
        peer_id = "node:00000000-0000-0000-0000-000000000002"
        table = RoutingTable()
        discovered = table.install_discovered(
            peer_id=peer_id,
            endpoint="/ip4/192.0.2.2/tcp/41003/p2p/12D3KooWPeer",
            transport_peer_id="12D3KooWPeer",
            adapter="libp2p",
        )
        table.replace_from_runtime(
            records=[{"peer_id": peer_id, "endpoint": "tcp://192.0.2.2:41002"}],
            adapter="libp2p",
        )
        self.assertEqual(table.resolve(peer_id=peer_id, adapter="libp2p"), discovered)
        table.mark_unavailable(peer_id=peer_id)
        retained = table.discovered(peer_id=peer_id, adapter="libp2p")
        self.assertIsNotNone(retained)
        assert retained is not None
        self.assertEqual(retained.endpoint, discovered.endpoint)
        self.assertEqual(retained.transport_peer_id, discovered.transport_peer_id)
        self.assertFalse(retained.connected)
        self.assertFalse(retained.reachable)
        with self.assertRaises(TransportRouteError):
            table.resolve(peer_id=peer_id, adapter="libp2p")

    def test_rediscovery_replaces_route_without_duplicates(self) -> None:
        peer_id = "node:00000000-0000-0000-0000-000000000005"
        table = RoutingTable()
        table.install_discovered(
            peer_id=peer_id,
            endpoint="/ip4/192.0.2.2/tcp/41003/p2p/12D3KooWOld",
            transport_peer_id="12D3KooWOld",
            adapter="libp2p",
        )
        table.mark_unavailable(peer_id=peer_id)
        table.install_discovered(
            peer_id=peer_id,
            endpoint="/ip4/192.0.2.2/tcp/42003/p2p/12D3KooWNew",
            transport_peer_id="12D3KooWNew",
            adapter="libp2p",
        )
        self.assertEqual(table.discovered_count(), 1)
        self.assertIn(
            "/tcp/42003/",
            table.resolve(peer_id=peer_id, adapter="libp2p").endpoint,
        )
        table.mark_transport_unavailable(transport_peer_id="12D3KooWNew")
        with self.assertRaises(TransportRouteError):
            table.resolve(peer_id=peer_id, adapter="libp2p")

    def test_advertised_endpoint_is_separate_from_wildcard_bind_address(self) -> None:
        with mock.patch.dict(
            "os.environ",
            {"SECKIT_DAEMON_ADVERTISED_ENDPOINT": "tcp://192.0.2.60:41001"},
            clear=False,
        ):
            self.assertEqual(
                _advertised_endpoint(
                    active_endpoint="tcp://0.0.0.0:41001",
                    transport_host="0.0.0.0",
                    tcp_port=41001,
                ),
                "tcp://192.0.2.60:41001",
            )

    def test_runtime_endpoint_registration_excludes_ephemeral_libp2p_identity(self) -> None:
        endpoint = _advertised_endpoint(
            active_endpoint="/ip4/0.0.0.0/tcp/41001/p2p/12D3KooWEphemeral",
            transport_host="0.0.0.0",
            tcp_port=41001,
            advertised_addresses=["192.0.2.60"],
        )
        self.assertEqual(endpoint, "tcp://192.0.2.60:41001")
        self.assertNotIn("12D3KooW", endpoint)


if __name__ == "__main__":
    unittest.main()
