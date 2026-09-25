"""
tests.test_daemon_transport

Verify the daemon transport abstraction without invoking runtime or protocol
processing.
"""

from __future__ import annotations

import asyncio
import importlib.abc
import inspect
import os
import socket
import stat
import sys
import tempfile
import threading
import time
import types
import unittest
from contextlib import ExitStack, asynccontextmanager
from pathlib import Path
from unittest import mock

from secrets_kit.daemon.client import daemon_tcp_host
from secrets_kit.daemon.routing import PeerRoute, RoutingTable, TransportRouteError
from secrets_kit.daemon.transport import (
    BUILTIN_TRANSPORTS,
    DirectTCPTransport,
    LibP2PTransport,
    PyLibP2PTransport,
    TransportError,
    TransportServices,
    _create_noise_only_host,
    _invoke_runtime_binding,
    _lan_ipv4_addresses,
    _LibP2PNotifee,
    _load_or_create_libp2p_identity,
    _peerstore_endpoint,
    create_transport,
    transport_mode,
)
from secrets_kit.identifiers import deterministic_identifier
from secrets_kit.transport.routes import configured_peer_destinations


def _binding_stream(
    *,
    peer_id: str,
    connection_type: object | None = None,
    transport_addresses: list[str] | None = None,
) -> types.SimpleNamespace:
    """Build one inbound binding stream with optional public connection metadata."""
    swarm_conn = None
    if connection_type is not None or transport_addresses is not None:
        swarm_conn = mock.Mock()
        swarm_conn.get_connection_type.return_value = connection_type
        swarm_conn.get_transport_addresses.return_value = list(transport_addresses or [])
    return types.SimpleNamespace(
        muxed_conn=types.SimpleNamespace(peer_id=peer_id),
        swarm_conn=swarm_conn,
        write=mock.AsyncMock(),
        close=mock.AsyncMock(),
    )


def _services(*, handler, routing_table: RoutingTable) -> TransportServices:
    """Return neutral daemon services for adapter contract tests."""
    return TransportServices(
        frame_handler=handler,
        routing_table=routing_table,
        sign_transport_binding=lambda challenge, identity: {},
        verify_transport_binding=lambda claim, challenge, identity: "node:test",
    )


class _FakeLifecycleHost:
    """Minimal host contract for listener-generation lifecycle tests."""

    def __init__(
        self,
        *,
        listen_addr: object,
        port: int,
        exited: threading.Event | None = None,
    ) -> None:
        self.listen_addr = listen_addr
        self.port = port
        self.exited = exited
        self.network = mock.Mock()

    def get_id(self) -> str:
        return "12D3KooWLifecycleIdentity"

    def get_network(self) -> mock.Mock:
        return self.network

    def set_stream_handler(self, protocol: str, handler: object) -> None:
        del protocol, handler

    def get_addrs(self) -> list[str]:
        value = str(self.listen_addr)
        return [value.rsplit("/tcp/", 1)[0] + f"/tcp/{self.port}"]

    @asynccontextmanager
    async def run(self, *, listen_addrs: list[object]):
        self.listen_addr = listen_addrs[0]
        try:
            yield self
        finally:
            if self.exited is not None:
                self.exited.set()


class DaemonTransportTests(unittest.TestCase):
    def test_route_wait_is_woken_by_authenticated_discovery(self) -> None:
        node = deterministic_identifier(
            identifier_type="node", namespace="transport-tests", name="route-wait"
        )
        table = RoutingTable()
        self.assertFalse(table.wait_connected(peer_id=node, adapter="libp2p", timeout=0.01))
        timer = threading.Timer(
            0.02,
            lambda: table.install_discovered(
                peer_id=node,
                endpoint="/ip4/192.0.2.1/tcp/4001/p2p/remote",
                transport_peer_id="remote",
                adapter="libp2p",
            ),
        )
        timer.start()
        try:
            self.assertTrue(table.wait_connected(peer_id=node, adapter="libp2p", timeout=1))
        finally:
            timer.join()

    """Exercise transport selection and opaque direct transport behavior."""

    def _wait_until(self, predicate, *, timeout: float = 2.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.01)
        self.fail("timed out waiting for transport lifecycle condition")

    def test_disconnect_preserves_route_only_with_remaining_open_peer_connection(self) -> None:
        """A per-connection close must not imply that every peer connection closed."""
        from secrets_kit.daemon.transport import _LibP2PNotifee

        for remaining, available in (((), False), ((True,), False), ((False,), True), ((True, False), True)):
            with self.subTest(remaining=remaining):
                node = deterministic_identifier(identifier_type="node", namespace="transport-tests", name="disconnect")
                table = RoutingTable(
                    [
                        PeerRoute(
                            peer_id=node,
                            endpoint="/ip4/192.0.2.99/tcp/4001/p2p/remote",
                            adapter="libp2p",
                        )
                    ]
                )
                table.install_discovered(peer_id=node, endpoint="/ip4/192.0.2.1/tcp/4001/p2p/remote", transport_peer_id="remote", adapter="libp2p")
                adapter = LibP2PTransport(host="127.0.0.1", requested_port=0, routing_table=table)
                closed = types.SimpleNamespace(muxed_conn=types.SimpleNamespace(peer_id="remote"), is_closed=True)
                connections = [types.SimpleNamespace(muxed_conn=types.SimpleNamespace(peer_id="remote"), is_closed=value) for value in remaining]
                network = types.SimpleNamespace(get_connections=mock.Mock(return_value=connections))
                asyncio.run(_LibP2PNotifee(transport=adapter).disconnected(network, closed))
                self.assertEqual(bool(table.routes()), available)
                network.get_connections.assert_called_once_with("remote")
                events = list(adapter._routing_events)
                self.assertEqual(len(events), 0 if available else 1)
                if not available:
                    self.assertEqual(events[0]['event'], 'route_unavailable')
                    self.assertEqual(events[0]['reason_type'], 'last_connection_closed')

    def test_disconnect_does_not_create_or_reactivate_unavailable_route(self) -> None:
        """An open transport connection alone is not a fresh admitted node binding."""
        from secrets_kit.daemon.transport import _LibP2PNotifee

        table = RoutingTable()
        adapter = LibP2PTransport(host="127.0.0.1", requested_port=0, routing_table=table)
        closed = types.SimpleNamespace(muxed_conn=types.SimpleNamespace(peer_id="remote"), is_closed=True)
        live = types.SimpleNamespace(muxed_conn=types.SimpleNamespace(peer_id="remote"), is_closed=False)
        network = types.SimpleNamespace(get_connections=mock.Mock(return_value=[live]))
        callback = _LibP2PNotifee(transport=adapter)
        asyncio.run(callback.disconnected(network, closed))
        self.assertEqual(table.routes(), ())
        node = deterministic_identifier(identifier_type="node", namespace="transport-tests", name="unavailable")
        table.install_discovered(peer_id=node, endpoint="/ip4/192.0.2.1/tcp/4001/p2p/remote", transport_peer_id="remote", adapter="libp2p")
        table.mark_unavailable(peer_id=node)
        asyncio.run(callback.disconnected(network, closed))
        self.assertEqual(table.routes(), ())

    def test_runtime_rejection_keeps_route_but_network_failure_invalidates_it(self) -> None:
        from secrets_kit.daemon.transport import _RemoteDeliveryRejected

        for failure, available in ((_RemoteDeliveryRejected("rejected"), True), (OSError("disconnected"), False)):
            with self.subTest(available=available):
                node_id = deterministic_identifier(identifier_type="node", namespace="transport-tests", name="receipt")
                table = RoutingTable()
                table.install_discovered(peer_id=node_id, endpoint="/ip4/192.0.2.1/tcp/4001/p2p/remote", transport_peer_id="remote", adapter="libp2p")
                adapter = LibP2PTransport(host="0.0.0.0", requested_port=0, routing_table=table)
                adapter._host_object = mock.Mock()
                adapter._trio_token = mock.Mock()
                with mock.patch("trio.from_thread.run", side_effect=failure):
                    receipt = adapter.send(peer_id=node_id, payload=b"opaque")
                self.assertFalse(receipt.delivered)
                self.assertEqual(bool(table.routes()), available)
                events = list(adapter._routing_events)
                self.assertEqual(len(events), 0 if available else 1)
                if not available:
                    self.assertEqual(events[0]['reason_type'], 'send_exception')
                    self.assertNotIn('disconnected', str(events))
                    self.assertNotIn('opaque', str(events))

    def test_runtime_retry_reuses_only_retained_authenticated_locator(self) -> None:
        """A bounded runtime retry must transmit without exposing stale fallbacks."""
        from secrets_kit.daemon.transport import TransportReceipt

        node_id = deterministic_identifier(
            identifier_type="node",
            namespace="transport-tests",
            name="retained-retry",
        )
        retained = "/ip4/192.0.2.1/tcp/4001/p2p/authenticated"
        stale = "/ip4/192.0.2.99/tcp/4001/p2p/bootstrap"
        table = RoutingTable(
            [PeerRoute(peer_id=node_id, endpoint=stale, adapter="libp2p")]
        )
        table.install_discovered(
            peer_id=node_id,
            endpoint=retained,
            transport_peer_id="authenticated",
            adapter="libp2p",
        )
        adapter = LibP2PTransport(
            host="0.0.0.0",
            requested_port=0,
            routing_table=table,
        )
        adapter._host_object = mock.Mock()
        adapter._trio_token = mock.Mock()
        delivered = TransportReceipt(
            delivered=True,
            transport="libp2p",
            endpoint=retained,
        )
        with mock.patch(
            "trio.from_thread.run",
            side_effect=[OSError("transient timeout"), delivered],
        ) as network:
            first = adapter.send(peer_id=node_id, payload=b"opaque")
            self.assertFalse(first.delivered)
            self.assertEqual(table.routes(adapter="libp2p"), ())
            second = adapter.send(peer_id=node_id, payload=b"opaque")

        self.assertTrue(second.delivered)
        self.assertEqual(network.call_count, 2)
        self.assertEqual(
            [call.args[2] for call in network.call_args_list],
            [retained, retained],
        )
        self.assertEqual(
            table.resolve(peer_id=node_id, adapter="libp2p").endpoint,
            retained,
        )

    def test_delivery_resolution_does_not_grant_unverified_locator_retry(self) -> None:
        """Runtime/bootstrap locators cannot impersonate retained binding evidence."""
        node_id = deterministic_identifier(
            identifier_type="node",
            namespace="transport-tests",
            name="unverified-retry",
        )
        stale = "/ip4/192.0.2.99/tcp/4001/p2p/bootstrap"
        table = RoutingTable(
            [PeerRoute(peer_id=node_id, endpoint=stale, adapter="libp2p")]
        )

        with self.assertRaisesRegex(
            TransportRouteError,
            "no authenticated transport route",
        ):
            table.resolve_retained(peer_id=node_id, adapter="libp2p")

    def test_delivery_retry_reauthentication_does_not_emit_recovery_wake(self) -> None:
        """Retry-driven binding refreshes stay operational, not scheduler wakes."""
        observed: list[dict[str, object]] = []
        table = RoutingTable()
        adapter = LibP2PTransport(
            host="0.0.0.0",
            requested_port=0,
            routing_table=table,
        )
        adapter._services = TransportServices(
            frame_handler=lambda _payload, _kind: (b"{}", False),
            routing_table=table,
            sign_transport_binding=lambda _challenge, _identity: {},
            verify_transport_binding=lambda _claim, _challenge, _identity: "node:test",
            observe=observed.append,
        )
        adapter._delivery_retry_bindings.add(("remote", object()))

        adapter._record_route_available(
            direction="outbound",
            transport_peer_id="remote",
            node_id="node:test",
            addresses=["/ip4/192.0.2.1/tcp/4001"],
            endpoint="/ip4/192.0.2.1/tcp/4001/p2p/remote",
            source="libp2p_discovery",
        )
        adapter._record_route_available(
            direction="outbound",
            transport_peer_id="remote",
            node_id="node:test",
            addresses=["/ip4/192.0.2.1/tcp/4001"],
            endpoint="/ip4/192.0.2.1/tcp/4001/p2p/remote",
            source="libp2p_discovery",
        )
        adapter._record_route_available(
            direction="outbound",
            transport_peer_id="other",
            node_id="node:other",
            addresses=["/ip4/192.0.2.2/tcp/4001"],
            endpoint="/ip4/192.0.2.2/tcp/4001/p2p/other",
            source="libp2p_discovery",
        )

        self.assertEqual(
            [event["event"] for event in observed],
            ["route_installed"],
        )
        self.assertEqual(
            [event["event"] for event in adapter._routing_events],
            ["route_installed", "route_installed", "route_installed"],
        )

    def test_undelivered_receipt_event_excludes_payload_and_error(self) -> None:
        from secrets_kit.daemon.transport import TransportReceipt

        node = deterministic_identifier(identifier_type="node", namespace="transport-tests", name="undelivered")
        table = RoutingTable()
        endpoint = "/ip4/192.0.2.1/tcp/4001/p2p/remote"
        table.install_discovered(peer_id=node, endpoint=endpoint, transport_peer_id="remote", adapter="libp2p")
        adapter = LibP2PTransport(host="127.0.0.1", requested_port=0, routing_table=table)
        adapter._host_object = mock.Mock()
        adapter._trio_token = mock.Mock()
        receipt = TransportReceipt(delivered=False, transport="libp2p", endpoint=endpoint, error="sensitive-error-canary")
        with mock.patch("trio.from_thread.run", return_value=receipt):
            self.assertIs(adapter.send(peer_id=node, payload=b"sensitive-payload-canary"), receipt)
        self.assertEqual(table.routes(), ())
        event, = adapter._routing_events
        self.assertEqual(set(event), {"timestamp", "event", "node_id", "reason_type"})
        self.assertEqual(event['reason_type'], 'undelivered_receipt')
        self.assertNotIn('sensitive', str(event))

    def test_circuit_switch_records_intent_before_closing_previous_connection(self) -> None:
        import multiaddr
        from libp2p.peer.peerinfo import info_from_p2p_addr

        remote = "12D3KooWEmKKnZoADrxx55LV7zAwpDWMCgbucL1jLKcsrQ2Nms9F"
        endpoint = f"/ip4/192.0.2.1/tcp/4001/p2p/{remote}/p2p-circuit/p2p/{remote}"
        adapter = LibP2PTransport(host="127.0.0.1", requested_port=0, routing_table=RoutingTable())
        adapter._circuit_dial_endpoints[remote] = endpoint.replace('192.0.2.1', '192.0.2.2')
        host = mock.Mock()
        adapter._host_object = host

        async def close_previous(peer):
            self.assertEqual(str(peer), remote)
            self.assertEqual(adapter._routing_events[-1]['event'], 'circuit_route_switch_started')

        host.get_network.return_value.close_peer = mock.AsyncMock(side_effect=close_previous)
        host.new_stream = mock.AsyncMock(side_effect=OSError("fixture dial failure"))
        asyncio.run(adapter._bind_candidate(info_from_p2p_addr(multiaddr.Multiaddr(endpoint))))
        host.get_network.return_value.close_peer.assert_awaited_once()

    def test_rss_disconnect_retries_selected_primary_without_secondary_switch(self) -> None:
        """A disconnect may requeue the selected route but must not erase its rank."""
        import multiaddr
        from libp2p.peer.peerinfo import info_from_p2p_addr

        primary_id = "12D3KooWSQA9BTmvTuWs9qW1nSCmQTAtkbSA8fEPVgMf7KEE6F1e"
        secondary_id = "12D3KooWNzr1bzY9jCEYDen2suUuyRGc3QBZheKLJwWZuirjKFAe"
        destination_id = "12D3KooWB9zdJUBTokkUCLWgMmUVk9N5VzaQq2G6ewxJGsiGE5zD"
        endpoints = [
            f"/ip4/192.0.2.{index}/tcp/4001/p2p/{relay_id}"
            for index, relay_id in enumerate((primary_id, secondary_id), 1)
        ]
        primary, secondary = [
            info_from_p2p_addr(multiaddr.Multiaddr(endpoint))
            for endpoint in endpoints
        ]
        adapter = LibP2PTransport(
            host="127.0.0.1",
            requested_port=0,
            relay_peers=endpoints,
        )
        adapter._relay_endpoint_states.update(
            {primary_id: "authenticated", secondary_id: "authenticated"}
        )
        adapter._spawn_scope_task = mock.Mock()

        adapter._queue_rss_route_candidates(
            host=mock.Mock(),
            relay_info=primary,
            response={"peer_transport_ids": [destination_id]},
        )
        adapter._transport_disconnected(transport_peer_id=destination_id)
        adapter._spawn_scope_task.reset_mock()

        for relay in (secondary, secondary, primary, primary):
            adapter._queue_rss_route_candidates(
                host=mock.Mock(),
                relay_info=relay,
                response={"peer_transport_ids": [destination_id]},
            )

        selected = str(adapter._candidate_infos[destination_id].addrs[0])
        self.assertIn(primary_id, selected)
        self.assertEqual(adapter._relay_candidate_ranks[destination_id], 0)
        adapter._spawn_scope_task.assert_called_once()
        queued = adapter._spawn_scope_task.call_args.args[1]
        self.assertIn(primary_id, str(queued.addrs[0]))

    def test_differing_rss_callbacks_serialize_binding_and_run_latest_candidate(
        self,
    ) -> None:
        """Concurrent endpoint callbacks for one destination never overlap binds."""
        import multiaddr
        import trio
        from libp2p.peer.peerinfo import info_from_p2p_addr

        relays = (
            "12D3KooWSQA9BTmvTuWs9qW1nSCmQTAtkbSA8fEPVgMf7KEE6F1e",
            "12D3KooWNzr1bzY9jCEYDen2suUuyRGc3QBZheKLJwWZuirjKFAe",
        )
        destination = "12D3KooWB9zdJUBTokkUCLWgMmUVk9N5VzaQq2G6ewxJGsiGE5zD"
        circuit_endpoints = [
            f"/ip4/192.0.2.{index}/tcp/4001/p2p/{relay_id}"
            f"/p2p-circuit/p2p/{destination}"
            for index, relay_id in enumerate(reversed(relays), 1)
        ]
        secondary, primary = [
            info_from_p2p_addr(multiaddr.Multiaddr(endpoint))
            for endpoint in circuit_endpoints
        ]
        secondary_endpoint, primary_endpoint = circuit_endpoints
        adapter = LibP2PTransport(host="127.0.0.1", requested_port=0)
        peerstore = mock.Mock()
        network = types.SimpleNamespace(close_peer=mock.AsyncMock())
        first_started = trio.Event()
        release_first = trio.Event()
        latest_started = trio.Event()
        active = 0
        maximum_active = 0
        attempts = 0

        async def open_binding_stream(*_args) -> None:
            nonlocal active, maximum_active, attempts
            attempts += 1
            active += 1
            maximum_active = max(maximum_active, active)
            try:
                if attempts == 1:
                    first_started.set()
                    await release_first.wait()
                else:
                    latest_started.set()
                raise OSError("fixture binding stop")
            finally:
                active -= 1

        adapter._host_object = types.SimpleNamespace(
            get_peerstore=lambda: peerstore,
            get_network=lambda: network,
            new_stream=open_binding_stream,
        )

        async def exercise() -> None:
            async with trio.open_nursery() as nursery:
                adapter._scope_nursery = nursery
                adapter._relay_candidate_ranks[destination] = 1
                adapter._candidate_infos[destination] = secondary
                adapter._notified_candidate_endpoints[destination] = secondary_endpoint
                nursery.start_soon(adapter._bind_candidate, secondary)
                await first_started.wait()

                adapter._relay_candidate_ranks[destination] = 0
                adapter._candidate_infos[destination] = primary
                adapter._notified_candidate_endpoints[destination] = primary_endpoint
                nursery.start_soon(adapter._bind_candidate, primary)
                await trio.sleep(0)
                release_first.set()
                await latest_started.wait()
                adapter._scope_nursery = None

        trio.run(exercise)

        self.assertEqual(attempts, 2)
        self.assertEqual(maximum_active, 1)
        network.close_peer.assert_awaited_once_with(primary.peer_id)

    def test_inbound_binding_preserves_verified_circuit(self) -> None:
        node_id = deterministic_identifier(identifier_type="node", namespace="transport-tests", name="inbound")
        table = RoutingTable()
        circuit = "/dns4/relay.example/tcp/4001/p2p/relay/p2p-circuit/p2p/remote"
        table.install_discovered(peer_id=node_id, endpoint=circuit, transport_peer_id="remote", adapter="libp2p")
        adapter = LibP2PTransport(host="0.0.0.0", requested_port=0, routing_table=table)
        adapter._peer_id = "local"
        adapter._sign_claim = mock.AsyncMock(return_value={})
        adapter._verify_claim = mock.AsyncMock(return_value=node_id)
        stream = types.SimpleNamespace(muxed_conn=types.SimpleNamespace(peer_id="remote"), write=mock.AsyncMock(), close=mock.AsyncMock())
        import trio

        with mock.patch("secrets_kit.daemon.transport._peerstore_endpoint", return_value="/ip4/192.0.2.1/tcp/4001/p2p/remote"), mock.patch(
            "secrets_kit.daemon.transport._read_stream_frame", new=mock.AsyncMock(side_effect=[b'{"version":1,"challenge":"test"}', b'{"version":1,"claim":{}}'])
        ):
            trio.run(adapter._handle_binding_stream, stream)
        adapter._verify_claim.assert_awaited_once()
        self.assertEqual(table.resolve(peer_id=node_id, adapter="libp2p").endpoint, circuit)
        self.assertIn(b'accepted', stream.write.call_args.args[0])

    def _run_inbound_binding(
        self,
        adapter: LibP2PTransport,
        stream: types.SimpleNamespace,
        *,
        peerstore_endpoint: str | None,
    ) -> None:
        """Run one inbound exchange, optionally replacing peerstore endpoint lookup."""
        import trio

        patches = [
            mock.patch(
                "secrets_kit.daemon.transport._read_stream_frame",
                new=mock.AsyncMock(
                    side_effect=[
                        b'{"version":1,"challenge":"test"}',
                        b'{"version":1,"claim":{"signature":"remote"}}',
                    ]
                ),
            )
        ]
        if peerstore_endpoint is not None:
            patches.append(
                mock.patch(
                    "secrets_kit.daemon.transport._peerstore_endpoint",
                    return_value=peerstore_endpoint,
                )
            )
        with ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            trio.run(adapter._handle_binding_stream, stream)

    def test_inbound_binding_after_outbound_yield_reuses_selected_circuit(self) -> None:
        """A lost outbound circuit attempt must not install the LAN advertisement."""
        from libp2p.connection_types import ConnectionType

        node_id = deterministic_identifier(
            identifier_type="node",
            namespace="transport-tests",
            name="lost-outbound-race",
        )
        table = RoutingTable()
        selected = "/dns4/relay.example/tcp/24001/p2p/relay/p2p-circuit/p2p/remote"
        lan = "/ip4/192.0.2.74/tcp/40035/p2p/remote"
        observed = "/p2p/relay/p2p-circuit/p2p/remote"
        adapter = LibP2PTransport(host="0.0.0.0", requested_port=0, routing_table=table)
        adapter._peer_id = "a-local"
        adapter._circuit_dial_endpoints["remote"] = selected
        adapter._binding_states["remote"] = (selected, "rejected")
        adapter._sign_claim = mock.AsyncMock(return_value={"signature": "local"})
        adapter._verify_claim = mock.AsyncMock(return_value=node_id)
        stream = _binding_stream(
            peer_id="remote",
            connection_type=ConnectionType.RELAYED,
            transport_addresses=[observed],
        )

        self._run_inbound_binding(adapter, stream, peerstore_endpoint=lan)

        self.assertEqual(table.resolve(peer_id=node_id, adapter="libp2p").endpoint, selected)
        self.assertEqual(adapter._binding_states["remote"], (selected, "healthy"))
        self.assertIn(b"accepted", stream.write.await_args_list[-1].args[0])

    def test_inbound_binding_keeps_verified_circuit_over_another_selected_circuit(self) -> None:
        """An already verified circuit stays ahead of a later selected circuit."""
        from libp2p.connection_types import ConnectionType

        node_id = deterministic_identifier(
            identifier_type="node",
            namespace="transport-tests",
            name="verified-circuit-precedence",
        )
        table = RoutingTable()
        verified = "/dns4/relay.example/tcp/24001/p2p/relay-a/p2p-circuit/p2p/remote"
        selected = "/dns4/relay.example/tcp/24001/p2p/relay-b/p2p-circuit/p2p/remote"
        table.install_discovered(
            peer_id=node_id,
            endpoint=verified,
            transport_peer_id="remote",
            adapter="libp2p",
        )
        adapter = LibP2PTransport(host="0.0.0.0", requested_port=0, routing_table=table)
        adapter._peer_id = "a-local"
        adapter._circuit_dial_endpoints["remote"] = selected
        adapter._sign_claim = mock.AsyncMock(return_value={"signature": "local"})
        adapter._verify_claim = mock.AsyncMock(return_value=node_id)
        stream = _binding_stream(
            peer_id="remote",
            connection_type=ConnectionType.RELAYED,
            transport_addresses=["/p2p/relay-b/p2p-circuit/p2p/remote"],
        )

        self._run_inbound_binding(
            adapter,
            stream,
            peerstore_endpoint="/ip4/192.0.2.74/tcp/40035/p2p/remote",
        )

        self.assertEqual(table.resolve(peer_id=node_id, adapter="libp2p").endpoint, verified)

    def test_signed_listen_record_does_not_replace_proven_relay_route(self) -> None:
        """Identify's signed listen address replaces the peerstore, not the relay route."""
        import multiaddr
        from libp2p.connection_types import ConnectionType
        from libp2p.crypto.ed25519 import create_new_key_pair
        from libp2p.peer.id import ID
        from libp2p.peer.peerstore import PeerStore, create_signed_peer_record

        identity = create_new_key_pair()
        peer_id = ID.from_pubkey(identity.public_key)
        relay_id = ID.from_pubkey(create_new_key_pair().public_key)
        listen = multiaddr.Multiaddr("/ip4/192.0.2.74/tcp/40035")
        selected = f"/dns4/relay.example/tcp/24001/p2p/{relay_id}/p2p-circuit/p2p/{peer_id}"
        store = PeerStore()
        store.add_addrs(peer_id, [multiaddr.Multiaddr(selected)], 120)
        self.assertTrue(
            store.consume_peer_record(
                create_signed_peer_record(peer_id, [listen], identity.private_key),
                ttl=120,
            )
        )
        stored = [str(address) for address in store.addrs(peer_id)]
        self.assertEqual(stored, [str(listen)])

        node_id = deterministic_identifier(
            identifier_type="node",
            namespace="transport-tests",
            name="signed-listen-overwrite",
        )
        table = RoutingTable()
        adapter = LibP2PTransport(host="0.0.0.0", requested_port=0, routing_table=table)
        adapter._peer_id = "a-local"
        adapter._host_object = mock.Mock()
        adapter._host_object.get_peerstore.return_value = store
        adapter._circuit_dial_endpoints[str(peer_id)] = selected
        adapter._binding_states[str(peer_id)] = (selected, "rejected")
        adapter._sign_claim = mock.AsyncMock(return_value={"signature": "local"})
        adapter._verify_claim = mock.AsyncMock(return_value=node_id)
        stream = _binding_stream(
            peer_id=peer_id,
            connection_type=ConnectionType.RELAYED,
            transport_addresses=[f"/p2p/{relay_id}/p2p-circuit/p2p/{peer_id}"],
        )

        self._run_inbound_binding(adapter, stream, peerstore_endpoint=None)

        route = table.resolve(peer_id=node_id, adapter="libp2p")
        self.assertEqual(route.endpoint, selected)
        self.assertNotIn("/ip4/192.0.2.74/", route.endpoint)

    def test_noise_chain_preserves_raw_connection_metadata(self) -> None:
        """Relay, direct and unknown metadata stay exact through Noise and Mplex."""
        from libp2p.connection_types import ConnectionType
        from libp2p.crypto.ed25519 import create_new_key_pair
        from libp2p.io.abc import ReadWriteCloser
        from libp2p.network.connection.raw_connection import RawConnection
        from libp2p.peer.id import ID
        from libp2p.security.noise.io import NoiseTransportReadWriter
        from libp2p.security.secure_session import SecureSession
        from libp2p.stream_muxer.mplex.mplex import Mplex
        from multiaddr import Multiaddr
        from noise.connection import NoiseConnection

        decoy_remote = ("203.0.113.9", 4001)

        class IdleRawStream(ReadWriteCloser):
            """Socket stand-in whose endpoint must not become transport metadata."""

            def get_remote_address(self) -> tuple[str, int] | None:
                return decoy_remote

            async def read(self, n: int | None = None) -> bytes:
                return b""

            async def write(self, data: bytes) -> None:
                return None

            async def close(self) -> None:
                return None

        relay_peer = ID.from_pubkey(create_new_key_pair().public_key).to_base58()
        remote_peer = ID.from_pubkey(create_new_key_pair().public_key).to_base58()
        relayed = Multiaddr(
            f"/ip4/198.51.100.8/tcp/4001/p2p/{relay_peer}/p2p-circuit/p2p/{remote_peer}"
        )
        direct = Multiaddr("/ip4/192.0.2.10/tcp/4001")
        cases = (
            ("relay", ConnectionType.RELAYED, [relayed]),
            ("direct", ConnectionType.DIRECT, [direct]),
            ("unknown", ConnectionType.UNKNOWN, []),
        )
        for name, conn_type, addresses in cases:
            with self.subTest(connection=name):
                raw = RawConnection(
                    IdleRawStream(),
                    initiator=False,
                    connection_type=conn_type,
                    addresses=list(addresses),
                )
                writer = NoiseTransportReadWriter(
                    raw,
                    NoiseConnection.from_name(b"Noise_XX_25519_ChaChaPoly_SHA256"),
                )
                local_key = create_new_key_pair()
                remote_key = create_new_key_pair()
                session = SecureSession(
                    local_peer=ID.from_pubkey(local_key.public_key),
                    local_private_key=local_key.private_key,
                    remote_peer=ID.from_pubkey(remote_key.public_key),
                    remote_permanent_pubkey=remote_key.public_key,
                    is_initiator=True,
                    conn=writer,
                )
                muxed = Mplex(session, session.get_remote_peer())
                for layer in (writer, session, muxed):
                    self.assertIs(layer.get_connection_type(), raw.get_connection_type())
                    self.assertIs(layer.get_connection_type(), conn_type)
                    got = layer.get_transport_addresses()
                    self.assertEqual(got, raw.get_transport_addresses())
                    self.assertEqual(got, addresses)
                    self.assertEqual(
                        [str(address) for address in got],
                        [str(address) for address in addresses],
                    )
                    self.assertTrue(
                        all(decoy_remote[0] not in str(address) for address in got)
                    )
                self.assertIs(writer.conn, raw)

    def test_peerstore_address_fallback_does_not_prove_relay(self) -> None:
        """Circuit text from get_transport_addresses is not proof when type is unknown."""
        from libp2p.connection_types import ConnectionType

        node_id = deterministic_identifier(
            identifier_type="node",
            namespace="transport-tests",
            name="address-fallback",
        )
        table = RoutingTable()
        selected = "/dns4/relay.example/tcp/24001/p2p/relay/p2p-circuit/p2p/remote"
        lan = "/ip4/192.0.2.12/tcp/59719/p2p/remote"
        adapter = LibP2PTransport(host="0.0.0.0", requested_port=0, routing_table=table)
        adapter._peer_id = "a-local"
        adapter._circuit_dial_endpoints["remote"] = selected
        adapter._sign_claim = mock.AsyncMock(return_value={"signature": "local"})
        adapter._verify_claim = mock.AsyncMock(return_value=node_id)
        stream = _binding_stream(
            peer_id="remote",
            connection_type=ConnectionType.UNKNOWN,
            transport_addresses=[selected],
        )

        self._run_inbound_binding(adapter, stream, peerstore_endpoint=lan)

        self.assertEqual(table.resolve(peer_id=node_id, adapter="libp2p").endpoint, lan)

    def test_direct_inbound_does_not_switch_to_selected_circuit(self) -> None:
        """A direct connection keeps its peerstore address when a circuit was also selected."""
        from libp2p.connection_types import ConnectionType

        node_id = deterministic_identifier(
            identifier_type="node",
            namespace="transport-tests",
            name="direct-inbound",
        )
        table = RoutingTable()
        selected = "/dns4/relay.example/tcp/24001/p2p/relay/p2p-circuit/p2p/remote"
        lan = "/ip4/192.0.2.12/tcp/59719/p2p/remote"
        adapter = LibP2PTransport(host="0.0.0.0", requested_port=0, routing_table=table)
        adapter._peer_id = "a-local"
        adapter._circuit_dial_endpoints["remote"] = selected
        adapter._sign_claim = mock.AsyncMock(return_value={"signature": "local"})
        adapter._verify_claim = mock.AsyncMock(return_value=node_id)
        stream = _binding_stream(
            peer_id="remote",
            connection_type=ConnectionType.DIRECT,
            transport_addresses=[lan],
        )

        self._run_inbound_binding(adapter, stream, peerstore_endpoint=lan)

        self.assertEqual(table.resolve(peer_id=node_id, adapter="libp2p").endpoint, lan)
        self.assertEqual(adapter._binding_states["remote"], (lan, "healthy"))

    def test_missing_connection_metadata_does_not_invent_circuit(self) -> None:
        """No swarm connection metadata leaves the peerstore endpoint in place."""
        node_id = deterministic_identifier(
            identifier_type="node",
            namespace="transport-tests",
            name="missing-connection-metadata",
        )
        table = RoutingTable()
        selected = "/dns4/relay.example/tcp/24001/p2p/relay/p2p-circuit/p2p/remote"
        lan = "/ip4/192.0.2.74/tcp/40035/p2p/remote"
        adapter = LibP2PTransport(host="0.0.0.0", requested_port=0, routing_table=table)
        adapter._peer_id = "a-local"
        adapter._circuit_dial_endpoints["remote"] = selected
        adapter._sign_claim = mock.AsyncMock(return_value={"signature": "local"})
        adapter._verify_claim = mock.AsyncMock(return_value=node_id)
        stream = _binding_stream(peer_id="remote")

        self._run_inbound_binding(adapter, stream, peerstore_endpoint=lan)

        self.assertEqual(table.resolve(peer_id=node_id, adapter="libp2p").endpoint, lan)

    def test_relayed_inbound_without_selected_circuit_installs_no_route(self) -> None:
        """Relayed metadata without a selected full circuit does not invent a route."""
        from libp2p.connection_types import ConnectionType

        node_id = deterministic_identifier(
            identifier_type="node",
            namespace="transport-tests",
            name="relay-without-selection",
        )
        table = RoutingTable()
        adapter = LibP2PTransport(host="0.0.0.0", requested_port=0, routing_table=table)
        adapter._peer_id = "a-local"
        adapter._sign_claim = mock.AsyncMock(return_value={"signature": "local"})
        adapter._verify_claim = mock.AsyncMock(return_value=node_id)
        stream = _binding_stream(
            peer_id="remote",
            connection_type=ConnectionType.RELAYED,
            transport_addresses=["/p2p/relay/p2p-circuit/p2p/remote"],
        )

        self._run_inbound_binding(
            adapter,
            stream,
            peerstore_endpoint="/ip4/192.0.2.74/tcp/40035/p2p/remote",
        )

        adapter._verify_claim.assert_awaited_once()
        self.assertEqual(table.routes(adapter="libp2p"), ())
        self.assertEqual(adapter._binding_states["remote"], ("", "healthy"))
        self.assertIn(b"accepted", stream.write.await_args_list[-1].args[0])

    def test_relayed_inbound_auth_failure_installs_no_route(self) -> None:
        """Admission failure on a proven relay installs neither LAN nor circuit."""
        from libp2p.connection_types import ConnectionType

        selected = "/dns4/relay.example/tcp/24001/p2p/relay/p2p-circuit/p2p/remote"
        table = RoutingTable()
        adapter = LibP2PTransport(host="0.0.0.0", requested_port=0, routing_table=table)
        adapter._peer_id = "a-local"
        adapter._circuit_dial_endpoints["remote"] = selected
        adapter._sign_claim = mock.AsyncMock(return_value={"signature": "local"})
        adapter._verify_claim = mock.AsyncMock(
            side_effect=TransportError("transport binding peer is not admitted")
        )
        stream = _binding_stream(
            peer_id="remote",
            connection_type=ConnectionType.RELAYED,
            transport_addresses=["/p2p/relay/p2p-circuit/p2p/remote"],
        )

        self._run_inbound_binding(
            adapter,
            stream,
            peerstore_endpoint="/ip4/192.0.2.74/tcp/40035/p2p/remote",
        )

        adapter._verify_claim.assert_awaited_once()
        self.assertEqual(table.routes(adapter="libp2p"), ())
        self.assertEqual(
            adapter._binding_states["remote"],
            ("/ip4/192.0.2.74/tcp/40035/p2p/remote", "rejected"),
        )
        self.assertIn(b"rejected", stream.write.await_args_list[-1].args[0])

    def test_inbound_binding_recovers_matching_cached_state_after_validation(self) -> None:
        endpoint = "/ip4/192.0.2.1/tcp/4001/p2p/remote"
        node_id = deterministic_identifier(
            identifier_type="node",
            namespace="transport-tests",
            name="inbound-recovery",
        )
        for prior_state in ("healthy", "rejected"):
            with self.subTest(prior_state=prior_state):
                table = RoutingTable()
                adapter = LibP2PTransport(
                    host="0.0.0.0",
                    requested_port=0,
                    routing_table=table,
                )
                adapter._peer_id = "local"
                adapter._binding_states["remote"] = (endpoint, prior_state)
                adapter._sign_claim = mock.AsyncMock(
                    return_value={"signature": "local"}
                )
                adapter._verify_claim = mock.AsyncMock(return_value=node_id)
                stream = types.SimpleNamespace(
                    muxed_conn=types.SimpleNamespace(peer_id="remote"),
                    write=mock.AsyncMock(),
                    close=mock.AsyncMock(),
                )
                read = mock.AsyncMock(
                    side_effect=[
                        b'{"version":1,"challenge":"recovery"}',
                        b'{"version":1,"claim":{"signature":"remote"}}',
                    ]
                )

                import trio

                with (
                    mock.patch(
                        "secrets_kit.daemon.transport._peerstore_endpoint",
                        return_value=endpoint,
                    ),
                    mock.patch(
                        "secrets_kit.daemon.transport._read_stream_frame",
                        new=read,
                    ),
                ):
                    trio.run(adapter._handle_binding_stream, stream)

                self.assertEqual(read.await_count, 2)
                adapter._sign_claim.assert_awaited_once_with(
                    challenge="recovery",
                    transport_identity="local",
                )
                adapter._verify_claim.assert_awaited_once()
                self.assertEqual(
                    table.resolve(peer_id=node_id, adapter="libp2p").endpoint,
                    endpoint,
                )
                self.assertEqual(
                    adapter._binding_states["remote"],
                    (endpoint, "healthy"),
                )
                self.assertEqual(getattr(adapter, "_inbound_binding_owners", {}), {})
                self.assertIn(b"accepted", stream.write.await_args_list[-1].args[0])
                stream.close.assert_awaited_once()

    def test_inbound_binding_invalid_recovery_claim_installs_no_route(self) -> None:
        endpoint = "/ip4/192.0.2.1/tcp/4001/p2p/remote"
        table = RoutingTable()
        adapter = LibP2PTransport(
            host="0.0.0.0",
            requested_port=0,
            routing_table=table,
        )
        adapter._peer_id = "local"
        adapter._binding_states["remote"] = (endpoint, "rejected")
        adapter._sign_claim = mock.AsyncMock(return_value={"signature": "local"})
        adapter._verify_claim = mock.AsyncMock(
            side_effect=TransportError("invalid recovery claim")
        )
        stream = types.SimpleNamespace(
            muxed_conn=types.SimpleNamespace(peer_id="remote"),
            write=mock.AsyncMock(),
            close=mock.AsyncMock(),
        )
        read = mock.AsyncMock(
            side_effect=[
                b'{"version":1,"challenge":"recovery"}',
                b'{"version":1,"claim":{"signature":"invalid"}}',
            ]
        )

        import trio

        with (
            mock.patch(
                "secrets_kit.daemon.transport._peerstore_endpoint",
                return_value=endpoint,
            ),
            mock.patch(
                "secrets_kit.daemon.transport._read_stream_frame",
                new=read,
            ),
        ):
            trio.run(adapter._handle_binding_stream, stream)

        self.assertEqual(read.await_count, 2)
        adapter._sign_claim.assert_awaited_once()
        adapter._verify_claim.assert_awaited_once()
        self.assertEqual(table.routes(adapter="libp2p"), ())
        self.assertEqual(
            adapter._binding_states["remote"],
            (endpoint, "rejected"),
        )
        self.assertEqual(getattr(adapter, "_inbound_binding_owners", {}), {})
        self.assertIn(b"rejected", stream.write.await_args_list[-1].args[0])
        stream.close.assert_awaited_once()

    def test_unavailable_peerstore_inbound_exchange_installs_no_route(self) -> None:
        """Missing, expired, or empty peerstore evidence still completes admission."""
        import json

        import multiaddr
        import trio
        from libp2p.crypto.ed25519 import create_new_key_pair
        from libp2p.peer.id import ID
        from libp2p.peer.peerstore import PeerStore, create_signed_peer_record

        node_id = deterministic_identifier(
            identifier_type="node",
            namespace="transport-tests",
            name="unavailable-peerstore",
        )
        circuit = "/dns4/relay.example/tcp/4001/p2p/relay/p2p-circuit/p2p/remote"
        stale = multiaddr.Multiaddr("/ip4/192.0.2.8/tcp/4001")

        def exercise(
            *,
            kind: str,
            claim_identity: str | None,
            omit_claim: bool = False,
            verify_error: TransportError | None = None,
            preserve_circuit: bool = False,
        ) -> tuple[mock.AsyncMock, RoutingTable, LibP2PTransport, list[str]]:
            identity = create_new_key_pair()
            peer_id = ID.from_pubkey(identity.public_key)
            store = PeerStore()
            clock = {"now": 1_700_000_000}
            verified: list[str] = []

            def verify(claim: dict[str, object], challenge: str, identity_text: str) -> str:
                del claim, challenge
                verified.append(identity_text)
                if verify_error is not None:
                    raise verify_error
                return node_id

            table = RoutingTable()
            if preserve_circuit:
                table.install_discovered(
                    peer_id=node_id,
                    endpoint=circuit,
                    transport_peer_id=str(peer_id),
                    adapter="libp2p",
                )
            adapter = LibP2PTransport(host="127.0.0.1", requested_port=0, routing_table=table)
            adapter._peer_id = "local-transport-peer"
            adapter._services = TransportServices(
                frame_handler=lambda payload, name: (b"", None),
                routing_table=table,
                sign_transport_binding=lambda challenge, identity_text: {
                    "transport_identity": identity_text
                },
                verify_transport_binding=verify,
            )
            adapter._host_object = mock.Mock()
            adapter._host_object.get_peerstore.return_value = store
            stream = types.SimpleNamespace(
                muxed_conn=types.SimpleNamespace(peer_id=peer_id),
                write=mock.AsyncMock(),
                close=mock.AsyncMock(),
            )
            response: dict[str, object] = {"version": 1}
            if not omit_claim:
                identity_text = str(peer_id) if claim_identity is None else claim_identity
                response["claim"] = {"transport_identity": identity_text}
            frames = [
                b'{"version":1,"challenge":"inbound-challenge"}',
                json.dumps(response, separators=(",", ":")).encode(),
            ]
            with (
                mock.patch("libp2p.peer.peerdata.time.time", side_effect=lambda: clock["now"]),
                mock.patch(
                    "secrets_kit.daemon.transport._read_stream_frame",
                    new=mock.AsyncMock(side_effect=frames),
                ),
            ):
                if kind == "expired":
                    store.consume_peer_record(
                        create_signed_peer_record(peer_id, [stale], identity.private_key),
                        ttl=1,
                    )
                    store.add_addrs(peer_id, [stale], 1)
                    clock["now"] += 5
                elif kind == "empty":
                    store.add_addrs(peer_id, [], 120)
                trio.run(adapter._handle_binding_stream, stream)
                if kind == "expired":
                    self.assertEqual(store.peer_data_map[peer_id].ttl, 1)
                    self.assertTrue(store.peer_data_map[peer_id].is_expired())
                elif kind == "missing":
                    self.assertNotIn(peer_id, store.peer_data_map)
                elif kind == "empty":
                    self.assertEqual(store.addrs(peer_id), [])
            return stream.write, table, adapter, verified

        for kind in ("expired", "missing", "empty"):
            with self.subTest(kind=kind, outcome="accepted"):
                write, table, adapter, verified = exercise(
                    kind=kind,
                    claim_identity=None,
                    preserve_circuit=(kind == "expired"),
                )
                self.assertEqual(len(verified), 1)
                if kind == "expired":
                    self.assertEqual(
                        table.resolve(peer_id=node_id, adapter="libp2p").endpoint,
                        circuit,
                    )
                    self.assertEqual(len(table.routes(adapter="libp2p")), 1)
                else:
                    self.assertEqual(table.routes(adapter="libp2p"), ())
                self.assertIn(b"accepted", write.await_args_list[-1].args[0])
                self.assertTrue(
                    any(
                        event["event"] == "identity_binding_verified"
                        for event in adapter._routing_events
                    )
                )
                installed = [
                    event
                    for event in adapter._routing_events
                    if event["event"] == "route_installed"
                ]
                if kind == "expired":
                    self.assertEqual([event["endpoint"] for event in installed], [circuit])
                else:
                    self.assertEqual(installed, [])

        with self.subTest(outcome="identity-mismatch"):
            write, table, adapter, verified = exercise(
                kind="expired",
                claim_identity="12D3KooWDifferentPeer",
            )
            self.assertEqual(verified, [])
            self.assertEqual(table.routes(adapter="libp2p"), ())
            self.assertIn(b"rejected", write.await_args_list[-1].args[0])
            rejected = [
                event
                for event in adapter._routing_events
                if event["event"] == "identity_binding_rejected"
            ]
            self.assertEqual(rejected[-1]["phase"], "verify_remote_claim")
            self.assertEqual(
                rejected[-1]["reason"],
                "transport binding identity does not match connection",
            )

        with self.subTest(outcome="runtime-rejection"):
            write, table, adapter, verified = exercise(
                kind="missing",
                claim_identity=None,
                verify_error=TransportError("admission rejected"),
            )
            self.assertEqual(len(verified), 1)
            self.assertEqual(table.routes(adapter="libp2p"), ())
            self.assertIn(b"rejected", write.await_args_list[-1].args[0])
            rejected = [
                event
                for event in adapter._routing_events
                if event["event"] == "identity_binding_rejected"
            ]
            self.assertEqual(rejected[-1]["reason"], "admission rejected")

        with self.subTest(outcome="omitted-claim"):
            write, table, adapter, verified = exercise(
                kind="empty",
                claim_identity=None,
                omit_claim=True,
            )
            self.assertEqual(verified, [])
            self.assertEqual(table.routes(adapter="libp2p"), ())
            rejected = [
                event
                for event in adapter._routing_events
                if event["event"] == "identity_binding_rejected"
            ]
            self.assertEqual(rejected[-1]["phase"], "verify_remote_claim")
            self.assertEqual(rejected[-1]["reason"], "transport binding response omitted claim")
            self.assertNotEqual(
                rejected[-1]["reason"],
                "transport binding identity does not match connection",
            )

    def test_inbound_binding_stalled_initial_read_is_bounded(self) -> None:
        """A stalled inbound request cannot leave its binding inflight."""
        import trio

        endpoint = "/ip4/192.0.2.1/tcp/4001/p2p/remote"
        adapter = LibP2PTransport(
            host="0.0.0.0",
            requested_port=0,
            routing_table=RoutingTable(),
        )
        adapter._peer_id = "local"
        adapter._sign_claim = mock.AsyncMock(return_value={"signature": "local"})
        stream = types.SimpleNamespace(
            muxed_conn=types.SimpleNamespace(peer_id="remote"),
            write=mock.AsyncMock(),
            close=mock.AsyncMock(),
        )

        async def stall(_stream: object) -> bytes:
            await trio.sleep_forever()

        async def exercise() -> bool:
            with (
                mock.patch(
                    "secrets_kit.daemon.transport.RUNTIME_BINDING_TIMEOUT_SECONDS",
                    0.01,
                ),
                mock.patch(
                    "secrets_kit.daemon.transport._peerstore_endpoint",
                    return_value=endpoint,
                ),
                mock.patch(
                    "secrets_kit.daemon.transport._read_stream_frame",
                    new=stall,
                ),
            ):
                with trio.move_on_after(0.1) as watchdog:
                    await adapter._handle_binding_stream(stream)
            return bool(watchdog.cancelled_caught)

        externally_cancelled = trio.run(exercise)
        self.assertFalse(
            externally_cancelled,
            f"inbound binding stayed pending: {adapter._binding_states.get('remote')!r}",
        )
        self.assertEqual(adapter._binding_states.get("remote"), (endpoint, "rejected"))
        self.assertEqual(adapter._rejected_bindings, 0)
        self.assertEqual(getattr(adapter, "_inbound_binding_owners", {}), {})
        adapter._sign_claim.assert_not_awaited()
        stream.close.assert_awaited_once()
        events = adapter.metadata()["routing_events"]
        self.assertEqual(
            [event["phase"] for event in events if event["event"] == "identity_binding_interrupted"],
            ["read_binding_request"],
        )
        self.assertEqual(
            [
                event["direction"]
                for event in events
                if event["event"] == "identity_binding_timeout"
            ],
            ["inbound"],
        )

    def test_inbound_binding_stalled_remote_claim_is_bounded(self) -> None:
        """A stalled remote claim cannot leave its binding inflight."""
        import trio

        endpoint = "/ip4/192.0.2.1/tcp/4001/p2p/remote"
        adapter = LibP2PTransport(
            host="0.0.0.0",
            requested_port=0,
            routing_table=RoutingTable(),
        )
        adapter._peer_id = "local"
        adapter._sign_claim = mock.AsyncMock(return_value={"signature": "local"})
        adapter._verify_claim = mock.AsyncMock(return_value="node")
        stream = types.SimpleNamespace(
            muxed_conn=types.SimpleNamespace(peer_id="remote"),
            write=mock.AsyncMock(),
            close=mock.AsyncMock(),
        )
        calls = 0

        async def read_then_stall(_stream: object) -> bytes:
            nonlocal calls
            calls += 1
            if calls == 1:
                return b'{"version":1,"challenge":"stalled-claim"}'
            await trio.sleep_forever()
            return b""

        async def exercise() -> bool:
            with (
                mock.patch(
                    "secrets_kit.daemon.transport.RUNTIME_BINDING_TIMEOUT_SECONDS",
                    0.01,
                ),
                mock.patch(
                    "secrets_kit.daemon.transport._peerstore_endpoint",
                    return_value=endpoint,
                ),
                mock.patch(
                    "secrets_kit.daemon.transport._read_stream_frame",
                    new=read_then_stall,
                ),
            ):
                with trio.move_on_after(0.1) as watchdog:
                    await adapter._handle_binding_stream(stream)
            return bool(watchdog.cancelled_caught)

        externally_cancelled = trio.run(exercise)
        self.assertFalse(
            externally_cancelled,
            f"inbound binding stayed pending: {adapter._binding_states.get('remote')!r}",
        )
        self.assertEqual(adapter._binding_states.get("remote"), (endpoint, "rejected"))
        self.assertEqual(calls, 2)
        adapter._sign_claim.assert_awaited_once_with(
            challenge="stalled-claim",
            transport_identity="local",
        )
        adapter._verify_claim.assert_not_awaited()
        stream.close.assert_awaited_once()
        events = adapter.metadata()["routing_events"]
        self.assertEqual(
            [event["phase"] for event in events if event["event"] == "identity_binding_interrupted"],
            ["read_remote_claim"],
        )
        self.assertEqual(
            [
                event["direction"]
                for event in events
                if event["event"] == "identity_binding_timeout"
            ],
            ["inbound"],
        )

    def test_inbound_binding_cancellation_releases_inflight_and_propagates(self) -> None:
        """Caller cancellation still propagates after inflight state is released."""
        import trio

        endpoint = "/ip4/192.0.2.1/tcp/4001/p2p/remote"
        adapter = LibP2PTransport(
            host="0.0.0.0",
            requested_port=0,
            routing_table=RoutingTable(),
        )
        adapter._peer_id = "local"
        adapter._sign_claim = mock.AsyncMock(return_value={"signature": "local"})
        stream = types.SimpleNamespace(
            muxed_conn=types.SimpleNamespace(peer_id="remote"),
            write=mock.AsyncMock(),
            close=mock.AsyncMock(),
        )

        async def stall(_stream: object) -> bytes:
            await trio.sleep_forever()

        async def exercise() -> None:
            with (
                mock.patch(
                    "secrets_kit.daemon.transport.RUNTIME_BINDING_TIMEOUT_SECONDS",
                    5.0,
                ),
                mock.patch(
                    "secrets_kit.daemon.transport._peerstore_endpoint",
                    return_value=endpoint,
                ),
                mock.patch(
                    "secrets_kit.daemon.transport._read_stream_frame",
                    new=stall,
                ),
            ):
                with trio.move_on_after(0.05) as cancellation:
                    await adapter._handle_binding_stream(stream)
            self.assertTrue(cancellation.cancelled_caught)

        trio.run(exercise)
        self.assertEqual(adapter._binding_states.get("remote"), (endpoint, "rejected"))
        self.assertEqual(adapter._rejected_bindings, 0)
        stream.close.assert_awaited_once()
        events = adapter.metadata()["routing_events"]
        self.assertEqual(
            [event["phase"] for event in events if event["event"] == "identity_binding_interrupted"],
            ["read_binding_request"],
        )
        self.assertFalse(any(event["event"] == "identity_binding_timeout" for event in events))

    def test_cancelled_inbound_keeps_outbound_inflight_after_disconnect(self) -> None:
        """Disconnect plus a new outbound bind must survive stale inbound cleanup."""
        import trio

        endpoint = "/ip4/192.0.2.1/tcp/4001/p2p/remote"
        adapter = LibP2PTransport(
            host="0.0.0.0",
            requested_port=0,
            routing_table=RoutingTable(),
        )
        adapter._peer_id = "local"
        peer = types.SimpleNamespace(
            peer_id="remote",
            addrs=["/ip4/192.0.2.1/tcp/4001"],
        )
        read_started = trio.Event()
        connect_started = trio.Event()

        async def stall(_stream: object) -> bytes:
            read_started.set()
            await trio.sleep_forever()

        async def stalled_connect(_peer: object) -> None:
            connect_started.set()
            await trio.sleep_forever()

        adapter._host_object = types.SimpleNamespace(connect=stalled_connect)
        stream = types.SimpleNamespace(
            muxed_conn=types.SimpleNamespace(peer_id="remote"),
            write=mock.AsyncMock(),
            close=mock.AsyncMock(),
        )

        async def exercise() -> tuple[str, str]:
            with mock.patch(
                "secrets_kit.daemon.transport._peerstore_endpoint",
                return_value=endpoint,
            ):
                with mock.patch(
                    "secrets_kit.daemon.transport._read_stream_frame",
                    new=stall,
                ):
                    with trio.move_on_after(1) as guard:
                        async with trio.open_nursery() as nursery:
                            nursery.start_soon(adapter._handle_binding_stream, stream)
                            await read_started.wait()
                            adapter._transport_disconnected(transport_peer_id="remote")
                            self.assertIsNone(adapter._binding_states.get("remote"))
                            nursery.start_soon(adapter._bind_candidate, peer)
                            await connect_started.wait()
                            outbound_state = adapter._binding_states["remote"]
                            self.assertEqual(outbound_state, (endpoint, "inflight"))
                            self.assertIn("remote", adapter._binding_inflight)
                            nursery.cancel_scope.cancel()
            self.assertFalse(guard.cancelled_caught, "replacement sequence stalled")
            return outbound_state

        outbound_state = trio.run(exercise)
        # The nursery cancels the outbound attempt itself, so that attempt
        # removes the inflight tuple it still owns. The pre-cancel identity
        # check is what shows inbound cleanup left the newer outbound state.
        self.assertEqual(outbound_state, (endpoint, "inflight"))
        self.assertIsNone(adapter._binding_states.get("remote"))
        self.assertNotIn("remote", adapter._binding_inflight)
        self.assertEqual(getattr(adapter, "_inbound_binding_owners", {}), {})

    def test_successful_inbound_keeps_outbound_inflight_after_disconnect(self) -> None:
        """A late inbound success must not replace the outbound attempt's state."""
        import trio

        endpoint = "/ip4/192.0.2.1/tcp/4001/p2p/remote"
        node_id = deterministic_identifier(
            identifier_type="node",
            namespace="transport-tests",
            name="stale-inbound-success",
        )
        table = RoutingTable()
        adapter = LibP2PTransport(
            host="0.0.0.0",
            requested_port=0,
            routing_table=table,
        )
        adapter._peer_id = "local"
        peer = types.SimpleNamespace(
            peer_id="remote",
            addrs=["/ip4/192.0.2.1/tcp/4001"],
        )
        verify_ready = trio.Event()
        release_verify = trio.Event()
        connect_started = trio.Event()
        accepted = trio.Event()

        async def verify_when_released(**_kwargs: object) -> str:
            verify_ready.set()
            await release_verify.wait()
            return node_id

        async def stalled_connect(_peer: object) -> None:
            connect_started.set()
            await trio.sleep_forever()

        async def write(payload: bytes) -> None:
            if b"accepted" in payload:
                accepted.set()

        adapter._host_object = types.SimpleNamespace(connect=stalled_connect)
        adapter._sign_claim = mock.AsyncMock(return_value={"signature": "local"})
        adapter._verify_claim = verify_when_released
        stream = types.SimpleNamespace(
            muxed_conn=types.SimpleNamespace(peer_id="remote"),
            write=write,
            close=mock.AsyncMock(),
        )
        read = mock.AsyncMock(
            side_effect=[
                b'{"version":1,"challenge":"stale-success"}',
                b'{"version":1,"claim":{"signature":"remote"}}',
            ]
        )

        async def exercise() -> tuple[str, str]:
            with mock.patch(
                "secrets_kit.daemon.transport._peerstore_endpoint",
                return_value=endpoint,
            ):
                with mock.patch(
                    "secrets_kit.daemon.transport._read_stream_frame",
                    new=read,
                ):
                    with trio.move_on_after(1) as guard:
                        async with trio.open_nursery() as nursery:
                            nursery.start_soon(adapter._handle_binding_stream, stream)
                            await verify_ready.wait()
                            adapter._transport_disconnected(transport_peer_id="remote")
                            nursery.start_soon(adapter._bind_candidate, peer)
                            await connect_started.wait()
                            outbound_state = adapter._binding_states["remote"]
                            self.assertEqual(outbound_state, (endpoint, "inflight"))
                            release_verify.set()
                            await accepted.wait()
                            nursery.cancel_scope.cancel()
            self.assertFalse(guard.cancelled_caught, "replacement sequence stalled")
            return outbound_state

        outbound_state = trio.run(exercise)
        # Inbound success does not replace the outbound tuple. Cancelling the
        # nursery then cancels that outbound attempt and removes only its tuple.
        self.assertEqual(outbound_state, (endpoint, "inflight"))
        self.assertIsNone(adapter._binding_states.get("remote"))
        self.assertNotIn("remote", adapter._binding_inflight)
        self.assertEqual(
            table.resolve(peer_id=node_id, adapter="libp2p").endpoint,
            endpoint,
        )
        self.assertEqual(getattr(adapter, "_inbound_binding_owners", {}), {})

    def test_inbound_binding_blocked_close_is_bounded(self) -> None:
        """Stream close after authentication cannot stall the binding task."""
        import trio

        endpoint = "/ip4/192.0.2.1/tcp/4001/p2p/remote"
        node_id = deterministic_identifier(
            identifier_type="node",
            namespace="transport-tests",
            name="inbound-close",
        )
        table = RoutingTable()
        adapter = LibP2PTransport(
            host="0.0.0.0",
            requested_port=0,
            routing_table=table,
        )
        adapter._peer_id = "local"
        adapter._sign_claim = mock.AsyncMock(return_value={"signature": "local"})
        adapter._verify_claim = mock.AsyncMock(return_value=node_id)
        close_started = trio.Event()

        async def blocked_close() -> None:
            close_started.set()
            await trio.sleep_forever()

        stream = types.SimpleNamespace(
            muxed_conn=types.SimpleNamespace(peer_id="remote"),
            write=mock.AsyncMock(),
            close=blocked_close,
        )
        read = mock.AsyncMock(
            side_effect=[
                b'{"version":1,"challenge":"close-bound"}',
                b'{"version":1,"claim":{"signature":"remote"}}',
            ]
        )

        async def exercise() -> bool:
            with (
                mock.patch(
                    "secrets_kit.daemon.transport.TRANSPORT_IO_TIMEOUT_SECONDS",
                    0.01,
                ),
                mock.patch(
                    "secrets_kit.daemon.transport._peerstore_endpoint",
                    return_value=endpoint,
                ),
                mock.patch(
                    "secrets_kit.daemon.transport._read_stream_frame",
                    new=read,
                ),
            ):
                with trio.move_on_after(0.1) as watchdog:
                    await adapter._handle_binding_stream(stream)
            return bool(watchdog.cancelled_caught)

        externally_cancelled = trio.run(exercise)
        self.assertFalse(externally_cancelled, "stream close was not bounded")
        self.assertTrue(close_started.is_set())
        self.assertEqual(adapter._binding_states.get("remote"), (endpoint, "healthy"))
        self.assertEqual(table.resolve(peer_id=node_id, adapter="libp2p").endpoint, endpoint)
        self.assertIn(b"accepted", stream.write.await_args_list[-1].args[0])

    def test_inbound_binding_authenticates_while_outbound_pending(self) -> None:
        """Inbound authentication finishes while an outbound attempt is pending.

        Success stays installed when that outbound attempt later fails. A
        rejected inbound exchange installs no route. Cancellation leaves a
        newer tuple in place. Peer-id order does not discard the exchange.
        """
        import trio

        endpoint = "/ip4/192.0.2.1/tcp/4001/p2p/remote"
        peer = types.SimpleNamespace(
            peer_id="remote",
            addrs=["/ip4/192.0.2.1/tcp/4001"],
        )

        def adapter_for(local_id: str, node_name: str) -> tuple[str, RoutingTable, LibP2PTransport]:
            node_id = deterministic_identifier(
                identifier_type="node",
                namespace="transport-tests",
                name=node_name,
            )
            table = RoutingTable()
            adapter = LibP2PTransport(
                host="0.0.0.0",
                requested_port=0,
                routing_table=table,
            )
            adapter._peer_id = local_id
            return node_id, table, adapter

        def success_survives_outbound_failure(local_id: str) -> None:
            node_id, table, adapter = adapter_for(
                local_id,
                f"inbound-survives-outbound-{local_id}",
            )
            outbound_pending = trio.Event()
            inbound_finished = trio.Event()
            adapter._sign_claim = mock.AsyncMock(return_value={"signature": "local"})
            adapter._verify_claim = mock.AsyncMock(return_value=node_id)
            stream = types.SimpleNamespace(
                muxed_conn=types.SimpleNamespace(peer_id="remote"),
                write=mock.AsyncMock(),
                close=mock.AsyncMock(),
            )
            read = mock.AsyncMock(
                side_effect=[
                    b'{"version":1,"challenge":"inbound-survives"}',
                    b'{"version":1,"claim":{"signature":"remote"}}',
                ]
            )

            async def fail_after_inbound(_peer: object) -> None:
                outbound_pending.set()
                await inbound_finished.wait()
                raise OSError("outbound binding failed")

            adapter._host_object = types.SimpleNamespace(connect=fail_after_inbound)

            async def succeed_while_outbound_pending() -> None:
                with trio.move_on_after(1) as guard:
                    async with trio.open_nursery() as nursery:
                        nursery.start_soon(adapter._bind_candidate, peer)
                        await outbound_pending.wait()
                        self.assertEqual(
                            adapter._binding_states.get("remote"),
                            (endpoint, "inflight"),
                        )
                        self.assertIn("remote", adapter._binding_inflight)
                        await adapter._handle_binding_stream(stream)
                        self.assertEqual(
                            adapter._binding_states.get("remote"),
                            (endpoint, "healthy"),
                        )
                        inbound_finished.set()
                self.assertFalse(guard.cancelled_caught, "outbound failure sequence stalled")

            with (
                mock.patch(
                    "secrets_kit.daemon.transport._peerstore_endpoint",
                    return_value=endpoint,
                ),
                mock.patch(
                    "secrets_kit.daemon.transport._read_stream_frame",
                    new=read,
                ),
            ):
                trio.run(succeed_while_outbound_pending)
            self.assertEqual(read.await_count, 2)
            adapter._sign_claim.assert_awaited_once_with(
                challenge="inbound-survives",
                transport_identity=local_id,
            )
            adapter._verify_claim.assert_awaited_once()
            self.assertEqual(adapter._binding_states.get("remote"), (endpoint, "healthy"))
            self.assertEqual(
                table.resolve(peer_id=node_id, adapter="libp2p").endpoint,
                endpoint,
            )
            self.assertNotIn("remote", adapter._binding_inflight)
            self.assertIn(b"accepted", stream.write.await_args_list[-1].args[0])
            stream.close.assert_awaited_once()

        def rejection_installs_no_route(local_id: str) -> None:
            _node_id, table, adapter = adapter_for(
                local_id,
                f"inbound-reject-while-outbound-{local_id}",
            )
            outbound_pending = trio.Event()
            inbound_finished = trio.Event()
            adapter._sign_claim = mock.AsyncMock(return_value={"signature": "local"})
            adapter._verify_claim = mock.AsyncMock(
                side_effect=TransportError("transport binding peer is not admitted")
            )
            stream = types.SimpleNamespace(
                muxed_conn=types.SimpleNamespace(peer_id="remote"),
                write=mock.AsyncMock(),
                close=mock.AsyncMock(),
            )
            read = mock.AsyncMock(
                side_effect=[
                    b'{"version":1,"challenge":"inbound-rejected"}',
                    b'{"version":1,"claim":{"signature":"remote"}}',
                ]
            )

            async def fail_after_rejection(_peer: object) -> None:
                outbound_pending.set()
                await inbound_finished.wait()
                raise OSError("outbound binding failed")

            adapter._host_object = types.SimpleNamespace(connect=fail_after_rejection)

            async def reject_while_outbound_pending() -> None:
                with trio.move_on_after(1) as guard:
                    async with trio.open_nursery() as nursery:
                        nursery.start_soon(adapter._bind_candidate, peer)
                        await outbound_pending.wait()
                        self.assertEqual(
                            adapter._binding_states.get("remote"),
                            (endpoint, "inflight"),
                        )
                        await adapter._handle_binding_stream(stream)
                        self.assertEqual(table.routes(adapter="libp2p"), ())
                        self.assertEqual(
                            adapter._binding_states.get("remote"),
                            (endpoint, "rejected"),
                        )
                        inbound_finished.set()
                self.assertFalse(guard.cancelled_caught, "outbound rejection sequence stalled")

            with (
                mock.patch(
                    "secrets_kit.daemon.transport._peerstore_endpoint",
                    return_value=endpoint,
                ),
                mock.patch(
                    "secrets_kit.daemon.transport._read_stream_frame",
                    new=read,
                ),
            ):
                trio.run(reject_while_outbound_pending)
            adapter._verify_claim.assert_awaited_once()
            self.assertEqual(table.routes(adapter="libp2p"), ())
            self.assertEqual(adapter._binding_states.get("remote"), (endpoint, "rejected"))
            self.assertNotIn("remote", adapter._binding_inflight)
            self.assertIn(b"rejected", stream.write.await_args_list[-1].args[0])
            self.assertFalse(
                any(
                    event["event"] == "route_installed"
                    for event in adapter.metadata()["routing_events"]
                )
            )
            stream.close.assert_awaited_once()

        def cancellation_preserves_newer_state(local_id: str) -> None:
            _node_id, table, adapter = adapter_for(
                local_id,
                f"inbound-cancel-newer-{local_id}",
            )
            newer = ("/ip4/192.0.2.9/tcp/4001/p2p/remote", "healthy")
            outbound_pending = trio.Event()
            inbound_reading = trio.Event()
            adapter._sign_claim = mock.AsyncMock(return_value={"signature": "local"})

            async def stall_read(_stream: object) -> bytes:
                inbound_reading.set()
                await trio.sleep_forever()

            async def stall_connect(_peer: object) -> None:
                outbound_pending.set()
                await trio.sleep_forever()

            adapter._host_object = types.SimpleNamespace(connect=stall_connect)
            stream = types.SimpleNamespace(
                muxed_conn=types.SimpleNamespace(peer_id="remote"),
                write=mock.AsyncMock(),
                close=mock.AsyncMock(),
            )

            async def cancel_after_newer_state() -> None:
                with trio.move_on_after(1) as guard:
                    async with trio.open_nursery() as nursery:
                        nursery.start_soon(adapter._bind_candidate, peer)
                        await outbound_pending.wait()
                        outbound_state = adapter._binding_states.get("remote")
                        self.assertEqual(outbound_state, (endpoint, "inflight"))
                        nursery.start_soon(adapter._handle_binding_stream, stream)
                        await inbound_reading.wait()
                        inbound_state = adapter._binding_states.get("remote")
                        self.assertEqual(inbound_state, (endpoint, "inflight"))
                        self.assertIsNot(inbound_state, outbound_state)
                        adapter._binding_states["remote"] = newer
                        nursery.cancel_scope.cancel()
                self.assertFalse(guard.cancelled_caught, "cancellation sequence stalled")

            with (
                mock.patch(
                    "secrets_kit.daemon.transport._peerstore_endpoint",
                    return_value=endpoint,
                ),
                mock.patch(
                    "secrets_kit.daemon.transport._read_stream_frame",
                    new=stall_read,
                ),
            ):
                trio.run(cancel_after_newer_state)
            self.assertIs(adapter._binding_states.get("remote"), newer)
            self.assertEqual(table.routes(adapter="libp2p"), ())
            self.assertEqual(adapter._rejected_bindings, 0)
            self.assertNotIn("remote", adapter._binding_inflight)
            adapter._sign_claim.assert_not_awaited()
            stream.close.assert_awaited_once()

        for local_id in ("z-local", "a-local"):
            with self.subTest(case="success_survives_outbound_failure", local_id=local_id):
                success_survives_outbound_failure(local_id)
            with self.subTest(case="rejection_installs_no_route", local_id=local_id):
                rejection_installs_no_route(local_id)
            with self.subTest(case="cancellation_preserves_newer_state", local_id=local_id):
                cancellation_preserves_newer_state(local_id)

    def test_remote_handoff_failure_is_classified_without_exposing_response(self) -> None:
        from secrets_kit.daemon.transport import _RemoteDeliveryRejected

        adapter = LibP2PTransport(host="0.0.0.0", requested_port=0, routing_table=RoutingTable())
        stream = types.SimpleNamespace(
            write=mock.AsyncMock(),
            close=mock.AsyncMock(side_effect=OSError("close failed")),
            reset=mock.AsyncMock(side_effect=OSError("reset failed")),
        )
        adapter._host_object = types.SimpleNamespace(connect=mock.AsyncMock(), new_stream=mock.AsyncMock(return_value=stream))
        endpoint = "/ip4/192.0.2.1/tcp/4001/p2p/12D3KooWEmKKnZoADrxx55LV7zAwpDWMCgbucL1jLKcsrQ2Nms9F"
        with mock.patch("secrets_kit.daemon.transport._read_stream_frame", new=mock.AsyncMock(return_value=b'{"status":"error","error":"runtime_handoff_failed","detail":"do-not-expose"}')):
            with self.assertRaisesRegex(_RemoteDeliveryRejected, "^remote runtime rejected delivery$"):
                import trio

                trio.run(adapter._send_async, b"opaque", endpoint)
        stream.close.assert_awaited_once()
        stream.reset.assert_awaited_once()

    def test_send_async_bounds_each_awaited_transport_phase(self) -> None:
        import trio

        from secrets_kit.daemon.transport import TransportUnavailable

        endpoint = "/ip4/192.0.2.1/tcp/4001/p2p/12D3KooWEmKKnZoADrxx55LV7zAwpDWMCgbucL1jLKcsrQ2Nms9F"

        async def stall(*_args) -> None:
            await trio.sleep_forever()

        for phase in ("connect", "open", "write", "read"):
            with self.subTest(phase=phase):
                adapter = LibP2PTransport(
                    host="0.0.0.0",
                    requested_port=0,
                    routing_table=RoutingTable(),
                )
                stream = types.SimpleNamespace(
                    write=mock.AsyncMock(),
                    close=mock.AsyncMock(),
                )
                host = types.SimpleNamespace(
                    connect=mock.AsyncMock(),
                    new_stream=mock.AsyncMock(return_value=stream),
                )
                adapter._host_object = host
                read = mock.AsyncMock(return_value=b'{"status":"ok"}')
                if phase == "connect":
                    host.connect.side_effect = stall
                elif phase == "open":
                    host.new_stream.side_effect = stall
                elif phase == "write":
                    stream.write.side_effect = stall
                else:
                    read.side_effect = stall

                with (
                    mock.patch(
                        "secrets_kit.daemon.transport.TRANSPORT_IO_TIMEOUT_SECONDS",
                        0.01,
                    ),
                    mock.patch(
                        "secrets_kit.daemon.transport._read_stream_frame",
                        new=read,
                    ),
                    self.assertRaisesRegex(
                        TransportUnavailable,
                        "^libp2p send timed out$",
                    ),
                ):
                    trio.run(adapter._send_async, b"opaque", endpoint)

                if phase in {"write", "read"}:
                    stream.close.assert_awaited_once()
                else:
                    stream.close.assert_not_awaited()

    def test_send_async_cancellation_closes_opened_stream(self) -> None:
        import trio

        adapter = LibP2PTransport(
            host="0.0.0.0",
            requested_port=0,
            routing_table=RoutingTable(),
        )
        stream = types.SimpleNamespace(
            write=mock.AsyncMock(),
            close=mock.AsyncMock(),
        )
        adapter._host_object = types.SimpleNamespace(
            connect=mock.AsyncMock(),
            new_stream=mock.AsyncMock(return_value=stream),
        )
        endpoint = "/ip4/192.0.2.1/tcp/4001/p2p/12D3KooWEmKKnZoADrxx55LV7zAwpDWMCgbucL1jLKcsrQ2Nms9F"

        async def stalled_read(_stream) -> bytes:
            await trio.sleep_forever()

        async def cancel_send() -> None:
            with trio.move_on_after(0.01) as cancellation:
                await adapter._send_async(b"opaque", endpoint)
            self.assertTrue(cancellation.cancelled_caught)

        with (
            mock.patch(
                "secrets_kit.daemon.transport.TRANSPORT_IO_TIMEOUT_SECONDS",
                1.0,
            ),
            mock.patch(
                "secrets_kit.daemon.transport._read_stream_frame",
                new=stalled_read,
            ),
        ):
            trio.run(cancel_send)

        stream.close.assert_awaited_once()

    def test_send_async_returns_successful_receipt_and_closes_stream(self) -> None:
        import trio

        adapter = LibP2PTransport(
            host="0.0.0.0",
            requested_port=0,
            routing_table=RoutingTable(),
        )
        stream = types.SimpleNamespace(
            write=mock.AsyncMock(),
            close=mock.AsyncMock(),
        )
        host = types.SimpleNamespace(
            connect=mock.AsyncMock(),
            new_stream=mock.AsyncMock(return_value=stream),
        )
        adapter._host_object = host
        endpoint = "/ip4/192.0.2.1/tcp/4001/p2p/12D3KooWEmKKnZoADrxx55LV7zAwpDWMCgbucL1jLKcsrQ2Nms9F"
        with mock.patch(
            "secrets_kit.daemon.transport._read_stream_frame",
            new=mock.AsyncMock(return_value=b'{"status":"ok"}'),
        ):
            receipt = trio.run(adapter._send_async, b"opaque", endpoint)

        self.assertTrue(receipt.delivered)
        self.assertEqual(receipt.endpoint, endpoint)
        host.connect.assert_awaited_once()
        host.new_stream.assert_awaited_once()
        stream.write.assert_awaited_once()
        stream.close.assert_awaited_once()

    def test_peerstore_route_prefers_circuit_over_identify_listener(self) -> None:
        circuit = "/dns4/relay.example/tcp/4001/p2p/relay/p2p-circuit"
        host = mock.Mock()
        host.get_peerstore.return_value.addrs.return_value = [
            "/ip4/0.0.0.0/tcp/4000", "/ip4/192.0.2.1/tcp/4000", circuit
        ]
        self.assertEqual(
            _peerstore_endpoint(host=host, transport_peer_id="peer"),
            circuit + "/p2p/peer",
        )

    def test_peerstore_wildcards_do_not_supply_reverse_route(self) -> None:
        host = mock.Mock()
        host.get_peerstore.return_value.addrs.return_value = [
            "/ip4/0.0.0.0/tcp/4000", "/ip6/::/tcp/4000"
        ]
        self.assertEqual(_peerstore_endpoint(host=host, transport_peer_id="peer"), "")

    def test_peerstore_direct_route_still_supported(self) -> None:
        host = mock.Mock()
        host.get_peerstore.return_value.addrs.return_value = ["/ip4/192.0.2.1/tcp/4000/p2p/peer"]
        self.assertEqual(
            _peerstore_endpoint(host=host, transport_peer_id="peer"),
            "/ip4/192.0.2.1/tcp/4000/p2p/peer",
        )

    def test_expired_signed_record_replacement_keeps_selected_address_only(self) -> None:
        """A stale signed record must clear, leaving only the selected circuit."""
        import json

        import multiaddr
        import trio
        from libp2p.crypto.ed25519 import create_new_key_pair
        from libp2p.peer.id import ID
        from libp2p.peer.peerinfo import info_from_p2p_addr
        from libp2p.peer.peerstore import PeerStore, create_signed_peer_record

        identity = create_new_key_pair()
        peer_id = ID.from_pubkey(identity.public_key)
        relay_id = ID.from_pubkey(create_new_key_pair().public_key)
        stale = (
            multiaddr.Multiaddr("/ip4/192.0.2.8/tcp/4001"),
            multiaddr.Multiaddr("/ip4/198.51.100.9/tcp/9"),
        )
        selected = f"/ip4/192.0.2.1/tcp/4001/p2p/{relay_id}/p2p-circuit/p2p/{peer_id}"
        store = PeerStore()
        clock = {"now": 1_700_000_000}

        def now() -> int:
            return clock["now"]

        verified: list[str] = []
        signed: list[str] = []

        def verify(claim: dict[str, object], challenge: str, identity_text: str) -> str:
            del claim, challenge
            verified.append(identity_text)
            raise TransportError("admission rejected")

        def sign(challenge: str, identity_text: str) -> dict[str, str]:
            del challenge
            signed.append(identity_text)
            return {"transport_identity": identity_text}

        with mock.patch("libp2p.peer.peerdata.time.time", side_effect=now):
            accepted = store.consume_peer_record(
                create_signed_peer_record(peer_id, list(stale), identity.private_key),
                ttl=1,
            )
            store.add_addrs(peer_id, list(stale), 1)
            self.assertTrue(accepted)
            self.assertIn(peer_id, store.peer_record_map)
            clock["now"] += 5
            self.assertTrue(store.peer_data_map[peer_id].is_expired())
            adapter = LibP2PTransport(
                host="127.0.0.1", requested_port=0, routing_table=RoutingTable()
            )
            adapter._services = TransportServices(
                frame_handler=lambda payload, name: (b"", None),
                routing_table=adapter._routing_table,
                sign_transport_binding=sign,
                verify_transport_binding=verify,
            )
            host = mock.Mock()
            host.get_peerstore.return_value = store
            host.new_stream = mock.AsyncMock(return_value=mock.AsyncMock())
            adapter._host_object = host
            claim = json.dumps(
                {
                    "version": 1,
                    "challenge": "remote-challenge",
                    "claim": {"transport_identity": str(peer_id)},
                },
                separators=(",", ":"),
            ).encode()
            with mock.patch(
                "secrets_kit.daemon.transport._read_stream_frame",
                new=mock.AsyncMock(return_value=claim),
            ):
                trio.run(adapter._bind_candidate, info_from_p2p_addr(multiaddr.Multiaddr(selected)))
            stored = [str(address) for address in store.addrs(peer_id)]

        self.assertEqual(stored, [selected])
        self.assertNotIn(peer_id, store.peer_record_map)
        for address in stale:
            self.assertNotIn(str(address), stored)
        self.assertEqual(verified, [str(peer_id)])
        self.assertEqual(signed, [])
        self.assertEqual(adapter._routing_table.routes(adapter=adapter.name), ())
        rejected = [
            event
            for event in adapter._routing_events
            if event["event"] == "identity_binding_rejected"
        ]
        self.assertEqual(rejected[-1]["phase"], "verify_remote_claim")
        self.assertEqual(rejected[-1]["reason_type"], "TransportError")

    def test_peerstore_endpoint_normalizes_missing_and_expired_records(self) -> None:
        """Unavailable peerstore evidence stays a transport error, not a library error."""
        import multiaddr
        from libp2p.crypto.ed25519 import create_new_key_pair
        from libp2p.peer.id import ID
        from libp2p.peer.peerstore import PeerStore, create_signed_peer_record

        identity = create_new_key_pair()
        peer_id = ID.from_pubkey(identity.public_key)
        missing = mock.Mock()
        missing.get_peerstore.return_value = PeerStore()
        with self.assertRaises(TransportError) as missing_error:
            _peerstore_endpoint(host=missing, transport_peer_id=peer_id)
        self.assertEqual(str(missing_error.exception), "connected peer has no peerstore address")

        store = PeerStore()
        clock = {"now": 1_700_000_000}

        def now() -> int:
            return clock["now"]

        with mock.patch("libp2p.peer.peerdata.time.time", side_effect=now):
            store.consume_peer_record(
                create_signed_peer_record(
                    peer_id, [multiaddr.Multiaddr("/ip4/192.0.2.8/tcp/4001")], identity.private_key
                ),
                ttl=1,
            )
            store.add_addrs(peer_id, [multiaddr.Multiaddr("/ip4/192.0.2.8/tcp/4001")], 1)
            clock["now"] += 5
            expired = mock.Mock()
            expired.get_peerstore.return_value = store
            with self.assertRaises(TransportError) as expired_error:
                _peerstore_endpoint(host=expired, transport_peer_id=peer_id)
        self.assertEqual(str(expired_error.exception), "connected peer has no peerstore address")

        empty = mock.Mock()
        empty.get_peerstore.return_value.addrs.return_value = []
        with self.assertRaises(TransportError) as empty_error:
            _peerstore_endpoint(host=empty, transport_peer_id=peer_id)
        self.assertEqual(str(empty_error.exception), "connected peer has no peerstore address")

        circuit = "/dns4/relay.example/tcp/4001/p2p/relay/p2p-circuit"
        preserved = mock.Mock()
        preserved.get_peerstore.return_value.addrs.return_value = [
            "/ip4/0.0.0.0/tcp/4000",
            circuit,
        ]
        self.assertEqual(
            _peerstore_endpoint(host=preserved, transport_peer_id="peer"),
            circuit + "/p2p/peer",
        )
        wildcards = mock.Mock()
        wildcards.get_peerstore.return_value.addrs.return_value = ["/ip6/::/tcp/4000"]
        self.assertEqual(_peerstore_endpoint(host=wildcards, transport_peer_id="peer"), "")

    def test_expired_peerstore_connection_notification_is_contained(self) -> None:
        """A peerstore miss must not fail libp2p's own connection notification."""
        import multiaddr
        import trio
        from libp2p.crypto.ed25519 import create_new_key_pair
        from libp2p.network.swarm import Swarm
        from libp2p.peer.id import ID
        from libp2p.peer.peerstore import PeerStore, create_signed_peer_record

        identity = create_new_key_pair()
        peer_id = ID.from_pubkey(identity.public_key)
        expired = PeerStore()
        clock = {"now": 1_700_000_000}

        def now() -> int:
            return clock["now"]

        with mock.patch("libp2p.peer.peerdata.time.time", side_effect=now):
            expired.consume_peer_record(
                create_signed_peer_record(
                    peer_id, [multiaddr.Multiaddr("/ip4/192.0.2.8/tcp/4001")], identity.private_key
                ),
                ttl=1,
            )
            expired.add_addrs(peer_id, [multiaddr.Multiaddr("/ip4/192.0.2.8/tcp/4001")], 1)
            clock["now"] += 5
            stores: tuple[PeerStore, ...] = (PeerStore(), expired)
            for store in stores:
                adapter = LibP2PTransport(
                    host="127.0.0.1", requested_port=0, routing_table=RoutingTable()
                )
                adapter._peer_id = "12D3KooWLocalDaemonIdentity"
                adapter._host_object = mock.Mock()
                adapter._host_object.get_peerstore.return_value = store
                connection = mock.Mock()
                connection.muxed_conn.peer_id = peer_id
                trio.run(
                    Swarm.notify_connected,
                    mock.Mock(notifees=(_LibP2PNotifee(transport=adapter),)),
                    connection,
                )
                self.assertEqual(adapter._routing_table.routes(adapter=adapter.name), ())
                self.assertFalse(
                    any(
                        event["event"] == "identity_binding_started"
                        for event in adapter._routing_events
                    )
                )

    def test_default_transport_mode_is_libp2p(self) -> None:
        previous = os.environ.pop("SECKIT_DAEMON_TRANSPORT", None)
        try:
            self.assertEqual(transport_mode(), "libp2p")
        finally:
            if previous is not None:
                os.environ["SECKIT_DAEMON_TRANSPORT"] = previous

    def test_libp2p_identity_is_stable_in_protected_runtime_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with mock.patch.dict(
                os.environ, {"SECKIT_DAEMON_RUNTIME_DIR": temp_dir}, clear=False
            ):
                first = _load_or_create_libp2p_identity()
                second = _load_or_create_libp2p_identity()
            key_path = Path(temp_dir) / "libp2p-identity.key"
            self.assertEqual(first.private_key.to_bytes(), second.private_key.to_bytes())
            self.assertEqual(stat.S_IMODE(key_path.stat().st_mode), 0o600)
            self.assertEqual(len(key_path.read_bytes()), 32)

    def test_builtin_registry_is_bounded_and_stable(self) -> None:
        self.assertEqual(BUILTIN_TRANSPORTS.names(), ("direct_tcp", "libp2p"))
        for adapter_type in (DirectTCPTransport, PyLibP2PTransport):
            self.assertEqual(
                tuple(inspect.signature(adapter_type.send).parameters),
                ("self", "peer_id", "payload"),
            )
            self.assertTrue(callable(adapter_type.snapshot))

    def test_managed_start_without_override_retains_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with mock.patch.dict(os.environ, {}, clear=True), mock.patch(
                "secrets_kit.daemon.client.Path.home", return_value=Path(temp_dir)
            ):
                first = _load_or_create_libp2p_identity()
                second = _load_or_create_libp2p_identity()
            self.assertEqual(first.private_key.to_bytes(), second.private_key.to_bytes())
            key = Path(temp_dir) / ".local/share/seckit/runtime/libp2p-identity.key"
            self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)

    def test_timed_out_outbound_binding_attempts_same_endpoint_again(self) -> None:
        """A timed-out attempt is not an authentication latch.

        Each timeout removes that attempt's inflight tuple, so the same
        endpoint is dialed again. Rejection suppression is covered separately.
        """
        import trio

        adapter = LibP2PTransport(host="0.0.0.0", requested_port=0, routing_table=RoutingTable())
        async def stalled_connect(_peer):
            async with trio.open_nursery() as nursery:
                nursery.start_soon(trio.sleep_forever)
        connect = mock.AsyncMock(side_effect=stalled_connect)
        adapter._host_object = types.SimpleNamespace(connect=connect)
        peer = types.SimpleNamespace(peer_id="remote", addrs=["/ip4/192.0.2.1/tcp/4001"])
        with mock.patch("secrets_kit.daemon.transport.RUNTIME_BINDING_TIMEOUT_SECONDS", 0.01):
            trio.run(adapter._connect_and_bind, peer)
            self.assertNotIn("remote", adapter._binding_inflight)
            self.assertIsNone(adapter._binding_states.get("remote"))
            trio.run(adapter._connect_and_bind, peer)
            adapter._transport_disconnected(transport_peer_id="remote")
            trio.run(adapter._connect_and_bind, peer)
        self.assertEqual(connect.await_count, 3)
        self.assertEqual(adapter._routing_table.discovered_count(), 0)
        events = adapter.metadata()["routing_events"]
        self.assertEqual(sum(e["event"] == "identity_binding_timeout" for e in events), 3)
        cancelled = [e for e in events if e["event"] == "identity_binding_interrupted"]
        self.assertEqual([e["phase"] for e in cancelled], ["connect", "connect", "connect"])

    def test_cancelled_outbound_attempt_retries_without_dropping_newer_state(self) -> None:
        """Cancellation clears only the cancelled attempt and leaves a newer tuple."""
        import trio

        endpoint = "/ip4/192.0.2.1/tcp/4001/p2p/remote"
        newer = ("/ip4/192.0.2.9/tcp/4001/p2p/remote", "inflight")
        adapter = LibP2PTransport(
            host="0.0.0.0",
            requested_port=0,
            routing_table=RoutingTable(),
        )
        started = trio.Event()

        async def stall_then_replace(_peer: object) -> None:
            started.set()
            adapter._binding_states["remote"] = newer
            await trio.sleep_forever()

        connect = mock.AsyncMock(side_effect=stall_then_replace)
        adapter._host_object = types.SimpleNamespace(connect=connect)
        peer = types.SimpleNamespace(peer_id="remote", addrs=["/ip4/192.0.2.1/tcp/4001"])

        async def cancel_replaced_attempt() -> None:
            async with trio.open_nursery() as nursery:
                nursery.start_soon(adapter._bind_candidate, peer)
                await started.wait()
                nursery.cancel_scope.cancel()

        trio.run(cancel_replaced_attempt)
        self.assertIs(adapter._binding_states.get("remote"), newer)
        self.assertNotIn("remote", adapter._binding_inflight)
        self.assertEqual(connect.await_count, 1)

        retry_started = trio.Event()

        async def stall_until_cancelled(_peer: object) -> None:
            retry_started.set()
            await trio.sleep_forever()

        async def cancel_owned_attempt() -> None:
            async with trio.open_nursery() as nursery:
                nursery.start_soon(adapter._bind_candidate, peer)
                await retry_started.wait()
                self.assertEqual(adapter._binding_states.get("remote"), (endpoint, "inflight"))
                nursery.cancel_scope.cancel()

        connect.side_effect = stall_until_cancelled
        adapter._binding_states.pop("remote", None)
        trio.run(cancel_owned_attempt)
        self.assertIsNone(adapter._binding_states.get("remote"))
        self.assertNotIn("remote", adapter._binding_inflight)
        self.assertEqual(connect.await_count, 2)

        again = trio.Event()

        async def stall_again(_peer: object) -> None:
            again.set()
            await trio.sleep_forever()

        async def retry_same_endpoint() -> None:
            async with trio.open_nursery() as nursery:
                nursery.start_soon(adapter._bind_candidate, peer)
                await again.wait()
                self.assertEqual(adapter._binding_states.get("remote"), (endpoint, "inflight"))
                nursery.cancel_scope.cancel()

        connect.side_effect = stall_again
        trio.run(retry_same_endpoint)
        self.assertEqual(connect.await_count, 3)
        self.assertIsNone(adapter._binding_states.get("remote"))

        connect.side_effect = OSError("admission rejected")
        trio.run(adapter._bind_candidate, peer)
        trio.run(adapter._bind_candidate, peer)
        self.assertEqual(connect.await_count, 4)
        self.assertEqual(adapter._binding_states.get("remote"), (endpoint, "rejected"))
        self.assertNotIn("remote", adapter._binding_inflight)

    def test_cancelled_rss_notification_allows_later_queue(self) -> None:
        """Cancellation forgets only the matching RSS notification.

        The next identical RSS response queues one bind. A duplicate of that
        response coalesces. A changed notification and a newer binding tuple
        stay cached, and this cleanup does not start another attempt.
        """
        import multiaddr
        import trio
        from libp2p.peer.peerinfo import info_from_p2p_addr

        relay_id = "12D3KooWSQA9BTmvTuWs9qW1nSCmQTAtkbSA8fEPVgMf7KEE6F1e"
        destination_id = "12D3KooWB9zdJUBTokkUCLWgMmUVk9N5VzaQq2G6ewxJGsiGE5zD"
        relay_endpoint = f"/ip4/192.0.2.1/tcp/4001/p2p/{relay_id}"
        relay = info_from_p2p_addr(multiaddr.Multiaddr(relay_endpoint))
        response = {"peer_transport_ids": [destination_id]}
        adapter = LibP2PTransport(
            host="127.0.0.1",
            requested_port=0,
            relay_peers=[relay_endpoint],
        )
        adapter._peer_id = "12D3KooWLocalDaemonIdentity"
        peerstore = mock.Mock()

        def host_for(stream: object) -> types.SimpleNamespace:
            return types.SimpleNamespace(
                get_peerstore=lambda: peerstore,
                get_network=lambda: types.SimpleNamespace(close_peer=mock.AsyncMock()),
                new_stream=stream,
            )

        def outbound_starts() -> int:
            return sum(
                event["event"] == "identity_binding_started"
                and event.get("direction") == "outbound"
                for event in adapter._routing_events
            )

        started = trio.Event()

        async def stall_stream(*_args: object) -> None:
            started.set()
            await trio.sleep_forever()

        adapter._host_object = host_for(stall_stream)

        async def queue_and_cancel() -> str:
            async with trio.open_nursery() as nursery:
                adapter._scope_nursery = nursery
                adapter._queue_rss_route_candidates(
                    host=adapter._host_object,
                    relay_info=relay,
                    response=response,
                )
                await started.wait()
                cached_endpoint = adapter._notified_candidate_endpoints[destination_id]
                nursery.cancel_scope.cancel()
            adapter._scope_nursery = None
            return cached_endpoint

        cached = trio.run(queue_and_cancel)
        original_candidate = adapter._candidate_infos[destination_id]
        self.assertEqual(outbound_starts(), 1)
        self.assertIsNone(adapter._binding_states.get(destination_id))
        self.assertNotIn(destination_id, adapter._notified_candidate_endpoints)
        self.assertIs(adapter._candidate_infos[destination_id], original_candidate)

        attempts = 0

        async def reject_stream(*_args: object) -> None:
            nonlocal attempts
            attempts += 1
            raise TransportError("peer is not admitted")

        adapter._host_object = host_for(reject_stream)

        async def requeue_and_coalesce() -> None:
            async with trio.open_nursery() as nursery:
                adapter._scope_nursery = nursery
                adapter._queue_rss_route_candidates(
                    host=adapter._host_object,
                    relay_info=relay,
                    response=response,
                )
                adapter._queue_rss_route_candidates(
                    host=adapter._host_object,
                    relay_info=relay,
                    response=response,
                )
            adapter._scope_nursery = None

        trio.run(requeue_and_coalesce)
        self.assertEqual(attempts, 1)
        self.assertEqual(outbound_starts(), 2)
        self.assertEqual(adapter._notified_candidate_endpoints[destination_id], cached)
        self.assertEqual(adapter._binding_states[destination_id][1], "rejected")

        adapter._binding_states.pop(destination_id, None)
        adapter._notified_candidate_endpoints.pop(destination_id, None)
        retarget_started = trio.Event()

        async def stall_for_retarget(*_args: object) -> None:
            retarget_started.set()
            await trio.sleep_forever()

        adapter._host_object = host_for(stall_for_retarget)
        replacement = f"{cached}/replaced"

        async def cancel_changed_notification() -> None:
            async with trio.open_nursery() as nursery:
                adapter._scope_nursery = nursery
                adapter._queue_rss_route_candidates(
                    host=adapter._host_object,
                    relay_info=relay,
                    response=response,
                )
                await retarget_started.wait()
                queued_candidate = adapter._candidate_infos[destination_id]
                adapter._notified_candidate_endpoints[destination_id] = replacement
                nursery.cancel_scope.cancel()
            adapter._scope_nursery = None
            return queued_candidate

        queued_candidate = trio.run(cancel_changed_notification)
        self.assertIsNone(adapter._binding_states.get(destination_id))
        self.assertEqual(
            adapter._notified_candidate_endpoints.get(destination_id),
            replacement,
        )
        self.assertIs(adapter._candidate_infos.get(destination_id), queued_candidate)
        self.assertEqual(outbound_starts(), 3)

        newer = (replacement, "healthy")
        newer_started = trio.Event()

        async def stall_for_newer_state(*_args: object) -> None:
            newer_started.set()
            await trio.sleep_forever()

        adapter._host_object = host_for(stall_for_newer_state)

        async def cancel_newer_state() -> None:
            async with trio.open_nursery() as nursery:
                adapter._scope_nursery = nursery
                adapter._queue_rss_route_candidates(
                    host=adapter._host_object,
                    relay_info=relay,
                    response=response,
                )
                await newer_started.wait()
                queued_candidate = adapter._candidate_infos[destination_id]
                adapter._binding_states[destination_id] = newer
                nursery.cancel_scope.cancel()
            adapter._scope_nursery = None
            return queued_candidate

        starts_before_newer = outbound_starts()
        queued_candidate = trio.run(cancel_newer_state)
        self.assertIs(adapter._binding_states.get(destination_id), newer)
        self.assertEqual(adapter._notified_candidate_endpoints.get(destination_id), cached)
        self.assertIs(adapter._candidate_infos.get(destination_id), queued_candidate)
        self.assertEqual(outbound_starts(), starts_before_newer + 1)

    def test_admission_change_retries_rejected_live_candidate_once(self) -> None:
        import trio

        node_id = deterministic_identifier(
            identifier_type="node",
            namespace="transport-tests",
            name="newly-admitted",
        )
        peer = types.SimpleNamespace(
            peer_id="12D3KooWRejectedUntilAdmission",
            addrs=["/ip4/192.0.2.1/tcp/4001"],
        )
        stream = types.SimpleNamespace(
            write=mock.AsyncMock(),
            close=mock.AsyncMock(),
        )
        peerstore = types.SimpleNamespace(
            get_protocols=lambda _peer_id: ["/seckit/identity-binding/1.0.0"]
        )
        host = types.SimpleNamespace(
            connect=mock.AsyncMock(),
            new_stream=mock.AsyncMock(return_value=stream),
            get_peerstore=lambda: peerstore,
        )
        adapter = LibP2PTransport(
            host="0.0.0.0",
            requested_port=0,
            routing_table=RoutingTable(),
        )
        adapter._host_object = host
        adapter._peer_id = "12D3KooWLocal"
        adapter._candidate_infos[str(peer.peer_id)] = peer
        adapter._verify_claim = mock.AsyncMock(
            side_effect=[TransportError("peer is not admitted"), node_id]
        )
        adapter._sign_claim = mock.AsyncMock(return_value={"signature": "opaque"})

        first_response = b'{"version":1,"challenge":"remote-challenge","claim":{}}'
        with mock.patch(
            "secrets_kit.daemon.transport._read_stream_frame",
            new=mock.AsyncMock(return_value=first_response),
        ):
            trio.run(adapter._connect_and_bind, peer)
        self.assertEqual(
            adapter._binding_states[str(peer.peer_id)][1],
            "rejected",
        )
        self.assertEqual(host.connect.await_count, 1)
        trio.run(adapter._connect_and_bind, peer)
        self.assertEqual(host.connect.await_count, 1)

        scheduled: list[object] = []

        class DeferredToken:
            def run_sync_soon(self, callback) -> None:
                scheduled.append(callback)

        spawned: list[tuple[object, object]] = []
        adapter._trio_token = DeferredToken()
        adapter._spawn_scope_task = lambda callback, candidate: spawned.append(
            (callback, candidate)
        )

        adapter.admission_changed()
        adapter.admission_changed()
        self.assertEqual(len(scheduled), 1)
        scheduled.pop()()
        self.assertEqual(len(spawned), 1)

        callback, candidate = spawned.pop()
        with mock.patch(
            "secrets_kit.daemon.transport._read_stream_frame",
            new=mock.AsyncMock(
                side_effect=[
                    first_response,
                    b'{"version":1,"status":"accepted"}',
                ]
            ),
        ):
            trio.run(callback, candidate)

        self.assertEqual(adapter._verify_claim.await_count, 2)
        self.assertEqual(host.connect.await_count, 2)
        route = adapter._routing_table.resolve(
            peer_id=node_id,
            adapter="libp2p",
        )
        self.assertEqual(route.transport_peer_id, str(peer.peer_id))
        adapter.admission_changed()
        self.assertEqual(scheduled, [])

    def test_runtime_override_and_detached_override_share_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with mock.patch.dict(os.environ, {"SECKIT_RUNTIME_DIR": temp_dir}, clear=True):
                first = _load_or_create_libp2p_identity()
            with mock.patch.dict(os.environ, {"SECKIT_DAEMON_RUNTIME_DIR": temp_dir}, clear=True):
                second = _load_or_create_libp2p_identity()
            self.assertEqual(first.private_key.to_bytes(), second.private_key.to_bytes())

    def test_unknown_transport_fails_closed(self) -> None:
        with mock.patch.dict(
            os.environ, {"SECKIT_DAEMON_TRANSPORT": "unreviewed_plugin"}, clear=False
        ):
            with self.assertRaisesRegex(TransportError, "registered adapter"):
                transport_mode()

    def test_py_libp2p_host_selects_noise_only_without_fastecdsa(self) -> None:
        observed: dict[str, object] = {}
        identity = object()
        noise_private_key = object()

        class RejectFastecdsa(importlib.abc.MetaPathFinder):
            def find_spec(self, fullname, path=None, target=None):
                if fullname == "fastecdsa" or fullname.startswith("fastecdsa."):
                    raise AssertionError(f"unexpected dependency import: {fullname}")
                return None

        class FakeNoiseTransport:
            def __init__(self, key_pair, *, noise_privkey) -> None:
                observed["noise_identity"] = key_pair
                observed["noise_private_key"] = noise_privkey

        class FakeMplexStream:
            def _read_return_when_blocked(self) -> bytearray:
                return bytearray(b"coalesced")

        libp2p_module = types.ModuleType("libp2p")
        libp2p_module.generate_new_ed25519_identity = lambda: identity

        def new_host(**kwargs):
            observed["host_options"] = kwargs
            return "noise-host"

        libp2p_module.new_host = new_host
        x25519_module = types.ModuleType("libp2p.crypto.x25519")
        x25519_module.create_new_key_pair = lambda: types.SimpleNamespace(
            private_key=noise_private_key
        )
        custom_types_module = types.ModuleType("libp2p.custom_types")
        custom_types_module.TProtocol = lambda value: value
        network_config_module = types.ModuleType("libp2p.network.config")
        network_config_module.ConnectionConfig = lambda **values: types.SimpleNamespace(**values)
        noise_module = types.ModuleType("libp2p.security.noise.transport")
        noise_module.PROTOCOL_ID = "/noise"
        noise_module.Transport = FakeNoiseTransport
        mplex_stream_module = types.ModuleType(
            "libp2p.stream_muxer.mplex.mplex_stream"
        )
        mplex_stream_module.MplexStream = FakeMplexStream
        blocker = RejectFastecdsa()
        sys.meta_path.insert(0, blocker)
        try:
            with (
                mock.patch.dict(os.environ, {}, clear=True),
                mock.patch("secrets_kit.daemon.transport._load_or_create_libp2p_identity", return_value=identity),
                mock.patch.dict(
                    sys.modules,
                    {
                        "libp2p": libp2p_module,
                        "libp2p.crypto.x25519": x25519_module,
                        "libp2p.custom_types": custom_types_module,
                        "libp2p.network.config": network_config_module,
                        "libp2p.security.noise.transport": noise_module,
                        "libp2p.stream_muxer.mplex.mplex_stream": mplex_stream_module,
                    },
                ),
            ):
                result = _create_noise_only_host(
                    listen_addr="/ip4/0.0.0.0/tcp/0", bootstrap=None
                )
                context = FakeMplexStream._seckit_circuit_boundary_context
                self.assertEqual(
                    FakeMplexStream()._read_return_when_blocked(),
                    bytearray(b"coalesced"),
                )
                token = context.set(True)
                try:
                    self.assertEqual(
                        FakeMplexStream()._read_return_when_blocked(), bytearray()
                    )
                finally:
                    context.reset(token)
        finally:
            sys.meta_path.remove(blocker)

        self.assertEqual(result, "noise-host")
        options = observed["host_options"]
        self.assertEqual(tuple(options["sec_opt"]), ("/noise",))
        self.assertIs(options["key_pair"], identity)
        self.assertIs(observed["noise_identity"], identity)
        self.assertIs(observed["noise_private_key"], noise_private_key)
        self.assertEqual(options["connection_config"].inbound_upgrade_timeout, 30.0)
        self.assertEqual(options["connection_config"].outbound_upgrade_timeout, 30.0)

    def test_direct_transport_moves_opaque_bytes(self) -> None:
        received: list[bytes] = []

        def handler(payload: bytes, kind: str) -> tuple[bytes, bool]:
            self.assertEqual(kind, "direct_tcp")
            received.append(payload)
            return b'{"response":"delivered","status":"ok"}', False

        server = DirectTCPTransport(host="127.0.0.1", requested_port=0)
        server.start(services=_services(handler=handler, routing_table=RoutingTable()))
        try:
            route_table = RoutingTable(
                [PeerRoute(peer_id="node:transport-test", host="127.0.0.1", port=server.snapshot().tcp_port)]
            )
            client = DirectTCPTransport(host="127.0.0.1", requested_port=0, routing_table=route_table)
            receipt = client.send(
                payload=b"opaque-envelope-bytes",
                peer_id="node:transport-test",
            )
            self.assertTrue(receipt.delivered)
            self.assertEqual(received, [b"opaque-envelope-bytes"])
        finally:
            server.stop()

    def test_direct_transport_keeps_receipt_open_for_slow_runtime_handoff(self) -> None:
        def handler(payload: bytes, kind: str) -> tuple[bytes, bool]:
            self.assertEqual(payload, b"slow-runtime-envelope")
            self.assertEqual(kind, "direct_tcp")
            time.sleep(2.2)
            return b'{"response":"delivered","status":"ok"}', False

        server = DirectTCPTransport(host="127.0.0.1", requested_port=0)
        server.start(services=_services(handler=handler, routing_table=RoutingTable()))
        try:
            route_table = RoutingTable(
                [PeerRoute(peer_id="node:slow-runtime", host="127.0.0.1", port=server.snapshot().tcp_port)]
            )
            client = DirectTCPTransport(host="127.0.0.1", requested_port=0, routing_table=route_table)
            receipt = client.send(
                payload=b"slow-runtime-envelope",
                peer_id="node:slow-runtime",
            )
            self.assertTrue(receipt.delivered)
        finally:
            server.stop()

    def test_multiaddr_route_remains_transport_neutral(self) -> None:
        node_id = deterministic_identifier(
            identifier_type="node", namespace="transport-tests", name="transport-route"
        )
        previous = os.environ.get("SECKIT_DAEMON_PEERS")
        os.environ["SECKIT_DAEMON_PEERS"] = (
            f"{node_id}@/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWTransportPeer"
        )
        try:
            routes = configured_peer_destinations()
        finally:
            if previous is None:
                os.environ.pop("SECKIT_DAEMON_PEERS", None)
            else:
                os.environ["SECKIT_DAEMON_PEERS"] = previous
        self.assertEqual(len(routes), 1)
        self.assertEqual(routes[0].endpoint, "/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWTransportPeer")
        self.assertIsNone(routes[0].host)
        self.assertIsNone(routes[0].port)
        self.assertEqual(routes[0].adapter, "libp2p")

    def test_daemon_bind_host_is_local_by_default(self) -> None:
        self.assertEqual(daemon_tcp_host(), "127.0.0.1")

    def test_libp2p_adapter_is_lazy_and_keeps_relay_transport_local(self) -> None:
        adapter = LibP2PTransport(
            host="127.0.0.1",
            requested_port=40123,
            discovery=True,
            relay_peers=["/ip4/127.0.0.1/tcp/40124/p2p/12D3KooWRelay"],
        )
        metadata = adapter.metadata()
        self.assertEqual(metadata["transport"], "libp2p")
        self.assertTrue(metadata["discovery"])
        self.assertTrue(metadata["relay_configured"])
        self.assertEqual(metadata["relay_connected"], 0)

    def test_hosted_relay_startup_has_bounded_public_network_allowance(self) -> None:
        adapter = PyLibP2PTransport(
            host="127.0.0.1",
            requested_port=0,
            discovery=False,
            relay_peers=["/ip4/192.0.2.1/tcp/4001/p2p/12D3KooWRelay"],
        )
        adapter._ready = mock.Mock()
        adapter._ready.wait.return_value = False
        worker = mock.Mock()
        with mock.patch("secrets_kit.daemon.transport.threading.Thread", return_value=worker):
            with self.assertRaisesRegex(TransportError, "did not become ready"):
                adapter.start(
                    services=_services(
                        handler=lambda _payload, _adapter: (b"{}", True),
                        routing_table=RoutingTable(),
                    )
                )
        adapter._ready.wait.assert_called_once_with(timeout=30.0)

    def test_automatic_libp2p_listener_binds_selected_lan_address(self) -> None:
        created: list[_FakeLifecycleHost] = []

        def create_host(*, listen_addr, bootstrap):
            self.assertIsNone(bootstrap)
            host = _FakeLifecycleHost(listen_addr=listen_addr, port=43123)
            created.append(host)
            return host

        adapter = PyLibP2PTransport(
            host="0.0.0.0",
            requested_port=0,
            discovery=False,
        )
        with (
            mock.patch(
                "secrets_kit.daemon.transport._lan_ipv4_addresses",
                return_value=["192.168.1.20"],
            ),
            mock.patch(
                "secrets_kit.daemon.transport._create_noise_only_host",
                side_effect=create_host,
            ),
        ):
            adapter.start(
                services=_services(
                    handler=lambda _payload, _adapter: (b"{}", True),
                    routing_table=RoutingTable(),
                )
            )
            try:
                snapshot = adapter.snapshot()
                self.assertEqual(snapshot.tcp_host, "192.168.1.20")
                self.assertEqual(snapshot.tcp_port, 43123)
                self.assertIn("/ip4/192.168.1.20/tcp/43123/", snapshot.endpoint)
                self.assertNotIn("0.0.0.0", snapshot.endpoint)
                self.assertEqual(len(created), 1)
            finally:
                adapter.stop()

    def test_libp2p_startup_fails_without_reported_bound_address(self) -> None:
        adapter = PyLibP2PTransport(
            host="0.0.0.0",
            requested_port=0,
            discovery=False,
        )
        host = _FakeLifecycleHost(
            listen_addr="/ip4/192.168.1.20/tcp/0",
            port=43123,
        )
        host.get_addrs = mock.Mock(return_value=[])
        with (
            mock.patch(
                "secrets_kit.daemon.transport._lan_ipv4_addresses",
                return_value=["192.168.1.20"],
            ),
            mock.patch(
                "secrets_kit.daemon.transport._create_noise_only_host",
                return_value=host,
            ),
        ):
            with self.assertRaisesRegex(
                TransportError,
                "no bound address for the selected listener",
            ):
                adapter.start(
                    services=_services(
                        handler=lambda _payload, _adapter: (b"{}", True),
                        routing_table=RoutingTable(),
                    )
                )
        self.assertIsNone(adapter.snapshot().endpoint)
        self.assertIsNone(adapter.snapshot().tcp_port)

    def test_automatic_offline_listener_is_loopback_without_mdns_announcement(self) -> None:
        adapter = PyLibP2PTransport(
            host="0.0.0.0",
            requested_port=0,
            discovery=True,
        )
        host = _FakeLifecycleHost(
            listen_addr="/ip4/127.0.0.1/tcp/0",
            port=43124,
        )
        with (
            mock.patch(
                "secrets_kit.daemon.transport._lan_ipv4_addresses",
                return_value=[],
            ),
            mock.patch(
                "secrets_kit.daemon.transport._create_noise_only_host",
                return_value=host,
            ),
            mock.patch.object(adapter, "_start_mdns_discovery") as start_mdns,
        ):
            adapter.start(
                services=_services(
                    handler=lambda _payload, _adapter: (b"{}", True),
                    routing_table=RoutingTable(),
                )
            )
            try:
                snapshot = adapter.snapshot()
                self.assertEqual(snapshot.tcp_host, "127.0.0.1")
                self.assertIn("/ip4/127.0.0.1/tcp/43124/", snapshot.endpoint)
                self.assertEqual(snapshot.advertised_addresses, ())
                start_mdns.assert_not_called()
            finally:
                adapter.stop()

    def test_lan_change_recreates_identity_host_and_updates_actual_endpoint(self) -> None:
        selected = ["192.168.1.20"]
        first_exited = threading.Event()
        created: list[_FakeLifecycleHost] = []

        def create_host(*, listen_addr, bootstrap):
            self.assertIsNone(bootstrap)
            host = _FakeLifecycleHost(
                listen_addr=listen_addr,
                port=43130 + len(created),
                exited=first_exited if not created else None,
            )
            created.append(host)
            return host

        adapter = PyLibP2PTransport(
            host="0.0.0.0",
            requested_port=0,
            discovery=False,
        )
        with (
            mock.patch(
                "secrets_kit.daemon.transport.LAN_LISTENER_REFRESH_INTERVAL_SECONDS",
                0.02,
            ),
            mock.patch(
                "secrets_kit.daemon.transport._lan_ipv4_addresses",
                side_effect=lambda: list(selected),
            ),
            mock.patch(
                "secrets_kit.daemon.transport._create_noise_only_host",
                side_effect=create_host,
            ) as create,
        ):
            adapter.start(
                services=_services(
                    handler=lambda _payload, _adapter: (b"{}", True),
                    routing_table=RoutingTable(),
                )
            )
            try:
                selected[:] = ["192.168.1.21"]
                self._wait_until(
                    lambda: (
                        len(created) == 2
                        and adapter.snapshot().tcp_host == "192.168.1.21"
                    )
                )
                snapshot = adapter.snapshot()
                self.assertTrue(first_exited.is_set())
                self.assertIn("/ip4/192.168.1.21/tcp/43131/", snapshot.endpoint)
                self.assertEqual(create.call_count, 2)
            finally:
                adapter.stop()

    def test_fixed_listener_override_does_not_restart_on_lan_change(self) -> None:
        created: list[_FakeLifecycleHost] = []

        def create_host(*, listen_addr, bootstrap):
            host = _FakeLifecycleHost(listen_addr=listen_addr, port=43140)
            created.append(host)
            return host

        adapter = PyLibP2PTransport(
            host="127.0.0.1",
            requested_port=0,
            discovery=False,
        )
        with (
            mock.patch(
                "secrets_kit.daemon.transport.LAN_LISTENER_REFRESH_INTERVAL_SECONDS",
                0.02,
            ),
            mock.patch(
                "secrets_kit.daemon.transport._lan_ipv4_addresses",
                side_effect=[["192.168.1.20"], ["192.168.1.21"]],
            ) as lan_addresses,
            mock.patch(
                "secrets_kit.daemon.transport._create_noise_only_host",
                side_effect=create_host,
            ),
        ):
            adapter.start(
                services=_services(
                    handler=lambda _payload, _adapter: (b"{}", True),
                    routing_table=RoutingTable(),
                )
            )
            try:
                time.sleep(0.08)
                self.assertEqual(len(created), 1)
                self.assertEqual(adapter.snapshot().tcp_host, "127.0.0.1")
                lan_addresses.assert_not_called()
            finally:
                adapter.stop()

    def test_shutdown_during_listener_recovery_prevents_further_restart(self) -> None:
        selected = ["192.168.1.20"]
        first_exited = threading.Event()
        attempts = 0

        def create_host(*, listen_addr, bootstrap):
            nonlocal attempts
            attempts += 1
            if attempts > 1:
                raise OSError("temporary bind failure")
            return _FakeLifecycleHost(
                listen_addr=listen_addr,
                port=43150,
                exited=first_exited,
            )

        adapter = PyLibP2PTransport(
            host="0.0.0.0",
            requested_port=0,
            discovery=False,
        )
        with (
            mock.patch(
                "secrets_kit.daemon.transport.LAN_LISTENER_REFRESH_INTERVAL_SECONDS",
                0.02,
            ),
            mock.patch(
                "secrets_kit.daemon.transport._lan_ipv4_addresses",
                side_effect=lambda: list(selected),
            ),
            mock.patch(
                "secrets_kit.daemon.transport._create_noise_only_host",
                side_effect=create_host,
            ),
        ):
            adapter.start(
                services=_services(
                    handler=lambda _payload, _adapter: (b"{}", True),
                    routing_table=RoutingTable(),
                )
            )
            selected[:] = ["192.168.1.21"]
            self._wait_until(lambda: first_exited.is_set() and attempts >= 2)
            worker = adapter._thread
            adapter.stop()
            stopped_attempts = attempts
            time.sleep(0.08)
            self.assertEqual(attempts, stopped_attempts)
            self.assertIsNotNone(worker)
            self.assertFalse(worker.is_alive())

    def test_mdns_advertises_actual_bound_port(self) -> None:
        observed: dict[str, object] = {}

        class FakeDiscovery:
            advertised_addresses = ("192.0.2.67",)

            def __init__(self, **kwargs):
                observed.update(kwargs)

            def start(self) -> None:
                observed["started"] = True

        class FakeLowLevel:
            @staticmethod
            def spawn_system_task(callback, peer_info) -> None:
                observed["scheduled"] = (callback, peer_info)

        class FakeNursery:
            def start_soon(self, callback, peer_info) -> None:
                observed["scheduled"] = (callback, peer_info)

        class FakeToken:
            def run_sync_soon(self, callback) -> None:
                observed["scheduled_from_thread"] = True
                callback()

        class FakePeer:
            peer_id = "12D3KooWDiscovered"

            def __init__(self, address: str = "192.0.2.67") -> None:
                self.addrs = [f"/ip4/{address}/tcp/43123"]

        fake_trio = types.SimpleNamespace(
            lowlevel=FakeLowLevel,
            RunFinishedError=RuntimeError,
        )
        selected = ["192.0.2.67"]
        host = types.SimpleNamespace(get_network=lambda: "swarm")
        adapter = LibP2PTransport(
            host="0.0.0.0",
            requested_port=0,
            discovery=True,
            interfaces=["192.0.2.67"],
        )
        adapter._port = 43123
        adapter._host = "192.0.2.67"
        adapter._host_object = host
        adapter._peer_id = "12D3KooWLocal"
        adapter._trio_token = FakeToken()
        adapter._scope_nursery = FakeNursery()
        with (
            mock.patch("secrets_kit.daemon.mdns.DaemonMDNS", FakeDiscovery),
            mock.patch(
                "secrets_kit.daemon.transport._lan_ipv4_addresses",
                side_effect=lambda: list(selected),
            ),
        ):
            adapter._start_mdns_discovery(
                host=host,
                trio=fake_trio,
                bound_host="192.0.2.67",
            )
            self.assertEqual(observed["addresses"](), ["192.0.2.67"])
            selected[:] = ["192.0.2.68"]
            self.assertEqual(observed["addresses"](), [])
        self.assertEqual(observed["port"], 43123)
        self.assertEqual(observed["interfaces"], ["192.0.2.67"])
        self.assertTrue(observed["started"])
        observed["on_candidate"](FakePeer("192.0.2.67"))
        self.assertTrue(observed["scheduled_from_thread"])
        self.assertEqual(observed["scheduled"][1].peer_id, "12D3KooWDiscovered")
        events = adapter.metadata()["routing_events"]
        self.assertEqual(events[0]["event"], "mdns_advertisement_started")
        self.assertEqual(events[0]["addresses"], ["192.0.2.67"])
        self.assertEqual(events[1]["event"], "mdns_advertisement_received")
        self.assertEqual(events[1]["transport_peer_id"], "12D3KooWDiscovered")
        adapter._discovery_service.advertised_addresses = ("192.0.2.68",)
        self.assertEqual(
            adapter.snapshot().advertised_addresses,
            ("192.0.2.68",),
        )

        relay_candidate = FakePeer("192.0.2.99")
        adapter._candidate_infos[FakePeer.peer_id] = relay_candidate
        adapter._relay_candidate_ranks[FakePeer.peer_id] = 0
        observed["on_candidate"](FakePeer())
        self.assertIs(adapter._candidate_infos[FakePeer.peer_id], relay_candidate)
        self.assertEqual(adapter._mdns_candidate_infos[FakePeer.peer_id].peer_id, FakePeer.peer_id)
        observed["on_remove"](FakePeer.peer_id)
        self.assertNotIn(FakePeer.peer_id, adapter._mdns_candidate_infos)
        self.assertIs(adapter._candidate_infos[FakePeer.peer_id], relay_candidate)

    def test_mdns_bind_failure_does_not_block_configured_transport(self) -> None:
        discovery = mock.Mock()
        discovery.start.side_effect = OSError(48, "Address already in use")
        adapter = LibP2PTransport(host="0.0.0.0", requested_port=0, discovery=True)
        adapter._port = 43123
        adapter._peer_id = "12D3KooWLocal"
        with mock.patch("secrets_kit.daemon.mdns.DaemonMDNS", return_value=discovery):
            adapter._start_mdns_discovery(
                host=types.SimpleNamespace(get_network=lambda: "swarm"),
                trio=types.SimpleNamespace(),
                bound_host="127.0.0.1",
            )
        self.assertIsNone(adapter._discovery_service)
        events = adapter.metadata()["routing_events"]
        self.assertEqual(events[-1]["event"], "mdns_advertisement_unavailable")
        self.assertEqual(events[-1]["error"], "OSError:48")
        discovery.stop.assert_called_once()

    def test_mdns_address_selection_skips_vpn_default_for_lan_default(self) -> None:
        routes = """Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            10.2.0.1           UGScg               utun4
default            192.168.1.1        UGScIg              en0
"""
        completed = types.SimpleNamespace(returncode=0, stdout=routes)
        addresses = {
            "utun4": [
                types.SimpleNamespace(family=socket.AF_INET, address="10.2.0.2")
            ],
            "en0": [
                types.SimpleNamespace(
                    family=socket.AF_INET, address="192.168.1.20"
                )
            ],
        }
        stats = {
            "utun4": types.SimpleNamespace(
                isup=True, flags="up,pointopoint,running,multicast"
            ),
            "en0": types.SimpleNamespace(
                isup=True, flags="up,broadcast,running,multicast"
            ),
        }
        with (
            mock.patch("secrets_kit.daemon.transport.sys.platform", "darwin"),
            mock.patch(
                "secrets_kit.daemon.transport.subprocess.run",
                return_value=completed,
            ) as run,
            mock.patch(
                "secrets_kit.daemon.transport.psutil.net_if_addrs",
                return_value=addresses,
            ),
            mock.patch(
                "secrets_kit.daemon.transport.psutil.net_if_stats",
                return_value=stats,
            ),
        ):
            self.assertEqual(_lan_ipv4_addresses(), ["192.168.1.20"])
        self.assertEqual(
            run.call_args.args[0],
            ["/usr/sbin/netstat", "-rn", "-f", "inet"],
        )
        self.assertEqual(run.call_args.kwargs["env"]["LC_ALL"], "C")
        self.assertEqual(run.call_args.kwargs["timeout"], 1.0)

    def test_mdns_address_selection_linux_prefers_lowest_metric(self) -> None:
        routes = """Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
wlan0 00000000 0101A8C0 0003 0 0 600 00000000 0 0 0
eth0 00000000 0101A8C0 0003 0 0 100 00000000 0 0 0
"""

        def address(value: str) -> object:
            return types.SimpleNamespace(family=socket.AF_INET, address=value)

        stats = {
            name: types.SimpleNamespace(
                isup=True, flags="up,broadcast,running,multicast"
            )
            for name in ("wlan0", "eth0")
        }
        with (
            mock.patch("secrets_kit.daemon.transport.sys.platform", "linux"),
            mock.patch(
                "builtins.open",
                mock.mock_open(read_data=routes),
            ),
            mock.patch(
                "secrets_kit.daemon.transport.psutil.net_if_addrs",
                return_value={
                    "wlan0": [address("192.168.1.30")],
                    "eth0": [address("192.168.1.20")],
                },
            ),
            mock.patch(
                "secrets_kit.daemon.transport.psutil.net_if_stats",
                return_value=stats,
            ),
        ):
            self.assertEqual(_lan_ipv4_addresses(), ["192.168.1.20"])

    def test_mdns_address_selection_ignores_malformed_and_down_routes(self) -> None:
        routes = """Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
broken not-hex 00000000 nope 0 0 metric 00000000 0 0 0
down0 00000000 0101A8C0 0003 0 0 10 00000000 0 0 0
"""
        with (
            mock.patch("secrets_kit.daemon.transport.sys.platform", "linux"),
            mock.patch("builtins.open", mock.mock_open(read_data=routes)),
            mock.patch(
                "secrets_kit.daemon.transport.psutil.net_if_addrs",
                return_value={
                    "down0": [
                        types.SimpleNamespace(
                            family=socket.AF_INET, address="192.168.1.20"
                        )
                    ]
                },
            ),
            mock.patch(
                "secrets_kit.daemon.transport.psutil.net_if_stats",
                return_value={
                    "down0": types.SimpleNamespace(
                        isup=False, flags="up,broadcast,running,multicast"
                    )
                },
            ),
        ):
            self.assertEqual(_lan_ipv4_addresses(), [])

    def test_mdns_address_selection_is_empty_without_default_routes(self) -> None:
        with (
            mock.patch("secrets_kit.daemon.transport.sys.platform", "linux"),
            mock.patch(
                "builtins.open",
                side_effect=OSError("route table unavailable"),
            ),
            mock.patch(
                "secrets_kit.daemon.transport.psutil.net_if_addrs",
                return_value={},
            ),
            mock.patch(
                "secrets_kit.daemon.transport.psutil.net_if_stats",
                return_value={},
            ),
        ):
            self.assertEqual(_lan_ipv4_addresses(), [])

    def test_removed_mdns_candidate_is_not_bound_from_queued_callback(self) -> None:
        queued: list[object] = []
        scheduled: list[object] = []

        class FakeDiscovery:
            advertised_addresses = ("192.0.2.67",)

            def __init__(self, **kwargs):
                self.options = kwargs

            def start(self) -> None:
                return

        class DeferredToken:
            def run_sync_soon(self, callback) -> None:
                queued.append(callback)

        class FakePeer:
            peer_id = "12D3KooWDiscovered"

            def __init__(self, address: str) -> None:
                self.addrs = [f"/ip4/{address}/tcp/43123"]

        fake_trio = types.SimpleNamespace(
            lowlevel=types.SimpleNamespace(
                spawn_system_task=lambda callback, peer: scheduled.append((callback, peer))
            ),
            RunFinishedError=RuntimeError,
        )
        adapter = LibP2PTransport(host="192.0.2.67", requested_port=0, discovery=True)
        adapter._port = 43123
        adapter._peer_id = "12D3KooWLocal"
        adapter._trio_token = DeferredToken()
        adapter._scope_nursery = types.SimpleNamespace(
            start_soon=lambda callback, peer: scheduled.append((callback, peer))
        )
        host = object()
        adapter._host_object = host
        with mock.patch("secrets_kit.daemon.mdns.DaemonMDNS", FakeDiscovery):
            adapter._start_mdns_discovery(host=host, trio=fake_trio)

        discovery = adapter._discovery_service
        discovery.options["on_candidate"](FakePeer("192.0.2.67"))
        discovery.options["on_candidate"](FakePeer("192.0.2.68"))
        queued.pop(0)()
        discovery.options["on_remove"](FakePeer.peer_id)
        queued.pop()()

        self.assertEqual(scheduled, [])

        # A late callback from the retired host must not populate its successor.
        adapter._host_object = object()
        retained_candidates = dict(adapter._mdns_candidate_infos)
        discovery.options["on_candidate"](FakePeer("192.0.2.69"))
        self.assertEqual(adapter._mdns_candidate_infos, retained_candidates)
        self.assertEqual(scheduled, [])

    def test_default_libp2p_transport_enables_discovery(self) -> None:
        previous_transport = os.environ.pop("SECKIT_DAEMON_TRANSPORT", None)
        previous_discovery = os.environ.pop("SECKIT_DAEMON_DISCOVERY", None)
        try:
            adapter = create_transport(host="0.0.0.0", requested_port=0)
            self.assertIsInstance(adapter, PyLibP2PTransport)
            self.assertTrue(adapter.metadata()["discovery"])
        finally:
            if previous_transport is not None:
                os.environ["SECKIT_DAEMON_TRANSPORT"] = previous_transport
            if previous_discovery is not None:
                os.environ["SECKIT_DAEMON_DISCOVERY"] = previous_discovery

    def test_libp2p_stop_lets_host_context_own_async_shutdown(self) -> None:
        adapter = PyLibP2PTransport(
            host="127.0.0.1",
            requested_port=0,
            discovery=False,
        )
        network = types.SimpleNamespace(close=mock.Mock())
        adapter._host_object = types.SimpleNamespace(get_network=lambda: network)

        adapter.stop()

        self.assertTrue(adapter._stop_event.is_set())
        network.close.assert_not_called()

    def test_discovered_candidate_connects_and_installs_one_validated_route(self) -> None:
        node_id = deterministic_identifier(
            identifier_type="node", namespace="transport-tests", name="discovered-node"
        )
        route_table = RoutingTable()
        adapter = LibP2PTransport(
            host="0.0.0.0", requested_port=0, routing_table=route_table
        )
        stream = types.SimpleNamespace(
            write=mock.AsyncMock(),
            close=mock.AsyncMock(),
        )
        host = types.SimpleNamespace(
            connect=mock.AsyncMock(),
            new_stream=mock.AsyncMock(return_value=stream),
            get_peerstore=lambda: types.SimpleNamespace(
                get_protocols=lambda peer_id: ["/seckit/identity-binding/1.0.0"]
            ),
        )
        peer_info = types.SimpleNamespace(
            peer_id="12D3KooWDiscovered",
            addrs=["/ip4/192.0.2.12/tcp/43123"],
        )
        adapter._host_object = host
        adapter._peer_id = "12D3KooWLocal"
        adapter._verify_claim = mock.AsyncMock(return_value=node_id)
        adapter._sign_claim = mock.AsyncMock(return_value={"signature": "opaque"})
        adapter._wait_for_identify = mock.AsyncMock()
        responses = [
            b'{"version":1,"challenge":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","claim":{}}',
            b'{"version":1,"status":"accepted"}',
        ]
        with mock.patch(
            "secrets_kit.daemon.transport._read_stream_frame",
            new=mock.AsyncMock(side_effect=responses),
        ):
            import trio
            trio.run(adapter._connect_and_bind, peer_info)
            trio.run(adapter._connect_and_bind, peer_info)

        host.connect.assert_awaited_once_with(peer_info)
        route = route_table.resolve(peer_id=node_id, adapter="libp2p")
        self.assertEqual(route.source, "libp2p_discovery")
        self.assertEqual(route.transport_peer_id, "12D3KooWDiscovered")
        self.assertIn("/tcp/43123/", route.endpoint)
        self.assertEqual(route_table.discovered_count(), 1)
        events = adapter.metadata()["routing_events"]
        verified = [event for event in events if event["event"] == "identity_binding_verified"]
        installed = [event for event in events if event["event"] == "route_installed"]
        self.assertEqual(verified[0]["node_id"], node_id)
        self.assertEqual(installed[0]["transport_peer_id"], "12D3KooWDiscovered")
        self.assertEqual(installed[0]["source"], "libp2p_discovery")
        status_route = adapter.metadata()["routes"][0]
        self.assertEqual(status_route["adapter"], "libp2p")
        self.assertEqual(status_route["host"], "192.0.2.12")
        self.assertEqual(status_route["port"], 43123)

        changed = types.SimpleNamespace(
            peer_id=peer_info.peer_id,
            addrs=["/ip4/192.0.2.13/tcp/43124"],
        )
        changed_stream = types.SimpleNamespace(
            write=mock.AsyncMock(),
            close=mock.AsyncMock(),
        )
        host.new_stream = mock.AsyncMock(return_value=changed_stream)
        with mock.patch(
            "secrets_kit.daemon.transport._read_stream_frame",
            new=mock.AsyncMock(side_effect=responses),
        ):
            trio.run(adapter._connect_and_bind, changed)
        self.assertEqual(host.connect.await_count, 2)
        self.assertIn(
            "/ip4/192.0.2.13/tcp/43124",
            route_table.resolve(peer_id=node_id, adapter="libp2p").endpoint,
        )

    def test_rejected_binding_records_exact_phase_and_reason(self) -> None:
        adapter = LibP2PTransport(host="0.0.0.0", requested_port=0)
        peer_info = types.SimpleNamespace(
            peer_id="12D3KooWRejected",
            addrs=["/ip4/192.0.2.99/tcp/43123"],
        )
        adapter._host_object = types.SimpleNamespace(
            connect=mock.AsyncMock(side_effect=OSError("connection refused"))
        )

        import trio
        trio.run(adapter._connect_and_bind, peer_info)

        events = adapter.metadata()["routing_events"]
        rejected = [event for event in events if event["event"] == "identity_binding_rejected"]
        self.assertEqual(len(rejected), 1)
        self.assertEqual(rejected[0]["phase"], "connect")
        self.assertEqual(rejected[0]["reason"], "connection refused")
        self.assertEqual(rejected[0]["reason_type"], "OSError")
        self.assertIn("connection refused", rejected[0]["reason_repr"])
        self.assertEqual(rejected[0]["reason_chain"][0]["type"], "OSError")

    def test_runtime_binding_failure_preserves_bounded_diagnostic(self) -> None:
        completed = types.SimpleNamespace(
            returncode=1,
            stdout=b"",
            stderr=b"ERROR: failed to verify transport binding: peer is not admitted\n",
        )
        with mock.patch("secrets_kit.daemon.transport.subprocess.run", return_value=completed):
            with self.assertRaisesRegex(
                TransportError,
                "failed to verify transport binding: peer is not admitted",
            ):
                _invoke_runtime_binding(operation="verify-transport-binding", request={})

    def test_binding_waits_for_built_in_identify_protocol_population(self) -> None:
        import trio

        observations = [[], ["/seckit/identity-binding/1.0.0"]]

        class FakePeerstore:
            def get_protocols(self, peer_id):
                self.peer_id = peer_id
                return observations.pop(0)

        peerstore = FakePeerstore()
        adapter = LibP2PTransport(host="0.0.0.0", requested_port=0)
        adapter._host_object = types.SimpleNamespace(get_peerstore=lambda: peerstore)

        async def wait() -> None:
            await adapter._wait_for_identify(peer_id="12D3KooWIdentified")

        trio.run(wait)
        self.assertEqual(peerstore.peer_id, "12D3KooWIdentified")
        self.assertEqual(observations, [])

    def test_direct_tcp_selection_is_explicit(self) -> None:
        previous = os.environ.get("SECKIT_DAEMON_TRANSPORT")
        os.environ["SECKIT_DAEMON_TRANSPORT"] = "direct_tcp"
        try:
            with mock.patch.dict(os.environ, {"SECKIT_UNSAFE_TEST_DIRECT_TCP": "0"}):
                with self.assertRaisesRegex(TransportError, "test transport only"):
                    create_transport(host="127.0.0.1", requested_port=40125)
            with mock.patch.dict(os.environ, {"SECKIT_UNSAFE_TEST_DIRECT_TCP": "1"}):
                self.assertIsInstance(create_transport(host="127.0.0.1", requested_port=40125), DirectTCPTransport)
        finally:
            if previous is None:
                os.environ.pop("SECKIT_DAEMON_TRANSPORT", None)
            else:
                os.environ["SECKIT_DAEMON_TRANSPORT"] = previous

    def test_rss_auth_failure_phase_distinguishes_deadline_stages(self) -> None:
        """Connect-blocked parent timeouts stay distinct from exchange stalls."""
        import json
        from collections.abc import Callable

        import trio
        import trio.testing

        from secrets_kit.daemon.transport import TransportUnavailable
        from secrets_kit.protocol.rss_auth import (
            RSS_SESSION_AUTH_PROTOCOL,
            RSS_SESSION_READY_PROTOCOL,
            RSSAuthenticationError,
            RSSRelayClientCredentials,
        )

        timeout_error = "RSS authentication exchange timed out"
        secret_markers = (
            "ent-secret-marker",
            "conn-secret-marker",
            "ret-secret-marker",
            "nonce-secret-marker",
            "proof-secret-marker",
        )
        credentials = RSSRelayClientCredentials(
            entitlement_id="ent-secret-marker",
            connection_id="conn-secret-marker",
            customer_private_key=b"\x11" * 32,
            customer_public_key=b"\x22" * 32,
            enrollment_token="ret-secret-marker",
        )
        challenge_frame = json.dumps(
            {
                "status": "challenge",
                "challenge": {
                    "protocol": RSS_SESSION_AUTH_PROTOCOL,
                    "challenge_id": "cid-1",
                    "challenge": "nonce-secret-marker",
                    "expires_at": 100,
                },
            }
        ).encode()
        ready_frame = json.dumps(
            {
                "protocol": RSS_SESSION_READY_PROTOCOL,
                "status": "ok",
                "peer_transport_ids": [],
            }
        ).encode()

        def assert_no_secrets(adapter: PyLibP2PTransport) -> None:
            rendered = json.dumps(adapter.metadata()["routing_events"])
            for marker in secret_markers:
                self.assertNotIn(marker, rendered)
            self.assertNotIn("customer_private_key", rendered)

        def failed_event(adapter: PyLibP2PTransport, peer_id: str) -> dict[str, object]:
            matches = [
                event
                for event in adapter.metadata()["routing_events"]
                if event["event"] == "rss_authentication_failed"
                and event["transport_peer_id"] == peer_id
            ]
            self.assertEqual(len(matches), 1)
            event = matches[0]
            self.assertEqual(
                set(event),
                {"timestamp", "event", "transport_peer_id", "error", "phase"},
            )
            self.assertEqual(event["error"], timeout_error)
            self.assertEqual(
                adapter._relay_endpoint_states[peer_id],
                f"failed:{timeout_error}",
            )
            return event

        def authenticated_event(adapter: PyLibP2PTransport, peer_id: str) -> dict[str, object]:
            matches = [
                event
                for event in adapter.metadata()["routing_events"]
                if event["event"] == "rss_authenticated"
                and event["transport_peer_id"] == peer_id
            ]
            self.assertEqual(len(matches), 1)
            event = matches[0]
            self.assertEqual(set(event), {"timestamp", "event", "transport_peer_id"})
            self.assertEqual(adapter._relay_endpoint_states[peer_id], "authenticated")
            return event

        async def stall() -> None:
            await trio.sleep_forever()

        def stream_for(
            *,
            frames: list[bytes],
            stall_write_at: int | None,
        ) -> types.SimpleNamespace:
            writes = 0

            async def write(_payload: bytes) -> None:
                nonlocal writes
                writes += 1
                if stall_write_at is not None and writes == stall_write_at:
                    await trio.sleep_forever()

            async def read_behavior() -> bytes:
                if not frames:
                    await trio.sleep_forever()
                return frames.pop(0)

            return types.SimpleNamespace(
                write=write,
                close=mock.AsyncMock(),
                read_behavior=read_behavior,
            )

        async def read_frame(stream: types.SimpleNamespace) -> bytes:
            return await stream.read_behavior()

        def run_case(
            *,
            targets: list[tuple[types.SimpleNamespace, bool]],
            connect: object,
            new_stream: object,
            expect_success: bool,
            prepare: Callable[[PyLibP2PTransport], None] | None = None,
            enroll_error: str | None = None,
        ) -> PyLibP2PTransport:
            adapter = PyLibP2PTransport(host="127.0.0.1", requested_port=0)
            if prepare is not None:
                prepare(adapter)
            network = types.SimpleNamespace(close_peer=mock.AsyncMock())
            host = types.SimpleNamespace(
                connect=connect,
                new_stream=new_stream,
                get_id=lambda: "local-transport",
                get_network=lambda: network,
            )

            async def run() -> None:
                with ExitStack() as stack:
                    stack.enter_context(
                        mock.patch(
                            "secrets_kit.daemon.transport.TRANSPORT_IO_TIMEOUT_SECONDS",
                            1.0,
                        )
                    )
                    stack.enter_context(
                        mock.patch(
                            "secrets_kit.daemon.transport.build_rss_session_proof",
                            return_value={"proof": "proof-secret-marker"},
                        )
                    )
                    stack.enter_context(
                        mock.patch(
                            "secrets_kit.daemon.transport._read_stream_frame",
                            new=read_frame,
                        )
                    )
                    if enroll_error is not None:
                        stack.enter_context(
                            mock.patch(
                                "secrets_kit.daemon.transport.perform_rss_https_enrollment",
                                side_effect=RSSAuthenticationError(enroll_error),
                            )
                        )
                    if expect_success:
                        loaded = await adapter._authenticate_relay_targets(
                            host=host,
                            relay_targets=targets,
                            credentials=credentials,
                        )
                        self.assertIs(loaded, credentials)
                        return
                    with self.assertRaisesRegex(
                        TransportUnavailable,
                        "no configured RSS endpoint authenticated",
                    ):
                        await adapter._authenticate_relay_targets(
                            host=host,
                            relay_targets=targets,
                            credentials=credentials,
                        )

            trio.run(run, clock=trio.testing.MockClock(autojump_threshold=0))
            assert_no_secrets(adapter)
            return adapter

        def peer(peer_id: str) -> types.SimpleNamespace:
            return types.SimpleNamespace(peer_id=peer_id)

        with self.subTest(phase="success"):
            ready = stream_for(
                frames=[challenge_frame, ready_frame],
                stall_write_at=None,
            )

            async def connect_ready(_relay: object) -> None:
                return None

            async def open_ready(
                _peer_id: object,
                _protocols: object,
            ) -> types.SimpleNamespace:
                return ready

            adapter = run_case(
                targets=[(peer("healthy"), False)],
                connect=connect_ready,
                new_stream=open_ready,
                expect_success=True,
            )
            authenticated_event(adapter, "healthy")
            self.assertEqual(adapter._relay_connected, 1)
            self.assertFalse(
                any(
                    event["event"] == "rss_authentication_failed"
                    for event in adapter.metadata()["routing_events"]
                )
            )

        with self.subTest(phase="connect_parent_versus_exchange"):
            blocked_id = "connect-blocked"
            stalled_id = "read-stalled"
            healthy_id = "healthy"
            stalled_stream = stream_for(frames=[], stall_write_at=None)
            healthy_stream = stream_for(
                frames=[challenge_frame, ready_frame],
                stall_write_at=None,
            )

            async def connect_mixed(relay: types.SimpleNamespace) -> None:
                if relay.peer_id == blocked_id:
                    await trio.sleep_forever()

            async def open_mixed(
                peer_id: object,
                _protocols: object,
            ) -> types.SimpleNamespace:
                if peer_id == stalled_id:
                    return stalled_stream
                if peer_id == healthy_id:
                    return healthy_stream
                raise AssertionError(peer_id)

            adapter = run_case(
                targets=[
                    (peer(blocked_id), False),
                    (peer(stalled_id), False),
                    (peer(healthy_id), False),
                ],
                connect=connect_mixed,
                new_stream=open_mixed,
                expect_success=True,
            )
            self.assertEqual(failed_event(adapter, blocked_id)["phase"], "host.connect")
            self.assertEqual(
                failed_event(adapter, stalled_id)["phase"],
                "reading_challenge",
            )
            authenticated_event(adapter, healthy_id)
            self.assertEqual(adapter._relay_connected, 1)

        with self.subTest(phase="parent_cancel_opening_rss_stream"):

            async def connect_slow(_relay: object) -> None:
                await trio.sleep(1.5)

            async def open_forever(
                _peer_id: object,
                _protocols: object,
            ) -> types.SimpleNamespace:
                await trio.sleep_forever()
                raise AssertionError("unreachable")

            adapter = run_case(
                targets=[(peer("open-cancelled"), False)],
                connect=connect_slow,
                new_stream=open_forever,
                expect_success=False,
            )
            self.assertEqual(
                failed_event(adapter, "open-cancelled")["phase"],
                "opening_rss_stream",
            )

        with self.subTest(phase="enrollment_keeps_prior_read_unlabeled"):
            enrollment = stream_for(
                frames=[json.dumps({"status": "enrollment_required"}).encode()],
                stall_write_at=None,
            )

            async def connect_enroll(_relay: object) -> None:
                return None

            async def open_enroll(
                _peer_id: object,
                _protocols: object,
            ) -> types.SimpleNamespace:
                return enrollment

            adapter = run_case(
                targets=[(peer("enroll-wait"), True)],
                connect=connect_enroll,
                new_stream=open_enroll,
                expect_success=False,
                enroll_error="enrollment rejected",
            )
            matches = [
                event
                for event in adapter.metadata()["routing_events"]
                if event["event"] == "rss_authentication_failed"
            ]
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0]["error"], "enrollment rejected")
            self.assertNotIn("phase", matches[0])
            self.assertEqual(
                adapter._relay_endpoint_states["enroll-wait"],
                "failed:enrollment rejected",
            )

        phase_cases = (
            ("opening_rss_stream", "open", None, 0),
            ("writing_request", "write", 1, 0),
            ("reading_challenge", "read", None, 0),
            ("writing_proof", "write", 2, 1),
            ("reading_response", "read", None, 1),
            ("closing_prior_retained_stream", "close", None, 2),
        )
        for phase, stall_kind, stall_write_at, frame_count in phase_cases:
            with self.subTest(phase=phase):
                peer_id = "relay-stage"
                exchange = stream_for(
                    frames=[challenge_frame, ready_frame][:frame_count],
                    stall_write_at=stall_write_at,
                )

                async def connect_stage(_relay: object) -> None:
                    return None

                async def open_stage(
                    _peer_id: object,
                    _protocols: object,
                    *,
                    stall_kind: str = stall_kind,
                    exchange: types.SimpleNamespace = exchange,
                ) -> types.SimpleNamespace:
                    if stall_kind == "open":
                        await trio.sleep_forever()
                    return exchange

                def prepare(
                    adapter: PyLibP2PTransport,
                    *,
                    stall_kind: str = stall_kind,
                    peer_id: str = peer_id,
                ) -> None:
                    if stall_kind != "close":
                        return
                    adapter._relay_control_streams[peer_id] = types.SimpleNamespace(
                        close=stall
                    )

                adapter = run_case(
                    targets=[(peer(peer_id), False)],
                    connect=connect_stage,
                    new_stream=open_stage,
                    expect_success=False,
                    prepare=prepare,
                )
                self.assertEqual(failed_event(adapter, peer_id)["phase"], phase)
                self.assertFalse(
                    any(
                        event["event"] == "rss_authenticated"
                        for event in adapter.metadata()["routing_events"]
                    )
                )

    def test_runtime_layers_do_not_import_libp2p(self) -> None:
        source_root = Path(__file__).parents[1] / "src" / "secrets_kit"
        runtime_paths = [source_root / name for name in ("runtime", "protocol", "backends", "crypto")]
        violations: list[str] = []
        for root in runtime_paths:
            for path in root.rglob("*.py"):
                if "libp2p" in path.read_text(encoding="utf-8"):
                    violations.append(str(path.relative_to(source_root)))
        self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main()
