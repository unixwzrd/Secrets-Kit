"""Public RSS client authentication and pre-reservation sequencing tests."""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import trio

from secrets_kit.cli.commands.rss import cmd_rss_checkout, cmd_rss_configure, cmd_rss_enroll
from secrets_kit.cli.parser import build_parser
from secrets_kit.crypto.models import generate_signing_keypair
from secrets_kit.crypto.persistence import signing_keypair_to_record
from secrets_kit.daemon.service import DaemonServiceError
from secrets_kit.daemon.transport import PyLibP2PTransport, TransportUnavailable
from secrets_kit.protocol.rss_auth import (
    RSS_ENROLLMENT_PROOF_PROTOCOL,
    RSS_SESSION_AUTH_PROTOCOL,
    RSS_SESSION_READY_PROTOCOL,
    RSSAuthenticationChallenge,
    RSSAuthenticationError,
    RSSRelayClientCredentials,
    build_rss_enrollment_proof,
    build_rss_session_proof,
    clear_consumed_rss_enrollment_token,
    configure_rss_client,
    create_rss_authentication_key_file,
    export_rss_authentication_identity,
    import_rss_authentication_identity,
    load_rss_relay_credentials_from_environment,
    load_rss_relay_peers_from_profile,
    perform_rss_https_enrollment,
    rss_auth_control_request,
)


class RSSAuthenticationProtocolTest(unittest.TestCase):
    def test_session_request_requires_current_device_identity(self) -> None:
        for value in (None, "", "x" * 257):
            with self.subTest(value_length=None if value is None else len(value)):
                with self.assertRaises(RSSAuthenticationError):
                    rss_auth_control_request(operation="session_challenge", entitlement_id="ent_test", connection_id=value)
        request = rss_auth_control_request(operation="session_challenge", entitlement_id="ent_test", connection_id="device-test")
        self.assertEqual(request["connection_id"], "device-test")
        self.assertNotIn("customer_private_key", request)

    def setUp(self) -> None:
        self.keypair = generate_signing_keypair()
        self.credentials = RSSRelayClientCredentials(
            entitlement_id="ent_test_123",
            connection_id="host-a:user-a",
            customer_private_key=self.keypair.private_key,
            customer_public_key=self.keypair.public_key,
            enrollment_token="ret1.opaque.signature",
            enrollment_url="https://rss-use1.example.test",
        )

    def test_proofs_never_serialize_private_key(self) -> None:
        enrollment_challenge = RSSAuthenticationChallenge(
            protocol=RSS_ENROLLMENT_PROOF_PROTOCOL,
            challenge_id="challenge-enroll",
            challenge="nonce-enroll",
            expires_at=100,
        )
        session_challenge = RSSAuthenticationChallenge(
            protocol=RSS_SESSION_AUTH_PROTOCOL,
            challenge_id="challenge-session",
            challenge="nonce-session",
            expires_at=100,
        )
        values = (
            build_rss_enrollment_proof(
                token=self.credentials.enrollment_token or "",
                challenge=enrollment_challenge,
                customer_private_key=self.keypair.private_key,
                customer_public_key=self.keypair.public_key,
                connection_id=self.credentials.connection_id,
            ),
            build_rss_session_proof(
                challenge=session_challenge,
                credentials=self.credentials,
                transport_identity="12D3KooWClient",
            ),
        )
        for value in values:
            serialized = json.dumps(value, sort_keys=True).encode("utf-8")
            self.assertNotIn(self.keypair.private_key, serialized)
            self.assertNotIn("private", value)

    def test_relay_authentication_enrolls_then_becomes_ready(self) -> None:
        adapter = PyLibP2PTransport(
            host="127.0.0.1",
            requested_port=0,
            relay_auth=self.credentials,
        )
        adapter._rss_auth_exchange = mock.AsyncMock(
            side_effect=[
                {"status": "enrollment_required"},
                {"status": "ok", "protocol": RSS_SESSION_READY_PROTOCOL},
            ]
        )
        host = SimpleNamespace(get_id=lambda: "12D3KooWClient")
        relay = SimpleNamespace(peer_id="12D3KooWRelay")

        with mock.patch("secrets_kit.daemon.transport.perform_rss_https_enrollment") as enroll:

            async def authenticate() -> None:
                await adapter._authenticate_rss_relay(
                    host=host,
                    relay_info=relay,
                    credentials=self.credentials,
                    allow_enrollment=True,
                )

            trio.run(authenticate)
        enroll.assert_called_once_with(credentials=self.credentials)

        self.assertEqual(adapter._rss_auth_exchange.await_count, 2)
        first = adapter._rss_auth_exchange.await_args_list[0].kwargs
        self.assertIsNotNone(first["proof_builder"])
        self.assertEqual(first["expected_challenge_protocol"], RSS_SESSION_AUTH_PROTOCOL)

    def test_relay_authentication_fails_closed_without_ret_when_enrollment_required(self) -> None:
        credentials = RSSRelayClientCredentials(
            entitlement_id=self.credentials.entitlement_id,
            connection_id=self.credentials.connection_id,
            customer_private_key=self.credentials.customer_private_key,
            customer_public_key=self.credentials.customer_public_key,
        )
        adapter = PyLibP2PTransport(host="127.0.0.1", requested_port=0, relay_auth=credentials)
        adapter._rss_auth_exchange = mock.AsyncMock(return_value={"status": "enrollment_required"})
        with self.assertRaisesRegex(TransportUnavailable, "enrollment is required"):
            asyncio.run(
                adapter._authenticate_rss_relay(
                    host=SimpleNamespace(get_id=lambda: "12D3KooWClient"),
                    relay_info=SimpleNamespace(peer_id="12D3KooWRelay"),
                    credentials=credentials,
                    allow_enrollment=True,
                )
            )

    def test_https_enrollment_requires_tls13_and_never_uses_noise_control(self) -> None:
        challenge = {
            "status": "challenge",
            "challenge": {
                "protocol": RSS_ENROLLMENT_PROOF_PROTOCOL,
                "challenge_id": "challenge-1",
                "challenge": "nonce-1",
                "expires_at": 100,
            },
        }
        responses = [challenge, {"status": "ok", "connection_id": self.credentials.connection_id, "entitlement_id": self.credentials.entitlement_id}]

        class Response:
            def __init__(self, value: dict[str, object]) -> None:
                self.value = value

            def __enter__(self) -> "Response":
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def read(self, _size: int) -> bytes:
                return json.dumps(self.value).encode()

        context = mock.Mock()
        with mock.patch(
            "secrets_kit.protocol.rss_auth.urllib.request.urlopen",
            side_effect=lambda *_args, **_kwargs: Response(responses.pop(0)),
        ) as open_url:
            perform_rss_https_enrollment(
                credentials=self.credentials,
                ssl_context=context,
            )
        self.assertEqual(context.minimum_version, __import__("ssl").TLSVersion.TLSv1_3)
        self.assertEqual(open_url.call_count, 2)
        for call in open_url.call_args_list:
            self.assertTrue(call.args[0].full_url.startswith("https://"))

    def test_https_enrollment_rejects_wrong_device_receipt(self) -> None:
        challenge = {
            "status": "challenge", "challenge": {
                "protocol": RSS_ENROLLMENT_PROOF_PROTOCOL,
                "challenge_id": "challenge", "challenge": "nonce", "expires_at": 100,
            },
        }
        with mock.patch("secrets_kit.protocol.rss_auth._https_json", side_effect=[
            challenge, {"status": "ok", "entitlement_id": self.credentials.entitlement_id, "connection_id": "another-device"},
        ]):
            with self.assertRaises(RSSAuthenticationError):
                perform_rss_https_enrollment(credentials=self.credentials, ssl_context=mock.Mock())

    def test_https_capacity_denial_is_bounded_and_distinct_from_unavailability(self) -> None:
        import io
        import urllib.error

        from secrets_kit.protocol.rss_auth import _https_json

        for code, body, expected in (
            (409, b'{"status":"denied","reason":"device_capacity_exhausted"}', "capacity is fully provisioned"),
            (403, b"private-provider-detail", "request was rejected"),
            (409, b"x" * 1025, "request was rejected"),
            (409, b'{"status":"denied","reason":"device_capacity_exhausted","extra":"private"}', "request was rejected"),
        ):
            with self.subTest(code=code, size=len(body)), mock.patch(
                "secrets_kit.protocol.rss_auth.urllib.request.urlopen",
                side_effect=urllib.error.HTTPError("https://example.test", code, "private", {}, io.BytesIO(body)),
            ):
                with self.assertRaisesRegex(RSSAuthenticationError, expected):
                    _https_json("https://example.test/v1/enrollment/complete", {}, context=mock.Mock())

    def test_ordered_endpoint_authentication_falls_back_without_sending_ret(self) -> None:
        adapter = PyLibP2PTransport(host="127.0.0.1", requested_port=0)
        primary = SimpleNamespace(peer_id="primary")
        secondary = SimpleNamespace(peer_id="secondary")
        host = SimpleNamespace(connect=mock.AsyncMock())

        async def authenticate_relay(**kwargs: object) -> bool:
            if kwargs["relay_info"] is primary:
                raise TransportUnavailable("primary unavailable")
            return False

        adapter._authenticate_rss_relay = mock.AsyncMock(side_effect=authenticate_relay)
        async def authenticate() -> object:
            return await adapter._authenticate_relay_targets(
                host=host,
                relay_targets=[(primary, True), (secondary, False)],
                credentials=self.credentials,
            )

        loaded = trio.run(authenticate)
        self.assertIs(loaded, self.credentials)
        self.assertEqual(adapter._relay_connected, 1)
        self.assertTrue(adapter._relay_endpoint_states["primary"].startswith("failed:"))
        self.assertEqual(adapter._relay_endpoint_states["secondary"], "authenticated")
        calls = adapter._authenticate_rss_relay.await_args_list
        enrollment_by_peer = {
            call.kwargs["relay_info"].peer_id: call.kwargs["allow_enrollment"]
            for call in calls
        }
        self.assertTrue(enrollment_by_peer["primary"])
        self.assertFalse(enrollment_by_peer["secondary"])

    def test_session_ready_requires_explicit_success_status(self) -> None:
        """The ready protocol label alone is not successful authentication."""
        for status in (None, "denied", "error"):
            with self.subTest(status=status):
                response = {"protocol": RSS_SESSION_READY_PROTOCOL}
                if status is not None:
                    response["status"] = status
                adapter = PyLibP2PTransport(host="127.0.0.1", requested_port=0)
                adapter._rss_auth_exchange = mock.AsyncMock(return_value=response)

                async def authenticate(adapter: PyLibP2PTransport = adapter) -> bool:
                    return await adapter._authenticate_rss_relay(
                        host=SimpleNamespace(get_id=lambda: "synthetic-client"),
                        relay_info=SimpleNamespace(peer_id="primary"),
                        credentials=self.credentials,
                        route_responses=[],
                    )

                with self.assertRaises(TransportUnavailable):
                    trio.run(authenticate)

    def test_existing_primary_authentication_finishes_pending_local_enrollment(self) -> None:
        """A recovered primary proves the device is enrolled without redeeming again."""
        credentials = replace(self.credentials, enrollment_token_file=Path("/synthetic/ret"))
        adapter = PyLibP2PTransport(host="127.0.0.1", requested_port=0)
        primary = SimpleNamespace(peer_id="primary")
        secondary = SimpleNamespace(peer_id="secondary")
        host = SimpleNamespace(connect=mock.AsyncMock())

        async def authenticate_relay(**kwargs: object) -> bool:
            if kwargs["relay_info"] is secondary:
                await trio.sleep(0.01)
            return False  # Existing session, no new enrollment response.

        adapter._authenticate_rss_relay = mock.AsyncMock(side_effect=authenticate_relay)

        async def authenticate() -> RSSRelayClientCredentials:
            return await adapter._authenticate_relay_targets(
                host=host, relay_targets=[(primary, True), (secondary, False)],
                credentials=credentials,
            )

        with mock.patch("secrets_kit.daemon.transport.clear_consumed_rss_enrollment_token") as clear:
            loaded = trio.run(authenticate)
        clear.assert_called_once_with(token_path=credentials.enrollment_token_file)
        self.assertIsNone(loaded.enrollment_token)
        self.assertIsNone(loaded.enrollment_token_file)
        self.assertEqual(loaded.connection_id, credentials.connection_id)
        self.assertEqual(loaded.customer_private_key, credentials.customer_private_key)
        self.assertEqual(adapter._relay_connected, 2)

    def test_failed_pending_ret_cleanup_does_not_report_primary_authenticated(self) -> None:
        credentials = replace(self.credentials, enrollment_token_file=Path("/synthetic/ret"))
        adapter = PyLibP2PTransport(host="127.0.0.1", requested_port=0)
        adapter._authenticate_rss_relay = mock.AsyncMock(return_value=False)

        async def authenticate() -> RSSRelayClientCredentials:
            return await adapter._authenticate_relay_targets(
                host=SimpleNamespace(connect=mock.AsyncMock()),
                relay_targets=[(SimpleNamespace(peer_id="primary"), True)],
                credentials=credentials,
            )

        with mock.patch(
            "secrets_kit.daemon.transport.clear_consumed_rss_enrollment_token",
            side_effect=OSError("cleanup unavailable"),
        ), self.assertRaises(TransportUnavailable):
            trio.run(authenticate)
        self.assertEqual(adapter._relay_connected, 0)
        self.assertTrue(adapter._relay_endpoint_states["primary"].startswith("failed:"))
        self.assertEqual(credentials.enrollment_token_file, Path("/synthetic/ret"))

    def test_secondary_only_authentication_preserves_pending_ret(self) -> None:
        """Fallback alone must not clear a pending primary enrollment reference."""
        credentials = replace(self.credentials, enrollment_token_file=Path("/synthetic/ret"))
        adapter = PyLibP2PTransport(host="127.0.0.1", requested_port=0)
        primary = SimpleNamespace(peer_id="primary")
        secondary = SimpleNamespace(peer_id="secondary")
        host = SimpleNamespace(connect=mock.AsyncMock())

        async def authenticate_relay(**kwargs: object) -> bool:
            if kwargs["relay_info"] is primary:
                raise TransportUnavailable("primary unavailable")
            return False

        adapter._authenticate_rss_relay = mock.AsyncMock(side_effect=authenticate_relay)

        async def authenticate() -> RSSRelayClientCredentials:
            return await adapter._authenticate_relay_targets(
                host=host, relay_targets=[(primary, True), (secondary, False)],
                credentials=credentials,
            )

        with mock.patch("secrets_kit.daemon.transport.clear_consumed_rss_enrollment_token") as clear:
            loaded = trio.run(authenticate)
        clear.assert_not_called()
        self.assertIs(loaded, credentials)
        self.assertEqual(adapter._relay_connected, 1)

    def test_slow_primary_does_not_block_secondary_authentication(self) -> None:
        adapter = PyLibP2PTransport(host="127.0.0.1", requested_port=0)
        primary = SimpleNamespace(peer_id="primary")
        secondary = SimpleNamespace(peer_id="secondary")
        connected: list[str] = []

        async def connect(relay_info: object) -> None:
            connected.append(str(relay_info.peer_id))
            if relay_info is primary:
                await trio.sleep_forever()

        host = SimpleNamespace(connect=mock.AsyncMock(side_effect=connect))
        adapter._authenticate_rss_relay = mock.AsyncMock(return_value=False)

        async def authenticate() -> object:
            return await adapter._authenticate_relay_targets(
                host=host,
                relay_targets=[(primary, True), (secondary, False)],
                credentials=self.credentials,
            )

        with mock.patch(
            "secrets_kit.daemon.transport.TRANSPORT_IO_TIMEOUT_SECONDS", 0.01
        ):
            loaded = trio.run(authenticate)

        self.assertIs(loaded, self.credentials)
        self.assertTrue(adapter._relay_endpoint_states["primary"].startswith("failed:"))
        self.assertEqual(adapter._relay_endpoint_states["secondary"], "authenticated")
        self.assertCountEqual(connected, ["primary", "secondary"])
        adapter._authenticate_rss_relay.assert_awaited_once()

    def test_slow_failed_primary_does_not_starve_secondary_route_selection(self) -> None:
        import multiaddr
        from libp2p.peer.peerinfo import info_from_p2p_addr

        primary_id = "12D3KooWSQA9BTmvTuWs9qW1nSCmQTAtkbSA8fEPVgMf7KEE6F1e"
        secondary_id = "12D3KooWNzr1bzY9jCEYDen2suUuyRGc3QBZheKLJwWZuirjKFAe"
        destination = "12D3KooWB9zdJUBTokkUCLWgMmUVk9N5VzaQq2G6ewxJGsiGE5zD"
        endpoints = [f"/ip4/192.0.2.{i}/tcp/4001/p2p/{peer}" for i, peer in enumerate((primary_id, secondary_id), 1)]
        primary, secondary = [info_from_p2p_addr(multiaddr.Multiaddr(e)) for e in endpoints]
        adapter = PyLibP2PTransport(host="127.0.0.1", requested_port=0, relay_peers=endpoints)
        adapter._connect_and_bind = mock.AsyncMock()
        adapter._rss_auth_exchange = mock.AsyncMock(return_value={
            "protocol": RSS_SESSION_READY_PROTOCOL, "status": "ok", "peer_transport_ids": [destination],
        })

        async def connect(relay_info: object) -> None:
            if relay_info is primary:
                await trio.sleep_forever()

        host = SimpleNamespace(connect=connect, get_id=lambda: "local")

        async def authenticate() -> None:
            adapter._relay_endpoint_states[primary_id] = "authenticated"
            adapter._queue_rss_route_candidates(host=host, relay_info=primary, response={"peer_transport_ids": [destination]})
            await adapter._authenticate_relay_targets(host=host, relay_targets=[(primary, True), (secondary, False)], credentials=self.credentials)
            await trio.sleep(0)

        with mock.patch("secrets_kit.daemon.transport.TRANSPORT_IO_TIMEOUT_SECONDS", 0.01):
            trio.run(authenticate)
        self.assertTrue(adapter._relay_endpoint_states[primary_id].startswith("failed:"))
        self.assertEqual(adapter._relay_candidate_ranks[destination], 1)
        self.assertIn(secondary_id, str(adapter._candidate_infos[destination].addrs[0]))

        async def recover() -> None:
            host.connect = mock.AsyncMock()
            await adapter._authenticate_relay_targets(host=host, relay_targets=[(primary, True), (secondary, False)], credentials=self.credentials)
            await trio.sleep(0)

        trio.run(recover)
        self.assertEqual(adapter._relay_candidate_ranks[destination], 0)
        self.assertIn(primary_id, str(adapter._candidate_infos[destination].addrs[0]))

    def test_authenticated_rss_response_queues_primary_circuit_route(self) -> None:
        import multiaddr
        from libp2p.peer.peerinfo import info_from_p2p_addr

        relay_id = "12D3KooWSQA9BTmvTuWs9qW1nSCmQTAtkbSA8fEPVgMf7KEE6F1e"
        destination_id = "12D3KooWB9zdJUBTokkUCLWgMmUVk9N5VzaQq2G6ewxJGsiGE5zD"
        relay_endpoint = f"/ip4/192.0.2.1/tcp/4001/p2p/{relay_id}"
        adapter = PyLibP2PTransport(
            host="127.0.0.1",
            requested_port=0,
            relay_peers=[relay_endpoint],
        )
        adapter._connect_and_bind = mock.AsyncMock()
        relay = info_from_p2p_addr(multiaddr.Multiaddr(relay_endpoint))

        async def queue() -> None:
            async with trio.open_nursery() as nursery:
                adapter._scope_nursery = nursery
                try:
                    adapter._queue_rss_route_candidates(
                        host=mock.Mock(),
                        relay_info=relay,
                        response={"peer_transport_ids": [destination_id]},
                    )
                    await trio.sleep(0)
                finally:
                    adapter._scope_nursery = None
            adapter._spawn_scope_task(
                adapter._connect_and_bind,
                adapter._candidate_infos[destination_id],
            )
            await trio.sleep(0)

        trio.run(queue)
        candidate = adapter._candidate_infos[destination_id]
        self.assertIn("/p2p-circuit", str(candidate.addrs[0]))
        self.assertEqual(str(candidate.peer_id), destination_id)
        adapter._connect_and_bind.assert_awaited_once()

        peerstore = mock.Mock()
        connecting = PyLibP2PTransport(host="127.0.0.1", requested_port=0)
        connecting._host_object = SimpleNamespace(
            get_peerstore=lambda: peerstore,
            new_stream=mock.AsyncMock(side_effect=RuntimeError("stop after dial")),
        )
        trio.run(connecting._connect_and_bind, candidate)
        stored_address = str(peerstore.add_addrs.call_args.args[1][0])
        self.assertTrue(stored_address.endswith(f"/p2p/{destination_id}"))

    def test_failed_primary_candidate_is_replaced_by_secondary_and_recovers(self) -> None:
        import multiaddr
        from libp2p.peer.peerinfo import info_from_p2p_addr

        primary_id = "12D3KooWSQA9BTmvTuWs9qW1nSCmQTAtkbSA8fEPVgMf7KEE6F1e"
        secondary_id = "12D3KooWNzr1bzY9jCEYDen2suUuyRGc3QBZheKLJwWZuirjKFAe"
        destination_id = "12D3KooWB9zdJUBTokkUCLWgMmUVk9N5VzaQq2G6ewxJGsiGE5zD"
        primary_endpoint = f"/ip4/192.0.2.1/tcp/4001/p2p/{primary_id}"
        secondary_endpoint = f"/ip4/192.0.2.2/tcp/4001/p2p/{secondary_id}"
        adapter = PyLibP2PTransport(
            host="127.0.0.1",
            requested_port=0,
            relay_peers=[primary_endpoint, secondary_endpoint],
        )
        adapter._connect_and_bind = mock.AsyncMock()
        primary = info_from_p2p_addr(multiaddr.Multiaddr(primary_endpoint))
        secondary = info_from_p2p_addr(multiaddr.Multiaddr(secondary_endpoint))

        async def queue() -> None:
            adapter._relay_endpoint_states[primary_id] = "authenticated"
            adapter._queue_rss_route_candidates(
                host=mock.Mock(),
                relay_info=primary,
                response={"peer_transport_ids": [destination_id]},
            )
            adapter._relay_endpoint_states[primary_id] = "failed:primary unavailable"
            adapter._relay_endpoint_states[secondary_id] = "authenticated"
            adapter._queue_rss_route_candidates(
                host=mock.Mock(),
                relay_info=secondary,
                response={"peer_transport_ids": [destination_id]},
            )
            self.assertIn(
                secondary_id,
                str(adapter._candidate_infos[destination_id].addrs[0]),
            )
            self.assertEqual(adapter._relay_candidate_ranks[destination_id], 1)
            adapter._relay_endpoint_states[primary_id] = "authenticated"
            adapter._queue_rss_route_candidates(
                host=mock.Mock(),
                relay_info=primary,
                response={"peer_transport_ids": [destination_id]},
            )
            await trio.sleep(0)

        trio.run(queue)
        self.assertIn(primary_id, str(adapter._candidate_infos[destination_id].addrs[0]))
        self.assertEqual(adapter._relay_candidate_ranks[destination_id], 0)

    def test_rss_candidate_coalescing_preserves_rank_and_rebinds_changed_endpoint(
        self,
    ) -> None:
        import multiaddr
        from libp2p.peer.peerinfo import info_from_p2p_addr

        primary_id = "12D3KooWSQA9BTmvTuWs9qW1nSCmQTAtkbSA8fEPVgMf7KEE6F1e"
        secondary_id = "12D3KooWNzr1bzY9jCEYDen2suUuyRGc3QBZheKLJwWZuirjKFAe"
        destination_id = "12D3KooWB9zdJUBTokkUCLWgMmUVk9N5VzaQq2G6ewxJGsiGE5zD"
        primary_endpoint = f"/ip4/192.0.2.1/tcp/4001/p2p/{primary_id}"
        secondary_endpoint = f"/ip4/192.0.2.2/tcp/4001/p2p/{secondary_id}"
        moved_primary_endpoint = f"/ip4/192.0.2.3/tcp/4001/p2p/{primary_id}"
        adapter = PyLibP2PTransport(
            host="127.0.0.1",
            requested_port=0,
            relay_peers=[primary_endpoint, secondary_endpoint],
        )
        adapter._spawn_scope_task = mock.Mock()
        primary, secondary, moved_primary = [
            info_from_p2p_addr(multiaddr.Multiaddr(endpoint))
            for endpoint in (
                primary_endpoint,
                secondary_endpoint,
                moved_primary_endpoint,
            )
        ]
        adapter._relay_endpoint_states.update(
            {primary_id: "authenticated", secondary_id: "authenticated"}
        )

        for relay in (primary, secondary, primary):
            adapter._queue_rss_route_candidates(
                host=mock.Mock(),
                relay_info=relay,
                response={"peer_transport_ids": [destination_id]},
            )

        self.assertEqual(adapter._relay_candidate_ranks[destination_id], 0)
        self.assertIn(
            primary_endpoint,
            str(adapter._candidate_infos[destination_id].addrs[0]),
        )
        adapter._spawn_scope_task.assert_called_once()

        adapter._queue_rss_route_candidates(
            host=mock.Mock(),
            relay_info=moved_primary,
            response={"peer_transport_ids": [destination_id]},
        )

        self.assertEqual(adapter._relay_candidate_ranks[destination_id], 0)
        self.assertIn(
            moved_primary_endpoint,
            str(adapter._candidate_infos[destination_id].addrs[0]),
        )
        self.assertEqual(adapter._spawn_scope_task.call_count, 2)

    def test_circuit_switch_closes_cached_connection_and_replaces_dial_address(self) -> None:
        import multiaddr
        from libp2p.peer.peerinfo import info_from_p2p_addr

        relays = ("12D3KooWSQA9BTmvTuWs9qW1nSCmQTAtkbSA8fEPVgMf7KEE6F1e", "12D3KooWNzr1bzY9jCEYDen2suUuyRGc3QBZheKLJwWZuirjKFAe")
        destination = "12D3KooWB9zdJUBTokkUCLWgMmUVk9N5VzaQq2G6ewxJGsiGE5zD"
        primary, secondary = [info_from_p2p_addr(multiaddr.Multiaddr(
            f"/ip4/192.0.2.{i}/tcp/4001/p2p/{relay}/p2p-circuit/p2p/{destination}"
        )) for i, relay in enumerate(relays, 1)]
        peerstore = mock.Mock()
        network = SimpleNamespace(close_peer=mock.AsyncMock())
        adapter = PyLibP2PTransport(host="127.0.0.1", requested_port=0)
        adapter._host_object = SimpleNamespace(
            get_peerstore=lambda: peerstore, get_network=lambda: network,
            new_stream=mock.AsyncMock(side_effect=RuntimeError("stop after dial selection")),
        )
        for candidate in (primary, primary):
            trio.run(adapter._connect_and_bind, candidate)
        network.close_peer.assert_not_awaited()
        for candidate in (secondary, secondary):
            trio.run(adapter._connect_and_bind, candidate)
        network.close_peer.assert_awaited_once_with(secondary.peer_id)
        peerstore.clear_addrs.assert_called_with(secondary.peer_id)
        self.assertIn(relays[1], str(peerstore.add_addrs.call_args.args[1][0]))

    def test_rss_startup_unavailability_retains_retry_without_reserving(self) -> None:
        import multiaddr
        from libp2p.relay.circuit_v2 import CircuitV2Protocol, CircuitV2Transport

        relay = "/ip4/192.0.2.1/tcp/4001/p2p/12D3KooWSQA9BTmvTuWs9qW1nSCmQTAtkbSA8fEPVgMf7KEE6F1e"
        for authenticated in (False, True):
            with self.subTest(authenticated=authenticated):
                adapter = PyLibP2PTransport(
                    host="127.0.0.1", requested_port=0,
                    relay_peers=[relay], relay_auth=self.credentials,
                )
                host = SimpleNamespace(get_network=lambda: SimpleNamespace(transport_manager=mock.Mock()))
                services = SimpleNamespace(enter_async_context=mock.AsyncMock())
                discovery = mock.Mock()
                discovery._add_relay = mock.AsyncMock()
                discovery.make_reservation = mock.AsyncMock(return_value=False)
                discovery.get_relay_info.return_value = SimpleNamespace(has_reservation=False)

                async def authenticate(*, adapter=adapter, authenticated=authenticated, **kwargs):
                    peer = str(kwargs["relay_targets"][0][0].peer_id)
                    adapter._relay_endpoint_states[peer] = "authenticated" if authenticated else "failed:denied"
                    if not authenticated:
                        raise TransportUnavailable("no configured RSS endpoint authenticated")
                    return self.credentials

                async def exercise(
                    adapter=adapter, authenticated=authenticated, discovery=discovery,
                    host=host, services=services, authenticate=authenticate,
                ):
                    with mock.patch.object(CircuitV2Protocol, "__init__", return_value=None), mock.patch.object(
                        CircuitV2Transport, "__init__", return_value=None
                    ), mock.patch("libp2p.relay.circuit_v2.discovery.RelayDiscovery", return_value=discovery) as factory, mock.patch.object(
                        adapter, "_authenticate_relay_targets", side_effect=authenticate
                    ):
                        await adapter._start_relay_services(host=host, multiaddr=multiaddr, services=services)
                        factory.assert_called_once_with(host, auto_reserve=False)
                    self.assertIs(adapter._relay_auth_refresh[1], self.credentials)
                    self.assertIs(adapter._relay_discovery_service, discovery)
                    if authenticated:
                        discovery.make_reservation.assert_awaited_once()
                    else:
                        discovery._add_relay.assert_not_awaited()
                        discovery.make_reservation.assert_not_awaited()

                trio.run(exercise)

    def test_transport_thread_starts_denied_and_recovers_on_authenticated_retry(self) -> None:
        from libp2p.relay.circuit_v2.discovery import RelayDiscovery

        from secrets_kit.daemon.routing import RoutingTable
        from secrets_kit.daemon.transport import TransportServices

        allow = threading.Event()
        reserved = threading.Event()
        adapter = PyLibP2PTransport(
            host="127.0.0.1", requested_port=0, discovery=False,
            relay_peers=["/ip4/127.0.0.1/tcp/1/p2p/12D3KooWSQA9BTmvTuWs9qW1nSCmQTAtkbSA8fEPVgMf7KEE6F1e"],
            relay_auth=self.credentials,
        )

        async def authenticate(**kwargs):
            peer = str(kwargs["relay_targets"][0][0].peer_id)
            adapter._relay_endpoint_states[peer] = "authenticated" if allow.is_set() else "failed:denied"
            adapter._relay_connected = int(allow.is_set())
            if not allow.is_set():
                raise TransportUnavailable("no configured RSS endpoint authenticated")
            return self.credentials

        async def reserve(peer):
            self.assertTrue(allow.is_set())
            self.assertIsNotNone(adapter._relay_discovery_service.get_relay_info(peer))
            reserved.set()
            return True

        services = TransportServices(
            frame_handler=lambda *_: (b"{}", True), routing_table=RoutingTable(),
            sign_transport_binding=lambda *_: {}, verify_transport_binding=lambda *_: "node:test",
        )
        with tempfile.TemporaryDirectory() as directory, mock.patch(
            "secrets_kit.daemon.client.runtime_dir", return_value=Path(directory)
        ), mock.patch("secrets_kit.daemon.transport.RSS_RELAY_MAINTENANCE_INTERVAL_SECONDS", 0.05), mock.patch.object(
            adapter, "_authenticate_relay_targets", side_effect=authenticate
        ), mock.patch.object(RelayDiscovery, "discover_relays", new=mock.AsyncMock()), mock.patch.object(
            RelayDiscovery, "make_reservation", side_effect=reserve
        ) as reservation:
            try:
                adapter.start(services=services)
                self.assertTrue(adapter._thread.is_alive())
                self.assertEqual(adapter.metadata()["relay_connected"], 0)
                reservation.assert_not_awaited()
                allow.set()
                self.assertTrue(reserved.wait(5), "authenticated retry did not reserve")
                self.assertEqual(adapter.metadata()["relay_connected"], 1)
            finally:
                adapter.stop()

    def test_cached_circuit_reads_response_without_waiting_for_eof(self) -> None:
        import multiaddr
        from libp2p.peer.peerinfo import info_from_p2p_addr
        from libp2p.relay.circuit_v2 import CircuitV2Protocol, CircuitV2Transport
        from libp2p.relay.circuit_v2.transport import HopMessage, RelayConnectionError, StatusCode

        adapter = PyLibP2PTransport(host="127.0.0.1", requested_port=0)
        manager = mock.Mock()
        host = SimpleNamespace(get_network=lambda: SimpleNamespace(transport_manager=manager))
        services = SimpleNamespace(enter_async_context=mock.AsyncMock(side_effect=RuntimeError("captured")))

        async def capture() -> None:
            with mock.patch.object(CircuitV2Protocol, "__init__", return_value=None), mock.patch.object(
                CircuitV2Transport, "__init__", return_value=None
            ), self.assertRaisesRegex(RuntimeError, "captured"):
                await adapter._start_relay_services(host=host, multiaddr=multiaddr, services=services)

        trio.run(capture)
        transport = manager.add_transport.call_args.args[0]
        address = multiaddr.Multiaddr(
            "/ip4/192.0.2.1/tcp/4001/p2p/12D3KooWSQA9BTmvTuWs9qW1nSCmQTAtkbSA8fEPVgMf7KEE6F1e"
            "/p2p-circuit/p2p/12D3KooWB9zdJUBTokkUCLWgMmUVk9N5VzaQq2G6ewxJGsiGE5zD"
        )
        response = HopMessage(type=HopMessage.STATUS)
        response.status.code = StatusCode.OK

        async def read(n=None):
            if n is None:
                await trio.sleep_forever()
            return response.SerializeToString()

        stream = SimpleNamespace(read=mock.AsyncMock(side_effect=read), write=mock.AsyncMock(),
                                 close=mock.AsyncMock(), reset=mock.AsyncMock())
        transport.host = SimpleNamespace(new_stream=mock.AsyncMock(return_value=stream))
        transport.performance_tracker = mock.Mock()

        async def dial() -> None:
            # Reproduce the installed dependency bug against the same open stream.
            with self.assertRaises(trio.TooSlowError), trio.fail_after(0.01):
                await CircuitV2Transport._dial_via_circuit_addr(
                    transport, address, info_from_p2p_addr(address)
                )
            stream.read.reset_mock()
            with trio.fail_after(0.2):
                connection = await transport._dial_via_circuit_addr(address, info_from_p2p_addr(address))
            self.assertIsNotNone(connection)

        trio.run(dial)
        stream.read.assert_awaited_once_with(1024)
        stream.close.assert_not_awaited()
        stream.reset.assert_not_awaited()

        async def denied() -> None:
            response.status.code = StatusCode.PERMISSION_DENIED
            with self.assertRaises(RelayConnectionError):
                await transport._dial_via_circuit_addr(address, info_from_p2p_addr(address))

        trio.run(denied)
        stream.reset.assert_awaited_once()

    def test_auth_exchange_retains_only_successful_ready_stream(self) -> None:
        for status in (None, "denied", "error", "ok"):
            with self.subTest(status=status):
                adapter = PyLibP2PTransport(host="127.0.0.1", requested_port=0)
                stream = SimpleNamespace(write=mock.AsyncMock(), close=mock.AsyncMock())
                response = {"protocol": RSS_SESSION_READY_PROTOCOL, "status": status}

                async def exchange(
                    adapter: PyLibP2PTransport = adapter,
                    stream: SimpleNamespace = stream,
                ) -> dict[str, object]:
                    return await adapter._rss_auth_exchange(
                        host=SimpleNamespace(new_stream=mock.AsyncMock(return_value=stream)),
                        relay_info=SimpleNamespace(peer_id="primary"),
                        request={}, proof_builder=lambda _: {},
                        expected_challenge_protocol=RSS_SESSION_AUTH_PROTOCOL,
                    )

                with mock.patch(
                    "secrets_kit.daemon.transport._read_stream_frame",
                    new=mock.AsyncMock(side_effect=[
                        json.dumps({"status": "challenge", "challenge": {}}).encode(),
                        json.dumps(response).encode(),
                    ]),
                ), mock.patch.object(RSSAuthenticationChallenge, "from_mapping"):
                    self.assertEqual(trio.run(exchange), response)
                if status == "ok":
                    self.assertIs(adapter._relay_control_streams["primary"], stream)
                    stream.close.assert_not_awaited()
                else:
                    self.assertEqual(adapter._relay_control_streams, {})
                    stream.close.assert_awaited_once()

    def test_rss_auth_exchange_times_out(self) -> None:
        adapter = PyLibP2PTransport(host="127.0.0.1", requested_port=0)

        async def blocked_new_stream(*_args: object, **_kwargs: object) -> object:
            await trio.sleep_forever()
            raise AssertionError("unreachable")

        host = SimpleNamespace(new_stream=blocked_new_stream)
        relay = SimpleNamespace(peer_id="primary")

        async def exchange() -> None:
            with (
                mock.patch(
                    "secrets_kit.daemon.transport.TRANSPORT_IO_TIMEOUT_SECONDS",
                    0.01,
                ),
                self.assertRaisesRegex(
                    TransportUnavailable,
                    "RSS authentication exchange timed out",
                ),
            ):
                await adapter._rss_auth_exchange(
                    host=host,
                    relay_info=relay,
                    request={"operation": "session_challenge"},
                )

        trio.run(exchange)

    def test_environment_loader_rejects_group_readable_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            key_path = Path(directory) / "rss-key.json"
            key_path.write_text(
                json.dumps(signing_keypair_to_record(keypair=self.keypair)),
                encoding="utf-8",
            )
            key_path.chmod(0o640)
            with mock.patch.dict(
                os.environ,
                {
                    "SECKIT_RSS_AUTH_KEY_FILE": str(key_path),
                    "SECKIT_RSS_ENTITLEMENT_ID": "ent_test_123",
                    "SECKIT_RSS_CONNECTION_ID": "host-a:user-a",
                },
                clear=False,
            ):
                with self.assertRaisesRegex(RSSAuthenticationError, "permissions are too broad"):
                    load_rss_relay_credentials_from_environment()

    def test_customer_key_file_creation_is_private_and_non_overwriting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "customer" / "rss-auth.json"
            create_rss_authentication_key_file(path=path)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                create_rss_authentication_key_file(path=path)

    def test_customer_configuration_creates_private_profile_and_loads_without_env(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            token_path = root / "ret"
            token_path.write_text("ret1.opaque.signature", encoding="utf-8")
            token_path.chmod(0o600)
            profile_path = root / "config" / "rss-client.json"
            configure_rss_client(
                enrollment_token_file=token_path,
                entitlement_id="ent_test_123",
                connection_id="host-a:user-a",
                relay_peers=["/ip4/192.0.2.1/tcp/4001/p2p/relay"],
                enrollment_url="https://rss-use1.example.test",
                profile_path=profile_path,
            )
            self.assertEqual(profile_path.stat().st_mode & 0o777, 0o600)
            with (
                mock.patch(
                    "secrets_kit.protocol.rss_auth.rss_client_profile_path",
                    return_value=profile_path,
                ),
                mock.patch.dict(os.environ, {}, clear=True),
            ):
                loaded = load_rss_relay_credentials_from_environment()
                peers = load_rss_relay_peers_from_profile()
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded.entitlement_id, "ent_test_123")
            self.assertEqual(peers, ("/ip4/192.0.2.1/tcp/4001/p2p/relay",))

    def test_rss_configure_cli_accepts_token_file_not_token_argument(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            [
                "rss",
                "configure",
                "--enrollment-token-file",
                "/protected/ret",
                "--entitlement-id",
                "ent_test_123",
                "--connection-id",
                "host-a:user-a",
                "--relay-peer",
                "/ip4/192.0.2.1/tcp/4001/p2p/relay",
                "--enrollment-url",
                "https://rss-use1.example.test",
            ]
        )
        self.assertIs(args.func, cmd_rss_configure)
        self.assertFalse(hasattr(args, "enrollment_token"))

    def test_customer_checkout_and_enroll_commands_are_supported(self) -> None:
        parser = build_parser()
        checkout = parser.parse_args(["rss", "checkout"])
        enroll = parser.parse_args(["rss", "enroll"])
        self.assertIs(checkout.func, cmd_rss_checkout)
        self.assertEqual(checkout.connection_units, 2)
        self.assertIs(enroll.func, cmd_rss_enroll)

    def test_enrollment_establishes_managed_daemon_service(self) -> None:
        with (
            mock.patch(
                "secrets_kit.cli.commands.rss.complete_rss_enrollment",
                return_value=Path("/protected/rss-client.json"),
            ),
            mock.patch("secrets_kit.cli.commands.rss.install_service") as install,
            mock.patch("secrets_kit.cli.commands.rss.request_daemon_status", return_value={"rss": {"authenticated_relays": 1}}),
        ):
            code = cmd_rss_enroll(args=SimpleNamespace())
        self.assertEqual(code, 0)
        install.assert_called_once_with(reload_runtime=True)

    def test_configuration_report_requires_observed_rss_authorization(self) -> None:
        from secrets_kit.cli.commands.rss import _report_configuration
        from secrets_kit.daemon.client import DaemonError

        for status, expected in [
            ({}, 1),
            ({"rss": {"authenticated_relays": 0}}, 1),
            ({"rss": {"authenticated_relays": True}}, 1),
            ({"rss": {"authenticated_relays": "1"}}, 1),
            ({"rss": {"authenticated_relays": 1}}, 0),
        ]:
            with self.subTest(status=status), mock.patch(
                "secrets_kit.cli.commands.rss.request_daemon_status", return_value=status
            ), mock.patch("secrets_kit.cli.commands.rss._fatal", return_value=1):
                self.assertEqual(_report_configuration(profile=Path("/protected/profile")), expected)
        with mock.patch(
            "secrets_kit.cli.commands.rss.request_daemon_status", side_effect=DaemonError("private error")
        ), mock.patch("secrets_kit.cli.commands.rss._fatal", return_value=1) as fatal:
            self.assertEqual(_report_configuration(profile=Path("/protected/profile")), 1)
            self.assertNotIn("private error", fatal.call_args.kwargs["message"])

    def test_capacity_feedback_is_allowlisted_and_never_overrides_success(self) -> None:
        from secrets_kit.cli.commands.rss import _report_configuration

        for error, count, expected in [
            ("RSS device capacity is fully provisioned", 0, "device_capacity_exhausted"),
            ("provider secret response", 0, "rss_authorization_pending"),
            ("RSS device capacity is fully provisioned", 1, None),
        ]:
            status = {"rss": {"authenticated_relays": count}, "routing": {"discovery": {"events": [
                {"event": "rss_authentication_failed", "error": error}
            ]}}}
            with self.subTest(error=error, count=count), mock.patch(
                "secrets_kit.cli.commands.rss.request_daemon_status", return_value=status
            ), mock.patch("secrets_kit.cli.commands.rss._fatal", return_value=1), mock.patch("builtins.print") as output:
                code = _report_configuration(profile=Path("/protected/profile"))
                result = json.loads(output.call_args.args[0])
                self.assertEqual(result.get("error"), expected)
                self.assertEqual(code, int(expected is not None))
                self.assertNotIn("provider secret response", output.call_args.args[0])

    def test_daemon_status_exposes_only_rss_configuration_and_authentication_count(self) -> None:
        from secrets_kit.daemon.server import _status_response

        adapter = mock.Mock()
        adapter.name = "libp2p"
        adapter.snapshot.return_value.as_dict.return_value = {
            "relay_configured": True, "relay_connected": 2,
        }
        with mock.patch("secrets_kit.daemon.server._invoke_runtime_status", return_value={"peers": []}):
            result = json.loads(_status_response(transport_adapter=adapter, routing_table=None))
        self.assertEqual(result["data"]["rss"], {"configured": True, "authenticated_relays": 2})

    def test_enrollment_service_failure_reports_supported_recovery(self) -> None:
        with (
            mock.patch(
                "secrets_kit.cli.commands.rss.complete_rss_enrollment",
                return_value=Path("/protected/rss-client.json"),
            ),
            mock.patch(
                "secrets_kit.cli.commands.rss.install_service",
                side_effect=DaemonServiceError("service manager rejected request"),
            ),
            mock.patch("secrets_kit.cli.commands.rss._fatal", return_value=1) as fatal,
        ):
            code = cmd_rss_enroll(args=SimpleNamespace())
        self.assertEqual(code, 1)
        self.assertIn("seckit daemon service install", fatal.call_args.kwargs["message"])
        self.assertNotIn("service manager rejected request", fatal.call_args.kwargs["message"])

    def test_identity_import_reloads_existing_daemon_configuration(self) -> None:
        from secrets_kit.cli.commands.rss import cmd_rss_identity_import

        with (
            mock.patch(
                "secrets_kit.cli.commands.rss.import_rss_authentication_identity",
                return_value=Path("/protected/rss-auth-key.json"),
            ),
            mock.patch("secrets_kit.cli.commands.rss.install_service") as install,
        ):
            code = cmd_rss_identity_import(args=SimpleNamespace(input="/protected/transfer.json"))
        self.assertEqual(code, 0)
        install.assert_called_once_with(reload_runtime=True)

    def test_configuration_failure_does_not_install_daemon_service(self) -> None:
        with (
            mock.patch(
                "secrets_kit.cli.commands.rss.configure_rss_client",
                side_effect=RSSAuthenticationError("configuration failed"),
            ),
            mock.patch("secrets_kit.cli.commands.rss.install_service") as install,
        ):
            code = cmd_rss_configure(
                args=SimpleNamespace(
                    enrollment_token_file="/protected/ret",
                    entitlement_id="ent_test",
                    connection_id="host-a",
                    relay_peer=["/ip4/192.0.2.1/tcp/4001/p2p/relay"],
                    enrollment_url="https://operator.example.test",
                )
            )
        self.assertEqual(code, 1)
        install.assert_not_called()

    def test_existing_customer_identity_configures_second_peer_without_ret(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            profile_path = Path(directory) / "rss-client.json"
            create_rss_authentication_key_file(path=profile_path.with_name("rss-auth-key.json"))
            configure_rss_client(
                enrollment_token_file=None,
                entitlement_id="ent_test_123",
                connection_id="host-b:user-a",
                relay_peers=["/ip4/192.0.2.1/tcp/4001/p2p/relay"],
                enrollment_url="https://rss-use1.example.test",
                profile_path=profile_path,
            )
            value = json.loads(profile_path.read_text(encoding="utf-8"))
            self.assertEqual(value["enrollment_token_file"], "")

    def test_new_customer_identity_fails_closed_without_ret(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RSSAuthenticationError, "Token is required"):
                configure_rss_client(
                    enrollment_token_file=None,
                    entitlement_id="ent_test_123",
                    connection_id="host-a:user-a",
                    relay_peers=["/ip4/192.0.2.1/tcp/4001/p2p/relay"],
                    enrollment_url="https://rss-use1.example.test",
                    profile_path=Path(directory) / "rss-client.json",
                )

    def test_connection_id_is_generated_when_omitted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            token = root / "ret"
            token.write_text("ret1.opaque.signature", encoding="utf-8")
            token.chmod(0o600)
            profile = configure_rss_client(
                enrollment_token_file=token,
                entitlement_id="ent_test_123",
                connection_id=None,
                relay_peers=["/ip4/192.0.2.1/tcp/4001/p2p/relay"],
                enrollment_url="https://rss-use1.example.test",
                profile_path=root / "rss-client.json",
            )
            value = json.loads(profile.read_text(encoding="utf-8"))
            self.assertTrue(value["connection_id"].startswith("connection-"))
            self.assertEqual(value["enrollment_primary"], value["relay_peers"][0])

    def test_protected_identity_export_import_handoff(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = root / "rss-client.json"
            key = profile.with_name("rss-auth-key.json")
            create_rss_authentication_key_file(path=key)
            original = key.read_bytes()
            configure_rss_client(
                enrollment_token_file=None,
                entitlement_id="ent_test_123",
                connection_id="connection-a",
                relay_peers=[
                    "/dns4/east.example.test/tcp/4001/p2p/east",
                    "/dns4/west.example.test/tcp/4001/p2p/west",
                ],
                enrollment_url="https://ops.example.test",
                profile_path=profile,
            )
            transfer = root / "transfer" / "identity.json"
            with mock.patch(
                "secrets_kit.protocol.rss_auth.rss_client_profile_path",
                return_value=profile,
            ):
                export_rss_authentication_identity(path=transfer)
                key.unlink()
                profile.unlink()
                import_rss_authentication_identity(path=transfer)
            self.assertEqual(key.read_bytes(), original)
            self.assertEqual(transfer.stat().st_mode & 0o777, 0o600)
            self.assertEqual(key.stat().st_mode & 0o777, 0o600)
            imported = json.loads(profile.read_text(encoding="utf-8"))
            self.assertEqual(imported["entitlement_id"], "ent_test_123")
            self.assertNotEqual(imported["connection_id"], "connection-a")

    def test_consumed_ret_is_removed_and_profile_cleared(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = root / "rss-client.json"
            token = root / "ret"
            token.write_text("ret1.opaque.signature", encoding="utf-8")
            token.chmod(0o600)
            profile.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "entitlement_id": "ent_test_123",
                        "connection_id": "connection-a",
                        "key_file": str(root / "rss-auth-key.json"),
                        "enrollment_token_file": str(token),
                        "relay_peers": ["relay"],
                        "enrollment_primary": "relay",
                        "enrollment_url": "https://rss-use1.example.test",
                    }
                ),
                encoding="utf-8",
            )
            profile.chmod(0o600)
            with mock.patch(
                "secrets_kit.protocol.rss_auth.rss_client_profile_path",
                return_value=profile,
            ):
                clear_consumed_rss_enrollment_token(token_path=token)
            self.assertFalse(token.exists())
            self.assertEqual(json.loads(profile.read_text())["enrollment_token_file"], "")


if __name__ == "__main__":
    unittest.main()
