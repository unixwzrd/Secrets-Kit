"""Focused lifecycle and candidate-ownership tests for daemon mDNS."""

from __future__ import annotations

import threading
import unittest
from unittest import mock

from zeroconf import ServiceInfo

from secrets_kit.daemon.mdns import SERVICE_TYPE, DaemonMDNS

LOCAL = "12D3KooWEmKKnZoADrxx55LV7zAwpDWMCgbucL1jLKcsrQ2Nms9F"
PEER_A = "12D3KooWSQA9BTmvTuWs9qW1nSCmQTAtkbSA8fEPVgMf7KEE6F1e"
PEER_B = "12D3KooWNzr1bzY9jCEYDen2suUuyRGc3QBZheKLJwWZuirjKFAe"


def _service(*, name: str, peer_id: str = PEER_A, address: str = "192.0.2.10", port: int = 43123) -> ServiceInfo:
    return ServiceInfo(
        type_=SERVICE_TYPE,
        name=name,
        port=port,
        properties={b"id": peer_id.encode()},
        parsed_addresses=[address],
    )


class _ServiceLookup:
    def __init__(self, services: dict[str, ServiceInfo | None]) -> None:
        self.services = services

    def get_service_info(self, type_: str, name: str, *, timeout: int) -> ServiceInfo | None:
        assert type_ == SERVICE_TYPE
        assert timeout > 0
        return self.services.get(name)


class DaemonMDNSTests(unittest.TestCase):
    """Verify updates and shutdown never escape mDNS candidate ownership."""

    def _active_discovery(self) -> tuple[DaemonMDNS, list[object], list[str]]:
        candidates: list[object] = []
        removed: list[str] = []
        discovery = DaemonMDNS(
            peer_id=LOCAL,
            port=43123,
            addresses=lambda: ["192.0.2.1"],
            on_candidate=candidates.append,
            on_remove=removed.append,
            refresh_interval=60,
        )
        discovery._active.set()
        return discovery, candidates, removed

    def test_add_update_remove_replaces_only_mdns_candidate(self) -> None:
        discovery, candidates, removed = self._active_discovery()
        name = f"one.{SERVICE_TYPE}"
        lookup = _ServiceLookup({name: _service(name=name)})
        discovery._zeroconf = lookup

        discovery.add_service(lookup, SERVICE_TYPE, name)
        lookup.services[name] = _service(name=name, address="192.0.2.11", port=44123)
        discovery.update_service(lookup, SERVICE_TYPE, name)
        discovery.remove_service(lookup, SERVICE_TYPE, f"unknown.{SERVICE_TYPE}")
        discovery.remove_service(lookup, SERVICE_TYPE, name)

        self.assertEqual(len(candidates), 2)
        self.assertEqual(str(candidates[-1].addrs[0]), "/ip4/192.0.2.11/tcp/44123")
        self.assertEqual(removed, [PEER_A])

    def test_interface_retirement_removes_old_candidates(self) -> None:
        discovery, candidates, removed = self._active_discovery()
        name = f"old-interface.{SERVICE_TYPE}"
        lookup = _ServiceLookup({name: _service(name=name)})
        discovery._zeroconf = lookup
        discovery.add_service(lookup, SERVICE_TYPE, name)
        discovery._detach_membership()
        discovery._remove_all_candidates()
        discovery.update_service(lookup, SERVICE_TYPE, name)
        self.assertEqual(removed, [PEER_A])
        self.assertEqual(len(candidates), 1)
        self.assertEqual(discovery._services, {})

    def test_multiple_service_names_keep_peer_until_last_remove(self) -> None:
        discovery, candidates, removed = self._active_discovery()
        first = f"first.{SERVICE_TYPE}"
        second = f"second.{SERVICE_TYPE}"
        lookup = _ServiceLookup(
            {
                first: _service(name=first, address="192.0.2.10"),
                second: _service(name=second, address="192.0.2.11"),
            }
        )
        discovery._zeroconf = lookup

        discovery.add_service(lookup, SERVICE_TYPE, first)
        discovery.add_service(lookup, SERVICE_TYPE, second)
        discovery.remove_service(lookup, SERVICE_TYPE, first)
        self.assertEqual(removed, [])
        self.assertEqual(str(candidates[-1].addrs[0]), "/ip4/192.0.2.11/tcp/43123")
        discovery.remove_service(lookup, SERVICE_TYPE, second)
        self.assertEqual(removed, [PEER_A])

    def test_update_changed_identity_removes_old_and_adds_new(self) -> None:
        discovery, candidates, removed = self._active_discovery()
        name = f"changed.{SERVICE_TYPE}"
        lookup = _ServiceLookup({name: _service(name=name, peer_id=PEER_A)})
        discovery._zeroconf = lookup
        discovery.add_service(lookup, SERVICE_TYPE, name)
        lookup.services[name] = _service(name=name, peer_id=PEER_B)

        discovery.update_service(lookup, SERVICE_TYPE, name)

        self.assertEqual(removed, [PEER_A])
        self.assertEqual([str(candidate.peer_id) for candidate in candidates], [PEER_A, PEER_B])

    def test_malformed_self_and_wildcard_announcements_are_rejected(self) -> None:
        discovery, candidates, removed = self._active_discovery()
        valid_name = f"valid.{SERVICE_TYPE}"
        missing_name = f"missing.{SERVICE_TYPE}"
        malformed_name = f"malformed.{SERVICE_TYPE}"
        self_name = f"self.{SERVICE_TYPE}"
        wildcard_name = f"wildcard.{SERVICE_TYPE}"
        missing = _service(name=missing_name)
        missing.properties.clear()
        lookup = _ServiceLookup(
            {
                valid_name: _service(name=valid_name),
                missing_name: missing,
                malformed_name: _service(name=malformed_name, peer_id="not-a-peer-id"),
                self_name: _service(name=self_name, peer_id=LOCAL),
                wildcard_name: _service(name=wildcard_name, address="0.0.0.0"),
            }
        )
        discovery._zeroconf = lookup
        discovery.add_service(lookup, SERVICE_TYPE, valid_name)
        for name in (missing_name, malformed_name, self_name, wildcard_name):
            discovery.add_service(lookup, SERVICE_TYPE, name)
        lookup.services[valid_name] = missing
        discovery.update_service(lookup, SERVICE_TYPE, valid_name)

        self.assertEqual(len(candidates), 1)
        self.assertEqual(removed, [PEER_A])

    def test_selected_lan_interface_actual_port_and_shutdown_disable_callbacks(self) -> None:
        created: dict[str, object] = {}
        fake_zeroconf = mock.Mock()
        fake_browser = mock.Mock()

        def make_zeroconf(*, interfaces, use_asyncio):
            created["interfaces"] = interfaces
            created["use_asyncio"] = use_asyncio
            return fake_zeroconf

        def make_browser(zeroconf, service_type, *, listener):
            created["listener"] = listener
            self.assertIs(zeroconf, fake_zeroconf)
            self.assertEqual(service_type, SERVICE_TYPE)
            return fake_browser

        candidates: list[object] = []
        discovery = DaemonMDNS(
            peer_id=LOCAL,
            port=45123,
            addresses=lambda: ["192.0.2.20"],
            on_candidate=candidates.append,
            on_remove=lambda _peer_id: None,
            refresh_interval=60,
        )
        with (
            mock.patch("secrets_kit.daemon.mdns.Zeroconf", side_effect=make_zeroconf),
            mock.patch("secrets_kit.daemon.mdns.ServiceBrowser", side_effect=make_browser),
        ):
            discovery.start()
            registered = fake_zeroconf.register_service.call_args.args[0]
            self.assertEqual(registered.port, 45123)
            self.assertEqual(registered.parsed_addresses(), ["192.0.2.20"])
            self.assertEqual(created["interfaces"], ["192.0.2.20"])
            discovery.stop()

        created["listener"].add_service(
            _ServiceLookup({f"late.{SERVICE_TYPE}": _service(name=f"late.{SERVICE_TYPE}")}),
            SERVICE_TYPE,
            f"late.{SERVICE_TYPE}",
        )
        self.assertEqual(candidates, [])
        fake_browser.cancel.assert_called_once()
        fake_zeroconf.close.assert_called_once()

    def test_address_switch_recreates_default_interface_membership(self) -> None:
        replacement_opened = threading.Event()
        caller_thread = threading.get_ident()
        observed_thread: list[int] = []
        addresses = iter((["192.0.2.30"], ["192.0.2.31"]))
        first_zeroconf = mock.Mock()
        second_zeroconf = mock.Mock()

        def register_replacement(_info: ServiceInfo) -> None:
            observed_thread.append(threading.get_ident())
            replacement_opened.set()

        second_zeroconf.register_service.side_effect = register_replacement
        discovery = DaemonMDNS(
            peer_id=LOCAL,
            port=43123,
            addresses=lambda: next(addresses),
            on_candidate=lambda _candidate: None,
            on_remove=lambda _peer_id: None,
            refresh_interval=0.01,
        )
        with (
            mock.patch(
                "secrets_kit.daemon.mdns.Zeroconf",
                side_effect=(first_zeroconf, second_zeroconf),
            ) as constructor,
            mock.patch(
                "secrets_kit.daemon.mdns.ServiceBrowser",
                side_effect=(mock.Mock(), mock.Mock()),
            ),
        ):
            discovery.start()
            self.assertTrue(replacement_opened.wait(timeout=1))
            discovery.stop()

        self.assertEqual(len(observed_thread), 1)
        self.assertNotEqual(observed_thread[0], caller_thread)
        self.assertEqual(constructor.call_count, 2)
        self.assertEqual(
            [call.kwargs["interfaces"] for call in constructor.call_args_list],
            [["192.0.2.30"], ["192.0.2.31"]],
        )
        first_zeroconf.unregister_service.assert_called_once()
        first_zeroconf.close.assert_called_once()
        self.assertEqual(
            second_zeroconf.register_service.call_args.args[0].parsed_addresses(),
            ["192.0.2.31"],
        )

    def test_offline_start_recovers_when_default_address_returns(self) -> None:
        registered = threading.Event()
        addresses = iter(([], ["192.0.2.41"], ["192.0.2.41"]))
        zeroconf = mock.Mock()
        zeroconf.register_service.side_effect = lambda _info: registered.set()
        discovery = DaemonMDNS(
            peer_id=LOCAL,
            port=43123,
            addresses=lambda: next(addresses),
            on_candidate=lambda _candidate: None,
            on_remove=lambda _peer_id: None,
            refresh_interval=0.01,
        )
        with (
            mock.patch("secrets_kit.daemon.mdns.Zeroconf", return_value=zeroconf),
            mock.patch("secrets_kit.daemon.mdns.ServiceBrowser", return_value=mock.Mock()),
        ):
            discovery.start()
            self.assertEqual(discovery.advertised_addresses, ())
            self.assertTrue(registered.wait(timeout=1))
            self.assertEqual(discovery.advertised_addresses, ("192.0.2.41",))
            discovery.stop()

    def test_address_provider_failure_does_not_open_or_leak_zeroconf(self) -> None:
        discovery = DaemonMDNS(
            peer_id=LOCAL,
            port=43123,
            addresses=mock.Mock(side_effect=OSError("offline")),
            on_candidate=lambda _candidate: None,
            on_remove=lambda _peer_id: None,
        )
        with mock.patch("secrets_kit.daemon.mdns.Zeroconf") as constructor:
            with self.assertRaisesRegex(OSError, "offline"):
                discovery.start()
        constructor.assert_not_called()
        self.assertFalse(discovery._active.is_set())

    def test_browser_start_failure_closes_open_zeroconf(self) -> None:
        zeroconf = mock.Mock()
        discovery = DaemonMDNS(
            peer_id=LOCAL,
            port=43123,
            addresses=lambda: ["192.0.2.42"],
            on_candidate=lambda _candidate: None,
            on_remove=lambda _peer_id: None,
        )
        with (
            mock.patch("secrets_kit.daemon.mdns.Zeroconf", return_value=zeroconf),
            mock.patch(
                "secrets_kit.daemon.mdns.ServiceBrowser",
                side_effect=OSError("browser failed"),
            ),
        ):
            with self.assertRaisesRegex(OSError, "browser failed"):
                discovery.start()
        zeroconf.unregister_service.assert_called_once()
        zeroconf.close.assert_called_once()

    def test_interfaces_override_is_forwarded_for_tests(self) -> None:
        discovery = DaemonMDNS(
            peer_id=LOCAL,
            port=43123,
            addresses=lambda: ["192.0.2.40"],
            on_candidate=lambda _candidate: None,
            on_remove=lambda _peer_id: None,
            interfaces=["192.0.2.40"],
            refresh_interval=60,
        )
        fake_zeroconf = mock.Mock()
        with (
            mock.patch("secrets_kit.daemon.mdns.Zeroconf", return_value=fake_zeroconf) as constructor,
            mock.patch("secrets_kit.daemon.mdns.ServiceBrowser", return_value=mock.Mock()),
        ):
            discovery.start()
            discovery.stop()
        constructor.assert_called_once_with(interfaces=["192.0.2.40"], use_asyncio=False)


if __name__ == "__main__":
    unittest.main()
