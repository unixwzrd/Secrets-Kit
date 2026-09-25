"""Lifecycle-scoped mDNS advertisement and discovery for the daemon transport.

Announcements produce unauthenticated libp2p dial candidates only. This module
does not mutate the peerstore, routing table, admission state, or application
authorization.
"""

from __future__ import annotations

import ipaddress
import logging
import secrets
import socket
import threading
from collections.abc import Callable, Sequence
from typing import Any

from libp2p.abc import Multiaddr
from libp2p.peer.id import ID
from libp2p.peer.peerinfo import PeerInfo
from zeroconf import InterfaceChoice, ServiceBrowser, ServiceInfo, ServiceListener, Zeroconf

LOGGER = logging.getLogger(__name__)
SERVICE_TYPE = "_p2p._udp.local."
SERVICE_LOOKUP_TIMEOUT_MS = 1000
MDNS_CLEANUP_TIMEOUT_SECONDS = 2.0
ADDRESS_REFRESH_INTERVAL_SECONDS = 5.0

CandidateCallback = Callable[[PeerInfo], None]
RemoveCallback = Callable[[str], None]
AddressProvider = Callable[[], list[str]]


class DaemonMDNS(ServiceListener):
    """Own one bounded zeroconf browser, advertisement, and callback lifecycle."""

    def __init__(
        self,
        *,
        peer_id: str,
        port: int,
        addresses: AddressProvider,
        on_candidate: CandidateCallback,
        on_remove: RemoveCallback,
        interfaces: InterfaceChoice
        | Sequence[str | int | tuple[Any, int]]
        | None = None,
        refresh_interval: float = ADDRESS_REFRESH_INTERVAL_SECONDS,
    ) -> None:
        if not 1 <= port <= 65535:
            raise ValueError("mDNS advertisement requires an actual TCP port")
        self._peer_id = peer_id
        self._port = port
        self._address_provider = addresses
        self._on_candidate = on_candidate
        self._on_remove = on_remove
        self._interfaces = interfaces
        self._refresh_interval = refresh_interval
        self._service_name = f"{secrets.token_hex(16)}.{SERVICE_TYPE}"
        self._zeroconf: Zeroconf | None = None
        self._browser: ServiceBrowser | None = None
        self._service_info: ServiceInfo | None = None
        self._services: dict[str, PeerInfo] = {}
        self._active = threading.Event()
        self._stop_refresh = threading.Event()
        self._refresh_thread: threading.Thread | None = None
        self._network_lock = threading.RLock()
        self._callback_lock = threading.RLock()

    @property
    def advertised_addresses(self) -> tuple[str, ...]:
        """Return the addresses in the currently registered service record."""
        info = self._service_info
        return tuple(info.parsed_addresses()) if info is not None else ()

    def start(self) -> None:
        """Open zeroconf resources and register the current default address."""
        if self._active.is_set():
            return
        addresses = self._address_provider()
        stop_refresh = threading.Event()
        self._stop_refresh = stop_refresh
        self._active.set()
        try:
            if addresses:
                with self._network_lock:
                    self._open_membership(addresses)
        except BaseException:
            self.stop()
            raise
        self._refresh_thread = threading.Thread(
            target=self._refresh_addresses,
            args=(stop_refresh,),
            name="seckit-mdns-address-refresh",
            daemon=True,
        )
        self._refresh_thread.start()

    def stop(self, *, timeout: float = MDNS_CLEANUP_TIMEOUT_SECONDS) -> None:
        """Disable callbacks immediately and bound network-resource cleanup."""
        with self._callback_lock:
            self._active.clear()
            self._services.clear()
        stop_refresh = self._stop_refresh
        stop_refresh.set()
        refresh_thread = self._refresh_thread
        if refresh_thread is not None and refresh_thread is not threading.current_thread():
            refresh_thread.join(timeout=max(0.0, timeout / 2))
        if self._refresh_thread is refresh_thread:
            self._refresh_thread = None

        def cleanup() -> None:
            with self._network_lock:
                browser, zeroconf, service_info = self._detach_membership()
                self._close_membership(
                    browser=browser,
                    zeroconf=zeroconf,
                    service_info=service_info,
                )

        cleanup_thread = threading.Thread(
            target=cleanup,
            name="seckit-mdns-cleanup",
            daemon=True,
        )
        cleanup_thread.start()
        if cleanup_thread is not threading.current_thread():
            cleanup_thread.join(timeout=max(0.0, timeout / 2))

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Add or replace one service-name-owned candidate."""
        self._update_service(zc=zc, type_=type_, name=name)

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Replace one service candidate, including a changed peer identity."""
        self._update_service(zc=zc, type_=type_, name=name)

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Remove only the candidate owned by this discovered service name."""
        del type_
        with self._callback_lock:
            if (
                not self._active.is_set()
                or zc is not self._zeroconf
                or name == self._service_name
            ):
                return
            previous = self._services.pop(name, None)
            if previous is None:
                return
            self._publish_removed_or_remaining(previous=previous, removed_name=name)

    def _update_service(self, *, zc: Zeroconf, type_: str, name: str) -> None:
        if (
            not self._active.is_set()
            or zc is not self._zeroconf
            or name == self._service_name
        ):
            return
        info = zc.get_service_info(type_, name, timeout=SERVICE_LOOKUP_TIMEOUT_MS)
        candidate = self._peer_info(info)
        with self._callback_lock:
            if not self._active.is_set() or zc is not self._zeroconf:
                return
            previous = self._services.get(name)
            if candidate is None:
                if previous is not None:
                    self._services.pop(name, None)
                    self._publish_removed_or_remaining(
                        previous=previous,
                        removed_name=name,
                    )
                return
            self._services[name] = candidate
            if previous is not None and previous.peer_id != candidate.peer_id:
                self._publish_removed_or_remaining(
                    previous=previous,
                    removed_name=name,
                )
            self._on_candidate(candidate)

    def _publish_removed_or_remaining(self, *, previous: PeerInfo, removed_name: str) -> None:
        peer_id = str(previous.peer_id)
        remaining = next(
            (
                candidate
                for service_name, candidate in self._services.items()
                if service_name != removed_name and str(candidate.peer_id) == peer_id
            ),
            None,
        )
        if not self._active.is_set():
            return
        if remaining is None:
            self._on_remove(peer_id)
        else:
            self._on_candidate(remaining)

    def _peer_info(self, info: ServiceInfo | None) -> PeerInfo | None:
        """Parse a bounded announcement without granting trust or mutating state."""
        if info is None or not isinstance(info.port, int) or not 1 <= info.port <= 65535:
            return None
        raw_peer_id = info.properties.get(b"id")
        if not isinstance(raw_peer_id, bytes):
            return None
        try:
            peer_id = ID.from_string(raw_peer_id.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return None
        if str(peer_id) == self._peer_id:
            return None
        addresses: list[Multiaddr] = []
        try:
            for raw_address in info.parsed_addresses():
                address = ipaddress.ip_address(raw_address)
                if address.is_unspecified:
                    return None
                protocol = "ip4" if address.version == 4 else "ip6"
                addresses.append(Multiaddr(f"/{protocol}/{address}/tcp/{info.port}"))
        except (TypeError, ValueError):
            return None
        if not addresses:
            return None
        return PeerInfo(peer_id=peer_id, addrs=addresses)

    def _new_service_info(self, addresses: list[str]) -> ServiceInfo:
        valid_addresses = [
            str(address)
            for raw in addresses
            if not (address := ipaddress.ip_address(raw)).is_unspecified
        ]
        return ServiceInfo(
            type_=SERVICE_TYPE,
            name=self._service_name,
            port=self._port,
            properties={b"id": self._peer_id.encode("utf-8")},
            server=f"{socket.gethostname()}.local.",
            parsed_addresses=valid_addresses,
        )

    def _refresh_addresses(self, stop_refresh: threading.Event | None = None) -> None:
        """Recreate default-interface membership when its IPv4 address changes."""
        stop_refresh = stop_refresh or self._stop_refresh
        while not stop_refresh.wait(self._refresh_interval):
            if not self._active.is_set():
                return
            try:
                addresses = self._address_provider()
                if stop_refresh.is_set() or not self._active.is_set():
                    return
                with self._network_lock:
                    if stop_refresh.is_set() or not self._active.is_set():
                        return
                    current = self.advertised_addresses
                    replacement = self._new_service_info(addresses)
                    selected = tuple(replacement.parsed_addresses())
                    if selected == current:
                        continue
                    browser, zeroconf, service_info = self._detach_membership()
                    self._remove_all_candidates()
                    self._close_membership(
                        browser=browser,
                        zeroconf=zeroconf,
                        service_info=service_info,
                    )
                    if selected:
                        self._open_membership(list(selected))
            except Exception:
                LOGGER.warning("mDNS address refresh failed", exc_info=True)

    def _remove_all_candidates(self) -> None:
        """Retire candidates owned by membership on the previous interface."""
        with self._callback_lock:
            peer_ids = {str(candidate.peer_id) for candidate in self._services.values()}
            self._services.clear()
            if not self._active.is_set():
                return
            for peer_id in peer_ids:
                self._on_remove(peer_id)

    def _open_membership(self, addresses: list[str]) -> None:
        """Open Zeroconf on the selected LAN address or explicit test override."""
        service_info = self._new_service_info(addresses)
        interfaces = addresses if self._interfaces is None else self._interfaces
        zeroconf = Zeroconf(interfaces=interfaces, use_asyncio=False)
        browser: ServiceBrowser | None = None
        try:
            zeroconf.register_service(service_info)
            self._zeroconf = zeroconf
            self._service_info = service_info
            browser = ServiceBrowser(zeroconf, SERVICE_TYPE, listener=self)
            self._browser = browser
        except BaseException:
            self._browser = None
            self._zeroconf = None
            self._service_info = None
            self._close_membership(
                browser=browser,
                zeroconf=zeroconf,
                service_info=service_info,
            )
            raise

    def _detach_membership(
        self,
    ) -> tuple[ServiceBrowser | None, Zeroconf | None, ServiceInfo | None]:
        """Detach current resources before bounded cleanup or replacement."""
        browser, self._browser = self._browser, None
        zeroconf, self._zeroconf = self._zeroconf, None
        service_info, self._service_info = self._service_info, None
        return browser, zeroconf, service_info

    @staticmethod
    def _close_membership(
        *,
        browser: ServiceBrowser | None,
        zeroconf: Zeroconf | None,
        service_info: ServiceInfo | None,
    ) -> None:
        """Release one detached membership without allowing cleanup failures out."""
        if zeroconf is None:
            return
        if browser is not None:
            try:
                browser.cancel()
            except Exception:
                LOGGER.debug("mDNS browser was unavailable during cancel", exc_info=True)
        if service_info is not None:
            try:
                zeroconf.unregister_service(service_info)
            except Exception:
                LOGGER.debug("mDNS service was unavailable during unregister", exc_info=True)
        try:
            zeroconf.close()
        except Exception:
            LOGGER.debug("mDNS zeroconf was unavailable during close", exc_info=True)


__all__ = ["DaemonMDNS", "SERVICE_TYPE"]
