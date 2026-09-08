"""IP classification and cached reverse-DNS hostnames.

Phase 9.6: talkers get a cheap, pure ``classify_ip`` category (loopback /
private / link-local / multicast / ...) so the UI can tell a public-range
host from a LAN neighbor without any resolution, plus an opt-in
``HostnameResolver`` that performs slow reverse-DNS lookups on background
daemon threads and serves answers from a monotonic-expiring cache — the
caller never blocks on the network.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
import time
from collections.abc import Iterable
from typing import Callable

# RFC 1918 private IPv4 ranges (public/share pool semantics only; kept as
# explicit networks to avoid the deprecated ``is_private`` on 3.13+).
_RFC1918 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
# IPv6 unique-local addresses (ULA) are the v6 analogue of RFC 1918.
_ULA = ipaddress.ip_network("fc00::/7")


def classify_ip(ip: str) -> str:
    """Return a short human category for ``ip`` (no network I/O).

    Categories: ``loopback``, ``link-local``, ``multicast``, ``broadcast``,
    ``private`` (RFC 1918 / ULA), ``unspecified``, ``public``, or
    ``invalid`` for unparseable input.
    """
    try:
        addr = ipaddress.ip_address(ip.strip().lower())
    except ValueError:
        return "invalid"
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link-local"
    if addr.is_multicast:
        return "multicast"
    if addr.is_unspecified:
        return "unspecified"
    if addr.version == 4:
        if ip.strip() == "255.255.255.255":
            return "broadcast"
        if any(addr in net for net in _RFC1918):
            return "private"
    elif addr in _ULA:
        return "private"
    return "public"


def _gethostbyaddr(ip: str) -> str:
    """Best-effort ``gethostbyaddr`` returning only the primary hostname."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ""


class HostnameResolver:
    """Thread-safe reverse-DNS resolver with a monotonic-expiring cache.

    Resolution happens on bounded daemon threads; ``name_for``/``kick``
    never perform network I/O on the caller's thread. Negative results are
    cached for the same TTL so a dead domain is not re-queried every tick.
    """

    def __init__(
        self,
        enabled: bool = False,
        ttl: float = 900.0,
        max_in_flight: int = 16,
        resolve: Callable[[str], str] | None = None,
    ) -> None:
        self._enabled = enabled
        self._ttl = ttl
        self._max_in_flight = max(1, max_in_flight)
        self._resolve = resolve if resolve is not None else _gethostbyaddr
        self._lock = threading.Lock()
        self._cache: dict[str, tuple[str, float]] = {}
        self._inflight: set[str] = set()

    @property
    def enabled(self) -> bool:
        return self._enabled

    def name_for(self, ip: str) -> str:
        """Cached hostname for ``ip``, or ``""`` when unknown/pending/disabled.

        Only consults the in-memory cache; never blocks on DNS.
        """
        if not self._enabled:
            return ""
        now = time.monotonic()
        with self._lock:
            entry = self._cache.get(ip)
            if entry is not None and now - entry[1] < self._ttl:
                return entry[0]
        return ""

    def kick(self, ips: Iterable[str]) -> None:
        """Ensure background lookups are in flight for the given IPs.

        Bounded to ``max_in_flight`` new lookups per call; already-cached or
        in-flight IPs are skipped.
        """
        if not self._enabled:
            return
        now = time.monotonic()
        with self._lock:
            targets = [
                ip
                for ip in ips
                if ip not in self._inflight
                and (ip not in self._cache or now - self._cache[ip][1] >= self._ttl)
            ][: self._max_in_flight]
            self._inflight.update(targets)
        for ip in targets:
            threading.Thread(target=self._lookup, args=(ip,), daemon=True).start()

    def _lookup(self, ip: str) -> None:
        try:
            name = self._resolve(ip).rstrip(".")
        except Exception:  # noqa: BLE001 - a resolver failure yields no name
            name = ""
        with self._lock:
            self._cache[ip] = (name, time.monotonic())
            self._inflight.discard(ip)
