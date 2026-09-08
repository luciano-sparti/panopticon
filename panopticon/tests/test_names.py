"""Tests for IP classification and the cached reverse-DNS resolver (9.6)."""

from __future__ import annotations

import time

from panopticon.core.event import PacketEvent
from panopticon.core.names import HostnameResolver, classify_ip
from panopticon.core.store import StateStore


def ev(timestamp, src="10.0.0.1", dst="8.8.8.8", size=100):
    return PacketEvent(timestamp, src, dst, "tcp", 1000, 80, size, service="http", payload=b"")


class TestClassifyIp:
    def test_loopback(self):
        assert classify_ip("127.0.0.1") == "loopback"
        assert classify_ip("::1") == "loopback"

    def test_private_rfc1918(self):
        for ip in ("10.0.0.1", "172.16.4.5", "192.168.1.2"):
            assert classify_ip(ip) == "private"

    def test_unique_local_ipv6_is_private(self):
        assert classify_ip("fd00::1") == "private"
        assert classify_ip("fc00::1") == "private"

    def test_link_local(self):
        assert classify_ip("169.254.4.4") == "link-local"
        assert classify_ip("fe80::1") == "link-local"

    def test_multicast(self):
        assert classify_ip("224.0.0.1") == "multicast"
        assert classify_ip("ff02::1") == "multicast"

    def test_broadcast_and_unspecified(self):
        assert classify_ip("255.255.255.255") == "broadcast"
        assert classify_ip("0.0.0.0") == "unspecified"
        assert classify_ip("::") == "unspecified"

    def test_public(self):
        assert classify_ip("8.8.8.8") == "public"
        assert classify_ip("2001:4860:4860::8888") == "public"

    def test_invalid(self):
        assert classify_ip("garbage") == "invalid"
        assert classify_ip("") == "invalid"


class TestHostnameResolver:
    def test_disabled_never_resolves(self):
        calls = []
        resolver = HostnameResolver(enabled=False, resolve=lambda ip: calls.append(ip) or ip)
        assert resolver.name_for("8.8.8.8") == ""
        resolver.kick(["8.8.8.8"])
        time.sleep(0.05)
        assert calls == []
        assert resolver.name_for("8.8.8.8") == ""

    def test_resolves_in_background_and_caches(self):
        calls = []

        def fake_resolve(ip):
            calls.append(ip)
            return f"host-{ip}.example.com."

        resolver = HostnameResolver(enabled=True, resolve=fake_resolve)
        assert resolver.name_for("8.8.8.8") == ""  # pending, no block
        resolver.kick(["8.8.8.8"])
        for _ in range(100):
            if calls:
                break
            time.sleep(0.01)
        assert calls == ["8.8.8.8"]
        for _ in range(100):
            name = resolver.name_for("8.8.8.8")
            if name:
                break
            time.sleep(0.01)
        assert name == "host-8.8.8.8.example.com"  # trailing dot stripped

        resolver.kick(["8.8.8.8"])
        time.sleep(0.02)
        assert len(calls) == 1  # cached, not re-resolved

    def test_negative_results_are_cached(self):
        calls = []
        resolver = HostnameResolver(
            enabled=True, ttl=3600.0, resolve=lambda ip: calls.append(ip) or ""
        )
        resolver.kick(["10.1.2.3"])
        for _ in range(100):
            if calls:
                break
            time.sleep(0.01)
        assert calls == ["10.1.2.3"]
        # Cache holds the empty name; name_for stays "" without re-resolving.
        resolver.kick(["10.1.2.3"])
        time.sleep(0.02)
        assert len(calls) == 1

    def test_ttl_expiry_re_resolves(self):
        calls = []
        resolver = HostnameResolver(
            enabled=True, ttl=0.05, resolve=lambda ip: calls.append(ip) or ip
        )
        resolver.kick(["8.8.8.8"])
        for _ in range(100):
            if calls:
                break
            time.sleep(0.01)
        time.sleep(0.07)  # cache expired
        assert resolver.name_for("8.8.8.8") == ""  # stale -> treated unknown
        resolver.kick(["8.8.8.8"])
        for _ in range(100):
            if len(calls) >= 2:
                break
            time.sleep(0.01)
        assert len(calls) == 2

    def test_inflight_dedupe_single_lookup(self):
        calls = []
        resolver = HostnameResolver(enabled=True, resolve=lambda ip: calls.append(ip) or ip)
        resolver.kick(["8.8.8.8"])
        resolver.kick(["8.8.8.8"])
        for _ in range(100):
            if len(calls) >= 1:
                break
            time.sleep(0.01)
        time.sleep(0.02)
        assert calls == ["8.8.8.8"]


class TestStoreNames:
    def test_snapshot_talkers_includes_class_and_name(self):
        store = StateStore()
        store.update(ev(0.0, src="10.0.0.1"))
        store.update(ev(1.0, src="8.8.8.8"))
        snap = store.snapshot_talkers()
        assert snap["10.0.0.1"]["class"] == "private"
        assert snap["8.8.8.8"]["class"] == "public"
        assert snap["10.0.0.1"]["name"] == ""  # no resolver attached

    def test_enabled_resolver_feeds_names(self):
        store = StateStore(names=HostnameResolver(enabled=True, resolve=lambda ip: f"{ip}.lan"))
        store.update(ev(0.0, src="192.168.1.5"))
        store.pump_hostnames()
        name = ""
        for _ in range(100):
            name = store.snapshot_talkers()["192.168.1.5"]["name"]
            if name:
                break
            time.sleep(0.01)
        assert name == "192.168.1.5.lan"

    def test_pump_hostnames_noop_without_resolver(self):
        store = StateStore()
        store.update(ev(0.0, src="10.0.0.1"))
        store.pump_hostnames()  # must not raise
