"""Auto self-tagging tests (monkeypatched IP resolution, no network).

Verifies that packets touching an owned IP get ``self:<hostname>`` tags
(and loopback gets ``self:localhost``), and that the pure IP-resolution
helpers parse real /proc dump formats.
"""

from panopticon.core import identity
from panopticon.core.event import PacketEvent
from panopticon.core.store import StateStore


def ev(ts, src="10.0.0.1", dst="8.8.8.8", proto="tcp", sport=1000, dport=80, size=100):
    return PacketEvent(ts, src, dst, proto, sport, dport, size, "http")


def make_store(monkeypatch, ips, host="testhost"):
    monkeypatch.setattr(identity, "resolve_owned_ips", lambda: set(ips))
    monkeypatch.setattr(identity, "hostname", lambda: host)
    return StateStore()


def test_owned_ip_gets_self_host_tag(monkeypatch):
    store = make_store(monkeypatch, ["10.0.0.5"], host="mypc")
    store.update(ev(0.0, src="10.0.0.5", dst="8.8.8.8"), now=0.0)
    assert "self:mypc" in store.tags_for("10.0.0.5")

    store.update(ev(1.0, src="8.8.8.8", dst="10.0.0.5"), now=1.0)
    assert "self:mypc" in store.tags_for("10.0.0.5")
    assert store.tags_for("8.8.8.8") == set()


def test_loopback_gets_self_localhost(monkeypatch):
    store = make_store(monkeypatch, ["127.0.0.1", "::1"])
    store.update(ev(0.0, src="127.0.0.1", dst="127.0.0.1"), now=0.0)
    assert store.tags_for("127.0.0.1") == {"self:localhost"}


def test_any_loopback_subnet_is_localhost(monkeypatch):
    store = make_store(monkeypatch, ["127.42.0.1"])
    store.update(ev(0.0, src="127.42.0.1", dst="8.8.8.8"), now=0.0)
    assert store.tags_for("127.42.0.1") == {"self:localhost"}


def test_self_tag_merges_into_talker_snapshot(monkeypatch):
    store = make_store(monkeypatch, ["10.0.0.5"], host="testhost")
    store.update(ev(0.0, src="10.0.0.5", dst="8.8.8.8"), now=0.0)
    assert store.snapshot_talkers()["10.0.0.5"]["tags"] == ["self:testhost"]


def test_resolve_owned_ips_includes_loopback_always(monkeypatch):
    monkeypatch.setattr(identity, "resolve_owned_ips", lambda: {"10.0.0.5"})
    monkeypatch.setattr(identity, "hostname", lambda: "host")
    store = StateStore()
    # Only the explicitly owned IP is tagged; loopback was overridden.
    store.update(ev(0.0, src="10.0.0.5"), now=0.0)
    assert "self:host" in store.tags_for("10.0.0.5")


def test_fib_trie_parser_extracts_local_ips():
    text = """
Main:
  +-- 127.0.0.0/8 1 0 0
     +-- 127.0.0.1/32 1 0 0 HOST
        |-- 127.0.0.1
           /32 host LOCAL
  +-- 192.168.1.0/24 2 1 2
     |-- 192.168.1.87
        /32 host LOCAL
     |-- 192.168.1.255
        /32 link UNICAST
"""
    assert identity._fib_trie_ips(text) == {"192.168.1.87"}


def test_if_inet6_parser_extracts_global_scope_only():
    text = """
00000000000000000000000000000001 01 80 10 80       lo
fe800000000000000000000000000000 02 40 20 80       eth0
26070000000000000000000000000001 02 40 00 80       eth0
fe800000000000000000000000000001 03 40 20 80       wlan0
"""
    assert identity._if_inet6_ips(text) == {"2607::1"}


def test_resolve_owned_ips_falls_back_when_proc_missing(monkeypatch):
    def _no_proc(*args, **kwargs):
        raise OSError("No /proc")

    monkeypatch.setattr("builtins.open", _no_proc)
    monkeypatch.setattr("panopticon.core.identity._fallback_ips", lambda: {"192.168.1.50"})
    ips = identity.resolve_owned_ips()
    assert "127.0.0.1" in ips
    assert "::1" in ips
    assert "192.168.1.50" in ips
