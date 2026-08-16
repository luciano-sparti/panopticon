"""Tests for StateStore: EWMA math, snapshots, eviction, counters."""

import pytest

from panopticon.core.event import PacketEvent
from panopticon.core.store import (
    MAX_TALKERS,
    STREAM_MAXLEN,
    TALKER_TTL,
    StateStore,
)

def ev(timestamp, src="10.0.0.1", dst="10.0.0.2", proto="tcp",
       sport=1000, dport=80, size=100):
    return PacketEvent(timestamp, src, dst, proto, sport, dport, size, "http")


class TestVelocityEWMA:
    def test_ewma_pps_and_bytes_sec(self):
        store = StateStore()
        for t in (0.0, 1.0, 2.0):
            store.update(ev(t), now=t)

        tele = store.snapshot_telemetry()
        # t=1: pps = 0.9*0 + 0.1*(1/1) = 0.1 ; bytes/sec = 0.9*0 + 0.1*(100/1) = 10
        # t=2: pps = 0.9*0.1 + 0.1*(1/1) = 0.19 ; bytes/sec = 0.9*10 + 0.1*(100/1) = 19
        assert tele["packets_per_sec"] == pytest.approx(0.19, abs=1e-3)
        assert tele["bytes_per_sec"] == pytest.approx(19.0, abs=1e-3)

    def test_ewma_avg_packet_size(self):
        store = StateStore()
        for t in (0.0, 1.0, 2.0):
            store.update(ev(t, size=100), now=t)
        # init = 100; then stays 100 via 0.9/0.1 blend of identical samples.
        assert store.snapshot_telemetry()["avg_packet_size"] == pytest.approx(100.0)

    def test_ewma_avg_size_responds_to_size_change(self):
        store = StateStore()
        store.update(ev(0.0, size=100), now=0.0)
        store.update(ev(1.0, size=200), now=1.0)
        # avg = 0.9*100 + 0.1*200 = 110
        assert store.snapshot_telemetry()["avg_packet_size"] == pytest.approx(110.0)

    def test_constant_packet_rate_is_stable(self):
        store = StateStore()
        for i in range(50):
            store.update(ev(float(i)), now=float(i))
        # Converges toward ~1.0 pps for a 1 packet/sec stream.
        assert store.snapshot_telemetry()["packets_per_sec"] == pytest.approx(1.0, abs=0.1)

    def test_zero_delta_burst_updates_velocity(self):
        store = StateStore()
        store.update(ev(0.0), now=0.0)
        store.update(ev(0.0), now=0.0)  # same timestamp: dt is clamped, not skipped
        tele = store.snapshot_telemetry()
        assert tele["packets_per_sec"] == pytest.approx(1e5, rel=1e-3)
        assert tele["bytes_per_sec"] == pytest.approx(1e7, rel=1e-3)
        assert tele["avg_packet_size"] == pytest.approx(100.0)


class TestSnapshots:
    def test_talker_snapshot_is_deep_copy(self):
        store = StateStore()
        store.update(ev(0.0, src="1.1.1.1"), now=0.0)

        snap = store.snapshot_talkers()
        snap["1.1.1.1"]["pkts"] = 999
        snap["1.1.1.1"]["bytes"] = 999

        fresh = store.snapshot_talkers()
        assert fresh["1.1.1.1"]["pkts"] == 1
        assert fresh["1.1.1.1"]["bytes"] == 100

    def test_stream_snapshot_is_independent_list(self):
        store = StateStore()
        store.update(ev(0.0), now=0.0)

        snap = store.snapshot_stream()
        snap.clear()
        assert len(store.snapshot_stream()) == 1

    def test_telemetry_snapshot_is_deep_copy(self):
        store = StateStore()
        store.update(ev(0.0, src="1.1.1.1"), now=0.0)

        tele = store.snapshot_telemetry()
        tele["protocol_mix"]["tcp"] = 0
        assert store.snapshot_telemetry()["protocol_mix"]["tcp"] == 100.0


class TestBoundedMemory:
    def test_stream_rolling_buffer_capped(self):
        store = StateStore()
        for i in range(STREAM_MAXLEN + 100):
            store.update(ev(float(i), src=f"ip{i}"), now=float(i))

        stream = store.snapshot_stream()
        assert len(stream) == STREAM_MAXLEN
        # Oldest surviving event is the 101st fed.
        assert stream[0].src == f"ip{100}"

    def test_top_talkers_capped(self):
        store = StateStore()
        for i in range(MAX_TALKERS + 100):
            store.update(ev(float(i), src=f"10.0.{i // 256}.{i % 256}"), now=float(i))

        assert len(store.snapshot_talkers()) == MAX_TALKERS

    def test_ttl_prune_removes_only_stale_talkers(self):
        store = StateStore()
        store.update(ev(0.0, src="stale"), now=0.0)
        store.update(ev(200.0, src="active"), now=200.0)

        removed = store.prune(now=200.0 + TALKER_TTL - 50)
        assert removed == 1
        talkers = store.snapshot_talkers()
        assert "stale" not in talkers
        assert "active" in talkers

    def test_ttl_prune_keeps_recent_talkers(self):
        store = StateStore()
        store.update(ev(0.0, src="fresh"), now=0.0)
        assert store.prune(now=TALKER_TTL) == 0
        assert "fresh" in store.snapshot_talkers()


class TestCounters:
    def test_unique_hosts_derived_from_top_talkers(self):
        store = StateStore()
        for src in ("1.1.1.1", "2.2.2.2", "3.3.3.3"):
            store.update(ev(0.0, src=src), now=0.0)
        assert store.snapshot_telemetry()["unique_hosts"] == 3

    def test_protocol_mix_percentages(self):
        store = StateStore()
        store.update(ev(0.0, src="a", proto="tcp"), now=0.0)
        store.update(ev(0.0, src="b", proto="tcp"), now=0.0)
        store.update(ev(0.0, src="c", proto="udp"), now=0.0)
        store.update(ev(0.0, src="d", proto="icmp"), now=0.0)

        mix = store.snapshot_telemetry()["protocol_mix"]
        assert mix["tcp"] == 50.0
        assert mix["udp"] == 25.0
        assert mix["icmp"] == 25.0
        assert mix["other"] == 0.0

    def test_dropped_packet_counter(self):
        store = StateStore()
        store.increment_dropped()
        store.increment_dropped(4)
        assert store.snapshot_telemetry()["dropped_packets"] == 5


class TestTags:
    def test_add_and_remove_tag_dedup(self):
        store = StateStore()
        store.add_tag("1.1.1.1", "server")
        store.add_tag("1.1.1.1", "server")
        assert store.tags_for("1.1.1.1") == {"server"}

        store.remove_tag("1.1.1.1", "missing")
        assert store.tags_for("1.1.1.1") == {"server"}

        store.remove_tag("1.1.1.1", "server")
        assert store.tags_for("1.1.1.1") == set()
        assert "1.1.1.1" not in store.snapshot_tags()

    def test_talker_snapshot_merges_tags(self):
        store = StateStore()
        store.update(ev(0.0, src="1.1.1.1"), now=0.0)
        store.add_tag("1.1.1.1", "server")
        store.add_tag("1.1.1.1", "web")
        snap = store.snapshot_talkers()
        assert snap["1.1.1.1"]["tags"] == ["server", "web"]
        assert snap["1.1.1.1"]["pkts"] == 1

    def test_talker_without_tags_has_empty_list(self):
        store = StateStore()
        store.update(ev(0.0, src="1.1.1.1"), now=0.0)
        assert store.snapshot_talkers()["1.1.1.1"]["tags"] == []

    def test_tags_survive_lru_eviction(self):
        store = StateStore()
        store.add_tag("10.0.0.1", "server")
        store.update(ev(0.0, src="10.0.0.1"), now=0.0)
        for i in range(MAX_TALKERS):
            store.update(
                ev(float(i), src=f"9.{i // 65536}.{(i // 256) % 256}.{i % 256}"),
                now=float(i),
            )
        assert "10.0.0.1" not in store.snapshot_talkers()
        assert store.tags_for("10.0.0.1") == {"server"}

        store.update(ev(9999.0, src="10.0.0.1"), now=9999.0)
        assert store.snapshot_talkers()["10.0.0.1"]["tags"] == ["server"]

    def test_pinned_talker_survives_ttl_prune(self):
        store = StateStore()
        store.update(ev(0.0, src="pinned"), now=0.0)
        store.add_tag("pinned", "pinned")
        assert store.prune(now=10000.0) == 0
        assert "pinned" in store.snapshot_talkers()

        store.update(ev(0.0, src="boring"), now=0.0)
        assert store.prune(now=10000.0) == 1
        assert "boring" not in store.snapshot_talkers()

    def test_load_tags_bulk_import(self):
        store = StateStore()
        store.load_tags({"1.1.1.1": ["a", "a"], "2.2.2.2": ["b"]})
        assert store.tags_for("1.1.1.1") == {"a"}
        assert store.tags_for("2.2.2.2") == {"b"}

    def test_snapshot_tags_returns_sorted_lists(self):
        store = StateStore()
        store.add_tag("1.1.1.1", "z")
        store.add_tag("1.1.1.1", "a")
        assert store.snapshot_tags() == {"1.1.1.1": ["a", "z"]}


class TestFlows:
    def test_flow_tracking_records_local_port(self):
        store = StateStore(self_ips={"10.0.0.1"}, self_host="host")
        store.update(ev(0.0, src="10.0.0.1", dst="8.8.8.8", sport=4444, dport=80), now=0.0)
        flow = store.snapshot_flow("8.8.8.8")
        assert flow == {"local_port": 4444, "remote_port": 80, "proto": "tcp"}

    def test_flow_tracking_remotes_side(self):
        store = StateStore(self_ips={"10.0.0.1"}, self_host="host")
        store.update(ev(0.0, src="8.8.8.8", dst="10.0.0.1", sport=80, dport=4444), now=0.0)
        assert store.snapshot_flow("8.8.8.8")["local_port"] == 4444

    def test_flow_for_unknown_ip_is_none(self):
        store = StateStore(self_ips={"10.0.0.1"}, self_host="host")
        assert store.snapshot_flow("nope") is None
