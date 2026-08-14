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
