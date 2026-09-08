"""Tests for StateStore: EWMA math, snapshots, eviction, counters."""

from dataclasses import FrozenInstanceError

import pytest

from panopticon.core.clock import Clock
from panopticon.core.event import PacketEvent
from panopticon.core.store import (
    MAX_TALKERS,
    SESSION_TTL,
    STREAM_MAXLEN,
    TALKER_TTL,
    StateStore,
)


def ev(
    timestamp,
    src="10.0.0.1",
    dst="10.0.0.2",
    proto="tcp",
    sport=1000,
    dport=80,
    size=100,
    payload=b"",
    flags="",
):
    return PacketEvent(
        timestamp,
        src,
        dst,
        proto,
        sport,
        dport,
        size,
        service="http",
        payload=payload,
        flags=flags,
    )


class TestVelocityEWMA:
    """Velocity math is driven by per-tick accumulation + flush (8.4).

    Updates accumulate packet/byte counts; ``flush_velocity(now)`` folds
    them into the EWMA once per refresh tick. The first flush only records
    the baseline (and seeds ``avg_packet_size`` exactly); velocity blends
    start on the second flush. Tests mirror the analyzer cadence:
    update(s) during the tick, then flush at the tick boundary.
    """

    def test_ewma_pps_and_bytes_sec(self):
        store = StateStore()
        store.update(ev(0.0), now=0.0)
        store.flush_velocity(now=1.0)  # dt=1 -> pps = 0.1*1 = 0.1 ; bps = 0.1*100 = 10
        store.update(ev(1.0), now=1.0)
        store.flush_velocity(now=2.0)  # dt=1 -> pps = 0.9*0.1 + 0.1*1 = 0.19
        store.update(ev(2.0), now=2.0)
        store.flush_velocity(now=3.0)  # dt=1 -> pps = 0.9*0.19 + 0.1*1 = 0.271

        tele = store.snapshot_telemetry()
        assert tele["packets_per_sec"] == pytest.approx(0.271, abs=1e-3)
        assert tele["bytes_per_sec"] == pytest.approx(27.1, abs=1e-3)

    def test_ewma_avg_packet_size(self):
        store = StateStore()
        for t in (0.0, 1.0, 2.0):
            store.update(ev(t, size=100), now=t)
            store.flush_velocity(now=t + 1.0)
        # seeded = 100; stays 100 via the 0.9/0.1 blend of identical samples.
        assert store.snapshot_telemetry()["avg_packet_size"] == pytest.approx(100.0)

    def test_ewma_avg_size_responds_to_size_change(self):
        store = StateStore()
        store.update(ev(0.0, size=100), now=0.0)
        store.flush_velocity(now=1.0)  # seeds avg = 100
        store.update(ev(1.0, size=200), now=1.0)
        store.flush_velocity(now=2.0)  # avg = 0.9*100 + 0.1*200 = 110
        assert store.snapshot_telemetry()["avg_packet_size"] == pytest.approx(110.0)

    def test_constant_packet_rate_is_stable(self):
        store = StateStore()
        for i in range(50):
            store.update(ev(float(i)), now=float(i))
            store.flush_velocity(now=float(i) + 1.0)
        # One packet per 1 s tick each flush -> converges toward ~1.0 pps.
        assert store.snapshot_telemetry()["packets_per_sec"] == pytest.approx(1.0, abs=0.1)

    def test_idle_tick_does_not_decay_rate(self):
        store = StateStore()
        store.update(ev(0.0), now=0.0)
        store.flush_velocity(now=1.0)
        store.flush_velocity(now=2.0)  # idle: 1 full second, no packets
        store.flush_velocity(now=3.0)  # idle
        # No packets arrived, so the rate is untouched (frozen, not decayed).
        assert store.snapshot_telemetry()["packets_per_sec"] == pytest.approx(0.1, abs=1e-3)

    def test_zero_delta_burst_updates_velocity(self):
        store = StateStore()
        store.flush_velocity(now=0.0)  # idle tick: baseline only
        store.update(ev(0.0), now=0.0)
        store.update(ev(0.0), now=0.0)  # same-tick burst accumulates
        store.flush_velocity(now=0.0)  # dt clamped to eps: burst read as one tick
        tele = store.snapshot_telemetry()
        # 2 packets in ~1e-6 s -> inst_pps = 2e6; EWMA x 0.1 = 2e5.
        assert tele["packets_per_sec"] == pytest.approx(2e5, rel=1e-3)
        assert tele["bytes_per_sec"] == pytest.approx(2e7, rel=1e-3)
        assert tele["avg_packet_size"] == pytest.approx(100.0)

    def test_initial_velocity_with_injected_clock(self):
        # When created at monotonic t0=100.0, a first flush at t1=100.5 evaluates dt=0.5
        clock = TestClockInjection._FakeMonotonic(100.0)
        store = StateStore(clock=Clock(clock))
        store.update(ev(100.2), now=100.2)
        clock.value = 100.5
        store.flush_velocity()  # dt = 0.5 -> inst_pps = 1 / 0.5 = 2.0 -> EWMA pps = 0.2
        tele = store.snapshot_telemetry()
        assert tele["packets_per_sec"] == pytest.approx(0.2, abs=1e-3)
        assert tele["bytes_per_sec"] == pytest.approx(20.0, abs=1e-3)


class TestSnapshots:
    def test_talker_snapshot_is_independent_copy(self):
        store = StateStore()
        store.update(ev(0.0, src="1.1.1.1"), now=0.0)

        snap = store.snapshot_talkers()
        snap["1.1.1.1"]["pkts"] = 999
        snap["1.1.1.1"]["bytes"] = 999

        fresh = store.snapshot_talkers()
        assert fresh["1.1.1.1"]["pkts"] == 1
        assert fresh["1.1.1.1"]["bytes"] == 100

    def test_talker_snapshot_added_tags_do_not_leak_back(self):
        store = StateStore()
        store.update(ev(0.0, src="1.1.1.1"), now=0.0)

        snap = store.snapshot_talkers()
        snap["1.1.1.1"]["tags"].append("forged")

        assert store.snapshot_tags().get("1.1.1.1") is None

    def test_stream_snapshot_is_independent_list(self):
        store = StateStore()
        store.update(ev(0.0), now=0.0)

        snap = store.snapshot_stream()
        snap.clear()
        assert len(store.snapshot_stream()) == 1

    def test_stream_snapshot_events_are_immutable_references(self):
        store = StateStore()
        store.update(ev(0.0, payload=b"GET /"), now=0.0)
        event = store.snapshot_stream()[0]
        with pytest.raises(FrozenInstanceError):
            event.summary = "mutated"  # frozen dataclass enforced at runtime

    def test_telemetry_snapshot_is_independent_copy(self):
        store = StateStore()
        store.update(ev(0.0, src="1.1.1.1"), now=0.0)

        tele = store.snapshot_telemetry()
        tele["protocol_mix"]["tcp"] = 0
        assert store.snapshot_telemetry()["protocol_mix"]["tcp"] == 100.0


class TestClockInjection:
    class _FakeMonotonic:
        def __init__(self, value=0.0):
            self.value = value

        def __call__(self):
            return self.value

    def test_prune_defaults_to_injected_clock(self):
        clock = self._FakeMonotonic(1000.0)
        store = StateStore(clock=Clock(clock))
        # Seed the talker at the monotonic anchor; its pkt time is NOT the
        # wall epoch, so a time.time()-based prune (the pre-9.5 behavior)
        # would see 1.7e9 - 1000 ≈ forever and evict it immediately.
        store.update(ev(1000.0, src="mid"), now=1000.0)
        assert "mid" in store.snapshot_talkers()

        clock.value = 1000.0 + TALKER_TTL / 2  # 150 s of true elapsed
        assert store.prune() == 0
        assert "mid" in store.snapshot_talkers()

        clock.value = 1000.0 + TALKER_TTL + 1  # just past TTL
        assert store.prune() == 1
        assert "mid" not in store.snapshot_talkers()

    def test_flush_velocity_defaults_to_injected_clock(self):
        clock = self._FakeMonotonic(1.0)
        store = StateStore(clock=Clock(clock))
        store.update(ev(0.0), now=0.0)
        store.flush_velocity()  # dt = 1.0 (last_flush 0.0) -> pps 0.1
        clock.value = 2.0
        store.update(ev(1.0), now=1.0)
        store.flush_velocity()  # dt = 2.0 - 1.0 = 1.0 -> pps 0.9*0.1 + 0.1*1 = 0.19
        assert store.snapshot_telemetry()["packets_per_sec"] == pytest.approx(0.19, abs=1e-3)


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


class TestSessions:
    """Session/flow tracking (9.8): conversations, states, pruning."""

    def test_tracks_tcp_conversations_with_state_transitions(self):
        store = StateStore()
        store.update(ev(0.0, src="10.0.0.1", dst="8.8.8.8", flags="S"), now=0.0)
        store.update(ev(0.1, src="8.8.8.8", dst="10.0.0.1", flags="SA"), now=0.1)
        sessions = store.snapshot_sessions()
        assert len(sessions) == 2
        states = {s["state"] for s in sessions}
        assert "handshake" in states and "established" in states

    def test_fin_closes_session(self):
        store = StateStore()
        store.update(ev(0.0, src="10.0.0.1", dst="8.8.8.8", flags="SA"), now=0.0)
        store.update(ev(0.1, src="10.0.0.1", dst="8.8.8.8", flags="FA"), now=0.1)
        closed = [s for s in store.snapshot_sessions() if s["state"] == "closed"]
        assert closed
        assert store.snapshot_telemetry()["active_sessions"] == 0

    def test_session_filter_by_ip_and_newest_first(self):
        store = StateStore()
        store.update(ev(0.0, src="10.0.0.2", dst="8.8.8.8", flags="S"), now=0.0)
        store.update(ev(0.0, src="10.0.0.1", dst="8.8.4.4", flags="S"), now=0.1)
        only = store.snapshot_sessions(ip="10.0.0.2")
        assert len(only) == 1
        assert only[0]["src"] == "10.0.0.2"
        all_s = store.snapshot_sessions()
        assert all_s[0]["dst"] == "8.8.4.4"  # most recent first

    def test_idle_sessions_pruned_with_talkers(self):
        store = StateStore()
        store.update(ev(0.0, src="10.0.0.1", dst="8.8.8.8", flags="S"), now=0.0)
        assert len(store.snapshot_sessions()) == 1
        store.prune(now=float(SESSION_TTL) + 1)
        assert store.snapshot_sessions() == []

    def test_udp_conversation_is_active(self):
        store = StateStore()
        store.update(ev(0.0, src="10.0.0.1", dst="8.8.8.8", proto="udp"), now=0.0)
        sessions = store.snapshot_sessions()
        assert len(sessions) == 1
        assert sessions[0]["state"] == "active"
        assert sessions[0]["proto"] == "udp"

    def test_snapshot_sessions_limit_nlargest(self):
        store = StateStore()
        for i in range(10):
            store.update(
                ev(float(i), src="10.0.0.1", dst=f"8.8.8.{i}", sport=1000 + i, dport=80, flags="S"),
                now=float(i),
            )
        # Total 10 sessions; request top 3
        top3 = store.snapshot_sessions(limit=3)
        assert len(top3) == 3
        assert [s["dst"] for s in top3] == ["8.8.8.9", "8.8.8.8", "8.8.8.7"]


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

    def test_dropped_packet_counters_split_by_cause(self):
        store = StateStore()
        store.increment_parse_failure()
        store.increment_queue_drop(4)
        tele = store.snapshot_telemetry()
        assert tele["parse_failures"] == 1
        assert tele["queue_drops"] == 4
        assert tele["dropped_packets"] == 5


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
