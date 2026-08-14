"""High-port detector tests using synthetic events (no root / live capture)."""

import pytest

from panopticon.core.event import PacketEvent
from panopticon.core.store import StateStore
from panopticon.detection.base import DetectorEngine
from panopticon.detection.high_port import HighPortDetector


def ev(t, dport, src="10.0.0.1", dst="8.8.8.8", proto="tcp",
       sport=1000, service="ephemeral"):
    return PacketEvent(t, src, dst, proto, sport, dport, 100, service)


def test_high_port_alert():
    detector = HighPortDetector()
    alert = detector.process_event(ev(1.0, 50000), 1.0)
    assert alert is not None
    assert alert.kind == "high_port"
    assert alert.severity == "info"
    assert "50000" in alert.summary


def test_below_threshold_no_alert():
    detector = HighPortDetector(threshold_port=49152)
    assert detector.process_event(ev(1.0, 49151), 1.0) is None


def test_boundary_exactly_threshold_alerts():
    detector = HighPortDetector(threshold_port=49152)
    assert detector.process_event(ev(1.0, 49152), 1.0) is not None


def test_non_flow_protocol_ignored():
    detector = HighPortDetector()
    icmp = PacketEvent(1.0, "10.0.0.1", "8.8.8.8", "icmp", 0, 50000, 100, "")
    assert detector.process_event(icmp, 1.0) is None


def test_same_flow_cooldown_dedup():
    detector = HighPortDetector(cooldown=300.0)
    assert detector.process_event(ev(0.0, 50000), 0.0) is not None
    assert detector.process_event(ev(10.0, 50000), 10.0) is None
    # After the cooldown elapses the same flow alerts again.
    assert detector.process_event(ev(301.0, 50000), 301.0) is not None


def test_different_flows_alert_independently():
    detector = HighPortDetector()
    assert detector.process_event(ev(0.0, 50000, dst="1.1.1.1"), 0.0) is not None
    assert detector.process_event(ev(0.0, 51000, dst="2.2.2.2"), 0.0) is not None


def test_ttl_prune_removes_stale_flows():
    detector = HighPortDetector(ttl=300.0)
    detector.process_event(ev(0.0, 50000), 0.0)
    detector.process_event(ev(1.0, 51000), 1.0)
    assert detector.prune(now=400.0) == 2
    assert detector.prune(now=400.0) == 0


def test_entry_cap_evicts_oldest_flow():
    detector = HighPortDetector(max_entries=2)
    assert detector.process_event(ev(0.0, 50000, dst="1.1.1.1"), 0.0) is not None
    assert detector.process_event(ev(0.0, 51000, dst="2.2.2.2"), 0.0) is not None
    # Third flow pushes the map over the cap and evicts the oldest entry.
    assert detector.process_event(ev(0.0, 52000, dst="3.3.3.3"), 0.0) is not None
    assert detector.process_event(ev(0.0, 50000, dst="1.1.1.1"), 0.0) is not None


def test_engine_does_not_collapse_flows():
    store = StateStore()
    engine = DetectorEngine(
        store,
        detectors=[HighPortDetector()],
        cooldown=30.0,
    )
    assert engine.process_event(ev(0.0, 50000, dst="1.1.1.1"), 0.0) is not None
    assert engine.process_event(ev(1.0, 51000, dst="2.2.2.2"), 1.0) is not None
    assert len(store.snapshot_alerts()) == 2


def test_engine_respects_internal_flow_cooldown():
    store = StateStore()
    engine = DetectorEngine(
        store,
        detectors=[HighPortDetector(cooldown=300.0)],
        cooldown=30.0,
    )
    assert engine.process_event(ev(0.0, 50000), 0.0) is not None
    assert engine.process_event(ev(10.0, 50000), 10.0) is None
    assert len(store.snapshot_alerts()) == 1
