"""SYN-scan detector tests using synthetic events (no root / live capture)."""

import pytest

from panopticon.core.event import PacketEvent
from panopticon.core.store import StateStore
from panopticon.detection.base import DetectorEngine
from panopticon.detection.syn_scan import SynScanDetector


def syn(t, i, src="10.0.0.1", flags="S", sport=40000, dst="8.8.8.8"):
    return PacketEvent(
        timestamp=t, src=src, dst=dst, proto="tcp",
        sport=sport, dport=10000 + i, size=60, service="", flags=flags,
    )


def test_below_threshold_no_alert():
    detector = SynScanDetector(threshold=20)
    for i in range(20):
        assert detector.process_event(syn(1.0, i), 1.0) is None


def test_threshold_exceeded_alerts():
    detector = SynScanDetector(threshold=3)
    for i in range(3):
        assert detector.process_event(syn(1.0, i), 1.0) is None
    alert = detector.process_event(syn(1.0, 3), 1.0)
    assert alert is not None
    assert alert.kind == "syn_scan"
    assert alert.severity == "warn"
    assert alert.src == "10.0.0.1"
    assert "10.0.0.1" in alert.summary


def test_non_tcp_and_non_syn_ignored():
    detector = SynScanDetector(threshold=1)
    udp = PacketEvent(1.0, "10.0.0.1", "8.8.8.8", "udp", 40000, 10000, 60, "")
    assert detector.process_event(udp, 1.0) is None
    ack = PacketEvent(1.0, "10.0.0.1", "8.8.8.8", "tcp", 40000, 10000, 60, "", "A")
    assert detector.process_event(ack, 1.0) is None
    assert detector.process_event(syn(1.0, 0, flags="SA"), 1.0) is None


def test_syn_ack_clears_pending_flow():
    detector = SynScanDetector(threshold=2)
    detector.process_event(syn(0.0, 0), 0.0)
    detector.process_event(syn(0.0, 1), 0.0)
    # Target answers the first SYN with a SYN-ACK.
    resp = PacketEvent(0.5, "8.8.8.8", "10.0.0.1", "tcp", 10000, 40000, 60, "", "SA")
    assert detector.process_event(resp, 0.5) is None
    # Without the response the count would be 3 > 2; now it stays at 2.
    assert detector.process_event(syn(1.0, 2), 1.0) is None
    assert detector.process_event(syn(1.0, 3), 1.0) is not None


def test_rst_clears_pending_flow():
    detector = SynScanDetector(threshold=2)
    detector.process_event(syn(0.0, 0), 0.0)
    detector.process_event(syn(0.0, 1), 0.0)
    # Target refuses with an RST (connection closed).
    resp = PacketEvent(0.5, "8.8.8.8", "10.0.0.1", "tcp", 10000, 40000, 60, "", "R")
    assert detector.process_event(resp, 0.5) is None
    assert detector.process_event(syn(1.0, 2), 1.0) is None
    # Scanner aborting a flow clears it too.
    detector = SynScanDetector(threshold=2)
    detector.process_event(syn(0.0, 0), 0.0)
    detector.process_event(syn(0.0, 1), 0.0)
    rst = PacketEvent(0.5, "10.0.0.1", "8.8.8.8", "tcp", 40000, 10000, 60, "", "R")
    assert detector.process_event(rst, 0.5) is None
    assert detector.process_event(syn(1.0, 2), 1.0) is None


def test_sliding_window_expires_old_syns():
    detector = SynScanDetector(threshold=2, window=5.0)
    detector.process_event(syn(0.0, 0), 0.0)
    detector.process_event(syn(1.0, 1), 1.0)
    # At t=7 both prior SYNs (7-0=7, 7-1=6) fall out of the 5s window.
    assert detector.process_event(syn(7.0, 2), 7.0) is None
    assert detector.process_event(syn(7.0, 3), 7.0) is None
    assert detector.process_event(syn(7.0, 4), 7.0) is not None


def test_prune_expires_stale_entries():
    detector = SynScanDetector(threshold=5, window=5.0)
    detector.process_event(syn(0.0, 0), 0.0)
    detector.process_event(syn(1.0, 1, src="10.0.0.2"), 1.0)
    detector.process_event(syn(1.0, 2), 1.0)
    assert detector.prune(now=100.0) == 3
    assert detector.prune(now=100.0) == 0


def test_engine_enforces_per_source_cooldown():
    store = StateStore()
    engine = DetectorEngine(
        store,
        detectors=[SynScanDetector(threshold=2)],
        cooldown=30.0,
    )
    engine.process_event(syn(0.0, 0), 0.0)
    engine.process_event(syn(0.0, 1), 0.0)
    alert = engine.process_event(syn(0.0, 2), 0.0)
    assert alert is not None and alert.kind == "syn_scan"
    # Immediate re-scan from the same source is suppressed by cooldown.
    engine.process_event(syn(0.0, 3), 0.0)
    engine.process_event(syn(0.0, 4), 0.0)
    assert engine.process_event(syn(0.0, 5), 0.0) is None
    assert len(store.snapshot_alerts()) == 1
    # After the cooldown elapses a fresh scan alerts again.
    engine.process_event(syn(31.0, 0), 31.0)
    engine.process_event(syn(31.0, 1), 31.0)
    assert engine.process_event(syn(31.0, 2), 31.0) is not None
    assert len(store.snapshot_alerts()) == 2


def test_distinct_sources_alert_independently():
    engine = DetectorEngine(
        StateStore(),
        detectors=[SynScanDetector(threshold=1)],
    )
    e1 = PacketEvent(0.0, "a", "8.8.8.8", "tcp", 1, 10000, 60, "", "S")
    e2 = PacketEvent(0.0, "b", "8.8.8.9", "tcp", 1, 10001, 60, "", "S")
    e3 = PacketEvent(0.0, "a", "8.8.8.10", "tcp", 1, 10002, 60, "", "S")
    e4 = PacketEvent(0.0, "b", "8.8.8.11", "tcp", 1, 10003, 60, "", "S")
    assert engine.process_event(e1, 0.0) is None
    assert engine.process_event(e2, 0.0) is None
    assert engine.process_event(e3, 0.0) is not None
    assert engine.process_event(e4, 0.0) is not None
