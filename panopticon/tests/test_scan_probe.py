"""ScanProbeDetector (FIN/NULL/Xmas) tests with synthetic events (9.8)."""

from panopticon.core.event import PacketEvent
from panopticon.detection.scan_probe import ScanProbeDetector


def probe(t, i, src="10.0.0.1", flags="F", sport=40000, dst="8.8.8.8"):
    return PacketEvent(
        timestamp=t,
        src=src,
        dst=dst,
        proto="tcp",
        sport=sport,
        dport=10000 + i,
        size=60,
        service="",
        flags=flags,
    )


def test_below_threshold_no_alert():
    detector = ScanProbeDetector(threshold=3)
    for i in range(3):
        assert detector.process_event(probe(1.0, i), 1.0) is None


def test_null_scan_alerts():
    detector = ScanProbeDetector(threshold=3)
    for i in range(3):
        assert detector.process_event(probe(1.0, i, flags=""), 1.0) is None
    alert = detector.process_event(probe(1.0, 3, flags=""), 1.0)
    assert alert is not None
    assert alert.kind == "null_scan"
    assert alert.severity == "warn"
    assert alert.src == "10.0.0.1"


def test_fin_scan_alerts():
    detector = ScanProbeDetector(threshold=3)
    for i in range(3):
        detector.process_event(probe(1.0, i, flags="F"), 1.0)
    alert = detector.process_event(probe(1.0, 4, flags="F"), 1.0)
    assert alert is not None
    assert alert.kind == "fin_scan"


def test_xmas_scan_alerts():
    detector = ScanProbeDetector(threshold=3)
    for i in range(3):
        detector.process_event(probe(1.0, i, flags="FPU"), 1.0)
    alert = detector.process_event(probe(1.0, 4, flags="FPU"), 1.0)
    assert alert is not None
    assert alert.kind == "xmas_scan"


def test_mixed_probes_alert_with_majority_kind():
    detector = ScanProbeDetector(threshold=5)
    # 3 FIN + 2 NULL -> 5 targets (no alert), 6th FIN makes majority FIN.
    for i in range(3):
        detector.process_event(probe(1.0, i, flags="F"), 1.0)
    for i in range(2):
        detector.process_event(probe(1.0, i + 100, flags=""), 1.0)
    alert = detector.process_event(probe(1.0, 200, flags="F"), 1.0)
    assert alert is not None
    assert alert.kind == "fin_scan"
    assert "FIN/NULL" in alert.summary


def test_normal_traffic_flags_ignored():
    detector = ScanProbeDetector(threshold=1)
    for flags in ("S", "SA", "A", "PA", "P", "FA"):
        event = probe(1.0, 0, flags=flags)
        assert detector.process_event(event, 1.0) is None


def test_ack_reply_clears_probe():
    detector = ScanProbeDetector(threshold=1)
    assert detector.process_event(probe(1.0, 0, flags="F"), 1.0) is None
    # The scanned host ACKs the FIN on its normal teardown ACK stream
    # (mirrored direction: src=dst/8.8.8.8, sport=10000, dst=10.0.0.1).
    reply = PacketEvent(1.1, "8.8.8.8", "10.0.0.1", "tcp", 10000, 40000, 60, "", flags="FA")
    assert detector.process_event(reply, 1.1) is None
    # Same target again: distinct-target count must not grow past cleared.
    assert detector.process_event(probe(1.2, 0, flags="F"), 1.2) is None


def test_rst_reply_clears_probe():
    detector = ScanProbeDetector(threshold=1)
    assert detector.process_event(probe(1.0, 0, flags=""), 1.0) is None
    reply = PacketEvent(1.1, "8.8.8.8", "10.0.0.1", "tcp", 10000, 40000, 60, "", flags="R")
    assert detector.process_event(reply, 1.1) is None
    assert detector.process_event(probe(1.2, 0, flags=""), 1.2) is None


def test_window_expiry_via_prune():
    detector = ScanProbeDetector(threshold=2, window=5.0)
    detector.process_event(probe(1.0, 0, flags="F"), 1.0)
    removed = detector.prune(10.0)
    assert removed == 1
    # After expiry, only one live probe remains; no alert at threshold 2.
    detector.process_event(probe(2.0, 1, flags="F"), 2.0)
    assert detector.process_event(probe(2.0, 2, flags="F"), 2.0) is None


def test_udp_and_icmp_ignored():
    detector = ScanProbeDetector(threshold=1)
    for proto, flags in (("udp", "F"), ("icmp", "F")):
        event = PacketEvent(1.0, "10.0.0.1", "8.8.8.8", proto, 40000, 10000, 60, "", flags)
        assert detector.process_event(event, 1.0) is None
