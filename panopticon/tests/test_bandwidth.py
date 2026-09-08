"""BandwidthDetector tests with synthetic events (9.9)."""

from panopticon.core.event import PacketEvent
from panopticon.detection.bandwidth import BandwidthDetector


def pkt(size, t, src="10.0.0.1"):
    return PacketEvent(
        timestamp=t,
        src=src,
        dst="8.8.8.8",
        proto="tcp",
        sport=40000,
        dport=80,
        size=size,
        service="http",
    )


def test_burst_within_threshold_stays_quiet():
    detector = BandwidthDetector(window=10.0, threshold=5000)
    for i in range(10):
        assert detector.process_event(pkt(400, 0.1 * i, "10.0.0.1"), 0.1 * i) is None
    # 10 * 400 = 4000 bytes / 10s < 5000 threshold -> no alert.


def test_burst_over_threshold_alerts_once_per_window():
    detector = BandwidthDetector(window=10.0, threshold=2000)
    alert = None
    for i in range(15):  # 300 bytes/s; first window closes at t=10 with 3300
        result = detector.process_event(pkt(300, float(i)), float(i))
        if result is not None:
            alert = result
            break
    assert alert is not None
    assert alert.kind == "bandwidth"
    assert alert.src == "10.0.0.1"
    assert "10.0.0.1" in alert.summary


def test_overflow_window_rolls_and_requalifies():
    detector = BandwidthDetector(window=10.0, threshold=3000)
    # First window closes at t=10 with 8 x 400 + 1 = 3201 bytes -> alert.
    for i in range(8):
        detector.process_event(pkt(400, float(i)), float(i))
    assert detector.process_event(pkt(1, 10.0), 10.0) is not None
    # Second window (10..20) is sparse: 800 bytes total stays quiet.
    assert detector.process_event(pkt(400, 15.0), 15.0) is None
    assert detector.process_event(pkt(400, 20.0), 20.0) is None


def test_empty_src_ignored():
    detector = BandwidthDetector(window=1.0, threshold=1)
    event = PacketEvent(1.0, "", "8.8.8.8", "tcp", 0, 80, 10, "")
    assert detector.process_event(event, 1.0) is None


def test_prune_forgets_idle_sources():
    detector = BandwidthDetector(window=10.0, threshold=1)
    detector.process_event(pkt(10, 1.0), 1.0)
    removed = detector.prune(50.0)
    assert removed == 1
    assert detector._last == {}
