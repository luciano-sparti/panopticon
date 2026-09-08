"""BeaconDetector tests with synthetic events (9.9)."""

from panopticon.core.event import PacketEvent
from panopticon.detection.beacon import BeaconDetector


def syn(t, src="10.0.0.1", dst="5.6.7.8", dport=4444, flags="S"):
    return PacketEvent(
        timestamp=t,
        src=src,
        dst=dst,
        proto="tcp",
        sport=40000 + int(t),
        dport=dport,
        size=60,
        service="",
        flags=flags,
    )


def test_regular_cadence_alerts():
    detector = BeaconDetector(min_conns=4, jitter_ratio=0.25)
    # Four connections, perfectly regular 10s cadence.
    for i in range(3):
        assert detector.process_event(syn(10.0 * (i + 1)), 10.0 * (i + 1)) is None
    alert = detector.process_event(syn(40.0), 40.0)
    assert alert is not None
    assert alert.kind == "beaconing"
    assert alert.src == "10.0.0.1"
    assert alert.dst == "5.6.7.8"
    assert "~10.0s intervals" in alert.summary


def test_jittery_cadence_no_alert():
    detector = BeaconDetector(min_conns=4, jitter_ratio=0.25)
    for t in (10.0, 30.0, 60.0, 100.0):  # growing gaps: not regular
        assert detector.process_event(syn(t), t) is None


def test_close_syns_are_retransmits_not_beacons():
    detector = BeaconDetector(min_conns=5, jitter_ratio=0.5)
    # SYN at 10.0 then retransmit at 10.2 should count as ONE connection.
    detector.process_event(syn(10.0), 10.0)
    detector.process_event(syn(10.2), 10.2)
    detector.process_event(syn(20.0), 20.0)
    detector.process_event(syn(20.2), 20.2)
    detector.process_event(syn(30.0), 30.0)
    detector.process_event(syn(30.2), 30.2)
    assert detector.process_event(syn(40.0), 40.0) is None  # only 4 opens < 5
    # A 5th real open (not a retransmit) finally reaches min_conns.
    alert = detector.process_event(syn(50.0), 50.0)
    assert alert is not None
    assert "opened 5 short connections" in alert.summary


def test_non_syn_traffic_ignored():
    detector = BeaconDetector(min_conns=2)
    for flags in ("A", "SA", "F"):
        event = syn(1.0, flags=flags)
        assert detector.process_event(event, 1.0) is None


def test_udp_ignored():
    detector = BeaconDetector(min_conns=2)
    event = PacketEvent(1.0, "10.0.0.1", "5.6.7.8", "udp", 40000, 4444, 60, "")
    assert detector.process_event(event, 1.0) is None


def test_alert_resets_flow_for_repeat_detection():
    detector = BeaconDetector(min_conns=3, jitter_ratio=0.1)
    alert = None
    for i in range(3):
        alert = detector.process_event(syn(10.0 * (i + 1)), 10.0 * (i + 1))
    assert alert is not None
    # Reset happened: new opens re-learn from scratch, no instant re-alert.
    assert detector.process_event(syn(42.0), 42.0) is None


def test_prune_forgets_idle_flows():
    detector = BeaconDetector(min_conns=2)
    detector.process_event(syn(1.0), 1.0)
    removed = detector.prune(2000.0)
    assert removed == 1
    assert detector._opens == {}
