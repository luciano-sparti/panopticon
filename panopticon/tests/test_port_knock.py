"""PortKnockDetector tests with synthetic events (9.9)."""

from panopticon.core.event import PacketEvent
from panopticon.detection.port_knock import PortKnockDetector


def hit(t, port, src="10.0.0.1", dst="2.3.4.5", proto="tcp"):
    return PacketEvent(
        timestamp=t,
        src=src,
        dst=dst,
        proto=proto,
        sport=40000,
        dport=port,
        size=60,
        service="",
    )


def test_many_ports_on_one_host_alerts():
    detector = PortKnockDetector(threshold=3)
    for port in (80, 443, 22):
        assert detector.process_event(hit(1.0, port), 1.0) is None
    alert = detector.process_event(hit(1.0, 8080), 1.0)
    assert alert is not None
    assert alert.kind == "port_knock"
    assert alert.src == "10.0.0.1"
    assert alert.dst == "2.3.4.5"
    assert "2.3.4.5" in alert.summary


def test_distinct_hosts_do_not_cross_count():
    detector = PortKnockDetector(threshold=3)
    # Exactly threshold(3) ports per host, spread across 4 hosts: no alert.
    for dst in ("2.3.4.5", "2.3.4.6", "2.3.4.7", "2.3.4.8"):
        for port in (80, 443, 22):
            assert detector.process_event(hit(1.0, port, dst=dst), 1.0) is None


def test_icmp_ignored_and_ssh_port0():
    detector = PortKnockDetector(threshold=1)
    icmp = PacketEvent(1.0, "10.0.0.1", "2.3.4.5", "icmp", 0, 0, 60, "")
    assert detector.process_event(icmp, 1.0) is None


def test_window_slides_old_ports_out():
    detector = PortKnockDetector(threshold=2, window=5.0)
    for port in (80, 443):
        detector.process_event(hit(1.0, port), 1.0)
    assert detector.process_event(hit(1.0, 22), 1.0) is not None  # 3 ports -> alert
    # The alert resets the (src, dst) pair; a fresh burst re-triggers.
    detector.process_event(hit(100.0, 80), 100.0)
    detector.process_event(hit(100.0, 443), 100.0)
    assert detector.process_event(hit(100.0, 22), 100.0) is not None


def test_prune_forgets_idle_targets():
    detector = PortKnockDetector(threshold=10, window=5.0)
    detector.process_event(hit(1.0, 80), 1.0)
    removed = detector.prune(60.0)
    assert removed == 1
    assert detector._ports == {}
